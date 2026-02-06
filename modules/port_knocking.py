# modules/port_knocking.py
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Sequence


@dataclass
class KnockReport:
    host: str
    knock_ports: list[int]
    per_port_result: list[bool]
    ssh_port: int
    ssh_open: bool


def _tcp_connect_once(host: str, port: int, timeout_s: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def send_knocks(
    host: str,
    ports: Sequence[int],
    delay_s: float = 0.3,
    timeout_s: float = 1.0,
) -> list[bool]:
    results: list[bool] = []
    for p in ports:
        results.append(_tcp_connect_once(host, int(p), timeout_s))
        time.sleep(max(0.0, delay_s))
    return results


def knock_then_test_ssh(
    host: str,
    knock_ports: Sequence[int],
    ssh_port: int = 22,
    delay_s: float = 0.3,
    timeout_s: float = 1.0,
    wait_after_s: float = 0.5,
) -> KnockReport:
    per_port = send_knocks(host, knock_ports, delay_s=delay_s, timeout_s=timeout_s)
    time.sleep(max(0.0, wait_after_s))
    ssh_open = _tcp_connect_once(host, ssh_port, timeout_s=timeout_s)
    return KnockReport(
        host=host,
        knock_ports=list(map(int, knock_ports)),
        per_port_result=per_port,
        ssh_port=ssh_port,
        ssh_open=ssh_open,
    )
