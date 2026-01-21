from __future__ import annotations

import socket
import os
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class UdpFloodConfig:
    target_ip: str
    target_port: int
    packet_size: int = 1024
    max_packets: int = 1000
    delay_s: float = 0.01


def udp_flood_simulation(cfg: UdpFloodConfig) -> tuple[int, float]:
    """
    Simulação controlada de tráfego UDP intensivo.
    Usar apenas em ambientes de teste (VM/localhost/rede de laboratório).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = os.urandom(cfg.packet_size)

    sent = 0
    t0 = time.time()

    try:
        for _ in range(cfg.max_packets):
            sock.sendto(payload, (cfg.target_ip, cfg.target_port))
            sent += 1
            if cfg.delay_s > 0:
                time.sleep(cfg.delay_s)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    elapsed = time.time() - t0
    return sent, elapsed
