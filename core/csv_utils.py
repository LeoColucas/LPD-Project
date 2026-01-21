from __future__ import annotations

import csv
from pathlib import Path
from datetime import datetime
from typing import Iterable, Optional

from modules.port_scanner import ScanResult


def write_open_ports_csv(
    filepath: str | Path,
    target_host: str,
    resolved_ip: str,
    started_at: datetime,
    finished_at: datetime,
    results: Iterable[ScanResult],
) -> Path:
    """
    Escreve um CSV com as portas abertas e metadados do scan.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    duration = finished_at - started_at

    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)

        # Cabeçalho "metadata" (linhas comentadas não são padrão CSV, então usamos key,value)
        w.writerow(["meta_key", "meta_value"])
        w.writerow(["target_host", target_host])
        w.writerow(["resolved_ip", resolved_ip])
        w.writerow(["started_at", started_at.isoformat(timespec="seconds")])
        w.writerow(["finished_at", finished_at.isoformat(timespec="seconds")])
        w.writerow(["duration", str(duration)])
        w.writerow([])

        # Tabela de resultados
        w.writerow(["host", "resolved_ip", "port", "state", "service"])
        for r in results:
            # assumes results já filtrados para open
            w.writerow([target_host, resolved_ip, r.port, "open", r.service])

    return path
