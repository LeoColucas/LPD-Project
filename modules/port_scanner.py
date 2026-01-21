from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Tuple


@dataclass(frozen=True)
class ScanResult:
    host: str
    port: int
    is_open: bool
    service: str = ""


def _resolve_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _scan_one_tcp(resolved_host: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    """
    Devolve (port, is_open, service). Usa o host já resolvido para evitar DNS repetido.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((resolved_host, port))  # connect_ex (como na aula)
        is_open = (code == 0)
        service = _resolve_service_name(port) if is_open else ""
        return port, is_open, service
    except (socket.timeout, OSError):
        return port, False, ""
    finally:
        try:
            s.close()
        except Exception:
            pass
def expand_targets(spec: str) -> List[str]:
    """
    Aceita:
      - "192.168.1.10"
      - "pc1.local,192.168.1.20"
      - "192.168.1.0/24"
      - "192.168.1.10-192.168.1.30"
    Devolve lista de targets (strings) para scanear.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("Targets vazios.")

    # Suporta lista por vírgulas
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    targets: List[str] = []

    for part in parts:
        # Intervalo IP: a-b
        if "-" in part and "/" not in part:
            a, b = part.split("-", 1)
            start_ip = ipaddress.ip_address(a.strip())
            end_ip = ipaddress.ip_address(b.strip())
            if start_ip.version != 4 or end_ip.version != 4:
                raise ValueError("Intervalos só suportados para IPv4 nesta versão.")
            if int(start_ip) > int(end_ip):
                start_ip, end_ip = end_ip, start_ip
            for x in range(int(start_ip), int(end_ip) + 1):
                targets.append(str(ipaddress.ip_address(x)))
            continue

        # CIDR: 192.168.1.0/24
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            if net.version != 4:
                raise ValueError("CIDR só suportado para IPv4 nesta versão.")
            # hosts() exclui network/broadcast
            targets.extend([str(ip) for ip in net.hosts()])
            continue

        # Hostname ou IP individual
        targets.append(part)

    # Remove duplicados mantendo ordem
    seen = set()
    out: List[str] = []
    for t in targets:
        if t not in seen:
            out.append(t)
            seen.add(t)
    return out

def parse_ports(spec: str) -> List[int]:
    """
    Aceita:
      "22"
      "22,80,443"
      "1-1024"
      "22,80-90,443"
    """
    ports: set[int] = set()
    spec = spec.strip()
    if not spec:
        raise ValueError("Especificação de portos vazia.")

    parts = [p.strip() for p in spec.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            start = int(a.strip())
            end = int(b.strip())
            if start <= 0 or end <= 0 or start > 65535 or end > 65535:
                raise ValueError(f"Intervalo inválido: {part}")
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):  # inclusivo
                ports.add(p)
        else:
            p = int(part)
            if p <= 0 or p > 65535:
                raise ValueError(f"Porto inválido: {p}")
            ports.add(p)

    return sorted(ports)


def validate_host(host: str) -> str:
    host = host.strip()
    if not host:
        raise ValueError("Host vazio.")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if " " in host:
        raise ValueError("Host inválido (contém espaços).")

    return host


def resolve_ip(host: str) -> str:
    """
    Resolve hostname -> IP (ou devolve o próprio IP se já for IP).
    Lança socket.gaierror se falhar.
    """
    return socket.gethostbyname(host)


def tcp_scan_simple(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    only_open: bool = True,
) -> Tuple[List[ScanResult], str, str]:
    """
    Modo sequencial (tipo aula).
    Devolve (results, elapsed_str, resolved_ip).
    """
    port_list = list(ports)
    t1 = datetime.now()

    try:
        resolved_ip = resolve_ip(host)
    except socket.gaierror:
        t2 = datetime.now()
        return ([], str(t2 - t1), "")

    results: List[ScanResult] = []
    timeout = max(0.05, float(timeout))

    for p in port_list:
        port, is_open, service = _scan_one_tcp(resolved_ip, p, timeout)
        r = ScanResult(host=host, port=port, is_open=is_open, service=service)
        if (not only_open) or r.is_open:
            results.append(r)

    t2 = datetime.now()
    return (sorted(results, key=lambda x: x.port), str(t2 - t1), resolved_ip)


def tcp_scan_threaded(
    host: str,
    ports: Iterable[int],
    timeout: float = 0.5,
    workers: int = 200,
    only_open: bool = True,
) -> Tuple[List[ScanResult], str, str]:
    """
    Modo rápido (threads).
    Devolve (results, elapsed_str, resolved_ip).
    """
    port_list = list(ports)
    t1 = datetime.now()

    try:
        resolved_ip = resolve_ip(host)
    except socket.gaierror:
        t2 = datetime.now()
        return ([], str(t2 - t1), "")

    results: List[ScanResult] = []

    workers = max(1, min(int(workers), 1000))
    timeout = max(0.05, float(timeout))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_scan_one_tcp, resolved_ip, p, timeout) for p in port_list]
        for fut in as_completed(futures):
            port, is_open, service = fut.result()
            r = ScanResult(host=host, port=port, is_open=is_open, service=service)
            if (not only_open) or r.is_open:
                results.append(r)

    t2 = datetime.now()
    return (sorted(results, key=lambda x: x.port), str(t2 - t1), resolved_ip)
