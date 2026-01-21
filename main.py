#!/usr/bin/env python3
"""
LPD Security Tool - CLI Skeleton
- Main menu loop
- Input validation
- Handlers for each feature
"""

from __future__ import annotations

from core.csv_utils import write_open_ports_csv
from modules.udp_flood import UdpFloodConfig, udp_flood_simulation
from modules.syn_flood import SynFloodConfig, syn_flood_simulation

from modules.port_scanner import (
    expand_targets,
    validate_host,
    parse_ports,
    tcp_scan_simple,
    tcp_scan_threaded,
)

import sys
from dataclasses import dataclass
from typing import Callable, Dict, Optional
from datetime import datetime


@dataclass(frozen=True)
class MenuOption:
    key: str
    label: str
    action: Callable[[], None]


def clear_screen() -> None:
    # Mantém simples e portável (não depende de 'clear' / 'cls')
    print("\n" * 3)


def pause(msg: str = "Enter para continuar...") -> None:
    try:
        input(msg)
    except (EOFError, KeyboardInterrupt):
        # Se o user mandar CTRL+D/CTRL+C aqui, voltamos ao menu
        print()


def read_choice(prompt: str, valid_keys: set[str]) -> str:
    while True:
        try:
            choice = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Entrada interrompida. A sair.")
            sys.exit(0)

        if choice in valid_keys:
            return choice

        print(f"[!] Opção inválida: {choice!r}. Válidas: {', '.join(sorted(valid_keys))}")


def print_menu(title: str, options: Dict[str, MenuOption]) -> None:
    print("=" * 60)
    print(title)
    print("=" * 60)
    for key in sorted(options.keys(), key=lambda k: (k == "0", k)):
        # regra: mostra "0 - Sair/Voltar" normalmente no fim
        print(f"{options[key].key} - {options[key].label}")
    print("-" * 60)


# -------------------------
# Handlers (stubs)
# -------------------------

def handle_port_scan() -> None:
    clear_screen()
    print("== Port Scanner (TCP connect) ==")
    print("Targets aceites: IP, hostname, lista por vírgulas, CIDR (ex: 192.168.1.0/24), intervalo (ex: 192.168.1.10-192.168.1.30)\n")

    targets_spec = input("Targets: ").strip()
    ports_spec = input("Portos (ex: 22,80,443 ou 1-1024): ").strip()

    try:
        targets = expand_targets(targets_spec)
        # valida cada target (hostname/IP)
        targets = [validate_host(t) for t in targets]
        ports = parse_ports(ports_spec)
    except ValueError as e:
        print(f"[!] Erro: {e}")
        pause()
        return

    mode = input("Modo [1=aula/seq, 2=rápido/threads] (default 2): ").strip() or "2"

    # parâmetros
    try:
        if mode == "1":
            timeout = float(input("Timeout por porto [1.0]: ").strip() or "1.0")
            workers = None
        else:
            timeout = float(input("Timeout por porto [0.5]: ").strip() or "0.5")
            workers = int(input("Threads [200]: ").strip() or "200")
    except ValueError:
        print("[!] Timeout/threads inválidos.")
        pause()
        return

    save = (input("\nGuardar resultados em CSV (um ficheiro por host)? [s/N]: ").strip().lower() or "n") == "s"

    # scan
    for host in targets:
        clear_screen()
        print(f"== Scan: {host} ==")
        started_at = datetime.now()

        try:
            if mode == "1":
                results, elapsed, resolved_ip = tcp_scan_simple(host, ports, timeout=timeout, only_open=True)
            else:
                results, elapsed, resolved_ip = tcp_scan_threaded(host, ports, timeout=timeout, workers=workers, only_open=True)
        except KeyboardInterrupt:
            print("\n[!] Interrompido.")
            pause()
            return

        finished_at = datetime.now()

        print(f"Target: {host}")
        print(f"IP resolvido: {resolved_ip or '(n/a)'}")

        if not results:
            print("Nenhum porto aberto encontrado (ou filtrado por firewall).")
            print(f"Tempo total: {elapsed}")
            if save:
                # mesmo sem portas abertas, podes optar por guardar (opcional). Aqui não guardo.
                pass
            pause("Enter para próximo host...")
            continue

        print("Portos abertos:")
        for r in results:
            svc = f" ({r.service})" if r.service else ""
            print(f" - {r.port}{svc}")
        print(f"Tempo total: {elapsed}")

        if save:
            safe_host = host.replace("/", "_").replace("\\", "_").replace(":", "_")
            fname = f"scan_{safe_host}_{started_at.strftime('%Y%m%d_%H%M%S')}.csv"
            out_path = f"reports/{fname}"
            try:
                path = write_open_ports_csv(
                    filepath=out_path,
                    target_host=host,
                    resolved_ip=resolved_ip or "",
                    started_at=started_at,
                    finished_at=finished_at,
                    results=results,
                )
                print(f"[+] CSV guardado em: {path}")
            except OSError as e:
                print(f"[!] Erro a escrever CSV: {e}")

        pause("Enter para próximo host...")

def handle_syn_flood() -> None:
    clear_screen()
    print("== TCP SYN Flood (Simulação Controlada) ==")
    print("⚠️ Usar apenas em ambiente de teste (localhost / VM).\n")

    ip = input("Target IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = int(input("Target port (ex: 80/25) [80]: ").strip() or "80")
    packets = int(input("Número de SYN packets [100]: ").strip() or "100")
    delay = float(input("Delay entre pacotes (s) [0.05]: ").strip() or "0.05")

    cfg = SynFloodConfig(
        target_ip=ip,
        target_port=port,
        max_packets=packets,
        delay_s=delay,
    )

    print("\nA enviar pacotes SYN...\n")
    sent, elapsed = syn_flood_simulation(cfg)

    print(f"SYN enviados: {sent}")
    print(f"Tempo total: {elapsed:.2f}s")
    print(f"Taxa média: {sent/elapsed:.2f} SYN/s")
    pause()


def handle_udp_flood() -> None:
    clear_screen()
    print("== UDP Flood (Simulação Controlada) ==")
    print("⚠️ Usar apenas em ambiente de teste (VM/localhost/rede controlada).\n")

    ip = input("Target IP [127.0.0.1]: ").strip() or "127.0.0.1"

    try:
        port = int(input("Target port [9999]: ").strip() or "9999")
        max_packets = int(input("Número de pacotes [1000]: ").strip() or "1000")
        packet_size = int(input("Tamanho do pacote (bytes) [1024]: ").strip() or "1024")
        delay_s = float(input("Delay entre pacotes (s) [0.01]: ").strip() or "0.01")
    except ValueError:
        print("[!] Valores inválidos.")
        pause()
        return

    cfg = UdpFloodConfig(
        target_ip=ip,
        target_port=port,
        packet_size=packet_size,
        max_packets=max_packets,
        delay_s=delay_s,
    )

    print("\nA enviar pacotes UDP... (CTRL+C para parar)\n")
    sent, elapsed = udp_flood_simulation(cfg)

    if elapsed <= 0:
        elapsed = 0.000001

    print(f"Pacotes enviados: {sent}")
    print(f"Tempo total: {elapsed:.2f}s")
    print(f"Taxa média: {sent/elapsed:.2f} pacotes/segundo")
    pause()


def handle_log_analysis() -> None:
    clear_screen()
    print("== Log Analysis ==")
    print("TODO: implementar análise de logs (ssh + http), geoip, CSV/PDF")
    pause()


def handle_secure_messaging() -> None:
    clear_screen()
    print("== Secure Messaging ==")
    print("TODO: implementar cliente/servidor + encriptação")
    pause()


def handle_port_knocking() -> None:
    clear_screen()
    print("== Port Knocking ==")
    print("TODO: implementar sequência de knocks + testes SSH")
    pause()


def handle_password_manager() -> None:
    clear_screen()
    print("== Password Manager ==")
    print("TODO: implementar CRUD + encriptação assimétrica + 2FA (pyotp)")
    pause()


def handle_about() -> None:
    clear_screen()
    print("LPD Security Tool")
    print("- CLI base para o projeto de Segurança Informática")
    print("- Python, outputs: CSV / SQLite / PDF")
    pause()


# -------------------------
# Main Menu
# -------------------------

def main_menu() -> None:
    options: Dict[str, MenuOption] = {
        "1": MenuOption("1", "Port scanner (detetar/listar portos)", handle_port_scan),
        "2": MenuOption("2", "UDP flood (simulação controlada)", handle_udp_flood),
        "3": MenuOption("3", "SYN flood (simulação controlada)", handle_syn_flood),
        "4": MenuOption("4", "Análise de logs (http/ssh)", handle_log_analysis),
        "5": MenuOption("5", "Mensagens seguras (cliente/servidor)", handle_secure_messaging),
        "6": MenuOption("6", "Port knocking (SSH)", handle_port_knocking),
        "7": MenuOption("7", "Password manager (2FA)", handle_password_manager),
        "9": MenuOption("9", "Sobre / Ajuda", handle_about),
        "0": MenuOption("0", "Sair", lambda: sys.exit(0)),
    }

    while True:
        clear_screen()
        print_menu("LPD Security Tool - Menu Principal", options)
        choice = read_choice("Escolha uma opção: ", set(options.keys()))
        options[choice].action()


def main(argv: Optional[list[str]] = None) -> int:
    _ = argv or sys.argv[1:]
    try:
        main_menu()
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0
    except KeyboardInterrupt:
        print("\n[!] Interrompido. A sair.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
