#!/usr/bin/env python3
"""
LPD Security Tool - CLI Skeleton
- Input validation
- Handlers for each feature
"""

from __future__ import annotations

from core.csv_utils import write_open_ports_csv, write_log_events_csv
from modules.udp_flood import UdpFloodConfig, udp_flood_simulation
from core.geoip_utils import GeoIpResolver
from modules.syn_flood import SynFloodConfig, syn_flood_simulation
from pathlib import Path

from modules.port_scanner import (
    expand_targets,
    validate_host,
    parse_ports,
    tcp_scan_simple,
    tcp_scan_threaded,
)
from modules.log_analysis import (
    parse_auth_log_ssh,
    parse_ufw_log,
    summarize,
)
from core.geoip_utils import GeoIpResolver
from core.csv_utils import write_log_events_csv

from modules.messaging import MessagingServer, MessagingClient

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
    print("== Análise de Logs (auth.log + ufw.log) ==")
    print("Extrai: IP origem, país, timestamps e detalhes (SSH + UFW).\n")

    auth_path = input("Caminho auth.log [/var/log/auth.log]: ").strip() or "/var/log/auth.log"
    ufw_path = input("Caminho syslog (UFW + remotos) [/var/log/syslog]: ").strip() or "/var/log/syslog"
    mmdb_path = Path("data/GeoLite2-Country.mmdb")
    if mmdb_path.exists():
        mmdb = str(mmdb_path)
        print(f"[i] GeoIP ativo: {mmdb}")
    else:
        mmdb = None
        print("[!] GeoIP não encontrado (data/GeoLite2-Country.mmdb). País será omitido.")

    save = (input("Guardar eventos em CSV? [s/N]: ").strip().lower() or "n") == "s"

    started_at = datetime.now()
    geo = GeoIpResolver(mmdb)

    try:
        events = []
        events += parse_auth_log_ssh(auth_path, geo)
        events += parse_ufw_log(ufw_path, geo)
    finally:
        geo.close()

    finished_at = datetime.now()

    if not events:
        print("\nSem eventos (ou ficheiros não encontrados / sem permissões).")
        print("Dica: para ler /var/log/* pode ser preciso: sudo -E .venv/bin/python main.py")
        pause()
        return

    events.sort(key=lambda e: e.timestamp)
    s = summarize(events)

    print(f"\nTotal de eventos: {s.total_events}")

    print("\nTop países (ISO):")
    for c, n in s.by_country:
        print(f" - {c}: {n}")

    print("\nTop IPs origem:")
    for ip, n in s.by_ip:
        print(f" - {ip}: {n}")

    print("\nPrimeiros 25 eventos:")
    for e in events[:25]:
        country = e.country_iso or "??"
        print(f"[{e.timestamp}] {e.service} {e.action} ip={e.ip} country={country} {e.detail}")

    if save:
        fname = f"logs_{started_at.strftime('%Y%m%d_%H%M%S')}.csv"
        out_path = f"reports/{fname}"
        try:
            p = write_log_events_csv(out_path, started_at, finished_at, events)
            print(f"\n[+] CSV guardado em: {p}")
        except OSError as ex:
            print(f"\n[!] Erro a escrever CSV: {ex}")

    pause()

def handle_secure_messaging() -> None:
    

    clear_screen()
    print("== Secure Messaging ==")
    print("1) Iniciar servidor")
    print("2) Iniciar cliente")
    print("0) Voltar")
    choice = input("> ").strip()

    if choice == "1":
        host = input("Host [127.0.0.1]: ").strip() or "127.0.0.1"
        port_str = input("Porta [5000]: ").strip() or "5000"
        data_dir = input("Diretório dados servidor [server_data]: ").strip() or "server_data"
        try:
            port = int(port_str)
        except ValueError:
            print("Porta inválida.")
            pause()
            return

        server = MessagingServer(host=host, port=port, data_dir=data_dir)
        server.start()
        print(f"\nServidor a correr em {host}:{port}")
        print("ENTER para parar o servidor...")
        input()
        server.stop()
        print("Servidor parado.")
        pause()
        return

    if choice == "2":
        host = input("Host do servidor [127.0.0.1]: ").strip() or "127.0.0.1"
        port_str = input("Porta do servidor [5000]: ").strip() or "5000"
        user_id = input("O teu userId (ex: alice): ").strip()
        key_dir = input("Diretório chaves cliente [client_keys]: ").strip() or "client_keys"
        if not user_id:
            print("userId é obrigatório.")
            pause()
            return
        try:
            port = int(port_str)
        except ValueError:
            print("Porta inválida.")
            pause()
            return

        client = MessagingClient(user_id=user_id, host=host, port=port, key_dir=key_dir)

        try:
            client.connect()
            # tenta registar automaticamente (idempotente)
            client.register()
        except Exception as e:
            print(f"Falha a ligar/registar: {e}")
            pause()
            return

        while True:
            clear_screen()
            print(f"== Secure Messaging (cliente: {user_id}) ==")
            print("1) Enviar mensagem")
            print("2) Listar mensagens (em que sou interveniente)")
            print("3) Download mensagens (por msgId)")
            print("4) Apagar mensagens (por msgId)")
            print("5) Export/Backup (encriptado para mim)")
            print("6) Ver/desencriptar ficheiro de mensagem (local)")
            print("7) Ver/desencriptar backup exportado (local)")
            print("0) Sair")
            op = input("> ").strip()

            try:
                if op == "1":
                    to = input("Para (userId): ").strip()
                    body = input("Mensagem: ").strip()
                    res = client.send_message(to=to, body=body)
                    print(f"OK. msgId={res.get('msgId')}")
                    pause()

                elif op == "2":
                    with_user = input("Filtrar por userId (enter=sem filtro): ").strip() or None
                    msgs = client.list_messages(with_user=with_user)
                    print("\nMensagens:")
                    for m in msgs:
                        print(f"- {m['msgId']} | {m['timestamp']} | {m['from']} -> {m['to']} | {m['size']} bytes")
                    pause()

                elif op == "3":
                    ids = input("msgIds separados por vírgula: ").strip()
                    msg_ids = [x.strip() for x in ids.split(",") if x.strip()]
                    out_dir = input("Guardar em diretório [downloads]: ").strip() or "downloads"
                    saved = client.download_messages(msg_ids=msg_ids, out_dir=out_dir)
                    print("\nGuardados:")
                    for p in saved:
                        print(f"- {p}")
                    pause()

                elif op == "4":
                    ids = input("msgIds separados por vírgula: ").strip()
                    msg_ids = [x.strip() for x in ids.split(",") if x.strip()]
                    client.delete_messages(msg_ids=msg_ids)
                    print("OK. Removido(s).")
                    pause()

                elif op == "5":
                    out_file = input("Ficheiro backup [backup.enc]: ").strip() or "backup.enc"
                    client.export_messages(out_file=out_file)
                    print(f"OK. Backup guardado em: {out_file}")
                    pause()

                elif op == "6":
                    path = input("Caminho do ficheiro msg_*.json: ").strip()
                    plain = client.decrypt_archived_message_file(path)
                    print("\n--- Mensagem desencriptada ---")
                    print(plain)
                    print("------------------------------")
                    pause()

                elif op == "7":
                    path = input("Caminho do backup *.enc: ").strip()
                    plain = client.decrypt_backup_file(path)
                    print("\n--- Backup desencriptado (texto) ---")
                    print(plain[:5000] + ("\n...(truncado)" if len(plain) > 5000 else ""))
                    print("------------------------------------")
                    pause()

                elif op == "0":
                    client.close()
                    return

            except Exception as e:
                print(f"Erro: {e}")
                pause()
        return

    # voltar
    return


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
