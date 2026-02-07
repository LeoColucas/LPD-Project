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
from modules.password_manager import PasswordManager, PasswordManagerError
from core.models import Finding

from core.db import init_db, insert_findings, stats_by_severity
from core.findings_csv import write_findings_csv
from core.pdf_report import write_pdf_report

RUN_FINDINGS: list[Finding] = []

def add_findings(items: list[Finding]) -> None:
    RUN_FINDINGS.extend(items)

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
from modules.port_knocking import knock_then_test_ssh



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
        targets = [validate_host(t) for t in targets]
        ports = parse_ports(ports_spec)
    except ValueError as e:
        print(f"[!] Erro: {e}")
        pause()
        return

    mode = input("Modo [1=aula/seq, 2=rápido/threads] (default 2): ").strip() or "2"

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

        # -------------------------
        # Findings (NOVO)
        # -------------------------
        findings: list[Finding] = []

        if not results:
            print("Nenhum porto aberto encontrado (ou filtrado por firewall).")
            print(f"Tempo total: {elapsed}")

            findings.append(Finding(
                timestamp=finished_at,
                category="PORTSCAN",
                severity="LOW",
                title="Scan sem portos abertos",
                details=f"elapsed={elapsed} timeout={timeout} mode={mode}",
                target=host,
                ip=resolved_ip or None,
                source="modules/port_scanner.py",
            ))

            add_findings(findings)

            pause("Enter para próximo host...")
            continue

        print("Portos abertos:")
        for r in results:
            svc = f" ({r.service})" if r.service else ""
            print(f" - {r.port}{svc}")
        print(f"Tempo total: {elapsed}")

        # 1 finding por porto aberto
        risky_ports = {22, 23, 21, 3389, 445, 5900, 3306, 5432}
        for r in results:
            sev = "MEDIUM" if r.port in risky_ports else "LOW"
            findings.append(Finding(
                timestamp=finished_at,
                category="PORTSCAN",
                severity=sev,
                title=f"Porto aberto: {r.port}",
                details=f"service={r.service or 'unknown'} elapsed={elapsed} timeout={timeout} mode={mode}",
                target=host,
                ip=resolved_ip or None,
                source="modules/port_scanner.py",
            ))

        add_findings(findings)

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

        print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
        pause("Enter para próximo host...")

def handle_syn_flood() -> None:
    clear_screen()
    print("== TCP SYN Flood (Simulação Controlada) ==")
    print("⚠️ Usar apenas em ambiente de teste (localhost / VM).\n")

    ip = input("Target IP [127.0.0.1]: ").strip() or "127.0.0.1"

    try:
        port = int(input("Target port (ex: 80/25) [80]: ").strip() or "80")
        packets = int(input("Número de SYN packets [100]: ").strip() or "100")
        delay = float(input("Delay entre pacotes (s) [0.05]: ").strip() or "0.05")
    except ValueError:
        print("[!] Valores inválidos.")
        pause()
        return

    cfg = SynFloodConfig(
        target_ip=ip,
        target_port=port,
        max_packets=packets,
        delay_s=delay,
    )

    print("\nA enviar pacotes SYN...\n")
    sent, elapsed = syn_flood_simulation(cfg)

    if elapsed <= 0:
        elapsed = 0.000001

    rate = sent / elapsed

    print(f"SYN enviados: {sent}")
    print(f"Tempo total: {elapsed:.2f}s")
    print(f"Taxa média: {rate:.2f} SYN/s")

    # -------------------------
    # Findings (NOVO)
    # -------------------------
    findings: list[Finding] = []
    findings.append(Finding(
        timestamp=datetime.now(),
        category="SYN",
        severity="LOW",  # simulação em lab
        title="SYN flood (simulação) executada",
        details=(
            f"target={ip}:{port} sent={sent} elapsed={elapsed:.2f}s "
            f"rate={rate:.2f}/s delay={delay} max_packets={packets}"
        ),
        target=ip,
        ip=ip,
        source="modules/syn_flood.py",
    ))

    add_findings(findings)
    print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")

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

    rate = sent / elapsed

    print(f"Pacotes enviados: {sent}")
    print(f"Tempo total: {elapsed:.2f}s")
    print(f"Taxa média: {rate:.2f} pacotes/segundo")

    # -------------------------
    # Findings (NOVO)
    # -------------------------
    findings: list[Finding] = []
    findings.append(Finding(
        timestamp=datetime.now(),
        category="UDP",
        severity="LOW",  # simulação em lab
        title="UDP flood (simulação) executada",
        details=(
            f"target={ip}:{port} sent={sent} elapsed={elapsed:.2f}s "
            f"rate={rate:.2f}/s size={packet_size}B delay={delay_s} max_packets={max_packets}"
        ),
        target=ip,
        ip=ip,
        source="modules/udp_flood.py",
    ))

    add_findings(findings)
    print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")

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

    # -------------------------
    # Findings (NOVO)
    # -------------------------
    findings: list[Finding] = []

    top_ip = s.by_ip[0][0] if s.by_ip else "-"
    top_country = s.by_country[0][0] if s.by_country else "-"
    duration_s = (finished_at - started_at).total_seconds()

    findings.append(Finding(
        timestamp=finished_at,
        category="LOG",
        severity="LOW",
        title="Resumo de análise de logs",
        details=(
            f"total_events={s.total_events} top_ip={top_ip} top_country={top_country} "
            f"duration={duration_s:.2f}s auth_path={auth_path} ufw_path={ufw_path} geoip={'on' if mmdb else 'off'}"
        ),
        target="localhost",
        source="modules/log_analysis.py",
    ))

    # Limite para não explodir SQLite/PDF se os logs forem enormes
    max_findings = 500

    for e in events[:max_findings]:
        # Heurística simples de severidade
        action = (str(e.action) if e.action is not None else "").lower()
        detail = (str(e.detail) if e.detail is not None else "").lower()

        if any(k in action for k in ("deny", "blocked")):
            sev = "MEDIUM"
        elif any(k in detail for k in ("failed password", "authentication failure", "invalid user", "bad password")):
            sev = "MEDIUM"
        else:
            sev = "LOW"

        country = e.country_iso or "??"

        findings.append(Finding(
            timestamp=e.timestamp,
            category="LOG",
            severity=sev,
            title=f"{e.service} {e.action}",
            details=f"ip={e.ip} country={country} {e.detail}",
            target="localhost",
            ip=e.ip,
            source="modules/log_analysis.py",
        ))

    # Se houve truncagem, regista isso no resumo (útil para o relatório)
    if len(events) > max_findings:
        findings.append(Finding(
            timestamp=finished_at,
            category="LOG",
            severity="LOW",
            title="Eventos truncados para relatório",
            details=f"events_total={len(events)} exported_findings={max_findings} (limite aplicado)",
            target="localhost",
            source="modules/log_analysis.py",
        ))

    add_findings(findings)
    print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")

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

        started_at = datetime.now()
        server.start()

        # Finding: servidor iniciado
        add_findings([Finding(
            timestamp=started_at,
            category="MSG",
            severity="LOW",
            title="Servidor de mensagens iniciado",
            details=f"host={host} port={port} data_dir={data_dir}",
            target=f"{host}:{port}",
            source="modules/messaging.py",
        )])

        print(f"\nServidor a correr em {host}:{port}")
        print("ENTER para parar o servidor...")
        input()

        stopped_at = datetime.now()
        server.stop()

        # Finding: servidor parado
        add_findings([Finding(
            timestamp=stopped_at,
            category="MSG",
            severity="LOW",
            title="Servidor de mensagens parado",
            details=f"host={host} port={port} uptime={(stopped_at-started_at).total_seconds():.2f}s",
            target=f"{host}:{port}",
            source="modules/messaging.py",
        )])

        print("Servidor parado.")
        print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
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
            t0 = datetime.now()
            client.connect()
            client.register()

            # Finding: cliente ligado + registado
            add_findings([Finding(
                timestamp=t0,
                category="MSG",
                severity="LOW",
                title="Cliente ligado e registado",
                details=f"user={user_id} server={host}:{port} key_dir={key_dir}",
                target=f"{host}:{port}",
                user=user_id,
                source="modules/messaging.py",
            )])

        except Exception as e:
            add_findings([Finding(
                timestamp=datetime.now(),
                category="MSG",
                severity="MEDIUM",
                title="Falha a ligar/registar cliente",
                details=f"user={user_id} server={host}:{port} error={e}",
                target=f"{host}:{port}",
                user=user_id,
                source="modules/messaging.py",
            )])
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
                    msg_id = res.get("msgId", "-")

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Mensagem enviada",
                        details=f"from={user_id} to={to} msgId={msg_id} size={len(body)}",
                        target=f"{host}:{port}",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print(f"OK. msgId={msg_id}")
                    pause()

                elif op == "2":
                    with_user = input("Filtrar por userId (enter=sem filtro): ").strip() or None
                    msgs = client.list_messages(with_user=with_user)

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Mensagens listadas",
                        details=f"user={user_id} filter={with_user or '-'} count={len(msgs)}",
                        target=f"{host}:{port}",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print("\nMensagens:")
                    for m in msgs:
                        print(f"- {m['msgId']} | {m['timestamp']} | {m['from']} -> {m['to']} | {m['size']} bytes")
                    pause()

                elif op == "3":
                    ids = input("msgIds separados por vírgula: ").strip()
                    msg_ids = [x.strip() for x in ids.split(",") if x.strip()]
                    out_dir = input("Guardar em diretório [downloads]: ").strip() or "downloads"
                    saved = client.download_messages(msg_ids=msg_ids, out_dir=out_dir)

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Mensagens descarregadas",
                        details=f"user={user_id} requested={len(msg_ids)} saved={len(saved)} out_dir={out_dir}",
                        target=f"{host}:{port}",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print("\nGuardados:")
                    for p in saved:
                        print(f"- {p}")
                    pause()

                elif op == "4":
                    ids = input("msgIds separados por vírgula: ").strip()
                    msg_ids = [x.strip() for x in ids.split(",") if x.strip()]
                    client.delete_messages(msg_ids=msg_ids)

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Mensagens apagadas",
                        details=f"user={user_id} msgIds={msg_ids}",
                        target=f"{host}:{port}",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print("OK. Removido(s).")
                    pause()

                elif op == "5":
                    out_file = input("Ficheiro backup [backup.enc]: ").strip() or "backup.enc"
                    client.export_messages(out_file=out_file)

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Backup exportado (encriptado)",
                        details=f"user={user_id} out_file={out_file}",
                        target=f"{host}:{port}",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print(f"OK. Backup guardado em: {out_file}")
                    pause()

                elif op == "6":
                    path = input("Caminho do ficheiro msg_*.json: ").strip()
                    plain = client.decrypt_archived_message_file(path)

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Mensagem local desencriptada",
                        details=f"user={user_id} path={path} plain_len={len(plain)}",
                        target="local",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print("\n--- Mensagem desencriptada ---")
                    print(plain)
                    print("------------------------------")
                    pause()

                elif op == "7":
                    path = input("Caminho do backup *.enc: ").strip()
                    plain = client.decrypt_backup_file(path)

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Backup local desencriptado",
                        details=f"user={user_id} path={path} plain_len={len(plain)}",
                        target="local",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print("\n--- Backup desencriptado (texto) ---")
                    print(plain[:5000] + ("\n...(truncado)" if len(plain) > 5000 else ""))
                    print("------------------------------------")
                    pause()

                elif op == "0":
                    client.close()

                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="MSG",
                        severity="LOW",
                        title="Cliente fechado",
                        details=f"user={user_id} server={host}:{port}",
                        target=f"{host}:{port}",
                        user=user_id,
                        source="modules/messaging.py",
                    )])

                    print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                    return

            except Exception as e:
                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="MSG",
                    severity="MEDIUM",
                    title="Erro na operação de messaging",
                    details=f"user={user_id} op={op} error={e}",
                    target=f"{host}:{port}",
                    user=user_id,
                    source="modules/messaging.py",
                )])
                print(f"Erro: {e}")
                pause()

        return

    # voltar
    return

def _parse_ports(s: str) -> list[int]:
    raw = s.replace(",", " ").split()
    ports: list[int] = []
    for x in raw:
        p = int(x)
        if not (1 <= p <= 65535):
            raise ValueError(f"Porta inválida: {p}")
        ports.append(p)
    if not ports:
        raise ValueError("Sequência vazia.")
    return ports


def handle_port_knocking() -> None:
    clear_screen()
    print("== Port Knocking ==")

    default_host = "192.168.56.102"
    default_seq = "7000,8000,9000"

    host = input(f"Servidor (default {default_host}): ").strip() or default_host
    seq_str = input(f"Sequência (default {default_seq}): ").strip() or default_seq

    try:
        ports = _parse_ports(seq_str)
    except ValueError as e:
        print(f"Erro: {e}")

        # Finding: input inválido
        add_findings([Finding(
            timestamp=datetime.now(),
            category="KNOCK",
            severity="LOW",
            title="Port knocking: sequência inválida",
            details=f"host={host} seq={seq_str!r} error={e}",
            target=host,
            ip=host,
            source="modules/port_knocking.py",
        )])

        print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
        pause()
        return

    report = knock_then_test_ssh(
        host=host,
        knock_ports=ports,
        ssh_port=22,
        delay_s=0.3,
        timeout_s=1.0,
        wait_after_s=0.5,
    )

    print("\n--- Resultado ---")
    print(f"Host: {report.host}")
    print(f"Sequência: {report.knock_ports}")
    print(f"Knocks (connect ok por porta): {report.per_port_result}")
    print(f"Teste SSH ({report.ssh_port}): {'ABERTO' if report.ssh_open else 'FECHADO'}")

    if report.ssh_open:
        print("✅ SSH acessível (temporariamente).")
        print(f"Ex: ssh <user>@{report.host}")
    else:
        print("❌ SSH ainda fechado. Verifica knockd, iptables e interface.")

    # -------------------------
    # Findings (NOVO)
    # -------------------------
    sev = "LOW" if report.ssh_open else "MEDIUM"

    add_findings([Finding(
        timestamp=datetime.now(),
        category="KNOCK",
        severity=sev,
        title="Port knocking executado",
        details=(
            f"host={report.host} seq={report.knock_ports} "
            f"per_port={report.per_port_result} ssh_port={report.ssh_port} ssh_open={report.ssh_open}"
        ),
        target=report.host,
        ip=report.host,
        source="modules/port_knocking.py",
    )])

    print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
    pause()

def handle_password_manager() -> None:
    clear_screen()
    print("== Password Manager ==")

    try:
        pm = PasswordManager()
        add_findings([Finding(
            timestamp=datetime.now(),
            category="PWD",
            severity="LOW",
            title="PasswordManager inicializado",
            details="init_ok",
            source="modules/password_manager.py",
        )])
    except Exception as e:
        print(f"[!] Falha a inicializar PasswordManager: {e}")
        add_findings([Finding(
            timestamp=datetime.now(),
            category="PWD",
            severity="MEDIUM",
            title="Falha ao inicializar PasswordManager",
            details=f"error={e}",
            source="modules/password_manager.py",
        )])
        pause()
        return

    while True:
        clear_screen()
        print("== Password Manager ==")
        print("1) Criar registo")
        print("2) Atualizar registo")
        print("3) Apagar registo")
        print("4) Consultar registo (2FA)")
        print("5) Listar registos (sem passwords)")
        print("8) Mostrar info 2FA (secret/uri)")
        print("0) Voltar")
        op = input("> ").strip()

        try:
            if op == "1":
                url = input("URL: ").strip()
                user = input("User: ").strip()
                pwd = input("Password: ").strip()
                if not url or not user or not pwd:
                    print("[!] URL/User/Password são obrigatórios.")
                    pause()
                    continue

                pm.create_record(url=url, user=user, password=pwd)
                print("[+] Registo criado.")

                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="MEDIUM",
                    title="Registo criado",
                    details=f"url={url} user={user}",
                    target=url,
                    user=user,
                    source="modules/password_manager.py",
                )])

                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                pause()

            elif op == "2":
                url = input("URL a atualizar: ").strip()
                if not url:
                    print("[!] URL é obrigatório.")
                    pause()
                    continue
                user = input("User (opcional p/ desambiguar): ").strip() or None
                new_user = input("Novo user (Enter mantém): ").strip() or None
                new_pwd = input("Nova password (Enter mantém): ").strip() or None
                if not new_user and not new_pwd:
                    print("[i] Nada para atualizar.")
                    pause()
                    continue

                pm.update_record(url=url, user=user, new_user=new_user, new_password=new_pwd)
                print("[+] Registo atualizado.")

                # Nunca guardar password no finding: só flags do que mudou
                changed = []
                if new_user:
                    changed.append("user")
                if new_pwd:
                    changed.append("password")
                changed_str = ",".join(changed) if changed else "-"

                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="MEDIUM",
                    title="Registo atualizado",
                    details=f"url={url} user_filter={user or '-'} changed={changed_str}",
                    target=url,
                    user=user or new_user or None,
                    source="modules/password_manager.py",
                )])

                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                pause()

            elif op == "3":
                url = input("URL a apagar: ").strip()
                if not url:
                    print("[!] URL é obrigatório.")
                    pause()
                    continue
                user = input("User (opcional p/ desambiguar): ").strip() or None
                c = input("Confirmar apagar? (s/N): ").strip().lower() or "n"
                if c != "s":
                    print("[i] Cancelado.")
                    pause()
                    continue

                pm.delete_record(url=url, user=user)
                print("[+] Registo apagado.")

                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="MEDIUM",
                    title="Registo apagado",
                    details=f"url={url} user_filter={user or '-'}",
                    target=url,
                    user=user,
                    source="modules/password_manager.py",
                )])

                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                pause()

            elif op == "4":
                url = input("URL a consultar: ").strip()
                if not url:
                    print("[!] URL é obrigatório.")
                    pause()
                    continue
                user = input("User (opcional p/ desambiguar): ").strip() or None
                code = input("Código 2FA (6 dígitos): ").strip()

                res = pm.consult_password(url=url, user=user, totp_code=code)

                print("\n--- Resultado ---")
                print(f"URL:  {res['url']}")
                print(f"User: {res['user']}")
                print(f"Pass: {res['pass']}")
                pause()

                # Finding: consulta OK (NÃO guardar pass)
                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="MEDIUM",
                    title="Password consultada (2FA validado)",
                    details=f"url={res['url']} user={res['user']}",
                    target=res["url"],
                    user=res["user"],
                    source="modules/password_manager.py",
                )])

                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                pause()

            elif op == "5":
                recs = pm.list_records()
                if not recs:
                    print("Sem registos.")
                    add_findings([Finding(
                        timestamp=datetime.now(),
                        category="PWD",
                        severity="LOW",
                        title="Listagem de registos (vazia)",
                        details="count=0",
                        source="modules/password_manager.py",
                    )])
                    print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                    pause()
                    continue

                print("\n== Registos ==")
                for r in recs:
                    print(f"- URL: {r['url']} | user: {r['user']}")

                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="LOW",
                    title="Listagem de registos",
                    details=f"count={len(recs)}",
                    source="modules/password_manager.py",
                )])

                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                pause()

            elif op == "8":
                info = pm.get_totp_setup_info()

                print("\n=== 2FA info ===")
                print("SECRET (coloca no Authenticator):")
                print(info["secret"])
                print("\nURI (se a app aceitar):")
                print(info["uri"])
                pause()

                # Finding: 2FA info mostrado (NÃO guardar secret/uri)
                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="LOW",
                    title="Info 2FA mostrada ao utilizador",
                    details="shown_totp_setup_info=true",
                    source="modules/password_manager.py",
                )])

                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                pause()

            elif op == "0":
                add_findings([Finding(
                    timestamp=datetime.now(),
                    category="PWD",
                    severity="LOW",
                    title="PasswordManager: sair do menu",
                    details="exit_menu",
                    source="modules/password_manager.py",
                )])
                print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
                return

            else:
                print("[!] Opção inválida.")
                pause()

        except PasswordManagerError as e:
            print(f"[!] {e}")

            add_findings([Finding(
                timestamp=datetime.now(),
                category="PWD",
                severity="MEDIUM",
                title="Erro PasswordManager",
                details=f"op={op} error={e}",
                source="modules/password_manager.py",
            )])

            print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
            pause()

        except Exception as e:
            print(f"[!] Erro inesperado: {e}")

            add_findings([Finding(
                timestamp=datetime.now(),
                category="PWD",
                severity="MEDIUM",
                title="Erro inesperado PasswordManager",
                details=f"op={op} error={e}",
                source="modules/password_manager.py",
            )])

            print(f"[i] Findings acumulados nesta execução: {len(RUN_FINDINGS)}")
            pause()


def handle_reports() -> None:
    from pathlib import Path
    Path("reports").mkdir(exist_ok=True)

    if not RUN_FINDINGS:
        print("[!] Não há findings nesta execução ainda. Corre um módulo primeiro.")
        pause()
        return

    # 1) SQLite
    con = init_db("reports/lpd.sqlite")
    insert_findings(con, RUN_FINDINGS)
    sev = stats_by_severity(con)
    con.close()
    print("[+] Guardado em SQLite: reports/lpd.sqlite")

    # 2) CSV (lista completa)
    csv_path = write_findings_csv("reports/findings_last_run.csv", RUN_FINDINGS)
    print(f"[+] CSV: {csv_path}")

    # 3) PDF
    pdf_path = write_pdf_report(
        "reports/report_last_run.pdf",
        RUN_FINDINGS,
        sev,
        meta={"scope": "última execução (RUN_FINDINGS)"}
    )
    print(f"[+] PDF: {pdf_path}")

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
        "8": MenuOption("8", "Relatórios (SQLite + CSV + PDF)", handle_reports),
        "9": MenuOption("9", "Sobre / Ajuda", handle_about),
        "0": MenuOption("0", "Sair", lambda: sys.exit(0)),
    }

    while True:
        clear_screen()
        print_menu("LPD Security Tool - Menu Principal", options)
        choice = read_choice("Escolha uma opção: ", set(options.keys()))
        options[choice].action()

def handle_about() -> None:
    clear_screen()
    print("LPD Security Tool")
    print("=" * 40)
    print("Projeto de Segurança Informática (LPD)")
    print()
    print("Funcionalidades:")
    print("- Port scanner TCP (sequencial e threaded)")
    print("- Análise de logs (auth.log / UFW / GeoIP)")
    print("- Simulação de ataques (SYN flood, UDP flood)")
    print("- Port knocking (SSH)")
    print("- Sistema de mensagens seguras (cliente/servidor)")
    print("- Password manager com 2FA (TOTP)")
    print()
    print("Relatórios e persistência:")
    print("- Findings normalizados por severidade")
    print("- Exportação CSV")
    print("- Base de dados SQLite")
    print("- Relatório PDF automático")
    print()
    print("Arquitetura:")
    print("- CLI desacoplada dos módulos")
    print("- Módulos independentes (core / modules)")
    print("- Findings acumulados por execução")
    print()
    print("Estado da execução atual:")
    print(f"- Findings acumulados: {len(RUN_FINDINGS)}")
    print()
    print("Nota:")
    print("Esta ferramenta destina-se apenas a ambientes controlados")
    print("(laboratório, VMs, localhost).")
    print("Autoria de Leonardo Colucas")
    print()
    pause("Enter para voltar ao menu...")


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
