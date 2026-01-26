from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, List, Dict, Tuple

from core.geoip_utils import GeoIpResolver

UFW_PREFIX_RE = re.compile(r"\[UFW (?P<action>BLOCK|ALLOW)\]\s*(?P<rest>.*)")

# apanha pares chave=valor típicos do kernel/ufw (IN= OUT= SRC= DST= PROTO= SPT= DPT= ...)
UFW_KV_RE = re.compile(r"(?P<k>[A-Z]+)=(?P<v>\S+)")

@dataclass(frozen=True)
class LogEvent:
    service: str
    timestamp: datetime
    hostname: str       
    ip: str
    action: str
    detail: str
    country_name: str = ""
    country_iso: str = ""



# -------------------------
# Helpers timestamp syslog
# -------------------------
def _parse_syslog_ts(prefix_15: str, year: int) -> Optional[datetime]:
    # ex: "Feb 25 10:55:03"
    try:
        return datetime.strptime(f"{year} {prefix_15}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    
def split_syslog_line(line: str, year: int) -> Optional[tuple[datetime, str, str]]:
    # Ex: "Feb 22 16:41:02 kali sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    parts = line.split()
    if len(parts) < 5:
        return None

    month, day, hms = parts[0], parts[1], parts[2]
    hostname = parts[3]

    ts = _parse_syslog_ts(f"{month} {day} {hms}", year)
    if not ts:
        return None

    msg = " ".join(parts[4:])
    return ts, hostname, msg

# -------------------------
# SSH (auth.log)
# -------------------------
SSH_FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)(?: port (?P<port>\d+))?"
)
SSH_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)(?: port (?P<port>\d+))?"
)
SSH_INVALID_USER_RE = re.compile(
    r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def parse_auth_log_ssh(
    path: str | Path,
    geo: GeoIpResolver,
    year: Optional[int] = None
) -> List[LogEvent]:

    p = Path(path)
    if not p.exists():
        return []

    year = year or datetime.now().year
    events: List[LogEvent] = []

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            row = split_syslog_line(line, year)
            if not row:
                continue

            ts, hostname, msg = row

            # Failed password
            m = SSH_FAILED_RE.search(msg)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                port = m.group("port") or ""
                g = geo.lookup(ip)

                events.append(LogEvent(
                    service="ssh",
                    timestamp=ts,
                    hostname=hostname,
                    ip=ip,
                    action="failed_login",
                    detail=f"user={user} src_port={port}".strip(),
                    country_name=g.country_name,
                    country_iso=g.country_iso,
                ))
                continue

            # Accepted login
            m = SSH_ACCEPTED_RE.search(msg)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                port = m.group("port") or ""
                g = geo.lookup(ip)

                events.append(LogEvent(
                    service="ssh",
                    timestamp=ts,
                    hostname=hostname,
                    ip=ip,
                    action="accepted_login",
                    detail=f"user={user} src_port={port}".strip(),
                    country_name=g.country_name,
                    country_iso=g.country_iso,
                ))
                continue

            # Invalid user
            m = SSH_INVALID_USER_RE.search(msg)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                g = geo.lookup(ip)

                events.append(LogEvent(
                    service="ssh",
                    timestamp=ts,
                    hostname=hostname,
                    ip=ip,
                    action="invalid_user",
                    detail=f"user={user}",
                    country_name=g.country_name,
                    country_iso=g.country_iso,
                ))

    return events
# -------------------------
# UFW (ufw.log)
# -------------------------
# Ex real: "... [UFW BLOCK] ... SRC=220.181.108.106 DST=193.137.135.82 ... PROTO=TCP SPT=38455 DPT=80 ..."
UFW_RE = re.compile(
    r"\[UFW (?P<action>BLOCK|ALLOW)\].*?\bIN=(?P<in>\S+)\b.*?\bSRC=(?P<src>\d+\.\d+\.\d+\.\d+)\b.*?\bDST=(?P<dst>\d+\.\d+\.\d+\.\d+)\b.*?\bPROTO=(?P<proto>\S+)\b(?:.*?\bSPT=(?P<spt>\d+)\b)?(?:.*?\bDPT=(?P<dpt>\d+)\b)?"
)
def _ufw_extract_fields(rest: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for m in UFW_KV_RE.finditer(rest):
        fields[m.group("k")] = m.group("v")
    return fields

def parse_ufw_log(
    path: str | Path,
    geo: GeoIpResolver,
    year: Optional[int] = None
) -> List[LogEvent]:
    """
    Lê syslog (ou ufw.log se existir) e extrai eventos UFW:
      - action: ufw_block / ufw_allow
      - ip: SRC=
      - detail: IN= OUT= DST= PROTO= SPT= DPT= ...
      - hostname: origem (muito útil para logs remotos)
    """
    p = Path(path)
    if not p.exists():
        return []

    year = year or datetime.now().year
    events: List[LogEvent] = []

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            row = split_syslog_line(line, year)
            if not row:
                continue

            ts, hostname, msg = row

            m = UFW_PREFIX_RE.search(msg)
            if not m:
                continue

            act = m.group("action")  # BLOCK ou ALLOW
            rest = m.group("rest")

            fields = _ufw_extract_fields(rest)

            src = fields.get("SRC")
            if not src:
                # sem SRC não dá para geolocalizar nem contar IPs
                continue

            dst = fields.get("DST", "")
            proto = fields.get("PROTO", "")
            spt = fields.get("SPT", "")
            dpt = fields.get("DPT", "")
            iface_in = fields.get("IN", "")
            iface_out = fields.get("OUT", "")

            g = geo.lookup(src)

            action = "ufw_block" if act == "BLOCK" else "ufw_allow"
            detail = f"in={iface_in} out={iface_out} dst={dst} proto={proto} spt={spt} dpt={dpt}".strip()

            events.append(LogEvent(
                service="ufw",
                timestamp=ts,
                hostname=hostname,
                ip=src,
                action=action,
                detail=detail,
                country_name=g.country_name,
                country_iso=g.country_iso,
            ))

    return events


# -------------------------
# Summary
# -------------------------
@dataclass(frozen=True)
class Summary:
    total_events: int
    by_country: List[Tuple[str, int]]
    by_ip: List[Tuple[str, int]]


def summarize(events: Iterable[LogEvent], top_n: int = 10) -> Summary:
    by_country: Dict[str, int] = {}
    by_ip: Dict[str, int] = {}
    total = 0

    for e in events:
        total += 1
        c = e.country_iso or "??"
        by_country[c] = by_country.get(c, 0) + 1
        by_ip[e.ip] = by_ip.get(e.ip, 0) + 1

    return Summary(
        total_events=total,
        by_country=sorted(by_country.items(), key=lambda kv: kv[1], reverse=True)[:top_n],
        by_ip=sorted(by_ip.items(), key=lambda kv: kv[1], reverse=True)[:top_n],
    )

def split_syslog_line(line: str, year: int) -> Optional[tuple[datetime, str, str]]:
    # Formato típico: "Feb 22 16:41:02 HOSTNAME programa[pid]: mensagem..."
    parts = line.split()
    if len(parts) < 5:
        return None

    month, day, hms = parts[0], parts[1], parts[2]
    hostname = parts[3]

    ts = _parse_syslog_ts(f"{month} {day} {hms}", year)
    if not ts:
        return None

    # msg = tudo a seguir ao hostname
    msg = " ".join(parts[4:])
    return ts, hostname, msg
