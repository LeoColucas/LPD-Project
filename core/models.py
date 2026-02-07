# core/models.py
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Finding:
    timestamp: datetime
    category: str          # "PORTSCAN", "LOG", "KNOCK", "MSG", "PWD"
    severity: str          # "LOW" | "MEDIUM" | "HIGH"
    title: str
    details: str

    target: Optional[str] = None   # host/ip
    source: Optional[str] = None   # ficheiro, módulo, etc
    ip: Optional[str] = None
    user: Optional[str] = None
