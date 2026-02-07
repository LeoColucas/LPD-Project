# core/findings_csv.py
import csv
from core.models import Finding

def write_findings_csv(path: str, findings: list[Finding]) -> str:
    fields = ["timestamp","category","severity","title","details","target","source","ip","user"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for x in findings:
            w.writerow({
                "timestamp": x.timestamp.isoformat(),
                "category": x.category,
                "severity": x.severity,
                "title": x.title,
                "details": x.details,
                "target": x.target or "",
                "source": x.source or "",
                "ip": x.ip or "",
                "user": x.user or "",
            })
    return path
