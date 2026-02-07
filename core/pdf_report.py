# core/pdf_report.py
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from core.models import Finding
from datetime import datetime

def write_pdf_report(path: str, findings: list[Finding], severity_stats: list[tuple[str,int]], meta: dict) -> str:
    c = canvas.Canvas(path, pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(2*cm, h-2*cm, "Relatório de Segurança")

    c.setFont("Helvetica", 10)
    c.drawString(2*cm, h-2.8*cm, f"Gerado em: {datetime.now().isoformat(timespec='seconds')}")
    c.drawString(2*cm, h-3.3*cm, f"Total de findings: {len(findings)}")
    c.drawString(2*cm, h-3.8*cm, f"Scope: {meta.get('scope','-')}")

    y = h-4.8*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Resumo por severidade")
    y -= 0.6*cm

    c.setFont("Helvetica", 10)
    for sev, cnt in severity_stats:
        c.drawString(2.2*cm, y, f"{sev}: {cnt}")
        y -= 0.45*cm

    y -= 0.4*cm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2*cm, y, "Achados (top 30)")
    y -= 0.7*cm

    c.setFont("Helvetica", 9)
    for f in findings[:30]:
        line = f"[{f.severity}] {f.timestamp.isoformat(timespec='seconds')} {f.category} - {f.title}"
        if y < 2*cm:
            c.showPage()
            y = h-2*cm
            c.setFont("Helvetica", 9)
        c.drawString(2*cm, y, line[:120])
        y -= 0.42*cm

    c.save()
    return path
