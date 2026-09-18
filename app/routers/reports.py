import csv
import io
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.services.ioc_service import lookup_indicator

router = APIRouter(tags=["Reports"])


def pdf_response(title: str, lines: list[str], filename: str) -> Response:
    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, 750, title)
    pdf.setFont("Helvetica", 9)
    y = 725
    for line in lines[:45]:
        pdf.drawString(40, y, line[:110])
        y -= 15
    pdf.save()
    return Response(output.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})


@router.get("/report/alert/{alert_id}.pdf")
def alert_pdf(alert_id: int, db: Session = Depends(get_db)) -> Response:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return pdf_response("SOC Analyst Toolkit Incident Report", [f"Alert #{alert.id}", alert.title, f"Severity: {alert.severity}", f"Status: {alert.status}", f"MITRE: {alert.mitre or 'N/A'}", f"Source: {alert.source or 'N/A'}", alert.notes or ""], f"alert-{alert.id}.pdf")


@router.get("/report/ioc/{indicator:path}.pdf")
def ioc_pdf(indicator: str) -> Response:
    result = lookup_indicator(indicator)
    return pdf_response("SOC Analyst Toolkit IOC Report", [f"Indicator: {indicator}", f"Type: {result['type']}", f"Verdict: {result['verdict']}", f"Score: {result['score']}", f"Sources: {', '.join(result['sources'])}"], "ioc-report.pdf")


@router.get("/export/alerts.json")
def alerts_json(db: Session = Depends(get_db)) -> Response:
    import json
    alerts = db.scalars(select(Alert).order_by(Alert.created_at.desc())).all()
    data = [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "mitre": a.mitre, "source": a.source, "notes": a.notes, "created_at": a.created_at.isoformat() if a.created_at else None} for a in alerts]
    return Response(json.dumps(data), media_type="application/json", headers={"Content-Disposition": "attachment; filename=alerts.json"})


@router.get("/export/alerts.csv")
def alerts_csv(db: Session = Depends(get_db)) -> Response:
    output = io.StringIO()
    fields = ["id", "title", "severity", "status", "mitre", "source", "notes", "created_at"]
    writer = csv.DictWriter(output, fieldnames=fields); writer.writeheader()
    for a in db.scalars(select(Alert).order_by(Alert.created_at.desc())).all():
        writer.writerow({field: getattr(a, field) for field in fields})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@router.get("/api/mitre/coverage")
def mitre_coverage(db: Session = Depends(get_db)) -> dict[str, int]:
    rows = db.execute(select(Alert.mitre, __import__("sqlalchemy").func.count(Alert.id)).where(Alert.mitre.is_not(None)).group_by(Alert.mitre)).all()
    return {technique: count for technique, count in rows}
