import csv
import io
import json
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import Response
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.schemas import EmailRequest
from app.services.email_service import analyze_email

router = APIRouter(prefix="/api/email", tags=["Email"])


@router.post("/analyze")
def analyze(request: EmailRequest) -> dict:
    return analyze_email(request.raw_email)


@router.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)) -> dict:
    if file.filename and not file.filename.lower().endswith((".eml", ".msg", ".txt")):
        raise HTTPException(400, "Upload an .eml, .msg, or .txt email file")
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(413, "Email file exceeds the 10 MB limit")
    result = analyze_email(content.decode("utf-8", errors="replace"))
    result["filename"] = file.filename
    result["file_size_bytes"] = len(content)
    return result


def _email_pdf(result: dict) -> Response:
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=letter)
    document.setFont("Helvetica-Bold", 16)
    document.drawString(40, 750, "SOC Analyst Toolkit Email Analysis")
    document.setFont("Helvetica", 9)
    y = 725
    lines = [
        f"Verdict: {result.get('verdict')}   Risk: {result.get('risk_score')}/100",
        f"From: {result.get('sender_name') or ''} <{result.get('sender_email') or ''}>",
        f"Domain: {result.get('sender_domain') or 'N/A'}",
        f"Subject: {result.get('subject') or 'N/A'}",
        f"SPF: {result.get('spf')}  DKIM: {result.get('dkim')}  DMARC: {result.get('dmarc')}",
        f"URLs: {len(result.get('urls', []))}  IPs: {len(result.get('ips', []))}  Hashes: {len(result.get('hashes', []))}",
        f"Attachments: {', '.join(result.get('attachments', [])) or 'None'}",
        f"Keywords: {', '.join(result.get('keyword_hits', [])) or 'None'}",
        f"Header mismatches: {'; '.join(result.get('header_mismatches', [])) or 'None'}",
    ]
    for line in lines:
        document.drawString(40, y, line[:115])
        y -= 16
    document.save()
    return Response(output.getvalue(), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=email-analysis.pdf"})


@router.post("/export/json")
def export_json(request: EmailRequest) -> Response:
    return Response(json.dumps(analyze_email(request.raw_email), indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=email-analysis.json"})


@router.post("/report.pdf")
def report_pdf(request: EmailRequest) -> Response:
    return _email_pdf(analyze_email(request.raw_email))
