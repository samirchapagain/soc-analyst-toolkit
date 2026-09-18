import csv
import io
import json
from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import Response
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.services.log_service import analyze_logs

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    if file.filename and not file.filename.lower().endswith((".log", ".txt", ".csv", ".json")):
        raise HTTPException(status_code=400, detail="Only .log, .txt, .csv, and .json files are accepted")
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds the 5 MB limit")
    return analyze_logs(content)


@router.post("/export/json")
async def export_json(file: UploadFile = File(...)) -> Response:
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "File exceeds the 5 MB limit")
    return Response(json.dumps(analyze_logs(content), indent=2), media_type="application/json", headers={"Content-Disposition": "attachment; filename=log-analysis.json"})


@router.post("/export/csv")
async def export_csv(file: UploadFile = File(...)) -> Response:
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "File exceeds the 5 MB limit")
    output = io.StringIO()
    fields = ["line", "rule_id", "rule_name", "severity", "mitre", "evidence"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for finding in analyze_logs(content)["findings"]:
        writer.writerow({field: finding.get(field, "") for field in fields})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=log-findings.csv"})


@router.post("/report.pdf")
async def report_pdf(file: UploadFile = File(...)) -> Response:
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(413, "File exceeds the 5 MB limit")
    result = analyze_logs(content)
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=letter)
    document.setFont("Helvetica-Bold", 16)
    document.drawString(40, 750, "SOC Analyst Toolkit Log Analysis")
    document.setFont("Helvetica", 9)
    document.drawString(40, 730, f"Lines: {result['total_lines']}   Findings: {result['total_findings']}")
    y = 705
    for finding in result["findings"][:40]:
        document.drawString(40, y, f"Line {finding['line']} | {finding['rule_name']} | {finding['severity']} | {finding['mitre']}"[:115])
        y -= 15
    document.save()
    return Response(output.getvalue(), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=log-analysis.pdf"})
