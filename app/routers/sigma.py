from fastapi import APIRouter
import yaml

router = APIRouter(prefix="/api/sigma", tags=["Sigma"])
TEMPLATES = [
    ("brute-force", "Brute Force", "authentication", "failed password", "high", "T1110"),
    ("encoded-powershell", "Encoded PowerShell", "process_creation", "-enc", "high", "T1059.001"),
    ("lsass-access", "LSASS Access", "process_creation", "lsass.exe", "critical", "T1003.001"),
    ("psexec", "PsExec", "process_creation", "psexec.exe", "high", "T1021.002"),
    ("sqli", "SQL Injection", "webserver", "union select", "high", "T1190"),
]


@router.post("/generate")
def generate(payload: dict) -> dict[str, str]:
    document = {
        "title": payload["title"], "id": payload["title"].lower().replace(" ", "-"),
        "status": "experimental", "logsource": {"product": payload["logsource"]},
        "detection": {"selection": {payload["detection_field"]: payload["detection_value"]}, "condition": "selection"},
        "level": payload["level"], "tags": [f"attack.{payload['mitre'].lower()}"],
    }
    return {"yaml": yaml.safe_dump(document, sort_keys=False)}


@router.get("/templates")
def templates() -> list[dict]:
    return [{"id": i, "title": title, "logsource": source, "detection_field": "message", "detection_value": value, "level": level, "mitre": mitre} for i, title, source, value, level, mitre in TEMPLATES]
