from fastapi import APIRouter, HTTPException, Query
from app.mitre.attack_data import TACTICS, TECHNIQUES, THREAT_PROFILES
from app.mitre.rule_factory import generate_rules, generate_profile, load_rules
from app.mitre.classifier import classify_findings, kill_chain_view, attack_heatmap
import yaml

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

@router.get("/tactics")
def tactics(): return TACTICS

@router.get("/techniques")
def techniques(q: str | None = Query(None)): 
    return [t for t in TECHNIQUES if not q or q.lower() in (t["id"] + " " + t["name"] + " " + t["description"]).lower()]

@router.get("/profiles")
def profiles(): return THREAT_PROFILES

@router.post("/generate")
def generate(payload: dict = {}):
    try: return generate_profile(payload["profile"]) if payload.get("profile") else generate_rules()
    except KeyError as exc: raise HTTPException(404, str(exc))

@router.get("/generate")
def generate_get(profile: str | None = None):
    try: return generate_profile(profile) if profile else generate_rules()
    except KeyError as exc: raise HTTPException(404, str(exc))

@router.post("/classify")
def classify(payload: dict | list = {}):
    if isinstance(payload, list):
        return classify_findings(payload)
    return classify_findings(payload.get("findings", []), payload.get("text"))

@router.post("/heatmap")
def heatmap(payload: dict = {}): return {"heatmap": attack_heatmap(payload.get("findings", [])), "kill_chain": kill_chain_view(payload.get("findings", []))}

@router.post("/export/sigma")
def export_sigma(payload: dict = {}):
    rules = payload.get("rules") or generate_rules()
    documents = []
    for rule in rules:
        documents.append({"title": rule["name"], "id": rule["id"], "status": "experimental",
                          "logsource": {"product": "generic"}, "detection": {"selection": {"message": rule.get("keywords", [])}, "condition": "selection"},
                          "level": rule.get("severity", "medium"), "tags": [f"attack.{rule['mitre'].lower()}"]})
    return {"yaml": yaml.safe_dump_all(documents, sort_keys=False), "rules": len(documents)}

@router.post("/reload")
def reload_rules(): 
    rules = load_rules()
    return {"status": "ok", "rules": len(rules)}

@router.get("/reload")
def reload_rules_get():
    return reload_rules()
