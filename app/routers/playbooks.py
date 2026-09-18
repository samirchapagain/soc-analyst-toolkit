import json
import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.integrations import notify_slack, create_case, block_ip
from app.models import PlaybookRun
from app.schemas import PlaybookRequest
from app.services.ioc_service import lookup_indicator
from app.services.auth_service import current_user

router = APIRouter(prefix="/api/playbook", tags=["Playbooks"])


@router.post("/run")
def run(payload: PlaybookRequest, db: Session = Depends(get_db), user=Depends(current_user)) -> dict:
    started = time.perf_counter()
    value = payload.input
    if payload.playbook == "ioc_triage":
        indicator = value.get("indicator", "").strip()
        if not indicator:
            raise HTTPException(422, "ioc_triage requires an indicator")
        steps = [{"step": "Enrich IOC", "action": "lookup_indicator", "status": "completed", "output": json.dumps(lookup_indicator(indicator)), "duration_ms": 1}, {"step": "Create case", "action": "create_case", "status": "completed", "output": create_case(indicator), "duration_ms": 1}]
    elif payload.playbook == "phishing_triage":
        steps = [{"step": "Notify Slack", "action": "notify_slack", "status": "completed", "output": notify_slack("Phishing triage started"), "duration_ms": 1}, {"step": "Create case", "action": "create_case", "status": "completed", "output": create_case("phishing"), "duration_ms": 1}]
    else:
        ip = value.get("ip", value.get("indicator", "")).strip()
        if not ip:
            raise HTTPException(422, "brute_force_response requires an ip")
        steps = [{"step": "Block IP", "action": "block_ip", "status": "completed", "output": block_ip(ip), "duration_ms": 1}, {"step": "Notify Slack", "action": "notify_slack", "status": "completed", "output": notify_slack("Brute force response executed"), "duration_ms": 1}]
    record = PlaybookRun(name=payload.playbook, input_data=json.dumps(value), result=json.dumps({"timeline": steps, "duration_ms": round((time.perf_counter() - started) * 1000, 2)}))
    db.add(record); db.commit(); db.refresh(record)
    return {"id": record.id, "playbook": payload.playbook, "timeline": steps}


@router.get("/runs")
def runs(db: Session = Depends(get_db), user=Depends(current_user)) -> list[dict]:
    return [{"id": row.id, "playbook": row.name, "status": row.status, "input": json.loads(row.input_data), "result": json.loads(row.result), "created_at": row.created_at} for row in db.scalars(select(PlaybookRun).order_by(PlaybookRun.created_at.desc())).all()]
