import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, AlertIOC
from app.schemas import AlertCreate, AlertListResponse, AlertResponse, AlertUpdate
from app.services.auth_service import current_user, require_roles
from app.services.ioc_service import lookup_indicator

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])
subscribers: set[asyncio.Queue[str]] = set()


@router.get("", response_model=AlertListResponse)
def list_alerts(
    q: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    mitre: str | None = None,
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    query = select(Alert)
    filters = []
    if q:
        filters.append(or_(Alert.title.contains(q), Alert.notes.contains(q), Alert.source.contains(q)))
    if severity:
        filters.append(Alert.severity == severity)
    if status_filter:
        filters.append(Alert.status == status_filter)
    if mitre:
        filters.append(Alert.mitre.contains(mitre))
    if filters:
        query = query.where(*filters)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = list(db.scalars(query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)).all())
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(payload: AlertCreate, db: Session = Depends(get_db), user=Depends(current_user)) -> Alert:
    alert = Alert(**payload.model_dump())
    db.add(alert)
    db.commit()
    db.refresh(alert)
    event = json.dumps({"id": alert.id, "title": alert.title, "severity": alert.severity, "status": alert.status})
    for queue in list(subscribers):
        await queue.put(event)
    return alert


@router.get("/stats/summary")
def alert_stats(db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count(Alert.id))) or 0
    severity_counts = dict(db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all())
    status_counts = dict(db.execute(select(Alert.status, func.count(Alert.id)).group_by(Alert.status)).all())
    return {
        "total": total,
        "by_severity": {
            severity: severity_counts.get(severity, 0)
            for severity in ("critical", "high", "medium", "low")
        },
        "by_status": {
            alert_status: status_counts.get(alert_status, 0)
            for alert_status in ("open", "in_progress", "closed")
        },
    }


@router.get("/stream")
async def stream_alerts() -> StreamingResponse:
    queue: asyncio.Queue[str] = asyncio.Queue()
    subscribers.add(queue)

    async def events() -> AsyncIterator[str]:
        try:
            yield "event: ready\ndata: {\"status\":\"connected\"}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            subscribers.discard(queue)

    return StreamingResponse(events(), media_type="text/event-stream")


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db), user=Depends(current_user)) -> Alert:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(alert, key, value)
    db.commit()
    db.refresh(alert)
    return alert


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(alert_id: int, db: Session = Depends(get_db), user=Depends(require_roles("admin"))) -> None:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()


@router.post("/{alert_id}/enrich")
def enrich_alert(alert_id: int, db: Session = Depends(get_db), user=Depends(current_user)) -> list[dict]:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    import re
    indicators = sorted(set(re.findall(r"(?:https?://[^\s,;]+|(?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9]{32,64})", alert.notes or "")))
    results = []
    for indicator in indicators:
        enrichment = lookup_indicator(indicator)
        db.add(AlertIOC(alert_id=alert.id, indicator=indicator, enrichment=json.dumps(enrichment)))
        results.append(enrichment)
    db.commit()
    return results
