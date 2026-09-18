from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from sqlalchemy import func, select

from app.database import SessionLocal
from app.models import ProviderCall
from app.providers.registry import PROVIDERS, available_providers, get_provider
from app.services.ioc_service import lookup_provider

router = APIRouter(prefix="/api/providers", tags=["Providers"])


@router.get("")
def providers() -> dict:
    return {"providers": available_providers()}


@router.get("/status")
def provider_status() -> dict:
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    db = SessionLocal()
    try:
        result = []
        for provider in PROVIDERS.values():
            last = db.scalar(select(ProviderCall).where(ProviderCall.provider == provider.name).order_by(ProviderCall.created_at.desc()).limit(1))
            calls_today = db.scalar(select(func.count(ProviderCall.id)).where(ProviderCall.provider == provider.name, ProviderCall.created_at >= since)) or 0
            result.append({"name": provider.name, "configured": provider.configured, "last_call": last.created_at if last else None, "last_status": last.status if last else None, "last_latency_ms": last.latency_ms if last else None, "calls_today": calls_today, "quota_used_pct": None})
        return {"providers": result}
    finally:
        db.close()


@router.post("/{name}/test")
def test_provider(name: str) -> dict:
    provider = get_provider(name)
    if provider is None:
        raise HTTPException(404, "Provider not found")
    return lookup_provider(provider.name, "8.8.8.8")
