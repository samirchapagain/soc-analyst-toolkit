import json
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from app.database import SessionLocal
from app.models import Cache


class CacheService:
    def __init__(self, ttl_hours: int = 24) -> None:
        self.ttl = timedelta(hours=ttl_hours)
        self._lock = Lock()

    def key(self, provider: str, indicator: str) -> str:
        return f"{provider}:{indicator.strip().lower()}"

    def get(self, key: str) -> Any | None:
        with self._lock:
            db = SessionLocal()
            try:
                row = db.query(Cache).filter(Cache.cache_key == key).first()
                if not row:
                    return None
                expires = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
                if expires <= datetime.now(timezone.utc):
                    db.delete(row)
                    db.commit()
                    return None
                return json.loads(row.value)
            finally:
                db.close()

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            db = SessionLocal()
            try:
                row = db.query(Cache).filter(Cache.cache_key == key).first()
                expiry = datetime.now(timezone.utc) + self.ttl
                if row:
                    row.value = json.dumps(value)
                    row.expires_at = expiry
                else:
                    db.add(Cache(cache_key=key, value=json.dumps(value), expires_at=expiry))
                db.commit()
            finally:
                db.close()


cache_service = CacheService()
