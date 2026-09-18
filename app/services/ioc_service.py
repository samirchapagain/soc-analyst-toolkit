import asyncio
import ipaddress
import os
import re
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any
from urllib.parse import urlparse

from app.database import SessionLocal
from app.models import ProviderCall
from app.providers.registry import PROVIDERS
from app.services.cache_service import cache_service

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
LIMITS = {"virustotal": (4, 60), "abuseipdb": (60, 60), "greynoise": (1, 60), "shodan": (60, 60), "urlscan": (100, 86400), "ipinfo": (60, 60), "hibp": (90, 60)}
_calls: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = Lock()


def detect_type(indicator: str) -> str:
    value = indicator.strip()
    if HASH_RE.fullmatch(value):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    if value.lower().startswith(("http://", "https://")) and urlparse(value).netloc:
        return "url"
    if IP_RE.fullmatch(value):
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
    if "@" in value and "." in value.rsplit("@", 1)[-1]:
        return "email"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    return "unknown"


def _allowed(provider: str) -> bool:
    limit, window = LIMITS.get(provider, (1000, 60))
    now = time.time()
    with _rate_lock:
        bucket = _calls[provider]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


def _log(provider: str, indicator: str, status: str, latency: int, error: str | None = None) -> None:
    db = SessionLocal()
    try:
        db.add(ProviderCall(provider=provider, indicator=indicator, status=status, latency_ms=latency, error=error))
        db.commit()
    finally:
        db.close()


def _provider_call(provider: Any, value: str, kind: str, demo: bool) -> tuple[str, dict[str, Any]]:
    started = time.perf_counter()
    if not provider.can_lookup(kind):
        return provider.name, {"provider": provider.name, "status": "unavailable", "reason": "unsupported"}
    if not demo and not provider.configured:
        _log(provider.name, value, "skipped", 0, "missing key")
        return provider.name, {"provider": provider.name, "status": "unavailable", "reason": "missing key"}
    if not demo and not _allowed(provider.name):
        _log(provider.name, value, "rate_limited", 0, "local quota guard")
        return provider.name, {"provider": provider.name, "status": "rate_limited", "reason": "local quota guard"}
    cache_key = cache_service.key(provider.name, value)
    if not demo:
        cached = cache_service.get(cache_key)
        if cached is not None:
            return provider.name, {"provider": provider.name, "status": "success", "data": cached, "cached": True}
    try:
        data = provider.demo(value, kind) if demo else provider.lookup(value, kind)
        latency = round((time.perf_counter() - started) * 1000)
        if not demo:
            cache_service.set(cache_key, data)
        _log(provider.name, value, "ok", latency)
        return provider.name, {"provider": provider.name, "status": "success", "data": data, "cached": False}
    except Exception as exc:
        latency = round((time.perf_counter() - started) * 1000)
        _log(provider.name, value, "error", latency, str(exc))
        return provider.name, {"provider": provider.name, "status": "error", "error": str(exc)}


def lookup_indicator(indicator: str) -> dict[str, Any]:
    value = indicator.strip()
    kind = detect_type(value)
    demo = os.getenv("DEMO_MODE", "true").lower() in {"1", "true", "yes", "on"}
    with ThreadPoolExecutor(max_workers=len(PROVIDERS)) as pool:
        futures = [pool.submit(_provider_call, provider, value, kind, demo) for provider in PROVIDERS.values()]
        completed = [future.result() for future in as_completed(futures)]
        results = dict(sorted(completed, key=lambda item: item[0]))
    successful = [item.get("data", {}) for item in results.values() if item.get("status") == "success"]
    scores = [int(item.get("score", item.get("abuse_confidence", 0)) or 0) for item in successful]
    score = round(sum(scores) / len(scores)) if scores else 0
    verdict = "malicious" if any(item.get("verdict") == "malicious" for item in successful) or score >= 60 else "suspicious" if any(item.get("verdict") == "suspicious" for item in successful) or score >= 30 else "clean"
    return {
        "indicator": value, "type": kind, "demo": demo, "verdict": verdict,
        "severity": "high" if score >= 60 else "medium" if score >= 30 else "low",
        "score": score, "confidence": "high" if len(successful) >= 5 else "medium" if len(successful) >= 2 else "low",
        "providers": results, "summary": {"responded": len(successful), "total": len(results), "sources": sorted(name for name, item in results.items() if item.get("status") == "success")},
    }


def lookup_provider(provider_name: str, indicator: str) -> dict[str, Any]:
    """Run a connectivity test against one provider without fan-out to all providers."""
    provider = PROVIDERS.get(provider_name)
    if provider is None:
        raise KeyError(provider_name)
    value = indicator.strip()
    return _provider_call(
        provider,
        value,
        detect_type(value),
        os.getenv("DEMO_MODE", "true").lower() in {"1", "true", "yes", "on"},
    )[1]
