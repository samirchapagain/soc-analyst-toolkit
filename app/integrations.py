"""Optional external integrations. All calls are safe no-op in DEMO_MODE."""
import os
from app.services.ioc_service import lookup_indicator

def enrich_indicator(indicator: str) -> dict:
    return lookup_indicator(indicator)

def integration_status() -> dict:
    return {"demo_mode": os.getenv("DEMO_MODE", "true").lower() == "true",
            "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY"))}


def block_ip(indicator: str) -> str:
    return f"Simulated block action for {indicator}"


def notify_slack(message: str) -> str:
    return f"Simulated Slack notification: {message}"


def create_case(subject: str) -> str:
    return f"Simulated case created for {subject}"
