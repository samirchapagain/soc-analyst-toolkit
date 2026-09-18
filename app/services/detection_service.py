import base64
import binascii
import json
import re
from typing import Any

from app.services.email_service import analyze_email
from app.services.ioc_service import detect_type, lookup_indicator
from app.services.log_service import analyze_logs
from app.mitre.rule_factory import generate_rules
from app.mitre.classifier import classify_findings

DETECTION_RULES = [
    {"id": "credential_phishing", "name": "Credential phishing", "severity": "high", "mitre": "T1566.002", "description": "Credential collection language.", "remediation": "Block sender and reset exposed credentials.", "why": "Common initial access technique."},
    {"id": "encoded_payload", "name": "Encoded payload", "severity": "high", "mitre": "T1027", "description": "Base64 or encoded PowerShell payload.", "remediation": "Decode safely and isolate execution host.", "why": "Encoding obscures malicious commands."},
]
GENERATED_RULES = generate_rules()
IOC_RE = re.compile(r"https?://[^\s,;]+|(?:\d{1,3}\.){3}\d{1,3}|\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}|[a-fA-F0-9]{24})?\b|(?<![@\w])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w])")


def _keyword_matches(text: str, keyword: str) -> bool:
    keyword = keyword.strip().lower()
    if not keyword:
        return False
    return re.search(rf"(?<!\w){re.escape(keyword)}(?!\w)", text) is not None


def _decode(text: str) -> list[dict[str, str]]:
    decoded = []
    candidates = re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/])", text)
    for candidate in candidates:
        try:
            value = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if value.strip():
            decoded.append({"encoding": "base64", "source": candidate, "value": value[:2000]})
    return decoded


def detect(text: str, content_type: str = "auto") -> dict[str, Any]:
    lowered = text.lower()
    content_types: list[str] = []
    findings: list[dict[str, Any]] = []
    decoded = _decode(text)
    if "mime-version:" in lowered or "\nfrom:" in lowered and "\nsubject:" in lowered:
        content_types.append("email")
        email = analyze_email(text)
        for keyword in email.get("keyword_hits", []):
            findings.append({"rule_id": "credential_phishing", "rule_name": "Credential phishing", "severity": "high", "mitre": "T1566.002", "evidence": keyword})
    if re.search(r"failed login|4625|powershell|mimikatz|psexec|union select", lowered):
        content_types.append("log")
        log = analyze_logs(text.encode())
        findings.extend(log["findings"])
    if decoded:
        content_types.append("base64")
        findings.append({"rule_id": "encoded_payload", "rule_name": "Encoded payload", "severity": "high", "mitre": "T1027", "evidence": decoded[0]["value"][:300]})
    iocs = sorted({value.rstrip(").]}") for value in IOC_RE.findall(text) if detect_type(value.rstrip(").]}")) != "unknown"})
    if iocs:
        content_types.append("ioc")
    if not content_types:
        content_types.append(content_type if content_type != "auto" else "text")
    # ATT&CK metadata rules run locally and do not require an integration.
    existing = {finding.get("mitre") for finding in findings}
    lowered_for_rules = text.lower()
    for rule in GENERATED_RULES:
        if rule["mitre"] in existing:
            continue
        if any(_keyword_matches(lowered_for_rules, keyword) for keyword in rule.get("keywords", [])):
            findings.append({"rule_id": rule["id"], "rule_name": rule["name"], "severity": rule["severity"],
                             "mitre": rule["mitre"], "tactic": rule["tactic"], "evidence": text[:300],
                             "description": rule["description"], "remediation": rule["remediation"], "why": rule["why"]})
    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = max((finding.get("severity", "low") for finding in findings), key=lambda value: severity_order.get(value, 0), default="none")
    timeline = [{"event": "classified", "content_types": content_types}, {"event": "analyzed", "findings": len(findings)}]
    classified = classify_findings(findings)
    return {"content_types": sorted(set(content_types)), "summary": {"threats_found": len(findings), "highest_severity": highest, "iocs_extracted": len(iocs), "rules_matched": len({finding.get("rule_id") for finding in findings})}, "iocs": iocs, "findings": findings, "mitre": classified, "decoded": decoded, "timeline": timeline}
