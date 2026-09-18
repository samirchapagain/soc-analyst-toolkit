import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse
from html import unescape

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HASH_RE = re.compile(r"(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")
KEYWORDS = ("verify your account", "click here", "urgent", "password reset", "wire transfer", "invoice attached", "attached document", "payment overdue", "avoid interruption of service", "confirm your identity", "account suspended", "unusual activity", "gift card", "bitcoin", "crypto wallet", "login to continue")
SUSPICIOUS_TLDS = (".zip", ".ru", ".tk", ".xyz", ".top", ".click", ".country", ".gq", ".cf")
DANGEROUS_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".hta", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z")
BRANDS = ("paypal", "microsoft", "google", "apple", "amazon", "netflix", "dhl", "fedex", "docusign")
DISPOSABLE = ("mailinator", "guerrillamail", "tempmail", "10minutemail", "yopmail")


def _domain(address: str | None) -> str | None:
    parsed = parseaddr(address or "")[1]
    return parsed.rsplit("@", 1)[1].lower() if "@" in parsed else None


def _auth_status(header: str, token: str) -> str:
    match = re.search(rf"{token}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", header, re.IGNORECASE)
    return match.group(1).lower() if match else "unknown"


def analyze_email(raw_email: str) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw_email.encode("utf-8", errors="replace"))
    from_name, sender_email = parseaddr(message.get("From", ""))
    sender_domain = _domain(sender_email)
    return_path = parseaddr(message.get("Return-Path", ""))[1] or None
    reply_to = parseaddr(message.get("Reply-To", ""))[1] or None
    auth_header = " ".join(message.get_all("Authentication-Results", []))
    auth_header += " " + " ".join(message.get_all("Received-SPF", []))
    urls: list[str] = []
    body_parts: list[str] = []
    for part in message.walk():
        if part.get_content_type() in {"text/plain", "text/html"}:
            try:
                body_parts.append(part.get_content())
            except (KeyError, LookupError):
                body_parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace") if part.get_payload(decode=True) else "")
    body = "\n".join(body_parts)
    html_body = "\n".join(part.get_content() for part in message.walk() if part.get_content_type() == "text/html")
    for url in URL_RE.findall(body):
        clean_url = url.rstrip(".,);]")
        if clean_url not in urls:
            urls.append(clean_url)
    ips = sorted({ip for ip in IP_RE.findall(raw_email) if _valid_ip(ip)})
    hashes = sorted(set(HASH_RE.findall(raw_email)))
    searchable_text = message.get("Subject", "") + "\n" + body
    if not body.strip():
        searchable_text += "\n" + raw_email
    lowered = searchable_text.lower()
    keyword_hits = [keyword for keyword in KEYWORDS if keyword in lowered]
    suspicious_tld_urls = [url for url in urls if any(urlparse(url).hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS if urlparse(url).hostname)]
    mismatches: list[str] = []
    if _domain(return_path) and sender_domain and _domain(return_path) != sender_domain:
        mismatches.append("Return-Path domain differs from From domain")
    if _domain(reply_to) and sender_domain and _domain(reply_to) != sender_domain:
        mismatches.append("Reply-To domain differs from From domain")
    spf = _auth_status(auth_header, "spf")
    dkim = _auth_status(auth_header, "dkim")
    dmarc = _auth_status(auth_header, "dmarc")
    attachments = [part.get_filename() for part in message.walk() if part.get_filename()]
    simulated_attachments = re.findall(
        r"(?:filename|file(?:name)?)\s*=\s*[\"']?([^\"'\]\r\n;]+)",
        raw_email,
        re.IGNORECASE,
    )
    for filename in simulated_attachments:
        filename = filename.strip()
        if filename and filename not in attachments:
            attachments.append(filename)
    dangerous_attachments = [name for name in attachments if name.lower().endswith(DANGEROUS_EXTENSIONS)]
    double_extensions = [
        name for name in attachments
        if len(name.rsplit("/", 1)[-1].split(".")) > 2
        and any(name.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)
    ]
    impersonation_hits = _brand_impersonation(sender_domain, from_name)
    display_name_spoof = bool(from_name and ("@" in from_name or any(brand in from_name.lower() for brand in BRANDS)) and not any(brand in (sender_domain or "") for brand in BRANDS))
    href_mismatches = _href_mismatches(html_body)
    disposable_sender = bool(sender_domain and any(item in sender_domain for item in DISPOSABLE))
    header_names = list(message.keys())
    header_values = {name: str(message.get(name, ""))[:2000] for name in header_names}
    attachment_type_mismatch = bool(
        dangerous_attachments
        and re.search(r"application/octet-stream|application/x-msdownload", raw_email, re.IGNORECASE)
    )
    score = min(100, len(keyword_hits) * 7 + len(suspicious_tld_urls) * 15 + len(mismatches) * 18 + len(dangerous_attachments) * 15 + len(double_extensions) * 10 + (15 if attachment_type_mismatch else 0) + len(impersonation_hits) * 15 + (12 if display_name_spoof else 0) + len(href_mismatches) * 12 + (15 if disposable_sender else 0) + sum(15 for status in (spf, dkim, dmarc) if status in {"fail", "softfail"}) + (10 if hashes else 0))
    return {
        "sender_name": from_name or None, "sender_email": sender_email or None, "sender_domain": sender_domain,
        "return_path": return_path, "reply_to": reply_to, "subject": message.get("Subject", ""),
        "spf": spf, "dkim": dkim, "dmarc": dmarc, "urls": urls, "ips": ips, "hashes": hashes,
        "keyword_hits": keyword_hits, "suspicious_tld_urls": suspicious_tld_urls, "header_mismatches": mismatches,
        "attachments": attachments, "dangerous_attachments": dangerous_attachments, "double_extension_attachments": double_extensions,
        "attachment_type_mismatch": attachment_type_mismatch,
        "brand_impersonation": impersonation_hits, "display_name_spoof": display_name_spoof,
        "href_mismatches": href_mismatches, "disposable_sender": disposable_sender,
        "message_id": message.get("Message-ID"), "date": message.get("Date"),
        "content_type": message.get_content_type(), "header_count": len(header_names),
        "headers": header_values, "body_preview": body[:2000],
        "risk_score": score, "verdict": "malicious" if score >= 60 else "suspicious" if score >= 30 else "clean",
    }


def _levenshtein(left: str, right: str) -> int:
    row = list(range(len(right) + 1))
    for i, first in enumerate(left, 1):
        previous = row[0]
        row[0] = i
        for j, second in enumerate(right, 1):
            current = row[j]
            row[j] = min(row[j] + 1, row[j - 1] + 1, previous + (first != second))
            previous = current
    return row[-1]


def _brand_impersonation(domain: str | None, display_name: str) -> list[str]:
    candidate = (domain or "").split(".")[0].lower()
    return [brand for brand in BRANDS if candidate and _levenshtein(candidate, brand) <= 2 and candidate != brand]


def _href_mismatches(html: str) -> list[str]:
    mismatches = []
    for href, visible in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.I | re.S):
        text = re.sub(r"<[^>]+>", "", unescape(visible)).strip()
        if text.startswith(("http://", "https://")) and urlparse(href).netloc.lower() != urlparse(text).netloc.lower():
            mismatches.append(f"{text} -> {href}")
    return mismatches


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
