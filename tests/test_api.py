import base64
import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ["DEMO_MODE"] = "true"
os.environ["DATABASE_URL"] = "sqlite:///./test_soc_toolkit.db"

from app.main import app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.mark.asyncio
async def test_health(client):
    assert (await client.get("/health")).json() == {"status": "ok", "database": "ok"}


@pytest.mark.asyncio
async def test_ioc_demo_determinism(client):
    first = (await client.post("/api/ioc/lookup", json={"indicator": "8.8.8.8"})).json()
    second = (await client.post("/api/ioc/lookup", json={"indicator": "8.8.8.8"})).json()
    assert first == second
    assert first["demo"] is True
    assert len(first["providers"]) == 12
    assert all("status" in provider for provider in first["providers"].values())


@pytest.mark.asyncio
async def test_provider_status_endpoint(client):
    response = await client.get("/api/providers/status")
    assert response.status_code == 200
    providers = response.json()["providers"]
    assert len(providers) == 12
    assert {"name", "configured", "calls_today", "last_status"} <= providers[0].keys()


@pytest.mark.asyncio
async def test_bulk_ioc_validation(client):
    response = await client.post("/api/ioc/bulk", json={"indicators": [" 8.8.8.8 "]})
    assert response.status_code == 200
    assert response.json()[0]["indicator"] == "8.8.8.8"

    invalid = await client.post("/api/ioc/bulk", json={"indicators": ["   "]})
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_playbook_requires_known_inputs(client):
    registration = await client.post("/api/auth/register", json={"username": "playbook-user", "email": "playbook@example.com", "password": "password123"})
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    unknown = await client.post("/api/playbook/run", json={"playbook": "unknown"}, headers=headers)
    assert unknown.status_code == 422
    missing_input = await client.post("/api/playbook/run", json={"playbook": "ioc_triage"}, headers=headers)
    assert missing_input.status_code == 422


@pytest.mark.asyncio
async def test_email_phishing(client):
    response = await client.post("/api/email/analyze", json={"raw_email": "From: Support <support@evil.ru>\nSubject: Urgent verify your account\n\nClick here http://evil.ru/login"})
    data = response.json()
    assert data["verdict"] in {"suspicious", "malicious"}
    assert data["keyword_hits"]


@pytest.mark.asyncio
async def test_email_detects_simulated_executable_attachment(client):
    raw_email = """From: Vendor Billing <billing@vendor-portal.example>
Subject: Invoice 78421 — payment overdue
Content-Type: multipart/mixed; boundary="BOUND_7F2A"

Hello Sanjay,
Please review the attached document and arrange payment as soon as possible to avoid interruption of service.
[Simulated attachment metadata: filename=Invoice_78421.pdf.exe; content-type=application/octet-stream]
"""
    response = await client.post("/api/email/analyze", json={"raw_email": raw_email})
    data = response.json()
    assert response.status_code == 200
    assert "Invoice_78421.pdf.exe" in data["attachments"]
    assert data["dangerous_attachments"] == ["Invoice_78421.pdf.exe"]
    assert data["double_extension_attachments"] == ["Invoice_78421.pdf.exe"]
    assert data["attachment_type_mismatch"] is True
    assert data["verdict"] == "malicious"


@pytest.mark.asyncio
async def test_logs_brute_force(client):
    response = await client.post("/api/logs/analyze", files={"file": ("auth.log", b"failed login for user", "text/plain")})
    assert response.json()["rule_summary"]["BRUTE_FORCE"] == 1


@pytest.mark.asyncio
async def test_alerts_crud(client):
    registration = await client.post("/api/auth/register", json={"username": "tester", "email": "tester@example.com", "password": "password123"})
    headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
    created = await client.post("/api/alerts", json={"title": "Test alert", "severity": "high"}, headers=headers)
    assert created.status_code == 201
    alert_id = created.json()["id"]
    listing = await client.get("/api/alerts")
    assert listing.status_code == 200
    assert "items" in listing.json()
    updated = await client.patch(f"/api/alerts/{alert_id}", json={"status": "closed"}, headers=headers)
    assert updated.json()["status"] == "closed"
    admin = await client.post("/api/auth/register", json={"username": "admin", "email": "admin@example.com", "password": "password123"})
    assert (await client.delete(f"/api/alerts/{alert_id}", headers={"Authorization": f"Bearer {admin.json()['access_token']}"})).status_code == 403


@pytest.mark.asyncio
async def test_sigma_and_playbook(client):
    sigma = await client.post("/api/sigma/generate", json={"title": "Test", "logsource": "windows", "detection_field": "CommandLine", "detection_value": "powershell", "level": "high", "mitre": "T1059.001"})
    assert sigma.status_code == 200
    assert "title: Test" in sigma.json()["yaml"]
    registration = await client.post("/api/auth/register", json={"username": "runner", "email": "runner@example.com", "password": "password123"})
    playbook = await client.post("/api/playbook/run", json={"playbook": "ioc_triage", "input": {"indicator": "8.8.8.8"}}, headers={"Authorization": f"Bearer {registration.json()['access_token']}"})
    assert playbook.status_code == 200
    assert playbook.json()["timeline"]


@pytest.mark.asyncio
@pytest.mark.parametrize("text", [
    "From: a@evil.ru\nSubject: urgent verify your account\n\nclick here http://evil.ru",
    "failed login 4625 from 10.0.0.1",
    "8.8.8.8, example.com, d41d8cd98f00b204e9800998ecf8427e",
    base64.b64encode(b"powershell -enc ZQB2AGkAbA==").decode(),
    "nothing unusual here",
])
async def test_universal_detect(client, text):
    response = await client.post("/api/detect", json={"text": text})
    assert response.status_code == 200
    assert "content_types" in response.json()


@pytest.mark.asyncio
async def test_routine_maintenance_email_has_no_mitre_false_positives(client):
    raw_email = """Delivered-To: user@company-target.example
Received: from mail.internal-it.example ([192.0.2.10])
    by mx.company-target.example with ESMTPS id A12B
Return-Path: <system-alerts@internal-it.example>
To: user@company-target.example
Subject: Scheduled Maintenance Notification: Internal Portal Services
From: IT Operations Team <system-alerts@internal-it.example>
Content-Type: text/plain; charset="UTF-8"

This is a routine notification for scheduled system maintenance.
Services will be temporarily unavailable. Please save your ongoing work.
Contact the official internal help portal if issues continue.
"""
    response = await client.post("/api/detect", json={"text": raw_email})
    data = response.json()
    assert response.status_code == 200
    assert data["summary"]["threats_found"] == 0
    assert data["summary"]["highest_severity"] == "none"


@pytest.mark.asyncio
async def test_content_transfer_encoding_is_not_encoded_powershell(client):
    raw_email = """Delivered-To: user@company-target.example
Received: from mail.internal-it.example ([192.0.2.10])
    by mx.company-target.example with ESMTPS id A12B
Return-Path: <system-alerts@internal-it.example>
To: user@company-target.example
Subject: Scheduled Maintenance Notification: Internal Portal Services
From: IT Operations Team <system-alerts@internal-it.example>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

This is a routine notification to inform you that our internal employee portal
will undergo scheduled system maintenance this weekend.
"""
    response = await client.post("/api/detect", json={"text": raw_email})
    data = response.json()
    assert response.status_code == 200
    assert not any(finding["mitre"] == "T1059.001" for finding in data["findings"])
