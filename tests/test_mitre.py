from fastapi.testclient import TestClient

from app.main import app
from app.mitre.attack_data import TACTICS, TECHNIQUES
from app.mitre.rule_factory import generate_rules, generate_profile
from app.mitre.classifier import attack_heatmap


def test_catalogue_and_factory():
    assert len(TACTICS) == 14
    assert len(TECHNIQUES) >= 80
    assert any(t["id"] == "T1566.002" for t in TECHNIQUES)
    assert len(generate_rules()) == len(TECHNIQUES)
    assert generate_profile("ransomware")


def test_mitre_endpoints_and_offline_detection():
    client = TestClient(app)
    assert len(client.get("/api/mitre/tactics").json()) == 14
    assert client.get("/api/mitre/techniques?q=powershell").json()
    response = client.post("/api/detect", json={"text": "powershell -enc Zg=="})
    assert response.status_code == 200
    assert any(item.get("mitre") == "T1059.001" for item in response.json()["findings"])


def test_heatmap():
    result = attack_heatmap([{"mitre": "T1566.002", "severity": "high"}])
    assert result[0]["technique_id"] == "T1566.002"
