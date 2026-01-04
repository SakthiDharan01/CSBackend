from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


def test_email_security_score():
    payload = {"email": "test@example.com"}
    response = client.post("/security_score/email", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "email"
    assert body["target"] == payload["email"]


def test_website_security_score():
    payload = {"url": "https://example.com"}
    response = client.post("/security_score/website", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "website"
    assert body["target"] == payload["url"]


def test_smb_report_generation():
    payload = {"business_name": "Example LLC", "assets": ["website", "email"]}
    response = client.post("/smb/report_generation", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "generated"
    assert body["risk_level"]
    assert body["report_id"]


def test_email_analyze_endpoint_structure():
    payload = {"email": "test@example.com"}
    response = client.post("/security_score/email/analyze", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == payload["email"]
    assert "risk_score" in body
    assert body["risk_level"] in {"Low", "Medium", "High", "Critical"}
    assert isinstance(body.get("flags", []), list)
    assert isinstance(body.get("details", {}), dict)
    assert isinstance(body.get("sources", {}), dict)


def test_website_passive_assessment():
    payload = {"url": "https://example.com"}
    response = client.post("/security_score/assessment", json=payload)
    assert response.status_code == 200
    body = response.json()

    assert body["url"] == payload["url"]
    assert isinstance(body["open_ports"], list)
    assert isinstance(body["possible_vulnerabilities"], list)
    assert 0 <= body["security_score"] <= 100
    assert body["overall_risk"] in {"LOW", "MEDIUM", "HIGH"}
    assert isinstance(body["recommended_actions"], list)
    assert "disclaimer" in body
