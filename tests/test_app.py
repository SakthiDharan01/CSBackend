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
