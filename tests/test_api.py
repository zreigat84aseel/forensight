"""Unit tests for the REST API (FastAPI test client, no real server needed)."""

import json

import pytest
from fastapi.testclient import TestClient

from forensight import api

EMAIL = (b"From: Bank Security <alerts@bank-secure.top>\r\n"
         b"Reply-To: collect@evil-mail.xyz\r\n"
         b"To: customer@example.com\r\n"
         b"Subject: Your account is suspended\r\n"
         b"Date: Mon, 19 Oct 2026 10:00:00 +0000\r\n"
         b"Content-Type: text/plain\r\n\r\n"
         b"Verify your account today at https://fake-bank.top/login\r\n")
CAMPAIGN = {"id": "C900", "size": 3, "first_seen": None, "last_seen": None, "emails": ["a.eml"],
            "indicators": [{"type": "reply_to", "value": "collect@evil-mail.xyz", "emails": 3}]}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FORENSIGHT_API_KEY", raising=False)
    campaigns = tmp_path / "campaigns.json"
    campaigns.write_text(json.dumps({"summary": {"campaigns": 1}, "campaigns": [CAMPAIGN]}))
    monkeypatch.setattr(api, "CAMPAIGNS_FILE", campaigns)
    return TestClient(api.app)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok" and response.json()["campaigns_loaded"] == 1


def test_analyze_returns_score_and_campaign(client):
    response = client.post("/analyze", files={"file": ("new.eml", EMAIL, "message/rfc822")})
    assert response.status_code == 200
    body = response.json()
    assert 0 <= body["score"] <= 100 and body["verdict"]
    assert len(body["evidence"]["sha256"]) == 64
    assert [c["id"] for c in body["campaigns"]] == ["C900"]          # matched by its reply-to address


def test_report_returns_html(client):
    response = client.post("/report", files={"file": ("new.eml", EMAIL, "message/rfc822")})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Forensic Report" in response.text and "default-src 'none'" in response.text


def test_rejects_wrong_type_and_empty_file(client):
    assert client.post("/analyze", files={"file": ("x.exe", b"MZ", "application/octet-stream")}).status_code == 415
    assert client.post("/analyze", files={"file": ("x.eml", b"", "message/rfc822")}).status_code == 400


def test_rejects_too_large_file(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 10)
    response = client.post("/analyze", files={"file": ("big.eml", EMAIL, "message/rfc822")})
    assert response.status_code == 413


def test_campaigns_and_rules(client):
    assert client.get("/campaigns").json()["campaigns"][0]["id"] == "C900"
    assert client.get("/campaigns/c900").json()["size"] == 3
    assert client.get("/campaigns/C999").status_code == 404
    yara = client.get("/campaigns/C900/rules/yara")
    assert yara.status_code == 200 and "rule Forensight_Campaign_C900_Email" in yara.text
    assert "logsource" in client.get("/campaigns/C900/rules/sigma").text
    assert json.loads(client.get("/campaigns/C900/rules/stix").text)["type"] == "bundle"
    assert client.get("/campaigns/C900/rules/exe").status_code == 400


def test_api_key_is_required_when_configured(client, monkeypatch):
    monkeypatch.setenv("FORENSIGHT_API_KEY", "s3cret-key")
    assert client.get("/health").status_code == 401
    assert client.get("/health", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/health", headers={"X-API-Key": "s3cret-key"}).status_code == 200
