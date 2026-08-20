"""Integration tests for the FastAPI endpoints."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_health_endpoint(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "gemini" in data
    assert "virustotal" in data
    assert "chromadb" in data


@pytest.mark.asyncio
async def test_analyze_valid_email(client):
    payload = {
        "email": {
            "from": "security@paypa1-alerts.com",
            "subject": "Urgent: Account limited",
            "body": "Click here to verify your account immediately: http://paypa1.tk/verify",
            "reply_to": "steal@evil.com",
        }
    }
    resp = await client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "fusion_result" in data
    assert "risk_score" in data["fusion_result"]
    assert data["fusion_result"]["risk_score"] >= 0
    assert data["fusion_result"]["classification"] in ("SAFE", "SUSPICIOUS", "HIGH RISK", "CRITICAL")


@pytest.mark.asyncio
async def test_analyze_empty_email_rejected(client):
    payload = {"email": {"from": "", "subject": "", "body": ""}}
    resp = await client.post("/api/analyze", json=payload)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_analyze_oversized_email_rejected(client):
    payload = {
        "email": {
            "from": "x@example.com",
            "subject": "big",
            "body": "A" * (600 * 1024),  # 600 KB
        }
    }
    resp = await client.post("/api/analyze", json=payload)
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_stats_endpoint(client):
    resp = await client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_analyzed" in data
    assert "gemini_available" in data


@pytest.mark.asyncio
async def test_history_endpoint(client):
    resp = await client.get("/api/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_memory_status_endpoint(client):
    resp = await client.get("/api/memory/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "available" in data
    assert "record_count" in data


@pytest.mark.asyncio
async def test_demo_emails_endpoint(client):
    resp = await client.get("/api/demo/emails")
    assert resp.status_code == 200
    data = resp.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 5


@pytest.mark.asyncio
async def test_demo_email_by_id(client):
    resp = await client.get("/api/demo/emails/demo_paypal_phishing")
    assert resp.status_code == 200
    data = resp.json()
    assert "email" in data
    assert "expected_classification" in data


@pytest.mark.asyncio
async def test_unknown_analysis_id_returns_404(client):
    resp = await client.get("/api/analysis/nonexistent-id-00000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_legitimate_email_lower_score(client):
    payload = {
        "email": {
            "from": "newsletter@cs.mit.edu",
            "subject": "CS Department: Monthly Newsletter",
            "body": "Dear students, please join us for the research symposium on Friday at 2pm in Building 32.",
        }
    }
    resp = await client.post("/api/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    score = data["fusion_result"]["risk_score"]
    classification = data["fusion_result"]["classification"]
    assert score < 60 or classification in ("SAFE", "SUSPICIOUS")
