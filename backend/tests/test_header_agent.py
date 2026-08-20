"""Tests for the Header / Metadata Agent."""

import pytest
from app.agents.header_agent import HeaderMetadataAgent


@pytest.fixture
def agent():
    return HeaderMetadataAgent()


def _parsed(from_email="", from_display="", reply_to="", reply_to_email="",
            subject="", spf="", dkim="", dmarc=""):
    return {
        "from_email": from_email,
        "from_display_name": from_display,
        "from_address": f'"{from_display}" <{from_email}>' if from_display else from_email,
        "reply_to": reply_to,
        "reply_to_email": reply_to_email,
        "subject": subject,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }


# ── Display name spoofing ──────────────────────────────────────────────────────

def test_display_name_spoofing_detected(agent):
    result = agent.analyze(_parsed(
        from_email="security@paypa1-alerts.com",
        from_display="PayPal Security",
    ))
    assert result.display_name_spoofing is True
    assert result.risk_score > 20


def test_legitimate_sender_no_spoofing(agent):
    result = agent.analyze(_parsed(
        from_email="noreply@github.com",
        from_display="GitHub",
    ))
    assert result.display_name_spoofing is False


# ── Reply-To mismatch ──────────────────────────────────────────────────────────

def test_reply_to_mismatch_detected(agent):
    result = agent.analyze(_parsed(
        from_email="support@paypal.com",
        reply_to="collect@attacker.xyz",
        reply_to_email="collect@attacker.xyz",
    ))
    assert result.reply_to_mismatch is True
    assert result.risk_score > 20


def test_same_domain_no_mismatch(agent):
    result = agent.analyze(_parsed(
        from_email="billing@company.com",
        reply_to="billing-replies@company.com",
        reply_to_email="billing-replies@company.com",
    ))
    assert result.reply_to_mismatch is False


# ── Typosquatting ──────────────────────────────────────────────────────────────

def test_typosquatting_detected(agent):
    result = agent.analyze(_parsed(from_email="security@paypa1.com"))
    assert result.domain_typosquatting is True or result.suspicious_domain is True
    assert result.risk_score > 30


def test_hyphenated_brand_domain(agent):
    result = agent.analyze(_parsed(from_email="noreply@microsoft-login-secure.com"))
    assert result.suspicious_domain is True


def test_legitimate_domain_not_flagged(agent):
    result = agent.analyze(_parsed(from_email="noreply@github.com"))
    assert result.risk_score < 30


# ── Authentication failures ────────────────────────────────────────────────────

def test_spf_fail_increases_score(agent):
    result_fail = agent.analyze(_parsed(from_email="x@example.com", spf="fail"))
    result_pass = agent.analyze(_parsed(from_email="x@example.com", spf="pass"))
    assert result_fail.risk_score > result_pass.risk_score
    assert "SPF FAIL" in result_fail.authentication_issues


def test_dkim_fail_increases_score(agent):
    result = agent.analyze(_parsed(from_email="x@example.com", dkim="fail"))
    assert "DKIM FAIL" in result.authentication_issues


# ── Suspicious subject ─────────────────────────────────────────────────────────

def test_urgent_subject_flagged(agent):
    result = agent.analyze(_parsed(
        from_email="x@example.com",
        subject="URGENT ACTION REQUIRED: Verify your account",
    ))
    assert result.risk_score > 10


# ── Combined high-risk scenario ────────────────────────────────────────────────

def test_full_phishing_headers_high_score(agent):
    result = agent.analyze(_parsed(
        from_email="security@paypa1-alerts.com",
        from_display="PayPal Security",
        reply_to="harvest@evilsite.tk",
        reply_to_email="harvest@evilsite.tk",
        subject="Urgent: Account limited",
        spf="fail",
    ))
    assert result.risk_score >= 60
    assert result.display_name_spoofing is True
    assert result.reply_to_mismatch is True
