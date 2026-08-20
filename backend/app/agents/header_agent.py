"""
Agent 1: Header / Metadata Agent

Analyzes email headers deterministically.
No LLM dependency — all rules-based.
"""

import re
import logging
from typing import Dict, List
from app.schemas.analysis import HeaderAgentResult
from app.utils.domain_analyzer import analyze_domain, compare_domains
from app.utils.email_parser import extract_domain_from_email

logger = logging.getLogger(__name__)

# Display name impersonation patterns
BRAND_DISPLAY_NAMES = [
    "paypal", "microsoft", "google", "apple", "amazon", "linkedin",
    "instagram", "facebook", "netflix", "dropbox", "chase", "wellsfargo",
    "bank of america", "irs", "dhl", "fedex", "ups", "usps", "docusign",
    "office365", "outlook", "onedrive", "sharepoint", "teams",
]

# Suspicious patterns in sender formatting
SUSPICIOUS_SENDER_PATTERNS = [
    r'noreply.*security',
    r'security.*alert',
    r'account.*verify',
    r'support.*team',
    r'helpdesk.*\d+',
    r'do-not-reply.*security',
]


class HeaderMetadataAgent:
    """
    Analyzes email headers using deterministic cybersecurity rules.
    Produces a structured risk assessment without LLM calls.
    """

    def __init__(self):
        self.agent_name = "header_metadata"

    def analyze(self, parsed_email: Dict) -> HeaderAgentResult:
        """Run all header analysis checks and return structured result."""
        logger.info("Header agent: starting analysis")

        findings = []
        indicators = []
        evidence = []
        recommendations = []
        risk_score = 0

        from_email = parsed_email.get("from_email", "")
        from_display_name = parsed_email.get("from_display_name", "")
        from_address = parsed_email.get("from_address", "")
        reply_to = parsed_email.get("reply_to", "")
        reply_to_email = parsed_email.get("reply_to_email", "")
        subject = parsed_email.get("subject", "")
        spf = parsed_email.get("spf", "")
        dkim = parsed_email.get("dkim", "")
        dmarc = parsed_email.get("dmarc", "")

        sender_domain = extract_domain_from_email(from_email)
        reply_to_domain = extract_domain_from_email(reply_to_email)

        # --- Check 1: Display name spoofing ---
        display_name_spoofing = False
        if from_display_name:
            display_lower = from_display_name.lower()
            for brand in BRAND_DISPLAY_NAMES:
                if brand in display_lower:
                    # Check if the actual sending domain matches the brand
                    brand_root = brand.replace(" ", "").replace("365", "").replace("online", "")
                    if brand_root and brand_root not in sender_domain.lower():
                        display_name_spoofing = True
                        findings.append(
                            f"Display name '{from_display_name}' impersonates '{brand}' but email comes from '{sender_domain}'"
                        )
                        indicators.append("display_name_spoofing")
                        evidence.append(f"From header: {from_address}")
                        risk_score += 35
                        break

        # --- Check 2: Reply-To mismatch ---
        reply_to_mismatch = False
        if reply_to_email and from_email:
            domain_comparison = compare_domains(sender_domain, reply_to_domain)
            if domain_comparison.get("mismatch"):
                reply_to_mismatch = True
                for reason in domain_comparison.get("reasons", []):
                    findings.append(reason)
                indicators.append("reply_to_mismatch")
                evidence.append(f"Reply-To: {reply_to}")
                risk_score += domain_comparison.get("risk_score", 30)

        # --- Check 3: Sender domain analysis ---
        sender_domain_result = {}
        suspicious_domain = False
        domain_typosquatting = False

        if sender_domain:
            sender_domain_result = analyze_domain(sender_domain)
            if sender_domain_result.get("is_suspicious"):
                suspicious_domain = True
                domain_typosquatting = sender_domain_result.get("is_typosquatting", False)
                for reason in sender_domain_result.get("reasons", []):
                    findings.append(reason)
                if domain_typosquatting:
                    indicators.append("typosquatting")
                indicators.append("suspicious_sender_domain")
                evidence.append(f"Sender domain: {sender_domain}")
                risk_score += sender_domain_result.get("risk_score", 0) * 0.7  # weighted

        # --- Check 4: Authentication failures ---
        authentication_issues = []
        if spf and spf.lower() in ("fail", "softfail"):
            authentication_issues.append(f"SPF {spf.upper()}")
            findings.append(f"SPF check {spf}: sender not authorized to send from this domain")
            indicators.append("spf_failure")
            risk_score += 20 if spf.lower() == "fail" else 10

        if dkim and dkim.lower() == "fail":
            authentication_issues.append("DKIM FAIL")
            findings.append("DKIM signature verification failed — email may have been tampered")
            indicators.append("dkim_failure")
            risk_score += 20

        if dmarc and dmarc.lower() == "fail":
            authentication_issues.append("DMARC FAIL")
            findings.append("DMARC policy check failed")
            indicators.append("dmarc_failure")
            risk_score += 15

        # --- Check 5: Suspicious sender formatting ---
        for pattern in SUSPICIOUS_SENDER_PATTERNS:
            if re.search(pattern, from_email.lower()):
                findings.append(f"Suspicious sender address pattern detected: {from_email}")
                indicators.append("suspicious_sender_format")
                risk_score += 15
                break

        # --- Check 6: Subject line heuristics ---
        subject_lower = subject.lower()
        urgent_subject_patterns = [
            ("urgent action required", 20),
            ("your account", 10),
            ("account suspended", 25),
            ("verify your", 15),
            ("click here", 10),
            ("confirm your", 15),
            ("limited time", 10),
            ("final notice", 20),
            ("security alert", 15),
            ("unusual activity", 15),
            ("update required", 10),
            ("action needed", 15),
        ]
        for pattern, score in urgent_subject_patterns:
            if pattern in subject_lower:
                findings.append(f"Suspicious subject pattern: '{pattern}'")
                indicators.append("suspicious_subject")
                risk_score += score
                break

        # --- Check 7: Homoglyph characters in display name ---
        if from_display_name:
            suspicious_chars = re.findall(r'[^\x00-\x7F]', from_display_name)
            if suspicious_chars:
                findings.append(
                    f"Non-ASCII characters in display name may be used for visual spoofing: {''.join(suspicious_chars)}"
                )
                indicators.append("homoglyph_display_name")
                risk_score += 25

        # --- Recommendations ---
        if display_name_spoofing:
            recommendations.append("Verify sender identity — display name does not match sending domain")
        if reply_to_mismatch:
            recommendations.append("Do NOT reply to this email — Reply-To leads to a different domain")
        if suspicious_domain:
            recommendations.append("The sender domain appears designed to impersonate a legitimate service")
        if authentication_issues:
            recommendations.append("Email failed authentication checks — high risk of spoofing or forgery")

        # Clamp and calculate confidence
        risk_score = min(int(risk_score), 100)
        confidence = self._calculate_confidence(
            display_name_spoofing, reply_to_mismatch, suspicious_domain, authentication_issues
        )

        logger.info(f"Header agent: score={risk_score}, confidence={confidence:.2f}")

        return HeaderAgentResult(
            agent=self.agent_name,
            risk_score=risk_score,
            confidence=confidence,
            findings=findings,
            indicators=indicators,
            evidence=evidence,
            recommendations=recommendations,
            display_name_spoofing=display_name_spoofing,
            reply_to_mismatch=reply_to_mismatch,
            suspicious_domain=suspicious_domain,
            domain_typosquatting=domain_typosquatting,
            authentication_issues=authentication_issues,
            sender_domain=sender_domain,
            reply_to_domain=reply_to_domain,
            metadata={
                "sender_domain_analysis": sender_domain_result,
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
            }
        )

    def _calculate_confidence(
        self,
        display_spoofing: bool,
        reply_mismatch: bool,
        suspicious_domain: bool,
        auth_issues: List[str],
    ) -> float:
        """
        Confidence is higher when multiple signals agree.
        Deterministic rules have inherently high confidence.
        """
        signals = sum([
            display_spoofing,
            reply_mismatch,
            suspicious_domain,
            len(auth_issues) > 0,
        ])
        # Base confidence of 0.70, increases with corroborating signals
        base = 0.70
        bonus = signals * 0.07
        return min(base + bonus, 0.97)
