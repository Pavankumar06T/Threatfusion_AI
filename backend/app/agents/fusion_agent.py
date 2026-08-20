"""
Fusion Agent — combines results from all specialized agents into a final verdict.

Uses transparent weighted scoring, not a black-box LLM decision.
Weights are configurable via settings.
"""

import logging
from typing import Dict, List
from datetime import datetime

from app.schemas.analysis import (
    FusionResult,
    RiskClassification,
    HeaderAgentResult,
    ContentAgentResult,
    URLAgentResult,
    MemoryAgentResult,
    EvidenceEvent,
)
from app.config import settings

logger = logging.getLogger(__name__)


class FusionAgent:
    """
    Combines all agent results into a final explainable verdict.
    Uses a transparent weighted scoring mechanism.
    """

    def __init__(self):
        self.weights = {
            "header": settings.weight_header,
            "content": settings.weight_content,
            "url": settings.weight_url,
            "memory": settings.weight_memory,
        }

    def analyze(
        self,
        header_result: HeaderAgentResult,
        content_result: ContentAgentResult,
        url_result: URLAgentResult,
        memory_result: MemoryAgentResult,
        evidence_timeline: List[EvidenceEvent],
    ) -> FusionResult:
        """Combine all agent results into a final assessment."""
        logger.info("Fusion agent: combining agent results")

        # Weighted score calculation
        raw_score = (
            header_result.risk_score * self.weights["header"] +
            content_result.risk_score * self.weights["content"] +
            url_result.risk_score * self.weights["url"] +
            memory_result.risk_score * self.weights["memory"]
        )

        # Deterministic adjustments based on critical signals
        adjustment = 0
        adjustment_reasons = []

        # Boost: confirmed malicious URLs
        if url_result.malicious_urls:
            boost = min(len(url_result.malicious_urls) * 10, 25)
            adjustment += boost
            adjustment_reasons.append(f"+{boost} for {len(url_result.malicious_urls)} malicious URL(s)")

        # Boost: display name spoofing + suspicious domain (strong indicator)
        if header_result.display_name_spoofing and header_result.suspicious_domain:
            adjustment += 15
            adjustment_reasons.append("+15 for display-name spoofing + suspicious domain")

        # Boost: reply-to mismatch + credential harvesting
        if header_result.reply_to_mismatch and content_result.credential_harvesting:
            adjustment += 10
            adjustment_reasons.append("+10 for reply-to mismatch + credential harvesting")

        # Boost: confirmed campaign match (memory)
        if memory_result.campaign_match and memory_result.highest_similarity >= 0.85:
            adjustment += 15
            adjustment_reasons.append("+15 for confirmed campaign match with high similarity")

        # Reduction: no suspicious signals at all
        if (
            header_result.risk_score < 10 and
            content_result.risk_score < 10 and
            url_result.risk_score < 10 and
            memory_result.risk_score < 10
        ):
            adjustment -= 10
            adjustment_reasons.append("-10 for low risk across all agents")

        final_score = min(max(int(raw_score + adjustment), 0), 100)
        classification = self._classify(final_score)
        confidence = self._calculate_confidence(
            header_result, content_result, url_result, memory_result
        )

        key_reasons = self._extract_key_reasons(
            header_result, content_result, url_result, memory_result
        )
        recommended_action = self._recommended_action(classification)
        summary = self._build_summary(
            classification, final_score, header_result, content_result,
            url_result, memory_result
        )
        explanation = self._build_explanation(
            classification, key_reasons, header_result,
            content_result, url_result, memory_result
        )

        agent_breakdown = {
            "header": {
                "score": header_result.risk_score,
                "weight": self.weights["header"],
                "weighted_contribution": round(header_result.risk_score * self.weights["header"], 1),
                "confidence": header_result.confidence,
                "key_findings": header_result.findings[:3],
            },
            "content": {
                "score": content_result.risk_score,
                "weight": self.weights["content"],
                "weighted_contribution": round(content_result.risk_score * self.weights["content"], 1),
                "confidence": content_result.confidence,
                "key_findings": content_result.findings[:3],
            },
            "url": {
                "score": url_result.risk_score,
                "weight": self.weights["url"],
                "weighted_contribution": round(url_result.risk_score * self.weights["url"], 1),
                "confidence": url_result.confidence,
                "key_findings": url_result.findings[:3],
            },
            "memory": {
                "score": memory_result.risk_score,
                "weight": self.weights["memory"],
                "weighted_contribution": round(memory_result.risk_score * self.weights["memory"], 1),
                "confidence": memory_result.confidence,
                "key_findings": memory_result.findings[:3],
            },
            "raw_weighted_score": round(raw_score, 1),
            "adjustments": adjustment_reasons,
            "final_score": final_score,
        }

        external_services = {
            "gemini": settings.gemini_available,
            "virustotal": settings.virustotal_available,
            "chromadb": memory_result.memory_available,
        }

        logger.info(
            f"Fusion agent: FINAL score={final_score}, "
            f"classification={classification}, confidence={confidence:.2f}"
        )

        return FusionResult(
            risk_score=final_score,
            classification=classification,
            confidence=confidence,
            summary=summary,
            key_reasons=key_reasons,
            agent_breakdown=agent_breakdown,
            evidence=evidence_timeline,
            recommended_action=recommended_action,
            explanation=explanation,
            external_services_used=external_services,
        )

    def _classify(self, score: int) -> RiskClassification:
        """Map numeric score to risk classification."""
        if score < settings.threshold_safe:
            return RiskClassification.SAFE
        elif score < settings.threshold_suspicious:
            return RiskClassification.SUSPICIOUS
        elif score < settings.threshold_high_risk:
            return RiskClassification.HIGH_RISK
        else:
            return RiskClassification.CRITICAL

    def _calculate_confidence(
        self,
        header: HeaderAgentResult,
        content: ContentAgentResult,
        url: URLAgentResult,
        memory: MemoryAgentResult,
    ) -> float:
        """Weighted average of agent confidences."""
        conf = (
            header.confidence * self.weights["header"] +
            content.confidence * self.weights["content"] +
            url.confidence * self.weights["url"] +
            memory.confidence * self.weights["memory"]
        )
        return round(min(max(conf, 0.0), 1.0), 3)

    def _extract_key_reasons(
        self,
        header: HeaderAgentResult,
        content: ContentAgentResult,
        url: URLAgentResult,
        memory: MemoryAgentResult,
    ) -> List[str]:
        """Extract the most important reasons for the verdict."""
        reasons = []

        # Header reasons
        if header.display_name_spoofing:
            reasons.append(
                f"Sender display name impersonates a legitimate brand but email originates from '{header.sender_domain}'"
            )
        if header.domain_typosquatting:
            reasons.append(f"Sender domain '{header.sender_domain}' appears to be a typosquatted version of a legitimate domain")
        if header.reply_to_mismatch:
            reasons.append(f"Reply-To domain '{header.reply_to_domain}' differs from the sender domain — replies would go to an attacker")
        if header.authentication_issues:
            reasons.append(f"Email failed authentication: {', '.join(header.authentication_issues)}")

        # Content reasons
        if content.credential_harvesting:
            reasons.append("Email requests credentials or login verification — classic phishing pattern")
        if content.authority_impersonation:
            reasons.append("Email impersonates authority figures (IT, management, government, banks)")
        if content.urgency_detected:
            reasons.append("Email uses artificial urgency to pressure the recipient into immediate action")
        if "prompt_injection_attempt" in (content.tactics or []):
            reasons.append("Email contains text designed to manipulate AI-based security systems")

        # URL reasons
        if url.malicious_urls:
            reasons.append(f"{len(url.malicious_urls)} URL(s) identified as malicious or highly suspicious")
        if url.virustotal_results:
            flagged = [r for r in url.virustotal_results if r.get("malicious", 0) > 0]
            if flagged:
                reasons.append(f"VirusTotal: {flagged[0].get('malicious')} security engines flagged a URL in this email")

        # Memory reasons
        if memory.campaign_match:
            reasons.append(
                f"Email closely resembles the '{memory.campaign_match}' phishing campaign "
                f"({memory.highest_similarity:.0%} similarity)"
            )

        return reasons[:7]  # Top 7 reasons

    def _recommended_action(self, classification: RiskClassification) -> str:
        """Return recommended action based on classification."""
        actions = {
            RiskClassification.SAFE: (
                "Email appears legitimate. Exercise normal caution before clicking links or providing information."
            ),
            RiskClassification.SUSPICIOUS: (
                "Treat with caution. Verify sender identity through official channels before taking any action. "
                "Do not click links or provide personal information."
            ),
            RiskClassification.HIGH_RISK: (
                "Do NOT interact with this email. Report to your IT security team. "
                "Do not click any links, open attachments, or reply. Move to spam/junk."
            ),
            RiskClassification.CRITICAL: (
                "IMMEDIATE THREAT — Delete this email. Do not click links or open attachments. "
                "Report to your IT/security team immediately. If credentials were already entered, "
                "change passwords and enable 2FA on all affected accounts NOW."
            ),
        }
        return actions.get(classification, "Exercise caution.")

    def _build_summary(
        self,
        classification: RiskClassification,
        score: int,
        header: HeaderAgentResult,
        content: ContentAgentResult,
        url: URLAgentResult,
        memory: MemoryAgentResult,
    ) -> str:
        """Build a one-paragraph summary of the analysis."""
        signal_count = sum([
            header.risk_score >= 30,
            content.risk_score >= 30,
            url.risk_score >= 30,
            memory.risk_score >= 30,
        ])

        if classification == RiskClassification.SAFE:
            return (
                f"ThreatFusion AI analyzed this email and assessed it as SAFE with a risk score of {score}/100. "
                "No significant phishing or social engineering indicators were detected across the four analysis agents."
            )
        elif classification == RiskClassification.SUSPICIOUS:
            return (
                f"ThreatFusion AI assessed this email as SUSPICIOUS with a risk score of {score}/100. "
                f"{signal_count} out of 4 agents detected potential threats. Exercise caution."
            )
        elif classification == RiskClassification.HIGH_RISK:
            return (
                f"ThreatFusion AI assessed this email as HIGH RISK with a risk score of {score}/100. "
                f"Multiple agents detected significant phishing indicators. This email should not be trusted."
            )
        else:
            return (
                f"ThreatFusion AI assessed this email as a CRITICAL THREAT with a risk score of {score}/100. "
                "All indicators point to a coordinated phishing attack. This email must be quarantined immediately."
            )

    def _build_explanation(
        self,
        classification: RiskClassification,
        key_reasons: List[str],
        header: HeaderAgentResult,
        content: ContentAgentResult,
        url: URLAgentResult,
        memory: MemoryAgentResult,
    ) -> str:
        """Build a human-readable explanation for non-security experts."""
        if not key_reasons:
            return (
                "No significant threats were detected. The email's sender, content, links, "
                "and similarity to known phishing campaigns all appear within normal parameters."
            )

        intro = {
            RiskClassification.SAFE: "While this email appears safe, here is what was checked",
            RiskClassification.SUSPICIOUS: "This email raised concerns for the following reasons",
            RiskClassification.HIGH_RISK: "This email shows multiple serious warning signs",
            RiskClassification.CRITICAL: "This email is almost certainly a phishing attack",
        }.get(classification, "Analysis findings")

        reasons_text = "; ".join(key_reasons[:4])
        return f"{intro}: {reasons_text}."
