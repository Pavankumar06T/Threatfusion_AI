"""
LangGraph orchestration workflow for ThreatFusion AI.

Runs Header, Content, URL, and Memory agents, then combines with Fusion Agent.
Agents run concurrently where possible.
"""

import asyncio
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Any

from app.agents import (
    HeaderMetadataAgent,
    ContentLinguisticAgent,
    URLThreatAgent,
    MemoryRAGAgent,
    FusionAgent,
)
from app.schemas.analysis import (
    AnalysisResponse,
    EvidenceEvent,
)
from app.utils.email_parser import parse_structured_email, parse_email_string
from app.config import settings

logger = logging.getLogger(__name__)

# Singleton agent instances (reuse across requests)
_header_agent = None
_content_agent = None
_url_agent = None
_memory_agent = None
_fusion_agent = None
_executor = ThreadPoolExecutor(max_workers=4)


def get_agents():
    """Get or initialize agent singletons."""
    global _header_agent, _content_agent, _url_agent, _memory_agent, _fusion_agent
    if _header_agent is None:
        logger.info("Initializing agents...")
        _header_agent = HeaderMetadataAgent()
        _content_agent = ContentLinguisticAgent()
        _url_agent = URLThreatAgent()
        _memory_agent = MemoryRAGAgent()
        _fusion_agent = FusionAgent()
        logger.info("All agents initialized")
    return _header_agent, _content_agent, _url_agent, _memory_agent, _fusion_agent


async def run_analysis(email_data: Dict) -> AnalysisResponse:
    """
    Main analysis orchestration using concurrent agent execution.
    
    Pipeline:
    1. Parse email
    2. Run Header, Content, URL agents concurrently
    3. Run Memory agent (needs parsed email)
    4. Run Fusion agent
    5. Return complete analysis
    """
    start_time = datetime.utcnow()
    analysis_id = str(uuid.uuid4())
    evidence_timeline = []
    fallback_reasons = []

    def add_event(event: str, detail: str = ""):
        evidence_timeline.append(EvidenceEvent(
            timestamp=datetime.utcnow().strftime("%H:%M:%S"),
            event=event,
            detail=detail,
        ))

    add_event("Analysis started", f"ID: {analysis_id}")

    # Parse email
    try:
        if isinstance(email_data, str):
            parsed = parse_email_string(email_data)
        else:
            parsed = parse_structured_email(email_data)
        add_event("Email parsed", f"From: {parsed.get('from_email', 'unknown')}")
    except Exception as e:
        logger.error(f"Email parsing failed: {e}")
        parsed = {
            "from_email": email_data.get("from_address", "") if isinstance(email_data, dict) else "",
            "subject": email_data.get("subject", "") if isinstance(email_data, dict) else "",
            "body_text": email_data.get("body", "") if isinstance(email_data, dict) else str(email_data),
            "all_urls": [],
        }
        fallback_reasons.append("Email parsing used fallback mode")

    header_agent, content_agent, url_agent, memory_agent, fusion_agent = get_agents()

    # Run Header, Content, URL agents concurrently using thread pool
    # (Agents are CPU-bound or I/O bound — use executor for thread safety)
    loop = asyncio.get_event_loop()

    try:
        header_future = loop.run_in_executor(_executor, header_agent.analyze, parsed)
        content_future = loop.run_in_executor(_executor, content_agent.analyze, parsed)
        url_future = loop.run_in_executor(_executor, url_agent.analyze, parsed)

        # Await all three concurrently
        header_result, content_result, url_result = await asyncio.gather(
            header_future, content_future, url_future,
            return_exceptions=True
        )

        # Handle exceptions from individual agents
        if isinstance(header_result, Exception):
            logger.error(f"Header agent failed: {header_result}")
            from app.schemas.analysis import HeaderAgentResult
            header_result = HeaderAgentResult(
                agent="header_metadata", risk_score=0, confidence=0.3,
                findings=[f"Header analysis failed: {str(header_result)[:100]}"],
                metadata={"error": True}
            )

        if isinstance(content_result, Exception):
            logger.error(f"Content agent failed: {content_result}")
            from app.schemas.analysis import ContentAgentResult
            content_result = ContentAgentResult(
                agent="content_linguistic", risk_score=0, confidence=0.3,
                findings=[f"Content analysis failed: {str(content_result)[:100]}"],
                metadata={"error": True}
            )

        if isinstance(url_result, Exception):
            logger.error(f"URL agent failed: {url_result}")
            from app.schemas.analysis import URLAgentResult
            url_result = URLAgentResult(
                agent="url_threat", risk_score=0, confidence=0.3,
                findings=[f"URL analysis failed: {str(url_result)[:100]}"],
                metadata={"error": True}
            )

    except Exception as e:
        logger.error(f"Concurrent agent execution failed: {e}")
        from app.schemas.analysis import HeaderAgentResult, ContentAgentResult, URLAgentResult
        header_result = HeaderAgentResult(agent="header_metadata", risk_score=0, confidence=0.1, findings=["Error"])
        content_result = ContentAgentResult(agent="content_linguistic", risk_score=0, confidence=0.1, findings=["Error"])
        url_result = URLAgentResult(agent="url_threat", risk_score=0, confidence=0.1, findings=["Error"])
        fallback_reasons.append("Agent execution encountered errors")

    add_event("Header analysis completed", f"Risk: {header_result.risk_score}/100")
    add_event("Content analysis completed", f"Risk: {content_result.risk_score}/100")
    add_event(
        f"URL analysis completed",
        f"{len(url_result.urls_found)} URLs found, {len(url_result.malicious_urls)} flagged"
    )

    if url_result.virustotal_results:
        add_event("VirusTotal lookup completed", f"{len(url_result.virustotal_results)} URLs checked")
    elif not settings.virustotal_available:
        add_event("VirusTotal unavailable", "Local heuristic URL analysis used")
        fallback_reasons.append("VirusTotal unavailable — local URL analysis used")

    if not settings.gemini_available:
        fallback_reasons.append("Gemini unavailable — heuristic content analysis used")
        add_event("Gemini unavailable", "Deterministic content analysis used")

    # Memory agent (sequential — depends on parsed email)
    try:
        memory_result = await loop.run_in_executor(_executor, memory_agent.analyze, parsed)
        add_event(
            "Similarity search completed",
            f"Best match: {memory_result.highest_similarity:.0%}" if memory_result.similar_emails else "No significant matches"
        )
    except Exception as e:
        logger.error(f"Memory agent failed: {e}")
        from app.schemas.analysis import MemoryAgentResult
        memory_result = MemoryAgentResult(
            agent="memory_rag", risk_score=0, confidence=0.3,
            findings=["Memory search failed"],
            memory_available=False,
        )

    if not memory_result.memory_available:
        fallback_reasons.append("ChromaDB unavailable — similarity search skipped")

    # Fusion agent
    try:
        add_event("Fusion analysis started", "Combining agent results")
        fusion_result = fusion_agent.analyze(
            header_result=header_result,
            content_result=content_result,
            url_result=url_result,
            memory_result=memory_result,
            evidence_timeline=evidence_timeline,
        )
        add_event(
            "Analysis complete",
            f"Classification: {fusion_result.classification} | Score: {fusion_result.risk_score}/100"
        )
    except Exception as e:
        logger.error(f"Fusion agent failed: {e}")
        from app.schemas.analysis import FusionResult, RiskClassification
        fusion_result = FusionResult(
            risk_score=0,
            classification=RiskClassification.SAFE,
            confidence=0.1,
            summary="Analysis failed",
            key_reasons=["Analysis pipeline error"],
            agent_breakdown={},
            evidence=evidence_timeline,
            recommended_action="Unable to analyze",
            explanation="The analysis pipeline encountered an error.",
        )

    # Store in memory for future similarity search
    try:
        if fusion_result.classification.value in ("HIGH RISK", "CRITICAL"):
            memory_agent.store_analysis(parsed, analysis_id, fusion_result.classification.value)
    except Exception:
        pass

    end_time = datetime.utcnow()
    processing_time_ms = int((end_time - start_time).total_seconds() * 1000)

    is_fallback = len(fallback_reasons) > 0

    return AnalysisResponse(
        id=analysis_id,
        timestamp=start_time,
        email_subject=parsed.get("subject", ""),
        email_from=parsed.get("from_email", ""),
        header_result=header_result,
        content_result=content_result,
        url_result=url_result,
        memory_result=memory_result,
        fusion_result=fusion_result,
        processing_time_ms=processing_time_ms,
        fallback_mode=is_fallback,
        fallback_reasons=fallback_reasons,
    )


def get_memory_agent() -> MemoryRAGAgent:
    """Get the memory agent instance."""
    _, _, _, memory_agent, _ = get_agents()
    return memory_agent
