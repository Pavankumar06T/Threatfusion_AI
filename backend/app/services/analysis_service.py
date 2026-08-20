"""Service layer for analysis persistence and retrieval."""

import json
import logging
from typing import List, Optional
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import AnalysisRecord
from app.schemas.analysis import (
    AnalysisResponse,
    AnalysisHistoryItem,
    StatsResponse,
    RiskClassification,
)
from app.config import settings

logger = logging.getLogger(__name__)


async def save_analysis(db: AsyncSession, analysis: AnalysisResponse) -> AnalysisRecord:
    """Persist an analysis result to the database."""
    try:
        record = AnalysisRecord(
            id=analysis.id,
            timestamp=analysis.timestamp,
            email_from=analysis.email_from[:255] if analysis.email_from else "",
            email_subject=analysis.email_subject[:255] if analysis.email_subject else "",
            email_body_preview="",  # Don't store body for privacy

            header_score=analysis.header_result.risk_score,
            content_score=analysis.content_result.risk_score,
            url_score=analysis.url_result.risk_score,
            memory_score=analysis.memory_result.risk_score,

            risk_score=analysis.fusion_result.risk_score,
            classification=analysis.fusion_result.classification.value,
            confidence=analysis.fusion_result.confidence,
            summary=analysis.fusion_result.summary[:1000],
            recommended_action=analysis.fusion_result.recommended_action[:500],
            explanation=analysis.fusion_result.explanation[:1000],

            full_result_json=analysis.model_dump_json(),
            processing_time_ms=analysis.processing_time_ms,
            fallback_mode=analysis.fallback_mode,
        )

        db.add(record)
        await db.flush()
        return record

    except Exception as e:
        logger.error(f"Failed to save analysis: {e}")
        raise


async def get_analysis_by_id(db: AsyncSession, analysis_id: str) -> Optional[AnalysisResponse]:
    """Retrieve a full analysis result by ID."""
    try:
        result = await db.execute(
            select(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
        )
        record = result.scalar_one_or_none()

        if not record:
            return None

        return AnalysisResponse.model_validate_json(record.full_result_json)

    except Exception as e:
        logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")
        return None


async def get_analysis_history(
    db: AsyncSession,
    limit: int = 50,
    offset: int = 0
) -> List[AnalysisHistoryItem]:
    """Get paginated analysis history."""
    try:
        result = await db.execute(
            select(AnalysisRecord)
            .order_by(desc(AnalysisRecord.timestamp))
            .limit(limit)
            .offset(offset)
        )
        records = result.scalars().all()

        return [
            AnalysisHistoryItem(
                id=r.id,
                timestamp=r.timestamp,
                email_from=r.email_from,
                email_subject=r.email_subject,
                risk_score=r.risk_score,
                classification=RiskClassification(r.classification),
                confidence=r.confidence,
            )
            for r in records
        ]

    except Exception as e:
        logger.error(f"Failed to retrieve history: {e}")
        return []


async def get_stats(db: AsyncSession, chroma_available: bool) -> StatsResponse:
    """Get aggregate statistics about all analyses."""
    try:
        total_result = await db.execute(select(func.count(AnalysisRecord.id)))
        total = total_result.scalar() or 0

        critical_result = await db.execute(
            select(func.count(AnalysisRecord.id)).where(AnalysisRecord.classification == "CRITICAL")
        )
        critical = critical_result.scalar() or 0

        high_result = await db.execute(
            select(func.count(AnalysisRecord.id)).where(AnalysisRecord.classification == "HIGH RISK")
        )
        high_risk = high_result.scalar() or 0

        suspicious_result = await db.execute(
            select(func.count(AnalysisRecord.id)).where(AnalysisRecord.classification == "SUSPICIOUS")
        )
        suspicious = suspicious_result.scalar() or 0

        safe_result = await db.execute(
            select(func.count(AnalysisRecord.id)).where(AnalysisRecord.classification == "SAFE")
        )
        safe = safe_result.scalar() or 0

        avg_result = await db.execute(select(func.avg(AnalysisRecord.risk_score)))
        avg_score = avg_result.scalar() or 0.0

        return StatsResponse(
            total_analyzed=total,
            critical_count=critical,
            high_risk_count=high_risk,
            suspicious_count=suspicious,
            safe_count=safe,
            avg_risk_score=round(float(avg_score), 1),
            gemini_available=settings.gemini_available,
            virustotal_available=settings.virustotal_available,
            chroma_available=chroma_available,
            db_healthy=True,
        )

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        return StatsResponse(
            total_analyzed=0,
            critical_count=0,
            high_risk_count=0,
            suspicious_count=0,
            safe_count=0,
            avg_risk_score=0.0,
            gemini_available=settings.gemini_available,
            virustotal_available=settings.virustotal_available,
            chroma_available=chroma_available,
            db_healthy=False,
        )


async def delete_analysis_by_id(db: AsyncSession, analysis_id: str) -> bool:
    """Delete a specific analysis record by ID."""
    try:
        result = await db.execute(
            select(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
        )
        record = result.scalar_one_or_none()
        if not record:
            return False

        await db.delete(record)
        await db.flush()
        return True
    except Exception as e:
        logger.error(f"Failed to delete analysis {analysis_id}: {e}")
        return False


async def clear_all_history(db: AsyncSession) -> int:
    """Delete all analysis records from history and return count deleted."""
    try:
        result = await db.execute(select(AnalysisRecord))
        records = result.scalars().all()
        count = len(records)
        for record in records:
            await db.delete(record)
        await db.flush()
        return count
    except Exception as e:
        logger.error(f"Failed to clear history: {e}")
        return 0

