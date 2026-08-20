"""
FastAPI routes for ThreatFusion AI.

All endpoints use proper input validation, error handling, and logging.
"""

import logging
import asyncio
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.analysis import (
    AnalyzeRequest,
    AnalysisResponse,
    AnalysisHistoryItem,
    StatsResponse,
    HealthResponse,
)
from app.graph.workflow import run_analysis, get_memory_agent
from app.database.session import get_db
from app.services.analysis_service import (
    save_analysis,
    get_analysis_by_id,
    get_analysis_history,
    get_stats,
    delete_analysis_by_id,
    clear_all_history,
)
from app.services.sample_data import ALL_SAMPLES
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_EMAIL_BODY_SIZE = settings.max_email_size_kb * 1024


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check system component status."""
    memory_agent = get_memory_agent()

    gemini_status = "connected" if settings.gemini_available else "unavailable (fallback mode)"
    vt_status = "connected" if settings.virustotal_available else "unavailable (fallback mode)"

    try:
        chroma_count = memory_agent.get_collection_count()
        chroma_status = f"ready ({chroma_count} records)"
    except Exception:
        chroma_status = "unavailable"

    return HealthResponse(
        status="healthy",
        gemini=gemini_status,
        virustotal=vt_status,
        chromadb=chroma_status,
        database="healthy",
    )


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyze an email for phishing and social engineering threats.
    
    Runs all four agents concurrently and returns a comprehensive analysis.
    """
    # Input validation
    email = request.email
    body = email.body or ""

    if len(body.encode()) > MAX_EMAIL_BODY_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Email body exceeds maximum size of {settings.max_email_size_kb}KB"
        )

    if not any([email.from_address, email.subject, email.body]):
        raise HTTPException(
            status_code=400,
            detail="Email must contain at least one of: from, subject, body"
        )

    # Build email dict for analysis pipeline
    email_dict = {
        "from_address": email.from_address,
        "to": email.to,
        "reply_to": email.reply_to,
        "subject": email.subject,
        "body": email.body,
        "headers": email.headers,
    }

    logger.info(f"Analysis request: from='{email.from_address}' subject='{email.subject[:50]}'")

    try:
        result = await asyncio.wait_for(
            run_analysis(email_dict),
            timeout=settings.analysis_timeout_seconds
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="Analysis timed out — email may be too complex for current timeout settings"
        )
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Analysis pipeline error — please try again"
        )

    # Persist result
    try:
        await save_analysis(db, result)
    except Exception as e:
        logger.warning(f"Failed to persist analysis: {e}")
        # Don't fail the request if persistence fails

    return result


@router.post("/analyze/file", response_model=AnalysisResponse)
async def analyze_email_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload and analyze a .eml file."""
    # Validate file type
    if not file.filename.lower().endswith('.eml'):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    # Read file with size limit
    content = await file.read(MAX_EMAIL_BODY_SIZE + 1)
    if len(content) > MAX_EMAIL_BODY_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {settings.max_email_size_kb}KB"
        )

    logger.info(f"EML file analysis: {file.filename} ({len(content)} bytes)")

    try:
        raw_email = content.decode('utf-8', errors='replace')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not decode file: {e}")

    try:
        result = await asyncio.wait_for(
            run_analysis(raw_email),
            timeout=settings.analysis_timeout_seconds
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Analysis timed out")
    except Exception as e:
        logger.error(f"File analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Analysis pipeline error")

    try:
        await save_analysis(db, result)
    except Exception as e:
        logger.warning(f"Failed to persist file analysis: {e}")

    return result


@router.get("/history", response_model=List[AnalysisHistoryItem])
async def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Get paginated analysis history."""
    return await get_analysis_history(db, limit=limit, offset=offset)


@router.delete("/history")
async def clear_history(db: AsyncSession = Depends(get_db)):
    """Delete all analysis records from history."""
    count = await clear_all_history(db)
    return {"message": "History cleared successfully", "deleted_count": count}


@router.get("/analysis/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve a specific analysis by ID."""
    result = await get_analysis_by_id(db, analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


@router.delete("/analysis/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a specific analysis by ID."""
    success = await delete_analysis_by_id(db, analysis_id)
    if not success:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"message": f"Analysis {analysis_id} deleted successfully"}




@router.get("/stats", response_model=StatsResponse)
async def get_statistics(db: AsyncSession = Depends(get_db)):
    """Get aggregate statistics across all analyses."""
    memory_agent = get_memory_agent()
    chroma_available = memory_agent.get_collection_count() >= 0

    return await get_stats(db, chroma_available=chroma_available)


@router.post("/memory/initialize")
async def initialize_memory():
    """
    Initialize ChromaDB with sample phishing data.
    Should be run once before using the similarity search feature.
    """
    memory_agent = get_memory_agent()

    if not memory_agent._memory_available:
        raise HTTPException(
            status_code=503,
            detail="ChromaDB is unavailable — cannot initialize memory"
        )

    try:
        ingested = memory_agent.ingest_sample_data(ALL_SAMPLES)
        total = memory_agent.get_collection_count()

        return {
            "success": True,
            "samples_ingested": ingested,
            "total_records": total,
            "message": f"Successfully ingested {ingested} samples. Memory database now contains {total} records.",
        }
    except Exception as e:
        logger.error(f"Memory initialization failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Memory initialization failed: {str(e)}"
        )


@router.get("/memory/status")
async def memory_status():
    """Get ChromaDB memory status."""
    memory_agent = get_memory_agent()
    count = memory_agent.get_collection_count()

    return {
        "available": memory_agent._memory_available,
        "record_count": count,
        "initialized": count > 0,
        "similarity_threshold": settings.rag_similarity_threshold,
        "top_k": settings.rag_top_k,
    }


@router.get("/demo/emails")
async def get_demo_emails():
    """Get list of available demo email scenarios."""
    from app.services.demo_emails import DEMO_SCENARIOS
    return {
        "scenarios": [
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "expected_classification": s["expected_classification"],
                "category": s["category"],
            }
            for s in DEMO_SCENARIOS
        ]
    }


@router.get("/demo/emails/{scenario_id}")
async def get_demo_email(scenario_id: str):
    """Get a specific demo email scenario."""
    from app.services.demo_emails import DEMO_SCENARIOS
    scenario = next((s for s in DEMO_SCENARIOS if s["id"] == scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="Demo scenario not found")
    return scenario
