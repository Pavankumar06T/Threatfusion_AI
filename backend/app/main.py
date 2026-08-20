"""
ThreatFusion AI — Backend Entry Point
Multi-Agent System for Explainable Phishing & Social Engineering Detection
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.config import settings
from app.database.session import init_db
from app.api.routes import router
from app.graph.workflow import get_agents  # pre-warm agents

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("threatfusion")


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("  ThreatFusion AI — Starting up")
    logger.info("=" * 60)

    # Init DB tables
    await init_db()
    logger.info("Database ready")

    # Pre-warm all agents so first request is fast
    get_agents()
    logger.info("All agents initialised")

    if not settings.gemini_available:
        logger.warning("GEMINI_API_KEY not set — content agent running in heuristic fallback mode")
    if not settings.virustotal_available:
        logger.warning("VIRUSTOTAL_API_KEY not set — URL agent running in local heuristic mode")

    logger.info(f"API docs → http://{settings.backend_host}:{settings.backend_port}/docs")
    logger.info("Ready to analyse emails ✓")
    logger.info("=" * 60)

    yield

    logger.info("ThreatFusion AI — Shutting down")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ThreatFusion AI",
    description=(
        "Multi-Agent System for Explainable Phishing & Social Engineering Detection. "
        "Four specialised agents — Header, Content, URL, Memory — feed a transparent "
        "Fusion Engine that returns an evidence-backed risk verdict."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────────
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ─────────────────────────────────────────────────────────────────────
app.include_router(router, prefix="/api")


@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": "ThreatFusion AI",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
    }
