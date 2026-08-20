"""SQLAlchemy ORM models for analysis persistence."""

from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    email_from = Column(String, default="")
    email_to = Column(String, default="")
    email_subject = Column(String, default="")
    email_body_preview = Column(String, default="")

    # Agent scores
    header_score = Column(Integer, default=0)
    content_score = Column(Integer, default=0)
    url_score = Column(Integer, default=0)
    memory_score = Column(Integer, default=0)

    # Final verdict
    risk_score = Column(Integer, default=0)
    classification = Column(String, default="SAFE")
    confidence = Column(Float, default=0.0)
    summary = Column(Text, default="")
    recommended_action = Column(Text, default="")
    explanation = Column(Text, default="")

    # Full JSON result stored as text
    full_result_json = Column(Text, default="")

    # Metadata
    processing_time_ms = Column(Integer, default=0)
    fallback_mode = Column(Boolean, default=False)
