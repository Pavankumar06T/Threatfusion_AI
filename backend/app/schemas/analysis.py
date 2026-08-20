"""Pydantic schemas for email analysis requests and responses."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class RiskClassification(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"


class EmailInput(BaseModel):
    from_address: str = Field("", alias="from")
    to: str = ""
    reply_to: str = ""
    subject: str = ""
    body: str = ""
    headers: Dict[str, str] = {}

    class Config:
        populate_by_name = True


class AnalyzeRequest(BaseModel):
    email: EmailInput


class AgentResult(BaseModel):
    agent: str
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    findings: List[str] = []
    indicators: List[str] = []
    evidence: List[str] = []
    recommendations: List[str] = []
    metadata: Dict[str, Any] = {}
    error: Optional[str] = None


class HeaderAgentResult(AgentResult):
    display_name_spoofing: bool = False
    reply_to_mismatch: bool = False
    suspicious_domain: bool = False
    domain_typosquatting: bool = False
    authentication_issues: List[str] = []
    sender_domain: str = ""
    reply_to_domain: str = ""


class ContentAgentResult(AgentResult):
    social_engineering: bool = False
    tactics: List[str] = []
    explanation: str = ""
    urgency_detected: bool = False
    credential_harvesting: bool = False
    authority_impersonation: bool = False


class URLInfo(BaseModel):
    url: str
    risk_score: int = 0
    is_malicious: bool = False
    is_suspicious: bool = False
    reasons: List[str] = []
    virustotal_result: Optional[Dict[str, Any]] = None


class URLAgentResult(AgentResult):
    urls_found: List[str] = []
    malicious_urls: List[URLInfo] = []
    suspicious_urls: List[URLInfo] = []
    virustotal_available: bool = False
    virustotal_results: List[Dict[str, Any]] = []


class SimilarEmail(BaseModel):
    id: str
    similarity: float
    subject: str
    campaign: str
    attack_type: str
    risk_level: str
    description: str


class MemoryAgentResult(AgentResult):
    similar_emails: List[SimilarEmail] = []
    highest_similarity: float = 0.0
    campaign_match: Optional[str] = None
    memory_available: bool = True


class EvidenceEvent(BaseModel):
    timestamp: str
    event: str
    detail: str = ""


class FusionResult(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    classification: RiskClassification
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    key_reasons: List[str]
    agent_breakdown: Dict[str, Any]
    evidence: List[EvidenceEvent]
    recommended_action: str
    explanation: str
    external_services_used: Dict[str, bool] = {}


class AnalysisResponse(BaseModel):
    id: str
    timestamp: datetime
    email_subject: str
    email_from: str
    header_result: HeaderAgentResult
    content_result: ContentAgentResult
    url_result: URLAgentResult
    memory_result: MemoryAgentResult
    fusion_result: FusionResult
    processing_time_ms: int
    fallback_mode: bool = False
    fallback_reasons: List[str] = []


class AnalysisHistoryItem(BaseModel):
    id: str
    timestamp: datetime
    email_from: str
    email_subject: str
    risk_score: int
    classification: RiskClassification
    confidence: float

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_analyzed: int
    critical_count: int
    high_risk_count: int
    suspicious_count: int
    safe_count: int
    avg_risk_score: float
    gemini_available: bool
    virustotal_available: bool
    chroma_available: bool
    db_healthy: bool


class HealthResponse(BaseModel):
    status: str
    gemini: str
    virustotal: str
    chromadb: str
    database: str
    version: str = "1.0.0"
