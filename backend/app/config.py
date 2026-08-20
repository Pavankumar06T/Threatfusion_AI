"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # API Keys
    gemini_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # Storage
    chroma_persist_directory: str = "./chroma_data"
    database_url: str = "sqlite+aiosqlite:///./threatfusion.db"

    # Operational
    log_level: str = "INFO"
    max_email_size_kb: int = 512
    analysis_timeout_seconds: int = 60

    # Fusion weights (must sum to 1.0)
    weight_header: float = 0.25
    weight_content: float = 0.25
    weight_url: float = 0.30
    weight_memory: float = 0.20

    # Risk thresholds
    threshold_safe: int = 25
    threshold_suspicious: int = 50
    threshold_high_risk: int = 75

    # Gemini model
    gemini_model: str = "gemini-1.5-flash"

    # RAG settings
    rag_top_k: int = 5
    rag_similarity_threshold: float = 0.75

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

    @property
    def gemini_available(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def virustotal_available(self) -> bool:
        return bool(self.virustotal_api_key)


settings = Settings()
