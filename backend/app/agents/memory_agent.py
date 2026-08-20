"""
Agent 4: Memory / RAG Agent

Uses ChromaDB for historical phishing campaign similarity search.
Provides context from past known-malicious emails.
"""

import json
import logging
import uuid
from typing import Dict, List, Optional
from datetime import datetime

from app.schemas.analysis import MemoryAgentResult, SimilarEmail
from app.config import settings

logger = logging.getLogger(__name__)

COLLECTION_NAME = "phishing_memory"


class MemoryRAGAgent:
    """
    Retrieves similar historical phishing emails using vector similarity search.
    Falls back to empty-memory mode if ChromaDB is unavailable.
    """

    def __init__(self):
        self.agent_name = "memory_rag"
        self._client = None
        self._collection = None
        self._embedding_fn = None
        self._memory_available = False
        self._initialize()

    def _initialize(self):
        """Initialize ChromaDB and embedding function."""
        try:
            import chromadb
            from chromadb.utils import embedding_functions

            self._client = chromadb.PersistentClient(
                path=settings.chroma_persist_directory
            )

            # Use sentence-transformers for embeddings (local, no API needed)
            self._embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )

            self._collection = self._client.get_or_create_collection(
                name=COLLECTION_NAME,
                embedding_function=self._embedding_fn,
                metadata={"description": "ThreatFusion phishing campaign memory"}
            )

            count = self._collection.count()
            self._memory_available = True
            logger.info(f"Memory agent: ChromaDB initialized with {count} records")

        except Exception as e:
            logger.warning(f"Memory agent: ChromaDB initialization failed: {e}")
            self._memory_available = False

    def analyze(self, parsed_email: Dict) -> MemoryAgentResult:
        """Search for similar historical phishing campaigns."""
        logger.info("Memory agent: starting similarity search")

        if not self._memory_available:
            logger.info("Memory agent: operating in empty-memory fallback mode")
            return MemoryAgentResult(
                agent=self.agent_name,
                risk_score=0,
                confidence=0.3,
                findings=["Historical threat memory unavailable — similarity search skipped"],
                memory_available=False,
                metadata={"fallback": True}
            )

        # Build search query from email features
        query_text = self._build_query(parsed_email)

        if not query_text.strip():
            return MemoryAgentResult(
                agent=self.agent_name,
                risk_score=0,
                confidence=0.5,
                findings=["Insufficient email content for similarity search"],
                memory_available=True,
            )

        count = self._collection.count()
        if count == 0:
            return MemoryAgentResult(
                agent=self.agent_name,
                risk_score=0,
                confidence=0.5,
                findings=["Threat memory database is empty — run /api/memory/initialize first"],
                memory_available=True,
                metadata={"db_count": 0}
            )

        try:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=min(settings.rag_top_k, count),
                include=["documents", "metadatas", "distances"]
            )

            similar_emails = []
            max_similarity = 0.0
            risk_score = 0
            findings = []
            evidence = []

            if results and results["ids"] and results["ids"][0]:
                for i, doc_id in enumerate(results["ids"][0]):
                    # ChromaDB returns L2 distances — convert to similarity score
                    distance = results["distances"][0][i]
                    # Convert distance to similarity (0-1, higher = more similar)
                    similarity = max(0.0, 1.0 - (distance / 2.0))

                    metadata = results["metadatas"][0][i]
                    document = results["documents"][0][i]

                    if similarity >= 0.40:  # Only report meaningful matches
                        similar_email = SimilarEmail(
                            id=doc_id,
                            similarity=round(similarity, 3),
                            subject=metadata.get("subject", "Unknown"),
                            campaign=metadata.get("campaign", "Unknown Campaign"),
                            attack_type=metadata.get("attack_type", "Unknown"),
                            risk_level=metadata.get("risk_level", "HIGH"),
                            description=metadata.get("description", ""),
                        )
                        similar_emails.append(similar_email)
                        max_similarity = max(max_similarity, similarity)

                        if similarity >= settings.rag_similarity_threshold:
                            findings.append(
                                f"High similarity ({similarity:.0%}) to '{metadata.get('campaign', 'known campaign')}'"
                            )
                            evidence.append(
                                f"Campaign: {metadata.get('campaign')} | "
                                f"Attack Type: {metadata.get('attack_type')} | "
                                f"Similarity: {similarity:.0%}"
                            )

            # Risk adjustment based on similarity
            if max_similarity >= 0.90:
                risk_score = 80
                findings.append("Extremely high similarity to confirmed phishing campaign")
            elif max_similarity >= 0.80:
                risk_score = 65
            elif max_similarity >= settings.rag_similarity_threshold:
                risk_score = 50
            elif max_similarity >= 0.50:
                risk_score = 30
                findings.append(f"Moderate similarity to known phishing patterns ({max_similarity:.0%})")
            elif max_similarity >= 0.40:
                risk_score = 15

            campaign_match = None
            if similar_emails:
                top_match = similar_emails[0]
                if top_match.similarity >= settings.rag_similarity_threshold:
                    campaign_match = top_match.campaign

            confidence = 0.70 + (max_similarity * 0.25) if similar_emails else 0.60

            logger.info(
                f"Memory agent: score={risk_score}, "
                f"max_similarity={max_similarity:.2f}, "
                f"matches={len(similar_emails)}"
            )

            return MemoryAgentResult(
                agent=self.agent_name,
                risk_score=risk_score,
                confidence=min(confidence, 0.95),
                findings=findings,
                evidence=evidence,
                indicators=[f"similarity_{e.campaign.lower().replace(' ', '_')}" for e in similar_emails[:2]],
                similar_emails=similar_emails,
                highest_similarity=max_similarity,
                campaign_match=campaign_match,
                memory_available=True,
                metadata={"db_count": count, "matches_found": len(similar_emails)},
                recommendations=self._build_recommendations(similar_emails, max_similarity),
            )

        except Exception as e:
            logger.error(f"Memory agent: similarity search failed: {e}")
            return MemoryAgentResult(
                agent=self.agent_name,
                risk_score=0,
                confidence=0.3,
                findings=[f"Similarity search failed: {str(e)[:100]}"],
                memory_available=True,
                metadata={"error": str(e)[:200]}
            )

    def store_analysis(self, parsed_email: Dict, analysis_id: str, risk_level: str):
        """Store analyzed email in memory for future reference."""
        if not self._memory_available or not self._collection:
            return

        try:
            query_text = self._build_query(parsed_email)
            if not query_text.strip():
                return

            metadata = {
                "subject": parsed_email.get("subject", "")[:200],
                "sender_domain": parsed_email.get("from_email", "").split("@")[-1] if "@" in parsed_email.get("from_email", "") else "",
                "campaign": "User-submitted analysis",
                "attack_type": "Unknown",
                "risk_level": risk_level,
                "description": f"Analyzed on {datetime.utcnow().isoformat()}",
                "source": "user_analysis",
                "timestamp": datetime.utcnow().isoformat(),
            }

            self._collection.add(
                documents=[query_text],
                metadatas=[metadata],
                ids=[analysis_id],
            )
        except Exception as e:
            logger.warning(f"Memory agent: store failed: {e}")

    def ingest_sample_data(self, samples: List[Dict]) -> int:
        """Ingest sample phishing data into ChromaDB."""
        if not self._memory_available or not self._collection:
            logger.error("Memory agent: ChromaDB unavailable for ingestion")
            return 0

        ingested = 0
        for sample in samples:
            try:
                doc_text = self._build_query_from_sample(sample)
                if not doc_text.strip():
                    continue

                metadata = {
                    "subject": sample.get("subject", "")[:200],
                    "sender": sample.get("from", "")[:200],
                    "campaign": sample.get("campaign", "Unknown")[:200],
                    "attack_type": sample.get("attack_type", "Unknown")[:100],
                    "risk_level": sample.get("risk_level", "HIGH")[:20],
                    "description": sample.get("description", "")[:500],
                    "source": sample.get("source", "demo_data")[:100],
                    "timestamp": datetime.utcnow().isoformat(),
                }

                doc_id = sample.get("id") or str(uuid.uuid4())

                # Check if already exists
                existing = self._collection.get(ids=[doc_id])
                if existing["ids"]:
                    continue

                self._collection.add(
                    documents=[doc_text],
                    metadatas=[metadata],
                    ids=[doc_id],
                )
                ingested += 1

            except Exception as e:
                logger.warning(f"Memory agent: failed to ingest sample: {e}")
                continue

        logger.info(f"Memory agent: ingested {ingested} samples")
        return ingested

    def get_collection_count(self) -> int:
        """Get the number of records in the memory database."""
        if not self._memory_available or not self._collection:
            return 0
        try:
            return self._collection.count()
        except Exception:
            return 0

    def _build_query(self, parsed_email: Dict) -> str:
        """Build a text query from parsed email for similarity search."""
        parts = []
        if parsed_email.get("subject"):
            parts.append(f"Subject: {parsed_email['subject']}")
        if parsed_email.get("from_email"):
            parts.append(f"From: {parsed_email['from_email']}")
        if parsed_email.get("body_text"):
            # Use first 1000 chars of body
            body_preview = parsed_email["body_text"][:1000]
            parts.append(f"Body: {body_preview}")
        if parsed_email.get("all_urls"):
            parts.append(f"URLs: {' '.join(parsed_email['all_urls'][:5])}")
        return "\n".join(parts)

    def _build_query_from_sample(self, sample: Dict) -> str:
        """Build query text from a sample data dict."""
        parts = []
        if sample.get("subject"):
            parts.append(f"Subject: {sample['subject']}")
        if sample.get("from"):
            parts.append(f"From: {sample['from']}")
        if sample.get("body"):
            parts.append(f"Body: {sample['body'][:1000]}")
        if sample.get("urls"):
            parts.append(f"URLs: {' '.join(sample['urls'][:5])}")
        return "\n".join(parts)

    def _build_recommendations(self, similar_emails: List[SimilarEmail], max_similarity: float) -> List[str]:
        """Build recommendations based on similarity results."""
        recs = []
        if max_similarity >= settings.rag_similarity_threshold:
            recs.append(
                "This email strongly resembles a known phishing campaign — treat as malicious"
            )
        elif max_similarity >= 0.50:
            recs.append(
                "This email has patterns in common with known phishing emails — exercise caution"
            )
        return recs
