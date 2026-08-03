"""
SOCPilot AI — Long-Term Memory (ChromaDB)
==========================================
Manages two ChromaDB collections:

  incidents       — Past SOC investigation reports stored as vector embeddings.
                    Used to retrieve semantically similar historical cases.

  knowledge_base  — Curated cybersecurity documentation (MITRE summaries,
                    malware descriptions, TTP context) for RAG retrieval.

Both collections persist to disk at the path configured in settings.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

import chromadb
from chromadb import Collection
from chromadb.config import Settings as ChromaSettings
from langchain_huggingface import HuggingFaceEmbeddings

from socpilot.config.settings import settings

logger = logging.getLogger(__name__)

# Collection name constants
INCIDENTS_COLLECTION = "incidents"
KNOWLEDGE_BASE_COLLECTION = "knowledge_base"


class ChromaLongTermMemory:
    """
    Persistent long-term memory backed by ChromaDB.

    Provides two separate namespaces:
      - incidents: historical SOC investigation cases
      - knowledge_base: cybersecurity reference documentation

    Uses HuggingFace sentence-transformer embeddings for semantic search.
    """

    def __init__(self) -> None:
        # Ensure persistence directory exists
        settings.chroma_persist_path.mkdir(parents=True, exist_ok=True)

        # Initialise ChromaDB persistent client
        self._client = chromadb.PersistentClient(
            path=str(settings.chroma_persist_path),
            settings=ChromaSettings(anonymized_telemetry=False),
        )

        # Load HuggingFace embedding function
        # ChromaDB requires its own embedding function wrapper
        self._embedding_fn = _HuggingFaceChromaEmbedder(settings.embedding_model)

        # Get or create collections
        self._incidents: Collection = self._client.get_or_create_collection(
            name=INCIDENTS_COLLECTION,
            embedding_function=self._embedding_fn,  # type: ignore[arg-type]
            metadata={"description": "Historical SOC investigation reports"},
        )
        self._knowledge_base: Collection = self._client.get_or_create_collection(
            name=KNOWLEDGE_BASE_COLLECTION,
            embedding_function=self._embedding_fn,  # type: ignore[arg-type]
            metadata={"description": "Cybersecurity reference knowledge"},
        )

        logger.info(
            "ChromaDB initialised at %s | incidents=%d | knowledge=%d",
            settings.chroma_persist_path,
            self._incidents.count(),
            self._knowledge_base.count(),
        )

    # ── Incidents ─────────────────────────────────────────────────────────────

    def add_incident(
        self,
        summary: str,
        iocs: List[str],
        report_id: str,
        severity: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store a completed SOC investigation as a historical incident.

        Args:
            summary: Text summary of the incident (used for embeddings).
            iocs: List of IoCs involved (stored in metadata).
            report_id: Unique report identifier.
            severity: Severity level string.
            metadata: Additional key-value metadata.

        Returns:
            The document ID used in ChromaDB.
        """
        doc_id = f"incident-{report_id}"
        meta = {
            "report_id": report_id,
            "severity": severity,
            "iocs": ", ".join(iocs[:20]),  # ChromaDB metadata must be strings
            **(metadata or {}),
        }
        self._incidents.upsert(
            ids=[doc_id],
            documents=[summary],
            metadatas=[meta],
        )
        logger.debug("Stored incident %s in ChromaDB", doc_id)
        return doc_id

    def query_incidents(
        self,
        query_text: str,
        n_results: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve semantically similar historical incidents.

        Args:
            query_text: The current alert text or IoC summary to search with.
            n_results: Maximum number of incidents to retrieve.

        Returns:
            List of dicts with 'document', 'metadata', and 'distance' keys.
        """
        count = self._incidents.count()
        if count == 0:
            return []

        results = self._incidents.query(
            query_texts=[query_text],
            n_results=min(n_results, count),
            include=["documents", "metadatas", "distances"],
        )

        incidents = []
        if results["documents"] and results["documents"][0]:
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            ):
                incidents.append(
                    {
                        "document": doc,
                        "metadata": meta,
                        "distance": dist,
                        # Convert cosine distance to similarity score
                        "similarity": max(0.0, 1.0 - dist),
                    }
                )
        return incidents

    # ── Knowledge Base ────────────────────────────────────────────────────────

    def add_knowledge(
        self,
        text: str,
        doc_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Add a cybersecurity knowledge document to the knowledge base.

        Args:
            text: The document content.
            doc_id: Optional stable identifier. Auto-generated if not provided.
            metadata: Optional key-value metadata (category, source, etc.).

        Returns:
            The document ID used in ChromaDB.
        """
        if doc_id is None:
            doc_id = f"doc-{uuid.uuid4().hex[:12]}"

        self._knowledge_base.upsert(
            ids=[doc_id],
            documents=[text],
            metadatas=[metadata or {}],
        )
        logger.debug("Stored knowledge doc %s", doc_id)
        return doc_id

    def query_knowledge(
        self,
        query_text: str,
        n_results: int = 5,
    ) -> List[str]:
        """
        Retrieve relevant cybersecurity knowledge documents.

        Args:
            query_text: The query to search with (alert text or IoC description).
            n_results: Maximum number of documents to retrieve.

        Returns:
            List of document text strings.
        """
        count = self._knowledge_base.count()
        if count == 0:
            return []

        results = self._knowledge_base.query(
            query_texts=[query_text],
            n_results=min(n_results, count),
            include=["documents"],
        )
        if results["documents"] and results["documents"][0]:
            return results["documents"][0]
        return []

    def get_knowledge_collection(self) -> Collection:
        """Return the raw ChromaDB knowledge_base collection (for LangChain retriever)."""
        return self._knowledge_base

    @property
    def incident_count(self) -> int:
        return self._incidents.count()

    @property
    def knowledge_count(self) -> int:
        return self._knowledge_base.count()


# ── Custom embedding function for ChromaDB ────────────────────────────────────


class _HuggingFaceChromaEmbedder:
    """
    Adapts LangChain's HuggingFaceEmbeddings to ChromaDB's EmbeddingFunction API.

    ChromaDB expects an object with a __call__ method that takes List[str]
    and returns List[List[float]]. LangChain's HuggingFaceEmbeddings provides
    embed_documents() which has the same signature.
    """

    def __init__(self, model_name: str) -> None:
        self._model_name = model_name
        self._model = HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )

    def name(self) -> str:
        return self._model_name

    def __call__(self, input: List[str]) -> List[List[float]]:  # noqa: A002
        return self._model.embed_documents(input)


# ── Singleton ─────────────────────────────────────────────────────────────────
_long_term_memory: ChromaLongTermMemory | None = None


def get_long_term_memory() -> ChromaLongTermMemory:
    """Return the singleton ChromaLongTermMemory instance."""
    global _long_term_memory
    if _long_term_memory is None:
        _long_term_memory = ChromaLongTermMemory()
    return _long_term_memory
