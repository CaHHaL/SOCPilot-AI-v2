"""
SOCPilot AI — MultiQueryRetriever Factory
==========================================
Builds a LangChain MultiQueryRetriever backed by ChromaDB for cybersecurity
knowledge retrieval.

The MultiQueryRetriever generates multiple query variants from the user input,
runs each variant against ChromaDB, then returns the unique union of all results.
This overcomes vocabulary mismatch limitations in single-query similarity search,
which is especially important for cybersecurity jargon and mixed IoC/technique
terminology.
"""

from __future__ import annotations

import logging
from typing import List

from langchain_classic.retrievers.multi_query import MultiQueryRetriever
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain_core.language_models import BaseChatModel

from socpilot.config.settings import settings

logger = logging.getLogger(__name__)


def build_embedding_model() -> HuggingFaceEmbeddings:
    """
    Instantiate the HuggingFace embedding model used for all RAG operations.

    Returns a cached HuggingFaceEmbeddings instance configured for
    normalised embeddings (unit-sphere cosine similarity).
    """
    return HuggingFaceEmbeddings(
        model_name=settings.embedding_model,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


def build_knowledge_vectorstore(embedding_model: HuggingFaceEmbeddings) -> Chroma:
    """
    Connect to the knowledge_base ChromaDB collection via LangChain's Chroma wrapper.

    This provides a LangChain-native retriever interface over the same
    ChromaDB collection that ChromaLongTermMemory manages directly.

    Args:
        embedding_model: The HuggingFace embedding model instance.

    Returns:
        A Chroma vectorstore object.
    """
    from chromadb.config import Settings as ChromaSettings
    return Chroma(
        collection_name="knowledge_base",
        embedding_function=embedding_model,
        persist_directory=str(settings.chroma_persist_path),
        client_settings=ChromaSettings(anonymized_telemetry=False),
    )


def build_multi_query_retriever(
    llm: BaseChatModel,
    k: int = 5,
) -> MultiQueryRetriever:
    """
    Build and return a MultiQueryRetriever for the cybersecurity knowledge base.

    The MultiQueryRetriever works by:
    1. Taking the user's query (alert text or IoC description)
    2. Using the LLM to generate 3 semantically different query variants
    3. Running each variant through the ChromaDB vector search
    4. Deduplicating and returning the unique union of all results

    This is critical for cybersecurity RAG because:
    - Analysts may describe the same attack in different ways
    - IoC context ("185.120.33.8" vs "suspicious IP" vs "external connection")
      requires query expansion to retrieve all relevant knowledge

    Args:
        llm: A LangChain chat model for query generation.
        k: Number of documents to retrieve per generated query.

    Returns:
        A configured MultiQueryRetriever instance.
    """
    embedding_model = build_embedding_model()
    vectorstore = build_knowledge_vectorstore(embedding_model)
    base_retriever = vectorstore.as_retriever(
        search_type="similarity",
        search_kwargs={"k": k},
    )

    retriever = MultiQueryRetriever.from_llm(
        retriever=base_retriever,
        llm=llm,
        include_original=True,  # Also run the original query, not just variants
    )

    logger.info("MultiQueryRetriever built with k=%d documents per query", k)
    return retriever


def retrieve_knowledge(
    retriever: MultiQueryRetriever,
    query: str,
) -> List[Document]:
    """
    Run a query through the MultiQueryRetriever and return relevant documents.

    Args:
        retriever: The configured MultiQueryRetriever.
        query: The search query (typically alert text + IoC context).

    Returns:
        List of LangChain Document objects with content and metadata.
    """
    try:
        docs = retriever.invoke(query)
        logger.info("RAG retrieved %d unique documents for query", len(docs))
        return docs
    except Exception as e:
        logger.warning("RAG retrieval failed: %s", e)
        return []


def format_docs_as_context(docs: List[Document]) -> str:
    """
    Format a list of retrieved documents into a single context string.

    The context string is included in the reasoning prompt so the LLM
    can cite cybersecurity knowledge when forming its analysis.

    Args:
        docs: Retrieved Document objects.

    Returns:
        A formatted multi-section string suitable for prompt injection.
    """
    if not docs:
        return "No relevant cybersecurity knowledge was retrieved."

    sections = []
    for i, doc in enumerate(docs, 1):
        meta = doc.metadata
        category = meta.get("category", "general")
        technique = meta.get("technique_id", "")
        header = f"[Knowledge #{i}]"
        if technique:
            header += f" [{technique}]"
        header += f" [{category.upper()}]"
        sections.append(f"{header}\n{doc.page_content.strip()}")

    return "\n\n---\n\n".join(sections)
