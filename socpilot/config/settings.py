"""
SOCPilot AI — Application Settings
===================================
Centralised configuration loaded from environment variables / .env file.
Uses pydantic-settings for type-safe, validated configuration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """
    All runtime configuration for SOCPilot AI.

    Values are read from environment variables (case-insensitive) or from
    a .env file in the current working directory.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── LLM ─────────────────────────────────────────────────────────────────
    groq_api_key: str = Field(
        default="",
        description="Groq API key. Required for LLM inference.",
    )
    groq_model: str = Field(
        default="llama-3.3-70b-versatile",
        description="Groq model identifier.",
    )

    # ── Threat Intelligence ──────────────────────────────────────────────────
    abuseipdb_api_key: str = Field(
        default="",
        description="AbuseIPDB API key for IP reputation lookups.",
    )
    virustotal_api_key: str = Field(
        default="",
        description="VirusTotal API key for file hash lookups.",
    )
    nvd_api_key: str = Field(
        default="",
        description="NVD NIST API key for CVE lookups (optional, rate-limited without).",
    )

    # ── Storage ──────────────────────────────────────────────────────────────
    chroma_persist_dir: str = Field(
        default="./chroma_db",
        description="Filesystem path for ChromaDB persistence.",
    )
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2",
        description="HuggingFace sentence-transformer model for embeddings.",
    )

    # ── Reports ──────────────────────────────────────────────────────────────
    reports_dir: str = Field(
        default="./reports",
        description="Directory where generated SOC reports are saved.",
    )

    # ── Logging ──────────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Log level for the application.",
    )

    # ── SIEM Integration Server ───────────────────────────────────────────────
    siem_server_host: str = Field(
        default="0.0.0.0",
        description="Host address for the SIEM integration webhook server.",
    )
    siem_server_port: int = Field(
        default=8000,
        description="Port for the SIEM integration webhook server.",
    )
    wazuh_min_alert_level: int = Field(
        default=5,
        description=(
            "Minimum Wazuh alert level (1-15) required to trigger an investigation. "
            "Alerts below this level are silently dropped."
        ),
    )
    wazuh_webhook_token: str = Field(
        default="",
        description=(
            "Optional shared secret for webhook authentication. "
            "When set, all /webhook/* requests must include "
            "'Authorization: Bearer <token>' header."
        ),
    )

    # ── Derived properties ───────────────────────────────────────────────────

    @property
    def chroma_persist_path(self) -> Path:
        """Resolved Path object for ChromaDB persistence directory."""
        return Path(self.chroma_persist_dir).resolve()

    @property
    def reports_path(self) -> Path:
        """Resolved Path object for report output directory."""
        return Path(self.reports_dir).resolve()

    @property
    def has_groq_key(self) -> bool:
        return bool(self.groq_api_key and self.groq_api_key != "your_groq_api_key_here")

    @property
    def has_abuseipdb_key(self) -> bool:
        return bool(
            self.abuseipdb_api_key
            and self.abuseipdb_api_key != "your_abuseipdb_key_here"
        )

    @property
    def has_virustotal_key(self) -> bool:
        return bool(
            self.virustotal_api_key
            and self.virustotal_api_key != "your_virustotal_key_here"
        )

    @property
    def has_nvd_key(self) -> bool:
        return bool(
            self.nvd_api_key and self.nvd_api_key != "your_nvd_api_key_here"
        )

    @field_validator("groq_model")
    @classmethod
    def validate_model(cls, v: str) -> str:
        known_models = {
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "llama-3.1-70b-versatile",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
        }
        if v not in known_models:
            # Allow unknown models — Groq may add new ones
            pass
        return v


# ── Singleton ─────────────────────────────────────────────────────────────────
# Import this instance everywhere; do not re-instantiate.
settings = AppSettings()
