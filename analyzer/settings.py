"""
Runtime configuration for the analyzer engine.

All tunables live in one place so the engine can be invoked identically
from the CLI, the FastAPI service, or any future caller. Construct a
Settings object directly, or use Settings.from_env() to load defaults
from environment variables (a .env file is loaded by main.py / api).
"""

import os
from dataclasses import dataclass, field, replace
from typing import Optional


@dataclass
class Settings:
    # --- External services ---------------------------------------------------
    vt_api_key: Optional[str] = None
    enable_vt: bool = True
    enable_dns: bool = True
    no_external: bool = False     # master switch: disables both DNS and VT

    # --- VirusTotal tuning ---------------------------------------------------
    vt_free_tier_delay: int = 15
    vt_max_retries: int = 3
    vt_request_timeout: int = 10
    vt_check_urls: bool = True
    vt_check_attachments: bool = True
    vt_upload_unknown_files: bool = False

    # --- Hashing -------------------------------------------------------------
    integrity_hash_algos: tuple = ("md5", "sha1", "sha256")

    # --- Reporting -----------------------------------------------------------
    pdf_max_indicators: int = 100

    @classmethod
    def from_env(cls, **overrides) -> "Settings":
        """Build a Settings instance from environment variables, with overrides."""
        base = cls(
            vt_api_key=os.getenv("VT_API_KEY"),
            enable_vt=_env_bool("ANALYZER_ENABLE_VT", True),
            enable_dns=_env_bool("ANALYZER_ENABLE_DNS", True),
            no_external=_env_bool("ANALYZER_NO_EXTERNAL", False),
            vt_check_urls=_env_bool("ANALYZER_VT_CHECK_URLS", True),
            vt_check_attachments=_env_bool("ANALYZER_VT_CHECK_ATTACHMENTS", True),
            vt_upload_unknown_files=_env_bool("ANALYZER_VT_UPLOAD", False),
        )
        return replace(base, **overrides) if overrides else base

    # --- Derived flags -------------------------------------------------------

    @property
    def dns_active(self) -> bool:
        return self.enable_dns and not self.no_external

    @property
    def vt_active(self) -> bool:
        return self.enable_vt and not self.no_external and bool(self.vt_api_key)

    @property
    def vt_url_active(self) -> bool:
        return self.vt_active and self.vt_check_urls

    @property
    def vt_attachment_active(self) -> bool:
        return self.vt_active and self.vt_check_attachments

    def summary(self) -> dict:
        """Compact serialisable view of effective configuration (no secrets)."""
        return {
            "no_external": self.no_external,
            "dns_active": self.dns_active,
            "vt_active": self.vt_active,
            "vt_url_active": self.vt_url_active,
            "vt_attachment_active": self.vt_attachment_active,
            "vt_upload_unknown_files": self.vt_upload_unknown_files,
        }


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")
