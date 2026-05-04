"""
Analyzer engine — single orchestrator for the full pipeline.

The engine is the only entry point that any caller (CLI, FastAPI service,
test, future GUI) should use. It owns the order of operations:

    integrity hash → parse → auth → urls → attachments → scoring

and returns an :class:`AnalysisResult` that is fully serialisable.

External I/O (DNS lookups, VirusTotal calls) is gated by Settings, so the
exact same engine call works in `--no-external` / local-only mode.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .attachments import AttachmentAnalysisResult, analyze_attachments
from .auth_checks import AuthCheckResult, run_auth_checks
from .indicators import ScoringResult, score_email
from .parser import EmailData, parse_email_bytes
from .settings import Settings
from .url_extractor import URLExtractionResult, extract_and_analyze_urls


ProgressFn = Callable[[str], None]


@dataclass
class IntegrityInfo:
    """Cryptographic fingerprint of the original .eml input.

    Persisted in the JSON / PDF report so a downstream consumer can verify
    that the file they hold is byte-identical to the one that was analysed.
    """
    source_filename: Optional[str]
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    analyzed_at: str  # ISO-8601 UTC


@dataclass
class AnalysisResult:
    integrity: IntegrityInfo
    email: EmailData
    auth: AuthCheckResult
    urls: URLExtractionResult
    attachments: AttachmentAnalysisResult
    scoring: ScoringResult
    settings_summary: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_email_file(
    path: str | Path,
    settings: Optional[Settings] = None,
    *,
    progress: Optional[ProgressFn] = None,
) -> AnalysisResult:
    """Read a .eml file from disk and run the full analysis pipeline."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Email file not found: {p}")
    raw = p.read_bytes()
    return analyze_email_bytes(
        raw,
        settings=settings,
        source_filename=p.name,
        progress=progress,
    )


def analyze_email_bytes(
    raw_bytes: bytes,
    settings: Optional[Settings] = None,
    *,
    source_filename: Optional[str] = None,
    progress: Optional[ProgressFn] = None,
) -> AnalysisResult:
    """Run the full analysis pipeline against raw .eml bytes.

    This is the path the API hits — no filesystem assumptions are made.
    """
    settings = settings or Settings.from_env()
    notify = progress or (lambda _msg: None)

    notify("Hashing source bytes")
    integrity = _compute_integrity(raw_bytes, source_filename)

    notify("Parsing email")
    email_data = parse_email_bytes(raw_bytes)

    notify(f"Running auth checks (DNS {'on' if settings.dns_active else 'off'})")
    auth_result = run_auth_checks(email_data, dns_enabled=settings.dns_active)

    notify("Extracting URLs")
    url_result = extract_and_analyze_urls(email_data.body_plain, email_data.body_html)

    if settings.vt_url_active and url_result.urls:
        _enrich_urls_with_vt(url_result, settings, notify)

    notify("Analyzing attachments")
    attachment_result = analyze_attachments(email_data, settings, progress=notify)

    notify("Computing risk score")
    scoring_result = score_email(email_data, auth_result, url_result, attachment_result)

    return AnalysisResult(
        integrity=integrity,
        email=email_data,
        auth=auth_result,
        urls=url_result,
        attachments=attachment_result,
        scoring=scoring_result,
        settings_summary=settings.summary(),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_integrity(raw_bytes: bytes, source_filename: Optional[str]) -> IntegrityInfo:
    return IntegrityInfo(
        source_filename=source_filename,
        size_bytes=len(raw_bytes),
        md5=hashlib.md5(raw_bytes).hexdigest(),
        sha1=hashlib.sha1(raw_bytes).hexdigest(),
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )


def _enrich_urls_with_vt(
    url_result: URLExtractionResult,
    settings: Settings,
    notify: ProgressFn,
) -> None:
    # Lazy import — keeps the offline / no-VT path independent of `requests`.
    from . import threat_intel

    notify(f"Querying VirusTotal for {len(url_result.urls)} URL(s)")
    vt_results = threat_intel.check_urls(
        [u.url for u in url_result.urls],
        settings.vt_api_key,
        free_tier_delay=settings.vt_free_tier_delay,
        max_retries=settings.vt_max_retries,
        request_timeout=settings.vt_request_timeout,
    )
    for u in url_result.urls:
        vt = vt_results.get(u.url)
        if not vt:
            continue
        u.vt_result = vt.to_dict()
        if vt.malicious > 0:
            u.flags.append(f"VirusTotal: flagged malicious by {vt.malicious} engine(s)")
    # Recompute suspicious count after VT enrichment
    url_result.suspicious_count = sum(1 for u in url_result.urls if u.flags)
