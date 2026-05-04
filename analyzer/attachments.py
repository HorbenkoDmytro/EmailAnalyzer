"""
Attachment analysis module.

For every attachment found by the parser this module computes the standard
trio of cryptographic hashes (MD5 / SHA-1 / SHA-256), runs heuristic checks
on the filename, and (when allowed by Settings) queries VirusTotal — first
by hash lookup, optionally falling back to an upload if the hash is unknown.

The result is a structured AttachmentAnalysisResult that the indicator
engine can score and the reporter can render.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Optional

from .parser import Attachment, EmailData
from .settings import Settings
from .url_extractor import SUSPICIOUS_ATTACHMENT_EXTENSIONS


# Document/image extensions commonly used in "double-extension" tricks
# (e.g. invoice.pdf.exe). Used to flag filenames where a benign-looking
# inner extension is followed by an executable-like outer one.
COMMON_DOC_EXTENSIONS: set[str] = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
    "rtf", "csv", "jpg", "jpeg", "png", "gif", "zip", "rar", "7z",
}


@dataclass
class AttachmentReport:
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    extension: str                    # ".exe", ".pdf", ... or ""
    has_suspicious_extension: bool
    has_double_extension: bool
    flags: list[str] = field(default_factory=list)
    vt_result: Optional[dict] = None  # Populated when VT lookups are enabled
    vt_uploaded: bool = False         # True when the file was uploaded for scanning


@dataclass
class AttachmentAnalysisResult:
    attachments: list[AttachmentReport]
    total_count: int
    suspicious_count: int


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_attachments(
    email_data: EmailData,
    settings: Settings,
    *,
    progress: Optional[Callable[[str], None]] = None,
) -> AttachmentAnalysisResult:
    """Hash every attachment, flag suspicious filenames, and (optionally) check VT."""
    reports: list[AttachmentReport] = [
        _build_report(att) for att in email_data.attachments
    ]

    if reports and settings.vt_attachment_active:
        if progress:
            progress(f"Checking {len(reports)} attachment hash(es) on VirusTotal")
        _enrich_with_virustotal(reports, email_data.attachments, settings, progress)

    suspicious_count = sum(1 for r in reports if r.flags)
    return AttachmentAnalysisResult(
        attachments=reports,
        total_count=len(reports),
        suspicious_count=suspicious_count,
    )


# ---------------------------------------------------------------------------
# Building reports
# ---------------------------------------------------------------------------

def _build_report(att: Attachment) -> AttachmentReport:
    payload = att.payload or b""
    md5, sha1, sha256 = _compute_hashes(payload)
    extension = _extract_extension(att.filename)
    suspicious_ext = extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS
    double_ext = _has_double_extension(att.filename)

    flags: list[str] = []
    if suspicious_ext:
        flags.append(
            f"High-risk extension '{extension}' — typical malware delivery format"
        )
    if double_ext:
        flags.append(
            f"Double extension in filename '{att.filename}' — common Windows-spoofing trick"
        )
    if att.content_type and not _content_type_matches_extension(att.content_type, extension):
        flags.append(
            f"Content-Type '{att.content_type}' does not match extension '{extension}'"
        )

    return AttachmentReport(
        filename=att.filename,
        content_type=att.content_type,
        size_bytes=att.size_bytes,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        extension=extension,
        has_suspicious_extension=suspicious_ext,
        has_double_extension=double_ext,
        flags=flags,
    )


def _compute_hashes(payload: bytes) -> tuple[str, str, str]:
    if not payload:
        return "", "", ""
    return (
        hashlib.md5(payload).hexdigest(),
        hashlib.sha1(payload).hexdigest(),
        hashlib.sha256(payload).hexdigest(),
    )


def _extract_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def _has_double_extension(filename: str) -> bool:
    """Detect filenames like ``invoice.pdf.exe`` where a benign extension is
    followed by an executable-like one."""
    parts = filename.lower().rsplit(".", 2)
    if len(parts) < 3:
        return False
    inner_ext, outer_ext = parts[1], parts[2]
    return inner_ext in COMMON_DOC_EXTENSIONS and ("." + outer_ext) in SUSPICIOUS_ATTACHMENT_EXTENSIONS


def _content_type_matches_extension(content_type: str, extension: str) -> bool:
    """Heuristic: a few well-known mismatches catch spoofed Office macros etc.

    We only flag obviously inconsistent pairs — this stays conservative to
    keep the false-positive rate low.
    """
    if not extension or not content_type:
        return True
    ct = content_type.lower()
    ext = extension.lower()
    expected = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".zip": "application/zip",
    }
    expected_ct = expected.get(ext)
    if expected_ct is None:
        return True
    return expected_ct in ct


# ---------------------------------------------------------------------------
# VirusTotal enrichment
# ---------------------------------------------------------------------------

def _enrich_with_virustotal(
    reports: list[AttachmentReport],
    raw_attachments: list[Attachment],
    settings: Settings,
    progress: Optional[Callable[[str], None]],
) -> None:
    # Imported lazily so the heuristics-only path doesn't require `requests`
    # to be installed (useful for unit tests and air-gapped runs).
    from . import threat_intel

    for report, att in zip(reports, raw_attachments):
        if not report.sha256:
            continue

        vt = threat_intel.check_file_hash(
            report.sha256,
            settings.vt_api_key,
            free_tier_delay=settings.vt_free_tier_delay,
            max_retries=settings.vt_max_retries,
            request_timeout=settings.vt_request_timeout,
        )

        if vt.not_found and settings.vt_upload_unknown_files and att.payload:
            if progress:
                progress(f"Uploading '{report.filename}' to VirusTotal (hash unknown)")
            uploaded = threat_intel.submit_file(
                att.payload,
                report.filename,
                settings.vt_api_key,
                request_timeout=max(settings.vt_request_timeout, 30),
            )
            if not uploaded.error:
                vt = uploaded
                report.vt_uploaded = True

        report.vt_result = vt.to_dict()

        if vt.malicious > 0:
            report.flags.append(
                f"VirusTotal: flagged malicious by {vt.malicious} engine(s)"
            )
        elif vt.suspicious > 0:
            report.flags.append(
                f"VirusTotal: flagged suspicious by {vt.suspicious} engine(s)"
            )
