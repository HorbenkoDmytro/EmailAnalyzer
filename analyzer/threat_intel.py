"""
VirusTotal v3 API integration for URL and file reputation checks.

Uses the public free-tier API (4 requests/minute). Implements exponential
backoff on rate-limit (HTTP 429) responses. All callers can opt in / out
via Settings; this module never decides on its own whether to call out.

API docs: https://developers.virustotal.com/reference/overview
"""

import base64
import time
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_FREE_TIER_DELAY = 15   # seconds between requests on free tier (4/min = 15s)
DEFAULT_MAX_RETRIES = 3
DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class VTResult:
    """Reputation result for a URL or a file hash. ``resource`` holds the
    original URL (for URL lookups) or the file hash (for file lookups)."""
    resource: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    permalink: str
    scan_date: Optional[str]
    error: Optional[str] = None
    not_found: bool = False  # True when VT has no record of the resource

    # Backward-compat alias used by the URL pipeline
    @property
    def url(self) -> str:
        return self.resource

    def to_dict(self) -> dict:
        return {
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "permalink": self.permalink,
            "scan_date": self.scan_date,
            "error": self.error,
            "not_found": self.not_found,
        }


# ---------------------------------------------------------------------------
# URL reputation
# ---------------------------------------------------------------------------

def check_urls(
    urls: list[str],
    api_key: str,
    *,
    free_tier_delay: int = DEFAULT_FREE_TIER_DELAY,
    max_retries: int = DEFAULT_MAX_RETRIES,
    request_timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, VTResult]:
    """Submit URLs to VirusTotal and return reputation results.

    Handles rate limiting with exponential backoff. Results are keyed
    by the original URL string.
    """
    results: dict[str, VTResult] = {}
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    for i, url in enumerate(urls):
        if i > 0:
            time.sleep(free_tier_delay)
        results[url] = _check_single_url(
            url, headers,
            free_tier_delay=free_tier_delay,
            max_retries=max_retries,
            request_timeout=request_timeout,
        )

    return results


def _check_single_url(
    url: str,
    headers: dict,
    *,
    free_tier_delay: int,
    max_retries: int,
    request_timeout: int,
) -> VTResult:
    """Submit a URL and retrieve its analysis report with retry logic."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    for attempt in range(max_retries):
        try:
            resp = requests.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=headers,
                timeout=request_timeout,
            )

            if resp.status_code == 200:
                return _parse_url_response(url, resp.json())

            if resp.status_code == 404:
                return _submit_and_retrieve_url(url, url_id, headers, request_timeout)

            if resp.status_code == 429:
                wait = (2 ** attempt) * free_tier_delay
                logger.warning("VirusTotal rate limit hit. Waiting %ds...", wait)
                time.sleep(wait)
                continue

            logger.warning("VirusTotal returned HTTP %d for %s", resp.status_code, url)
            return _empty_vt_result(
                url,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )

        except requests.RequestException as exc:
            logger.error("VirusTotal request failed: %s", exc)
            if attempt == max_retries - 1:
                return _empty_vt_result(url, error=str(exc))
            time.sleep(2 ** attempt)

    return _empty_vt_result(url, error="Max retries exceeded")


def _submit_and_retrieve_url(url: str, url_id: str, headers: dict, request_timeout: int) -> VTResult:
    """Submit a URL for scanning, then poll for the result."""
    try:
        post_resp = requests.post(
            f"{VT_BASE}/urls",
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=f"url={requests.utils.quote(url)}",
            timeout=request_timeout,
        )
        if post_resp.status_code not in (200, 201):
            return _empty_vt_result(url, error=f"Submit failed: HTTP {post_resp.status_code}")
    except requests.RequestException as exc:
        return _empty_vt_result(url, error=str(exc))

    for wait in (5, 10, 20):
        time.sleep(wait)
        try:
            resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=request_timeout)
            if resp.status_code == 200:
                return _parse_url_response(url, resp.json())
        except requests.RequestException:
            pass

    return VTResult(
        resource=url, malicious=0, suspicious=0, harmless=0, undetected=0,
        permalink=f"https://www.virustotal.com/gui/url/{url_id}",
        scan_date=None, error="Analysis still pending — check VT permalink manually",
    )


def _parse_url_response(url: str, data: dict) -> VTResult:
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        meta = attrs.get("last_analysis_date")
        scan_date = (
            datetime.fromtimestamp(meta, tz=timezone.utc).isoformat()
            if meta else None
        )
        permalink = f"https://www.virustotal.com/gui/url/{data['data']['id']}"
        return VTResult(
            resource=url,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            permalink=permalink,
            scan_date=scan_date,
        )
    except (KeyError, TypeError) as exc:
        return _empty_vt_result(url, error=f"Parse error: {exc}")


# ---------------------------------------------------------------------------
# File hash reputation
# ---------------------------------------------------------------------------

def check_file_hash(
    file_hash: str,
    api_key: str,
    *,
    free_tier_delay: int = DEFAULT_FREE_TIER_DELAY,
    max_retries: int = DEFAULT_MAX_RETRIES,
    request_timeout: int = DEFAULT_TIMEOUT,
) -> VTResult:
    """Look up a file by hash on VirusTotal's /files/{id} endpoint.

    Returns a VTResult with ``not_found=True`` when the file has never been
    seen by VT. The caller can then choose to upload the file for scanning
    via :func:`submit_file`.
    """
    if not file_hash:
        return _empty_vt_result(file_hash, error="empty hash")

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    permalink = f"https://www.virustotal.com/gui/file/{file_hash}"

    for attempt in range(max_retries):
        try:
            resp = requests.get(
                f"{VT_BASE}/files/{file_hash}",
                headers=headers,
                timeout=request_timeout,
            )
            if resp.status_code == 200:
                return _parse_file_response(file_hash, resp.json())
            if resp.status_code == 404:
                return VTResult(
                    resource=file_hash, malicious=0, suspicious=0, harmless=0, undetected=0,
                    permalink=permalink, scan_date=None, not_found=True,
                )
            if resp.status_code == 429:
                wait = (2 ** attempt) * free_tier_delay
                logger.warning("VirusTotal rate limit hit. Waiting %ds...", wait)
                time.sleep(wait)
                continue
            return VTResult(
                resource=file_hash, malicious=0, suspicious=0, harmless=0, undetected=0,
                permalink=permalink, scan_date=None,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )
        except requests.RequestException as exc:
            logger.error("VirusTotal file lookup failed: %s", exc)
            if attempt == max_retries - 1:
                return VTResult(
                    resource=file_hash, malicious=0, suspicious=0, harmless=0, undetected=0,
                    permalink=permalink, scan_date=None, error=str(exc),
                )
            time.sleep(2 ** attempt)

    return VTResult(
        resource=file_hash, malicious=0, suspicious=0, harmless=0, undetected=0,
        permalink=permalink, scan_date=None, error="Max retries exceeded",
    )


def submit_file(
    file_bytes: bytes,
    filename: str,
    api_key: str,
    *,
    poll_waits: tuple = (10, 20, 30),
    request_timeout: int = 30,
) -> VTResult:
    """Upload a file to VirusTotal and poll for the analysis result.

    Use sparingly — uploads count against the (small) free-tier quota and
    take significantly longer than hash lookups. Caller should usually try
    :func:`check_file_hash` first and only fall back to upload when the
    hash is unknown.
    """
    if not file_bytes:
        return _empty_vt_result("", error="empty file")

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        files = {"file": (filename or "attachment", file_bytes)}
        post_resp = requests.post(
            f"{VT_BASE}/files",
            headers=headers,
            files=files,
            timeout=request_timeout,
        )
        if post_resp.status_code not in (200, 201):
            return _empty_vt_result(
                filename,
                error=f"Upload failed: HTTP {post_resp.status_code}: {post_resp.text[:200]}",
            )
        analysis_id = post_resp.json().get("data", {}).get("id")
        if not analysis_id:
            return _empty_vt_result(filename, error="Upload succeeded but no analysis id returned")
    except requests.RequestException as exc:
        return _empty_vt_result(filename, error=f"Upload error: {exc}")

    for wait in poll_waits:
        time.sleep(wait)
        try:
            resp = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=headers,
                timeout=request_timeout,
            )
            if resp.status_code != 200:
                continue
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                meta = attrs.get("date")
                scan_date = (
                    datetime.fromtimestamp(meta, tz=timezone.utc).isoformat()
                    if meta else None
                )
                # /analyses references the file via meta.file_info.sha256
                meta_block = resp.json().get("meta", {}).get("file_info", {})
                file_id = meta_block.get("sha256") or analysis_id
                return VTResult(
                    resource=file_id,
                    malicious=stats.get("malicious", 0),
                    suspicious=stats.get("suspicious", 0),
                    harmless=stats.get("harmless", 0),
                    undetected=stats.get("undetected", 0),
                    permalink=f"https://www.virustotal.com/gui/file/{file_id}",
                    scan_date=scan_date,
                )
        except requests.RequestException:
            continue

    return VTResult(
        resource=filename, malicious=0, suspicious=0, harmless=0, undetected=0,
        permalink=f"https://www.virustotal.com/gui/file-analysis/{analysis_id}",
        scan_date=None, error="Analysis still pending — check VT permalink manually",
    )


def _parse_file_response(file_hash: str, data: dict) -> VTResult:
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        meta = attrs.get("last_analysis_date")
        scan_date = (
            datetime.fromtimestamp(meta, tz=timezone.utc).isoformat()
            if meta else None
        )
        return VTResult(
            resource=file_hash,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
            scan_date=scan_date,
        )
    except (KeyError, TypeError) as exc:
        return _empty_vt_result(file_hash, error=f"Parse error: {exc}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_vt_result(resource: str, *, error: Optional[str] = None) -> VTResult:
    return VTResult(
        resource=resource,
        malicious=0, suspicious=0, harmless=0, undetected=0,
        permalink="", scan_date=None, error=error,
    )
