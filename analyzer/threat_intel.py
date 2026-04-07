"""
VirusTotal v3 API integration for URL reputation checks.

Uses the public free-tier API (4 requests/minute). Implements exponential
backoff on rate-limit (HTTP 429) responses. Gracefully degrades to None
if no API key is provided.

API docs: https://developers.virustotal.com/reference/overview
"""

import base64
import time
import logging
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
FREE_TIER_DELAY = 15   # seconds between requests on free tier (4/min = 15s)
MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class VTResult:
    url: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    permalink: str
    scan_date: Optional[str]
    error: Optional[str] = None     # Set if the lookup failed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_urls(urls: list[str], api_key: str) -> dict[str, VTResult]:
    """Submit URLs to VirusTotal and return reputation results.

    Handles rate limiting with exponential backoff. Results are keyed
    by the original URL string.

    Args:
        urls: List of URLs to check.
        api_key: VirusTotal API key.

    Returns:
        Dict mapping each URL to its VTResult.
    """
    results: dict[str, VTResult] = {}
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    for i, url in enumerate(urls):
        if i > 0:
            # Respect free-tier rate limit between requests
            time.sleep(FREE_TIER_DELAY)

        result = _check_single_url(url, headers)
        results[url] = result

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_single_url(url: str, headers: dict) -> VTResult:
    """Submit a URL and retrieve its analysis report with retry logic."""
    # VirusTotal uses URL-safe base64 of the URL as the resource ID
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    for attempt in range(MAX_RETRIES):
        try:
            # Try fetching an existing report first (avoids consuming quota)
            resp = requests.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=headers,
                timeout=10,
            )

            if resp.status_code == 200:
                return _parse_response(url, resp.json())

            if resp.status_code == 404:
                # No existing report — submit for analysis
                return _submit_and_retrieve(url, url_id, headers)

            if resp.status_code == 429:
                wait = (2 ** attempt) * FREE_TIER_DELAY
                logger.warning("VirusTotal rate limit hit. Waiting %ds...", wait)
                time.sleep(wait)
                continue

            logger.warning("VirusTotal returned HTTP %d for %s", resp.status_code, url)
            return VTResult(
                url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
                permalink="", scan_date=None,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )

        except requests.RequestException as exc:
            logger.error("VirusTotal request failed: %s", exc)
            if attempt == MAX_RETRIES - 1:
                return VTResult(
                    url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
                    permalink="", scan_date=None, error=str(exc),
                )
            time.sleep(2 ** attempt)

    return VTResult(
        url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
        permalink="", scan_date=None, error="Max retries exceeded",
    )


def _submit_and_retrieve(url: str, url_id: str, headers: dict) -> VTResult:
    """Submit a URL for scanning, then poll for the result."""
    try:
        post_resp = requests.post(
            f"{VT_BASE}/urls",
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=f"url={requests.utils.quote(url)}",
            timeout=10,
        )
        if post_resp.status_code not in (200, 201):
            return VTResult(
                url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
                permalink="", scan_date=None,
                error=f"Submit failed: HTTP {post_resp.status_code}",
            )
    except requests.RequestException as exc:
        return VTResult(
            url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
            permalink="", scan_date=None, error=str(exc),
        )

    # Poll for result (up to 3 attempts with increasing delays)
    for wait in (5, 10, 20):
        time.sleep(wait)
        try:
            resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=10)
            if resp.status_code == 200:
                return _parse_response(url, resp.json())
        except requests.RequestException:
            pass

    return VTResult(
        url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
        permalink=f"https://www.virustotal.com/gui/url/{url_id}",
        scan_date=None, error="Analysis still pending — check VT permalink manually",
    )


def _parse_response(url: str, data: dict) -> VTResult:
    """Parse a VirusTotal v3 URL analysis response into VTResult."""
    try:
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        meta = attrs.get("last_analysis_date")
        scan_date = None
        if meta:
            from datetime import datetime, timezone
            scan_date = datetime.fromtimestamp(meta, tz=timezone.utc).isoformat()
        permalink = f"https://www.virustotal.com/gui/url/{data['data']['id']}"
        return VTResult(
            url=url,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            permalink=permalink,
            scan_date=scan_date,
        )
    except (KeyError, TypeError) as exc:
        return VTResult(
            url=url, malicious=0, suspicious=0, harmless=0, undetected=0,
            permalink="", scan_date=None, error=f"Parse error: {exc}",
        )
