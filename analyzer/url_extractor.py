"""
URL extraction and heuristic analysis module.

Extracts all URLs from both plain-text and HTML email bodies, then runs
a series of heuristic checks to flag suspicious characteristics. No external
API calls are made here — everything is pattern-based and DNS-based.
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# ---------------------------------------------------------------------------
# Known threat indicator lists
# ---------------------------------------------------------------------------

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "short.link", "tiny.cc", "rb.gy", "cutt.ly",
    "shorturl.at", "rebrand.ly", "bl.ink", "v.gd", "s.id",
}

SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free / heavily abused TLDs
    ".xyz", ".top", ".click", ".download", ".stream",
    ".loan", ".review", ".trade", ".work", ".date",
    ".accountant", ".science", ".racing",
}

SUSPICIOUS_ATTACHMENT_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".ps1", ".msi", ".dll",
    ".docm", ".xlsm", ".pptm",  # Macro-enabled Office files
}

# Regex for extracting URLs from plain text
URL_REGEX = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class URLResult:
    url: str
    domain: str
    display_text: Optional[str]          # For HTML anchors — text the user sees
    is_ip_based: bool
    is_shortener: bool
    has_suspicious_tld: bool
    is_homograph: bool                   # Punycode / lookalike domain
    display_text_mismatch: bool          # Anchor text looks like a different domain
    flags: list[str] = field(default_factory=list)  # Human-readable descriptions
    vt_result: Optional[dict] = None     # Populated later by threat_intel module


@dataclass
class URLExtractionResult:
    urls: list[URLResult]
    total_count: int
    suspicious_count: int


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_and_analyze_urls(
    body_plain: str,
    body_html: str,
) -> URLExtractionResult:
    """Extract all URLs from email body parts and run heuristic checks.

    Args:
        body_plain: Plain-text body of the email.
        body_html: HTML body of the email.

    Returns:
        URLExtractionResult with all URLs and their analysis.
    """
    urls: list[URLResult] = []
    seen: set[str] = set()

    # Extract from plain text
    for url in _extract_from_plain(body_plain):
        if url not in seen:
            seen.add(url)
            urls.append(_analyze_url(url, display_text=None))

    # Extract from HTML (includes anchor display text)
    for url, display in _extract_from_html(body_html):
        if url not in seen:
            seen.add(url)
            urls.append(_analyze_url(url, display_text=display))
        else:
            # Update existing entry with display text if we have it
            for existing in urls:
                if existing.url == url and display and not existing.display_text:
                    existing.display_text = display
                    if _check_display_text_mismatch(url, display):
                        existing.display_text_mismatch = True
                        existing.flags.append(
                            f"Anchor text '{display}' does not match actual URL domain"
                        )

    suspicious_count = sum(1 for u in urls if u.flags)

    return URLExtractionResult(
        urls=urls,
        total_count=len(urls),
        suspicious_count=suspicious_count,
    )


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_from_plain(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def _extract_from_html(html: str) -> list[tuple[str, Optional[str]]]:
    """Return list of (url, display_text) tuples from HTML body."""
    results: list[tuple[str, Optional[str]]] = []

    if not html:
        return results

    if BS4_AVAILABLE:
        soup = BeautifulSoup(html, "html.parser")
        # <a href="...">text</a>
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith("http"):
                display = tag.get_text(strip=True) or None
                results.append((href, display))
        # <form action="...">
        for tag in soup.find_all("form", action=True):
            action = tag["action"].strip()
            if action.startswith("http"):
                results.append((action, "[FORM ACTION]"))
        # <img src="..."> — pixel trackers
        for tag in soup.find_all("img", src=True):
            src = tag["src"].strip()
            if src.startswith("http"):
                results.append((src, "[IMG SRC]"))
    else:
        # Fallback regex extraction from raw HTML
        for url in URL_REGEX.findall(html):
            results.append((url, None))

    return results


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _analyze_url(url: str, display_text: Optional[str]) -> URLResult:
    """Run all heuristic checks on a single URL and build URLResult."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]  # Strip port
    except Exception:
        domain = ""

    flags: list[str] = []

    is_ip = _check_ip_based(domain)
    if is_ip:
        flags.append(f"IP-based URL ('{domain}') — domain names expected in legitimate mail")

    is_shortener = _check_shortener(domain)
    if is_shortener:
        flags.append(f"URL shortener detected ('{domain}') — hides real destination")

    has_suspicious_tld = _check_suspicious_tld(domain)
    if has_suspicious_tld:
        tld = _get_tld(domain)
        flags.append(f"Suspicious TLD '{tld}' — frequently used in phishing campaigns")

    is_homograph = _check_homograph(domain)
    if is_homograph:
        flags.append(f"Possible homograph/punycode domain '{domain}' — may mimic a trusted brand")

    mismatch = _check_display_text_mismatch(url, display_text)
    if mismatch:
        flags.append(f"Anchor text '{display_text}' does not match URL domain '{domain}'")

    return URLResult(
        url=url,
        domain=domain,
        display_text=display_text,
        is_ip_based=is_ip,
        is_shortener=is_shortener,
        has_suspicious_tld=has_suspicious_tld,
        is_homograph=is_homograph,
        display_text_mismatch=mismatch,
        flags=flags,
    )


def _check_ip_based(domain: str) -> bool:
    """Return True if the domain part of the URL is a raw IP address."""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _check_shortener(domain: str) -> bool:
    return domain in URL_SHORTENERS


def _check_suspicious_tld(domain: str) -> bool:
    tld = _get_tld(domain)
    return tld in SUSPICIOUS_TLDS


def _get_tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return f".{parts[-1]}" if len(parts) > 1 else ""


def _check_homograph(domain: str) -> bool:
    """Detect punycode-encoded domains (xn--) which are often used in lookalike attacks."""
    return "xn--" in domain.lower()


def _check_display_text_mismatch(url: str, display_text: Optional[str]) -> bool:
    """Check if the anchor display text looks like a domain different from the real URL."""
    if not display_text:
        return False
    # Only check if display text looks like a URL or domain
    display_lower = display_text.lower().strip()
    if not ("http" in display_lower or "www." in display_lower or "." in display_lower):
        return False
    # Extract displayed domain candidate
    display_parsed = urlparse(display_lower if display_lower.startswith("http") else f"http://{display_lower}")
    display_domain = display_parsed.netloc.split(":")[0]
    try:
        real_domain = urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return False
    if not display_domain or not real_domain:
        return False
    return display_domain != real_domain
