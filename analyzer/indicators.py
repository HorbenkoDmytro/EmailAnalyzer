"""
Weighted risk scoring engine.

Each indicator is assigned a weight (1–10) reflecting its severity.
All triggered indicators are summed to produce a total risk score,
which maps to a qualitative risk level (Low / Medium / High / Critical).

Weights are deliberately documented so reviewers/recruiters can see
the threat-modelling reasoning behind each choice.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .auth_checks import AuthCheckResult, AuthStatus
from .parser import EmailData
from .url_extractor import URLExtractionResult, SUSPICIOUS_ATTACHMENT_EXTENSIONS


# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


RISK_THRESHOLDS = {
    RiskLevel.LOW: (0, 9),
    RiskLevel.MEDIUM: (10, 19),
    RiskLevel.HIGH: (20, 34),
    RiskLevel.CRITICAL: (35, 9999),
}

# Urgency and credential-harvesting keyword sets
URGENCY_KEYWORDS = {
    "urgent", "immediately", "action required", "act now", "verify now",
    "account suspended", "account closed", "limited time", "expires",
    "within 24 hours", "within 48 hours", "final notice", "last chance",
    "warning", "alert", "important notice", "response required",
}

CREDENTIAL_KEYWORDS = {
    "password", "username", "login", "sign in", "verify your account",
    "credit card", "bank account", "social security", "ssn",
    "billing information", "payment details", "confirm your identity",
    "update your information",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IndicatorHit:
    name: str
    weight: int
    detail: str
    category: str   # auth / header / url / content / attachment


@dataclass
class ScoringResult:
    hits: list[IndicatorHit]
    total_score: int
    risk_level: RiskLevel
    recommendations: list[str]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_email(
    email_data: EmailData,
    auth_result: AuthCheckResult,
    url_result: URLExtractionResult,
) -> ScoringResult:
    """Evaluate all indicators and compute the overall risk score.

    Args:
        email_data: Parsed email.
        auth_result: SPF/DKIM/DMARC results.
        url_result: Extracted and analysed URLs.

    Returns:
        ScoringResult with per-indicator hits and aggregate score.
    """
    hits: list[IndicatorHit] = []

    hits.extend(_check_auth_indicators(auth_result))
    hits.extend(_check_header_indicators(email_data))
    hits.extend(_check_url_indicators(url_result))
    hits.extend(_check_content_indicators(email_data))
    hits.extend(_check_attachment_indicators(email_data))

    total = sum(h.weight for h in hits)
    risk_level = _score_to_risk(total)
    recommendations = _build_recommendations(hits, risk_level)

    return ScoringResult(
        hits=hits,
        total_score=total,
        risk_level=risk_level,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Indicator checks
# ---------------------------------------------------------------------------

def _check_auth_indicators(auth: AuthCheckResult) -> list[IndicatorHit]:
    """Authentication indicators — highest weights because they are objective."""
    hits = []

    # SPF
    if auth.spf.status == AuthStatus.FAIL:
        hits.append(IndicatorHit(
            name="SPF Fail",
            weight=8,
            detail=auth.spf.detail,
            category="auth",
        ))
    elif auth.spf.status == AuthStatus.SOFTFAIL:
        hits.append(IndicatorHit(
            name="SPF Soft-Fail",
            weight=5,
            detail=auth.spf.detail,
            category="auth",
        ))
    elif auth.spf.status == AuthStatus.MISSING:
        hits.append(IndicatorHit(
            name="SPF Missing",
            weight=4,
            detail=auth.spf.detail,
            category="auth",
        ))

    # DKIM
    if auth.dkim.status == AuthStatus.FAIL:
        hits.append(IndicatorHit(
            name="DKIM Fail",
            weight=7,
            detail=auth.dkim.detail,
            category="auth",
        ))
    elif auth.dkim.domain_mismatch:
        hits.append(IndicatorHit(
            name="DKIM Domain Mismatch",
            weight=7,
            detail=auth.dkim.detail,
            category="auth",
        ))
    elif auth.dkim.status == AuthStatus.MISSING:
        hits.append(IndicatorHit(
            name="DKIM Missing",
            weight=4,
            detail=auth.dkim.detail,
            category="auth",
        ))

    # DMARC
    if auth.dmarc.status == AuthStatus.FAIL:
        hits.append(IndicatorHit(
            name="DMARC Fail",
            weight=6,
            detail=auth.dmarc.detail,
            category="auth",
        ))
    elif auth.dmarc.status == AuthStatus.MISSING:
        hits.append(IndicatorHit(
            name="DMARC Missing",
            weight=4,
            detail=auth.dmarc.detail,
            category="auth",
        ))
    elif auth.dmarc.policy == "none":
        hits.append(IndicatorHit(
            name="DMARC Policy = none",
            weight=3,
            detail="DMARC exists but policy is 'none' — no enforcement on failure.",
            category="auth",
        ))

    return hits


def _check_header_indicators(email_data: EmailData) -> list[IndicatorHit]:
    """Header-based indicators — spoofing, mismatches, suspicious metadata."""
    hits = []

    # Reply-To domain mismatch
    if email_data.reply_to and "@" in email_data.reply_to:
        from_domain = email_data.from_address.split("@")[-1].lower()
        reply_domain = email_data.reply_to.split("@")[-1].lower()
        if from_domain and reply_domain and from_domain != reply_domain:
            hits.append(IndicatorHit(
                name="Reply-To Domain Mismatch",
                weight=7,
                detail=(
                    f"From domain '{from_domain}' differs from Reply-To domain '{reply_domain}'. "
                    "Replies would go to a different mailbox — classic phishing technique."
                ),
                category="header",
            ))

    # Display name spoofing (display name contains a brand name but address doesn't match)
    spoof = _check_display_name_spoofing(email_data)
    if spoof:
        hits.append(spoof)

    # Suspicious X-Mailer (e.g. PHPMailer, Sendblaster)
    if email_data.x_mailer:
        mailer_lower = email_data.x_mailer.lower()
        suspicious_mailers = {"phpmailer", "sendblaster", "mass mailer", "bulk mail"}
        if any(m in mailer_lower for m in suspicious_mailers):
            hits.append(IndicatorHit(
                name="Suspicious X-Mailer",
                weight=3,
                detail=f"X-Mailer header '{email_data.x_mailer}' is associated with bulk/spam tools.",
                category="header",
            ))

    # Private / bogon IP in X-Originating-IP
    if email_data.x_originating_ip:
        import ipaddress
        try:
            ip = ipaddress.ip_address(email_data.x_originating_ip.strip())
            if ip.is_private or ip.is_loopback:
                hits.append(IndicatorHit(
                    name="Private Originating IP",
                    weight=4,
                    detail=f"X-Originating-IP '{email_data.x_originating_ip}' is a private address — may indicate misconfiguration or forgery.",
                    category="header",
                ))
        except ValueError:
            pass

    return hits


def _check_display_name_spoofing(email_data: EmailData) -> Optional[IndicatorHit]:
    """Detect when the display name implies a trusted brand but the address doesn't match."""
    TRUSTED_BRANDS = {
        "paypal", "amazon", "google", "microsoft", "apple", "facebook",
        "instagram", "netflix", "bank of america", "chase", "wells fargo",
        "dhl", "fedex", "ups", "irs", "linkedin",
    }
    display = email_data.from_display_name.lower()
    address_domain = email_data.from_address.split("@")[-1].lower() if "@" in email_data.from_address else ""

    for brand in TRUSTED_BRANDS:
        if brand in display:
            # Check that the actual sending domain matches the brand
            expected_domain = brand.replace(" ", "") + ".com"
            if expected_domain not in address_domain:
                return IndicatorHit(
                    name="Display Name Spoofing",
                    weight=8,
                    detail=(
                        f"Display name contains '{brand}' but actual From address is "
                        f"'{email_data.from_address}'. Classic impersonation technique."
                    ),
                    category="header",
                )
    return None


def _check_url_indicators(url_result: URLExtractionResult) -> list[IndicatorHit]:
    """URL-based indicators derived from the url_extractor analysis."""
    hits = []
    ip_count = sum(1 for u in url_result.urls if u.is_ip_based)
    shortener_count = sum(1 for u in url_result.urls if u.is_shortener)
    suspicious_tld_count = sum(1 for u in url_result.urls if u.has_suspicious_tld)
    homograph_count = sum(1 for u in url_result.urls if u.is_homograph)
    mismatch_count = sum(1 for u in url_result.urls if u.display_text_mismatch)
    vt_hits = [u for u in url_result.urls if u.vt_result and u.vt_result.get("malicious", 0) > 0]

    if ip_count:
        hits.append(IndicatorHit(
            name=f"IP-Based URL(s) ({ip_count})",
            weight=7,
            detail=f"{ip_count} URL(s) use raw IP addresses instead of domain names.",
            category="url",
        ))
    if shortener_count:
        hits.append(IndicatorHit(
            name=f"URL Shortener(s) ({shortener_count})",
            weight=5,
            detail=f"{shortener_count} URL(s) use shortening services to hide the real destination.",
            category="url",
        ))
    if suspicious_tld_count:
        hits.append(IndicatorHit(
            name=f"Suspicious TLD(s) ({suspicious_tld_count})",
            weight=6,
            detail=f"{suspicious_tld_count} URL(s) have TLDs commonly used in phishing.",
            category="url",
        ))
    if homograph_count:
        hits.append(IndicatorHit(
            name=f"Homograph Domain(s) ({homograph_count})",
            weight=9,
            detail=f"{homograph_count} URL(s) use punycode / lookalike characters.",
            category="url",
        ))
    if mismatch_count:
        hits.append(IndicatorHit(
            name=f"Anchor Text Mismatch(es) ({mismatch_count})",
            weight=6,
            detail=f"{mismatch_count} hyperlink(s) display a trusted domain but point elsewhere.",
            category="url",
        ))
    for vt_url in vt_hits:
        malicious = vt_url.vt_result["malicious"]
        hits.append(IndicatorHit(
            name="VirusTotal Malicious URL",
            weight=10,
            detail=f"URL '{vt_url.url[:80]}' flagged malicious by {malicious} VT engine(s).",
            category="url",
        ))

    return hits


def _check_content_indicators(email_data: EmailData) -> list[IndicatorHit]:
    """Heuristic checks on email body content."""
    hits = []
    combined_text = (email_data.body_plain + " " + email_data.subject).lower()

    urgency_found = [kw for kw in URGENCY_KEYWORDS if kw in combined_text]
    if urgency_found:
        hits.append(IndicatorHit(
            name="Urgency Language",
            weight=4,
            detail=f"Urgency keywords detected: {', '.join(urgency_found[:5])}.",
            category="content",
        ))

    credential_found = [kw for kw in CREDENTIAL_KEYWORDS if kw in combined_text]
    if credential_found:
        hits.append(IndicatorHit(
            name="Credential Harvesting Language",
            weight=5,
            detail=f"Credential-related keywords: {', '.join(credential_found[:5])}.",
            category="content",
        ))

    return hits


def _check_attachment_indicators(email_data: EmailData) -> list[IndicatorHit]:
    hits = []
    for att in email_data.attachments:
        ext = "." + att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
        if ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            hits.append(IndicatorHit(
                name=f"Suspicious Attachment: {att.filename}",
                weight=8,
                detail=f"Attachment '{att.filename}' ({att.content_type}) has a high-risk extension '{ext}'.",
                category="attachment",
            ))
    return hits


# ---------------------------------------------------------------------------
# Score mapping and recommendations
# ---------------------------------------------------------------------------

def _score_to_risk(score: int) -> RiskLevel:
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score <= high:
            return level
    return RiskLevel.CRITICAL


def _build_recommendations(hits: list[IndicatorHit], risk: RiskLevel) -> list[str]:
    recs: list[str] = []
    categories = {h.category for h in hits}

    if "auth" in categories:
        recs.append("Do not trust this email — authentication failures indicate spoofing or forgery.")
    if "url" in categories:
        recs.append("Do NOT click any links in this email. Verify URLs directly via your browser.")
    if "content" in categories:
        recs.append("Urgency or credential language is a social-engineering red flag. Verify through official channels.")
    if "attachment" in categories:
        recs.append("Do NOT open attachments. Scan with an up-to-date AV tool first.")
    if risk == RiskLevel.CRITICAL:
        recs.append("CRITICAL RISK — quarantine this email and report to your security team immediately.")
    elif risk == RiskLevel.HIGH:
        recs.append("HIGH RISK — treat as malicious until proven otherwise.")

    if not recs:
        recs.append("No significant indicators detected. Email appears legitimate, but always stay vigilant.")

    return recs
