"""
Email authentication checks: SPF, DKIM, DMARC.

This module inspects the Authentication-Results header and performs live
DNS lookups with dnspython to determine the authentication posture of an
incoming email. Understanding these three protocols is fundamental to
detecting spoofed or forged emails.

  SPF  — defines which servers are allowed to send mail for a domain
  DKIM — cryptographically signs the message so recipients can verify it
  DMARC — policy layer that tells receivers what to do on SPF/DKIM failure
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from .parser import EmailData


class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    MISSING = "missing"
    UNKNOWN = "unknown"


@dataclass
class SPFResult:
    status: AuthStatus
    sender_domain: str
    record: Optional[str]       # Raw TXT record from DNS
    detail: str                  # Human-readable explanation


@dataclass
class DKIMResult:
    status: AuthStatus
    signing_domain: Optional[str]   # d= value from DKIM-Signature
    from_domain: str
    domain_mismatch: bool           # True if signing domain ≠ From domain
    detail: str


@dataclass
class DMARCResult:
    status: AuthStatus
    domain: str
    policy: Optional[str]           # none / quarantine / reject
    pct: Optional[int]              # Percentage of mail subject to policy
    record: Optional[str]
    detail: str


@dataclass
class AuthCheckResult:
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult


def run_auth_checks(email_data: EmailData) -> AuthCheckResult:
    """Run all three authentication checks against the parsed email.

    Combines header inspection with live DNS queries where possible.

    Args:
        email_data: Parsed email from parser.py.

    Returns:
        AuthCheckResult containing SPF, DKIM, and DMARC results.
    """
    spf = _check_spf(email_data)
    dkim = _check_dkim(email_data)
    dmarc = _check_dmarc(email_data)
    return AuthCheckResult(spf=spf, dkim=dkim, dmarc=dmarc)


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

def _check_spf(email_data: EmailData) -> SPFResult:
    """Inspect SPF by reading the Authentication-Results header and querying DNS."""
    sender_domain = email_data.from_address.split("@")[-1] if "@" in email_data.from_address else ""

    # First, parse the Authentication-Results header (fastest / most reliable)
    header_status = _parse_auth_results_for(email_data.authentication_results, "spf")
    received_spf = email_data.received_spf or ""

    if header_status in (AuthStatus.PASS, AuthStatus.FAIL, AuthStatus.SOFTFAIL, AuthStatus.NEUTRAL):
        record = _lookup_spf_record(sender_domain)
        detail = _build_spf_detail(header_status, sender_domain, received_spf)
        return SPFResult(status=header_status, sender_domain=sender_domain, record=record, detail=detail)

    # Fall back to Received-SPF header
    if received_spf:
        status = _parse_received_spf(received_spf)
        record = _lookup_spf_record(sender_domain)
        return SPFResult(
            status=status,
            sender_domain=sender_domain,
            record=record,
            detail=f"Derived from Received-SPF header: {received_spf[:120]}",
        )

    # Fall back to DNS lookup only (no verdict in headers)
    record = _lookup_spf_record(sender_domain)
    if record:
        return SPFResult(
            status=AuthStatus.UNKNOWN,
            sender_domain=sender_domain,
            record=record,
            detail="SPF record exists but no authentication result header found.",
        )

    return SPFResult(
        status=AuthStatus.MISSING,
        sender_domain=sender_domain,
        record=None,
        detail=f"No SPF record found for domain '{sender_domain}'.",
    )


def _lookup_spf_record(domain: str) -> Optional[str]:
    """Query TXT records for the domain and return the SPF record if present."""
    if not DNS_AVAILABLE or not domain:
        return None
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() for s in rdata.strings)
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return None


def _parse_received_spf(header: str) -> AuthStatus:
    header_lower = header.lower()
    if "pass" in header_lower:
        return AuthStatus.PASS
    if "softfail" in header_lower:
        return AuthStatus.SOFTFAIL
    if "fail" in header_lower:
        return AuthStatus.FAIL
    if "neutral" in header_lower:
        return AuthStatus.NEUTRAL
    return AuthStatus.UNKNOWN


def _build_spf_detail(status: AuthStatus, domain: str, received_spf: str) -> str:
    messages = {
        AuthStatus.PASS: f"SPF passed — sending server is authorised for '{domain}'.",
        AuthStatus.FAIL: f"SPF FAILED — sending server is NOT authorised for '{domain}'. High spoofing risk.",
        AuthStatus.SOFTFAIL: f"SPF soft-fail — sending server is not strongly authorised for '{domain}'.",
        AuthStatus.NEUTRAL: f"SPF neutral — domain owner makes no assertion about '{domain}'.",
    }
    base = messages.get(status, "SPF result unknown.")
    if received_spf:
        base += f" Raw: {received_spf[:100]}"
    return base


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

def _check_dkim(email_data: EmailData) -> DKIMResult:
    """Inspect DKIM by parsing the DKIM-Signature header and Authentication-Results."""
    from_domain = email_data.from_address.split("@")[-1] if "@" in email_data.from_address else ""

    signing_domain = _extract_dkim_domain(email_data.dkim_signature)
    domain_mismatch = bool(signing_domain and signing_domain.lower() != from_domain.lower())

    header_status = _parse_auth_results_for(email_data.authentication_results, "dkim")

    if header_status == AuthStatus.PASS and not domain_mismatch:
        return DKIMResult(
            status=AuthStatus.PASS,
            signing_domain=signing_domain,
            from_domain=from_domain,
            domain_mismatch=False,
            detail=f"DKIM signature passed and signing domain '{signing_domain}' matches From domain.",
        )

    if header_status == AuthStatus.FAIL:
        return DKIMResult(
            status=AuthStatus.FAIL,
            signing_domain=signing_domain,
            from_domain=from_domain,
            domain_mismatch=domain_mismatch,
            detail=f"DKIM signature verification FAILED for domain '{signing_domain}'.",
        )

    if domain_mismatch:
        return DKIMResult(
            status=AuthStatus.FAIL,
            signing_domain=signing_domain,
            from_domain=from_domain,
            domain_mismatch=True,
            detail=(
                f"DKIM domain mismatch — email signed by '{signing_domain}' "
                f"but From header shows '{from_domain}'. Possible spoofing."
            ),
        )

    if not email_data.dkim_signature:
        return DKIMResult(
            status=AuthStatus.MISSING,
            signing_domain=None,
            from_domain=from_domain,
            domain_mismatch=False,
            detail="No DKIM-Signature header found. Email is unsigned.",
        )

    return DKIMResult(
        status=AuthStatus.UNKNOWN,
        signing_domain=signing_domain,
        from_domain=from_domain,
        domain_mismatch=domain_mismatch,
        detail="DKIM-Signature present but result could not be determined from headers.",
    )


def _extract_dkim_domain(dkim_header: Optional[str]) -> Optional[str]:
    """Extract the d= domain tag from a DKIM-Signature header."""
    if not dkim_header:
        return None
    match = re.search(r"\bd=([^;\s]+)", dkim_header)
    return match.group(1).strip() if match else None


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def _check_dmarc(email_data: EmailData) -> DMARCResult:
    """Check DMARC policy by querying _dmarc.<domain> DNS TXT record."""
    from_domain = email_data.from_address.split("@")[-1] if "@" in email_data.from_address else ""

    header_status = _parse_auth_results_for(email_data.authentication_results, "dmarc")

    record = _lookup_dmarc_record(from_domain)
    policy, pct = _parse_dmarc_record(record)

    if header_status == AuthStatus.PASS:
        return DMARCResult(
            status=AuthStatus.PASS,
            domain=from_domain,
            policy=policy,
            pct=pct,
            record=record,
            detail=f"DMARC passed. Policy: {policy or 'none'} ({pct or 100}% enforcement).",
        )

    if header_status == AuthStatus.FAIL:
        return DMARCResult(
            status=AuthStatus.FAIL,
            domain=from_domain,
            policy=policy,
            pct=pct,
            record=record,
            detail=f"DMARC FAILED. Policy on failure: {policy or 'none'}.",
        )

    if not record:
        return DMARCResult(
            status=AuthStatus.MISSING,
            domain=from_domain,
            policy=None,
            pct=None,
            record=None,
            detail=f"No DMARC record found for '_dmarc.{from_domain}'. Domain is unprotected.",
        )

    weak_policy = policy in (None, "none")
    return DMARCResult(
        status=AuthStatus.NEUTRAL if weak_policy else AuthStatus.UNKNOWN,
        domain=from_domain,
        policy=policy,
        pct=pct,
        record=record,
        detail=(
            f"DMARC record found with policy='{policy}' — "
            + ("weak protection, no enforcement action taken." if weak_policy else "enforcement active.")
        ),
    )


def _lookup_dmarc_record(domain: str) -> Optional[str]:
    """Query _dmarc.<domain> for the DMARC TXT record."""
    if not DNS_AVAILABLE or not domain:
        return None
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = "".join(s.decode() for s in rdata.strings)
            if txt.startswith("v=DMARC1"):
                return txt
    except Exception:
        pass
    return None


def _parse_dmarc_record(record: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    """Extract p= policy and pct= from a raw DMARC TXT record."""
    if not record:
        return None, None
    policy = None
    pct = None
    p_match = re.search(r"\bp=(\w+)", record)
    if p_match:
        policy = p_match.group(1).lower()
    pct_match = re.search(r"\bpct=(\d+)", record)
    if pct_match:
        pct = int(pct_match.group(1))
    return policy, pct


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _parse_auth_results_for(header: Optional[str], protocol: str) -> AuthStatus:
    """Parse the Authentication-Results header for a specific protocol verdict."""
    if not header:
        return AuthStatus.MISSING
    pattern = rf"{protocol}=(\w+)"
    match = re.search(pattern, header, re.IGNORECASE)
    if not match:
        return AuthStatus.MISSING
    verdict = match.group(1).lower()
    mapping = {
        "pass": AuthStatus.PASS,
        "fail": AuthStatus.FAIL,
        "softfail": AuthStatus.SOFTFAIL,
        "neutral": AuthStatus.NEUTRAL,
    }
    return mapping.get(verdict, AuthStatus.UNKNOWN)
