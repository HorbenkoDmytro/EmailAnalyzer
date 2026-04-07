"""Tests for the authentication checks module."""

import pytest
from pathlib import Path

from analyzer.parser import parse_email_file
from analyzer.auth_checks import (
    run_auth_checks, AuthStatus,
    _parse_auth_results_for, _extract_dkim_domain, _parse_dmarc_record,
)

SAMPLES = Path(__file__).parent / "samples"


class TestAuthResultParsing:
    AUTH_HEADER = (
        "mx.example.com; "
        "dkim=pass header.i=@gmail.com; "
        "spf=pass smtp.mailfrom=alice@gmail.com; "
        "dmarc=pass header.from=gmail.com"
    )

    def test_spf_pass_parsed(self):
        assert _parse_auth_results_for(self.AUTH_HEADER, "spf") == AuthStatus.PASS

    def test_dkim_pass_parsed(self):
        assert _parse_auth_results_for(self.AUTH_HEADER, "dkim") == AuthStatus.PASS

    def test_dmarc_pass_parsed(self):
        assert _parse_auth_results_for(self.AUTH_HEADER, "dmarc") == AuthStatus.PASS

    def test_missing_returns_missing(self):
        assert _parse_auth_results_for(None, "spf") == AuthStatus.MISSING

    def test_fail_parsed(self):
        header = "mx.example.com; spf=fail smtp.mailfrom=bad@evil.com"
        assert _parse_auth_results_for(header, "spf") == AuthStatus.FAIL

    def test_softfail_parsed(self):
        header = "mx.example.com; spf=softfail smtp.mailfrom=bad@evil.com"
        assert _parse_auth_results_for(header, "spf") == AuthStatus.SOFTFAIL


class TestDKIMDomainExtraction:
    def test_extracts_d_tag(self):
        sig = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20210112"
        assert _extract_dkim_domain(sig) == "gmail.com"

    def test_returns_none_for_empty(self):
        assert _extract_dkim_domain(None) is None
        assert _extract_dkim_domain("") is None


class TestDMARCRecordParsing:
    def test_parses_reject_policy(self):
        record = "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"
        policy, pct = _parse_dmarc_record(record)
        assert policy == "reject"
        assert pct == 100

    def test_parses_none_policy(self):
        record = "v=DMARC1; p=none"
        policy, pct = _parse_dmarc_record(record)
        assert policy == "none"
        assert pct is None

    def test_none_record_returns_nones(self):
        policy, pct = _parse_dmarc_record(None)
        assert policy is None
        assert pct is None


class TestFullAuthCheckPhishing:
    def setup_method(self):
        email_data = parse_email_file(SAMPLES / "phishing.eml")
        self.auth = run_auth_checks(email_data)

    def test_spf_fails(self):
        assert self.auth.spf.status in (AuthStatus.FAIL, AuthStatus.SOFTFAIL, AuthStatus.MISSING)

    def test_dkim_fails_or_mismatch(self):
        assert self.auth.dkim.status in (AuthStatus.FAIL, AuthStatus.MISSING) or self.auth.dkim.domain_mismatch

    def test_returns_auth_check_result(self):
        assert self.auth.spf is not None
        assert self.auth.dkim is not None
        assert self.auth.dmarc is not None


class TestFullAuthCheckClean:
    def setup_method(self):
        email_data = parse_email_file(SAMPLES / "clean_email.eml")
        self.auth = run_auth_checks(email_data)

    def test_spf_passes(self):
        assert self.auth.spf.status == AuthStatus.PASS

    def test_dkim_passes(self):
        assert self.auth.dkim.status == AuthStatus.PASS

    def test_dmarc_passes(self):
        assert self.auth.dmarc.status == AuthStatus.PASS
