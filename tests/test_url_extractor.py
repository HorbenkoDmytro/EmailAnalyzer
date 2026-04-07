"""Tests for the URL extraction and analysis module."""

import pytest
from analyzer.url_extractor import (
    extract_and_analyze_urls,
    _check_ip_based, _check_shortener, _check_suspicious_tld,
    _check_homograph, _check_display_text_mismatch,
    _extract_from_plain, _extract_from_html,
)


class TestURLExtraction:
    def test_extracts_http_url_from_plain(self):
        urls = _extract_from_plain("Visit http://example.com for details")
        assert "http://example.com" in urls

    def test_extracts_https_url(self):
        urls = _extract_from_plain("Go to https://secure.example.com/path?q=1")
        assert any("secure.example.com" in u for u in urls)

    def test_extracts_anchor_href_from_html(self):
        html = '<a href="https://phish.tk/steal">Click here</a>'
        results = _extract_from_html(html)
        urls = [r[0] for r in results]
        assert any("phish.tk" in u for u in urls)

    def test_extracts_display_text_from_anchor(self):
        html = '<a href="https://phish.tk/steal">Click here</a>'
        results = _extract_from_html(html)
        texts = [r[1] for r in results]
        assert "Click here" in texts

    def test_extracts_form_action(self):
        html = '<form action="http://evil.com/post.php"><input></form>'
        results = _extract_from_html(html)
        urls = [r[0] for r in results]
        assert any("evil.com" in u for u in urls)


class TestIPBasedCheck:
    def test_ipv4_detected(self):
        assert _check_ip_based("192.168.1.100") is True

    def test_ipv6_detected(self):
        assert _check_ip_based("::1") is True

    def test_domain_not_detected(self):
        assert _check_ip_based("example.com") is False


class TestShortenerCheck:
    def test_bitly_detected(self):
        assert _check_shortener("bit.ly") is True

    def test_tinyurl_detected(self):
        assert _check_shortener("tinyurl.com") is True

    def test_legitimate_domain_not_detected(self):
        assert _check_shortener("paypal.com") is False


class TestSuspiciousTLD:
    def test_tk_detected(self):
        assert _check_suspicious_tld("suspicious.tk") is True

    def test_ml_detected(self):
        assert _check_suspicious_tld("free-money.ml") is True

    def test_com_not_detected(self):
        assert _check_suspicious_tld("paypal.com") is False

    def test_org_not_detected(self):
        assert _check_suspicious_tld("wikipedia.org") is False


class TestHomographCheck:
    def test_punycode_detected(self):
        assert _check_homograph("xn--pple-43d.com") is True

    def test_normal_domain_not_detected(self):
        assert _check_homograph("apple.com") is False


class TestDisplayTextMismatch:
    def test_mismatch_detected(self):
        # URL goes to evil.com but displays paypal.com
        assert _check_display_text_mismatch("http://evil.com/login", "http://paypal.com") is True

    def test_no_mismatch_for_plain_text(self):
        assert _check_display_text_mismatch("http://paypal.com", "Click here") is False

    def test_no_mismatch_when_domains_match(self):
        assert _check_display_text_mismatch("http://paypal.com/login", "paypal.com") is False


class TestFullExtraction:
    PHISHING_PLAIN = """
    URGENT: Click http://bit.ly/verify-now to restore your account.
    Or visit http://185.220.101.45/login.php
    """

    PHISHING_HTML = """
    <html><body>
    <a href="http://phish.tk/steal">Click here to verify</a>
    <a href="http://paypal.com.evil.xyz/login">http://paypal.com</a>
    </body></html>
    """

    def test_full_extraction_finds_urls(self):
        result = extract_and_analyze_urls(self.PHISHING_PLAIN, self.PHISHING_HTML)
        assert result.total_count > 0

    def test_suspicious_urls_flagged(self):
        result = extract_and_analyze_urls(self.PHISHING_PLAIN, self.PHISHING_HTML)
        assert result.suspicious_count > 0

    def test_ip_url_flagged(self):
        result = extract_and_analyze_urls(self.PHISHING_PLAIN, "")
        ip_urls = [u for u in result.urls if u.is_ip_based]
        assert len(ip_urls) > 0

    def test_shortener_flagged(self):
        result = extract_and_analyze_urls(self.PHISHING_PLAIN, "")
        shortener_urls = [u for u in result.urls if u.is_shortener]
        assert len(shortener_urls) > 0
