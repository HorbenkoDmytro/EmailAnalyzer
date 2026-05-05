"""Tests for the email parser module."""

import pytest
from pathlib import Path

from analyzer.parser import parse_email_file, parse_email_string, EmailData

SAMPLES = Path(__file__).parent / "samples"


class TestParsePhishingEmail:
    def setup_method(self):
        self.data = parse_email_file(SAMPLES / "phishing.eml")

    def test_from_address_extracted(self):
        assert "amaz0n-delivery.tk" in self.data.from_address

    def test_reply_to_extracted(self):
        assert self.data.reply_to is not None
        assert "quick-survey" in self.data.reply_to

    def test_subject_extracted(self):
        assert "ALERT" in self.data.subject

    def test_x_mailer_extracted(self):
        assert self.data.x_mailer is not None
        assert "Sendblaster" in self.data.x_mailer

    def test_x_originating_ip_extracted(self):
        assert self.data.x_originating_ip is not None

    def test_body_plain_contains_url(self):
        assert "http" in self.data.body_plain

    def test_body_html_contains_form(self):
        assert "form" in self.data.body_html.lower()

    def test_dkim_signature_extracted(self):
        # Phishing email has a (failing) DKIM signature header
        assert self.data.dkim_signature is not None

    def test_received_chain_is_list(self):
        assert isinstance(self.data.received_chain, list)


class TestParseCleanEmail:
    def setup_method(self):
        self.data = parse_email_file(SAMPLES / "clean_email.eml")

    def test_from_address(self):
        assert "stripe.com" in self.data.from_address

    def test_reply_to_matches_from(self):
        if self.data.reply_to:
            assert "stripe.com" in self.data.reply_to

    def test_authentication_results_present(self):
        assert self.data.authentication_results is not None

    def test_body_plain_not_empty(self):
        assert len(self.data.body_plain) > 0

    def test_no_attachments(self):
        assert self.data.attachments == []


class TestParseEmailString:
    MINIMAL = """\
From: test@example.com
To: dest@example.com
Subject: Hello

Body text here.
"""

    def test_minimal_email_parsed(self):
        data = parse_email_string(self.MINIMAL)
        assert data.from_address == "test@example.com"
        assert data.subject == "Hello"
        assert "Body text" in data.body_plain

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_email_file("/nonexistent/path/email.eml")
