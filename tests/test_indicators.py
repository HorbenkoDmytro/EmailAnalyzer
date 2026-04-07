"""Tests for the risk scoring engine."""

import pytest
from pathlib import Path

from analyzer.parser import parse_email_file
from analyzer.auth_checks import run_auth_checks
from analyzer.url_extractor import extract_and_analyze_urls
from analyzer.indicators import score_email, RiskLevel, _score_to_risk

SAMPLES = Path(__file__).parent / "samples"


class TestScoreToRisk:
    def test_low_risk(self):
        assert _score_to_risk(0) == RiskLevel.LOW
        assert _score_to_risk(9) == RiskLevel.LOW

    def test_medium_risk(self):
        assert _score_to_risk(10) == RiskLevel.MEDIUM
        assert _score_to_risk(19) == RiskLevel.MEDIUM

    def test_high_risk(self):
        assert _score_to_risk(20) == RiskLevel.HIGH
        assert _score_to_risk(34) == RiskLevel.HIGH

    def test_critical_risk(self):
        assert _score_to_risk(35) == RiskLevel.CRITICAL
        assert _score_to_risk(100) == RiskLevel.CRITICAL


class TestScoringPhishingEmail:
    def setup_method(self):
        email_data = parse_email_file(SAMPLES / "phishing.eml")
        auth_result = run_auth_checks(email_data)
        url_result = extract_and_analyze_urls(email_data.body_plain, email_data.body_html)
        self.scoring = score_email(email_data, auth_result, url_result)

    def test_risk_is_high_or_critical(self):
        assert self.scoring.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_score_is_positive(self):
        assert self.scoring.total_score > 0

    def test_indicators_triggered(self):
        assert len(self.scoring.hits) > 0

    def test_recommendations_provided(self):
        assert len(self.scoring.recommendations) > 0

    def test_auth_indicators_present(self):
        auth_hits = [h for h in self.scoring.hits if h.category == "auth"]
        assert len(auth_hits) > 0

    def test_url_indicators_present(self):
        url_hits = [h for h in self.scoring.hits if h.category == "url"]
        assert len(url_hits) > 0

    def test_content_indicators_present(self):
        content_hits = [h for h in self.scoring.hits if h.category == "content"]
        assert len(content_hits) > 0


class TestScoringCleanEmail:
    def setup_method(self):
        email_data = parse_email_file(SAMPLES / "clean_email.eml")
        auth_result = run_auth_checks(email_data)
        url_result = extract_and_analyze_urls(email_data.body_plain, email_data.body_html)
        self.scoring = score_email(email_data, auth_result, url_result)

    def test_risk_is_low(self):
        assert self.scoring.risk_level == RiskLevel.LOW

    def test_score_is_minimal(self):
        assert self.scoring.total_score < 10
