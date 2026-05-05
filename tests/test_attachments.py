"""Tests for the attachment analysis pipeline.

Exercises the full path: parser → attachments.analyze_attachments → engine
scoring. Uses a dedicated sample (phishing_with_attachment.eml) whose two
attachments have known, precomputed hashes so we can verify byte-level
correctness rather than just "some hash was produced".
"""

from pathlib import Path

import pytest

from analyzer import analyze_email_file
from analyzer.attachments import analyze_attachments
from analyzer.parser import parse_email_file
from analyzer.settings import Settings

SAMPLES = Path(__file__).parent / "samples"
SAMPLE = SAMPLES / "phishing_with_attachment.eml"
CLEAN_SAMPLE = SAMPLES / "clean_with_attachment.eml"


# Hashes precomputed from the raw payload bytes embedded (base64) in the
# sample files. If you regenerate the samples, update these values.
EXPECTED = {
    "invoice.pdf.exe": {
        "size": 24,
        "md5": "0c977dbcfd379eaf28f1c942e48b5872",
        "sha1": "1329a5a09807bf8a4b1073eb7fec284659f6e975",
        "sha256": "08f151e323a8b72152fbc289aceb66390af9f857d82e4916ece43ef248ff366c",
    },
    "report.docm": {
        "size": 23,
        "md5": "26ff31c03ffb348891c3bf0a85510a44",
        "sha1": "3f46e32945d60257b1fb9ff574dbdda4b228d58b",
        "sha256": "801305a30babfd5c20fe61fee5852705dc7342ff7886ac5e550a8dcff882462e",
    },
    "meeting-agenda.pdf": {
        "size": 26,
        "md5": "7dd369b7a90ba52a2d8c3d03fbfac387",
        "sha1": "d78fbb9a9f193fb56e70406797dc1a7d9b3fd29b",
        "sha256": "d630bf5e0cdc7993d8670cecda6f9a5a886b18f86e3ac2e2c5d2903d81462f7e",
    },
    "expense-receipt.png": {
        "size": 24,
        "md5": "1a0b355e21257ea063d3626e4a510f8b",
        "sha1": "a5837a9aa3ce815e74b4bbd01316ad195270313f",
        "sha256": "2ba2e9cdfe26f6eedc6cd6714185f38e5bb6adcb170bea009623e0637910b472",
    },
}


# ---------------------------------------------------------------------------
# Parser captures attachments
# ---------------------------------------------------------------------------

class TestParserCapturesAttachments:
    def setup_method(self):
        self.data = parse_email_file(SAMPLE)

    def test_two_attachments_parsed(self):
        assert len(self.data.attachments) == 2

    def test_filenames_preserved(self):
        names = sorted(a.filename for a in self.data.attachments)
        assert names == ["invoice.pdf.exe", "report.docm"]

    def test_payload_bytes_preserved(self):
        # Parser must keep the decoded bytes so the attachments module can
        # hash and (optionally) upload them. Empty payload would silently
        # break VT enrichment.
        for a in self.data.attachments:
            assert a.payload, f"empty payload for {a.filename}"
            assert a.size_bytes == len(a.payload)

    def test_content_types_preserved(self):
        types = {a.filename: a.content_type for a in self.data.attachments}
        assert types["invoice.pdf.exe"] == "application/octet-stream"
        assert "macroenabled" in types["report.docm"].lower()


# ---------------------------------------------------------------------------
# Attachments module — hashes
# ---------------------------------------------------------------------------

class TestAttachmentHashes:
    def setup_method(self):
        data = parse_email_file(SAMPLE)
        self.result = analyze_attachments(data, Settings(no_external=True))
        self.by_name = {r.filename: r for r in self.result.attachments}

    def test_total_count(self):
        assert self.result.total_count == 2

    def test_hash_lengths(self):
        for r in self.result.attachments:
            assert len(r.md5) == 32
            assert len(r.sha1) == 40
            assert len(r.sha256) == 64

    def test_hashes_are_lowercase_hex(self):
        for r in self.result.attachments:
            for h in (r.md5, r.sha1, r.sha256):
                assert all(c in "0123456789abcdef" for c in h), f"non-hex char in {h}"

    def test_known_hashes_invoice(self):
        r = self.by_name["invoice.pdf.exe"]
        exp = EXPECTED["invoice.pdf.exe"]
        assert r.size_bytes == exp["size"]
        assert r.md5 == exp["md5"]
        assert r.sha1 == exp["sha1"]
        assert r.sha256 == exp["sha256"]

    def test_known_hashes_macro_doc(self):
        r = self.by_name["report.docm"]
        exp = EXPECTED["report.docm"]
        assert r.size_bytes == exp["size"]
        assert r.md5 == exp["md5"]
        assert r.sha1 == exp["sha1"]
        assert r.sha256 == exp["sha256"]


# ---------------------------------------------------------------------------
# Attachments module — heuristic flags
# ---------------------------------------------------------------------------

class TestAttachmentFlags:
    def setup_method(self):
        data = parse_email_file(SAMPLE)
        self.result = analyze_attachments(data, Settings(no_external=True))
        self.by_name = {r.filename: r for r in self.result.attachments}

    def test_exe_flagged_as_suspicious_extension(self):
        r = self.by_name["invoice.pdf.exe"]
        assert r.has_suspicious_extension is True
        assert r.extension == ".exe"

    def test_double_extension_detected(self):
        r = self.by_name["invoice.pdf.exe"]
        assert r.has_double_extension is True

    def test_docm_flagged_as_suspicious_extension(self):
        r = self.by_name["report.docm"]
        assert r.has_suspicious_extension is True
        assert r.extension == ".docm"

    def test_docm_not_double_extension(self):
        r = self.by_name["report.docm"]
        assert r.has_double_extension is False

    def test_suspicious_count_matches_flagged_attachments(self):
        # Both attachments carry at least one flag.
        assert self.result.suspicious_count == 2

    def test_vt_skipped_in_local_only_mode(self):
        for r in self.result.attachments:
            assert r.vt_result is None
            assert r.vt_uploaded is False


# ---------------------------------------------------------------------------
# Engine — end-to-end
# ---------------------------------------------------------------------------

class TestEngineWithAttachments:
    def setup_method(self):
        self.result = analyze_email_file(SAMPLE, Settings(no_external=True))

    def test_integrity_hash_computed(self):
        assert len(self.result.integrity.sha256) == 64
        assert self.result.integrity.size_bytes > 0

    def test_attachments_propagated_to_result(self):
        assert self.result.attachments.total_count == 2
        names = {a.filename for a in self.result.attachments.attachments}
        assert names == {"invoice.pdf.exe", "report.docm"}

    def test_attachment_indicators_in_scoring(self):
        attachment_hits = [h for h in self.result.scoring.hits if h.category == "attachment"]
        # Expected: suspicious-extension hits for both files + double-extension
        # hit for invoice.pdf.exe.
        names = [h.name for h in attachment_hits]
        assert any("Suspicious Attachment: invoice.pdf.exe" in n for n in names)
        assert any("Suspicious Attachment: report.docm" in n for n in names)
        assert any("Double-Extension Attachment: invoice.pdf.exe" in n for n in names)

    def test_overall_risk_is_critical(self):
        # Auth fails + suspicious attachments + suspicious URLs / language
        # combined should comfortably exceed the Critical threshold (35).
        assert self.result.scoring.total_score >= 35
        assert self.result.scoring.risk_level.value == "Critical"

    def test_attachment_recommendation_present(self):
        assert any(
            "attachment" in r.lower() for r in self.result.scoring.recommendations
        )


# ---------------------------------------------------------------------------
# Clean email with benign attachments — symmetric counter-test
# ---------------------------------------------------------------------------

class TestCleanEmailWithAttachments:
    """A legitimate email carrying ordinary .pdf and .png attachments must
    still produce a Low-risk verdict and zero attachment indicators. This
    is the counter-example to TestEngineWithAttachments — without it, a
    naive implementation that flags every attachment would still pass the
    phishing tests."""

    def setup_method(self):
        self.parsed = parse_email_file(CLEAN_SAMPLE)
        self.attachments = analyze_attachments(
            self.parsed, Settings(no_external=True)
        )
        self.result = analyze_email_file(CLEAN_SAMPLE, Settings(no_external=True))
        self.by_name = {r.filename: r for r in self.attachments.attachments}

    # --- parser ---------------------------------------------------------

    def test_two_attachments_parsed(self):
        assert len(self.parsed.attachments) == 2

    def test_payload_bytes_preserved(self):
        for a in self.parsed.attachments:
            assert a.payload
            assert a.size_bytes == len(a.payload)

    # --- hashes ---------------------------------------------------------

    def test_known_hashes_pdf(self):
        r = self.by_name["meeting-agenda.pdf"]
        exp = EXPECTED["meeting-agenda.pdf"]
        assert r.size_bytes == exp["size"]
        assert r.md5 == exp["md5"]
        assert r.sha1 == exp["sha1"]
        assert r.sha256 == exp["sha256"]

    def test_known_hashes_png(self):
        r = self.by_name["expense-receipt.png"]
        exp = EXPECTED["expense-receipt.png"]
        assert r.size_bytes == exp["size"]
        assert r.md5 == exp["md5"]
        assert r.sha1 == exp["sha1"]
        assert r.sha256 == exp["sha256"]

    # --- flags ----------------------------------------------------------

    def test_pdf_not_flagged(self):
        r = self.by_name["meeting-agenda.pdf"]
        assert r.has_suspicious_extension is False
        assert r.has_double_extension is False
        assert r.flags == []

    def test_png_not_flagged(self):
        r = self.by_name["expense-receipt.png"]
        assert r.has_suspicious_extension is False
        assert r.has_double_extension is False
        assert r.flags == []

    def test_suspicious_count_is_zero(self):
        assert self.attachments.suspicious_count == 0

    def test_content_type_extension_match(self):
        # Content-Type values match expected MIME for their extension —
        # so the content-type-mismatch heuristic must NOT fire.
        assert self.by_name["meeting-agenda.pdf"].content_type == "application/pdf"
        assert self.by_name["expense-receipt.png"].content_type == "image/png"

    # --- engine end-to-end ---------------------------------------------

    def test_overall_risk_is_low(self):
        assert self.result.scoring.risk_level.value == "Low"
        assert self.result.scoring.total_score < 10

    def test_no_attachment_indicators_in_scoring(self):
        attachment_hits = [
            h for h in self.result.scoring.hits if h.category == "attachment"
        ]
        assert attachment_hits == []

    def test_all_auth_passes(self):
        from analyzer.auth_checks import AuthStatus
        assert self.result.auth.spf.status == AuthStatus.PASS
        assert self.result.auth.dkim.status == AuthStatus.PASS
        assert self.result.auth.dmarc.status == AuthStatus.PASS

    def test_integrity_hash_computed(self):
        assert len(self.result.integrity.sha256) == 64
        assert self.result.integrity.size_bytes > 0
