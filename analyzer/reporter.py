"""
PDF report generator using ReportLab.

Produces a professional, multi-section analysis report that can be
shared with stakeholders or attached to a security incident ticket.

Sections:
  1. Cover page — metadata + overall risk badge
  2. Authentication results — SPF / DKIM / DMARC with colour-coded status
  3. URL analysis table — per-URL heuristic flags
  4. Suspicious indicators — weighted hit list
  5. Recommendations
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from .attachments import AttachmentAnalysisResult
from .auth_checks import AuthCheckResult, AuthStatus
from .engine import IntegrityInfo
from .indicators import ScoringResult, RiskLevel
from .parser import EmailData
from .url_extractor import URLExtractionResult


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

COLOUR_PASS = colors.HexColor("#2ECC71")
COLOUR_FAIL = colors.HexColor("#E74C3C")
COLOUR_WARN = colors.HexColor("#F39C12")
COLOUR_INFO = colors.HexColor("#3498DB")
COLOUR_DARK = colors.HexColor("#2C3E50")
COLOUR_LIGHT = colors.HexColor("#ECF0F1")
COLOUR_WHITE = colors.white

RISK_COLOURS = {
    RiskLevel.LOW: colors.HexColor("#2ECC71"),
    RiskLevel.MEDIUM: colors.HexColor("#F39C12"),
    RiskLevel.HIGH: colors.HexColor("#E67E22"),
    RiskLevel.CRITICAL: colors.HexColor("#E74C3C"),
}

STATUS_COLOURS = {
    AuthStatus.PASS: COLOUR_PASS,
    AuthStatus.FAIL: COLOUR_FAIL,
    AuthStatus.SOFTFAIL: COLOUR_WARN,
    AuthStatus.NEUTRAL: COLOUR_INFO,
    AuthStatus.MISSING: COLOUR_WARN,
    AuthStatus.UNKNOWN: COLOUR_INFO,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf_report(
    output_path: str | Path,
    email_data: EmailData,
    auth_result: AuthCheckResult,
    url_result: URLExtractionResult,
    scoring_result: ScoringResult,
    attachment_result: Optional[AttachmentAnalysisResult] = None,
    integrity: Optional[IntegrityInfo] = None,
) -> Path:
    """Generate a PDF report and save it to output_path.

    Args:
        output_path: File path for the output PDF.
        email_data: Parsed email data.
        auth_result: SPF/DKIM/DMARC results.
        url_result: URL extraction and analysis results.
        scoring_result: Weighted indicator scoring results.
        attachment_result: Optional attachment analysis (hashes + VT verdicts).
        integrity: Optional original-file integrity info to render on the cover.

    Returns:
        Path to the generated PDF file.
    """
    path = Path(output_path)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="Phishing Email Analysis Report",
        author="Phishing Email Analyzer",
    )

    styles = _build_styles()
    story = []

    _add_cover(story, styles, email_data, scoring_result, integrity)
    _add_auth_section(story, styles, auth_result)
    _add_url_section(story, styles, url_result)
    if attachment_result is not None:
        _add_attachment_section(story, styles, attachment_result)
    _add_indicators_section(story, styles, scoring_result)
    _add_recommendations(story, styles, scoring_result)

    doc.build(story)
    return path


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"],
            fontSize=24, textColor=COLOUR_DARK, spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"],
            fontSize=11, textColor=colors.grey, spaceAfter=4,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"],
            fontSize=14, textColor=COLOUR_DARK, spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["Normal"],
            fontSize=9, leading=13,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["Normal"],
            fontSize=8, leading=11, textColor=colors.grey,
        ),
        "mono": ParagraphStyle(
            "Mono", parent=base["Code"],
            fontSize=7.5, leading=10,
        ),
        "risk_badge": ParagraphStyle(
            "RiskBadge", parent=base["Normal"],
            fontSize=18, alignment=TA_CENTER, textColor=COLOUR_WHITE,
        ),
        "detail": ParagraphStyle(
            "Detail", parent=base["Normal"],
            fontSize=8, leading=11, textColor=colors.HexColor("#555555"),
        ),
    }


# ---------------------------------------------------------------------------
# Cover page
# ---------------------------------------------------------------------------

def _add_cover(story, styles, email_data: EmailData, scoring: ScoringResult,
               integrity: Optional[IntegrityInfo] = None):
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_colour = RISK_COLOURS[scoring.risk_level]

    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Phishing Email Analysis Report", styles["title"]))
    story.append(Paragraph(f"Generated: {now}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=COLOUR_DARK, spaceAfter=12))

    # Metadata table
    meta_rows = [
        ["From", _safe(email_data.from_address)],
        ["Display Name", _safe(email_data.from_display_name)],
        ["To", _safe(", ".join(email_data.to_addresses))],
        ["Reply-To", _safe(email_data.reply_to)],
        ["Subject", _safe(email_data.subject)],
        ["Date", _safe(email_data.date)],
        ["Message-ID", _safe(email_data.message_id)],
    ]
    meta_table = Table(meta_rows, colWidths=[3.5 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (0, -1), COLOUR_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [COLOUR_WHITE, colors.HexColor("#F7F9FA")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.8 * cm))

    # Risk badge
    badge_text = f"Risk Level: {scoring.risk_level.value.upper()}   Score: {scoring.total_score}"
    badge_table = Table([[Paragraph(badge_text, styles["risk_badge"])]], colWidths=[16.5 * cm])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), risk_colour),
        ("ROUNDEDCORNERS", [8]),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 0.5 * cm))

    if integrity is not None:
        integrity_rows = [
            ["Original file", _safe(integrity.source_filename)],
            ["Size", f"{integrity.size_bytes:,} bytes"],
            ["MD5", integrity.md5],
            ["SHA-1", integrity.sha1],
            ["SHA-256", integrity.sha256],
            ["Analyzed at", integrity.analyzed_at],
        ]
        integrity_table = Table(integrity_rows, colWidths=[3.5 * cm, 13 * cm])
        integrity_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 2), (1, 4), "Courier"),
            ("BACKGROUND", (0, 0), (0, -1), COLOUR_LIGHT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(Paragraph("File Integrity", styles["h2"]))
        story.append(integrity_table)
        story.append(Spacer(1, 0.3 * cm))


# ---------------------------------------------------------------------------
# Authentication section
# ---------------------------------------------------------------------------

def _add_auth_section(story, styles, auth: AuthCheckResult):
    story.append(Paragraph("Authentication Results", styles["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_LIGHT, spaceAfter=8))

    rows = [["Protocol", "Status", "Details"]]
    for label, result in [("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)]:
        status = result.status
        colour = STATUS_COLOURS.get(status, COLOUR_INFO)
        status_cell = Paragraph(
            f'<font color="#{_hex(colour)}">{status.value.upper()}</font>',
            ParagraphStyle("sc", fontSize=9, fontName="Helvetica-Bold"),
        )
        rows.append([label, status_cell, Paragraph(result.detail[:180], styles["detail"])])

    auth_table = Table(rows, colWidths=[2.5 * cm, 2.5 * cm, 11.5 * cm])
    auth_table.setStyle(_standard_table_style(header=True))
    story.append(auth_table)
    story.append(Spacer(1, 0.5 * cm))


# ---------------------------------------------------------------------------
# URL section
# ---------------------------------------------------------------------------

def _add_url_section(story, styles, url_result: URLExtractionResult):
    story.append(Paragraph(
        f"URL Analysis  ({url_result.total_count} found, {url_result.suspicious_count} suspicious)",
        styles["h2"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_LIGHT, spaceAfter=8))

    if not url_result.urls:
        story.append(Paragraph("No URLs found in this email.", styles["body"]))
        return

    rows = [["URL", "Domain", "Flags"]]
    for u in url_result.urls:
        flag_text = "; ".join(u.flags) if u.flags else "None"
        vt_info = ""
        if u.vt_result and not u.vt_result.get("error"):
            mal = u.vt_result.get("malicious", 0)
            vt_info = f" | VT: {mal} malicious"
        rows.append([
            Paragraph(_safe(u.url[:60]) + ("…" if len(u.url) > 60 else ""), styles["mono"]),
            Paragraph(_safe(u.domain), styles["mono"]),
            Paragraph(flag_text + vt_info, styles["detail"]),
        ])

    url_table = Table(rows, colWidths=[5.5 * cm, 3.5 * cm, 7.5 * cm])
    url_table.setStyle(_standard_table_style(header=True))
    story.append(url_table)
    story.append(Spacer(1, 0.5 * cm))


# ---------------------------------------------------------------------------
# Attachments section
# ---------------------------------------------------------------------------

def _add_attachment_section(story, styles, attachments: AttachmentAnalysisResult):
    story.append(Paragraph(
        f"Attachments  ({attachments.total_count} found, {attachments.suspicious_count} suspicious)",
        styles["h2"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_LIGHT, spaceAfter=8))

    if not attachments.attachments:
        story.append(Paragraph("No attachments present.", styles["body"]))
        return

    rows = [["Filename", "Type", "Size", "Hashes", "Flags / VT"]]
    for a in attachments.attachments:
        hash_block = (
            f"MD5: {a.md5 or '—'}<br/>"
            f"SHA1: {a.sha1 or '—'}<br/>"
            f"SHA256: {a.sha256 or '—'}"
        )
        flag_text = "; ".join(a.flags) if a.flags else "None"
        if a.vt_result and not a.vt_result.get("error") and not a.vt_result.get("not_found"):
            mal = a.vt_result.get("malicious", 0)
            sus = a.vt_result.get("suspicious", 0)
            flag_text += f"<br/><i>VT: {mal} malicious, {sus} suspicious</i>"
        elif a.vt_result and a.vt_result.get("not_found"):
            flag_text += "<br/><i>VT: hash not in database</i>"
        rows.append([
            Paragraph(_safe(a.filename), styles["mono"]),
            Paragraph(_safe(a.content_type), styles["small"]),
            Paragraph(f"{a.size_bytes:,} B", styles["small"]),
            Paragraph(hash_block, styles["mono"]),
            Paragraph(flag_text, styles["detail"]),
        ])

    att_table = Table(rows, colWidths=[3.2 * cm, 2.5 * cm, 1.3 * cm, 5.5 * cm, 4 * cm])
    att_table.setStyle(_standard_table_style(header=True))
    story.append(att_table)
    story.append(Spacer(1, 0.5 * cm))


# ---------------------------------------------------------------------------
# Indicators section
# ---------------------------------------------------------------------------

def _add_indicators_section(story, styles, scoring: ScoringResult):
    story.append(Paragraph(
        f"Suspicious Indicators  ({len(scoring.hits)} triggered)", styles["h2"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_LIGHT, spaceAfter=8))

    if not scoring.hits:
        story.append(Paragraph("No suspicious indicators triggered.", styles["body"]))
        return

    rows = [["Indicator", "Category", "Weight", "Detail"]]
    for hit in sorted(scoring.hits, key=lambda h: h.weight, reverse=True):
        weight_colour = COLOUR_FAIL if hit.weight >= 7 else COLOUR_WARN if hit.weight >= 4 else COLOUR_INFO
        weight_cell = Paragraph(
            f'<font color="#{_hex(weight_colour)}"><b>{hit.weight}</b></font>',
            ParagraphStyle("wc", fontSize=9),
        )
        rows.append([
            Paragraph(hit.name, styles["body"]),
            Paragraph(hit.category.upper(), styles["small"]),
            weight_cell,
            Paragraph(hit.detail[:150], styles["detail"]),
        ])

    ind_table = Table(rows, colWidths=[4 * cm, 2 * cm, 1.5 * cm, 9 * cm])
    ind_table.setStyle(_standard_table_style(header=True))
    story.append(ind_table)
    story.append(Spacer(1, 0.5 * cm))


# ---------------------------------------------------------------------------
# Recommendations section
# ---------------------------------------------------------------------------

def _add_recommendations(story, styles, scoring: ScoringResult):
    story.append(Paragraph("Recommendations", styles["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOUR_LIGHT, spaceAfter=8))
    for i, rec in enumerate(scoring.recommendations, 1):
        story.append(Paragraph(f"{i}. {rec}", styles["body"]))
        story.append(Spacer(1, 3))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "Report generated by Phishing Email Analyzer — github.com/simoamine/phishing-email-analyzer",
        styles["small"],
    ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _standard_table_style(header: bool = False) -> TableStyle:
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CCCCCC")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1),
         [COLOUR_WHITE, colors.HexColor("#F7F9FA")]),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), COLOUR_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOUR_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    return TableStyle(style)


def _safe(value) -> str:
    """Convert None or empty to dash for display."""
    if value is None or value == "":
        return "—"
    return str(value)


def _hex(colour) -> str:
    """Return 6-char hex string for a ReportLab colour."""
    r = int(colour.red * 255)
    g = int(colour.green * 255)
    b = int(colour.blue * 255)
    return f"{r:02X}{g:02X}{b:02X}"
