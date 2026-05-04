#!/usr/bin/env python3
"""
Phishing Email Analyzer — CLI entry point.

The CLI is a thin layer over :mod:`analyzer.engine`. All analysis logic
lives in the engine; this file only handles argument parsing, terminal
rendering, and writing report artefacts to disk.

Usage:
  python main.py <email.eml>
  python main.py <email.eml> --output report.pdf --vt-key YOUR_KEY
  python main.py <email.eml> --no-external --json --verbose
  python main.py <email.eml> --local-only

Run --help for full option reference.
"""

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from analyzer import AnalysisResult, Settings, analyze_email_file
from analyzer.auth_checks import AuthStatus
from analyzer.indicators import RiskLevel
from analyzer.reporter import generate_pdf_report

load_dotenv()

console = Console()

RISK_STYLES = {
    RiskLevel.LOW: "bold green",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.HIGH: "bold dark_orange",
    RiskLevel.CRITICAL: "bold red",
}

AUTH_STYLES = {
    AuthStatus.PASS: "green",
    AuthStatus.FAIL: "red",
    AuthStatus.SOFTFAIL: "yellow",
    AuthStatus.NEUTRAL: "cyan",
    AuthStatus.MISSING: "yellow",
    AuthStatus.UNKNOWN: "cyan",
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Analyze an email file (.eml) for phishing indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py suspicious.eml
  python main.py suspicious.eml --output report.pdf --vt-key abc123
  python main.py suspicious.eml --no-external --json --verbose
  python main.py suspicious.eml --local-only
        """,
    )
    p.add_argument("email_file", help="Path to the .eml file to analyze")
    p.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="PDF output path (default: report_<timestamp>.pdf)",
    )
    p.add_argument(
        "--vt-key",
        metavar="KEY",
        default=os.getenv("VT_API_KEY"),
        help="VirusTotal API key (or set VT_API_KEY env var)",
    )
    p.add_argument(
        "--no-vt",
        action="store_true",
        help="Skip VirusTotal lookups (URLs and attachments)",
    )
    p.add_argument(
        "--no-external",
        action="store_true",
        help="Disable all external network calls (DNS + VirusTotal). Implies --no-vt.",
    )
    p.add_argument(
        "--local-only",
        action="store_true",
        help="Alias for --no-external; runs the analyzer fully offline.",
    )
    p.add_argument(
        "--vt-upload",
        action="store_true",
        help="Upload attachments whose hash is unknown to VirusTotal "
             "(slow; consumes free-tier quota).",
    )
    p.add_argument(
        "--no-pdf",
        action="store_true",
        help="Skip PDF report generation",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed analysis output in the terminal",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Also write a JSON summary alongside the PDF",
    )
    return p


def build_settings(args) -> Settings:
    no_external = args.no_external or args.local_only
    enable_vt = not args.no_vt and not no_external
    return Settings.from_env(
        vt_api_key=args.vt_key,
        no_external=no_external,
        enable_vt=enable_vt,
        vt_upload_unknown_files=args.vt_upload,
    )


def main() -> int:
    args = build_parser().parse_args()

    email_path = Path(args.email_file)
    if not email_path.exists():
        console.print(f"[red]Error:[/red] File not found: {email_path}")
        return 1

    settings = build_settings(args)

    console.print(Panel(
        f"[bold]Phishing Email Analyzer[/bold]\n"
        f"Analyzing: [cyan]{email_path}[/cyan]\n"
        f"Mode: {_mode_label(settings)}",
        border_style="blue",
    ))

    def _progress(msg: str) -> None:
        console.print(f"[dim]·[/dim] {msg}")

    try:
        result = analyze_email_file(email_path, settings, progress=_progress)
    except Exception as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        return 1

    _print_email_summary(result)
    _print_integrity(result)
    _print_auth_results(result, verbose=args.verbose)
    _print_url_results(result, verbose=args.verbose)
    _print_attachment_results(result, verbose=args.verbose)
    _print_risk_score(result)

    output_path = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    if not args.no_pdf:
        try:
            generate_pdf_report(
                output_path,
                result.email,
                result.auth,
                result.urls,
                result.scoring,
                attachment_result=result.attachments,
                integrity=result.integrity,
            )
            console.print(f"\n[green]PDF report saved:[/green] {output_path}")
        except Exception as exc:
            console.print(f"[red]PDF generation failed:[/red] {exc}")

    if args.json:
        json_path = Path(output_path).with_suffix(".json")
        json_path.write_text(json.dumps(_serialise(result), indent=2), encoding="utf-8")
        console.print(f"[green]JSON summary saved:[/green] {json_path}")

    return 0


# ---------------------------------------------------------------------------
# Rich terminal output helpers
# ---------------------------------------------------------------------------

def _mode_label(settings: Settings) -> str:
    if settings.no_external:
        return "[yellow]local-only (no DNS / no VirusTotal)[/yellow]"
    parts = []
    parts.append("DNS on" if settings.dns_active else "DNS off")
    if settings.vt_active:
        parts.append("VirusTotal on")
    elif settings.enable_vt and not settings.vt_api_key:
        parts.append("VirusTotal disabled (no API key)")
    else:
        parts.append("VirusTotal off")
    return ", ".join(parts)


def _print_email_summary(result: AnalysisResult) -> None:
    email_data = result.email
    console.print("\n[bold underline]Email Metadata[/bold underline]")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", min_width=15)
    grid.add_column()
    rows = [
        ("From", email_data.from_address),
        ("Display Name", email_data.from_display_name or "—"),
        ("Reply-To", email_data.reply_to or "—"),
        ("Subject", email_data.subject),
        ("Date", email_data.date or "—"),
        ("X-Mailer", email_data.x_mailer or "—"),
        ("Attachments", str(len(email_data.attachments))),
    ]
    for label, value in rows:
        grid.add_row(label + ":", value)
    console.print(grid)


def _print_integrity(result: AnalysisResult) -> None:
    integ = result.integrity
    console.print("\n[bold underline]File Integrity[/bold underline]")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", min_width=10)
    grid.add_column()
    grid.add_row("File:", integ.source_filename or "—")
    grid.add_row("Size:", f"{integ.size_bytes:,} bytes")
    grid.add_row("MD5:", integ.md5)
    grid.add_row("SHA-1:", integ.sha1)
    grid.add_row("SHA-256:", integ.sha256)
    console.print(grid)


def _print_auth_results(result: AnalysisResult, verbose: bool) -> None:
    auth_result = result.auth
    console.print("\n[bold underline]Authentication Results[/bold underline]")
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
    table.add_column("Protocol", width=8)
    table.add_column("Status", width=12)
    table.add_column("Detail")

    for label, item in [("SPF", auth_result.spf), ("DKIM", auth_result.dkim), ("DMARC", auth_result.dmarc)]:
        style = AUTH_STYLES.get(item.status, "")
        detail = item.detail if verbose else item.detail[:80] + ("…" if len(item.detail) > 80 else "")
        table.add_row(label, Text(item.status.value.upper(), style=style), detail)

    console.print(table)


def _print_url_results(result: AnalysisResult, verbose: bool) -> None:
    url_result = result.urls
    console.print(
        f"\n[bold underline]URLs[/bold underline] "
        f"({url_result.total_count} found, "
        f"[{'red' if url_result.suspicious_count else 'green'}]"
        f"{url_result.suspicious_count} suspicious[/])"
    )
    if not url_result.urls:
        console.print("  No URLs found.")
        return
    for u in url_result.urls:
        colour = "red" if u.flags else "green"
        label = "[SUSPICIOUS]" if u.flags else "[clean]"
        console.print(f"  [{colour}]{label}[/{colour}] {u.url[:90]}")
        if verbose and u.flags:
            for flag in u.flags:
                console.print(f"      [dim]• {flag}[/dim]")


def _print_attachment_results(result: AnalysisResult, verbose: bool) -> None:
    attachments = result.attachments
    console.print(
        f"\n[bold underline]Attachments[/bold underline] "
        f"({attachments.total_count} found, "
        f"[{'red' if attachments.suspicious_count else 'green'}]"
        f"{attachments.suspicious_count} suspicious[/])"
    )
    if not attachments.attachments:
        console.print("  No attachments.")
        return
    for a in attachments.attachments:
        colour = "red" if a.flags else "green"
        label = "[SUSPICIOUS]" if a.flags else "[clean]"
        size = f"{a.size_bytes:,}B"
        console.print(
            f"  [{colour}]{label}[/{colour}] {a.filename} "
            f"[dim]({a.content_type}, {size})[/dim]"
        )
        if a.sha256:
            console.print(f"      [dim]sha256: {a.sha256}[/dim]")
        if verbose:
            if a.md5:
                console.print(f"      [dim]md5:    {a.md5}[/dim]")
            if a.sha1:
                console.print(f"      [dim]sha1:   {a.sha1}[/dim]")
        if a.flags:
            for flag in a.flags:
                console.print(f"      [yellow]• {flag}[/yellow]")
        if a.vt_result and a.vt_result.get("permalink") and verbose:
            console.print(f"      [dim]VT: {a.vt_result['permalink']}[/dim]")


def _print_risk_score(result: AnalysisResult) -> None:
    scoring = result.scoring
    style = RISK_STYLES.get(scoring.risk_level, "bold")
    console.print(Panel(
        f"[{style}]RISK LEVEL: {scoring.risk_level.value.upper()}[/{style}]\n"
        f"Score: {scoring.total_score}  |  Indicators triggered: {len(scoring.hits)}",
        title="[bold]Analysis Summary[/bold]",
        border_style="red" if scoring.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else "yellow",
    ))
    console.print("\n[bold underline]Recommendations[/bold underline]")
    for i, rec in enumerate(scoring.recommendations, 1):
        console.print(f"  {i}. {rec}")


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

def _serialise(result: AnalysisResult) -> dict:
    """Return a JSON-friendly view of the AnalysisResult."""
    email = result.email
    return {
        "integrity": asdict(result.integrity),
        "settings": result.settings_summary,
        "metadata": {
            "from": email.from_address,
            "from_display": email.from_display_name,
            "to": email.to_addresses,
            "reply_to": email.reply_to,
            "subject": email.subject,
            "date": email.date,
            "message_id": email.message_id,
            "x_mailer": email.x_mailer,
            "x_originating_ip": email.x_originating_ip,
        },
        "auth": {
            "spf": {"status": result.auth.spf.status.value, "detail": result.auth.spf.detail},
            "dkim": {"status": result.auth.dkim.status.value, "detail": result.auth.dkim.detail},
            "dmarc": {"status": result.auth.dmarc.status.value, "detail": result.auth.dmarc.detail,
                       "policy": result.auth.dmarc.policy},
        },
        "urls": [
            {
                "url": u.url,
                "domain": u.domain,
                "display_text": u.display_text,
                "flags": u.flags,
                "vt": u.vt_result,
            }
            for u in result.urls.urls
        ],
        "attachments": [
            {
                "filename": a.filename,
                "content_type": a.content_type,
                "size_bytes": a.size_bytes,
                "md5": a.md5,
                "sha1": a.sha1,
                "sha256": a.sha256,
                "flags": a.flags,
                "vt": a.vt_result,
                "vt_uploaded": a.vt_uploaded,
            }
            for a in result.attachments.attachments
        ],
        "scoring": {
            "risk_level": result.scoring.risk_level.value,
            "total_score": result.scoring.total_score,
            "indicators": [
                {"name": h.name, "weight": h.weight, "category": h.category, "detail": h.detail}
                for h in result.scoring.hits
            ],
            "recommendations": result.scoring.recommendations,
        },
    }


if __name__ == "__main__":
    sys.exit(main())
