#!/usr/bin/env python3
"""
Phishing Email Analyzer — CLI entry point.

Usage:
  python main.py <email.eml>
  python main.py <email.eml> --output report.pdf --vt-key YOUR_KEY
  python main.py <email.eml> --no-vt --verbose
  python main.py <email.eml> --json

Run --help for full option reference.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from analyzer.parser import parse_email_file
from analyzer.auth_checks import run_auth_checks, AuthStatus
from analyzer.url_extractor import extract_and_analyze_urls
from analyzer.indicators import score_email, RiskLevel
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
  python main.py suspicious.eml --no-vt --json --verbose
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
        help="Skip VirusTotal URL checks",
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


def main() -> int:
    args = build_parser().parse_args()

    email_path = Path(args.email_file)
    if not email_path.exists():
        console.print(f"[red]Error:[/red] File not found: {email_path}")
        return 1

    # --- Parse ---
    console.print(Panel(
        f"[bold]Phishing Email Analyzer[/bold]\nAnalyzing: [cyan]{email_path}[/cyan]",
        border_style="blue",
    ))

    with console.status("[bold blue]Parsing email...[/bold blue]"):
        try:
            email_data = parse_email_file(email_path)
        except Exception as exc:
            console.print(f"[red]Failed to parse email:[/red] {exc}")
            return 1

    _print_email_summary(email_data)

    # --- Auth checks ---
    with console.status("[bold blue]Running SPF / DKIM / DMARC checks...[/bold blue]"):
        auth_result = run_auth_checks(email_data)

    _print_auth_results(auth_result, verbose=args.verbose)

    # --- URL extraction ---
    with console.status("[bold blue]Extracting and analyzing URLs...[/bold blue]"):
        url_result = extract_and_analyze_urls(email_data.body_plain, email_data.body_html)

    _print_url_results(url_result, verbose=args.verbose)

    # --- VirusTotal ---
    if not args.no_vt and args.vt_key and url_result.urls:
        from analyzer.threat_intel import check_urls
        console.print(f"\n[bold blue]VirusTotal:[/bold blue] Checking {len(url_result.urls)} URL(s)…")
        console.print("[dim]  (free tier: 15s between requests — this may take a moment)[/dim]")
        vt_results = check_urls([u.url for u in url_result.urls], args.vt_key)
        for u in url_result.urls:
            vt = vt_results.get(u.url)
            if vt:
                u.vt_result = {
                    "malicious": vt.malicious,
                    "suspicious": vt.suspicious,
                    "harmless": vt.harmless,
                    "undetected": vt.undetected,
                    "permalink": vt.permalink,
                    "scan_date": vt.scan_date,
                    "error": vt.error,
                }
                if vt.malicious > 0:
                    console.print(f"  [red]MALICIOUS[/red] ({vt.malicious} engines): {u.url[:80]}")
                elif vt.error:
                    console.print(f"  [yellow]VT Error[/yellow] for {u.url[:60]}: {vt.error}")
                else:
                    console.print(f"  [green]Clean[/green]: {u.url[:80]}")
    elif not args.no_vt and not args.vt_key:
        console.print("\n[dim]VirusTotal skipped — no API key provided (use --vt-key or VT_API_KEY env var)[/dim]")

    # --- Scoring ---
    with console.status("[bold blue]Computing risk score...[/bold blue]"):
        scoring = score_email(email_data, auth_result, url_result)

    _print_risk_score(scoring)

    # --- PDF report ---
    output_path = args.output or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    with console.status(f"[bold blue]Generating PDF report → {output_path}[/bold blue]"):
        try:
            generate_pdf_report(output_path, email_data, auth_result, url_result, scoring)
            console.print(f"\n[green]PDF report saved:[/green] {output_path}")
        except Exception as exc:
            console.print(f"[red]PDF generation failed:[/red] {exc}")

    # --- Optional JSON output ---
    if args.json:
        json_path = Path(output_path).with_suffix(".json")
        _write_json(json_path, email_data, auth_result, url_result, scoring)
        console.print(f"[green]JSON summary saved:[/green] {json_path}")

    return 0


# ---------------------------------------------------------------------------
# Rich terminal output helpers
# ---------------------------------------------------------------------------

def _print_email_summary(email_data):
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


def _print_auth_results(auth_result, verbose: bool):
    console.print("\n[bold underline]Authentication Results[/bold underline]")
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
    table.add_column("Protocol", width=8)
    table.add_column("Status", width=12)
    table.add_column("Detail")

    for label, result in [("SPF", auth_result.spf), ("DKIM", auth_result.dkim), ("DMARC", auth_result.dmarc)]:
        style = AUTH_STYLES.get(result.status, "")
        detail = result.detail if verbose else result.detail[:80] + ("…" if len(result.detail) > 80 else "")
        table.add_row(label, Text(result.status.value.upper(), style=style), detail)

    console.print(table)


def _print_url_results(url_result, verbose: bool):
    console.print(
        f"\n[bold underline]URLs[/bold underline] "
        f"({url_result.total_count} found, "
        f"[{'red' if url_result.suspicious_count else 'green'}]{url_result.suspicious_count} suspicious[/])"
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


def _print_risk_score(scoring):
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
# JSON export
# ---------------------------------------------------------------------------

def _write_json(path: Path, email_data, auth_result, url_result, scoring):
    data = {
        "metadata": {
            "from": email_data.from_address,
            "from_display": email_data.from_display_name,
            "reply_to": email_data.reply_to,
            "subject": email_data.subject,
            "date": email_data.date,
        },
        "auth": {
            "spf": {"status": auth_result.spf.status.value, "detail": auth_result.spf.detail},
            "dkim": {"status": auth_result.dkim.status.value, "detail": auth_result.dkim.detail},
            "dmarc": {"status": auth_result.dmarc.status.value, "detail": auth_result.dmarc.detail},
        },
        "urls": [
            {
                "url": u.url,
                "domain": u.domain,
                "flags": u.flags,
                "vt": u.vt_result,
            }
            for u in url_result.urls
        ],
        "scoring": {
            "risk_level": scoring.risk_level.value,
            "total_score": scoring.total_score,
            "indicators": [
                {"name": h.name, "weight": h.weight, "category": h.category, "detail": h.detail}
                for h in scoring.hits
            ],
            "recommendations": scoring.recommendations,
        },
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
