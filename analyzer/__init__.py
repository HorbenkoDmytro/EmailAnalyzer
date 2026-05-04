"""Phishing Email Analyzer — public package surface.

Re-exports the engine entry points so callers can do::

    from analyzer import analyze_email_file, Settings, AnalysisResult

The exports are loaded lazily so importing a single submodule (e.g.
``analyzer.parser``) doesn't pull in heavy optional dependencies like
``requests`` (used by ``threat_intel``) when they aren't needed.
"""

__all__ = [
    "AnalysisResult",
    "IntegrityInfo",
    "Settings",
    "analyze_email_bytes",
    "analyze_email_file",
]


def __getattr__(name: str):
    if name in {"AnalysisResult", "IntegrityInfo", "analyze_email_bytes", "analyze_email_file"}:
        from . import engine
        return getattr(engine, name)
    if name == "Settings":
        from .settings import Settings
        return Settings
    raise AttributeError(f"module 'analyzer' has no attribute {name!r}")
