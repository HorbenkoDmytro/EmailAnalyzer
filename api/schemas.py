"""
Pydantic models for the FastAPI service.

These mirror the engine's dataclasses but are kept as their own layer so
that the public JSON contract is decoupled from internal types — and so
that FastAPI can produce a complete OpenAPI schema for ``/docs``.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field

from analyzer.engine import AnalysisResult


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = Field(..., examples=["ok"])
    time: str
    version: str


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------

class IntegritySchema(BaseModel):
    source_filename: Optional[str]
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    analyzed_at: str


class MetadataSchema(BaseModel):
    from_address: str
    from_display_name: str
    to_addresses: list[str]
    reply_to: Optional[str]
    subject: str
    date: Optional[str]
    message_id: Optional[str]
    x_mailer: Optional[str]
    x_originating_ip: Optional[str]


class AuthItemSchema(BaseModel):
    status: str
    detail: str


class AuthSchema(BaseModel):
    spf: AuthItemSchema
    dkim: AuthItemSchema
    dmarc: AuthItemSchema
    dmarc_policy: Optional[str] = None


class URLSchema(BaseModel):
    url: str
    domain: str
    display_text: Optional[str] = None
    flags: list[str] = []
    vt: Optional[dict[str, Any]] = None


class AttachmentSchema(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    extension: str
    flags: list[str] = []
    vt: Optional[dict[str, Any]] = None
    vt_uploaded: bool = False


class IndicatorSchema(BaseModel):
    name: str
    weight: int
    category: str
    detail: str


class ScoringSchema(BaseModel):
    risk_level: str
    total_score: int
    indicators: list[IndicatorSchema]
    recommendations: list[str]


# ---------------------------------------------------------------------------
# Top-level response
# ---------------------------------------------------------------------------

class AnalysisResponse(BaseModel):
    integrity: IntegritySchema
    settings: dict[str, Any]
    metadata: MetadataSchema
    auth: AuthSchema
    urls: list[URLSchema]
    attachments: list[AttachmentSchema]
    scoring: ScoringSchema

    @classmethod
    def from_engine(cls, result: AnalysisResult) -> "AnalysisResponse":
        return cls(
            integrity=IntegritySchema(
                source_filename=result.integrity.source_filename,
                size_bytes=result.integrity.size_bytes,
                md5=result.integrity.md5,
                sha1=result.integrity.sha1,
                sha256=result.integrity.sha256,
                analyzed_at=result.integrity.analyzed_at,
            ),
            settings=result.settings_summary,
            metadata=MetadataSchema(
                from_address=result.email.from_address,
                from_display_name=result.email.from_display_name,
                to_addresses=result.email.to_addresses,
                reply_to=result.email.reply_to,
                subject=result.email.subject,
                date=result.email.date,
                message_id=result.email.message_id,
                x_mailer=result.email.x_mailer,
                x_originating_ip=result.email.x_originating_ip,
            ),
            auth=AuthSchema(
                spf=AuthItemSchema(status=result.auth.spf.status.value, detail=result.auth.spf.detail),
                dkim=AuthItemSchema(status=result.auth.dkim.status.value, detail=result.auth.dkim.detail),
                dmarc=AuthItemSchema(status=result.auth.dmarc.status.value, detail=result.auth.dmarc.detail),
                dmarc_policy=result.auth.dmarc.policy,
            ),
            urls=[
                URLSchema(
                    url=u.url, domain=u.domain, display_text=u.display_text,
                    flags=list(u.flags), vt=u.vt_result,
                )
                for u in result.urls.urls
            ],
            attachments=[
                AttachmentSchema(
                    filename=a.filename, content_type=a.content_type,
                    size_bytes=a.size_bytes, md5=a.md5, sha1=a.sha1, sha256=a.sha256,
                    extension=a.extension, flags=list(a.flags),
                    vt=a.vt_result, vt_uploaded=a.vt_uploaded,
                )
                for a in result.attachments.attachments
            ],
            scoring=ScoringSchema(
                risk_level=result.scoring.risk_level.value,
                total_score=result.scoring.total_score,
                indicators=[
                    IndicatorSchema(name=h.name, weight=h.weight, category=h.category, detail=h.detail)
                    for h in result.scoring.hits
                ],
                recommendations=list(result.scoring.recommendations),
            ),
        )


# ---------------------------------------------------------------------------
# Async job endpoints
# ---------------------------------------------------------------------------

class JobAccepted(BaseModel):
    job_id: str
    status: str = "pending"
    status_url: str


class JobStatus(BaseModel):
    job_id: str
    status: str  # pending | running | completed | failed
    submitted_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[AnalysisResponse] = None
