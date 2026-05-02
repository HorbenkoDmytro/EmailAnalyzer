"""
FastAPI service that exposes the analyzer engine over HTTP.

Endpoints
---------
GET  /health                 → liveness check
POST /analyze                → run analysis (sync) or enqueue (async)
GET  /analyze/jobs/{job_id}  → poll an async job

The service does not own any analysis logic — it constructs Settings from
the request, calls :func:`analyzer.engine.analyze_email_bytes`, and serialises
the result through :class:`api.schemas.AnalysisResponse`.

Run with::

    uvicorn api.main:app --reload --port 8000
"""

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import (
    BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile,
)

from analyzer import Settings, analyze_email_bytes

from .schemas import (
    AnalysisResponse, HealthResponse, JobAccepted, JobStatus,
)

load_dotenv()
logger = logging.getLogger("analyzer.api")

API_VERSION = "1.0.0"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB

app = FastAPI(
    title="Phishing Email Analyzer API",
    description=(
        "HTTP front-end for the phishing email analyzer engine. "
        "Accepts .eml uploads and returns SPF/DKIM/DMARC results, "
        "URL and attachment analysis, and a weighted risk score."
    ),
    version=API_VERSION,
)


# In-memory job store. Sufficient for single-process deployments; replace
# with Redis or a database when horizontally scaling.
_JOBS: dict[str, JobStatus] = {}
_JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        time=datetime.now(timezone.utc).isoformat(),
        version=API_VERSION,
    )


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------

@app.post(
    "/analyze",
    response_model=None,  # response shape depends on `mode`
    tags=["analysis"],
    summary="Analyze an .eml file (sync or async)",
)
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description=".eml file to analyze"),
    mode: str = Form("sync", description="'sync' returns the full report; 'async' enqueues a job"),
    no_external: bool = Form(False, description="Disable all external network calls (DNS + VT)"),
    enable_vt: bool = Form(True, description="Enable VirusTotal lookups (requires vt_api_key)"),
    vt_api_key: Optional[str] = Form(None, description="Override the VT_API_KEY env var"),
    vt_upload_unknown_files: bool = Form(False, description="Upload unknown attachment hashes to VT"),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty upload")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(raw)} bytes); max is {MAX_UPLOAD_BYTES}",
        )
    if mode not in ("sync", "async"):
        raise HTTPException(status_code=400, detail="mode must be 'sync' or 'async'")

    settings = _build_settings(
        no_external=no_external,
        enable_vt=enable_vt,
        vt_api_key=vt_api_key,
        vt_upload_unknown_files=vt_upload_unknown_files,
    )

    if mode == "sync":
        try:
            result = analyze_email_bytes(raw, settings, source_filename=file.filename)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Could not parse email: {exc}") from exc
        except Exception as exc:  # pragma: no cover — defensive top-level catch
            logger.exception("Analysis failed")
            raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc
        return AnalysisResponse.from_engine(result)

    # mode == "async"
    job_id = str(uuid.uuid4())
    job = JobStatus(
        job_id=job_id,
        status="pending",
        submitted_at=datetime.now(timezone.utc).isoformat(),
    )
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    background_tasks.add_task(_run_job, job_id, raw, file.filename, settings)
    return JobAccepted(job_id=job_id, status_url=f"/analyze/jobs/{job_id}")


@app.get(
    "/analyze/jobs/{job_id}",
    response_model=JobStatus,
    tags=["analysis"],
    summary="Poll an async analysis job",
)
def analyze_job_status(job_id: str) -> JobStatus:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_settings(
    *,
    no_external: bool,
    enable_vt: bool,
    vt_api_key: Optional[str],
    vt_upload_unknown_files: bool,
) -> Settings:
    overrides = {
        "no_external": no_external,
        "enable_vt": enable_vt and not no_external,
        "vt_upload_unknown_files": vt_upload_unknown_files,
    }
    if vt_api_key:
        overrides["vt_api_key"] = vt_api_key
    return Settings.from_env(**overrides)


def _run_job(job_id: str, raw: bytes, filename: Optional[str], settings: Settings) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return
        job.status = "running"

    try:
        result = analyze_email_bytes(raw, settings, source_filename=filename)
        response = AnalysisResponse.from_engine(result)
        with _JOBS_LOCK:
            current = _JOBS.get(job_id)
            if current is not None:
                current.status = "completed"
                current.completed_at = datetime.now(timezone.utc).isoformat()
                current.result = response
    except Exception as exc:
        logger.exception("Async analysis failed for job %s", job_id)
        with _JOBS_LOCK:
            current = _JOBS.get(job_id)
            if current is not None:
                current.status = "failed"
                current.completed_at = datetime.now(timezone.utc).isoformat()
                current.error = str(exc)
