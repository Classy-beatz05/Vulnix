import asyncio
import json
import os
import tempfile

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app import models, schemas, auth, engine_runner
from app.database import get_db
from app.security_utils import validate_target_url, SSRFError
from app.config import settings

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _log(db: Session, request: Request, user_id: str, action: str, detail: str = ""):
    db.add(models.AuditLog(
        user_id=user_id,
        ip_address=request.client.host if request.client else None,
        action=action,
        detail=detail,
    ))
    db.commit()


@router.post("/url", response_model=schemas.AssessmentOut, status_code=201)
def start_url_assessment(
    payload: schemas.StartUrlAssessment,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="You must confirm authorization to test this target.")

    try:
        normalized = validate_target_url(payload.target)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=str(e))

    assessment = models.Assessment(owner_id=user.id, target=normalized, type="url", status="queued")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    _log(db, request, user.id, "start_assessment", f"url:{normalized}")
    engine_runner.start_url_job(assessment.id, normalized)
    return assessment


@router.post("/zip", response_model=schemas.AssessmentOut, status_code=201)
def start_zip_assessment(
    request: Request,
    file: UploadFile = File(...),
    authorized: bool = Form(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    if not authorized:
        raise HTTPException(status_code=400, detail="You must confirm authorization to test this project.")
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted.")

    max_bytes = settings.max_zip_size_mb * 1024 * 1024
    fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="vulnix_upload_")
    size = 0
    with os.fdopen(fd, "wb") as out:
        while chunk := file.file.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                out.close()
                os.remove(tmp_path)
                raise HTTPException(status_code=413, detail=f"ZIP exceeds {settings.max_zip_size_mb}MB limit.")
            out.write(chunk)

    assessment = models.Assessment(owner_id=user.id, target=file.filename, type="zip", status="queued")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    _log(db, request, user.id, "start_assessment", f"zip:{file.filename}")
    engine_runner.start_zip_job(assessment.id, tmp_path)
    return assessment


@router.get("", response_model=list[schemas.AssessmentSummaryOut])
def list_assessments(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    rows = (
        db.query(models.Assessment)
        .filter(models.Assessment.owner_id == user.id)
        .order_by(models.Assessment.created_at.desc())
        .all()
    )
    out = []
    for a in rows:
        out.append(schemas.AssessmentSummaryOut(
            id=a.id, target=a.target, type=a.type, status=a.status,
            score=a.score, risk=a.risk, created_at=a.created_at,
            finding_count=len(a.findings),
        ))
    return out


def _get_owned_assessment(db, assessment_id, user):
    a = db.query(models.Assessment).filter(
        models.Assessment.id == assessment_id, models.Assessment.owner_id == user.id
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return a


@router.get("/{assessment_id}", response_model=schemas.AssessmentOut)
def get_assessment(assessment_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    return _get_owned_assessment(db, assessment_id, user)


@router.get("/{assessment_id}/stream")
async def stream_progress(
    assessment_id: str,
    request: Request,
    token: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Browser EventSource cannot set an Authorization header, so this route
    accepts the JWT as a `?token=` query param in addition to the header —
    every other route keeps header-only auth via get_current_user.
    """
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            raw_token = auth_header[7:]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing authentication token.")

    user = auth.get_user_from_raw_token(raw_token, db)
    _get_owned_assessment(db, assessment_id, user)  # ownership check

    async def event_gen():
        from app.database import SessionLocal
        last_payload = None
        while True:
            session = SessionLocal()
            try:
                a = session.query(models.Assessment).get(assessment_id)
                if not a:
                    break
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for f in a.findings:
                    counts[f.severity] += 1
                payload = json.dumps({
                    "status": a.status, "phase": a.phase, "progress": a.progress,
                    "counts": counts, "error": a.error,
                })
                if payload != last_payload:
                    yield f"data: {payload}\n\n"
                    last_payload = payload
                if a.status in ("completed", "failed", "stopped"):
                    break
            finally:
                session.close()
            await asyncio.sleep(0.6)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.post("/{assessment_id}/stop", response_model=schemas.AssessmentOut)
def stop_assessment(assessment_id: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    a = _get_owned_assessment(db, assessment_id, user)
    if a.status in ("queued", "running"):
        a.status = "stopped"
        db.commit()
        _log(db, request, user.id, "stop_assessment", assessment_id)
    return a
