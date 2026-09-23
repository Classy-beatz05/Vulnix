import csv
import io
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app import models, auth
from app.database import get_db

router = APIRouter(prefix="/reports", tags=["reports"])


def _get_assessment(db, assessment_id, user):
    a = db.query(models.Assessment).filter(
        models.Assessment.id == assessment_id, models.Assessment.owner_id == user.id
    ).first()
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return a


@router.get("/{assessment_id}/json")
def export_json(assessment_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    a = _get_assessment(db, assessment_id, user)
    payload = {
        "target": a.target, "type": a.type, "score": a.score, "risk": a.risk,
        "assets_discovered": a.assets_discovered, "tests_run": a.tests_run,
        "category_scores": a.category_scores, "created_at": a.created_at.isoformat(),
        "findings": [
            {"title": f.title, "category": f.category, "severity": f.severity, "cvss": f.cvss,
             "asset": f.asset, "status": f.status, "description": f.description,
             "impact": f.impact, "remediation": f.remediation, "evidence": f.evidence}
            for f in a.findings
        ],
    }
    headers = {"Content-Disposition": f"attachment; filename=vulnix-{a.id}.json"}
    return JSONResponse(content=payload, headers=headers)


@router.get("/{assessment_id}/csv")
def export_csv(assessment_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    a = _get_assessment(db, assessment_id, user)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Finding", "Asset", "Severity", "CVSS", "Status", "Category"])
    for f in a.findings:
        writer.writerow([f.title, f.asset, f.severity, f.cvss, f.status, f.category])
    buf.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=vulnix-{a.id}.csv"}
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers=headers)


@router.get("/{assessment_id}/pdf")
def export_pdf(assessment_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    a = _get_assessment(db, assessment_id, user)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    y = height - 60

    def line(text, size=11, gap=16, bold=False):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 60
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(50, y, text[:110])
        y -= gap

    line("VULNIX — Assessment Report", 16, 24, bold=True)
    line(f"Target: {a.target}")
    line(f"Date: {a.created_at.strftime('%Y-%m-%d %H:%M UTC')}")
    line(f"Security Score: {a.score}/100  ({a.risk})", bold=True)
    line("")
    line("Findings by severity:", bold=True)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in a.findings:
        counts[f.severity] += 1
    for k, v in counts.items():
        line(f"  {k.title()}: {v}")
    line("")
    line("Detail:", bold=True)
    for f in a.findings:
        line(f"[{f.severity.upper()}] {f.title} — {f.asset} — CVSS {f.cvss} — {f.status}")

    c.save()
    buf.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=vulnix-{a.id}.pdf"}
    return StreamingResponse(iter([buf.getvalue()]), media_type="application/pdf", headers=headers)
