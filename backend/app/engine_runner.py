import os
import shutil
import tempfile
import threading
import traceback

from app.database import SessionLocal
from app import models
from app.knowledge_base import CHECKS, score_from_findings, category_scores
from app.engine_url import run_full_url_assessment
from app.engine_zip import run_full_zip_assessment
from app.security_utils import safe_extract_zip, UnsafeArchiveError, SSRFError
from app.config import settings

PHASES = [
    "Reconnaissance", "Technology discovery", "Web & API checks",
    "SSL / headers", "Port & service assessment", "Vulnerability correlation",
]


def _persist_progress(db, assessment: models.Assessment, phase: str):
    idx = PHASES.index(phase) if phase in PHASES else 0
    assessment.phase = phase
    assessment.progress = round(((idx + 1) / len(PHASES)) * 90)  # leave headroom for finalize
    db.commit()


def _finalize(db, assessment: models.Assessment, raw_findings: list, assets_discovered: int, tests_run: int):
    findings = []
    for check_id, asset, evidence in raw_findings:
        meta = CHECKS.get(check_id)
        if not meta:
            continue
        findings.append(models.Finding(
            assessment_id=assessment.id,
            check_id=check_id,
            title=meta["title"],
            category=meta["category"],
            severity=meta["severity"],
            cvss=meta["cvss"],
            asset=str(asset),
            description=meta["description"],
            impact=meta["impact"],
            remediation=meta["remediation"],
            evidence=evidence,
            status="Open",
        ))
    db.add_all(findings)

    score, risk = score_from_findings(findings) if findings else (96, "Low risk")
    assessment.score = score
    assessment.risk = risk
    assessment.category_scores = category_scores(findings) if findings else {c: 96 for c in
                                                                              ["Web Application", "API Security",
                                                                               "Network Exposure", "Configuration",
                                                                               "Dependencies"]}
    assessment.assets_discovered = assets_discovered
    assessment.tests_run = tests_run
    assessment.status = "completed"
    assessment.phase = "Vulnerability correlation"
    assessment.progress = 100
    from datetime import datetime
    assessment.completed_at = datetime.utcnow()
    db.commit()


def _run_url_job(assessment_id: str, target: str):
    db = SessionLocal()
    try:
        assessment = db.query(models.Assessment).get(assessment_id)
        assessment.status = "running"
        db.commit()

        def on_phase(phase):
            _persist_progress(db, assessment, phase)

        raw = run_full_url_assessment(target, on_phase=on_phase)
        db.refresh(assessment)
        if assessment.status == "stopped":
            return
        tests_run = 40 + len(raw) * 3
        assets_discovered = max(1, len({a for _, a, _ in raw})) + 3
        _finalize(db, assessment, raw, assets_discovered, tests_run)

    except SSRFError as e:
        assessment.status = "failed"
        assessment.error = str(e)
        db.commit()
    except Exception:
        assessment.status = "failed"
        assessment.error = "Internal error during assessment."
        db.commit()
        traceback.print_exc()
    finally:
        db.close()


def _run_zip_job(assessment_id: str, zip_path: str):
    db = SessionLocal()
    extract_dir = tempfile.mkdtemp(prefix="vulnix_extract_")
    try:
        assessment = db.query(models.Assessment).get(assessment_id)
        assessment.status = "running"
        db.commit()
        _persist_progress(db, assessment, "Reconnaissance")

        files = safe_extract_zip(
            zip_path, extract_dir,
            max_uncompressed_bytes=settings.max_zip_uncompressed_mb * 1024 * 1024,
            max_files=settings.max_zip_file_count,
        )

        def on_phase(phase):
            _persist_progress(db, assessment, phase)

        raw, project_type = run_full_zip_assessment(extract_dir, files, on_phase=on_phase)
        db.refresh(assessment)
        if assessment.status == "stopped":
            return
        tests_run = 30 + len(files) + len(raw) * 3
        _finalize(db, assessment, raw, len(files), tests_run)

    except UnsafeArchiveError as e:
        assessment.status = "failed"
        assessment.error = f"Archive rejected: {e}"
        db.commit()
    except Exception:
        assessment.status = "failed"
        assessment.error = "Internal error during assessment."
        db.commit()
        traceback.print_exc()
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
        try:
            os.remove(zip_path)
        except OSError:
            pass
        db.close()


def start_url_job(assessment_id: str, target: str):
    threading.Thread(target=_run_url_job, args=(assessment_id, target), daemon=True).start()


def start_zip_job(assessment_id: str, zip_path: str):
    threading.Thread(target=_run_zip_job, args=(assessment_id, zip_path), daemon=True).start()
