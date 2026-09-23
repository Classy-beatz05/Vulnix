from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import models, schemas, auth
from app.database import get_db
from app.engine_url import (check_https_and_headers, check_tls, check_wellknown_paths,
                             check_error_verbosity)
from app.security_utils import validate_target_url, SSRFError
from urllib.parse import urlparse

router = APIRouter(prefix="/findings", tags=["findings"])

# maps a check_id back to the single-check function that can re-verify it live
RECHECKS = {
    "missing_hsts": check_https_and_headers, "missing_csp": check_https_and_headers,
    "missing_xfo": check_https_and_headers, "missing_xcto": check_https_and_headers,
    "server_disclosure": check_https_and_headers, "permissive_cors": check_https_and_headers,
    "insecure_cookie": check_https_and_headers, "no_https": check_https_and_headers,
    "weak_tls_version": check_tls, "cert_expiring": check_tls, "cert_expired": check_tls,
    "exposed_git": check_wellknown_paths, "exposed_env": check_wellknown_paths,
    "missing_security_txt": check_wellknown_paths, "verbose_error": check_error_verbosity,
}


def _log(db: Session, request: Request, user_id: str, action: str, detail: str = ""):
    db.add(models.AuditLog(user_id=user_id, ip_address=request.client.host if request.client else None,
                            action=action, detail=detail))
    db.commit()


@router.post("/{finding_id}/retest", response_model=schemas.RetestResult)
def retest_finding(finding_id: str, request: Request, db: Session = Depends(get_db),
                    user: models.User = Depends(auth.get_current_user)):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    assessment = db.query(models.Assessment).filter(models.Assessment.id == finding.assessment_id).first()
    if not assessment or assessment.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Finding not found.")

    if assessment.type != "url":
        # source-derived findings need a fresh upload to genuinely re-verify
        finding.status = "Retesting"
        db.commit()
        finding.status = "Open"
        db.commit()
        _log(db, request, user.id, "retest_finding", finding_id)
        return schemas.RetestResult(id=finding.id, status=finding.status)

    finding.status = "Retesting"
    db.commit()

    check_fn = RECHECKS.get(finding.check_id)
    still_present = True
    if check_fn:
        try:
            base_url = validate_target_url(assessment.target)
            if check_fn is check_tls:
                results = check_fn(urlparse(base_url).hostname)
            else:
                results = check_fn(base_url)
            still_present = any(check_id == finding.check_id for check_id, _, _ in results)
        except SSRFError:
            still_present = True

    finding.status = "Open" if still_present else "Fixed"
    db.commit()
    _log(db, request, user.id, "retest_finding", f"{finding_id}:{finding.status}")
    return schemas.RetestResult(id=finding.id, status=finding.status)
