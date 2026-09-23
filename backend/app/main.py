from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import Base, engine
from app.rate_limit import RateLimitMiddleware
from app.routers import auth, assessments, findings, reports

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VULNIX Security Assessment API",
    description="Authorized-target security assessment engine: discovery, "
                "passive web/TLS/header checks, ZIP static analysis, "
                "findings, retest, and reporting.",
    version="1.0.0",
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    # Bearer-token auth (not cookies) is used throughout, so credentials
    # don't need to cross origins — this lets CORS_ORIGINS=* work in dev
    # without the browser rejecting the combination of "*" + credentials.
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(assessments.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "ok"}
