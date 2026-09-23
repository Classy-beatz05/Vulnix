from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserOut(BaseModel):
    id: str
    email: EmailStr

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class StartUrlAssessment(BaseModel):
    target: str = Field(min_length=4, max_length=2048)
    authorized: bool = Field(
        description="Must be true — caller confirms authorization to test this target."
    )


class FindingOut(BaseModel):
    id: str
    check_id: str
    title: str
    category: str
    severity: str
    cvss: float
    asset: str
    description: str
    impact: str
    remediation: List[str]
    evidence: str
    status: str

    class Config:
        from_attributes = True


class AssessmentOut(BaseModel):
    id: str
    target: str
    type: str
    status: str
    phase: str
    progress: int
    error: Optional[str]
    score: Optional[int]
    risk: Optional[str]
    assets_discovered: int
    tests_run: int
    category_scores: dict
    created_at: datetime
    completed_at: Optional[datetime]
    findings: List[FindingOut] = []

    class Config:
        from_attributes = True


class AssessmentSummaryOut(BaseModel):
    id: str
    target: str
    type: str
    status: str
    score: Optional[int]
    risk: Optional[str]
    created_at: datetime
    finding_count: int

    class Config:
        from_attributes = True


class RetestResult(BaseModel):
    id: str
    status: str
