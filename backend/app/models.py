import uuid
from datetime import datetime

from sqlalchemy import (Column, String, Integer, Float, DateTime, ForeignKey,
                         Text, JSON, Boolean)
from sqlalchemy.orm import relationship

from app.database import Base


def gen_id():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=gen_id)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    assessments = relationship("Assessment", back_populates="owner")


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(String, primary_key=True, default=gen_id)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)

    target = Column(String, nullable=False)
    type = Column(String, nullable=False)  # "url" or "zip"

    status = Column(String, default="queued")  # queued/running/completed/failed/stopped
    phase = Column(String, default="")
    progress = Column(Integer, default=0)
    error = Column(Text, nullable=True)

    score = Column(Integer, nullable=True)
    risk = Column(String, nullable=True)
    assets_discovered = Column(Integer, default=0)
    tests_run = Column(Integer, default=0)
    category_scores = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="assessments")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=gen_id)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)

    check_id = Column(String, nullable=False)
    title = Column(String, nullable=False)
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # critical/high/medium/low
    cvss = Column(Float, nullable=False)
    asset = Column(String, nullable=False)

    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    remediation = Column(JSON, default=list)
    evidence = Column(Text, nullable=False)

    status = Column(String, default="Open")  # Open/Retesting/Fixed
    created_at = Column(DateTime, default=datetime.utcnow)

    assessment = relationship("Assessment", back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String, primary_key=True, default=gen_id)
    user_id = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    action = Column(String, nullable=False)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
