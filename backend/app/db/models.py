from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="tester")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    consent_logs = relationship("ConsentLog", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class ConsentLog(Base):
    __tablename__ = "consent_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(512), nullable=False)
    target_type = Column(String(20), nullable=False)  # url or repo
    confirmed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="consent_logs")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target = Column(String(512), nullable=False)
    target_type = Column(String(20), nullable=False)  # url or repo
    status = Column(String(50), nullable=False, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(50), nullable=False)  # sast, dast, dependency, secret
    rule_id = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=True)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    severity_raw = Column(String(50), nullable=False)
    cvss_score = Column(Float, nullable=True)
    ai_confidence = Column(String(50), nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_fix_diff = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="open")  # open, confirmed, low_confidence, false_positive, fixed

    # ── Plain-language fields (added in PR 8 & enhanced) ─────────────────
    plain_title = Column(Text, nullable=True)           # Short headline, no jargon
    plain_location = Column(Text, nullable=True)        # User-visible location, never a file path
    plain_whats_wrong = Column(Text, nullable=True)     # Detailed 2-3 sentence layman explanation
    plain_why_it_exists = Column(Text, nullable=True)   # Layman explanation of why this bug exists
    plain_real_world_impact = Column(Text, nullable=True)  # Concrete business impact
    plain_risk_level = Column(String(120), nullable=True)  # e.g. "Fix this now — ..."
    plain_what_to_do = Column(Text, nullable=True)      # Next steps for non-technical owner
    feature_area = Column(String(100), nullable=True)   # Login & Accounts, Payments & Checkout, etc.

    scan = relationship("Scan", back_populates="findings")

