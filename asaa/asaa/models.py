"""SQLAlchemy ORM models — the persistent realisation of the Ch.5 class
diagram (5.4) and entity-relationship diagram (5.5).

Key design property (Ch.5 6.1): the per-target authorisation invariant is a
data-model invariant. `Scan.auth_record_id` is a real foreign key to
`AuthorizationRecord`; the Authorisation Guard validates it before a Mode 2/3
scan row is ever persisted, so it is impossible to store an active-mode scan
without a recorded authorisation.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        String, Text)
from sqlalchemy.orm import relationship

from .db import Base


def _uid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_uid)
    email = Column(String, unique=True, nullable=False)
    display_name = Column(String, nullable=False, default="Analyst")
    created_at = Column(DateTime, default=_now)
    targets = relationship("Target", back_populates="owner")


class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True, default=_uid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False, unique=True)
    owner_email = Column(String, nullable=False)
    status = Column(String, default="Registered")
    created_at = Column(DateTime, default=_now)

    owner = relationship("User", back_populates="targets")
    authorizations = relationship("AuthorizationRecord", back_populates="target",
                                  cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    technologies = relationship("TargetTechnology", back_populates="target",
                                cascade="all, delete-orphan")
    alerts = relationship("AlertRecord", back_populates="target",
                          cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="target",
                           cascade="all, delete-orphan")


class AuthorizationRecord(Base):
    """One record per mode the target owner has authorised (UC-1)."""
    __tablename__ = "authorization_records"
    id = Column(String, primary_key=True, default=_uid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    covers_mode_2 = Column(Boolean, default=False)
    covers_mode_3 = Column(Boolean, default=False)
    document_name = Column(String, nullable=True)
    document_hash = Column(String, nullable=True)     # SHA-256 of uploaded auth doc
    acknowledged = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)
    target = relationship("Target", back_populates="authorizations")


class Scan(Base):
    """Single table for all three modes (ERD 5.5). `mode` distinguishes them;
    `auth_record_id` is NULL for Mode 1 and REQUIRED for Mode 2/3."""
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=_uid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    mode = Column(String, nullable=False)             # MODE_1 | MODE_2 | MODE_3
    status = Column(String, default="queued")
    auth_record_id = Column(String, ForeignKey("authorization_records.id"),
                            nullable=True)             # FK enforces the invariant
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)
    summary = Column(Text, nullable=True)             # JSON blob of mode-specific meta

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan",
                            cascade="all, delete-orphan")
    narrative = relationship("NarrativeText", back_populates="scan", uselist=False,
                             cascade="all, delete-orphan")
    simulations = relationship("SimulationEvidence", back_populates="scan",
                               cascade="all, delete-orphan")


class TechnologyComponent(Base):
    """Normalised technology detail with a CPE 2.3 string (Ch.5 5.4)."""
    __tablename__ = "technology_components"
    id = Column(String, primary_key=True, default=_uid)
    vendor = Column(String, nullable=False)
    product = Column(String, nullable=False)
    version = Column(String, nullable=True)
    cpe = Column(String, nullable=True)


class TargetTechnology(Base):
    """Association class Target <-> TechnologyComponent (Ch.5 5.4)."""
    __tablename__ = "target_technologies"
    id = Column(String, primary_key=True, default=_uid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    component_id = Column(String, ForeignKey("technology_components.id"), nullable=False)
    detected_version = Column(String, nullable=True)
    evidence = Column(String, nullable=True)
    observed_at = Column(DateTime, default=_now)

    target = relationship("Target", back_populates="technologies")
    component = relationship("TechnologyComponent")


class CveReference(Base):
    __tablename__ = "cve_references"
    id = Column(String, primary_key=True, default=_uid)
    cve_id = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    published = Column(String, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=_uid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    identifier = Column(String, nullable=False)       # e.g. ASAA-H-001
    category = Column(String, nullable=False)         # OWASP class / header / TLS
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)         # info|low|medium|high|critical
    cvss = Column(Float, nullable=True)
    evidence = Column(Text, nullable=True)
    source_tool = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    ecc_control = Column(String, nullable=True)
    scan = relationship("Scan", back_populates="findings")
    cve_links = relationship("FindingCveReference", back_populates="finding",
                             cascade="all, delete-orphan")


class FindingCveReference(Base):
    """Association class Finding <-> CveReference (Ch.5 5.4)."""
    __tablename__ = "finding_cve_references"
    id = Column(String, primary_key=True, default=_uid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    cve_ref_id = Column(String, ForeignKey("cve_references.id"), nullable=False)
    match_confidence = Column(Float, default=1.0)
    evidence_source = Column(String, nullable=True)
    finding = relationship("Finding", back_populates="cve_links")
    cve = relationship("CveReference")


class NarrativeText(Base):
    __tablename__ = "narrative_texts"
    id = Column(String, primary_key=True, default=_uid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    language = Column(String, default="en")
    provider = Column(String, nullable=True)          # which Mode 3 provider produced it
    body = Column(Text, nullable=False)
    techniques = Column(Text, nullable=True)          # JSON list of ATT&CK ids
    scan = relationship("Scan", back_populates="narrative")


class SimulationEvidence(Base):
    __tablename__ = "simulation_evidence"
    id = Column(String, primary_key=True, default=_uid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=True)
    outcome = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
    scan = relationship("Scan", back_populates="simulations")


class AlertRecord(Base):
    """Independent aggregate produced by the CVE Monitoring Service (UC-5)."""
    __tablename__ = "alert_records"
    id = Column(String, primary_key=True, default=_uid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    cve_id = Column(String, nullable=False)
    component = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    cvss = Column(Float, nullable=True)
    channel = Column(String, default="email")
    dispatched_at = Column(DateTime, default=_now)
    target = relationship("Target", back_populates="alerts")


class Report(Base):
    __tablename__ = "reports"
    id = Column(String, primary_key=True, default=_uid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    language = Column(String, default="en")
    depth = Column(String, default="full")
    path = Column(String, nullable=True)
    content_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=_now)
    target = relationship("Target", back_populates="reports")


class AuditEntry(Base):
    """Append-only, hash-chained audit log (NFR-S-4, ECC 2-12)."""
    __tablename__ = "audit_entries"
    seq = Column(Integer, primary_key=True, autoincrement=True)
    id = Column(String, default=_uid)
    actor = Column(String, nullable=False)
    target_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    status = Column(String, nullable=False)           # ok | denied
    detail = Column(Text, nullable=True)
    ref_id = Column(String, nullable=True)            # related scan/report id
    source_ip = Column(String, nullable=True)
    timestamp = Column(DateTime, default=_now)
    ts_iso = Column(String, nullable=False)           # canonical string used for hashing
    prev_hash = Column(String, nullable=True)
    entry_hash = Column(String, nullable=False)
