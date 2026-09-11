"""Orchestration Service (Ch.5 5.1).

The central coordinator: accepts scan requests, consults the Authorisation
Guard before any active action, routes to the correct pipeline, persists
findings, and writes an audit entry for every event. This is the only module
the API layer calls to perform assessments.
"""
from __future__ import annotations

import datetime as dt
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, auth_guard, config
from .models import (AlertRecord, AuthorizationRecord, CveReference, Finding,
                     FindingCveReference, NarrativeText, Report, Scan,
                     SimulationEvidence, Target, TargetTechnology,
                     TechnologyComponent)
from .pipelines import active as active_pipe
from .pipelines import passive as passive_pipe
from .reasoning import engine as reasoning_engine
from .services import cve as cve_service


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _upsert_component(db: Session, comp: dict) -> TechnologyComponent:
    existing = db.execute(
        select(TechnologyComponent).where(
            TechnologyComponent.vendor == comp["vendor"],
            TechnologyComponent.product == comp["product"],
            TechnologyComponent.version == comp.get("version"))
    ).scalar_one_or_none()
    if existing:
        return existing
    tc = TechnologyComponent(vendor=comp["vendor"], product=comp["product"],
                             version=comp.get("version"), cpe=comp.get("cpe"))
    db.add(tc)
    db.flush()
    return tc


def _cve_ref(db: Session, hit: dict) -> CveReference:
    existing = db.execute(
        select(CveReference).where(CveReference.cve_id == hit["cve_id"])
    ).scalar_one_or_none()
    if existing:
        return existing
    ref = CveReference(cve_id=hit["cve_id"], description=hit["description"],
                       cvss=hit["cvss"], severity=hit["severity"],
                       published=hit.get("published"))
    db.add(ref)
    db.flush()
    return ref


# --- Mode 1 ----------------------------------------------------------------
def run_mode1(db: Session, target: Target, actor: str) -> dict:
    scan = Scan(target_id=target.id, mode="MODE_1", status="running", auth_record_id=None)
    db.add(scan)
    db.commit()

    result = passive_pipe.run_passive(target.url)
    if not result.get("reachable"):
        scan.status = "incomplete"
        scan.summary = json.dumps({"error": result.get("error")})
        scan.finished_at = _now()
        db.commit()
        audit.record(db, actor=actor, action="MODE_1_SCAN", status="ok",
                     target_id=target.id, ref_id=scan.id,
                     detail="Target unreachable")
        return {"scan_id": scan.id, "status": "incomplete", "error": result.get("error")}

    # persist detected technologies
    for comp in result["components"]:
        tc = _upsert_component(db, comp)
        db.add(TargetTechnology(target_id=target.id, component_id=tc.id,
                                detected_version=comp.get("version"),
                                evidence=comp.get("evidence")))

    # CVE matching against the local index
    cve_hits = cve_service.match_target(result["components"])

    # persist header/TLS findings
    persisted_findings = []
    for f in result["findings"]:
        row = Finding(scan_id=scan.id, identifier=f["identifier"], category=f["category"],
                      title=f["title"], severity=f["severity"], cvss=f.get("cvss"),
                      evidence=f.get("evidence"), source_tool=f.get("source_tool"),
                      remediation=f.get("remediation"), ecc_control=f.get("ecc_control"))
        db.add(row)
        persisted_findings.append(row)

    # persist a CVE-match finding per hit, linked to its CveReference
    db.flush()
    for hit in cve_hits:
        ref = _cve_ref(db, hit)
        f = Finding(scan_id=scan.id, identifier=hit["cve_id"],
                    category="Vulnerable/Outdated Component (OWASP A06)",
                    title=f"{hit['component']} affected by {hit['cve_id']}",
                    severity=hit["severity"], cvss=hit["cvss"],
                    evidence=hit["description"][:400], source_tool="CVE Matcher",
                    remediation="Upgrade the affected component to a fixed version.",
                    ecc_control="ECC 2-10")
        db.add(f)
        db.flush()
        db.add(FindingCveReference(finding_id=f.id, cve_ref_id=ref.id,
                                   match_confidence=hit["match_confidence"],
                                   evidence_source=hit["matched_on"]))
        persisted_findings.append(f)

    scan.status = "complete"
    scan.finished_at = _now()
    scan.summary = json.dumps({"components": len(result["components"]),
                               "cve_matches": len(cve_hits),
                               "tls": result.get("tls", {}).get("protocol")})
    target.status = "Mode 1 Complete"
    db.commit()

    audit.record(db, actor=actor, action="MODE_1_SCAN", status="ok",
                 target_id=target.id, ref_id=scan.id,
                 detail=f"{len(result['components'])} components, {len(cve_hits)} CVE matches")
    return {"scan_id": scan.id, "status": "complete",
            "components": result["components"], "tls": result.get("tls"),
            "findings": len(persisted_findings), "cve_matches": cve_hits}


# --- Mode 2 ----------------------------------------------------------------
def run_mode2(db: Session, target: Target, actor: str, source_ip: str | None = None) -> dict:
    # Authorisation Guard FIRST — no probe is sent if it denies.
    try:
        auth_id = auth_guard.resolve(db, target, "MODE_2")
    except auth_guard.AuthorizationDenied as denial:
        audit.record(db, actor=actor, action="MODE_2_SCAN", status="denied",
                     target_id=target.id, source_ip=source_ip,
                     detail="Authorisation guard denied: no Mode 2 authorisation record")
        return {"denied": True, "reason": str(denial)}

    # components from the latest Mode 1 scan
    comps = [{"vendor": tt.component.vendor, "product": tt.component.product,
              "version": tt.detected_version} for tt in target.technologies]

    scan = Scan(target_id=target.id, mode="MODE_2", status="running", auth_record_id=auth_id)
    db.add(scan)
    db.commit()

    result = active_pipe.run_active(target.url, comps)
    for f in result["findings"]:
        db.add(Finding(scan_id=scan.id, identifier=f["identifier"], category=f["category"],
                       title=f["title"], severity=f["severity"], cvss=f.get("cvss"),
                       evidence=f.get("evidence"), source_tool=f.get("source_tool"),
                       remediation=f.get("remediation"), ecc_control=f.get("ecc_control")))
    scan.status = "complete"
    scan.finished_at = _now()
    scan.summary = json.dumps({"tool": result["tool"], "findings": len(result["findings"])})
    db.commit()

    audit.record(db, actor=actor, action="MODE_2_SCAN", status="ok",
                 target_id=target.id, ref_id=scan.id, source_ip=source_ip,
                 detail=f"{result['tool']}: {len(result['findings'])} findings (auth={auth_id})")
    return {"denied": False, "scan_id": scan.id, "tool": result["tool"],
            "findings": result["findings"], "rate_limit": result["rate_limit"]}


# --- Mode 3 ----------------------------------------------------------------
def _gather_findings(db: Session, target: Target) -> list[dict]:
    out = []
    for scan in target.scans:
        for f in scan.findings:
            out.append({"identifier": f.identifier, "category": f.category,
                        "title": f.title, "severity": f.severity, "cvss": f.cvss,
                        "evidence": f.evidence, "remediation": f.remediation,
                        "ecc_control": f.ecc_control})
    return out


def run_mode3(db: Session, target: Target, actor: str, simulate: bool = False,
              source_ip: str | None = None) -> dict:
    try:
        auth_id = auth_guard.resolve(db, target, "MODE_3")
    except auth_guard.AuthorizationDenied as denial:
        audit.record(db, actor=actor, action="MODE_3_REASONING", status="denied",
                     target_id=target.id, source_ip=source_ip,
                     detail="Authorisation guard denied: no Mode 3 authorisation record")
        return {"denied": True, "reason": str(denial)}

    findings = _gather_findings(db, target)
    cves = []
    for scan in target.scans:
        for f in scan.findings:
            for link in f.cve_links:
                cves.append({"cve_id": link.cve.cve_id, "cvss": link.cve.cvss,
                             "component": f.title})

    context = {"target": {"name": target.name, "url": target.url},
               "findings": findings, "cves": cves}
    result = reasoning_engine.run_reasoning(context)

    scan = Scan(target_id=target.id, mode="MODE_3", status="complete",
                auth_record_id=auth_id, finished_at=_now(),
                summary=json.dumps({"provider": result["provider"],
                                    "degraded": result["degraded"]}))
    db.add(scan)
    db.flush()
    db.add(NarrativeText(scan_id=scan.id, language="en", provider=result["provider"],
                         body=result["narrative"],
                         techniques=json.dumps(result["techniques"])))
    if simulate:
        db.add(SimulationEvidence(scan_id=scan.id, module="benchmark/non-destructive",
                                  outcome="simulated",
                                  detail="Controlled simulation on benchmark target; no destructive action."))
    db.commit()

    audit.record(db, actor=actor, action="MODE_3_REASONING", status="ok",
                 target_id=target.id, ref_id=scan.id, source_ip=source_ip,
                 detail=f"provider={result['provider']} degraded={result['degraded']}")
    result["scan_id"] = scan.id
    result["denied"] = False
    return result


# --- CVE monitoring (UC-5) -------------------------------------------------
def run_cve_monitor(db: Session, actor: str = "scheduler") -> dict:
    """Re-match every registered target against the local index and raise
    alerts above the CVSS threshold (simulates the scheduled UC-5 flow)."""
    targets = db.execute(select(Target)).scalars().all()
    created = 0
    for target in targets:
        comps = [{"vendor": tt.component.vendor, "product": tt.component.product,
                  "version": tt.detected_version} for tt in target.technologies]
        for hit in cve_service.match_target(comps):
            if hit["cvss"] < config.CVE_ALERT_THRESHOLD:
                continue
            exists = db.execute(select(AlertRecord).where(
                AlertRecord.target_id == target.id, AlertRecord.cve_id == hit["cve_id"])
            ).scalar_one_or_none()
            if exists:
                continue
            db.add(AlertRecord(target_id=target.id, cve_id=hit["cve_id"],
                               component=hit["component"], severity=hit["severity"],
                               cvss=hit["cvss"], channel="email"))
            created += 1
            db.flush()
            audit.record(db, actor=actor, action="CVE_ALERT", status="ok",
                         target_id=target.id, ref_id=hit["cve_id"],
                         detail=f"{hit['cve_id']} CVSS {hit['cvss']} -> {target.name}")
    db.commit()
    return {"alerts_created": created}


# --- Registration (UC-1) ---------------------------------------------------
def register_target(db: Session, user_id: str, name: str, url: str, owner_email: str,
                    actor: str, doc_name: str | None = None,
                    doc_hash: str | None = None) -> Target:
    """Register a target. Mode 2/3 are enabled only when a written-authorisation
    document is supplied; its SHA-256 hash is stored so the authorisation on
    file is tamper-evident (UC-1)."""
    target = Target(user_id=user_id, name=name, url=url, owner_email=owner_email)
    db.add(target)
    db.flush()
    authorised = bool(doc_name and doc_hash)
    if authorised:
        db.add(AuthorizationRecord(target_id=target.id, covers_mode_2=True,
                                   covers_mode_3=True, acknowledged=True,
                                   document_name=doc_name, document_hash=doc_hash))
    db.commit()
    detail = f"{name} authorised={'yes' if authorised else 'no'}"
    if authorised:
        detail += f' doc="{doc_name}" sha256:{doc_hash[:16]}'
    audit.record(db, actor=actor, action="REGISTER_TARGET", status="ok",
                 target_id=target.id, detail=detail)
    return target
