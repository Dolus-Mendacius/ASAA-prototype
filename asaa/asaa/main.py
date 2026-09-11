"""ASAA FastAPI application (Ch.5 5.1 Web Interface + REST API).

Serves the REST API for the three modes, CVE monitoring, audit log, and report
export, plus the single-page dashboard. Runnable stand-alone for the demo:
    uvicorn asaa.main:app --reload
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, config, orchestration
from .db import get_session, init_db, SessionLocal
from .models import (AlertRecord, AuditEntry, AuthorizationRecord, Report, Scan,
                     Target, User)
from .services import cve as cve_service
from .services import mailer as mail_service
from .services import report as report_service

app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION)
BASE = Path(__file__).resolve().parent
REPORTS_DIR = BASE / "reports"
app.mount("/static", StaticFiles(directory=BASE / "web" / "static"), name="static")


def _store_auth_document(upload: UploadFile) -> dict:
    """Validate, hash (SHA-256), and persist an uploaded authorisation document.
    Returns {name, hash} or raises ValueError for an invalid upload."""
    ext = Path(upload.filename or "").suffix.lower()
    if ext not in config.AUTH_DOC_ALLOWED_EXT:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: PDF, PNG, JPG.")
    data = upload.file.read()
    if not data:
        raise ValueError("Uploaded authorisation document is empty.")
    if len(data) > config.AUTH_DOC_MAX_BYTES:
        raise ValueError("Authorisation document exceeds the size limit.")
    digest = hashlib.sha256(data).hexdigest()
    config.AUTH_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    (config.AUTH_DOCS_DIR / f"{digest}{ext}").write_bytes(data)
    return {"name": upload.filename, "hash": digest, "ext": ext}


def _actor(db: Session) -> tuple[str, str]:
    """Single authenticated User role for the prototype (NFR-Sec-4)."""
    user = db.execute(select(User)).scalars().first()
    if not user:
        user = User(email="analyst@asaa.local", display_name="Analyst")
        db.add(user)
        db.commit()
        db.refresh(user)
    return user.id, user.email


@app.on_event("startup")
def _startup():
    init_db()
    db = SessionLocal()
    try:
        _actor(db)
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (BASE / "web" / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"app": config.APP_NAME, "version": config.APP_VERSION,
            "reasoning_provider": config.REASONING_PROVIDER,
            "cve_threshold": config.CVE_ALERT_THRESHOLD,
            "email_configured": mail_service.is_configured()}


@app.get("/api/targets")
def list_targets(db: Session = Depends(get_session)):
    out = []
    for t in db.execute(select(Target)).scalars().all():
        auth = t.authorizations[0] if t.authorizations else None
        out.append({"id": t.id, "name": t.name, "url": t.url, "status": t.status,
                    "authorized_active": bool(auth and auth.covers_mode_2),
                    "auth_doc": auth.document_name if auth else None,
                    "auth_hash": (auth.document_hash[:16] if auth and auth.document_hash else None),
                    "scans": len(t.scans), "alerts": len(t.alerts)})
    return out


@app.post("/api/targets")
async def create_target(
    name: str = Form(...),
    url: str = Form(...),
    owner_email: str = Form(""),
    authorization: UploadFile | None = File(None),
    db: Session = Depends(get_session),
):
    uid, email = _actor(db)
    existing = db.execute(select(Target).where(Target.url == url.strip())).scalar_one_or_none()
    if existing:
        return JSONResponse({"error": "Target URL already registered"}, status_code=409)
    doc = None
    if authorization is not None and authorization.filename:
        try:
            doc = _store_auth_document(authorization)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
    t = orchestration.register_target(
        db, uid, name.strip(), url.strip(), owner_email.strip() or email, actor=email,
        doc_name=(doc["name"] if doc else None), doc_hash=(doc["hash"] if doc else None))
    return {"id": t.id, "name": t.name, "url": t.url, "status": t.status,
            "authorized_active": bool(doc)}


def _get_target(db: Session, target_id: str) -> Target | None:
    return db.execute(select(Target).where(Target.id == target_id)).scalar_one_or_none()


@app.post("/api/targets/{target_id}/mode1")
def mode1(target_id: str, db: Session = Depends(get_session)):
    t = _get_target(db, target_id)
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)
    _, email = _actor(db)
    return orchestration.run_mode1(db, t, actor=email)


@app.post("/api/targets/{target_id}/authorize")
def authorize_target(target_id: str, authorization: UploadFile = File(...),
                     db: Session = Depends(get_session)):
    """Grant Mode 2/3 authorisation to an already-registered target by uploading
    the written-authorisation document (UC-1 add-authorisation path). The
    document is hashed (SHA-256) and stored; Mode 2/3 unlock only with a document."""
    t = _get_target(db, target_id)
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)
    _, email = _actor(db)
    try:
        doc = _store_auth_document(authorization)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    rec = t.authorizations[0] if t.authorizations else None
    if rec:
        rec.covers_mode_2 = True
        rec.covers_mode_3 = True
        rec.acknowledged = True
        rec.document_name = doc["name"]
        rec.document_hash = doc["hash"]
    else:
        db.add(AuthorizationRecord(target_id=t.id, covers_mode_2=True,
                                   covers_mode_3=True, acknowledged=True,
                                   document_name=doc["name"], document_hash=doc["hash"]))
    db.commit()
    audit.record(db, actor=email, action="ADD_AUTHORISATION", status="ok",
                 target_id=t.id,
                 detail=f'authorisation document "{doc["name"]}" sha256:{doc["hash"][:16]} recorded')
    return {"authorized": True, "document": doc["name"], "hash": doc["hash"]}


@app.get("/api/targets/{target_id}/authorization")
def get_authorization_doc(target_id: str, db: Session = Depends(get_session)):
    """Serve the stored authorisation document as evidence."""
    t = _get_target(db, target_id)
    if not t or not t.authorizations:
        return JSONResponse({"error": "no authorisation on file"}, status_code=404)
    rec = t.authorizations[0]
    if not rec.document_hash:
        return JSONResponse({"error": "no document"}, status_code=404)
    ext = Path(rec.document_name or "").suffix.lower() or ".bin"
    path = config.AUTH_DOCS_DIR / f"{rec.document_hash}{ext}"
    if not path.exists():
        return JSONResponse({"error": "document file missing"}, status_code=404)
    return FileResponse(str(path), filename=rec.document_name or path.name)


@app.post("/api/targets/{target_id}/mode2")
def mode2(target_id: str, request: Request, db: Session = Depends(get_session)):
    t = _get_target(db, target_id)
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)
    _, email = _actor(db)
    result = orchestration.run_mode2(db, t, actor=email, source_ip=request.client.host)
    status = 403 if result.get("denied") else 200
    return JSONResponse(result, status_code=status)


@app.post("/api/targets/{target_id}/mode3")
async def mode3(target_id: str, request: Request, db: Session = Depends(get_session)):
    t = _get_target(db, target_id)
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)
    _, email = _actor(db)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    result = orchestration.run_mode3(db, t, actor=email,
                                     simulate=bool(body.get("simulate")),
                                     source_ip=request.client.host)
    status = 403 if result.get("denied") else 200
    return JSONResponse(result, status_code=status)


@app.get("/api/targets/{target_id}/findings")
def findings(target_id: str, db: Session = Depends(get_session)):
    t = _get_target(db, target_id)
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)
    modes = {"MODE_1": [], "MODE_2": [], "MODE_3": []}
    narrative = None
    for scan in sorted(t.scans, key=lambda s: s.started_at or 0):
        for f in scan.findings:
            modes.get(scan.mode, []).append({
                "identifier": f.identifier, "category": f.category, "title": f.title,
                "severity": f.severity, "cvss": f.cvss, "evidence": f.evidence,
                "source_tool": f.source_tool, "remediation": f.remediation,
                "cves": [l.cve.cve_id for l in f.cve_links]})
        if scan.mode == "MODE_3" and scan.narrative:
            narrative = {"body": scan.narrative.body, "provider": scan.narrative.provider,
                         "techniques": json.loads(scan.narrative.techniques or "[]")}
    tech = [{"vendor": tt.component.vendor, "product": tt.component.product,
             "version": tt.detected_version, "cpe": tt.component.cpe}
            for tt in t.technologies]
    return {"target": {"name": t.name, "url": t.url, "status": t.status},
            "technologies": tech, "modes": modes, "narrative": narrative}


@app.get("/api/alerts")
def alerts(db: Session = Depends(get_session)):
    out = []
    for a in db.execute(select(AlertRecord).order_by(AlertRecord.cvss.desc())).scalars().all():
        t = _get_target(db, a.target_id)
        out.append({"cve_id": a.cve_id, "component": a.component, "cvss": a.cvss,
                    "severity": a.severity, "target": t.name if t else a.target_id,
                    "channel": a.channel})
    return out


@app.post("/api/monitor/run")
def run_monitor(db: Session = Depends(get_session)):
    return orchestration.run_cve_monitor(db)


@app.get("/api/audit")
def audit_log(db: Session = Depends(get_session)):
    entries = db.execute(select(AuditEntry).order_by(AuditEntry.seq.desc())).scalars().all()
    return [{"seq": e.seq, "actor": e.actor, "action": e.action, "status": e.status,
             "detail": e.detail, "timestamp": e.timestamp.isoformat(),
             "entry_hash": e.entry_hash[:12], "prev_hash": (e.prev_hash or "")[:12]}
            for e in entries]


@app.get("/api/audit/verify")
def audit_verify(db: Session = Depends(get_session)):
    return audit.verify_chain(db)


@app.get("/api/cve/status")
def cve_status(db: Session = Depends(get_session)):
    index = cve_service.load_index()
    return {"local_index_size": len(index), "threshold": config.CVE_ALERT_THRESHOLD,
            "note": "Live NVD sync wired (services.cve.sync_from_nvd); cached index serves when the feed is unreachable."}


@app.post("/api/targets/{target_id}/report")
async def make_report(target_id: str, request: Request, db: Session = Depends(get_session)):
    t = _get_target(db, target_id)
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    language = body.get("language", "en")
    depth = body.get("depth", "full")

    data = findings(target_id, db)
    all_findings, remediation, narrative = [], [], None
    for mode_findings in data["modes"].values():
        all_findings.extend(mode_findings)
    for f in all_findings:
        if f.get("remediation"):
            remediation.append({"action": f["remediation"], "ecc": "ECC 2-10"})
    if data.get("narrative"):
        narrative = data["narrative"]["body"]
    highs = [f for f in all_findings if f["severity"] in ("high", "critical")]
    executive = (f"This assessment of {t.name} identified {len(all_findings)} findings, "
                 f"of which {len(highs)} are high or critical severity. "
                 "Priority remediation items are listed in Section 4, each mapped to an "
                 "ECC-2:2024 control. This report is an academic-prototype output.")
    compliance = ("Findings are mapped to ECC-2:2024 Control 2-10 (Vulnerabilities "
                  "Management) and Control 2-11 (Penetration Testing). The append-only "
                  "audit trail supports Control 2-12. Sovereign inference (HUMAIN) and "
                  "in-Kingdom persistence support Control 4-1-3.2 and PDPL Article 29.")

    report_data = {"target": {"name": t.name, "url": t.url}, "executive": executive,
                   "findings": all_findings, "narrative": narrative,
                   "remediation": remediation[:12], "compliance": compliance}
    path, chash = report_service.generate_pdf(report_data, REPORTS_DIR, language, depth)
    _, email = _actor(db)
    r = Report(target_id=t.id, language=language, depth=depth, path=path, content_hash=chash)
    db.add(r)
    db.commit()
    audit.record(db, actor=email, action="REPORT_EXPORT", status="ok",
                 target_id=t.id, ref_id=r.id, detail=f"lang={language} depth={depth}")

    # Optional email delivery (UC-6). Recipient defaults to the target owner.
    email_result = {"sent": False, "reason": "not requested"}
    if body.get("email"):
        recipient = (body.get("email_to") or t.owner_email or "").strip()
        subject = f"ASAA security assessment report — {t.name}"
        mail_body = (f"Attached is the ASAA security assessment report for {t.name} "
                     f"({t.url}).\nLanguage: {language}. Content hash: {chash}.\n\n"
                     "This is an academic-prototype output; findings labelled "
                     "AI-assisted require human review.")
        email_result = mail_service.send_email(recipient, subject, mail_body, path)
        audit.record(db, actor=email,
                     action="REPORT_EMAIL", status="ok" if email_result.get("sent") else "failed",
                     target_id=t.id, ref_id=r.id,
                     detail=f"to={recipient} sent={email_result.get('sent')} "
                            f"{email_result.get('reason','')}".strip())

    return {"report_id": r.id, "language": language, "depth": depth,
            "content_hash": chash, "download": f"/api/reports/{r.id}",
            "email": email_result}


@app.get("/api/reports/{report_id}")
def download_report(report_id: str, db: Session = Depends(get_session)):
    r = db.execute(select(Report).where(Report.id == report_id)).scalar_one_or_none()
    if not r or not r.path or not Path(r.path).exists():
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(r.path, media_type="application/pdf", filename=Path(r.path).name)
