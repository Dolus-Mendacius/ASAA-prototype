"""Append-only, tamper-evident audit log (NFR-S-4, ECC-2:2024 Control 2-12).

Every persisting action calls `record()`. Each entry stores the hash of the
previous entry, so any modification or deletion of a past entry breaks the
chain and is detectable by `verify_chain()`. The demo exposes both writing
(via every mode) and verification (a dashboard button) so the committee can
see the integrity property, not just be told about it.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEntry

GENESIS = "0" * 64


def _canonical(actor, target_id, action, status, detail, ref_id, source_ip, ts_iso, prev_hash) -> str:
    payload = {
        "actor": actor, "target_id": target_id, "action": action, "status": status,
        "detail": detail, "ref_id": ref_id, "source_ip": source_ip,
        "timestamp": ts_iso, "prev_hash": prev_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def record(db: Session, *, actor: str, action: str, status: str = "ok",
           target_id: str | None = None, detail: str | None = None,
           ref_id: str | None = None, source_ip: str | None = None) -> AuditEntry:
    last = db.execute(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).scalar_one_or_none()
    prev_hash = last.entry_hash if last else GENESIS
    ts = dt.datetime.now(dt.timezone.utc)
    ts_iso = ts.isoformat()
    canonical = _canonical(actor, target_id, action, status, detail, ref_id, source_ip, ts_iso, prev_hash)
    entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
    entry = AuditEntry(
        actor=actor, target_id=target_id, action=action, status=status, detail=detail,
        ref_id=ref_id, source_ip=source_ip, timestamp=ts, ts_iso=ts_iso, prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_chain(db: Session) -> dict:
    """Recompute the chain and report the first break, if any."""
    entries = db.execute(select(AuditEntry).order_by(AuditEntry.seq.asc())).scalars().all()
    prev_hash = GENESIS
    for e in entries:
        canonical = _canonical(e.actor, e.target_id, e.action, e.status, e.detail,
                               e.ref_id, e.source_ip, e.ts_iso, prev_hash)
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        if e.prev_hash != prev_hash or e.entry_hash != expected:
            return {"intact": False, "broken_at_seq": e.seq, "count": len(entries)}
        prev_hash = e.entry_hash
    return {"intact": True, "broken_at_seq": None, "count": len(entries)}
