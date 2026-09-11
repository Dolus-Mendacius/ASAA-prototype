"""Authorisation Guard (NFR-S-1, NFR-S-2; Ch.5 6.1).

The guard is the single chokepoint every active-mode (Mode 2 / Mode 3) request
must pass. It resolves the target's authorisation record for the requested mode
and returns the record id, or raises `AuthorizationDenied`. The orchestration
service refuses to construct a Scan row without the id the guard returns, and
the DB foreign key makes an active-mode scan physically unstorable otherwise.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuthorizationRecord, Target


class AuthorizationDenied(Exception):
    def __init__(self, target_id: str, mode: str):
        self.target_id = target_id
        self.mode = mode
        super().__init__(f"No valid authorisation record covering {mode} for target {target_id}")


def resolve(db: Session, target: Target, mode: str) -> str:
    """Return the id of an AuthorizationRecord covering `mode`, or raise."""
    if mode == "MODE_1":
        return None  # passive reconnaissance is authorisation-free by design
    records = db.execute(
        select(AuthorizationRecord).where(AuthorizationRecord.target_id == target.id)
    ).scalars().all()
    for r in records:
        if not r.acknowledged:
            continue
        if mode == "MODE_2" and r.covers_mode_2:
            return r.id
        if mode == "MODE_3" and r.covers_mode_3:
            return r.id
    raise AuthorizationDenied(target.id, mode)
