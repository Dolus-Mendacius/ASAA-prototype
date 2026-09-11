"""Central configuration for the ASAA prototype.

All tunables live here so the demo can be reconfigured without touching code.
Values map back to the SP-I design (Chapter 4 NFRs and Chapter 5 specs).
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"


def _load_dotenv() -> None:
    """Minimal .env loader (no dependency): populates os.environ from a .env
    file at the project root if present, without overriding real env vars."""
    for candidate in (BASE_DIR.parent / ".env", BASE_DIR / ".env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
        break


_load_dotenv()

# --- Persistence -----------------------------------------------------------
# SQLite for the academic prototype; SQLAlchemy makes the swap to the
# Postgres container described in the Ch.5 deployment diagram a one-line change.
DATABASE_URL = os.getenv("ASAA_DATABASE_URL", f"sqlite:///{BASE_DIR / 'asaa.db'}")

# --- CVE monitoring (Ch.5 5.6.4) ------------------------------------------
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SYNC_INTERVAL_HOURS = int(os.getenv("ASAA_NVD_SYNC_HOURS", "6"))  # NFR-P-3
CVE_ALERT_THRESHOLD = float(os.getenv("ASAA_CVE_THRESHOLD", "7.0"))   # High+Critical
LOCAL_CVE_INDEX = DATA_DIR / "cve_index.json"

# --- Safety / rate limiting (NFR-S-3) -------------------------------------
ACTIVE_SCAN_RPS = float(os.getenv("ASAA_ACTIVE_RPS", "1.0"))
ACTIVE_SCAN_BURST = int(os.getenv("ASAA_ACTIVE_BURST", "5"))

# --- Mode 3 reasoning provider (Ch.5 5.6.3) -------------------------------
# Order of preference. The engine tries HUMAIN, then a dev LLM behind the
# abstraction layer (Objective 5), and finally the deterministic canned
# provider so the demo always produces a narrative.
REASONING_PROVIDER = os.getenv("ASAA_REASONING_PROVIDER", "auto")  # auto|humain|openai|anthropic|canned
HUMAIN_API_BASE = os.getenv("ASAA_HUMAIN_API_BASE", "")
HUMAIN_API_KEY = os.getenv("ASAA_HUMAIN_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("ASAA_OPENAI_MODEL", "gpt-4o")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ASAA_ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

# --- Authorisation documents (UC-1) ---------------------------------------
# Uploaded written-authorisation documents are hashed (SHA-256) and stored so
# the on-file authorisation is tamper-evident and can be produced as evidence.
AUTH_DOCS_DIR = DATA_DIR / "auth_docs"
AUTH_DOC_MAX_BYTES = int(os.getenv("ASAA_AUTH_DOC_MAX_BYTES", str(10 * 1024 * 1024)))
AUTH_DOC_ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg"}

# --- Email / SMTP (UC-5 email channel, report delivery) --------------------
# Configure with a Mailtrap sandbox inbox for the demo (host sandbox.smtp.mailtrap.io,
# port 587 or 2525, the inbox username/password). Leave blank to disable sending;
# report generation still works and returns the download link.
SMTP_HOST = os.getenv("ASAA_SMTP_HOST", "")
SMTP_PORT = int(os.getenv("ASAA_SMTP_PORT", "587"))
SMTP_USER = os.getenv("ASAA_SMTP_USER", "")
SMTP_PASS = os.getenv("ASAA_SMTP_PASS", "")
SMTP_FROM = os.getenv("ASAA_SMTP_FROM", "asaa-noreply@asaa.local")
SMTP_TLS = os.getenv("ASAA_SMTP_TLS", "true").lower() in ("1", "true", "yes")
EMAIL_ALERTS = os.getenv("ASAA_EMAIL_ALERTS", "false").lower() in ("1", "true", "yes")

# --- Audit log (NFR-S-4) ---------------------------------------------------
AUDIT_RETENTION_MONTHS = 12

# --- App -------------------------------------------------------------------
APP_NAME = "Autonomous Security Assessment Agent (ASAA)"
APP_VERSION = "0.9.0-prototype"
