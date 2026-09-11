"""End-to-end test for the two new features:
  1. authorisation document upload + SHA-256 hashing
  2. real email delivery of the report (against a local capture SMTP server)
Runs entirely locally; no external network.
"""
import email
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
from aiosmtpd.controller import Controller

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
(ROOT / "asaa" / "asaa.db").exists() and (ROOT / "asaa" / "asaa.db").unlink()

# --- local capture SMTP server (stands in for Mailtrap) --------------------
CAPTURED = []


class Handler:
    async def handle_DATA(self, server, session, envelope):
        CAPTURED.append(envelope.content)
        return "250 OK"


ctrl = Controller(Handler(), hostname="127.0.0.1", port=8025)
ctrl.start()

env = dict(os.environ,
           ASAA_REASONING_PROVIDER="canned",
           ASAA_SMTP_HOST="127.0.0.1", ASAA_SMTP_PORT="8025",
           ASAA_SMTP_TLS="false", ASAA_SMTP_USER="", ASAA_SMTP_PASS="",
           ASAA_SMTP_FROM="asaa@demo.local")
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "asaa.main:app",
                        "--host", "127.0.0.1", "--port", "8087"],
                       stdout=open("/tmp/asaa.log", "w"), stderr=subprocess.STDOUT, env=env)
B = "http://127.0.0.1:8087"
try:
    for _ in range(40):
        try:
            if httpx.get(f"{B}/api/health", timeout=2).status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
    h = httpx.get(f"{B}/api/health").json()
    print("email_configured:", h["email_configured"])

    # --- 1. register WITH authorisation document (multipart) ---
    pdf = b"%PDF-1.4\n% ASAA test authorisation letter\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
    r = httpx.post(f"{B}/api/targets",
                   data={"name": "DocTarget", "url": "http://doc.test/", "owner_email": "owner@doc.test"},
                   files={"authorization": ("auth_letter.pdf", pdf, "application/pdf")}).json()
    tid = r["id"]
    import hashlib
    expected = hashlib.sha256(pdf).hexdigest()
    print("register authorized_active:", r["authorized_active"])
    lst = [x for x in httpx.get(f"{B}/api/targets").json() if x["id"] == tid][0]
    print("stored doc name:", lst["auth_doc"], "| stored hash prefix:", lst["auth_hash"])
    print("hash matches SHA-256 of file:", expected.startswith(lst["auth_hash"]))
    doc = httpx.get(f"{B}/api/targets/{tid}/authorization")
    print("doc retrievable:", doc.status_code == 200, "| bytes match:", doc.content == pdf)

    # --- 2. Mode 2 allowed on the authorised target ---
    httpx.post(f"{B}/api/targets/{tid}/mode1")
    m2 = httpx.post(f"{B}/api/targets/{tid}/mode2").json()
    print("mode2 denied on authorised target:", m2.get("denied"))

    # --- 3. register WITHOUT a document -> Mode 1 only, denied Mode 2 ---
    r2 = httpx.post(f"{B}/api/targets",
                    data={"name": "NoDoc", "url": "http://nodoc.test/"}).json()
    print("no-doc authorized_active:", r2["authorized_active"])
    d2 = httpx.post(f"{B}/api/targets/{r2['id']}/mode2").json()
    print("mode2 denied on no-doc target:", d2.get("denied"))

    # --- 4. email the report ---
    rep = httpx.post(f"{B}/api/targets/{tid}/report",
                     json={"language": "en", "email": True, "email_to": "prof@uni.test"}).json()
    print("email result:", rep["email"])
    time.sleep(0.5)
    print("SMTP captured messages:", len(CAPTURED))
    if CAPTURED:
        msg = email.message_from_bytes(CAPTURED[-1])
        atts = [p.get_filename() for p in msg.walk() if p.get_filename()]
        print("attachment(s) in captured email:", atts)
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()
    ctrl.stop()
