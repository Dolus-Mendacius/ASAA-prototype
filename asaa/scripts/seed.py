"""Seed a clean demo state via the running ASAA API.

Usage: python scripts/seed.py [base_url] [target_url]
Creates one authorised target (registered WITH a generated authorisation-letter
PDF, so its SHA-256 is stored) and one unauthorised target (with a logged Mode 2
denial), then runs a monitoring sweep.
"""
import io
import sys
import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
TARGET = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8000/"


def _sample_auth_pdf() -> bytes:
    """Generate a small, real authorisation-letter PDF for the demo."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(70, 780, "Written Authorisation for Security Assessment")
        c.setFont("Helvetica", 11)
        lines = [
            "I, the authorised owner of the system below, grant permission for ASAA to",
            "perform passive reconnaissance, active scanning, and controlled red-team",
            "reasoning against the following target:",
            "",
            f"    Target: {TARGET}",
            "",
            "This authorisation covers Mode 1, Mode 2, and Mode 3 assessment.",
            "",
            "Signed: ____________________        Date: __________",
        ]
        y = 740
        for ln in lines:
            c.drawString(70, y, ln)
            y -= 22
        c.showPage()
        c.save()
        return buf.getvalue()
    except Exception:
        return b"%PDF-1.4\n% ASAA demo authorisation letter\n"


def main():
    c = httpx.Client(base_url=BASE, timeout=60)
    # authorised target: register WITH an authorisation document (multipart)
    t = c.post("/api/targets",
               data={"name": "Al-Waha Portal", "url": TARGET, "owner_email": "owner@alwaha.sa"},
               files={"authorization": ("authorization_letter.pdf", _sample_auth_pdf(), "application/pdf")}
               ).json()
    tid = t["id"]
    c.post(f"/api/targets/{tid}/mode1")
    c.post(f"/api/targets/{tid}/mode2")
    c.post(f"/api/targets/{tid}/mode3", json={"simulate": True})

    # unauthorised target: no document -> Mode 1 only, and a denied Mode 2
    u = c.post("/api/targets",
               data={"name": "Unauthorised Site", "url": TARGET.rstrip("/")}).json()
    if "id" in u:
        c.post(f"/api/targets/{u['id']}/mode2")

    c.post("/api/monitor/run")
    print("Seeded. Verify:", c.get("/api/audit/verify").json())


if __name__ == "__main__":
    main()
