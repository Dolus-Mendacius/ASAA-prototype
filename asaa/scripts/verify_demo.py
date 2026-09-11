"""Self-contained end-to-end verification: starts the ASAA server as a
subprocess, seeds it, screenshots the dashboard, tears down. One process, no
shell background jobs."""
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

for f in (ROOT / "asaa" / "asaa.db",):
    if f.exists():
        f.unlink()

env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH="/opt/pw-browsers",
           ASAA_REASONING_PROVIDER="auto")
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "asaa.main:app",
                        "--host", "127.0.0.1", "--port", "8080"],
                       stdout=open("/tmp/asaa.log", "w"), stderr=subprocess.STDOUT, env=env)
try:
    # wait for health
    for _ in range(40):
        try:
            if httpx.get("http://127.0.0.1:8080/api/health", timeout=2).status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
    else:
        raise SystemExit("server did not come up")
    print("server up")

    # seed
    subprocess.run([sys.executable, "scripts/seed.py"], check=True)

    # screenshots
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page(viewport={"width": 1440, "height": 1050})
        page.goto("http://127.0.0.1:8080", wait_until="networkidle")
        page.wait_for_timeout(900)
        page.click("text=Al-Waha Portal")
        page.wait_for_timeout(1300)
        page.screenshot(path=str(DOCS / "01_mode1_findings.png"), full_page=True)
        try:
            page.click("text=Mode 3")
            page.wait_for_timeout(700)
            page.screenshot(path=str(DOCS / "02_mode3_narrative.png"), full_page=True)
        except Exception as e:
            print("mode3 tab:", e)
        try:
            page.click("text=Verify hash chain")
            page.wait_for_timeout(900)
            page.screenshot(path=str(DOCS / "03_audit_verify.png"), full_page=True)
        except Exception as e:
            print("verify:", e)
        b.close()
    print("screenshots:", [p.name for p in DOCS.glob("*.png")])
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except Exception:
        srv.kill()
