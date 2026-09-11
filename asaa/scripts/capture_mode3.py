import os, subprocess, sys, time
from pathlib import Path
import httpx
ROOT = Path(__file__).resolve().parent.parent; os.chdir(ROOT)
env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH="/opt/pw-browsers", ASAA_REASONING_PROVIDER="auto")
srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "asaa.main:app", "--host","127.0.0.1","--port","8080"],
                       stdout=open("/tmp/asaa.log","w"), stderr=subprocess.STDOUT, env=env)
try:
    for _ in range(40):
        try:
            if httpx.get("http://127.0.0.1:8080/api/health", timeout=2).status_code==200: break
        except Exception: time.sleep(0.5)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b=p.chromium.launch(); page=b.new_page(viewport={"width":1240,"height":900})
        page.goto("http://127.0.0.1:8080", wait_until="networkidle"); page.wait_for_timeout(900)
        page.click("text=Al-Waha Portal"); page.wait_for_timeout(1300)
        page.evaluate("setTab('MODE_3')"); page.wait_for_timeout(700)
        # scroll the panel into view
        page.eval_on_selector("#panel", "el=>el.scrollIntoView()")
        page.wait_for_timeout(300)
        page.screenshot(path="docs/02_mode3_narrative.png")
        print("captured mode3")
        b.close()
finally:
    srv.terminate()
    try: srv.wait(timeout=5)
    except Exception: srv.kill()
