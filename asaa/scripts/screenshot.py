"""Drive the dashboard with a headless browser and capture screenshots."""
import sys
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8080"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/home/claude/asaa/docs"


def run():
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium-1200/chrome-linux/chrome"
                              if False else None)
        page = b.new_page(viewport={"width": 1440, "height": 1000})
        page.goto(BASE, wait_until="networkidle")
        page.wait_for_timeout(800)
        # select the authorised target
        page.click("text=Al-Waha Portal")
        page.wait_for_timeout(1200)
        page.screenshot(path=f"{OUT}/01_mode1_findings.png", full_page=True)
        # Mode 3 tab
        page.click("text=Mode 3")
        page.wait_for_timeout(600)
        page.screenshot(path=f"{OUT}/02_mode3_narrative.png", full_page=True)
        # verify chain
        page.click("text=Verify hash chain")
        page.wait_for_timeout(800)
        page.screenshot(path=f"{OUT}/03_audit_verify.png", full_page=True)
        b.close()
        print("screenshots written to", OUT)


if __name__ == "__main__":
    run()
