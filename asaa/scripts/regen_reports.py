import os, subprocess, sys, time
from pathlib import Path
import httpx
ROOT = Path(__file__).resolve().parent.parent; os.chdir(ROOT)
(ROOT/"asaa"/"asaa.db").exists() and (ROOT/"asaa"/"asaa.db").unlink()
env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH="/opt/pw-browsers", ASAA_REASONING_PROVIDER="auto")
srv = subprocess.Popen([sys.executable,"-m","uvicorn","asaa.main:app","--host","127.0.0.1","--port","8080"],
                       stdout=open("/tmp/asaa.log","w"), stderr=subprocess.STDOUT, env=env)
try:
    for _ in range(40):
        try:
            if httpx.get("http://127.0.0.1:8080/api/health",timeout=2).status_code==200: break
        except Exception: time.sleep(0.5)
    subprocess.run([sys.executable,"scripts/seed.py"],check=True)
    tid = httpx.get("http://127.0.0.1:8080/api/targets").json()[0]["id"]
    for lang in ("en","ar"):
        r = httpx.post(f"http://127.0.0.1:8080/api/targets/{tid}/report", json={"language":lang,"depth":"full"}, timeout=30).json()
        print(lang, r.get("content_hash"), r.get("download"))
finally:
    srv.terminate()
    try: srv.wait(timeout=5)
    except Exception: srv.kill()
