## Quick start

```bash
pip install -r requirements.txt
# Arabic PDF font (Linux): sudo apt-get install fonts-kacst
./run_demo.sh          # starts benchmark target + ASAA + seeds a demo state
# open http://127.0.0.1:8080
```

Or with Docker:

```bash
docker compose up --build
# ASAA on :8080, benchmark target on :8000
```

**Mailtrap setup (2 min):** create a free account at mailtrap.io → Email Testing
→ your Inbox → SMTP Settings → copy the host, port, username, and password into
`.env` (`ASAA_SMTP_HOST/PORT/USER/PASS`). Then use the "Email report" button;
the email with the PDF attachment appears in your Mailtrap inbox.
