# ASAA — Live Demo Script (SP-II)

A ~7-minute walkthrough for the project committee. Each step names the SP-I
artefact it demonstrates, so the demo maps directly onto the report.

**Before you start:** `./run_demo.sh` (or `docker compose up`), then open
`http://127.0.0.1:8080`. The seed already creates one authorised target
("Al-Waha Portal") fully assessed and one "Unauthorised Site". For a clean live
run, delete `asaa/asaa.db` first and register targets yourself.

---

### 0. Frame it (20s)
"ASAA is a sovereign, three-mode web security assessment platform. Everything
you'll see maps to the design in our SP-I report — the three modes, the
per-target authorisation invariant, continuous CVE monitoring, the audit log,
and bilingual reporting."

### 1. Register a target — UC-1 (40s)
- Left panel → Name `Al-Waha Portal`, URL `http://127.0.0.1:8000/`, **Choose
  File** and attach a written-authorisation PDF, Add target.
- Point out: the document is **SHA-256 hashed** and stored — the audit entry
  (bottom panel) records `doc="..." sha256:...`, and the green **"✓ authorised ·
  <file> · <hash>"** badge in the console links to the stored document. "The
  authorisation is a hashed artifact, not a checkbox — tamper-evident evidence."
- Honest line if asked "how do you know it's genuine?": "Hashing makes the
  on-file document tamper-evident and non-repudiable; proving the person is
  really allowed to scan the asset is done by domain-ownership verification,
  which is our production control and future work."

### 2. Mode 1 — passive recon + CVE matching — UC-2, 5.6.1, 5.6.4 (90s)
- Select the target → **Run Mode 1**.
- Point to the **detected stack chips** (Apache 2.4.49, PHP 7.2.1, WordPress
  4.6.1, jQuery 1.12.4, Bootstrap 3.3.7) — "this is real fingerprinting from a
  single passive GET plus a TLS handshake, no active probe."
- Point to the **findings table**: missing security headers, and a block of
  **real CVEs** matched to the exact versions — two criticals (CVE-2021-42013,
  CVE-2019-11043 at CVSS 9.8). "The matcher walks CPE + version ranges against
  our local NVD index; the live NVD sync is wired for deployment."

### 3. The authorisation invariant — NFR-S-1/2, Ch.6 (60s)  ★ compliance moment
- Register a second target **without** ticking authorisation ("Unauthorised
  Site"), select it → **Run Mode 2**.
- It is **denied** with a red toast, and a **denied** entry appears in the audit
  log. "This isn't a UI check — `Scan.auth_record_id` is a foreign key, so an
  active-mode scan without a recorded authorisation is impossible to store. The
  guard blocked it before any packet left the system."

### 4. Mode 2 — authorised active scan — UC-3, 5.6.2 (30s)
- Back to the authorised target → **Run Mode 2**.
- OWASP Top 10 findings appear (SQLi, XSS, IDOR, misconfig), rate-limited at
  1 req/s (NFR-S-3). "Mode 2 only stores normalised findings — the reasoning is
  Mode 3's job."

### 5. Mode 3 — AI attack-path narrative — UC-4, 5.6.3 (75s)  ★ headline
- **Run Mode 3** → open the **Mode 3 tab**.
- Show the **ATT&CK technique tags** and the **chained narrative**: it takes the
  individually-scored findings and chains them into one realistic attack path
  (foothold → escalation → account takeover), with ECC-mapped remediation.
  "This is the reasoning gap from our literature review — a scanner lists
  findings; ASAA explains how they combine."
- Note the provider line. "In production this runs on HUMAIN's sovereign
  endpoint; behind the abstraction we can also use a dev LLM; right now it's the
  deterministic fallback, still built from the real findings."

### 6. Continuous CVE monitoring — UC-5, PF-2 (30s)
- Left panel → **Run monitoring sweep**. Alerts appear for the high/critical
  CVEs above the CVSS 7.0 threshold, each written to the audit log. "This is the
  scheduled flow that re-evaluates every registered target against new CVEs."

### 7. Bilingual report + email — UC-6, 5.6.5 (45s)
- **Report EN** then **Report AR**. Open both PDFs. Show the Arabic report reads
  right-to-left with a proper executive summary, findings register, the Mode 3
  narrative, and ECC-mapped remediation. Each report is content-hashed.
- Then type an address in the **"email report to…"** field and click **Email
  report**. Switch to your Mailtrap inbox and show the email arriving **with the
  PDF attached**. "The report can be delivered by email straight from the
  platform — here it's a Mailtrap sandbox so nothing goes to real inboxes."
- (If SMTP isn't set up, the button reports "generated but not emailed" and the
  download still works — so the demo never breaks.)

### 8. Tamper-evident audit log — NFR-S-4, ECC 2-12, UC-7 (30s)  ★ compliance moment
- Bottom panel → **Verify hash chain** → green "intact across N entries".
- Optional kicker: in a terminal,
  `sqlite3 asaa/asaa.db "UPDATE audit_entries SET detail='x' WHERE seq=2"`,
  click **Verify** again → it reports the exact broken entry. "The log is
  append-only and hash-chained, so any edit is detectable — that's our ECC 2-12
  evidence."

### Close (20s)
"So end to end: authorised registration, passive recon with live CVE matching,
a structurally-enforced authorisation gate, AI reasoning over the findings,
continuous monitoring, bilingual reporting, and a tamper-evident audit trail —
the SP-I design, running."

---

## If something fails live
- **Target unreachable on Mode 1:** the benchmark target isn't up — run
  `python scripts/mock_target.py 8000`, or point at a running Juice Shop.
- **Mode 3 slow:** it's trying a live LLM; unset `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`
  or set `ASAA_REASONING_PROVIDER=canned` for an instant deterministic narrative.
- **Arabic report shows boxes:** install the font — `sudo apt-get install fonts-kacst`.
- **Email not sending:** check `.env` has the Mailtrap `ASAA_SMTP_USER`/`PASS`;
  the health chip / `/api/health` shows `email_configured`. Sending needs
  outbound network to Mailtrap.
- **Clean slate:** stop the server, delete `asaa/asaa.db`, restart, re-seed.
