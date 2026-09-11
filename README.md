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

Point Mode 1 at the bundled benchmark target (`http://127.0.0.1:8000/`) or at a
real authorised benchmark such as OWASP Juice Shop / DVWA / Metasploitable 2.

---

## What the demo shows (mapped to SP-I)

| Capability | Where | SP-I reference |
|---|---|---|
| Target registration + authorisation capture | `orchestration.register_target` | UC-1 |
| **Mode 1 passive recon** (fingerprint, headers, TLS) | `pipelines/passive.py` | UC-2, 5.6.1 |
| **Live CVE matching** (CPE + version ranges) | `services/cve.py` | 5.6.4 |
| Mode 2 active scan (rate-limited, OWASP Top 10) | `pipelines/active.py` | UC-3, 5.6.2 |
| **Mode 3 AI attack-narrative** (ATT&CK + ECC remediation) | `reasoning/` | UC-4, 5.6.3 |
| Sovereign/dev/canned LLM abstraction | `reasoning/providers.py` | Objective 5 |
| **Per-target authorisation guard** (data-layer invariant) | `auth_guard.py` + FK on `Scan` | NFR-S-1/2, Ch.6 |
| **Hash-chained append-only audit log** | `audit.py` | NFR-S-4, ECC 2-12 |
| Continuous CVE monitoring + alerts | `orchestration.run_cve_monitor` | UC-5, PF-2 |
| Bilingual PDF report (RTL Arabic) | `services/report.py` | UC-6, 5.6.5 |

The domain model (`models.py`) mirrors the Ch.5 class/ER diagrams: a single
`Scan` table keyed by `mode` with a nullable-for-Mode-1 / required-for-Mode-2/3
`auth_record_id` foreign key, association classes for `TargetTechnology`,
`FindingCveReference`, and `CveAffectedComponent`, and independent `AlertRecord`
and `Report` aggregates.

**Mailtrap setup (2 min):** create a free account at mailtrap.io → Email Testing
→ your Inbox → SMTP Settings → copy the host, port, username, and password into
`.env` (`ASAA_SMTP_HOST/PORT/USER/PASS`). Then use the "Email report" button;
the email with the PDF attachment appears in your Mailtrap inbox.
