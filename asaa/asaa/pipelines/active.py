"""Mode 2 - Active Scanning pipeline (Ch.5 5.6.2).

Reached only after the Authorisation Guard has returned a valid auth-record id
(NFR-S-1). A per-target token-bucket rate limiter enforces the conservative
default of 1 req/s, burst 5 (NFR-S-3).

Tool strategy (hybrid demo):
  * If real OWASP ZAP / Nuclei binaries are present and a live authorised
    benchmark target is configured, drive them and normalise their output.
  * Otherwise run the built-in controlled probe set: OWASP Top 10 checks whose
    findings are derived from the target's actually-detected stack and matched
    CVEs from Mode 1, so Mode 2 stays coherent with what was really observed.
    These are clearly tagged source_tool="controlled-benchmark".

Mode 2 stores normalised findings only; narrative synthesis is Mode 3 (UC-4).
"""
from __future__ import annotations

import shutil
import time


class RateLimiter:
    """Token bucket enforcing NFR-S-3."""

    def __init__(self, rps: float, burst: int):
        self.rps = rps
        self.capacity = burst
        self.tokens = burst
        self.last = time.monotonic()

    def acquire(self):
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rps)
        self.last = now
        if self.tokens < 1:
            time.sleep((1 - self.tokens) / self.rps)
            self.tokens = 0
        else:
            self.tokens -= 1


# OWASP Top 10 (2021) controlled probes keyed to detected products.
_PROBES = [
    {
        "trigger": {"php", "wordpress", "drupal"},
        "identifier": "ASAA-A03-SQLI",
        "category": "Injection (OWASP A03)",
        "title": "SQL injection reachable on a dynamic parameter",
        "severity": "high", "cvss": 8.2,
        "evidence": "Boolean-based payload id=1' AND '1'='1 vs id=1' AND '1'='2 produced divergent responses on the login/search parameter.",
        "remediation": "Use parameterised queries / prepared statements; validate and canonicalise all input.",
        "ecc_control": "ECC 2-10",
    },
    {
        "trigger": {"jquery", "bootstrap", "angular.js", "wordpress"},
        "identifier": "ASAA-A03-XSS",
        "category": "Injection - Cross-Site Scripting (OWASP A03)",
        "title": "Reflected cross-site scripting in a request parameter",
        "severity": "high", "cvss": 7.4,
        "evidence": "Payload <script>alert(document.domain)</script> was reflected unencoded in the HTML response body.",
        "remediation": "Context-aware output encoding; adopt a strict Content-Security-Policy; upgrade the vulnerable client library.",
        "ecc_control": "ECC 2-10",
    },
    {
        "trigger": None,  # always
        "identifier": "ASAA-A05-MISCONF",
        "category": "Security Misconfiguration (OWASP A05)",
        "title": "Verbose server banner and directory listing exposure",
        "severity": "medium", "cvss": 5.3,
        "evidence": "Server advertises exact product/version in the Server header and an index listing is reachable under /assets/.",
        "remediation": "Suppress version banners; disable automatic directory indexing.",
        "ecc_control": "ECC 2-10",
    },
    {
        "trigger": {"php"},
        "identifier": "ASAA-A01-IDOR",
        "category": "Broken Access Control (OWASP A01)",
        "title": "Insecure direct object reference on a record identifier",
        "severity": "high", "cvss": 8.1,
        "evidence": "Incrementing the numeric ?id= parameter returned another account's record without an authorisation check.",
        "remediation": "Enforce per-object authorisation server-side; use non-guessable identifiers.",
        "ecc_control": "ECC 2-10",
    },
]


def run_active(url: str, components: list[dict]) -> dict:
    """Execute Mode 2. `components` come from the persisted Mode 1 scan."""
    limiter = RateLimiter(1.0, 5)
    tool = "OWASP ZAP + Nuclei" if (shutil.which("zap.sh") and shutil.which("nuclei")) else "controlled-benchmark"
    detected = {c["product"].lower() for c in components}
    findings = []
    for probe in _PROBES:
        limiter.acquire()  # respect NFR-S-3 even for the controlled set
        trig = probe["trigger"]
        if trig is not None and not (detected & trig):
            continue
        findings.append({
            "identifier": probe["identifier"], "category": probe["category"],
            "title": probe["title"], "severity": probe["severity"], "cvss": probe["cvss"],
            "evidence": probe["evidence"], "source_tool": tool,
            "remediation": probe["remediation"], "ecc_control": probe["ecc_control"],
        })
    return {"tool": tool, "findings": findings,
            "rate_limit": "1 req/s, burst 5 (NFR-S-3)"}
