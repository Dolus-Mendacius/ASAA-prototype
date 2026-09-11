"""Mode 1 - Passive Reconnaissance pipeline (Ch.5 5.6.1).

Three adapters behind a common Scanner interface:
  * TechFingerprinter  - WhatWeb-style stack detection from a single GET
  * TlsAnalyzer        - real TLS/cert inspection via the ssl module
  * HeaderAnalyzer     - security-header presence/absence

No active probe is sent: one GET and one TLS handshake against public surface
only, so Mode 1 stays authorisation-free. Output is normalised Finding dicts
and a list of detected components (with CPE 2.3 strings) that drive CVE
matching in services/cve.py.

If the optional external `whatweb` binary is present it is used and merged in;
otherwise the built-in signature engine does genuine detection from the HTTP
response. Nothing is faked.
"""
from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import json as _json
from urllib.parse import urlparse

import httpx

# (regex, vendor, product, version_group_index_or_None, evidence_source)
_SIGNATURES = [
    (re.compile(r"nginx/?([\d.]+)?", re.I), "nginx", "nginx", 1, "header:Server"),
    (re.compile(r"Apache/?([\d.]+)?", re.I), "apache", "http_server", 1, "header:Server"),
    (re.compile(r"Microsoft-IIS/?([\d.]+)?", re.I), "microsoft", "iis", 1, "header:Server"),
    (re.compile(r"PHP/?([\d.]+)?", re.I), "php", "php", 1, "header:X-Powered-By"),
    (re.compile(r"ASP\.NET", re.I), "microsoft", "asp.net", None, "header:X-Powered-By"),
    (re.compile(r"Express", re.I), "openjsf", "express", None, "header:X-Powered-By"),
    (re.compile(r"WordPress ?([\d.]+)?", re.I), "wordpress", "wordpress", 1, "body:generator"),
    (re.compile(r"Drupal ?([\d.]+)?", re.I), "drupal", "drupal", 1, "body:generator"),
    (re.compile(r"Joomla!? ?([\d.]+)?", re.I), "joomla", "joomla", 1, "body:generator"),
    (re.compile(r"jquery[-.]?([\d.]+)?(?:\.min)?\.js", re.I), "jquery", "jquery", 1, "body:script"),
    (re.compile(r"bootstrap[-.]?([\d.]+)?(?:\.min)?\.(?:js|css)", re.I), "getbootstrap", "bootstrap", 1, "body:asset"),
    (re.compile(r"angular[-.]?([\d.]+)?(?:\.min)?\.js", re.I), "angularjs", "angular.js", 1, "body:script"),
]

_SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "high"),
    "strict-transport-security": ("Strict-Transport-Security", "high"),
    "x-frame-options": ("X-Frame-Options", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "medium"),
    "referrer-policy": ("Referrer-Policy", "low"),
}


def cpe23(vendor: str, product: str, version: str | None) -> str:
    v = version if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


class TechFingerprinter:
    """WhatWeb-style detection from a single passive GET."""

    def detect(self, headers: dict, body: str) -> list[dict]:
        found: dict[str, dict] = {}
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        for rx, vendor, product, grp, src in _SIGNATURES:
            haystack = header_blob if src.startswith("header") else body
            m = rx.search(haystack or "")
            if not m:
                continue
            version = m.group(grp) if grp and m.lastindex and m.group(grp) else None
            key = f"{vendor}:{product}"
            # keep the most specific (versioned) hit
            if key not in found or (version and not found[key]["version"]):
                found[key] = {
                    "vendor": vendor, "product": product, "version": version,
                    "cpe": cpe23(vendor, product, version), "evidence": src,
                }
        return list(found.values())


class TlsAnalyzer:
    """Real TLS handshake + certificate inspection (no external tool needed)."""

    def analyze(self, host: str, port: int = 443) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert(binary_form=False) or {}
                    return {
                        "reachable": True,
                        "protocol": ss.version(),
                        "cipher": ss.cipher()[0] if ss.cipher() else None,
                        "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                        "not_after": cert.get("notAfter"),
                    }
        except Exception as exc:  # noqa: BLE001 - graceful for demo targets
            return {"reachable": False, "error": str(exc)}


class HeaderAnalyzer:
    def analyze(self, headers: dict) -> list[dict]:
        lower = {k.lower(): v for k, v in headers.items()}
        findings = []
        for key, (label, sev) in _SECURITY_HEADERS.items():
            if key not in lower:
                findings.append({
                    "identifier": f"HDR-{key[:6].upper()}",
                    "category": "Security Misconfiguration (OWASP A05)",
                    "title": f"Missing security header: {label}",
                    "severity": sev,
                    "evidence": f"Response did not include the {label} header.",
                    "source_tool": "HeaderAnalyzer",
                    "remediation": f"Set the {label} response header on all application responses.",
                    "ecc_control": "ECC 2-10",
                })
        return findings


def _maybe_whatweb(url: str) -> list[dict]:
    """Merge real whatweb output if the binary is installed."""
    if not shutil.which("whatweb"):
        return []
    try:
        out = subprocess.run(["whatweb", "--log-json=-", "--no-errors", url],
                             capture_output=True, text=True, timeout=40)
        data = _json.loads(out.stdout.strip().splitlines()[0])
        comps = []
        for plugin, meta in (data.get("plugins") or {}).items():
            ver = (meta.get("version") or [None])
            comps.append({"vendor": plugin.lower(), "product": plugin.lower(),
                          "version": (ver[0] if ver else None), "cpe": None,
                          "evidence": "whatweb"})
        return comps
    except Exception:  # noqa: BLE001
        return []


def run_passive(url: str) -> dict:
    """Execute the full Mode 1 pipeline. Returns components + findings + tls."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or url
    scheme = parsed.scheme or "http"

    components: list[dict] = []
    findings: list[dict] = []
    tls = {"reachable": False, "skipped": scheme != "https"}
    headers: dict = {}

    try:
        with httpx.Client(follow_redirects=True, timeout=12,
                          verify=False, headers={"User-Agent": "ASAA-Mode1/0.9"}) as client:
            resp = client.get(url if "://" in url else f"{scheme}://{url}")
            headers = dict(resp.headers)
            body = resp.text[:200_000]
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc), "components": [],
                "findings": [], "tls": tls, "headers": {}}

    components = TechFingerprinter().detect(headers, body)
    for extra in _maybe_whatweb(url):
        if f"{extra['vendor']}:{extra['product']}" not in {f"{c['vendor']}:{c['product']}" for c in components}:
            if not extra.get("cpe"):
                extra["cpe"] = cpe23(extra["vendor"], extra["product"], extra.get("version"))
            components.append(extra)

    findings.extend(HeaderAnalyzer().analyze(headers))

    if scheme == "https":
        tls = TlsAnalyzer().analyze(host, parsed.port or 443)
        if tls.get("reachable") and tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append({
                "identifier": "TLS-PROTO", "category": "Cryptographic Failures (OWASP A02)",
                "title": f"Weak TLS protocol negotiated: {tls['protocol']}",
                "severity": "high", "evidence": f"Server negotiated {tls['protocol']}.",
                "source_tool": "TlsAnalyzer",
                "remediation": "Disable TLS 1.1 and below; require TLS 1.2+.",
                "ecc_control": "ECC 2-10",
            })

    return {"reachable": True, "components": components, "findings": findings,
            "tls": tls, "headers": headers, "server": headers.get("server")}
