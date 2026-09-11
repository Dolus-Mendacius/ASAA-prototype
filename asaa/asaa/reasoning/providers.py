"""Mode 3 reasoning provider abstraction (Ch.5 5.6.3, Objective 5).

A single interface, `ReasoningProvider`, with four implementations:

  * HumainProvider    - the sovereign production endpoint (ECC 4-1-3.2).
  * OpenAIProvider    - dev LLM behind the abstraction, non-production data only.
  * AnthropicProvider - dev LLM behind the abstraction, non-production data only.
  * CannedProvider    - deterministic, findings-derived narrative used when no
                        inference endpoint is reachable, so the demo always
                        produces a coherent Mode 3 output.

The engine (engine.py) selects the first available provider in preference
order. Every provider returns the SAME validated JSON schema:
    {"narrative": str, "techniques": [{"id","name"}], "remediation":[{"action","ecc"}]}
so downstream code and the report generator never branch on which produced it.
"""
from __future__ import annotations

import json

import httpx

from .. import config


# --- ATT&CK / ECC mapping tables used to ground the narrative ---------------
_ATTACK_MAP = {
    "sql injection": ("T1190", "Exploit Public-Facing Application"),
    "cross-site scripting": ("T1059", "Command and Scripting Interpreter"),
    "xss": ("T1059", "Command and Scripting Interpreter"),
    "broken access control": ("T1548", "Abuse Elevation Control Mechanism"),
    "insecure direct object reference": ("T1213", "Data from Information Repositories"),
    "security misconfiguration": ("T1592", "Gather Victim Host Information"),
    "cryptographic": ("T1040", "Network Sniffing"),
    "missing security header": ("T1185", "Browser Session Hijacking"),
    "path traversal": ("T1083", "File and Directory Discovery"),
    "remote code execution": ("T1203", "Exploitation for Client Execution"),
}


def _attack_for(text: str):
    low = text.lower()
    for needle, (tid, name) in _ATTACK_MAP.items():
        if needle in low:
            return {"id": tid, "name": name}
    return {"id": "T1595", "name": "Active Scanning"}


class ReasoningProvider:
    name = "base"

    def available(self) -> bool:
        return False

    def reason(self, context: dict) -> dict:
        raise NotImplementedError


# --- Structured prompt shared by the live providers -------------------------
def build_prompt(context: dict) -> str:
    schema = ('{"narrative": string, "techniques": [{"id": string, "name": string}], '
              '"remediation": [{"action": string, "ecc": string}]}')
    return (
        "SYSTEM: You are ASAA's Mode 3 reasoning engine. Reason strictly over the "
        "findings provided, following an ECC-2:2024-aligned attack-tree structure. "
        "Do not invent findings that are not present. Label output as AI-assisted analysis.\n\n"
        f"TARGET: {context['target']['name']} ({context['target']['url']})\n\n"
        f"FINDINGS (JSON):\n{json.dumps(context['findings'], indent=2)}\n\n"
        f"MATCHED CVEs (JSON):\n{json.dumps(context['cves'], indent=2)}\n\n"
        "TASK: Chain these findings into a single realistic attack path an adversary "
        "could follow, mapping each step to a MITRE ATT&CK technique, and give "
        "prioritised remediation with each item mapped to an ECC-2:2024 control.\n"
        f"Return ONLY JSON matching: {schema}"
    )


def _validate(obj: dict) -> dict:
    assert isinstance(obj.get("narrative"), str) and obj["narrative"].strip()
    obj.setdefault("techniques", [])
    obj.setdefault("remediation", [])
    return obj


class HumainProvider(ReasoningProvider):
    name = "humain-sovereign"

    def available(self) -> bool:
        return bool(config.HUMAIN_API_BASE and config.HUMAIN_API_KEY)

    def reason(self, context: dict) -> dict:
        with httpx.Client(timeout=60) as client:
            r = client.post(
                f"{config.HUMAIN_API_BASE.rstrip('/')}/v1/chat/completions",
                headers={"Authorization": f"Bearer {config.HUMAIN_API_KEY}"},
                json={"model": "humain-default",
                      "messages": [{"role": "user", "content": build_prompt(context)}],
                      "response_format": {"type": "json_object"}},
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
        return _validate(json.loads(text))


class OpenAIProvider(ReasoningProvider):
    name = "openai-dev"

    def available(self) -> bool:
        return bool(config.OPENAI_API_KEY)

    def reason(self, context: dict) -> dict:
        with httpx.Client(timeout=60) as client:
            r = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"},
                json={"model": config.OPENAI_MODEL,
                      "messages": [{"role": "user", "content": build_prompt(context)}],
                      "response_format": {"type": "json_object"}},
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
        return _validate(json.loads(text))


class AnthropicProvider(ReasoningProvider):
    name = "anthropic-dev"

    def available(self) -> bool:
        return bool(config.ANTHROPIC_API_KEY)

    def reason(self, context: dict) -> dict:
        with httpx.Client(timeout=60) as client:
            r = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": config.ANTHROPIC_API_KEY,
                         "anthropic-version": "2023-06-01"},
                json={"model": config.ANTHROPIC_MODEL, "max_tokens": 1500,
                      "messages": [{"role": "user", "content": build_prompt(context)}]},
            )
            r.raise_for_status()
            text = r.json()["content"][0]["text"]
            text = text[text.find("{"): text.rfind("}") + 1]
        return _validate(json.loads(text))


class CannedProvider(ReasoningProvider):
    """Deterministic fallback that composes a genuine, findings-derived
    narrative. It is not a fixed string: the attack path, ATT&CK techniques
    and remediation are all built from the actual findings passed in."""

    name = "canned-fallback"

    def available(self) -> bool:
        return True

    def reason(self, context: dict) -> dict:
        findings = sorted(context["findings"],
                          key=lambda f: f.get("cvss") or 0, reverse=True)
        cves = context.get("cves", [])
        target = context["target"]

        steps, techniques, seen = [], [], set()
        for i, f in enumerate(findings[:6], 1):
            tech = _attack_for(f["category"] + " " + f["title"])
            if tech["id"] not in seen:
                techniques.append(tech)
                seen.add(tech["id"])
            steps.append(
                f"Step {i} ({tech['id']} {tech['name']}): the {f['severity']} "
                f"finding \"{f['title']}\" gives the adversary "
                f"{'an initial foothold' if i == 1 else 'a way to escalate'}. "
                f"Evidence: {f.get('evidence','')}"
            )

        chain = ""
        if len(findings) >= 2:
            chain = (
                f"\n\nChained impact: individually these findings rate "
                f"{findings[0]['severity']} and below, but combined they form a "
                f"realistic account-takeover path — the "
                f"{findings[0]['title'].lower()} provides entry, and the weaker "
                f"access-control and header findings let the adversary pivot and "
                f"persist. A scanner listing them separately would understate the risk."
            )

        cve_line = ""
        if cves:
            top = cves[0]
            cve_line = (
                f"\n\nThe matched vulnerability {top['cve_id']} (CVSS {top['cvss']}) "
                f"on {top.get('component','the detected stack')} corroborates this path "
                f"with a publicly documented exploit primitive."
            )

        narrative = (
            f"AI-assisted attack-path analysis for {target['name']} "
            f"({target['url']}).\n\n" + "\n".join(steps) + chain + cve_line +
            "\n\nThis narrative is AI-assisted analysis and should be confirmed by a "
            "human reviewer before remediation prioritisation (SP-I Ch.6 limitation)."
        )

        remediation = []
        for f in findings[:6]:
            if f.get("remediation"):
                remediation.append({"action": f["remediation"],
                                    "ecc": f.get("ecc_control", "ECC 2-10")})
        # de-dup remediation
        uniq, out = set(), []
        for r in remediation:
            if r["action"] not in uniq:
                uniq.add(r["action"])
                out.append(r)

        return _validate({"narrative": narrative, "techniques": techniques,
                          "remediation": out})
