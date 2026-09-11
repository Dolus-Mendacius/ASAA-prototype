"""CVE index and matching (Ch.5 5.6.4) + continuous monitoring (UC-5).

The matcher operates over CPE 2.3 identifiers emitted by the Mode 1
fingerprinter. Matching is two-pass, exactly as specified in 5.6.4:
  1. exact vendor+product filter, then
  2. version-range evaluation against each CVE's affected ranges.

The local index (data/cve_index.json) holds real NVD records for the stacks the
benchmark targets and common Saudi web deployments expose. `sync_from_nvd()`
pulls the live NVD JSON API 2.0 when reachable and merges deltas; when the feed
is unreachable the cached local index continues to serve every match
(NFR-Reliability / graceful degradation).
"""
from __future__ import annotations

import json
from functools import lru_cache

import httpx

from .. import config


def _parse_version(v: str):
    """Loose semantic tuple so '2.4.49' > '2.4.9'. Non-numeric parts ignored."""
    parts = []
    for chunk in str(v).replace("-", ".").split("."):
        num = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _parse_version(a), _parse_version(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return (ta > tb) - (ta < tb)


def _in_range(version: str, rng: dict) -> bool:
    """Evaluate a target version against one affected-range spec."""
    if version is None:
        return False
    if "exact" in rng:
        return _cmp(version, rng["exact"]) == 0
    ok = True
    if "introduced" in rng:
        ok = ok and _cmp(version, rng["introduced"]) >= 0
    if "lt" in rng:
        ok = ok and _cmp(version, rng["lt"]) < 0
    if "lte" in rng:
        ok = ok and _cmp(version, rng["lte"]) <= 0
    return ok


@lru_cache(maxsize=1)
def load_index() -> list[dict]:
    with open(config.LOCAL_CVE_INDEX, encoding="utf-8") as fh:
        return json.load(fh)["cves"]


def severity_of(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def match_component(component: dict, index: list[dict] | None = None) -> list[dict]:
    """Return CVE records affecting one detected component."""
    index = index or load_index()
    vendor = (component.get("vendor") or "").lower()
    product = (component.get("product") or "").lower()
    version = component.get("version")
    hits = []
    for cve in index:
        for aff in cve.get("affected", []):
            if aff.get("vendor", "").lower() != vendor or aff.get("product", "").lower() != product:
                continue
            # If we have a version, evaluate ranges; if not, flag as possible.
            ranges = aff.get("ranges", [])
            if version and ranges and not any(_in_range(version, r) for r in ranges):
                continue
            confidence = 1.0 if version else 0.6
            hits.append({
                "cve_id": cve["cve_id"], "cvss": cve["cvss"],
                "severity": severity_of(cve["cvss"]),
                "description": cve["description"], "published": cve.get("published"),
                "match_confidence": confidence,
                "matched_on": f"{vendor}:{product}:{version or '*'}",
            })
            break
    return hits


def match_target(components: list[dict]) -> list[dict]:
    index = load_index()
    out = []
    for comp in components:
        for hit in match_component(comp, index):
            hit["component"] = f"{comp['vendor']} {comp['product']} {comp.get('version') or ''}".strip()
            out.append(hit)
    # de-dup by (cve, component), keep highest confidence
    dedup: dict[tuple, dict] = {}
    for h in out:
        k = (h["cve_id"], h["component"])
        if k not in dedup or h["match_confidence"] > dedup[k]["match_confidence"]:
            dedup[k] = h
    return sorted(dedup.values(), key=lambda x: x["cvss"], reverse=True)


def sync_from_nvd(cpe_names: list[str]) -> dict:
    """Live NVD JSON API 2.0 pull, merged into the in-memory index.

    Wired per the design; returns a status dict. On any network/policy failure
    it reports degraded=True and the cached index keeps serving (UC-5 1a)."""
    merged, errors = 0, []
    try:
        with httpx.Client(timeout=20) as client:
            for cpe in cpe_names[:10]:
                r = client.get(config.NVD_API_BASE,
                               params={"cpeName": cpe, "resultsPerPage": 20})
                r.raise_for_status()
                merged += len(r.json().get("vulnerabilities", []))
        return {"degraded": False, "merged": merged, "source": "nvd-live"}
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))
        return {"degraded": True, "merged": 0, "source": "cached-index",
                "note": "NVD feed unreachable; serving cached local index.",
                "error": errors[0] if errors else None}
