"""Mode 3 engine: selects a provider in preference order and runs it, with
graceful fallback to the canned provider (UC-4 3a, Objective 5)."""
from __future__ import annotations

from .. import config
from .providers import (AnthropicProvider, CannedProvider, HumainProvider,
                        OpenAIProvider)

_ORDER = {
    "auto": [HumainProvider, OpenAIProvider, AnthropicProvider, CannedProvider],
    "humain": [HumainProvider, CannedProvider],
    "openai": [OpenAIProvider, CannedProvider],
    "anthropic": [AnthropicProvider, CannedProvider],
    "canned": [CannedProvider],
}


def run_reasoning(context: dict) -> dict:
    """Return {narrative, techniques, remediation, provider, degraded}."""
    chain = _ORDER.get(config.REASONING_PROVIDER, _ORDER["auto"])
    tried = []
    for cls in chain:
        provider = cls()
        if not provider.available():
            continue
        try:
            result = provider.reason(context)
            result["provider"] = provider.name
            result["degraded"] = provider.name == "canned-fallback"
            result["providers_tried"] = tried + [provider.name]
            return result
        except Exception as exc:  # noqa: BLE001 - fall through to next provider
            tried.append(f"{provider.name}:error")
            continue
    # canned is always available; this is only reached if explicitly disabled
    result = CannedProvider().reason(context)
    result.update({"provider": "canned-fallback", "degraded": True,
                   "providers_tried": tried})
    return result
