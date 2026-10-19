"""Tool Analyzer (spec section 1).

Answers "what *kind of power* does this tool have?" purely from configurable
metadata, before any argument is looked at.  Unknown tools are not trusted by
default: they fall back to name heuristics with reduced confidence, which the
risk engine treats as an uncertainty penalty rather than as safety.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import ASLConfig, get_config
from app.models.enums import CAPABILITY_WEIGHT, Capability, ToolCategory
from app.models.tool_call import ToolAnalysis, ToolInvocation, ToolProfile


class ToolRegistry:
    """Loads and serves tool metadata from JSON so tools stay configurable."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        raw: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        self.version: str = raw.get("version", "0")
        self.profiles: dict[str, ToolProfile] = {}
        for entry in raw.get("tools", []):
            profile = ToolProfile(**entry)
            self.profiles[profile.tool_name] = profile
        self.name_heuristics: dict[str, dict[str, Any]] = raw.get("name_heuristics", {})
        self.analyzer_hints: dict[str, list[str]] = raw.get("analyzer_hints", {})
        self.unknown_defaults: dict[str, Any] = raw.get("unknown_tool_defaults", {})

    # -- lookup ---------------------------------------------------------
    def get(self, tool_name: str) -> ToolProfile | None:
        return self.profiles.get(tool_name)

    def names(self) -> list[str]:
        return sorted(self.profiles)

    def infer_analyzer(self, tool_name: str) -> str:
        lowered = tool_name.lower()
        for analyzer, hints in self.analyzer_hints.items():
            if any(hint in lowered for hint in hints):
                return analyzer
        return "generic"

    def infer_profile(self, tool_name: str) -> tuple[ToolProfile, float]:
        """Best-effort profile for a tool that is not in the registry.

        Returns the inferred profile plus the confidence we have in it.
        """
        lowered = tool_name.lower()
        caps: set[Capability] = set()
        sensitivity = int(self.unknown_defaults.get("sensitivity", 60))
        category = ToolCategory(self.unknown_defaults.get("category", "UNKNOWN"))
        reversible = bool(self.unknown_defaults.get("reversible", True))
        confidence = float(self.unknown_defaults.get("confidence", 0.35))
        hits = 0

        for token, meta in self.name_heuristics.items():
            if token in lowered:
                hits += 1
                caps.update(Capability(c) for c in meta.get("capabilities", []))
                sensitivity = max(sensitivity, int(meta.get("sensitivity", 0)))
                if meta.get("category") and meta["category"] != "UNKNOWN":
                    category = ToolCategory(meta["category"])
                reversible = reversible and bool(meta.get("reversible", True))

        if not caps:
            caps = {Capability(c) for c in self.unknown_defaults.get("capabilities", ["READ"])}
        else:
            # Some evidence about the tool raises confidence, but never to the
            # level of a registered tool.
            confidence = min(0.6, confidence + 0.1 * hits)

        profile = ToolProfile(
            tool_name=tool_name,
            category=category,
            sensitivity=sensitivity,
            capabilities=sorted(caps, key=lambda c: c.value),
            analyzer=self.infer_analyzer(tool_name),
            reversible=reversible,
            description="inferred from tool name; not in registry",
        )
        return profile, confidence


@lru_cache(maxsize=4)
def _registry_for(path: str) -> ToolRegistry:
    return ToolRegistry(path)


def get_registry(config: ASLConfig | None = None) -> ToolRegistry:
    config = config or get_config()
    return _registry_for(config.tool_registry_path)


class ToolAnalyzer:
    """Turns a tool name into a `ToolAnalysis`."""

    def __init__(self, config: ASLConfig | None = None, registry: ToolRegistry | None = None) -> None:
        self.config = config or get_config()
        self.registry = registry or get_registry(self.config)

    def profile_for(self, tool_name: str) -> tuple[ToolProfile, bool, float]:
        """Return (profile, known_tool, confidence)."""
        profile = self.registry.get(tool_name)
        if profile is not None:
            return profile, True, 0.95
        profile, confidence = self.registry.infer_profile(tool_name)
        return profile, False, confidence

    def analyze(self, invocation: ToolInvocation) -> ToolAnalysis:
        profile, known, confidence = self.profile_for(invocation.tool_name)
        risk = self.static_risk(profile, known)
        reasons = [f"category={profile.category}", f"sensitivity={profile.sensitivity}"]
        if not known:
            reasons.append("tool not in registry: profile inferred from name")
        if not profile.reversible:
            reasons.append("irreversible action")
        if profile.requires_auth:
            reasons.append("requires authenticated credentials")
        return ToolAnalysis(
            tool_name=invocation.tool_name,
            category=profile.category,
            sensitivity=profile.sensitivity,
            capabilities=list(profile.capabilities),
            risk=risk,
            confidence=confidence,
            known_tool=known,
            reversible=profile.reversible,
            explanation="; ".join(reasons),
        )

    @staticmethod
    def static_risk(profile: ToolProfile, known: bool) -> float:
        """Risk the tool carries *before* its arguments are known.

        Sensitivity dominates; the most destructive capability the tool can
        reach pulls the score up; irreversibility and unknown provenance add a
        fixed premium.
        """
        cap_peak = max((CAPABILITY_WEIGHT[c] for c in profile.capability_set), default=0)
        risk = 0.65 * profile.sensitivity + 0.35 * cap_peak
        if not profile.reversible:
            risk += 6.0
        if not known:
            risk += 8.0
        return round(min(100.0, max(0.0, risk)), 2)
