"""Semantic Capability Extractor (spec section 3).

Merges what the *tool* can do with what the *arguments* reveal it is doing, and
reports the difference.  That difference - a capability the arguments unlock
which the tool profile never promised - is one of the more useful signals in
the whole pipeline: `python.execute` is declared as EXECUTE, but
`os.remove('/etc/passwd')` also unlocks DELETE against a system path.
"""

from __future__ import annotations

from app.models.enums import CAPABILITY_WEIGHT, Capability
from app.models.tool_call import (
    ArgumentAnalysis,
    CapabilityAssessment,
    ToolAnalysis,
)

IMPLICATIONS: dict[Capability, set[Capability]] = {
    Capability.DOWNLOAD: {Capability.NETWORK},
    Capability.UPLOAD: {Capability.NETWORK},
    Capability.EMAIL: {Capability.NETWORK},
    Capability.PRIVILEGE_CHANGE: {Capability.MODIFY},
}


def close_implications(capabilities: set[Capability]) -> set[Capability]:
    """Add structurally implied capabilities (DOWNLOAD implies NETWORK, ...)."""
    out = set(capabilities)
    for cap in capabilities:
        out |= IMPLICATIONS.get(cap, set())
    return out


class CapabilityExtractor:
    """Produces the authoritative capability set for one invocation."""

    def extract(
        self,
        tool_analysis: ToolAnalysis,
        argument_analysis: ArgumentAnalysis | None = None,
    ) -> CapabilityAssessment:
        from_tool = set(tool_analysis.capabilities)
        from_args = set(argument_analysis.capabilities) if argument_analysis else set()

        escalations = from_args - close_implications(from_tool)

        merged = close_implications(from_tool | from_args)
        weight = self.weigh(merged)

        if tool_analysis.known_tool:
            evidenced = merged
        elif from_args:
            evidenced = close_implications(from_args)
        else:
            evidenced = merged

        confidence = self._confidence(tool_analysis, argument_analysis, escalations)
        parts = [f"tool declares {sorted(c.value for c in from_tool) or 'nothing'}"]
        if from_args:
            parts.append(f"arguments imply {sorted(c.value for c in from_args)}")
        if escalations:
            parts.append(f"argument-only escalation to {sorted(c.value for c in escalations)}")

        return CapabilityAssessment(
            capabilities=sorted(merged, key=lambda c: c.value),
            from_tool=sorted(from_tool, key=lambda c: c.value),
            from_arguments=sorted(from_args, key=lambda c: c.value),
            escalations=sorted(escalations, key=lambda c: c.value),
            evidenced=sorted(evidenced, key=lambda c: c.value),
            weight=weight,
            confidence=confidence,
            explanation="; ".join(parts),
        )

    @staticmethod
    def weigh(capabilities: set[Capability]) -> float:
        """Severity of a capability *set*.

        The most destructive capability dominates; additional distinct
        capabilities add a bounded breadth premium, because a call that can
        both read and transmit is worse than one that can only read.
        """
        if not capabilities:
            return 0.0
        weights = sorted((CAPABILITY_WEIGHT[c] for c in capabilities), reverse=True)
        breadth = sum(min(6.0, w * 0.12) for w in weights[1:])
        return round(min(100.0, weights[0] + breadth), 2)

    @staticmethod
    def _confidence(
        tool_analysis: ToolAnalysis,
        argument_analysis: ArgumentAnalysis | None,
        escalations: set[Capability],
    ) -> float:
        if argument_analysis is None:
            return round(tool_analysis.confidence * 0.8, 3)
        conf = 0.5 * tool_analysis.confidence + 0.5 * argument_analysis.confidence
        if not argument_analysis.parse_ok:
            conf *= 0.85
        if escalations:
            conf = min(0.97, conf + 0.03)
        return round(min(1.0, max(0.0, conf)), 3)
