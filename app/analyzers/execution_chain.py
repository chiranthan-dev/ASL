"""Execution Chain Analyzer (spec section 12).

Scores the *relationship* between actions, not the actions themselves. The
specification's own example is the whole point:

    READ -> DOWNLOAD -> EXECUTE -> DELETE     must outrank
    READ -> PROCESS  -> WRITE

Every individual step in the first chain is defensible. The kill chain is an
emergent property of the ordering, so it can only be seen by something that
looks at edges. That is what the behavior graph was built for.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.context import AnalysisContext
from app.models.enums import Capability, ResourceClass, Scope

BOUNDARY_SENSITIVE = {"EXFILTRATION_VIA_MAIL", "READ_THEN_UPLOAD", "EXFILTRATION"}

OUTSIDE = {ResourceClass.EMAIL_RECIPIENT_EXTERNAL, ResourceClass.EXTERNAL_ENDPOINT}

CONTAINED_RISK = 35.0

PRIOR_PATTERN_FLOOR = 30.0

SENSITIVE_SOURCES = {
    ResourceClass.CREDENTIAL_STORE, ResourceClass.PRODUCTION_RESOURCE,
    ResourceClass.SENSITIVE_TABLE, ResourceClass.SYSTEM_PATH,
}

CHAIN_PATTERNS: tuple[tuple[str, tuple[Capability, ...], float, str], ...] = (
    ("STAGED_INTRUSION",
     (Capability.DOWNLOAD, Capability.EXECUTE, Capability.DELETE), 97.0,
     "fetch a payload, run it, then remove the evidence"),
    ("EXFILTRATION",
     (Capability.DATABASE, Capability.UPLOAD), 95.0,
     "read stored data, then push it to an external destination"),
    ("EXFILTRATION_VIA_MAIL",
     (Capability.READ, Capability.EMAIL), 82.0,
     "read local data, then mail it out"),
    ("READ_THEN_UPLOAD",
     (Capability.READ, Capability.UPLOAD), 88.0,
     "read data, then upload it"),
    ("DOWNLOAD_EXECUTE",
     (Capability.DOWNLOAD, Capability.EXECUTE), 90.0,
     "run something that was just downloaded"),
    ("ESCALATE_THEN_ACT",
     (Capability.PRIVILEGE_CHANGE, Capability.EXECUTE), 93.0,
     "raise privileges, then use them"),
    ("WRITE_THEN_EXECUTE",
     (Capability.WRITE, Capability.EXECUTE), 86.0,
     "write a file, then run it"),
    ("COVER_TRACKS",
     (Capability.EXECUTE, Capability.DELETE), 84.0,
     "run something, then delete afterwards"),
    ("BENIGN_PROCESSING",
     (Capability.READ, Capability.WRITE), 22.0,
     "read input, produce output: the ordinary shape of useful work"),
)


@dataclass
class ChainAssessment:
    risk: float
    confidence: float
    explanation: str
    matched: list[str]
    detail: dict


class ExecutionChainAnalyzer:
    name = "execution_chain"

    def analyze(self, context: AnalysisContext) -> ChainAssessment:
        sequence = context.history.capability_sequence + [sorted(context.capability_set, key=lambda c: c.value)]
        flat = [cap for step in sequence for cap in step]
        detail: dict[str, object] = {
            "capability_sequence": [[c.value for c in step] for step in sequence],
            "transitions": list(context.chain_fingerprint.transitions),
            "steps": len(sequence),
        }

        matched: list[str] = []
        prior: list[str] = []
        risk = 15.0 if len(sequence) > 1 else 8.0
        explanations: list[str] = []

        crosses = self._crosses_boundary(context)
        sensitive_payload = self._touched_sensitive(context)
        current = context.capability_set
        for name, pattern, pattern_risk, description in CHAIN_PATTERNS:
            if not self._is_subsequence(pattern, flat):
                continue
            if pattern[-1] not in current:
                if pattern_risk >= 80.0:
                    prior.append(name)
                continue
            matched.append(name)
            if name in BOUNDARY_SENSITIVE and not crosses and not sensitive_payload:
                explanations.append(
                    f"{' -> '.join(c.value for c in pattern)}: {description}"
                    " (destination is internal, so not treated as exfiltration)")
                risk = max(risk, CONTAINED_RISK)
            else:
                explanations.append(f"{' -> '.join(c.value for c in pattern)}: {description}")
                risk = max(risk, pattern_risk)
        detail["crosses_trust_boundary"] = crosses
        detail["sensitive_payload"] = sensitive_payload
        detail["prior_patterns"] = prior

        if prior:
            risk = max(risk, PRIOR_PATTERN_FLOOR)
            explanations.append(
                f"earlier in this session: {', '.join(sorted(set(prior)))} "
                "(already scored when it occurred)")

        if matched == ["BENIGN_PROCESSING"] and len(sequence) == 1:
            risk = 12.0

        data_flow = [t for t in context.chain_fingerprint.transitions if "DATA_FLOW" in t]
        if data_flow:
            risk = min(100.0, risk + 5)
            explanations.append(f"{len(data_flow)} data-flow link(s) between steps")
        detail["data_flow_edges"] = data_flow

        if len(sequence) >= 4 and len({c for c in flat}) >= 5:
            risk = min(100.0, risk + 8)
            explanations.append("many distinct capabilities exercised in one session")

        if context.arguments.scope in (Scope.RECURSIVE, Scope.UNBOUNDED) and len(sequence) > 1:
            risk = min(100.0, risk + 5)

        confidence = 0.85 if matched else 0.6
        if len(sequence) == 1:
            confidence = 0.7
            explanations.append("single step: no chain to evaluate yet")

        detail["matched_patterns"] = matched
        return ChainAssessment(
            risk=round(risk, 2),
            confidence=confidence,
            explanation="; ".join(explanations) or "no meaningful relationship between actions",
            matched=matched,
            detail=detail,
        )

    @staticmethod
    def _touched_sensitive(context: AnalysisContext) -> bool:
        """Has this session read anything that should not be forwarded at all?

        Looks at the whole session, not just this call: the read that matters
        happened on an earlier turn, and by the time the mail is sent the current
        call touches only a mailbox.
        """
        seen = set(context.history.resource_classes)
        seen |= {r.resource_class.value for r in context.arguments.resources}
        return bool(seen & {c.value for c in SENSITIVE_SOURCES})

    @staticmethod
    def _crosses_boundary(context: AnalysisContext) -> bool:
        """Does *this* step send data outside the organisation?

        Judged from the resources the argument analyzer actually resolved, not
        from the capability alone. Absent evidence either way, an outward
        capability is assumed to cross -- unknown destinations are not given the
        benefit of the doubt.
        """
        outward = {Capability.UPLOAD, Capability.EMAIL} & context.capability_set
        if not outward:
            return False
        classes = {r.resource_class for r in context.arguments.resources}
        if classes & OUTSIDE:
            return True
        internal = {ResourceClass.EMAIL_RECIPIENT_INTERNAL} & classes
        return not internal

    @staticmethod
    def _is_subsequence(pattern: tuple[Capability, ...], sequence: list[Capability]) -> bool:
        """Does `pattern` appear in order (gaps allowed) inside `sequence`?"""
        it = iter(sequence)
        return all(any(item is target for item in it) for target in pattern)
