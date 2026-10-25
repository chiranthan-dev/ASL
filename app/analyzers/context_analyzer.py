"""Context Analyzer (spec section 9).

Judges the call against its surroundings: the prompt that supposedly motivated
it, the conversation, what the session has already done, and how this call
compares to the ones before it.

The signal this exists to catch is **prompt-action divergence**: the user asked
for a picture of a dog and the agent proposed deleting a directory. Under
prompt injection or agent malfunction, that gap is the earliest visible symptom,
and it is invisible to any analyzer that only looks at the call itself.
"""

from __future__ import annotations

import re

from app.models.context import AnalysisContext
from app.models.enums import Capability

PROMPT_EXPECTATIONS: tuple[tuple[str, set[Capability]], ...] = (
    (r"\b(search|look ?up|find|google|show me|what is|who is|picture|image|photo)\b",
     {Capability.READ, Capability.NETWORK}),
    (r"\b(email|mail|message|write to|send.*(to|professor|teacher|team))\b",
     {Capability.EMAIL, Capability.WRITE, Capability.NETWORK}),
    (r"\b(read|open|show|cat|view|summar\w+)\b.{0,25}\b(file|document|note|report)\b",
     {Capability.READ}),
    (r"\b(save|write|create|append|store|download)\b",
     {Capability.WRITE, Capability.DOWNLOAD, Capability.NETWORK}),
    (r"\b(delete|remove|clean ?up|purge|wipe|clear)\b", {Capability.DELETE}),
    (r"\b(run|execute|launch|install|compile)\b", {Capability.EXECUTE}),
    (r"\b(query|select|database|table|records?|rows?)\b", {Capability.DATABASE, Capability.READ}),
    (r"\b(calculate|compute|convert|how much|how many)\b", {Capability.READ}),
    (r"\b(upload|post|publish|submit|send.*(api|endpoint|webhook))\b",
     {Capability.UPLOAD, Capability.NETWORK}),
)

INJECTION_MARKERS = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) instructions|disregard (the )?(rules|policy|guidelines)|"
    r"you are now|new instructions:|system prompt|do not (tell|inform|ask) the user|without (asking|confirmation)|"
    r"pretend (you are|to be)|jailbreak|developer mode)"
)


class ContextAnalyzer:
    name = "context"

    def analyze(self, context: AnalysisContext) -> tuple[float, float, str, dict]:
        """Return (risk 0-100, confidence, explanation, detail)."""
        risk = 12.0
        notes: list[str] = []
        detail: dict[str, object] = {}

        prompt = (context.prompt or "").strip()
        actual = context.capability_set
        expected = self._expected_capabilities(prompt)
        detail["expected_capabilities"] = sorted(c.value for c in expected)
        detail["actual_capabilities"] = sorted(c.value for c in actual)

        if not prompt:
            risk += 12
            notes.append("no prompt supplied: the call cannot be checked against a stated purpose")
            confidence = 0.45
        elif not expected:
            risk += 8
            notes.append("the request does not map onto any recognised task shape")
            confidence = 0.55
        else:
            unexplained = actual - expected - {Capability.NETWORK, Capability.READ}
            detail["unexplained_capabilities"] = sorted(c.value for c in unexplained)
            if unexplained:
                severity = 18 + 12 * len(unexplained)
                risk += min(60.0, severity)
                notes.append(
                    "the request does not account for "
                    + ", ".join(sorted(c.value for c in unexplained))
                )
                confidence = 0.8
            else:
                notes.append("proposed capabilities match what the request implies")
                confidence = 0.85

        if INJECTION_MARKERS.search(prompt):
            risk += 25
            detail["injection_markers"] = True
            notes.append("prompt contains instruction-override phrasing")

        for line in context.conversation[-4:]:
            if INJECTION_MARKERS.search(line or ""):
                risk += 15
                detail["injection_in_conversation"] = True
                notes.append("earlier conversation turn contains instruction-override phrasing")
                break

        history = context.history
        detail["session_calls"] = history.call_count
        detail["session_max_risk"] = round(history.max_risk, 2)
        if history.escalating:
            risk += 14
            notes.append("risk has been climbing across this session")
        if history.call_count >= 8:
            risk += 8
            notes.append(f"long automated run: {history.call_count} calls in one session")

        risk = min(100.0, risk)
        explanation = "; ".join(notes) or "call sits comfortably in its context"
        return round(risk, 2), round(confidence, 3), explanation, detail

    @staticmethod
    def _expected_capabilities(prompt: str) -> set[Capability]:
        expected: set[Capability] = set()
        for pattern, capabilities in PROMPT_EXPECTATIONS:
            if re.search(pattern, prompt, re.I):
                expected |= capabilities
        return expected
