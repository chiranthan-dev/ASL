"""Intent Analyzer (spec section 4).

Classifies *what this call is for* from evidence already gathered — capabilities,
resource classes, findings and the chain it sits in — rather than from what the
prompt claims. The prompt is used only as weak corroboration, because in a
prompt-injection scenario the prompt is exactly the thing that lies.

Rules are ordered most-severe first: an action that is both destructive and
exfiltrating is reported as the worse of the two.
"""

from __future__ import annotations

import re

from app.models.context import AnalysisContext
from app.models.enums import Capability, Intent, ResourceClass, Scope

INTENT_RISK: dict[Intent, tuple[float, str]] = {
    Intent.PRIVILEGE_ESCALATION: (95.0, "changes who is allowed to do what"),
    Intent.DATA_EXFILTRATION: (94.0, "moves data out of the trust boundary"),
    Intent.DESTRUCTIVE_ACTION: (90.0, "destroys data or infrastructure"),
    Intent.CODE_EXECUTION: (72.0, "runs code whose behaviour is decided at runtime"),
    Intent.DATA_TRANSFER: (55.0, "moves data between systems"),
    Intent.COMMUNICATION: (35.0, "sends a message on the user's behalf"),
    Intent.FILE_MANAGEMENT: (38.0, "creates, edits or moves files"),
    Intent.DATA_PROCESSING: (28.0, "reads and transforms stored data"),
    Intent.INFORMATION_RETRIEVAL: (12.0, "reads information without changing anything"),
    Intent.UNKNOWN: (55.0, "purpose could not be established, which is itself a risk"),
}

PROMPT_SIGNALS: tuple[tuple[str, Intent], ...] = (
    (r"\b(exfiltrat|leak|steal|smuggle|siphon)\w*", Intent.DATA_EXFILTRATION),
    (r"\b(wipe|destroy|nuke|erase everything|delete all|drop (the )?(database|table))\b", Intent.DESTRUCTIVE_ACTION),
    (r"\b(escalate|root|admin rights|sudo|bypass (the )?(auth|permission|security))\b", Intent.PRIVILEGE_ESCALATION),
    (r"\b(run|execute|launch)\b.{0,20}\b(script|binary|payload|exe|command)\b", Intent.CODE_EXECUTION),
    (r"\b(email|message|mail|notify|send)\b", Intent.COMMUNICATION),
    (r"\b(find|search|look up|show me|what is|who is)\b", Intent.INFORMATION_RETRIEVAL),
)

INJECTION_MARKERS = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) instructions|disregard (the )?(rules|policy)|"
    r"you are now|system prompt|developer mode|act as (an? )?(admin|root)|without (asking|confirmation))"
)


SENSITIVE_SESSION_CLASSES = {
    ResourceClass.CREDENTIAL_STORE.value, ResourceClass.PRODUCTION_RESOURCE.value,
    ResourceClass.SENSITIVE_TABLE.value, ResourceClass.SYSTEM_PATH.value,
}


class IntentAnalyzer:
    """Evidence-first intent classification."""

    name = "intent"

    def analyze(self, context: AnalysisContext) -> tuple[Intent, float, float, str]:
        """Return (intent, risk 0-100, confidence 0-1, explanation)."""
        caps = context.capability_set
        resources = {r.resource_class for r in context.arguments.resources}
        codes = context.finding_codes()
        chain_caps = set(context.chain_fingerprint.capabilities)

        intent, evidence = self._classify(caps, resources, codes, chain_caps, context)
        base, rationale = INTENT_RISK[intent]
        risk = base * self._target_scale(intent, context, evidence)
        confidence = 0.85 if evidence else 0.5

        prompt_intent = self._prompt_intent(context.prompt)
        if prompt_intent is not None:
            if prompt_intent is intent:
                confidence = min(0.95, confidence + 0.08)
                evidence.append(f"the request itself reads as {intent.value.lower().replace('_', ' ')}")
            elif INTENT_RISK[prompt_intent][0] > base:
                risk = min(100.0, (risk + INTENT_RISK[prompt_intent][0]) / 2 + 8)
                evidence.append(
                    f"the wording suggests {prompt_intent.value} even though the call looks like {intent.value}"
                )

        if INJECTION_MARKERS.search(context.prompt or ""):
            risk = min(100.0, risk + 15)
            confidence = max(0.5, confidence - 0.1)
            evidence.append("prompt contains instruction-override phrasing typical of prompt injection")

        if context.arguments.scope in (Scope.RECURSIVE, Scope.UNBOUNDED) and intent in (
            Intent.DESTRUCTIVE_ACTION, Intent.FILE_MANAGEMENT, Intent.DATA_PROCESSING
        ):
            risk = min(100.0, risk + 6)
            evidence.append(f"scope is {context.arguments.scope.value}")

        explanation = f"{intent.value}: {rationale}"
        if evidence:
            explanation += " — " + "; ".join(evidence[:3])
        return intent, round(risk, 2), round(confidence, 3), explanation

    TARGET_SENSITIVE = {
        Intent.COMMUNICATION, Intent.FILE_MANAGEMENT, Intent.DATA_PROCESSING,
        Intent.DATA_TRANSFER, Intent.INFORMATION_RETRIEVAL,
    }

    def _target_scale(self, intent: Intent, context: AnalysisContext, evidence: list[str]) -> float:
        """Scale non-hostile intents by what they are actually aimed at.

        Charging a flat 35 for "sends a message" repeats the mistake this whole
        project is about: it scores the category, not the act. One internal mail
        with no attachment is not the same event as a bulk external send, even
        though both are COMMUNICATION.
        """
        if intent not in self.TARGET_SENSITIVE:
            return 1.0
        if context.sensitive_resource:
            return 1.0
        if context.arguments.scope in (Scope.RECURSIVE, Scope.UNBOUNDED):
            return 1.0
        if context.arguments.findings:
            return 0.8
        evidence.append("aimed at an ordinary, single, non-sensitive target")
        return 0.55

    def _classify(
        self,
        caps: set[Capability],
        resources: set[ResourceClass],
        codes: set[str],
        chain_caps: set[Capability],
        context: AnalysisContext,
    ) -> tuple[Intent, list[str]]:
        evidence: list[str] = []
        sensitive = context.sensitive_resource

        if Capability.PRIVILEGE_CHANGE in caps:
            return Intent.PRIVILEGE_ESCALATION, ["call changes permissions, ownership or identity"]

        sending = caps & {Capability.UPLOAD, Capability.EMAIL}
        evidenced = context.evidenced_set
        reading = evidenced & {Capability.READ, Capability.DATABASE, Capability.SENSOR_ACCESS}
        if reading and sending & evidenced:
            return Intent.DATA_EXFILTRATION, ["the same call both reads data and sends it outward"]
        if sending and (
            ResourceClass.EXTERNAL_ENDPOINT in resources or ResourceClass.EMAIL_RECIPIENT_EXTERNAL in resources
        ) and (sensitive or "HTTP_EXFILTRATION_SHAPE" in codes or "EMAIL_EXTERNAL_ATTACHMENT" in codes):
            return Intent.DATA_EXFILTRATION, ["sensitive material is leaving for an external destination"]
        if sending and (chain_caps & {Capability.READ, Capability.DATABASE}) \
                and len(context.chain_fingerprint.steps) > 1:
            outward = (ResourceClass.EXTERNAL_ENDPOINT in resources
                       or ResourceClass.EMAIL_RECIPIENT_EXTERNAL in resources)
            carried_sensitive = bool(
                set(context.history.resource_classes) & SENSITIVE_SESSION_CLASSES)
            if outward or sensitive or carried_sensitive:
                where = "outside the organisation" if outward else "onward"
                return Intent.DATA_EXFILTRATION, [
                    f"an earlier step read data and this step sends it {where}"]

        if Capability.DELETE in caps:
            if sensitive or context.arguments.scope in (Scope.RECURSIVE, Scope.UNBOUNDED):
                return Intent.DESTRUCTIVE_ACTION, ["deletes sensitive or wide-scoped targets"]
            evidence.append("deletes a single ordinary target")
            return Intent.FILE_MANAGEMENT, evidence

        if Capability.EXECUTE in caps:
            if Capability.DOWNLOAD in chain_caps:
                return Intent.CODE_EXECUTION, ["executes something that was just downloaded"]
            return Intent.CODE_EXECUTION, ["runs code or a command"]

        if Capability.EMAIL in caps:
            return Intent.COMMUNICATION, ["sends a message"]

        if caps & {Capability.WRITE, Capability.MODIFY}:
            if Capability.DATABASE in caps:
                return Intent.DATA_PROCESSING, ["writes to stored data"]
            if Capability.UPLOAD in caps or ResourceClass.EXTERNAL_ENDPOINT in resources:
                return Intent.DATA_TRANSFER, ["moves data to another system"]
            return Intent.FILE_MANAGEMENT, ["creates or modifies files"]

        if Capability.DOWNLOAD in caps and ResourceClass.BINARY in resources:
            return Intent.DATA_TRANSFER, ["fetches an executable artifact"]

        if Capability.DATABASE in caps:
            return Intent.DATA_PROCESSING, ["queries stored data"]

        if caps & {Capability.READ, Capability.NETWORK}:
            return Intent.INFORMATION_RETRIEVAL, ["reads public or local information"]

        return Intent.UNKNOWN, []

    @staticmethod
    def _prompt_intent(prompt: str) -> Intent | None:
        if not prompt:
            return None
        best: Intent | None = None
        for pattern, intent in PROMPT_SIGNALS:
            if re.search(pattern, prompt, re.I):
                if best is None or INTENT_RISK[intent][0] > INTENT_RISK[best][0]:
                    best = intent
        return best
