"""Shared evaluation context.

Every analyzer from phase 9 onwards needs the same bundle of state: the call
being judged, what the earlier stages concluded about it, who is asking, where
they are asking from, and what has already happened in this session.  Passing
one object keeps analyzer signatures uniform, which is what allows the risk
engine to iterate over analyzers generically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import Capability, Environment
from app.models.fingerprint import BehavioralFingerprint, FingerprintMatch
from app.models.tool_call import (
    ArgumentAnalysis,
    CapabilityAssessment,
    ToolAnalysis,
    ToolInvocation,
)


@dataclass
class SessionHistory:
    """What this session has already done, as seen by the analyzers."""

    call_count: int = 0
    capability_sequence: list[list[Capability]] = field(default_factory=list)
    risk_scores: list[float] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    #: every resource class the session has touched so far. A chain analyzer that
    #: only sees capabilities cannot tell "read notes, then mail them" from
    #: "read a private key, then mail it" -- both are READ followed by EMAIL.
    resource_classes: list[str] = field(default_factory=list)
    started_at: float = 0.0

    @property
    def max_risk(self) -> float:
        return max(self.risk_scores, default=0.0)

    @property
    def escalating(self) -> bool:
        """Is risk trending upward across the session?"""
        if len(self.risk_scores) < 2:
            return False
        first_half = self.risk_scores[: len(self.risk_scores) // 2] or [0.0]
        second_half = self.risk_scores[len(self.risk_scores) // 2 :]
        return sum(second_half) / len(second_half) > sum(first_half) / len(first_half) + 10


@dataclass
class UserState:
    """Trust memory for the caller (phase 10 of the spec)."""

    user_id: str
    trust_score: float = 0.5
    successful_actions: int = 0
    blocked_actions: int = 0
    anomalies: int = 0
    known: bool = False


@dataclass
class AnalysisContext:
    """Everything the analyzers, risk engine and decision engine may read."""

    invocation: ToolInvocation
    tool: ToolAnalysis
    arguments: ArgumentAnalysis
    capabilities: CapabilityAssessment
    fingerprint: BehavioralFingerprint
    chain_fingerprint: BehavioralFingerprint
    match: FingerprintMatch
    user: UserState
    history: SessionHistory
    prompt: str = ""
    conversation: list[str] = field(default_factory=list)
    environment: Environment = Environment.SANDBOX
    session_id: str = ""
    device_id: str | None = None
    policy_version: str | None = None
    transitions: list[str] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def capability_set(self) -> set[Capability]:
        return set(self.capabilities.capabilities)

    @property
    def evidenced_set(self) -> set[Capability]:
        """Capabilities the arguments (or a registered profile) actually show,
        without the guesses made from an unregistered tool's name."""
        return set(self.capabilities.evidenced or self.capabilities.capabilities)

    @property
    def resource_classes(self) -> set[str]:
        return {r.resource_class.value for r in self.arguments.resources}

    @property
    def sensitive_resource(self) -> bool:
        return any(r.sensitive for r in self.arguments.resources)

    def finding_codes(self) -> set[str]:
        return {f.code for f in self.arguments.findings}

    def user_id_trusted(self, floor: float = 0.4) -> bool:
        """Is the caller established enough to be considered for a fast path?

        Deliberately weak: this is an identity sanity check, not an
        authorization. Everything else in the fast-path gate still applies.
        """
        return self.user.known and self.user.trust_score >= floor
