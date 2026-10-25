"""Decision, response and audit models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Capability, Decision, DecisionPath, Environment, Intent
from app.models.risk import RiskAssessment
from app.models.tool_call import new_id, utcnow


class DecisionResult(BaseModel):
    """Output of the Decision Engine (spec section 16)."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    path: DecisionPath = DecisionPath.FULL_ANALYSIS
    human_verification_required: bool = False
    human_verification_reasons: list[str] = Field(default_factory=list)
    explanation: str = ""


class CallEvaluation(BaseModel):
    """Everything ASL concluded about one intercepted tool call."""

    model_config = ConfigDict(extra="forbid")

    call_id: str
    tool_name: str
    #: what the call asked for; kept so a held call can run after a human confirms
    arguments: dict[str, Any] = Field(default_factory=dict)
    decision: Decision
    risk_score: float
    confidence: float
    fast_path: bool = False
    fingerprint: str | None = None
    #: the *sequence* fingerprint for the session so far. This, not `fingerprint`,
    #: is what the store keys authorization memory on -- a single call collapses to
    #: one of a few dozen capability/resource shapes, while the sequence is what
    #: actually distinguishes behaviours.
    chain_fingerprint: str | None = None
    fingerprint_novelty: float | None = None
    capabilities: list[Capability] = Field(default_factory=list)
    intent: Intent = Intent.UNKNOWN
    signals: dict[str, float] = Field(default_factory=dict)
    findings: list[str] = Field(default_factory=list)
    explanation: str = ""
    latency_ms: float = 0.0
    risk_assessment: RiskAssessment | None = None


class TraceEvent(BaseModel):
    """One observable step of the pipeline, for the inspector UI.

    The trace is not debug output: it is the explainability surface.  Every
    stage records what it received, what it concluded and why, so a reviewer
    can follow a decision end to end without reading the code.
    """

    model_config = ConfigDict(extra="forbid")

    index: int
    stage: str                       # machine id, e.g. "argument_analyzer"
    title: str                       # human title, e.g. "2. Argument Analyzer"
    status: str = "ok"               # ok | skipped | warning | critical
    summary: str = ""                # one line the UI shows while animating
    detail: dict[str, Any] = Field(default_factory=dict)
    highlights: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    call_id: str | None = None


class EvaluationResponse(BaseModel):
    """Payload of POST /evaluate: session roll-up plus per-call detail."""

    model_config = ConfigDict(extra="forbid")

    decision: Decision
    risk_score: float
    confidence: float
    fast_path: bool
    fingerprint: str | None = None
    signals: dict[str, float] = Field(default_factory=dict)
    explanation: str = ""
    session_id: str = ""
    user_id: str = ""
    prompt: str = ""
    environment: Environment = Environment.SANDBOX
    agent_reasoning: str = ""
    #: the agent's reply to the user, written by a live model after authorization;
    #: empty when the planner is the mock (the UI then uses its template reply)
    answer: str = ""
    #: who planned: "mock", "mock-fallback", "caller" or "llm:<model>"
    planner: str = ""
    calls: list[CallEvaluation] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    latency_ms: float = 0.0


class AuditRecord(BaseModel):
    """One immutable audit row (spec section 17)."""

    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(default_factory=lambda: new_id("audit"))
    timestamp: datetime = Field(default_factory=utcnow)
    user_id: str
    session_id: str
    environment: Environment = Environment.SANDBOX
    tool_name: str
    capabilities: list[Capability] = Field(default_factory=list)
    fingerprint_id: str | None = None
    risk_score: float = 0.0
    confidence: float = 0.0
    decision: Decision = Decision.BLOCK
    path: DecisionPath = DecisionPath.FULL_ANALYSIS
    signals: dict[str, Any] = Field(default_factory=dict)
    explanation: str = ""
    outcome: str | None = None
    latency_ms: float = 0.0
