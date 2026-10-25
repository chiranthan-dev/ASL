"""Request-side models: what the agent proposes to do."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    Capability,
    Environment,
    ResourceClass,
    Scope,
    Severity,
    ToolCategory,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class ToolInvocation(BaseModel):
    """A single proposed tool call, intercepted before execution."""

    model_config = ConfigDict(extra="forbid")

    call_id: str = Field(default_factory=lambda: new_id("call"))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)

    def argument_digest(self) -> str:
        """Stable hash of arguments, for audit correlation (never for trust)."""
        blob = json.dumps(self.arguments, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


class EvaluationRequest(BaseModel):
    """Payload of `POST /evaluate`."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    prompt: str = ""
    tool_calls: list[ToolInvocation] = Field(default_factory=list)
    environment: Environment = Environment.SANDBOX
    session_id: str = Field(default_factory=lambda: new_id("sess"))
    device_id: str | None = None
    policy_version: str | None = None
    conversation: list[str] = Field(default_factory=list)


class ToolProfile(BaseModel):
    """Static, configurable metadata about a tool (spec section 1)."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    category: ToolCategory = ToolCategory.UNKNOWN
    sensitivity: int = Field(default=50, ge=0, le=100)
    capabilities: list[Capability] = Field(default_factory=list)
    analyzer: str = "generic"
    payload_keys: list[str] = Field(default_factory=list)
    reversible: bool = True
    requires_auth: bool = False
    description: str = ""

    @property
    def capability_set(self) -> set[Capability]:
        return set(self.capabilities)


class ToolAnalysis(BaseModel):
    """Output of the Tool Analyzer."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    category: ToolCategory
    sensitivity: int = Field(ge=0, le=100)
    capabilities: list[Capability]
    risk: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    known_tool: bool = True
    reversible: bool = True
    explanation: str = ""


class Finding(BaseModel):
    """One concrete observation made by an analyzer.

    Findings are the atomic unit of explainability: every point of risk that a
    decision carries must be traceable to at least one finding.
    """

    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Severity
    message: str
    capabilities: list[Capability] = Field(default_factory=list)
    evidence: str | None = None
    analyzer: str = "argument"


class ResourceDescriptor(BaseModel):
    """A normalized description of *what* an action touches.

    Deliberately tool-name-free: this is what lets the fingerprint generator
    recognise `filesystem.delete("/prod/db/")` and
    `shell.execute("rm -rf /prod/db")` as the same behaviour.
    """

    model_config = ConfigDict(extra="forbid")

    resource_class: ResourceClass
    scope: Scope = Scope.SINGLE
    identifier: str | None = None
    sensitive: bool = False

    def token(self) -> str:
        return f"{self.resource_class.value}:{self.scope.value}"


class ArgumentAnalysis(BaseModel):
    """Output of the Argument Analyzer."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    analyzer: str
    capabilities: list[Capability] = Field(default_factory=list)
    resources: list[ResourceDescriptor] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk: float = Field(default=0.0, ge=0, le=100)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    scope: Scope = Scope.SINGLE
    parse_ok: bool = True
    explanation: str = ""

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        order = list(Severity)
        return max((f.severity for f in self.findings), key=order.index)


class CapabilityAssessment(BaseModel):
    """Output of the Semantic Capability Extractor."""

    model_config = ConfigDict(extra="forbid")

    capabilities: list[Capability] = Field(default_factory=list)
    from_tool: list[Capability] = Field(default_factory=list)
    from_arguments: list[Capability] = Field(default_factory=list)
    escalations: list[Capability] = Field(default_factory=list)
    evidenced: list[Capability] = Field(default_factory=list)
    weight: float = Field(default=0.0, ge=0, le=100)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    explanation: str = ""

    @property
    def capability_set(self) -> set[Capability]:
        return set(self.capabilities)
