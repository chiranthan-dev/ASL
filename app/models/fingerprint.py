"""Behavior-graph and behavioral-fingerprint models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Capability, EdgeType, NodeKind, ResourceClass, Scope
from app.models.tool_call import utcnow


class BehaviorNode(BaseModel):
    """One node of the session behavior graph."""

    model_config = ConfigDict(extra="forbid")

    node_id: str
    kind: NodeKind
    label: str
    tool: str | None = None
    capability: Capability | None = None
    resource_class: ResourceClass | None = None
    scope: Scope = Scope.NONE
    identifier: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    risk: float = 0.0
    confidence: float = 0.5

    def semantic_label(self) -> str:
        """Tool-name-free label used for canonicalisation."""
        if self.kind is NodeKind.CAPABILITY:
            return f"CAP:{self.capability}"
        if self.kind is NodeKind.RESOURCE:
            return f"RES:{self.resource_class}:{self.scope}"
        return f"ACT:{self.label}"


class BehaviorEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    edge_type: EdgeType = EdgeType.SEQUENCE
    weight: float = 1.0


class BehaviorGraphSnapshot(BaseModel):
    """Serialisable view of a session behavior graph (for API/audit)."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    user_id: str | None = None
    nodes: list[BehaviorNode] = Field(default_factory=list)
    edges: list[BehaviorEdge] = Field(default_factory=list)
    capability_sequence: list[list[Capability]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)


class BehavioralFingerprint(BaseModel):
    """Deterministic canonical signature of a behavior graph (spec section 6)."""

    model_config = ConfigDict(extra="forbid")

    fingerprint_id: str
    canonical_representation: str
    graph_hash: str
    capabilities: list[Capability] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    transitions: list[str] = Field(default_factory=list)
    resource_classes: list[ResourceClass] = Field(default_factory=list)
    max_scope: Scope = Scope.NONE
    created_at: datetime = Field(default_factory=utcnow)

    occurrence_count: int = 0
    historical_risk: float = 0.0
    successful_executions: int = 0
    blocked_executions: int = 0
    confidence: float = 0.0
    last_seen: datetime | None = None

    def to_row(self) -> dict[str, Any]:
        """Flatten for SQLite persistence (phase 6)."""
        return {
            "fingerprint_id": self.fingerprint_id,
            "canonical_representation": self.canonical_representation,
            "graph_hash": self.graph_hash,
            "capabilities": ",".join(c.value for c in self.capabilities),
            "steps": "|".join(self.steps),
            "transitions": "|".join(self.transitions),
            "max_scope": self.max_scope.value,
            "created_at": self.created_at.isoformat(),
            "occurrence_count": self.occurrence_count,
            "historical_risk": self.historical_risk,
            "successful_executions": self.successful_executions,
            "blocked_executions": self.blocked_executions,
            "confidence": self.confidence,
        }


class FingerprintMatch(BaseModel):
    """Result of looking a fingerprint up in the trust store (spec section 7)."""

    model_config = ConfigDict(extra="forbid")

    query_fingerprint_id: str
    matched_fingerprint_id: str | None = None
    similarity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    historical_risk: float = 100.0
    previous_outcome: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    novelty_score: float = Field(default=1.0, ge=0.0, le=1.0)
    occurrence_count: int = 0
    explanation: str = ""
