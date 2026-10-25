"""Risk-signal and fused-risk models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Capability


class RiskSignal(BaseModel):
    """One named contribution to the fused risk score.

    `value` is the analyzer 0-100 risk claim, `weight` is how much the fusion
    strategy let it matter, `confidence` is how sure the analyzer is.  Keeping
    the three separate is what makes the final explanation auditable.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    value: float = Field(ge=0.0, le=100.0)
    weight: float = Field(default=1.0, ge=0.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    detail: str = ""

    @property
    def contribution(self) -> float:
        return self.value * self.weight


class RiskAssessment(BaseModel):
    """Output of the Adaptive Risk Engine (spec section 15)."""

    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    strategy: str = "WeightedRiskFusion"
    signals: list[RiskSignal] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=list)
    invariants: list[str] = Field(default_factory=list)
    disagreement: float = Field(default=0.0, ge=0.0, le=1.0)
    behavioural_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    call_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    explanation: str = ""

    def signal_map(self) -> dict[str, float]:
        return {s.name: round(s.value, 2) for s in self.signals}
