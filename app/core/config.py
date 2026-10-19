"""Central configuration.

Every threshold and weight in ASL lives here so that experiments only ever
change configuration, never code.  Values may be overridden by a JSON file
(path in ``ASL_CONFIG_FILE``) or by ``ASL_*`` environment variables.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_ROOT.parent


class FusionWeights(BaseModel):
    """Baseline weights for `WeightedRiskFusion`.

    Research note: this weighted model is an intentionally simple *baseline*.
    The novelty claim of ASL rests on behavioral fingerprinting and adaptive
    authorization, not on these numbers -- alternative `RiskFusionStrategy`
    implementations must be swappable without touching analyzers.
    """

    model_config = ConfigDict(extra="forbid")

    tool: float = 1.0
    argument: float = 1.6
    intent: float = 1.4
    capability: float = 1.2
    fingerprint: float = 1.3
    execution_chain: float = 1.5
    context: float = 0.8
    user_trust: float = 0.7
    environment: float = 0.9
    anomaly: float = 1.1
    llm_confidence: float = 0.6
    #: heaviest weight in the table: a request for a prohibited purpose is the
    #: most direct evidence available about what is actually being asked for.
    request_policy: float = 1.8


class ASLConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # ---- fast path (spec section 8) ----
    fingerprint_similarity_threshold: float = 0.98
    historical_risk_threshold: float = 10.0
    fingerprint_confidence_threshold: float = 0.95
    fast_path_min_occurrences: int = 2
    fast_path_max_environment: str = "production"  # fast path still allowed, checks still run
    fast_path_enabled: bool = True

    #: Per-class historical-risk ceilings for the fast path.
    #:
    #: A single global ceiling forces a bad trade: set it at the spec's 10 and
    #: nothing that changes state can ever become cheap; raise it globally and
    #: the gate loosens for destructive behaviour too. Classifying by *trust
    #: boundary* separates the two concerns — the question is not "is this
    #: reversible" but "does this leave the organisation or destroy something".
    #:
    #:   READ_ONLY              observes; changes nothing            -> 10
    #:   INTERNAL_EFFECT        changes state, stays inside          -> 25
    #:   OUTWARD_OR_DESTRUCTIVE crosses the boundary or destroys     -> never
    fast_path_risk_ceilings: dict[str, float] = Field(
        default_factory=lambda: {"READ_ONLY": 10.0, "INTERNAL_EFFECT": 25.0}
    )

    # ---- decision thresholds (spec section 16) ----
    risk_allow_threshold: float = 20.0
    risk_log_threshold: float = 50.0
    risk_challenge_threshold: float = 70.0
    risk_sandbox_threshold: float = 90.0

    # ---- human verification triggers ----
    low_confidence_threshold: float = 0.55
    analyzer_disagreement_threshold: float = 0.45
    high_impact_capabilities: list[str] = Field(
        default_factory=lambda: ["DELETE", "PRIVILEGE_CHANGE", "EXECUTE"]
    )

    # ---- fingerprint similarity mix (phase 5/7) ----
    similarity_weight_capabilities: float = 0.20
    similarity_weight_steps: float = 0.50
    similarity_weight_transitions: float = 0.20
    similarity_weight_scope: float = 0.10

    # ---- trust ----
    user_trust_initial: float = 0.5
    user_trust_max_risk_reduction: float = 8.0

    # ---- fusion ----
    fusion_strategy: str = "WeightedRiskFusion"
    weights: FusionWeights = Field(default_factory=FusionWeights)
    #: risk floors that no amount of trust or averaging may lower
    invariant_floors: dict[str, float] = Field(
        default_factory=lambda: {
            "DESTRUCTIVE_PRODUCTION": 92.0,
            "CREDENTIAL_ACCESS": 90.0,
            "PRIVILEGE_ESCALATION": 90.0,
            "REMOTE_CODE_EXECUTION": 88.0,
            "EXFILTRATION_CHAIN": 90.0,
            "PROHIBITED_PURPOSE": 95.0,
        }
    )

    # ---- storage ----
    database_path: str = str(PROJECT_ROOT / "asl_state.db")
    #: FULL is maximally durable but fsyncs every commit; NORMAL under WAL keeps
    #: the database crash-safe and only risks the most recent commits on power
    #: loss. Set to FULL if the audit trail must survive that.
    sqlite_synchronous: str = "NORMAL"
    tool_registry_path: str = str(PACKAGE_ROOT / "tools" / "tool_registry.json")
    policy_version: str = "2026.08.1"

    # ---- misc ----
    max_arguments_bytes: int = 200_000
    mock_llm: bool = True

    # ---- live model (optional) ----
    # When mock_llm is False, the planner calls an OpenAI-compatible chat
    # endpoint. Ollama exposes one at http://127.0.0.1:11434/v1 with no key, so
    # ASL can drive a real local model with no cloud dependency. The planner
    # always degrades to the deterministic MockAgent on any error, so turning
    # this on can never break the pipeline.
    llm_base_url: str = "http://127.0.0.1:11434/v1"
    llm_model: str = "qwen2.5:7b"
    llm_api_key: str = ""
    llm_timeout_s: float = 60.0

    def with_overrides(self, **kwargs: Any) -> "ASLConfig":
        return self.model_copy(update=kwargs)


def _env_overrides() -> dict[str, Any]:
    """Read ``ASL_<FIELD>`` environment variables, coercing to the field type."""
    out: dict[str, Any] = {}
    for name, field in ASLConfig.model_fields.items():
        raw = os.environ.get(f"ASL_{name.upper()}")
        if raw is None:
            continue
        annotation = field.annotation
        try:
            if annotation is bool:
                out[name] = raw.strip().lower() in {"1", "true", "yes", "on"}
            elif annotation is float:
                out[name] = float(raw)
            elif annotation is int:
                out[name] = int(raw)
            else:
                out[name] = raw
        except ValueError:
            continue
    return out


def load_config(path: str | Path | None = None) -> ASLConfig:
    """Build a config from defaults + optional JSON file + environment."""
    data: dict[str, Any] = {}
    path = path or os.environ.get("ASL_CONFIG_FILE")
    if path:
        p = Path(path)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
    data.update(_env_overrides())
    return ASLConfig(**data)


@lru_cache(maxsize=1)
def get_config() -> ASLConfig:
    return load_config()


def reset_config_cache() -> None:
    """Test hook: force the next `get_config()` to re-read env/file."""
    get_config.cache_clear()
