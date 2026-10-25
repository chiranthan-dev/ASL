"""FastAPI surface (spec section: API).

    POST /evaluate      intercept a prompt (or explicit tool calls) and decide
    GET  /health        liveness plus a snapshot of what has been learned
    GET  /fingerprints  the behavioral fingerprint store
    GET  /audit         the decision trail

Plus endpoints the inspector UI needs: `/api/scenarios`, `/api/graph/{id}`,
`/api/config` and `/api/reset`.
"""

from __future__ import annotations

from typing import Any

import threading

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import get_config
from app.core.engine import ASLEngine
from app.models.decision import EvaluationResponse
from app.models.enums import Environment
from app.models.tool_call import EvaluationRequest, ToolInvocation, new_id
from app.trust.fingerprint_store import summarize
from demos.scenarios import SCENARIOS

router = APIRouter()
_engine: ASLEngine | None = None


def get_engine() -> ASLEngine:
    global _engine
    if _engine is None:
        _engine = ASLEngine()
    return _engine


def set_engine(engine: ASLEngine) -> None:
    """Injection point for tests and for `python -m app.main`."""
    global _engine
    _engine = engine


class PromptRequest(BaseModel):
    """Inspector-friendly body: a prompt is enough, everything else optional."""

    model_config = ConfigDict(extra="forbid")

    user_id: str = "demo_user"
    prompt: str = ""
    tool_calls: list[ToolInvocation] = Field(default_factory=list)
    environment: Environment = Environment.SANDBOX
    session_id: str | None = None
    device_id: str | None = None
    policy_version: str | None = None
    conversation: list[str] = Field(default_factory=list)

    def to_evaluation_request(self) -> EvaluationRequest:
        return EvaluationRequest(
            user_id=self.user_id,
            prompt=self.prompt,
            tool_calls=self.tool_calls,
            environment=self.environment,
            session_id=self.session_id or new_id("sess"),
            device_id=self.device_id,
            policy_version=self.policy_version,
            conversation=self.conversation,
        )


@router.post("/evaluate", response_model=EvaluationResponse)
def evaluate(request: PromptRequest) -> EvaluationResponse:
    if not request.prompt and not request.tool_calls:
        raise HTTPException(status_code=422, detail="supply a prompt or at least one tool call")
    return get_engine().evaluate(request.to_evaluation_request())


@router.get("/health")
def health() -> dict[str, Any]:
    engine = get_engine()
    fingerprints = engine.store.all(500)
    return {
        "status": "ok",
        "policy_version": engine.config.policy_version,
        "fusion_strategy": engine.fusion.name,
        "agent": getattr(engine.agent, "name", "unknown"),
        "mock_llm": engine.config.mock_llm,
        "planner_model": (None if engine.config.mock_llm else engine.config.llm_model),
        "fingerprints": {**summarize(fingerprints), "count": engine.store.count()},
        "audit": engine.audit.statistics(),
    }


@router.get("/fingerprints")
def fingerprints(limit: int = 100) -> dict[str, Any]:
    engine = get_engine()
    items = engine.fingerprints(limit)
    return {"count": len(items), "fingerprints": items}


@router.get("/fingerprints/{fingerprint_id}")
def fingerprint_detail(fingerprint_id: str) -> dict[str, Any]:
    engine = get_engine()
    stored = engine.store.get(fingerprint_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="unknown fingerprint")
    return {
        "fingerprint": {
            "fingerprint_id": stored.fingerprint_id,
            "canonical_representation": stored.canonical_representation,
            "graph_hash": stored.graph_hash,
            "capabilities": [c.value for c in stored.capabilities],
            "steps": stored.steps,
            "transitions": stored.transitions,
            "occurrence_count": stored.occurrence_count,
            "historical_risk": stored.historical_risk,
            "confidence": stored.confidence,
            "successful_executions": stored.successful_executions,
            "blocked_executions": stored.blocked_executions,
        },
        "observations": engine.store.observations(fingerprint_id),
    }


@router.get("/api/user/{user_id}")
def user_trust(user_id: str) -> dict[str, Any]:
    """The caller's trust record.

    Surfaced so the UI can explain a refused fast path: the identity check needs
    0.40 and trust is lost far faster than it is earned, so "why did that not go
    fast" is usually answered here.
    """
    engine = get_engine()
    state = engine.trust.state(user_id)
    return {
        "user_id": state.user_id,
        "trust_score": state.trust_score,
        "successful_actions": state.successful_actions,
        "blocked_actions": state.blocked_actions,
        "anomalies": state.anomalies,
        "known": state.known,
        "fast_path_identity_floor": 0.4,
    }


@router.get("/api/library")
def library(q: str = "", population: str = "", limit: int = 60,
            offset: int = 0, eligible: bool = False) -> dict[str, Any]:
    """Searchable view of the seeded behaviour library.

    Every row here was produced by a real evaluation - see `seed_library.py`.
    The stored prompt is a display label only; nothing in the authorization
    path reads it.
    """
    engine = get_engine()
    limit = max(1, min(limit, 200))
    return engine.store.library(query=q.strip(), population=population,
                                limit=limit, offset=max(0, offset),
                                eligible=eligible)


_seed_state: dict[str, Any] = {"running": False, "summary": None, "error": None}


@router.post("/api/library/seed")
def start_seed(target: int = 2500) -> dict[str, Any]:
    if _seed_state["running"]:
        return {"running": True, "already": True}

    def run() -> None:
        try:
            import seed_library
            _seed_state["summary"] = seed_library.seed(
                target=max(200, min(target, 12000)), reset=False, quiet=True)
            _seed_state["error"] = None
        except Exception as exc:
            _seed_state["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            _seed_state["running"] = False

    _seed_state["running"] = True
    _seed_state["summary"] = None
    threading.Thread(target=run, daemon=True, name="asl-seed").start()
    return {"running": True, "started": True}


@router.get("/api/library/seed")
def seed_status() -> dict[str, Any]:
    return dict(_seed_state)


@router.get("/api/library/stats")
def library_stats() -> dict[str, Any]:
    engine = get_engine()
    stats = engine.store.library_stats()
    stats["store_total"] = engine.store.count()
    return stats


@router.get("/audit")
def audit(limit: int = 50) -> dict[str, Any]:
    engine = get_engine()
    return {"entries": engine.audit.entries(limit), "statistics": engine.audit.statistics()}


@router.get("/api/scenarios")
def scenarios() -> dict[str, Any]:
    return {
        "scenarios": [
            {
                "id": s.scenario_id,
                "prompt": s.prompt,
                "expectation": s.expectation,
                "label": s.label,
                "tags": s.tags,
            }
            for s in SCENARIOS
        ]
    }


@router.get("/api/graph/{session_id}")
def session_graph(session_id: str) -> dict[str, Any]:
    return get_engine().session_graph(session_id)


@router.get("/api/config")
def config() -> dict[str, Any]:
    cfg = get_config()
    return {
        "thresholds": {
            "fingerprint_similarity_threshold": cfg.fingerprint_similarity_threshold,
            "historical_risk_threshold": cfg.historical_risk_threshold,
            "fingerprint_confidence_threshold": cfg.fingerprint_confidence_threshold,
            "fast_path_min_occurrences": cfg.fast_path_min_occurrences,
            "risk_allow_threshold": cfg.risk_allow_threshold,
            "risk_log_threshold": cfg.risk_log_threshold,
            "risk_challenge_threshold": cfg.risk_challenge_threshold,
            "risk_sandbox_threshold": cfg.risk_sandbox_threshold,
        },
        "weights": cfg.weights.model_dump(),
        "invariant_floors": cfg.invariant_floors,
        "policy_version": cfg.policy_version,
        "fusion_strategy": cfg.fusion_strategy,
    }


@router.post("/api/reset")
def reset() -> dict[str, Any]:
    get_engine().reset()
    return {"status": "reset", "fingerprints": 0}
