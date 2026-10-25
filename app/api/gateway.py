"""ASL Gateway API: a chat front end with a working approvals queue.

`/evaluate` decides; this module adds what a product needs around that decision.
A call ASL holds for confirmation (CHALLENGE) is parked in an approvals queue
instead of being dropped. Nothing runs until a person confirms it; a denial is
final. Either way the agent is told what happened and writes its reply from
that, so the conversation never pretends a held action ran.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.enums import Decision, Environment
from app.models.tool_call import EvaluationRequest, ToolInvocation, new_id

router = APIRouter(prefix="/api/gateway", tags=["gateway"])

_lock = threading.Lock()
_approvals: dict[str, dict[str, Any]] = {}
_activity: deque[dict[str, Any]] = deque(maxlen=200)


def _note(user_id: str, session_id: str, decision: str, subject: str) -> None:
    _activity.appendleft({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id, "session_id": session_id,
        "decision": decision, "tool_name": subject, "path": "GATEWAY",
    })

_DECISION_TEXT = {
    Decision.CHALLENGE: "Not dangerous enough to refuse, not routine enough to pass unattended.",
}
_INVARIANT_TEXT = {
    "DESTRUCTIVE_PRODUCTION": "This would destroy data in production.",
    "PRIVILEGE_ESCALATION": "This escalates privilege.",
}


def _plain_reason(call: Any) -> str:
    """One readable sentence for the approvals queue (mirrors the page's wording)."""
    invariants = list(getattr(call.risk_assessment, "invariants", None) or [])
    if invariants:
        return _INVARIANT_TEXT.get(invariants[0], invariants[0].replace("_", " ").lower() + ".")
    if call.findings:
        text = call.findings[0].split(": ", 1)[-1]
        return text[:1].upper() + text[1:] + ("" if text.endswith((".", "!", "?")) else ".")
    return _DECISION_TEXT.get(call.decision, "Held by ASL for a person to confirm.")


def _engine():
    from app.api.routes import get_engine

    return get_engine()


class ChatRequest(BaseModel):
    message: str
    user_id: str = "demo_user"
    session_id: str = Field(default_factory=lambda: new_id("sess"))
    environment: Environment = Environment.SANDBOX


class Resolution(BaseModel):
    approve: bool


@router.post("/chat")
def chat(body: ChatRequest) -> dict[str, Any]:
    if not body.message.strip():
        raise HTTPException(status_code=422, detail="empty message")
    engine = _engine()
    result = engine.evaluate(EvaluationRequest(
        user_id=body.user_id, prompt=body.message, environment=body.environment,
        session_id=body.session_id))
    created = []
    with _lock:
        if not result.calls:
            refused = result.decision is Decision.BLOCK
            _note(body.user_id, body.session_id, "REFUSED" if refused else "ANSWERED",
                  "request" if refused else "no tool needed")
        for call in result.calls:
            if call.decision is not Decision.CHALLENGE:
                continue
            item = {
                "approval_id": new_id("apr"),
                "call_id": call.call_id,
                "tool_name": call.tool_name,
                "arguments": call.arguments,
                "risk_score": round(call.risk_score),
                "reason": _plain_reason(call),
                "prompt": body.message,
                "user_id": body.user_id,
                "session_id": body.session_id,
                "created_at": time.time(),
                "status": "pending",
            }
            _approvals[item["approval_id"]] = item
            created.append(item)
    payload = result.model_dump(mode="json")
    payload["approvals"] = created
    return payload


@router.get("/approvals")
def approvals() -> dict[str, Any]:
    with _lock:
        items = sorted(_approvals.values(), key=lambda a: a["created_at"], reverse=True)
    return {"pending": [a for a in items if a["status"] == "pending"],
            "resolved": [a for a in items if a["status"] != "pending"][:20]}


@router.get("/activity")
def activity(limit: int = Query(14, ge=1, le=200)) -> dict[str, Any]:
    """The console log: per-call audit rows plus the gateway's own decisions,
    newest first."""
    rows = list(_engine().audit.entries(limit))
    with _lock:
        rows += list(_activity)[:limit]
    rows.sort(key=lambda r: str(r.get("timestamp", "")), reverse=True)
    return {"entries": rows[:limit]}


@router.post("/approvals/{approval_id}")
def resolve(approval_id: str, body: Resolution) -> dict[str, Any]:
    with _lock:
        item = _approvals.get(approval_id)
        if item is None:
            raise HTTPException(status_code=404, detail="unknown approval")
        if item["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"already {item['status']}")
        item["status"] = "confirmed" if body.approve else "denied"
        item["resolved_at"] = time.time()
        _note(item["user_id"], item["session_id"],
              "CONFIRMED" if body.approve else "DENIED", item["tool_name"])

    engine = _engine()
    if body.approve:
        result = engine.tools.execute(ToolInvocation(
            tool_name=item["tool_name"], arguments=item["arguments"]))
        outcome = {"tool": item["tool_name"], "verdict": "CONFIRMED by the user",
                   "executed": bool(result.ok),
                   "output": result.output if result.ok else result.error}
    else:
        outcome = {"tool": item["tool_name"], "verdict": "DENIED by the user",
                   "executed": False, "why_not_run": "the user chose not to allow it"}
    item["outcome"] = outcome

    compose = getattr(engine.agent, "compose", None)
    answer = compose(item["prompt"], [outcome]) if compose else ""
    if not answer:
        answer = (f"Done: {item['tool_name']} ran after you confirmed it."
                  if body.approve else f"Understood. {item['tool_name']} was not run.")
    item["answer"] = answer
    return item
