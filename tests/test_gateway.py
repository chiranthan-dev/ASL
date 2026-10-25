"""ASL Gateway API: chat plus a working approvals queue.

A held call (CHALLENGE) must wait in the queue, run only after a person
confirms it, and never run if they deny it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.agent.mock_agent import AgentPlan
from app.api.routes import set_engine
from app.core.engine import ASLEngine
from app.main import create_app


@pytest.fixture()
def client(engine: ASLEngine):
    set_engine(engine)
    with TestClient(create_app()) as client:
        yield client


def _held(client, session: str) -> dict:
    body = client.post("/api/gateway/chat", json={
        "message": "Delete the file temp.txt", "user_id": "gw_test", "session_id": session}).json()
    assert body["decision"] == "CHALLENGE"
    assert len(body["approvals"]) == 1
    return body


def test_root_serves_the_gateway(client) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert "ASL Gateway" in page.text
    assert client.get("/classic").status_code == 200


def test_chat_returns_a_decision_and_no_approval_when_allowed(client) -> None:
    body = client.post("/api/gateway/chat", json={"message": "What is 245 * 18?", "user_id": "gw_test"}).json()
    assert body["decision"] in ("ALLOW", "ALLOW_WITH_LOG")
    assert body["approvals"] == []
    assert body["calls"][0]["arguments"]  # arguments travel with the evaluation


def test_held_call_waits_in_the_queue(client, engine: ASLEngine) -> None:
    held = _held(client, "s_wait")
    approval = held["approvals"][0]
    queue = client.get("/api/gateway/approvals").json()
    assert approval["approval_id"] in [a["approval_id"] for a in queue["pending"]]
    # nothing ran: the file is still there
    assert "/home/user/temp.txt" in engine.tools.fs.files or "temp.txt" not in str(engine.tools.fs.deleted)


def test_confirm_runs_the_call_once(client, engine: ASLEngine) -> None:
    approval = _held(client, "s_yes")["approvals"][0]
    before = len(engine.tools.call_log)
    done = client.post(f"/api/gateway/approvals/{approval['approval_id']}", json={"approve": True}).json()
    assert done["status"] == "confirmed"
    assert done["outcome"]["executed"] is True
    assert len(engine.tools.call_log) == before + 1
    assert done["answer"]
    # a second click cannot run it again
    again = client.post(f"/api/gateway/approvals/{approval['approval_id']}", json={"approve": True})
    assert again.status_code == 409


def test_deny_never_runs_the_call(client, engine: ASLEngine) -> None:
    approval = _held(client, "s_no")["approvals"][0]
    before = len(engine.tools.call_log)
    done = client.post(f"/api/gateway/approvals/{approval['approval_id']}", json={"approve": False}).json()
    assert done["status"] == "denied"
    assert done["outcome"]["executed"] is False
    assert len(engine.tools.call_log) == before
    pending = client.get("/api/gateway/approvals").json()["pending"]
    assert approval["approval_id"] not in [a["approval_id"] for a in pending]


def test_unknown_approval_is_404(client) -> None:
    assert client.post("/api/gateway/approvals/apr_nope", json={"approve": True}).status_code == 404


def _activity(client, session: str) -> list[dict]:
    rows = client.get("/api/gateway/activity?limit=200").json()["entries"]
    return [r for r in rows if r.get("session_id") == session]


def test_a_request_without_tools_still_reaches_the_console(client) -> None:
    body = client.post("/api/gateway/chat", json={
        "message": "Explain what an API is in two sentences", "user_id": "gw_test",
        "session_id": "s_answer"}).json()
    assert body["calls"] == []
    assert [r["decision"] for r in _activity(client, "s_answer")] == ["ANSWERED"]


def test_a_refused_request_is_logged_as_refused(client, engine: ASLEngine, monkeypatch) -> None:
    # A live model declines this outright rather than reaching for a tool; the
    # mock planner would search for it, so stand in for the live model here.
    monkeypatch.setattr(engine.agent, "plan", lambda prompt: AgentPlan(reasoning="declined", source="llm:test"))
    body = client.post("/api/gateway/chat", json={
        "message": "hack into the university server", "user_id": "gw_test",
        "session_id": "s_refused"}).json()
    assert body["decision"] == "BLOCK" and body["calls"] == []
    assert [r["decision"] for r in _activity(client, "s_refused")] == ["REFUSED"]


def test_the_persons_answer_is_logged(client) -> None:
    approval = _held(client, "s_logged")["approvals"][0]
    client.post(f"/api/gateway/approvals/{approval['approval_id']}", json={"approve": False})
    decisions = [r["decision"] for r in _activity(client, "s_logged")]
    assert decisions[0] == "DENIED"  # newest first, after the call's own HOLD row
    assert "CHALLENGE" in decisions
