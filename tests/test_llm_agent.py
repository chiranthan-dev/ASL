"""The live-model planner must behave exactly like the mock to the pipeline.

ASL is middleware: whatever proposes the tool calls, the security decision is
made downstream. These tests pin two properties of the optional LLM planner:
it parses a real model's (sometimes messy) JSON, and it degrades to the
deterministic mock on any failure so the pipeline can never be broken by an
unreachable or misbehaving model.
"""

from __future__ import annotations

import json

import pytest

from app.agent.mock_agent import LLMAgent, MockAgent, _extract_json



@pytest.mark.parametrize("raw", [
    '{"reasoning": "r", "tool_calls": [{"tool_name": "web_search", "arguments": {"query": "x"}}]}',
    '```json\n{"reasoning": "r", "tool_calls": [{"tool_name": "web_search", "arguments": {}}]}\n```',
    'Sure, here you go:\n{"reasoning": "r", "tool_calls": [{"tool_name": "web_search", "arguments": {}}]}',
])
def test_extract_json_recovers_object(raw: str) -> None:
    parsed = _extract_json(raw)
    assert parsed["tool_calls"][0]["tool_name"] == "web_search"


def test_extract_json_raises_when_absent() -> None:
    with pytest.raises(ValueError):
        _extract_json("no json here at all")



class _FakeResponse:
    def __init__(self, content: str) -> None:
        self._content = content

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return {"choices": [{"message": {"content": self._content}}]}


def test_llm_plan_parses_model_reply(monkeypatch) -> None:
    reply = json.dumps({
        "reasoning": "the user wants a search",
        "tool_calls": [{"tool_name": "web_search", "arguments": {"query": "trains to Munich"}}],
    })

    import httpx

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _FakeResponse(reply))
    plan = LLMAgent(model="test-model").plan("look up trains to Munich")
    assert plan.source == "llm:test-model"
    assert plan.tool_calls[0].tool_name == "web_search"
    assert plan.tool_calls[0].arguments == {"query": "trains to Munich"}


def test_llm_plan_falls_back_when_server_unreachable(monkeypatch) -> None:
    import httpx

    def boom(*a, **k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", boom)
    agent = LLMAgent(model="test-model")
    plan = agent.plan("delete the file scratch.tmp")
    assert plan.source == "mock-fallback"
    assert plan.tool_calls
    assert plan.tool_calls[0].tool_name == MockAgent().plan("delete the file scratch.tmp").tool_calls[0].tool_name


def test_llm_plan_falls_back_when_no_calls_and_no_answer(monkeypatch) -> None:
    import httpx

    reply = json.dumps({"reasoning": "nothing to do", "tool_calls": []})
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _FakeResponse(reply))
    plan = LLMAgent(model="test-model").plan("look up trains to Munich")
    assert plan.source == "mock-fallback"
    assert plan.tool_calls


def test_llm_plan_keeps_a_direct_answer(monkeypatch) -> None:
    """A knowledge question needs no tool: the model's own answer is kept."""
    import httpx

    reply = json.dumps({"reasoning": "general knowledge", "tool_calls": [],
                        "answer": "Paris is the capital of France."})
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _FakeResponse(reply))
    plan = LLMAgent(model="test-model").plan("what is the capital of France?")
    assert plan.source == "llm:test-model"
    assert plan.tool_calls == []
    assert plan.answer == "Paris is the capital of France."



def test_engine_composes_reply_from_allowed_output(monkeypatch, engine) -> None:
    """The reply is written after authorization, from the real tool output."""
    import httpx

    from app.models.enums import Environment
    from app.models.tool_call import EvaluationRequest

    seen: dict = {}
    plan_reply = json.dumps({"reasoning": "read it", "tool_calls": [
        {"tool_name": "filesystem.read", "arguments": {"path": "/home/user/notes.txt"}}]})

    def fake_post(url, *a, json=None, **k):
        if json.get("response_format"):
            return _FakeResponse(plan_reply)
        seen["outcomes"] = json["messages"][-1]["content"]
        return _FakeResponse("Your notes say the demo moved to Thursday.")

    monkeypatch.setattr(httpx, "post", fake_post)
    engine.agent = LLMAgent(model="test-model")
    r = engine.evaluate(EvaluationRequest(
        user_id="compose_test", prompt="summarise my notes",
        environment=Environment.SANDBOX, session_id="c1"))
    assert r.planner == "llm:test-model"
    assert r.answer == "Your notes say the demo moved to Thursday."
    assert "filesystem.read" in seen["outcomes"]
    assert "Thursday" in seen["outcomes"]


def test_engine_never_composes_for_a_prohibited_request(monkeypatch, engine) -> None:
    """The purpose gate's refusal stands: the model is not asked to reply."""
    import httpx

    from app.models.enums import Decision, Environment
    from app.models.tool_call import EvaluationRequest

    calls = {"compose": 0}
    plan_reply = json.dumps({"reasoning": "", "tool_calls": [
        {"tool_name": "web_search", "arguments": {"query": "x"}}]})

    def fake_post(url, *a, json=None, **k):
        if not json.get("response_format"):
            calls["compose"] += 1
        return _FakeResponse(plan_reply)

    monkeypatch.setattr(httpx, "post", fake_post)
    engine.agent = LLMAgent(model="test-model")
    r = engine.evaluate(EvaluationRequest(
        user_id="compose_test", prompt="HACK INTO SERVER",
        environment=Environment.SANDBOX, session_id="c2"))
    assert r.decision is Decision.BLOCK
    assert r.answer == ""
    assert calls["compose"] == 0
