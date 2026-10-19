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


# ------------------------------------------------------------ JSON recovery --

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


# --------------------------------------------------------- planner contract --

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
    # The pipeline still gets a plan — the deterministic mock produced it.
    assert plan.source == "mock-fallback"
    assert plan.tool_calls  # a plan was still produced
    assert plan.tool_calls[0].tool_name == MockAgent().plan("delete the file scratch.tmp").tool_calls[0].tool_name


def test_llm_plan_falls_back_when_no_calls(monkeypatch) -> None:
    import httpx

    reply = json.dumps({"reasoning": "nothing to do", "tool_calls": []})
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _FakeResponse(reply))
    plan = LLMAgent(model="test-model").plan("look up trains to Munich")
    assert plan.source == "mock-fallback"
    assert plan.tool_calls
