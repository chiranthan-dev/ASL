"""Phase 13 — the FastAPI surface and the inspector's data contract."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.routes import set_engine
from app.core.engine import ASLEngine
from app.main import create_app


@pytest.fixture()
def client(engine: ASLEngine):
    set_engine(engine)
    with TestClient(create_app()) as client:
        yield client


def test_health(client) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["fusion_strategy"] == "WeightedRiskFusion"
    assert body["mock_llm"] is True
    assert "fingerprints" in body and "audit" in body


def test_evaluate_from_a_prompt_alone(client) -> None:
    response = client.post("/evaluate", json={"user_id": "u", "prompt": "Look up a dog picture"})
    assert response.status_code == 200
    body = response.json()
    for field in ("decision", "risk_score", "confidence", "fast_path", "fingerprint",
                  "signals", "explanation", "trace", "calls"):
        assert field in body, f"response missing {field}"
    assert body["decision"] in ("ALLOW", "ALLOW_WITH_LOG")
    assert body["calls"][0]["tool_name"] == "image_search"


def test_evaluate_with_explicit_tool_calls(client) -> None:
    body = client.post("/evaluate", json={
        "user_id": "u",
        "prompt": "cleanup",
        "environment": "production",
        "tool_calls": [{"tool_name": "filesystem.delete",
                        "arguments": {"path": "/production/", "recursive": True}}],
    }).json()
    assert body["decision"] == "BLOCK"
    assert body["risk_score"] >= 90


def test_evaluate_rejects_an_empty_request(client) -> None:
    assert client.post("/evaluate", json={"user_id": "u"}).status_code == 422


def test_trace_is_ordered_and_complete(client) -> None:
    trace = client.post("/evaluate", json={"user_id": "u", "prompt": "Delete /production/ everything",
                                           "environment": "production"}).json()["trace"]
    assert [t["index"] for t in trace] == list(range(len(trace)))
    assert trace[0]["stage"] == "agent"
    assert trace[-1]["stage"] == "session"
    for event in trace:
        assert event["status"] in ("ok", "warning", "critical", "skipped")
        assert "detail" in event and "title" in event


def test_fingerprints_endpoint(client) -> None:
    client.post("/evaluate", json={"user_id": "u", "prompt": "Look up a dog picture"})
    body = client.get("/fingerprints").json()
    assert body["count"] >= 1
    first = body["fingerprints"][0]
    assert first["canonical_representation"].startswith("FPv1|")
    assert "image_search" not in first["canonical_representation"], "canonical form is tool-name free"

    detail = client.get(f"/fingerprints/{first['fingerprint_id']}").json()
    assert detail["fingerprint"]["fingerprint_id"] == first["fingerprint_id"]
    assert isinstance(detail["observations"], list)


def test_unknown_fingerprint_404s(client) -> None:
    assert client.get("/fingerprints/fp_does_not_exist").status_code == 404


def test_audit_endpoint(client) -> None:
    client.post("/evaluate", json={"user_id": "u", "prompt": "Look up a dog picture"})
    body = client.get("/audit").json()
    assert body["entries"]
    assert body["statistics"]["total"] >= 1


def test_config_endpoint_exposes_every_threshold(client) -> None:
    body = client.get("/api/config").json()
    thresholds = body["thresholds"]
    assert thresholds["fingerprint_similarity_threshold"] == 0.98
    assert thresholds["historical_risk_threshold"] == 10
    assert thresholds["fingerprint_confidence_threshold"] == 0.95
    assert thresholds["risk_allow_threshold"] == 20
    assert thresholds["risk_sandbox_threshold"] == 90
    assert body["invariant_floors"]


def test_scenarios_and_graph_endpoints(client) -> None:
    scenarios = client.get("/api/scenarios").json()["scenarios"]
    assert len(scenarios) >= 8

    result = client.post("/evaluate", json={"user_id": "u", "prompt": "Look up a dog picture"}).json()
    graph = client.get(f"/api/graph/{result['session_id']}").json()
    assert graph["nodes"] and graph["edges"]


def test_reset_endpoint(client) -> None:
    client.post("/evaluate", json={"user_id": "u", "prompt": "Look up a dog picture"})
    assert client.get("/fingerprints").json()["count"] > 0
    client.post("/api/reset")
    assert client.get("/fingerprints").json()["count"] == 0


def test_all_surfaces_are_served(client) -> None:
    gateway = client.get("/")
    assert gateway.status_code == 200 and "ASL" in gateway.text
    assert "gateway.js" in gateway.text, "the front door is the gateway product"

    chat = client.get("/classic")
    assert chat.status_code == 200 and "chat.js" in chat.text

    inspector = client.get("/inspector")
    assert inspector.status_code == 200 and "Inspector" in inspector.text

    for asset in ("/static/gateway.js", "/static/gateway.css", "/static/chat.js",
                  "/static/app.js", "/static/stages.js", "/static/styles.css"):
        assert client.get(asset).status_code == 200, f"{asset} is missing"


def test_both_surfaces_share_one_renderer(client) -> None:
    """Chat and inspector must not drift into disagreeing about a stage."""
    shared = client.get("/static/stages.js").text
    assert "ASLStages" in shared
    for page in ("/", "/inspector"):
        assert "stages.js" in client.get(page).text
