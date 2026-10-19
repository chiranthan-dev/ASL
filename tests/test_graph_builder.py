"""Phase 4 - Behavior Graph Builder."""

from __future__ import annotations

import pytest

from app.core.pipeline import BehaviorPipeline
from app.models.enums import Capability, EdgeType, NodeKind
from app.models.tool_call import ToolInvocation


@pytest.fixture()
def pipeline() -> BehaviorPipeline:
    return BehaviorPipeline()


def feed(pipeline: BehaviorPipeline, session: str, calls: list[tuple[str, dict]]):
    return [
        pipeline.process(ToolInvocation(tool_name=name, arguments=args), session, "user_1")
        for name, args in calls
    ]


def test_invocation_node_carries_provenance(pipeline: BehaviorPipeline) -> None:
    insight = feed(pipeline, "s1", [("image_search", {"query": "dogs"})])[0]
    node = pipeline.graph.graph("s1").nodes[insight.node_id]
    assert node["kind"] == NodeKind.INVOCATION.value
    assert node["tool"] == "image_search"
    assert node["user_id"] == "user_1"
    assert node["session_id"] == "s1"
    assert node["timestamp"]
    assert node["risk"] >= 0
    assert "READ" in node["capabilities"]


def test_capability_and_resource_nodes_are_attached(pipeline: BehaviorPipeline) -> None:
    insight = feed(pipeline, "s2", [("filesystem.delete", {"path": "/production/db/"})])[0]
    graph = pipeline.graph.graph("s2")
    kinds = {
        graph.nodes[t]["kind"]
        for _, t in graph.out_edges(insight.node_id)
    }
    assert NodeKind.CAPABILITY.value in kinds
    assert NodeKind.RESOURCE.value in kinds


def test_sequence_edges_follow_call_order(pipeline: BehaviorPipeline) -> None:
    insights = feed(pipeline, "s3", [
        ("filesystem.read", {"path": "/home/user/notes.txt"}),
        ("filesystem.write", {"path": "/home/user/summary.txt", "content": "x"}),
    ])
    graph = pipeline.graph.graph("s3")
    sequence = [
        (u, v) for u, v, d in graph.edges(data=True)
        if d.get("edge_type") == EdgeType.SEQUENCE.value
    ]
    assert (insights[0].node_id, insights[1].node_id) in sequence


def test_explicit_data_flow_when_the_same_resource_is_reused(pipeline: BehaviorPipeline) -> None:
    insights = feed(pipeline, "s4", [
        ("filesystem.read", {"path": "/home/user/notes.txt"}),
        ("filesystem.delete", {"path": "/home/user/notes.txt"}),
    ])
    graph = pipeline.graph.graph("s4")
    flows = [
        d for u, v, d in graph.edges(data=True)
        if d.get("edge_type") == EdgeType.DATA_FLOW.value
        and u == insights[0].node_id and v == insights[1].node_id
    ]
    assert flows and flows[0]["inferred"] is False


def test_inferred_data_flow_for_download_then_execute(pipeline: BehaviorPipeline) -> None:
    insights = feed(pipeline, "s5", [
        ("web_fetch", {"url": "http://cdn.example/setup.exe"}),
        ("shell.execute", {"command": "./setup.exe"}),
    ])
    graph = pipeline.graph.graph("s5")
    flows = [
        d for u, v, d in graph.edges(data=True)
        if d.get("edge_type") == EdgeType.DATA_FLOW.value
        and u == insights[0].node_id and v == insights[1].node_id
    ]
    assert flows, "a produce-then-consume pair must be linked"
    assert flows[0]["inferred"] is True
    assert flows[0]["weight"] < 1.0, "an inferred link must be weaker than an observed one"


def test_capability_sequence_reads_like_the_workflow(pipeline: BehaviorPipeline) -> None:
    feed(pipeline, "s6", [
        ("filesystem.read", {"path": "/home/user/notes.txt"}),
        ("web_fetch", {"url": "http://cdn.example/payload.bin"}),
        ("shell.execute", {"command": "./payload.bin"}),
        ("filesystem.delete", {"path": "/home/user/notes.txt"}),
    ])
    sequence = pipeline.graph.capability_sequence("s6")
    assert Capability.READ in sequence[0]
    assert Capability.DOWNLOAD in sequence[1]
    assert Capability.EXECUTE in sequence[2]
    assert Capability.DELETE in sequence[3]


def test_snapshot_window_limits_to_recent_calls(pipeline: BehaviorPipeline) -> None:
    feed(pipeline, "s7", [
        ("image_search", {"query": "a"}),
        ("web_search", {"query": "b"}),
        ("calculator", {"expression": "1+1"}),
    ])
    full = pipeline.graph.snapshot("s7")
    windowed = pipeline.graph.snapshot("s7", window=1)
    assert len(full.capability_sequence) == 3
    assert len(windowed.capability_sequence) == 1
    invocations = [n for n in windowed.nodes if n.kind is NodeKind.INVOCATION]
    assert len(invocations) == 1


def test_sessions_are_isolated(pipeline: BehaviorPipeline) -> None:
    feed(pipeline, "s8", [("image_search", {"query": "a"})])
    feed(pipeline, "s9", [("calculator", {"expression": "2"})])
    assert pipeline.graph.graph("s8").number_of_nodes() > 0
    assert set(pipeline.graph.invocation_order("s8")).isdisjoint(pipeline.graph.invocation_order("s9"))
