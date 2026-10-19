"""Behavior Graph Builder (spec section 5).

Builds one NetworkX `MultiDiGraph` per session:

    INVOCATION --CAPABILITY--> capability nodes
    INVOCATION --RESOURCE----> resource nodes
    INVOCATION --SEQUENCE----> next INVOCATION
    INVOCATION --DATA_FLOW---> later INVOCATION that consumes what it produced

The graph is the substrate for two later stages: the fingerprint generator
canonicalises it, and the execution-chain analyzer reasons over its paths.
Keeping *both* the invocation layer (tool-specific, auditable) and the
capability layer (tool-agnostic, comparable) in one graph is what lets the
fingerprint drop tool names without losing the workflow shape.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import Any, Iterable

import networkx as nx

from app.models.enums import (
    Capability,
    EdgeType,
    NodeKind,
    ResourceClass,
    Scope,
)
from app.models.fingerprint import BehaviorEdge, BehaviorGraphSnapshot, BehaviorNode
from app.models.tool_call import (
    ArgumentAnalysis,
    CapabilityAssessment,
    ResourceDescriptor,
    ToolAnalysis,
    ToolInvocation,
    utcnow,
)

#: capabilities that produce data another step could consume
PRODUCING = {Capability.READ, Capability.DOWNLOAD, Capability.DATABASE, Capability.SENSOR_ACCESS}
#: capabilities that consume data produced earlier
CONSUMING = {
    Capability.EXECUTE, Capability.UPLOAD, Capability.EMAIL, Capability.WRITE,
    Capability.MODIFY, Capability.DELETE,
}


class BehaviorGraphBuilder:
    """Accumulates session behavior graphs in memory.

    A session's graph is small (tens of nodes) and short-lived; durable
    knowledge is carried forward by fingerprints, not by keeping graphs.
    """

    #: how many sessions to keep resident before evicting the oldest
    MAX_RESIDENT_SESSIONS = 64

    def __init__(self, data_flow_window: int = 4, max_sessions: int | None = None) -> None:
        # Ordered: insertion order is eviction order.
        self._graphs: OrderedDict[str, nx.MultiDiGraph] = OrderedDict()
        self._order: dict[str, list[str]] = {}
        self.data_flow_window = data_flow_window
        self.max_sessions = max_sessions or self.MAX_RESIDENT_SESSIONS

    # -- accessors ------------------------------------------------------
    def graph(self, session_id: str) -> nx.MultiDiGraph:
        """Get (or create) a session's graph, evicting the oldest if needed.

        Session graphs are working memory, not storage: everything durable has
        already been folded into a fingerprint by the time a session goes cold.
        Keeping every graph forever leaks in any long-running process — measured
        as steadily climbing evaluation latency across a 200-scenario run, from
        GC pressure rather than from any single call getting slower.
        """
        if session_id in self._graphs:
            self._graphs.move_to_end(session_id)
            return self._graphs[session_id]

        while len(self._graphs) >= self.max_sessions:
            evicted, _ = self._graphs.popitem(last=False)
            self._order.pop(evicted, None)

        self._graphs[session_id] = nx.MultiDiGraph(session_id=session_id)
        self._order[session_id] = []
        return self._graphs[session_id]

    def invocation_order(self, session_id: str) -> list[str]:
        return list(self._order.get(session_id, []))

    def sessions(self) -> list[str]:
        return list(self._graphs)

    def reset(self, session_id: str | None = None) -> None:
        if session_id is None:
            self._graphs.clear()
            self._order.clear()
        else:
            self._graphs.pop(session_id, None)
            self._order.pop(session_id, None)

    # -- construction ---------------------------------------------------
    def add_invocation(
        self,
        session_id: str,
        user_id: str,
        invocation: ToolInvocation,
        tool_analysis: ToolAnalysis,
        capability_assessment: CapabilityAssessment,
        argument_analysis: ArgumentAnalysis | None = None,
        risk: float = 0.0,
        confidence: float | None = None,
    ) -> str:
        """Add one intercepted call and return its invocation node id."""
        graph = self.graph(session_id)
        order = self._order[session_id]

        # `evidenced`, not `capabilities`: the graph is what the fingerprint is
        # built from, and a fingerprint must describe the act rather than our
        # guess about the tool that performed it.
        capabilities = list(capability_assessment.evidenced
                            or capability_assessment.capabilities)
        resources = list(argument_analysis.resources) if argument_analysis else []
        scope = argument_analysis.scope if argument_analysis else Scope.SINGLE
        node_id = invocation.call_id

        graph.add_node(
            node_id,
            kind=NodeKind.INVOCATION.value,
            label="+".join(c.value for c in capabilities) or "NONE",
            tool=invocation.tool_name,
            category=tool_analysis.category.value,
            capabilities=[c.value for c in capabilities],
            scope=scope.value,
            session_id=session_id,
            user_id=user_id,
            timestamp=invocation.timestamp.isoformat(),
            risk=risk,
            confidence=confidence if confidence is not None else capability_assessment.confidence,
            step=len(order),
        )

        for capability in capabilities:
            cap_node = f"{node_id}#CAP:{capability.value}"
            graph.add_node(
                cap_node,
                kind=NodeKind.CAPABILITY.value,
                label=capability.value,
                capability=capability.value,
                session_id=session_id,
                step=len(order),
            )
            graph.add_edge(node_id, cap_node, key=EdgeType.CAPABILITY.value,
                           edge_type=EdgeType.CAPABILITY.value, weight=1.0)

        for resource in resources:
            res_node = self._resource_node_id(resource)
            if res_node is None:
                continue
            graph.add_node(
                res_node,
                kind=NodeKind.RESOURCE.value,
                label=resource.resource_class.value,
                resource_class=resource.resource_class.value,
                scope=resource.scope.value,
                identifier=resource.identifier,
                sensitive=resource.sensitive,
                session_id=session_id,
            )
            graph.add_edge(node_id, res_node, key=EdgeType.RESOURCE.value,
                           edge_type=EdgeType.RESOURCE.value, weight=1.0)

        if order:
            previous = order[-1]
            graph.add_edge(previous, node_id, key=EdgeType.SEQUENCE.value,
                           edge_type=EdgeType.SEQUENCE.value, weight=1.0)

        self._link_data_flow(graph, order, node_id, resources, set(capabilities))
        order.append(node_id)
        return node_id

    # -- data flow ------------------------------------------------------
    @staticmethod
    def _resource_node_id(resource: ResourceDescriptor) -> str | None:
        if resource.resource_class in (ResourceClass.NONE,):
            return None
        key = resource.identifier or resource.resource_class.value.lower()
        return f"res:{key}"

    def _link_data_flow(
        self,
        graph: nx.MultiDiGraph,
        order: list[str],
        node_id: str,
        resources: Iterable[ResourceDescriptor],
        capabilities: set[Capability],
    ) -> None:
        """Connect this call to earlier calls whose output it plausibly consumes.

        Two rules, of different strength:

        * **explicit** (weight 1.0) - the two calls name the same resource
          identifier, so the link is observed rather than guessed;
        * **inferred** (weight 0.5) - an earlier call produced data and this
          one consumes data, within a short window.  Marked `inferred` so
          downstream stages can discount it.
        """
        identifiers = {r.identifier for r in resources if r.identifier}
        for earlier in reversed(order[-self.data_flow_window:]):
            earlier_caps = {Capability(c) for c in graph.nodes[earlier].get("capabilities", [])}
            earlier_ids = {
                graph.nodes[target].get("identifier")
                for _, target, data in graph.out_edges(earlier, data=True)
                if data.get("edge_type") == EdgeType.RESOURCE.value
            }
            shared = identifiers & {i for i in earlier_ids if i}
            if shared:
                graph.add_edge(earlier, node_id, key=EdgeType.DATA_FLOW.value,
                               edge_type=EdgeType.DATA_FLOW.value, weight=1.0,
                               inferred=False, via=sorted(shared)[0])
            elif earlier_caps & PRODUCING and capabilities & CONSUMING:
                graph.add_edge(earlier, node_id, key=f"{EdgeType.DATA_FLOW.value}:inferred",
                               edge_type=EdgeType.DATA_FLOW.value, weight=0.5, inferred=True)

    # -- views ----------------------------------------------------------
    def capability_sequence(self, session_id: str) -> list[list[Capability]]:
        graph = self.graph(session_id)
        return [
            [Capability(c) for c in graph.nodes[n].get("capabilities", [])]
            for n in self._order.get(session_id, [])
        ]

    def snapshot(self, session_id: str, window: int | None = None) -> BehaviorGraphSnapshot:
        """Serialise the session graph (optionally only the last `window` calls)."""
        graph = self.graph(session_id)
        order = self._order.get(session_id, [])
        selected = order if window is None else order[-window:]
        keep: set[str] = set(selected)
        for node in selected:
            keep.update(
                target for _, target, data in graph.out_edges(node, data=True)
                if data.get("edge_type") in (EdgeType.CAPABILITY.value, EdgeType.RESOURCE.value)
            )

        nodes: list[BehaviorNode] = []
        for node_id in graph.nodes:
            if node_id not in keep:
                continue
            attrs: dict[str, Any] = graph.nodes[node_id]
            nodes.append(BehaviorNode(
                node_id=node_id,
                kind=NodeKind(attrs["kind"]),
                label=attrs.get("label", ""),
                tool=attrs.get("tool"),
                capability=Capability(attrs["capability"]) if attrs.get("capability") else None,
                resource_class=ResourceClass(attrs["resource_class"]) if attrs.get("resource_class") else None,
                scope=Scope(attrs.get("scope", Scope.NONE.value)),
                identifier=attrs.get("identifier"),
                session_id=attrs.get("session_id"),
                user_id=attrs.get("user_id"),
                timestamp=self._parse_ts(attrs.get("timestamp")),
                risk=float(attrs.get("risk", 0.0)),
                confidence=float(attrs.get("confidence", 0.5)),
            ))

        edges = [
            BehaviorEdge(
                source=u, target=v,
                edge_type=EdgeType(data.get("edge_type", EdgeType.SEQUENCE.value)),
                weight=float(data.get("weight", 1.0)),
            )
            for u, v, data in graph.edges(data=True)
            if u in keep and v in keep
        ]

        sequence = [
            [Capability(c) for c in graph.nodes[n].get("capabilities", [])]
            for n in selected
        ]
        user_id = next((graph.nodes[n].get("user_id") for n in selected if graph.nodes[n].get("user_id")), None)
        return BehaviorGraphSnapshot(
            session_id=session_id, user_id=user_id,
            nodes=nodes, edges=edges, capability_sequence=sequence,
        )

    @staticmethod
    def _parse_ts(value: Any) -> datetime:
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
        return utcnow()
