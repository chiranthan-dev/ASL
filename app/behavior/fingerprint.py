"""Behavioral Fingerprint Generator (spec section 6).

A fingerprint is a deterministic, tool-name-free canonicalisation of a behavior
graph.  Two workflows that *do the same thing* must fingerprint the same way
even when they use different tools:

    filesystem.delete("/prod/db/")          ->  DELETE@PRODUCTION_RESOURCE:RECURSIVE
    shell.execute("rm -rf /prod/db")        ->  DELETE@PRODUCTION_RESOURCE:RECURSIVE

Canonical form (version-tagged so stored fingerprints stay interpretable):

    FPv1|<step>;<step>;...||<transition>,<transition>,...||SCOPE:<max scope>

* a **step** is `CAPS[A+B]@RES[CLASS:SCOPE]` for one invocation,
* a **transition** is `PRIMARY_CAP-EDGE->PRIMARY_CAP` between two invocations.

`graph_hash` is a Weisfeiler-Lehman hash of the relabelled graph, which
captures structure the linear canonical form flattens (branching, joins).
"""

from __future__ import annotations

import hashlib
import re
import warnings
from difflib import SequenceMatcher
from typing import Iterable

import networkx as nx

from app.core.config import ASLConfig, get_config
from app.models.enums import (
    CAPABILITY_WEIGHT,
    RESOURCE_SENSITIVITY,
    Capability,
    EdgeType,
    NodeKind,
    ResourceClass,
    Scope,
)
from app.models.fingerprint import BehaviorGraphSnapshot, BehavioralFingerprint

CANONICAL_VERSION = "FPv1"
_SCOPE_ORDER = list(Scope)


def _primary_capability(capabilities: Iterable[Capability]) -> str:
    caps = list(capabilities)
    if not caps:
        return "NONE"
    return max(caps, key=lambda c: CAPABILITY_WEIGHT[c]).value


class FingerprintGenerator:
    """Canonicalises behavior graphs into comparable fingerprints."""

    def __init__(self, config: ASLConfig | None = None) -> None:
        self.config = config or get_config()

    # -- generation -----------------------------------------------------
    def generate(self, snapshot: BehaviorGraphSnapshot) -> BehavioralFingerprint:
        invocations = [n for n in snapshot.nodes if n.kind is NodeKind.INVOCATION]
        invocations.sort(key=lambda n: (n.timestamp, n.node_id))
        index = {n.node_id: i for i, n in enumerate(invocations)}

        resources_by_call = self._resources_by_call(snapshot)
        steps = [self._step_token(node, resources_by_call.get(node.node_id, [])) for node in invocations]
        transitions = self._transition_tokens(snapshot, invocations, index)

        capabilities = sorted(
            {c for seq in snapshot.capability_sequence for c in seq}
            or {c for node in invocations for c in self._caps_of(node)},
            key=lambda c: c.value,
        )
        resource_classes = sorted(
            {rc for rcs in resources_by_call.values() for rc, _ in rcs}, key=lambda r: r.value
        )
        max_scope = max(
            [Scope.NONE] + [s for rcs in resources_by_call.values() for _, s in rcs],
            key=_SCOPE_ORDER.index,
        )

        canonical = (
            f"{CANONICAL_VERSION}|{';'.join(steps)}"
            f"||{','.join(transitions)}"
            f"||SCOPE:{max_scope.value}"
        )
        graph_hash = self.graph_hash(snapshot)
        fingerprint_id = "fp_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

        return BehavioralFingerprint(
            fingerprint_id=fingerprint_id,
            canonical_representation=canonical,
            graph_hash=graph_hash,
            capabilities=capabilities,
            steps=steps,
            transitions=transitions,
            resource_classes=resource_classes,
            max_scope=max_scope,
        )

    # -- canonical pieces -----------------------------------------------
    @staticmethod
    def _caps_of(node) -> list[Capability]:
        if node.capability:
            return [node.capability]
        return [Capability(c) for c in node.label.split("+") if c in Capability.__members__]

    @staticmethod
    def _resources_by_call(
        snapshot: BehaviorGraphSnapshot,
    ) -> dict[str, list[tuple[ResourceClass, Scope]]]:
        nodes = {n.node_id: n for n in snapshot.nodes}
        out: dict[str, list[tuple[ResourceClass, Scope]]] = {}
        for edge in snapshot.edges:
            if edge.edge_type is not EdgeType.RESOURCE:
                continue
            target = nodes.get(edge.target)
            if target is None or target.resource_class is None:
                continue
            out.setdefault(edge.source, []).append((target.resource_class, target.scope))
        return out

    @staticmethod
    def _step_token(node, resources: list[tuple[ResourceClass, Scope]]) -> str:
        caps = "+".join(sorted(c.value for c in FingerprintGenerator._caps_of(node))) or "NONE"
        if resources:
            unique = sorted({f"{rc.value}:{sc.value}" for rc, sc in resources})
            res = ",".join(unique)
        else:
            res = f"{ResourceClass.NONE.value}:{Scope.NONE.value}"
        return f"CAPS[{caps}]@RES[{res}]"

    @staticmethod
    def _transition_tokens(
        snapshot: BehaviorGraphSnapshot,
        invocations: list,
        index: dict[str, int],
    ) -> list[str]:
        caps_by_node = {n.node_id: FingerprintGenerator._caps_of(n) for n in invocations}
        tokens: list[tuple[int, str]] = []
        for edge in snapshot.edges:
            if edge.edge_type not in (EdgeType.SEQUENCE, EdgeType.DATA_FLOW):
                continue
            if edge.source not in index or edge.target not in index:
                continue
            src = _primary_capability(caps_by_node.get(edge.source, []))
            dst = _primary_capability(caps_by_node.get(edge.target, []))
            tokens.append((index[edge.source], f"{src}-{edge.edge_type.value}->{dst}"))
        # order by position, then lexically, so the form is deterministic
        return [t for _, t in sorted(set(tokens), key=lambda p: (p[0], p[1]))]

    # -- structural hash -------------------------------------------------
    @staticmethod
    def graph_hash(snapshot: BehaviorGraphSnapshot) -> str:
        """Weisfeiler-Lehman hash over semantic (tool-free) node labels."""
        g = nx.DiGraph()
        nodes = {n.node_id: n for n in snapshot.nodes}
        for node_id, node in nodes.items():
            g.add_node(node_id, label=node.semantic_label())
        for edge in snapshot.edges:
            if edge.source in nodes and edge.target in nodes:
                g.add_edge(edge.source, edge.target, et=edge.edge_type.value)
        if g.number_of_nodes() == 0:
            return hashlib.sha256(b"empty").hexdigest()[:32]
        with warnings.catch_warnings():
            # NetworkX >= 3.5 warns that directed-graph hashes changed; we only
            # ever compare hashes produced by this same version.
            warnings.simplefilter("ignore", UserWarning)
            return nx.weisfeiler_lehman_graph_hash(g, node_attr="label", edge_attr="et", iterations=3)

    # -- similarity ------------------------------------------------------
    def similarity(self, a: BehavioralFingerprint, b: BehavioralFingerprint) -> float:
        """Graded similarity in [0, 1].

        Identical canonical forms short-circuit to 1.0.  Otherwise up to four
        views are mixed with configurable weights: capability overlap, ordered
        step similarity, transition overlap and scope proximity.  Step
        similarity is weighted highest because a step carries both the action
        and its target, and the target is what separates
        `delete("temp.txt")` from `delete("/production/database/")`.

        Single-step workflows have no transitions at all; counting "both empty"
        as perfect transition agreement would hand every one-call comparison a
        free score, so that view is dropped from the mean instead.
        """
        if a.canonical_representation == b.canonical_representation:
            return 1.0

        cfg = self.config
        cap = _jaccard({c.value for c in a.capabilities}, {c.value for c in b.capabilities})
        step = step_sequence_similarity(a.steps, b.steps)
        scope_gap = abs(_SCOPE_ORDER.index(a.max_scope) - _SCOPE_ORDER.index(b.max_scope))
        scope = 1.0 - scope_gap / (len(_SCOPE_ORDER) - 1)

        views = [
            (cfg.similarity_weight_capabilities, cap),
            (cfg.similarity_weight_steps, step),
            (cfg.similarity_weight_scope, scope),
        ]
        if a.transitions or b.transitions:
            views.append(
                (cfg.similarity_weight_transitions, _jaccard(set(a.transitions), set(b.transitions)))
            )

        denominator = sum(weight for weight, _ in views)
        total = sum(weight * value for weight, value in views)
        score = total / denominator if denominator else 0.0

        # Structural agreement is corroborating evidence, but must never lift a
        # weak match over the fast-path threshold on its own.
        if a.graph_hash == b.graph_hash:
            score = min(0.97, score + 0.02)
        return round(min(1.0, max(0.0, score)), 4)

    def novelty(self, best_similarity: float) -> float:
        return round(max(0.0, min(1.0, 1.0 - best_similarity)), 4)


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


_STEP_RE = re.compile(r"CAPS\[(?P<caps>[^\]]*)\]@RES\[(?P<res>[^\]]*)\]")


def parse_step(token: str) -> tuple[set[str], set[str]]:
    """Split a step token back into its capability and resource sets."""
    m = _STEP_RE.match(token)
    if not m:
        return {token}, set()
    caps = {c for c in m.group("caps").split("+") if c}
    res = {r for r in m.group("res").split(",") if r}
    return caps, res


def _resource_similarity(res_a: set[str], res_b: set[str]) -> float:
    """How close are two sets of `CLASS:SCOPE` resource tokens?

    Graded by *sensitivity distance* rather than set overlap.  A plain FILE and
    a PRODUCTION_RESOURCE are both "a thing on disk", but treating them as
    merely non-equal would make `delete("temp.txt")` look as close to
    `delete("/production/database/")` as `rm -rf` does - which is exactly the
    conflation this project exists to avoid.  The most sensitive resource on
    each side dominates, because that is the one that determines the blast
    radius, and scope proximity multiplies in for the same reason.
    """
    if res_a == res_b:
        return 1.0
    if not res_a or not res_b:
        return 0.0

    def peak(tokens: set[str]) -> tuple[int, int]:
        classes, scopes = [], []
        for token in tokens:
            name, _, scope = token.partition(":")
            try:
                classes.append(RESOURCE_SENSITIVITY[ResourceClass(name)])
            except (KeyError, ValueError):
                classes.append(RESOURCE_SENSITIVITY[ResourceClass.UNKNOWN])
            try:
                scopes.append(_SCOPE_ORDER.index(Scope(scope)))
            except ValueError:
                scopes.append(_SCOPE_ORDER.index(Scope.SINGLE))
        return max(classes), max(scopes)

    sensitivity_a, scope_a = peak(res_a)
    sensitivity_b, scope_b = peak(res_b)
    class_similarity = 1.0 - abs(sensitivity_a - sensitivity_b) / 100.0
    scope_similarity = 1.0 - abs(scope_a - scope_b) / (len(_SCOPE_ORDER) - 1)
    exact_overlap = _jaccard(res_a, res_b)
    return max(exact_overlap, class_similarity * scope_similarity)


def step_similarity(a: str, b: str) -> float:
    """Partial-credit similarity between two step tokens.

    Exact string comparison is too brittle: `shell.execute("rm -rf /prod/db")`
    produces CAPS[DELETE+EXECUTE] where `filesystem.delete("/prod/db/")`
    produces CAPS[DELETE], yet the two steps describe the same event against
    the same resource.  The resource half carries slightly more weight than the
    capability half: what an action touches constrains its impact more than the
    mechanism it used to touch it.
    """
    if a == b:
        return 1.0
    caps_a, res_a = parse_step(a)
    caps_b, res_b = parse_step(b)
    capability_overlap = _jaccard(caps_a, caps_b)
    resource_overlap = _resource_similarity(res_a, res_b)
    if capability_overlap == 0.0:
        # Disjoint capabilities mean these are different actions; touching
        # comparably ordinary resources must not make them look alike.
        return round(0.3 * resource_overlap, 4)
    return round(0.45 * capability_overlap + 0.55 * resource_overlap, 4)


def step_sequence_similarity(a: list[str], b: list[str]) -> float:
    """Order-sensitive similarity between two step sequences.

    Positions are compared pairwise (workflow order matters) and the score is
    normalised by the *longer* sequence, so an extra step is a real penalty
    rather than something the shorter sequence gets for free.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    pairwise = sum(step_similarity(x, y) for x, y in zip(a, b))
    aligned = pairwise / max(len(a), len(b))
    # Reward sequences that share the same multiset of steps even when the
    # order shifted, without letting reordering count as identity.
    unordered = SequenceMatcher(None, sorted(a), sorted(b)).ratio()
    return round(max(aligned, 0.9 * unordered), 4)
