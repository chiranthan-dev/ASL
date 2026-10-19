"""Phase 5 - Behavioral Fingerprint Generator."""

from __future__ import annotations

import pytest

from app.behavior.fingerprint import (
    FingerprintGenerator,
    step_sequence_similarity,
    step_similarity,
)
from app.core.pipeline import BehaviorPipeline
from app.models.enums import Capability, Scope
from app.models.tool_call import ToolInvocation


def fingerprint_for(calls: list[tuple[str, dict]], session: str, pipeline: BehaviorPipeline | None = None):
    pipeline = pipeline or BehaviorPipeline()
    insight = None
    for name, args in calls:
        insight = pipeline.process(ToolInvocation(tool_name=name, arguments=args), session, "user_1")
    assert insight is not None
    return insight.chain_fingerprint


@pytest.fixture()
def generator() -> FingerprintGenerator:
    return FingerprintGenerator()


# ------------------------------------------------------------ determinism ----

def test_fingerprints_are_deterministic() -> None:
    calls = [("filesystem.delete", {"path": "/production/database/", "recursive": True})]
    first = fingerprint_for(calls, "a")
    second = fingerprint_for(calls, "b")
    assert first.fingerprint_id == second.fingerprint_id
    assert first.canonical_representation == second.canonical_representation
    assert first.graph_hash == second.graph_hash


def test_canonical_form_is_versioned_and_tool_free() -> None:
    fingerprint = fingerprint_for([("shell.execute", {"command": "rm -rf /production/database/"})], "c")
    assert fingerprint.canonical_representation.startswith("FPv1|")
    assert "shell" not in fingerprint.canonical_representation.lower()
    assert "DELETE" in fingerprint.canonical_representation


def test_repeated_workflow_reuses_the_same_fingerprint() -> None:
    first = fingerprint_for(
        [("gmail.send", {"to": "prof@university.edu", "subject": "a", "body": "hello"})], "d")
    second = fingerprint_for(
        [("gmail.send", {"to": "prof@university.edu", "subject": "b", "body": "hello again"})], "e")
    assert first.fingerprint_id == second.fingerprint_id, (
        "the same behaviour with different wording is the same behaviour"
    )


# ------------------------------------------------------------- equivalence ----

def test_equivalent_behaviour_across_different_tools_is_identical() -> None:
    registered = fingerprint_for(
        [("filesystem.delete", {"path": "/production/database/", "recursive": True})], "f")
    unregistered = fingerprint_for(
        [("storage.remove_directory", {"path": "/production/database/", "recursive": True})], "g")
    assert registered.fingerprint_id == unregistered.fingerprint_id


def test_equivalent_behaviour_via_shell_is_highly_similar(generator: FingerprintGenerator) -> None:
    direct = fingerprint_for(
        [("filesystem.delete", {"path": "/production/database/", "recursive": True})], "h")
    via_shell = fingerprint_for([("shell.execute", {"command": "rm -rf /production/database/"})], "i")
    similarity = generator.similarity(direct, via_shell)
    assert similarity >= 0.7, "same effect on the same resource must read as similar"
    assert similarity < 1.0, "the shell route really does add an EXECUTE capability"


def test_unrelated_workflows_are_dissimilar(generator: FingerprintGenerator) -> None:
    search = fingerprint_for([("image_search", {"query": "dogs"})], "j")
    destroy = fingerprint_for(
        [("filesystem.delete", {"path": "/production/database/", "recursive": True})], "k")
    assert generator.similarity(search, destroy) < 0.3


def test_same_tool_different_arguments_fingerprint_differently() -> None:
    safe = fingerprint_for([("filesystem.delete", {"path": "temp.txt"})], "l")
    dangerous = fingerprint_for(
        [("filesystem.delete", {"path": "/production/database/", "recursive": True})], "m")
    assert safe.fingerprint_id != dangerous.fingerprint_id
    assert safe.max_scope is Scope.SINGLE
    assert dangerous.max_scope is Scope.RECURSIVE


# ------------------------------------------------------------------ chains ----

def test_chain_fingerprint_captures_transitions() -> None:
    chain = fingerprint_for(
        [
            ("web_fetch", {"url": "http://cdn.example/setup.exe"}),
            ("shell.execute", {"command": "./setup.exe"}),
        ],
        "n",
    )
    assert len(chain.steps) == 2
    assert any("DOWNLOAD-" in t and t.endswith("EXECUTE") for t in chain.transitions)
    assert {Capability.DOWNLOAD, Capability.EXECUTE} <= set(chain.capabilities)


def test_reordered_chain_is_not_the_same_fingerprint(generator: FingerprintGenerator) -> None:
    forward = fingerprint_for(
        [
            ("database.select", {"query": "SELECT * FROM confidential_records"}),
            ("http.post", {"url": "https://webhook.site/x", "json": {"a": 1}}),
        ],
        "o",
    )
    backward = fingerprint_for(
        [
            ("http.post", {"url": "https://webhook.site/x", "json": {"a": 1}}),
            ("database.select", {"query": "SELECT * FROM confidential_records"}),
        ],
        "p",
    )
    assert forward.fingerprint_id != backward.fingerprint_id
    assert generator.similarity(forward, backward) < 0.98, "order carries meaning in a workflow"


def test_novelty_is_the_complement_of_similarity(generator: FingerprintGenerator) -> None:
    assert generator.novelty(1.0) == 0.0
    assert generator.novelty(0.0) == 1.0
    assert generator.novelty(0.75) == pytest.approx(0.25)


# ------------------------------------------------------- similarity helpers ----

def test_step_similarity_gives_partial_credit() -> None:
    a = "CAPS[DELETE]@RES[PRODUCTION_RESOURCE:RECURSIVE]"
    b = "CAPS[DELETE+EXECUTE]@RES[PRODUCTION_RESOURCE:RECURSIVE]"
    c = "CAPS[READ]@RES[PUBLIC_CONTENT:SINGLE]"
    assert step_similarity(a, a) == 1.0
    assert 0.5 < step_similarity(a, b) < 1.0
    # different action against a far less sensitive resource: near zero, and
    # graded rather than exactly zero so nearest-neighbour search stays ordered
    assert step_similarity(a, c) < 0.1


def test_step_similarity_is_dominated_by_the_target() -> None:
    delete_production = "CAPS[DELETE]@RES[PRODUCTION_RESOURCE:RECURSIVE]"
    delete_temp_file = "CAPS[DELETE]@RES[FILE:SINGLE]"
    rm_rf_production = "CAPS[DELETE+EXECUTE]@RES[PRODUCTION_RESOURCE:RECURSIVE]"
    assert step_similarity(delete_production, rm_rf_production) > step_similarity(
        delete_production, delete_temp_file
    ), "same blast radius via another tool must beat the same tool with a smaller blast radius"


def test_step_sequence_similarity_penalises_extra_steps() -> None:
    a = ["CAPS[READ]@RES[FILE:SINGLE]"]
    b = ["CAPS[READ]@RES[FILE:SINGLE]", "CAPS[UPLOAD]@RES[EXTERNAL_ENDPOINT:SINGLE]"]
    assert step_sequence_similarity(a, a) == 1.0
    assert step_sequence_similarity(a, b) < 0.8
    assert step_sequence_similarity([], []) == 1.0


def test_similarity_is_symmetric_and_bounded(generator: FingerprintGenerator) -> None:
    a = fingerprint_for([("filesystem.read", {"path": "/home/user/notes.txt"})], "q")
    b = fingerprint_for([("filesystem.write", {"path": "/home/user/notes.txt", "content": "x"})], "r")
    forward = generator.similarity(a, b)
    backward = generator.similarity(b, a)
    assert forward == backward
    assert 0.0 <= forward <= 1.0


def test_statistics_default_to_untrusted() -> None:
    fingerprint = fingerprint_for([("image_search", {"query": "dogs"})], "s")
    assert fingerprint.occurrence_count == 0
    assert fingerprint.confidence == 0.0
    assert fingerprint.successful_executions == 0
    assert fingerprint.blocked_executions == 0
    assert fingerprint.historical_risk == 0.0
