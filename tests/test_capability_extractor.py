"""Phase 3 - Semantic Capability Extractor."""

from __future__ import annotations

import pytest

from app.analyzers.argument_analyzer import ArgumentAnalyzer
from app.analyzers.tool_analyzer import ToolAnalyzer
from app.behavior.capability_extractor import CapabilityExtractor, close_implications
from app.models.enums import Capability
from app.models.tool_call import ToolInvocation


@pytest.fixture(scope="module")
def stack():
    return ToolAnalyzer(), ArgumentAnalyzer(), CapabilityExtractor()


def assess(stack, tool_name: str, arguments: dict):
    tool_analyzer, argument_analyzer, extractor = stack
    call = ToolInvocation(tool_name=tool_name, arguments=arguments)
    profile, _, _ = tool_analyzer.profile_for(tool_name)
    tool_analysis = tool_analyzer.analyze(call)
    argument_analysis = argument_analyzer.analyze(call, profile)
    return extractor.extract(tool_analysis, argument_analysis)


def test_implication_closure() -> None:
    assert Capability.NETWORK in close_implications({Capability.DOWNLOAD})
    assert Capability.NETWORK in close_implications({Capability.EMAIL})
    assert Capability.MODIFY in close_implications({Capability.PRIVILEGE_CHANGE})


def test_benign_search_capabilities(stack) -> None:
    assessment = assess(stack, "image_search", {"query": "golden retriever"})
    assert set(assessment.capabilities) == {Capability.READ, Capability.NETWORK}
    assert assessment.escalations == []


def test_python_delete_is_an_escalation(stack) -> None:
    assessment = assess(stack, "python.execute", {"code": "import os\nos.remove('/important/file')"})
    assert Capability.EXECUTE in assessment.capabilities
    assert Capability.DELETE in assessment.capabilities
    assert Capability.DELETE in assessment.escalations, (
        "the tool profile declares EXECUTE only; DELETE comes from the arguments"
    )


def test_shell_rm_escalates_beyond_declared_capabilities(stack) -> None:
    assessment = assess(stack, "shell.execute", {"command": "rm -rf /production/database/"})
    assert Capability.DELETE in assessment.escalations
    assert assessment.weight >= 85


def test_capability_weight_ranks_destructive_sets(stack) -> None:
    extractor = stack[2]
    read_only = extractor.weigh({Capability.READ})
    read_net = extractor.weigh({Capability.READ, Capability.NETWORK})
    destructive = extractor.weigh({Capability.DELETE, Capability.EXECUTE})
    assert read_only < read_net < destructive
    assert destructive <= 100


def test_confidence_blends_tool_and_argument_confidence(stack) -> None:
    known = assess(stack, "filesystem.delete", {"path": "/tmp/x.txt"})
    unknown = assess(stack, "zzz_opaque_plugin", {"foo": "bar"})
    assert known.confidence > unknown.confidence
