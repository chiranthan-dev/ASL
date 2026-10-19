"""Phase 2 - Tool Analyzer."""

from __future__ import annotations

import pytest

from app.analyzers.tool_analyzer import ToolAnalyzer, get_registry
from app.models.enums import Capability, ToolCategory
from app.models.tool_call import ToolInvocation

REQUIRED_TOOLS = [
    "image_search", "web_search", "web_fetch", "calculator", "gmail.send",
    "filesystem.read", "filesystem.write", "filesystem.delete",
    "python.execute", "shell.execute",
    "database.select", "database.insert", "database.update", "database.delete",
    "http.get", "http.post",
]


@pytest.fixture(scope="module")
def analyzer() -> ToolAnalyzer:
    return ToolAnalyzer()


def test_registry_contains_every_initial_tool() -> None:
    registry = get_registry()
    assert set(REQUIRED_TOOLS) <= set(registry.names())


@pytest.mark.parametrize("tool_name", REQUIRED_TOOLS)
def test_every_tool_analyses(analyzer: ToolAnalyzer, tool_name: str) -> None:
    analysis = analyzer.analyze(ToolInvocation(tool_name=tool_name))
    assert analysis.known_tool is True
    assert 0 <= analysis.sensitivity <= 100
    assert 0 <= analysis.risk <= 100
    assert analysis.confidence >= 0.9
    assert analysis.capabilities


def test_risk_ordering_follows_destructive_power(analyzer: ToolAnalyzer) -> None:
    def risk(name: str) -> float:
        return analyzer.analyze(ToolInvocation(tool_name=name)).risk

    assert risk("calculator") < risk("web_search") < risk("filesystem.read")
    assert risk("filesystem.read") < risk("filesystem.write") < risk("filesystem.delete")
    assert risk("database.select") < risk("database.delete")
    assert risk("python.execute") < risk("shell.execute")


def test_unknown_tool_is_inferred_with_low_confidence(analyzer: ToolAnalyzer) -> None:
    analysis = analyzer.analyze(ToolInvocation(tool_name="storage.remove_directory"))
    assert analysis.known_tool is False
    assert analysis.confidence < 0.7, "an unregistered tool must never be trusted like a registered one"
    assert Capability.DELETE in analysis.capabilities
    assert analysis.risk > 50


def test_unknown_tool_without_hints_falls_back_to_defaults(analyzer: ToolAnalyzer) -> None:
    analysis = analyzer.analyze(ToolInvocation(tool_name="zzz_opaque_plugin"))
    assert analysis.known_tool is False
    assert analysis.category is ToolCategory.UNKNOWN
    assert analysis.capabilities == [Capability.READ]
    assert analysis.confidence <= 0.4


def test_sensitivity_is_configuration_not_code() -> None:
    registry = get_registry()
    profile = registry.get("shell.execute")
    assert profile is not None
    assert profile.sensitivity >= 90
    assert profile.reversible is False
    assert profile.analyzer == "shell"
