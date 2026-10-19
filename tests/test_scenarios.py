"""End-to-end behaviour of the demo scenarios at the phase-5 boundary.

These assertions are about *relative* judgements (this must be riskier than
that, these two must fingerprint the same) rather than absolute scores, because
absolute scores only become meaningful once the risk engine lands in phase 10.
"""

from __future__ import annotations

import pytest

from app.behavior.fingerprint import FingerprintGenerator
from app.core.pipeline import BehaviorPipeline, CallInsight
from app.models.enums import Capability
from app.models.tool_call import ToolInvocation
from demos.scenarios import SCENARIOS_BY_ID, Scenario


@pytest.fixture(scope="module")
def results() -> dict[str, list[CallInsight]]:
    pipeline = BehaviorPipeline()
    out: dict[str, list[CallInsight]] = {}
    for scenario_id, scenario in SCENARIOS_BY_ID.items():
        out[scenario_id] = _run(pipeline, scenario)
    return out


def _run(pipeline: BehaviorPipeline, scenario: Scenario) -> list[CallInsight]:
    return [
        pipeline.process(
            ToolInvocation(tool_name=call.tool_name, arguments=call.arguments),
            scenario.session_id,
            scenario.user_id,
        )
        for call in scenario.tool_calls
    ]


def test_every_scenario_runs(results) -> None:
    assert len(results) == len(SCENARIOS_BY_ID)
    assert all(insights for insights in results.values())


def test_1_benign_image_search_is_read_only_and_cheap(results) -> None:
    insight = results["1_benign_image_search"][0]
    assert set(insight.capabilities.capabilities) == {Capability.READ, Capability.NETWORK}
    assert insight.provisional_risk < 25
    assert insight.arguments.findings == []


def test_2_benign_email_is_email_plus_write(results) -> None:
    insight = results["2_benign_email"][0]
    assert {Capability.EMAIL, Capability.WRITE} <= set(insight.capabilities.capabilities)
    assert insight.provisional_risk < 50


def test_3_repeat_of_a_benign_email_matches_its_fingerprint(results) -> None:
    first = results["2_benign_email"][0].fingerprint
    repeat = results["3_repeated_benign_email"][0].fingerprint
    assert first.fingerprint_id == repeat.fingerprint_id, (
        "the fast path in phase 8 depends on this identity holding"
    )


def test_4_download_then_execute_forms_a_chain(results) -> None:
    insights = results["4_download_then_execute"]
    chain = insights[-1].chain_fingerprint
    assert {Capability.DOWNLOAD, Capability.EXECUTE} <= set(chain.capabilities)
    assert any(t.startswith("DOWNLOAD-") and t.endswith("EXECUTE") for t in chain.transitions)
    assert insights[-1].provisional_risk > 70


def test_5_database_exfiltration_chain(results) -> None:
    insights = results["5_unauthorized_database_exfiltration"]
    chain = insights[-1].chain_fingerprint
    assert {Capability.DATABASE, Capability.READ, Capability.UPLOAD} <= set(chain.capabilities)
    assert any("UPLOAD" in t for t in chain.transitions)
    assert all(i.provisional_risk > 60 for i in insights)


def test_6_production_mass_delete_is_top_of_scale(results) -> None:
    insight = results["6_production_mass_delete"][0]
    assert insight.provisional_risk >= 90
    codes = {f.code for f in insight.arguments.findings}
    assert {"PATH_PRODUCTION", "PATH_MASS_DELETE"} <= codes


def test_7_same_tool_different_arguments_diverge(results) -> None:
    safe = results["7a_delete_temp_file"][0]
    dangerous = results["7b_delete_production_database"][0]
    assert safe.tool.tool_name == dangerous.tool.tool_name
    assert safe.tool.risk == dangerous.tool.risk, "tool-level risk cannot tell these apart"
    assert dangerous.arguments.risk - safe.arguments.risk > 40, "argument analysis must"
    assert dangerous.provisional_risk - safe.provisional_risk > 25
    assert safe.fingerprint.fingerprint_id != dangerous.fingerprint.fingerprint_id


def test_8_and_9_equivalence_across_tools(results) -> None:
    generator = FingerprintGenerator()
    baseline = results["7b_delete_production_database"][0].fingerprint
    via_shell = results["8_equivalent_delete_via_shell"][0].fingerprint
    via_unknown_tool = results["9_equivalent_delete_unknown_tool"][0].fingerprint

    assert via_unknown_tool.fingerprint_id == baseline.fingerprint_id
    assert generator.similarity(baseline, via_shell) >= 0.7


def test_unknown_tool_is_flagged_for_the_risk_engine(results) -> None:
    insight = results["9_equivalent_delete_unknown_tool"][0]
    assert insight.tool.known_tool is False
    assert any("not in the registry" in note for note in insight.notes)
    assert insight.tool.confidence < 0.7
