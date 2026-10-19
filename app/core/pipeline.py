"""Behavior pipeline: stages 1-6 of the ASL core (phases 1-5 of the build).

    ToolInvocation
      -> ToolAnalyzer            (what power does this tool have?)
      -> ArgumentAnalyzer        (what is it actually being asked to do?)
      -> CapabilityExtractor     (semantic capabilities + escalations)
      -> BehaviorGraphBuilder    (how does it relate to what came before?)
      -> FingerprintGenerator    (canonical, tool-name-free signature)

The trust store, fast path, remaining analyzers, risk fusion and the decision
engine plug in *after* this, consuming `CallInsight` and the fingerprint.  The
`provisional_risk` computed here is explicitly a placeholder for the phase-10
risk engine: it exists so the behavior graph can carry a per-node risk, and it
is never used to authorize anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analyzers.argument_analyzer import ArgumentAnalyzer
from app.analyzers.tool_analyzer import ToolAnalyzer
from app.behavior.capability_extractor import CapabilityExtractor
from app.behavior.fingerprint import FingerprintGenerator
from app.behavior.graph_builder import BehaviorGraphBuilder
from app.core.config import ASLConfig, get_config
from app.models.fingerprint import BehavioralFingerprint
from app.models.tool_call import (
    ArgumentAnalysis,
    CapabilityAssessment,
    ToolAnalysis,
    ToolInvocation,
)


@dataclass
class CallInsight:
    """Everything stages 1-4 concluded about a single intercepted call."""

    invocation: ToolInvocation
    tool: ToolAnalysis
    arguments: ArgumentAnalysis
    capabilities: CapabilityAssessment
    node_id: str
    provisional_risk: float
    session_id: str
    user_id: str
    fingerprint: BehavioralFingerprint | None = None
    chain_fingerprint: BehavioralFingerprint | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[str]:
        return [f"{f.code}({f.severity}): {f.message}" for f in self.arguments.findings]


class BehaviorPipeline:
    """Wires the behavior-side analyzers together."""

    def __init__(
        self,
        config: ASLConfig | None = None,
        graph_builder: BehaviorGraphBuilder | None = None,
    ) -> None:
        self.config = config or get_config()
        self.tool_analyzer = ToolAnalyzer(self.config)
        self.argument_analyzer = ArgumentAnalyzer(self.config)
        self.capability_extractor = CapabilityExtractor()
        self.graph = graph_builder or BehaviorGraphBuilder()
        self.fingerprints = FingerprintGenerator(self.config)

    def process(
        self,
        invocation: ToolInvocation,
        session_id: str,
        user_id: str,
        chain_window: int | None = None,
    ) -> CallInsight:
        profile, known, _ = self.tool_analyzer.profile_for(invocation.tool_name)
        tool_analysis = self.tool_analyzer.analyze(invocation)
        argument_analysis = self.argument_analyzer.analyze(invocation, profile)
        capability_assessment = self.capability_extractor.extract(tool_analysis, argument_analysis)

        provisional = self.provisional_risk(tool_analysis, argument_analysis, capability_assessment)
        node_id = self.graph.add_invocation(
            session_id=session_id,
            user_id=user_id,
            invocation=invocation,
            tool_analysis=tool_analysis,
            capability_assessment=capability_assessment,
            argument_analysis=argument_analysis,
            risk=provisional,
            confidence=capability_assessment.confidence,
        )

        insight = CallInsight(
            invocation=invocation,
            tool=tool_analysis,
            arguments=argument_analysis,
            capabilities=capability_assessment,
            node_id=node_id,
            provisional_risk=provisional,
            session_id=session_id,
            user_id=user_id,
        )
        insight.fingerprint = self.fingerprints.generate(self.graph.snapshot(session_id, window=1))
        insight.chain_fingerprint = self.fingerprints.generate(
            self.graph.snapshot(session_id, window=chain_window)
        )
        if not known:
            insight.notes.append("tool is not in the registry; profile inferred from its name")
        if capability_assessment.escalations:
            insight.notes.append(
                "arguments unlock capabilities the tool profile does not declare: "
                + ", ".join(c.value for c in capability_assessment.escalations)
            )
        return insight

    def provisional_risk(
        self,
        tool: ToolAnalysis,
        arguments: ArgumentAnalysis,
        capabilities: CapabilityAssessment,
    ) -> float:
        """Placeholder for the phase-10 risk engine.

        Argument evidence outweighs tool metadata, because what a tool is
        *being asked to do* is more informative than what it *could* do - that
        is the whole reason `filesystem.delete("temp.txt")` and
        `filesystem.delete("/production/")` must not score the same.  Capability
        weight adds a small premium for raw destructive power.  Real fusion
        (intent, chain, trust, anomaly, history) replaces this in phase 10.
        """
        blended = 0.4 * tool.risk + 0.6 * arguments.risk + 0.05 * capabilities.weight
        return round(min(100.0, blended), 2)
