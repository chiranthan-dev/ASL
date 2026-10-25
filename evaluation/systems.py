"""The four systems compared in the evaluation (spec: EVALUATION).

    1. NoASL              the agent with nothing in front of it
    2. StaticRules        a conventional tool-name allow/deny policy
    3. ASLWithoutFingerprints   full ASL minus behavioural memory  ← the ablation
    4. FullASL            everything

System 3 is the whole point. It differs from system 4 in exactly two ways: the
fast path is disabled, and the fingerprint signal is pinned to a constant so
history cannot inform risk. Every analyzer, weight and threshold is otherwise
identical, so the difference between 3 and 4 is attributable to behavioural
fingerprinting and to nothing else.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.config import ASLConfig
from app.core.engine import ASLEngine
from app.models.enums import Decision, Environment
from app.models.tool_call import EvaluationRequest, ToolInvocation
from app.trust.fingerprint_store import FingerprintStore
from evaluation.corpus import EvalScenario

INTERVENED = {Decision.CHALLENGE, Decision.SANDBOX, Decision.BLOCK}


@dataclass
class Outcome:
    """One system's verdict on one scenario."""

    scenario_id: str
    category: str
    harmful: bool
    decision: Decision
    risk_score: float = 0.0
    latency_ms: float = 0.0
    fast_path: bool = False
    fingerprint_hit: bool = False
    human_verification: bool = False
    tools: list[str] = field(default_factory=list)

    @property
    def intervened(self) -> bool:
        return self.decision in INTERVENED

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK


class EvaluatedSystem:
    """Common interface: judge a scenario, return an `Outcome`."""

    name = "system"
    description = ""

    def prepare(self) -> None:
        """Reset any learned state between full evaluation runs."""

    def close(self) -> None:
        """Release resources (open database handles) when the run is over."""

    def judge(self, scenario: EvalScenario) -> Outcome:
        raise NotImplementedError



class NoASL(EvaluatedSystem):
    """The baseline the whole field starts from: the agent just runs the tool."""

    name = "agent_without_asl"
    description = "no authorization layer; every proposed call executes"

    def judge(self, scenario: EvalScenario) -> Outcome:
        started = time.perf_counter()
        return Outcome(
            scenario_id=scenario.scenario_id, category=scenario.category, harmful=scenario.harmful,
            decision=Decision.ALLOW,
            latency_ms=round((time.perf_counter() - started) * 1000, 4),
        )



class StaticRules(EvaluatedSystem):
    """A conventional policy: deny by tool name, plus a keyword blocklist.

    This is a fair rendering of what most deployed agent stacks do today —
    per-tool allow/deny with a few string rules — and it is deliberately not a
    straw man: it blocks the genuinely dangerous tools outright and greps for
    the obvious dangerous strings.
    """

    name = "static_rules"
    description = "tool-name allow/deny list plus keyword matching on arguments"

    DENIED_TOOLS = {"shell.execute", "python.execute", "filesystem.delete", "database.delete"}
    CONFIRM_TOOLS = {"filesystem.write", "database.update", "database.insert", "gmail.send", "http.post"}
    DANGEROUS_STRINGS = re.compile(
        r"(?i)(rm\s+-rf|drop\s+table|/etc/(passwd|shadow)|\.ssh/|id_rsa|\.aws/credentials|"
        r"sudo|chmod\s+777|curl.*\|\s*(ba)?sh|webhook\.site|pastebin)"
    )

    def __init__(self, engine: ASLEngine) -> None:
        self.agent = engine.agent

    def judge(self, scenario: EvalScenario) -> Outcome:
        started = time.perf_counter()
        calls = scenario.tool_calls or [
            {"tool_name": c.tool_name, "arguments": c.arguments}
            for c in self.agent.plan(scenario.prompt).tool_calls
        ]

        decision = Decision.ALLOW
        for call in calls:
            blob = str(call.get("arguments", ""))
            if call["tool_name"] in self.DENIED_TOOLS or self.DANGEROUS_STRINGS.search(blob):
                decision = Decision.BLOCK
                break
            if call["tool_name"] in self.CONFIRM_TOOLS:
                decision = Decision.CHALLENGE

        return Outcome(
            scenario_id=scenario.scenario_id, category=scenario.category, harmful=scenario.harmful,
            decision=decision,
            latency_ms=round((time.perf_counter() - started) * 1000, 4),
            tools=[c["tool_name"] for c in calls],
        )



class ASLSystem(EvaluatedSystem):
    """Full ASL."""

    name = "asl_full"
    description = "every stage, fingerprint memory and fast path enabled"

    def __init__(self, config: ASLConfig, store_path: str) -> None:
        self.config = config
        self.store_path = store_path
        self.engine = self._build()

    def _build(self) -> ASLEngine:
        store = FingerprintStore(self.config, path=self.store_path)
        store.reset()
        return ASLEngine(config=self.config, store=store)

    def prepare(self) -> None:
        self.engine.reset()

    def close(self) -> None:
        self.engine.store.close()

    def judge(self, scenario: EvalScenario) -> Outcome:
        result = None
        for attempt in range(scenario.repeat):
            request = EvaluationRequest(
                user_id=scenario.user_id,
                prompt=scenario.prompt,
                tool_calls=[ToolInvocation(**c) for c in scenario.tool_calls],
                environment=Environment(scenario.environment),
                session_id=f"{scenario.scenario_id}_{attempt}",
            )
            result = self.engine.evaluate(request)
        assert result is not None

        worst = max(result.calls, key=lambda c: c.risk_score, default=None)
        return Outcome(
            scenario_id=scenario.scenario_id, category=scenario.category, harmful=scenario.harmful,
            decision=result.decision,
            risk_score=result.risk_score,
            latency_ms=result.latency_ms,
            fast_path=result.fast_path,
            fingerprint_hit=bool(worst and (worst.fingerprint_novelty or 1.0) < 0.5),
            human_verification=any(
                t.detail.get("human_verification") for t in result.trace if t.stage == "decision"
            ),
            tools=[c.tool_name for c in result.calls],
        )


class ASLWithoutFingerprints(ASLSystem):
    """The ablation: same pipeline, no behavioural memory.

    Two changes and nothing else:

    * the fast path is switched off, so repetition can never buy anything;
    * the fingerprint signal is pinned to a constant, so novelty and history
      cannot move the risk score in either direction.

    Whatever separates this from `ASLSystem` is what behavioural fingerprinting
    contributed.
    """

    name = "asl_without_fingerprints"
    description = "all analyzers, no fingerprint memory and no fast path"

    NEUTRAL_FINGERPRINT_RISK = 50.0

    def _build(self) -> ASLEngine:
        engine = super()._build()
        engine.config = self.config.with_overrides(fast_path_enabled=False)
        engine.fast_path.config = engine.config
        engine._fingerprint_risk = staticmethod(
            lambda context: ASLWithoutFingerprints.NEUTRAL_FINGERPRINT_RISK
        )
        return engine


def build_systems(config: ASLConfig, store_dir: str) -> list[EvaluatedSystem]:
    """The four systems, in reporting order."""
    full = ASLSystem(config, f"{store_dir}/eval_full.db")
    return [
        NoASL(),
        StaticRules(full.engine),
        ASLWithoutFingerprints(config, f"{store_dir}/eval_ablation.db"),
        full,
    ]
