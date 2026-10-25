"""ASL engine — the middleware itself.

Wires every stage together and records a `TraceEvent` for each one, so the same
run can be consumed three ways: as an authorization decision (the API), as an
explanation (the audit log), and as an animation (the inspector UI).

    prompt -> agent -> [ per tool call ]
        1 tool analyzer      5 fingerprint            9 environment
        2 argument analyzer  6 trust lookup          10 execution chain
        3 capabilities       7 anomaly detector      11 llm confidence
        4 behavior graph     8 fast path gate        12 risk fusion
                                                     13 decision
                                                     14 execute (mock)
                                                     15 audit + learning

Stages 9-11 and the intent/context analyzers are skipped on a fast path — and
recorded as skipped, so the saving is visible rather than implied.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from app.agent.mock_agent import AgentPlan, LLMAgent, MockAgent
from app.analyzers.anomaly_detector import AnomalyDetector, StatisticalAnomalyDetector
from app.analyzers.confidence import ConfidenceEstimator, MockLLMConfidenceEstimator
from app.analyzers.context_analyzer import ContextAnalyzer
from app.analyzers.environment_analyzer import EnvironmentAnalyzer, TrustAnalyzer
from app.analyzers.execution_chain import ExecutionChainAnalyzer
from app.analyzers.intent_analyzer import IntentAnalyzer
from app.analyzers.request_policy import (PolicyAssessment, PolicySeverity,
                                          RequestPolicyAnalyzer)
from app.audit.logger import AuditLogger
from app.behavior.graph_builder import BehaviorGraphBuilder
from app.core.config import ASLConfig, get_config
from app.core.decision_engine import DecisionEngine
from app.core.pipeline import BehaviorPipeline, CallInsight
from app.core.risk_engine import RiskFusionStrategy, build_signals, get_strategy
from app.models.context import AnalysisContext, SessionHistory
from app.models.decision import CallEvaluation, EvaluationResponse, TraceEvent
from app.models.enums import Capability, Decision, DecisionPath, Intent, NodeKind
from app.models.risk import RiskAssessment, RiskSignal
from app.models.tool_call import EvaluationRequest, ToolInvocation
from app.tools.mock_tools import MockToolbox
from app.trust.fast_path import FastPathEvaluator
from app.trust.fingerprint_store import FingerprintStore
from app.trust.trust_memory import TrustMemory


@dataclass
class _Tracer:
    """Collects stage events with timings."""

    events: list[TraceEvent] = field(default_factory=list)
    _clock: float = field(default_factory=time.perf_counter)

    def add(
        self,
        stage: str,
        title: str,
        summary: str,
        detail: dict[str, Any] | None = None,
        highlights: list[str] | None = None,
        status: str = "ok",
        call_id: str | None = None,
    ) -> TraceEvent:
        now = time.perf_counter()
        event = TraceEvent(
            index=len(self.events),
            stage=stage,
            title=title,
            status=status,
            summary=summary,
            detail=detail or {},
            highlights=highlights or [],
            duration_ms=round((now - self._clock) * 1000, 3),
            call_id=call_id,
        )
        self._clock = now
        self.events.append(event)
        return event


class ASLEngine:
    """Adaptive Security Layer: intercept, analyze, decide, learn."""

    def __init__(
        self,
        config: ASLConfig | None = None,
        store: FingerprintStore | None = None,
        agent: Any | None = None,
        fusion: RiskFusionStrategy | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        confidence_estimator: ConfidenceEstimator | None = None,
    ) -> None:
        self.config = config or get_config()
        self.store = store or FingerprintStore(self.config)
        self.graph = BehaviorGraphBuilder()
        self.pipeline = BehaviorPipeline(self.config, graph_builder=self.graph)
        self.trust = TrustMemory(self.store, self.config)
        self.fast_path = FastPathEvaluator(self.store, self.config)
        self.fusion = fusion or get_strategy(config=self.config)
        self.decisions = DecisionEngine(self.config)
        self.audit = AuditLogger(self.store, self.trust, self.config)
        self.agent = agent or self._default_agent()
        self.anomaly = anomaly_detector or StatisticalAnomalyDetector(self.store)
        self.confidence = confidence_estimator or MockLLMConfidenceEstimator()
        self.tools = MockToolbox()

        self.intent_analyzer = IntentAnalyzer()
        self.context_analyzer = ContextAnalyzer()
        self.environment_analyzer = EnvironmentAnalyzer(self.config)
        self.trust_analyzer = TrustAnalyzer(self.config)
        self.chain_analyzer = ExecutionChainAnalyzer()
        self.request_policy = RequestPolicyAnalyzer()

        self._histories: dict[str, SessionHistory] = {}

    # -- public API --------------------------------------------------------
    def evaluate(
        self, request: EvaluationRequest, executor: Callable[[ToolInvocation], Any] | None = None,
    ) -> EvaluationResponse:
        """Authorize every call in the request.

        `executor` runs an *allowed* call and returns a ToolResult. It defaults to the
        built-in mock toolbox; the gateway passes its own sandboxed executor so allowed
        calls act on a real (jailed) workspace and their output reaches the agent.
        """
        started = time.perf_counter()
        tracer = _Tracer()

        plan = self._plan(request, tracer)
        calls = request.tool_calls or plan.tool_calls

        # The request gate runs once per request, not per call: it judges the
        # *purpose*, and the purpose does not change between the tool calls that
        # serve it. It runs before any of them, because a prohibited request
        # should not be reachable no matter how innocuous its tool calls look.
        policy = self.request_policy.analyze(request.prompt, request.conversation)
        tracer.add(
            "request_policy",
            "0b. Request Policy Gate",
            policy.explanation,
            detail=policy.as_dict(),
            highlights=[policy.category] if policy.category else [],
            status={"NONE": "ok", "RESTRICTED": "warning", "PROHIBITED": "critical"}[policy.severity.value],
        )

        evaluations: list[CallEvaluation] = []
        for call in calls:
            evaluations.append(self._evaluate_call(call, request, tracer, policy, executor))

        decision = DecisionEngine.summarize([e.decision for e in evaluations])
        worst = max(evaluations, key=lambda e: e.risk_score, default=None)

        # A prohibited request is refused even when it produced no tool call at
        # all. Without this, "write me a keylogger" -- which the planner answers
        # from knowledge rather than by invoking anything -- returned ALLOW at
        # risk 0, because a decision was only ever derived from the calls. The
        # gate judges the request; it must not depend on the request having
        # reached for a tool.
        policy_refusal = policy is not None and policy.severity is PolicySeverity.PROHIBITED
        if policy_refusal:
            decision = Decision.BLOCK

        answer = self._compose_answer(request, plan, policy, evaluations, tracer)

        latency = round((time.perf_counter() - started) * 1000, 3)

        tracer.add(
            "session",
            "Session roll-up",
            f"{len(evaluations)} call(s) evaluated — strictest decision {decision.value}",
            detail={
                "decisions": [e.decision.value for e in evaluations],
                "risks": [e.risk_score for e in evaluations],
                "fast_path_calls": sum(1 for e in evaluations if e.fast_path),
                "latency_ms": latency,
            },
            status="critical" if decision is Decision.BLOCK else "ok",
        )

        return EvaluationResponse(
            decision=decision,
            risk_score=(max(worst.risk_score if worst else 0.0, policy.risk)
                        if policy_refusal else (worst.risk_score if worst else 0.0)),
            confidence=worst.confidence if worst else (policy.confidence if policy_refusal else 0.0),
            fast_path=all(e.fast_path for e in evaluations) if evaluations else False,
            fingerprint=worst.fingerprint if worst else None,
            signals=worst.signals if worst else {},
            explanation=(policy.explanation if policy_refusal and not worst
                         else worst.explanation if worst else "nothing to evaluate"),
            session_id=request.session_id,
            user_id=request.user_id,
            prompt=request.prompt,
            environment=request.environment,
            agent_reasoning=plan.reasoning,
            answer=answer,
            planner=plan.source,
            calls=evaluations,
            trace=tracer.events,
            latency_ms=latency,
        )

    def _default_agent(self) -> Any:
        """A deterministic mock by default; a live model when configured.

        `LLMAgent` falls back to `MockAgent` on any error, so selecting it here
        never risks the pipeline even if no model server is reachable.
        """
        if self.config.mock_llm:
            return MockAgent()
        return LLMAgent(
            base_url=self.config.llm_base_url,
            model=self.config.llm_model,
            api_key=self.config.llm_api_key or None,
            timeout=self.config.llm_timeout_s,
        )

    def reset(self) -> None:
        """Forget everything learned (demo button / test isolation)."""
        self.store.reset()
        self.graph.reset()
        self.tools.reset()
        self._histories.clear()

    # -- stages ------------------------------------------------------------
    def _plan(self, request: EvaluationRequest, tracer: _Tracer) -> AgentPlan:
        if request.tool_calls:
            plan = AgentPlan(
                tool_calls=list(request.tool_calls),
                reasoning="tool calls supplied directly by the caller; no agent planning needed",
                matched_rules=["explicit"],
                source="caller",
            )
        else:
            plan = self.agent.plan(request.prompt)
        if plan.source.startswith("llm:"):
            who = plan.source[4:]
        elif plan.source == "mock-fallback":
            who = "mock fallback: model unreachable"
        elif plan.source == "caller":
            who = "calls supplied by caller"
        else:
            who = "mock"
        tracer.add(
            "agent",
            f"0. LLM Agent ({who})",
            f"proposed {len(plan.tool_calls)} tool call(s)",
            detail=plan.as_dict(),
            highlights=[c.tool_name for c in plan.tool_calls],
        )
        return plan

    def _compose_answer(
        self, request: EvaluationRequest, plan: AgentPlan, policy: PolicyAssessment,
        evaluations: list[CallEvaluation], tracer: _Tracer,
    ) -> str:
        """Let a live model write the reply, from what was actually authorized.

        Only a live model composes; the mock's replies are templated in the UI.
        Nothing is composed when the request gate flagged the purpose: the gate's
        refusal stands on its own, and asking a model to write a reply to a
        prohibited request would hand it exactly the request the gate refused.
        """
        if not plan.source.startswith("llm:") or policy.severity is not PolicySeverity.NONE:
            return ""
        if not evaluations:
            return plan.answer
        compose = getattr(self.agent, "compose", None)
        if compose is None:
            return ""
        executed = {e.call_id: e.detail for e in tracer.events if e.stage == "execute"}
        outcomes = []
        for ev in evaluations:
            run = executed.get(ev.call_id) or {}
            ran = bool(run.get("ok"))
            outcome = {"tool": ev.tool_name, "verdict": ev.decision.value, "executed": ran}
            if ran:
                # Only the output: a small model recites whatever it is shown, and
                # risk scores are the UI's job, not the reply's.
                outcome["output"] = run.get("output")
            else:
                outcome["why_not_run"] = (ev.explanation or run.get("error") or run.get("reason") or "")[:240]
            outcomes.append(outcome)
        return compose(request.prompt, outcomes)

    def _evaluate_call(
        self, call: ToolInvocation, request: EvaluationRequest, tracer: _Tracer,
        policy: PolicyAssessment | None = None,
        executor: Callable[[ToolInvocation], Any] | None = None,
    ) -> CallEvaluation:
        call_started = time.perf_counter()
        history = self._histories.setdefault(
            request.session_id, SessionHistory(started_at=time.time())
        )

        # --- stages 1-5: behavior pipeline ------------------------------
        insight = self.pipeline.process(call, request.session_id, request.user_id)
        self._trace_behavior_stages(insight, tracer)

        # --- stage 6: fingerprint trust lookup --------------------------
        # Authorization memory is keyed on what *this call* does, never on the
        # session's running chain. Keying it on the chain looked appealing --
        # it makes a repeated workflow cheap -- but it is wrong: the chain grows
        # with every turn, so the same action repeated three times in one
        # conversation produced three different keys and the layer forgot a
        # behaviour it had seen 944 times. Familiarity has to attach to the act.
        #
        # The chain is not discarded. It is still recorded by the audit learner
        # (workflow-level memory) and it is still what the execution-chain
        # analyzer reads to catch a sequence of individually innocent steps.
        # It contributes as a *signal*; it is not the identity of this call.
        match = self.store.find_best_match(insight.fingerprint, request.user_id)
        chain_match = (
            self.store.find_best_match(insight.chain_fingerprint, request.user_id)
            if len(insight.chain_fingerprint.steps) > 1 else None
        )
        user_state = self.trust.state(request.user_id)
        context = AnalysisContext(
            invocation=call,
            tool=insight.tool,
            arguments=insight.arguments,
            capabilities=insight.capabilities,
            fingerprint=insight.fingerprint,
            chain_fingerprint=insight.chain_fingerprint,
            match=match,
            user=user_state,
            history=history,
            prompt=request.prompt,
            conversation=request.conversation,
            environment=request.environment,
            session_id=request.session_id,
            device_id=request.device_id,
            policy_version=request.policy_version,
            transitions=list(insight.chain_fingerprint.transitions),
        )
        if policy is not None and policy.fired:
            context.extras["policy_severity"] = policy.severity.value
            context.extras["policy_category"] = policy.category
            context.extras["policy_explanation"] = policy.explanation
        # Is this behaviour one the store has literally never held before? The
        # query fingerprint is not written until the learning step at the end of
        # the request, so an absent row here means genuinely first contact --
        # which is the state the UI surfaces as "new fingerprint".
        first_seen = self.store.get(match.query_fingerprint_id) is None
        tracer.add(
            "trust_lookup",
            "6. Fingerprint Trust Engine",
            match.explanation,
            detail={
                "first_seen": first_seen,
                "query_fingerprint": match.query_fingerprint_id,
                "matched_fingerprint": match.matched_fingerprint_id,
                "similarity": match.similarity_score,
                "novelty": match.novelty_score,
                "historical_risk": match.historical_risk,
                "confidence": match.confidence,
                "occurrences": match.occurrence_count,
                "previous_outcome": match.previous_outcome,
                "known_fingerprints": self.store.count(),
                "user": self.trust.describe(user_state),
                # The session's running sequence, reported alongside but kept out
                # of this call's identity. A novel *chain* of familiar acts is a
                # reason to look harder, not a reason to forget the acts.
                "chain_fingerprint": (chain_match.query_fingerprint_id
                                      if chain_match else None),
                "chain_steps": len(insight.chain_fingerprint.steps),
                "chain_first_seen": (
                    self.store.get(chain_match.query_fingerprint_id) is None
                    if chain_match else None),
                "chain_occurrences": chain_match.occurrence_count if chain_match else None,
            },
            highlights=[f"novelty {match.novelty_score:.0%}", f"similarity {match.similarity_score:.2f}"],
            status="warning" if match.novelty_score > 0.5 else "ok",
            call_id=call.call_id,
        )

        # --- stage 7: anomaly detection (cheap, needed by the fast path) --
        anomaly = self.anomaly.score(context)
        context.extras["anomaly_flag"] = anomaly.anomalous
        context.extras["anomaly_detail"] = "; ".join(anomaly.reasons[:2])
        tracer.add(
            "anomaly",
            "7. Anomaly Detector",
            f"anomaly score {anomaly.score:.0f}" + (" — flagged" if anomaly.anomalous else ""),
            detail={"score": anomaly.score, "anomalous": anomaly.anomalous,
                    "reasons": anomaly.reasons, **anomaly.detail},
            highlights=anomaly.reasons[:2],
            status="warning" if anomaly.anomalous else "ok",
            call_id=call.call_id,
        )

        # --- stage 8: fast path gate -------------------------------------
        verdict = self.fast_path.evaluate(context)
        tracer.add(
            "fast_path",
            "8. Fast Path Gate",
            verdict.reason,
            detail=verdict.as_dict(),
            highlights=["FAST_PATH_ALLOW" if verdict.eligible else "FULL_ASL_ANALYSIS"],
            status="ok" if verdict.eligible else "warning",
            call_id=call.call_id,
        )

        if verdict.eligible:
            assessment = RiskAssessment(
                risk_score=match.historical_risk,
                confidence=match.confidence,
                strategy="fast-path",
                signals=[RiskSignal(name="fingerprint", value=match.historical_risk,
                                    confidence=match.confidence,
                                    detail="validated behaviour, expensive analysis skipped")],
                capabilities=sorted(context.capability_set, key=lambda c: c.value),
                # Carry the existing history forward unchanged, on *both* keys.
                # A fast-pathed run learns nothing new about the behaviour — it
                # skipped the analysis — so recording a fresh number would let
                # repetition quietly launder a behaviour's risk toward zero.
                # `call_risk` must be set explicitly: left at its default it
                # records 0.0 for every fast-pathed run, which is that same
                # laundering, and it makes the fast path progressively easier to
                # obtain the more it is used.
                behavioural_risk=match.historical_risk,
                call_risk=match.historical_risk,
                explanation=verdict.reason,
            )
            decision = self.decisions.fast_path_decision(context, match.historical_risk, match.confidence)
            for stage, title in (
                ("intent", "4. Intent Analyzer"), ("context", "9. Context Analyzer"),
                ("environment", "10. Environment Analyzer"), ("user_trust", "11. User Trust"),
                ("execution_chain", "12. Execution Chain"), ("llm_confidence", "13. LLM Confidence"),
                ("risk_engine", "14. Adaptive Risk Engine"),
            ):
                tracer.add(stage, title, "skipped: fast path", status="skipped", call_id=call.call_id)
            intent = Intent.UNKNOWN
        else:
            assessment, intent = self._full_analysis(context, anomaly, tracer, call, policy)
            decision = self.decisions.decide(assessment, context)

        tracer.add(
            "decision",
            "15. Decision Engine",
            f"{decision.decision.value} at risk {decision.risk_score:.0f}",
            detail={
                "decision": decision.decision.value,
                "risk_score": decision.risk_score,
                "confidence": decision.confidence,
                "path": decision.path.value,
                "bands": {
                    "ALLOW": f"< {self.config.risk_allow_threshold}",
                    "ALLOW_WITH_LOG": f"{self.config.risk_allow_threshold}-{self.config.risk_log_threshold}",
                    "CHALLENGE": f"{self.config.risk_log_threshold}-{self.config.risk_challenge_threshold}",
                    "SANDBOX": f"{self.config.risk_challenge_threshold}-{self.config.risk_sandbox_threshold}",
                    "BLOCK": f">= {self.config.risk_sandbox_threshold}",
                },
                "human_verification": decision.human_verification_required,
                "human_verification_reasons": decision.human_verification_reasons,
                "explanation": decision.explanation,
            },
            highlights=[decision.decision.value] + decision.human_verification_reasons[:2],
            status="critical" if decision.decision is Decision.BLOCK else (
                "warning" if decision.decision in (Decision.SANDBOX, Decision.CHALLENGE) else "ok"),
            call_id=call.call_id,
        )

        # --- stage 16: execution (mock) -----------------------------------
        outcome = self._maybe_execute(call, decision.decision, tracer, executor)

        # --- stage 17: audit + learning -----------------------------------
        latency = round((time.perf_counter() - call_started) * 1000, 3)
        record = self.audit.record(context, assessment, decision, latency,
                                   outcome=outcome, anomalous=anomaly.anomalous)
        stored = self.store.get(context.fingerprint.fingerprint_id)
        tracer.add(
            "audit",
            "17. Audit & Learning",
            f"recorded {record.audit_id}; fingerprint now seen {stored.occurrence_count if stored else 1}x",
            detail={
                "audit_id": record.audit_id,
                "fingerprint_id": context.fingerprint.fingerprint_id,
                "occurrence_count": stored.occurrence_count if stored else 1,
                "fingerprint_confidence": stored.confidence if stored else 0.0,
                "historical_risk": stored.historical_risk if stored else decision.risk_score,
                "successful_executions": stored.successful_executions if stored else 0,
                "blocked_executions": stored.blocked_executions if stored else 0,
                "user_trust": self.trust.state(request.user_id).trust_score,
                "outcome": outcome,
            },
            highlights=[
                f"seen {stored.occurrence_count if stored else 1}x",
                f"fp confidence {stored.confidence if stored else 0:.2f}",
            ],
            call_id=call.call_id,
        )

        history.call_count += 1
        history.capability_sequence.append(sorted(context.capability_set, key=lambda c: c.value))
        history.risk_scores.append(decision.risk_score)
        history.decisions.append(decision.decision.value)
        history.tools.append(call.tool_name)
        history.resource_classes.extend(
            r.resource_class.value for r in context.arguments.resources)

        return CallEvaluation(
            call_id=call.call_id,
            tool_name=call.tool_name,
            decision=decision.decision,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            fast_path=verdict.eligible,
            fingerprint=context.fingerprint.fingerprint_id,
            # The session's running sequence. Distinct from `fingerprint`, which
            # is this one call and is what the trust lookup is keyed on.
            chain_fingerprint=context.chain_fingerprint.fingerprint_id,
            fingerprint_novelty=match.novelty_score,
            capabilities=sorted(context.capability_set, key=lambda c: c.value),
            intent=intent,
            signals=assessment.signal_map(),
            findings=[f"{f.code}: {f.message}" for f in context.arguments.findings],
            explanation=decision.explanation,
            latency_ms=latency,
            risk_assessment=assessment,
        )

    # -- helpers -----------------------------------------------------------
    def _trace_behavior_stages(self, insight: CallInsight, tracer: _Tracer) -> None:
        call_id = insight.invocation.call_id
        tool = insight.tool
        tracer.add(
            "tool_analyzer",
            "1. Tool Analyzer",
            f"{tool.category.value.lower()} tool, sensitivity {tool.sensitivity}, static risk {tool.risk:.0f}",
            detail={
                "tool_name": tool.tool_name,
                "category": tool.category.value,
                "sensitivity": tool.sensitivity,
                "capabilities": [c.value for c in tool.capabilities],
                "risk": tool.risk,
                "confidence": tool.confidence,
                "known_tool": tool.known_tool,
                "reversible": tool.reversible,
                "explanation": tool.explanation,
            },
            highlights=[c.value for c in tool.capabilities],
            status="warning" if not tool.known_tool else "ok",
            call_id=call_id,
        )

        arguments = insight.arguments
        tracer.add(
            "argument_analyzer",
            "2. Argument Analyzer",
            f"{arguments.analyzer} analyzer: risk {arguments.risk:.0f}, scope {arguments.scope.value}",
            detail={
                "analyzer": arguments.analyzer,
                "arguments": insight.invocation.arguments,
                "risk": arguments.risk,
                "confidence": arguments.confidence,
                "scope": arguments.scope.value,
                "parse_ok": arguments.parse_ok,
                "findings": [
                    {"code": f.code, "severity": f.severity.value, "message": f.message,
                     "evidence": f.evidence}
                    for f in arguments.findings
                ],
                "resources": [
                    {"class": r.resource_class.value, "scope": r.scope.value,
                     "identifier": r.identifier, "sensitive": r.sensitive}
                    for r in arguments.resources
                ],
                "explanation": arguments.explanation,
            },
            highlights=[f.code for f in arguments.findings[:4]],
            status="critical" if arguments.risk >= 80 else ("warning" if arguments.risk >= 45 else "ok"),
            call_id=call_id,
        )

        capabilities = insight.capabilities
        tracer.add(
            "capability_extractor",
            "3. Capability Extractor",
            "+".join(c.value for c in capabilities.capabilities) or "no capabilities",
            detail={
                "capabilities": [c.value for c in capabilities.capabilities],
                "from_tool": [c.value for c in capabilities.from_tool],
                "from_arguments": [c.value for c in capabilities.from_arguments],
                "escalations": [c.value for c in capabilities.escalations],
                "weight": capabilities.weight,
                "confidence": capabilities.confidence,
                "explanation": capabilities.explanation,
            },
            highlights=([f"escalation: {c.value}" for c in capabilities.escalations]
                        or [c.value for c in capabilities.capabilities[:4]]),
            status="warning" if capabilities.escalations else "ok",
            call_id=call_id,
        )

        snapshot = self.graph.snapshot(insight.session_id)
        tracer.add(
            "behavior_graph",
            "4. Behavior Graph",
            f"{len(snapshot.nodes)} nodes, {len(snapshot.edges)} edges in this session",
            detail={
                "nodes": [
                    {"id": n.node_id, "kind": n.kind.value, "label": n.label, "tool": n.tool,
                     "risk": n.risk, "scope": n.scope.value,
                     "resource_class": n.resource_class.value if n.resource_class else None}
                    for n in snapshot.nodes
                ],
                "edges": [
                    {"source": e.source, "target": e.target, "type": e.edge_type.value, "weight": e.weight}
                    for e in snapshot.edges
                ],
                "capability_sequence": [[c.value for c in step] for step in snapshot.capability_sequence],
                "current_node": insight.node_id,
            },
            highlights=[
                " -> ".join("+".join(c.value for c in step) for step in snapshot.capability_sequence[-3:])
            ],
            call_id=call_id,
        )

        fingerprint = insight.chain_fingerprint
        tracer.add(
            "fingerprint",
            "5. Fingerprint Generator",
            fingerprint.canonical_representation,
            detail={
                "fingerprint_id": insight.fingerprint.fingerprint_id,
                "chain_fingerprint_id": fingerprint.fingerprint_id,
                "canonical_representation": fingerprint.canonical_representation,
                "graph_hash": fingerprint.graph_hash,
                "steps": fingerprint.steps,
                "transitions": fingerprint.transitions,
                "capabilities": [c.value for c in fingerprint.capabilities],
                "max_scope": fingerprint.max_scope.value,
            },
            highlights=[insight.fingerprint.fingerprint_id] + fingerprint.transitions[:2],
            call_id=call_id,
        )

    def _full_analysis(
        self, context: AnalysisContext, anomaly: Any, tracer: _Tracer, call: ToolInvocation,
        policy: PolicyAssessment | None = None,
    ) -> tuple[RiskAssessment, Intent]:
        intent, intent_risk, intent_confidence, intent_explanation = self.intent_analyzer.analyze(context)
        tracer.add(
            "intent", "4b. Intent Analyzer",
            f"{intent.value} (risk {intent_risk:.0f})",
            detail={"intent": intent.value, "risk": intent_risk,
                    "confidence": intent_confidence, "explanation": intent_explanation},
            highlights=[intent.value],
            status="critical" if intent_risk >= 85 else ("warning" if intent_risk >= 50 else "ok"),
            call_id=call.call_id,
        )

        ctx_risk, ctx_confidence, ctx_explanation, ctx_detail = self.context_analyzer.analyze(context)
        tracer.add(
            "context", "9. Context Analyzer", ctx_explanation,
            detail={"risk": ctx_risk, "confidence": ctx_confidence, **ctx_detail},
            highlights=ctx_detail.get("unexplained_capabilities", [])[:3],
            status="warning" if ctx_risk >= 45 else "ok",
            call_id=call.call_id,
        )

        env_risk, env_confidence, env_explanation, env_detail = self.environment_analyzer.analyze(context)
        tracer.add(
            "environment", "10. Environment Analyzer", env_explanation,
            detail={"risk": env_risk, "confidence": env_confidence, **env_detail},
            highlights=[context.environment.value],
            status="warning" if env_risk >= 55 else "ok",
            call_id=call.call_id,
        )

        trust_risk, trust_confidence, trust_explanation, trust_detail = self.trust_analyzer.analyze(context)
        tracer.add(
            "user_trust", "11. User Trust Manager", trust_explanation,
            detail={"risk": trust_risk, "confidence": trust_confidence, **trust_detail},
            highlights=[f"trust {context.user.trust_score:.2f}"],
            call_id=call.call_id,
        )

        chain = self.chain_analyzer.analyze(context)
        tracer.add(
            "execution_chain", "12. Execution Chain Analyzer", chain.explanation,
            detail={"risk": chain.risk, "confidence": chain.confidence, **chain.detail},
            highlights=chain.matched[:3],
            status="critical" if chain.risk >= 85 else ("warning" if chain.risk >= 50 else "ok"),
            call_id=call.call_id,
        )

        estimate = self.confidence.estimate(context)
        tracer.add(
            "llm_confidence", "13. LLM Confidence Estimator",
            f"confidence {estimate.confidence:.2f} ({estimate.source})",
            detail={"confidence": estimate.confidence, "risk": estimate.risk_contribution,
                    "explanation": estimate.explanation, "source": estimate.source, **estimate.detail},
            highlights=[f"{estimate.confidence:.2f}"],
            status="warning" if estimate.confidence < 0.55 else "ok",
            call_id=call.call_id,
        )

        signals = build_signals(context, {
            "tool": (context.tool.risk, context.tool.confidence, context.tool.explanation),
            "argument": (context.arguments.risk, context.arguments.confidence, context.arguments.explanation),
            "capability": (context.capabilities.weight, context.capabilities.confidence,
                           context.capabilities.explanation),
            "intent": (intent_risk, intent_confidence, intent_explanation),
            "fingerprint": (self._fingerprint_risk(context), max(0.3, context.match.confidence or 0.3),
                            context.match.explanation),
            "context": (ctx_risk, ctx_confidence, ctx_explanation),
            "environment": (env_risk, env_confidence, env_explanation),
            "user_trust": (trust_risk, trust_confidence, trust_explanation),
            "execution_chain": (chain.risk, chain.confidence, chain.explanation),
            "anomaly": (anomaly.score, anomaly.confidence, "; ".join(anomaly.reasons[:2])),
            "llm_confidence": (estimate.risk_contribution, estimate.confidence, estimate.explanation),
        }, self.config)

        # Only emitted when it fired: a zero-valued signal on every benign
        # request would drag the whole baseline down and flatter ordinary work.
        if policy is not None and policy.fired:
            signals.extend(build_signals(context, {
                "request_policy": (policy.risk, policy.confidence, policy.explanation),
            }, self.config))

        assessment = self.fusion.fuse(signals, context)
        tracer.add(
            "risk_engine", "14. Adaptive Risk Engine",
            assessment.explanation,
            detail={
                "strategy": assessment.strategy,
                "risk_score": assessment.risk_score,
                "confidence": assessment.confidence,
                "disagreement": assessment.disagreement,
                "invariants": assessment.invariants,
                "signals": [
                    {"name": s.name, "value": s.value, "weight": s.weight,
                     "confidence": s.confidence, "detail": s.detail}
                    for s in assessment.signals
                ],
            },
            highlights=[f"risk {assessment.risk_score:.0f}"] + assessment.invariants[:2],
            status="critical" if assessment.risk_score >= 90 else (
                "warning" if assessment.risk_score >= 50 else "ok"),
            call_id=call.call_id,
        )
        return assessment, intent

    @staticmethod
    def _fingerprint_risk(context: AnalysisContext) -> float:
        """Novelty *amplifies* severity rather than creating it.

        A never-before-seen image search and a never-before-seen production
        wipe are equally novel, and it would be absurd to score them alike.
        So novelty scales the action's own severity (capability weight and
        analysed argument risk), and past bad history sets a floor underneath.
        """
        novelty = context.match.novelty_score
        severity = 0.5 * context.capabilities.weight + 0.5 * context.arguments.risk
        return round(min(100.0, max(context.match.historical_risk, novelty * severity)), 2)

    def _maybe_execute(
        self, call: ToolInvocation, decision: Decision, tracer: _Tracer,
        executor: Callable[[ToolInvocation], Any] | None = None,
    ) -> str | None:
        if decision in (Decision.ALLOW, Decision.ALLOW_WITH_LOG):
            result = (executor or self.tools.execute)(call)
            tracer.add(
                "execute", "16. Tool Execution (mock)",
                f"{call.tool_name} executed against mock state" if result.ok else f"failed: {result.error}",
                detail={"ok": result.ok, "output": result.output, "error": result.error,
                        "simulated": result.simulated},
                highlights=["executed" if result.ok else "failed"],
                status="ok" if result.ok else "warning",
                call_id=call.call_id,
            )
            return "success" if result.ok else "failure"

        reason = {
            Decision.CHALLENGE: "held for user confirmation",
            Decision.SANDBOX: "would run in a constrained sandbox",
            Decision.BLOCK: "refused",
        }[decision]
        tracer.add(
            "execute", "16. Tool Execution (mock)", f"not executed: {reason}",
            detail={"executed": False, "reason": reason},
            highlights=["not executed"],
            status="critical" if decision is Decision.BLOCK else "warning",
            call_id=call.call_id,
        )
        return "not_executed"

    # -- inspection --------------------------------------------------------
    def fingerprints(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            {
                "fingerprint_id": f.fingerprint_id,
                "canonical_representation": f.canonical_representation,
                "graph_hash": f.graph_hash,
                "capabilities": [c.value for c in f.capabilities],
                "steps": f.steps,
                "max_scope": f.max_scope.value,
                "occurrence_count": f.occurrence_count,
                "historical_risk": f.historical_risk,
                "successful_executions": f.successful_executions,
                "blocked_executions": f.blocked_executions,
                "confidence": f.confidence,
                "created_at": f.created_at.isoformat(),
                "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            }
            for f in self.store.all(limit)
        ]

    def session_graph(self, session_id: str) -> dict[str, Any]:
        snapshot = self.graph.snapshot(session_id)
        return {
            "session_id": session_id,
            "nodes": [
                {"id": n.node_id, "kind": n.kind.value, "label": n.label, "tool": n.tool,
                 "risk": n.risk, "capability": n.capability.value if n.capability else None,
                 "resource_class": n.resource_class.value if n.resource_class else None}
                for n in snapshot.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "type": e.edge_type.value}
                for e in snapshot.edges
            ],
        }
