"""Audit & Learning (spec section 17).

Two jobs, deliberately in one place because they must not diverge:

* **Audit** — write an immutable record of every decision with the signals that
  produced it, so any decision can be reconstructed later.
* **Learning** — fold the same event into the fingerprint statistics and the
  user's trust record, which is what makes the next evaluation cheaper (or
  stricter).

Learning is intentionally conservative: a decision teaches the system that this
behaviour *was judged*, never that it is *safe*. Only genuine allows raise a
fingerprint's confidence, and any block leaves a permanent mark.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.config import ASLConfig, get_config
from app.models.context import AnalysisContext
from app.models.decision import AuditRecord, DecisionResult
from app.models.enums import Decision
from app.models.risk import RiskAssessment
from app.trust.fingerprint_store import FingerprintStore
from app.trust.trust_memory import TrustMemory


class AuditLogger:
    def __init__(
        self,
        store: FingerprintStore,
        trust: TrustMemory,
        config: ASLConfig | None = None,
    ) -> None:
        self.store = store
        self.trust = trust
        self.config = config or get_config()
        self.recent_records: list[AuditRecord] = []

    def record(
        self,
        context: AnalysisContext,
        assessment: RiskAssessment,
        decision: DecisionResult,
        latency_ms: float,
        outcome: str | None = None,
        anomalous: bool = False,
    ) -> AuditRecord:
        record = AuditRecord(
            user_id=context.user.user_id,
            session_id=context.session_id,
            environment=context.environment,
            tool_name=context.invocation.tool_name,
            capabilities=sorted(context.capability_set, key=lambda c: c.value),
            fingerprint_id=context.fingerprint.fingerprint_id,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            decision=decision.decision,
            path=decision.path,
            signals=assessment.signal_map(),
            explanation=decision.explanation,
            outcome=outcome,
            latency_ms=round(latency_ms, 3),
        )

        self.store.write_audit({
            "audit_id": record.audit_id,
            "timestamp": record.timestamp.isoformat(),
            "user_id": record.user_id,
            "session_id": record.session_id,
            "environment": record.environment.value,
            "tool_name": record.tool_name,
            "capabilities": ",".join(c.value for c in record.capabilities),
            "fingerprint_id": record.fingerprint_id,
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "decision": record.decision.value,
            "path": record.path.value,
            "signals": json.dumps(record.signals),
            "explanation": record.explanation,
            "outcome": record.outcome,
            "latency_ms": record.latency_ms,
        })

        self.learn(context, decision, assessment, outcome=outcome, anomalous=anomalous)

        self.recent_records.append(record)
        del self.recent_records[:-200]
        return record

    def learn(
        self,
        context: AnalysisContext,
        decision: DecisionResult,
        assessment: RiskAssessment | None = None,
        outcome: str | None = None,
        anomalous: bool = False,
    ) -> None:
        """Update fingerprint statistics and user trust from one decision.

        The fingerprint records `behavioural_risk` — what the *action* was
        worth — while the audit row keeps the fully modulated score. Mixing the
        two would let a stranger's first visit permanently inflate the record
        of an otherwise ordinary behaviour.
        """
        behavioural = assessment.behavioural_risk if assessment else decision.risk_score
        per_call = assessment.call_risk if assessment else decision.risk_score
        self.store.record_observation(
            context.fingerprint,
            user_id=context.user.user_id,
            session_id=context.session_id,
            environment=context.environment.value,
            risk_score=per_call,
            confidence=decision.confidence,
            decision=decision.decision,
            path=decision.path.value,
            outcome=outcome,
        )
        if len(context.chain_fingerprint.steps) > 1:
            self.store.record_observation(
                context.chain_fingerprint,
                user_id=context.user.user_id,
                session_id=context.session_id,
                environment=context.environment.value,
                risk_score=behavioural,
                confidence=decision.confidence,
                decision=decision.decision,
                path=decision.path.value,
                outcome=outcome,
            )
        self.trust.record(context.user.user_id, decision.decision, anomalous=anomalous)

    def entries(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.store.audit_entries(limit)

    def statistics(self) -> dict[str, Any]:
        entries = self.store.audit_entries(500)
        if not entries:
            return {"decisions": {}, "total": 0, "recent_window": 0,
                    "fast_path_rate": 0.0, "mean_latency_ms": 0.0, "blocked": 0}
        counts: dict[str, int] = {}
        for entry in entries:
            counts[entry["decision"]] = counts.get(entry["decision"], 0) + 1
        fast = sum(1 for e in entries if e["path"] == "FAST_PATH_ALLOW")
        return {
            "decisions": counts,
            "total": self.store.audit_count(),
            "recent_window": len(entries),
            "fast_path_rate": round(fast / len(entries), 4),
            "mean_latency_ms": round(sum(e["latency_ms"] for e in entries) / len(entries), 3),
            "blocked": counts.get(Decision.BLOCK.value, 0),
        }
