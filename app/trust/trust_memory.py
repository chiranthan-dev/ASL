"""User Trust Manager (spec section 10).

Trust is asymmetric on purpose: it is earned slowly and lost quickly, because
the cost of wrongly trusting a compromised account is much higher than the cost
of making a good user wait for one more check.

Trust is an *input* to risk, never an override.  The risk engine caps how much
risk trust may subtract (`user_trust_max_risk_reduction`) and refuses to apply
it at all where an invariant floor has fired.
"""

from __future__ import annotations

from app.core.config import ASLConfig, get_config
from app.models.context import UserState
from app.models.enums import Decision
from app.trust.fingerprint_store import FingerprintStore

TRUST_GAIN_PER_SUCCESS = 0.02
#: A refusal is serious: we declined to do what the account asked for.
TRUST_LOSS_PER_BLOCK = 0.25
#: Diverted into a sandbox -- uncertain, but contained and not refused.
TRUST_LOSS_PER_SANDBOX = 0.05
#: Referred to a human. This is the layer working as intended, not a strike
#: against the account, so it costs half of what one clean action earns.
TRUST_LOSS_PER_CHALLENGE = 0.01
TRUST_LOSS_PER_ANOMALY = 0.10
TRUST_FLOOR = 0.05
TRUST_CEILING = 0.95


class TrustMemory:
    """Reads and updates the per-user trust record."""

    def __init__(self, store: FingerprintStore, config: ASLConfig | None = None) -> None:
        self.store = store
        self.config = config or get_config()

    def state(self, user_id: str) -> UserState:
        row = self.store.user_row(user_id)
        if row is None:
            return UserState(user_id=user_id, trust_score=self.config.user_trust_initial, known=False)
        return UserState(
            user_id=user_id,
            trust_score=float(row["trust_score"]),
            successful_actions=int(row["successful_actions"]),
            blocked_actions=int(row["blocked_actions"]),
            anomalies=int(row["anomalies"]),
            known=True,
        )

    def record(self, user_id: str, decision: Decision, anomalous: bool = False) -> UserState:
        state = self.state(user_id)
        trust = state.trust_score
        successes, blocks, anomalies = state.successful_actions, state.blocked_actions, state.anomalies

        if decision in (Decision.ALLOW, Decision.ALLOW_WITH_LOG):
            successes += 1
            trust += TRUST_GAIN_PER_SUCCESS
        elif decision is Decision.BLOCK:
            blocks += 1
            trust -= TRUST_LOSS_PER_BLOCK
        elif decision is Decision.SANDBOX:
            blocks += 1
            trust -= TRUST_LOSS_PER_SANDBOX
        elif decision is Decision.CHALLENGE:
            # Counted, but not held against the account: being asked to confirm
            # is a normal outcome for legitimate high-impact work.
            trust -= TRUST_LOSS_PER_CHALLENGE
        if anomalous:
            anomalies += 1
            trust -= TRUST_LOSS_PER_ANOMALY

        trust = round(min(TRUST_CEILING, max(TRUST_FLOOR, trust)), 4)
        self.store.upsert_user(
            user_id,
            trust_score=trust,
            successful_actions=successes,
            blocked_actions=blocks,
            anomalies=anomalies,
        )
        return UserState(
            user_id=user_id, trust_score=trust, successful_actions=successes,
            blocked_actions=blocks, anomalies=anomalies, known=True,
        )

    def describe(self, state: UserState) -> str:
        if not state.known:
            return "first time we have seen this user: no track record to lean on"
        return (
            f"trust {state.trust_score:.2f} from {state.successful_actions} allowed, "
            f"{state.blocked_actions} stopped, {state.anomalies} anomalies"
        )
