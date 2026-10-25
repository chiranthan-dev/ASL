"""Fast Path (spec section 8).

    similarity >= 0.98  AND  historical_risk < 10  AND  confidence >= 0.95
    AND lightweight validation (identity, environment, policy version, anomaly)
        -> FAST_PATH_ALLOW
    otherwise
        -> FULL_ASL_ANALYSIS

The fast path skips *expensive analysis*, never *security checks*.  Two extra
guards beyond the specified thresholds:

* **Invariant guard.** Behaviour that touches an invariant category
  (destruction of production, credential access, privilege change, download
  -> execute, exfiltration shape) is never eligible, no matter how familiar it
  has become.  Familiarity is not a safety property for these.
* **Provenance guard.** The trusted history must belong to *this* user in
  *this* environment under *this* policy version.  A fingerprint trusted in
  sandbox lends nothing to the same behaviour in production.

Every check is returned with its verdict so the decision stays inspectable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import ASLConfig, get_config
from app.models.context import AnalysisContext
from app.models.enums import Capability, Decision, Environment, ResourceClass, Scope
from app.trust.fingerprint_store import FingerprintStore

INVARIANT_CAPABILITIES = {Capability.PRIVILEGE_CHANGE, Capability.AUTHENTICATE}
INVARIANT_RESOURCES = {ResourceClass.CREDENTIAL_STORE, ResourceClass.PRODUCTION_RESOURCE,
                       ResourceClass.SYSTEM_PATH, ResourceClass.SENSITIVE_TABLE}

READING = {Capability.READ, Capability.NETWORK, Capability.DATABASE, Capability.DOWNLOAD,
           Capability.SENSOR_ACCESS}
OUTWARD = {Capability.UPLOAD, Capability.EMAIL}
DESTRUCTIVE = {Capability.DELETE, Capability.EXECUTE, Capability.PRIVILEGE_CHANGE}
EXTERNAL_RESOURCES = {ResourceClass.EXTERNAL_ENDPOINT, ResourceClass.EMAIL_RECIPIENT_EXTERNAL,
                      ResourceClass.BINARY}

READ_ONLY = "READ_ONLY"
INTERNAL_EFFECT = "INTERNAL_EFFECT"
OUTWARD_OR_DESTRUCTIVE = "OUTWARD_OR_DESTRUCTIVE"


def classify_behaviour(context: AnalysisContext) -> str:
    """Which fast-path class does this behaviour belong to?

    Deliberately keyed on the **trust boundary**, not on reversibility. Sending
    one internal email is irreversible yet contained; posting the same content
    to an external endpoint is the event that actually matters. Classifying by
    reversibility would put those two in the same bucket and would mean nothing
    that changes state could ever become cheap — which is the whole point of an
    adaptive layer.
    """
    caps = context.capability_set
    resources = {r.resource_class for r in context.arguments.resources}

    if caps & DESTRUCTIVE:
        return OUTWARD_OR_DESTRUCTIVE
    if caps & OUTWARD and (resources & EXTERNAL_RESOURCES or context.sensitive_resource):
        return OUTWARD_OR_DESTRUCTIVE
    if resources & (INVARIANT_RESOURCES | EXTERNAL_RESOURCES) and caps & (OUTWARD | {Capability.WRITE}):
        return OUTWARD_OR_DESTRUCTIVE
    if caps - READING:
        return INTERNAL_EFFECT
    return READ_ONLY


@dataclass
class Check:
    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class FastPathVerdict:
    eligible: bool
    checks: list[Check] = field(default_factory=list)
    reason: str = ""

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    def as_dict(self) -> dict[str, object]:
        return {
            "eligible": self.eligible,
            "reason": self.reason,
            "checks": [c.as_dict() for c in self.checks],
            "path": "FAST_PATH_ALLOW" if self.eligible else "FULL_ASL_ANALYSIS",
        }


class FastPathEvaluator:
    def __init__(self, store: FingerprintStore, config: ASLConfig | None = None) -> None:
        self.store = store
        self.config = config or get_config()

    def evaluate(self, context: AnalysisContext) -> FastPathVerdict:
        cfg = self.config
        match = context.match
        checks: list[Check] = []

        if not cfg.fast_path_enabled:
            return FastPathVerdict(False, [Check("enabled", False, "fast path disabled by policy")],
                                   "fast path disabled")

        checks.append(Check(
            "similarity",
            match.similarity_score >= cfg.fingerprint_similarity_threshold,
            f"{match.similarity_score:.3f} vs required {cfg.fingerprint_similarity_threshold}",
        ))
        behaviour_class = classify_behaviour(context)
        ceiling = cfg.fast_path_risk_ceilings.get(behaviour_class)
        if ceiling is None:
            checks.append(Check(
                "behaviour class",
                False,
                f"{behaviour_class}: crosses the trust boundary or destroys, so the fast path "
                f"is closed to it at any risk level",
            ))
        else:
            checks.append(Check(
                "historical risk",
                match.historical_risk < ceiling,
                f"{match.historical_risk:.1f} vs limit {ceiling} for {behaviour_class}",
            ))
        checks.append(Check(
            "fingerprint confidence",
            match.confidence >= cfg.fingerprint_confidence_threshold,
            f"{match.confidence:.3f} vs required {cfg.fingerprint_confidence_threshold}",
        ))
        checks.append(Check(
            "repetitions",
            match.occurrence_count >= cfg.fast_path_min_occurrences,
            f"seen {match.occurrence_count}x, need {cfg.fast_path_min_occurrences}",
        ))

        invariant = self._invariant_reason(context)
        checks.append(Check(
            "invariant guard",
            invariant is None,
            invariant or "behaviour is not in a never-fast-path category",
        ))

        checks.extend(self._validation_checks(context))

        eligible = all(c.passed for c in checks)
        if eligible:
            reason = (
                f"identical to a behaviour allowed {match.occurrence_count}x for this user "
                f"in this environment, with historical risk {match.historical_risk:.1f}"
            )
        else:
            first = next(c for c in checks if not c.passed)
            reason = f"full analysis required: {first.name} ({first.detail})"
        return FastPathVerdict(eligible, checks, reason)

    def _invariant_reason(self, context: AnalysisContext) -> str | None:
        severity = context.extras.get("policy_severity", "NONE")
        if severity != "NONE":
            return (f"the request itself was flagged {severity} "
                    f"({context.extras.get('policy_category')}): never fast-pathed")
        caps = context.capability_set
        resources = {r.resource_class for r in context.arguments.resources}

        if caps & INVARIANT_CAPABILITIES:
            return f"touches {sorted(c.value for c in caps & INVARIANT_CAPABILITIES)}: never fast-pathed"
        if resources & INVARIANT_RESOURCES:
            names = sorted(r.value for r in resources & INVARIANT_RESOURCES)
            return f"targets {names}: never fast-pathed"
        if Capability.DELETE in caps and context.arguments.scope in (Scope.RECURSIVE, Scope.UNBOUNDED):
            return "wide-scope deletion: never fast-pathed"
        if {Capability.DOWNLOAD, Capability.EXECUTE} <= caps:
            return "download-then-execute: never fast-pathed"
        if {Capability.DATABASE, Capability.UPLOAD} <= caps:
            return "database read feeding an upload: never fast-pathed"
        return None

    def _validation_checks(self, context: AnalysisContext) -> list[Check]:
        matched = context.match.matched_fingerprint_id
        users = self.store.users_seen(matched) if matched else set()
        environments = self.store.environments_seen(matched) if matched else set()
        policy = context.policy_version or self.config.policy_version

        checks = [
            Check(
                "user identity",
                context.user.known and context.user_id_trusted(),
                self._identity_detail(context, users),
            ),
            Check(
                "user has run this before",
                context.user.user_id in users,
                f"prior runs by this user: {'yes' if context.user.user_id in users else 'no'}",
            ),
            Check(
                "environment",
                context.environment.value in environments
                and not (context.environment is Environment.PRODUCTION and context.user.trust_score < 0.8),
                f"trusted in {sorted(environments) or 'nowhere'}, now in {context.environment.value}",
            ),
            Check(
                "policy version",
                policy == self.config.policy_version,
                f"request {policy} vs active {self.config.policy_version}",
            ),
            Check(
                "no anomaly",
                not context.extras.get("anomaly_flag", False),
                context.extras.get("anomaly_detail", "no anomaly indicator raised"),
            ),
            Check(
                "no prior block",
                context.match.previous_outcome not in (Decision.BLOCK.value, Decision.SANDBOX.value),
                f"last outcome: {context.match.previous_outcome or 'none'}",
            ),
        ]
        return checks

    @staticmethod
    def _identity_detail(context: AnalysisContext, users: set[str]) -> str:
        if not context.user.known:
            return "unknown user: no trust record"
        return f"{context.user.user_id} trust {context.user.trust_score:.2f}"
