"""Fingerprint Trust Engine (spec sections 6-7) — SQLite persistence.

Stores behavioral fingerprints and everything that happened to them, and
answers the only question the fast path is allowed to ask: *have we seen this
behaviour before, how did it go, and how sure are we?*

Three rules are enforced here rather than left to callers:

* **Risk ratchets up fast and decays slowly.** `historical_risk` jumps to any
  worse observation immediately but only creeps down, so one benign repetition
  cannot launder a bad history.
* **A single block is permanent.** Once a fingerprint has been blocked, its
  confidence is crushed and `blocked_executions` stays on the record forever.
* **Confidence is earned per observation**, saturating rather than jumping, so
  novelty always costs at least a few full analyses.
"""

from __future__ import annotations

import functools
import json
import math
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

from app.behavior.fingerprint import FingerprintGenerator
from app.core.config import ASLConfig, get_config
from app.models.enums import Capability, Decision, Scope
from app.models.fingerprint import BehavioralFingerprint, FingerprintMatch
from app.models.tool_call import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint_id           TEXT PRIMARY KEY,
    canonical_representation TEXT    NOT NULL,
    graph_hash               TEXT    NOT NULL,
    capabilities             TEXT    NOT NULL,
    steps                    TEXT    NOT NULL,
    transitions              TEXT    NOT NULL,
    resource_classes         TEXT    NOT NULL DEFAULT '',
    max_scope                TEXT    NOT NULL,
    created_at               TEXT    NOT NULL,
    last_seen                TEXT,
    occurrence_count         INTEGER NOT NULL DEFAULT 0,
    historical_risk          REAL    NOT NULL DEFAULT 0.0,
    successful_executions    INTEGER NOT NULL DEFAULT 0,
    blocked_executions       INTEGER NOT NULL DEFAULT 0,
    confidence               REAL    NOT NULL DEFAULT 0.0,
    policy_version           TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_fp_graph_hash ON fingerprints(graph_hash);

CREATE TABLE IF NOT EXISTS fingerprint_capabilities (
    fingerprint_id TEXT NOT NULL REFERENCES fingerprints(fingerprint_id) ON DELETE CASCADE,
    capability     TEXT NOT NULL,
    PRIMARY KEY (fingerprint_id, capability)
);
CREATE INDEX IF NOT EXISTS ix_fpcap_capability ON fingerprint_capabilities(capability);

CREATE TABLE IF NOT EXISTS fingerprint_observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_id TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    environment    TEXT NOT NULL,
    risk_score     REAL NOT NULL,
    confidence     REAL NOT NULL,
    decision       TEXT NOT NULL,
    path           TEXT NOT NULL,
    outcome        TEXT,
    occurred_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_obs_fingerprint ON fingerprint_observations(fingerprint_id);
CREATE INDEX IF NOT EXISTS ix_obs_user ON fingerprint_observations(user_id, occurred_at);

CREATE TABLE IF NOT EXISTS users (
    user_id            TEXT PRIMARY KEY,
    trust_score        REAL    NOT NULL DEFAULT 0.5,
    successful_actions INTEGER NOT NULL DEFAULT 0,
    blocked_actions    INTEGER NOT NULL DEFAULT 0,
    anomalies          INTEGER NOT NULL DEFAULT 0,
    first_seen         TEXT    NOT NULL,
    last_seen          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS anomaly_stats (
    scope     TEXT NOT NULL,
    key       TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    mean      REAL    NOT NULL DEFAULT 0.0,
    m2        REAL    NOT NULL DEFAULT 0.0,
    last_seen TEXT,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id       TEXT PRIMARY KEY,
    timestamp      TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    environment    TEXT NOT NULL,
    tool_name      TEXT NOT NULL,
    capabilities   TEXT NOT NULL,
    fingerprint_id TEXT,
    risk_score     REAL NOT NULL,
    confidence     REAL NOT NULL,
    decision       TEXT NOT NULL,
    path           TEXT NOT NULL,
    signals        TEXT NOT NULL,
    explanation    TEXT NOT NULL,
    outcome        TEXT,
    latency_ms     REAL NOT NULL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS ix_audit_time ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_user ON audit_log(user_id, timestamp);

CREATE TABLE IF NOT EXISTS policy_versions (
    version      TEXT PRIMARY KEY,
    activated_at TEXT NOT NULL,
    config_json  TEXT NOT NULL
);
"""

#: how quickly confidence saturates with clean repetitions
CONFIDENCE_TAU = 1.25
#: weight of a new observation when historical risk is *falling*
RISK_DECAY_ALPHA = 0.25

#: Risk at which a fingerprint's confidence starts being discounted.
#:
#: This must not sit below the highest fast-path ceiling. It previously sat at
#: 20 while the INTERNAL_EFFECT ceiling was 25, and the 0.8 discount capped
#: confidence at 0.792 against a 0.95 gate -- so anything scoring 20-25 was
#: barred from the fast path by a constant that no policy mentions, and the
#: configured ceiling of 25 was unreachable. Aligning the two leaves the stated
#: policy (10 read-only, 25 internal, never outward) as the only thing deciding.
RISK_DISCOUNT_AT = 25.0
RISK_HEAVY_DISCOUNT_AT = 50.0

_T = TypeVar("_T")


LIBRARY_SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprint_library (
    fingerprint_id TEXT PRIMARY KEY REFERENCES fingerprints(fingerprint_id) ON DELETE CASCADE,
    prompt         TEXT NOT NULL DEFAULT '',
    tool_name      TEXT NOT NULL DEFAULT '',
    arguments      TEXT NOT NULL DEFAULT '{}',
    calls          TEXT NOT NULL DEFAULT '[]',
    decision       TEXT NOT NULL DEFAULT '',
    population     TEXT NOT NULL DEFAULT 'routine'
);
CREATE INDEX IF NOT EXISTS ix_lib_population ON fingerprint_library(population);
"""


def synchronized(method: Callable[..., _T]) -> Callable[..., _T]:
    """Serialise access to the SQLite connection.

    The API serves requests from a thread pool and the store holds a single
    connection opened with `check_same_thread=False`. Without this lock a read
    can interleave with another thread's write transaction and observe a
    half-applied state — which showed up as a freshly-stored fingerprint
    briefly reporting as zero fingerprints. Reads must never be able to see a
    torn write, least of all in a component whose whole job is deciding what is
    safe.
    """

    @functools.wraps(method)
    def wrapper(self: "FingerprintStore", *args: Any, **kwargs: Any) -> _T:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class FingerprintStore:
    """SQLite-backed fingerprint memory."""

    def __init__(self, config: ASLConfig | None = None, path: str | Path | None = None) -> None:
        self.config = config or get_config()
        self.path = str(path or self.config.database_path)
        self.generator = FingerprintGenerator(self.config)
        # Re-entrant: find_best_match calls _candidates, record_observation calls get.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # One decision writes ~7 rows across 4 tables (fingerprint statistics,
        # observations, anomaly baselines, trust, audit). In the default
        # rollback journal at synchronous=FULL each of those is its own fsync,
        # which measured as ~3 ms per commit and made authorization latency
        # dominated by disk sync rather than by analysis. WAL plus
        # synchronous=NORMAL keeps the database crash-safe and only risks losing
        # the most recent commits on a power failure — an acceptable trade for
        # statistics and, with this documented, for a research audit log.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA synchronous={self.config.sqlite_synchronous}")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._record_policy_version()

    # -- lifecycle ------------------------------------------------------
    @synchronized
    def close(self) -> None:
        self._conn.close()

    @synchronized
    def reset(self) -> None:
        """Wipe learned state.  Used by tests and the demo "forget" button."""
        with self._conn:
            for table in (
                "fingerprint_observations", "fingerprint_capabilities", "fingerprints",
                "users", "anomaly_stats", "audit_log",
            ):
                self._conn.execute(f"DELETE FROM {table}")
        self._record_policy_version()

    @synchronized
    def _record_policy_version(self) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO policy_versions(version, activated_at, config_json) VALUES (?,?,?)",
                (self.config.policy_version, utcnow().isoformat(), self.config.model_dump_json()),
            )

    # -- writes ---------------------------------------------------------
    @synchronized
    def upsert(self, fingerprint: BehavioralFingerprint) -> BehavioralFingerprint:
        """Insert a fingerprint if new; return the stored version with statistics."""
        existing = self.get(fingerprint.fingerprint_id)
        if existing is not None:
            return existing
        row = fingerprint.to_row()
        row["resource_classes"] = ",".join(r.value for r in fingerprint.resource_classes)
        row["policy_version"] = self.config.policy_version
        row["last_seen"] = None
        with self._conn:
            self._conn.execute(
                """INSERT INTO fingerprints
                   (fingerprint_id, canonical_representation, graph_hash, capabilities, steps,
                    transitions, resource_classes, max_scope, created_at, last_seen,
                    occurrence_count, historical_risk, successful_executions,
                    blocked_executions, confidence, policy_version)
                   VALUES (:fingerprint_id, :canonical_representation, :graph_hash, :capabilities,
                           :steps, :transitions, :resource_classes, :max_scope, :created_at,
                           :last_seen, :occurrence_count, :historical_risk, :successful_executions,
                           :blocked_executions, :confidence, :policy_version)""",
                row,
            )
            self._conn.executemany(
                "INSERT OR IGNORE INTO fingerprint_capabilities(fingerprint_id, capability) VALUES (?,?)",
                [(fingerprint.fingerprint_id, c.value) for c in fingerprint.capabilities],
            )
        return self.get(fingerprint.fingerprint_id) or fingerprint

    @synchronized
    def record_observation(
        self,
        fingerprint: BehavioralFingerprint,
        *,
        user_id: str,
        session_id: str,
        environment: str,
        risk_score: float,
        confidence: float,
        decision: Decision,
        path: str,
        outcome: str | None = None,
    ) -> BehavioralFingerprint:
        """Fold one decision into a fingerprint's statistics (phase 12 learning)."""
        self.upsert(fingerprint)
        stored = self.get(fingerprint.fingerprint_id)
        assert stored is not None

        # A block is charged to the shared behaviour only when the *behaviour*
        # earned it. `risk_score` here is already behavioural (see AuditLogger.
        # learn), so an intervention driven purely by circumstance -- an
        # untrusted user, a production environment, a refused purpose -- must not
        # count against a fingerprint that thousands of legitimate sessions
        # share. This is the same asymmetry `historical_risk` already observes;
        # leaving it out of the counter reopened the poisoning channel through
        # `confidence`, which collapses as 0.2/blocks and never recovers.
        intervened = decision in (Decision.BLOCK, Decision.CHALLENGE, Decision.SANDBOX)
        blocked = intervened and risk_score >= self.config.risk_log_threshold
        succeeded = decision in (Decision.ALLOW, Decision.ALLOW_WITH_LOG) and outcome != "failure"

        occurrences = stored.occurrence_count + 1
        successes = stored.successful_executions + (1 if succeeded else 0)
        blocks = stored.blocked_executions + (1 if blocked else 0)
        historical = self._blend_risk(stored.historical_risk, risk_score, first=stored.occurrence_count == 0)
        new_confidence = self.confidence_for(successes, blocks, historical)

        with self._conn:
            self._conn.execute(
                """UPDATE fingerprints SET occurrence_count=?, successful_executions=?,
                   blocked_executions=?, historical_risk=?, confidence=?, last_seen=?
                   WHERE fingerprint_id=?""",
                (occurrences, successes, blocks, historical, new_confidence,
                 utcnow().isoformat(), fingerprint.fingerprint_id),
            )
            self._conn.execute(
                """INSERT INTO fingerprint_observations
                   (fingerprint_id, user_id, session_id, environment, risk_score, confidence,
                    decision, path, outcome, occurred_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (fingerprint.fingerprint_id, user_id, session_id, environment, risk_score,
                 confidence, decision.value, path, outcome, utcnow().isoformat()),
            )
        return self.get(fingerprint.fingerprint_id) or stored

    @staticmethod
    def _blend_risk(current: float, observed: float, first: bool) -> float:
        """Ratchet up immediately, decay slowly."""
        if first:
            return round(observed, 3)
        if observed >= current:
            return round(observed, 3)
        return round(current + RISK_DECAY_ALPHA * (observed - current), 3)

    @staticmethod
    def confidence_for(successes: int, blocks: int, historical_risk: float) -> float:
        """Saturating confidence in a fingerprint's benign track record.

        Clean repetitions raise it along `1 - e^(-n/tau)`, so the first sighting
        is never trusted and roughly four clean sightings are needed before the
        fast path becomes possible at all.  Any block collapses it.
        """
        if successes <= 0:
            return 0.0
        confidence = 1.0 - math.exp(-successes / CONFIDENCE_TAU)
        if blocks:
            confidence *= 0.2 / blocks
        if historical_risk >= RISK_HEAVY_DISCOUNT_AT:
            confidence *= 0.4
        elif historical_risk >= RISK_DISCOUNT_AT:
            confidence *= 0.8
        return round(min(0.99, max(0.0, confidence)), 4)

    # -- reads ----------------------------------------------------------
    @synchronized
    def get(self, fingerprint_id: str) -> BehavioralFingerprint | None:
        row = self._conn.execute(
            "SELECT * FROM fingerprints WHERE fingerprint_id=?", (fingerprint_id,)
        ).fetchone()
        return self._row_to_fingerprint(row) if row else None

    @synchronized
    def all(self, limit: int = 200) -> list[BehavioralFingerprint]:
        rows = self._conn.execute(
            "SELECT * FROM fingerprints ORDER BY occurrence_count DESC, created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [self._row_to_fingerprint(r) for r in rows]

    @synchronized
    def observations(self, fingerprint_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM fingerprint_observations WHERE fingerprint_id=? ORDER BY observation_id DESC LIMIT ?",
            (fingerprint_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # -- demo library (seed_library.py) ---------------------------------
    # The library records ONE representative prompt/tool-call per fingerprint so
    # the UI can show a human what a fingerprint actually means. It is a display
    # aid: nothing in the authorization path reads it, because a fingerprint's
    # meaning must come from its canonical form, not from a stored label.
    @synchronized
    def ensure_library_table(self) -> None:
        self._conn.executescript(LIBRARY_SCHEMA)
        cols = {r["name"] for r in
                self._conn.execute("PRAGMA table_info(fingerprint_library)")}
        if "calls" not in cols:  # migrate a store seeded before replay existed
            self._conn.execute(
                "ALTER TABLE fingerprint_library ADD COLUMN calls TEXT NOT NULL DEFAULT '[]'")
        self._conn.commit()

    @synchronized
    def record_library_example(
        self,
        fingerprint_id: str,
        prompt: str,
        tool_name: str,
        arguments: dict[str, Any],
        decision: str,
        population: str,
        calls: list[dict[str, Any]] | None = None,
    ) -> None:
        self._conn.execute(
            """INSERT INTO fingerprint_library
                   (fingerprint_id, prompt, tool_name, arguments, decision,
                    population, calls)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(fingerprint_id) DO NOTHING""",
            (fingerprint_id, prompt, tool_name,
             json.dumps(arguments, default=str)[:2000], decision, population,
             json.dumps(calls or [], default=str)[:6000]),
        )
        self._conn.commit()

    @synchronized
    def library(
        self,
        query: str = "",
        population: str = "",
        limit: int = 60,
        offset: int = 0,
        eligible: bool = False,
    ) -> dict[str, Any]:
        """Every fingerprint in the store, with its seeded example when it has one.

        The join is a LEFT JOIN on purpose. Fingerprints created at runtime -- by
        someone using the chat -- have no seeded example, and an inner join hid
        them entirely, so the one view that claims to show the store's contents
        was showing a subset of it.
        """
        self._conn.executescript(LIBRARY_SCHEMA)
        where, params = ["1=1"], []
        if population == "runtime":
            where.append("l.fingerprint_id IS NULL")
        elif population in ("routine", "hostile"):
            where.append("l.population = ?")
            params.append(population)
        if eligible:
            # The three fingerprint-side conditions the fast path requires. The
            # per-user provenance checks cannot be answered here -- they depend
            # on who is asking -- so a row shown by this filter is *capable* of
            # the fast path, not guaranteed to take it on the first replay.
            # Only single-step shapes can qualify: authorization memory is keyed
            # on what one call does, so a multi-step chain is never the thing the
            # fast path consults.
            where.append("f.canonical_representation NOT LIKE '%;%'")
            where.append("f.blocked_executions = 0")
            where.append("f.confidence >= ?")
            params.append(self.config.fingerprint_confidence_threshold)
            # The risk ceiling is per class, so it is applied row by row below.
            # Using max(ceilings) here listed READ_ONLY shapes that cleared 25 but
            # not their own ceiling of 10 -- the filter promised a fast path it
            # could not deliver.
        if query:
            where.append(
                "(f.canonical_representation LIKE ? OR IFNULL(l.prompt,'') LIKE ? "
                " OR IFNULL(l.tool_name,'') LIKE ? OR f.capabilities LIKE ? "
                " OR f.resource_classes LIKE ? OR f.fingerprint_id LIKE ?)")
            params.extend([f"%{query}%"] * 6)
        clause = " AND ".join(where)
        # When filtering to fast-path candidates, the lowest-risk behaviours are
        # the ones that will actually clear a per-class ceiling, so lead with them.
        order = ("f.historical_risk ASC, f.occurrence_count DESC" if eligible
                 else "f.occurrence_count DESC, f.historical_risk ASC")

        total = int(self._conn.execute(
            f"""SELECT COUNT(*) AS n FROM fingerprints f
                LEFT JOIN fingerprint_library l USING (fingerprint_id)
                WHERE {clause}""",
            params).fetchone()["n"])

        rows = self._conn.execute(
            f"""SELECT f.fingerprint_id, f.canonical_representation, f.capabilities,
                       f.resource_classes, f.max_scope, f.occurrence_count,
                       f.historical_risk, f.confidence, f.successful_executions,
                       f.blocked_executions, l.prompt, l.tool_name, l.arguments,
                       l.decision, l.population, l.calls
                FROM fingerprints f
                LEFT JOIN fingerprint_library l USING (fingerprint_id)
                WHERE {clause}
                ORDER BY {order}
                LIMIT ? OFFSET ?""",
            (*params, 10000 if eligible else limit, 0 if eligible else offset)).fetchall()

        items = []
        for r in rows:
            d = dict(r)
            d["capabilities"] = [c for c in (d["capabilities"] or "").split(",") if c]
            d["resource_classes"] = [c for c in (d["resource_classes"] or "").split(",") if c]
            try:
                d["arguments"] = json.loads(d["arguments"] or "{}")
            except (ValueError, TypeError):
                d["arguments"] = {}
            try:
                d["calls"] = json.loads(d["calls"] or "[]")
            except (ValueError, TypeError):
                d["calls"] = []
            d["population"] = d["population"] or "runtime"
            d["decision"] = d["decision"] or ""
            if not d["tool_name"]:
                # No seeded example: describe it from the canonical form itself.
                d["tool_name"] = " -> ".join(
                    st.split("@")[0].replace("CAPS[", "").replace("]", "")
                    for st in (d["canonical_representation"] or "")
                        .split("|")[1].split(";")) or d["fingerprint_id"]
            items.append(d)

        if eligible:
            items = [d for d in items if self._within_class_ceiling(d)]
            total = len(items)
            items = items[offset:offset + limit]
        return {"total": total, "items": items, "limit": limit, "offset": offset}

    def _within_class_ceiling(self, row: dict[str, Any]) -> bool:
        """Does this shape clear the ceiling for its own fast-path class?

        Mirrors fast_path.classify_behaviour from the stored columns. Anything
        destructive or outward-facing has no ceiling at all and is excluded.
        """
        caps = set(row["capabilities"])
        resources = set(row["resource_classes"])
        reading = {"READ", "NETWORK", "DATABASE", "DOWNLOAD", "SENSOR_ACCESS"}
        destructive = {"DELETE", "EXECUTE", "PRIVILEGE_CHANGE"}
        outward = {"UPLOAD", "EMAIL"}
        outside = {"EXTERNAL_ENDPOINT", "EMAIL_RECIPIENT_EXTERNAL", "BINARY",
                   "CREDENTIAL_STORE", "PRODUCTION_RESOURCE", "SYSTEM_PATH",
                   "SENSITIVE_TABLE"}
        if caps & destructive or caps & outward:
            return False
        if resources & outside and (caps & outward or "WRITE" in caps):
            return False
        ceilings = self.config.fast_path_risk_ceilings
        cls = "INTERNAL_EFFECT" if caps - reading else "READ_ONLY"
        return row["historical_risk"] < ceilings.get(cls, 0.0)

    @synchronized
    def library_stats(self) -> dict[str, Any]:
        self._conn.executescript(LIBRARY_SCHEMA)
        row = self._conn.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN l.population='routine' THEN 1 ELSE 0 END) AS routine,
                      SUM(CASE WHEN l.population='hostile' THEN 1 ELSE 0 END) AS hostile,
                      SUM(CASE WHEN l.fingerprint_id IS NULL THEN 1 ELSE 0 END) AS runtime,
                      SUM(CASE WHEN f.blocked_executions = 0
                                AND f.confidence >= ?
                                AND f.historical_risk < ?
                               THEN 1 ELSE 0 END) AS trusted
               FROM fingerprints f
               LEFT JOIN fingerprint_library l USING (fingerprint_id)""",
            (self.config.fingerprint_confidence_threshold,
             max(self.config.fast_path_risk_ceilings.values())),
        ).fetchone()
        return {k: int(row[k] or 0)
                for k in ("total", "routine", "hostile", "runtime", "trusted")}

    @synchronized
    def audit_count(self) -> int:
        return int(self._conn.execute(
            "SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"])

    @synchronized
    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM fingerprints").fetchone()["n"])

    # -- similarity search (spec section 7) ------------------------------
    @synchronized
    def find_best_match(
        self, query: BehavioralFingerprint, user_id: str | None = None
    ) -> FingerprintMatch:
        """Nearest stored fingerprint, with its history.

        Candidates are shortlisted by shared capability or identical graph hash
        (an inverted index, not a full scan), then scored with the graded
        similarity function.  An exact id match short-circuits.
        """
        exact = self.get(query.fingerprint_id)
        if exact is not None and exact.occurrence_count > 0:
            return self._match_from(query, exact, 1.0, user_id)

        candidates = self._candidates(query)
        best: tuple[float, BehavioralFingerprint] | None = None
        for candidate in candidates:
            score = self.generator.similarity(query, candidate)
            if best is None or score > best[0]:
                best = (score, candidate)

        if best is None:
            return FingerprintMatch(
                query_fingerprint_id=query.fingerprint_id,
                similarity_score=0.0,
                historical_risk=0.0,
                confidence=0.0,
                novelty_score=1.0,
                occurrence_count=0,
                explanation="no comparable behaviour has ever been recorded: fully novel",
            )
        return self._match_from(query, best[1], best[0], user_id)

    @synchronized
    def _candidates(self, query: BehavioralFingerprint, limit: int = 60) -> list[BehavioralFingerprint]:
        capabilities = [c.value for c in query.capabilities] or ["READ"]
        placeholders = ",".join("?" for _ in capabilities)
        rows = self._conn.execute(
            f"""SELECT f.* FROM fingerprints f
                WHERE f.graph_hash = ?
                   OR f.fingerprint_id IN (
                        SELECT fingerprint_id FROM fingerprint_capabilities
                        WHERE capability IN ({placeholders}))
                ORDER BY f.occurrence_count DESC
                LIMIT ?""",
            (query.graph_hash, *capabilities, limit),
        ).fetchall()
        return [self._row_to_fingerprint(r) for r in rows]

    def _match_from(
        self,
        query: BehavioralFingerprint,
        candidate: BehavioralFingerprint,
        score: float,
        user_id: str | None,
    ) -> FingerprintMatch:
        previous = self._previous_outcome(candidate.fingerprint_id, user_id)
        exact = score >= 0.999
        note = "exact match" if exact else f"nearest known behaviour ({score:.2f} similar)"
        return FingerprintMatch(
            query_fingerprint_id=query.fingerprint_id,
            matched_fingerprint_id=candidate.fingerprint_id,
            similarity_score=round(score, 4),
            historical_risk=candidate.historical_risk if exact else max(candidate.historical_risk, 0.0),
            previous_outcome=previous,
            # Confidence in the *match* is the stored confidence discounted by
            # how far the query is from it: a 0.8-similar neighbour cannot lend
            # its full track record to a behaviour we have not actually seen.
            confidence=round(candidate.confidence * score, 4),
            novelty_score=self.generator.novelty(score),
            occurrence_count=candidate.occurrence_count,
            explanation=(
                f"{note}: seen {candidate.occurrence_count}x, "
                f"historical risk {candidate.historical_risk:.1f}, "
                f"{candidate.successful_executions} allowed / {candidate.blocked_executions} stopped"
            ),
        )

    @synchronized
    def _previous_outcome(self, fingerprint_id: str, user_id: str | None) -> str | None:
        query = "SELECT decision FROM fingerprint_observations WHERE fingerprint_id=?"
        params: list[Any] = [fingerprint_id]
        if user_id:
            query += " AND user_id=?"
            params.append(user_id)
        query += " ORDER BY observation_id DESC LIMIT 1"
        row = self._conn.execute(query, params).fetchone()
        return row["decision"] if row else None

    @synchronized
    def environments_seen(self, fingerprint_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT environment FROM fingerprint_observations WHERE fingerprint_id=?",
            (fingerprint_id,),
        ).fetchall()
        return {r["environment"] for r in rows}

    @synchronized
    def users_seen(self, fingerprint_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT user_id FROM fingerprint_observations WHERE fingerprint_id=?",
            (fingerprint_id,),
        ).fetchall()
        return {r["user_id"] for r in rows}

    # -- anomaly statistics (used by phase 13 detector) -------------------
    @synchronized
    def observe_stat(self, scope: str, key: str, value: float) -> tuple[float, float, int]:
        """Welford update; returns (mean, stddev, count) *before* this value."""
        row = self._conn.execute(
            "SELECT count, mean, m2 FROM anomaly_stats WHERE scope=? AND key=?", (scope, key)
        ).fetchone()
        count, mean, m2 = (row["count"], row["mean"], row["m2"]) if row else (0, 0.0, 0.0)
        prior = (mean, math.sqrt(m2 / count) if count > 1 else 0.0, count)

        count += 1
        delta = value - mean
        mean += delta / count
        m2 += delta * (value - mean)
        with self._conn:
            self._conn.execute(
                """INSERT INTO anomaly_stats(scope, key, count, mean, m2, last_seen)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(scope, key) DO UPDATE SET count=?, mean=?, m2=?, last_seen=?""",
                (scope, key, count, mean, m2, utcnow().isoformat(),
                 count, mean, m2, utcnow().isoformat()),
            )
        return prior

    @synchronized
    def seen_key(self, scope: str, key: str) -> int:
        row = self._conn.execute(
            "SELECT count FROM anomaly_stats WHERE scope=? AND key=?", (scope, key)
        ).fetchone()
        return int(row["count"]) if row else 0

    # -- audit ------------------------------------------------------------
    @synchronized
    def write_audit(self, record: dict[str, Any]) -> None:
        with self._conn:
            self._conn.execute(
                """INSERT INTO audit_log
                   (audit_id, timestamp, user_id, session_id, environment, tool_name, capabilities,
                    fingerprint_id, risk_score, confidence, decision, path, signals, explanation,
                    outcome, latency_ms)
                   VALUES (:audit_id,:timestamp,:user_id,:session_id,:environment,:tool_name,
                           :capabilities,:fingerprint_id,:risk_score,:confidence,:decision,:path,
                           :signals,:explanation,:outcome,:latency_ms)""",
                record,
            )

    @synchronized
    def audit_entries(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for row in rows:
            entry = dict(row)
            try:
                entry["signals"] = json.loads(entry["signals"])
            except (TypeError, ValueError):
                entry["signals"] = {}
            out.append(entry)
        return out

    # -- user trust rows (used by TrustMemory) ----------------------------
    @synchronized
    def user_row(self, user_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        return dict(row) if row else None

    @synchronized
    def upsert_user(self, user_id: str, **fields: Any) -> dict[str, Any]:
        now = utcnow().isoformat()
        existing = self.user_row(user_id)
        if existing is None:
            payload = {
                "user_id": user_id,
                "trust_score": fields.get("trust_score", self.config.user_trust_initial),
                "successful_actions": fields.get("successful_actions", 0),
                "blocked_actions": fields.get("blocked_actions", 0),
                "anomalies": fields.get("anomalies", 0),
                "first_seen": now,
                "last_seen": now,
            }
            with self._conn:
                self._conn.execute(
                    """INSERT INTO users(user_id, trust_score, successful_actions, blocked_actions,
                                         anomalies, first_seen, last_seen)
                       VALUES (:user_id,:trust_score,:successful_actions,:blocked_actions,
                               :anomalies,:first_seen,:last_seen)""",
                    payload,
                )
            return payload
        merged = {**existing, **fields, "last_seen": now}
        with self._conn:
            self._conn.execute(
                """UPDATE users SET trust_score=?, successful_actions=?, blocked_actions=?,
                   anomalies=?, last_seen=? WHERE user_id=?""",
                (merged["trust_score"], merged["successful_actions"], merged["blocked_actions"],
                 merged["anomalies"], now, user_id),
            )
        return merged

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _row_to_fingerprint(row: sqlite3.Row) -> BehavioralFingerprint:
        return BehavioralFingerprint(
            fingerprint_id=row["fingerprint_id"],
            canonical_representation=row["canonical_representation"],
            graph_hash=row["graph_hash"],
            capabilities=[Capability(c) for c in row["capabilities"].split(",") if c],
            steps=[s for s in row["steps"].split("|") if s],
            transitions=[t for t in row["transitions"].split("|") if t],
            max_scope=Scope(row["max_scope"]),
            created_at=_parse_dt(row["created_at"]),
            last_seen=_parse_dt(row["last_seen"]) if row["last_seen"] else None,
            occurrence_count=row["occurrence_count"],
            historical_risk=row["historical_risk"],
            successful_executions=row["successful_executions"],
            blocked_executions=row["blocked_executions"],
            confidence=row["confidence"],
        )


def _parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def summarize(fingerprints: Iterable[BehavioralFingerprint]) -> dict[str, Any]:
    items = list(fingerprints)
    return {
        "count": len(items),
        "total_observations": sum(f.occurrence_count for f in items),
        "trusted": sum(1 for f in items if f.confidence >= 0.95 and f.blocked_executions == 0),
        "blocked": sum(1 for f in items if f.blocked_executions > 0),
    }
