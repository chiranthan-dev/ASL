"""Phases 6-7 — SQLite trust memory and similarity search."""

from __future__ import annotations

from app.behavior.fingerprint import FingerprintGenerator
from app.core.pipeline import BehaviorPipeline
from app.models.enums import Decision
from app.models.tool_call import ToolInvocation
from app.trust.fingerprint_store import FingerprintStore
from app.trust.trust_memory import TrustMemory


def fingerprint_for(tool: str, arguments: dict, session: str = "t"):
    pipeline = BehaviorPipeline()
    insight = pipeline.process(ToolInvocation(tool_name=tool, arguments=arguments), session, "u")
    return insight.fingerprint


def observe(store: FingerprintStore, fp, decision=Decision.ALLOW, risk=8.0, user="u", env="sandbox"):
    return store.record_observation(
        fp, user_id=user, session_id="s", environment=env, risk_score=risk,
        confidence=0.9, decision=decision, path="FULL_ASL_ANALYSIS", outcome="success",
    )



def test_new_fingerprint_starts_untrusted(store: FingerprintStore) -> None:
    fp = fingerprint_for("image_search", {"query": "dogs"})
    stored = store.upsert(fp)
    assert stored.occurrence_count == 0
    assert stored.confidence == 0.0
    assert store.count() == 1


def test_confidence_grows_with_clean_repetition(store: FingerprintStore) -> None:
    fp = fingerprint_for("image_search", {"query": "dogs"})
    confidences = [observe(store, fp).confidence for _ in range(5)]
    assert confidences == sorted(confidences), "confidence must grow monotonically"
    assert confidences[0] < 0.6, "one sighting is never enough to be trusted"
    assert confidences[-1] >= 0.95, "a handful of clean runs should reach the fast-path bar"


def test_a_single_block_collapses_confidence(store: FingerprintStore) -> None:
    fp = fingerprint_for("filesystem.delete", {"path": "/production/", "recursive": True})
    for _ in range(6):
        observe(store, fp)
    before = store.get(fp.fingerprint_id).confidence
    after = observe(store, fp, decision=Decision.BLOCK, risk=95.0).confidence
    assert before > 0.9 and after < 0.3
    assert store.get(fp.fingerprint_id).blocked_executions == 1


def test_risk_ratchets_up_fast_and_decays_slowly(store: FingerprintStore) -> None:
    fp = fingerprint_for("filesystem.write", {"path": "/home/user/a.txt", "content": "x"})
    observe(store, fp, risk=10.0)
    spiked = observe(store, fp, risk=90.0)
    assert spiked.historical_risk == 90.0, "a bad run is adopted immediately"
    calmed = observe(store, fp, risk=10.0)
    assert calmed.historical_risk > 50.0, "one good run must not erase a bad history"


def test_observations_are_recorded(store: FingerprintStore) -> None:
    fp = fingerprint_for("image_search", {"query": "dogs"})
    observe(store, fp, user="alice", env="sandbox")
    observe(store, fp, user="bob", env="production")
    assert store.users_seen(fp.fingerprint_id) == {"alice", "bob"}
    assert store.environments_seen(fp.fingerprint_id) == {"sandbox", "production"}
    assert len(store.observations(fp.fingerprint_id)) == 2



def test_unknown_behaviour_is_fully_novel(store: FingerprintStore) -> None:
    match = store.find_best_match(fingerprint_for("image_search", {"query": "dogs"}))
    assert match.matched_fingerprint_id is None
    assert match.novelty_score == 1.0
    assert match.similarity_score == 0.0


def test_exact_repeat_matches_itself(store: FingerprintStore) -> None:
    fp = fingerprint_for("image_search", {"query": "dogs"})
    observe(store, fp)
    match = store.find_best_match(fingerprint_for("image_search", {"query": "cats"}, "t2"))
    assert match.matched_fingerprint_id == fp.fingerprint_id
    assert match.similarity_score == 1.0
    assert match.novelty_score == 0.0


def test_equivalent_behaviour_via_another_tool_matches(store: FingerprintStore) -> None:
    baseline = fingerprint_for("filesystem.delete", {"path": "/production/db/", "recursive": True})
    observe(store, baseline, decision=Decision.ALLOW, risk=80.0)
    other = fingerprint_for("storage.remove_directory", {"path": "/production/db/", "recursive": True}, "t2")
    match = store.find_best_match(other)
    assert match.matched_fingerprint_id == baseline.fingerprint_id
    assert match.similarity_score == 1.0, "different tool name, same behaviour"


def test_match_confidence_is_discounted_by_distance(store: FingerprintStore) -> None:
    baseline = fingerprint_for("filesystem.delete", {"path": "/production/db/", "recursive": True})
    for _ in range(6):
        observe(store, baseline)
    near = fingerprint_for("shell.execute", {"command": "rm -rf /production/db/"}, "t2")
    match = store.find_best_match(near)
    stored = store.get(baseline.fingerprint_id)
    assert 0 < match.similarity_score < 1.0
    assert match.confidence < stored.confidence, (
        "a neighbour cannot lend its full track record to behaviour we have not seen"
    )


def test_dissimilar_behaviour_scores_low(store: FingerprintStore) -> None:
    observe(store, fingerprint_for("image_search", {"query": "dogs"}))
    match = store.find_best_match(
        fingerprint_for("filesystem.delete", {"path": "/production/", "recursive": True}, "t2"))
    assert match.similarity_score < 0.4


def test_reset_forgets_everything(store: FingerprintStore) -> None:
    observe(store, fingerprint_for("image_search", {"query": "dogs"}))
    assert store.count() == 1
    store.reset()
    assert store.count() == 0



def test_trust_is_earned_slowly_and_lost_quickly(store: FingerprintStore, config) -> None:
    trust = TrustMemory(store, config)
    assert trust.state("newbie").known is False

    for _ in range(5):
        state = trust.record("newbie", Decision.ALLOW)
    earned = state.trust_score
    assert earned > config.user_trust_initial

    after_block = trust.record("newbie", Decision.BLOCK)
    assert after_block.trust_score < config.user_trust_initial, (
        "one block must cost more than five successes earned"
    )
    assert after_block.blocked_actions == 1


def test_trust_is_bounded(store: FingerprintStore, config) -> None:
    trust = TrustMemory(store, config)
    for _ in range(80):
        state = trust.record("veteran", Decision.ALLOW)
    assert state.trust_score <= 0.95
    for _ in range(20):
        state = trust.record("veteran", Decision.BLOCK)
    assert state.trust_score >= 0.05


def test_similarity_is_generator_backed(store: FingerprintStore) -> None:
    """The store must not invent its own notion of similarity."""
    assert isinstance(store.generator, FingerprintGenerator)
