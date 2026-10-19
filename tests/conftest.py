"""Shared fixtures.

Every test that touches the trust store gets its own throwaway SQLite file, so
learning in one test can never leak into another — an engine that remembers
between tests would make failures depend on execution order.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import load_config
from app.core.engine import ASLEngine
from app.trust.fingerprint_store import FingerprintStore


@pytest.fixture()
def config(tmp_path: Path):
    return load_config().with_overrides(database_path=str(tmp_path / "asl_test.db"))


@pytest.fixture()
def store(config) -> FingerprintStore:
    store = FingerprintStore(config)
    yield store
    store.close()


@pytest.fixture()
def engine(config, store) -> ASLEngine:
    return ASLEngine(config=config, store=store)
