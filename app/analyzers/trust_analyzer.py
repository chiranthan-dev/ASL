"""User Trust Manager signal (spec section 10).

Kept as its own module to match the specified structure; the implementation
lives next to the environment analyzer because both turn *deployment context*
(who and where) into a bounded risk contribution, and they share the rule that
neither may override an invariant.
"""

from __future__ import annotations

from app.analyzers.environment_analyzer import TrustAnalyzer

__all__ = ["TrustAnalyzer"]
