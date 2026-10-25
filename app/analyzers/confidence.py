"""LLM Confidence Estimator (spec section 14).

Asks: *how sure are we that we understood this call at all?* — separate from
how dangerous the call is. Low understanding is not safety; it is a reason to
involve a human, so this estimator emits both a confidence and a risk
contribution that rises as confidence falls.

The default estimator is deterministic and needs no API key. An
OpenAI-compatible adapter is provided for experiments and is imported lazily,
so the dependency is optional and the prototype never requires credentials.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.context import AnalysisContext


@dataclass
class ConfidenceEstimate:
    confidence: float
    risk_contribution: float
    explanation: str = ""
    source: str = "mock"
    detail: dict = field(default_factory=dict)


class ConfidenceEstimator(ABC):
    name = "llm_confidence"

    @abstractmethod
    def estimate(self, context: AnalysisContext) -> ConfidenceEstimate:
        ...


class MockLLMConfidenceEstimator(ConfidenceEstimator):
    """Deterministic stand-in for a model-based estimator.

    Combines the concrete evidence of comprehension the pipeline already has:
    whether the payload parsed, whether the tool was recognised, whether the
    analyzers agree, and whether the prompt explains the call.
    """

    def estimate(self, context: AnalysisContext) -> ConfidenceEstimate:
        factors: dict[str, float] = {}
        notes: list[str] = []

        factors["argument_parse"] = 1.0 if context.arguments.parse_ok else 0.45
        if not context.arguments.parse_ok:
            notes.append("payload did not parse cleanly, so the analysis is partial")

        factors["tool_known"] = 1.0 if context.tool.known_tool else 0.5
        if not context.tool.known_tool:
            notes.append("tool is not in the registry, so its powers are inferred rather than declared")

        factors["analyzer_agreement"] = self._agreement(context, notes)
        factors["prompt_support"] = 0.9 if (context.prompt or "").strip() else 0.55
        if not (context.prompt or "").strip():
            notes.append("no prompt to corroborate the call")

        factors["specialised_analyzer"] = 0.95 if context.arguments.analyzer != "generic" else 0.7

        confidence = 1.0
        for value in factors.values():
            confidence *= value
        confidence = round(min(0.98, max(0.05, confidence ** 0.6)), 3)

        risk_contribution = round(min(100.0, (1.0 - confidence) * 85.0), 2)

        return ConfidenceEstimate(
            confidence=confidence,
            risk_contribution=risk_contribution,
            explanation="; ".join(notes) or "call was understood cleanly by every stage",
            source="mock",
            detail={"factors": {k: round(v, 3) for k, v in factors.items()}},
        )

    @staticmethod
    def _agreement(context: AnalysisContext, notes: list[str]) -> float:
        values = [context.tool.risk, context.arguments.risk, context.capabilities.weight]
        spread = max(values) - min(values)
        if spread > 55:
            notes.append(f"analyzers disagree sharply (spread {spread:.0f} points)")
            return 0.6
        if spread > 30:
            return 0.8
        return 0.95


class OpenAICompatibleConfidenceEstimator(ConfidenceEstimator):
    """Optional adapter for any OpenAI-compatible chat completions endpoint.

    Never required: if the dependency or the key is missing, the caller falls
    back to the mock estimator. Model-agnostic by construction — the base URL
    and model name are both parameters.
    """

    PROMPT = (
        "You are a security reviewer. Given a proposed tool call and its static analysis, "
        "reply with JSON {\"confidence\": 0..1, \"risk\": 0..100, \"reason\": \"...\"} describing "
        "how confident you are that the call was correctly understood."
    )

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self._fallback = MockLLMConfidenceEstimator()

    def estimate(self, context: AnalysisContext) -> ConfidenceEstimate:
        payload = self._payload(context)
        try:
            import httpx

            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self.PROMPT},
                        {"role": "user", "content": json.dumps(payload)},
                    ],
                    "temperature": 0,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            parsed: dict[str, Any] = json.loads(content)
        except Exception as exc:
            estimate = self._fallback.estimate(context)
            estimate.explanation += f" (LLM estimator unavailable: {type(exc).__name__})"
            estimate.source = "mock-fallback"
            return estimate

        confidence = float(parsed.get("confidence", 0.5))
        return ConfidenceEstimate(
            confidence=round(min(1.0, max(0.0, confidence)), 3),
            risk_contribution=round(float(parsed.get("risk", (1 - confidence) * 80)), 2),
            explanation=str(parsed.get("reason", "")),
            source=f"llm:{self.model}",
            detail={"raw": parsed},
        )

    @staticmethod
    def _payload(context: AnalysisContext) -> dict[str, Any]:
        return {
            "prompt": context.prompt,
            "tool": context.invocation.tool_name,
            "arguments": context.invocation.arguments,
            "capabilities": sorted(c.value for c in context.capability_set),
            "findings": [f.code for f in context.arguments.findings],
        }
