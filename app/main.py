"""Entry point.

    python -m app.main            serve the API + inspector UI on :8000
    python -m app.main --cli      run the demo scenarios in the terminal
    python -m app.main --list     list scenario ids

Everything runs locally with no API key: the agent is a mock LLM and every
tool is an inert mock.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import get_config, load_config
from app.core.pipeline import BehaviorPipeline, CallInsight
from app.models.tool_call import ToolInvocation
from demos.scenarios import SCENARIOS, Scenario

STATIC_DIR = Path(__file__).resolve().parent / "api" / "static"


def _seed_database_if_missing() -> None:
    """On a fresh checkout the runtime DB does not exist; seed it from the
    committed snapshot so the demo opens with a populated fingerprint library."""
    import shutil

    # load_config, not get_config: this runs at import time, and get_config is
    # cached -- reading it here froze the config before --live-model could set it.
    cfg = load_config()
    runtime = Path(cfg.database_path)
    seed = runtime.with_name("asl_state.seeded.db")
    if not runtime.exists() and seed.exists():
        shutil.copyfile(seed, runtime)


def create_app() -> FastAPI:
    _seed_database_if_missing()
    app = FastAPI(
        title="ASL — Adaptive Security Layer",
        description="Adaptive runtime authorization for safe tool invocation in agentic AI systems",
        version="0.5.0",
    )
    app.include_router(router)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        def chat() -> FileResponse:
            """Chat is the front door: it shows the system doing its job."""
            return FileResponse(str(STATIC_DIR / "chat.html"))

        @app.get("/inspector", include_in_schema=False)
        def inspector() -> FileResponse:
            """The dashboard: every stage, every signal, side by side."""
            return FileResponse(str(STATIC_DIR / "index.html"))

    return app


app = create_app()


# --------------------------------------------------------------- CLI demo ----

def _print_insight(insight: CallInsight, index: int) -> None:
    call = insight.invocation
    print(f"  [{index}] {call.tool_name}({json.dumps(call.arguments, default=str)[:90]})")
    print(f"      tool      : category={insight.tool.category} sensitivity={insight.tool.sensitivity}"
          f" risk={insight.tool.risk} confidence={insight.tool.confidence}")
    print(f"      arguments : analyzer={insight.arguments.analyzer} risk={insight.arguments.risk}"
          f" scope={insight.arguments.scope} confidence={insight.arguments.confidence}")
    print(f"      capability: {'+'.join(c.value for c in insight.capabilities.capabilities) or 'NONE'}"
          f"  weight={insight.capabilities.weight}")
    if insight.capabilities.escalations:
        print("      escalation: " + ", ".join(c.value for c in insight.capabilities.escalations)
              + "  (not declared by the tool profile)")
    for finding in insight.findings[:4]:
        print(f"      finding   : {finding}")
    if insight.fingerprint is not None:
        print(f"      fingerprint: {insight.fingerprint.fingerprint_id}"
              f"  {insight.fingerprint.canonical_representation}")
    print(f"      provisional risk (pre-fusion): {insight.provisional_risk}")


def run_scenario(scenario: Scenario, pipeline: BehaviorPipeline) -> list[CallInsight]:
    print("=" * 100)
    print(f"{scenario.scenario_id}: {scenario.prompt}")
    print(f"  expectation: {scenario.expectation}")
    insights: list[CallInsight] = []
    for index, call in enumerate(scenario.tool_calls, start=1):
        insight = pipeline.process(
            ToolInvocation(tool_name=call.tool_name, arguments=call.arguments),
            session_id=scenario.session_id,
            user_id=scenario.user_id,
        )
        insights.append(insight)
        _print_insight(insight, index)
    chain = insights[-1].chain_fingerprint if insights else None
    if chain is not None and len(scenario.tool_calls) > 1:
        print(f"  chain fingerprint: {chain.fingerprint_id}")
        print(f"    canonical: {chain.canonical_representation}")
        print(f"    transitions: {chain.transitions}")
    return insights


def run_cli(scenario_id: str | None) -> int:
    selected = [s for s in SCENARIOS if scenario_id in (None, s.scenario_id)]
    if not selected:
        print(f"no such scenario: {scenario_id}", file=sys.stderr)
        return 2
    pipeline = BehaviorPipeline()
    for scenario in selected:
        run_scenario(scenario, pipeline)
    print("=" * 100)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASL — Adaptive Security Layer")
    parser.add_argument("--cli", action="store_true", help="run the behavior pipeline in the terminal")
    parser.add_argument("--scenario", default=None, help="run a single scenario by id (implies --cli)")
    parser.add_argument("--list", action="store_true", help="list scenario ids and exit")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--live-model", action="store_true",
        help="use a real local LLM (OpenAI-compatible, e.g. Ollama) as the planner "
             "instead of the deterministic mock; falls back to the mock if unreachable",
    )
    parser.add_argument("--model", default=None, help="override the live model id (e.g. qwen2.5:7b)")
    parser.add_argument("--base-url", default=None, help="override the OpenAI-compatible base URL")
    args = parser.parse_args(argv)

    if args.live_model:
        import os

        os.environ["ASL_MOCK_LLM"] = "false"
        if args.model:
            os.environ["ASL_LLM_MODEL"] = args.model
        if args.base_url:
            os.environ["ASL_LLM_BASE_URL"] = args.base_url
        get_config.cache_clear()  # pick up the overrides set above

    if args.list:
        for scenario in SCENARIOS:
            print(f"{scenario.scenario_id:<28} {scenario.prompt}")
        return 0

    if args.cli or args.scenario:
        return run_cli(args.scenario)

    import uvicorn

    live = not get_config().mock_llm
    print("ASL — Adaptive Security Layer")
    print(f"  inspector UI : http://{args.host}:{args.port}/")
    print(f"  API docs     : http://{args.host}:{args.port}/docs")
    if live:
        cfg = get_config()
        print(f"  planner      : live model {cfg.llm_model} via {cfg.llm_base_url}")
        print("  (falls back to the deterministic mock if the model is unreachable)\n")
    else:
        print("  mock agent, mock tools, no API key required\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
