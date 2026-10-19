"""Score the Request Policy Gate on the frozen paraphrase sets.

Reports, per set, how many requests the gate refuses or escalates. Hostile sets
should be high; benign near-miss sets should be zero. Run with
`python -m evaluation.policy_gate [label]`; the label names the output file so a
before/after pair can be kept side by side.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from app.analyzers.request_policy import PolicySeverity, RequestPolicyAnalyzer
from evaluation import paraphrase_sets as ps
from evaluation.rewriting import PARAPHRASE

RESULTS_DIR = Path(__file__).resolve().parent / "results"

SETS = {
    "original": (list(PARAPHRASE), True),
    "rewritten": (list(PARAPHRASE.values()), True),
    "dev_hostile": (ps.DEV_HOSTILE, True),
    "heldout_hostile": (ps.HELDOUT_HOSTILE, True),
    "dev_benign": (ps.DEV_BENIGN, False),
    "heldout_benign": (ps.HELDOUT_BENIGN, False),
}


def run(label: str) -> dict:
    gate = RequestPolicyAnalyzer()
    out = {"label": label,
           "sets_sha256": hashlib.sha256(Path(ps.__file__).read_bytes()).hexdigest(),
           "sets": {}}
    for name, (items, hostile) in SETS.items():
        fired, prohibited, wrong = 0, 0, []
        for text in items:
            a = gate.analyze(text)
            fired += int(a.fired)
            prohibited += int(a.severity is PolicySeverity.PROHIBITED)
            if a.fired != hostile:
                wrong.append(text)
        out["sets"][name] = {"n": len(items), "fired": fired, "prohibited": prohibited,
                             "rate": round(fired / len(items), 4), "wrong": wrong}
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / f"policy_gate_{label}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


if __name__ == "__main__":
    res = run(sys.argv[1] if len(sys.argv) > 1 else "current")
    for name, r in res["sets"].items():
        print(f"{name:<16} {r['fired']:>2}/{r['n']:<3} ({r['rate']:.2f})")
        if "heldout" not in name or (len(sys.argv) > 2 and sys.argv[2] == "--show-heldout"):
            for w in r["wrong"]:
                print("      x", w)
