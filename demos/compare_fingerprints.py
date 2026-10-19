"""Fingerprint equivalence demo.

Runs a set of workflows through the pipeline and prints a similarity matrix over
their behavioral fingerprints.  This is the "money slide" of the project: the
same behaviour expressed through different tools collapses to the same (or a
near-identical) fingerprint, while the same *tool* with different arguments
does not.

    python -m demos.compare_fingerprints
"""

from __future__ import annotations

from app.behavior.fingerprint import FingerprintGenerator
from app.core.pipeline import BehaviorPipeline
from app.models.fingerprint import BehavioralFingerprint
from app.models.tool_call import ToolInvocation

CASES: list[tuple[str, str, dict]] = [
    ("A  fs.delete /production/database/", "filesystem.delete",
     {"path": "/production/database/", "recursive": True}),
    ("B  shell rm -rf /production/database/", "shell.execute",
     {"command": "rm -rf /production/database/"}),
    ("C  unregistered storage plugin", "storage.remove_directory",
     {"path": "/production/database/", "recursive": True}),
    ("D  python shutil.rmtree", "python.execute",
     {"code": "import shutil\nshutil.rmtree('/production/database/')"}),
    ("E  fs.delete temp.txt", "filesystem.delete",
     {"path": "temp.txt"}),
    ("F  image search", "image_search",
     {"query": "golden retriever puppy"}),
]


def build() -> list[tuple[str, BehavioralFingerprint]]:
    pipeline = BehaviorPipeline()
    out: list[tuple[str, BehavioralFingerprint]] = []
    for index, (label, tool, arguments) in enumerate(CASES):
        insight = pipeline.process(
            ToolInvocation(tool_name=tool, arguments=arguments),
            session_id=f"cmp_{index}",
            user_id="panel_demo",
        )
        out.append((label, insight.fingerprint))
    return out


def main() -> int:
    generator = FingerprintGenerator()
    rows = build()

    print("\nCanonical forms (no tool name appears in any of them)\n" + "-" * 96)
    for label, fingerprint in rows:
        print(f"{label:<40} {fingerprint.fingerprint_id}")
        print(f"{'':<40} {fingerprint.canonical_representation}")

    print("\nSimilarity matrix\n" + "-" * 96)
    header = "".join(f"{label.split()[0]:>8}" for label, _ in rows)
    print(f"{'':<42}{header}")
    for label, a in rows:
        cells = "".join(f"{generator.similarity(a, b):>8.2f}" for _, b in rows)
        print(f"{label:<42}{cells}")

    print(
        "\nRead it as:\n"
        "  A = C  exactly (1.00) - a registered tool and an unregistered plugin, same behaviour\n"
        "  B = D  exactly (1.00) - a shell command and a Python program, same behaviour\n"
        "  A ~ B  0.73           - same destruction, but the shell/python route really does\n"
        "                          add an EXECUTE capability, so it is close, not identical\n"
        "  A ~ E  0.65 < 0.73    - the SAME TOOL with a smaller blast radius is further away\n"
        "                          than a DIFFERENT TOOL with the same blast radius\n"
        "  * ~ F  0.08           - an unrelated read-only workflow\n"
        "Nothing here reaches the 0.98 fast-path threshold except an exact match.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
