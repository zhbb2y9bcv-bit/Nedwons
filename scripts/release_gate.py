#!/usr/bin/env python3
"""Release gate: refuse to ship while the project's own records say it is not ready.

Two checks, both deliberately static so they run identically in CI and on a laptop:

1. NO CRITICAL RISK IS STILL OPEN. `RISK_REGISTER.md` is the project's honest account of what is
   unproven; a release that contradicts it is a release built on a claim the team has already
   written down as false. Critical + OPEN blocks. Everything else (High, MITIGATING, ACCEPTED)
   is reported but does not block — those are judgements the register has already made.

2. NO PLACEHOLDER CI JOB REMAINS. A job whose only step echoes "enabled later" is worse than a
   missing job: the release workflow depends on it, so it goes green and looks like coverage. The
   gate therefore reads the workflow it is part of and refuses if any job still has no real work.

Exit 0 = may ship. Exit 1 = blocked, with the reasons on stdout.

`--explain` prints the full picture (including non-blocking findings) without changing the exit
code, which is what you want when reading a failed run.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RISK_REGISTER = REPO / "RISK_REGISTER.md"
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"

# A table row is only a risk row if its table has the Sev/Status columns. The register also has an
# "Accepted risks" table with a different shape (ID | Risk | Owner | Rationale), and misreading its
# Owner column as a severity is exactly the kind of silent nonsense a gate must not do.
RISK_HEADER = ("id", "risk", "sev", "status", "owner", "note")


def cells(line: str) -> list[str]:
    """Split a markdown table row into its cells."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    parts = stripped.split("|")
    # A well-formed row has empty strings either side of the pipes.
    return [p.strip() for p in parts[1:-1]]


def normalize(value: str) -> str:
    """Strip markdown emphasis and whitespace so `**CLOSED**` and `CLOSED` compare equal."""
    return re.sub(r"[*`]", "", value).strip()


def parse_risks(text: str) -> list[dict]:
    """Rows from the tables that actually carry Sev and Status."""
    risks: list[dict] = []
    in_risk_table = False
    for line in text.splitlines():
        row = cells(line)
        if not row:
            in_risk_table = False
            continue
        header = tuple(normalize(c).lower() for c in row)
        if header == RISK_HEADER:
            in_risk_table = True
            continue
        # The |---|---| separator under a header.
        if all(set(normalize(c)) <= {"-", ":"} and c for c in row):
            continue
        if not in_risk_table or len(row) != len(RISK_HEADER):
            continue
        risks.append(
            {
                "id": normalize(row[0]),
                "severity": normalize(row[2]),
                "status": normalize(row[3]),
                "risk": normalize(row[1]),
            }
        )
    return risks


def blocking_risks(risks: list[dict]) -> list[dict]:
    """Critical and still OPEN.

    `startswith("OPEN")` rather than equality on purpose: the register writes statuses like
    "CLOSED (Rust side)", and a future "OPEN (pending audit)" must still block.
    """
    return [
        r
        for r in risks
        if r["severity"].lower() == "critical" and r["status"].upper().startswith("OPEN")
    ]


def placeholder_jobs(text: str) -> list[str]:
    """Jobs that only look like coverage.

    Two signals, because one is not enough. A job whose every `run:` is an `echo` is obviously
    inert — but a job can also perform a real-looking command (`xcodebuild -version`) and still
    build nothing, which no heuristic can tell from a genuine job. So a step explicitly NAMED
    "Placeholder" also marks its job, which makes the convention enforceable: if you leave a stub,
    label it, and the gate will hold you to it.

    Parsed by indentation rather than a YAML library so the gate has no dependency to install; the
    workflow's shape is fixed and this only needs to find steps per job.
    """
    offenders: list[str] = []
    current: str | None = None
    has_real_step = False
    declared_placeholder = False
    in_jobs = False

    def flush() -> None:
        if current is not None and (not has_real_step or declared_placeholder):
            offenders.append(current)

    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        job = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if job:
            flush()
            current = job.group(1)
            has_real_step = False
            declared_placeholder = False
            continue
        stripped = line.strip()
        if re.match(r"^-?\s*name:\s*placeholder\b", stripped, re.IGNORECASE):
            declared_placeholder = True
        if stripped.startswith("- uses:") or stripped.startswith("uses:"):
            # An action step is real work (checkout alone is not, but it never stands alone).
            if "actions/checkout" not in stripped:
                has_real_step = True
        if stripped.startswith("run:") or stripped.startswith("- run:"):
            body = stripped.split("run:", 1)[1].strip()
            # `run: |` introduces a block; treat it as real and let the echo test below catch
            # single-line placeholders only.
            if body in {"|", ">"}:
                has_real_step = True
            elif not body.startswith("echo "):
                has_real_step = True
    flush()
    return offenders


SELF_TEST_REGISTER = """
## Risks
| ID | Risk | Sev | Status | Owner | Note |
|----|------|-----|--------|-------|------|
| R-001 | a closed critical | Critical | **CLOSED** | x | done |
| R-002 | an open high | High | OPEN | x | pending |
| R-003 | a mitigating medium | Medium | MITIGATING | x | partial |

## Accepted risks (explicit)
| ID | Risk | Owner | Rationale |
|----|------|-------|-----------|
| R-900 | inherent exposure | product | accepted deliberately |
"""


def self_test() -> int:
    """Exercise the parser and the job scanner against synthetic inputs.

    A gate is a piece of security infrastructure like any other: if its parser silently stops
    matching, it reports success forever. These cases pin the behaviours that would make that
    happen — misreading a differently-shaped table, missing a bolded status, or treating a stub
    job as coverage.
    """
    failures: list[str] = []

    def check(name: str, actual, expected) -> None:
        if actual != expected:
            failures.append(f"{name}: expected {expected!r}, got {actual!r}")

    risks = parse_risks(SELF_TEST_REGISTER)
    # The 4-column "Accepted risks" table must NOT be read as if it had Sev/Status: doing so would
    # interpret its Owner column ("product") as a severity.
    check("only risk-table rows parsed", [r["id"] for r in risks], ["R-001", "R-002", "R-003"])
    check("bold status normalized", risks[0]["status"], "CLOSED")
    check("a closed critical does not block", blocking_risks(risks), [])

    open_critical = parse_risks(
        SELF_TEST_REGISTER.replace("| Critical | **CLOSED** |", "| Critical | OPEN |")
    )
    check(
        "an open critical blocks",
        [r["id"] for r in blocking_risks(open_critical)],
        ["R-001"],
    )
    # Statuses are written with parentheses too; a future "OPEN (pending audit)" must still block.
    qualified = parse_risks(
        SELF_TEST_REGISTER.replace("| Critical | **CLOSED** |", "| Critical | OPEN (pending) |")
    )
    check("a qualified OPEN still blocks", len(blocking_risks(qualified)), 1)

    workflow = """
jobs:
  real:
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
  echo_only:
    steps:
      - uses: actions/checkout@v4
      - run: echo "enabled later"
  looks_busy:
    steps:
      - uses: actions/checkout@v4
      - name: Placeholder
        run: xcodebuild -version
  checkout_only:
    steps:
      - uses: actions/checkout@v4
"""
    check(
        "placeholder jobs detected",
        sorted(placeholder_jobs(workflow)),
        ["checkout_only", "echo_only", "looks_busy"],
    )

    if failures:
        print("release gate SELF-TEST FAILED:")
        for f in failures:
            print(f"  {f}")
        return 1
    print("release gate self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print the full picture, including non-blocking findings",
    )
    parser.add_argument(
        "--placeholders-only",
        action="store_true",
        help=(
            "enforce only the no-placeholder-job rule and REPORT open risks without blocking. "
            "This is the pull-request mode: a permanently open critical risk (an external audit "
            "that has not happened yet) must not turn every CI run red, but a fake job must "
            "always fail. The release workflow runs the full gate."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify the gate's own parser against synthetic inputs and exit",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not RISK_REGISTER.exists():
        print(f"release gate: {RISK_REGISTER} is missing", file=sys.stderr)
        return 1
    if not WORKFLOW.exists():
        print(f"release gate: {WORKFLOW} is missing", file=sys.stderr)
        return 1

    risks = parse_risks(RISK_REGISTER.read_text())
    if not risks:
        # A gate that silently passes because its input stopped parsing is worse than no gate.
        print("release gate: parsed ZERO risks — the register format changed", file=sys.stderr)
        return 1

    blocking = blocking_risks(risks)
    placeholders = placeholder_jobs(WORKFLOW.read_text())

    if args.explain:
        by_status: dict[str, int] = {}
        for r in risks:
            by_status[f"{r['severity']}/{r['status']}"] = (
                by_status.get(f"{r['severity']}/{r['status']}", 0) + 1
            )
        print(f"parsed {len(risks)} risks from RISK_REGISTER.md")
        for key in sorted(by_status):
            print(f"  {by_status[key]:>3}  {key}")
        print()

    ok = True
    if blocking:
        if args.placeholders_only:
            print("NOTE — critical risks still OPEN (not blocking this pull request):")
            for r in blocking:
                print(f"  {r['id']}  {r['risk'][:110]}")
            print("  These BLOCK the release workflow. See scripts/release_gate.py.")
            print()
        else:
            ok = False
            print("BLOCKED — critical risks are still OPEN:")
            for r in blocking:
                print(f"  {r['id']}  {r['risk'][:110]}")
            print()
    if placeholders:
        ok = False
        print("BLOCKED — CI jobs with no real work (they go green and look like coverage):")
        for job in placeholders:
            print(f"  {job}")
        print()

    if ok:
        scope = "placeholder check" if args.placeholders_only else "release gate"
        print(f"{scope} PASSED ({len(risks)} risks parsed, no placeholder jobs)")
        return 0
    print("release gate FAILED: resolve the items above, or downgrade/accept them in")
    print("RISK_REGISTER.md with the reasoning written down.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
