#!/usr/bin/env python
"""Daily monitor for the local CSD-Foundry checkout.

Runs the full AGENTS.md gate suite (ruff format, ruff lint, mypy, pytest) plus
all documented CLI validation gates, then prints a compact pass/fail summary
and a one-line HEAD/HEAD@{1} delta. Designed to be invoked by a scheduled
automation; safe to run manually.

Exit code 0 means every gate passed AND no upstream-pull conflict occurred.
Non-zero means at least one gate failed or the pull was blocked; see output.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VENV_PYTHON = REPO / ".venv" / "Scripts" / "python.exe"
FALLBACK_PYTHON = sys.executable


def _run(cmd: list[str], *, timeout: int = 600, cwd: Path = REPO) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def _git(args: list[str]) -> tuple[int, str, str]:
    return _run(["git"] + args, timeout=120)


def main() -> int:
    python = str(VENV_PYTHON) if VENV_PYTHON.exists() else FALLBACK_PYTHON
    results: list[tuple[str, int, str]] = []
    overall = 0

    def record(name: str, rc: int, detail: str = "") -> None:
        nonlocal overall
        results.append((name, rc, detail.strip()))
        if rc != 0:
            overall = rc

    # 0. Preflight: report working-tree dirt and current HEAD.
    rc, head_before, _ = _git(["rev-parse", "--short", "HEAD"])
    head_before = head_before.strip()
    rc_st, status_out, _ = _git(["status", "--short"])
    dirty_count = len([line for line in status_out.splitlines() if line.strip()])

    # 1. Fetch (non-destructive). Do NOT auto-pull if the tree is dirty — that
    #    would risk clobbering local work or producing a merge conflict.
    rc_fetch, _, err_fetch = _git(["fetch", "origin", "main"])
    rc_ahead, ahead_out, _ = _git(["rev-list", "--count", "HEAD..origin/main"])
    behind = int(ahead_out.strip()) if ahead_out.strip().isdigit() else 0

    pulled = False
    if behind == 0:
        record("git.up-to-date", 0)
    elif dirty_count > 0:
        # Refuse to pull over local changes. Report and proceed against current HEAD.
        record(
            "git.pull-skipped-dirty-tree",
            1,
            f"{dirty_count} local files modified; behind origin by {behind}",
        )
    else:
        rc_pull, _, err_pull = _git(["pull", "--ff-only", "origin", "main"])
        pulled = rc_pull == 0
        record("git.pull", rc_pull, err_pull)

    # 2. Static gates.
    if shutil.which("ruff"):
        rc, out, err = _run(["ruff", "format", "--check", "."], timeout=180)
        record("ruff.format", rc, err or out[-300:])
        rc, out, err = _run(["ruff", "check", "."], timeout=180)
        record("ruff.lint", rc, err or out[-300:])
    else:
        record("ruff.missing", 127, "ruff not on PATH")

    rc, out, err = _run([python, "-m", "mypy", "src"], timeout=300)
    record("mypy.src", rc, err[-300:] or out[-300:])

    # 3. pytest.
    rc, out, err = _run([python, "-m", "pytest"], timeout=900)
    # pytest prints its summary line on the last stdout line(s).
    summary = ""
    for line in out.splitlines()[::-1]:
        if "passed" in line or "failed" in line or "error" in line:
            summary = line.strip()
            break
    record("pytest", rc, summary or err[-200:])

    # 4. CLI gates (compact: exit code + JSON status field).
    cli_gates = [
        ("v0.1.scenarios", ["csd-foundry", "scenarios", "validate", "--release", "v0.1"]),
        ("v0.1.mutations", ["csd-foundry", "mutations", "evaluate", "--release", "v0.1"]),
        ("v0.3.temporal", ["csd-foundry", "temporal", "validate", "--release", "v0.3"]),
        ("v0.3.temporal-mutations", ["csd-foundry", "temporal", "mutations", "--release", "v0.3"]),
        ("v0.5.contract-freeze", [python, "scripts/validate_contract_freeze_v0_5.py"]),
        ("v0.5.governance", ["csd-foundry-governance", "--release", "v0.5"]),
        ("v0.5.admission", ["csd-foundry-admission", "--release", "v0.5"]),
        ("v0.5.temporal", ["csd-foundry-temporal-v0-5", "--release", "v0.5"]),
        (
            "v0.1.seed",
            [python, "scripts/validate_csd_reasoning_seed.py", "--directory", "data/seed/v0.1"],
        ),
    ]
    for sub in (
        "contracts",
        "determinism",
        "identities",
        "replay",
        "execution",
        "publication",
        "reconciliation",
    ):
        cli_gates.append((f"v0.4.{sub}", ["csd-foundry", "synthesize", sub, "--release", "v0.4"]))

    for name, cmd in cli_gates:
        rc, out, err = _run(cmd, timeout=300)
        status = ""
        if out:
            try:
                status = "status=" + json.loads(out).get("status", "?")
            except json.JSONDecodeError:
                status = "non-json"
        record(name, rc, status or (err[-150:]))

    # 5. Report.
    rc_head, head_after, _ = _git(["rev-parse", "--short", "HEAD"])
    head_after = head_after.strip()
    delta = "no change" if head_before == head_after else f"{head_before} -> {head_after}"

    print("=" * 70)
    print(f"CSD-Foundry monitor  HEAD: {head_after}  ({delta})")
    tree_state = (
        f"working tree: {dirty_count} modified files  |  "
        f"behind origin: {behind}  |  pulled this run: {pulled}"
    )
    print(tree_state)
    print("-" * 70)
    width = max(len(n) for n, _, _ in results)
    for name, rc, detail in results:
        mark = "PASS" if rc == 0 else f"FAIL({rc})"
        suffix = f"  {detail}" if detail and rc != 0 else (f"  {detail}" if detail else "")
        print(f"  {name:<{width}}  {mark}{suffix}")
    print("=" * 70)
    n_pass = sum(1 for _, rc, _ in results if rc == 0)
    n_fail = len(results) - n_pass
    verdict = "ALL GREEN" if overall == 0 else "REGRESSION"
    print(f"{n_pass} passed, {n_fail} failed of {len(results)} checks  ->  {verdict}")
    return overall


if __name__ == "__main__":
    sys.exit(main())
