#!/usr/bin/env python3
"""Compile the deterministic E1 label-space audit artifact.

Standalone orchestration script. Rebuilds the selection contract and Foundry
bundle in-process from the frozen scenario registry, runs the label-space
audit, and writes (or validates) ``data/e1/v1/label_space_audit.json``.

Pure CPU. No tokenizer, no model, no GPU.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow execution both as a script and as an importlib-loaded module.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
)
from csd_foundry.empirical.e1.label_space_audit import (
    audit_e1_label_space,
    validate_label_space_audit,
    write_label_space_audit,
)
from csd_foundry.scenarios.registry import SCENARIOS

_DEFAULT_RELEASE = "e1-foundry-artifacts/1"
_DEFAULT_SELECTION_RELEASE = "e1-candidate/1"
_DEFAULT_AUDIT_RELEASE = "e1-label-space-audit/1"
_DEFAULT_OUTPUT = Path("data/e1/v1/label_space_audit.json")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/compile_label_space_audit.py",
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument(
        "--release",
        default=_DEFAULT_RELEASE,
        help="Foundry bundle release (default: %(default)s)",
    )
    parser.add_argument(
        "--selection-release",
        default=_DEFAULT_SELECTION_RELEASE,
        help="Selection contract release (default: %(default)s)",
    )
    parser.add_argument(
        "--audit-release",
        default=_DEFAULT_AUDIT_RELEASE,
        help="Audit artifact release (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help="Audit artifact path (default: %(default)s)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Recompile and byte-compare against the on-disk artifact.",
    )
    return parser


def compile_audit(*, source_commit: str, release: str, selection_release: str) -> object:
    """Compile the audit artifact from the frozen scenario registry."""

    selection = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=selection_release,
        source_commit=source_commit,
    )
    bundle = compile_e1_foundry_artifacts(
        SCENARIOS,
        selection,
        release=release,
        selection_release=selection_release,
        source_commit=source_commit,
    )
    return audit_e1_label_space(
        bundle,
        selection,
        release=_DEFAULT_AUDIT_RELEASE,
        source_commit=source_commit,
    )


def main() -> None:
    args = _parser().parse_args()
    audit = compile_audit(
        source_commit=args.source_commit,
        release=args.release,
        selection_release=args.selection_release,
    )
    if args.validate:
        if not validate_label_space_audit(audit, str(args.output)):
            print(f"audit artifact mismatch: {args.output}", file=sys.stderr)
            raise SystemExit(1)
        print(f"audit artifact verified: {args.output}")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_label_space_audit(audit, str(args.output))
    print(f"audit artifact written: {args.output}")


if __name__ == "__main__":
    main()
