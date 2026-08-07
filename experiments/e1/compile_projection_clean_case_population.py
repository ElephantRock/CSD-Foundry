#!/usr/bin/env python3
"""Compile the E1 primary projection and clean-case population artifacts.

Standalone orchestration. Authenticates the immutable A0c predecessor audit
against pinned constants, selects ``basis_disposition`` as the E1 primary
semantic projection, compiles four straightforward valid transition clean cases
across four symbolic families, and emits a population-support receipt under
``data/e1/v3/``.

Pure CPU. No tokenizer, no model, no GPU.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from csd_foundry.empirical.e1.projection_clean_case_population import (
    RELEASE,
    compile_projection_clean_case_population,
)

_DEFAULT_OUTPUT_DIRECTORY = Path("data/e1/v3")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/compile_projection_clean_case_population.py",
    )
    parser.add_argument(
        "--source-commit",
        required=True,
        help="Git commit SHA that produced these artifacts (commit S).",
    )
    parser.add_argument(
        "--predecessor-audit",
        type=Path,
        default=Path("data/e1/v2/label_space_audit.json"),
        help="Predecessor (A0c) audit artifact path.",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=_DEFAULT_OUTPUT_DIRECTORY,
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Recompile and byte-compare all artifacts on disk.",
    )
    return parser


def _module_sha256() -> str:
    """SHA-256 of the exact implementation module bytes (compiler identity)."""

    module_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "csd_foundry"
        / "empirical"
        / "e1"
        / "projection_clean_case_population.py"
    )
    return hashlib.sha256(module_path.read_bytes()).hexdigest()


def compile_artifacts(
    *,
    source_commit: str,
    predecessor_audit_path: Path,
) -> dict[str, bytes]:
    """Compile the six canonical artifacts and return them keyed by filename."""

    predecessor_audit_bytes = predecessor_audit_path.read_bytes()
    population = compile_projection_clean_case_population(
        source_commit=source_commit,
        predecessor_audit_bytes=predecessor_audit_bytes,
        compiler_implementation_sha256=_module_sha256(),
    )
    return population.artifacts()


def main() -> None:
    args = _parser().parse_args()
    artifacts = compile_artifacts(
        source_commit=args.source_commit,
        predecessor_audit_path=args.predecessor_audit,
    )

    if args.validate:
        for name, content in artifacts.items():
            path = args.output_directory / name
            if not path.exists() or path.read_bytes() != content:
                print(f"artifact mismatch: {path}", file=sys.stderr)
                raise SystemExit(1)
        print(f"all artifacts verified under {args.output_directory}")
        return

    args.output_directory.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (args.output_directory / name).write_bytes(content)
    print(f"artifacts written under {args.output_directory} (release {RELEASE})")


if __name__ == "__main__":
    main()
