#!/usr/bin/env python3
"""Compile the E1 response ABI, tokenizer codebook, parser, and metric artifacts.

Standalone orchestration. Authenticates the immutable A0b1 population-support
receipt and the A0c predecessor audit, loads the frozen
``sshleifer/tiny-gpt2`` tokenizer, generates and verifies the single-token
codebook, builds the strict parser, the primary family-macro accuracy and
clean-case safety metric contracts, and the development + clean evaluation
cases, and emits a receipt under ``data/e1/v4/``.

The tokenizer loads slowly on first call (~15s). ``HF_HOME`` is honored so an
existing local cache can be reused; otherwise the Hugging Face Hub is contacted.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from csd_foundry.empirical.e1.response_abi_metrics import (
    RELEASE,
    compile_response_abi_metrics,
)

_DEFAULT_OUTPUT_DIRECTORY = Path("data/e1/v4")
_DEFAULT_PREDECESSOR_RECEIPT = Path("data/e1/v3/population_support_receipt.json")
_DEFAULT_PREDECESSOR_AUDIT = Path("data/e1/v2/label_space_audit.json")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/compile_response_abi_metrics.py",
    )
    parser.add_argument(
        "--source-commit",
        required=True,
        help="Git commit SHA that produced these artifacts (commit S).",
    )
    parser.add_argument(
        "--predecessor-receipt",
        type=Path,
        default=_DEFAULT_PREDECESSOR_RECEIPT,
        help="Predecessor (A0b1) population-support receipt path.",
    )
    parser.add_argument(
        "--predecessor-audit",
        type=Path,
        default=_DEFAULT_PREDECESSOR_AUDIT,
        help="Predecessor (A0c) label-space audit path.",
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


def compile_artifacts(
    *,
    source_commit: str,
    predecessor_receipt_path: Path,
    predecessor_audit_path: Path,
) -> dict[str, bytes]:
    """Compile the six canonical artifacts and return them keyed by filename."""

    return compile_response_abi_metrics(
        source_commit=source_commit,
        predecessor_population_receipt_path=str(predecessor_receipt_path),
        predecessor_audit_path=str(predecessor_audit_path),
    )


def main() -> None:
    args = _parser().parse_args()
    artifacts = compile_artifacts(
        source_commit=args.source_commit,
        predecessor_receipt_path=args.predecessor_receipt,
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
    # Honor an existing local HF cache if the caller did not set HF_HOME.
    _local_cache = Path("artifacts") / "e0h-windows-native-v2" / "hf-home"
    if "HF_HOME" not in os.environ and _local_cache.is_dir():
        os.environ["HF_HOME"] = str(_local_cache)
    main()
