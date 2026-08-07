#!/usr/bin/env python3
"""Compile the E1 A1 conventional-control response artifacts.

Standalone orchestration. Authenticates the immutable A0b2 response-ABI
receipt and its frozen response ABI and tokenizer codebook constituents,
re-derives the frozen E1 training population at the predecessor source
commit, applies the three frozen event rules, and emits four artifacts
under ``data/e1/v5/``:

* ``conventional_rule_catalog.json`` — the frozen three-rule authority.
* ``conventional_control_responses.jsonl`` — one response per training record.
* ``conventional_control_manifest.json`` — counts, IDs, and provenance.
* ``a1_receipt.json`` — source_commit, constituent digests, and predecessor identity.

The compiler performs no model execution, no runner/oracle loading, no GPU
allocation, and reads no reference labels, traces, verification outputs, or
evaluation cases.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from csd_foundry.empirical.e1.conventional_generator import (
    RELEASE,
    compile_conventional_generator,
)

_DEFAULT_OUTPUT_DIRECTORY = Path("data/e1/v5")
_DEFAULT_A0B2_RECEIPT = Path("data/e1/v4/a0b2_receipt.json")
_DEFAULT_RESPONSE_ABI = Path("data/e1/v4/response_abi.json")
_DEFAULT_TOKENIZER_CODEBOOK = Path("data/e1/v4/tokenizer_codebook.json")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/compile_conventional_generator.py",
    )
    parser.add_argument(
        "--source-commit",
        required=True,
        help="Git commit SHA that produced these artifacts (commit S).",
    )
    parser.add_argument(
        "--a0b2-receipt",
        type=Path,
        default=_DEFAULT_A0B2_RECEIPT,
        help="Predecessor (A0b2) response-ABI receipt path.",
    )
    parser.add_argument(
        "--response-abi",
        type=Path,
        default=_DEFAULT_RESPONSE_ABI,
        help="Frozen response ABI path.",
    )
    parser.add_argument(
        "--tokenizer-codebook",
        type=Path,
        default=_DEFAULT_TOKENIZER_CODEBOOK,
        help="Frozen tokenizer codebook path.",
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
    a0b2_receipt_path: Path,
    response_abi_path: Path,
    tokenizer_codebook_path: Path,
) -> dict[str, bytes]:
    """Compile the four canonical artifacts and return them keyed by filename."""

    return compile_conventional_generator(
        source_commit=source_commit,
        a0b2_receipt_path=str(a0b2_receipt_path),
        response_abi_path=str(response_abi_path),
        tokenizer_codebook_path=str(tokenizer_codebook_path),
    )


def main() -> None:
    args = _parser().parse_args()
    artifacts = compile_artifacts(
        source_commit=args.source_commit,
        a0b2_receipt_path=args.a0b2_receipt,
        response_abi_path=args.response_abi,
        tokenizer_codebook_path=args.tokenizer_codebook,
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
