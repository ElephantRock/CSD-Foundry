#!/usr/bin/env python3
"""Compile the E1 A2 paired-curriculum and evaluation artifacts.

Standalone orchestration. Authenticates the immutable A0b2 response-ABI
receipt, the A1 conventional-control receipt, and the predecessor selection
contract; compiles the Foundry training records through the executable
semantics; projects each Foundry record through the A0b2 basis-disposition
truth table; loads the A1 conventional responses; builds the common codeword
task format for both arms; tokenizes both with the frozen
``sshleifer/tiny-gpt2`` tokenizer; validates recordwise token isometry;
packages the development + clean evaluation sets; and instantiates the
PR #74 paired ``E1CurriculumEvaluationContract``.

Emits 12 artifacts under ``data/e1/v6/``:

* ``paired_task_format.json`` — common codeword task format definition.
* ``control_train.jsonl`` — 19 control-arm codeword task records.
* ``foundry_train.jsonl`` — 19 Foundry-arm codeword task records.
* ``control_curriculum_manifest.json`` — control arm manifest.
* ``foundry_curriculum_manifest.json`` — Foundry arm manifest
  (binds raw oracle/verification digests).
* ``development_evaluation.jsonl`` — 4 development transition records.
* ``clean_evaluation.jsonl`` — 4 clean-case records.
* ``evaluation_manifest.json`` — binds both evaluation sets.
* ``tokenization_manifest.json`` — per-record tokenization receipts.
* ``paired_e1_contract.json`` — ``E1CurriculumEvaluationContract``
  instantiation.
* ``paired_e1_manifest.json`` — paired manifest.
* ``a2_receipt.json`` — final receipt binding everything.

The tokenizer loads slowly on first call (~15s). ``HF_HOME`` is honored so an
existing local cache can be reused; otherwise the Hugging Face Hub is
contacted.

The compiler performs no model execution, no GPU allocation, and no metric
evaluation.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from csd_foundry.empirical.e1.paired_curriculum_compiler import (
    RELEASE,
    compile_paired_curriculum,
)

_DEFAULT_OUTPUT_DIRECTORY = Path("data/e1/v6")
_DEFAULT_A1_RECEIPT = Path("data/e1/v5/a1_receipt.json")
_DEFAULT_A1_RESPONSES = Path("data/e1/v5/conventional_control_responses.jsonl")
_DEFAULT_A0B2_RECEIPT = Path("data/e1/v4/a0b2_receipt.json")
_DEFAULT_RESPONSE_ABI = Path("data/e1/v4/response_abi.json")
_DEFAULT_TOKENIZER_CODEBOOK = Path("data/e1/v4/tokenizer_codebook.json")
_DEFAULT_EVALUATION_CASES = Path("data/e1/v4/evaluation_cases.jsonl")
_DEFAULT_SELECTION_CONTRACT = Path("data/e1/v2/selection_contract.json")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/compile_paired_curriculum.py",
    )
    parser.add_argument(
        "--source-commit",
        required=True,
        help="Git commit SHA that produced these artifacts (commit S).",
    )
    parser.add_argument(
        "--a1-receipt",
        type=Path,
        default=_DEFAULT_A1_RECEIPT,
        help="Predecessor (A1) conventional-control receipt path.",
    )
    parser.add_argument(
        "--a1-responses",
        type=Path,
        default=_DEFAULT_A1_RESPONSES,
        help="Predecessor (A1) conventional responses path.",
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
        "--evaluation-cases",
        type=Path,
        default=_DEFAULT_EVALUATION_CASES,
        help="Frozen evaluation cases path.",
    )
    parser.add_argument(
        "--selection-contract",
        type=Path,
        default=_DEFAULT_SELECTION_CONTRACT,
        help="Predecessor selection contract path.",
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
    a1_receipt_path: Path,
    a1_responses_path: Path,
    a0b2_receipt_path: Path,
    response_abi_path: Path,
    tokenizer_codebook_path: Path,
    evaluation_cases_path: Path,
    selection_contract_path: Path,
) -> dict[str, bytes]:
    """Compile the 12 canonical artifacts and return them keyed by filename."""

    return compile_paired_curriculum(
        source_commit=source_commit,
        a1_receipt_path=str(a1_receipt_path),
        a1_responses_path=str(a1_responses_path),
        a0b2_receipt_path=str(a0b2_receipt_path),
        response_abi_path=str(response_abi_path),
        tokenizer_codebook_path=str(tokenizer_codebook_path),
        evaluation_cases_path=str(evaluation_cases_path),
        selection_contract_path=str(selection_contract_path),
    )


def main() -> None:
    args = _parser().parse_args()
    artifacts = compile_artifacts(
        source_commit=args.source_commit,
        a1_receipt_path=args.a1_receipt,
        a1_responses_path=args.a1_responses,
        a0b2_receipt_path=args.a0b2_receipt,
        response_abi_path=args.response_abi,
        tokenizer_codebook_path=args.tokenizer_codebook,
        evaluation_cases_path=args.evaluation_cases,
        selection_contract_path=args.selection_contract,
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
