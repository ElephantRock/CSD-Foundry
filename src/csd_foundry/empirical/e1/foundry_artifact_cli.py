"""CLI for deterministic E1 executable-semantics artifact compilation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
    validate_e1_foundry_artifacts,
    write_e1_foundry_artifacts,
)
from csd_foundry.scenarios.registry import SCENARIOS

_DEFAULT_OUTPUT_DIRECTORY = Path("artifacts/e1/foundry-v1")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e1.foundry_artifact_cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("compile", "validate"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--release", default="e1-foundry-artifacts/1")
        command_parser.add_argument("--selection-release", default="e1-candidate/1")
        command_parser.add_argument("--source-commit", required=True)
        command_parser.add_argument(
            "--output-dir",
            type=Path,
            default=_DEFAULT_OUTPUT_DIRECTORY,
        )
    return parser


def main() -> None:
    args = _parser().parse_args()
    selection = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=args.selection_release,
        source_commit=args.source_commit,
    )
    if args.command == "compile":
        bundle = compile_e1_foundry_artifacts(
            SCENARIOS,
            selection,
            release=args.release,
            selection_release=args.selection_release,
            source_commit=args.source_commit,
        )
        write_e1_foundry_artifacts(bundle, args.output_dir)
        payload = {
            "status": "compiled",
            "output_directory": str(args.output_dir),
            **bundle.to_dict(),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    report = validate_e1_foundry_artifacts(
        args.output_dir,
        SCENARIOS,
        selection,
        release=args.release,
        selection_release=args.selection_release,
        source_commit=args.source_commit,
    )
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    raise SystemExit(0 if report.success else 1)


if __name__ == "__main__":
    main()
