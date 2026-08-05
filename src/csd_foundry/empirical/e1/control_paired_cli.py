"""CLI for E1 conventional-control and paired-artifact compilation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from csd_foundry.empirical.e1.artifact_set_io import validate_artifact_files
from csd_foundry.empirical.e1.control_paired_compiler import (
    E1ControlArtifactBundle,
    E1PairedArtifactBundle,
    compile_e1_control_prompts,
    compile_e1_conventional_control,
    finalize_e1_paired_artifacts,
    load_conventional_responses,
    load_token_inventory,
    write_artifact_files,
)
from csd_foundry.empirical.e1.experiment_contract import (
    E1ExperimentContract,
    compile_e1_experiment_contract,
)
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    E1FoundryArtifactBundle,
    compile_e1_foundry_artifacts,
)
from csd_foundry.scenarios.registry import SCENARIOS

_DEFAULT_SELECTION_RELEASE = "e1-candidate/1"
_DEFAULT_FOUNDRY_RELEASE = "e1-foundry-artifacts/1"
_DEFAULT_CONTROL_RELEASE = "e1-control-artifacts/1"
_DEFAULT_PAIRED_RELEASE = "e1-paired-artifacts/1"


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--selection-release", default=_DEFAULT_SELECTION_RELEASE)
    parser.add_argument("--foundry-release", default=_DEFAULT_FOUNDRY_RELEASE)


def _add_control_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--control-release", default=_DEFAULT_CONTROL_RELEASE)
    parser.add_argument("--generator-revision-digest", required=True)
    parser.add_argument("--generation-command-digest", required=True)
    parser.add_argument("--validation-command-digest", required=True)


def _add_paired_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--token-inventory", type=Path, required=True)
    parser.add_argument("--paired-release", default=_DEFAULT_PAIRED_RELEASE)
    parser.add_argument("--primary-metric-implementation-digest", required=True)
    parser.add_argument("--safety-metric-implementation-digest", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e1.control_paired_cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prompts = subparsers.add_parser("prompts")
    _add_source_arguments(prompts)
    prompts.add_argument("--output-dir", type=Path, required=True)

    for command in ("compile-control", "validate-control"):
        control = subparsers.add_parser(command)
        _add_source_arguments(control)
        _add_control_arguments(control)
        control.add_argument("--output-dir", type=Path, required=True)

    for command in ("finalize", "validate-paired"):
        paired = subparsers.add_parser(command)
        _add_source_arguments(paired)
        _add_control_arguments(paired)
        _add_paired_arguments(paired)
        paired.add_argument("--output-dir", type=Path, required=True)
    return parser


def _source_bundles(
    args: argparse.Namespace,
) -> tuple[
    E1ExperimentContract,
    E1FoundryArtifactBundle,
]:
    source_commit = cast(str, args.source_commit)
    selection_release = cast(str, args.selection_release)
    foundry_release = cast(str, args.foundry_release)
    selection = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=selection_release,
        source_commit=source_commit,
    )
    foundry = compile_e1_foundry_artifacts(
        SCENARIOS,
        selection,
        release=foundry_release,
        selection_release=selection_release,
        source_commit=source_commit,
    )
    return selection, foundry


def _control_bundle(
    args: argparse.Namespace,
    foundry: E1FoundryArtifactBundle,
) -> E1ControlArtifactBundle:
    responses_path = cast(Path, args.responses)
    responses = load_conventional_responses(responses_path.read_bytes())
    return compile_e1_conventional_control(
        foundry,
        responses,
        release=cast(str, args.control_release),
        generator_revision_digest=cast(str, args.generator_revision_digest),
        generation_command_digest=cast(str, args.generation_command_digest),
        validation_command_digest=cast(str, args.validation_command_digest),
    )


def _paired_bundle(
    args: argparse.Namespace,
    selection: E1ExperimentContract,
    foundry: E1FoundryArtifactBundle,
    control: E1ControlArtifactBundle,
) -> E1PairedArtifactBundle:
    inventory_path = cast(Path, args.token_inventory)
    inventory = load_token_inventory(inventory_path.read_text(encoding="utf-8"))
    return finalize_e1_paired_artifacts(
        selection,
        foundry,
        control,
        inventory,
        release=cast(str, args.paired_release),
        source_commit=cast(str, args.source_commit),
        primary_metric_implementation_digest=cast(str, args.primary_metric_implementation_digest),
        safety_metric_implementation_digest=cast(str, args.safety_metric_implementation_digest),
    )


def main() -> None:
    args = _parser().parse_args()
    selection, foundry = _source_bundles(args)
    output_dir = cast(Path, args.output_dir)

    if args.command == "prompts":
        prompt_file = compile_e1_control_prompts(foundry)
        write_artifact_files((prompt_file,), output_dir)
        print(
            json.dumps(
                {
                    "status": "compiled",
                    "output_directory": str(output_dir),
                    "prompt_inventory": prompt_file.receipt(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    control = _control_bundle(args, foundry)
    if args.command == "compile-control":
        write_artifact_files(control.files, output_dir)
        print(
            json.dumps(
                {
                    "status": "compiled",
                    "output_directory": str(output_dir),
                    **control.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if args.command == "validate-control":
        report = validate_artifact_files(output_dir, control.files)
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        raise SystemExit(0 if report.success else 1)

    paired = _paired_bundle(args, selection, foundry, control)
    if args.command == "finalize":
        write_artifact_files(paired.files, output_dir)
        print(
            json.dumps(
                {
                    "status": "compiled",
                    "output_directory": str(output_dir),
                    **paired.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    report = validate_artifact_files(output_dir, paired.files)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    raise SystemExit(0 if report.success else 1)


if __name__ == "__main__":
    main()
