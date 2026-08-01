"""Command-line entry point for CSD Foundry."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from csd_foundry.kernel.oracle import CsdOracle


def _emit(payload: dict[str, object], output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(rendered, end="")
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")


def _add_release_argument(
    parser: argparse.ArgumentParser,
    *,
    default: str,
) -> None:
    parser.add_argument("--release", default=default, help="release identifier")
    parser.add_argument("--output", help="optional JSON output path")


def main() -> None:
    parser = argparse.ArgumentParser(prog="csd-foundry")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="execute the M-01 dependency-change fixture")

    scenarios = sub.add_parser("scenarios", help="validate executable scenario releases")
    scenario_sub = scenarios.add_subparsers(dest="scenario_command", required=True)
    scenario_validate = scenario_sub.add_parser("validate", help="validate a scenario release")
    _add_release_argument(scenario_validate, default="v0.1")

    mutations = sub.add_parser("mutations", help="evaluate invariant-targeted mutations")
    mutation_sub = mutations.add_subparsers(dest="mutation_command", required=True)
    mutation_evaluate = mutation_sub.add_parser("evaluate", help="evaluate mutation kill coverage")
    _add_release_argument(mutation_evaluate, default="v0.1")

    temporal = sub.add_parser("temporal", help="validate temporal kernel releases")
    temporal_sub = temporal.add_subparsers(dest="temporal_command", required=True)
    temporal_validate = temporal_sub.add_parser("validate", help="validate temporal scenarios")
    _add_release_argument(temporal_validate, default="v0.3")
    temporal_mutations = temporal_sub.add_parser(
        "mutations",
        help="evaluate temporal mutation coverage",
    )
    _add_release_argument(temporal_mutations, default="v0.3")

    synthesize = sub.add_parser("synthesize", help="operate the synthesis engine")
    synthesis_sub = synthesize.add_subparsers(dest="synthesis_command", required=True)
    synthesis_contracts = synthesis_sub.add_parser(
        "contracts",
        help="validate synthesis contracts and release policies",
    )
    _add_release_argument(synthesis_contracts, default="v0.4")
    synthesis_determinism = synthesis_sub.add_parser(
        "determinism",
        help="validate deterministic choice primitives and frozen vectors",
    )
    _add_release_argument(synthesis_determinism, default="v0.4")
    synthesis_identities = synthesis_sub.add_parser(
        "identities",
        help="validate canonical values and deterministic entity identities",
    )
    _add_release_argument(synthesis_identities, default="v0.4")
    synthesis_replay = synthesis_sub.add_parser(
        "replay",
        help="validate deterministic choice ledgers and attempt replay",
    )
    _add_release_argument(synthesis_replay, default="v0.4")
    synthesis_execution = synthesis_sub.add_parser(
        "execution",
        help="validate execution inventories and bounded operational evidence",
    )
    _add_release_argument(synthesis_execution, default="v0.4")

    args = parser.parse_args()

    if args.command == "demo":
        from csd_foundry.fixtures.v0_1.scenarios import m01

        state, event = m01()
        demo_result = CsdOracle().apply(state, event)
        print(json.dumps(asdict(demo_result.trace), indent=2, sort_keys=True))
        return

    if args.command == "scenarios" and args.scenario_command == "validate":
        from csd_foundry.scenarios.registry import SCENARIOS
        from csd_foundry.scenarios.runner import validate_release

        scenario_result = validate_release(SCENARIOS, args.release)
        _emit(scenario_result.to_dict(), args.output)
        if not scenario_result.success:
            raise SystemExit(1)
        return

    if args.command == "mutations" and args.mutation_command == "evaluate":
        from csd_foundry.synthesis.scenario_mutations import evaluate_release

        mutation_result = evaluate_release(args.release)
        _emit(mutation_result.to_dict(), args.output)
        if not mutation_result.success:
            raise SystemExit(1)
        return

    if args.command == "temporal" and args.temporal_command == "validate":
        from csd_foundry.temporal.v0_3 import validate_release as validate_temporal_release

        temporal_result = validate_temporal_release(args.release)
        _emit(temporal_result.to_dict(), args.output)
        if not temporal_result.success:
            raise SystemExit(1)
        return

    if args.command == "temporal" and args.temporal_command == "mutations":
        from csd_foundry.synthesis.temporal_mutations import (
            evaluate_release as evaluate_temporal_mutations,
        )

        temporal_mutation_result = evaluate_temporal_mutations(args.release)
        _emit(temporal_mutation_result.to_dict(), args.output)
        if not temporal_mutation_result.success:
            raise SystemExit(1)
        return

    if args.command == "synthesize" and args.synthesis_command == "determinism":
        from csd_foundry.synthesis.v0_4.determinism_validation import (
            validate_determinism,
        )

        determinism_result = validate_determinism(args.release)
        _emit(determinism_result.to_dict(), args.output)
        if not determinism_result.success:
            raise SystemExit(1)
        return

    if args.command == "synthesize" and args.synthesis_command == "identities":
        from csd_foundry.synthesis.v0_4.identity_validation import (
            validate_identities,
        )

        identity_result = validate_identities(args.release)
        _emit(identity_result.to_dict(), args.output)
        if not identity_result.success:
            raise SystemExit(1)
        return

    if args.command == "synthesize" and args.synthesis_command == "replay":
        from csd_foundry.synthesis.v0_4.replay_validation import validate_replay

        replay_result = validate_replay(args.release)
        _emit(replay_result.to_dict(), args.output)
        if not replay_result.success:
            raise SystemExit(1)
        return

    if args.command == "synthesize" and args.synthesis_command == "execution":
        from csd_foundry.synthesis.v0_4.execution_validation import (
            validate_execution_protocol,
        )

        execution_result = validate_execution_protocol(args.release)
        _emit(execution_result.to_dict(), args.output)
        if not execution_result.success:
            raise SystemExit(1)
        return

    if args.command == "synthesize" and args.synthesis_command == "contracts":
        from csd_foundry.synthesis.v0_4.validation import (
            validate_release as validate_synthesis_contracts,
        )

        synthesis_result = validate_synthesis_contracts(args.release)
        _emit(synthesis_result.to_dict(), args.output)
        if not synthesis_result.success:
            raise SystemExit(1)
        return

    parser.error("unsupported command")
