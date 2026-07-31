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


def _add_release_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release", default="v0.1", help="scenario release identifier")
    parser.add_argument("--output", help="optional JSON output path")


def main() -> None:
    parser = argparse.ArgumentParser(prog="csd-foundry")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="execute the M-01 dependency-change fixture")

    scenarios = sub.add_parser("scenarios", help="validate executable scenario releases")
    scenario_sub = scenarios.add_subparsers(dest="scenario_command", required=True)
    scenario_validate = scenario_sub.add_parser("validate", help="validate a scenario release")
    _add_release_argument(scenario_validate)

    mutations = sub.add_parser("mutations", help="evaluate invariant-targeted mutations")
    mutation_sub = mutations.add_subparsers(dest="mutation_command", required=True)
    mutation_evaluate = mutation_sub.add_parser("evaluate", help="evaluate mutation kill coverage")
    _add_release_argument(mutation_evaluate)

    args = parser.parse_args()

    if args.command == "demo":
        from csd_foundry.fixtures.v0_1.scenarios import m01

        state, event = m01()
        result = CsdOracle().apply(state, event)
        print(json.dumps(asdict(result.trace), indent=2, sort_keys=True))
        return

    if args.command == "scenarios" and args.scenario_command == "validate":
        from csd_foundry.scenarios.registry import SCENARIOS
        from csd_foundry.scenarios.runner import validate_release

        result = validate_release(SCENARIOS, args.release)
        _emit(result.to_dict(), args.output)
        if not result.success:
            raise SystemExit(1)
        return

    if args.command == "mutations" and args.mutation_command == "evaluate":
        from csd_foundry.synthesis.scenario_mutations import evaluate_release

        result = evaluate_release(args.release)
        _emit(result.to_dict(), args.output)
        if not result.success:
            raise SystemExit(1)
        return

    parser.error("unsupported command")
