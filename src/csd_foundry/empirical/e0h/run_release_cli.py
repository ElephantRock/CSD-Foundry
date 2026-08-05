"""CLI for deterministic E0-H run-release compilation and reconstruction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from csd_foundry.empirical.e0h.run_release import (
    compile_e0h_run_release,
    load_e0h_run_release_inputs,
    validate_e0h_run_release,
    write_e0h_run_release,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e0h.run_release_cli")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("compile", "validate"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--inputs", type=Path, required=True)
        command_parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    inputs = load_e0h_run_release_inputs(args.inputs.read_text(encoding="utf-8"))
    if args.command == "compile":
        bundle = compile_e0h_run_release(inputs)
        write_e0h_run_release(bundle, args.output_dir)
        print(
            json.dumps(
                {
                    "status": "compiled",
                    "output_directory": str(args.output_dir),
                    **bundle.to_dict(),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    report = validate_e0h_run_release(args.output_dir, inputs)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    raise SystemExit(0 if report.success else 1)


if __name__ == "__main__":
    main()
