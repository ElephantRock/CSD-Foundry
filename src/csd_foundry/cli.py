"""Command-line entry point for CSD Foundry."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from csd_foundry.kernel.oracle import CsdOracle


def main() -> None:
    parser = argparse.ArgumentParser(prog="csd-foundry")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="execute the M-01 dependency-change fixture")
    args = parser.parse_args()

    if args.command == "demo":
        from fixtures.v0_1.scenarios import m01

        state, event = m01()
        result = CsdOracle().apply(state, event)
        print(json.dumps(asdict(result.trace), indent=2, sort_keys=True))
