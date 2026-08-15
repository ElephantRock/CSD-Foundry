"""CLI gate for the P3.7 Phase-3 integrated qualification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from csd_foundry.governance.v0_5.phase3_qualification import run_phase3_qualification


def main() -> None:
    parser = argparse.ArgumentParser(prog="csd-foundry-phase3-qualification-v0-5")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = run_phase3_qualification()
    rendered = json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    raise SystemExit(0 if report.success else 1)


if __name__ == "__main__":
    main()
