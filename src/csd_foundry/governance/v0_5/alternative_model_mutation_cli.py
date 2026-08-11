"""CLI gate for the v0.5-D4 alternative-model mutation campaign."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from csd_foundry.governance.v0_5.alternative_model_mutations import (
    evaluate_alternative_mutations,
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="csd-foundry-alternative-model-mutations-v0-5")
    parser.add_argument("--release", default="v0.5")
    parser.add_argument("--output")
    args = parser.parse_args()
    report = evaluate_alternative_mutations(args.release)
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
