import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_seed_manifest_counts_and_validation() -> None:
    manifest = json.loads((ROOT / "data/seed/v0.1/csd_reasoning_manifest_v0.1.json").read_text())
    assert manifest["sft"]["records"] == 252
    assert manifest["preference"]["records"] == 63
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/validate_csd_reasoning_seed.py"),
            "--directory",
            str(ROOT / "data/seed/v0.1"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert '"status": "valid"' in completed.stdout
