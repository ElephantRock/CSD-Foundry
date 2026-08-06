#!/usr/bin/env python3
"""Repaired Windows-native E0-H v2 adapter over the reviewed v1 native harness."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_harness() -> ModuleType:
    path = Path(__file__).parents[1] / "windows_native_v1" / "native_harness.py"
    spec = importlib.util.spec_from_file_location("e0h_windows_native_v1_harness_for_v2", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load reviewed native harness from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    _load_harness().main()


if __name__ == "__main__":
    main()
