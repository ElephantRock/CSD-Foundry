#!/usr/bin/env python3
"""Deterministic artifact archiver for the repaired Windows-native E0-H v2 release."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_archiver() -> ModuleType:
    path = Path(__file__).parents[1] / "windows_native_v1" / "archive_artifacts.py"
    spec = importlib.util.spec_from_file_location(
        "e0h_windows_native_v1_archiver_for_v2", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load reviewed archiver from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    _load_archiver().main()


if __name__ == "__main__":
    main()
