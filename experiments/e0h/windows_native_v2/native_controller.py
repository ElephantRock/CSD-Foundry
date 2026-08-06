#!/usr/bin/env python3
"""Repaired Windows-native E0-H v2 controller over the reviewed v1 controller."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

RELEASE = "e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2"


def _load_controller() -> ModuleType:
    path = Path(__file__).parents[1] / "windows_native_v1" / "native_controller.py"
    spec = importlib.util.spec_from_file_location("e0h_windows_native_v1_controller_for_v2", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load reviewed controller from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.RELEASE = RELEASE
    return module


def main() -> None:
    _load_controller().main()


if __name__ == "__main__":
    main()
