"""Executable scenario registry and validation API."""

from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.runner import ReleaseResult, validate_release
from csd_foundry.scenarios.spec import ScenarioSpec

__all__ = ["ReleaseResult", "SCENARIOS", "ScenarioSpec", "validate_release"]
