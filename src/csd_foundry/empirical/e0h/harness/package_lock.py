"""Validate the concrete E0-H Python graph and hash-locked install surface."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
from pathlib import Path
from typing import cast

from csd_foundry.empirical.e0h import E0HRunReleaseInputs
from csd_foundry.empirical.e0h.harness.common import RunPaths, read_json_object
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PACKAGE_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_EXPECTED_INDEX = "https://download.pytorch.org/whl/cu128"
_EXPECTED_ROOT_PACKAGES = {
    "accelerate": "accelerate_version",
    "torch": "torch_version",
    "transformers": "transformers_version",
}


def _package_receipts(payload: dict[str, object]) -> tuple[dict[str, object], ...]:
    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise E0HRunReleaseError("python lock packages must be a nonempty list")
    packages: list[dict[str, object]] = []
    for raw in raw_packages:
        if not isinstance(raw, dict):
            raise E0HRunReleaseError("python lock package receipt must be an object")
        receipt = cast(dict[str, object], raw)
        if set(receipt) != {"filename", "name", "sha256", "size_bytes", "version"}:
            raise E0HRunReleaseError("python lock package receipt fields do not match schema")
        filename = receipt["filename"]
        name = receipt["name"]
        digest = receipt["sha256"]
        size = receipt["size_bytes"]
        version = receipt["version"]
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise E0HRunReleaseError("python lock wheel filename must be flat")
        if not filename.endswith(".whl"):
            raise E0HRunReleaseError("python lock member must be a wheel")
        if not isinstance(name, str) or _PACKAGE_NAME.fullmatch(name) is None:
            raise E0HRunReleaseError("python lock package name is not normalized")
        if (
            not isinstance(version, str)
            or not version
            or any(character.isspace() for character in version)
        ):
            raise E0HRunReleaseError("python lock package version is invalid")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise E0HRunReleaseError("python lock package digest must be lowercase SHA-256")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise E0HRunReleaseError("python lock package size must be a positive integer")
        packages.append(receipt)
    names = [cast(str, package["name"]) for package in packages]
    if names != sorted(names) or len(names) != len(set(names)):
        raise E0HRunReleaseError("python lock package names must be unique and sorted")
    return tuple(packages)


def _lock_digest(payload: dict[str, object]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "lock_digest"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _requirements_text(packages: tuple[dict[str, object], ...]) -> str:
    lines = [f"--extra-index-url {_EXPECTED_INDEX}"]
    for package in packages:
        lines.append(f"{package['name']}=={package['version']} --hash=sha256:{package['sha256']}")
    return "\n".join(lines) + "\n"


def verify_python_lock(paths: RunPaths, inputs: E0HRunReleaseInputs) -> dict[str, object]:
    """Verify the committed wheel graph, its digest, and the pip hash lock."""

    lock_path = paths.run_root / "python_lock.json"
    requirements_path = paths.run_root / "requirements-cu128.lock"
    payload = read_json_object(lock_path)
    if set(payload) != {
        "extra_index_url",
        "lock_digest",
        "packages",
        "python_version",
        "schema_version",
    }:
        raise E0HRunReleaseError("python lock fields do not match schema")
    if payload["schema_version"] != "e0h-python-lock/1":
        raise E0HRunReleaseError("unexpected python lock schema")
    if payload["python_version"] != inputs.environment.python_version:
        raise E0HRunReleaseError("python lock version does not match the environment")
    if payload["extra_index_url"] != _EXPECTED_INDEX:
        raise E0HRunReleaseError("python lock uses an unexpected package index")
    lock_digest = payload["lock_digest"]
    if not isinstance(lock_digest, str) or _SHA256.fullmatch(lock_digest) is None:
        raise E0HRunReleaseError("python lock digest must be lowercase SHA-256")
    if lock_digest != _lock_digest(payload):
        raise E0HRunReleaseError("python lock digest mismatch")

    packages = _package_receipts(payload)
    by_name = {cast(str, package["name"]): package for package in packages}
    for package_name, environment_field in _EXPECTED_ROOT_PACKAGES.items():
        package = by_name.get(package_name)
        if package is None:
            raise E0HRunReleaseError(f"python lock omits required package: {package_name}")
        expected = getattr(inputs.environment, environment_field)
        observed = cast(str, package["version"]).split("+", maxsplit=1)[0]
        if observed != expected:
            raise E0HRunReleaseError(
                f"python lock {package_name} version mismatch; "
                f"expected={expected}, observed={observed}"
            )

    if requirements_path.is_symlink() or not requirements_path.is_file():
        raise E0HRunReleaseError("hash-locked requirements file is unavailable")
    try:
        requirements = requirements_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise E0HRunReleaseError("hash-locked requirements are not UTF-8") from exc
    expected_requirements = _requirements_text(packages)
    if requirements != expected_requirements:
        raise E0HRunReleaseError("hash-locked requirements do not match the Python lock")
    return payload


def verify_installed_python_lock(
    paths: RunPaths,
    inputs: E0HRunReleaseInputs,
) -> dict[str, str]:
    """Require every installed distribution to equal the committed lock version."""

    payload = verify_python_lock(paths, inputs)
    packages = _package_receipts(payload)
    observed: dict[str, str] = {}
    for package in packages:
        name = cast(str, package["name"])
        expected = cast(str, package["version"])
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise E0HRunReleaseError(f"locked package is not installed: {name}") from exc
        if version != expected:
            raise E0HRunReleaseError(
                f"installed package version mismatch for {name}; "
                f"expected={expected}, observed={version}"
            )
        observed[name] = version
    return observed
