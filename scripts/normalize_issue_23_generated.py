"""Normalize issue #23 generated sources before repository linting."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

validation_path = ROOT / "src/csd_foundry/synthesis/v0_4/publication_validation.py"
validation = validation_path.read_text(encoding="utf-8")
validation = validation.replace(
    "from dataclasses import dataclass\n",
    "from contextlib import suppress\nfrom dataclasses import dataclass\n",
    1,
)
validation = validation.replace(
    """            try:
                store.publish_bytes(
                    accepted.canonical_bytes,
                    expected_digest=accepted.digest,
                    fault_injector=inject,
                )
            except InjectedPublicationCrash:
                pass
""",
    """            with suppress(InjectedPublicationCrash):
                store.publish_bytes(
                    accepted.canonical_bytes,
                    expected_digest=accepted.digest,
                    fault_injector=inject,
                )
""",
    1,
)
validation_path.write_text(validation, encoding="utf-8")

vectors_path = ROOT / "src/csd_foundry/synthesis/v0_4/publication_vectors.py"
lines = vectors_path.read_text(encoding="utf-8").splitlines()
normalized: list[str] = []
in_expected_mapping = False
for line in lines:
    if line == "EXPECTED_PUBLICATION_DIGESTS: dict[str, str] = {":
        in_expected_mapping = True
        normalized.append(line)
        continue
    if in_expected_mapping and line == "}":
        in_expected_mapping = False
        normalized.append(line)
        continue
    if in_expected_mapping:
        stripped = line.strip()
        key, value = stripped.removesuffix(",").split(": ", 1)
        normalized.extend((f"    {key}: (", f"        {value}", "    ),"))
        continue
    normalized.append(line)
vectors_path.write_text("\n".join(normalized) + "\n", encoding="utf-8")
