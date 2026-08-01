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
start = lines.index("EXPECTED_PUBLICATION_DIGESTS: dict[str, str] = {")
end = lines.index("}", start)
entries: list[tuple[str, str]] = []
for line in lines[start + 1 : end]:
    key, value = line.strip().removesuffix(",").split(": ", 1)
    entries.append((key, value))

constant_lines: list[str] = []
mapping_lines = ["EXPECTED_PUBLICATION_DIGESTS: dict[str, str] = {"]
for index, (key, value) in enumerate(entries):
    name = f"_EXPECTED_PUBLICATION_DIGEST_{index}"
    constant_lines.extend((f"{name} = (", f"    {value}", ")"))
    mapping_lines.append(f"    {key}: {name},")
mapping_lines.append("}")

normalized = (
    lines[:start]
    + constant_lines
    + [""]
    + mapping_lines
    + lines[end + 1 :]
)
vectors_path.write_text("\n".join(normalized) + "\n", encoding="utf-8")
