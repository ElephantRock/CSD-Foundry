"""Canonical JSONL parser for externally generated E1 control responses."""

from __future__ import annotations

from csd_foundry.empirical.e1.control_paired_compiler import (
    ConventionalControlResponse,
    E1ControlArtifactError,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, load_json_text


def load_conventional_responses(content: bytes) -> tuple[ConventionalControlResponse, ...]:
    """Load exact canonical JSONL responses, including the terminal newline."""

    if not content:
        raise E1ControlArtifactError("control response JSONL is empty")
    try:
        lines = content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise E1ControlArtifactError("control response JSONL is not UTF-8") from exc
    if not lines or any(not line.endswith("\n") for line in lines):
        raise E1ControlArtifactError("control response JSONL requires one LF-terminated row")

    responses: list[ConventionalControlResponse] = []
    for line_number, line in enumerate(lines, start=1):
        if line.endswith("\r\n"):
            raise E1ControlArtifactError(
                f"control response line {line_number} uses CRLF instead of LF"
            )
        parsed = load_json_text(line.removesuffix("\n"))
        if not isinstance(parsed, dict):
            raise E1ControlArtifactError(f"response line {line_number} is not an object")
        if set(parsed) != {"record_id", "target"}:
            raise E1ControlArtifactError(
                f"response line {line_number} fields do not match the closed schema"
            )
        record_id = parsed["record_id"]
        target = parsed["target"]
        if not isinstance(record_id, str) or not isinstance(target, str):
            raise E1ControlArtifactError(
                f"response line {line_number} requires string record_id and target"
            )
        responses.append(ConventionalControlResponse(record_id, target))

    reconstructed = b"".join(canonical_json_bytes(response.to_dict()) for response in responses)
    if reconstructed != content:
        raise E1ControlArtifactError("control response JSONL bytes are not canonical")
    return tuple(responses)
