"""Tests for whole-file canonical E1 control response parsing."""

import pytest

from csd_foundry.empirical.e1.control_paired_compiler import E1ControlArtifactError
from csd_foundry.empirical.e1.control_response_io import load_conventional_responses
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_json_text


def _content() -> bytes:
    return canonical_json_bytes(
        {
            "record_id": "e1-control/train/M-01/case",
            "target": canonical_json_text(
                {
                    "schema_version": "conventional-synthetic-label/1",
                    "decision": "generated_without_executable_validation",
                }
            ),
        }
    )


def test_control_response_jsonl_round_trips_exact_bytes() -> None:
    content = _content()

    responses = load_conventional_responses(content)

    assert len(responses) == 1
    assert canonical_json_bytes(responses[0].to_dict()) == content


def test_control_response_jsonl_rejects_missing_terminal_newline() -> None:
    with pytest.raises(E1ControlArtifactError, match="LF-terminated"):
        load_conventional_responses(_content().rstrip(b"\n"))


def test_control_response_jsonl_rejects_crlf_and_unknown_fields() -> None:
    with pytest.raises(E1ControlArtifactError, match="CRLF"):
        load_conventional_responses(_content().replace(b"\n", b"\r\n", 1))

    content = canonical_json_bytes(
        {
            "record_id": "e1-control/train/M-01/case",
            "target": canonical_json_text({"decision": "x"}),
            "unexpected": True,
        }
    )
    with pytest.raises(E1ControlArtifactError, match="closed schema"):
        load_conventional_responses(content)


def test_control_response_jsonl_rejects_noncanonical_object_bytes() -> None:
    target = canonical_json_text({"decision": "x"})
    content = (
        '{"target":'
        + repr(target).replace("'", '"')
        + ',"record_id":"e1-control/train/M-01/case"}\n'
    ).encode("utf-8")

    with pytest.raises((E1ControlArtifactError, ValueError)):
        load_conventional_responses(content)
