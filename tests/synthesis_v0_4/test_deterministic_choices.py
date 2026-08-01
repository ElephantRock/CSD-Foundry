from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from csd_foundry.synthesis.v0_4.choice_paths import (
    MAX_ATTEMPT_INDEX,
    AttemptKey,
    AttemptRange,
    ChoiceOperation,
    ChoicePath,
    ChoiceValidationError,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.choice_policy import load_choice_algorithm_policy
from csd_foundry.synthesis.v0_4.choice_vectors import (
    KNOWN_ANSWER_SEED_HEX,
    KNOWN_ANSWER_VECTORS,
)
from csd_foundry.synthesis.v0_4.determinism_validation import validate_determinism
from csd_foundry.synthesis.v0_4.deterministic_choices import (
    bounded_integer,
    canonical_choice_material,
    choose_ratio,
    weighted_choice,
)
from csd_foundry.synthesis.v0_4.serialization import load_json_text
from csd_foundry.synthesis.v0_4.specs import (
    CHOICE_ALGORITHM_SPEC,
    RELEASE_POLICY_SPEC,
)

ROOT = Path(__file__).resolve().parents[2]


def _seed() -> RootSeed:
    return RootSeed.from_hex(
        KNOWN_ANSWER_SEED_HEX,
        SeedProvenance.KNOWN_ANSWER_FIXTURE,
    )


def _path(*segments: str | int, sample_index: int = 0) -> ChoicePath:
    return ChoicePath(
        AttemptKey(SampleKey("v0.4", "known-answer", sample_index), 0),
        "known-answer",
        tuple(segments),
    )


def test_determinism_release_and_required_vector_paths() -> None:
    report = validate_determinism("v0.4")
    assert report.success
    assert report.vectors_passed == len(KNOWN_ANSWER_VECTORS) == 7
    assert report.forced_redraw_vectors >= 1
    assert report.multiple_redraw_vectors >= 1
    assert report.multi_block_vectors >= 1
    assert report.typed_segment_separation
    assert report.release_seed_valid
    assert report.maximum_attempt_index == MAX_ATTEMPT_INDEX


def test_forced_redraw_resets_block_counter() -> None:
    result = bounded_integer(_seed(), _path("redraw", 1, sample_index=1), 129)
    assert result.draw_index == 2
    assert [draw.candidate_hex for draw in result.draws] == ["b8", "b1", "2e"]
    assert [draw.block_count for draw in result.draws] == [1, 1, 1]


def test_large_bound_uses_multiple_hmac_blocks() -> None:
    bound = (1 << 264) + 12345
    result = bounded_integer(_seed(), _path("large-bound", 1, sample_index=2), bound)
    assert result.width == 34
    assert result.block_count == 2
    assert 0 <= result.value < bound


def test_integer_and_string_segments_remain_distinct() -> None:
    integer_path = _path("segment", 1, sample_index=3)
    string_path = _path("segment", "1", sample_index=3)
    domain = {"upper_exclusive": 1000}
    assert canonical_choice_material(
        integer_path, ChoiceOperation.BOUNDED_INTEGER, domain
    ) != canonical_choice_material(string_path, ChoiceOperation.BOUNDED_INTEGER, domain)
    assert bounded_integer(_seed(), integer_path, 1000).value == 798
    assert bounded_integer(_seed(), string_path, 1000).value == 141


@pytest.mark.parametrize("bad_segment", [False, -1, "", "UPPER", "é"])
def test_invalid_choice_path_segments_fail_closed(bad_segment: object) -> None:
    with pytest.raises(ChoiceValidationError):
        ChoicePath(
            AttemptKey(SampleKey("v0.4", "known-answer", 0), 0),
            "known-answer",
            (bad_segment,),  # type: ignore[arg-type]
        )


def test_attempt_range_has_a_hard_uint32_ceiling() -> None:
    sample = SampleKey("v0.4", "known-answer", 0)
    assert AttemptKey(sample, MAX_ATTEMPT_INDEX).attempt_index == MAX_ATTEMPT_INDEX
    assert AttemptRange(MAX_ATTEMPT_INDEX + 1).contains(MAX_ATTEMPT_INDEX)
    with pytest.raises(ChoiceValidationError):
        AttemptKey(sample, MAX_ATTEMPT_INDEX + 1)
    with pytest.raises(ChoiceValidationError):
        AttemptRange(0)
    with pytest.raises(ChoiceValidationError):
        AttemptRange(MAX_ATTEMPT_INDEX + 2)


@pytest.mark.parametrize(
    "bound",
    [
        1,
        2,
        255,
        256,
        257,
        (1 << 32) - 1,
        1 << 32,
        (1 << 32) + 1,
        (1 << 264) + 12345,
    ],
)
def test_bounded_integer_boundary_ranges(bound: int) -> None:
    result = bounded_integer(_seed(), _path("boundary", bound), bound)
    assert 0 <= result.value < bound


@pytest.mark.parametrize("bound", [0, -1, 1.5, True])
def test_invalid_bounded_integer_domains_fail_closed(bound: object) -> None:
    with pytest.raises(ChoiceValidationError):
        bounded_integer(_seed(), _path("bad-bound"), bound)  # type: ignore[arg-type]


def test_weighted_choice_uses_exact_positive_integer_weights() -> None:
    result = weighted_choice(
        _seed(),
        _path("weighted", "status", sample_index=4),
        ["a", "b", "c"],
        [3, 7, 11],
    )
    assert result.selected_index == 1
    assert result.selected_value == "b"
    assert result.ticket.value == 7
    assert result.cumulative_weights == (3, 10, 21)

    invalid_cases = (
        (["a", "b"], []),
        (["a", "b"], [1, 0]),
        (["a", "b"], [1, -1]),
        (["a", "b"], [1, True]),
    )
    for values, weights in invalid_cases:
        with pytest.raises(ChoiceValidationError):
            weighted_choice(_seed(), _path("bad-weight"), values, weights)
    with pytest.raises(ChoiceValidationError):
        weighted_choice(_seed(), _path("duplicates"), ["a", "a"], [1, 1])


def test_exact_ratio_rejects_invalid_ratios() -> None:
    assert choose_ratio(_seed(), _path("ratio", "flag", sample_index=5), 2, 5).selected
    for numerator, denominator in ((-1, 5), (6, 5), (1, 0), (True, 5)):
        with pytest.raises(ChoiceValidationError):
            choose_ratio(
                _seed(),
                _path("bad-ratio"),
                numerator,  # type: ignore[arg-type]
                denominator,
            )


def test_release_seed_is_explicit_and_release_eligible() -> None:
    raw = RELEASE_POLICY_SPEC["root_seed"]
    provenance = RELEASE_POLICY_SPEC["root_seed_provenance"]
    assert isinstance(raw, str)
    assert isinstance(provenance, str)
    seed = RootSeed.from_hex(raw, SeedProvenance(provenance))
    assert seed.release_eligible
    with pytest.raises(ChoiceValidationError):
        RootSeed.from_text("test", SeedProvenance.UNIFORM_RANDOM_256)
    with pytest.raises(ChoiceValidationError):
        RootSeed.from_hex("00" * 32, SeedProvenance.UNIFORM_RANDOM_256)


def test_choice_policy_satisfies_exact_collision_bound() -> None:
    policy = load_choice_algorithm_policy()
    assert policy.display_digest_bits == 128
    assert policy.design_identity_ceiling == 10_000_000
    assert policy.collision_probability_upper_bound <= policy.collision_risk_ceiling


def test_repository_policy_and_vector_catalog_match_packaged_values() -> None:
    policy = load_json_text((ROOT / "specs/v0.4/choice_algorithm.json").read_text(encoding="utf-8"))
    vector_document = load_json_text(
        (ROOT / "data/canary/v0.4/algorithm-v1/choice_vectors.json").read_text(encoding="utf-8")
    )
    assert policy == CHOICE_ALGORITHM_SPEC
    assert isinstance(vector_document, dict)
    assert vector_document["vectors"] == list(KNOWN_ANSWER_VECTORS)


def test_choice_result_is_independent_of_python_hash_seed() -> None:
    script = "\n".join(
        (
            "from csd_foundry.synthesis.v0_4 import choice_paths as paths",
            "from csd_foundry.synthesis.v0_4 import choice_vectors as vectors",
            "from csd_foundry.synthesis.v0_4 import deterministic_choices as choices",
            "seed = paths.RootSeed.from_hex(",
            "    vectors.KNOWN_ANSWER_SEED_HEX,",
            "    paths.SeedProvenance.KNOWN_ANSWER_FIXTURE,",
            ")",
            "path = paths.ChoicePath(",
            "    paths.AttemptKey(paths.SampleKey('v0.4', 'known-answer', 1), 0),",
            "    'known-answer',",
            "    ('redraw', 1),",
            ")",
            "result = choices.bounded_integer(seed, path, 129)",
            "print(f'{result.material_digest}:{result.value}:{result.draw_index}')",
        )
    )
    outputs = set()
    for hash_seed in ("0", "1", "42", "random"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = hash_seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.add(completed.stdout.strip())
    assert len(outputs) == 1


def test_choice_algorithm_schema_is_normative() -> None:
    schema = json.loads(
        (ROOT / "specs/v0.4/choice_algorithm.schema.json").read_text(encoding="utf-8")
    )
    assert schema["properties"]["algorithm_id"]["const"] == ("csd-choice-hmac-sha256-rejection")
    assert schema["properties"]["digest_primitive"]["const"] == "hmac-sha256"
    assert schema["properties"]["maximum_attempt_index"]["const"] == 4294967295
