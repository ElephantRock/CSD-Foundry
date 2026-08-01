"""Validation and release evidence for deterministic choice algorithm version 1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from csd_foundry.synthesis.v0_4.choice_paths import (
    MAX_ATTEMPT_INDEX,
    AttemptKey,
    ChoicePath,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.choice_policy import load_choice_algorithm_policy
from csd_foundry.synthesis.v0_4.choice_vectors import (
    KNOWN_ANSWER_SEED_HEX,
    KNOWN_ANSWER_VECTORS,
)
from csd_foundry.synthesis.v0_4.deterministic_choices import (
    ALGORITHM_ID,
    ALGORITHM_VERSION,
    BoundedIntegerResult,
    bounded_integer,
    choose_ratio,
    weighted_choice,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256
from csd_foundry.synthesis.v0_4.specs import RELEASE_POLICY_SPEC


@dataclass(frozen=True, slots=True)
class DeterminismReport:
    release: str
    algorithm_id: str
    algorithm_version: int
    known_answer_vectors: int
    vectors_passed: int
    forced_redraw_vectors: int
    multiple_redraw_vectors: int
    multi_block_vectors: int
    typed_segment_separation: bool
    release_seed_valid: bool
    maximum_attempt_index: int
    vector_catalog_digest: str
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "algorithm_id": self.algorithm_id,
            "algorithm_version": self.algorithm_version,
            "known_answer_vectors": self.known_answer_vectors,
            "vectors_passed": self.vectors_passed,
            "forced_redraw_vectors": self.forced_redraw_vectors,
            "multiple_redraw_vectors": self.multiple_redraw_vectors,
            "multi_block_vectors": self.multi_block_vectors,
            "typed_segment_separation": self.typed_segment_separation,
            "release_seed_valid": self.release_seed_valid,
            "maximum_attempt_index": self.maximum_attempt_index,
            "vector_catalog_digest": self.vector_catalog_digest,
            "release_scale_claimed": False,
            "errors": list(self.errors),
            "claim_boundary": (
                "This report validates the frozen deterministic choice algorithm and known-answer "
                "vectors. It does not establish entity identity allocation, production shard "
                "orchestration, planner completeness, state construction, or release-scale output."
            ),
        }


def _mapping(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{field_name} must be an object")
    return cast(dict[str, object], value)


def _integer(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    return value


def _string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def _segments(data: dict[str, object]) -> tuple[str | int, ...]:
    value = data.get("segments")
    if not isinstance(value, list):
        raise ValueError("segments must be an array")
    result: list[str | int] = []
    for segment in value:
        if type(segment) is int or isinstance(segment, str):
            result.append(segment)
        else:
            raise ValueError("known-answer segments must preserve string/integer types")
    return tuple(result)


def _path(data: dict[str, object]) -> ChoicePath:
    sample = SampleKey(
        release="v0.4",
        target_id="known-answer",
        sample_index=_integer(data, "sample_index"),
    )
    return ChoicePath(
        attempt_key=AttemptKey(sample, 0),
        namespace="known-answer",
        segments=_segments(data),
    )


def _draw_payload(result: BoundedIntegerResult) -> list[dict[str, object]]:
    return [
        {
            "draw_index": draw.draw_index,
            "candidate_hex": draw.candidate_hex,
            "candidate": draw.candidate,
            "block_count": draw.block_count,
        }
        for draw in result.draws
    ]


def _bounded_payload(result: BoundedIntegerResult) -> dict[str, object]:
    return {
        "value": result.value,
        "draw_index": result.draw_index,
        "candidate_hex": result.candidate_hex,
        "candidate": result.candidate,
        "limit": result.limit,
        "width": result.width,
        "block_count": result.block_count,
        "draws": _draw_payload(result),
        "domain_digest": result.domain_digest,
        "material_digest": result.material_digest,
    }


def _validate_vector(
    seed: RootSeed,
    vector: dict[str, object],
) -> tuple[int, int, bool, str | None]:
    operation = _string(vector, "operation")
    expected = _mapping(vector.get("expected"), "expected")
    path = _path(vector)

    if operation == "bounded_integer":
        bounded_result = bounded_integer(
            seed,
            path,
            _integer(vector, "upper_exclusive"),
        )
        if _bounded_payload(bounded_result) != expected:
            raise ValueError("bounded result does not match expected vector")
        return (
            int(bounded_result.draw_index > 0),
            int(bounded_result.draw_index > 1),
            bounded_result.block_count > 1,
            bounded_result.material_digest,
        )

    if operation == "integer_weighted_index":
        values_raw = vector.get("values")
        weights_raw = vector.get("weights")
        if not isinstance(values_raw, list) or not all(
            isinstance(item, str) for item in values_raw
        ):
            raise ValueError("weighted vector values must contain strings")
        if not isinstance(weights_raw, list) or not all(
            isinstance(item, int) and not isinstance(item, bool)
            for item in weights_raw
        ):
            raise ValueError("weighted vector weights must contain integers")
        weighted_result = weighted_choice(
            seed,
            path,
            cast(list[str], values_raw),
            cast(list[int], weights_raw),
        )
        payload = {
            "selected_index": weighted_result.selected_index,
            "selected_value": weighted_result.selected_value,
            "ticket_value": weighted_result.ticket.value,
            "draw_index": weighted_result.ticket.draw_index,
            "candidate_hex": weighted_result.ticket.candidate_hex,
            "candidate": weighted_result.ticket.candidate,
            "limit": weighted_result.ticket.limit,
            "width": weighted_result.ticket.width,
            "block_count": weighted_result.ticket.block_count,
            "cumulative_weights": list(weighted_result.cumulative_weights),
            "domain_digest": weighted_result.ticket.domain_digest,
            "material_digest": weighted_result.ticket.material_digest,
        }
        if payload != expected:
            raise ValueError("weighted result does not match expected vector")
        return (
            0,
            0,
            weighted_result.ticket.block_count > 1,
            weighted_result.ticket.material_digest,
        )

    if operation == "boolean_ratio":
        boolean_result = choose_ratio(
            seed,
            path,
            _integer(vector, "numerator"),
            _integer(vector, "denominator"),
        )
        payload = {
            "selected": boolean_result.selected,
            "ticket_value": boolean_result.ticket.value,
            "draw_index": boolean_result.ticket.draw_index,
            "candidate_hex": boolean_result.ticket.candidate_hex,
            "candidate": boolean_result.ticket.candidate,
            "limit": boolean_result.ticket.limit,
            "width": boolean_result.ticket.width,
            "block_count": boolean_result.ticket.block_count,
            "domain_digest": boolean_result.ticket.domain_digest,
            "material_digest": boolean_result.ticket.material_digest,
        }
        if payload != expected:
            raise ValueError("ratio result does not match expected vector")
        return (
            0,
            0,
            boolean_result.ticket.block_count > 1,
            boolean_result.ticket.material_digest,
        )

    raise ValueError(f"unsupported known-answer operation: {operation}")


def validate_determinism(release: str = "v0.4") -> DeterminismReport:
    errors: list[str] = []
    passed = 0
    forced_redraws = 0
    multiple_redraws = 0
    multi_block = 0
    segment_digests: dict[str, str] = {}

    if release != "v0.4":
        errors.append(f"unsupported deterministic-choice release: {release}")
    else:
        try:
            load_choice_algorithm_policy()
        except ValueError as exc:
            errors.append(str(exc))

        seed = RootSeed.from_hex(
            KNOWN_ANSWER_SEED_HEX,
            SeedProvenance.KNOWN_ANSWER_FIXTURE,
        )
        for raw_vector in KNOWN_ANSWER_VECTORS:
            vector = _mapping(raw_vector, "known-answer vector")
            vector_id = _string(vector, "vector_id")
            try:
                redraw, multiple, uses_multiple_blocks, material_digest = _validate_vector(
                    seed,
                    vector,
                )
            except ValueError as exc:
                errors.append(f"{vector_id}: {exc}")
                continue
            passed += 1
            forced_redraws += redraw
            multiple_redraws += multiple
            multi_block += int(uses_multiple_blocks)
            if vector_id in {"path-integer-segment", "path-string-segment"}:
                assert material_digest is not None
                segment_digests[vector_id] = material_digest

    typed_segment_separation = bool(
        len(segment_digests) == 2
        and segment_digests["path-integer-segment"]
        != segment_digests["path-string-segment"]
    )
    if not typed_segment_separation:
        errors.append("integer and string choice-path segments are not separated")
    if forced_redraws == 0:
        errors.append("known-answer catalog does not exercise rejection and redraw")
    if multiple_redraws == 0:
        errors.append("known-answer catalog does not exercise multiple rejected draws")
    if multi_block == 0:
        errors.append("known-answer catalog does not exercise multi-block candidates")

    release_seed_valid = False
    try:
        root_seed = RELEASE_POLICY_SPEC["root_seed"]
        provenance = RELEASE_POLICY_SPEC["root_seed_provenance"]
        if not isinstance(root_seed, str) or not isinstance(provenance, str):
            raise ValueError("release seed fields must be strings")
        release_seed = RootSeed.from_hex(root_seed, SeedProvenance(provenance))
        release_seed_valid = release_seed.release_eligible
    except (KeyError, ValueError) as exc:
        errors.append(f"release seed: {exc}")

    return DeterminismReport(
        release=release,
        algorithm_id=ALGORITHM_ID,
        algorithm_version=ALGORITHM_VERSION,
        known_answer_vectors=len(KNOWN_ANSWER_VECTORS),
        vectors_passed=passed,
        forced_redraw_vectors=forced_redraws,
        multiple_redraw_vectors=multiple_redraws,
        multi_block_vectors=multi_block,
        typed_segment_separation=typed_segment_separation,
        release_seed_valid=release_seed_valid,
        maximum_attempt_index=MAX_ATTEMPT_INDEX,
        vector_catalog_digest=canonical_sha256(KNOWN_ANSWER_VECTORS),
        errors=tuple(errors),
    )
