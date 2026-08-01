"""Strict immutable canonical values for digest-bearing v0.4 contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias, Union, cast

from csd_foundry.synthesis.v0_4.serialization import JSONValue, canonical_json_bytes


class CanonicalValueError(ValueError):
    """Raised when a value is not part of the canonical-value algebra."""


CanonicalScalar: TypeAlias = None | bool | int | str
CanonicalValue: TypeAlias = Union[CanonicalScalar, "CanonicalArray", "CanonicalObject"]


def _validate_string(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise CanonicalValueError(f"{field_name} must be an exact string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalValueError(f"{field_name} must be valid UTF-8") from exc
    return value


def validate_canonical_value(value: object) -> CanonicalValue:
    """Validate and return an immutable canonical value without coercion."""

    if value is None:
        return None
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is str:
        return _validate_string(value, "canonical string")
    if type(value) is CanonicalArray or type(value) is CanonicalObject:
        return value
    raise CanonicalValueError(
        "canonical values permit only null, exact booleans, exact integers, UTF-8 strings, "
        "exact CanonicalArray values, and exact CanonicalObject values"
    )


@dataclass(frozen=True, slots=True)
class CanonicalArray:
    values: tuple[CanonicalValue, ...]

    def __post_init__(self) -> None:
        if type(self.values) is not tuple:
            raise CanonicalValueError("canonical array values must be an immutable tuple")
        for value in self.values:
            validate_canonical_value(value)

    def to_json_value(self) -> list[JSONValue]:
        return [canonical_to_json_value(value) for value in self.values]


@dataclass(frozen=True, slots=True)
class CanonicalField:
    name: str
    value: CanonicalValue

    def __post_init__(self) -> None:
        _validate_string(self.name, "canonical object field name")
        if not self.name:
            raise CanonicalValueError("canonical object field names must be nonempty")
        validate_canonical_value(self.value)


@dataclass(frozen=True, slots=True)
class CanonicalObject:
    fields: tuple[CanonicalField, ...]

    def __post_init__(self) -> None:
        if type(self.fields) is not tuple:
            raise CanonicalValueError("canonical object fields must be an immutable tuple")
        if not all(type(field) is CanonicalField for field in self.fields):
            raise CanonicalValueError(
                "canonical object fields must contain exact CanonicalField values"
            )
        names = tuple(field.name for field in self.fields)
        if len(names) != len(set(names)):
            raise CanonicalValueError("canonical object field names must be unique")
        expected = tuple(sorted(names, key=lambda name: name.encode("utf-8")))
        if names != expected:
            raise CanonicalValueError(
                "canonical object fields must be sorted by unsigned UTF-8 byte order"
            )

    @classmethod
    def from_pairs(cls, pairs: tuple[tuple[str, CanonicalValue], ...]) -> CanonicalObject:
        if cls is not CanonicalObject:
            raise CanonicalValueError("canonical object construction requires the exact class")
        if type(pairs) is not tuple:
            raise CanonicalValueError("canonical object pairs must be an immutable tuple")
        for pair in pairs:
            if type(pair) is not tuple or len(pair) != 2:
                raise CanonicalValueError(
                    "canonical object pairs must contain exact two-element tuples"
                )
        fields = tuple(CanonicalField(name, value) for name, value in pairs)
        return cls(tuple(sorted(fields, key=lambda field: field.name.encode("utf-8"))))

    def to_json_value(self) -> dict[str, JSONValue]:
        return {field.name: canonical_to_json_value(field.value) for field in self.fields}


def canonical_to_json_value(value: CanonicalValue) -> JSONValue:
    validated = validate_canonical_value(value)
    if type(validated) is CanonicalArray:
        return validated.to_json_value()
    if type(validated) is CanonicalObject:
        return validated.to_json_value()
    return cast(JSONValue, validated)


def canonical_value_bytes(value: CanonicalValue) -> bytes:
    return canonical_json_bytes(canonical_to_json_value(value))
