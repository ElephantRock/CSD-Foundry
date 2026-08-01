"""Canonical integer-only JSON serialization for v0.4 synthesis artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import fields, is_dataclass
from enum import StrEnum
from typing import TypeAlias, cast


class CanonicalSerializationError(ValueError):
    """Raised when a value cannot be represented by canonical semantic JSON."""


JSONScalar: TypeAlias = None | bool | int | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def _reject_float(value: str) -> object:
    raise CanonicalSerializationError(f"floating-point JSON number is prohibited: {value}")


def _reject_constant(value: str) -> object:
    raise CanonicalSerializationError(f"non-finite JSON number is prohibited: {value}")


def _sort_key(value: JSONValue) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def to_json_value(value: object) -> JSONValue:
    """Convert supported Python values into deterministic JSON-compatible values."""

    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise CanonicalSerializationError("floating-point semantic values are prohibited")
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_json_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        converted: dict[str, JSONValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalSerializationError("canonical JSON object keys must be strings")
            converted[key] = to_json_value(item)
        return converted
    if isinstance(value, (tuple, list)):
        return [to_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        converted_items = [to_json_value(item) for item in value]
        return sorted(converted_items, key=_sort_key)
    raise CanonicalSerializationError(
        f"unsupported canonical JSON type: {type(value).__qualname__}"
    )


def canonical_json_bytes(value: object) -> bytes:
    normalized = to_json_value(value)
    return (
        json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def canonical_json_text(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def load_json_text(text: str) -> JSONValue:
    parsed = json.loads(
        text,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )
    return cast(JSONValue, to_json_value(parsed))
