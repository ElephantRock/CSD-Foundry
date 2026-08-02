"""Executable v0.5 canonicalization and domain-separated digest rules."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, NoReturn


class GovernanceContractError(ValueError):
    """Stable fail-closed error raised by the v0.5 contract layer."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        if type(code) is not str or not code:
            raise TypeError("governance error code must be a nonempty exact string")
        self.code = code
        self.detail = detail
        super().__init__(code if detail is None else f"{code}:{detail}")


def _fail(code: str, detail: str | None = None) -> NoReturn:
    raise GovernanceContractError(code, detail)


def _ordered_keys(value: dict[str, Any]) -> list[str]:
    keys = list(value)
    first: list[str] = []
    if "schema_version" in keys:
        first.append("schema_version")
        keys.remove("schema_version")
    return first + sorted(keys, key=lambda key: key.encode("utf-8"))


def _normalize(value: Any, schema: dict[str, Any]) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, float):
        _fail("FLOAT_PROHIBITED")
    if isinstance(value, dict):
        if not all(type(key) is str for key in value):
            _fail("NON_STRING_OBJECT_KEY")
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        return {
            key: _normalize(value[key], properties.get(key, {})) for key in _ordered_keys(value)
        }
    if isinstance(value, list):
        item_schema = schema.get("items", {}) if isinstance(schema, dict) else {}
        items = [_normalize(item, item_schema) for item in value]
        kind = schema.get("x-csd-collection-kind", "ORDERED_SEQUENCE")
        if kind in {"SET", "MULTISET"}:
            keyed = sorted(
                (
                    json.dumps(
                        item,
                        ensure_ascii=False,
                        allow_nan=False,
                        separators=(",", ":"),
                    ).encode("utf-8"),
                    item,
                )
                for item in items
            )
            if kind == "SET" and any(
                previous[0] == current[0]
                for previous, current in zip(keyed, keyed[1:], strict=False)
            ):
                _fail("DUPLICATE_SET_MEMBER")
            return [item for _, item in keyed]
        if kind != "ORDERED_SEQUENCE":
            _fail("UNKNOWN_COLLECTION_KIND", str(kind))
        return items
    _fail("UNSUPPORTED_TYPE", type(value).__qualname__)


def canonical_bytes(value: Any, schema: dict[str, Any]) -> bytes:
    """Return exact v0.5 canonical JSON bytes under the supplied frozen schema."""

    if type(schema) is not dict:
        _fail("SCHEMA_TYPE_INVALID")
    try:
        rendered = json.dumps(
            _normalize(value, schema),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (UnicodeEncodeError, ValueError) as exc:
        _fail("CANONICALIZATION_FAILED", str(exc))
    return (rendered + "\n").encode("utf-8")


def domain_digest(
    value: dict[str, Any],
    schema: dict[str, Any],
    digest_field: str,
    domain_prefix: str,
) -> str:
    """Compute the frozen SHA-256 digest after removing the self-digest field."""

    if type(value) is not dict:
        _fail("CONTRACT_VALUE_NOT_OBJECT")
    if type(digest_field) is not str or not digest_field:
        _fail("DIGEST_FIELD_INVALID")
    if type(domain_prefix) is not str or not domain_prefix:
        _fail("DOMAIN_PREFIX_INVALID")
    unsigned = deepcopy(value)
    unsigned.pop(digest_field, None)
    payload = domain_prefix.encode("utf-8") + canonical_bytes(unsigned, schema)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def catalog_digest(value: dict[str, Any], domain: bytes) -> str:
    """Compute frozen policy/vector catalog commitments."""

    unsigned = deepcopy(value)
    unsigned.pop("catalog_digest", None)
    payload = (
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain + payload).hexdigest()
