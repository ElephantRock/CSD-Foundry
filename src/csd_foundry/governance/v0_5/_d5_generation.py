, ...],
    comparison_receipts: tuple[dict[str, object], ...],
) -> bytes:
    value: dict[str, Any] = {
        "schema_version": PREPARED_BUNDLE_SCHEMA_VERSION,
        "manifest": manifest.to_json_value(),
        "completion": completion.to_json_value(),
        "claim": claim.to_json_value(),
        "semantic_receipt": semantic_receipt.to_json_value(),
        "evidence_plan": evidence_plan.to_json_value(),
        "assumption_plan": assumption_plan.to_json_value(),
        "alt_model_plan": alt_model_plan.to_json_value(),
        "disposition_receipt": disposition.to_json_value(),
        "evidence_events": [event.to_json_value() for event in evidence_events],
        "assumption_events": [event.to_json_value() for event in assumption_events],
        "alt_model_events": [event.to_json_value() for event in alt_model_events],
        "comparison_receipts": [dict(item) for item in comparison_receipts],
    }
    return _json_bytes(value)


def _deserialize_events(raw_events: list[Any], registry_type: str) -> tuple[RegistryEvent, ...]:
    """Deserialize a list of JSON event values into typed RegistryEvent objects.

    Each event must target ``registry_type``; a mismatch is a finalization
    failure. Used by both commit and recovery to reconstruct the event tuples
    fed into :meth:`D5GenerationStore._verify_finalization`.
    """

    if type(raw_events) is not list:
        raise D5GenerationConflictError("D5_PREPARED_BUNDLE_EVENTS_INVALID")
    events: list[RegistryEvent] = []
    for value in raw_events:
        if type(value) is not dict:
            raise D5GenerationConflictError("D5_PREPARED_BUNDLE_EVENT_INVALID")
        if value.get("registry_type") != registry_type:
            raise D5GenerationConflictError("D5_EVENT_REGISTRY_TYPE_MISMATCH")
        events.append(cast(RegistryEvent, RegistryEvent.from_json(value)))
    return tuple(events)


def _verify_plan_json(plan_json: dict[str, Any], domain: str, expected_digest: str) -> None:
    """Verify a persisted plan JSON's self-digest matches the manifest citation.

    Recomputes the domain-separated digest from the unsigned fields (every key
    except ``plan_digest``) using the same canonicalization the projection
    modules use. This mechanically proves the persisted plan JSON is intact
    without requiring per-type ``from_json`` constructors for every nested
    receipt/decision type.
    """

    if plan_json.get("plan_digest") != expected_digest:
        raise D5GenerationConflictError("D5_FINALIZATION_PLAN_DIGEST_MISMATCH")
    unsigned = {key: value for key, value in plan_json.items() if key != "plan_digest"}
    recomputed = _domain_digest(domain, unsigned)
    if recomputed != expected_digest:
        raise D5GenerationConflictError("D5_FINALIZATION_PLAN_DIGEST_CORRUPT")


def _domain_digest(domain: str, value: object) -> str:
    """Domain-separated digest matching the projection modules' canonical form."""

    payload = _json_bytes(value)
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def _verify_projected_heads(
    manifest: D5GenerationManifest,
    store: FilesystemRegistryStore,
    registry: str,
) -> None:
    """Post-install verification that manifest heads reconstruct from installed objects.

    Walks each entity chain from the manifest head set through the object store
    (now that every event object has been installed) and recomputes the
    projected root, confirming it still matches the manifest. This is the
    defect-1 replacement for the old live-store projected-root check.
    """

    heads = manifest.head_entities(registry)
    reconstructed_root = _snapshot_root(_REGISTRY_TYPES[registry], heads)
    expected_root = _manifest_projected_root(manifest, registry)
    if reconstructed_root != expected_root:
        raise D5GenerationConflictError(f"D5_{registry.upper()}_PROJECTED_ROOT_INSTALL_MISMATCH")
    # Walk each chain to confirm every event object is retrievable.
    view = GenerationRegistryView(
        store=store,
        registry_type=_REGISTRY_TYPES[registry],
        heads=heads,
    )
    for head in heads:
        chain = view.reconstruct_entity(_REGISTRY_TYPES[registry], head.entity_id)
        if not chain or chain[-1].digest != head.event_digest:
            raise D5GenerationConflictError(f"D5_{registry.upper()}_CHAIN_RECONSTRUCTION_FAILED")


def _manifest_projected_root(manifest: D5GenerationManifest, registry: str) -> str:
    if registry == "evidence":
        return manifest.evidence_projected_root
    if registry == "assumption":
        return manifest.assumption_projected_root
    return manifest.alt_model_projected_root


def _require_registry_type(value: object) -> None:
    if type(value) is not str or value not in _REGISTRY_PHASE_SET:
        raise D5GenerationError("D5_REGISTRY_TYPE_INVALID")


_REGISTRY_PHASE_SET = {"EVIDENCE_UNIT", "ASSUMPTION", "ALTERNATIVE_MODEL"}


def _require_digest(value: object, code: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise D5GenerationError(code)
    return value


def _require_digest_tuple(values: tuple[str, ...], code: str) -> None:
    if type(values) is not tuple:
        raise D5GenerationError(code)
    for item in values:
        _require_digest(item, code)


def _require_head_set(heads: tuple[dict[str, object], ...], code: str) -> None:
    if type(heads) is not tuple:
        raise D5GenerationError(code)
    entity_ids: list[str] = []
    for item in heads:
        if type(item) is not dict:
            raise D5GenerationError(code)
        if set(item) != {"entity_id", "entity_sequence", "event_digest"}:
            raise D5GenerationError(code)
        entity_id = item["entity_id"]
        entity_sequence = item["entity_sequence"]
        event_digest = item["event_digest"]
        if type(entity_id) is not str or _TOKEN.fullmatch(entity_id) is None:
            raise D5GenerationError(code)
        if type(entity_sequence) is not int or entity_sequence < 1:
            raise D5GenerationError(code)
        _require_digest(event_digest, code)
        entity_ids.append(entity_id)
    if entity_ids != sorted(entity_ids) or len(set(entity_ids)) != len(entity_ids):
        raise D5GenerationError(code)


def _digest_hex(value: str) -> str:
    _require_digest(value, "D5_DIGEST_INVALID")
    return value.removeprefix("sha256:")


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise D5GenerationConflictError(f"D5_{label.upper().replace(' ', '_')}_INVALID") from exc
    if type(value) is not dict:
        raise D5GenerationConflictError(f"D5_{label.upper().replace(' ', '_')}_INVALID")
    return cast(dict[str, Any], value)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _write_fsync(path: Path, payload: bytes, *, exclusive: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)


__all__ = [
    "D5GenerationConflictError",
    "D5GenerationError",
    "D5GenerationManifest",
    "D5GenerationStore",
    "DispositionAdapterFactory",
    "DispositionProjector",
    "GenerationRegistryView",
    "QuarantineAdapterFactory",
    "QuarantineProjector",
    "ReferenceDispositionAdapter",
    "ReferenceQuarantineAdapter",
    "ReferenceQuarantineProjection",
]
