from __future__ import annotations

import json
from pathlib import Path

SHARD_POLICY_DIGEST = "625417f57640b047bf26f87c17311a86da97dd0a5defcb746ece1c9d19a40114"
SAMPLE_KEY_POLICY_DIGEST = "b035f20b7e9c8232798b5409c14d7559742e32051d924db01fec01fa995f4e25"
VALIDATION_POLICY_DIGEST = "f318b92ac128a35d16123559353f28dd8a2255d2c767e98e2e27035bca382569"
TARGET_DEFINITION_DIGEST = "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one replacement, found {count}: {old[:100]!r}")
    return text.replace(old, new)


def patch_protocol() -> None:
    path = Path("src/csd_foundry/synthesis/v0_4/execution_protocol.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey\n",
        "from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey\n"
        "from csd_foundry.synthesis.v0_4.generation_namespace import GenerationNamespace\n",
    )
    text = replace_once(
        text,
        "class ExecutionInventory:\n    release: str\n    generation_namespace_digest: str\n",
        "class ExecutionInventory:\n    release: str\n    generation_namespace: GenerationNamespace\n",
    )
    text = replace_once(
        text,
        '        _require_constant(self.release, "v0.4", "release")\n'
        '        _require_digest(self.generation_namespace_digest, "generation_namespace_digest")\n'
        '        _require_digest(self.root_seed_commitment, "root_seed_commitment")\n',
        '        _require_constant(self.release, "v0.4", "release")\n'
        '        if type(self.generation_namespace) is not GenerationNamespace:\n'
        '            raise ExecutionProtocolError(\n'
        '                "generation_namespace must use the exact GenerationNamespace class"\n'
        '            )\n'
        '        if self.generation_namespace.release != self.release:\n'
        '            raise ExecutionProtocolError(\n'
        '                "generation namespace and inventory releases must match"\n'
        '            )\n'
        '        _require_digest(self.root_seed_commitment, "root_seed_commitment")\n',
    )
    text = replace_once(
        text,
        '        if self.shard_policy_digest != canonical_sha256(shard_policy_document()):\n'
        '            raise ExecutionProtocolError("shard policy digest does not match version 1")\n',
        '        if self.shard_policy_digest != canonical_sha256(shard_policy_document()):\n'
        '            raise ExecutionProtocolError("shard policy digest does not match version 1")\n'
        '        namespace_shard_tuple = (\n'
        '            self.generation_namespace.shard_policy_id,\n'
        '            self.generation_namespace.shard_policy_version,\n'
        '            self.generation_namespace.shard_policy_digest,\n'
        '        )\n'
        '        inventory_shard_tuple = (\n'
        '            self.shard_policy_id,\n'
        '            self.shard_policy_version,\n'
        '            self.shard_policy_digest,\n'
        '        )\n'
        '        if namespace_shard_tuple != inventory_shard_tuple:\n'
        '            raise ExecutionProtocolError(\n'
        '                "inventory shard policy does not match the generation namespace"\n'
        '            )\n',
    )
    marker = "    def to_json_value(self) -> dict[str, object]:\n        return {\n            \"generation_namespace_digest\": self.generation_namespace_digest,"
    replacement = (
        "    @property\n"
        "    def generation_namespace_digest(self) -> str:\n"
        "        return self.generation_namespace.digest\n\n"
        "    def to_json_value(self) -> dict[str, object]:\n"
        "        return {\n"
        "            \"generation_namespace_digest\": self.generation_namespace_digest,"
    )
    text = replace_once(text, marker, replacement)

    addition = '''


def validate_supersession_history(
    records: tuple[InventorySupersessionRecord, ...],
) -> tuple[InventorySupersessionRecord, ...]:
    """Validate append-only supersession order without reactivating prior inventories."""

    if type(records) is not tuple:
        raise ExecutionProtocolError("supersession history must be an immutable tuple")
    superseded: set[str] = set()
    record_digests: set[str] = set()
    for record in records:
        if type(record) is not InventorySupersessionRecord:
            raise ExecutionProtocolError(
                "supersession history must contain exact supersession records"
            )
        if record.digest in record_digests:
            raise ExecutionProtocolError("supersession history contains a duplicate record")
        if record.superseded_inventory_digest in superseded:
            raise ExecutionProtocolError("an inventory cannot be superseded more than once")
        if record.replacement_inventory_digest in superseded:
            raise ExecutionProtocolError(
                "a previously superseded inventory cannot be reactivated"
            )
        record_digests.add(record.digest)
        superseded.add(record.superseded_inventory_digest)
    return records


def append_inventory_supersession(
    history: tuple[InventorySupersessionRecord, ...],
    record: InventorySupersessionRecord,
) -> tuple[InventorySupersessionRecord, ...]:
    if type(history) is not tuple:
        raise ExecutionProtocolError("supersession history must be an immutable tuple")
    if type(record) is not InventorySupersessionRecord:
        raise ExecutionProtocolError("new supersession must use the exact record class")
    return validate_supersession_history((*history, record))
'''
    if "def validate_supersession_history(" in text:
        raise RuntimeError("supersession history validator already exists")
    text += addition
    path.write_text(text, encoding="utf-8")


def patch_validation() -> None:
    path = Path("src/csd_foundry/synthesis/v0_4/execution_validation.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "    assigned_shard,\n",
        "    append_inventory_supersession,\n    assigned_shard,\n",
    )
    text = replace_once(
        text,
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n",
        "from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace\n"
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n",
    )
    text = replace_once(
        text,
        "        generation_namespace_digest=_TARGET_ALPHA_NAMESPACE_DIGEST,\n",
        "        generation_namespace=build_generation_namespace(\n"
        "            _TARGET_ALPHA_DEFINITION_DIGEST\n"
        "        ),\n",
    )
    old_block = '''    supersession_append_only = False
    try:
        InventorySupersessionRecord(
            superseded_inventory_digest=inventory.digest,
            replacement_inventory_digest=inventory.digest,
            superseding_run_id="run-v2",
            reason_code="target-change",
            reason_facts=CanonicalObject.from_pairs((("reason", "same-inventory"),)),
        )
    except ExecutionProtocolError:
        supersession_append_only = True
'''
    new_block = '''    supersession_append_only = False
    first_supersession = _supersession()
    reactivation = InventorySupersessionRecord(
        superseded_inventory_digest=first_supersession.replacement_inventory_digest,
        replacement_inventory_digest=first_supersession.superseded_inventory_digest,
        superseding_run_id="run-v3",
        reason_code="reactivation-attempt",
        reason_facts=CanonicalObject.from_pairs((("reason", "cycle"),)),
    )
    try:
        append_inventory_supersession((first_supersession,), reactivation)
    except ExecutionProtocolError:
        supersession_append_only = True
'''
    text = replace_once(text, old_block, new_block)
    path.write_text(text, encoding="utf-8")


def patch_inventory_fixture(path_value: str, target_constant: str) -> None:
    path = Path(path_value)
    text = path.read_text(encoding="utf-8")
    if "from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace" not in text:
        anchor = "from csd_foundry.synthesis.v0_4.serialization import canonical_sha256\n"
        text = replace_once(
            text,
            anchor,
            "from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace\n"
            + anchor,
        )
    if "_TARGET_DEFINITION_DIGEST" not in text:
        namespace_marker = '_NAMESPACE_DIGEST = "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"\n'
        text = replace_once(
            text,
            namespace_marker,
            f'_TARGET_DEFINITION_DIGEST = "{TARGET_DEFINITION_DIGEST}"\n' + namespace_marker,
        )
    text = text.replace(
        "        generation_namespace_digest=_NAMESPACE_DIGEST,\n",
        "        generation_namespace=build_generation_namespace(\n"
        "            _TARGET_DEFINITION_DIGEST\n"
        "        ),\n",
    )
    path.write_text(text, encoding="utf-8")


def patch_review_tests() -> None:
    patch_inventory_fixture("tests/test_v0_4_execution_protocol.py", "_TARGET_DEFINITION_DIGEST")
    patch_inventory_fixture("tests/test_v0_4_execution_exact_types.py", "_TARGET_DEFINITION_DIGEST")
    patch_inventory_fixture("tests/test_v0_4_execution_review_regressions.py", "_TARGET_DEFINITION_DIGEST")

    path = Path("tests/test_v0_4_execution_review_regressions.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "    ExecutionInventory,\n",
        "    ExecutionInventory,\n    InventorySupersessionRecord,\n",
    )
    text = replace_once(
        text,
        "    SampleExecutionSpec,\n",
        "    SampleExecutionSpec,\n    append_inventory_supersession,\n",
    )
    addition = '''


def test_inventory_rejects_generation_namespace_shard_policy_drift() -> None:
    policy = OperationalRetryPolicy(0)
    inventory = _inventory(policy)
    incompatible_namespace = replace(
        inventory.generation_namespace,
        shard_policy_version=2,
        shard_policy_digest=canonical_sha256({"shard-policy": 2}),
    )
    with pytest.raises(ExecutionProtocolError, match="generation namespace"):
        replace(inventory, generation_namespace=incompatible_namespace)


def test_supersession_history_rejects_reactivation_cycles() -> None:
    first = InventorySupersessionRecord(
        superseded_inventory_digest=canonical_sha256({"inventory": "a"}),
        replacement_inventory_digest=canonical_sha256({"inventory": "b"}),
        superseding_run_id="run-b",
        reason_code="replacement",
        reason_facts=CanonicalObject.from_pairs((("reason", "a-to-b"),)),
    )
    reactivation = InventorySupersessionRecord(
        superseded_inventory_digest=first.replacement_inventory_digest,
        replacement_inventory_digest=first.superseded_inventory_digest,
        superseding_run_id="run-a",
        reason_code="reactivation",
        reason_facts=CanonicalObject.from_pairs((("reason", "b-to-a"),)),
    )
    with pytest.raises(ExecutionProtocolError, match="cannot be reactivated"):
        append_inventory_supersession((first,), reactivation)
'''
    if "test_supersession_history_rejects_reactivation_cycles" not in text:
        text += addition
    path.write_text(text, encoding="utf-8")


def patch_schema() -> None:
    path = Path("specs/v0.4/execution_protocol.schema.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    definitions = document["$defs"]
    inventory_properties = definitions["executionInventory"]["properties"]
    inventory_properties["sample_key_encoding_policy_digest"] = {
        "const": SAMPLE_KEY_POLICY_DIGEST
    }
    inventory_properties["shard_policy_digest"] = {"const": SHARD_POLICY_DIGEST}
    inventory_properties["validation_policy_digest"] = {
        "const": VALIDATION_POLICY_DIGEST
    }
    cardinality_branches = []
    for retries in range(256):
        total = retries + 1
        cardinality_branches.append(
            {
                "properties": {
                    "failure_receipt_digests": {
                        "maxItems": total,
                        "minItems": total,
                    },
                    "maximum_operational_retries": {"const": retries},
                    "total_execution_count": {"const": total},
                },
                "required": [
                    "failure_receipt_digests",
                    "maximum_operational_retries",
                    "total_execution_count",
                ],
            }
        )
    definitions["operationalExhaustion"]["allOf"] = [
        {"oneOf": cardinality_branches}
    ]
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def patch_artifact_tests() -> None:
    path = Path("tests/test_v0_4_execution_artifacts.py")
    text = path.read_text(encoding="utf-8")
    addition = f'''


def test_execution_schema_pins_policies_and_exhaustion_cardinality() -> None:
    document = _load("specs/v0.4/execution_protocol.schema.json")
    assert type(document) is dict
    definitions = document["$defs"]
    inventory_properties = definitions["executionInventory"]["properties"]
    assert inventory_properties["sample_key_encoding_policy_digest"] == {{
        "const": "{SAMPLE_KEY_POLICY_DIGEST}"
    }}
    assert inventory_properties["shard_policy_digest"] == {{
        "const": "{SHARD_POLICY_DIGEST}"
    }}
    assert inventory_properties["validation_policy_digest"] == {{
        "const": "{VALIDATION_POLICY_DIGEST}"
    }}
    branches = definitions["operationalExhaustion"]["allOf"][0]["oneOf"]
    assert len(branches) == 256
    retry_two = branches[2]["properties"]
    assert retry_two["maximum_operational_retries"] == {{"const": 2}}
    assert retry_two["total_execution_count"] == {{"const": 3}}
    assert retry_two["failure_receipt_digests"] == {{
        "maxItems": 3,
        "minItems": 3,
    }}
'''
    if "test_execution_schema_pins_policies_and_exhaustion_cardinality" not in text:
        text += addition
    path.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    path = Path("docs/execution_protocol_v0.4.md")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "An `ExecutionInventory` is immutable, content-addressed authority. It commits the generation\nnamespace, root-seed commitment, sample-key encoding policy, shard policy, shard count,\n",
        "An `ExecutionInventory` is immutable, content-addressed authority. Construction requires the\nexact `GenerationNamespace` object and verifies that its digest and shard-policy tuple match\nthe inventory before canonical bytes can be emitted. The inventory also commits the root-seed\ncommitment, sample-key encoding policy, shard policy, shard count,\n",
    )
    text = replace_once(
        text,
        "inventory is linked through a new append-only `InventorySupersessionRecord`. The previous\ninventory and all partial evidence remain addressable under their original digests.\n",
        "inventory is linked through a new append-only `InventorySupersessionRecord`. New records\nare validated against the ordered supersession history; duplicate supersession and any path\nthat reactivates a previously superseded inventory fail closed. The previous inventory and all\npartial evidence remain addressable under their original digests.\n",
    )
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_protocol()
    patch_validation()
    patch_review_tests()
    patch_schema()
    patch_artifact_tests()
    patch_docs()


if __name__ == "__main__":
    main()
