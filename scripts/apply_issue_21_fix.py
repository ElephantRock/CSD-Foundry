from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

V1_SCHEMA_PATH = ROOT / "specs/v0.4/execution_protocol.schema.json"
V2_SCHEMA_PATH = ROOT / "specs/v0.4/execution_protocol_v2.schema.json"
V1_CANARY_PATH = ROOT / "data/canary/v0.4/execution-v1/execution_vectors.json"
V2_CANARY_PATH = ROOT / "data/canary/v0.4/execution-v2/execution_vectors.json"

V1_SCHEMA_SHA256 = "f2c08484af668aeb647825a5639fbc0f66b0fd07dbe1a16e97039b9b3c750d47"
V1_CANARY_SHA256 = "875d5af490bf3b10142419a5c0f1b2ad8bb66092426e4ff15bc6c75dc971b5bd"
V2_CATALOG_DIGEST = "5a9bbee3603ed72bf5eb1b6b2ac324469262b5f1aee31cdd8b638d318966418f"

VECTOR_IDS = [
    "sample-key-encoding",
    "shard-assignment",
    "required-schema-versions",
    "retry-policy",
    "execution-inventory",
    "operational-exhaustion",
    "inventory-supersession",
]
EXPECTED_DIGESTS = {
    "execution-inventory": "24318c3f24ffa6ce8c5e2c57ddcb40634d472bde5f1152093a4ff9449ef152e9",
    "inventory-supersession": "d48582ce74f7a9705b4140e5d4137cc22bd123117dd7562ceacdb4b032420e2b",
    "operational-exhaustion": "251e31ca0c559bf28bd3a58aa20c3a7a19eea592a3b54beeb4f6fdcfa85831e3",
    "required-schema-versions": "4cd4c074fed2955a9004df64de0979239ff135cc93b1f6e6e1a6d58bf0a6531a",
    "retry-policy": "30320e0bb4bba10b71b8862157bc3a3b27356e940dcf36f0a1e601b7355795f7",
    "sample-key-encoding": "897a55e7039c5cc98c52497bf3a7656bdaf00424765ff1f0a30ab2da77e9d5fa",
    "shard-assignment": "ba5111604090596f7ac8591f5b10954dfd10650877711f80d5c7990bff2c3367",
}


def canonical_sha256(value: object) -> str:
    encoded = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one replacement target, found {count}")
    return text.replace(old, new, 1)


def verify_v1_artifacts() -> None:
    schema_digest = hashlib.sha256(V1_SCHEMA_PATH.read_bytes()).hexdigest()
    if schema_digest != V1_SCHEMA_SHA256:
        raise RuntimeError(f"unexpected v1 schema digest: {schema_digest}")
    canary_digest = hashlib.sha256(V1_CANARY_PATH.read_bytes()).hexdigest()
    if canary_digest != V1_CANARY_SHA256:
        raise RuntimeError(f"unexpected v1 canary digest: {canary_digest}")


def write_execution_vectors() -> None:
    path = ROOT / "src/csd_foundry/synthesis/v0_4/execution_vectors.py"
    path.write_text(
        '''"""Frozen known-answer vectors for v0.4 execution-protocol evidence version 2."""

from __future__ import annotations

from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

EXECUTION_VECTOR_EVIDENCE_VERSION = 2
EXECUTION_VECTOR_IDS = (
    "sample-key-encoding",
    "shard-assignment",
    "required-schema-versions",
    "retry-policy",
    "execution-inventory",
    "operational-exhaustion",
    "inventory-supersession",
)

EXPECTED_EXECUTION_DIGESTS: dict[str, str] = {
    "execution-inventory": "24318c3f24ffa6ce8c5e2c57ddcb40634d472bde5f1152093a4ff9449ef152e9",
    "inventory-supersession": "d48582ce74f7a9705b4140e5d4137cc22bd123117dd7562ceacdb4b032420e2b",
    "operational-exhaustion": "251e31ca0c559bf28bd3a58aa20c3a7a19eea592a3b54beeb4f6fdcfa85831e3",
    "required-schema-versions": "4cd4c074fed2955a9004df64de0979239ff135cc93b1f6e6e1a6d58bf0a6531a",
    "retry-policy": "30320e0bb4bba10b71b8862157bc3a3b27356e940dcf36f0a1e601b7355795f7",
    "sample-key-encoding": "897a55e7039c5cc98c52497bf3a7656bdaf00424765ff1f0a30ab2da77e9d5fa",
    "shard-assignment": "ba5111604090596f7ac8591f5b10954dfd10650877711f80d5c7990bff2c3367",
}

LEGACY_EXECUTION_VECTOR_V1_CATALOG_DIGEST = (
    "ae40bcce9e169c5bc11c9a3e83ab582124e973c1c7afafefdb99a74e2833a341"
)
FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST = (
    "5a9bbee3603ed72bf5eb1b6b2ac324469262b5f1aee31cdd8b638d318966418f"
)


def execution_vector_catalog_commitment() -> dict[str, object]:
    return {
        "evidence_version": EXECUTION_VECTOR_EVIDENCE_VERSION,
        "expected_digests": EXPECTED_EXECUTION_DIGESTS,
        "vector_ids": list(EXECUTION_VECTOR_IDS),
    }


def validate_execution_vector_catalog() -> None:
    if tuple(EXPECTED_EXECUTION_DIGESTS) != tuple(sorted(EXPECTED_EXECUTION_DIGESTS)):
        raise ValueError("execution vector digests must use sorted vector IDs")
    if set(EXECUTION_VECTOR_IDS) != set(EXPECTED_EXECUTION_DIGESTS):
        raise ValueError("execution vector IDs and expected digests differ")
    if (
        canonical_sha256(execution_vector_catalog_commitment())
        != FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST
    ):
        raise ValueError("execution vector catalog digest changed")
''',
        encoding="utf-8",
    )


def patch_execution_validation() -> None:
    path = ROOT / "src/csd_foundry/synthesis/v0_4/execution_validation.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '"""Validation and immutable evidence for v0.4 execution protocol version 1."""',
        '"""Validation and immutable evidence for v0.4 execution protocol and evidence v2."""',
        label="execution validation docstring",
    )
    text = replace_once(
        text,
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n"
        "    EXECUTION_VECTOR_IDS,\n",
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n"
        "    EXECUTION_VECTOR_EVIDENCE_VERSION,\n"
        "    EXECUTION_VECTOR_IDS,\n",
        label="execution vector import",
    )
    text = replace_once(
        text,
        '_RELEASE_ROOT_SEED_COMMITMENT = "6e5306d9779ade6c6e8bdf5d3d88431e8a4a9fb5ea2e4526949923319400661e"\n',
        '_RELEASE_ROOT_SEED_COMMITMENT = "6e5306d9779ade6c6e8bdf5d3d88431e8a4a9fb5ea2e4526949923319400661e"\n'
        "EXECUTION_SCHEMA_DOCUMENT_VERSION = 2\n",
        label="schema document version constant",
    )
    text = replace_once(
        text,
        "    vector_catalog_digest: str\n"
        "    sample_key_encoding_stable: bool\n",
        "    vector_catalog_digest: str\n"
        "    vector_evidence_version: int\n"
        "    execution_schema_document_version: int\n"
        "    sample_key_encoding_stable: bool\n",
        label="validation report fields",
    )
    text = replace_once(
        text,
        '        return {\n            "errors": list(self.errors),\n',
        '        return {\n'
        '            "errors": list(self.errors),\n'
        '            "execution_schema_document_version": (\n'
        '                self.execution_schema_document_version\n'
        '            ),\n',
        label="validation report schema version serialization",
    )
    text = replace_once(
        text,
        '            "vector_catalog_digest": self.vector_catalog_digest,\n'
        '            "vector_count": self.vector_count,\n',
        '            "vector_catalog_digest": self.vector_catalog_digest,\n'
        '            "vector_count": self.vector_count,\n'
        '            "vector_evidence_version": self.vector_evidence_version,\n',
        label="validation report evidence version serialization",
    )
    text = replace_once(
        text,
        "        vector_catalog_digest=FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,\n"
        "        sample_key_encoding_stable=sample_key_encoding_stable,\n",
        "        vector_catalog_digest=FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,\n"
        "        vector_evidence_version=EXECUTION_VECTOR_EVIDENCE_VERSION,\n"
        "        execution_schema_document_version=EXECUTION_SCHEMA_DOCUMENT_VERSION,\n"
        "        sample_key_encoding_stable=sample_key_encoding_stable,\n",
        label="validation report constructor versions",
    )
    path.write_text(text, encoding="utf-8")


def write_v2_canary() -> None:
    payload = {
        "catalog_digest": V2_CATALOG_DIGEST,
        "evidence_version": 2,
        "expected_digests": EXPECTED_DIGESTS,
        "release": "v0.4",
        "sample_key_encoding_id": "csd-sample-key-canonical-json",
        "sample_key_encoding_version": 1,
        "schema_version": "0.4.0",
        "shard_policy_id": "csd-shard-contract",
        "shard_policy_version": 1,
        "vector_ids": VECTOR_IDS,
    }
    commitment = {
        "evidence_version": payload["evidence_version"],
        "expected_digests": payload["expected_digests"],
        "vector_ids": payload["vector_ids"],
    }
    actual = canonical_sha256(commitment)
    if actual != V2_CATALOG_DIGEST:
        raise RuntimeError(f"unexpected v2 catalog digest: {actual}")
    write_json(V2_CANARY_PATH, payload)


def write_v2_schema() -> None:
    v1 = json.loads(V1_SCHEMA_PATH.read_text(encoding="utf-8"))
    v2 = copy.deepcopy(v1)
    v2["$comment"] = (
        "Schema document version 2 supersedes execution_protocol.schema.json for current "
        "validation while preserving all serialized v0.4 artifact schema_version values."
    )
    v2["$id"] = "urn:csd-foundry:execution-protocol-schema:v0.4:2"
    retry_policy = v2["$defs"]["operationalRetryPolicy"]
    retry_policy["allOf"] = [
        {
            "oneOf": [
                {
                    "properties": {
                        "maximum_operational_retries": {"const": retries},
                        "maximum_total_executions": {"const": retries + 1},
                    },
                    "required": [
                        "maximum_operational_retries",
                        "maximum_total_executions",
                    ],
                }
                for retries in range(256)
            ]
        }
    ]
    write_json(V2_SCHEMA_PATH, v2)


def patch_artifact_tests() -> None:
    path = ROOT / "tests/test_v0_4_execution_artifacts.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "import json\n",
        "import hashlib\nimport json\n\nimport pytest\nfrom jsonschema import Draft202012Validator, ValidationError\n",
        label="artifact test imports",
    )
    text = replace_once(
        text,
        "from csd_foundry.synthesis.v0_4.execution_validation import validate_execution_protocol\n",
        "from csd_foundry.synthesis.v0_4.execution_validation import (\n"
        "    EXECUTION_SCHEMA_DOCUMENT_VERSION,\n"
        "    validate_execution_protocol,\n"
        ")\n",
        label="artifact validation imports",
    )
    text = replace_once(
        text,
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n"
        "    EXECUTION_VECTOR_IDS,\n",
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n"
        "    EXECUTION_VECTOR_EVIDENCE_VERSION,\n"
        "    EXECUTION_VECTOR_IDS,\n",
        label="artifact vector imports",
    )
    text = replace_once(
        text,
        "    FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,\n"
        ")\n",
        "    FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,\n"
        "    execution_vector_catalog_commitment,\n"
        ")\n",
        label="artifact commitment import",
    )
    text = replace_once(
        text,
        "_ROOT = Path(__file__).resolve().parents[1]\n",
        "_ROOT = Path(__file__).resolve().parents[1]\n"
        '_CURRENT_EXECUTION_SCHEMA = "specs/v0.4/execution_protocol_v2.schema.json"\n'
        '_V1_EXECUTION_SCHEMA_SHA256 = (\n'
        '    "f2c08484af668aeb647825a5639fbc0f66b0fd07dbe1a16e97039b9b3c750d47"\n'
        ')\n'
        '_V1_EXECUTION_CANARY_SHA256 = (\n'
        '    "875d5af490bf3b10142419a5c0f1b2ad8bb66092426e4ff15bc6c75dc971b5bd"\n'
        ')\n',
        label="artifact constants",
    )
    text = replace_once(
        text,
        '    document = _load("data/canary/v0.4/execution-v1/execution_vectors.json")\n',
        '    document = _load("data/canary/v0.4/execution-v2/execution_vectors.json")\n',
        label="current execution canary path",
    )
    text = replace_once(
        text,
        '    assert type(document) is dict\n'
        '    assert document["vector_ids"] == list(EXECUTION_VECTOR_IDS)\n',
        '    assert type(document) is dict\n'
        '    assert document["evidence_version"] == EXECUTION_VECTOR_EVIDENCE_VERSION\n'
        '    assert document["vector_ids"] == list(EXECUTION_VECTOR_IDS)\n',
        label="canary evidence version assertion",
    )
    text = replace_once(
        text,
        '    assert document["catalog_digest"] == FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST\n',
        '    assert document["catalog_digest"] == FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST\n'
        '    assert execution_vector_catalog_commitment() == {\n'
        '        "evidence_version": document["evidence_version"],\n'
        '        "expected_digests": document["expected_digests"],\n'
        '        "vector_ids": document["vector_ids"],\n'
        '    }\n',
        label="canary commitment assertion",
    )
    text = text.replace(
        '_load("specs/v0.4/execution_protocol.schema.json")',
        "_load(_CURRENT_EXECUTION_SCHEMA)",
    )
    text += '''


def test_v1_execution_artifacts_remain_byte_identical() -> None:
    assert hashlib.sha256(
        (_ROOT / "specs/v0.4/execution_protocol.schema.json").read_bytes()
    ).hexdigest() == _V1_EXECUTION_SCHEMA_SHA256
    assert hashlib.sha256(
        (_ROOT / "data/canary/v0.4/execution-v1/execution_vectors.json").read_bytes()
    ).hexdigest() == _V1_EXECUTION_CANARY_SHA256


def test_current_execution_schema_is_versioned_and_well_formed() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
    assert type(document) is dict
    assert document["$id"] == "urn:csd-foundry:execution-protocol-schema:v0.4:2"
    assert EXECUTION_SCHEMA_DOCUMENT_VERSION == 2
    Draft202012Validator.check_schema(document)


def test_retry_policy_schema_rejects_inconsistent_derived_count() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
    assert type(document) is dict
    retry_schema = document["$defs"]["operationalRetryPolicy"]
    validator = Draft202012Validator(retry_schema)
    validator.validate(
        {
            "maximum_operational_retries": 2,
            "maximum_total_executions": 3,
            "schema_version": "csd-operational-retry-policy/0.4",
        }
    )
    with pytest.raises(ValidationError):
        validator.validate(
            {
                "maximum_operational_retries": 2,
                "maximum_total_executions": 1,
                "schema_version": "csd-operational-retry-policy/0.4",
            }
        )
'''
    path.write_text(text, encoding="utf-8")


def patch_protocol_tests() -> None:
    path = ROOT / "tests/test_v0_4_execution_protocol.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n"
        "    EXPECTED_EXECUTION_DIGESTS,\n",
        "from csd_foundry.synthesis.v0_4.execution_vectors import (\n"
        "    EXPECTED_EXECUTION_DIGESTS,\n"
        "    FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,\n"
        "    execution_vector_catalog_commitment,\n",
        label="protocol test vector imports",
    )
    text += '''


def test_execution_catalog_commitment_covers_expected_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_digest = FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST
    changed = "0" * 64
    monkeypatch.setitem(EXPECTED_EXECUTION_DIGESTS, "retry-policy", changed)
    assert canonical_sha256(execution_vector_catalog_commitment()) != original_digest
    with pytest.raises(ValueError, match="catalog digest changed"):
        validate_execution_vector_catalog()
'''
    path.write_text(text, encoding="utf-8")


def patch_pyproject() -> None:
    path = ROOT / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        'dev = [\n  "mypy>=1.15",\n',
        'dev = [\n  "jsonschema>=4.23",\n  "mypy>=1.15",\n',
        label="jsonschema dev dependency",
    )
    path.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    path = ROOT / "docs/execution_protocol_v0.4.md"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "Execution-protocol canary version 1 contains seven independently pinned vectors covering:\n",
        "Execution-protocol evidence version 2 contains seven independently pinned vectors covering:\n",
        label="frozen evidence version",
    )
    text = replace_once(
        text,
        "Any change to the vector catalog or expected digests requires a new evidence version.\n",
        "Any change to the vector catalog or expected digests requires a new evidence version.\n\n"
        "### Corrective supersession boundary\n\n"
        "The original `execution-v1` canary and `execution_protocol.schema.json` remain\n"
        "byte-identical historical artifacts. They are not rewritten. Evidence version 2 is the\n"
        "current catalog authority: its catalog digest commits the ordered vector IDs and the\n"
        "complete expected-digest mapping. Schema document version 2 is the current ingestion\n"
        "authority: it exhaustively binds each uint8 retry count to exactly one derived total\n"
        "execution count.\n\n"
        "This supersession changes neither execution-protocol semantics nor any vector value,\n"
        "generation namespace, choice identity, replay commitment, inventory digest, or runtime\n"
        "retry-policy serialization. It only strengthens the independent evidence commitment and\n"
        "external schema/API equivalence.\n",
        label="supersession documentation",
    )
    path.write_text(text, encoding="utf-8")


def patch_report() -> None:
    path = ROOT / "reports/execution_protocol_v0.4.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["execution_schema_document_version"] = 2
    report["vector_catalog_digest"] = V2_CATALOG_DIGEST
    report["vector_evidence_version"] = 2
    write_json(path, report)


def verify_outputs() -> None:
    v2_canary = json.loads(V2_CANARY_PATH.read_text(encoding="utf-8"))
    commitment = {
        "evidence_version": v2_canary["evidence_version"],
        "expected_digests": v2_canary["expected_digests"],
        "vector_ids": v2_canary["vector_ids"],
    }
    if canonical_sha256(commitment) != v2_canary["catalog_digest"]:
        raise RuntimeError("v2 canary does not commit its expected values")

    schema = json.loads(V2_SCHEMA_PATH.read_text(encoding="utf-8"))
    branches = schema["$defs"]["operationalRetryPolicy"]["allOf"][0]["oneOf"]
    if len(branches) != 256:
        raise RuntimeError("v2 retry-policy relation must contain 256 branches")
    for retries, branch in enumerate(branches):
        properties = branch["properties"]
        if properties["maximum_operational_retries"] != {"const": retries}:
            raise RuntimeError(f"retry branch {retries} has the wrong retry constant")
        if properties["maximum_total_executions"] != {"const": retries + 1}:
            raise RuntimeError(f"retry branch {retries} has the wrong execution constant")

    verify_v1_artifacts()


def main() -> None:
    verify_v1_artifacts()
    write_execution_vectors()
    patch_execution_validation()
    write_v2_canary()
    write_v2_schema()
    patch_artifact_tests()
    patch_protocol_tests()
    patch_pyproject()
    patch_docs()
    patch_report()
    verify_outputs()


if __name__ == "__main__":
    main()
