from __future__ import annotations

import importlib
import json
import pprint
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        if new in text:
            return
        raise RuntimeError(f"anchor not found in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def integrate_specs(identity_policy: dict[str, object]) -> None:
    path = ROOT / "src/csd_foundry/synthesis/v0_4/specs.py"
    replace_once(
        path,
        '    "choice_algorithm.schema.json",\n)',
        '    "choice_algorithm.schema.json",\n    "identity_policy.schema.json",\n)',
    )
    rendered = pprint.pformat(identity_policy, width=100, sort_dicts=False)
    replace_once(
        path,
        "\nSPEC_DOCUMENTS: dict[str, dict[str, object]] = {",
        f"\nIDENTITY_POLICY_SPEC: dict[str, object] = {rendered}\n\n\n"
        "SPEC_DOCUMENTS: dict[str, dict[str, object]] = {",
    )
    replace_once(
        path,
        '    "choice_algorithm.json": CHOICE_ALGORITHM_SPEC,\n}',
        '    "choice_algorithm.json": CHOICE_ALGORITHM_SPEC,\n'
        '    "identity_policy.json": IDENTITY_POLICY_SPEC,\n}',
    )


def integrate_cli() -> None:
    path = ROOT / "src/csd_foundry/cli.py"
    parser_anchor = (
        "    synthesis_determinism = synthesis_sub.add_parser(\n"
        '        "determinism",\n'
        '        help="validate deterministic choice primitives and frozen vectors",\n'
        "    )\n"
        '    _add_release_argument(synthesis_determinism, default="v0.4")\n'
    )
    parser_addition = (
        "    synthesis_identities = synthesis_sub.add_parser(\n"
        '        "identities",\n'
        '        help="validate canonical values and deterministic entity identities",\n'
        "    )\n"
        '    _add_release_argument(synthesis_identities, default="v0.4")\n'
    )
    replace_once(path, parser_anchor, parser_anchor + parser_addition)

    handler_anchor = (
        '    if args.command == "synthesize" and args.synthesis_command == "contracts":\n'
    )
    handler = (
        '    if args.command == "synthesize" and args.synthesis_command == "identities":\n'
        "        from csd_foundry.synthesis.v0_4.identity_validation import (\n"
        "            validate_identities,\n"
        "        )\n\n"
        "        identity_result = validate_identities(args.release)\n"
        "        _emit(identity_result.to_dict(), args.output)\n"
        "        if not identity_result.success:\n"
        "            raise SystemExit(1)\n"
        "        return\n\n"
    )
    replace_once(path, handler_anchor, handler + handler_anchor)


def integrate_ci() -> None:
    path = ROOT / ".github/workflows/ci.yml"
    editable = "      - run: csd-foundry synthesize determinism --release v0.4\n"
    replace_once(
        path,
        editable,
        editable + "      - run: csd-foundry synthesize identities --release v0.4\n",
    )
    prefix = "          /tmp/csd-installed/bin/csd-foundry synthesize "
    determinism = prefix + "determinism --release v0.4 > determinism-report.json\n"
    identities = prefix + "identities --release v0.4 > identities-report.json\n"
    replace_once(path, determinism, determinism + identities)
    report_check = "          test -s determinism-report.json\n"
    replace_once(
        path,
        report_check,
        report_check + "          test -s identities-report.json\n",
    )


def identity_schema(identity_policy: dict[str, object]) -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://elephantrock.dev/csd-foundry/v0.4/identity_policy.schema.json",
        "title": "CSD Foundry v0.4 deterministic identity policy",
        "type": "object",
        "additionalProperties": False,
        "required": list(identity_policy.keys()),
        "properties": {
            "release": {"const": "v0.4"},
            "schema_version": {"const": "0.4.0"},
            "algorithm_id": {"const": "csd-identity-hmac-sha256"},
            "algorithm_version": {"const": 1},
            "identity_schema_version": {"const": "csd-identity/0.4"},
            "digest_primitive": {"const": "hmac-sha256"},
            "full_digest_bits": {"const": 256},
            "display_digest_bits": {"const": 128},
            "role_ordinal_encoding": {"const": "uint32"},
            "volume_policy_status": {"const": "provisional"},
            "design_identity_ceiling": {"type": "integer", "minimum": 1},
            "collision_risk_ceiling_numerator": {"type": "integer", "minimum": 0},
            "collision_risk_ceiling_denominator": {"type": "integer", "minimum": 1},
            "replay_policy_id": {"const": "csd-replay-contract"},
            "replay_policy_version": {"const": 1},
            "shard_policy_id": {"const": "csd-shard-contract"},
            "shard_policy_version": {"const": 1},
            "per_kind_projected_counts": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["entity_kind", "projected_count"],
                    "properties": {
                        "entity_kind": {"type": "string", "minLength": 1},
                        "projected_count": {"type": "integer", "minimum": 0},
                    },
                },
            },
        },
    }


def main() -> None:
    from csd_foundry.synthesis.v0_4.identity_policy import expected_identity_policy_spec
    from csd_foundry.synthesis.v0_4.identity_vectors import KNOWN_ANSWER_IDENTITY_VECTORS

    policy = expected_identity_policy_spec()
    integrate_specs(policy)
    integrate_cli()
    integrate_ci()

    validation = ROOT / "src/csd_foundry/synthesis/v0_4/validation.py"
    replace_once(validation, "        policy_count=5,", "        policy_count=6,")
    tests = ROOT / "tests/synthesis_v0_4/test_contracts.py"
    replace_once(
        tests,
        "    assert report.schema_document_count == 7",
        "    assert report.schema_document_count == 8",
    )
    replace_once(
        tests, "    assert report.policy_count == 5", "    assert report.policy_count == 6"
    )

    write_json(ROOT / "specs/v0.4/identity_policy.json", policy)
    write_json(ROOT / "specs/v0.4/identity_policy.schema.json", identity_schema(policy))
    catalog = {
        "release": "v0.4",
        "schema_version": "0.4.0",
        "algorithm_id": "csd-identity-hmac-sha256",
        "algorithm_version": 1,
        "vectors": list(KNOWN_ANSWER_IDENTITY_VECTORS),
    }
    write_json(ROOT / "data/canary/v0.4/identity-v1/identity_vectors.json", catalog)

    import csd_foundry.synthesis.v0_4.specs as packaged_specs

    importlib.invalidate_caches()
    importlib.reload(packaged_specs)
    from csd_foundry.synthesis.v0_4.identity_validation import validate_identities

    report = validate_identities("v0.4")
    if not report.success:
        raise RuntimeError(f"identity validation failed during integration: {report.errors}")
    write_json(ROOT / "reports/deterministic_identities_v0.4.json", report.to_dict())


if __name__ == "__main__":
    main()
