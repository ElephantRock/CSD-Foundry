"""Frozen known-answer vectors for deterministic-choice algorithm version 1."""

from __future__ import annotations

KNOWN_ANSWER_SEED_HEX = (
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

KNOWN_ANSWER_VECTORS: tuple[dict[str, object], ...] = (
    {
        "vector_id": "bounded-first-draw-byte-boundary",
        "operation": "bounded_integer",
        "sample_index": 1,
        "segments": ["integer", 256],
        "upper_exclusive": 256,
        "expected": {
            "value": 81,
            "draw_index": 0,
            "candidate_hex": "51",
            "candidate": 81,
            "limit": 256,
            "width": 1,
            "block_count": 1,
            "draws": [
                {
                    "draw_index": 0,
                    "candidate_hex": "51",
                    "candidate": 81,
                    "block_count": 1,
                }
            ],
            "domain_digest": (
                "c59b2647f72a9bd0c9bc95ea853a4e49"
                "eefa5c6abf6a1dd4502f962ac326d845"
            ),
            "material_digest": (
                "09590bcc4f489edd3614c022d6ab946eb"
                "436178f4281746aab2de52169bdcdb7"
            ),
        },
    },
    {
        "vector_id": "bounded-forced-two-redraws",
        "operation": "bounded_integer",
        "sample_index": 1,
        "segments": ["redraw", 1],
        "upper_exclusive": 129,
        "expected": {
            "value": 46,
            "draw_index": 2,
            "candidate_hex": "2e",
            "candidate": 46,
            "limit": 129,
            "width": 1,
            "block_count": 1,
            "draws": [
                {
                    "draw_index": 0,
                    "candidate_hex": "b8",
                    "candidate": 184,
                    "block_count": 1,
                },
                {
                    "draw_index": 1,
                    "candidate_hex": "b1",
                    "candidate": 177,
                    "block_count": 1,
                },
                {
                    "draw_index": 2,
                    "candidate_hex": "2e",
                    "candidate": 46,
                    "block_count": 1,
                },
            ],
            "domain_digest": (
                "5e4272db7d6c1d2f3b1234ac39a5ca51"
                "7507987e56046b24d28ac95d6bbddf58"
            ),
            "material_digest": (
                "c5139073d58b47bdb7a0ce526e7ef3b7"
                "29a79591514088a1ec9acacdcb21a913"
            ),
        },
    },
    {
        "vector_id": "bounded-multi-block-large-bound",
        "operation": "bounded_integer",
        "sample_index": 2,
        "segments": ["large-bound", 1],
        "upper_exclusive": (
            29642774844752946028434172162224104410437116074403984394101141506025761187835961
        ),
        "expected": {
            "value": (
                28446368668670228683197603542708101144192992882973321343280535939444739969544426
            ),
            "draw_index": 0,
            "candidate_hex": (
                "dff5aaea19f189217ccd10cf2beb7aa038"
                "a7fbc8b314005a7dab2d515e6cac247291"
            ),
            "candidate": (
                6638785159048577193024017995718683384671669877475061841227835091783189484856963729
            ),
            "limit": (
                7558907585412001237250713901367146624661464598973016020495791084036569102898170055
            ),
            "width": 34,
            "block_count": 2,
            "draws": [
                {
                    "draw_index": 0,
                    "candidate_hex": (
                        "dff5aaea19f189217ccd10cf2beb7aa038"
                        "a7fbc8b314005a7dab2d515e6cac247291"
                    ),
                    "candidate": (
                        6638785159048577193024017995718683384671669877475061841227835091783189484856963729
                    ),
                    "block_count": 2,
                }
            ],
            "domain_digest": (
                "38346770454dcc67c1e11ef2a06d24844"
                "f0665090ffaafc2542c8b7ddda82a17"
            ),
            "material_digest": (
                "7380f5eecf7a5a20385486dbdadfa8abe"
                "7b633fe56fafb56345d57123023c129"
            ),
        },
    },
    {
        "vector_id": "path-integer-segment",
        "operation": "bounded_integer",
        "sample_index": 3,
        "segments": ["segment", 1],
        "upper_exclusive": 1000,
        "expected": {
            "value": 798,
            "draw_index": 0,
            "candidate_hex": "978e",
            "candidate": 38798,
            "limit": 65000,
            "width": 2,
            "block_count": 1,
            "draws": [
                {
                    "draw_index": 0,
                    "candidate_hex": "978e",
                    "candidate": 38798,
                    "block_count": 1,
                }
            ],
            "domain_digest": (
                "8b239c23ec616ae8ae470eef66367228e5"
                "694294381e22d338d8aadfe2036607"
            ),
            "material_digest": (
                "e68c4f6a37878004316237bd0b9daaf0d"
                "9eabfa88e35c01334999b42ad371c50"
            ),
        },
    },
    {
        "vector_id": "path-string-segment",
        "operation": "bounded_integer",
        "sample_index": 3,
        "segments": ["segment", "1"],
        "upper_exclusive": 1000,
        "expected": {
            "value": 141,
            "draw_index": 0,
            "candidate_hex": "d765",
            "candidate": 55141,
            "limit": 65000,
            "width": 2,
            "block_count": 1,
            "draws": [
                {
                    "draw_index": 0,
                    "candidate_hex": "d765",
                    "candidate": 55141,
                    "block_count": 1,
                }
            ],
            "domain_digest": (
                "8b239c23ec616ae8ae470eef66367228e5"
                "694294381e22d338d8aadfe2036607"
            ),
            "material_digest": (
                "503f1f60d3cb8a9ed9ec584f2ebd7344"
                "3d296374c8d3783ff0bee2baf2c6c50c"
            ),
        },
    },
    {
        "vector_id": "integer-weighted-selection",
        "operation": "integer_weighted_index",
        "sample_index": 4,
        "segments": ["weighted", "status"],
        "values": ["a", "b", "c"],
        "weights": [3, 7, 11],
        "expected": {
            "selected_index": 1,
            "selected_value": "b",
            "ticket_value": 7,
            "draw_index": 0,
            "candidate_hex": "85",
            "candidate": 133,
            "limit": 252,
            "width": 1,
            "block_count": 1,
            "cumulative_weights": [3, 10, 21],
            "domain_digest": (
                "ff27e4d95d1b80ab5ea747e2a1ff1e2a"
                "fa72fcf852e65cd74fe3796f8172e91d"
            ),
            "material_digest": (
                "89fcca0a9de8a1ab32a0645c1badc909"
                "14ac41254bb92b1e80fd6f3abd6894a3"
            ),
        },
    },
    {
        "vector_id": "exact-ratio-boolean",
        "operation": "boolean_ratio",
        "sample_index": 5,
        "segments": ["ratio", "flag"],
        "numerator": 2,
        "denominator": 5,
        "expected": {
            "selected": True,
            "ticket_value": 0,
            "draw_index": 0,
            "candidate_hex": "05",
            "candidate": 5,
            "limit": 255,
            "width": 1,
            "block_count": 1,
            "domain_digest": (
                "f61c35fe4162b5c8295801a314a0521fc"
                "cb0593ce310ce3a864feed58967d52"
            ),
            "material_digest": (
                "804ea3ff097d26e03b4ea1a086579066"
                "3e144307a3823d830d534d6607597409"
            ),
        },
    },
)
