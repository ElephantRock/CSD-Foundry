        ],
    )


def test_metric_controller_parses_via_a0b2_and_treats_malformed_as_incorrect(
    metric_controller: ModuleType,
) -> None:
    """Defect 5/6: raw suffixes are parsed by the frozen A0b2 parser; malformed
    output is counted as incorrect, not TECHNICALLY_INVALID."""

    keys = sorted(_gold_case_keys())
    # Every prediction emits a malformed suffix "X" (rejected by the strict
    # parser). All four dev families are wrong; primary accuracy is 0 for each
    # classification arm.
    records: list[dict[str, Any]] = []
    for set_name in metric_controller.ALL_PREDICTION_SETS:
        for key in keys:
            records.append(_make_raw_prediction(set_name, key, "X"))
    primary_accuracies, safety_counts = metric_controller._evaluate_predictions(
        prediction_records=records,
        dev_cases=[
            json.loads(line)
            for line in (DATA_V6 / "development_evaluation.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ],
        clean_cases=[
            json.loads(line)
            for line in (DATA_V6 / "clean_evaluation.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ],
    )
    for arm in ("BASE", "CONTROL", "FOUNDRY"):
        assert primary_accuracies[arm] == 0.0
        # Malformed increments clean_malformed_count and clean_exact_error_count.
        assert safety_counts[arm]["clean_malformed_count"] == 4
        assert safety_counts[arm]["clean_exact_error_count"] == 4
    terminal, _evidence = metric_controller._classify_run(
        sealed_execution_passed=True,
        primary_accuracies=primary_accuracies,
        safety_counts=safety_counts,
    )
    # Tied-at-zero accuracy with no safety regression => NO_OBSERVED_SIGNAL,
    # NOT TECHNICALLY_INVALID (malformed is incorrect, not invalid).
    assert terminal == "NO_OBSERVED_SIGNAL"


def test_metric_controller_authenticates_gold_bytes(metric_controller: ModuleType) -> None:
    """Defect 6/7: the gold bytes are authenticated against the A2 receipt."""

    dev_cases, clean_cases = metric_controller._authenticate_gold_bytes(
        ROOT,
        dev_path=DATA_V6 / "development_evaluation.jsonl",
        clean_path=DATA_V6 / "clean_evaluation.jsonl",
    )
    assert len(dev_cases) == 4
    assert len(clean_cases) == 4


def test_metric_controller_rejects_tampered_gold_bytes(
    metric_controller: ModuleType, tmp_path: Path
) -> None:
    """Defect 6: a tampered gold file fails SHA-256 authentication."""

    fake = tmp_path / "development_evaluation.jsonl"
    fake.write_text(
        (DATA_V6 / "development_evaluation.jsonl")
        .read_text(encoding="utf-8")
        .replace("REMOVES_ONLY", "BOTH", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        metric_controller._authenticate_gold_bytes(
            ROOT,
            dev_path=fake,
            clean_path=DATA_V6 / "clean_evaluation.jsonl",
        )


def test_metric_controller_rejects_duplicate_predictions(
    metric_controller: ModuleType,
) -> None:
    """Defect 6: duplicate prediction cases are rejected."""

    keys = sorted(_gold_case_keys())
    records: list[dict[str, Any]] = []
    for set_name in metric_controller.ALL_PREDICTION_SETS:
        for key in keys:
            records.append(_make_raw_prediction(set_name, key, "A"))
    # Duplicate the first record (over-count).
    records.append(records[0])
    with pytest.raises(ValueError):
        metric_controller._evaluate_predictions(
            prediction_records=records,
            dev_cases=[
                json.loads(line)
                for line in (DATA_V6 / "development_evaluation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
            clean_cases=[
                json.loads(line)
                for line in (DATA_V6 / "clean_evaluation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
        )


# ---------------------------------------------------------------------------
# Defect 4: Two-mode direct/successor provenance gate (analogous to A0b2/A1/A2).
# ---------------------------------------------------------------------------

_COMPILED_RELEASE_FILES = frozenset(
    {
        "artifact_manifest.json",
        "budget_contract.json",
        "checkpoint_contract.json",
        "classification_contract.json",
        "e1_run_contract.json",
        "environment_lock.json",
        "evaluation_access_contract.json",
        "launch_commands.json",
        "reconstruction_receipt.json",
        "run_inputs_lock.json",
        "sealed_prompt_inventory.jsonl",
        "sealed_prompt_manifest.json",
        "storage_contract.json",
        "training_recipe.json",
    }
)


def test_git_history_provenance_gate_two_mode() -> None:
    """Two-mode provenance gate for the compiled release artifacts.

    Direct mode: HEAD changes exactly the 14 compiled_release files →
    receipt.source_commit == HEAD^, diff == exactly those 14 files.

    Successor mode: HEAD changes other files → locate introduction commit,
    verify all 14 current blobs match introduction blobs.
    """

    import subprocess

    release_dir = ROOT / "experiments" / "e1" / "windows_native_v1" / "compiled_release"
    receipt_path = release_dir / "reconstruction_receipt.json"
    if not receipt_path.is_file():
        pytest.skip("compiled_release/reconstruction_receipt.json not yet committed")

    def _git(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=str(ROOT),
                check=True,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            pytest.fail(f"git command failed: {exc}")
        return completed.stdout.strip()

    # Read the committed receipt.
    receipt_text = _git(
        "show",
        "HEAD:experiments/e1/windows_native_v1/compiled_release/reconstruction_receipt.json",
    )
    receipt = json.loads(receipt_text)
    committed_source_commit = receipt["source_commit"]

    # Resolve the artifact commit via parent inspection.
    parents = _git("show", "-s", "--format=%P", "HEAD").split()
    head_tip = parents[1] if len(parents) >= 2 else _git("rev-parse", "HEAD")

    head_diff = set(
        line for line in _git("diff", "--name-only", f"{head_tip}^", head_tip).splitlines() if line
    )
    expected_paths = frozenset(
        f"experiments/e1/windows_native_v1/compiled_release/{name}"
        for name in _COMPILED_RELEASE_FILES
    )

    if head_diff == expected_paths:
        # Direct mode: enforce S→A adjacency exactly.
        implementation_commit = _git("rev-parse", f"{head_tip}^")
        assert committed_source_commit == implementation_commit, (
            f"receipt source_commit {committed_source_commit!r} does not match "
            f"git-derived implementation commit {implementation_commit!r}"
        )
    else:
        # Successor mode: locate introduction commit, verify blob identity.
        receipt_rel = (
            "experiments/e1/windows_native_v1/compiled_release/reconstruction_receipt.json"
        )
        introductions = _git(
            "log",
            "--diff-filter=A",
            "--format=%H",
            "--",
            receipt_rel,
        ).splitlines()
        assert introductions, f"no commit found introducing {receipt_rel}"
        frozen_commit = introductions[-1]

        for name in _COMPILED_RELEASE_FILES:
            rel = f"experiments/e1/windows_native_v1/compiled_release/{name}"
            frozen_blob = _git("rev-parse", f"{frozen_commit}:{rel}")
            current_blob = _git("hash-object", rel)
            assert current_blob == frozen_blob, f"frozen compiled_release artifact changed: {rel}"
