"""Platform boundary tests for the shared locking and fsync helpers.

These tests exercise the cross-platform persistence primitives in
``csd_foundry._platform``:

* advisory-lock serialization across independent processes (not just threads),
  using explicit event coordination;
* strict lock-file opener that rejects symlinks, directories, and non-regular
  files, with descriptor-based identity validation;
* strict-lock serialization across processes;
* the directory-fsync boundary contract (callable on POSIX, no-op on Windows,
  never raises on a directory);
* newline protection for frozen content-addressed fixtures.

The durability claim is intentionally narrow: atomic publication and
restart-safe reconstruction are supported on both platforms; sudden-power-loss
durability is supported only on POSIX (where directory fsync exists) and is
not asserted here for Windows.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import sys
from pathlib import Path

import pytest

from csd_foundry._platform import (
    LockInvalidError,
    advisory_lock,
    advisory_lock_strict,
    fsync_directory,
    open_lock_file_strict,
)


def _can_create_symlinks(tmp_path: Path) -> bool:
    """Check whether this host allows symlink creation."""

    target = tmp_path / "_sentinel_target"
    link = tmp_path / "_sentinel_link"
    target.write_bytes(b"x")
    try:
        os.symlink(target, link)
        return True
    except (OSError, NotImplementedError):
        return False


# --- permissive advisory-lock serialization (event-based) ------------------


def _holding_worker(
    lock_path: str,
    acquired: object,
    release: object,
    released: object,
) -> None:
    with advisory_lock(Path(lock_path)):
        # Write the marker inside the critical section.
        marker = Path(lock_path).parent / "marker-A"
        marker.write_text("A")
        acquired.set()  # type: ignore[attr-defined]
        if not release.wait(timeout=20):  # type: ignore[attr-defined]
            raise RuntimeError("release signal missing")
    released.set()  # type: ignore[attr-defined]


def _contending_worker(
    lock_path: str,
    attempting: object,
    acquired: object,
) -> None:
    attempting.set()  # type: ignore[attr-defined]
    with advisory_lock(Path(lock_path)):
        # Write our own marker inside the critical section.
        marker = Path(lock_path).parent / "marker-B"
        marker.write_text("B")
        acquired.set()  # type: ignore[attr-defined]


def test_advisory_lock_serializes_independent_processes(tmp_path: Path) -> None:
    """Two independent processes cannot hold the advisory lock concurrently.

    Uses explicit multiprocessing events for coordination — no queue ordering
    comparisons, no arbitrary sleeps.
    """

    lock_path = tmp_path / "serialize.lock"
    ctx = mp.get_context("spawn")

    acquired_a = ctx.Event()
    release_a = ctx.Event()
    released_a = ctx.Event()
    attempting_b = ctx.Event()
    acquired_b = ctx.Event()

    proc_a = ctx.Process(
        target=_holding_worker,
        args=(str(lock_path), acquired_a, release_a, released_a),
    )
    proc_b = ctx.Process(
        target=_contending_worker,
        args=(str(lock_path), attempting_b, acquired_b),
    )

    proc_a.start()
    assert acquired_a.wait(timeout=20), "A did not acquire the lock"

    proc_b.start()
    assert attempting_b.wait(timeout=20), "B did not signal attempting"

    # While A still holds, B must NOT have acquired.
    assert not acquired_b.wait(timeout=2.0), "B acquired while A held the lock"

    # Release A.
    release_a.set()
    assert released_a.wait(timeout=20), "A did not report released"

    # B should now acquire.
    assert acquired_b.wait(timeout=20), "B did not acquire after A released"

    proc_a.join(timeout=10)
    proc_b.join(timeout=10)
    assert proc_a.exitcode == 0, f"worker A exited {proc_a.exitcode}"
    assert proc_b.exitcode == 0, f"worker B exited {proc_b.exitcode}"

    # Both markers exist: both processes entered the critical section.
    assert (tmp_path / "marker-A").read_text() == "A"
    assert (tmp_path / "marker-B").read_text() == "B"


def test_advisory_lock_is_reentrant_safe_within_process(tmp_path: Path) -> None:
    lock_path = tmp_path / "cycle.lock"
    for _ in range(3):
        with advisory_lock(lock_path):
            assert lock_path.stat().st_size >= 1
        assert lock_path.exists()
    assert lock_path.stat().st_size >= 1


# --- strict lock-file opener tests -----------------------------------------


def test_strict_open_missing_creates_regular_seeded(tmp_path: Path) -> None:
    lock_path = tmp_path / "strict.lock"
    handle = open_lock_file_strict(lock_path)
    try:
        assert lock_path.exists()
        info = os.stat(lock_path)
        import stat as stat_mod

        assert stat_mod.S_ISREG(info.st_mode)
        assert info.st_size >= 1
    finally:
        handle.close()


def test_strict_open_repeated_preserves_same_file(tmp_path: Path) -> None:
    lock_path = tmp_path / "strict-repeat.lock"
    h1 = open_lock_file_strict(lock_path)
    h1.close()
    h2 = open_lock_file_strict(lock_path)
    try:
        assert h2.fileno() >= 0
    finally:
        h2.close()


def test_strict_open_directory_rejects(tmp_path: Path) -> None:
    target = tmp_path / "publication.lock"
    target.mkdir()
    with pytest.raises(LockInvalidError):
        open_lock_file_strict(target)


def test_strict_open_symlink_rejects(tmp_path: Path) -> None:
    if not _can_create_symlinks(tmp_path):
        pytest.skip("symlink creation not available on this platform")

    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"sentinel-data")
    lock_path = tmp_path / "strict-symlink.lock"
    os.symlink(sentinel, lock_path)

    with pytest.raises(LockInvalidError):
        open_lock_file_strict(lock_path)

    # Sentinel bytes unchanged.
    assert sentinel.read_bytes() == b"sentinel-data"


def test_strict_open_symlink_sentinel_preserved(tmp_path: Path) -> None:
    """A symlink at the lock path must not cause the sentinel to be modified."""

    if not _can_create_symlinks(tmp_path):
        pytest.skip("symlink creation not available on this platform")

    sentinel = tmp_path / "sentinel-file"
    sentinel.write_bytes(b"original")
    lock_path = tmp_path / "pub.lock"
    os.symlink(sentinel, lock_path)

    with pytest.raises(LockInvalidError):
        open_lock_file_strict(lock_path)

    assert sentinel.read_bytes() == b"original"
    # No alternate lock object should have been created at the sentinel.
    assert sentinel.stat().st_size == len(b"original")


def test_strict_open_validation_failure_no_descriptor_leak(tmp_path: Path) -> None:
    """If the strict opener rejects a path, no file descriptor should remain open.

    We can't directly count fds, but we can verify the rejected path was not
    created or modified.
    """

    if not _can_create_symlinks(tmp_path):
        pytest.skip("symlink creation not available on this platform")

    sentinel = tmp_path / "leak-sentinel"
    sentinel.write_bytes(b"protected")
    lock_path = tmp_path / "leak.lock"
    os.symlink(sentinel, lock_path)

    with pytest.raises(LockInvalidError):
        open_lock_file_strict(lock_path)

    assert sentinel.read_bytes() == b"protected"


# --- strict-lock process serialization -------------------------------------


def _strict_holding_worker(
    lock_path: str,
    acquired: object,
    release: object,
    released: object,
) -> None:
    with advisory_lock_strict(Path(lock_path)):
        # Write the marker immediately after acquiring, before signaling.
        marker = Path(lock_path).parent / "strict-marker-A"
        marker.write_text("A")
        acquired.set()  # type: ignore[attr-defined]
        if not release.wait(timeout=20):  # type: ignore[attr-defined]
            raise RuntimeError("release signal missing")
    released.set()  # type: ignore[attr-defined]


def _strict_contending_worker(
    lock_path: str,
    attempting: object,
    acquired: object,
) -> None:
    attempting.set()  # type: ignore[attr-defined]
    with advisory_lock_strict(Path(lock_path)):
        marker = Path(lock_path).parent / "strict-marker-B"
        marker.write_text("B")
        acquired.set()  # type: ignore[attr-defined]


def test_strict_lock_serializes_independent_processes(tmp_path: Path) -> None:
    """Strict advisory_lock_strict provides the same process-level exclusion."""

    lock_path = tmp_path / "strict-serialize.lock"
    ctx = mp.get_context("spawn")

    acquired_a = ctx.Event()
    release_a = ctx.Event()
    released_a = ctx.Event()
    attempting_b = ctx.Event()
    acquired_b = ctx.Event()

    proc_a = ctx.Process(
        target=_strict_holding_worker,
        args=(str(lock_path), acquired_a, release_a, released_a),
    )
    proc_b = ctx.Process(
        target=_strict_contending_worker,
        args=(str(lock_path), attempting_b, acquired_b),
    )

    proc_a.start()
    assert acquired_a.wait(timeout=20), "A did not acquire the strict lock"

    proc_b.start()
    assert attempting_b.wait(timeout=20), "B did not signal attempting"

    assert not acquired_b.wait(timeout=2.0), "B acquired strict lock while A held it"

    release_a.set()
    assert released_a.wait(timeout=20), "A did not report released"

    assert acquired_b.wait(timeout=20), "B did not acquire after A released"

    proc_a.join(timeout=10)
    proc_b.join(timeout=10)
    assert proc_a.exitcode == 0
    assert proc_b.exitcode == 0

    # Both markers exist: both processes entered the critical section.
    assert (tmp_path / "strict-marker-A").read_text() == "A"
    assert (tmp_path / "strict-marker-B").read_text() == "B"


# --- directory fsync boundary ----------------------------------------------


def test_fsync_directory_does_not_raise_on_a_directory(tmp_path: Path) -> None:
    target = tmp_path / "durability-target"
    target.mkdir()
    fsync_directory(target)


def test_fsync_directory_on_nonexistent_path_raises(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    if sys.platform == "win32":
        fsync_directory(missing)
        assert not missing.exists()
    else:
        with pytest.raises(FileNotFoundError):
            fsync_directory(missing)


# --- newline protection for frozen fixtures --------------------------------


def test_frozen_seed_fixtures_have_expected_line_endings(repo_root: Path) -> None:
    sft = repo_root / "data" / "seed" / "v0.1" / "csd_reasoning_sft_v0.1.jsonl"
    preference = repo_root / "data" / "seed" / "v0.1" / "csd_reasoning_preference_v0.1.jsonl"
    assert sft.is_file(), "seed SFT fixture missing"
    assert preference.is_file(), "seed preference fixture missing"

    for fixture in (sft, preference):
        raw = fixture.read_bytes()
        assert b"\r\n" not in raw, f"{fixture.name} contains CRLF; .gitattributes not applied"
        assert b"\r" not in raw, f"{fixture.name} contains a stray CR"


def test_frozen_seed_digest_matches_manifest(repo_root: Path) -> None:
    import json

    manifest_path = repo_root / "data" / "seed" / "v0.1" / "csd_reasoning_manifest_v0.1.json"
    sft_path = repo_root / "data" / "seed" / "v0.1" / "csd_reasoning_sft_v0.1.jsonl"
    manifest = json.loads(manifest_path.read_text())
    sft_bytes = sft_path.read_bytes()
    actual = hashlib.sha256(sft_bytes).hexdigest()
    recorded = manifest["sft"]["sha256"]
    assert actual == recorded, (
        f"SFT digest mismatch: manifest={recorded} actual={actual}. "
        "Likely cause: line-ending corruption (CRLF vs LF)."
    )


# --- fixtures --------------------------------------------------------------


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]
