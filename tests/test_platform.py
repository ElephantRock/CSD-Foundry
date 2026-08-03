"""Platform boundary tests for the shared locking and fsync helpers.

These tests exercise the cross-platform persistence primitives in
``csd_foundry._platform``:

* advisory-lock serialization across independent processes (not just threads),
  since the stores rely on process-wide exclusive locking for append-only
  compare-and-append correctness;
* the directory-fsync boundary contract (callable on POSIX, no-op on Windows,
  never raises on a directory);
* newline protection for frozen content-addressed fixtures (the ``.gitattributes``
  rule that prevents ``core.autocrlf`` from invalidating committed digests).

The durability claim is intentionally narrow: atomic publication and
restart-safe reconstruction are supported on both platforms; sudden-power-loss
durability is supported only on POSIX (where directory fsync exists) and is
not asserted here for Windows.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import queue as queue_module
import sys
import time
from pathlib import Path

import pytest

from csd_foundry._platform import advisory_lock, fsync_directory

# --- advisory-lock serialization -------------------------------------------


def _lock_worker(
    lock_path: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    payload: str,
    hold_seconds: float,
) -> None:
    """Worker that acquires the advisory lock and writes a marker file.

    Designed to be picklable for Windows ``spawn`` (module-level, simple args).
    Reports its phase through a multiprocessing queue so the parent can assert
    ordering without arbitrary sleeps. ``hold_seconds`` widens the contention
    window so cross-platform spawn latency cannot mask a serialization bug.
    """

    lock = Path(lock_path)
    result_queue.put(("WORKER_STARTED", payload))
    try:
        with advisory_lock(lock):
            result_queue.put(("LOCK_ACQUIRED", payload, os.getpid()))
            time.sleep(hold_seconds)
            marker = lock.parent / f"marker-{payload}"
            marker.write_bytes(payload.encode())
            result_queue.put(("MARKER_WRITTEN", payload))
    except Exception as exc:  # noqa: BLE001 - surface any failure to the parent
        result_queue.put(("WORKER_ERROR", payload, repr(exc)))


def test_advisory_lock_serializes_independent_processes(tmp_path: Path) -> None:
    """Two independent processes cannot hold the advisory lock concurrently.

    Process A acquires the lock, holds it, writes a marker, and releases.
    Process B attempts the same lock and must wait until A releases before it
    can enter the critical section and observe/write its own marker.

    Correctness is established by strict message ordering on a shared queue
    (bounded get-timeout), not by arbitrary sleeps: A's MARKER_WRITTEN (release)
    must be observed before B's LOCK_ACQUIRED.
    """

    lock_path = tmp_path / "serialize.lock"
    ctx = mp.get_context("spawn")
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]

    # A holds long enough that B's spawn latency cannot let it sneak in.
    proc_a = ctx.Process(
        target=_lock_worker,
        args=(str(lock_path), queue, "A", 1.0),
    )
    # B holds only briefly; it just needs to prove it got in after A released.
    proc_b = ctx.Process(
        target=_lock_worker,
        args=(str(lock_path), queue, "B", 0.1),
    )

    proc_a.start()

    # Wait for A to report it holds the lock.
    msg = queue.get(timeout=20)
    assert msg[0] == "WORKER_STARTED" and msg[1] == "A", msg
    msg = queue.get(timeout=20)
    assert msg[0] == "LOCK_ACQUIRED" and msg[1] == "A", msg

    # Start B while A still holds the lock. B must block on acquisition.
    proc_b.start()

    # Drain messages in arrival order. Collect them so we can assert the
    # relative ordering of A's release vs B's acquisition without racing.
    seen: list[tuple] = []
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline and len(seen) < 4:
        try:
            seen.append(queue.get(timeout=2.0))
        except queue_module.Empty:
            break

    proc_a.join(timeout=10)
    proc_b.join(timeout=10)
    assert proc_a.exitcode == 0, f"worker A exited {proc_a.exitcode}"
    assert proc_b.exitcode == 0, f"worker B exited {proc_b.exitcode}"

    # Index the messages by (event, payload) for ordering assertions.
    events = {(m[0], m[1]): idx for idx, m in enumerate(seen) if len(m) >= 2}

    # B must have reported started and acquired (eventually).
    assert ("WORKER_STARTED", "B") in events, f"B never started: {seen}"
    assert ("LOCK_ACQUIRED", "B") in events, f"B never acquired: {seen}"
    # A must have released (written its marker) before B acquired.
    assert ("MARKER_WRITTEN", "A") in events, f"A never released: {seen}"
    assert events[("MARKER_WRITTEN", "A")] < events[("LOCK_ACQUIRED", "B")], (
        f"serialization broken: B acquired before A released. messages={seen}"
    )

    # The protected shared result was not clobbered: both markers exist.
    assert (tmp_path / "marker-A").read_text() == "A"
    assert (tmp_path / "marker-B").read_text() == "B"


def test_advisory_lock_is_reentrant_safe_within_process(tmp_path: Path) -> None:
    """Within one process, sequential lock acquire/release cycles succeed.

    This complements the cross-process test: it verifies the lock file's
    ensure-one-byte initialization is idempotent across repeated acquisitions
    on an existing file (regression guard for the byte-0 vs EOF seek fix).
    """

    lock_path = tmp_path / "cycle.lock"
    for _ in range(3):
        with advisory_lock(lock_path):
            assert lock_path.stat().st_size >= 1
        # After release, the file persists with at least the seed byte.
        assert lock_path.exists()
    assert lock_path.stat().st_size >= 1


# --- directory fsync boundary ----------------------------------------------


def test_fsync_directory_does_not_raise_on_a_directory(tmp_path: Path) -> None:
    """``fsync_directory`` must be invocable on a directory on every platform.

    On POSIX this opens the directory and fsyncs it; on Windows it is a no-op.
    The supported contract is "callable without raising", not "guarantees
    power-loss durability" (the latter is POSIX-only and is not asserted here).
    """

    target = tmp_path / "durability-target"
    target.mkdir()
    # Must not raise.
    fsync_directory(target)


def test_fsync_directory_on_nonexistent_path_raises(tmp_path: Path) -> None:
    """On POSIX, fsync_directory opens the dir fd; a missing dir must surface.

    On Windows the function is a no-op and will not raise for a missing path
    (it returns before touching the filesystem). This test asserts the POSIX
    behavior conditionally so it documents both branches honestly.
    """

    missing = tmp_path / "does-not-exist"
    if sys.platform == "win32":
        # No-op path: does not raise, does not create.
        fsync_directory(missing)
        assert not missing.exists()
    else:
        with pytest.raises(FileNotFoundError):
            fsync_directory(missing)


# --- newline protection for frozen fixtures --------------------------------


def test_frozen_seed_fixtures_have_expected_line_endings(repo_root: Path) -> None:
    """Frozen content-addressed seed fixtures must be LF-only in the tree.

    This guards the ``.gitattributes`` rule: if ``core.autocrlf=true`` rewrites
    these files to CRLF on checkout, their SHA-256 digests diverge from the
    frozen manifest and every seed/execution-artifact test fails. The fix is
    the committed ``.gitattributes``, not rewriting expected digests.
    """

    sft = repo_root / "data" / "seed" / "v0.1" / "csd_reasoning_sft_v0.1.jsonl"
    preference = repo_root / "data" / "seed" / "v0.1" / "csd_reasoning_preference_v0.1.jsonl"
    assert sft.is_file(), "seed SFT fixture missing"
    assert preference.is_file(), "seed preference fixture missing"

    for fixture in (sft, preference):
        raw = fixture.read_bytes()
        assert b"\r\n" not in raw, f"{fixture.name} contains CRLF; .gitattributes not applied"
        assert b"\r" not in raw, f"{fixture.name} contains a stray CR"


def test_frozen_seed_digest_matches_manifest(repo_root: Path) -> None:
    """The seed manifest's recorded SFT digest must match the on-disk bytes.

    This is the direct invariant the newline fix protects: the manifest digest
    was computed over LF bytes, so CRLF corruption breaks it. Asserting here
    gives a focused, fast check independent of the full seed validator.
    """

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
    """Resolve the repository root from this test file's location."""

    return Path(__file__).resolve().parents[1]
