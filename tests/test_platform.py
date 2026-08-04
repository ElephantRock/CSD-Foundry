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
    LockInitializationError,
    LockInvalidError,
    _open_posix_lock_file_strict,
    _open_windows_lock_file_strict,
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
    try:
        first_fd = h1.fileno()
        first_handle_stat = os.fstat(first_fd)
        first_path_stat = os.lstat(lock_path)
        first_bytes = lock_path.read_bytes()
    finally:
        h1.close()
    # Capture the on-disk identity after the first handle is closed so the
    # second open can be compared against it via st_dev/st_ino (the descriptor
    # identity and the path identity must agree, and both must agree with the
    # first-open identity).
    first_disk_stat = os.lstat(lock_path)

    h2 = open_lock_file_strict(lock_path)
    try:
        second_fd = h2.fileno()
        second_handle_stat = os.fstat(second_fd)
        second_path_stat = os.lstat(lock_path)
        # Descriptor identity matches path identity for the second open.
        assert (second_handle_stat.st_dev, second_handle_stat.st_ino) == (
            second_path_stat.st_dev,
            second_path_stat.st_ino,
        )
        # Second-open identity matches first-open identity (same file, not a
        # freshly created replacement).
        assert (second_handle_stat.st_dev, second_handle_stat.st_ino) == (
            first_handle_stat.st_dev,
            first_handle_stat.st_ino,
        )
        assert (second_path_stat.st_dev, second_path_stat.st_ino) == (
            first_path_stat.st_dev,
            first_path_stat.st_ino,
        )
        assert (second_path_stat.st_dev, second_path_stat.st_ino) == (
            first_disk_stat.st_dev,
            first_disk_stat.st_ino,
        )
        # The file remains a regular file.
        import stat as stat_mod

        assert stat_mod.S_ISREG(second_handle_stat.st_mode)
        assert stat_mod.S_ISREG(second_path_stat.st_mode)
        # Bytes unchanged: the seed was not appended a second time (the file
        # already held the one-byte seed from the first open, so the second
        # open's size check skipped re-seeding).
        assert lock_path.read_bytes() == first_bytes
        assert second_handle_stat.st_size == first_handle_stat.st_size
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


# --- direct seed-failure ownership tests ------------------------------------
#
# The strict openers transfer descriptor ownership to ``_finish_lock_file_open``,
# which must close the descriptor (directly via ``os.close`` on fdopen failure,
# or indirectly via ``handle.close()`` on seed failure) so no descriptor is
# leaked. Because the seed path is only reached when the opened descriptor
# reports a zero size, each test opens a missing path (which is created empty)
# and then injects the failure into the relevant step via monkeypatching. The
# descriptor having been closed is asserted by ``os.fstat(fd)`` raising
# ``OSError`` (EBADF on a recycled/closed descriptor).


def _create_empty_lock_then_get_fd_for_seed_failure(tmp_path: Path) -> int:
    """Open a fresh missing lock path under an os.open that captures the fd.

    Returns the captured fd WITHOUT closing it, so a seed-failure test can
    assert it was closed by the helper. The real ``os.open`` is restored by the
    caller's monkeypatch teardown.
    """

    captured: list[int] = []

    real_open = os.open

    def capturing_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        fd = real_open(path, flags, *args, **kwargs)
        captured.append(fd)
        return fd

    # Patch os.open only long enough to capture the fd, then restore it before
    # the helper runs so the helper's own calls (none in the seed path) are
    # unaffected. The captured fd is the one the opener hands to the helper.
    import csd_foundry._platform as plat

    lock_path = tmp_path / "seed-fail.lock"
    plat.os.open = capturing_open  # type: ignore[attr-defined]
    try:
        with pytest.raises(LockInitializationError):
            open_lock_file_strict(lock_path)
    finally:
        plat.os.open = real_open  # type: ignore[attr-defined]
    assert len(captured) == 1, f"expected exactly one os.open fd, got {captured}"
    return captured[0]


@pytest.mark.parametrize(
    "fail_step",
    ["write", "flush", "fsync"],
)
def test_strict_open_seed_failure_closes_descriptor(tmp_path: Path, fail_step: str) -> None:
    """A seed failure (write/flush/fsync) raises LockInitializationError and the
    underlying descriptor is closed (no leak).

    The seed is reached only for a freshly-created (zero-size) lock file, so
    each parameter run creates a missing lock path and injects the failure into
    the named seed step. ``os.fstat(fd)`` must then raise ``OSError`` (EBADF),
    proving the descriptor was closed by the helper.
    """

    import csd_foundry._platform as plat

    real_fdopen = os.fdopen
    real_fsync = os.fsync

    fd_holder: dict[str, int | None] = {"fd": None}

    def tracking_fdopen(fd, *args, **kwargs):  # type: ignore[no-untyped-def]
        handle = real_fdopen(fd, *args, **kwargs)
        fd_holder["fd"] = fd
        real_write = handle.write
        real_flush = handle.flush

        def failing_write(data):  # type: ignore[no-untyped-def]
            if fail_step == "write":
                raise OSError("injected write failure")
            return real_write(data)

        def failing_flush():  # type: ignore[no-untyped-def]
            if fail_step == "flush":
                raise OSError("injected flush failure")
            return real_flush()

        handle.write = failing_write  # type: ignore[method-assign]
        handle.flush = failing_flush  # type: ignore[method-assign]
        return handle

    def failing_fsync(fd):  # type: ignore[no-untyped-def]
        if fail_step == "fsync":
            raise OSError("injected fsync failure")
        return real_fsync(fd)

    plat.os.fdopen = tracking_fdopen  # type: ignore[attr-defined]
    plat.os.fsync = failing_fsync  # type: ignore[attr-defined]
    try:
        fd = _create_empty_lock_then_get_fd_for_seed_failure(tmp_path)
    finally:
        plat.os.fdopen = real_fdopen  # type: ignore[attr-defined]
        plat.os.fsync = real_fsync  # type: ignore[attr-defined]

    # The descriptor must be closed: fstat raises OSError (EBADF on POSIX,
    # EBADF/Invalid handle on Windows). The helper closed it via handle.close()
    # (write/flush/fsync all reach the post-fdopen path).
    with pytest.raises(OSError):
        os.fstat(fd)
    # The captured fd matches the one the helper closed (defensive: ensures the
    # tracking fdopen actually ran for the seed path).
    assert fd_holder["fd"] == fd


def test_strict_open_fdopen_failure_closes_raw_fd(tmp_path: Path) -> None:
    """If ``os.fdopen`` fails, the raw descriptor is closed (no leak) and
    LockInitializationError is raised.

    fdopen failure is a distinct ownership branch from seed failure: the helper
    has not yet produced a handle, so it must close the raw ``fd`` itself.
    """

    import csd_foundry._platform as plat

    real_open = os.open
    real_fdopen = os.fdopen
    captured: list[int] = []

    def capturing_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        fd = real_open(path, flags, *args, **kwargs)
        captured.append(fd)
        return fd

    def failing_fdopen(fd, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError("injected fdopen failure")

    plat.os.open = capturing_open  # type: ignore[attr-defined]
    plat.os.fdopen = failing_fdopen  # type: ignore[attr-defined]
    lock_path = tmp_path / "fdopen-fail.lock"
    try:
        with pytest.raises(LockInitializationError):
            open_lock_file_strict(lock_path)
    finally:
        plat.os.open = real_open  # type: ignore[attr-defined]
        plat.os.fdopen = real_fdopen  # type: ignore[attr-defined]

    assert len(captured) == 1, f"expected exactly one os.open fd, got {captured}"
    fd = captured[0]
    # The raw descriptor was closed by the helper (fdopen failed, so no handle
    # existed to close -- the helper closed the raw fd directly).
    with pytest.raises(OSError):
        os.fstat(fd)


# --- privilege-independent Windows/POSIX validation tests -------------------
#
# The Windows strict opener's seven-step validation depends on lstat / open /
# fstat shapes that require symlink-creation privilege to produce for real on
# Windows. These tests monkeypatch ``os.lstat``, ``os.open``, and ``os.fstat``
# to synthesize each rejection branch on every platform (POSIX included), so
# the validation logic is covered regardless of host privileges. They target
# ``_open_windows_lock_file_strict`` (and the POSIX opener) directly.


def _make_stat_result(*, mode: int, dev: int = 1, ino: int = 1, size: int = 0) -> os.stat_result:
    """Build an ``os.stat_result`` with the given mode/identity/size."""

    return os.stat_result((mode, ino, dev, 1, 0, 0, size, 0, 0, 0))


_REG_MODE = 0o100644  # regular file, rw-r--r--
_LNK_MODE = 0o120777  # symlink
_DIR_MODE = 0o040755  # directory


def test_windows_strict_open_initial_lstat_symlink_rejects(monkeypatch, tmp_path: Path) -> None:
    """Step 1: an initial lstat reporting a symlink is rejected."""

    lock_path = tmp_path / "win.lock"
    monkeypatch.setattr(os, "lstat", lambda p: _make_stat_result(mode=_LNK_MODE))
    with pytest.raises(LockInvalidError):
        _open_windows_lock_file_strict(lock_path)


def test_windows_strict_open_initial_lstat_directory_rejects(monkeypatch, tmp_path: Path) -> None:
    """Step 1: an initial lstat reporting a directory is rejected."""

    lock_path = tmp_path / "win.lock"
    monkeypatch.setattr(os, "lstat", lambda p: _make_stat_result(mode=_DIR_MODE))
    with pytest.raises(LockInvalidError):
        _open_windows_lock_file_strict(lock_path)


def test_windows_strict_open_second_lstat_symlink_rejects(monkeypatch, tmp_path: Path) -> None:
    """Step 4: a second lstat reporting a symlink (after a regular first lstat
    and a regular fstat) is rejected."""

    lock_path = tmp_path / "win.lock"
    calls = {"n": 0}

    def lstat(p):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        # First lstat: regular. Second lstat: symlink (concurrent replacement).
        return _make_stat_result(mode=_REG_MODE if calls["n"] == 1 else _LNK_MODE)

    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        # Return a real fd to a real temp file so fstat/fdopen have something
        # valid to operate on; the validation failure happens at step 4 (second
        # lstat), before fdopen.
        return real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "fstat", lambda fd: _make_stat_result(mode=_REG_MODE, size=1))
    try:
        with pytest.raises(LockInvalidError):
            _open_windows_lock_file_strict(lock_path)
    finally:
        # Clean up the real temp file we used to back the fake fd.
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()


def test_windows_strict_open_second_lstat_nonregular_rejects(monkeypatch, tmp_path: Path) -> None:
    """Step 4: a second lstat reporting a non-regular, non-symlink shape (e.g.
    a directory) is rejected."""

    lock_path = tmp_path / "win.lock"
    calls = {"n": 0}

    def lstat(p):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return _make_stat_result(mode=_REG_MODE if calls["n"] == 1 else _DIR_MODE)

    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        return real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "fstat", lambda fd: _make_stat_result(mode=_REG_MODE, size=1))
    try:
        with pytest.raises(LockInvalidError):
            _open_windows_lock_file_strict(lock_path)
    finally:
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()


def test_windows_strict_open_identity_mismatch_rejects(monkeypatch, tmp_path: Path) -> None:
    """Step 5: the opened descriptor and the second-lstat path disagree on
    identity (st_dev/st_ino), indicating a replacement that swapped in a
    different file."""

    lock_path = tmp_path / "win.lock"
    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        return real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)

    monkeypatch.setattr(os, "lstat", lambda p: _make_stat_result(mode=_REG_MODE, dev=2, ino=9))
    monkeypatch.setattr(os, "open", fake_open)
    # fstat reports a DIFFERENT identity than the second lstat (dev=1, ino=1).
    monkeypatch.setattr(
        os, "fstat", lambda fd: _make_stat_result(mode=_REG_MODE, dev=1, ino=1, size=1)
    )
    try:
        with pytest.raises(LockInvalidError):
            _open_windows_lock_file_strict(lock_path)
    finally:
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()


def test_windows_strict_open_fstat_nonregular_rejects(monkeypatch, tmp_path: Path) -> None:
    """Step 3: fstat on the opened descriptor reporting a non-regular shape
    (e.g. a directory or a dereferenced symlink) is rejected."""

    lock_path = tmp_path / "win.lock"
    real_open = os.open

    def fake_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        return real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)

    monkeypatch.setattr(os, "lstat", lambda p: _make_stat_result(mode=_REG_MODE))
    monkeypatch.setattr(os, "open", fake_open)
    # fstat reports a directory (non-regular): the open call followed a symlink
    # into a directory, or the path was a directory all along.
    monkeypatch.setattr(os, "fstat", lambda fd: _make_stat_result(mode=_DIR_MODE))
    try:
        with pytest.raises(LockInvalidError):
            _open_windows_lock_file_strict(lock_path)
    finally:
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()


def test_windows_strict_open_seed_failure_closes_descriptor(monkeypatch, tmp_path: Path) -> None:
    """Step 6: a seed failure (write/flush/fsync) on a freshly-created
    (zero-size) lock file raises LockInitializationError and the descriptor is
    closed (no leak). All validation passes; only the seed fails."""

    lock_path = tmp_path / "win.lock"
    real_open = os.open
    real_fdopen = os.fdopen
    real_fstat = os.fstat
    real_fsync = os.fsync
    captured: list[int] = []

    def capturing_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        fd = real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)
        captured.append(fd)
        return fd

    def tracking_fdopen(fd, *args, **kwargs):  # type: ignore[no-untyped-def]
        handle = real_fdopen(fd, *args, **kwargs)

        def failing_write(data):  # type: ignore[no-untyped-def]
            raise OSError("injected write failure")

        handle.write = failing_write  # type: ignore[method-assign]
        return handle

    monkeypatch.setattr(os, "lstat", lambda p: _make_stat_result(mode=_REG_MODE))
    monkeypatch.setattr(os, "open", capturing_open)
    monkeypatch.setattr(os, "fstat", lambda fd: _make_stat_result(mode=_REG_MODE, size=0))
    monkeypatch.setattr(os, "fdopen", tracking_fdopen)
    try:
        with pytest.raises(LockInitializationError):
            _open_windows_lock_file_strict(lock_path)
    finally:
        monkeypatch.setattr(os, "open", real_open)
        monkeypatch.setattr(os, "fdopen", real_fdopen)
        monkeypatch.setattr(os, "fstat", real_fstat)
        monkeypatch.setattr(os, "fsync", real_fsync)
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()

    assert len(captured) == 1, f"expected exactly one os.open fd, got {captured}"
    # Descriptor closed by the helper (handle.close() on seed failure).
    with pytest.raises(OSError):
        os.fstat(captured[0])


def test_posix_strict_open_fstat_nonregular_rejects(monkeypatch, tmp_path: Path) -> None:
    """POSIX opener: fstat on the opened descriptor reporting a non-regular
    shape is rejected with LockInvalidError (the descriptor is closed)."""

    lock_path = tmp_path / "posix.lock"
    real_open = os.open
    real_fstat = os.fstat
    captured: list[int] = []

    def capturing_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        fd = real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)
        captured.append(fd)
        return fd

    monkeypatch.setattr(os, "open", capturing_open)
    # fstat reports a directory: non-regular.
    monkeypatch.setattr(os, "fstat", lambda fd: _make_stat_result(mode=_DIR_MODE))
    try:
        with pytest.raises(LockInvalidError):
            _open_posix_lock_file_strict(lock_path)
    finally:
        monkeypatch.setattr(os, "open", real_open)
        monkeypatch.setattr(os, "fstat", real_fstat)
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()

    assert len(captured) == 1, f"expected exactly one os.open fd, got {captured}"
    # Descriptor closed by the opener's validation-failure path.
    with pytest.raises(OSError):
        os.fstat(captured[0])


def test_posix_strict_open_seed_failure_closes_descriptor(monkeypatch, tmp_path: Path) -> None:
    """POSIX opener: a seed failure on a freshly-created (zero-size) lock file
    raises LockInitializationError and the descriptor is closed (no leak)."""

    lock_path = tmp_path / "posix.lock"
    real_open = os.open
    real_fdopen = os.fdopen
    real_fstat = os.fstat
    real_fsync = os.fsync
    captured: list[int] = []

    def capturing_open(path, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        fd = real_open(tmp_path / "_real_for_open", os.O_RDWR | os.O_CREAT, 0o644)
        captured.append(fd)
        return fd

    def tracking_fdopen(fd, *args, **kwargs):  # type: ignore[no-untyped-def]
        handle = real_fdopen(fd, *args, **kwargs)

        def failing_write(data):  # type: ignore[no-untyped-def]
            raise OSError("injected write failure")

        handle.write = failing_write  # type: ignore[method-assign]
        return handle

    monkeypatch.setattr(os, "open", capturing_open)
    monkeypatch.setattr(os, "fstat", lambda fd: _make_stat_result(mode=_REG_MODE, size=0))
    monkeypatch.setattr(os, "fdopen", tracking_fdopen)
    try:
        with pytest.raises(LockInitializationError):
            _open_posix_lock_file_strict(lock_path)
    finally:
        monkeypatch.setattr(os, "open", real_open)
        monkeypatch.setattr(os, "fdopen", real_fdopen)
        monkeypatch.setattr(os, "fstat", real_fstat)
        monkeypatch.setattr(os, "fsync", real_fsync)
        backing = tmp_path / "_real_for_open"
        if backing.exists():
            backing.unlink()

    assert len(captured) == 1, f"expected exactly one os.open fd, got {captured}"
    # Descriptor closed by the helper (handle.close() on seed failure).
    with pytest.raises(OSError):
        os.fstat(captured[0])


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
