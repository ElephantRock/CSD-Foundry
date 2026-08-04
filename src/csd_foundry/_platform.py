"""Cross-platform file locking and directory durability primitives.

The governed registries and publication substrate require exclusive file
locking and directory fsync to preserve the append-only / atomic-completion
invariants (Charter §4.2, §4.4). POSIX provides ``fcntl.flock`` and directory
file descriptors that can be ``fsync``-ed; Windows provides neither directly.

This module dispatches to the native primitive on each platform:

* POSIX (Linux / macOS): ``fcntl.flock`` for locking, and ``os.open`` on the
  directory followed by ``os.fsync`` for directory durability.
* Windows: ``msvcrt.locking`` for exclusive byte-range locking on the lock
  file. Directory fsync has no Windows equivalent: directories cannot be
  opened as file descriptors, and ``os.sync`` is unavailable. Atomicity and
  durability rely on NTFS journaling plus the stores' use of ``os.replace``;
  ``fsync_directory`` is therefore a no-op on Windows.

Locking semantics differ across platforms in ways that do not affect this
codebase: both implementations provide process-wide exclusive advisory
locking on the lock file, which is sufficient for single-writer registry
mutators. The lock file is opened in binary append+read mode so it is
created on first use.

Strict opener (:func:`open_lock_file_strict`) provides acquisition-time
validation against cooperating store operators:

    lstat path
    reject symlink/non-regular shape
    atomically create a missing regular file or open an existing path
    without truncation; subsequent path-shape and identity checks must
    succeed before the descriptor is seeded or locked
    fstat opened descriptor
    lstat path again
    require same regular-file identity
    seed only after validation

The opener does not seed or lock through a symlink or replacement detected
during acquisition. A noncooperating actor replacing directory entries after
validation is outside the cooperative single-host claim.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import IO

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

_LOCK_FILE_MODE = 0o644


def _open_lock_file(lock_path: Path) -> IO[bytes]:
    """Open (creating if necessary) the lock file used for advisory locking.

    The file is opened ``a+b`` and ensured to contain at least one byte. This
    matters on Windows: ``msvcrt.locking`` locks a byte range that must exist
    in the file, so a zero-length lock file makes the one-byte lock range
    undefined. POSIX ``fcntl.flock`` is indifferent to file length.
    """

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # Intentionally not a `with`: the handle is returned to the caller
    # (advisory_lock) which owns its closure.
    handle = open(lock_path, "a+b", _LOCK_FILE_MODE)  # noqa: SIM115
    if lock_path.stat().st_size == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    return handle


def lock_file(handle: IO[bytes]) -> None:
    """Acquire an exclusive advisory lock on an already-open file handle."""

    fileno = handle.fileno()
    if sys.platform == "win32":
        os.lseek(fileno, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fileno, msvcrt.LK_LOCK, 1)
        except OSError as exc:
            raise OSError(f"failed to acquire file lock: {exc}") from exc
    else:
        fcntl.flock(fileno, fcntl.LOCK_EX)


def unlock_file(handle: IO[bytes]) -> None:
    """Release a lock previously acquired by :func:`lock_file`.

    Errors on release are suppressed: a closing handle or an already-released
    lock must not mask the original operation's outcome.
    """

    fileno = handle.fileno()
    try:
        if sys.platform == "win32":
            try:
                os.lseek(fileno, 0, os.SEEK_SET)
                msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        else:
            fcntl.flock(fileno, fcntl.LOCK_UN)
    except OSError:
        pass


@contextmanager
def advisory_lock(lock_path: Path) -> Iterator[IO[bytes]]:
    """Context manager wrapping an exclusive advisory lock on ``lock_path``.

    Yields the underlying open binary file handle so callers may inspect or
    truncate it; most callers ignore the yield value. The file is closed on
    exit.
    """

    handle = _open_lock_file(lock_path)
    try:
        lock_file(handle)
        try:
            yield handle
        finally:
            unlock_file(handle)
    finally:
        handle.close()


class LockInvalidError(OSError):
    """Raised by :func:`open_lock_file_strict` when the lock path is not a
    regular file (e.g. it is a symlink or a directory).

    This is a distinct ``OSError`` subclass so the strict opener's caller can
    separate "the lock path itself is malformed" (which the caller normalizes
    to ``ASSUMPTION_POLICY_STORE_LOCK_INVALID``) from "the lock path is a valid
    file but acquiring the lock failed" (which stays
    ``ASSUMPTION_POLICY_STORE_LOCK_FAILED``).
    """


class LockInitializationError(OSError):
    """Raised by :func:`open_lock_file_strict` when a validated lock-file
    descriptor was acquired but the handle initialization failed (``os.fdopen``
    or the seed write/flush/fsync raised).

    This is a distinct ``OSError`` subclass so the strict opener's caller can
    separate "the validated descriptor could not be turned into a usable handle
    or seeded" (which the caller normalizes to
    ``ASSUMPTION_POLICY_STORE_LOCK_FAILED`` -- the lock path is a valid regular
    file, but a usable lock could not be established) from "the lock path itself
    is malformed" (``LockInvalidError``, normalized to ``LOCK_INVALID``) and
    from a body-time ``OSError`` (operation failure, never mislabeled).
    """


def _finish_lock_file_open(fd: int, *, opened_size: int) -> IO[bytes]:
    """Turn a validated raw lock-file descriptor into a seeded binary handle.

    Takes ownership of ``fd``: on success the returned handle owns the
    descriptor, and the caller MUST NOT close ``fd`` independently. On failure
    the descriptor is always closed here (never leaked), and the failure is
    re-raised as :class:`LockInitializationError`:

    * if ``os.fdopen`` fails, the raw ``fd`` is closed before re-raising;
    * if ``os.fdopen`` succeeds but the seed (``write`` / ``flush`` /
      ``os.fsync``) fails, the handle is closed (which closes the descriptor)
      before re-raising.

    The seed is written only when the opened descriptor reported a zero size,
    matching the original permissive opener's contract that the lock file
    contains at least one byte (required by ``msvcrt.locking`` on Windows).
    """

    try:
        handle = os.fdopen(fd, "a+b")  # noqa: SIM115
    except Exception as exc:
        # fdopen failed: the raw descriptor is still ours to close. Closing it
        # here means the caller never has to.
        with suppress(OSError):
            os.close(fd)
        raise LockInitializationError("lock file handle could not be opened") from exc
    if opened_size == 0:
        try:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
        except Exception as exc:
            # The seed failed: the handle (and thus the descriptor) is ours, so
            # close it before re-raising so no descriptor is leaked.
            with suppress(OSError):
                handle.close()
            raise LockInitializationError("lock file could not be seeded") from exc
    return handle


def _open_windows_lock_file_strict(lock_path: Path) -> IO[bytes]:
    """Windows strict lock-file opener with cooperative acquisition-time validation.

    Algorithm (seven cooperative validation steps):
      1. lstat the path; reject an observed symlink or non-regular shape.
      2. Atomically create a missing regular file or open an existing path
         without truncation; subsequent path-shape and identity checks must
         succeed before the descriptor is seeded or locked.
      3. fstat the opened descriptor and require a regular file. A symlink to
         a regular file may also produce a regular descriptor; the second lstat
         and descriptor/path identity comparison detect the observed symlink or
         replacement before seeding and locking.
      4. lstat the path again; reject an observed symlink or non-regular shape.
      5. Require the descriptor and path to identify the same regular file.
      6. Seed only after all checks succeed (when the opened descriptor
         reported a zero size).
      7. Return the seeded handle; the caller owns its lifetime.
    """

    binary = getattr(os, "O_BINARY", 0)
    append = getattr(os, "O_APPEND", 0)
    fd: int | None = None

    while True:
        try:
            before = os.lstat(lock_path)
        except FileNotFoundError:
            try:
                fd = os.open(
                    lock_path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | append | binary,
                    _LOCK_FILE_MODE,
                )
            except FileExistsError:
                continue
            break

        if stat.S_ISLNK(before.st_mode):
            raise LockInvalidError("lock path is a symlink")
        if not stat.S_ISREG(before.st_mode):
            raise LockInvalidError("lock path is not a regular file")

        try:
            fd = os.open(lock_path, os.O_RDWR | append | binary)
        except OSError as exc:
            raise LockInvalidError("lock path could not be opened") from exc
        break

    assert fd is not None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise LockInvalidError("opened lock object is not regular")
        after = os.lstat(lock_path)
        if stat.S_ISLNK(after.st_mode):
            raise LockInvalidError("lock path became a symlink")
        if not stat.S_ISREG(after.st_mode):
            raise LockInvalidError("lock path became non-regular")
        if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
            raise LockInvalidError("lock path changed during acquisition")
    except Exception:
        os.close(fd)
        raise

    # The descriptor is validated; transfer ownership to the helper. The helper
    # closes the descriptor (directly or via the handle) on any failure and
    # re-raises as LockInitializationError. On success the returned handle owns
    # the descriptor and the caller MUST NOT close ``fd`` independently.
    return _finish_lock_file_open(fd, opened_size=opened.st_size)


def _open_posix_lock_file_strict(lock_path: Path) -> IO[bytes]:
    """POSIX strict lock-file opener using O_NOFOLLOW + descriptor validation."""

    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    flags |= no_follow
    try:
        fd = os.open(lock_path, flags, _LOCK_FILE_MODE)
    except OSError as exc:
        raise LockInvalidError("lock path could not be opened") from exc

    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise LockInvalidError("opened lock object is not regular")
    except Exception:
        os.close(fd)
        raise

    # The descriptor is validated; transfer ownership to the helper. The helper
    # closes the descriptor (directly or via the handle) on any failure and
    # re-raises as LockInitializationError. On success the returned handle owns
    # the descriptor and the caller MUST NOT close ``fd`` independently.
    return _finish_lock_file_open(fd, opened_size=opened.st_size)


def open_lock_file_strict(lock_path: Path) -> IO[bytes]:
    """Open (creating if necessary) the lock file, refusing symlinks.

    This is the strict variant of :func:`_open_lock_file` used by the
    assumption-policy publisher.

    * **POSIX:** ``os.open`` with ``O_NOFOLLOW`` rejects symlinks at the kernel
      level. After opening, ``fstat`` on the descriptor confirms a regular
      file. Descriptor-based size check avoids path-based ``stat`` races.
    * **Windows:** No ``O_NOFOLLOW`` equivalent exists. The opener performs
      acquisition-time validation: ``lstat`` the path (rejects symlinks and
      non-regular shapes), open without truncation, ``fstat`` the descriptor
      (confirms regular), ``lstat`` again (detects concurrent replacement),
      and verify descriptor/path identity match (``st_dev`` + ``st_ino``).

    The strict opener never seeds or locks through a symlink detected during
    acquisition. A noncooperating actor replacing directory entries after
    validation is outside the cooperative single-host claim.

    The caller owns the returned handle's lifetime.
    """

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        return _open_windows_lock_file_strict(lock_path)
    return _open_posix_lock_file_strict(lock_path)


@contextmanager
def advisory_lock_strict(lock_path: Path) -> Iterator[IO[bytes]]:
    """Strict variant of :func:`advisory_lock` that refuses lock-path symlinks.

    Identical to :func:`advisory_lock` except it opens the lock file via
    :func:`open_lock_file_strict`. A symlink (or directory, or other non-regular
    shape) at ``lock_path`` raises :class:`LockInvalidError` (an ``OSError``
    subclass) during ``__enter__``, before any lock is acquired.

    The existing :func:`advisory_lock` is intentionally left untouched: the
    temporal, admission, and registry stores rely on the permissive opener and
    must not change behavior.
    """

    handle = open_lock_file_strict(lock_path)
    try:
        lock_file(handle)
        try:
            yield handle
        finally:
            unlock_file(handle)
    finally:
        handle.close()


def fsync_directory(path: Path) -> None:
    """Best-effort durable flush of ``path``'s directory entry.

    On POSIX this opens the directory read-only and ``fsync``-s the resulting
    descriptor, which durably persists directory mutations (creation, rename,
    deletion) on the parent. On Windows this is a no-op: directories cannot be
    opened as file descriptors, ``os.sync`` is unavailable, and durability
    relies on NTFS journaling plus the callers' use of ``os.replace``.
    """

    if sys.platform == "win32":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
