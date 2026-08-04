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
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
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
        # msvcrt.locking locks `nbytes` starting at the current file position.
        # Seek to 0 so lock and unlock always target the same byte (byte 0),
        # regardless of prior reads/writes on this handle.
        os.lseek(fileno, 0, os.SEEK_SET)
        # LK_LOCK blocks (retrying) until the lock is held or the OS gives up;
        # LK_NBLCK would raise immediately. The byte range we lock is arbitrary
        # but must be consistent across lock/unlock and must exist in the file
        # (see _open_lock_file).
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
                # Seek back to byte 0 before releasing; msvcrt.locking unlocks
                # the range starting at the current file position, and lock_file
                # locks byte 0.
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


def open_lock_file_strict(lock_path: Path) -> IO[bytes]:
    """Open (creating if necessary) the lock file, refusing symlinks.

    This is the strict variant of :func:`_open_lock_file` used by the
    assumption-policy publisher. It guarantees the lock path is a regular file
    by the time a handle is returned, so a malicious or accidental symlink at
    ``publication.lock`` can never be followed into an attacker-controlled file
    or a directory.

    * **POSIX:** ``os.open`` with ``O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW``.
      ``O_NOFOLLOW`` causes the kernel to reject a symlink at ``lock_path``
      with ``ELOOP`` before any handle is handed out. On success the descriptor
      is wrapped in a Python file object.
    * **Windows:** ``msvcrt.locking`` has no ``O_NOFOLLOW`` equivalent, so the
      path is opened ``a+b`` (the existing, Windows-compatible approach) and
      then ``os.fstat`` is consulted: if the opened descriptor is not a regular
      file (``S_ISREG`` is false) -- which happens when ``lock_path`` is a
      directory or a symlink the runtime transparently dereferenced -- the
      handle is closed and ``LockInvalidError`` is raised.

    Like :func:`_open_lock_file`, the file is seeded with one byte on first
    use so the Windows byte-range lock is well-defined regardless of platform.

    The caller owns the returned handle's lifetime.
    """

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        # Intentionally not a `with`: the handle is returned to the caller.
        handle = open(lock_path, "a+b", _LOCK_FILE_MODE)  # noqa: SIM115
        try:
            info = os.fstat(handle.fileno())
        except OSError as exc:
            handle.close()
            raise LockInvalidError(f"lock path not statable: {exc}") from exc
        if not stat.S_ISREG(info.st_mode):
            # The opened descriptor is a directory or (if the runtime
            # dereferenced a symlink) anything other than a regular file.
            handle.close()
            raise LockInvalidError("lock path is not a regular file")
        if lock_path.stat().st_size == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
        return handle
    # POSIX: O_NOFOLLOW rejects a symlink at the path itself with ELOOP before
    # any file is opened or followed. A directory or other non-regular shape at
    # the path surfaces as a different errno. Every open() failure here is a
    # shape/open failure: the publisher normalizes it to LOCK_INVALID.
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    try:
        fd = os.open(lock_path, flags, _LOCK_FILE_MODE)
    except OSError as exc:
        raise LockInvalidError(f"lock path could not be opened: {exc}") from exc
    # Intentionally not a `with`: the handle is returned to the caller.
    handle = os.fdopen(fd, "a+b")  # noqa: SIM115
    if lock_path.stat().st_size == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    return handle


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
