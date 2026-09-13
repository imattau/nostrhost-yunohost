"""Native operation locking (Moulinette ``MoulinetteLock`` replacement).

Moulinette's lock was a PID-file poller under ``/var/run/moulinette_<ns>.lock``
that could race and required ``psutil`` process-tree checks to detect stale
locks.  This module keeps the same call contract -- ``acquire``/``release``,
context-manager support, an optional timeout -- but backs it with real
``flock(2)`` exclusive locks.  ``flock`` releases automatically when the
process dies, so stale-lock handling is handled by the kernel.

The lock *namespace* is the compatibility entry point Stage 2 needs
(``LockManager("yunohost", timeout=30)``), while ``LockManager`` also accepts
an ordered set of *resource* scopes so the executor (Stage 3+) can hold
resource-level locks instead of one global lock -- independent operations
then run concurrently when their resource sets do not overlap.
"""

from __future__ import annotations

import errno
import fcntl
import os
import time
from pathlib import Path
from typing import Any, Iterable

from .core import LockAcquireTimeout

DEFAULT_LOCK_DIR = "/var/run/nostrhost/locks"


class LockManager:
    """Acquire exclusive ``flock`` locks for a namespace and/or resources.

    Keyword arguments:
        - namespace -- Compatibility namespace (the historical global lock
            name, e.g. ``"yunohost"``).  When given without resources, the
            lock is a single file ``<namespace>.lock``.
        - resources -- Ordered resource scopes for fine-grained locking.
            Each becomes a ``<scope>.lock`` file; all are acquired in order.
        - timeout -- Seconds to wait before raising ``LockAcquireTimeout``.
            None (default) waits indefinitely.
        - interval -- Poll interval while waiting for a contended lock.
        - lock_dir -- Directory holding the lock files.
        - enable_lock -- When False, ``acquire``/context-manager entry is a
            no-op (used by the fork's ``enable_lock=False`` path).
    """

    def __init__(
        self,
        namespace: str | None = None,
        resources: Iterable[str] = (),
        timeout: float | None = None,
        interval: float = 0.5,
        lock_dir: str = DEFAULT_LOCK_DIR,
        enable_lock: bool = True,
    ) -> None:
        self.namespace = namespace
        self.resources = [str(r) for r in resources]
        self.timeout = timeout
        self.interval = interval
        self.lock_dir = lock_dir
        self.enable_lock = enable_lock
        self._handles: list[Any] = []
        self._locked = False

    def _lock_names(self) -> list[str]:
        if self.resources:
            return [f"{r}.lock" for r in self.resources]
        if self.namespace is not None:
            return [f"{self.namespace}.lock"]
        return []

    def acquire(self) -> None:
        """Acquire all locks in order, waiting up to ``timeout``."""
        if not self.enable_lock or self._locked:
            return
        names = self._lock_names()
        if not names:
            raise LockAcquireTimeout("no lock namespace or resources given", raw_msg=True)

        Path(self.lock_dir).mkdir(parents=True, exist_ok=True)
        start = time.time()
        acquired: list[Any] = []
        try:
            for name in names:
                path = Path(self.lock_dir) / name
                handle = path.open("a+")
                while True:
                    try:
                        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError as exc:
                        if exc.errno not in (errno.EACCES, errno.EAGAIN):
                            handle.close()
                            raise
                        if self.timeout is not None and (
                            time.time() - start
                        ) > self.timeout:
                            for acquired_handle in acquired:
                                fcntl.flock(acquired_handle, fcntl.LOCK_UN)
                                acquired_handle.close()
                            raise LockAcquireTimeout("instance_already_running")
                        time.sleep(self.interval)
                handle.seek(0)
                handle.truncate()
                handle.write(f"{os.getpid()}\n")
                handle.flush()
                acquired.append(handle)
        except Exception:
            for acquired_handle in acquired:
                try:
                    fcntl.flock(acquired_handle, fcntl.LOCK_UN)
                except OSError:
                    pass
                acquired_handle.close()
            raise
        self._handles = acquired
        self._locked = True

    def release(self) -> None:
        """Release all held locks."""
        if not self._locked:
            return
        for handle in self._handles:
            try:
                fcntl.flock(handle, fcntl.LOCK_UN)
            except OSError:
                pass
            handle.close()
        self._handles = []
        self._locked = False

    def __enter__(self) -> "LockManager":
        self.acquire()
        return self

    def __exit__(self, *args: object) -> None:
        self.release()

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup
        self.release()
