"""
Single-instance guard and virtual environment enforcement.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


class InstanceLockError(RuntimeError):
    """Raised when another instance is already running."""


@dataclass(frozen=True)
class InstanceLock:
    """Holds the lock file handle to keep the lock alive."""

    handle: TextIO
    path: Path


def ensure_virtualenv() -> None:
    """Exit if the process is not running inside a virtual environment."""
    if os.environ.get("FILE_MANAGER_ALLOW_SYSTEM_PYTHON") == "1":
        return
    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    real_prefix = getattr(sys, "real_prefix", None)
    in_venv = sys.prefix != base_prefix or real_prefix is not None
    if not in_venv:
        message = (
            "ERROR: This app must run inside the .venv interpreter.\n"
            "Activate the venv or run: .\\.venv\\Scripts\\python.exe src\\main.py\n"
            "To override: set FILE_MANAGER_ALLOW_SYSTEM_PYTHON=1\n"
        )
        print(message, file=sys.stderr)
        raise SystemExit(2)


def _lock_file(handle: TextIO) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise InstanceLockError("Another instance is already running.") from exc
    else:
        import fcntl

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise InstanceLockError("Another instance is already running.") from exc


def _write_lock_info(handle: TextIO) -> None:
    handle.seek(0)
    handle.truncate()
    info = [
        f"pid={os.getpid()}",
        f"python={sys.executable}",
        f"argv={' '.join(sys.argv)}",
    ]
    handle.write("\n".join(info))
    handle.flush()


def acquire_instance_lock(lock_path: Path) -> InstanceLock:
    """Acquire a non-blocking instance lock or raise InstanceLockError."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        _lock_file(handle)
        _write_lock_info(handle)
    except Exception:
        handle.close()
        raise
    return InstanceLock(handle=handle, path=lock_path)
