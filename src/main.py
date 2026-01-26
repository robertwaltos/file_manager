
"""
Main entry point for running the file management system.
"""

import os
import sys
from pathlib import Path

from orchestrator.main import main
from utils.instance_guard import InstanceLockError, acquire_instance_lock, ensure_virtualenv

if __name__ == "__main__":
    ensure_virtualenv()
    if os.environ.get("FILE_MANAGER_ALLOW_MULTI_INSTANCE") != "1":
        try:
            _lock = acquire_instance_lock(Path("data") / "file_manager.lock")
        except InstanceLockError as exc:
            message = (
                "ERROR: Another file_manager instance is already running.\n"
                "If this is a mistake, close the other process or set "
                "FILE_MANAGER_ALLOW_MULTI_INSTANCE=1 to override.\n"
            )
            print(message, file=sys.stderr)
            raise SystemExit(2) from exc
    main()
