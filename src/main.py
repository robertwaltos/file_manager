
"""
Main entry point for running the file management system.
"""

import faulthandler
import os
import sys
import traceback
import threading
from datetime import datetime
from pathlib import Path

from orchestrator.main import main
from utils.instance_guard import InstanceLockError, acquire_instance_lock, ensure_virtualenv


def _enable_crash_diagnostics() -> None:
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    crash_log = logs_dir / f"crash_traceback_{datetime.utcnow().strftime('%Y%m%d')}.log"
    crash_stream = crash_log.open("a", encoding="utf-8")
    faulthandler.enable(file=crash_stream, all_threads=True)

    def _hook(exc_type, exc, tb):
        with crash_log.open("a", encoding="utf-8") as handle:
            handle.write("\n")
            handle.write(datetime.utcnow().isoformat() + " Unhandled exception\n")
            traceback.print_exception(exc_type, exc, tb, file=handle)
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook
    if hasattr(threading, "excepthook"):
        def _thread_hook(args):
            _hook(args.exc_type, args.exc_value, args.exc_traceback)
        threading.excepthook = _thread_hook

if __name__ == "__main__":
    ensure_virtualenv()
    _enable_crash_diagnostics()
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
