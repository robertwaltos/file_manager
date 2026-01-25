"""
Simple web dashboard backed by the state SQLite database.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse

from database import DatabaseManager


class DashboardServer:
    """Serve a lightweight status dashboard over HTTP."""

    def __init__(
        self,
        db_paths: dict,
        host: str = "127.0.0.1",
        port: int = 8765,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.db_paths = db_paths
        self.host = host
        self.port = port
        self.logger = logger or logging.getLogger("file_manager")
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the dashboard server in a background thread."""
        if self._server is not None:
            return
        handler = self._build_handler()
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.logger.info("Dashboard server running at http://%s:%s", self.host, self.port)

    def stop(self) -> None:
        """Stop the dashboard server."""
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _build_handler(self):
        db_paths = self.db_paths
        logger = self.logger

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    self._send_html(_dashboard_html())
                    return
                if parsed.path == "/api/status":
                    payload = _fetch_status(db_paths)
                    self._send_json(payload)
                    return
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

            def _send_html(self, content: str) -> None:
                encoded = content.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _send_json(self, payload: dict) -> None:
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, format: str, *args) -> None:
                logger.debug("Dashboard: " + format, *args)

        return Handler


def _fetch_status(db_paths: dict) -> dict:
    db_manager = DatabaseManager(db_paths)
    try:
        db_manager.initialize()
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "inventory_count": db_manager.count_inventory(),
            "hash_count": db_manager.count_hashes(),
            "corruption_count": db_manager.count_corruptions(),
            "duplicate_candidates": db_manager.count_duplicate_candidates(),
            "permission_issues": db_manager.count_permission_issues(resolved=False),
            "task_summary": db_manager.task_status_summary(),
            "tasks": db_manager.list_tasks(),
            "incomplete_operations": db_manager.list_incomplete_operations(),
            "recent_operations": db_manager.list_recent_operations(limit=20),
        }
    finally:
        db_manager.close()


def _dashboard_html() -> str:
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\" />\n"
        "  <title>File Manager Dashboard</title>\n"
        "  <style>\n"
        "    body { font-family: Arial, sans-serif; margin: 24px; }\n"
        "    h1, h2 { margin-bottom: 8px; }\n"
        "    .summary { margin-bottom: 16px; font-size: 14px; }\n"
        "    table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }\n"
        "    th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 12px; text-align: left; }\n"
        "    th { background: #f2f2f2; }\n"
        "    .pill { display: inline-block; padding: 2px 6px; border-radius: 10px; background: #eee; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>File Manager Dashboard</h1>\n"
        "  <div class=\"summary\" id=\"summary\">Loading...</div>\n"
        "  <h2>Tasks</h2>\n"
        "  <table>\n"
        "    <thead><tr><th>Task</th><th>Status</th><th>Attempts</th><th>Last Error</th></tr></thead>\n"
        "    <tbody id=\"tasks\"></tbody>\n"
        "  </table>\n"
        "  <h2>Recent Operations</h2>\n"
        "  <table>\n"
        "    <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Started</th><th>Finished</th></tr></thead>\n"
        "    <tbody id=\"operations\"></tbody>\n"
        "  </table>\n"
        "  <script>\n"
        "    async function refresh() {\n"
        "      const response = await fetch('/api/status');\n"
        "      const data = await response.json();\n"
        "      const summary = `Inventory: ${data.inventory_count} | Hashes: ${data.hash_count} | ` +\n"
        "        `Corruptions: ${data.corruption_count} | Duplicates: ${data.duplicate_candidates} | ` +\n"
        "        `Permissions: ${data.permission_issues}`;\n"
        "      document.getElementById('summary').textContent = summary;\n"
        "      const tasks = document.getElementById('tasks');\n"
        "      tasks.innerHTML = '';\n"
        "      (data.tasks || []).forEach(task => {\n"
        "        const row = document.createElement('tr');\n"
        "        row.innerHTML = `<td>${task.name}</td><td><span class=\"pill\">${task.status}</span></td>` +\n"
        "          `<td>${task.attempts}</td><td>${task.last_error || ''}</td>`;\n"
        "        tasks.appendChild(row);\n"
        "      });\n"
        "      const ops = document.getElementById('operations');\n"
        "      ops.innerHTML = '';\n"
        "      (data.recent_operations || []).forEach(op => {\n"
        "        const row = document.createElement('tr');\n"
        "        row.innerHTML = `<td>${op.operation_id}</td><td>${op.operation_type}</td>` +\n"
        "          `<td><span class=\"pill\">${op.status}</span></td><td>${op.started_at || ''}</td>` +\n"
        "          `<td>${op.finished_at || ''}</td>`;\n"
        "        ops.appendChild(row);\n"
        "      });\n"
        "    }\n"
        "    refresh();\n"
        "    setInterval(refresh, 5000);\n"
        "  </script>\n"
        "</body>\n"
        "</html>\n"
    )
