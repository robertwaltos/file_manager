"""
Duplicate handling plan generation and execution.
"""

from __future__ import annotations

import html
import json
import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import AppConfig, ensure_directories
from database import DatabaseManager
from utils import ActivityTracker, ResourceMonitor


@dataclass
class DuplicatePlanStats:
    """Summary statistics for a duplicate handling plan."""

    report_path: Path
    plan_path: Path
    review_path: Path
    group_count: int
    move_count: int


@dataclass
class DuplicateApplyStats:
    """Summary statistics for applying a duplicate handling plan."""

    plan_path: Path
    result_path: Path
    moved: int
    copied: int
    deleted: int
    skipped: int
    errors: int


class DuplicatePlanEngine:
    """Build and optionally execute duplicate move plans."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: Optional[DatabaseManager],
        logger: Optional[logging.Logger],
        movement_logger: Optional[logging.Logger] = None,
        monitor: Optional[ResourceMonitor] = None,
        activity_tracker: Optional[ActivityTracker] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.movement_logger = movement_logger or logging.getLogger("file_manager.movement")
        self.monitor = monitor
        self.activity_tracker = activity_tracker
        self.progress_log_interval = int(
            self.config.get("duplicates", "plan_progress_log_interval", default=1000)
        )
        self.backup_root = self.config.resolve_path("paths", "duplicates_backup", default="data/duplicates_backup")
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")
        self.plan_prefix = str(self.config.get("duplicates", "plan_prefix", default="movement_plan"))
        self.review_prefix = str(
            self.config.get("duplicates", "review_manifest_prefix", default="duplicate_review")
        )
        self.backup_action = str(self.config.get("duplicates", "backup_action", default="move")).lower()
        self.delete_after_backup = bool(
            self.config.get("duplicates", "delete_after_backup", default=False)
        )
        self.delete_copy_after_backup = bool(
            self.config.get("duplicates", "delete_copy_after_backup", default=False)
        )
        self.link_mode = str(self.config.get("duplicates", "link_mode", default="")).lower()
        self.backup_before_link = bool(
            self.config.get("duplicates", "backup_before_link", default=True)
        )
        self.google_drive_marker = str(
            self.config.get("duplicates", "google_drive_marker", default="Google Drive")
        )
        self.google_drive_target = self._resolve_google_drive_target()

    def build_plan(self, report_path: Path) -> DuplicatePlanStats:
        """Build a move plan and review manifest from a duplicate report."""
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        groups = report_data.get("groups", [])
        ensure_directories([self.backup_root, self.logs_root, self.google_drive_target])

        plan_groups = []
        moves = []
        move_index = 0

        for index, group in enumerate(groups, start=1):
            primary = group.get("primary", {})
            duplicates = group.get("duplicates", [])
            self._touch("duplicate_plan", index, interval=100)
            self._log_progress("duplicate_plan", index, len(groups))
            planned_duplicates = []
            for duplicate in duplicates:
                move_index += 1
                source_path = duplicate["file_path"]
                file_id = duplicate.get("file_id", "unknown")
                is_google_drive = self._is_google_drive_path(source_path)
                link_enabled = self.link_mode in {"hardlink", "symlink"}
                destination_root = self.google_drive_target if is_google_drive else self.backup_root
                action = "move" if is_google_drive else self.backup_action
                delete_after_backup = False if is_google_drive else self.delete_after_backup
                delete_copy_after_backup = False if is_google_drive else self.delete_copy_after_backup
                destination = self._build_destination(source_path, file_id, destination_root)
                link_target = ""
                backup_destination = ""
                backup_action = self.backup_action

                if link_enabled and not is_google_drive:
                    action = self.link_mode
                    link_target = str(primary.get("file_path", ""))
                    if self.backup_before_link:
                        backup_destination = str(self._build_destination(source_path, file_id, self.backup_root))
                planned = {
                    "move_id": move_index,
                    "source": source_path,
                    "destination": str(destination),
                    "action": action,
                    "delete_after_backup": delete_after_backup,
                    "delete_copy_after_backup": delete_copy_after_backup,
                    "file_id": file_id,
                    "modification_date": duplicate.get("modification_date", ""),
                    "link_target": link_target,
                    "backup_destination": backup_destination,
                    "backup_action": backup_action,
                }
                planned_duplicates.append(planned)
                moves.append(planned)
            plan_groups.append(
                {
                    "group_id": index,
                    "hash_type": group.get("hash_type", ""),
                    "hash_value": group.get("hash_value", ""),
                    "file_name": group.get("file_name", ""),
                    "size": group.get("size", 0),
                    "primary": primary,
                    "duplicates": planned_duplicates,
                }
            )

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        plan_path = self.logs_root / f"{self.plan_prefix}_{timestamp}.json"
        review_path = self.backup_root / f"{self.review_prefix}_{timestamp}.html"

        plan = {
            "generated_at": datetime.utcnow().isoformat(),
            "report_path": str(report_path),
            "backup_root": str(self.backup_root),
            "default_action": self.backup_action,
            "group_count": len(plan_groups),
            "move_count": len(moves),
            "groups": plan_groups,
            "moves": moves,
        }

        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        review_path.write_text(self._build_review_manifest(plan), encoding="utf-8")

        return DuplicatePlanStats(
            report_path=report_path,
            plan_path=plan_path,
            review_path=review_path,
            group_count=len(plan_groups),
            move_count=len(moves),
        )

    def apply_plan(self, plan_path: Path, operation_id: Optional[str] = None) -> DuplicateApplyStats:
        """Execute a duplicate move plan with optional deletion."""
        plan_data = json.loads(plan_path.read_text(encoding="utf-8"))
        moves = plan_data.get("moves", [])
        delete_after_backup_default = bool(self.config.get("duplicates", "delete_after_backup", default=False))
        delete_copy_after_backup_default = bool(
            self.config.get("duplicates", "delete_copy_after_backup", default=False)
        )
        allow_delete = os.environ.get("FILE_MANAGER_DELETE_DUPLICATES", "").lower() in {"1", "true", "yes"}
        if operation_id is None:
            operation_id = f"duplicate_plan_apply_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        moved = copied = deleted = skipped = errors = 0
        results = []

        for index, move in enumerate(moves, start=1):
            source = Path(move["source"])
            destination = Path(move["destination"])
            action = str(move.get("action", self.backup_action)).lower()
            delete_after_backup = bool(move.get("delete_after_backup", delete_after_backup_default))
            delete_copy_after_backup = bool(
                move.get("delete_copy_after_backup", delete_copy_after_backup_default)
            )
            self._touch("duplicate_apply", index, interval=100)
            self._log_progress("duplicate_apply", index, len(moves))
            if action in {"hardlink", "symlink"}:
                if not source.exists():
                    skipped += 1
                    results.append(self._result_entry(move, "skipped", "source_missing"))
                    continue
                if not allow_delete:
                    skipped += 1
                    results.append(self._result_entry(move, "skipped", "delete_confirmation_required"))
                    continue
                link_target = Path(move.get("link_target", ""))
                if not link_target.exists():
                    errors += 1
                    results.append(self._result_entry(move, "error", "link_target_missing"))
                    continue
                backup_destination = move.get("backup_destination", "")
                backup_action = str(move.get("backup_action", self.backup_action)).lower()
                rollback = None
                try:
                    if backup_destination:
                        backup_path = self._resolve_conflict(Path(backup_destination))
                        backup_path.parent.mkdir(parents=True, exist_ok=True)
                        if backup_action == "copy":
                            shutil.copy2(source, backup_path)
                        else:
                            shutil.move(source, backup_path)
                        if backup_action == "copy":
                            source.unlink()
                        rollback = {"action": "copy", "source": str(backup_path), "destination": str(source)}
                    else:
                        source.unlink()
                        rollback = {"action": "delete", "source": str(source)}

                    if action == "hardlink":
                        os.link(link_target, source)
                    else:
                        os.symlink(link_target, source)

                    copied += 1
                    results.append(self._result_entry(move, "completed", "ok"))
                    self.movement_logger.info("Duplicate link created: %s -> %s (%s)", source, link_target, action)
                    if self.db_manager is not None:
                        self.db_manager.record_file_operation(
                            operation_id,
                            action=action,
                            source_path=str(source),
                            destination_path=str(link_target),
                            status="completed",
                            size=None,
                            rollback=rollback,
                        )
                except Exception as exc:
                    errors += 1
                    results.append(self._result_entry(move, "error", str(exc)))
                    self.movement_logger.error("Duplicate link failed: %s -> %s (%s)", source, link_target, exc)
                    if self.db_manager is not None:
                        self.db_manager.record_file_operation(
                            operation_id,
                            action=action,
                            source_path=str(source),
                            destination_path=str(link_target),
                            status="failed",
                            size=None,
                            error_message=str(exc),
                        )
                continue
            if not source.exists():
                skipped += 1
                results.append(self._result_entry(move, "skipped", "source_missing"))
                continue
            destination = self._resolve_conflict(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)

            if self.monitor is not None:
                self.monitor.throttle()

            try:
                source_size = source.stat().st_size
                if action == "copy":
                    shutil.copy2(source, destination)
                    copied += 1
                else:
                    shutil.move(source, destination)
                    moved += 1
            except Exception as exc:
                errors += 1
                results.append(self._result_entry(move, "error", str(exc)))
                self.movement_logger.error("Duplicate move failed: %s -> %s (%s)", source, destination, exc)
                if self.db_manager is not None:
                    self.db_manager.record_file_operation(
                        operation_id,
                        action=action,
                        source_path=str(source),
                        destination_path=str(destination),
                        status="failed",
                        size=None,
                        error_message=str(exc),
                    )
                continue

            if not destination.exists():
                errors += 1
                results.append(self._result_entry(move, "error", "destination_missing"))
                self.movement_logger.error("Destination missing after move: %s", destination)
                if self.db_manager is not None:
                    self.db_manager.record_file_operation(
                        operation_id,
                        action=action,
                        source_path=str(source),
                        destination_path=str(destination),
                        status="failed",
                        size=None,
                        error_message="destination_missing",
                    )
                continue

            if destination.stat().st_size != source_size:
                errors += 1
                results.append(self._result_entry(move, "error", "size_mismatch"))
                self.movement_logger.error("Size mismatch after move: %s", destination)
                if self.db_manager is not None:
                    self.db_manager.record_file_operation(
                        operation_id,
                        action=action,
                        source_path=str(source),
                        destination_path=str(destination),
                        status="failed",
                        size=source_size,
                        error_message="size_mismatch",
                    )
                continue

            rollback = None
            if action == "move":
                rollback = {"action": "move", "source": str(destination), "destination": str(source)}
            elif action == "copy":
                if delete_after_backup and allow_delete:
                    if not delete_copy_after_backup:
                        rollback = {"action": "copy", "source": str(destination), "destination": str(source)}
                else:
                    rollback = {"action": "delete", "source": str(destination)}

            if action == "copy" and delete_after_backup and allow_delete:
                try:
                    source.unlink()
                    deleted += 1
                except Exception as exc:
                    errors += 1
                    results.append(self._result_entry(move, "error", f"delete_failed:{exc}"))
                    self.movement_logger.error("Delete failed: %s (%s)", source, exc)
                    if self.db_manager is not None:
                        self.db_manager.record_file_operation(
                            operation_id,
                            action="delete",
                            source_path=str(source),
                            destination_path=None,
                            status="failed",
                            size=source_size,
                            error_message=f"delete_failed:{exc}",
                        )
                    continue
                if delete_copy_after_backup:
                    try:
                        destination.unlink()
                        deleted += 1
                    except Exception as exc:
                        errors += 1
                        results.append(self._result_entry(move, "error", f"delete_backup_failed:{exc}"))
                        self.movement_logger.error("Backup delete failed: %s (%s)", destination, exc)
                        if self.db_manager is not None:
                            self.db_manager.record_file_operation(
                                operation_id,
                                action="delete",
                                source_path=str(destination),
                                destination_path=None,
                                status="failed",
                                size=source_size,
                                error_message=f"delete_backup_failed:{exc}",
                            )
                        continue

            results.append(self._result_entry(move, "completed", "ok"))
            self.movement_logger.info("Duplicate %s -> %s (%s)", source, destination, action)
            if self.db_manager is not None:
                self.db_manager.record_file_operation(
                    operation_id,
                    action=action,
                    source_path=str(source),
                    destination_path=str(destination),
                    status="completed",
                    size=source_size,
                    rollback=rollback,
                )

        execution = {
            "executed_at": datetime.utcnow().isoformat(),
            "plan_path": str(plan_path),
            "delete_after_backup_default": delete_after_backup_default,
            "delete_copy_after_backup_default": delete_copy_after_backup_default,
            "allow_delete": allow_delete,
            "summary": {
                "moved": moved,
                "copied": copied,
                "deleted": deleted,
                "skipped": skipped,
                "errors": errors,
            },
            "results": results,
        }

        result_path = self.logs_root / f"{self.plan_prefix}_execution_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        result_path.write_text(json.dumps(execution, indent=2), encoding="utf-8")

        return DuplicateApplyStats(
            plan_path=plan_path,
            result_path=result_path,
            moved=moved,
            copied=copied,
            deleted=deleted,
            skipped=skipped,
            errors=errors,
        )

    def _build_destination(self, source_path: str, file_id: str | int, root: Path) -> Path:
        source = Path(source_path)
        encoded_parent = self._encode_path(str(source.parent))
        destination_dir = root / encoded_parent
        stem = source.stem
        suffix = source.suffix
        return destination_dir / f"{stem}__id{file_id}{suffix}"

    def _resolve_conflict(self, destination: Path) -> Path:
        if not destination.exists():
            return destination
        stem = destination.stem
        suffix = destination.suffix
        parent = destination.parent
        counter = 1
        while True:
            candidate = parent / f"{stem}__dup{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    def _encode_path(self, value: str) -> str:
        encoded = []
        for char in value:
            if char.isalnum() or char in "-_.":
                encoded.append(char)
            elif char in {":", "\\", "/"}:
                encoded.append("__")
            elif ord(char) < 128:
                encoded.append("_")
            else:
                encoded.append(f"_u{ord(char):04X}")
        return "".join(encoded).strip("_") or "root"

    def _resolve_google_drive_target(self) -> Path:
        value = self.config.get("duplicates", "google_drive_target", default=None)
        if not value:
            return self.backup_root
        path = Path(value)
        if not path.is_absolute():
            path = (self.config.root_dir / path).resolve()
        return path

    def _is_google_drive_path(self, value: str) -> bool:
        def normalize(path_value: str) -> str:
            return path_value.replace("\\", "/").lower()

        marker_norm = normalize(self.google_drive_marker)
        if not marker_norm:
            return False
        return marker_norm in normalize(value)

    def _build_review_manifest(self, plan: dict) -> str:
        rows = []
        for group in plan.get("groups", []):
            primary = group.get("primary", {})
            primary_path = html.escape(str(primary.get("file_path", "")))
            for duplicate in group.get("duplicates", []):
                rows.append(
                    "<tr>"
                    f"<td>{group.get('group_id')}</td>"
                    f"<td>{html.escape(str(group.get('file_name', '')))}</td>"
                    f"<td>{group.get('size')}</td>"
                    f"<td>{primary_path}</td>"
                    f"<td>{html.escape(str(duplicate.get('source', '')))}</td>"
                    f"<td>{html.escape(str(duplicate.get('destination', '')))}</td>"
                    f"<td>{html.escape(str(group.get('hash_type', '')))}</td>"
                    "</tr>"
                )

        rows_html = "\n".join(rows) if rows else "<tr><td colspan=\"7\">No duplicates.</td></tr>"
        generated_at = html.escape(plan.get("generated_at", ""))
        report_path = html.escape(plan.get("report_path", ""))

        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"utf-8\" />\n"
            "  <title>Duplicate Review</title>\n"
            "  <style>\n"
            "    body { font-family: Arial, sans-serif; margin: 24px; }\n"
            "    table { border-collapse: collapse; width: 100%; }\n"
            "    th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 12px; }\n"
            "    th { background: #f2f2f2; text-align: left; }\n"
            "    .meta { margin-bottom: 16px; font-size: 12px; color: #555; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <h1>Duplicate Review</h1>\n"
            f"  <div class=\"meta\">Generated: {generated_at}</div>\n"
            f"  <div class=\"meta\">Report: {report_path}</div>\n"
            "  <table>\n"
            "    <thead>\n"
            "      <tr>\n"
            "        <th>Group</th>\n"
            "        <th>Name</th>\n"
            "        <th>Size</th>\n"
            "        <th>Primary</th>\n"
            "        <th>Duplicate</th>\n"
            "        <th>Destination</th>\n"
            "        <th>Hash Type</th>\n"
            "      </tr>\n"
            "    </thead>\n"
            "    <tbody>\n"
            f"{rows_html}\n"
            "    </tbody>\n"
            "  </table>\n"
            "</body>\n"
            "</html>\n"
        )

    def _touch(self, note: str, count: int, interval: int = 200) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

    def _log_progress(self, phase: str, current: int, total: int) -> None:
        if self.progress_log_interval <= 0:
            return
        if current % self.progress_log_interval != 0:
            return
        self.logger.info("Duplicate %s progress: %s/%s", phase, current, total)

    def _result_entry(self, move: dict, status: str, message: str) -> dict:
        return {
            "move_id": move.get("move_id"),
            "source": move.get("source"),
            "destination": move.get("destination"),
            "status": status,
            "message": message,
        }
