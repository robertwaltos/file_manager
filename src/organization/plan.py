"""
Organization plan generation and execution based on AI classifications.
"""

from __future__ import annotations

import html
import json
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import AppConfig, ensure_directories
from database import DatabaseManager
from utils import ActivityTracker, ResourceMonitor


IMAGE_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".tif",
    ".tiff",
    ".webp",
    ".heic",
    ".heif",
}
VIDEO_EXTS = {".mp4", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".webm"}
DOC_EXTS = {
    ".pdf",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx",
    ".xls",
    ".xlsx",
    ".odt",
    ".ods",
    ".odp",
    ".rtf",
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".xml",
    ".epub",
    ".mobi",
    ".azw",
    ".azw3",
}
AUDIO_EXTS = {".mp3", ".flac", ".wav", ".aac", ".m4a", ".ogg", ".wma"}


@dataclass
class OrganizationPlanStats:
    """Summary stats for organization plan generation."""

    plan_path: Path
    review_path: Path
    move_count: int


@dataclass
class OrganizationApplyStats:
    """Summary stats for organization plan application."""

    plan_path: Path
    result_path: Path
    moved: int
    copied: int
    skipped: int
    errors: int


class OrganizationPlanEngine:
    """Build and optionally execute organization plans."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
        logger: Optional[logging.Logger] = None,
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
            self.config.get("organization", "progress_log_interval", default=1000)
        )
        self.enabled = bool(self.config.get("organization", "enabled", default=True))
        self.apply_enabled = bool(self.config.get("organization", "apply_plan", default=False))
        self.action = str(self.config.get("organization", "action", default="move")).lower()
        self.use_year_subdir = bool(self.config.get("organization", "use_year_subdir", default=True))
        self.plan_prefix = str(self.config.get("organization", "plan_prefix", default="organization_plan"))
        self.review_prefix = str(self.config.get("organization", "review_prefix", default="organization_review"))
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")
        self.duplicates_root = self.config.resolve_path("paths", "duplicates_backup", default="data/duplicates_backup")
        self.corrupted_root = self.config.resolve_path("paths", "corrupted", default="data/corrupted_files")
        self.nsfw_root = self.config.resolve_path("paths", "nsfw_review", default="data/nsfw_review")
        self.root = None
        self.root = self._resolve_root("root", default="")
        self.inbox_root = self._resolve_root("inbox_root", default="data/organized/inbox")
        self.inbox_group_min_count = int(
            self.config.get("organization", "inbox_group_min_count", default=0)
        )
        self.inbox_group_by = str(
            self.config.get("organization", "inbox_group_by", default="category")
        ).lower()
        self.uncategorized_to_inbox = bool(
            self.config.get("organization", "uncategorized_to_inbox", default=True)
        )
        self.images_root = self._resolve_root("images_root", default="data/organized/images")
        self.videos_root = self._resolve_root("videos_root", default="data/organized/videos")
        self.documents_root = self._resolve_root("documents_root", default="data/organized/documents")
        self.audio_root = self._resolve_root("audio_root", default="data/organized/audio")
        self.other_root = self._resolve_root("other_root", default="data/organized/other")
        self.category_destinations = self._normalize_destination_map(
            self.config.get("organization", "category_destinations", default={})
        )
        self.subcategory_destinations = self._normalize_destination_map(
            self.config.get("organization", "subcategory_destinations", default={})
        )
        self.extension_destinations = {
            key.lower(): value
            for key, value in self._normalize_destination_map(
                self.config.get("organization", "extension_destinations", default={})
            ).items()
        }
        self.path_keyword_destinations = self._normalize_destination_map(
            self.config.get("organization", "path_keyword_destinations", default={})
        )

    def build_plan(self) -> Optional[OrganizationPlanStats]:
        """Build an organization plan from AI classifications."""
        if not self.enabled:
            self.logger.info("Organization plan disabled.")
            return None

        ensure_directories(
            [
                self.logs_root,
                self.images_root,
                self.videos_root,
                self.documents_root,
                self.audio_root,
                self.other_root,
                self.inbox_root,
            ]
        )
        planned: list[dict] = []
        inbox_counts: dict[str, int] = {}
        for index, entry in enumerate(self.db_manager.list_classifications(), start=1):
            source = Path(entry["file_path"])
            if not source.exists():
                continue
            if self._is_quarantine_path(source):
                continue
            self._touch("organization_plan", index, interval=200)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "Organization plan progress: %s planned=%s",
                    index,
                    len(planned),
                )
            destination = self._resolve_destination(source, entry)
            if destination is None:
                continue
            if self._same_path(source, destination):
                continue
            group_key = ""
            if self._is_inbox_destination(destination) and self.inbox_group_min_count > 0:
                group_key = self._inbox_group_key(entry, source)
                if group_key:
                    inbox_counts[group_key] = inbox_counts.get(group_key, 0) + 1
            planned.append(
                {
                    "source": str(source),
                    "destination": str(destination),
                    "action": self.action,
                    "category": entry.get("category", ""),
                    "subcategory": entry.get("subcategory", ""),
                    "group_key": group_key,
                }
            )

        moves = []
        for item in planned:
            destination = Path(item["destination"])
            group_key = item.get("group_key") or ""
            if (
                group_key
                and self._is_inbox_destination(destination)
                and inbox_counts.get(group_key, 0) >= self.inbox_group_min_count
            ):
                destination = self.inbox_root / self._sanitize_folder_name(group_key) / destination.name
            moves.append(
                {
                    "source": item["source"],
                    "destination": str(destination),
                    "action": item["action"],
                    "category": item.get("category", ""),
                    "subcategory": item.get("subcategory", ""),
                }
            )

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        plan_path = self.logs_root / f"{self.plan_prefix}_{timestamp}.json"
        review_path = self.logs_root / f"{self.review_prefix}_{timestamp}.html"
        plan_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "action": self.action,
                    "move_count": len(moves),
                    "moves": moves,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        review_path.write_text(self._build_review_manifest(moves), encoding="utf-8")

        return OrganizationPlanStats(plan_path=plan_path, review_path=review_path, move_count=len(moves))

    def apply_plan(self, plan_path: Path, operation_id: str) -> OrganizationApplyStats:
        """Apply an organization plan."""
        plan_data = json.loads(plan_path.read_text(encoding="utf-8"))
        moves = plan_data.get("moves", [])
        moved = copied = skipped = errors = 0
        results = []

        for index, move in enumerate(moves, start=1):
            source = Path(move["source"])
            destination = Path(move["destination"])
            action = str(move.get("action", self.action)).lower()
            if not source.exists():
                skipped += 1
                results.append(self._result_entry(move, "skipped", "source_missing"))
                continue
            destination = self._resolve_conflict(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if self.monitor is not None:
                self.monitor.throttle()
            self._touch("organization_apply", index, interval=200)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "Organization apply progress: %s/%s moved=%s copied=%s skipped=%s errors=%s",
                    index,
                    len(moves),
                    moved,
                    copied,
                    skipped,
                    errors,
                )

            try:
                source_size = source.stat().st_size
                if action == "copy":
                    shutil.copy2(source, destination)
                    copied += 1
                    rollback = {"action": "delete", "source": str(destination)}
                else:
                    shutil.move(source, destination)
                    moved += 1
                    rollback = {"action": "move", "source": str(destination), "destination": str(source)}
            except Exception as exc:
                errors += 1
                results.append(self._result_entry(move, "error", str(exc)))
                self.movement_logger.error("Organization move failed: %s -> %s (%s)", source, destination, exc)
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
                continue

            file_id = self.db_manager.get_file_id_by_path(move["source"])
            if file_id is not None:
                self.db_manager.update_file_path(file_id, str(destination))
            results.append(self._result_entry(move, "completed", "ok"))
            self.db_manager.record_file_operation(
                operation_id,
                action=action,
                source_path=str(source),
                destination_path=str(destination),
                status="completed",
                size=source_size,
                rollback=rollback,
            )

        result_path = self.logs_root / f"{self.plan_prefix}_execution_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        result_path.write_text(
            json.dumps(
                {
                    "executed_at": datetime.utcnow().isoformat(),
                    "plan_path": str(plan_path),
                    "summary": {
                        "moved": moved,
                        "copied": copied,
                        "skipped": skipped,
                        "errors": errors,
                    },
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return OrganizationApplyStats(
            plan_path=plan_path,
            result_path=result_path,
            moved=moved,
            copied=copied,
            skipped=skipped,
            errors=errors,
        )

    def _touch(self, note: str, count: int, interval: int = 200) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

    def _build_destination(self, source: Path, entry: dict) -> Optional[Path]:
        ext = source.suffix.lower()
        if ext in IMAGE_EXTS:
            base = self.images_root
        elif ext in VIDEO_EXTS:
            base = self.videos_root
        elif ext in DOC_EXTS:
            base = self.documents_root
        elif ext in AUDIO_EXTS:
            base = self.audio_root
        else:
            base = self.other_root

        category = entry.get("category") or "Uncategorized"
        subcategory = entry.get("subcategory") or ""
        year = self._year_from_entry(entry) if self.use_year_subdir else ""

        parts = [base]
        if year:
            parts.append(Path(year))
        if category:
            parts.append(Path(category))
        if subcategory and subcategory != category:
            parts.append(Path(subcategory))
        destination_dir = Path(*parts)
        return destination_dir / source.name

    def _resolve_destination(self, source: Path, entry: dict) -> Optional[Path]:
        category = str(entry.get("category", "")).strip()
        subcategory = str(entry.get("subcategory", "")).strip().lower()
        ext = source.suffix.lower()
        path_value = str(source).lower()

        if self.path_keyword_destinations:
            for keyword, destination in self.path_keyword_destinations.items():
                if keyword and keyword in path_value:
                    return destination / source.name

        if ext in self.extension_destinations:
            return self.extension_destinations[ext] / source.name

        category_key = category.lower()
        if category_key and category_key in self.category_destinations:
            return self.category_destinations[category_key] / source.name

        if self.uncategorized_to_inbox and category_key in {"uncategorized", "unknown", "other"}:
            return self.inbox_root / source.name

        if subcategory in self.subcategory_destinations:
            return self.subcategory_destinations[subcategory] / source.name

        if self.inbox_root:
            return self.inbox_root / source.name

        return self._build_destination(source, entry)

    def _year_from_entry(self, entry: dict) -> str:
        value = entry.get("modification_date", "")
        if value:
            return value[:4]
        return "Unknown"

    def _resolve_root(self, key: str, default: str) -> Path:
        value = self.config.get("organization", key, default=default)
        if value is None:
            return (self.config.root_dir / default).resolve()
        value_str = str(value).strip()
        if not value_str:
            return (self.config.root_dir / default).resolve()
        path = Path(value_str)
        if not path.is_absolute():
            if self.root is not None and key != "root":
                return (self.root / path).resolve()
            return (self.config.root_dir / path).resolve()
        return path

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

    def _same_path(self, source: Path, destination: Path) -> bool:
        try:
            return source.resolve() == destination.resolve()
        except OSError:
            return False

    def _is_quarantine_path(self, path: Path) -> bool:
        path_norm = str(path).replace("\\", "/").lower()
        for root in (self.duplicates_root, self.corrupted_root, self.nsfw_root):
            root_norm = str(root).replace("\\", "/").lower()
            if path_norm.startswith(root_norm):
                return True
        return False

    def _normalize_destination_map(self, mapping: dict) -> dict[str, Path]:
        normalized: dict[str, Path] = {}
        for key, value in (mapping or {}).items():
            if value is None:
                continue
            value_str = str(value).strip()
            if not value_str:
                continue
            destination = Path(value_str)
            if not destination.is_absolute():
                if self.root is not None:
                    destination = (self.root / destination).resolve()
                else:
                    destination = (self.config.root_dir / destination).resolve()
            normalized[str(key).strip().lower()] = destination
        return normalized

    def _is_inbox_destination(self, destination: Path) -> bool:
        try:
            return destination.parent.resolve() == self.inbox_root.resolve()
        except OSError:
            return str(destination.parent).replace("\\", "/").lower() == str(self.inbox_root).replace("\\", "/").lower()

    def _inbox_group_key(self, entry: dict, source: Path) -> str:
        if self.inbox_group_by == "extension":
            return source.suffix.lower().lstrip(".")
        if self.inbox_group_by == "subcategory":
            return str(entry.get("subcategory", "")).strip()
        if self.inbox_group_by == "category":
            value = str(entry.get("category", "")).strip()
            return value or str(entry.get("subcategory", "")).strip()
        return ""

    def _sanitize_folder_name(self, value: str) -> str:
        safe = "".join(char if char.isalnum() or char in (" ", "-", "_") else "_" for char in value)
        safe = safe.strip().replace("  ", " ")
        return safe or "Inbox"

    def _build_review_manifest(self, moves: list[dict]) -> str:
        rows = []
        for move in moves:
            rows.append(
                "<tr>"
                f"<td>{html.escape(move.get('source', ''))}</td>"
                f"<td>{html.escape(move.get('destination', ''))}</td>"
                f"<td>{html.escape(move.get('category', ''))}</td>"
                f"<td>{html.escape(move.get('subcategory', ''))}</td>"
                "</tr>"
            )

        rows_html = "\n".join(rows) if rows else "<tr><td colspan=\"4\">No moves.</td></tr>"
        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"utf-8\" />\n"
            "  <title>Organization Review</title>\n"
            "  <style>\n"
            "    body { font-family: Arial, sans-serif; margin: 24px; }\n"
            "    table { border-collapse: collapse; width: 100%; }\n"
            "    th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 12px; }\n"
            "    th { background: #f2f2f2; text-align: left; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <h1>Organization Review</h1>\n"
            "  <table>\n"
            "    <thead>\n"
            "      <tr>\n"
            "        <th>Source</th>\n"
            "        <th>Destination</th>\n"
            "        <th>Category</th>\n"
            "        <th>Subcategory</th>\n"
            "      </tr>\n"
            "    </thead>\n"
            "    <tbody>\n"
            f"{rows_html}\n"
            "    </tbody>\n"
            "  </table>\n"
            "</body>\n"
            "</html>\n"
        )

    def _result_entry(self, move: dict, status: str, message: str) -> dict:
        return {
            "source": move.get("source"),
            "destination": move.get("destination"),
            "status": status,
            "message": message,
        }
