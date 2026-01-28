"""
NSFW quarantine handling.
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

try:
    from PIL import Image, ImageFilter
except ImportError:  # pragma: no cover
    Image = None
    ImageFilter = None


@dataclass
class NsfwMoveStats:
    """Summary of NSFW quarantine moves."""

    moved: int
    skipped: int
    errors: int
    report_path: Path
    review_path: Path


class NsfwMover:
    """Move flagged NSFW files into the review directory."""

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
            self.config.get("nsfw", "progress_log_interval", default=200)
        )
        self.enabled = bool(self.config.get("nsfw", "enabled", default=True))
        self.move_flagged = bool(self.config.get("nsfw", "move_flagged", default=True))
        self.review_prefix = str(self.config.get("nsfw", "review_prefix", default="nsfw_review"))
        self.report_prefix = str(self.config.get("nsfw", "report_prefix", default="nsfw_report"))
        self.nsfw_threshold = float(
            self.config.get(
                "nsfw", "threshold", default=self.config.get("ai_models", "nsfw_threshold", default=0.85)
            )
        )
        self.thumbnail_max_px = int(self.config.get("nsfw", "thumbnail_max_px", default=256))
        self.thumbnail_blur_radius = int(self.config.get("nsfw", "thumbnail_blur_radius", default=8))
        self.thumbnail_subdir = str(self.config.get("nsfw", "thumbnail_subdir", default="thumbnails"))
        self.review_root = self.config.resolve_path("paths", "nsfw_review", default="data/nsfw_review")
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")

    def run(self, operation_id: Optional[str] = None) -> Optional[NsfwMoveStats]:
        """Move NSFW files and emit a report."""
        if not self.enabled or not self.move_flagged:
            self.logger.info("NSFW review mover disabled.")
            return None
        ensure_directories([self.review_root, self.logs_root])
        if operation_id is None:
            operation_id = f"nsfw_quarantine_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        candidates = self.db_manager.list_nsfw_classifications(self.nsfw_threshold)
        moved = skipped = errors = 0
        results = []
        if Image is not None:
            (self.review_root / self.thumbnail_subdir).mkdir(parents=True, exist_ok=True)

        for index, entry in enumerate(candidates, start=1):
            source_path = Path(entry["file_path"])
            if not source_path.exists():
                skipped += 1
                results.append(self._result(entry, "skipped", "source_missing"))
                continue
            if self._is_in_review_root(source_path):
                skipped += 1
                results.append(self._result(entry, "skipped", "already_quarantined"))
                continue
            if self.monitor is not None:
                self.monitor.throttle()
            self._touch("nsfw_quarantine", index, interval=100)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "NSFW quarantine progress: %s moved=%s skipped=%s errors=%s",
                    index,
                    moved,
                    skipped,
                    errors,
                )

            destination = self._build_destination(source_path, entry["file_id"])
            destination = self._resolve_conflict(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)

            try:
                source_size = source_path.stat().st_size
                shutil.move(source_path, destination)
            except Exception as exc:
                errors += 1
                results.append(self._result(entry, "error", str(exc)))
                self.movement_logger.error("NSFW move failed: %s -> %s (%s)", source_path, destination, exc)
                self.db_manager.record_file_operation(
                    operation_id,
                    action="move",
                    source_path=str(source_path),
                    destination_path=str(destination),
                    status="failed",
                    size=None,
                    error_message=str(exc),
                )
                continue

            if not destination.exists() or destination.stat().st_size != source_size:
                errors += 1
                results.append(self._result(entry, "error", "size_mismatch"))
                self.movement_logger.error("NSFW move validation failed: %s", destination)
                self.db_manager.record_file_operation(
                    operation_id,
                    action="move",
                    source_path=str(source_path),
                    destination_path=str(destination),
                    status="failed",
                    size=source_size,
                    error_message="size_mismatch",
                )
                continue

            self.db_manager.update_file_path(entry["file_id"], str(destination))
            moved += 1
            thumbnail = self._build_thumbnail(destination, entry["file_id"])
            results.append(self._result(entry, "moved", "ok", thumbnail))
            self.movement_logger.info("NSFW file moved: %s -> %s", source_path, destination)
            self.db_manager.record_file_operation(
                operation_id,
                action="move",
                source_path=str(source_path),
                destination_path=str(destination),
                status="completed",
                size=source_size,
                rollback={"action": "move", "source": str(destination), "destination": str(source_path)},
            )

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_path = self.logs_root / f"{self.report_prefix}_{timestamp}.json"
        review_path = self.review_root / f"{self.review_prefix}_{timestamp}.html"

        report_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "threshold": self.nsfw_threshold,
                    "moved": moved,
                    "skipped": skipped,
                    "errors": errors,
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        review_path.write_text(self._build_review_manifest(results), encoding="utf-8")

        return NsfwMoveStats(
            moved=moved,
            skipped=skipped,
            errors=errors,
            report_path=report_path,
            review_path=review_path,
        )

    def _touch(self, note: str, count: int, interval: int = 100) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

    def _build_destination(self, source_path: Path, file_id: int) -> Path:
        encoded_parent = self._encode_path(str(source_path.parent))
        destination_dir = self.review_root / encoded_parent
        stem = source_path.stem
        suffix = source_path.suffix
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

    def _is_in_review_root(self, path: Path) -> bool:
        root_norm = str(self.review_root).replace("\\", "/").lower()
        path_norm = str(path).replace("\\", "/").lower()
        return path_norm.startswith(root_norm)

    def _build_review_manifest(self, results: list[dict]) -> str:
        rows = []
        for entry in results:
            thumbnail_html = ""
            if entry.get("thumbnail"):
                thumbnail_html = f"<img src=\"{html.escape(entry['thumbnail'])}\" width=\"120\" />"
            rows.append(
                "<tr>"
                f"<td>{thumbnail_html}</td>"
                f"<td>{html.escape(entry.get('file_path', ''))}</td>"
                f"<td>{html.escape(str(entry.get('nsfw_score', '')))}</td>"
                f"<td>{html.escape(entry.get('status', ''))}</td>"
                f"<td>{html.escape(entry.get('message', ''))}</td>"
                "</tr>"
            )

        rows_html = "\n".join(rows) if rows else "<tr><td colspan=\"5\">No NSFW files.</td></tr>"
        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"utf-8\" />\n"
            "  <title>NSFW Review</title>\n"
            "  <style>\n"
            "    body { font-family: Arial, sans-serif; margin: 24px; }\n"
            "    table { border-collapse: collapse; width: 100%; }\n"
            "    th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 12px; }\n"
            "    th { background: #f2f2f2; text-align: left; }\n"
            "  </style>\n"
            "</head>\n"
            "<body>\n"
            "  <h1>NSFW Review</h1>\n"
            "  <table>\n"
            "    <thead>\n"
            "      <tr>\n"
            "        <th>Preview</th>\n"
            "        <th>File</th>\n"
            "        <th>Score</th>\n"
            "        <th>Status</th>\n"
            "        <th>Message</th>\n"
            "      </tr>\n"
            "    </thead>\n"
            "    <tbody>\n"
            f"{rows_html}\n"
            "    </tbody>\n"
            "  </table>\n"
            "</body>\n"
            "</html>\n"
        )

    def _result(self, entry: dict, status: str, message: str, thumbnail: str | None = None) -> dict:
        return {
            "file_id": entry["file_id"],
            "file_path": entry["file_path"],
            "nsfw_score": entry.get("nsfw_score"),
            "status": status,
            "message": message,
            "thumbnail": thumbnail or "",
        }

    def _build_thumbnail(self, path: Path, file_id: int) -> str:
        if Image is None or ImageFilter is None:
            return ""
        if path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}:
            return ""
        try:
            with Image.open(path) as image:
                image = image.convert("RGB")
                image.thumbnail((self.thumbnail_max_px, self.thumbnail_max_px))
                if self.thumbnail_blur_radius > 0:
                    image = image.filter(ImageFilter.GaussianBlur(self.thumbnail_blur_radius))
                target_dir = self.review_root / self.thumbnail_subdir
                target_dir.mkdir(parents=True, exist_ok=True)
                target = target_dir / f"{path.stem}__id{file_id}.jpg"
                image.save(target, format="JPEG", quality=85)
            return str(target.relative_to(self.review_root)).replace("\\", "/")
        except Exception:
            return ""
