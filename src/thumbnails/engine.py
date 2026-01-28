"""
Thumbnail detection and cleanup engine.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import AppConfig, ensure_directories
from database import DatabaseManager
from utils import ActivityTracker, ResourceMonitor

try:
    from PIL import Image
except ImportError:  # pragma: no cover - optional dependency
    Image = None


_DIMENSION_PATTERN = re.compile(r"(?P<w>\d{2,4})x(?P<h>\d{2,4})", re.IGNORECASE)


@dataclass
class ThumbnailReportStats:
    """Summary statistics for thumbnail detection."""

    report_path: Path
    candidate_count: int
    skipped_missing: int


@dataclass
class ThumbnailApplyStats:
    """Summary statistics for thumbnail cleanup."""

    report_path: Path
    result_path: Path
    moved: int
    deleted: int
    skipped: int
    errors: int


class ThumbnailCleanupEngine:
    """Detect and optionally clean up likely thumbnail images."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
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

        self.enabled = bool(self.config.get("thumbnails", "enabled", default=True))
        self.apply_cleanup = bool(self.config.get("thumbnails", "apply_cleanup", default=False))
        self.report_prefix = str(
            self.config.get("thumbnails", "report_prefix", default="thumbnail_report")
        )
        self.result_prefix = str(
            self.config.get("thumbnails", "result_prefix", default="thumbnail_cleanup")
        )
        self.action = str(self.config.get("thumbnails", "action", default="move")).lower()
        self.quarantine_root = self.config.resolve_path(
            "thumbnails", "quarantine_path", default="F:/Thumbnails_to_delete"
        )
        self.progress_log_interval = int(
            self.config.get("thumbnails", "progress_log_interval", default=10000)
        )
        self.max_size_bytes = int(
            self.config.get("thumbnails", "max_size_bytes", default=1_048_576)
        )
        self.max_dimension_px = int(
            self.config.get("thumbnails", "max_dimension_px", default=512)
        )
        self.image_extensions = {
            ext.lower()
            for ext in self.config.get(
                "thumbnails",
                "image_extensions",
                default=[
                    ".jpg",
                    ".jpeg",
                    ".png",
                    ".gif",
                    ".bmp",
                    ".webp",
                    ".tif",
                    ".tiff",
                    ".heic",
                    ".heif",
                ],
            )
        }
        self.name_markers = {
            marker.lower()
            for marker in self.config.get(
                "thumbnails",
                "name_markers",
                default=["thumb", "thumbnail", "preview", "tbn", "tn"],
            )
        }
        self.dir_markers = {
            marker.lower()
            for marker in self.config.get(
                "thumbnails",
                "directory_markers",
                default=["thumbs", "thumbnails", ".thumbnails", "previews", "preview"],
            )
        }
        self.cover_markers = {
            marker.lower()
            for marker in self.config.get(
                "thumbnails",
                "cover_name_markers",
                default=[
                    "cover",
                    "folder",
                    "front",
                    "album",
                    "albumart",
                    "artwork",
                    "poster",
                    "booklet",
                ],
            )
        }
        self.cover_audio_extensions = {
            ext.lower()
            for ext in self.config.get(
                "thumbnails",
                "cover_audio_extensions",
                default=[
                    ".mp3",
                    ".flac",
                    ".wav",
                    ".aac",
                    ".m4a",
                    ".ogg",
                    ".wma",
                    ".alac",
                    ".aiff",
                    ".ape",
                ],
            )
        }
        self.cover_doc_extensions = {
            ext.lower()
            for ext in self.config.get(
                "thumbnails",
                "cover_doc_extensions",
                default=[
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
                    ".epub",
                    ".mobi",
                    ".azw",
                    ".azw3",
                    ".cbz",
                    ".cbr",
                ],
            )
        }
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")
        self._cover_dir_cache: dict[Path, tuple[bool, bool]] = {}

    def run(self) -> Optional[ThumbnailReportStats]:
        """Run thumbnail detection and optional cleanup."""
        if not self.enabled:
            self.logger.info("Thumbnail cleanup disabled.")
            return None

        stats = self.build_report()
        self.logger.info(
            "Thumbnail report generated. Candidates=%s Report=%s",
            stats.candidate_count,
            stats.report_path,
        )
        self._maybe_apply_cleanup(stats.report_path)
        return stats

    def build_report(self) -> ThumbnailReportStats:
        """Scan inventory for thumbnail candidates and emit a JSON report."""
        ensure_directories([self.logs_root])
        candidates = []
        skipped_missing = 0
        total_inventory = None
        try:
            total_inventory = self.db_manager.count_inventory(accessible_only=True)
        except Exception:
            total_inventory = None

        for index, entry in enumerate(self.db_manager.iter_inventory(accessible_only=True), start=1):
            path = Path(entry.file_path)
            if not path.exists():
                skipped_missing += 1
                continue
            if self.monitor is not None:
                self.monitor.throttle()
            self._touch("thumbnails_report", index, interval=500)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                total_label = total_inventory if total_inventory is not None else "?"
                self.logger.info(
                    "Thumbnail scan progress: %s/%s candidates=%s skipped_missing=%s",
                    index,
                    total_label,
                    len(candidates),
                    skipped_missing,
                )
            candidate = self._evaluate_candidate(path, entry.size, entry.file_id)
            if candidate is not None:
                candidates.append(candidate)

        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "candidate_count": len(candidates),
            "skipped_missing": skipped_missing,
            "max_size_bytes": self.max_size_bytes,
            "max_dimension_px": self.max_dimension_px,
            "candidates": candidates,
        }
        report_path = self.logs_root / f"{self.report_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return ThumbnailReportStats(
            report_path=report_path,
            candidate_count=len(candidates),
            skipped_missing=skipped_missing,
        )

    def apply_report(self, report_path: Path) -> ThumbnailApplyStats:
        """Move or delete thumbnail candidates listed in the report."""
        report_data = json.loads(report_path.read_text(encoding="utf-8"))
        candidates = report_data.get("candidates", [])
        moved = deleted = skipped = errors = 0
        results = []
        total_candidates = len(candidates)
        operation_id = f"thumbnail_cleanup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        if self.action == "move":
            ensure_directories([self.quarantine_root, self.logs_root])

        for index, candidate in enumerate(candidates, start=1):
            file_path = Path(candidate.get("file_path", ""))
            if not file_path.exists():
                skipped += 1
                results.append(self._result_entry(candidate, "skipped", "missing"))
                continue
            if file_path.is_symlink():
                skipped += 1
                results.append(self._result_entry(candidate, "skipped", "symlink"))
                continue
            if self.monitor is not None:
                self.monitor.throttle()
            self._touch("thumbnails_apply", index, interval=200)
            if self.progress_log_interval > 0 and index % self.progress_log_interval == 0:
                self.logger.info(
                    "Thumbnail cleanup progress: %s/%s moved=%s deleted=%s skipped=%s errors=%s",
                    index,
                    total_candidates,
                    moved,
                    deleted,
                    skipped,
                    errors,
                )
            try:
                if self.action == "move":
                    destination = self._build_destination(file_path, candidate.get("file_id", ""))
                    destination = self._resolve_conflict(destination)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source_size = file_path.stat().st_size
                    shutil.move(file_path, destination)
                    if not destination.exists() or destination.stat().st_size != source_size:
                        raise OSError("move_validation_failed")
                    file_id = candidate.get("file_id")
                    if file_id:
                        self.db_manager.update_file_path(int(file_id), str(destination))
                    moved += 1
                    results.append(self._result_entry(candidate, "moved", "ok"))
                    self.movement_logger.info("Thumbnail moved: %s -> %s", file_path, destination)
                    self.db_manager.record_file_operation(
                        operation_id,
                        action="move",
                        source_path=str(file_path),
                        destination_path=str(destination),
                        status="completed",
                        size=source_size,
                        rollback={"action": "move", "source": str(destination), "destination": str(file_path)},
                    )
                else:
                    file_path.unlink()
                    deleted += 1
                    self.db_manager.delete_file_by_path(str(file_path))
                    results.append(self._result_entry(candidate, "deleted", "ok"))
                    self.movement_logger.info("Thumbnail deleted: %s", file_path)
                    self.db_manager.record_file_operation(
                        operation_id,
                        action="delete",
                        source_path=str(file_path),
                        destination_path=None,
                        status="completed",
                        size=None,
                    )
            except Exception as exc:
                errors += 1
                results.append(self._result_entry(candidate, "error", str(exc)))
                self.movement_logger.error("Thumbnail cleanup failed: %s (%s)", file_path, exc)

        result = {
            "executed_at": datetime.utcnow().isoformat(),
            "report_path": str(report_path),
            "summary": {"moved": moved, "deleted": deleted, "skipped": skipped, "errors": errors},
            "results": results,
        }
        result_path = self.logs_root / f"{self.result_prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        return ThumbnailApplyStats(
            report_path=report_path,
            result_path=result_path,
            moved=moved,
            deleted=deleted,
            skipped=skipped,
            errors=errors,
        )

    def _evaluate_candidate(self, path: Path, size: int, file_id: int) -> Optional[dict]:
        if path.suffix.lower() not in self.image_extensions:
            return None

        stem = path.stem.lower()
        reasons = []
        marker = self._match_dir_marker(path)
        if marker:
            reasons.append(f"dir_marker:{marker}")

        name_marker = self._match_name_marker(stem)
        if name_marker:
            reasons.append(f"name_marker:{name_marker}")

        name_dimensions = self._dimensions_from_name(stem)
        if name_dimensions:
            reasons.append(f"name_dimensions:{name_dimensions[0]}x{name_dimensions[1]}")

        if not reasons:
            return None

        if self._is_cover_image(path):
            return None

        size_ok = size > 0 and size <= self.max_size_bytes
        dimension_ok = False
        width = height = None

        if name_dimensions:
            dimension_ok = max(name_dimensions) <= self.max_dimension_px
        elif not size_ok and self.max_dimension_px > 0:
            width, height = self._read_dimensions(path)
            if width is not None and height is not None:
                dimension_ok = max(width, height) <= self.max_dimension_px

        if not (size_ok or dimension_ok):
            return None

        if size_ok:
            reasons.append("size_threshold")
        if dimension_ok:
            reasons.append("dimension_threshold")

        return {
            "file_id": file_id,
            "file_path": str(path),
            "size": size,
            "width": width,
            "height": height,
            "reasons": reasons,
        }

    def _match_dir_marker(self, path: Path) -> str | None:
        for part in path.parent.parts:
            part_lower = part.lower()
            for marker in self.dir_markers:
                if marker and marker in part_lower:
                    return marker
        return None

    def _match_name_marker(self, stem: str) -> str | None:
        tokens = self._tokenize(stem)
        for marker in self.name_markers:
            if marker in tokens:
                return marker
        for marker in self.name_markers:
            if len(marker) >= 4 and marker in stem:
                return marker
        return None

    def _dimensions_from_name(self, stem: str) -> tuple[int, int] | None:
        match = _DIMENSION_PATTERN.search(stem)
        if not match:
            return None
        return int(match.group("w")), int(match.group("h"))

    def _tokenize(self, value: str) -> list[str]:
        return [token for token in re.split(r"[^a-z0-9]+", value) if token]

    def _read_dimensions(self, path: Path) -> tuple[Optional[int], Optional[int]]:
        if Image is None:
            return None, None
        try:
            with Image.open(path) as image:
                width, height = image.size
            return int(width), int(height)
        except Exception:
            return None, None

    def _is_cover_image(self, path: Path) -> bool:
        stem_tokens = set(self._tokenize(path.stem.lower()))
        if not stem_tokens.intersection(self.cover_markers):
            return False
        has_audio, has_docs = self._dir_contains_media_or_docs(path.parent)
        return has_audio or has_docs

    def _dir_contains_media_or_docs(self, directory: Path) -> tuple[bool, bool]:
        cached = self._cover_dir_cache.get(directory)
        if cached is not None:
            return cached
        has_audio = False
        has_docs = False
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not entry.is_file():
                        continue
                    ext = Path(entry.name).suffix.lower()
                    if ext in self.cover_audio_extensions:
                        has_audio = True
                    if ext in self.cover_doc_extensions:
                        has_docs = True
                    if has_audio or has_docs:
                        break
        except OSError:
            pass
        self._cover_dir_cache[directory] = (has_audio, has_docs)
        return has_audio, has_docs

    def _maybe_apply_cleanup(self, report_path: Path) -> None:
        confirmed = os.environ.get("FILE_MANAGER_APPLY_THUMBNAIL_CLEANUP", "").lower() in {
            "1",
            "true",
            "yes",
        }
        legacy_confirm = os.environ.get("FILE_MANAGER_DELETE_THUMBNAILS", "").lower() in {"1", "true", "yes"}
        require_confirmation = bool(
            self.config.get("safety", "require_approval_for_deletion", default=True)
        )
        if not self.apply_cleanup and not (confirmed or legacy_confirm):
            self.logger.info(
                "Thumbnail cleanup not applied. Set FILE_MANAGER_APPLY_THUMBNAIL_CLEANUP=1 to apply."
            )
            return
        if require_confirmation and not (confirmed or legacy_confirm):
            self.logger.warning("Thumbnail cleanup confirmation required. Skipping cleanup.")
            return
        stats = self.apply_report(report_path)
        self.logger.info(
            "Thumbnail cleanup complete. Moved=%s Deleted=%s Skipped=%s Errors=%s Result=%s",
            stats.moved,
            stats.deleted,
            stats.skipped,
            stats.errors,
            stats.result_path,
        )

    def _result_entry(self, candidate: dict, status: str, message: str) -> dict:
        return {
            "file_path": candidate.get("file_path"),
            "status": status,
            "message": message,
        }

    def _touch(self, note: str, count: int, interval: int = 200) -> None:
        if self.activity_tracker is None:
            return
        if count % interval == 0:
            self.activity_tracker.touch(note)

    def _build_destination(self, source_path: Path, file_id: str | int) -> Path:
        encoded_parent = self._encode_path(str(source_path.parent))
        destination_dir = self.quarantine_root / encoded_parent
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
