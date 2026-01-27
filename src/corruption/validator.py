"""
Format-specific corruption validation and optional repair.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import AppConfig, ensure_directories
from corruption.checker import IntegrityChecker
from database import DatabaseManager
from utils import ResourceMonitor

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

try:
    import fitz
except ImportError:  # pragma: no cover
    fitz = None

try:
    import docx
except ImportError:  # pragma: no cover
    docx = None

try:
    import openpyxl
except ImportError:  # pragma: no cover
    openpyxl = None


@dataclass
class CorruptionValidationStats:
    """Summary of validation and repair results."""

    scanned: int
    corrupted: int
    repaired: int
    errors: int
    report_path: Path


class CorruptionValidator:
    """Validate files and optionally attempt repairs."""

    def __init__(
        self,
        config: AppConfig,
        db_manager: DatabaseManager,
        logger: Optional[logging.Logger] = None,
        monitor: Optional[ResourceMonitor] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger("file_manager")
        self.monitor = monitor
        self.enabled = bool(self.config.get("corruption", "enabled", default=True))
        self.repair_enabled = bool(self.config.get("corruption", "repair_enabled", default=False))
        self.repair_output = self.config.resolve_path(
            "corruption", "repair_output", default=self.config.resolve_path("paths", "staging", default="data/staging")
        )
        self.logs_root = self.config.resolve_path("paths", "logs", default="logs")
        self.max_files = int(self.config.get("corruption", "max_files_per_run", default=0))
        self.checker = IntegrityChecker(logger=self.logger)

    def run(self) -> Optional[CorruptionValidationStats]:
        """Run validation and optional repair, returning stats."""
        if not self.enabled:
            self.logger.info("Corruption validation disabled.")
            return None
        ensure_directories([self.logs_root, self.repair_output])
        scanned = corrupted = repaired = errors = 0
        results = []

        for entry in self.db_manager.iter_inventory(accessible_only=True):
            if self.max_files and scanned >= self.max_files:
                break
            path = Path(entry.file_path)
            if not path.exists():
                continue
            if self.monitor is not None:
                self.monitor.throttle()
            scanned += 1
            if self.db_manager.corruption_exists(entry.file_id):
                continue
            result = self.checker.check(path)
            if result is None:
                continue
            corrupted += 1
            self.db_manager.record_corruption(entry.file_id, result.error_type, result.error_message)
            repair_path = None
            repair_error = ""
            if self.repair_enabled:
                repair_path, repair_error = self._attempt_repair(path)
                if repair_path:
                    repaired += 1
                elif repair_error:
                    errors += 1
            results.append(
                {
                    "file_id": entry.file_id,
                    "file_path": str(path),
                    "error_type": result.error_type,
                    "error_message": result.error_message,
                    "repair_path": str(repair_path) if repair_path else "",
                    "repair_error": repair_error,
                }
            )

        report_path = self.logs_root / f"corruption_validation_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.utcnow().isoformat(),
                    "scanned": scanned,
                    "corrupted": corrupted,
                    "repaired": repaired,
                    "errors": errors,
                    "results": results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return CorruptionValidationStats(
            scanned=scanned,
            corrupted=corrupted,
            repaired=repaired,
            errors=errors,
            report_path=report_path,
        )

    def _attempt_repair(self, path: Path) -> tuple[Optional[Path], str]:
        suffix = path.suffix.lower()
        if suffix in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}:
            return self._repair_image(path)
        if suffix in {".mp4", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".webm"}:
            return self._repair_video(path)
        if suffix in {".pdf"}:
            return self._repair_pdf(path)
        if suffix in {".docx"}:
            return self._repair_docx(path)
        if suffix in {".xlsx", ".xlsm", ".xls"}:
            return self._repair_xlsx(path)
        if suffix in {".zip"}:
            return self._repair_zip(path)
        return None, "unsupported_extension"

    def _repair_image(self, path: Path) -> tuple[Optional[Path], str]:
        if Image is None:
            return None, "pillow_missing"
        try:
            with Image.open(path) as img:
                img.load()
                output = self._repair_output_path(path, suffix_override=path.suffix)
                output.parent.mkdir(parents=True, exist_ok=True)
                img.save(output)
                return output, ""
        except Exception as exc:
            return None, str(exc)

    def _repair_video(self, path: Path) -> tuple[Optional[Path], str]:
        if shutil.which("ffmpeg") is None:
            return None, "ffmpeg_missing"
        output = self._repair_output_path(path, suffix_override=path.suffix)
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["ffmpeg", "-y", "-v", "error", "-i", str(path), "-c", "copy", str(output)],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            if result.returncode != 0:
                return None, result.stderr.strip() or "ffmpeg_failed"
        except Exception as exc:
            return None, str(exc)
        return (output, "") if output.exists() else (None, "ffmpeg_no_output")

    def _repair_pdf(self, path: Path) -> tuple[Optional[Path], str]:
        if fitz is None:
            return None, "pymupdf_missing"
        try:
            doc = fitz.open(path)
            output = self._repair_output_path(path, suffix_override=path.suffix)
            output.parent.mkdir(parents=True, exist_ok=True)
            doc.save(output)
            doc.close()
            return output, ""
        except Exception as exc:
            return None, str(exc)

    def _repair_docx(self, path: Path) -> tuple[Optional[Path], str]:
        if docx is None:
            return None, "python_docx_missing"
        try:
            document = docx.Document(path)
            output = self._repair_output_path(path, suffix_override=path.suffix)
            output.parent.mkdir(parents=True, exist_ok=True)
            document.save(output)
            return output, ""
        except Exception as exc:
            return None, str(exc)

    def _repair_xlsx(self, path: Path) -> tuple[Optional[Path], str]:
        if openpyxl is None:
            return None, "openpyxl_missing"
        try:
            workbook = openpyxl.load_workbook(path, read_only=False, data_only=True)
            output = self._repair_output_path(path, suffix_override=path.suffix)
            output.parent.mkdir(parents=True, exist_ok=True)
            workbook.save(output)
            workbook.close()
            return output, ""
        except Exception as exc:
            return None, str(exc)

    def _repair_zip(self, path: Path) -> tuple[Optional[Path], str]:
        import tempfile
        import zipfile

        try:
            with zipfile.ZipFile(path) as archive:
                with tempfile.TemporaryDirectory() as tmpdir:
                    archive.extractall(tmpdir)
                    output = self._repair_output_path(path, suffix_override=path.suffix)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as out_zip:
                        root_path = Path(tmpdir)
                        for file_path in root_path.rglob("*"):
                            if file_path.is_file():
                                out_zip.write(file_path, file_path.relative_to(root_path))
                    return output, ""
        except Exception as exc:
            return None, str(exc)

    def _repair_output_path(self, path: Path, suffix_override: str) -> Path:
        safe_name = path.stem + "_repaired" + suffix_override
        return self.repair_output / safe_name
