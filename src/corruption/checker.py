"""
File integrity checks for basic corruption detection.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


MAGIC_SIGNATURES = {
    ".jpg": [b"\xFF\xD8\xFF"],
    ".jpeg": [b"\xFF\xD8\xFF"],
    ".png": [b"\x89PNG\r\n\x1A\n"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".pdf": [b"%PDF"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".docx": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".xlsx": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".pptx": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    ".7z": [b"7z\xBC\xAF\x27\x1C"],
    ".rar": [b"Rar!\x1A\x07\x00", b"Rar!\x1A\x07\x01\x00"],
}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"}
PDF_EXTS = {".pdf"}
DOC_EXTS = {".docx"}
SHEET_EXTS = {".xlsx"}
ZIP_EXTS = {".zip"}
SEVENZ_EXTS = {".7z"}
RAR_EXTS = {".rar"}
VIDEO_EXTS = {".mp4", ".mkv", ".mov", ".avi", ".wmv", ".flv", ".webm"}


@dataclass(frozen=True)
class CorruptionResult:
    """Represents a file integrity failure."""

    file_path: str
    error_type: str
    error_message: str


class IntegrityChecker:
    """Run magic header and format-specific validation checks."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger("file_manager")

    def check(self, path: Path) -> Optional[CorruptionResult]:
        """Return a CorruptionResult if a file fails integrity checks."""
        ext = path.suffix.lower()
        magic_issue = self._check_magic(path, ext)
        if magic_issue is not None:
            return magic_issue

        format_issue = self._check_format(path, ext)
        if format_issue is not None:
            return format_issue

        return None

    def _check_magic(self, path: Path, ext: str) -> Optional[CorruptionResult]:
        if ext not in MAGIC_SIGNATURES:
            return None
        signatures = MAGIC_SIGNATURES[ext]
        max_len = max(len(sig) for sig in signatures)
        try:
            with path.open("rb") as handle:
                header = handle.read(max_len)
        except (OSError, IOError) as exc:
            return CorruptionResult(str(path), "magic_read_error", str(exc))

        for signature in signatures:
            if header.startswith(signature):
                return None
        return CorruptionResult(str(path), "magic_mismatch", f"Header does not match {ext} signature.")

    def _check_format(self, path: Path, ext: str) -> Optional[CorruptionResult]:
        if ext in IMAGE_EXTS:
            return self._check_image(path)
        if ext in PDF_EXTS:
            return self._check_pdf(path)
        if ext in DOC_EXTS:
            return self._check_docx(path)
        if ext in SHEET_EXTS:
            return self._check_xlsx(path)
        if ext in ZIP_EXTS:
            return self._check_zip(path)
        if ext in SEVENZ_EXTS:
            return self._check_7z(path)
        if ext in RAR_EXTS:
            return self._check_rar(path)
        if ext in VIDEO_EXTS:
            return self._check_video(path)
        return None

    def _check_image(self, path: Path) -> Optional[CorruptionResult]:
        try:
            from PIL import Image
        except ImportError:
            self.logger.warning("Pillow not available; skipping image check for %s", path)
            return None
        try:
            with Image.open(path) as img:
                img.verify()
        except Exception as exc:
            return CorruptionResult(str(path), "image_decode_error", str(exc))
        return None

    def _check_pdf(self, path: Path) -> Optional[CorruptionResult]:
        try:
            import fitz
        except ImportError:
            self.logger.warning("PyMuPDF not available; skipping PDF check for %s", path)
            return None
        try:
            doc = fitz.open(path)
            if doc.page_count > 0:
                doc.load_page(0)
            doc.close()
        except Exception as exc:
            return CorruptionResult(str(path), "pdf_open_error", str(exc))
        return None

    def _check_docx(self, path: Path) -> Optional[CorruptionResult]:
        try:
            import docx
        except ImportError:
            self.logger.warning("python-docx not available; skipping docx check for %s", path)
            return None
        try:
            docx.Document(path)
        except Exception as exc:
            return CorruptionResult(str(path), "docx_open_error", str(exc))
        return None

    def _check_xlsx(self, path: Path) -> Optional[CorruptionResult]:
        try:
            import openpyxl
        except ImportError:
            self.logger.warning("openpyxl not available; skipping xlsx check for %s", path)
            return None
        try:
            workbook = openpyxl.load_workbook(path, read_only=True)
            workbook.close()
        except Exception as exc:
            return CorruptionResult(str(path), "xlsx_open_error", str(exc))
        return None

    def _check_zip(self, path: Path) -> Optional[CorruptionResult]:
        import zipfile

        try:
            with zipfile.ZipFile(path) as archive:
                bad_file = archive.testzip()
            if bad_file:
                return CorruptionResult(str(path), "zip_integrity_error", f"Corrupt member: {bad_file}")
        except Exception as exc:
            return CorruptionResult(str(path), "zip_open_error", str(exc))
        return None

    def _check_7z(self, path: Path) -> Optional[CorruptionResult]:
        try:
            import py7zr
        except ImportError:
            self.logger.warning("py7zr not available; skipping 7z check for %s", path)
            return None
        try:
            with py7zr.SevenZipFile(path, mode="r") as archive:
                archive.test()
        except Exception as exc:
            return CorruptionResult(str(path), "7z_integrity_error", str(exc))
        return None

    def _check_rar(self, path: Path) -> Optional[CorruptionResult]:
        try:
            import rarfile
        except ImportError:
            self.logger.warning("rarfile not available; skipping rar check for %s", path)
            return None
        try:
            with rarfile.RarFile(path) as archive:
                archive.testrar()
        except Exception as exc:
            return CorruptionResult(str(path), "rar_integrity_error", str(exc))
        return None

    def _check_video(self, path: Path) -> Optional[CorruptionResult]:
        if shutil.which("ffprobe") is None:
            self.logger.warning("ffprobe not available; skipping video check for %s", path)
            return None
        try:
            result = subprocess.run(
                ["ffprobe", "-v", "error", "-show_format", "-show_streams", str(path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except Exception as exc:
            return CorruptionResult(str(path), "ffprobe_error", str(exc))

        if result.returncode != 0:
            return CorruptionResult(str(path), "video_probe_error", result.stderr.strip())
        return None
