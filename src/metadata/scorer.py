"""
Metadata richness scoring for files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

try:
    import fitz  # PyMuPDF
except ImportError:  # pragma: no cover
    fitz = None

try:
    from docx import Document
except ImportError:  # pragma: no cover
    Document = None

try:
    import openpyxl
except ImportError:  # pragma: no cover
    openpyxl = None


@dataclass
class MetadataScorer:
    """Score files based on available embedded metadata."""

    cache: dict[Path, int] = field(default_factory=dict)

    image_extensions: set[str] = field(
        default_factory=lambda: {
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
    )
    pdf_extensions: set[str] = field(default_factory=lambda: {".pdf"})
    doc_extensions: set[str] = field(default_factory=lambda: {".docx"})
    sheet_extensions: set[str] = field(default_factory=lambda: {".xlsx", ".xlsm", ".xls"})

    def score(self, path: Path) -> int:
        """Return a metadata richness score for a file."""
        cached = self.cache.get(path)
        if cached is not None:
            return cached
        score = 0
        suffix = path.suffix.lower()
        if suffix in self.image_extensions:
            score = self._score_image(path)
        elif suffix in self.pdf_extensions:
            score = self._score_pdf(path)
        elif suffix in self.doc_extensions:
            score = self._score_docx(path)
        elif suffix in self.sheet_extensions:
            score = self._score_sheet(path)
        self.cache[path] = score
        return score

    def _score_image(self, path: Path) -> int:
        if Image is None:
            return 0
        try:
            with Image.open(path) as image:
                exif = image.getexif()
                if exif:
                    return len(exif)
        except Exception:
            return 0
        return 0

    def _score_pdf(self, path: Path) -> int:
        if fitz is None:
            return 0
        try:
            doc = fitz.open(path)
            metadata = doc.metadata or {}
            doc.close()
            return sum(1 for value in metadata.values() if value)
        except Exception:
            return 0

    def _score_docx(self, path: Path) -> int:
        if Document is None:
            return 0
        try:
            document = Document(path)
            props = document.core_properties
            values = [
                props.title,
                props.subject,
                props.author,
                props.category,
                props.comments,
                props.keywords,
                props.last_modified_by,
                props.revision,
            ]
            return sum(1 for value in values if value)
        except Exception:
            return 0

    def _score_sheet(self, path: Path) -> int:
        if openpyxl is None:
            return 0
        try:
            workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
            props = workbook.properties
            values = [
                props.title,
                props.subject,
                props.creator,
                props.description,
                props.keywords,
                props.lastModifiedBy,
            ]
            workbook.close()
            return sum(1 for value in values if value)
        except Exception:
            return 0
