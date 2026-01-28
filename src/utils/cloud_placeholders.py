"""
Detect cloud placeholder files on Windows (OneDrive/iCloud/etc.).
"""

from __future__ import annotations

import os
from pathlib import Path


# Windows file attribute flags
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000


def is_cloud_placeholder(path: Path) -> bool:
    """Return True if a path looks like a cloud placeholder (Windows only)."""
    if os.name != "nt":
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    attrs = getattr(stat, "st_file_attributes", 0)
    if attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS:
        return True
    if attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN:
        return True
    if (attrs & FILE_ATTRIBUTE_OFFLINE) and (attrs & FILE_ATTRIBUTE_REPARSE_POINT):
        return True
    return False
