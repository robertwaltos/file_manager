"""
Duplicate detection utilities.
"""

from .engine import DuplicateEngine, DuplicateStats
from .plan import DuplicateApplyStats, DuplicatePlanEngine, DuplicatePlanStats

__all__ = [
    "DuplicateApplyStats",
    "DuplicateEngine",
    "DuplicatePlanEngine",
    "DuplicatePlanStats",
    "DuplicateStats",
]
