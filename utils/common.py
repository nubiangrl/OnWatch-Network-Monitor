"""Shared utility helpers for On Watch Network Monitor.

Phase 28.2 extracts dependency-free helpers from the legacy monolithic app.py.
"""

from datetime import datetime
from typing import Any


def now() -> str:
    """Return the current local timestamp in the application's standard format."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def clean_ascii(value: Any) -> str:
    """Convert a value to a trimmed ASCII-safe string."""
    if value is None:
        return ""

    text = str(value)
    text = text.replace("\\xa0", " ")
    return text.encode("ascii", "ignore").decode("ascii").strip()

