"""Configuration file I/O for On Watch Network Monitor.

This module owns only JSON file loading and atomic JSON file writing.
Application-specific normalization and runtime-state synchronization remain
in app.py until later refactor phases.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def load_json_config(config_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and validate a JSON configuration object from disk."""
    path = Path(config_path)

    with path.open("r", encoding="utf-8") as config_file:
        payload = json.load(config_file)

    if not isinstance(payload, dict):
        raise ValueError(
            f"Configuration root must be a JSON object, not "
            f"{type(payload).__name__}."
        )

    return payload


def atomic_write_json_config(
    config_path: str | os.PathLike[str],
    payload: dict[str, Any],
    *,
    indent: int = 4,
) -> None:
    """Write a JSON configuration object atomically."""
    if not isinstance(payload, dict):
        raise TypeError("Configuration payload must be a dictionary.")

    path = Path(config_path)
    parent = path.parent

    if str(parent) not in {"", "."}:
        parent.mkdir(parents=True, exist_ok=True)

    temp_path = Path(f"{path}.tmp")

    try:
        with temp_path.open("w", encoding="utf-8") as config_file:
            json.dump(payload, config_file, indent=indent)
            config_file.flush()
            os.fsync(config_file.fileno())

        os.replace(temp_path, path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
