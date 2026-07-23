"""Background worker and scheduler helpers for On Watch Network Monitor."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any


def start_background_worker(
    target: Callable[..., Any],
    *,
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    name: str | None = None,
    daemon: bool = True,
    start: bool = True,
) -> threading.Thread:
    """Create and optionally start a consistently configured background worker."""
    worker = threading.Thread(
        target=target,
        args=args,
        kwargs=kwargs or {},
        name=name,
        daemon=daemon,
    )
    if start:
        worker.start()
    return worker


def start_monitoring_worker(target: Callable[[], Any]) -> threading.Thread:
    """Start the primary monitoring engine worker."""
    return start_background_worker(
        target,
        name="onwatch-monitoring-engine",
        daemon=True,
    )


def start_restore_worker(
    target: Callable[..., Any],
    filename: str,
    requested_by: str,
) -> threading.Thread:
    """Start one asynchronous restore worker."""
    return start_background_worker(
        target,
        args=(filename, requested_by),
        name="onwatch-restore-worker",
        daemon=True,
    )


def refresh_ieee_oui_cache_background(namespace):
    try:
        namespace['refresh_ieee_oui_cache'](force=False)
    finally:
        with namespace['IEEE_OUI_LOCK']:
            namespace['IEEE_OUI_REFRESH_THREAD'] = None

def schedule_ieee_oui_refresh_if_needed(namespace):
    needs_refresh = any((namespace['_ieee_cache_needs_refresh'](os.path.join(namespace['IEEE_OUI_CACHE_DIR'], filename)) for _, _, filename in namespace['IEEE_OUI_REGISTRIES']))
    if not needs_refresh:
        return
    with namespace['IEEE_OUI_LOCK']:
        if namespace['IEEE_OUI_REFRESH_THREAD'] and namespace['IEEE_OUI_REFRESH_THREAD'].is_alive():
            return
        namespace['IEEE_OUI_REFRESH_THREAD'] = start_background_worker(target=lambda: refresh_ieee_oui_cache_background(namespace), name='ieee-oui-refresh', daemon=True, start=False)
        namespace['IEEE_OUI_REFRESH_THREAD'].start()
