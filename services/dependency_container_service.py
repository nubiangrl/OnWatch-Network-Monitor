"""Validated application dependency container for On Watch Network Monitor."""

from __future__ import annotations

from collections.abc import Iterator, MutableMapping
from typing import Any


CORE_DEPENDENCIES = (
    "app",
    "config",
    "load_config",
    "load_uptime_stats",
    "write_event",
    "monitor_loop",
    "start_monitoring_worker",
    "build_dashboard_context",
    "build_topology_change_summary",
    "build_self_building_topology_summary",
    "build_self_building_topology",
    "check_topology_changes",
    "discover_cdp_neighbors",
    "discover_lldp_neighbors",
    "build_link_confidence_database",
    "_phase26b5_snapshot",
    "_phase26b5_settings",
    "save_config",
    "now",
    "phase27_relationship_engine_summary",
    "build_root_cause_topology_summary",
    "analyze_root_cause_topology",
    "build_phase26_infrastructure_payload",
)


class ApplicationDependencyContainer(MutableMapping[str, Any]):
    """Live, validated mapping over the application's module namespace."""

    def __init__(self, namespace: MutableMapping[str, Any]) -> None:
        self._namespace = namespace

    def __getitem__(self, key: str) -> Any:
        return self._namespace[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._namespace[key] = value

    def __delitem__(self, key: str) -> None:
        del self._namespace[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._namespace)

    def __len__(self) -> int:
        return len(self._namespace)

    def validate(self, required: tuple[str, ...] = CORE_DEPENDENCIES) -> None:
        missing = [name for name in required if name not in self._namespace]
        if missing:
            raise RuntimeError(
                "Application dependency validation failed. Missing: "
                + ", ".join(sorted(missing))
            )


def create_dependency_container(
    namespace: MutableMapping[str, Any],
) -> ApplicationDependencyContainer:
    """Create and validate the live application dependency boundary."""
    container = ApplicationDependencyContainer(namespace)
    container.validate()
    return container
