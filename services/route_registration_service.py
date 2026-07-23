"""Central route registration and dependency wiring for On Watch Network Monitor."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import jsonify

from routes.api import (
    register_api_routes,
    register_topology_intelligence_api_routes,
)
from routes.dashboard import register_dashboard_routes
from routes.topology_api import register_topology_lifecycle_api_routes


def _require(namespace: Mapping[str, Any], name: str) -> Any:
    """Return one required dependency with a clear startup error when absent."""
    try:
        return namespace[name]
    except KeyError as exc:
        raise RuntimeError(
            f"Missing route-registration dependency: {name}"
        ) from exc


def register_application_routes(app: Any, namespace: Mapping[str, Any]) -> None:
    """Register all modular routes using one explicit dependency container."""
    register_dashboard_routes(
        app,
        _require(namespace, "build_dashboard_context"),
    )

    register_api_routes(app)

    build_topology_change_summary = _require(
        namespace,
        "build_topology_change_summary",
    )

    def topology_change_summary_compatibility() -> Any:
        return jsonify(build_topology_change_summary())

    app.add_url_rule(
        "/api/topology-change-summary",
        endpoint="api_topology_change_summary",
        view_func=topology_change_summary_compatibility,
        methods=["GET"],
    )

    register_topology_lifecycle_api_routes(
        app,
        build_self_building_topology_summary=_require(
            namespace,
            "build_self_building_topology_summary",
        ),
        build_self_building_topology=_require(
            namespace,
            "build_self_building_topology",
        ),
        build_topology_change_summary=build_topology_change_summary,
        check_topology_changes=_require(namespace, "check_topology_changes"),
        discover_cdp_neighbors=_require(namespace, "discover_cdp_neighbors"),
        discover_lldp_neighbors=_require(namespace, "discover_lldp_neighbors"),
        build_link_confidence_database=_require(
            namespace,
            "build_link_confidence_database",
        ),
        build_snapshot=_require(namespace, "_phase26b5_snapshot"),
        topology_change_settings=_require(namespace, "_phase26b5_settings"),
        save_config=_require(namespace, "save_config"),
        write_event=_require(namespace, "write_event"),
        now=_require(namespace, "now"),
        config=_require(namespace, "config"),
    )

    register_topology_intelligence_api_routes(
        app,
        relationship_summary=_require(
            namespace,
            "phase27_relationship_engine_summary",
        ),
        root_cause_summary=_require(
            namespace,
            "build_root_cause_topology_summary",
        ),
        analyze_root_cause=_require(
            namespace,
            "analyze_root_cause_topology",
        ),
        infrastructure_payload=_require(
            namespace,
            "build_phase26_infrastructure_payload",
        ),
        write_event=_require(namespace, "write_event"),
    )
