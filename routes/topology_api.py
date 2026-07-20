"""Topology lifecycle API routes for On Watch Network Monitor."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, jsonify, request


def register_topology_lifecycle_api_routes(
    app: Flask,
    *,
    build_self_building_topology_summary: Callable[[], dict[str, Any]],
    build_self_building_topology: Callable[..., dict[str, Any]],
    build_topology_change_summary: Callable[[], dict[str, Any]],
    check_topology_changes: Callable[..., dict[str, Any]],
    discover_cdp_neighbors: Callable[..., Any],
    discover_lldp_neighbors: Callable[..., Any],
    build_link_confidence_database: Callable[..., Any],
    build_snapshot: Callable[[dict[str, Any]], dict[str, Any]],
    topology_change_settings: Callable[[], dict[str, Any]],
    save_config: Callable[[], None],
    write_event: Callable[[str], None],
    now: Callable[[], str],
    config: dict[str, Any],
) -> None:
    """Register self-building topology and change-detection API routes."""

    @app.route("/api/self-building-topology")
    def api_self_building_topology():
        try:
            return jsonify(build_self_building_topology_summary())
        except Exception as exc:
            write_event(f"ERROR | SELF-BUILDING TOPOLOGY API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.4",
                "message": str(exc),
            }), 500

    @app.route("/api/self-building-topology/rebuild", methods=["POST"])
    def api_self_building_topology_rebuild():
        try:
            payload = build_self_building_topology(force=True)
            return jsonify(payload)
        except Exception as exc:
            write_event(f"ERROR | SELF-BUILDING TOPOLOGY REBUILD API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.4",
                "message": str(exc),
            }), 500

    @app.route("/api/topology-change-detection")
    def api_topology_change_detection():
        try:
            return jsonify(build_topology_change_summary())
        except Exception as exc:
            write_event(f"ERROR | TOPOLOGY CHANGE DETECTION API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.5",
                "message": str(exc),
            }), 500

    @app.route("/api/topology-change-detection/check", methods=["POST"])
    def api_topology_change_detection_check():
        try:
            body = request.get_json(silent=True) or {}
            confirm_immediately = bool(
                body.get("confirm_immediately", False)
            )
            return jsonify(check_topology_changes(
                force=True,
                confirm_immediately=confirm_immediately,
            ))
        except Exception as exc:
            write_event(f"ERROR | TOPOLOGY CHANGE CHECK API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.5",
                "message": str(exc),
            }), 500

    @app.route("/api/topology-change-detection/baseline", methods=["POST"])
    def api_topology_change_detection_baseline():
        try:
            discover_cdp_neighbors(force=True)
            discover_lldp_neighbors(force=True)
            build_link_confidence_database(force=True)

            topology = build_self_building_topology(force=True)
            snapshot = build_snapshot(topology)
            stamp = now()

            config["phase26b5_accepted_snapshot"] = snapshot
            config["phase26b5_pending_change"] = {}

            settings = topology_change_settings()
            settings.update({
                "status": "BASELINE RESET",
                "last_check": stamp,
                "last_reconciliation": stamp,
                "accepted_link_count": len(snapshot.get("links", [])),
                "pending_confirmation_count": 0,
            })

            save_config()
            write_event(
                "CONFIG | TOPOLOGY BASELINE RESET | Phase 26B.5 | "
                f"Links: {len(snapshot.get('links', []))}"
            )

            return jsonify({
                "success": True,
                "phase": "26B.5",
                "status": "BASELINE RESET",
                "snapshot": snapshot,
            })
        except Exception as exc:
            write_event(f"ERROR | TOPOLOGY BASELINE API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.5",
                "message": str(exc),
            }), 500
