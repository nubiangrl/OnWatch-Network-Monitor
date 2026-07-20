"""API routes for On Watch Network Monitor."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, jsonify, request


def register_api_routes(app: Flask) -> None:
    """Register lightweight core API endpoints."""

    @app.route("/api/ping")
    def api_ping():
        return jsonify({
            "status": "ok",
            "version": "Phase 28.7",
        })


def register_topology_intelligence_api_routes(
    app: Flask,
    *,
    relationship_summary: Callable[[], dict[str, Any]],
    root_cause_summary: Callable[[], dict[str, Any]],
    analyze_root_cause: Callable[..., dict[str, Any]],
    infrastructure_payload: Callable[[], dict[str, Any]],
    write_event: Callable[[str], None],
) -> None:
    """Register relationship, root-cause, and infrastructure API routes."""

    @app.route("/api/relationship-engine")
    def api_relationship_engine():
        return jsonify(relationship_summary())

    @app.route("/api/root-cause-topology")
    def api_root_cause_topology():
        try:
            return jsonify(root_cause_summary())
        except Exception as exc:
            write_event(f"ERROR | ROOT CAUSE TOPOLOGY API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.6",
                "message": str(exc),
            }), 500

    @app.route("/api/root-cause-topology/analyze", methods=["POST"])
    def api_root_cause_topology_analyze():
        try:
            body = request.get_json(silent=True) or {}
            return jsonify(analyze_root_cause(
                force=True,
                confirm_immediately=bool(
                    body.get("confirm_immediately", False)
                ),
            ))
        except Exception as exc:
            write_event(f"ERROR | ROOT CAUSE TOPOLOGY ANALYZE API | {exc}")
            return jsonify({
                "success": False,
                "phase": "26B.6",
                "message": str(exc),
            }), 500

    @app.route("/api/network-map-infrastructure")
    def api_network_map_infrastructure():
        try:
            return jsonify(infrastructure_payload())
        except Exception as exc:
            write_event(f"ERROR | PHASE 26 INFRASTRUCTURE MAP | {exc}")
            return jsonify({
                "success": False,
                "message": str(exc),
            }), 500
