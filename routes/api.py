"""Core API routes for On Watch Network Monitor."""

from __future__ import annotations

from flask import Flask, jsonify


def register_api_routes(app: Flask) -> None:
    """Register lightweight core API endpoints."""

    @app.route("/api/ping")
    def api_ping():
        return jsonify({
            "status": "ok",
            "version": "Phase 28.6",
        })
