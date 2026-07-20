"""Dashboard page routes for On Watch Network Monitor."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from flask import Flask, render_template


def register_dashboard_routes(
    app: Flask,
    build_dashboard_context: Callable[[], dict[str, Any]],
) -> None:
    """Register the primary dashboard page routes."""

    @app.route("/")
    def dashboard():
        context = build_dashboard_context()
        return render_template("dashboard.html", **context)

    @app.route("/operations")
    def operations_page():
        context = build_dashboard_context()
        return render_template("operations.html", **context)

    @app.route("/provisioning")
    def provisioning_page():
        context = build_dashboard_context()
        return render_template("provisioning.html", **context)

    @app.route("/analytics")
    def analytics_page():
        context = build_dashboard_context()
        return render_template("analytics.html", **context)

    @app.route("/noc-tools")
    def noc_tools_page():
        context = build_dashboard_context()
        return render_template("noc_tools.html", **context)
