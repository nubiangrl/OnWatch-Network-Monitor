"""Application bootstrap and service wiring for On Watch Network Monitor."""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any


def run_application(namespace: MutableMapping[str, Any]) -> None:
    """Initialize application services, start workers, and launch Flask."""
    os_module = namespace["os"]
    app = namespace["app"]

    os_module.makedirs("logs", exist_ok=True)
    namespace["load_config"]()
    namespace["load_uptime_stats"]()

    devices = namespace["DEVICES"]
    status = namespace["status"]
    previous_status = namespace["previous_status"]

    for name, ip_address in devices.items():
        status[name] = {
            "ip": ip_address,
            "state": "CHECKING",
            "latency": "N/A",
            "last_checked": "Starting...",
            "last_change": "Starting...",
        }
        previous_status[name] = None

    write_event = namespace["write_event"]
    write_event("SYSTEM | Network Monitor Dashboard started")

    if namespace["RELATIONSHIP_ENGINE_READY"]:
        relationship_store = namespace["RELATIONSHIP_STORE"]
        relationship_count = relationship_store.count() if relationship_store else 0
        write_event(
            "SYSTEM | PHASE 27B RELATIONSHIP ENGINE READY | "
            f"Relationships: {relationship_count}"
        )
    else:
        write_event(
            "WARNING | PHASE 27B RELATIONSHIP ENGINE NOT READY | "
            f"{namespace['RELATIONSHIP_MIGRATION']}"
        )

    namespace["build_link_confidence_database"](force=True)
    namespace["rebuild_auto_infrastructure_links"]()
    namespace["build_self_building_topology"](force=True)
    namespace["check_topology_changes"](force=True)
    namespace["analyze_root_cause_topology"](force=True)

    namespace["start_monitoring_worker"](namespace["monitor_loop"])

    app.run(host="0.0.0.0", port=5050)
