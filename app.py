from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from ping3 import ping
from datetime import datetime, timedelta
import threading
import time
import json
import os
import subprocess
import socket
import shutil
import tempfile
import tarfile
import ipaddress
import re
import csv
import io
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
import smtplib
from email.message import EmailMessage
from utils.common import clean_ascii, now
from utils.time_helpers import (
    calculate_alert_duration,
    calculate_overlap_seconds,
    format_duration_seconds,
    format_time_ago,
    parse_timestamp,
)
from services.config_service import (
    atomic_write_json_config,
    load_json_config,
)
from services.device_service import (
    get_map_icon,
    get_map_status_class,
    is_lan_ip,
    normalize_mac_address,
    validate_ip,
)
from services.snmp_service import (
    _snmp_value_from_line,
    is_snmp_noise_event,
    is_usable_snmp_interface,
    parse_snmpwalk_oid_integer_map,
    run_snmpwalk_oid_readonly,
    run_snmpwalk_readonly,
)
from services.relationship_service import (
    _relationship_state_details,
    get_dependency_icon,
    normalize_relationship_entry,
)
from services.monitoring_service import (
    check_device,
    get_device_down_minutes,
    parse_latency_ms,
    status_number_to_text,
)
from services.alert_service import (
    alert_id,
    event_age_bucket,
    event_age_weight,
    get_event_log_lines,
    get_event_severity_weight,
    load_alert_history,
    normalize_alert_severity,
    normalize_event_device_name,
    normalize_transition_key,
    parse_event_timestamp_from_line,
    read_recent_events,
    save_alert_history,
    write_event,
)
from services.discovery_service import (
    _cdp_oid_suffix,
    _decode_cdp_address,
    _lldp_local_oid_suffix,
    _lldp_remote_oid_suffix,
    _parse_cdp_walk,
    _parse_lldp_local_walk,
    _parse_lldp_remote_walk,
    _stable_discovered_link_id,
    _stable_lldp_link_id,
)
from services.infrastructure_service import (
    AUTO_INFRASTRUCTURE_LINK_SOURCE,
    LEGACY_AUTO_INFRASTRUCTURE_LINK_SOURCES,
    _infrastructure_registry_order,
    _infrastructure_role_rank,
    _is_explicit_saved_infrastructure_link,
    _is_generated_infrastructure_link,
    _stable_auto_infrastructure_link_id,
    is_snmp_capable_infrastructure_role,
    normalize_infrastructure_role,
)
from services.topology_builder_service import (
    _confidence_physical_key,
    _phase26b5_snapshot_key,
    get_core_topology_type_names,
)
from routes.dashboard import register_dashboard_routes
from routes.api import (
    register_api_routes,
    register_topology_intelligence_api_routes,
)
from routes.topology_api import register_topology_lifecycle_api_routes



# ======================================================
# PHASE 27A - AUTHORITATIVE RELATIONSHIP ENGINE
# ======================================================
try:
    from relationship_engine import (
        initialize_relationship_engine,
        serialize_relationships_for_legacy_projection,
    )
    RELATIONSHIP_ENGINE_IMPORT_ERROR = None
except Exception as relationship_engine_import_error:
    initialize_relationship_engine = None
    serialize_relationships_for_legacy_projection = None
    RELATIONSHIP_ENGINE_IMPORT_ERROR = relationship_engine_import_error

# ======================================================
# PHASE 12C.2 - REMOTE RESTORE ENGINE IMPORTS
# ======================================================
try:
    from remote_restore_engine import (
        get_remote_restore_config,
        get_remote_servers,
        get_remote_groups,
        load_remote_deployment_history,
        test_remote_server_connection,
        test_remote_group_connections,
        deploy_backup_to_remote_targets,
        build_remote_restore_summary
    )
except Exception as remote_restore_import_error:
    get_remote_restore_config = None
    get_remote_servers = None
    get_remote_groups = None
    load_remote_deployment_history = None
    test_remote_server_connection = None
    test_remote_group_connections = None
    deploy_backup_to_remote_targets = None
    build_remote_restore_summary = None


app = Flask(__name__)

# PHASE 26B.7G - FULL HARD-CODED INFRASTRUCTURE REMOVAL
# Device identity, role, topology placement, and interface choices are data-driven.

CONFIG_FILE = "config.json"
EVENT_LOG = "logs/events.log"
CISCO_LOG_FILE = "/var/log/cisco/cisco.log"
KNOWLEDGE_BASE_FILE = "data/knowledge_base.json"
ALERTS_FILE = "data/alerts.json"
PROVISIONING_AUDIT_FILE = "data/provisioning_audit.json"
UPTIME_STATS_FILE = "data/uptime_stats.json"
INTERNET_HISTORY_FILE = "data/internet_uptime_history.json"
BACKUP_DIR = os.path.expanduser("~/backups")
RESTORE_AUDIT_FILE = "data/restore_audit.json"
RESTORE_STATUS_FILE = "data/restore_status.json"
PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))

# PHASE 26B.7G: Interface and port choices are populated exclusively from SNMP discovery.

config = {}
DEVICES = {}
CHECK_INTERVAL = 15
SNMP_COMMUNITY = "public"
ROUTER_IP = ""
SWITCH_IP = ""
SWITCH_PORTS = {}
ROUTER_MONITORED_INTERFACES = []
DEVICE_TYPES = {}
DEVICE_RELATIONSHIPS = {}
RELATIONSHIP_STORE = None
RELATIONSHIP_MANAGER = None
RELATIONSHIP_MIGRATION = {}
RELATIONSHIP_ENGINE_READY = False
INFRASTRUCTURE = {}
INFRASTRUCTURE_DEVICES = {}
SLEEP_DETECTION = {}

status = {}
previous_status = {}

router_interfaces = {}
switch_links = {}

previous_router_interfaces = {}
previous_switch_links = {}

last_full_scan = "Starting..."
total_alerts = 0
total_recoveries = 0

INTERNET_CHECK_TARGETS = []
previous_internet_outage_state = None

# PHASE 16A.2B - INFRASTRUCTURE DISCOVERY ENGINE STATE
INFRASTRUCTURE_INTERFACE_INVENTORY = {}
INFRASTRUCTURE_DISCOVERY_INTERVAL = 300
LAST_INFRASTRUCTURE_DISCOVERY = 0

# PHASE 26B.1 - CDP NEIGHBOR DISCOVERY + DISCOVERED LINK DATABASE
CDP_DISCOVERY_INTERVAL = 60
LAST_CDP_DISCOVERY = 0
CDP_DISCOVERY_LOCK = threading.Lock()

# PHASE 26B.2 - LLDP NEIGHBOR DISCOVERY
LLDP_DISCOVERY_INTERVAL = 60
LAST_LLDP_DISCOVERY = 0
LLDP_DISCOVERY_LOCK = threading.Lock()

# PHASE 12B.5.3 - ALERT STATE TRANSITION ENGINE
# Stores recent alert/recovery transitions so Smart Refresh and Voice Alerts
# can react to NEW events instead of only seeing the current steady state.
ALERT_TRANSITION_LOCK = threading.Lock()
ALERT_TRANSITION_EVENTS = []
ACTIVE_ALERT_TRANSITION_KEYS = set()
ALERT_TRANSITION_SEQUENCE = 0





def initialize_phase27_relationship_engine():
    """Initialize Phase 27A without breaking legacy relationship consumers."""
    global RELATIONSHIP_STORE, RELATIONSHIP_MANAGER
    global RELATIONSHIP_MIGRATION, RELATIONSHIP_ENGINE_READY

    RELATIONSHIP_STORE = None
    RELATIONSHIP_MANAGER = None
    RELATIONSHIP_MIGRATION = {}
    RELATIONSHIP_ENGINE_READY = False

    if initialize_relationship_engine is None:
        config.setdefault("relationship_engine", {}).update({
            "phase": "27C.1",
            "ready": False,
            "import_error": clean_ascii(RELATIONSHIP_ENGINE_IMPORT_ERROR),
            "updated_at": now(),
        })
        return False

    try:
        (
            RELATIONSHIP_STORE,
            RELATIONSHIP_MANAGER,
            RELATIONSHIP_MIGRATION,
        ) = initialize_relationship_engine(
            config,
            config_path=CONFIG_FILE,
            autosave=False,
            migrate_legacy=True,
        )
        RELATIONSHIP_ENGINE_READY = True
        config.setdefault("relationship_engine", {}).update({
            "phase": "27C.1",
            "ready": True,
            "engine_version": RELATIONSHIP_MIGRATION.get("engine_version", ""),
            "relationship_count": RELATIONSHIP_MIGRATION.get(
                "relationship_count",
                RELATIONSHIP_STORE.count() if RELATIONSHIP_STORE else 0,
            ),
            "migration": dict(RELATIONSHIP_MIGRATION),
            "updated_at": now(),
        })
        return True
    except Exception as exc:
        RELATIONSHIP_STORE = None
        RELATIONSHIP_MANAGER = None
        RELATIONSHIP_MIGRATION = {
            "success": False,
            "phase": "27A",
            "errors": [str(exc)],
        }
        config.setdefault("relationship_engine", {}).update({
            "phase": "27C.1",
            "ready": False,
            "initialization_error": str(exc),
            "updated_at": now(),
        })
        return False


def sync_legacy_relationships_to_phase27(save=False):
    """Mirror legacy relationship writes into the authoritative Phase 27 store.

    Phase 27A keeps config["device_relationships"] intact for compatibility.
    Newer phases can read directly from RELATIONSHIP_MANAGER while older
    dashboard, topology, and root-cause code continues to operate unchanged.
    """
    if not RELATIONSHIP_ENGINE_READY or RELATIONSHIP_MANAGER is None:
        return {
            "success": False,
            "phase": "27A",
            "reason": "relationship_engine_not_ready",
            "processed": 0,
        }

    processed = 0
    failed = 0
    errors = []

    legacy_relationships = config.get("device_relationships", {})
    if not isinstance(legacy_relationships, dict):
        legacy_relationships = {}

    for child_name, relationship in legacy_relationships.items():
        if not isinstance(relationship, dict):
            continue

        parent_name = clean_ascii(relationship.get("parent", ""))
        child_name = clean_ascii(child_name)
        if not parent_name or not child_name or parent_name == child_name:
            continue

        state_details = relationship.get("relationship_state_details", {})
        if not isinstance(state_details, dict):
            state_details = {}

        source = clean_ascii(
            relationship.get(
                "source",
                relationship.get(
                    "selection_source",
                    state_details.get("source", "UNKNOWN"),
                ),
            )
        ) or "UNKNOWN"

        parent_interface = clean_ascii(
            relationship.get(
                "source_interface",
                relationship.get("parent_interface", ""),
            )
        )
        child_interface = clean_ascii(
            relationship.get(
                "destination_interface",
                relationship.get(
                    "target_interface",
                    relationship.get("child_interface", ""),
                ),
            )
        )

        payload = {
            "parent": parent_name,
            "child": child_name,
            "parent_interface": parent_interface,
            "child_interface": child_interface,
            "relationship_type": relationship.get(
                "relationship_type",
                "VIRTUAL"
                if clean_ascii(relationship.get("relationship", "")).lower().find("virtual") >= 0
                else "PHYSICAL",
            ),
            "relationship_state": relationship.get(
                "relationship_state",
                state_details.get("state", "CONFIGURED"),
            ),
            "relationship_state_details": clean_ascii(
                relationship.get(
                    "state_details",
                    relationship.get("relationship", ""),
                )
            ),
            "confidence": relationship.get(
                "confidence",
                state_details.get("confidence", 0),
            ),
            "currently_verified": bool(
                relationship.get("currently_verified", False)
            ),
            "active": bool(relationship.get("active", True)),
            "evidence_sources": relationship.get("evidence_sources", []),
            "evidence_id": relationship.get("evidence_id", ""),
            "source": source,
            "last_verified_at": relationship.get(
                "last_verified_at",
                state_details.get("last_verified", ""),
            ),
            "last_seen_at": relationship.get("last_seen_at", ""),
            "metadata": {
                "legacy_relationship": relationship.get("relationship", ""),
                "selection_source": relationship.get("selection_source", ""),
                "phase27_compatibility_write": True,
                "legacy_updated_at": relationship.get("updated_at", ""),
            },
        }

        try:
            RELATIONSHIP_MANAGER.upsert_relationship(
                payload,
                save=False,
                prefer_higher_priority=True,
            )
            processed += 1
        except Exception as exc:
            failed += 1
            errors.append(f"{child_name}: {exc}")

    if RELATIONSHIP_STORE is not None:
        RELATIONSHIP_STORE.sync_to_config(save=save)

    engine_metadata = config.setdefault("relationship_engine", {})
    engine_metadata.update({
        "phase": "27C.1",
        "ready": True,
        "last_compatibility_sync": now(),
        "last_compatibility_sync_processed": processed,
        "last_compatibility_sync_failed": failed,
        "relationship_count": (
            RELATIONSHIP_STORE.count() if RELATIONSHIP_STORE else 0
        ),
    })
    if errors:
        engine_metadata["last_compatibility_sync_errors"] = errors[-25:]
    else:
        engine_metadata.pop("last_compatibility_sync_errors", None)

    return {
        "success": failed == 0,
        "phase": "27A",
        "processed": processed,
        "failed": failed,
        "errors": errors,
        "relationship_count": (
            RELATIONSHIP_STORE.count() if RELATIONSHIP_STORE else 0
        ),
    }



def _refresh_legacy_relationship_projection():
    """Keep config['device_relationships'] aligned with the authoritative store."""
    if RELATIONSHIP_ENGINE_READY and RELATIONSHIP_MANAGER is not None and serialize_relationships_for_legacy_projection is not None:
        projection = serialize_relationships_for_legacy_projection(
            RELATIONSHIP_MANAGER,
            existing=config.get("device_relationships", {}),
        )
        config["device_relationships"] = projection
        return projection
    return config.get("device_relationships", {})


def phase27_write_relationship(
    *,
    parent,
    child,
    parent_interface="",
    child_interface="",
    relationship_type="PHYSICAL",
    relationship_state="CONFIGURED",
    confidence=0,
    currently_verified=False,
    active=True,
    evidence_sources=None,
    evidence_id="",
    source="UNKNOWN",
    state_details="",
    metadata=None,
    legacy_relationship="",
    selection_source="",
    save=False,
):
    """Phase 27B manager-first relationship write.

    RelationshipManager is authoritative. config["device_relationships"] is
    updated afterward as a compatibility projection for legacy consumers.
    """
    parent = clean_ascii(parent)
    child = clean_ascii(child)
    if not parent or not child or parent == child:
        return {
            "success": False,
            "reason": "invalid_parent_or_child",
            "relationship_id": "",
        }

    payload = {
        "parent": parent,
        "child": child,
        "parent_interface": clean_ascii(parent_interface),
        "child_interface": clean_ascii(child_interface),
        "relationship_type": clean_ascii(relationship_type) or "PHYSICAL",
        "relationship_state": clean_ascii(relationship_state) or "CONFIGURED",
        "confidence": confidence,
        "currently_verified": bool(currently_verified),
        "active": bool(active),
        "evidence_sources": list(evidence_sources or []),
        "evidence_id": clean_ascii(evidence_id),
        "source": clean_ascii(source) or "UNKNOWN",
        "state_details": clean_ascii(state_details or legacy_relationship),
        "last_verified_at": now() if currently_verified else "",
        "last_seen_at": now() if currently_verified else "",
        "metadata": dict(metadata or {}),
    }

    relationship = None
    error = ""
    if RELATIONSHIP_ENGINE_READY and RELATIONSHIP_MANAGER is not None:
        try:
            relationship = RELATIONSHIP_MANAGER.record_evidence(
                parent,
                child,
                parent_interface=parent_interface,
                child_interface=child_interface,
                relationship_type=relationship_type,
                relationship_state=relationship_state,
                confidence=confidence,
                currently_verified=currently_verified,
                active=active,
                source=source,
                evidence_id=evidence_id,
                observed_at=now() if currently_verified else "",
                details=state_details or legacy_relationship,
                metadata=dict(metadata or {}),
                relationship_id="",
                save=False,
            )
        except Exception as exc:
            error = str(exc)
            try:
                relationship = RELATIONSHIP_MANAGER.upsert_relationship(
                    payload,
                    save=False,
                    prefer_higher_priority=True,
                )
            except Exception as exc2:
                error = f"{error}; {exc2}"

    # Compatibility projection. During Phase 27B this is no longer the
    # authoritative write target.
    config.setdefault("device_relationships", {})
    if RELATIONSHIP_ENGINE_READY and RELATIONSHIP_MANAGER is not None:
        _refresh_legacy_relationship_projection()
    else:
        legacy_record = {
            "parent": parent,
            "relationship": (
                clean_ascii(legacy_relationship)
                or clean_ascii(state_details)
                or "Relationship Manager Link"
            ),
            "source": clean_ascii(source) or "relationship_manager",
            "selection_source": clean_ascii(selection_source),
            "source_interface": clean_ascii(parent_interface),
            "destination_interface": clean_ascii(child_interface),
            "confidence": int(confidence or 0),
            "evidence_sources": list(evidence_sources or []),
            "evidence_id": clean_ascii(evidence_id),
            "relationship_state": clean_ascii(relationship_state) or "CONFIGURED",
            "relationship_state_details": _relationship_state_details(
                relationship_state,
                confidence,
                source,
                now() if currently_verified else "",
            ),
            "currently_verified": bool(currently_verified),
            "active": bool(active),
            "last_verified_at": now() if currently_verified else "",
            "updated_at": now(),
        }
        if relationship is not None:
            legacy_record["relationship_id"] = relationship.id
        config["device_relationships"][child] = legacy_record

    if RELATIONSHIP_STORE is not None:
        try:
            RELATIONSHIP_STORE.sync_to_config(save=save)
        except Exception as exc:
            if not error:
                error = str(exc)

    return {
        "success": relationship is not None and not error,
        "relationship_id": relationship.id if relationship is not None else "",
        "error": error,
        "legacy_projected": True,
    }


def phase27_write_discovery_relationship(record, protocol):
    """Write one CDP/LLDP observation directly to RelationshipManager."""
    if not isinstance(record, dict):
        return {"success": False, "reason": "invalid_record"}

    protocol = clean_ascii(protocol).upper() or "DISCOVERY"
    local_device = clean_ascii(record.get("local_device", ""))
    remote_device = clean_ascii(record.get("remote_device", ""))
    if not local_device or not remote_device or local_device == remote_device:
        return {"success": False, "reason": "unresolved_device"}

    active = bool(record.get("active", True))
    confidence = int(record.get("confidence", 0) or 0)
    result = phase27_write_relationship(
        parent=local_device,
        child=remote_device,
        parent_interface=record.get("local_interface", ""),
        child_interface=record.get("remote_interface", ""),
        relationship_type="PHYSICAL",
        relationship_state="LIVE" if active else "STALE",
        confidence=confidence,
        currently_verified=active,
        active=active,
        evidence_sources=[protocol],
        evidence_id=record.get("id", ""),
        source=protocol,
        state_details=f"{protocol} neighbor observation",
        metadata={
            "phase": "27B",
            "discovery_protocol": protocol,
            "local_ip": record.get("local_ip", ""),
            "remote_ip": record.get("remote_ip", ""),
            "local_port_index": record.get("local_port_index", ""),
            "remote_device_id": record.get("remote_device_id", ""),
            "remote_platform": record.get("remote_platform", ""),
            "first_seen": record.get("first_seen", ""),
            "last_seen": record.get("last_seen", ""),
            "manager_first_write": True,
        },
        legacy_relationship=f"{protocol} Discovered Physical Link",
        selection_source=f"{protocol.lower()}_discovery",
        save=False,
    )
    return result


def phase27_relationship_engine_summary():
    """Return safe operational status for testing Phase 27."""
    relationships = {}
    if RELATIONSHIP_MANAGER is not None:
        try:
            relationships = RELATIONSHIP_MANAGER.serialize_all()
        except Exception:
            relationships = {}

    source_counts = {}
    state_counts = {}
    for item in relationships.values():
        if not isinstance(item, dict):
            continue
        source = clean_ascii(item.get("source", "UNKNOWN")) or "UNKNOWN"
        state = clean_ascii(item.get("relationship_state", "UNKNOWN")) or "UNKNOWN"
        source_counts[source] = source_counts.get(source, 0) + 1
        state_counts[state] = state_counts.get(state, 0) + 1

    return {
        "success": bool(RELATIONSHIP_ENGINE_READY),
        "phase": "27C.1",
        "ready": bool(RELATIONSHIP_ENGINE_READY),
        "relationship_count": len(relationships),
        "source_counts": source_counts,
        "state_counts": state_counts,
        "migration": dict(RELATIONSHIP_MIGRATION or {}),
        "metadata": dict(config.get("relationship_engine", {}) or {}),
        "relationships": relationships,
        "legacy_compatibility_count": len(
            config.get("device_relationships", {})
            if isinstance(config.get("device_relationships", {}), dict)
            else {}
        ),
        "last_updated": now(),
    }


def phase27_delete_device_relationships(device_name):
    """Remove a deleted device from the authoritative relationship store."""
    if not RELATIONSHIP_ENGINE_READY or RELATIONSHIP_MANAGER is None:
        return 0
    try:
        return RELATIONSHIP_MANAGER.delete_device_relationships(
            clean_ascii(device_name),
            save=False,
        )
    except Exception:
        return 0


def load_config():
    global config, DEVICES, CHECK_INTERVAL
    global SNMP_COMMUNITY, ROUTER_IP, SWITCH_IP
    global SWITCH_PORTS, ROUTER_MONITORED_INTERFACES
    global DEVICE_TYPES, DEVICE_RELATIONSHIPS, INFRASTRUCTURE
    global INFRASTRUCTURE_DEVICES
    global INFRASTRUCTURE_INTERFACE_INVENTORY
    global SLEEP_DETECTION
    global CDP_DISCOVERY_INTERVAL
    global LLDP_DISCOVERY_INTERVAL
    global LINK_CONFIDENCE_INTERVAL
    global INTERNET_CHECK_TARGETS
    global RELATIONSHIP_STORE, RELATIONSHIP_MANAGER
    global RELATIONSHIP_MIGRATION, RELATIONSHIP_ENGINE_READY

    config = load_json_config(CONFIG_FILE)

    DEVICES = config.get("devices", {})
    CHECK_INTERVAL = config.get("check_interval_seconds", 15)

    SNMP_COMMUNITY = config.get("snmp", {}).get("community", "public")
    ROUTER_IP = config.get("snmp", {}).get("router_ip", "")
    SWITCH_IP = config.get("snmp", {}).get("switch_ip", "")
    SWITCH_PORTS = config.get("switch_ports", {})
    DEVICE_TYPES = config.get("device_types", {})
    DEVICE_RELATIONSHIPS = config.get("device_relationships", {})
    INFRASTRUCTURE = config.get("infrastructure", {})
    ensure_infrastructure_registry()
    INFRASTRUCTURE_DEVICES = config.get("infrastructure_devices", {})
    INFRASTRUCTURE_INTERFACE_INVENTORY = config.setdefault("infrastructure_interface_inventory", {})
    SLEEP_DETECTION = config.get("sleep_detection", {})

    phase26b1 = config.setdefault("phase26b1_cdp_discovery", {})
    phase26b1.setdefault("enabled", True)
    phase26b1.setdefault("interval_seconds", 60)
    phase26b1.setdefault("inactive_after_misses", 1)
    phase26b1.setdefault("retain_inactive_links", True)
    config.setdefault("discovered_infrastructure_links", {})
    config.setdefault("cdp_neighbor_inventory", {})
    try:
        CDP_DISCOVERY_INTERVAL = max(30, int(phase26b1.get("interval_seconds", 60)))
    except (TypeError, ValueError):
        CDP_DISCOVERY_INTERVAL = 60

    phase26b2 = config.setdefault("phase26b2_lldp_discovery", {})
    phase26b2.setdefault("enabled", True)
    phase26b2.setdefault("interval_seconds", 60)
    phase26b2.setdefault("inactive_after_misses", 1)
    phase26b2.setdefault("retain_inactive_links", True)
    config.setdefault("lldp_neighbor_inventory", {})
    try:
        LLDP_DISCOVERY_INTERVAL = max(30, int(phase26b2.get("interval_seconds", 60)))
    except (TypeError, ValueError):
        LLDP_DISCOVERY_INTERVAL = 60

    phase26b3 = config.setdefault("phase26b3_link_confidence", {})
    phase26b3.setdefault("enabled", True)
    phase26b3.setdefault("interval_seconds", 60)
    phase26b3.setdefault("include_manual_links", True)
    phase26b3.setdefault("manual_only_confidence", 80)
    phase26b3.setdefault("lldp_only_confidence", 95)
    phase26b3.setdefault("cdp_only_confidence", 98)
    phase26b3.setdefault("multi_protocol_confidence", 100)
    phase26b3.setdefault("minimum_active_confidence", 70)
    config.setdefault("merged_physical_links", {})
    config.setdefault("generated_infrastructure_links", [])
    config.setdefault("phase26b4_self_building_topology", {
        "enabled": True,
        "phase": "26B.4",
        "interval_seconds": 60,
        "minimum_confidence": 70,
        "include_manual_fallback": True,
        "prefer_discovered_links": True,
        "last_build": "",
        "generated_link_count": 0,
        "active_infrastructure_link_count": 0,
        "endpoint_link_count": 0,
        "root_count": 0,
        "topology_valid": False
    })
    try:
        LINK_CONFIDENCE_INTERVAL = max(30, int(phase26b3.get("interval_seconds", 60)))
    except (TypeError, ValueError):
        LINK_CONFIDENCE_INTERVAL = 60

    ROUTER_MONITORED_INTERFACES = config.get(
        "router_monitored_interfaces",
        []
    )

    # PHASE 26B.7I - Internet checks are entirely data-driven.
    # Every provisioned device typed as Internet contributes its configured IP.
    # Optional extra targets must be explicitly stored in internet_monitoring.targets.
    configured_targets = []
    for device_name, ip_address in config.get("devices", {}).items():
        device_type = clean_ascii(config.get("device_types", {}).get(device_name, ""))
        if normalize_infrastructure_role(device_type) == "Internet":
            target = clean_ascii(ip_address)
            if target and target not in configured_targets:
                configured_targets.append(target)

    internet_monitoring = config.setdefault("internet_monitoring", {})
    internet_monitoring.setdefault("enabled", True)
    internet_monitoring.setdefault("targets", [])
    for raw_target in internet_monitoring.get("targets", []):
        target = clean_ascii(raw_target)
        if target and target not in configured_targets:
            configured_targets.append(target)

    INTERNET_CHECK_TARGETS = configured_targets

    # PHASE 26B.7I - Controlled Discovery is the default behavior.
    controlled = config.setdefault("controlled_discovery", {})
    controlled.setdefault("enabled", True)
    controlled.setdefault("allow_infrastructure_discovery", True)
    controlled.setdefault("allow_endpoint_observation", True)
    controlled.setdefault("allow_endpoint_auto_inventory", False)
    controlled.setdefault("allow_endpoint_auto_topology", False)
    controlled.setdefault("require_provisioning_for_devices", True)

    auto_linking = config.setdefault("infrastructure_auto_linking", {})
    auto_linking.setdefault("enabled", True)
    auto_linking.setdefault("source", AUTO_INFRASTRUCTURE_LINK_SOURCE)
    auto_linking.setdefault("preserve_manual_links", True)
    auto_linking.setdefault("rebuild_on_provision", True)
    auto_linking.setdefault("rebuild_on_delete", True)
    auto_linking.setdefault("rebuild_after_discovery", True)
    auto_linking.setdefault("minimum_physical_confidence", 70)
    auto_linking.setdefault("allow_role_fallback", True)
    # PHASE 26B.9B - Never invent a generic upstream parent for an
    # additional router when CDP/LLDP/verified physical evidence is absent.
    auto_linking.setdefault("allow_router_role_fallback", False)
    auto_linking.setdefault("preserve_last_verified_relationship", True)
    auto_linking.setdefault("cached_relationship_confidence", 70)
    auto_linking.setdefault("remove_stale_generated_links", True)
    # PHASE 26B.8O - Preserve verified interface evidence.
    # This installation's current physical path is:
    # Internet -> Modem -> Switch -> Router.
    # The list is stored in config so future sites can change the order without
    # hard-coding device names in the topology engine.
    auto_linking.setdefault(
        "preferred_role_path",
        ["Internet", "Modem", "Switch", "Router"],
    )
    auto_linking.setdefault("phase", "26B.8O")
    config.setdefault("generated_infrastructure_links", [])

    # PHASE 27A - Initialize the authoritative store after legacy structures
    # have been loaded and normalized. Existing consumers remain unchanged.
    initialize_phase27_relationship_engine()


# ======================================================
# PHASE 16A.1 - INFRASTRUCTURE REGISTRY ENGINE
# ======================================================




def register_infrastructure_device(device_name, ip_address, role, snmp_enabled=None):
    """Add/update one device in the Phase 16 infrastructure registry."""
    device_name = clean_ascii(device_name)
    ip_address = clean_ascii(ip_address)
    role = normalize_infrastructure_role(role)

    if not device_name or not ip_address:
        return False

    if snmp_enabled is None:
        snmp_enabled = is_snmp_capable_infrastructure_role(role)

    config.setdefault("infrastructure_devices", {})
    existing = config["infrastructure_devices"].get(device_name, {})

    config["infrastructure_devices"][device_name] = {
        "ip": ip_address,
        "role": role,
        "snmp_enabled": bool(snmp_enabled),
        "source": existing.get("source", "provisioning"),
        "registered_at": existing.get("registered_at", now()),
        "updated_at": now()
    }

    return True


def unregister_infrastructure_device(device_name):
    device_name = clean_ascii(device_name)
    if not device_name:
        return False
    if device_name in config.get("infrastructure_devices", {}):
        config["infrastructure_devices"].pop(device_name, None)
        return True
    return False


def cleanup_deleted_device_everywhere(device_name):
    """Phase 16D cleanup engine.

    A deleted inventory/infrastructure device must disappear from every
    ON WATCH data structure, not just config["devices"]. This prevents
    stale routers/switches from continuing to appear in Registered
    Infrastructure Devices, the topology builder, relationship paths,
    interface inventory, and SNMP cache panels.
    """
    device_name = clean_ascii(device_name)
    if not device_name:
        return {"removed_links": 0, "removed_ports": 0}

    phase27_delete_device_relationships(device_name)

    removed_links = 0
    removed_ports = 0

    for key in [
        "devices",
        "device_types",
        "device_relationships",
        "infrastructure_devices",
        "infrastructure_interface_inventory",
        "provisioned_virtual_inheritance",
        "maintenance_devices",
        "provisioning_grace_devices"
    ]:
        if isinstance(config.get(key), dict):
            config[key].pop(device_name, None)

    # Remove SNMP universal inventory cache for the deleted device.
    snmp_cache = config.get("snmp_inventory", {})
    if isinstance(snmp_cache, dict):
        devices_cache = snmp_cache.get("devices", {})
        if isinstance(devices_cache, dict):
            devices_cache.pop(device_name, None)

    # Remove old router monitoring selections if the deleted device was the
    # primary configured router and the interfaces are no longer valid.
    if clean_ascii(config.get("infrastructure", {}).get("edge_router", "")) == device_name:
        config["router_monitored_interfaces"] = []

    # Remove any relationship entries where the deleted device was the parent.
    for child_name, relationship in list(config.get("device_relationships", {}).items()):
        if isinstance(relationship, dict) and clean_ascii(relationship.get("parent", "")) == device_name:
            config["device_relationships"].pop(child_name, None)
            config.get("provisioned_virtual_inheritance", {}).pop(child_name, None)

    # Remove switch-port mappings assigned to the deleted device.
    for port_index, port_device in list(config.get("switch_ports", {}).items()):
        if clean_ascii(port_device) == device_name:
            config["switch_ports"].pop(port_index, None)
            removed_ports += 1

    # Remove ALL topology links touching the deleted device, including core
    # infrastructure links and endpoint links.
    links = get_physical_topology_config()
    remaining_links = []
    for link in links:
        link_from = clean_ascii(link.get("from", ""))
        link_to = clean_ascii(link.get("to", ""))
        if device_name in [link_from, link_to]:
            removed_links += 1
            continue
        remaining_links.append(link)
    config["infrastructure_links"] = remaining_links

    # If any saved infrastructure role pointer references the deleted device,
    # clear the pointer so ensure_infrastructure_registry cannot recreate it.
    if isinstance(config.get("infrastructure"), dict):
        for role_key, role_device in list(config["infrastructure"].items()):
            if clean_ascii(role_device) == device_name:
                config["infrastructure"][role_key] = ""

    # Remove live in-memory status remnants.
    status.pop(device_name, None)
    previous_status.pop(device_name, None)

    if bool(config.get("infrastructure_auto_linking", {}).get("rebuild_on_delete", True)):
        rebuild_auto_infrastructure_links()

    return {"removed_links": removed_links, "removed_ports": removed_ports}


def prune_stale_infrastructure_registry():
    """Remove infrastructure registry/cache entries for devices no longer in inventory."""
    config.setdefault("devices", {})
    valid_devices = set(config.get("devices", {}).keys())

    removed = []
    for device_name in list(config.get("infrastructure_devices", {}).keys()):
        if device_name not in valid_devices:
            cleanup_deleted_device_everywhere(device_name)
            removed.append(device_name)

    return removed


def ensure_infrastructure_registry():
    """Build the registry from existing config without breaking old router/switch settings."""
    config.setdefault("infrastructure_devices", {})
    config.setdefault("devices", {})
    config.setdefault("device_types", {})

    # Migrate the current core infrastructure names into the new registry.
    legacy_pairs = [
        (config.get("infrastructure", {}).get("edge_router", ""), "Router"),
        (config.get("infrastructure", {}).get("main_switch", ""), "Switch"),
        (config.get("infrastructure", {}).get("internet_gateway", ""), "Modem"),
        (config.get("infrastructure", {}).get("internet", ""), "Internet")
    ]

    for device_name, role in legacy_pairs:
        device_name = clean_ascii(device_name)
        if device_name and device_name in config.get("devices", {}):
            existing = config["infrastructure_devices"].get(device_name, {})
            register_infrastructure_device(
                device_name,
                config["devices"].get(device_name, ""),
                existing.get("role", role),
                existing.get("snmp_enabled", is_snmp_capable_infrastructure_role(role))
            )
            config["infrastructure_devices"][device_name]["source"] = existing.get("source", "legacy_migration")

    # Also register any device already typed as infrastructure.
    infrastructure_types = ["router", "switch", "firewall", "access point", "ups", "dns", "dhcp", "vpn", "modem"]
    for device_name, device_type in config.get("device_types", {}).items():
        role = normalize_infrastructure_role(device_type)
        if any(keyword in clean_ascii(device_type).lower() for keyword in infrastructure_types):
            existing = config["infrastructure_devices"].get(device_name, {})
            register_infrastructure_device(
                device_name,
                config.get("devices", {}).get(device_name, ""),
                existing.get("role", role),
                existing.get("snmp_enabled", is_snmp_capable_infrastructure_role(role))
            )
            config["infrastructure_devices"][device_name]["source"] = existing.get("source", "device_type_scan")

    # Phase 16D: do not allow stale/deleted infrastructure records to
    # reappear on the dashboard after the device has been removed.
    prune_stale_infrastructure_registry()

    return config.get("infrastructure_devices", {})


def get_infrastructure_devices():
    ensure_infrastructure_registry()
    return config.get("infrastructure_devices", {})


def get_infrastructure_by_role(role):
    role = normalize_infrastructure_role(role)
    return {
        name: info
        for name, info in get_infrastructure_devices().items()
        if normalize_infrastructure_role(info.get("role", "")) == role
    }


def get_router_devices():
    return get_infrastructure_by_role("Router")


def get_switch_devices():
    return get_infrastructure_by_role("Switch")


def get_firewall_devices():
    return get_infrastructure_by_role("Firewall")


def get_access_point_devices():
    return get_infrastructure_by_role("Access Point")


def build_infrastructure_registry_summary():
    devices = get_infrastructure_devices()
    roles = {}
    snmp_enabled = 0

    for info in devices.values():
        role = normalize_infrastructure_role(info.get("role", "Infrastructure"))
        roles[role] = roles.get(role, 0) + 1
        if info.get("snmp_enabled"):
            snmp_enabled += 1

    return {
        "phase": "16A.1",
        "total": len(devices),
        "snmp_enabled": snmp_enabled,
        "roles": roles,
        "devices": devices,
        "last_updated": now()
    }




# ======================================================
# PHASE 26B.7H - PORTABLE BLANK-SLATE NETWORK DESIGN
# ======================================================
NETWORK_DESIGN_DICT_KEYS = [
    "devices",
    "device_types",
    "device_relationships",
    "switch_ports",
    "provisioned_virtual_inheritance",
    "provisioning_grace_devices",
    "device_metadata",
    "maintenance_devices",
    "infrastructure_devices",
    "infrastructure_interface_inventory",
    "port_ownership",
    "infrastructure_relationships",
    "discovered_infrastructure_links",
    "cdp_neighbor_inventory",
    "lldp_neighbor_inventory",
    "merged_physical_links",
    "phase26b5_accepted_snapshot",
    "phase26b5_pending_change",
    "phase26b6_pending_incident",
    "phase26b6_active_incident",
    "phase26b6_last_incident",
    "phase26b5_last_change",
    "relationship_store",
    "device_relationship_index"
]

NETWORK_DESIGN_LIST_KEYS = [
    "router_monitored_interfaces",
    "provisioning_reserved_ips",
    "infrastructure_links",
    "generated_infrastructure_links",
    "phase26b6_root_cause_history",
    "phase26b5_topology_change_history",
    "phase26b7_maintenance_history"
]


def reset_network_design_state():
    """Remove all site-specific inventory, topology, mappings and discovery state.

    Application preferences, notification settings, credentials, UI settings,
    backup settings and monitoring feature switches are preserved. This allows
    the same On Watch installation to move from one location to another and be
    redesigned from an empty network inventory.
    """
    global config, DEVICES, DEVICE_TYPES, DEVICE_RELATIONSHIPS
    global SWITCH_PORTS, ROUTER_MONITORED_INTERFACES
    global INFRASTRUCTURE, INFRASTRUCTURE_DEVICES
    global INFRASTRUCTURE_INTERFACE_INVENTORY
    global ROUTER_IP, SWITCH_IP
    global status, previous_status, router_interfaces, switch_links
    global previous_router_interfaces, previous_switch_links

    for key in NETWORK_DESIGN_DICT_KEYS:
        config[key] = {}

    for key in NETWORK_DESIGN_LIST_KEYS:
        config[key] = []

    config["infrastructure"] = {
        "internet": "",
        "internet_gateway": "",
        "edge_router": "",
        "main_switch": "",
        "main_switch_vlan": ""
    }

    snmp_settings = config.setdefault("snmp", {})
    snmp_settings["router_ip"] = ""
    snmp_settings["switch_ip"] = ""

    config["internet_monitoring"] = {
        "enabled": True,
        "targets": []
    }

    config["controlled_discovery"] = {
        "enabled": True,
        "allow_infrastructure_discovery": True,
        "allow_endpoint_observation": True,
        "allow_endpoint_auto_inventory": False,
        "allow_endpoint_auto_topology": False,
        "require_provisioning_for_devices": True
    }

    config["infrastructure_auto_linking"] = {
        "enabled": True,
        "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
        "preserve_manual_links": True,
        "rebuild_on_provision": True,
        "rebuild_on_delete": True,
        "last_rebuild": "",
        "auto_link_count": 0,
        "root_count": 0,
        "roots": []
    }

    sleep_settings = config.setdefault("sleep_detection", {})
    sleep_settings["sleep_allowed_devices"] = []

    maintenance = config.setdefault("maintenance_mode", {})
    maintenance["active"] = {}

    scheduled = config.setdefault("scheduled_maintenance", {})
    scheduled["schedules"] = []

    classification = config.setdefault("intelligent_alert_classification", {})
    classification["critical_device_names"] = []

    service_impact = config.setdefault("service_impact_awareness", {})
    service_impact["services"] = []

    dynamic_topology = config.setdefault("dynamic_physical_topology", {})
    dynamic_topology.update({
        "nodes": [],
        "links": [],
        "relationships": [],
        "roots": [],
        "last_updated": now()
    })

    phase14 = config.setdefault("phase14_dependency_engine", {})
    for key in ["dependencies", "relationships", "device_paths", "root_devices"]:
        if key in phase14:
            phase14[key] = {} if isinstance(phase14.get(key), dict) else []

    for section_name in [
        "phase26b4_topology",
        "phase26b5_topology_change_detection",
        "phase26b6_root_cause_topology"
    ]:
        section = config.setdefault(section_name, {})
        for key in list(section.keys()):
            if key in {
                "nodes", "links", "relationships", "roots", "root_devices",
                "generated_links", "accepted_links", "rejected_links",
                "current_snapshot", "previous_snapshot", "active_incidents",
                "impacted_devices", "suppressed_devices"
            }:
                section[key] = {} if isinstance(section.get(key), dict) else []
        section["last_updated"] = now()

    snmp_inventory = config.setdefault("snmp_inventory", {})
    snmp_inventory["devices"] = {}

    config.setdefault("phase26b1_cdp_discovery", {}).update({
        "last_discovery": "",
        "last_polled_devices": 0,
        "active_links": 0,
        "inactive_links": 0,
        "neighbors_found": 0
    })
    config.setdefault("phase26b2_lldp_discovery", {}).update({
        "last_discovery": "",
        "last_polled_devices": 0,
        "active_links": 0,
        "inactive_links": 0,
        "neighbors_found": 0
    })
    config.setdefault("phase26b3_link_confidence", {}).update({
        "last_build": "",
        "evidence_count": 0,
        "merged_link_count": 0,
        "verified_link_count": 0,
        "rejected_link_count": 0
    })
    config.setdefault("phase26b4_self_building_topology", {}).update({
        "last_build": "",
        "generated_link_count": 0,
        "active_infrastructure_link_count": 0,
        "endpoint_link_count": 0,
        "root_count": 0,
        "topology_valid": False
    })

    DEVICES = {}
    DEVICE_TYPES = {}
    DEVICE_RELATIONSHIPS = {}
    SWITCH_PORTS = {}
    ROUTER_MONITORED_INTERFACES = []
    INFRASTRUCTURE = config["infrastructure"]
    INFRASTRUCTURE_DEVICES = {}
    INFRASTRUCTURE_INTERFACE_INVENTORY = {}
    ROUTER_IP = ""
    SWITCH_IP = ""

    status.clear()
    previous_status.clear()
    router_interfaces.clear()
    switch_links.clear()
    previous_router_interfaces.clear()
    previous_switch_links.clear()

    initialize_phase27_relationship_engine()
    save_config()

    write_event(
        "CONFIG | NETWORK DESIGN RESET | All site-specific inventory, topology, "
        "port mappings, infrastructure roles and discovery caches cleared"
    )

    return {
        "success": True,
        "message": "Network design reset complete. On Watch is ready for a new site.",
        "devices": 0,
        "infrastructure": 0,
        "links": 0
    }


# ======================================================
# PHASE 26B.8 - AUTO INFRASTRUCTURE LINK CREATION
# ======================================================

INFRASTRUCTURE_PARENT_ROLE_PREFERENCES = {
    "Internet": [],
    "Modem": ["Internet"],
    "Firewall": ["Modem", "Internet"],
    "VPN Gateway": ["Firewall", "Router", "Modem", "Internet"],
    "Router": ["Firewall", "Modem", "Internet"],
    "Switch": ["Router", "Firewall", "Modem", "Internet"],
    "Access Point": ["Switch", "Router", "Firewall", "Modem", "Internet"],
    "DNS Server": ["Switch", "Router", "Firewall", "Modem", "Internet"],
    "DHCP Server": ["Switch", "Router", "Firewall", "Modem", "Internet"],
    "UPS": ["Switch", "Router", "Firewall", "Modem", "Internet"],
}






def _select_auto_infrastructure_parent(device_name, device_role, registry, eligible_names=None):
    preferences = INFRASTRUCTURE_PARENT_ROLE_PREFERENCES.get(
        normalize_infrastructure_role(device_role),
        ["Switch", "Router", "Firewall", "Modem", "Internet"],
    )
    allowed = set(eligible_names or registry.keys())
    ordered_registry = sorted(registry.items(), key=_infrastructure_registry_order)
    for preferred_role in preferences:
        for candidate_name, candidate_info in ordered_registry:
            candidate_name = clean_ascii(candidate_name)
            if not candidate_name or candidate_name == device_name or candidate_name not in allowed:
                continue
            candidate_info = candidate_info if isinstance(candidate_info, dict) else {}
            if normalize_infrastructure_role(candidate_info.get("role", "")) == preferred_role:
                return candidate_name
    return ""






def _registry_name_by_ip(registry, ip_address):
    ip_address = clean_ascii(ip_address)
    if not ip_address:
        return ""
    for name, info in registry.items():
        info = info if isinstance(info, dict) else {}
        if clean_ascii(info.get("ip", config.get("devices", {}).get(name, ""))) == ip_address:
            return clean_ascii(name)
    return ""


def _canonical_registered_infrastructure_name(value, registry, ip_address=""):
    by_ip = _registry_name_by_ip(registry, ip_address)
    if by_ip:
        return by_ip
    raw = clean_ascii(value)
    if raw in registry:
        return raw
    resolved = _canonical_inventory_device(raw, clean_ascii(ip_address))
    if resolved in registry:
        return resolved
    token = _confidence_device_token(raw)
    if not token:
        return ""
    for name in registry:
        candidate = _confidence_device_token(name)
        if candidate == token or (candidate and (candidate.endswith(token) or token.endswith(candidate))):
            return clean_ascii(name)
    return ""






def _phase26b8_physical_edges(registry, minimum_confidence):
    """Return unique CDP/LLDP-backed edges between provisioned devices only."""
    best = {}
    for link in config.get("merged_physical_links", {}).values():
        if not isinstance(link, dict) or not bool(link.get("active", False)):
            continue
        active_sources = {clean_ascii(x).upper() for x in (link.get("active_sources", []) or [])}
        protocol_sources = active_sources & {"CDP", "LLDP"}
        confidence = int(link.get("confidence", 0) or 0)
        if not protocol_sources or confidence < minimum_confidence:
            continue
        endpoint_a = link.get("endpoint_a", {}) if isinstance(link.get("endpoint_a"), dict) else {}
        endpoint_b = link.get("endpoint_b", {}) if isinstance(link.get("endpoint_b"), dict) else {}
        name_a = _canonical_registered_infrastructure_name(endpoint_a.get("device", ""), registry)
        name_b = _canonical_registered_infrastructure_name(endpoint_b.get("device", ""), registry)
        if not name_a or not name_b or name_a == name_b:
            continue
        pair = tuple(sorted((name_a, name_b), key=str.lower))
        candidate = {
            "a": name_a,
            "a_interface": clean_ascii(endpoint_a.get("interface", "")),
            "b": name_b,
            "b_interface": clean_ascii(endpoint_b.get("interface", "")),
            "confidence": confidence,
            "evidence_sources": sorted(protocol_sources),
            "evidence_id": clean_ascii(link.get("id", "")),
        }
        current = best.get(pair)
        if current is None or confidence > int(current.get("confidence", 0)):
            best[pair] = candidate
    return list(best.values())


def _phase26b9c_cached_physical_edges(registry, cached_confidence=70):
    """Return inactive historical CDP/LLDP edges for stable stale placement.

    These edges are never treated as currently verified. They are used only
    when a previously discovered physical relationship has temporarily lost
    active CDP/LLDP evidence. This prevents the map from inventing a different
    parent or splitting a known child into a second topology tree.
    """
    best = {}
    merged_links = config.get("merged_physical_links", {})
    if not isinstance(merged_links, dict):
        return []

    for link in merged_links.values():
        if not isinstance(link, dict) or bool(link.get("active", False)):
            continue

        historical_sources = {
            clean_ascii(value).upper()
            for value in (link.get("sources", []) or [])
            if clean_ascii(value)
        }
        protocol_sources = historical_sources & {"CDP", "LLDP"}
        if not protocol_sources:
            continue

        endpoint_a = link.get("endpoint_a", {}) if isinstance(link.get("endpoint_a"), dict) else {}
        endpoint_b = link.get("endpoint_b", {}) if isinstance(link.get("endpoint_b"), dict) else {}
        name_a = _canonical_registered_infrastructure_name(endpoint_a.get("device", ""), registry)
        name_b = _canonical_registered_infrastructure_name(endpoint_b.get("device", ""), registry)
        if not name_a or not name_b or name_a == name_b:
            continue

        pair = tuple(sorted((name_a, name_b), key=str.lower))
        candidate = {
            "a": name_a,
            "a_interface": clean_ascii(endpoint_a.get("interface", "")),
            "b": name_b,
            "b_interface": clean_ascii(endpoint_b.get("interface", "")),
            "confidence": max(1, min(100, int(cached_confidence or 70))),
            "evidence_sources": sorted(protocol_sources),
            "evidence_id": clean_ascii(link.get("id", "")),
        }
        current = best.get(pair)
        if current is None:
            best[pair] = candidate

    return list(best.values())


def _phase26b8_orient_physical_edges(registry, explicit_links, physical_edges):
    """Orient physical cables outward from provisioned roots without name rules."""
    adjacency = {name: [] for name in registry}
    for edge in physical_edges:
        adjacency.setdefault(edge["a"], []).append((edge["b"], edge, True))
        adjacency.setdefault(edge["b"], []).append((edge["a"], edge, False))

    explicit_children = {clean_ascii(x.get("to", "")) for x in explicit_links}
    explicit_parents = {clean_ascii(x.get("from", "")) for x in explicit_links}
    roots = [name for name in explicit_parents - explicit_children if name in registry]
    for name, info in registry.items():
        if normalize_infrastructure_role((info or {}).get("role", "")) == "Internet" and name not in roots:
            roots.append(name)
    if not roots and registry:
        roots = [min(registry, key=lambda n: (_infrastructure_role_rank((registry[n] or {}).get("role", "")), _infrastructure_registry_order((n, registry[n]))))]

    explicit_child_set = set(explicit_children)
    visited = set()
    oriented = []

    def walk(component_root):
        queue = [component_root]
        visited.add(component_root)
        while queue:
            parent = queue.pop(0)
            neighbors = sorted(adjacency.get(parent, []), key=lambda row: (-int(row[1].get("confidence", 0)), clean_ascii(row[0]).lower()))
            for child, edge, parent_is_a in neighbors:
                if child in visited:
                    continue
                visited.add(child)
                queue.append(child)
                if child in explicit_child_set:
                    continue
                oriented.append({
                    "parent": parent,
                    "child": child,
                    "parent_interface": edge["a_interface"] if parent_is_a else edge["b_interface"],
                    "child_interface": edge["b_interface"] if parent_is_a else edge["a_interface"],
                    "confidence": edge["confidence"],
                    "evidence_sources": edge["evidence_sources"],
                    "evidence_id": edge["evidence_id"],
                })

    for root in sorted(set(roots), key=lambda n: (_infrastructure_role_rank((registry[n] or {}).get("role", "")), _infrastructure_registry_order((n, registry[n])))):
        if root not in visited:
            walk(root)

    # Disconnected discovered components become additional roots. This avoids
    # inventing a cross-component role link when physical evidence says none exists.
    for name in sorted(registry, key=lambda n: (_infrastructure_role_rank((registry[n] or {}).get("role", "")), _infrastructure_registry_order((n, registry[n])))):
        if name not in visited and adjacency.get(name):
            roots.append(name)
            walk(name)
    return oriented, sorted(set(roots))



def _phase26b8n_preferred_role_path_links(registry, settings):
    """Build the configured core path and preserve verified cable evidence.

    The configured role path controls only parent/child direction. When CDP or
    LLDP has verified the same two provisioned devices, the discovered local
    interfaces, confidence, and evidence IDs are copied onto the configured
    path link in the configured direction.

    Example:
        Configured direction: Main Switch -> Edge Router
        Discovery may report: Edge Router Gi0/0 <-> Main Switch Gi1/0/21

    The saved link remains Main Switch -> Edge Router while carrying:
        source_interface      = Gi1/0/21
        destination_interface = Gi0/0
        evidence_sources      = ["CDP", "LLDP"]
    """
    raw_path = settings.get(
        "preferred_role_path",
        ["Internet", "Modem", "Switch", "Router"],
    )
    if not isinstance(raw_path, list):
        return []

    role_path = []
    for raw_role in raw_path:
        role = normalize_infrastructure_role(raw_role)
        if role and role not in role_path:
            role_path.append(role)

    ordered_registry = sorted(registry.items(), key=_infrastructure_registry_order)
    selected = []
    used_names = set()

    for role in role_path:
        for device_name, info in ordered_registry:
            device_name = clean_ascii(device_name)
            info = info if isinstance(info, dict) else {}
            if (
                device_name
                and device_name not in used_names
                and normalize_infrastructure_role(info.get("role", "")) == role
            ):
                selected.append((device_name, role))
                used_names.add(device_name)
                break

    try:
        minimum_confidence = max(
            0,
            min(
                100,
                int(settings.get("minimum_physical_confidence", 70) or 70),
            ),
        )
    except (TypeError, ValueError):
        minimum_confidence = 70

    physical_edges = _phase26b8_physical_edges(registry, minimum_confidence)
    physical_by_pair = {}
    for edge in physical_edges:
        if not isinstance(edge, dict):
            continue
        endpoint_a = clean_ascii(edge.get("a", ""))
        endpoint_b = clean_ascii(edge.get("b", ""))
        if not endpoint_a or not endpoint_b or endpoint_a == endpoint_b:
            continue
        pair = frozenset((endpoint_a, endpoint_b))
        current = physical_by_pair.get(pair)
        if current is None or int(edge.get("confidence", 0) or 0) > int(current.get("confidence", 0) or 0):
            physical_by_pair[pair] = edge

    links = []
    for index in range(len(selected) - 1):
        parent_name, parent_role = selected[index]
        child_name, child_role = selected[index + 1]
        stamp = now()

        source_interface = ""
        destination_interface = ""
        confidence = 90
        evidence_sources = ["CONFIGURED_ROLE_PATH"]
        evidence_id = f"{parent_role}->{child_role}"
        link_type = "Configured Infrastructure Role Path"
        relationship_state = "CONFIGURED"
        relationship_source = "CONFIGURED_ROLE_PATH"
        currently_verified = False
        last_verified_at = ""

        physical = physical_by_pair.get(frozenset((parent_name, child_name)))
        if physical:
            if clean_ascii(physical.get("a", "")) == parent_name:
                source_interface = clean_ascii(physical.get("a_interface", ""))
                destination_interface = clean_ascii(physical.get("b_interface", ""))
            else:
                source_interface = clean_ascii(physical.get("b_interface", ""))
                destination_interface = clean_ascii(physical.get("a_interface", ""))

            confidence = int(physical.get("confidence", 0) or 0)
            evidence_sources = list(physical.get("evidence_sources", []) or [])
            evidence_id = clean_ascii(physical.get("evidence_id", ""))
            link_type = "Configured Direction with Verified Physical Evidence"
            relationship_state = "LIVE"
            relationship_source = ",".join(evidence_sources) or "CDP/LLDP"
            currently_verified = True
            last_verified_at = stamp

        links.append({
            "id": _stable_auto_infrastructure_link_id(parent_name, child_name),
            "from": parent_name,
            "to": child_name,
            "source_interface": source_interface,
            "destination_interface": destination_interface,
            "target_interface": destination_interface,
            "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
            "selection_source": "preferred_role_path",
            "link_type": link_type,
            "confidence": confidence,
            "evidence_sources": evidence_sources,
            "evidence_id": evidence_id,
            "relationship_state": relationship_state,
            "relationship_state_details": _relationship_state_details(
                relationship_state,
                confidence,
                relationship_source,
                last_verified_at,
            ),
            "currently_verified": currently_verified,
            "last_verified_at": last_verified_at,
            "active": True,
            "auto_generated": True,
            "created_at": stamp,
            "updated_at": stamp,
        })

    return links


def rebuild_auto_infrastructure_links():
    """Create, update and remove generated infrastructure links from live evidence.

    Controlled Discovery remains enforced: CDP/LLDP may connect only devices
    already present in the provisioned infrastructure registry. It never creates
    inventory devices.
    """
    settings = config.setdefault("infrastructure_auto_linking", {})
    settings.setdefault("enabled", True)
    settings.setdefault("source", AUTO_INFRASTRUCTURE_LINK_SOURCE)
    settings.setdefault("preserve_manual_links", True)
    settings.setdefault("rebuild_on_provision", True)
    settings.setdefault("rebuild_on_delete", True)
    settings.setdefault("rebuild_after_discovery", True)
    settings.setdefault("prefer_verified_physical_links", True)
    settings.setdefault("minimum_physical_confidence", 70)
    settings.setdefault("allow_role_fallback", True)
    # PHASE 26B.9B - Routers without physical evidence remain unattached
    # instead of being reassigned to a modem/gateway by role hierarchy.
    settings.setdefault("allow_router_role_fallback", False)
    settings.setdefault("preserve_last_verified_relationship", True)
    settings.setdefault("cached_relationship_confidence", 70)
    settings.setdefault("remove_stale_generated_links", True)
    settings.setdefault(
        "preferred_role_path",
        ["Internet", "Modem", "Switch", "Router"],
    )

    if not bool(settings.get("enabled", True)):
        return {"enabled": False, "created": 0, "updated": 0, "removed": 0, "roots": [], "links": []}

    registry = get_infrastructure_devices()
    valid_names = set(registry)
    prior_generated = [x for x in config.get("generated_infrastructure_links", []) if isinstance(x, dict)]
    prior_by_id = {clean_ascii(x.get("id", "")): x for x in prior_generated if clean_ascii(x.get("id", ""))}

    explicit_links = []
    if bool(settings.get("preserve_manual_links", True)):
        for link in get_physical_topology_config():
            if not isinstance(link, dict) or not _is_explicit_saved_infrastructure_link(link):
                continue
            parent = clean_ascii(link.get("from", ""))
            child = clean_ascii(link.get("to", ""))
            if parent in valid_names and child in valid_names and parent != child:
                saved = dict(link)
                saved["source"] = clean_ascii(saved.get("source", "manual")) or "manual"
                saved["selection_source"] = "explicit_saved_link"
                saved["auto_generated"] = False
                explicit_links.append(saved)

    # PHASE 26B.8O - Use configured direction and retain physical evidence
    # guidance. Explicit user-saved links still take precedence for the same
    # child, while CDP/LLDP continues to supply physical interface evidence.
    existing_explicit_children = {
        clean_ascii(link.get("to", ""))
        for link in explicit_links
        if isinstance(link, dict)
    }
    for preferred_link in _phase26b8n_preferred_role_path_links(registry, settings):
        child_name = clean_ascii(preferred_link.get("to", ""))
        if child_name and child_name not in existing_explicit_children:
            explicit_links.append(preferred_link)
            existing_explicit_children.add(child_name)

    relationships = config.setdefault("device_relationships", {})
    for child, relationship in list(relationships.items()):
        if not isinstance(relationship, dict):
            continue
        if clean_ascii(relationship.get("source", "")).lower() in LEGACY_AUTO_INFRASTRUCTURE_LINK_SOURCES or clean_ascii(relationship.get("selection_source", "")).lower() in {"role_hierarchy", "verified_physical_link", "discovered_physical_link", "preferred_role_path"}:
            relationships.pop(child, None)

    explicit_children = set()
    placed_names = set()
    for link in explicit_links:
        parent = clean_ascii(link.get("from", ""))
        child = clean_ascii(link.get("to", ""))
        explicit_children.add(child)
        placed_names.update((parent, child))
        selection_source = clean_ascii(
            link.get("selection_source", "explicit_saved_link")
        ) or "explicit_saved_link"
        link_confidence = int(link.get("confidence", 80) or 80)
        link_evidence_sources = list(
            link.get("evidence_sources", ["MANUAL"]) or ["MANUAL"]
        )

        if selection_source == "preferred_role_path":
            state_name = clean_ascii(link.get("relationship_state", "CONFIGURED")) or "CONFIGURED"
            state_source = clean_ascii(
                link.get("relationship_state_details", {}).get("source", "")
                if isinstance(link.get("relationship_state_details"), dict)
                else ""
            ) or "CONFIGURED_ROLE_PATH"
            last_verified = clean_ascii(link.get("last_verified_at", ""))
            currently_verified = bool(link.get("currently_verified", False))
        else:
            state_name = "MANUAL"
            state_source = clean_ascii(link.get("source", "manual")) or "manual"
            last_verified = ""
            currently_verified = False

        relationships[child] = {
            "parent": parent,
            "relationship": clean_ascii(link.get("link_type", "Manual Infrastructure Link")) or "Manual Infrastructure Link",
            "source": clean_ascii(link.get("source", "manual")) or "manual",
            "selection_source": selection_source,
            "source_interface": clean_ascii(link.get("source_interface", "")),
            "destination_interface": clean_ascii(link.get("target_interface", "") or link.get("destination_interface", "")),
            "confidence": link_confidence,
            "evidence_sources": link_evidence_sources,
            "evidence_id": clean_ascii(link.get("evidence_id", "")),
            "relationship_state": state_name,
            "relationship_state_details": _relationship_state_details(
                state_name,
                link_confidence,
                state_source,
                last_verified,
            ),
            "currently_verified": currently_verified,
            "last_verified_at": last_verified,
            "updated_at": now(),
        }
        phase27_write_relationship(
            parent=parent,
            child=child,
            parent_interface=relationships[child].get("source_interface", ""),
            child_interface=relationships[child].get("destination_interface", ""),
            relationship_type="PHYSICAL",
            relationship_state=relationships[child].get("relationship_state", "CONFIGURED"),
            confidence=relationships[child].get("confidence", 0),
            currently_verified=relationships[child].get("currently_verified", False),
            active=True,
            evidence_sources=relationships[child].get("evidence_sources", []),
            evidence_id=relationships[child].get("evidence_id", ""),
            source=relationships[child].get("source", AUTO_INFRASTRUCTURE_LINK_SOURCE),
            state_details=relationships[child].get("relationship", ""),
            metadata={
                "phase": "27B",
                "selection_source": relationships[child].get("selection_source", ""),
                "manager_first_write": True,
            },
            legacy_relationship=relationships[child].get("relationship", ""),
            selection_source=relationships[child].get("selection_source", ""),
            save=False,
        )

    minimum_confidence = max(0, min(100, int(settings.get("minimum_physical_confidence", 70) or 70)))
    physical_edges = _phase26b8_physical_edges(registry, minimum_confidence)
    oriented, roots = _phase26b8_orient_physical_edges(registry, explicit_links, physical_edges)

    generated = [
        dict(link)
        for link in explicit_links
        if clean_ascii(link.get("selection_source", "")).lower() == "preferred_role_path"
    ]
    for item in oriented:
        parent = item["parent"]
        child = item["child"]
        if child in explicit_children:
            continue
        link_id = _stable_auto_infrastructure_link_id(parent, child)
        previous = prior_by_id.get(link_id, {})
        stamp = now()
        link = {
            "id": link_id,
            "from": parent,
            "to": child,
            "source_interface": item["parent_interface"],
            "destination_interface": item["child_interface"],
            "target_interface": item["child_interface"],
            "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
            "selection_source": "discovered_physical_link",
            "link_type": "Auto-Created Physical Infrastructure Link",
            "confidence": item["confidence"],
            "evidence_sources": item["evidence_sources"],
            "evidence_id": item["evidence_id"],
            "relationship_state": "LIVE",
            "relationship_state_details": _relationship_state_details(
                "LIVE",
                item["confidence"],
                ",".join(item["evidence_sources"]) or "CDP/LLDP",
                stamp,
            ),
            "currently_verified": True,
            "active": True,
            "auto_generated": True,
            "created_at": previous.get("created_at", stamp),
            "last_verified_at": stamp,
            "updated_at": stamp,
        }
        generated.append(link)
        placed_names.update((parent, child))
        relationships[child] = {
            "parent": parent,
            "relationship": link["link_type"],
            "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
            "selection_source": "discovered_physical_link",
            "source_interface": item["parent_interface"],
            "destination_interface": item["child_interface"],
            "confidence": item["confidence"],
            "evidence_sources": item["evidence_sources"],
            "evidence_id": item["evidence_id"],
            "relationship_state": "LIVE",
            "relationship_state_details": _relationship_state_details(
                "LIVE",
                item["confidence"],
                ",".join(item["evidence_sources"]) or "CDP/LLDP",
                stamp,
            ),
            "currently_verified": True,
            "last_verified_at": stamp,
            "updated_at": stamp,
        }
        phase27_write_relationship(
            parent=parent,
            child=child,
            parent_interface=item["parent_interface"],
            child_interface=item["child_interface"],
            relationship_type="PHYSICAL",
            relationship_state="LIVE",
            confidence=item["confidence"],
            currently_verified=True,
            active=True,
            evidence_sources=item["evidence_sources"],
            evidence_id=item["evidence_id"],
            source=AUTO_INFRASTRUCTURE_LINK_SOURCE,
            state_details=link["link_type"],
            metadata={
                "phase": "27B",
                "selection_source": "discovered_physical_link",
                "manager_first_write": True,
            },
            legacy_relationship=link["link_type"],
            selection_source="discovered_physical_link",
            save=False,
        )

    # PHASE 26B.9C - LAST VERIFIED RELATIONSHIP PRESERVATION
    #
    # When active CDP/LLDP evidence disappears, preserve the last known physical
    # parent/child placement as STALE. The link remains visible and keeps the
    # topology stable, but is clearly marked as not currently verified.
    cached_relationship_count = 0
    if bool(settings.get("preserve_last_verified_relationship", True)):
        try:
            cached_confidence = max(
                1,
                min(100, int(settings.get("cached_relationship_confidence", 70) or 70)),
            )
        except (TypeError, ValueError):
            cached_confidence = 70

        cached_edges = _phase26b9c_cached_physical_edges(registry, cached_confidence)
        cached_oriented, _cached_roots = _phase26b8_orient_physical_edges(
            registry,
            explicit_links,
            cached_edges,
        )

        already_parented = {
            clean_ascii(child_name)
            for child_name, relationship in relationships.items()
            if clean_ascii(child_name)
            and isinstance(relationship, dict)
            and clean_ascii(relationship.get("parent", ""))
        }

        for item in cached_oriented:
            parent = clean_ascii(item.get("parent", ""))
            child = clean_ascii(item.get("child", ""))
            if (
                not parent
                or not child
                or child in explicit_children
                or child in already_parented
            ):
                continue

            link_id = _stable_auto_infrastructure_link_id(parent, child)
            previous = prior_by_id.get(link_id, {})
            stamp = now()
            link = {
                "id": link_id,
                "from": parent,
                "to": child,
                "source_interface": clean_ascii(item.get("parent_interface", "")),
                "destination_interface": clean_ascii(item.get("child_interface", "")),
                "target_interface": clean_ascii(item.get("child_interface", "")),
                "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
                "selection_source": "cached_physical_link",
                "link_type": "Last Verified Physical Infrastructure Link",
                "confidence": cached_confidence,
                "evidence_sources": list(item.get("evidence_sources", []) or []),
                "evidence_id": clean_ascii(item.get("evidence_id", "")),
                "active": True,
                "currently_verified": False,
                "relationship_state": "CACHED",
                "relationship_state_details": _relationship_state_details(
                    "CACHED",
                    cached_confidence,
                    ",".join(list(item.get("evidence_sources", []) or [])) or "CDP/LLDP",
                    previous.get("last_verified_at", previous.get("updated_at", stamp)),
                ),
                "auto_generated": True,
                "created_at": previous.get("created_at", stamp),
                "last_verified_at": previous.get(
                    "last_verified_at",
                    previous.get("updated_at", stamp),
                ),
                "updated_at": stamp,
            }
            generated.append(link)
            placed_names.update((parent, child))
            already_parented.add(child)
            relationships[child] = {
                "parent": parent,
                "relationship": link["link_type"],
                "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
                "selection_source": "cached_physical_link",
                "source_interface": link["source_interface"],
                "destination_interface": link["destination_interface"],
                "confidence": cached_confidence,
                "evidence_sources": link["evidence_sources"],
                "evidence_id": link["evidence_id"],
                "relationship_state": "CACHED",
                "relationship_state_details": _relationship_state_details(
                    "CACHED",
                    cached_confidence,
                    ",".join(link["evidence_sources"]) or "CDP/LLDP",
                    link["last_verified_at"],
                ),
                "currently_verified": False,
                "last_verified_at": link["last_verified_at"],
                "updated_at": stamp,
            }
            cached_relationship_count += 1

    role_fallback_count = 0
    if bool(settings.get("allow_role_fallback", True)):
        # PHASE 26B.8M - PARENT-COVERAGE FIX
        #
        # "placed_names" contains both sides of a discovered physical edge.
        # A device can therefore be present in placed_names only because it is
        # acting as a parent (for example Main Switch -> Edge Router), while
        # still having no upstream parent of its own. The previous condition
        # skipped every placed device, which left Main Switch as an extra root.
        #
        # Track actual children instead. Any infrastructure device without a
        # relationship entry still needs an upstream role-fallback parent.
        parented_names = {
            clean_ascii(child_name)
            for child_name, relationship in relationships.items()
            if clean_ascii(child_name)
            and isinstance(relationship, dict)
            and clean_ascii(relationship.get("parent", ""))
        }

        for name, info in sorted(registry.items(), key=_infrastructure_registry_order):
            name = clean_ascii(name)
            if not name or name in parented_names:
                continue

            info = info if isinstance(info, dict) else {}
            device_role = normalize_infrastructure_role(info.get("role", ""))

            # PHASE 26B.9B - DISCOVERY-LOSS SAFETY
            #
            # Additional routers must not be assigned to a modem, gateway, or
            # another generic role-based parent when CDP/LLDP/verified physical
            # evidence disappears. Keep the provisioned router in inventory,
            # but expose it as an unattached topology root until discovery or a
            # manually configured physical link establishes the real parent.
            if (
                device_role == "Router"
                and not bool(settings.get("allow_router_role_fallback", False))
            ):
                roots.append(name)
                placed_names.add(name)
                continue

            parent = _select_auto_infrastructure_parent(
                name,
                device_role,
                registry,
                placed_names,
            )
            if not parent:
                roots.append(name)
                placed_names.add(name)
                continue
            link_id = _stable_auto_infrastructure_link_id(parent, name)
            previous = prior_by_id.get(link_id, {})
            stamp = now()
            link = {
                "id": link_id,
                "from": parent,
                "to": name,
                "source_interface": "",
                "destination_interface": "",
                "target_interface": "",
                "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
                "selection_source": "role_hierarchy",
                "link_type": "Role-Based Infrastructure Link",
                "confidence": 50,
                "evidence_sources": [],
                "evidence_id": "",
                "relationship_state": "CONFIGURED",
                "relationship_state_details": _relationship_state_details(
                    "CONFIGURED",
                    50,
                    "ROLE_HIERARCHY",
                    "",
                ),
                "currently_verified": False,
                "active": True,
                "auto_generated": True,
                "created_at": previous.get("created_at", stamp),
                "updated_at": stamp,
            }
            generated.append(link)
            relationships[name] = {
                "parent": parent,
                "relationship": link["link_type"],
                "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
                "selection_source": "role_hierarchy",
                "source_interface": "",
                "destination_interface": "",
                "confidence": 50,
                "evidence_sources": [],
                "evidence_id": "",
                "relationship_state": "CONFIGURED",
                "relationship_state_details": _relationship_state_details(
                    "CONFIGURED",
                    50,
                    "ROLE_HIERARCHY",
                    "",
                ),
                "currently_verified": False,
                "last_verified_at": "",
                "updated_at": stamp,
            }
            placed_names.add(name)
            parented_names.add(name)
            role_fallback_count += 1

    current_by_id = {x["id"]: x for x in generated}
    created = len(set(current_by_id) - set(prior_by_id))
    removed = len(set(prior_by_id) - set(current_by_id))
    updated = 0
    compare_fields = ("from", "to", "source_interface", "destination_interface", "confidence", "evidence_id", "selection_source", "relationship_state", "currently_verified")
    for link_id in set(current_by_id) & set(prior_by_id):
        if any(current_by_id[link_id].get(k) != prior_by_id[link_id].get(k) for k in compare_fields):
            updated += 1

    config["generated_infrastructure_links"] = generated
    saved_explicit_links = [
        link for link in explicit_links
        if clean_ascii(link.get("selection_source", "")).lower() != "preferred_role_path"
    ]
    config["infrastructure_links"] = saved_explicit_links + generated
    roots = sorted(set(clean_ascii(x) for x in roots if clean_ascii(x)))
    settings.update({
        "phase": "26B.9E",
        "last_rebuild": now(),
        "auto_link_count": len(generated),
        "physical_link_count": len([x for x in generated if x.get("selection_source") == "discovered_physical_link"]),
        "role_fallback_link_count": role_fallback_count,
        "cached_relationship_link_count": cached_relationship_count,
        "preserved_explicit_link_count": len(explicit_links),
        "created_last_rebuild": created,
        "updated_last_rebuild": updated,
        "removed_last_rebuild": removed,
        "root_count": len(roots),
        "roots": roots,
        "source": AUTO_INFRASTRUCTURE_LINK_SOURCE,
    })
    phase27_sync = sync_legacy_relationships_to_phase27(save=False)
    settings["phase27_relationship_sync"] = {
        "success": phase27_sync.get("success", False),
        "processed": phase27_sync.get("processed", 0),
        "failed": phase27_sync.get("failed", 0),
        "relationship_count": phase27_sync.get("relationship_count", 0),
        "updated_at": now(),
    }

    write_event(
        f"CONFIG | AUTO INFRASTRUCTURE LINKS | Phase 26B.9E | "
        f"Explicit: {len(explicit_links)} | Physical: {settings['physical_link_count']} | "
        f"Cached: {cached_relationship_count} | Role Fallback: {role_fallback_count} | "
        f"Created: {created} | Updated: {updated} | Removed: {removed}"
    )
    return {
        "enabled": True,
        "phase": "26B.9E",
        "created": created,
        "updated": updated,
        "removed": removed,
        "preserved_explicit_links": len(explicit_links),
        "physical_links": settings["physical_link_count"],
        "role_fallback_links": role_fallback_count,
        "cached_relationship_links": cached_relationship_count,
        "roots": roots,
        "links": generated,
    }

# ======================================================
# PHASE 16A.2B - INFRASTRUCTURE DISCOVERY ENGINE
# ======================================================
def load_infrastructure_interface_inventory():
    """Return the Phase 16A.2B infrastructure interface inventory cache."""
    config.setdefault("infrastructure_interface_inventory", {})
    return config["infrastructure_interface_inventory"]


def save_infrastructure_interface_inventory():
    """Save Phase 16A.2B discovery results into config.json."""
    save_config()


def should_discover_infrastructure_role(role):
    """Only SNMP-capable infrastructure devices are discovered in Phase 16A.2B."""
    role = normalize_infrastructure_role(role)
    return role in ["Router", "Switch", "Firewall", "Access Point"]


def normalize_infrastructure_discovered_interfaces(raw_interfaces):
    """Clean and sort discovered SNMP interfaces for infrastructure inventory."""
    cleaned = {}

    if not isinstance(raw_interfaces, dict):
        return cleaned

    for index, info in raw_interfaces.items():
        if not isinstance(info, dict):
            continue

        name = clean_ascii(info.get("name", ""))
        if not is_usable_snmp_interface(name):
            continue

        cleaned[str(index)] = normalize_interface_record(index, info, source=info.get("source", "snmp"))

    return dict(sorted(cleaned.items(), key=interface_sort_key))


def discover_infrastructure_interfaces(force=False):
    """
    Phase 16A.2B discovery engine.

    Discovers SNMP interfaces for registered infrastructure devices:
    - Router
    - Switch
    - Firewall
    - Access Point

    It intentionally skips:
    - Internet
    - Modem

    Normal monitor_loop runs are throttled to once every 5 minutes.
    Manual API runs can force discovery immediately.
    """
    global LAST_INFRASTRUCTURE_DISCOVERY
    global INFRASTRUCTURE_INTERFACE_INVENTORY

    current_time = time.time()

    if (
        not force and
        LAST_INFRASTRUCTURE_DISCOVERY and
        current_time - LAST_INFRASTRUCTURE_DISCOVERY < INFRASTRUCTURE_DISCOVERY_INTERVAL
    ):
        return load_infrastructure_interface_inventory()

    registry = get_infrastructure_devices()
    inventory = load_infrastructure_interface_inventory()

    devices_discovered = 0
    interfaces_found = 0

    for device_name, info in registry.items():
        device_name = clean_ascii(device_name)
        role = normalize_infrastructure_role(info.get("role", "Infrastructure"))
        ip_address = clean_ascii(info.get("ip", DEVICES.get(device_name, "")))

        if not device_name or not ip_address:
            continue

        if not should_discover_infrastructure_role(role):
            continue

        if not bool(info.get("snmp_enabled", False)):
            continue

        discovered_interfaces = {}

        try:
            # Reuse the existing Phase 15A.1 SNMP discovery/cache engine.
            discovered_interfaces = discover_device_interfaces(device_name, force_live=True)

            # If the device is registered as infrastructure but not present in
            # DEVICES, fall back to direct SNMP interface discovery by IP.
            if not discovered_interfaces:
                raw_interfaces = get_snmp_interfaces(ip_address)
                discovered_interfaces = normalize_infrastructure_discovered_interfaces(raw_interfaces)

        except Exception as e:
            write_event(f"ERROR | INFRASTRUCTURE DISCOVERY | {device_name} ({ip_address}) failed: {e}")
            discovered_interfaces = {}

        interface_count = len(discovered_interfaces)

        inventory[device_name] = {
            "phase": "16A.2B",
            "role": role,
            "ip": ip_address,
            "last_discovery": now(),
            "interfaces_found": interface_count,
            "interfaces": discovered_interfaces,
            "status": "SUCCESS" if interface_count > 0 else "NO INTERFACES FOUND"
        }

        devices_discovered += 1
        interfaces_found += interface_count

    config["infrastructure_interface_inventory"] = inventory
    INFRASTRUCTURE_INTERFACE_INVENTORY = inventory

    LAST_INFRASTRUCTURE_DISCOVERY = current_time

    try:
        save_infrastructure_interface_inventory()
    except Exception as e:
        write_event(f"ERROR | INFRASTRUCTURE DISCOVERY | Save failed: {e}")

    write_event(
        f"CONFIG | INFRASTRUCTURE DISCOVERY | Phase 16A.2B | "
        f"Devices Discovered: {devices_discovered} | Interfaces Found: {interfaces_found}"
    )

    return inventory


def build_infrastructure_discovery_summary():
    """Build a compact API summary for Phase 16A.2B."""
    inventory = load_infrastructure_interface_inventory()

    devices_discovered = 0
    interfaces_found = 0
    last_discovery = ""

    for item in inventory.values():
        if not isinstance(item, dict):
            continue

        devices_discovered += 1
        interfaces_found += int(item.get("interfaces_found", 0) or 0)

        stamp = clean_ascii(item.get("last_discovery", ""))
        if stamp > last_discovery:
            last_discovery = stamp

    return {
        "phase": "16A.2B",
        "devices_discovered": devices_discovered,
        "interfaces_found": interfaces_found,
        "last_discovery": last_discovery,
        "inventory": inventory
    }


# ======================================================
# PHASE 26B.1 - CDP NEIGHBOR DISCOVERY ENGINE
# ======================================================
CDP_CACHE_DEVICE_ID_OID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT_OID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_PLATFORM_OID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.8"
CDP_CACHE_ADDRESS_OID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.4"










def _canonical_inventory_device(remote_id, remote_ip=""):
    """Resolve CDP Device ID/IP to the current On Watch inventory name."""
    remote_id = clean_ascii(remote_id)
    remote_ip = clean_ascii(remote_ip)
    if remote_ip:
        for name, ip in config.get("devices", {}).items():
            if clean_ascii(ip) == remote_ip:
                return clean_ascii(name)

    normalized = remote_id.replace("+", " ").replace("_", " ")
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    short_id = normalized.split(".", 1)[0]
    for name in config.get("devices", {}):
        candidate = clean_ascii(name).replace("+", " ").replace("_", " ")
        candidate = re.sub(r"\s+", " ", candidate).strip().lower()
        if candidate in {normalized, short_id} or candidate.split(".", 1)[0] == short_id:
            return clean_ascii(name)
    return remote_id


def _local_interface_name(device_name, ifindex):
    inventory = config.get("infrastructure_interface_inventory", {}).get(device_name, {})
    interfaces = inventory.get("interfaces", {}) if isinstance(inventory, dict) else {}
    record = interfaces.get(str(ifindex), {}) if isinstance(interfaces, dict) else {}
    return clean_ascii(record.get("name", "")) or f"ifIndex {ifindex}"




def discover_cdp_neighbors(force=False):
    """Poll CISCO-CDP-MIB on registered Cisco infrastructure devices.

    Results are saved separately in:
      config["cdp_neighbor_inventory"]
      config["discovered_infrastructure_links"]

    Manual infrastructure_links are intentionally not modified in Phase 26B.1.
    """
    global LAST_CDP_DISCOVERY

    settings = config.get("phase26b1_cdp_discovery", {})
    if not bool(settings.get("enabled", True)):
        return config.get("discovered_infrastructure_links", {})

    current_time = time.time()
    if not force and LAST_CDP_DISCOVERY and current_time - LAST_CDP_DISCOVERY < CDP_DISCOVERY_INTERVAL:
        return config.get("discovered_infrastructure_links", {})

    if not CDP_DISCOVERY_LOCK.acquire(blocking=False):
        return config.get("discovered_infrastructure_links", {})

    try:
        existing = config.setdefault("discovered_infrastructure_links", {})
        neighbor_inventory = config.setdefault("cdp_neighbor_inventory", {})
        seen_ids = set()
        poll_stamp = now()
        polled_devices = 0
        discovered_neighbors = 0

        for device_name, info in get_infrastructure_devices().items():
            role = normalize_infrastructure_role(info.get("role", ""))
            if role not in ["Router", "Switch"] or not info.get("snmp_enabled", False):
                continue
            ip_address = clean_ascii(info.get("ip", DEVICES.get(device_name, "")))
            if not ip_address:
                continue

            polled_devices += 1
            device_ids = _parse_cdp_walk(snmpwalk(ip_address, CDP_CACHE_DEVICE_ID_OID))
            remote_ports = _parse_cdp_walk(snmpwalk(ip_address, CDP_CACHE_DEVICE_PORT_OID))
            platforms = _parse_cdp_walk(snmpwalk(ip_address, CDP_CACHE_PLATFORM_OID))
            addresses = _parse_cdp_walk(snmpwalk(ip_address, CDP_CACHE_ADDRESS_OID))

            rows = []
            for key, remote_id in device_ids.items():
                local_ifindex, remote_index = key
                remote_port = clean_ascii(remote_ports.get(key, ""))
                remote_ip = _decode_cdp_address(addresses.get(key, ""))
                remote_name = _canonical_inventory_device(remote_id, remote_ip)
                local_interface = _local_interface_name(device_name, local_ifindex)
                link_id = _stable_discovered_link_id(device_name, local_ifindex, remote_name, remote_port)
                seen_ids.add(link_id)
                discovered_neighbors += 1

                prior = existing.get(link_id, {}) if isinstance(existing.get(link_id, {}), dict) else {}
                record = {
                    "id": link_id,
                    "local_device": clean_ascii(device_name),
                    "local_ip": ip_address,
                    "local_interface": local_interface,
                    "local_port_index": str(local_ifindex),
                    "remote_device": remote_name,
                    "remote_device_id": clean_ascii(remote_id),
                    "remote_ip": remote_ip,
                    "remote_interface": remote_port,
                    "remote_platform": clean_ascii(platforms.get(key, "")),
                    "source": "CDP",
                    "confidence": 100,
                    "active": True,
                    "first_seen": prior.get("first_seen", poll_stamp),
                    "last_seen": poll_stamp,
                    "last_polled": poll_stamp,
                    "miss_count": 0
                }
                existing[link_id] = record
                phase27_write_discovery_relationship(record, "CDP")
                rows.append(record)

            neighbor_inventory[device_name] = {
                "device": clean_ascii(device_name),
                "ip": ip_address,
                "source": "CISCO-CDP-MIB",
                "last_discovery": poll_stamp,
                "neighbors_found": len(rows),
                "neighbors": rows,
                "status": "SUCCESS" if rows else "NO CDP NEIGHBORS"
            }

        inactive_after = max(1, int(settings.get("inactive_after_misses", 1) or 1))
        retain_inactive = bool(settings.get("retain_inactive_links", True))
        for link_id in list(existing.keys()):
            item = existing.get(link_id, {})
            if not isinstance(item, dict) or clean_ascii(item.get("source", "")).upper() != "CDP":
                continue
            if link_id in seen_ids:
                continue
            item["miss_count"] = int(item.get("miss_count", 0) or 0) + 1
            item["last_polled"] = poll_stamp
            if item["miss_count"] >= inactive_after:
                item["active"] = False
                item["inactive_since"] = item.get("inactive_since", poll_stamp)
                if not retain_inactive:
                    existing.pop(link_id, None)

        config["discovered_infrastructure_links"] = existing
        config["cdp_neighbor_inventory"] = neighbor_inventory
        cdp_links = [
            value for value in existing.values()
            if isinstance(value, dict) and clean_ascii(value.get("source", "")).upper() == "CDP"
        ]
        config.setdefault("phase26b1_cdp_discovery", {}).update({
            "phase": "26B.1",
            "last_discovery": poll_stamp,
            "last_polled_devices": polled_devices,
            "active_links": sum(1 for value in cdp_links if value.get("active")),
            "inactive_links": sum(1 for value in cdp_links if not value.get("active")),
            "neighbors_found": discovered_neighbors
        })
        LAST_CDP_DISCOVERY = current_time
        save_config()
        write_event(
            f"CONFIG | CDP DISCOVERY | Phase 26B.1 | Devices Polled: {polled_devices} | "
            f"Neighbors Found: {discovered_neighbors} | Active Links: {config['phase26b1_cdp_discovery']['active_links']}"
        )
        return existing
    except Exception as exc:
        write_event(f"ERROR | CDP DISCOVERY | Phase 26B.1 failed: {exc}")
        return config.get("discovered_infrastructure_links", {})
    finally:
        CDP_DISCOVERY_LOCK.release()


def build_cdp_discovery_summary():
    links = config.get("discovered_infrastructure_links", {})
    cdp_links = [
        value for value in links.values()
        if isinstance(value, dict) and clean_ascii(value.get("source", "")).upper() == "CDP"
    ]
    active = [value for value in cdp_links if value.get("active")]
    inactive = [value for value in cdp_links if not value.get("active")]
    return {
        "success": True,
        "phase": "26B.1",
        "settings": config.get("phase26b1_cdp_discovery", {}),
        "active_link_count": len(active),
        "inactive_link_count": len(inactive),
        "active_links": active,
        "inactive_links": inactive,
        "neighbor_inventory": config.get("cdp_neighbor_inventory", {})
    }



# ======================================================
# PHASE 26B.2 - LLDP NEIGHBOR DISCOVERY ENGINE
# ======================================================
# IEEE 802.1AB LLDP-MIB. Remote table index is:
#   lldpRemTimeMark.localPortNum.remIndex
LLDP_LOC_PORT_ID_OID = ".1.0.8802.1.1.2.1.3.7.1.3"
LLDP_LOC_PORT_DESC_OID = ".1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_CHASSIS_ID_OID = ".1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_ID_OID = ".1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC_OID = ".1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME_OID = ".1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_SYS_DESC_OID = ".1.0.8802.1.1.2.1.4.1.1.10"










def _normalize_interface_token(value):
    """Create a comparable token for long/short interface spellings."""
    text = clean_ascii(value).lower().replace(" ", "")
    replacements = (
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("ethernet", "eth"),
        ("port-channel", "po"),
        ("portchannel", "po"),
    )
    for old, new in replacements:
        if text.startswith(old):
            text = new + text[len(old):]
            break
    return re.sub(r"[^a-z0-9/]", "", text)


def _lldp_local_interface_name(device_name, local_port_num, local_port_ids, local_port_descs):
    """Resolve LLDP localPortNum to the SNMP-discovered interface name."""
    port_num = str(local_port_num)
    advertised_id = clean_ascii(local_port_ids.get(port_num, ""))
    advertised_desc = clean_ascii(local_port_descs.get(port_num, ""))

    inventory = config.get("infrastructure_interface_inventory", {}).get(device_name, {})
    interfaces = inventory.get("interfaces", {}) if isinstance(inventory, dict) else {}

    # Some platforms use ifIndex directly as lldpLocPortNum.
    direct = interfaces.get(port_num, {}) if isinstance(interfaces, dict) else {}
    if isinstance(direct, dict) and clean_ascii(direct.get("name", "")):
        direct_name = clean_ascii(direct.get("name", ""))
        candidates = {_normalize_interface_token(advertised_id), _normalize_interface_token(advertised_desc)}
        if not any(candidates) or _normalize_interface_token(direct_name) in candidates:
            return direct_name

    wanted = {
        _normalize_interface_token(advertised_id),
        _normalize_interface_token(advertised_desc),
    }
    wanted.discard("")
    for record in interfaces.values() if isinstance(interfaces, dict) else []:
        if not isinstance(record, dict):
            continue
        for field in ("name", "description", "alias"):
            value = clean_ascii(record.get(field, ""))
            if value and _normalize_interface_token(value) in wanted:
                return clean_ascii(record.get("name", "")) or value

    return advertised_id or advertised_desc or f"LLDP port {port_num}"




def discover_lldp_neighbors(force=False):
    """Poll the standard LLDP-MIB on SNMP-enabled routers and switches.

    LLDP records share config["discovered_infrastructure_links"] with CDP,
    but use source="LLDP" and unique lldp-* IDs. Manual links remain unchanged.
    """
    global LAST_LLDP_DISCOVERY

    settings = config.get("phase26b2_lldp_discovery", {})
    if not bool(settings.get("enabled", True)):
        return config.get("discovered_infrastructure_links", {})

    current_time = time.time()
    if not force and LAST_LLDP_DISCOVERY and current_time - LAST_LLDP_DISCOVERY < LLDP_DISCOVERY_INTERVAL:
        return config.get("discovered_infrastructure_links", {})

    if not LLDP_DISCOVERY_LOCK.acquire(blocking=False):
        return config.get("discovered_infrastructure_links", {})

    try:
        existing = config.setdefault("discovered_infrastructure_links", {})
        neighbor_inventory = config.setdefault("lldp_neighbor_inventory", {})
        seen_ids = set()
        poll_stamp = now()
        polled_devices = 0
        discovered_neighbors = 0

        for device_name, info in get_infrastructure_devices().items():
            role = normalize_infrastructure_role(info.get("role", ""))
            if role not in ["Router", "Switch"] or not info.get("snmp_enabled", False):
                continue
            ip_address = clean_ascii(info.get("ip", DEVICES.get(device_name, "")))
            if not ip_address:
                continue

            polled_devices += 1
            local_port_ids = _parse_lldp_local_walk(snmpwalk(ip_address, LLDP_LOC_PORT_ID_OID))
            local_port_descs = _parse_lldp_local_walk(snmpwalk(ip_address, LLDP_LOC_PORT_DESC_OID))
            chassis_ids = _parse_lldp_remote_walk(snmpwalk(ip_address, LLDP_REM_CHASSIS_ID_OID))
            remote_port_ids = _parse_lldp_remote_walk(snmpwalk(ip_address, LLDP_REM_PORT_ID_OID))
            remote_port_descs = _parse_lldp_remote_walk(snmpwalk(ip_address, LLDP_REM_PORT_DESC_OID))
            system_names = _parse_lldp_remote_walk(snmpwalk(ip_address, LLDP_REM_SYS_NAME_OID))
            system_descs = _parse_lldp_remote_walk(snmpwalk(ip_address, LLDP_REM_SYS_DESC_OID))

            all_keys = set(chassis_ids) | set(remote_port_ids) | set(system_names)
            rows = []
            for key in sorted(all_keys):
                _time_mark, local_port_num, _remote_index = key
                chassis_id = clean_ascii(chassis_ids.get(key, ""))
                remote_system_name = clean_ascii(system_names.get(key, ""))
                raw_remote_name = remote_system_name or chassis_id or "Unknown LLDP Neighbor"
                remote_name = _canonical_inventory_device(raw_remote_name, "")
                remote_port_id = clean_ascii(remote_port_ids.get(key, ""))
                remote_port_desc = clean_ascii(remote_port_descs.get(key, ""))
                remote_interface = remote_port_id or remote_port_desc or "Unknown port"
                local_interface = _lldp_local_interface_name(
                    device_name, local_port_num, local_port_ids, local_port_descs
                )
                link_id = _stable_lldp_link_id(
                    device_name, local_port_num, remote_name, remote_interface
                )
                seen_ids.add(link_id)
                discovered_neighbors += 1

                prior = existing.get(link_id, {}) if isinstance(existing.get(link_id, {}), dict) else {}
                record = {
                    "id": link_id,
                    "local_device": clean_ascii(device_name),
                    "local_ip": ip_address,
                    "local_interface": local_interface,
                    "local_port_index": str(local_port_num),
                    "remote_device": remote_name,
                    "remote_device_id": raw_remote_name,
                    "remote_chassis_id": chassis_id,
                    "remote_ip": "",
                    "remote_interface": remote_interface,
                    "remote_port_description": remote_port_desc,
                    "remote_platform": clean_ascii(system_descs.get(key, "")),
                    "source": "LLDP",
                    "confidence": 95,
                    "active": True,
                    "first_seen": prior.get("first_seen", poll_stamp),
                    "last_seen": poll_stamp,
                    "last_polled": poll_stamp,
                    "miss_count": 0,
                }
                existing[link_id] = record
                phase27_write_discovery_relationship(record, "LLDP")
                rows.append(record)

            neighbor_inventory[device_name] = {
                "device": clean_ascii(device_name),
                "ip": ip_address,
                "source": "IEEE-LLDP-MIB",
                "last_discovery": poll_stamp,
                "neighbors_found": len(rows),
                "neighbors": rows,
                "status": "SUCCESS" if rows else "NO LLDP NEIGHBORS",
            }

        inactive_after = max(1, int(settings.get("inactive_after_misses", 1) or 1))
        retain_inactive = bool(settings.get("retain_inactive_links", True))
        for link_id in list(existing.keys()):
            item = existing.get(link_id, {})
            if not isinstance(item, dict) or clean_ascii(item.get("source", "")).upper() != "LLDP":
                continue
            if link_id in seen_ids:
                continue
            item["miss_count"] = int(item.get("miss_count", 0) or 0) + 1
            item["last_polled"] = poll_stamp
            if item["miss_count"] >= inactive_after:
                item["active"] = False
                item["inactive_since"] = item.get("inactive_since", poll_stamp)
                if not retain_inactive:
                    existing.pop(link_id, None)

        config["discovered_infrastructure_links"] = existing
        config["lldp_neighbor_inventory"] = neighbor_inventory
        lldp_links = [
            value for value in existing.values()
            if isinstance(value, dict) and clean_ascii(value.get("source", "")).upper() == "LLDP"
        ]
        config.setdefault("phase26b2_lldp_discovery", {}).update({
            "phase": "26B.2",
            "last_discovery": poll_stamp,
            "last_polled_devices": polled_devices,
            "active_links": sum(1 for value in lldp_links if value.get("active")),
            "inactive_links": sum(1 for value in lldp_links if not value.get("active")),
            "neighbors_found": discovered_neighbors,
        })
        LAST_LLDP_DISCOVERY = current_time
        save_config()
        write_event(
            f"CONFIG | LLDP DISCOVERY | Phase 26B.2 | Devices Polled: {polled_devices} | "
            f"Neighbors Found: {discovered_neighbors} | Active Links: "
            f"{config['phase26b2_lldp_discovery']['active_links']}"
        )
        return existing
    except Exception as exc:
        write_event(f"ERROR | LLDP DISCOVERY | Phase 26B.2 failed: {exc}")
        return config.get("discovered_infrastructure_links", {})
    finally:
        LLDP_DISCOVERY_LOCK.release()


def build_lldp_discovery_summary():
    links = config.get("discovered_infrastructure_links", {})
    lldp_links = [
        value for value in links.values()
        if isinstance(value, dict) and clean_ascii(value.get("source", "")).upper() == "LLDP"
    ]
    active = [value for value in lldp_links if value.get("active")]
    inactive = [value for value in lldp_links if not value.get("active")]
    return {
        "success": True,
        "phase": "26B.2",
        "settings": config.get("phase26b2_lldp_discovery", {}),
        "active_link_count": len(active),
        "inactive_link_count": len(inactive),
        "active_links": active,
        "inactive_links": inactive,
        "neighbor_inventory": config.get("lldp_neighbor_inventory", {}),
    }



# ======================================================
# PHASE 26B.3 - LINK CONFIDENCE ENGINE
# ======================================================
LINK_CONFIDENCE_LOCK = threading.Lock()
LAST_LINK_CONFIDENCE_BUILD = 0


def _confidence_invalid_value(value):
    text = clean_ascii(value).strip().lower()
    if not text:
        return False
    invalid_markers = (
        "no such object", "no such instance", "unknown object identifier",
        "end of mib", "timeout", "error in packet", "unknown lldp neighbor"
    )
    return any(marker in text for marker in invalid_markers)


def _confidence_device_token(value):
    text = clean_ascii(value).replace("+", " ").replace("_", " ").strip().lower()
    text = text.split(".", 1)[0]
    text = re.sub(r"\b(cisco|the|lab|com|local)\b", " ", text)
    return re.sub(r"[^a-z0-9]+", "", text)


def _confidence_canonical_device(value):
    raw = clean_ascii(value)
    if not raw:
        return raw
    exact = _canonical_inventory_device(raw, "")
    if exact in config.get("devices", {}):
        return exact
    token = _confidence_device_token(raw)
    if not token:
        return raw
    best = None
    for name in config.get("devices", {}):
        candidate = _confidence_device_token(name)
        if candidate == token:
            return clean_ascii(name)
        if candidate and (candidate.endswith(token) or token.endswith(candidate)):
            if best is None or len(candidate) < len(_confidence_device_token(best)):
                best = clean_ascii(name)
    return best or raw


def _confidence_interface_token(value):
    text = clean_ascii(value).strip().lower().replace(" ", "")
    replacements = (
        ("gigabitethernet", "gi"), ("tengigabitethernet", "te"),
        ("fastethernet", "fa"), ("ethernet", "eth"),
        ("port-channel", "po"), ("portchannel", "po")
    )
    for old, new in replacements:
        if text.startswith(old):
            text = new + text[len(old):]
            break
    return re.sub(r"[^a-z0-9/.-]+", "", text)


def _confidence_endpoint(device, interface):
    return {
        "device": _confidence_canonical_device(device),
        "interface": clean_ascii(interface),
        "device_token": _confidence_device_token(_confidence_canonical_device(device)),
        "interface_token": _confidence_interface_token(interface),
    }




def _manual_evidence_rows():
    """Return only explicit user-saved links as MANUAL confidence evidence."""
    rows = []
    for item in config.get("infrastructure_links", []) or []:
        if not isinstance(item, dict) or not _is_explicit_saved_infrastructure_link(item):
            continue
        source_device = clean_ascii(item.get("from", ""))
        target_device = clean_ascii(item.get("to", ""))
        source_interface = clean_ascii(item.get("source_interface", ""))
        target_interface = clean_ascii(item.get("target_interface", "") or item.get("destination_interface", ""))
        if not source_device or not target_device:
            continue
        rows.append({
            "id": clean_ascii(item.get("id", "")),
            "source": "MANUAL",
            "active": True,
            "local_device": source_device,
            "local_interface": source_interface,
            "remote_device": target_device,
            "remote_interface": target_interface,
        })
    return rows


def build_link_confidence_database(force=False):
    """Merge directional CDP/LLDP advertisements and manual links into physical links."""
    global LAST_LINK_CONFIDENCE_BUILD
    settings = config.get("phase26b3_link_confidence", {})
    if not bool(settings.get("enabled", True)):
        return config.get("merged_physical_links", {})
    current_time = time.time()
    if not force and LAST_LINK_CONFIDENCE_BUILD and current_time - LAST_LINK_CONFIDENCE_BUILD < LINK_CONFIDENCE_INTERVAL:
        return config.get("merged_physical_links", {})
    if not LINK_CONFIDENCE_LOCK.acquire(blocking=False):
        return config.get("merged_physical_links", {})
    try:
        evidence = []
        rejected = []
        for record in config.get("discovered_infrastructure_links", {}).values():
            if not isinstance(record, dict):
                continue
            source = clean_ascii(record.get("source", "")).upper()
            if source not in {"CDP", "LLDP"}:
                continue
            values = [record.get("remote_device"), record.get("remote_device_id"), record.get("remote_interface")]
            if any(_confidence_invalid_value(value) for value in values):
                rejected.append(clean_ascii(record.get("id", "")))
                continue
            if not clean_ascii(record.get("local_device", "")) or not clean_ascii(record.get("remote_device", "")):
                rejected.append(clean_ascii(record.get("id", "")))
                continue
            evidence.append(dict(record))
        if bool(settings.get("include_manual_links", True)):
            evidence.extend(_manual_evidence_rows())

        # Manual links can identify LLDP endpoints that advertise only a MAC address.
        manual_by_local = {}
        for row in evidence:
            if clean_ascii(row.get("source", "")).upper() != "MANUAL":
                continue
            for local_device, local_interface, remote_device, remote_interface in (
                (row.get("local_device"), row.get("local_interface"), row.get("remote_device"), row.get("remote_interface")),
                (row.get("remote_device"), row.get("remote_interface"), row.get("local_device"), row.get("local_interface")),
            ):
                key = (_confidence_device_token(local_device), _confidence_interface_token(local_interface))
                manual_by_local.setdefault(key, []).append((remote_device, remote_interface))

        groups = {}
        for row in evidence:
            local = _confidence_endpoint(row.get("local_device", ""), row.get("local_interface", ""))
            remote = _confidence_endpoint(row.get("remote_device", ""), row.get("remote_interface", ""))
            source = clean_ascii(row.get("source", "")).upper()
            if source == "LLDP" and re.fullmatch(r"[0-9a-f]{12}", remote["device_token"] or ""):
                matches = manual_by_local.get((local["device_token"], local["interface_token"]), [])
                if len(matches) == 1:
                    remote = _confidence_endpoint(matches[0][0], matches[0][1])
                    row["inferred_remote_device"] = remote["device"]
                    row["inferred_from"] = "MANUAL_PORT_MAPPING"
            if not local["device_token"] or not remote["device_token"]:
                rejected.append(clean_ascii(row.get("id", "")))
                continue
            key = _confidence_physical_key(local, remote)
            group = groups.setdefault(key, {"key": key, "endpoints": [local, remote], "evidence": []})
            group["evidence"].append(row)

        merged = {}
        stamp = now()
        prior_db = config.get("merged_physical_links", {})
        for key, group in groups.items():
            sources = sorted(set(clean_ascii(x.get("source", "")).upper() for x in group["evidence"]))
            active_sources = sorted(set(
                clean_ascii(x.get("source", "")).upper() for x in group["evidence"]
                if x.get("active", True)
            ))
            protocol_sources = set(active_sources) & {"CDP", "LLDP"}
            if {"CDP", "LLDP"}.issubset(protocol_sources):
                confidence = int(settings.get("multi_protocol_confidence", 100))
            elif "CDP" in protocol_sources:
                confidence = int(settings.get("cdp_only_confidence", 98))
            elif "LLDP" in protocol_sources:
                confidence = int(settings.get("lldp_only_confidence", 95))
            elif "MANUAL" in active_sources:
                confidence = int(settings.get("manual_only_confidence", 80))
            else:
                confidence = 0
            bidirectional = False
            directions = set()
            for item in group["evidence"]:
                directions.add((
                    _confidence_device_token(item.get("local_device", "")),
                    _confidence_device_token(item.get("remote_device", "")),
                    clean_ascii(item.get("source", "")).upper(),
                ))
            for a, b, source in list(directions):
                if (b, a, source) in directions:
                    bidirectional = True
                    break
            prior = prior_db.get(key, {}) if isinstance(prior_db.get(key, {}), dict) else {}
            endpoint_a, endpoint_b = group["endpoints"]
            active = confidence >= int(settings.get("minimum_active_confidence", 70)) and bool(active_sources)
            merged[key] = {
                "id": key,
                "endpoint_a": {"device": endpoint_a["device"], "interface": endpoint_a["interface"]},
                "endpoint_b": {"device": endpoint_b["device"], "interface": endpoint_b["interface"]},
                "confidence": max(0, min(100, confidence)),
                "active": active,
                "sources": sources,
                "active_sources": active_sources,
                "bidirectional": bidirectional,
                "evidence_count": len(group["evidence"]),
                "evidence_ids": [clean_ascii(x.get("id", "")) for x in group["evidence"] if clean_ascii(x.get("id", ""))],
                "first_seen": prior.get("first_seen", stamp),
                "last_evaluated": stamp,
                "status": "VERIFIED" if confidence == 100 else ("HIGH" if confidence >= 90 else ("MANUAL" if confidence >= 70 else "INACTIVE")),
            }
        config["merged_physical_links"] = merged
        active_links = [x for x in merged.values() if x.get("active")]
        config.setdefault("phase26b3_link_confidence", {}).update({
            "phase": "26B.3",
            "last_build": stamp,
            "raw_evidence_count": len(evidence),
            "rejected_evidence_count": len([x for x in rejected if x]),
            "rejected_evidence_ids": [x for x in rejected if x],
            "merged_link_count": len(merged),
            "active_link_count": len(active_links),
            "verified_link_count": sum(1 for x in active_links if x.get("confidence") == 100),
        })
        LAST_LINK_CONFIDENCE_BUILD = current_time
        save_config()
        write_event(
            f"CONFIG | LINK CONFIDENCE | Phase 26B.3 | Evidence: {len(evidence)} | "
            f"Merged Links: {len(merged)} | Verified: {config['phase26b3_link_confidence']['verified_link_count']} | "
            f"Rejected: {config['phase26b3_link_confidence']['rejected_evidence_count']}"
        )
        return merged
    except Exception as exc:
        write_event(f"ERROR | LINK CONFIDENCE | Phase 26B.3 failed: {exc}")
        return config.get("merged_physical_links", {})
    finally:
        LINK_CONFIDENCE_LOCK.release()


def build_link_confidence_summary():
    links = list(config.get("merged_physical_links", {}).values())
    links.sort(key=lambda item: (-int(item.get("confidence", 0)), clean_ascii(item.get("id", ""))))
    return {
        "success": True,
        "phase": "26B.3",
        "settings": config.get("phase26b3_link_confidence", {}),
        "merged_link_count": len(links),
        "active_link_count": sum(1 for item in links if item.get("active")),
        "verified_link_count": sum(1 for item in links if item.get("active") and item.get("confidence") == 100),
        "links": links,
    }



# ======================================================
# PHASE 26B.4 - SELF-BUILDING TOPOLOGY ENGINE
# ======================================================
SELF_BUILDING_TOPOLOGY_LOCK = threading.Lock()
LAST_SELF_BUILDING_TOPOLOGY_BUILD = 0


def _phase26b4_settings():
    settings = config.setdefault("phase26b4_self_building_topology", {})
    settings.setdefault("enabled", True)
    settings.setdefault("phase", "26B.4")
    settings.setdefault("interval_seconds", 60)
    settings.setdefault("minimum_confidence", 70)
    settings.setdefault("include_manual_fallback", True)
    settings.setdefault("prefer_discovered_links", True)
    return settings


def _phase26b4_is_infrastructure_device(device_name):
    name = clean_ascii(device_name)
    if not name:
        return False
    if is_core_topology_device(name) or is_infrastructure_topology_device(name):
        return True
    registry = get_infrastructure_devices()
    return name in registry


def _phase26b4_link_rank(link):
    sources = set(clean_ascii(value).upper() for value in link.get("active_sources", []))
    discovered = bool(sources & {"CDP", "LLDP"})
    return (
        1 if discovered else 0,
        int(link.get("confidence", 0) or 0),
        int(link.get("evidence_count", 0) or 0),
        1 if link.get("bidirectional") else 0,
    )


def _phase26b4_device_pair_key(device_a, device_b):
    return tuple(sorted((
        _confidence_device_token(device_a),
        _confidence_device_token(device_b),
    )))


def _phase26b4_synthetic_link(merged_link):
    endpoint_a = merged_link.get("endpoint_a", {}) if isinstance(merged_link.get("endpoint_a", {}), dict) else {}
    endpoint_b = merged_link.get("endpoint_b", {}) if isinstance(merged_link.get("endpoint_b", {}), dict) else {}
    device_a = _confidence_canonical_device(endpoint_a.get("device", ""))
    device_b = _confidence_canonical_device(endpoint_b.get("device", ""))
    interface_a = clean_ascii(endpoint_a.get("interface", ""))
    interface_b = clean_ascii(endpoint_b.get("interface", ""))
    return {
        "id": clean_ascii(merged_link.get("id", "")),
        "from": device_a,
        "to": device_b,
        "source_interface": interface_a,
        "target_interface": interface_b,
        "source_port_index": "",
        "target_port_index": "",
        "link_type": "Auto-Discovered Physical Link",
        "label": f"{device_a} to {device_b}",
        "confidence": int(merged_link.get("confidence", 0) or 0),
        "sources": list(merged_link.get("sources", [])),
        "active_sources": list(merged_link.get("active_sources", [])),
        "bidirectional": bool(merged_link.get("bidirectional", False)),
        "evidence_count": int(merged_link.get("evidence_count", 0) or 0),
        "evidence_ids": list(merged_link.get("evidence_ids", [])),
        "auto_generated": True,
        "phase": "26B.4",
    }


def build_self_building_topology(force=False):
    """Build the physical infrastructure topology from merged CDP/LLDP/manual evidence.

    The generated link list is the topology source used by the network map while
    Phase 26B.4 is enabled. Saved manual links remain evidence and fallback; they
    are not deleted or rewritten.
    """
    global LAST_SELF_BUILDING_TOPOLOGY_BUILD
    settings = _phase26b4_settings()
    if not bool(settings.get("enabled", True)):
        return config.get("phase26b4_topology", {})

    current_time = time.time()
    interval = max(10, int(settings.get("interval_seconds", 60) or 60))
    if not force and LAST_SELF_BUILDING_TOPOLOGY_BUILD and current_time - LAST_SELF_BUILDING_TOPOLOGY_BUILD < interval:
        return config.get("phase26b4_topology", {})
    if not SELF_BUILDING_TOPOLOGY_LOCK.acquire(blocking=False):
        return config.get("phase26b4_topology", {})

    try:
        merged_db = build_link_confidence_database(force=force)
        minimum_confidence = int(settings.get("minimum_confidence", 70) or 70)
        candidates = []
        rejected = []

        for merged_link in merged_db.values():
            if not isinstance(merged_link, dict):
                continue
            if not merged_link.get("active"):
                continue
            confidence = int(merged_link.get("confidence", 0) or 0)
            if confidence < minimum_confidence:
                rejected.append({"id": clean_ascii(merged_link.get("id", "")), "reason": "below minimum confidence"})
                continue
            synthetic = _phase26b4_synthetic_link(merged_link)
            if not synthetic.get("from") or not synthetic.get("to") or synthetic.get("from") == synthetic.get("to"):
                rejected.append({"id": clean_ascii(merged_link.get("id", "")), "reason": "invalid endpoints"})
                continue
            candidates.append((merged_link, synthetic))

        # One physical cable per device pair. This collapses duplicate endpoint
        # representations such as Terminal Server Fa0/0 versus eth0, preferring
        # discovered and higher-confidence evidence.
        best_by_pair = {}
        for merged_link, synthetic in candidates:
            pair_key = _phase26b4_device_pair_key(synthetic["from"], synthetic["to"])
            current = best_by_pair.get(pair_key)
            if current is None or _phase26b4_link_rank(merged_link) > _phase26b4_link_rank(current[0]):
                best_by_pair[pair_key] = (merged_link, synthetic)

        selected_links = [value[1] for value in best_by_pair.values()]
        selected_links.sort(key=lambda item: (
            -int(item.get("confidence", 0) or 0),
            clean_ascii(item.get("from", "")).lower(),
            clean_ascii(item.get("to", "")).lower(),
        ))

        infrastructure_links = []
        endpoint_links = []
        registry = get_infrastructure_devices()
        infrastructure_names = set(registry.keys())
        controlled = config.get("controlled_discovery", {})
        allow_endpoint_auto_topology = bool(
            controlled.get("allow_endpoint_auto_topology", False)
        )

        for link in selected_links:
            from_name = clean_ascii(link.get("from", ""))
            to_name = clean_ascii(link.get("to", ""))

            # Controlled Discovery source of truth:
            # a topology node must already exist in provisioned infrastructure.
            from_is_infra = from_name in infrastructure_names
            to_is_infra = to_name in infrastructure_names

            if from_is_infra and to_is_infra:
                infrastructure_links.append(link)
            elif allow_endpoint_auto_topology:
                endpoint_link = dict(link)
                endpoint_link["is_endpoint_link"] = True
                endpoint_link["link_type"] = "Observed Endpoint Link"
                endpoint_links.append(endpoint_link)
            else:
                rejected.append({
                    "id": clean_ascii(link.get("id", "")),
                    "reason": "controlled discovery: endpoint observations do not create topology"
                })

        reconciled = reconcile_phase26_infrastructure_topology(
            infrastructure_links,
            infrastructure_names,
            registry,
        )

        # Store the reconciled direction in the generated source list so all map
        # consumers see a stable parent -> child orientation.
        generated_links = []
        relationship_by_id = {
            clean_ascii(item.get("id", "")): item
            for item in reconciled.get("relationships", [])
            if clean_ascii(item.get("id", ""))
        }
        for raw in infrastructure_links:
            oriented = relationship_by_id.get(clean_ascii(raw.get("id", "")))
            if oriented:
                enriched = dict(raw)
                enriched.update({
                    "from": oriented.get("from", raw.get("from", "")),
                    "to": oriented.get("to", raw.get("to", "")),
                    "source_interface": oriented.get("source_interface", raw.get("source_interface", "")),
                    "target_interface": oriented.get("target_interface", raw.get("target_interface", "")),
                    "saved_direction_reversed": oriented.get("saved_direction_reversed", False),
                })
                generated_links.append(enriched)
            else:
                generated_links.append(raw)

        if bool(config.get("controlled_discovery", {}).get("allow_endpoint_auto_topology", False)):
            generated_links.extend(endpoint_links)
        stamp = now()
        payload = {
            "success": True,
            "phase": "26B.4",
            "mode": "Controlled Infrastructure Discovery",
            "source_of_truth": "Provisioned infrastructure inventory plus verified infrastructure-only discovery evidence",
            "generated_links": generated_links,
            "infrastructure_links": generated_links[:len(infrastructure_links)],
            "endpoint_links": endpoint_links,
            "relationships": reconciled.get("relationships", []),
            "roots": reconciled.get("roots", []),
            "children_by_parent": reconciled.get("children_by_parent", {}),
            "parent_by_child": reconciled.get("parent_by_child", {}),
            "validation": reconciled.get("validation", {}),
            "rejected_links": rejected,
            "last_build": stamp,
            "summary": {
                "merged_candidates": len(candidates),
                "unique_device_pairs": len(selected_links),
                "generated_link_count": len(generated_links),
                "active_infrastructure_link_count": len(infrastructure_links),
                "endpoint_link_count": len(endpoint_links),
                "root_count": len(reconciled.get("roots", [])),
                "topology_valid": bool(reconciled.get("validation", {}).get("valid", False)),
                "duplicate_device_pairs_collapsed": max(0, len(candidates) - len(selected_links)),
            },
        }
        config["generated_infrastructure_links"] = generated_links
        config["phase26b4_topology"] = payload
        settings.update({
            "last_build": stamp,
            "generated_link_count": len(generated_links),
            "active_infrastructure_link_count": len(infrastructure_links),
            "endpoint_link_count": len(endpoint_links),
            "root_count": len(reconciled.get("roots", [])),
            "topology_valid": bool(reconciled.get("validation", {}).get("valid", False)),
            "duplicate_device_pairs_collapsed": max(0, len(candidates) - len(selected_links)),
        })
        LAST_SELF_BUILDING_TOPOLOGY_BUILD = current_time
        save_config()
        write_event(
            f"CONFIG | SELF-BUILDING TOPOLOGY | Phase 26B.4 | "
            f"Infrastructure Links: {len(infrastructure_links)} | Endpoint Links: {len(endpoint_links)} | "
            f"Roots: {len(reconciled.get('roots', []))} | Valid: {settings['topology_valid']}"
        )
        return payload
    except Exception as exc:
        write_event(f"ERROR | SELF-BUILDING TOPOLOGY | Phase 26B.4 failed: {exc}")
        return config.get("phase26b4_topology", {"success": False, "phase": "26B.4", "message": str(exc)})
    finally:
        SELF_BUILDING_TOPOLOGY_LOCK.release()


def build_self_building_topology_summary():
    payload = build_self_building_topology(force=False)
    return {
        "success": bool(payload.get("success", False)),
        "phase": "26B.4",
        "settings": _phase26b4_settings(),
        "summary": payload.get("summary", {}),
        "roots": payload.get("roots", []),
        "relationships": payload.get("relationships", []),
        "generated_links": payload.get("generated_links", []),
        "validation": payload.get("validation", {}),
        "last_build": payload.get("last_build", ""),
    }


# ======================================================
# PHASE 26B.5 - TOPOLOGY CHANGE DETECTION & AUTO-RECONCILIATION
# ======================================================
TOPOLOGY_CHANGE_LOCK = threading.Lock()
LAST_TOPOLOGY_CHANGE_CHECK = 0


def _phase26b5_settings():
    settings = config.setdefault("phase26b5_topology_change_detection", {})
    settings.setdefault("enabled", True)
    settings.setdefault("phase", "26B.5")
    settings.setdefault("interval_seconds", 60)
    settings.setdefault("confirmation_cycles", 2)
    settings.setdefault("history_limit", 100)
    settings.setdefault("auto_reconcile", True)
    settings.setdefault("detect_endpoint_changes", True)
    settings.setdefault("detect_evidence_changes", True)
    return settings


def _phase26b5_link_record(link):
    """Return only stable, topology-significant fields for comparison."""
    return {
        "id": clean_ascii(link.get("id", "")),
        "from": clean_ascii(link.get("from", "")),
        "to": clean_ascii(link.get("to", "")),
        "source_interface": _confidence_interface_token(link.get("source_interface", "")),
        "target_interface": _confidence_interface_token(link.get("target_interface", "")),
        "confidence": int(link.get("confidence", 0) or 0),
        "active_sources": sorted(clean_ascii(x).upper() for x in link.get("active_sources", []) if clean_ascii(x)),
        "bidirectional": bool(link.get("bidirectional", False)),
        "is_endpoint_link": bool(link.get("is_endpoint_link", False)),
    }


def _phase26b5_snapshot(topology):
    settings = _phase26b5_settings()
    links = []
    for link in topology.get("generated_links", []) if isinstance(topology, dict) else []:
        if not isinstance(link, dict):
            continue
        if link.get("is_endpoint_link") and not bool(settings.get("detect_endpoint_changes", True)):
            continue
        record = _phase26b5_link_record(link)
        if not bool(settings.get("detect_evidence_changes", True)):
            record.pop("confidence", None)
            record.pop("active_sources", None)
            record.pop("bidirectional", None)
        links.append(record)
    links.sort(key=lambda x: (x.get("id", ""), x.get("from", ""), x.get("to", "")))
    relationships = []
    for item in topology.get("relationships", []) if isinstance(topology, dict) else []:
        if isinstance(item, dict):
            relationships.append({
                "id": clean_ascii(item.get("id", "")),
                "from": clean_ascii(item.get("from", "")),
                "to": clean_ascii(item.get("to", "")),
                "source_interface": _confidence_interface_token(item.get("source_interface", "")),
                "target_interface": _confidence_interface_token(item.get("target_interface", "")),
            })
    relationships.sort(key=lambda x: (x.get("id", ""), x.get("from", ""), x.get("to", "")))
    return {
        "links": links,
        "relationships": relationships,
        "roots": sorted(clean_ascii(x) for x in topology.get("roots", []) if clean_ascii(x)),
        "topology_valid": bool(topology.get("validation", {}).get("valid", False)),
    }




def _phase26b5_index(items):
    indexed = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = clean_ascii(item.get("id", ""))
        if not key:
            key = "|".join([
                clean_ascii(item.get("from", "")),
                clean_ascii(item.get("source_interface", "")),
                clean_ascii(item.get("to", "")),
                clean_ascii(item.get("target_interface", "")),
            ])
        indexed[key] = item
    return indexed


def _phase26b5_diff(old_snapshot, new_snapshot):
    old_links = _phase26b5_index(old_snapshot.get("links", []))
    new_links = _phase26b5_index(new_snapshot.get("links", []))
    added = [new_links[key] for key in sorted(new_links.keys() - old_links.keys())]
    removed = [old_links[key] for key in sorted(old_links.keys() - new_links.keys())]
    changed = []
    for key in sorted(old_links.keys() & new_links.keys()):
        if old_links[key] != new_links[key]:
            changed.append({"id": key, "before": old_links[key], "after": new_links[key]})

    old_rel = _phase26b5_index(old_snapshot.get("relationships", []))
    new_rel = _phase26b5_index(new_snapshot.get("relationships", []))
    relationship_added = [new_rel[key] for key in sorted(new_rel.keys() - old_rel.keys())]
    relationship_removed = [old_rel[key] for key in sorted(old_rel.keys() - new_rel.keys())]
    relationship_changed = []
    for key in sorted(old_rel.keys() & new_rel.keys()):
        if old_rel[key] != new_rel[key]:
            relationship_changed.append({"id": key, "before": old_rel[key], "after": new_rel[key]})

    roots_changed = old_snapshot.get("roots", []) != new_snapshot.get("roots", [])
    validity_changed = old_snapshot.get("topology_valid") != new_snapshot.get("topology_valid")
    changed_any = bool(added or removed or changed or relationship_added or relationship_removed or relationship_changed or roots_changed or validity_changed)
    return {
        "changed": changed_any,
        "added_links": added,
        "removed_links": removed,
        "modified_links": changed,
        "added_relationships": relationship_added,
        "removed_relationships": relationship_removed,
        "modified_relationships": relationship_changed,
        "roots_before": old_snapshot.get("roots", []),
        "roots_after": new_snapshot.get("roots", []),
        "roots_changed": roots_changed,
        "valid_before": old_snapshot.get("topology_valid"),
        "valid_after": new_snapshot.get("topology_valid"),
        "validity_changed": validity_changed,
    }


def _phase26b5_change_severity(diff):
    if diff.get("removed_relationships") or diff.get("valid_after") is False:
        return "CRITICAL"
    if diff.get("removed_links") or diff.get("modified_relationships") or diff.get("roots_changed"):
        return "WARNING"
    return "INFO"


def _phase26b5_change_summary(diff):
    return (
        f"Added Links: {len(diff.get('added_links', []))} | "
        f"Removed Links: {len(diff.get('removed_links', []))} | "
        f"Modified Links: {len(diff.get('modified_links', []))} | "
        f"Relationship Changes: "
        f"+{len(diff.get('added_relationships', []))}/"
        f"-{len(diff.get('removed_relationships', []))}/"
        f"~{len(diff.get('modified_relationships', []))}"
    )


def _phase26b5_append_history(record):
    history = config.setdefault("phase26b5_topology_change_history", [])
    history.append(record)
    limit = max(10, int(_phase26b5_settings().get("history_limit", 100) or 100))
    if len(history) > limit:
        del history[:-limit]


def check_topology_changes(force=False, confirm_immediately=False):
    """Detect stable physical-topology changes and automatically reconcile the map.

    Normal monitor-loop checks require the same candidate change for two cycles by
    default. This suppresses one-poll CDP/LLDP gaps. API tests may use
    confirm_immediately=true to validate the engine without waiting two cycles.
    """
    global LAST_TOPOLOGY_CHANGE_CHECK
    settings = _phase26b5_settings()
    if not bool(settings.get("enabled", True)):
        return {"success": True, "phase": "26B.5", "enabled": False}

    current_time = time.time()
    interval = max(10, int(settings.get("interval_seconds", 60) or 60))
    if not force and LAST_TOPOLOGY_CHANGE_CHECK and current_time - LAST_TOPOLOGY_CHANGE_CHECK < interval:
        return build_topology_change_summary()
    if not TOPOLOGY_CHANGE_LOCK.acquire(blocking=False):
        return build_topology_change_summary()

    try:
        # Discovery has normally just run in monitor_loop. Forced checks refresh it.
        if force:
            discover_cdp_neighbors(force=True)
            discover_lldp_neighbors(force=True)
            build_link_confidence_database(force=True)
        topology = build_self_building_topology(force=True)
        snapshot = _phase26b5_snapshot(topology)
        snapshot_key = _phase26b5_snapshot_key(snapshot)
        accepted = config.get("phase26b5_accepted_snapshot")
        stamp = now()
        LAST_TOPOLOGY_CHANGE_CHECK = current_time
        settings["last_check"] = stamp

        if not isinstance(accepted, dict) or not accepted:
            config["phase26b5_accepted_snapshot"] = snapshot
            config["phase26b5_pending_change"] = {}
            settings.update({
                "status": "BASELINE ESTABLISHED",
                "last_reconciliation": stamp,
                "accepted_link_count": len(snapshot.get("links", [])),
                "pending_confirmation_count": 0,
            })
            save_config()
            write_event(f"CONFIG | TOPOLOGY CHANGE DETECTION | Phase 26B.5 | Baseline established with {len(snapshot.get('links', []))} links")
            return {"success": True, "phase": "26B.5", "status": "BASELINE ESTABLISHED", "change_confirmed": False, "snapshot": snapshot}

        diff = _phase26b5_diff(accepted, snapshot)
        if not diff.get("changed"):
            config["phase26b5_pending_change"] = {}
            settings.update({
                "status": "STABLE",
                "pending_confirmation_count": 0,
                "accepted_link_count": len(snapshot.get("links", [])),
            })
            save_config()
            return {"success": True, "phase": "26B.5", "status": "STABLE", "change_confirmed": False, "diff": diff}

        pending = config.get("phase26b5_pending_change", {})
        if not isinstance(pending, dict) or pending.get("snapshot_key") != snapshot_key:
            pending = {"snapshot_key": snapshot_key, "first_seen": stamp, "last_seen": stamp, "confirmation_count": 1, "diff": diff}
        else:
            pending["last_seen"] = stamp
            pending["confirmation_count"] = int(pending.get("confirmation_count", 0) or 0) + 1
            pending["diff"] = diff
        config["phase26b5_pending_change"] = pending
        required = 1 if confirm_immediately else max(1, int(settings.get("confirmation_cycles", 2) or 2))
        settings.update({
            "status": "CHANGE PENDING CONFIRMATION",
            "pending_confirmation_count": pending["confirmation_count"],
            "required_confirmation_count": required,
        })

        if pending["confirmation_count"] < required:
            save_config()
            write_event(
                f"NOTICE | TOPOLOGY CHANGE PENDING | Phase 26B.5 | "
                f"Confirmation {pending['confirmation_count']} of {required} | {_phase26b5_change_summary(diff)}"
            )
            return {"success": True, "phase": "26B.5", "status": "CHANGE PENDING CONFIRMATION", "change_confirmed": False, "confirmation_count": pending["confirmation_count"], "required": required, "diff": diff}

        severity = _phase26b5_change_severity(diff)
        incident_id = "topology-" + datetime.now().strftime("%Y%m%d%H%M%S%f")
        record = {
            "id": incident_id,
            "phase": "26B.5",
            "detected_at": stamp,
            "severity": severity,
            "status": "AUTO-RECONCILED" if bool(settings.get("auto_reconcile", True)) else "DETECTED",
            "summary": _phase26b5_change_summary(diff),
            "diff": diff,
            "topology_valid": snapshot.get("topology_valid", False),
            "roots": snapshot.get("roots", []),
        }
        if bool(settings.get("auto_reconcile", True)):
            # build_self_building_topology already generated the reconciled tree.
            config["phase26b5_accepted_snapshot"] = snapshot
            settings["last_reconciliation"] = stamp
            settings["reconciliation_count"] = int(settings.get("reconciliation_count", 0) or 0) + 1
        _phase26b5_append_history(record)
        config["phase26b5_last_change"] = record
        config["phase26b5_pending_change"] = {}
        settings.update({
            "status": record["status"],
            "last_change": stamp,
            "last_change_id": incident_id,
            "last_change_severity": severity,
            "pending_confirmation_count": 0,
            "accepted_link_count": len(snapshot.get("links", [])),
        })
        save_config()
        write_event(f"{severity} | TOPOLOGY CHANGE {record['status']} | Phase 26B.5 | {incident_id} | {record['summary']}")
        return {"success": True, "phase": "26B.5", "status": record["status"], "change_confirmed": True, "incident": record, "topology": topology}
    except Exception as exc:
        write_event(f"ERROR | TOPOLOGY CHANGE DETECTION | Phase 26B.5 failed: {exc}")
        return {"success": False, "phase": "26B.5", "message": str(exc)}
    finally:
        TOPOLOGY_CHANGE_LOCK.release()


def build_topology_change_summary():
    settings = _phase26b5_settings()
    history = config.get("phase26b5_topology_change_history", [])
    pending = config.get("phase26b5_pending_change", {})
    accepted = config.get("phase26b5_accepted_snapshot", {})
    return {
        "success": True,
        "phase": "26B.5",
        "mode": "Topology Change Detection & Auto-Reconciliation",
        "settings": settings,
        "status": settings.get("status", "NOT INITIALIZED"),
        "accepted_snapshot": accepted,
        "pending_change": pending,
        "last_change": config.get("phase26b5_last_change", {}),
        "history_count": len(history),
        "history": list(reversed(history[-25:])),
    }



# ================================================================
# PHASE 26B.6A - INCIDENT HISTORY LIFECYCLE CLEANUP
# ================================================================
ROOT_CAUSE_TOPOLOGY_LOCK = threading.Lock()
LAST_ROOT_CAUSE_TOPOLOGY_CHECK = 0


def _phase26b6_settings():
    settings = config.setdefault("phase26b6_root_cause_topology", {})
    defaults = {
        "enabled": True,
        "phase": "26B.6A",
        "interval_seconds": 30,
        "confirmation_cycles": 2,
        "history_limit": 100,
        "suppress_downstream_alerts": True,
        "include_endpoint_impact": True,
        "status": "NOT INITIALIZED",
    }
    for key, value in defaults.items():
        settings.setdefault(key, value)
    return settings


def _phase26b6_state(device_name):
    name = clean_ascii(device_name)
    if is_device_in_maintenance(name):
        return "MAINTENANCE"
    info = status.get(name, {})
    state = clean_ascii(info.get("state", "UNKNOWN")).upper() or "UNKNOWN"
    if name == get_internet_service_name() and state in {"UNKNOWN", "CHECKING"}:
        checks = config.get("internet_uptime", {})
        state = clean_ascii(checks.get("current_state", state)).upper() or state
    return state


def _phase26b6_graph():
    topology = config.get("phase26b4_topology", {})
    relationships = topology.get("relationships", []) if isinstance(topology, dict) else []
    generated = topology.get("generated_links", []) if isinstance(topology, dict) else []
    children = {}
    parents = {}
    edge_by_child = {}
    for rel in relationships:
        parent = clean_ascii(rel.get("from", "")); child = clean_ascii(rel.get("to", ""))
        if parent and child:
            children.setdefault(parent, []).append(child); parents[child] = parent; edge_by_child[child] = rel
    endpoints = {}
    for link in generated:
        if not link.get("is_endpoint_link"):
            continue
        parent = clean_ascii(link.get("from", "")); child = clean_ascii(link.get("to", ""))
        if parent and child:
            endpoints.setdefault(parent, []).append(child); parents.setdefault(child, parent); edge_by_child[child] = link
    roots = [clean_ascii(x) for x in topology.get("roots", []) if clean_ascii(x)]
    return children, endpoints, parents, edge_by_child, roots


def _phase26b6_descendants(node, children, endpoints):
    result=[]; queue=list(children.get(node, [])) + list(endpoints.get(node, [])); seen=set()
    while queue:
        item=queue.pop(0)
        if item in seen: continue
        seen.add(item); result.append(item)
        queue.extend(children.get(item, [])); queue.extend(endpoints.get(item, []))
    return result


def _phase26b6_depth(node, parents):
    depth=0; seen=set(); current=node
    while current in parents and current not in seen:
        seen.add(current); current=parents[current]; depth += 1
    return depth


def _phase26b6_signature(incident):
    return "|".join([clean_ascii(incident.get("root_cause", "")), clean_ascii(incident.get("failure_type", "")), clean_ascii(incident.get("root_interface", ""))]).lower()




def _phase26b6a_normalize_history(save=False):
    """Collapse duplicate lifecycle records so each incident ID appears once.

    The newest copy wins, but fields from older copies are preserved when the
    newer copy does not contain them. RECOVERED takes precedence over ACTIVE.
    """
    raw = config.setdefault("phase26b6_root_cause_history", [])
    if not isinstance(raw, list):
        raw = []

    by_id = {}
    order = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        incident_id = clean_ascii(item.get("id", ""))
        if not incident_id:
            incident_id = "legacy-" + _phase26b6_signature(item)
        if incident_id not in by_id:
            by_id[incident_id] = dict(item)
            order.append(incident_id)
            continue

        merged = dict(by_id[incident_id])
        merged.update({k: v for k, v in item.items() if v not in (None, "", [], {})})
        statuses = {clean_ascii(by_id[incident_id].get("status", "")).upper(), clean_ascii(item.get("status", "")).upper()}
        if "RECOVERED" in statuses:
            merged["status"] = "RECOVERED"
        elif "ACTIVE" in statuses:
            merged["status"] = "ACTIVE"
        by_id[incident_id] = merged

    normalized = [by_id[i] for i in order]
    limit = max(10, int(_phase26b6_settings().get("history_limit", 100) or 100))
    normalized = normalized[-limit:]
    changed = normalized != raw
    config["phase26b6_root_cause_history"] = normalized
    if changed and save:
        save_config()
    return normalized, changed


def _phase26b6a_upsert_history(incident):
    """Insert or update one incident lifecycle record by incident ID."""
    if not isinstance(incident, dict) or not incident:
        return
    history, _ = _phase26b6a_normalize_history(save=False)
    incident_id = clean_ascii(incident.get("id", ""))
    replaced = False
    for idx, item in enumerate(history):
        if clean_ascii(item.get("id", "")) == incident_id and incident_id:
            merged = dict(item)
            merged.update(incident)
            history[idx] = merged
            replaced = True
            break
    if not replaced:
        history.append(dict(incident))
    limit = max(10, int(_phase26b6_settings().get("history_limit", 100) or 100))
    config["phase26b6_root_cause_history"] = history[-limit:]


def analyze_root_cause_topology(force=False, confirm_immediately=False):
    """Correlate live device/link states with the accepted physical topology.

    The highest failed upstream component becomes the primary incident. Every
    unreachable descendant is attached as impact and may be suppressed from
    duplicate alerting. Two matching cycles are required by default.
    """
    global LAST_ROOT_CAUSE_TOPOLOGY_CHECK
    settings=_phase26b6_settings()
    if not settings.get("enabled", True):
        return {"success": True, "phase": "26B.6A", "enabled": False}
    now_epoch=time.time(); interval=max(10, int(settings.get("interval_seconds", 30) or 30))
    if not force and LAST_ROOT_CAUSE_TOPOLOGY_CHECK and now_epoch-LAST_ROOT_CAUSE_TOPOLOGY_CHECK < interval:
        return build_root_cause_topology_summary()
    if not ROOT_CAUSE_TOPOLOGY_LOCK.acquire(blocking=False):
        return build_root_cause_topology_summary()
    try:
        _phase26b6a_normalize_history(save=False)
        LAST_ROOT_CAUSE_TOPOLOGY_CHECK=now_epoch; stamp=now(); settings["last_check"]=stamp
        children,endpoints,parents,edge_by_child,roots=_phase26b6_graph()
        infra=set(roots) | set(children.keys()) | {x for values in children.values() for x in values}
        unhealthy={name:_phase26b6_state(name) for name in infra if _phase26b6_state(name) in {"DOWN","CRITICAL","LINK_DOWN","UNREACHABLE"}}
        candidates=[]
        for name,state_value in unhealthy.items():
            parent=parents.get(name, "")
            # Do not promote a child when an upstream ancestor is already failed.
            ancestor_failed=False; cursor=parent; seen=set()
            while cursor and cursor not in seen:
                seen.add(cursor)
                if cursor in unhealthy: ancestor_failed=True; break
                cursor=parents.get(cursor, "")
            if not ancestor_failed:
                candidates.append(name)
        candidates.sort(key=lambda n: (_phase26b6_depth(n, parents), n.lower()))
        incident=None
        if candidates:
            root=candidates[0]; edge=edge_by_child.get(root, {}); impacted=_phase26b6_descendants(root, children, endpoints)
            phase26b7 = get_phase26b7_settings()
            impacted_states=[]
            for x in impacted:
                in_maintenance = is_device_in_maintenance(x)
                if in_maintenance and phase26b7.get("suppress_downstream_maintenance_impact", True):
                    impacted_states.append({"name":x,"state":get_maintenance_state_label(),"suppressed":True,"suppression_reason":"MAINTENANCE"})
                else:
                    impacted_states.append({"name":x,"state":_phase26b6_state(x),"suppressed":bool(settings.get("suppress_downstream_alerts",True)),"suppression_reason":"DOWNSTREAM" if settings.get("suppress_downstream_alerts",True) else ""})
            failure_type="UPSTREAM DEVICE FAILURE" if root in roots else "TOPOLOGY NODE FAILURE"
            root_interface=clean_ascii(edge.get("target_interface", edge.get("source_interface", "")))
            confidence=100 if unhealthy.get(root) in {"DOWN","CRITICAL"} else 95
            incident={
                "id":"rca-"+datetime.now().strftime("%Y%m%d%H%M%S%f"), "phase":"26B.6A", "detected_at":stamp,
                "severity":"CRITICAL", "status":"ACTIVE", "root_cause":root, "root_state":unhealthy[root],
                "failure_type":failure_type, "root_interface":root_interface, "upstream_parent":parents.get(root,""),
                "confidence":confidence, "impacted_devices":impacted_states, "impacted_count":len(impacted_states),
                "suppressed_alert_count":len(impacted_states) if settings.get("suppress_downstream_alerts",True) else 0,
                "summary":f"Primary incident: {root} is {unhealthy[root]}; {len(impacted_states)} downstream device(s) impacted.",
            }
        active=config.get("phase26b6_active_incident", {})
        pending=config.get("phase26b6_pending_incident", {})
        if incident is None:
            config["phase26b6_pending_incident"]={}
            if isinstance(active,dict) and active:
                recovered=dict(active); recovered["status"]="RECOVERED"; recovered["recovered_at"]=stamp
                _phase26b6a_upsert_history(recovered)
                config["phase26b6_last_incident"]=recovered; config["phase26b6_active_incident"]={}
                settings.update({"status":"RECOVERED","last_recovery":stamp,"active_incident_count":0})
                write_event(f"RECOVERY | ROOT CAUSE TOPOLOGY | Phase 26B.6A | {recovered.get('root_cause','')} recovered")
            else:
                settings.update({"status":"HEALTHY","active_incident_count":0})
            save_config(); return {"success":True,"phase":"26B.6A","status":settings["status"],"incident":{}}
        sig=_phase26b6_signature(incident); required=1 if confirm_immediately else max(1,int(settings.get("confirmation_cycles",2) or 2))
        if isinstance(active,dict) and active and _phase26b6_signature(active)==sig:
            active.update({"last_seen":stamp,"root_state":incident["root_state"],"impacted_devices":incident["impacted_devices"],"impacted_count":incident["impacted_count"],"suppressed_alert_count":incident["suppressed_alert_count"]})
            config["phase26b6_active_incident"]=active; _phase26b6a_upsert_history(active); settings.update({"status":"ACTIVE INCIDENT","active_incident_count":1})
            save_config(); return {"success":True,"phase":"26B.6A","status":"ACTIVE INCIDENT","incident":active}
        if not isinstance(pending,dict) or pending.get("signature")!=sig:
            pending={"signature":sig,"confirmation_count":1,"first_seen":stamp,"last_seen":stamp,"incident":incident}
        else:
            pending["confirmation_count"]=int(pending.get("confirmation_count",0))+1; pending["last_seen"]=stamp; pending["incident"]=incident
        config["phase26b6_pending_incident"]=pending
        if pending["confirmation_count"]<required:
            settings.update({"status":"INCIDENT PENDING CONFIRMATION","pending_confirmation_count":pending["confirmation_count"],"required_confirmation_count":required})
            save_config(); return {"success":True,"phase":"26B.6A","status":settings["status"],"confirmation_count":pending["confirmation_count"],"required":required,"candidate":incident}
        incident["confirmed_at"]=stamp; config["phase26b6_active_incident"]=incident; config["phase26b6_last_incident"]=incident; config["phase26b6_pending_incident"]={}
        _phase26b6a_upsert_history(incident)
        settings.update({"status":"ACTIVE INCIDENT","last_incident":stamp,"active_incident_count":1,"pending_confirmation_count":0,"last_root_cause":incident["root_cause"],"last_confidence":incident["confidence"]})
        save_config(); write_event(f"CRITICAL | ROOT CAUSE TOPOLOGY | Phase 26B.6A | {incident['root_cause']} | Impacted: {incident['impacted_count']} | Confidence: {incident['confidence']}%")
        return {"success":True,"phase":"26B.6A","status":"ACTIVE INCIDENT","incident":incident}
    except Exception as exc:
        write_event(f"ERROR | ROOT CAUSE TOPOLOGY | Phase 26B.6A failed: {exc}")
        return {"success":False,"phase":"26B.6A","message":str(exc)}
    finally:
        ROOT_CAUSE_TOPOLOGY_LOCK.release()


def build_root_cause_topology_summary():
    settings = _phase26b6_settings()
    history, cleaned = _phase26b6a_normalize_history(save=True)
    settings["phase"] = "26B.6A"
    settings["history_lifecycle_cleanup"] = True
    settings["history_duplicates_removed"] = bool(cleaned)
    return {
        "success": True,
        "phase": "26B.6A",
        "mode": "Root Cause Topology Intelligence + Incident History Lifecycle Cleanup",
        "status": settings.get("status", "NOT INITIALIZED"),
        "settings": settings,
        "active_incident": config.get("phase26b6_active_incident", {}),
        "pending_incident": config.get("phase26b6_pending_incident", {}),
        "last_incident": config.get("phase26b6_last_incident", {}),
        "history_count": len(history),
        "history": list(reversed(history[-25:])),
    }

def save_config():
    """Save config.json atomically so monitor_loop never reads a half-written file."""
    if RELATIONSHIP_ENGINE_READY and RELATIONSHIP_STORE is not None:
        try:
            RELATIONSHIP_STORE.sync_to_config(save=False)
        except Exception as exc:
            config.setdefault("relationship_engine", {}).update({
                "phase": "27A",
                "ready": False,
                "save_sync_error": str(exc),
                "updated_at": now(),
            })

    atomic_write_json_config(CONFIG_FILE, config)




def get_notification_settings():
    return config.get("notifications", {})






# ======================================================
# PHASE 12B.5.3 - ALERT STATE TRANSITION ENGINE HELPERS
# ======================================================


def build_transition_event_id():
    """Create a unique event id for each alert/recovery transition."""
    global ALERT_TRANSITION_SEQUENCE

    ALERT_TRANSITION_SEQUENCE += 1
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"evt-{stamp}-{ALERT_TRANSITION_SEQUENCE}"


def queue_alert_transition_event(
    event_type,
    severity,
    source,
    device,
    problem,
    previous_state="",
    current_state="",
    port="",
    root_cause="",
    voice_message=""
):
    """
    Store an alert or recovery event for the dashboard API.

    event_type values:
    - ALERT
    - RESOLVED

    These events are intentionally separate from the active alert table.
    Active alerts show what is currently wrong.
    Transition events tell the browser what JUST changed so voice alerts
    and visual banners can react exactly once.
    """
    event_type = clean_ascii(event_type).upper()
    severity = clean_ascii(severity).upper() or "INFO"
    source = clean_ascii(source)
    device = clean_ascii(device)
    problem = clean_ascii(problem)
    previous_state = clean_ascii(previous_state)
    current_state = clean_ascii(current_state)
    port = clean_ascii(port)
    root_cause = clean_ascii(root_cause)

    if not voice_message:
        if event_type == "RESOLVED":
            voice_message = f"Alert resolved. {device} {problem} has cleared."
        else:
            voice_message = f"{severity} alert. {device}. {problem}."

    voice_message = clean_ascii(voice_message)

    event = {
        "event_id": build_transition_event_id(),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "device": device,
        "problem": problem,
        "previous_state": previous_state,
        "current_state": current_state,
        "port": port,
        "root_cause": root_cause,
        "voice_message": voice_message,
        "time": now(),
        "new_alert": event_type == "ALERT",
        "alert_resolved": event_type == "RESOLVED"
    }

    with ALERT_TRANSITION_LOCK:
        ALERT_TRANSITION_EVENTS.append(event)
        # Keep only recent transition events in memory.
        del ALERT_TRANSITION_EVENTS[:-25]

    write_event(
        f"TRANSITION | {event_type} | {source} | {device} | {problem} | {previous_state} -> {current_state}"
    )

    return event


def register_alert_transition(
    source,
    device,
    problem,
    previous_state,
    current_state,
    severity="WARNING",
    port="",
    root_cause=""
):
    """Register an UP->DOWN style transition and suppress duplicates."""
    key = normalize_transition_key(source, device, problem, port)

    with ALERT_TRANSITION_LOCK:
        already_active = key in ACTIVE_ALERT_TRANSITION_KEYS
        if not already_active:
            ACTIVE_ALERT_TRANSITION_KEYS.add(key)

    if already_active:
        return None

    if port:
        voice_message = f"{severity} alert. {device}. {problem}. Affected port {port}."
    else:
        voice_message = f"{severity} alert. {device}. {problem}."

    return queue_alert_transition_event(
        "ALERT",
        severity,
        source,
        device,
        problem,
        previous_state=previous_state,
        current_state=current_state,
        port=port,
        root_cause=root_cause,
        voice_message=voice_message
    )


def register_recovery_transition(
    source,
    device,
    problem,
    previous_state,
    current_state,
    severity="INFO",
    port="",
    root_cause=""
):
    """Register a DOWN->UP style transition and suppress duplicate resolved messages."""
    key = normalize_transition_key(source, device, problem, port)

    with ALERT_TRANSITION_LOCK:
        was_active = key in ACTIVE_ALERT_TRANSITION_KEYS
        if was_active:
            ACTIVE_ALERT_TRANSITION_KEYS.discard(key)

    # Even if the active set was lost due to restart, still allow real DOWN->UP
    # transitions to generate one recovery event.
    if not was_active and clean_ascii(previous_state).upper() not in ["DOWN", "ERROR", "UNKNOWN", "TESTING"]:
        return None

    if port:
        voice_message = f"Alert resolved. {device}. {problem} on {port} has cleared."
    else:
        voice_message = f"Alert resolved. {device}. {problem} has cleared."

    return queue_alert_transition_event(
        "RESOLVED",
        severity,
        source,
        device,
        problem,
        previous_state=previous_state,
        current_state=current_state,
        port=port,
        root_cause=root_cause,
        voice_message=voice_message
    )


def get_alert_transition_api_state():
    """Return recent transition events for Smart Refresh."""
    with ALERT_TRANSITION_LOCK:
        events = list(ALERT_TRANSITION_EVENTS[-10:])
        latest_event = events[-1] if events else None

    return {
        "enabled": True,
        "phase": "12B.5.3",
        "latest_event": latest_event,
        "events": events,
        "new_alert": bool(latest_event and latest_event.get("event_type") == "ALERT"),
        "alert_resolved": bool(latest_event and latest_event.get("event_type") == "RESOLVED"),
        "latest_event_id": latest_event.get("event_id", "") if latest_event else "",
        "latest_voice_message": latest_event.get("voice_message", "") if latest_event else "",
        "active_transition_count": len(ACTIVE_ALERT_TRANSITION_KEYS)
    }


def send_sms_alert(alert):
    settings = get_notification_settings()

    if not settings.get("sms_enabled", False):
        return

    smtp_server = clean_ascii(settings.get("smtp_server", "smtp.gmail.com"))
    smtp_port = settings.get("smtp_port", 587)
    email_sender = clean_ascii(settings.get("email_sender", ""))
    email_app_password = clean_ascii(settings.get("email_app_password", ""))
    sms_recipient = clean_ascii(settings.get("sms_recipient", ""))

    if not email_sender or not email_app_password or not sms_recipient:
        write_event("ERROR | SMS ALERT | Missing notification settings")
        return

    subject = clean_ascii("CRITICAL ALERT")

    body = (
        "CRITICAL ALERT\n\n"
        f"Device/Link: {clean_ascii(alert.get('device', 'Unknown'))}\n"
        f"Problem: {clean_ascii(alert.get('problem', 'Unknown'))}\n"
        f"Time: {clean_ascii(alert.get('time', now()))}\n"
    )

    body = clean_ascii(body)

    try:
        msg = EmailMessage()
        msg["From"] = email_sender
        msg["To"] = sms_recipient
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(email_sender, email_app_password)
            server.send_message(msg)

        write_event(
            f"CONFIG | SMS ALERT SENT | {clean_ascii(alert.get('device'))} | {clean_ascii(alert.get('problem'))}"
        )

    except Exception as e:
        write_event(f"ERROR | SMS ALERT FAILED | {e}")


def send_sms_recovery(alert):
    settings = get_notification_settings()

    if not settings.get("sms_enabled", False):
        return

    smtp_server = clean_ascii(settings.get("smtp_server", "smtp.gmail.com"))
    smtp_port = settings.get("smtp_port", 587)
    email_sender = clean_ascii(settings.get("email_sender", ""))
    email_app_password = clean_ascii(settings.get("email_app_password", ""))
    sms_recipient = clean_ascii(settings.get("sms_recipient", ""))

    if not email_sender or not email_app_password or not sms_recipient:
        write_event("ERROR | SMS RECOVERY | Missing notification settings")
        return

    subject = clean_ascii("ALERT RESOLVED")

    body = (
        "ALERT RESOLVED\n\n"
        f"Device/Link: {clean_ascii(alert.get('device', 'Unknown'))}\n"
        f"Problem: {clean_ascii(alert.get('problem', 'Unknown'))}\n"
        f"Recovered: {clean_ascii(alert.get('resolved_time', now()))}\n"
        f"Duration: {clean_ascii(alert.get('duration', 'Unknown'))}\n"
    )

    body = clean_ascii(body)

    try:
        msg = EmailMessage()
        msg["From"] = email_sender
        msg["To"] = sms_recipient
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(email_sender, email_app_password)
            server.send_message(msg)

        write_event(
            f"CONFIG | SMS RECOVERY SENT | {clean_ascii(alert.get('device'))} | Duration {clean_ascii(alert.get('duration'))}"
        )

    except Exception as e:
        write_event(f"ERROR | SMS RECOVERY FAILED | {e}")




def load_knowledge_base():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(KNOWLEDGE_BASE_FILE):
        with open(KNOWLEDGE_BASE_FILE, "w") as f:
            json.dump([], f, indent=4)
        return []

    try:
        with open(KNOWLEDGE_BASE_FILE, "r") as f:
            return json.load(f)

    except Exception as e:
        write_event(f"ERROR | KNOWLEDGE BASE LOAD FAILED | {e}")
        return []


def save_knowledge_base(notes):
    os.makedirs("data", exist_ok=True)

    with open(KNOWLEDGE_BASE_FILE, "w") as f:
        json.dump(notes, f, indent=4)



def ensure_backup_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def safe_backup_filename(filename):
    filename = os.path.basename(filename)

    if not filename.endswith(".tar.gz"):
        return ""

    if "/" in filename or "\\" in filename or ".." in filename:
        return ""

    return filename


def list_backup_files():
    ensure_backup_dir()

    backups = []

    for filename in os.listdir(BACKUP_DIR):
        if not filename.endswith(".tar.gz"):
            continue

        path = os.path.join(BACKUP_DIR, filename)

        if not os.path.isfile(path):
            continue

        try:
            stat_info = os.stat(path)
            size_mb = round(stat_info.st_size / (1024 * 1024), 2)
            modified = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

            backups.append({
                "filename": filename,
                "size_mb": size_mb,
                "modified": modified
            })

        except Exception:
            continue

    return sorted(backups, key=lambda item: item.get("modified", ""), reverse=True)


def create_monitor_backup(version_label="phase7f", description_label="backupcenter"):
    ensure_backup_dir()

    version_label = clean_ascii(version_label).lower().replace(" ", "-")
    description_label = clean_ascii(description_label).lower().replace(" ", "-")

    if not version_label:
        version_label = "phase7f"

    if not description_label:
        description_label = "backupcenter"

    date_label = datetime.now().strftime("%Y%m%d")
    filename = f"network-monitor-{date_label}-{version_label}-{description_label}.tar.gz"
    backup_path = os.path.join(BACKUP_DIR, filename)

    project_parent = os.path.dirname(PROJECT_DIR)
    project_folder = os.path.basename(PROJECT_DIR)

    result = subprocess.run(
        ["tar", "-czf", backup_path, "-C", project_parent, project_folder],
        capture_output=True,
        text=True,
        timeout=120
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Backup command failed")

    return filename


# ======================================================
# PHASE 12C.1 - RESTORE EXECUTION ENGINE UPGRADE
# ======================================================
# This upgrade keeps the existing One-Click Restore Center, but makes the
# restore process safer and easier to track from the dashboard.
#
# Phase 12C.1 adds:
# - restore execution status file
# - active restore lock protection
# - safer tar extraction validation
# - staged restore execution worker
# - emergency pre-restore backup
# - restore audit trail with success/failure details
# - delayed restart scheduling after the browser receives a response

RESTORE_EXECUTION_LOCK = threading.Lock()
RESTORE_EXECUTION_STATE = {
    "active": False,
    "phase": "idle",
    "message": "Restore engine is idle",
    "started_at": "",
    "finished_at": "",
    "restored_backup": "",
    "emergency_backup": "",
    "requested_by": "",
    "error": ""
}


def atomic_json_write(path, payload):
    """Write JSON safely so a partial write does not corrupt the file."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    temp_path = f"{path}.tmp"

    with open(temp_path, "w") as f:
        json.dump(payload, f, indent=4)

    os.replace(temp_path, path)


def load_restore_audit():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(RESTORE_AUDIT_FILE):
        return []

    try:
        with open(RESTORE_AUDIT_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        write_event(f"ERROR | RESTORE CENTER | Restore audit load failed: {e}")
        return []


def save_restore_audit(items):
    os.makedirs("data", exist_ok=True)
    atomic_json_write(RESTORE_AUDIT_FILE, items)


def add_restore_audit_entry(entry):
    history = load_restore_audit()
    history.insert(0, entry)
    history = history[:100]
    save_restore_audit(history)


def load_restore_status():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(RESTORE_STATUS_FILE):
        return dict(RESTORE_EXECUTION_STATE)

    try:
        with open(RESTORE_STATUS_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            status_data = dict(RESTORE_EXECUTION_STATE)
            status_data.update(data)
            return status_data
    except Exception as e:
        write_event(f"ERROR | RESTORE CENTER | Restore status load failed: {e}")

    return dict(RESTORE_EXECUTION_STATE)


def save_restore_status(status_data):
    os.makedirs("data", exist_ok=True)
    atomic_json_write(RESTORE_STATUS_FILE, status_data)


def update_restore_execution_state(**kwargs):
    """Update the in-memory and on-disk restore execution state."""
    global RESTORE_EXECUTION_STATE

    with RESTORE_EXECUTION_LOCK:
        RESTORE_EXECUTION_STATE.update(kwargs)
        RESTORE_EXECUTION_STATE["updated_at"] = now()
        snapshot = dict(RESTORE_EXECUTION_STATE)

    save_restore_status(snapshot)
    return snapshot


def validate_restore_archive(backup_path):
    """
    Validate a tar.gz backup archive before extraction.

    Blocks:
    - absolute paths
    - ../ path traversal
    - symlinks and hard links
    - device files and other special tar members
    """
    project_folder = os.path.basename(PROJECT_DIR)
    member_names = []
    has_project_folder = False
    has_app_py = False

    try:
        with tarfile.open(backup_path, "r:gz") as tar:
            for member in tar.getmembers():
                member_name = member.name
                member_names.append(member_name)

                if member_name.startswith("/"):
                    raise RuntimeError("Backup archive contains an unsafe absolute path")

                parts = member_name.split("/")
                if ".." in parts:
                    raise RuntimeError("Backup archive contains unsafe path traversal")

                if member.issym() or member.islnk():
                    raise RuntimeError("Backup archive contains unsafe links")

                if not (member.isfile() or member.isdir()):
                    raise RuntimeError("Backup archive contains unsupported special files")

                if parts and parts[0] == project_folder:
                    has_project_folder = True

                if member_name.endswith("/app.py") or member_name == "app.py":
                    has_app_py = True

    except tarfile.TarError as e:
        raise RuntimeError(f"Backup archive could not be read: {e}")

    if not member_names:
        raise RuntimeError("Backup archive is empty")

    if not has_app_py:
        raise RuntimeError("Backup archive does not appear to contain app.py")

    return {
        "project_folder_detected": has_project_folder,
        "member_count": len(member_names),
        "project_folder": project_folder
    }


def safe_extract_tar(backup_path, temp_dir):
    """Extract only after validation, checking final paths stay inside temp_dir."""
    temp_dir_abs = os.path.abspath(temp_dir)

    with tarfile.open(backup_path, "r:gz") as tar:
        members = tar.getmembers()

        for member in members:
            target_path = os.path.abspath(os.path.join(temp_dir_abs, member.name))
            if not target_path.startswith(temp_dir_abs + os.sep) and target_path != temp_dir_abs:
                raise RuntimeError("Backup archive attempted to extract outside the restore staging area")

        tar.extractall(temp_dir_abs, members=members)


def find_restored_project_folder(temp_dir):
    """Find the extracted project folder that contains app.py."""
    expected = os.path.join(temp_dir, os.path.basename(PROJECT_DIR))
    if os.path.exists(os.path.join(expected, "app.py")):
        return expected

    for root, dirs, files in os.walk(temp_dir):
        if "app.py" in files:
            return root

    raise RuntimeError("Could not locate restored project folder after extraction")


def extract_restore_archive(backup_path, temp_dir):
    validate_restore_archive(backup_path)
    safe_extract_tar(backup_path, temp_dir)
    return find_restored_project_folder(temp_dir)


def copy_restored_project(source_dir):
    """
    Copy restored files into the live project directory.

    rsync --delete is preferred so the live project exactly matches the backup.
    Runtime/cache folders are excluded so the restore does not bring back stale
    bytecode or temporary files. If rsync is not installed, this falls back to
    Python copytree without delete.
    """
    if not os.path.exists(source_dir):
        raise RuntimeError("Restore source folder not found")

    if os.path.abspath(source_dir) == os.path.abspath(PROJECT_DIR):
        raise RuntimeError("Restore source and live project directory are the same")

    rsync_path = shutil.which("rsync")

    if rsync_path:
        result = subprocess.run(
            [
                rsync_path,
                "-a",
                "--delete",
                "--exclude", "__pycache__",
                "--exclude", "*.pyc",
                "--exclude", ".DS_Store",
                "--exclude", "data/restore_status.json",
                source_dir.rstrip("/") + "/",
                PROJECT_DIR.rstrip("/") + "/"
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "rsync restore failed")

        return "rsync"

    shutil.copytree(source_dir, PROJECT_DIR, dirs_exist_ok=True)
    return "copytree"


def schedule_onwatch_restart(delay_seconds=5):
    """
    Schedule a restart after the HTTP response has time to return.
    The service names cover the common names used during this project.
    """
    restart_command = (
        f"sleep {int(delay_seconds)}; "
        "(systemctl restart on-watch 2>/dev/null || "
        "systemctl restart onwatch 2>/dev/null || "
        "systemctl restart network-monitor 2>/dev/null || "
        "systemctl restart network-monitor-dashboard 2>/dev/null || "
        "true)"
    )

    try:
        subprocess.Popen(
            ["bash", "-lc", restart_command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        return True
    except Exception as e:
        write_event(f"ERROR | RESTORE CENTER | Restart scheduling failed: {e}")
        return False


def restore_monitor_backup(filename, requested_by="Dashboard"):
    """
    Phase 12C.1 Restore Execution Engine.

    Safety flow:
    1. Validate requested filename.
    2. Prevent two restore jobs from running at the same time.
    3. Validate selected archive.
    4. Create emergency backup of the current live system.
    5. Extract selected archive to a temporary staging folder.
    6. Copy staged files into PROJECT_DIR.
    7. Record restore audit and status.
    8. Schedule delayed service restart.
    """
    safe_name = safe_backup_filename(filename)

    if not safe_name:
        raise RuntimeError("Invalid backup filename")

    backup_path = os.path.join(BACKUP_DIR, safe_name)

    if not os.path.exists(backup_path):
        raise RuntimeError("Selected backup file does not exist")

    with RESTORE_EXECUTION_LOCK:
        if RESTORE_EXECUTION_STATE.get("active"):
            raise RuntimeError("A restore job is already running")

        RESTORE_EXECUTION_STATE.update({
            "active": True,
            "phase": "starting",
            "message": "Restore job has started",
            "started_at": now(),
            "finished_at": "",
            "restored_backup": safe_name,
            "emergency_backup": "",
            "requested_by": clean_ascii(requested_by),
            "error": ""
        })
        save_restore_status(dict(RESTORE_EXECUTION_STATE))

    emergency_backup = ""
    temp_dir = tempfile.mkdtemp(prefix="onwatch_restore_")
    copy_method = "not-started"

    try:
        update_restore_execution_state(phase="validating", message="Validating selected backup archive")
        backup_info = validate_restore_archive(backup_path)

        update_restore_execution_state(phase="emergency-backup", message="Creating emergency backup before restore")
        emergency_backup = create_monitor_backup("phase12c1", "pre-restore-emergency")
        update_restore_execution_state(emergency_backup=emergency_backup)

        update_restore_execution_state(phase="extracting", message="Extracting backup into restore staging area")
        source_dir = extract_restore_archive(backup_path, temp_dir)

        update_restore_execution_state(phase="copying", message="Copying restored files into live project")
        copy_method = copy_restored_project(source_dir)

        update_restore_execution_state(phase="restart-scheduled", message="Restore copy completed. Restart has been scheduled")
        restart_scheduled = schedule_onwatch_restart()

        audit_entry = {
            "time": now(),
            "action": "RESTORE_COMPLETED",
            "phase": "12C.1",
            "restored_backup": safe_name,
            "emergency_backup": emergency_backup,
            "requested_by": clean_ascii(requested_by),
            "copy_method": copy_method,
            "restart_scheduled": restart_scheduled,
            "project_dir": PROJECT_DIR,
            "backup_member_count": backup_info.get("member_count", 0)
        }

        add_restore_audit_entry(audit_entry)
        update_restore_execution_state(
            active=False,
            phase="completed",
            message="Restore completed successfully. Restart scheduled.",
            finished_at=now(),
            error=""
        )

        write_event(
            f"CONFIG | RESTORE CENTER | Phase 12C.1 restore completed from {safe_name} | Emergency backup: {emergency_backup} | Method: {copy_method}"
        )

        return audit_entry

    except Exception as e:
        audit_entry = {
            "time": now(),
            "action": "RESTORE_FAILED",
            "phase": "12C.1",
            "restored_backup": safe_name,
            "emergency_backup": emergency_backup,
            "requested_by": clean_ascii(requested_by),
            "copy_method": copy_method,
            "error": str(e),
            "project_dir": PROJECT_DIR
        }
        add_restore_audit_entry(audit_entry)
        update_restore_execution_state(
            active=False,
            phase="failed",
            message="Restore failed. Current live system was not restarted.",
            finished_at=now(),
            error=str(e)
        )
        write_event(f"ERROR | RESTORE CENTER | Phase 12C.1 restore failed from {safe_name}: {e}")
        raise

    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


def restore_monitor_backup_async(filename, requested_by="Dashboard"):
    """Run restore in a background thread so the web request can return quickly."""
    safe_name = safe_backup_filename(filename)
    if not safe_name:
        raise RuntimeError("Invalid backup filename")

    with RESTORE_EXECUTION_LOCK:
        if RESTORE_EXECUTION_STATE.get("active"):
            raise RuntimeError("A restore job is already running")

    worker = threading.Thread(
        target=restore_monitor_backup,
        args=(safe_name, requested_by),
        daemon=True
    )
    worker.start()

    return {
        "time": now(),
        "action": "RESTORE_STARTED",
        "phase": "12C.1",
        "restored_backup": safe_name,
        "requested_by": clean_ascii(requested_by),
        "message": "Restore job started in the background"
    }


def read_cisco_events(limit=20):
    events = []

    if not os.path.exists(CISCO_LOG_FILE):
        return events

    try:
        with open(CISCO_LOG_FILE, "r", errors="ignore") as f:
            lines = f.readlines()[-limit:]

        for line in reversed(lines):
            device = "Unknown"
            event = "Unknown"
            interface = "-"
            user = "-"
            source_ip = "-"

            for infrastructure_name, infrastructure_info in get_infrastructure_devices().items():
                infrastructure_ip = clean_ascii(infrastructure_info.get("ip", DEVICES.get(infrastructure_name, "")))
                if infrastructure_ip and infrastructure_ip in line:
                    device = infrastructure_name
                    break

            try:
                timestamp = line.split()[0]
                time_only = timestamp.split("T")[1][:8]
            except Exception:
                time_only = "--:--:--"

            if "%SYS-5-CONFIG_I" in line:
                event = "Configuration Changed"

                if " by " in line:
                    try:
                        user = line.split(" by ")[1].split()[0]
                    except Exception:
                        user = "-"

                if "(" in line and ")" in line:
                    try:
                        source_ip = line.split("(")[-1].split(")")[0]
                    except Exception:
                        source_ip = "-"

            elif "LOGGINGHOST_STARTSTOP" in line:
                event = "Syslog Started"
                user = "System"

            elif "LINK-3-UPDOWN" in line:
                event = "Interface Link Change"
                user = "System"

                if "Interface " in line:
                    try:
                        interface = line.split("Interface ")[1].split(",")[0]
                        interface = short_interface_name(interface)
                    except Exception:
                        interface = "-"

                if "changed state to down" in line.lower():
                    event = "Interface Link Down"
                elif "changed state to up" in line.lower():
                    event = "Interface Link Up"

            elif "LINEPROTO-5-UPDOWN" in line:
                event = "Line Protocol Change"
                user = "System"

                if "Interface " in line:
                    try:
                        interface = line.split("Interface ")[1].split(",")[0]
                        interface = short_interface_name(interface)
                    except Exception:
                        interface = "-"

                if "changed state to down" in line.lower():
                    event = "Line Protocol Down"
                elif "changed state to up" in line.lower():
                    event = "Line Protocol Up"

            elif "SEC_LOGIN" in line:
                event = "Login Event"

                if "user" in line.lower():
                    try:
                        user = line.split("user ")[1].split()[0]
                    except Exception:
                        user = "-"

            events.append({
                "time": time_only,
                "device": device,
                "event": event,
                "interface": interface,
                "user": user,
                "source_ip": source_ip,
                "raw": line.strip()
            })

    except Exception as e:
        print(f"Cisco log parse error: {e}")

    return events






def check_internet_targets():
    """Check only Internet targets explicitly configured by the operator."""
    results = {}

    if not INTERNET_CHECK_TARGETS:
        return "UNKNOWN", results

    for target in INTERNET_CHECK_TARGETS:
        state, latency = check_device(target)
        results[target] = {
            "state": state,
            "latency": latency
        }

    failed_targets = [
        target for target, info in results.items()
        if info.get("state") != "UP"
    ]

    if len(failed_targets) == len(INTERNET_CHECK_TARGETS):
        return "DOWN", results

    return "UP", results


def update_internet_uptime_tracking():
    global previous_internet_outage_state

    internet_name = get_internet_service_name()
    if not internet_name:
        previous_internet_outage_state = None
        return

    internet_state, internet_results = check_internet_targets()
    previous_last_change = status.get(internet_name, {}).get("last_change", "Starting...")

    if previous_internet_outage_state is not None and previous_internet_outage_state != internet_state:
        previous_last_change = now()

    status[internet_name] = {
        "ip": ", ".join(INTERNET_CHECK_TARGETS),
        "state": internet_state,
        "latency": "Multiple targets",
        "last_checked": now(),
        "last_change": previous_last_change
    }

    if previous_internet_outage_state is None:
        previous_internet_outage_state = internet_state
        return

    if previous_internet_outage_state != internet_state:
        if internet_state == "DOWN":
            write_event("ALERT | INTERNET OUTAGE | External internet targets failed: " + ", ".join(INTERNET_CHECK_TARGETS))
            record_uptime_outage_start(internet_name, "Internet Outage")
        elif internet_state == "UP":
            write_event("RECOVERY | INTERNET OUTAGE | External internet connectivity restored")
            record_uptime_outage_end(internet_name, "Internet Outage")

    previous_internet_outage_state = internet_state


def snmpwalk(ip, oid):
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", SNMP_COMMUNITY, ip, oid],
            capture_output=True,
            text=True,
            timeout=6
        )

        if result.returncode != 0:
            return []

        return result.stdout.strip().splitlines()

    except Exception as e:
        write_event(f"ERROR | SNMP failed for {ip}: {e}")
        return []


def parse_oid_index(line):
    try:
        return line.split("=")[0].strip().split(".")[-1]
    except Exception:
        return None


def parse_string_value(line):
    try:
        return line.split("STRING:")[1].strip().replace('"', '')
    except Exception:
        return "Unknown"


def parse_integer_value(line):
    try:
        return int(line.split("INTEGER:")[1].strip())
    except Exception:
        return 0




def short_interface_name(name):
    return (
        name.replace("TwentyFiveGigE", "Twe")
            .replace("TwentyFiveGigabitEthernet", "Twe")
            .replace("FortyGigabitEthernet", "Fo")
            .replace("TenGigabitEthernet", "Te")
            .replace("GigabitEthernet", "Gi")
            .replace("FastEthernet", "Fa")
            .replace("Ethernet", "Eth")
            .replace("Serial", "Se")
            .replace("Embedded-Service-Engine", "ESE")
            .replace("Backplane-GigabitEthernet", "Backplane-Gi")
    )


def get_snmp_interfaces(ip):
    name_oid = "1.3.6.1.2.1.2.2.1.2"
    status_oid = "1.3.6.1.2.1.2.2.1.8"

    name_lines = snmpwalk(ip, name_oid)
    status_lines = snmpwalk(ip, status_oid)

    names = {}
    states = {}

    for line in name_lines:
        index = parse_oid_index(line)
        if index:
            names[index] = parse_string_value(line)

    for line in status_lines:
        index = parse_oid_index(line)
        if index:
            states[index] = status_number_to_text(parse_integer_value(line))

    interfaces = {}

    for index, name in names.items():
        interfaces[index] = {
            "name": name,
            "short_name": short_interface_name(name),
            "state": states.get(index, "UNKNOWN"),
            "last_checked": now()
        }

    return interfaces


# ======================================================
# PHASE 15A.1 - UNIVERSAL SNMP DISCOVERY ENGINE
# ======================================================
def is_network_infrastructure_device(device_name):
    """True for inventory devices whose interfaces should come from SNMP.

    Phase 16B fix:
    Routers, switches, firewalls, and access points all use SNMP-discovered
    interfaces as the source of truth. Nothing in the topology mapper should
    depend on hard-coded router or switch port lists.
    """
    device_name = clean_ascii(device_name)
    device_type = clean_ascii(detect_map_device_type(device_name, DEVICES.get(device_name, "")))
    role = normalize_infrastructure_role(device_type)

    return role in ["Router", "Switch", "Firewall", "Access Point"]




def interface_sort_key(item):
    """Sort interfaces in human order and support both legacy and SNMP records.

    Phase 16A.3B.1 fix:
    owned/unassigned port panels pass full interface dictionaries here.
    If we sort the dictionary string representation, ports can appear out of
    order. This version extracts short_name/name/index before sorting so
    Gi1/0/2 comes before Gi1/0/6, Gi1/0/7, Gi1/0/20, etc.
    """

    if isinstance(item, tuple):
        index, info = item

        if isinstance(info, str):
            label = info
        elif isinstance(info, dict):
            label = (
                clean_ascii(info.get("short_name", ""))
                or clean_ascii(info.get("name", ""))
                or clean_ascii(info.get("port_label", ""))
                or clean_ascii(index)
            )
        else:
            label = str(info)

    elif isinstance(item, dict):
        label = (
            clean_ascii(item.get("short_name", ""))
            or clean_ascii(item.get("name", ""))
            or clean_ascii(item.get("port_label", ""))
            or clean_ascii(item.get("index", ""))
        )
    else:
        label = str(item)

    label = clean_ascii(label)
    numbers = [int(part) for part in re.findall(r"\d+", label)]
    return (re.sub(r"\d+", "", label), numbers, label)


def normalize_interface_record(index, info, source="snmp"):
    name = clean_ascii(info.get("name", ""))
    short_name = clean_ascii(info.get("short_name", "")) or short_interface_name(name)
    state_value = clean_ascii(info.get("state", "UNKNOWN")) or "UNKNOWN"

    return {
        "index": clean_ascii(index),
        "name": name,
        "short_name": short_name,
        "state": state_value,
        "last_checked": clean_ascii(info.get("last_checked", now())) or now(),
        "source": source
    }


def get_snmp_inventory_cache():
    return config.setdefault("snmp_inventory", {
        "enabled": True,
        "phase": "15A.1",
        "source_of_truth": "SNMP discovered interfaces and ports",
        "cache_fallback_only": True,
        "last_discovery": "",
        "devices": {}
    })


def get_cached_device_interfaces(device_name):
    cache = config.get("snmp_inventory", {}).get("devices", {}).get(device_name, {})
    interfaces = cache.get("interfaces", {})
    cleaned = {}

    if isinstance(interfaces, dict):
        for index, info in interfaces.items():
            if isinstance(info, dict):
                record = normalize_interface_record(index, info, source="cache")
                if is_usable_snmp_interface(record.get("name", "")):
                    cleaned[str(index)] = record

    return dict(sorted(cleaned.items(), key=interface_sort_key))


def update_device_interface_cache(device_name, ip, device_type, interfaces):
    if not device_name or not interfaces:
        return

    inventory_cache = get_snmp_inventory_cache()
    inventory_cache["enabled"] = True
    inventory_cache["phase"] = "15A.1"
    inventory_cache["source_of_truth"] = "SNMP discovered interfaces and ports"
    inventory_cache["cache_fallback_only"] = True
    inventory_cache["last_discovery"] = now()
    inventory_cache.setdefault("devices", {})

    inventory_cache["devices"][device_name] = {
        "ip": clean_ascii(ip),
        "device_type": clean_ascii(device_type),
        "last_discovery": now(),
        "interface_count": len(interfaces),
        "interfaces": {
            str(index): normalize_interface_record(index, info, source="snmp")
            for index, info in interfaces.items()
        }
    }

    try:
        save_config()
    except Exception as e:
        write_event(f"ERROR | SNMP INVENTORY CACHE | Save failed for {device_name}: {e}")


def discover_device_interfaces(device_name, force_live=True):
    """Discover router/switch interfaces by SNMP with cache fallback only."""
    device_name = clean_ascii(device_name)
    ip = clean_ascii(DEVICES.get(device_name, ""))
    device_type = clean_ascii(detect_map_device_type(device_name, ip))

    if not device_name or not ip:
        return {}

    live_interfaces = {}

    if force_live:
        raw_interfaces = get_snmp_interfaces(ip)

        for index, info in raw_interfaces.items():
            name = clean_ascii(info.get("name", ""))
            if not is_usable_snmp_interface(name):
                continue
            live_interfaces[str(index)] = normalize_interface_record(index, info, source="snmp")

        if live_interfaces:
            live_interfaces = dict(sorted(live_interfaces.items(), key=interface_sort_key))
            update_device_interface_cache(device_name, ip, device_type, live_interfaces)
            return live_interfaces

    cached_interfaces = get_cached_device_interfaces(device_name)
    if cached_interfaces:
        write_event(f"CONFIG | SNMP INVENTORY | Using cached SNMP interfaces for {device_name}")

    return cached_interfaces


def get_discovered_interfaces_for_topology_device(device_name, force_live=False):
    """Return SNMP-discovered interfaces for any SNMP-managed topology device.

    Phase 16C performance fix:
    Normal page loads must never run live SNMP discovery. Dashboard and
    Provisioning pages use the cached SNMP inventory so navigation stays fast.
    Live discovery is still available by passing force_live=True from explicit
    provisioning/discovery actions.
    """
    if not is_network_infrastructure_device(device_name):
        return {}
    return discover_device_interfaces(device_name, force_live=force_live)


def get_interface_labels_for_device(device_name):
    interfaces = get_discovered_interfaces_for_topology_device(device_name)
    labels = []

    for index, info in sorted(interfaces.items(), key=interface_sort_key):
        label = clean_ascii(info.get("short_name", "")) or clean_ascii(info.get("name", "")) or f"Index {index}"
        if label not in labels:
            labels.append(label)

    return labels


def find_interface_index_for_device(device_name, interface_label):
    interface_label = clean_ascii(interface_label)
    if not interface_label:
        return ""

    interfaces = get_discovered_interfaces_for_topology_device(device_name)

    for index, info in interfaces.items():
        labels = {
            clean_ascii(index),
            clean_ascii(info.get("name", "")),
            clean_ascii(info.get("short_name", ""))
        }
        if interface_label in labels:
            return clean_ascii(index)

    return ""


def get_primary_switch_name():
    return get_physical_topology_primary_switch()


def get_primary_switch_interfaces():
    switch_name = get_primary_switch_name()
    if not switch_name:
        return {}
    return get_discovered_interfaces_for_topology_device(switch_name)


def get_all_router_interfaces():
    """Return SNMP-discovered interfaces for the registry-selected primary router."""
    router_name = get_primary_router_name()
    if not router_name:
        router_names = get_infrastructure_names_by_role("Router")
        router_name = router_names[0] if router_names else ""
    return get_discovered_interfaces_for_topology_device(router_name) if router_name else {}


def get_router_topology_mapped_interface_indexes(all_interfaces=None):
    """Return router interface indexes that are actually used in saved topology links.

    Router alerting must follow the physical topology. SNMP can discover unused
    router ports such as Gi0/1 or ESE0/0, but those ports should not create
    critical alerts unless they are connected/mapped in infrastructure_links.
    """
    if all_interfaces is None:
        all_interfaces = get_all_router_interfaces()

    router_names = set()
    edge_router_name = clean_ascii(INFRASTRUCTURE.get("edge_router", ""))
    if edge_router_name:
        router_names.add(edge_router_name)

    for device_name, ip in DEVICES.items():
        if clean_ascii(detect_map_device_type(device_name, ip)).lower() == "router":
            router_names.add(clean_ascii(device_name))

    mapped_indexes = set()

    for link in get_physical_topology_config():
        from_device = clean_ascii(link.get("from", ""))
        to_device = clean_ascii(link.get("to", ""))

        if from_device in router_names:
            interface_label = clean_ascii(link.get("source_interface", ""))
        elif to_device in router_names:
            interface_label = clean_ascii(link.get("target_interface", ""))
        else:
            continue

        if not interface_label:
            continue

        for index, info in all_interfaces.items():
            possible_labels = {
                clean_ascii(index),
                clean_ascii(info.get("name", "")),
                clean_ascii(info.get("short_name", "")),
                short_interface_name(clean_ascii(info.get("name", "")))
            }

            if interface_label in possible_labels:
                mapped_indexes.add(clean_ascii(index))
                break

    return mapped_indexes


def get_effective_router_monitored_interface_indexes(all_interfaces=None):
    """Return router interfaces selected by the admin for monitoring.

    SNMP discovery is inventory only. The checkboxes on Router Monitoring are
    the authority for alerting. Topology mapping is separate and only decides
    whether a selected interface is already used in the topology editor.
    """
    if all_interfaces is None:
        all_interfaces = get_all_router_interfaces()

    discovered_indexes = {clean_ascii(index) for index in all_interfaces.keys()}
    selected = {clean_ascii(index) for index in config.get("router_monitored_interfaces", [])}

    # Keep only selected interfaces that still exist in live/cached SNMP inventory.
    return selected.intersection(discovered_indexes)


def get_router_interfaces():
    """Return only admin-selected router interfaces for alert monitoring."""
    all_interfaces = get_all_router_interfaces()
    effective_indexes = get_effective_router_monitored_interface_indexes(all_interfaces)

    monitored = {}
    for index, info in all_interfaces.items():
        if clean_ascii(index) in effective_indexes:
            monitored[index] = info

    return monitored


def get_monitored_router_interface_labels_for_device(device_name):
    """Return SNMP-discovered router interface labels for topology mapping.

    Phase 16B fix:
    Router Monitoring selections are for alert monitoring only. They must not
    limit what can be physically mapped. When a router is provisioned, all
    usable SNMP-discovered router interfaces are available in the topology
    builder until one is saved in a topology link.
    """
    return get_interface_labels_for_device(device_name)


def get_switch_links():
    switch_name = get_primary_switch_name()
    interfaces = get_primary_switch_interfaces()

    links = {}

    for index, friendly_name in SWITCH_PORTS.items():
        index = clean_ascii(index)
        grace_info = get_device_provisioning_grace(friendly_name)
        maintenance_info = get_device_maintenance_info(friendly_name)

        if index in interfaces:
            port_info = interfaces[index]

            # PHASE 26B.7B HOTFIX:
            # The switch interface must always report its real SNMP physical
            # state. Maintenance belongs to the endpoint device, not the port.
            physical_state = clean_ascii(port_info.get("state", "UNKNOWN")).upper() or "UNKNOWN"

            links[index] = {
                "port": port_info["short_name"],
                "full_port": port_info["name"],
                "device": friendly_name,
                "state": physical_state,
                "raw_state": physical_state,
                "physical_state": physical_state,
                "maintenance_mode": bool(maintenance_info),
                "maintenance_context": get_maintenance_state_label() if maintenance_info else "",
                "maintenance_reason": maintenance_info.get("reason", "") if maintenance_info else "",
                "maintenance_remaining": format_maintenance_remaining(maintenance_info.get("remaining_seconds", -1)) if maintenance_info else "",
                "provisioning_grace": bool(grace_info),
                "provisioning_context": get_provisioning_state_label() if grace_info else "",
                "grace_remaining_seconds": grace_info.get("remaining_seconds", 0) if grace_info else 0,
                "last_checked": now(),
                "snmp_source": "SNMP"
            }
        else:
            # No live/cached interface record is available. Keep the physical
            # port state UNKNOWN while retaining endpoint lifecycle context.
            physical_state = "UNKNOWN"

            links[index] = {
                "port": f"Index {index}",
                "full_port": f"Index {index}",
                "device": friendly_name,
                "state": physical_state,
                "raw_state": physical_state,
                "physical_state": physical_state,
                "maintenance_mode": bool(maintenance_info),
                "maintenance_context": get_maintenance_state_label() if maintenance_info else "",
                "maintenance_reason": maintenance_info.get("reason", "") if maintenance_info else "",
                "maintenance_remaining": format_maintenance_remaining(maintenance_info.get("remaining_seconds", -1)) if maintenance_info else "",
                "provisioning_grace": bool(grace_info),
                "provisioning_context": get_provisioning_state_label() if grace_info else "",
                "grace_remaining_seconds": grace_info.get("remaining_seconds", 0) if grace_info else 0,
                "last_checked": now(),
                "snmp_source": "SNMP_CACHE_OR_UNAVAILABLE"
            }

    return links


def get_available_ports():
    """Available endpoint switch ports come from SNMP-discovered primary switch ports only."""
    used_ports = {clean_ascii(port) for port in SWITCH_PORTS.keys()}
    available = {}

    for index, info in get_primary_switch_interfaces().items():
        index = clean_ascii(index)
        if index in used_ports:
            continue
        label = clean_ascii(info.get("short_name", "")) or clean_ascii(info.get("name", "")) or f"Index {index}"
        available[index] = label

    return dict(sorted(available.items(), key=interface_sort_key))



def get_selectable_switch_ports():
    """All SNMP-discovered primary switch ports for Port Mapper / Inventory UI."""
    selectable = {}

    for index, info in get_primary_switch_interfaces().items():
        index = clean_ascii(index)
        label = clean_ascii(info.get("short_name", "")) or clean_ascii(info.get("name", "")) or f"Index {index}"
        selectable[index] = label

    return dict(sorted(selectable.items(), key=interface_sort_key))


def get_switch_port_label(port_index):
    port_index = clean_ascii(port_index)
    return get_selectable_switch_ports().get(port_index, f"Index {port_index}")




def diagnose_network():
    """Return a role-based diagnosis using the live Infrastructure Registry."""
    role_states = {}
    for role in ("Internet", "Modem", "Firewall", "Router", "Switch", "Access Point"):
        role_states[role] = [
            (name, clean_ascii(status.get(name, {}).get("state", "UNKNOWN")).upper())
            for name in get_infrastructure_names_by_role(role)
        ]

    for role in ("Internet", "Modem", "Firewall", "Router", "Switch"):
        failed = [name for name, state_value in role_states.get(role, []) if state_value in {"DOWN", "ERROR", "UNKNOWN"}]
        if failed:
            return f"{role} infrastructure issue detected: " + ", ".join(failed)

    down_router_links = [info.get("short_name", "Unknown interface") for info in router_interfaces.values() if info.get("state") == "DOWN"]
    down_switch_links = [f"{info.get('device', 'Unknown device')} ({info.get('port', 'Unknown port')})" for info in switch_links.values() if info.get("state") == "DOWN"]
    if down_router_links:
        return "Monitored router links down: " + ", ".join(down_router_links)
    if down_switch_links:
        return "Switch links down: " + ", ".join(down_switch_links)

    down_devices = [name for name, info in status.items() if info.get("state") == "DOWN"]
    if down_devices:
        return "Some devices are down: " + ", ".join(down_devices)
    return "Network appears healthy."


def monitor_loop():
    global last_full_scan
    global total_alerts
    global total_recoveries
    global router_interfaces
    global switch_links
    global previous_router_interfaces
    global previous_switch_links

    while True:
        load_config()

        discover_infrastructure_interfaces()
        discover_cdp_neighbors()
        discover_lldp_neighbors()
        build_link_confidence_database()
        if bool(config.get("infrastructure_auto_linking", {}).get("rebuild_after_discovery", True)):
            rebuild_auto_infrastructure_links()
        check_topology_changes()

        scheduled_changed = apply_scheduled_maintenance()
        maintenance_changed = cleanup_expired_maintenance()
        provisioning_changed = cleanup_expired_provisioning_grace()

        if scheduled_changed or maintenance_changed or provisioning_changed:
            save_config()
            load_config()

        # Internet Uptime Monitoring
        update_internet_uptime_tracking()

        for name, ip in DEVICES.items():
            maintenance_info = get_device_maintenance_info(name)

            if maintenance_info:
                status[name] = {
                    "ip": ip,
                    "state": get_maintenance_state_label(),
                    "raw_state": "MAINTENANCE",
                    "latency": f"Maintenance: {maintenance_info.get('reason', 'Maintenance')}",
                    "raw_latency": "N/A",
                    "sleep_allowed": is_sleep_allowed_device(name),
                    "sleep_grace_minutes": get_sleep_grace_minutes(),
                    "maintenance_mode": True,
                    "maintenance_reason": maintenance_info.get("reason", "Maintenance"),
                    "maintenance_remaining": format_maintenance_remaining(maintenance_info.get("remaining_seconds", -1)),
                    "last_checked": now(),
                    "last_change": maintenance_info.get("start", now())
                }

                previous_status[name] = get_maintenance_state_label()
                continue

            grace_info = get_device_provisioning_grace(name)

            if grace_info:
                status[name] = {
                    "ip": ip,
                    "state": get_provisioning_state_label(),
                    "raw_state": "PROVISIONING",
                    "latency": f"Provisioning grace: {grace_info.get('remaining_seconds', 0)}s",
                    "raw_latency": "N/A",
                    "sleep_allowed": is_sleep_allowed_device(name),
                    "sleep_grace_minutes": get_sleep_grace_minutes(),
                    "provisioning_grace": True,
                    "grace_remaining_seconds": grace_info.get("remaining_seconds", 0),
                    "last_checked": now(),
                    "last_change": grace_info.get("start", now())
                }

                previous_status[name] = get_provisioning_state_label()
                continue

            raw_state, latency = check_device(ip)
            old_raw_state = previous_status.get(name)
            old_effective_state = status.get(name, {}).get("state")

            previous_last_change = status.get(name, {}).get("last_change", "Starting...")
            if old_raw_state != raw_state:
                effective_last_change = now()
            else:
                effective_last_change = previous_last_change

            effective_state = apply_sleep_detection_state(
                name,
                raw_state,
                effective_last_change
            )

            effective_latency = latency
            if effective_state == get_sleep_status_label():
                effective_latency = "Sleeping"

            if old_effective_state and old_effective_state != effective_state:
                if effective_state == get_sleep_status_label():
                    write_event(f"SLEEP | DEVICE | {name} ({ip}) entered sleep detection window")

                elif old_effective_state == get_sleep_status_label() and effective_state == "UP":
                    total_recoveries += 1
                    write_event(f"WAKE | DEVICE | {name} ({ip}) woke from sleep and changed to UP")

                elif effective_state == "DOWN":
                    total_alerts += 1
                    transition_problem = "Device DOWN"
                    if is_sleep_allowed_device(name):
                        write_event(f"ALERT | DEVICE | {name} ({ip}) exceeded sleep detection grace window and changed to DOWN")
                        transition_problem = "Device exceeded sleep detection grace window and changed to DOWN"
                    else:
                        write_event(f"ALERT | DEVICE | {name} ({ip}) changed from {old_effective_state} to DOWN")

                    register_alert_transition(
                        source="device",
                        device=name,
                        problem=transition_problem,
                        previous_state=old_effective_state,
                        current_state=effective_state,
                        severity=classify_alert_severity(name, transition_problem, "device")
                    )

                elif effective_state == "UP":
                    total_recoveries += 1
                    write_event(f"RECOVERY | DEVICE | {name} ({ip}) changed from {old_effective_state} to UP")

                    register_recovery_transition(
                        source="device",
                        device=name,
                        problem="Device DOWN",
                        previous_state=old_effective_state,
                        current_state=effective_state,
                        severity="INFO"
                    )

                elif effective_state == "ERROR":
                    write_event(f"ERROR | DEVICE | {name} ({ip}) changed from {old_effective_state} to ERROR")

            status[name] = {
                "ip": ip,
                "state": effective_state,
                "raw_state": raw_state,
                "latency": effective_latency,
                "raw_latency": latency,
                "sleep_allowed": is_sleep_allowed_device(name),
                "sleep_grace_minutes": get_sleep_grace_minutes(),
                "last_checked": now(),
                "last_change": effective_last_change
            }

            previous_status[name] = raw_state

        for old_device in list(status.keys()):
            if old_device not in DEVICES and old_device != get_internet_service_name():
                status.pop(old_device, None)
                previous_status.pop(old_device, None)

        new_router_interfaces = get_router_interfaces()

        for index, info in new_router_interfaces.items():
            old_state = previous_router_interfaces.get(index)

            if old_state and old_state != info["state"]:
                if info["state"] == "DOWN":
                    total_alerts += 1
                    write_event(f"ALERT | ROUTER LINK | {info['name']} changed from {old_state} to DOWN")

                    register_alert_transition(
                        source="router_link",
                        device=info.get("short_name", info.get("name", "Router Link")),
                        problem="Router Link DOWN",
                        previous_state=old_state,
                        current_state=info.get("state", "DOWN"),
                        severity="CRITICAL",
                        port=info.get("short_name", ""),
                        root_cause=info.get("name", "Router Link")
                    )

                elif info["state"] == "UP":
                    total_recoveries += 1
                    write_event(f"RECOVERY | ROUTER LINK | {info['name']} changed from {old_state} to UP")

                    register_recovery_transition(
                        source="router_link",
                        device=info.get("short_name", info.get("name", "Router Link")),
                        problem="Router Link DOWN",
                        previous_state=old_state,
                        current_state=info.get("state", "UP"),
                        severity="INFO",
                        port=info.get("short_name", ""),
                        root_cause=info.get("name", "Router Link")
                    )

            previous_router_interfaces[index] = info["state"]

        router_interfaces = new_router_interfaces

        new_switch_links = get_switch_links()

        for index, info in new_switch_links.items():
            old_state = previous_switch_links.get(index)

            if (
                info.get("maintenance_mode") or
                info.get("state") == get_maintenance_state_label() or
                info.get("provisioning_grace") or
                info.get("state") == get_provisioning_state_label()
            ):
                previous_switch_links[index] = info["state"]
                continue

            if old_state and old_state != info["state"]:
                if info["state"] == "DOWN":
                    total_alerts += 1
                    write_event(
                        f"ALERT | SWITCH LINK | {info['device']} on {info['port']} changed from {old_state} to DOWN"
                    )

                    register_alert_transition(
                        source="switch_link",
                        device=info.get("device", "Switch Link"),
                        problem="Switch Link DOWN",
                        previous_state=old_state,
                        current_state=info.get("state", "DOWN"),
                        severity=classify_alert_severity(info.get("device", "Switch Link"), "Switch Link DOWN", "switch"),
                        port=info.get("port", ""),
                        root_cause=f"Switch Port {info.get('port', '')}"
                    )

                elif info["state"] == "UP":
                    total_recoveries += 1
                    write_event(
                        f"RECOVERY | SWITCH LINK | {info['device']} on {info['port']} changed from {old_state} to UP"
                    )

                    register_recovery_transition(
                        source="switch_link",
                        device=info.get("device", "Switch Link"),
                        problem="Switch Link DOWN",
                        previous_state=old_state,
                        current_state=info.get("state", "UP"),
                        severity="INFO",
                        port=info.get("port", ""),
                        root_cause=f"Switch Port {info.get('port', '')}"
                    )

            previous_switch_links[index] = info["state"]

        switch_links = new_switch_links

        # PHASE 13B.2 - Make the current switch link state authoritative for
        # endpoint availability before dashboard/service-impact views read status.
        apply_switch_link_override_to_device_status(new_switch_links)

        last_full_scan = now()
        analyze_root_cause_topology()

        time.sleep(CHECK_INTERVAL)










def load_internet_history():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(INTERNET_HISTORY_FILE):
        with open(INTERNET_HISTORY_FILE, "w") as f:
            json.dump([], f, indent=4)
        return []

    try:
        with open(INTERNET_HISTORY_FILE, "r") as f:
            history = json.load(f)

        if isinstance(history, list):
            return history

        return []

    except Exception as e:
        write_event(f"ERROR | INTERNET HISTORY LOAD FAILED | {e}")
        return []


def save_internet_history(history):
    os.makedirs("data", exist_ok=True)

    with open(INTERNET_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


def add_internet_history_entry(start_time, end_time, duration_seconds, status_value="RESOLVED"):
    history = load_internet_history()

    history_item = {
        "start_time": start_time,
        "end_time": end_time,
        "duration": format_duration_seconds(duration_seconds),
        "duration_seconds": duration_seconds,
        "status": status_value,
        "targets": ", ".join(INTERNET_CHECK_TARGETS)
    }

    history.append(history_item)

    # Keep newest entries first for display
    history = sorted(
        history,
        key=lambda item: item.get("start_time", ""),
        reverse=True
    )

    save_internet_history(history)


def get_recent_internet_history(limit=5):
    history = load_internet_history()

    return history[:limit]


def clear_internet_history():
    save_internet_history([])



def period_start_today():
    return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)


def period_start_week():
    current_time = datetime.now()
    start = current_time - timedelta(days=current_time.weekday())
    return start.replace(hour=0, minute=0, second=0, microsecond=0)


def period_start_month():
    current_time = datetime.now()
    return current_time.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def period_start_last_30_days():
    return datetime.now() - timedelta(days=30)




def get_internet_availability_report():
    stats = load_uptime_stats()
    history = load_internet_history()
    current_time = datetime.now()
    monitor_started = parse_timestamp(stats.get("monitor_started", ""))
    if not monitor_started:
        monitor_started = current_time

    outages = []

    for item in history:
        start_dt = parse_timestamp(item.get("start_time", ""))
        end_dt = parse_timestamp(item.get("end_time", ""))
        if start_dt and end_dt:
            outages.append({"start": start_dt, "end": end_dt, "status": "RESOLVED"})

    for outage in stats.get("active_outages", {}).values():
        start_dt = parse_timestamp(outage.get("start_time", ""))
        if start_dt:
            outages.append({"start": start_dt, "end": current_time, "status": "ACTIVE"})

    def build_period(label, period_start):
        start_time = max(monitor_started, period_start)
        monitored_seconds = max(1, int((current_time - start_time).total_seconds()))
        downtime_seconds = 0
        outage_count = 0
        longest_seconds = 0

        for outage in outages:
            overlap_seconds = calculate_overlap_seconds(
                start_time,
                current_time,
                outage["start"],
                outage["end"]
            )
            if overlap_seconds > 0:
                downtime_seconds += overlap_seconds
                outage_count += 1
                longest_seconds = max(longest_seconds, overlap_seconds)

        uptime_seconds = max(0, monitored_seconds - downtime_seconds)
        availability = (uptime_seconds / monitored_seconds) * 100
        average_seconds = int(downtime_seconds / outage_count) if outage_count else 0

        return {
            "label": label,
            "availability": f"{availability:.2f}%",
            "monitored_time": format_duration_seconds(monitored_seconds),
            "downtime": format_duration_seconds(downtime_seconds),
            "downtime_seconds": downtime_seconds,
            "outages": outage_count,
            "average_outage": format_duration_seconds(average_seconds),
            "longest_outage": format_duration_seconds(longest_seconds)
        }

    total_monitored_seconds = max(1, int((current_time - monitor_started).total_seconds()))
    total_downtime_seconds = 0
    total_outage_count = 0
    longest_total_seconds = 0

    for outage in outages:
        overlap_seconds = calculate_overlap_seconds(
            monitor_started,
            current_time,
            outage["start"],
            outage["end"]
        )
        if overlap_seconds > 0:
            total_downtime_seconds += overlap_seconds
            total_outage_count += 1
            longest_total_seconds = max(longest_total_seconds, overlap_seconds)

    total_availability = (
        max(0, total_monitored_seconds - total_downtime_seconds) /
        total_monitored_seconds
    ) * 100
    average_total_seconds = int(total_downtime_seconds / total_outage_count) if total_outage_count else 0

    return {
        "monitor_started": stats.get("monitor_started", ""),
        "total_availability": f"{total_availability:.2f}%",
        "total_monitored_time": format_duration_seconds(total_monitored_seconds),
        "total_downtime": format_duration_seconds(total_downtime_seconds),
        "total_downtime_seconds": total_downtime_seconds,
        "total_outages": total_outage_count,
        "average_outage": format_duration_seconds(average_total_seconds),
        "longest_outage": format_duration_seconds(longest_total_seconds),
        "active_outages": len(stats.get("active_outages", {})),
        "today": build_period("Today", period_start_today()),
        "week": build_period("This Week", period_start_week()),
        "month": build_period("This Month", period_start_month()),
        "last_30_days": build_period("Last 30 Days", period_start_last_30_days())
    }


def reset_internet_availability_data():
    save_uptime_stats(create_fresh_uptime_stats())
    clear_internet_history()


def create_fresh_uptime_stats():
    return {
        "monitor_started": now(),
        "total_outages": 0,
        "total_recoveries": 0,
        "today_date": datetime.now().strftime("%Y-%m-%d"),
        "today_outages": 0,
        "longest_outage_seconds": 0,
        "last_outage_time": "",
        "last_recovery_time": "",
        "accumulated_downtime_seconds": 0,
        "active_outages": {}
    }


def load_uptime_stats():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(UPTIME_STATS_FILE):
        stats = {
            "monitor_started": now(),
            "total_outages": 0,
            "total_recoveries": 0,
            "today_date": datetime.now().strftime("%Y-%m-%d"),
            "today_outages": 0,
            "longest_outage_seconds": 0,
            "last_outage_time": "",
            "last_recovery_time": "",
            "accumulated_downtime_seconds": 0,
            "active_outages": {}
        }

        save_uptime_stats(stats)
        return stats

    try:
        with open(UPTIME_STATS_FILE, "r") as f:
            stats = json.load(f)

    except Exception as e:
        write_event(f"ERROR | UPTIME STATS LOAD FAILED | {e}")
        stats = {
            "monitor_started": now(),
            "total_outages": 0,
            "total_recoveries": 0,
            "today_date": datetime.now().strftime("%Y-%m-%d"),
            "today_outages": 0,
            "longest_outage_seconds": 0,
            "last_outage_time": "",
            "last_recovery_time": "",
            "accumulated_downtime_seconds": 0,
            "active_outages": {}
        }

    # Ensure all expected keys exist for future upgrades.
    # Permanent fix: if monitor_started exists but is blank, set it automatically.
    if not stats.get("monitor_started"):
        stats["monitor_started"] = now()
        save_uptime_stats(stats)

    stats.setdefault("total_outages", 0)
    stats.setdefault("total_recoveries", 0)
    stats.setdefault("today_date", datetime.now().strftime("%Y-%m-%d"))
    stats.setdefault("today_outages", 0)
    stats.setdefault("longest_outage_seconds", 0)
    stats.setdefault("last_outage_time", "")
    stats.setdefault("last_recovery_time", "")
    stats.setdefault("accumulated_downtime_seconds", 0)
    stats.setdefault("active_outages", {})

    current_date = datetime.now().strftime("%Y-%m-%d")
    if stats.get("today_date") != current_date:
        stats["today_date"] = current_date
        stats["today_outages"] = 0
        save_uptime_stats(stats)

    return stats


def save_uptime_stats(stats):
    os.makedirs("data", exist_ok=True)

    with open(UPTIME_STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)


def record_uptime_outage_start(device, problem):
    stats = load_uptime_stats()
    outage_key = alert_id(device, problem)

    if outage_key in stats.get("active_outages", {}):
        return

    current_time = now()

    stats["active_outages"][outage_key] = {
        "device": device,
        "problem": problem,
        "start_time": current_time
    }

    stats["total_outages"] = int(stats.get("total_outages", 0)) + 1
    stats["today_outages"] = int(stats.get("today_outages", 0)) + 1
    stats["last_outage_time"] = current_time

    save_uptime_stats(stats)


def record_uptime_outage_end(device, problem):
    stats = load_uptime_stats()
    outage_key = alert_id(device, problem)

    outage = stats.get("active_outages", {}).get(outage_key)

    if not outage:
        return

    start_time = outage.get("start_time", "")
    end_time = now()

    start_dt = parse_timestamp(start_time)
    end_dt = parse_timestamp(end_time)

    duration_seconds = 0

    if start_dt and end_dt:
        duration_seconds = max(0, int((end_dt - start_dt).total_seconds()))

    stats["accumulated_downtime_seconds"] = int(
        stats.get("accumulated_downtime_seconds", 0)
    ) + duration_seconds

    if duration_seconds > int(stats.get("longest_outage_seconds", 0)):
        stats["longest_outage_seconds"] = duration_seconds

    stats["total_recoveries"] = int(stats.get("total_recoveries", 0)) + 1
    stats["last_recovery_time"] = end_time

    add_internet_history_entry(
        start_time,
        end_time,
        duration_seconds,
        "RESOLVED"
    )

    stats.get("active_outages", {}).pop(outage_key, None)

    save_uptime_stats(stats)




def get_uptime_dashboard_stats():
    stats = load_uptime_stats()

    monitor_started = parse_timestamp(stats.get("monitor_started", ""))
    current_time = datetime.now()

    elapsed_seconds = 0
    if monitor_started:
        elapsed_seconds = max(1, int((current_time - monitor_started).total_seconds()))

    active_downtime_seconds = 0

    for outage in stats.get("active_outages", {}).values():
        start_dt = parse_timestamp(outage.get("start_time", ""))
        if start_dt:
            active_downtime_seconds += max(0, int((current_time - start_dt).total_seconds()))

    total_downtime_seconds = int(stats.get("accumulated_downtime_seconds", 0)) + active_downtime_seconds

    if elapsed_seconds > 0:
        network_uptime = max(0, 100 - ((total_downtime_seconds / elapsed_seconds) * 100))
    else:
        network_uptime = 100

    return {
        "network_uptime": f"{network_uptime:.2f}%",
        "today_outages": stats.get("today_outages", 0),
        "longest_outage": format_duration_seconds(stats.get("longest_outage_seconds", 0)),
        "last_outage": format_time_ago(stats.get("last_outage_time", "")),
        "total_outages": stats.get("total_outages", 0),
        "total_recoveries": stats.get("total_recoveries", 0),
        "active_outages": len(stats.get("active_outages", {}))
    }










def sync_alert_history(active_alerts):
    history = load_alert_history()
    active_ids = {alert["id"] for alert in active_alerts}

    existing_active = {
        item["id"]: item
        for item in history
        if item.get("status") == "ACTIVE"
    }

    for alert in active_alerts:
        if alert["id"] not in existing_active:
            new_history_item = {
                "id": alert["id"],
                "severity": alert["severity"],
                "device": alert["device"],
                "problem": alert["problem"],
                "alert_time": alert["time"],
                "resolved_time": "",
                "duration": "",
                "status": "ACTIVE",
                "acknowledged": False,
                "sms_alert_sent": False,
                "sms_recovery_sent": False
            }

            if alert.get("severity") == "CRITICAL" and not new_history_item.get("sms_alert_sent", False):
                send_sms_alert(alert)
                new_history_item["sms_alert_sent"] = True

            history.append(new_history_item)

    for item in history:
        if item.get("status") == "ACTIVE" and item.get("id") not in active_ids:
            item["status"] = "RESOLVED"
            item["resolved_time"] = now()
            item["duration"] = calculate_alert_duration(
                item.get("alert_time", ""),
                item.get("resolved_time", "")
            )

            if item.get("severity") == "CRITICAL" and not item.get("sms_recovery_sent", False):
                send_sms_recovery(item)
                item["sms_recovery_sent"] = True

    save_alert_history(history)
    return history



# PHASE 11H - INTELLIGENT ALERT CLASSIFICATION ENGINE
def get_intelligent_alert_classification_config():
    settings = config.setdefault("intelligent_alert_classification", {
        "enabled": True,
        "phase": "11H",
        "critical_device_types": [
            "Internet",
            "Modem",
            "Router",
            "Switch",
            "Server",
            "Server / NAS",
            "Virtual Machine"
        ],
        "warning_device_types": [
            "Desktop PC",
            "Windows PC",
            "Laptop",
            "Mac",
            "Chromebook",
            "Printer",
            "Camera",
            "Other Endpoint"
        ],
        "info_device_types": [
            "TV",
            "Gaming Console",
            "Mobile Device",
            "IoT Device"
        ],
        "critical_device_names": [],
        "default_endpoint_severity": "WARNING",
        "default_unknown_severity": "WARNING",
        "switch_link_inherits_endpoint_severity": True
    })
    configured = [clean_ascii(name) for name in settings.get("critical_device_names", []) if clean_ascii(name) in DEVICES]
    settings["critical_device_names"] = sorted(set(configured) | get_all_infrastructure_names())
    return settings




def get_device_alert_type(device_name):
    device_name = clean_ascii(device_name)

    if device_name in DEVICE_TYPES:
        return clean_ascii(DEVICE_TYPES.get(device_name, ""))

    # If a display label includes a discovered interface in parentheses, extract the inventory name.
    if "(" in device_name and ")" in device_name:
        base_name = clean_ascii(device_name.split("(")[0])
        if base_name in DEVICE_TYPES:
            return clean_ascii(DEVICE_TYPES.get(base_name, ""))

    return clean_ascii(detect_map_device_type(device_name, DEVICES.get(device_name, "")))


def classify_alert_severity(device_name, problem="", source="device"):
    settings = get_intelligent_alert_classification_config()

    if not settings.get("enabled", True):
        return "CRITICAL" if source in ["router", "infrastructure"] else "WARNING"

    device_name = clean_ascii(device_name)
    problem = clean_ascii(problem)
    source = clean_ascii(source).lower()

    critical_names = set(clean_ascii(item) for item in settings.get("critical_device_names", []))
    critical_types = set(clean_ascii(item) for item in settings.get("critical_device_types", []))
    warning_types = set(clean_ascii(item) for item in settings.get("warning_device_types", []))
    info_types = set(clean_ascii(item) for item in settings.get("info_device_types", []))

    # Router interfaces and core infrastructure links remain critical.
    if source == "router":
        return "CRITICAL"

    if device_name in critical_names:
        return "CRITICAL"

    # Switch link labels may include port suffix.
    base_name = device_name
    if "(" in base_name and ")" in base_name:
        base_name = clean_ascii(base_name.split("(")[0])

    if base_name in critical_names:
        return "CRITICAL"

    device_type = get_device_alert_type(base_name)

    if device_type in critical_types:
        return "CRITICAL"

    if device_type in info_types:
        return "INFO"

    if device_type in warning_types:
        return "WARNING"

    # Router, switch, modem, internet, and server keywords are infrastructure.
    name_text = f"{base_name} {device_type} {problem}".lower()
    if any(token in name_text for token in ["internet", "modem", "router", "switch", "server", "nas", "firewall"]):
        return "CRITICAL"

    return normalize_alert_severity(settings.get("default_unknown_severity", "WARNING"))


def build_alert_record(device_name, problem, time_value, acknowledged_lookup, source="device"):
    severity = classify_alert_severity(device_name, problem, source)
    aid = alert_id(device_name, problem)

    return {
        "id": aid,
        "severity": severity,
        "device": device_name,
        "problem": problem,
        "time": time_value,
        "acknowledged": acknowledged_lookup.get(aid, False),
        "classification_phase": "11H",
        "device_type": get_device_alert_type(device_name)
    }

def get_active_alerts():
    alerts = []
    history = load_alert_history()

    acknowledged = {
        item["id"]: item.get("acknowledged", False)
        for item in history
        if item.get("status") == "ACTIVE"
    }

    for name, info in status.items():
        state = info.get("state", "UNKNOWN")

        if state == get_maintenance_state_label() or info.get("maintenance_mode"):
            continue

        if state == "DOWN":
            problem = "Device DOWN"
            alerts.append(
                build_alert_record(
                    name,
                    problem,
                    info.get("last_checked", now()),
                    acknowledged,
                    source="device"
                )
            )

        elif state in ["ERROR", "UNKNOWN", "TESTING"]:
            problem = f"Device {state}"
            alerts.append(
                build_alert_record(
                    name,
                    problem,
                    info.get("last_checked", now()),
                    acknowledged,
                    source="device"
                )
            )

    for idx, iface in router_interfaces.items():
        state = iface.get("state", "UNKNOWN")
        device = iface.get("short_name", iface.get("name", idx))

        if state == "DOWN":
            problem = "Router Interface DOWN"
            alerts.append(
                build_alert_record(
                    device,
                    problem,
                    iface.get("last_checked", now()),
                    acknowledged,
                    source="router"
                )
            )

        elif state in ["ERROR", "UNKNOWN", "TESTING"]:
            problem = f"Router Interface {state}"
            alerts.append(
                build_alert_record(
                    device,
                    problem,
                    iface.get("last_checked", now()),
                    acknowledged,
                    source="router"
                )
            )

    for idx, link in switch_links.items():
        state = link.get("state", "UNKNOWN")
        endpoint_name = clean_ascii(link.get("device", "Unknown"))
        device = f"{endpoint_name} ({link.get('port', idx)})"

        if (
            state == get_maintenance_state_label() or
            link.get("maintenance_mode") or
            state == get_provisioning_state_label() or
            link.get("provisioning_grace")
        ):
            continue

        if state == "DOWN":
            problem = "Switch Link DOWN"
            alerts.append(
                build_alert_record(
                    device,
                    problem,
                    link.get("last_checked", now()),
                    acknowledged,
                    source="switch_link"
                )
            )

        elif state in ["ERROR", "UNKNOWN", "TESTING"]:
            problem = f"Switch Link {state}"
            alerts.append(
                build_alert_record(
                    device,
                    problem,
                    link.get("last_checked", now()),
                    acknowledged,
                    source="switch_link"
                )
            )

    # ======================================================
    # PHASE 16A.3C - INFRASTRUCTURE DEPENDENCY SUPPRESSION
    # ======================================================

    root_cause_priority = []
    for role in ("Internet", "Modem", "Firewall", "Router", "Switch", "Access Point"):
        root_cause_priority.extend(get_infrastructure_names_by_role(role))

    root_cause_alert = None
    suppressed_alerts = []

    for root_device in root_cause_priority:
        root_device = clean_ascii(root_device)

        if not root_device:
            continue

        for alert in alerts:
            alert_device = clean_ascii(
                alert.get("device", "")
            )

            if alert_device.startswith(root_device):
                root_cause_alert = alert
                break

        if root_cause_alert:
            break

    if root_cause_alert:
        filtered_alerts = []

        for alert in alerts:

            if alert.get("id") == root_cause_alert.get("id"):
                alert["root_cause"] = True
                filtered_alerts.append(alert)
            else:
                suppressed_alerts.append(alert)

        root_cause_alert["suppressed_count"] = len(
            suppressed_alerts
        )

        root_cause_alert["impacted_devices"] = [
            item.get("device", "Unknown")
            for item in suppressed_alerts
        ]

        alerts = filtered_alerts

    return alerts

# PHASE 10A - NETWORK INTELLIGENCE FOUNDATION


def get_device_category_counts():
    infrastructure_names = set(INFRASTRUCTURE.values()) if isinstance(INFRASTRUCTURE, dict) else set()
    physical_count = 0
    virtual_count = 0
    infrastructure_count = 0

    for device_name in DEVICES.keys():
        device_type = DEVICE_TYPES.get(device_name, "")

        if device_name in infrastructure_names:
            infrastructure_count += 1
        elif device_type in ["Virtual Machine", "VM", "Child Device"]:
            virtual_count += 1
        else:
            physical_count += 1

    return {
        "infrastructure": infrastructure_count,
        "physical": physical_count,
        "virtual": virtual_count,
        "total": len(DEVICES)
    }



# PHASE 10B - NETWORK INTELLIGENCE ENGINE
def calculate_network_intelligence_score(active_alerts=None):
    if active_alerts is None:
        active_alerts = get_active_alerts()

    score = 100

    critical_count = sum(
        1 for alert in active_alerts
        if alert.get("severity") == "CRITICAL"
    )

    warning_count = sum(
        1 for alert in active_alerts
        if alert.get("severity") == "WARNING"
    )

    down_devices = sum(
        1 for device in status.values()
        if device.get("state") == "DOWN"
    )

    unstable_devices = sum(
        1 for device in status.values()
        if device.get("state") in ["ERROR", "UNKNOWN", "TESTING"]
    )

    down_switch_links = sum(
        1 for link in switch_links.values()
        if link.get("state") == "DOWN"
    )

    down_router_links = sum(
        1 for iface in router_interfaces.values()
        if iface.get("state") == "DOWN"
    )

    score -= critical_count * 10
    score -= warning_count * 3
    score -= down_devices * 5
    score -= unstable_devices * 2
    score -= down_switch_links * 4
    score -= down_router_links * 6

    return max(0, min(100, score))


def calculate_network_grade(score):
    if score >= 97:
        return "A+"

    if score >= 90:
        return "A"

    if score >= 80:
        return "B"

    if score >= 70:
        return "C"

    if score >= 60:
        return "D"

    return "F"


def calculate_network_score_label(score):
    if score >= 97:
        return "Excellent"

    if score >= 90:
        return "Healthy"

    if score >= 80:
        return "Good"

    if score >= 70:
        return "Needs Attention"

    if score >= 60:
        return "At Risk"

    return "Critical"


def get_weakest_link(active_alerts=None):
    if active_alerts is None:
        active_alerts = get_active_alerts()

    critical_alerts = [
        alert for alert in active_alerts
        if alert.get("severity") == "CRITICAL"
    ]

    if critical_alerts:
        return critical_alerts[0].get("device", "Unknown Device")

    warning_alerts = [
        alert for alert in active_alerts
        if alert.get("severity") == "WARNING"
    ]

    if warning_alerts:
        return warning_alerts[0].get("device", "Unknown Device")

    # Phase 10C.2:
    # Weakest Link now compares LAN devices only.
    # Internet health is displayed separately in the Internet Health panel.
    latency_candidates = []

    for device_name, info in status.items():
        if is_internet_device(device_name):
            continue

        device_ip = info.get("ip", "")

        if not is_lan_ip(device_ip):
            continue

        latency_ms = parse_latency_ms(info.get("latency"))

        if latency_ms is not None:
            latency_candidates.append({
                "device": device_name,
                "latency": latency_ms
            })

    if latency_candidates:
        slowest = sorted(
            latency_candidates,
            key=lambda item: item["latency"],
            reverse=True
        )[0]

        if slowest["latency"] >= 25:
            return f"{slowest['device']} ({round(slowest['latency'], 2)} ms)"

    return "No LAN Weak Links Detected"


def get_network_recommendation(active_alerts=None, weakest_link=""):
    if active_alerts is None:
        active_alerts = get_active_alerts()

    if not active_alerts:
        return "All systems healthy. No action required."

    critical_alerts = [
        alert for alert in active_alerts
        if alert.get("severity") == "CRITICAL"
    ]

    if critical_alerts:
        device_name = critical_alerts[0].get("device", "Unknown Device")
        problem = critical_alerts[0].get("problem", "Critical issue")
        return f"Investigate {device_name} immediately. Current issue: {problem}."

    warning_alerts = [
        alert for alert in active_alerts
        if alert.get("severity") == "WARNING"
    ]

    if warning_alerts:
        device_name = warning_alerts[0].get("device", "Unknown Device")
        problem = warning_alerts[0].get("problem", "Warning condition")
        return f"Review {device_name}. Warning detected: {problem}."

    if weakest_link and weakest_link != "No Weak Links Detected":
        return f"Monitor {weakest_link}. It is currently the weakest observed link."

    return "Network is stable. Continue monitoring."


def get_device_risk_ranking():
    ranking = []

    for device_name, info in status.items():
        risk = 0
        reasons = []

        state = info.get("state", "UNKNOWN")

        if state == "DOWN":
            risk += 100
            reasons.append("Device down")

        elif state in ["ERROR", "UNKNOWN", "TESTING"]:
            risk += 50
            reasons.append(f"State {state}")

        latency_ms = parse_latency_ms(info.get("latency"))

        if latency_ms is not None:
            if latency_ms >= 100:
                risk += 30
                reasons.append("Very high latency")
            elif latency_ms >= 50:
                risk += 20
                reasons.append("High latency")
            elif latency_ms >= 25:
                risk += 10
                reasons.append("Elevated latency")
            else:
                risk += int(min(latency_ms, 5))

        ranking.append({
            "device": device_name,
            "risk": risk,
            "state": state,
            "latency": info.get("latency", "N/A"),
            "reason": ", ".join(reasons) if reasons else "Normal"
        })

    ranking.sort(
        key=lambda item: item.get("risk", 0),
        reverse=True
    )

    return ranking[:5]


def build_network_summary_text(total_devices, active_alert_count, average_latency, score_label):
    if active_alert_count == 0:
        status_text = "All monitored infrastructure is healthy."
    elif active_alert_count == 1:
        status_text = "1 active alert is currently detected."
    else:
        status_text = f"{active_alert_count} active alerts are currently detected."

    return (
        f"{total_devices} devices monitored. "
        f"{status_text} "
        f"Average response time is {average_latency}. "
        f"Network condition: {score_label}."
    )


def build_risk_ranking_html(risk_ranking):
    rows = ""

    for item in risk_ranking:
        risk = int(item.get("risk", 0))
        risk_class = "green"

        if risk >= 80:
            risk_class = "red"
        elif risk >= 30:
            risk_class = "orange"
        elif risk > 0:
            risk_class = "blue"

        rows += (
            f"<tr>"
            f"<td>{item.get('device', '')}</td>"
            f"<td class='{risk_class}'><strong>{risk}</strong></td>"
            f"<td>{item.get('state', '')}</td>"
            f"<td>{item.get('latency', '')}</td>"
            f"<td>{item.get('reason', '')}</td>"
            f"</tr>"
        )

    if not rows:
        rows = "<tr><td colspan='5'>No device risk data available.</td></tr>"

    return rows



# PHASE 10C.2 - LAN / INTERNET HEALTH SPLIT ENGINE
def is_internet_device(device_name):
    return clean_ascii(device_name) == get_internet_service_name() or normalize_infrastructure_role(DEVICE_TYPES.get(device_name, "")) == "Internet"




def get_internet_latency_details():
    internet_status = status.get(get_internet_service_name(), {})
    internet_state = internet_status.get("state", "UNKNOWN")
    target_results = {}

    try:
        internet_state_check, target_results = check_internet_targets()
    except Exception:
        internet_state_check = internet_state

    latency_values = []
    for target, info in target_results.items():
        latency_ms = parse_latency_ms(info.get("latency"))
        if latency_ms is not None:
            latency_values.append(latency_ms)

    average_latency = "N/A"
    highest_latency = None

    if latency_values:
        average_latency = f"{round(sum(latency_values) / len(latency_values), 2)} ms"
        highest_latency = max(latency_values)

    if internet_state != "UP":
        health_label = "DOWN"
        health_class = "red"
    elif highest_latency is None:
        health_label = "UNKNOWN"
        health_class = "orange"
    elif highest_latency < 50:
        health_label = "Excellent"
        health_class = "green"
    elif highest_latency < 100:
        health_label = "Good"
        health_class = "blue"
    elif highest_latency < 200:
        health_label = "Watch"
        health_class = "orange"
    else:
        health_label = "Poor"
        health_class = "red"

    return {
        "state": internet_state,
        "average_latency": average_latency,
        "health_label": health_label,
        "health_class": health_class,
        "targets": target_results
    }


def build_internet_target_rows(targets):
    rows = ""

    for target, info in targets.items():
        state = info.get("state", "UNKNOWN")
        rows += (
            f"<tr><td>{target}</td>"
            f"<td class='status {state}'>{state}</td>"
            f"<td>{info.get('latency', 'N/A')}</td></tr>"
        )

    if not rows:
        rows = "<tr><td colspan='3'>No internet target data available.</td></tr>"

    return rows


def build_lan_health():
    lan_devices = []

    for device_name, ip_address in DEVICES.items():
        if is_internet_device(device_name):
            continue
        if not is_lan_ip(ip_address):
            continue

        info = status.get(device_name, {})
        state = info.get("state", "UNKNOWN")
        latency_text = info.get("latency", "N/A")
        latency_ms = parse_latency_ms(latency_text)

        lan_devices.append({
            "device": device_name,
            "ip": ip_address,
            "state": state,
            "latency": latency_text,
            "latency_ms": latency_ms
        })

    total = len(lan_devices)
    online = sum(1 for item in lan_devices if item.get("state") == "UP")
    offline = sum(1 for item in lan_devices if item.get("state") == "DOWN")
    warning = sum(1 for item in lan_devices if item.get("state") in ["ERROR", "UNKNOWN", "TESTING"])

    latency_values = [item.get("latency_ms") for item in lan_devices if item.get("latency_ms") is not None]

    average_latency = "N/A"
    if latency_values:
        average_latency = f"{round(sum(latency_values) / len(latency_values), 2)} ms"

    weakest_lan = "No LAN Weak Links Detected"

    down_device = next((item for item in lan_devices if item.get("state") == "DOWN"), None)

    if down_device:
        weakest_lan = down_device.get("device", "Unknown LAN Device")
    elif latency_values:
        slowest = sorted(
            [item for item in lan_devices if item.get("latency_ms") is not None],
            key=lambda item: item.get("latency_ms", 0),
            reverse=True
        )[0]

        if slowest.get("latency_ms", 0) >= 25:
            weakest_lan = f"{slowest.get('device')} ({round(slowest.get('latency_ms'), 2)} ms)"

    switch_total = len(switch_links)
    switch_up = sum(1 for item in switch_links.values() if item.get("state") == "UP")
    switch_health = f"{switch_up}/{switch_total} Up" if switch_total else "N/A"

    if offline > 0:
        health_label = "Attention"
        health_class = "red"
    elif warning > 0:
        health_label = "Watch"
        health_class = "orange"
    elif latency_values and max(latency_values) >= 25:
        health_label = "Good"
        health_class = "blue"
    else:
        health_label = "Excellent"
        health_class = "green"

    return {
        "health_label": health_label,
        "health_class": health_class,
        "total_devices": total,
        "online_devices": online,
        "offline_devices": offline,
        "warning_devices": warning,
        "average_latency": average_latency,
        "weakest_lan": weakest_lan,
        "switch_health": switch_health
    }


def build_internet_health():
    latency_details = get_internet_latency_details()
    availability_report = get_internet_availability_report()
    uptime_stats = get_uptime_dashboard_stats()

    return {
        "state": latency_details.get("state", "UNKNOWN"),
        "health_label": latency_details.get("health_label", "UNKNOWN"),
        "health_class": latency_details.get("health_class", "orange"),
        "average_latency": latency_details.get("average_latency", "N/A"),
        "availability_today": availability_report.get("today", {}).get("availability", "N/A"),
        "outages_today": uptime_stats.get("today_outages", 0),
        "target_rows": build_internet_target_rows(latency_details.get("targets", {}))
    }


def build_lan_internet_health_split():
    return {
        "lan": build_lan_health(),
        "internet": build_internet_health()
    }




# PHASE 10D - DEVICE CLASSIFICATION ENGINE
def get_device_classification(device_name, ip_address=""):
    infrastructure_names = set(INFRASTRUCTURE.values()) if isinstance(INFRASTRUCTURE, dict) else set()
    name_text = clean_ascii(device_name).lower()
    type_text = clean_ascii(DEVICE_TYPES.get(device_name, "")).lower()

    if device_name == get_internet_service_name():
        return "Critical Infrastructure"

    if device_name in infrastructure_names:
        return "Critical Infrastructure"

    if is_infrastructure_topology_device(device_name):
        return "Critical Infrastructure"

    # Phase 10D.1:
    # Monitoring Server VM and other VM devices are separated from normal servers.
    if any(keyword in name_text for keyword in ["monitoring server vm", " vm", "virtual"]):
        return "Virtual Systems"

    if any(keyword in type_text for keyword in ["virtual machine", "vm"]):
        return "Virtual Systems"

    if any(keyword in name_text for keyword in ["omv", "file server", "terminal server", "server"]):
        return "Servers"

    if any(keyword in type_text for keyword in ["server", "nas"]):
        return "Servers"

    if any(keyword in name_text for keyword in ["mac", "windows", "host", "pc", "laptop", "desktop"]):
        return "Workstations"

    return "Other Devices"


def get_device_monitoring_policy(device_name, device_class=""):
    if not device_class:
        device_class = get_device_classification(device_name)

    if device_class == "Critical Infrastructure":
        return {
            "priority": "Critical",
            "sleep_allowed": False,
            "risk_multiplier": 1.8,
            "description": "Core network device. Any outage should be treated as high priority."
        }

    if device_class == "Servers":
        return {
            "priority": "High",
            "sleep_allowed": False,
            "risk_multiplier": 1.35,
            "description": "Server or service device. Should normally remain online."
        }

    if device_class == "Virtual Systems":
        return {
            "priority": "High",
            "sleep_allowed": False,
            "risk_multiplier": 1.45,
            "description": "Virtual system or monitoring VM. Critical to dashboard visibility and monitoring operations."
        }

    if device_class == "Workstations":
        return {
            "priority": "Normal",
            "sleep_allowed": True,
            "risk_multiplier": 0.45,
            "description": "User workstation. Sleep or power-saving disconnects are allowed."
        }

    return {
        "priority": "Standard",
        "sleep_allowed": True,
        "risk_multiplier": 0.75,
        "description": "Non-critical endpoint or accessory device."
    }


def is_sleep_allowed_device(device_name):
    if not SLEEP_DETECTION.get("enabled", True):
        return False

    explicit_sleep_devices = SLEEP_DETECTION.get("sleep_allowed_devices", [])
    if device_name in explicit_sleep_devices:
        return True

    device_class = get_device_classification(device_name)
    policy = get_device_monitoring_policy(device_name, device_class)

    return bool(policy.get("sleep_allowed", False))


def get_sleep_grace_minutes():
    try:
        return int(SLEEP_DETECTION.get("sleep_grace_minutes", 30))
    except Exception:
        return 30


def get_sleep_status_label():
    return clean_ascii(SLEEP_DETECTION.get("sleep_state_label", "SLEEPING")) or "SLEEPING"




def apply_sleep_detection_state(device_name, raw_state, last_change_text):
    if raw_state != "DOWN":
        return raw_state

    # PHASE 13B.2 - SWITCH PORT OVERRIDES SLEEP DETECTION
    # Sleep Detection is only valid when the physical switch link is still UP.
    # If the assigned Cisco switch port is DOWN, that is a real link-down event,
    # not a sleeping endpoint.
    for link in switch_links.values():
        if clean_ascii(link.get("device", "")) == clean_ascii(device_name):
            link_state = clean_ascii(link.get("state", "")).upper()
            raw_link_state = clean_ascii(link.get("raw_state", "")).upper()

            if link_state == "DOWN" or raw_link_state == "DOWN":
                return "DOWN"

    if not is_sleep_allowed_device(device_name):
        return raw_state

    down_minutes = get_device_down_minutes(last_change_text)

    if down_minutes <= get_sleep_grace_minutes():
        return get_sleep_status_label()

    return "DOWN"


def apply_switch_link_override_to_device_status(current_switch_links):
    """
    PHASE 13B.2 - Switch Port Overrides Sleep Detection.

    If a device's assigned Cisco switch port is physically DOWN, the device
    must be treated as DOWN / LINK DOWN even if that device is normally allowed
    to enter the SLEEPING state.

    This prevents cases like Alicia MAC showing as SLEEPING when Gi1/0/2 is
    unplugged from the switch.
    """
    for index, link in current_switch_links.items():
        device_name = clean_ascii(link.get("device", ""))
        if not device_name or device_name not in status:
            continue

        link_state = clean_ascii(link.get("state", "")).upper()
        raw_link_state = clean_ascii(link.get("raw_state", "")).upper()

        if link_state != "DOWN" and raw_link_state != "DOWN":
            continue

        device_info = status.get(device_name, {})

        # Maintenance and provisioning are intentional lifecycle states and
        # should still suppress alarms/impact. Everything else should show the
        # real physical link condition.
        if device_info.get("maintenance_mode") or device_info.get("provisioning_grace"):
            continue

        if device_info.get("state") == get_maintenance_state_label():
            continue

        if device_info.get("state") == get_provisioning_state_label():
            continue

        previous_state = clean_ascii(device_info.get("state", ""))

        status[device_name] = dict(device_info)
        status[device_name].update({
            "state": "DOWN",
            "raw_state": "LINK_DOWN",
            "latency": f"Cisco switch port {link.get('port', index)} link down",
            "raw_latency": "N/A",
            "sleep_overridden_by_switch_link": True,
            "switch_port": link.get("port", ""),
            "switch_port_index": str(index),
            "switch_link_state": link_state or raw_link_state,
            "last_checked": now()
        })

        if previous_state == get_sleep_status_label():
            write_event(
                f"LINK OVERRIDE | DEVICE | {device_name} changed from SLEEPING to DOWN because {link.get('port', index)} is DOWN"
            )


def build_sleep_detection_engine():
    # Phase 11B Sync Patch:
    # Build sleep tracking from the policy engine, not only from the static
    # config sleep_allowed_devices list. This keeps Sleep Detection, NOC
    # Operations, and Lifecycle counts synchronized after Smart Provisioning.
    explicit_sleep_devices = SLEEP_DETECTION.get("sleep_allowed_devices", [])

    sleep_devices = []
    seen_devices = set()

    for device_name in explicit_sleep_devices:
        if device_name in DEVICES and device_name not in seen_devices:
            sleep_devices.append(device_name)
            seen_devices.add(device_name)

    for device_name in DEVICES.keys():
        if device_name in seen_devices:
            continue

        if is_sleep_allowed_device(device_name):
            sleep_devices.append(device_name)
            seen_devices.add(device_name)

    sleeping_devices = []
    awake_devices = []
    expired_devices = []

    for device_name in sleep_devices:
        info = status.get(device_name, {})
        state = info.get("state", "UNKNOWN")
        raw_state = info.get("raw_state", state)
        last_change = info.get("last_change", "Starting...")
        down_minutes = get_device_down_minutes(last_change) if raw_state == "DOWN" else 0

        item = {
            "device": device_name,
            "ip": DEVICES.get(device_name, ""),
            "state": state,
            "raw_state": raw_state,
            "latency": info.get("latency", "N/A"),
            "down_minutes": down_minutes,
            "grace_minutes": get_sleep_grace_minutes(),
            "last_change": last_change
        }

        if state == get_sleep_status_label():
            sleeping_devices.append(item)
        elif raw_state == "DOWN":
            expired_devices.append(item)
        else:
            awake_devices.append(item)

    if expired_devices:
        engine_state = "Attention"
        engine_class = "red"
    elif sleeping_devices:
        engine_state = "Sleep Detected"
        engine_class = "blue"
    else:
        engine_state = "Normal"
        engine_class = "green"

    return {
        "enabled": SLEEP_DETECTION.get("enabled", True),
        "engine_state": engine_state,
        "engine_class": engine_class,
        "sleep_allowed_count": len(sleep_devices),
        "sleeping_count": len(sleeping_devices),
        "awake_count": len(awake_devices),
        "expired_count": len(expired_devices),
        "sleeping_devices": sleeping_devices,
        "awake_devices": awake_devices,
        "expired_devices": expired_devices,
        "grace_minutes": get_sleep_grace_minutes()
    }

def build_sleep_detection_html(sleep_engine):
    rows = ""

    combined = (
        sleep_engine.get("sleeping_devices", []) +
        sleep_engine.get("expired_devices", []) +
        sleep_engine.get("awake_devices", [])
    )

    for item in combined:
        state = item.get("state", "UNKNOWN")
        raw_state = item.get("raw_state", state)
        sleep_note = "Awake"

        if state == get_sleep_status_label():
            sleep_note = f"Sleeping {item.get('down_minutes', 0)} min / {item.get('grace_minutes', 30)} min grace"
        elif raw_state == "DOWN":
            sleep_note = "Grace expired - treated as DOWN"

        rows += (
            f"<tr>"
            f"<td>{item.get('device', '')}</td>"
            f"<td>{item.get('ip', '')}</td>"
            f"<td class='status {state}'>{state}</td>"
            f"<td>{sleep_note}</td>"
            f"<td>{item.get('last_change', 'Starting...')}</td>"
            f"</tr>"
        )

    if not rows:
        rows = "<tr><td colspan='5'>No sleep-aware devices configured.</td></tr>"

    return {
        "rows": rows
    }



def build_device_classification_engine():
    class_order = [
        "Critical Infrastructure",
        "Servers",
        "Virtual Systems",
        "Workstations",
        "Other Devices"
    ]

    classes = {
        class_name: {
            "total": 0,
            "online": 0,
            "offline": 0,
            "warning": 0,
            "sleeping": 0,
            "sleep_allowed": 0,
            "devices": []
        }
        for class_name in class_order
    }

    for device_name, ip_address in DEVICES.items():
        info = status.get(device_name, {})
        state = info.get("state", "UNKNOWN")
        device_class = get_device_classification(device_name, ip_address)
        policy = get_device_monitoring_policy(device_name, device_class)

        if device_class not in classes:
            classes[device_class] = {
                "total": 0,
                "online": 0,
                "offline": 0,
                "warning": 0,
                "sleeping": 0,
                "sleep_allowed": 0,
                "devices": []
            }

        class_data = classes[device_class]
        class_data["total"] += 1

        if state == "UP":
            class_data["online"] += 1
        elif state == get_sleep_status_label():
            class_data["online"] += 1
            class_data["sleeping"] += 1
        elif state == "DOWN":
            class_data["offline"] += 1
        else:
            class_data["warning"] += 1

        if policy.get("sleep_allowed"):
            class_data["sleep_allowed"] += 1

        class_data["devices"].append({
            "name": device_name,
            "ip": ip_address,
            "state": state,
            "latency": info.get("latency", "N/A"),
            "class": device_class,
            "priority": policy.get("priority", "Standard"),
            "sleep_allowed": policy.get("sleep_allowed", False),
            "policy": policy.get("description", "")
        })

    summary = {}

    for class_name, class_data in classes.items():
        total = class_data.get("total", 0)
        online = class_data.get("online", 0)
        offline = class_data.get("offline", 0)
        warning = class_data.get("warning", 0)
        sleeping = class_data.get("sleeping", 0)

        if total == 0:
            health_percent = 100
        else:
            health_percent = round((online / total) * 100)

        if offline > 0:
            health_label = "Attention"
            health_class = "red"
        elif warning > 0:
            health_label = "Watch"
            health_class = "orange"
        elif total == 0:
            health_label = "N/A"
            health_class = "blue"
        else:
            health_label = "Healthy"
            health_class = "green"

        summary[class_name] = {
            "total": total,
            "online": online,
            "offline": offline,
            "warning": warning,
            "sleeping": sleeping,
            "sleep_allowed": class_data.get("sleep_allowed", 0),
            "health_percent": health_percent,
            "health_label": health_label,
            "health_class": health_class,
            "devices": class_data.get("devices", [])
        }

    critical = summary.get("Critical Infrastructure", {})
    servers = summary.get("Servers", {})
    virtual_systems = summary.get("Virtual Systems", {})
    workstations = summary.get("Workstations", {})

    overall_text = (
        f"Critical Infrastructure {critical.get('online', 0)}/{critical.get('total', 0)} online. "
        f"Servers {servers.get('online', 0)}/{servers.get('total', 0)} online. "
        f"Virtual Systems {virtual_systems.get('online', 0)}/{virtual_systems.get('total', 0)} online. "
        f"Workstations {workstations.get('online', 0)}/{workstations.get('total', 0)} online. "
        f"Sleep-aware workstation monitoring is enabled."
    )

    return {
        "classes": summary,
        "overall_text": overall_text
    }


def build_device_classification_html(classification):
    class_cards = ""
    device_rows = ""

    class_order = [
        "Critical Infrastructure",
        "Servers",
        "Virtual Systems",
        "Workstations",
        "Other Devices"
    ]

    for class_name in class_order:
        class_data = classification.get("classes", {}).get(class_name, {})
        if not class_data:
            continue

        class_cards += (
            f"<div class='device-class-card'>"
            f"<div class='device-class-title'>{class_name}</div>"
            f"<div class='device-class-count {class_data.get('health_class', 'blue')}'>{class_data.get('online', 0)}/{class_data.get('total', 0)}</div>"
            f"<div class='device-class-health {class_data.get('health_class', 'blue')}'>{class_data.get('health_label', 'N/A')}</div>"
            f"<div class='device-class-subtext'>Sleep Allowed: {class_data.get('sleep_allowed', 0)} | Sleeping: {class_data.get('sleeping', 0)}</div>"
            f"</div>"
        )

        for device in class_data.get("devices", []):
            sleep_text = "Yes" if device.get("sleep_allowed") else "No"
            state = device.get("state", "UNKNOWN")
            priority = device.get("priority", "Standard")

            priority_class = "green"
            if priority == "Critical":
                priority_class = "red"
            elif priority == "High":
                priority_class = "orange"
            elif priority == "Normal":
                priority_class = "blue"

            device_rows += (
                f"<tr>"
                f"<td>{device.get('name', '')}</td>"
                f"<td>{device.get('class', '')}</td>"
                f"<td class='{priority_class}'><strong>{priority}</strong></td>"
                f"<td>{sleep_text}</td>"
                f"<td class='status {state}'>{state}</td>"
                f"<td>{device.get('latency', 'N/A')}</td>"
                f"</tr>"
            )

    if not class_cards:
        class_cards = "<div class='device-class-empty'>No classification data available.</div>"

    if not device_rows:
        device_rows = "<tr><td colspan='6'>No classified devices available.</td></tr>"

    return {
        "class_cards": class_cards,
        "device_rows": device_rows
    }


def build_network_intelligence():
    load_config()

    category_counts = get_device_category_counts()
    active_alerts = get_active_alerts()
    critical_count = sum(1 for alert in active_alerts if alert.get("severity") == "CRITICAL")
    warning_count = sum(1 for alert in active_alerts if alert.get("severity") == "WARNING")

    intelligence_score = calculate_network_intelligence_score(active_alerts)
    network_grade = calculate_network_grade(intelligence_score)
    score_label = calculate_network_score_label(intelligence_score)
    weakest_link = get_weakest_link(active_alerts)
    recommendation = get_network_recommendation(active_alerts, weakest_link)
    risk_ranking = get_device_risk_ranking()

    latency_values = []
    device_latency_rows = []
    device_history_rows = []

    for device_name, ip_address in DEVICES.items():
        info = status.get(device_name, {})
        state = info.get("state", "UNKNOWN")
        latency_text = info.get("latency", "N/A")
        latency_ms = parse_latency_ms(latency_text)

        if latency_ms is not None:
            latency_values.append(latency_ms)

        device_latency_rows.append({
            "name": device_name,
            "ip": ip_address,
            "state": state,
            "latency": latency_text,
            "last_checked": info.get("last_checked", "Starting..."),
            "last_change": info.get("last_change", "Starting...")
        })

        device_history_rows.append({
            "name": device_name,
            "state": state,
            "last_seen": info.get("last_checked", "Starting..."),
            "last_change": info.get("last_change", "Starting..."),
            "latency": latency_text
        })

    average_latency = "N/A"
    if latency_values:
        average_latency = f"{round(sum(latency_values) / len(latency_values), 2)} ms"

    fastest_device = "N/A"
    slowest_device = "N/A"

    candidates = [
        row for row in device_latency_rows
        if parse_latency_ms(row.get("latency")) is not None
    ]

    if candidates:
        best = sorted(
            candidates,
            key=lambda row: parse_latency_ms(row.get("latency"))
        )[0]

        slowest = sorted(
            candidates,
            key=lambda row: parse_latency_ms(row.get("latency")),
            reverse=True
        )[0]

        fastest_device = f"{best['name']} ({best['latency']})"
        slowest_device = f"{slowest['name']} ({slowest['latency']})"

    managed_links = []

    for index, interface_info in get_primary_switch_interfaces().items():
        label = clean_ascii(interface_info.get("short_name", "")) or clean_ascii(interface_info.get("name", "")) or f"Index {index}"
        if index in SWITCH_PORTS:
            linked_device = SWITCH_PORTS.get(index, "")
            link_info = switch_links.get(index, {})
            managed_links.append({
                "port": label,
                "index": index,
                "device": linked_device,
                "state": link_info.get("state", "UNKNOWN"),
                "last_checked": link_info.get("last_checked", "Starting...")
            })

    switch_link_health = "N/A"

    if managed_links:
        up_links = sum(1 for link in managed_links if link.get("state") == "UP")
        switch_link_health = f"{up_links}/{len(managed_links)} Up"

    executive_summary = build_network_summary_text(
        len(DEVICES),
        len(active_alerts),
        average_latency,
        score_label
    )

    return {
        "category_counts": category_counts,
        "average_latency": average_latency,
        "fastest_device": fastest_device,
        "slowest_device": slowest_device,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "active_alert_count": len(active_alerts),
        "switch_link_health": switch_link_health,
        "device_latency_rows": device_latency_rows,
        "device_history_rows": device_history_rows,
        "managed_links": managed_links,

        # Phase 10B intelligence fields
        "intelligence_score": intelligence_score,
        "network_grade": network_grade,
        "score_label": score_label,
        "weakest_link": weakest_link,
        "recommendation": recommendation,
        "risk_ranking": risk_ranking,
        "summary": executive_summary
    }


def build_network_intelligence_html(intelligence):
    latency_rows = ""
    for row in intelligence.get("device_latency_rows", []):
        state = row.get("state", "UNKNOWN")
        latency_rows += f"<tr><td>{row.get('name','')}</td><td>{row.get('ip','')}</td><td class='status {state}'>{state}</td><td>{row.get('latency','')}</td><td>{row.get('last_checked','')}</td></tr>"

    if not latency_rows:
        latency_rows = "<tr><td colspan='5'>No latency data available yet.</td></tr>"

    history_rows = ""
    for row in intelligence.get("device_history_rows", []):
        state = row.get("state", "UNKNOWN")
        history_rows += f"<tr><td>{row.get('name','')}</td><td class='status {state}'>{state}</td><td>{row.get('last_seen','')}</td><td>{row.get('last_change','')}</td></tr>"

    if not history_rows:
        history_rows = "<tr><td colspan='4'>No device history available yet.</td></tr>"

    link_rows = ""
    for link in intelligence.get("managed_links", [])[:10]:
        state = link.get("state", "UNKNOWN")
        link_rows += f"<tr><td>{link.get('port','')}</td><td>{link.get('device','')}</td><td class='status {state}'>{state}</td><td>{link.get('last_checked','')}</td></tr>"

    if not link_rows:
        link_rows = "<tr><td colspan='4'>No managed switch links available yet.</td></tr>"

    risk_rows = build_risk_ranking_html(
        intelligence.get("risk_ranking", [])
    )

    return {
        "latency_rows": latency_rows,
        "history_rows": history_rows,
        "link_rows": link_rows,
        "risk_rows": risk_rows
    }





# PHASE 10C.3 - EVENT AGING ENGINE













def analyze_event_log_trends():
    lines = get_event_log_lines(1500)

    device_alerts = {}
    device_recoveries = {}
    device_weighted_alerts = {}
    device_recent_alerts = {}
    device_last_alert = {}
    device_last_recovery = {}
    device_age_buckets = {}

    internet_alerts = 0
    internet_recoveries = 0
    internet_weighted_alerts = 0.0
    internet_recent_alerts = 0
    internet_last_alert = ""
    internet_age_buckets = {}

    switch_alerts = {}
    router_alerts = {}

    for line in lines:
        clean_line = line.strip()
        event_time = parse_event_timestamp_from_line(clean_line)
        base_weight = event_age_weight(event_time)
        severity_weight = get_event_severity_weight(clean_line)
        weight = round(base_weight * severity_weight, 2)
        bucket = event_age_bucket(event_time)

        if "ALERT | DEVICE |" in clean_line:
            try:
                raw_device = clean_line.split("ALERT | DEVICE |", 1)[1].split(" changed", 1)[0].strip()
                device_name = normalize_event_device_name(raw_device)

                device_alerts[device_name] = device_alerts.get(device_name, 0) + 1
                device_weighted_alerts[device_name] = round(
                    device_weighted_alerts.get(device_name, 0.0) + weight,
                    2
                )

                if bucket in ["0-6h", "6-24h"]:
                    device_recent_alerts[device_name] = device_recent_alerts.get(device_name, 0) + 1

                device_age_buckets.setdefault(device_name, {})
                device_age_buckets[device_name][bucket] = device_age_buckets[device_name].get(bucket, 0) + 1

                if event_time:
                    previous = parse_timestamp(device_last_alert.get(device_name, ""))
                    if not previous or event_time > previous:
                        device_last_alert[device_name] = event_time.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

        if "RECOVERY | DEVICE |" in clean_line:
            try:
                raw_device = clean_line.split("RECOVERY | DEVICE |", 1)[1].split(" changed", 1)[0].strip()
                device_name = normalize_event_device_name(raw_device)

                device_recoveries[device_name] = device_recoveries.get(device_name, 0) + 1

                if event_time:
                    previous = parse_timestamp(device_last_recovery.get(device_name, ""))
                    if not previous or event_time > previous:
                        device_last_recovery[device_name] = event_time.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

        if "ALERT | INTERNET OUTAGE" in clean_line:
            internet_alerts += 1
            internet_weighted_alerts = round(internet_weighted_alerts + weight, 2)

            if bucket in ["0-6h", "6-24h"]:
                internet_recent_alerts += 1

            internet_age_buckets[bucket] = internet_age_buckets.get(bucket, 0) + 1

            if event_time:
                internet_last_alert = event_time.strftime("%Y-%m-%d %H:%M:%S")

        if "RECOVERY | INTERNET OUTAGE" in clean_line:
            internet_recoveries += 1

        if "ALERT | SWITCH LINK |" in clean_line:
            try:
                item = clean_line.split("ALERT | SWITCH LINK |", 1)[1].split(" changed", 1)[0].strip()
                switch_alerts[item] = switch_alerts.get(item, 0) + 1
            except Exception:
                pass

        if "ALERT | ROUTER LINK |" in clean_line:
            try:
                item = clean_line.split("ALERT | ROUTER LINK |", 1)[1].split(" changed", 1)[0].strip()
                router_alerts[item] = router_alerts.get(item, 0) + 1
            except Exception:
                pass

    return {
        "device_alerts": device_alerts,
        "device_recoveries": device_recoveries,
        "device_weighted_alerts": device_weighted_alerts,
        "device_recent_alerts": device_recent_alerts,
        "device_last_alert": device_last_alert,
        "device_last_recovery": device_last_recovery,
        "device_age_buckets": device_age_buckets,
        "internet_alerts": internet_alerts,
        "internet_recoveries": internet_recoveries,
        "internet_weighted_alerts": round(internet_weighted_alerts, 2),
        "internet_recent_alerts": internet_recent_alerts,
        "internet_last_alert": internet_last_alert,
        "internet_age_buckets": internet_age_buckets,
        "switch_alerts": switch_alerts,
        "router_alerts": router_alerts,
        "total_event_lines": len(lines)
    }



def calculate_device_stability_scores():
    trend_data = analyze_event_log_trends()
    device_alerts = trend_data.get("device_alerts", {})
    device_recoveries = trend_data.get("device_recoveries", {})
    device_weighted_alerts = trend_data.get("device_weighted_alerts", {})
    device_recent_alerts = trend_data.get("device_recent_alerts", {})
    device_last_alert = trend_data.get("device_last_alert", {})

    stability_rows = []

    for device_name, ip_address in DEVICES.items():
        info = status.get(device_name, {})
        state = info.get("state", "UNKNOWN")
        alert_count = int(device_alerts.get(device_name, 0))
        recovery_count = int(device_recoveries.get(device_name, 0))
        recent_alert_count = int(device_recent_alerts.get(device_name, 0))
        weighted_alert_count = float(device_weighted_alerts.get(device_name, 0.0))
        device_class = get_device_classification(device_name, ip_address)
        policy = get_device_monitoring_policy(device_name, device_class)
        sleep_allowed = bool(policy.get("sleep_allowed", False))
        risk_multiplier = float(policy.get("risk_multiplier", 1.0))

        score = 100

        if state == "DOWN":
            score -= 40
        elif state == get_sleep_status_label():
            score -= 0
        elif state in ["ERROR", "UNKNOWN", "TESTING"]:
            score -= 15

        # Phase 10D classification policy:
        # Critical infrastructure is weighted higher.
        # Workstations are sleep-aware and weighted lower.
        weighted_penalty = min(38, weighted_alert_count * 7) * risk_multiplier

        if sleep_allowed:
            weighted_penalty *= 0.45

        score -= weighted_penalty

        recent_penalty = 0
        if recent_alert_count >= 3:
            recent_penalty = 18
        elif recent_alert_count == 2:
            recent_penalty = 12
        elif recent_alert_count == 1:
            recent_penalty = 6

        if sleep_allowed:
            recent_penalty *= 0.35
        else:
            recent_penalty *= risk_multiplier

        score -= recent_penalty

        historical_penalty = 0
        if alert_count >= 10:
            historical_penalty = 10
        elif alert_count >= 6:
            historical_penalty = 7
        elif alert_count >= 3:
            historical_penalty = 4
        elif alert_count >= 1:
            historical_penalty = 2

        if sleep_allowed:
            historical_penalty *= 0.30
        else:
            historical_penalty *= risk_multiplier

        score -= historical_penalty

        # Flapping penalty only applies when there are recent events.
        if recent_alert_count >= 2 and recovery_count >= 2:
            if sleep_allowed:
                score -= 3
            else:
                score -= (8 * risk_multiplier)

        latency_ms = parse_latency_ms(info.get("latency"))
        if latency_ms is not None:
            if latency_ms >= 100:
                score -= 20
            elif latency_ms >= 50:
                score -= 12
            elif latency_ms >= 25:
                score -= 6

        score = int(max(0, min(100, round(score))))

        if state == get_sleep_status_label():
            rating = "Sleep Aware"
        elif recent_alert_count >= 3:
            rating = "Flapping"
        elif recent_alert_count >= 1:
            rating = "Recent Event"
        elif alert_count >= 5 and weighted_alert_count >= 2:
            rating = "Intermittent"
        elif score >= 97:
            rating = "Excellent"
        elif score >= 90:
            rating = "Stable"
        elif score >= 80:
            rating = "Good"
        elif score >= 70:
            rating = "Watch"
        else:
            rating = "At Risk"

        stability_rows.append({
            "device": device_name,
            "ip": ip_address,
            "score": score,
            "rating": rating,
            "state": state,
            "alerts": alert_count,
            "recoveries": recovery_count,
            "recent_alerts": recent_alert_count,
            "weighted_alerts": round(weighted_alert_count, 2),
            "last_alert": device_last_alert.get(device_name, ""),
            "latency": info.get("latency", "N/A"),
            "device_class": device_class,
            "sleep_allowed": sleep_allowed,
            "priority": policy.get("priority", "Standard")
        })

    stability_rows.sort(
        key=lambda item: (
            item.get("score", 0),
            -item.get("recent_alerts", 0),
            -item.get("weighted_alerts", 0)
        ),
        reverse=True
    )

    return stability_rows



def build_reliability_rankings(stability_rows):
    most_reliable = sorted(
        stability_rows,
        key=lambda item: (item.get("score", 0), -item.get("alerts", 0)),
        reverse=True
    )[:5]

    needs_attention = sorted(
        stability_rows,
        key=lambda item: (item.get("score", 0), -item.get("alerts", 0))
    )[:5]

    return {
        "most_reliable": most_reliable,
        "needs_attention": needs_attention
    }


def build_network_forecast(intelligence_score, active_alert_count, stability_rows):
    trend_data = analyze_event_log_trends()
    internet_alerts = int(trend_data.get("internet_alerts", 0))
    internet_recent_alerts = int(trend_data.get("internet_recent_alerts", 0))
    internet_weighted_alerts = float(trend_data.get("internet_weighted_alerts", 0.0))

    average_stability = 100
    if stability_rows:
        average_stability = round(
            sum(item.get("score", 0) for item in stability_rows) / len(stability_rows),
            1
        )

    unstable_devices = [
        item for item in stability_rows
        if item.get("score", 100) < 90
    ]

    recent_unstable_devices = [
        item for item in stability_rows
        if item.get("recent_alerts", 0) > 0
    ]

    critical_recent_unstable = [
        item for item in recent_unstable_devices
        if item.get("device_class") == "Critical Infrastructure"
    ]

    server_recent_unstable = [
        item for item in recent_unstable_devices
        if item.get("device_class") == "Servers"
    ]

    virtual_recent_unstable = [
        item for item in recent_unstable_devices
        if item.get("device_class") == "Virtual Systems"
    ]

    workstation_recent_unstable = [
        item for item in recent_unstable_devices
        if item.get("device_class") == "Workstations"
    ]

    risk_points = 0

    if intelligence_score < 90:
        risk_points += 16

    if active_alert_count > 0:
        risk_points += active_alert_count * 14

    # Internet risk now uses event aging.
    risk_points += min(18, int(internet_weighted_alerts * 5))

    if internet_recent_alerts >= 2:
        risk_points += 14
    elif internet_recent_alerts == 1:
        risk_points += 7

    if average_stability < 80:
        risk_points += 18
    elif average_stability < 90:
        risk_points += 10
    elif average_stability < 96:
        risk_points += 4

    # Phase 10D forecast classification weighting:
    # Infrastructure events are serious. Workstation sleep events are lighter.
    if recent_unstable_devices:
        risk_points += min(
            22,
            (len(critical_recent_unstable) * 10) +
            (len(server_recent_unstable) * 6) +
            (len(virtual_recent_unstable) * 7) +
            (len(workstation_recent_unstable) * 2)
        )
    elif unstable_devices:
        risk_points += min(10, len(unstable_devices) * 3)

    # Cap risk if there are no active alerts and no recent instability.
    if active_alert_count == 0 and internet_recent_alerts == 0 and not recent_unstable_devices:
        risk_points = min(risk_points, 18)

    if risk_points <= 18:
        risk_level = "LOW"
        forecast_text = "Network forecast is stable. Historical events are aging out normally."
    elif risk_points <= 35:
        risk_level = "MODERATE"
        forecast_text = "Some trend activity remains in history. Continue monitoring, but no immediate action is required."
    elif risk_points <= 60:
        risk_level = "ELEVATED"
        forecast_text = "Network risk is increasing. Review recent unstable devices, outages, and recurring alerts."
    else:
        risk_level = "HIGH"
        forecast_text = "High predictive risk detected. Investigate unstable devices and active alerts immediately."

    return {
        "risk_level": risk_level,
        "risk_points": risk_points,
        "forecast_text": forecast_text,
        "average_stability": average_stability,
        "internet_trend_events": internet_alerts,
        "internet_recent_events": internet_recent_alerts,
        "internet_weighted_events": round(internet_weighted_alerts, 2),
        "unstable_device_count": len(unstable_devices),
        "recent_unstable_device_count": len(recent_unstable_devices),
        "critical_recent_unstable_count": len(critical_recent_unstable),
        "server_recent_unstable_count": len(server_recent_unstable),
        "virtual_recent_unstable_count": len(virtual_recent_unstable),
        "workstation_recent_unstable_count": len(workstation_recent_unstable)
    }



def build_predictive_alerts(stability_rows, forecast):
    predictive_alerts = []

    attention_devices = sorted(
        [
            item for item in stability_rows
            if (
                item.get("recent_alerts", 0) > 0
                or item.get("score", 100) < 85
                or item.get("weighted_alerts", 0) >= 2.5
            )
        ],
        key=lambda item: (
            item.get("score", 100),
            -item.get("recent_alerts", 0),
            -item.get("weighted_alerts", 0)
        )
    )

    for item in attention_devices[:4]:
        if item.get("recent_alerts", 0) >= 2:
            issue = f"{item.get('recent_alerts')} recent disconnect events detected"
            recommendation = "Check for active flapping, power-saving settings, Wi-Fi/Ethernet stability, or device sleep behavior."
        elif item.get("recent_alerts", 0) == 1:
            issue = "1 recent disconnect event detected"
            recommendation = "Monitor this device. If it repeats, review connectivity and power settings."
        elif item.get("weighted_alerts", 0) >= 2.5:
            issue = f"Weighted event score is {item.get('weighted_alerts')}"
            recommendation = "Historical events remain relevant but are aging out. Continue monitoring."
        else:
            issue = f"Stability score is {item.get('score')}%"
            recommendation = "Review recent alerts, ping stability, and device health."

        predictive_alerts.append({
            "device": item.get("device", "Unknown"),
            "issue": issue,
            "recommendation": recommendation
        })

    if forecast.get("internet_recent_events", 0) >= 1:
        predictive_alerts.append({
            "device": get_internet_service_name(),
            "issue": f"{forecast.get('internet_recent_events')} recent internet outage event(s) detected",
            "recommendation": "Monitor modem gateway and ISP availability."
        })
    elif forecast.get("internet_weighted_events", 0) >= 1:
        predictive_alerts.append({
            "device": get_internet_service_name(),
            "issue": f"{forecast.get('internet_trend_events')} historical internet outage event(s) aging out",
            "recommendation": "No immediate action required unless outages repeat."
        })

    if not predictive_alerts:
        predictive_alerts.append({
            "device": "Network",
            "issue": "No predictive issues detected",
            "recommendation": "Continue normal monitoring."
        })

    return predictive_alerts[:5]



def build_historical_summary_addon(stability_rows, forecast):
    recent_attention_devices = [
        item for item in stability_rows
        if item.get("recent_alerts", 0) > 0
    ]

    historical_attention_devices = [
        item for item in stability_rows
        if item.get("weighted_alerts", 0) >= 2.5 and item.get("recent_alerts", 0) == 0
    ]

    messages = []

    if recent_attention_devices:
        worst = sorted(
            recent_attention_devices,
            key=lambda item: (
                item.get("score", 100),
                -item.get("recent_alerts", 0)
            )
        )[0]

        messages.append(
            f"{worst.get('device')} has {worst.get('recent_alerts')} recent alert event(s)."
        )
    elif historical_attention_devices:
        worst = sorted(
            historical_attention_devices,
            key=lambda item: (
                item.get("weighted_alerts", 0),
                -item.get("alerts", 0)
            ),
            reverse=True
        )[0]

        messages.append(
            f"{worst.get('device')} has older historical events that are aging out."
        )

    if forecast.get("internet_recent_events", 0) >= 1:
        messages.append(
            f"Internet history shows {forecast.get('internet_recent_events')} recent outage event(s)."
        )
    elif forecast.get("internet_weighted_events", 0) > 0:
        messages.append(
            "Older internet outage events are aging out normally."
        )

    if not messages:
        return "Historical weighting shows no recurring instability."

    return " ".join(messages)



def build_phase10c_html(phase10c):
    stability_rows = ""
    for item in phase10c.get("stability_scores", [])[:8]:
        score = int(item.get("score", 0))
        color_class = "green"
        if score < 70:
            color_class = "red"
        elif score < 85:
            color_class = "orange"
        elif score < 95:
            color_class = "blue"

        stability_rows += (
            f"<tr>"
            f"<td>{item.get('device', '')}</td>"
            f"<td class='{color_class}'><strong>{score}%</strong></td>"
            f"<td>{item.get('rating', '')}</td>"
            f"<td class='status {item.get('state', 'UNKNOWN')}'>{item.get('state', 'UNKNOWN')}</td>"
            f"<td>{item.get('alerts', 0)}</td>"
            f"<td>{item.get('latency', 'N/A')}</td>"
            f"</tr>"
        )

    if not stability_rows:
        stability_rows = "<tr><td colspan='6'>No stability data available yet.</td></tr>"

    reliable_rows = ""
    rankings = phase10c.get("reliability_rankings", {}).get("most_reliable", [])
    for idx, item in enumerate(rankings, start=1):
        score = int(item.get("score", 0))
        color_class = "green"
        if score < 70:
            color_class = "red"
        elif score < 85:
            color_class = "orange"
        elif score < 95:
            color_class = "blue"

        reliable_rows += (
            f"<tr>"
            f"<td>{idx}</td>"
            f"<td>{item.get('device', '')}</td>"
            f"<td class='{color_class}'><strong>{score}%</strong></td>"
            f"<td>{item.get('rating', '')}</td>"
            f"</tr>"
        )

    if not reliable_rows:
        reliable_rows = "<tr><td colspan='4'>No reliability rankings available yet.</td></tr>"

    predictive_rows = ""
    for item in phase10c.get("predictive_alerts", []):
        predictive_rows += (
            f"<tr>"
            f"<td>{item.get('device', '')}</td>"
            f"<td>{item.get('issue', '')}</td>"
            f"<td>{item.get('recommendation', '')}</td>"
            f"</tr>"
        )

    if not predictive_rows:
        predictive_rows = "<tr><td colspan='3'>No predictive alerts available.</td></tr>"

    return {
        "stability_rows": stability_rows,
        "reliable_rows": reliable_rows,
        "predictive_rows": predictive_rows
    }


def build_phase10c_predictive_intelligence(network_intelligence):
    stability_scores = calculate_device_stability_scores()
    reliability_rankings = build_reliability_rankings(stability_scores)

    forecast = build_network_forecast(
        int(network_intelligence.get("intelligence_score", 100)),
        int(network_intelligence.get("active_alert_count", 0)),
        stability_scores
    )

    predictive_alerts = build_predictive_alerts(stability_scores, forecast)
    historical_summary = build_historical_summary_addon(stability_scores, forecast)

    return {
        "forecast": forecast,
        "stability_scores": stability_scores,
        "reliability_rankings": reliability_rankings,
        "predictive_alerts": predictive_alerts,
        "historical_summary": historical_summary
    }



# ======================================================
# PHASE 13A - SERVICE IMPACT AWARENESS ENGINE
# ======================================================
def get_service_impact_config():
    """Return service-impact configuration. Services are config-driven."""
    cfg = config.get("service_impact_awareness", {})
    if not isinstance(cfg, dict):
        cfg = {}

    return {
        "enabled": cfg.get("enabled", True),
        "phase": cfg.get("phase", "13A.3"),
        "title": cfg.get("title", "Service Impact Awareness"),
        "healthy_states": cfg.get("healthy_states", ["UP", "SLEEPING", "MAINTENANCE", "PROVISIONING"]),
        # Maintenance / provisioning states must not create service-impact problems.
        # If a state is listed as healthy, it is removed from degraded_states below.
        "degraded_states": cfg.get("degraded_states", []),
        "services": cfg.get("services", []) if isinstance(cfg.get("services", []), list) else [],
        "dynamic_endpoint_types": cfg.get(
            "dynamic_endpoint_types",
            ["Laptop", "Desktop", "Windows PC", "Mac", "Chromebook"]
        )
    }


def get_service_device_state(device_name):
    """
    Get normalized/effective state for service-impact calculations.

    PHASE 13A.3 / 13B.1 - Service Membership Accuracy Fix
    ------------------------------------------------------
    A device can still appear healthy at the ping/lifecycle layer while its
    assigned Cisco switch port is down. Service Impact must use the effective
    member state, not only the endpoint state.

    Maintenance and provisioning remain service-impact safe. If a device is
    intentionally in MAINTENANCE or PROVISIONING, that state wins and does not
    degrade a service.
    """
    name = clean_ascii(device_name)

    if not name:
        return {"name": "", "state": "UNKNOWN", "ip": ""}

    info = status.get(name, {})
    base_state = clean_ascii(info.get("state", "UNKNOWN")).upper() or "UNKNOWN"

    if not info and name in DEVICES:
        base_state = "UNKNOWN"

    ip_addr = clean_ascii(info.get("ip", DEVICES.get(name, "")))

    maintenance_label = clean_ascii(
        config.get("maintenance_mode", {}).get("state_label", "MAINTENANCE")
    ).upper() or "MAINTENANCE"
    provisioning_label = clean_ascii(
        config.get("provisioning_grace", {}).get("state_label", "PROVISIONING")
    ).upper() or "PROVISIONING"

    switch_port = ""
    switch_index = ""
    switch_state = ""
    switch_raw_state = ""

    for index, mapped_device in SWITCH_PORTS.items():
        if clean_ascii(mapped_device).lower() != name.lower():
            continue

        switch_index = clean_ascii(index)
        link = switch_links.get(index, switch_links.get(str(index), {}))
        switch_port = clean_ascii(
            link.get("port", get_dynamic_switch_port_label(index))
        )
        switch_state = clean_ascii(link.get("state", "UNKNOWN")).upper() or "UNKNOWN"
        switch_raw_state = clean_ascii(link.get("raw_state", switch_state)).upper() or switch_state
        break

    effective_state = base_state
    effective_reason = "Device lifecycle state"

    # Maintenance/provisioning are intentional states and must not create
    # service degradation across the dashboard.
    if base_state in [maintenance_label, provisioning_label]:
        effective_state = base_state
        effective_reason = f"Device intentionally in {base_state}"

    # A mapped Cisco switch port that is physically down means the member is
    # unavailable for service-impact purposes, even if endpoint sleep detection
    # has labeled the endpoint as SLEEPING.
    elif switch_state == "DOWN" or switch_raw_state == "DOWN":
        effective_state = "LINK_DOWN"
        effective_reason = f"Assigned switch port {switch_port or switch_index} is DOWN"

    return {
        "name": name,
        "state": effective_state,
        "base_state": base_state,
        "ip": ip_addr,
        "switch_index": switch_index,
        "switch_port": switch_port,
        "switch_state": switch_state,
        "switch_raw_state": switch_raw_state,
        "effective_reason": effective_reason
    }


def build_service_impact_awareness():
    """
    Build Phase 13A service health from config-defined services.

    No service names, members, or dependencies are hard-coded here. The engine
    reads service_impact_awareness.services from config.json and calculates
    UP, DEGRADED, or DOWN based on required and optional device health.
    """
    cfg = get_service_impact_config()

    if not cfg.get("enabled", True):
        return {
            "enabled": False,
            "phase": cfg.get("phase", "13A"),
            "title": cfg.get("title", "Service Impact Awareness"),
            "summary": "Service Impact Awareness is disabled.",
            "overall_state": "DISABLED",
            "overall_class": "disabled",
            "services": [],
            "affected_services": [],
            "unaffected_services": [],
            "counts": {"total": 0, "up": 0, "degraded": 0, "down": 0},
            "last_updated": now()
        }

    healthy_states = {clean_ascii(item).upper() for item in cfg.get("healthy_states", [])}
    degraded_states = {clean_ascii(item).upper() for item in cfg.get("degraded_states", [])}

    # PHASE 13A.2 - Maintenance-safe service impact
    # Healthy always wins over degraded. This prevents states such as
    # MAINTENANCE or PROVISIONING from showing as available in the count
    # while still forcing the service to DEGRADED.
    degraded_states = degraded_states - healthy_states

    services = []

    for raw_service in cfg.get("services", []):
        if not isinstance(raw_service, dict):
            continue

        name = clean_ascii(raw_service.get("name", "Unnamed Service")) or "Unnamed Service"
        priority = clean_ascii(raw_service.get("priority", "standard")).lower() or "standard"
        description = clean_ascii(raw_service.get("description", ""))
        required_names = raw_service.get("required_devices", [])
        optional_names = raw_service.get("optional_devices", raw_service.get("member_devices", []))

        if not isinstance(required_names, list):
            required_names = []
        if not isinstance(optional_names, list):
            optional_names = []

        # PHASE 13A.1 - Dynamic Service Membership
        # Services can now build membership automatically from device_types.
        # Example: Work From Home can include every Laptop, Desktop, Windows PC,
        # Mac, and Chromebook without manually listing each device.
        dynamic_types = raw_service.get("dynamic_device_types", [])
        if not isinstance(dynamic_types, list):
            dynamic_types = []

        dynamic_names = []
        if dynamic_types:
            wanted_types = {clean_ascii(item).lower() for item in dynamic_types}
            for device_name, device_type in DEVICE_TYPES.items():
                if clean_ascii(device_type).lower() in wanted_types:
                    dynamic_names.append(device_name)

        # Keep manually configured optional devices for other services, but
        # de-duplicate after adding dynamic members.
        merged_optional_names = []
        seen_optional_names = set()
        for item in list(optional_names) + dynamic_names:
            item_name = clean_ascii(item)
            item_key = item_name.lower()
            if item_name and item_key not in seen_optional_names:
                merged_optional_names.append(item_name)
                seen_optional_names.add(item_key)

        required = [get_service_device_state(item) for item in required_names]
        optional = [get_service_device_state(item) for item in merged_optional_names]

        required_down = [item for item in required if item.get("state") not in healthy_states]
        required_degraded = [item for item in required if item.get("state") in degraded_states]
        optional_down = [item for item in optional if item.get("state") not in healthy_states]
        optional_up = [item for item in optional if item.get("state") in healthy_states]
        optional_degraded = [item for item in optional if item.get("state") in degraded_states]

        minimum_optional_up = raw_service.get("minimum_optional_up", 0)
        try:
            minimum_optional_up = int(minimum_optional_up)
        except Exception:
            minimum_optional_up = 0

        state = "UP"
        reason = "All required service dependencies are available."

        if required_down:
            state = "DOWN"
            reason = "Required dependency unavailable: " + ", ".join([item.get("name") for item in required_down[:3]])
        elif optional and minimum_optional_up > 0 and len(optional_up) < minimum_optional_up:
            state = "DOWN"
            reason = f"Not enough service endpoints available: {len(optional_up)}/{minimum_optional_up} minimum online."
        elif required_degraded or optional_degraded or optional_down:
            state = "DEGRADED"
            if optional_down:
                reason = "Optional service member impacted: " + ", ".join([item.get("name") for item in optional_down[:3]])
            else:
                reason = "Service is available, but one or more members are not in normal UP state."

        services.append({
            "name": name,
            "priority": priority,
            "description": description,
            "state": state,
            "state_class": state.lower(),
            "reason": reason,
            "required_devices": required,
            "optional_devices": optional,
            "required_down": required_down,
            "optional_down": optional_down,
            "required_count": len(required),
            "optional_count": len(optional),
            "available_optional_count": len(optional_up),
            "minimum_optional_up": minimum_optional_up,
            "dynamic_device_types": dynamic_types,
            "dynamic_member_count": len(dynamic_names)
        })

    affected = [svc for svc in services if svc.get("state") != "UP"]
    unaffected = [svc for svc in services if svc.get("state") == "UP"]
    down_count = sum(1 for svc in services if svc.get("state") == "DOWN")
    degraded_count = sum(1 for svc in services if svc.get("state") == "DEGRADED")
    up_count = sum(1 for svc in services if svc.get("state") == "UP")

    if down_count:
        overall_state = "SERVICE IMPACT DETECTED"
        overall_class = "down"
        summary = f"{down_count} service(s) down and {degraded_count} degraded."
    elif degraded_count:
        overall_state = "SERVICE DEGRADED"
        overall_class = "degraded"
        summary = f"{degraded_count} service(s) degraded. Core services may still be available."
    else:
        overall_state = "ALL SERVICES OPERATIONAL"
        overall_class = "up"
        summary = "All configured services are available."

    return {
        "enabled": True,
        "phase": cfg.get("phase", "13A"),
        "title": cfg.get("title", "Service Impact Awareness"),
        "summary": summary,
        "overall_state": overall_state,
        "overall_class": overall_class,
        "services": services,
        "affected_services": affected,
        "unaffected_services": unaffected,
        "counts": {
            "total": len(services),
            "up": up_count,
            "degraded": degraded_count,
            "down": down_count
        },
        "last_updated": now()
    }



# ======================================================
# PHASE 13B.3 - SERVICE IMPACT DRILL DOWN ENGINE
# ======================================================
def get_service_drilldown_config():
    """Return Phase 13B drilldown config with safe defaults."""
    return config.get("service_impact_drilldown", {
        "enabled": True,
        "phase": "13B",
        "title": "Service Impact Drill Down"
    })


def find_switch_link_for_device(device_name):
    """Find the managed switch port mapped to a device."""
    device_name = clean_ascii(device_name)
    if not device_name:
        return {}

    for index, mapped_device in SWITCH_PORTS.items():
        if clean_ascii(mapped_device).lower() != device_name.lower():
            continue

        link = switch_links.get(index, {})
        return {
            "index": clean_ascii(index),
            "port": clean_ascii(link.get("port", get_dynamic_switch_port_label(index))),
            "full_port": clean_ascii(link.get("full_port", "")),
            "device": device_name,
            "state": clean_ascii(link.get("state", "UNKNOWN")).upper() or "UNKNOWN",
            "raw_state": clean_ascii(link.get("raw_state", link.get("state", "UNKNOWN"))).upper() or "UNKNOWN"
        }

    return {}


def infer_service_member_root_cause(member):
    """Infer the best root cause for a single impacted service member."""
    member_name = clean_ascii(member.get("name", ""))
    member_state = clean_ascii(member.get("state", "UNKNOWN")).upper() or "UNKNOWN"
    device_type = clean_ascii(DEVICE_TYPES.get(member_name, "Unknown")) or "Unknown"
    switch_link = find_switch_link_for_device(member_name)
    link_state = clean_ascii(switch_link.get("state", "")).upper()
    link_raw_state = clean_ascii(switch_link.get("raw_state", "")).upper()

    infra = config.get("infrastructure", {})
    internet_name = get_infrastructure_name("internet")
    gateway_name = get_infrastructure_name("internet_gateway")
    router_name = get_infrastructure_name("edge_router")
    switch_name = get_infrastructure_name("main_switch")

    physical_root = find_physical_link_root_cause_for_device(member_name)
    if physical_root:
        return physical_root

    if member_name == internet_name:
        return {
            "type": "Internet / ISP Link",
            "device": member_name,
            "port": "WAN / ISP",
            "state": member_state,
            "confidence": 99,
            "recommended_action": "Verify ISP connectivity, modem WAN status, and upstream Internet availability."
        }

    if member_name == gateway_name:
        return {
            "type": "Modem / Gateway",
            "device": member_name,
            "port": "Gateway",
            "state": member_state,
            "confidence": 98,
            "recommended_action": "Verify modem power, coax/WAN signal, and the Ethernet handoff to the Cisco router."
        }

    if member_name == router_name:
        return {
            "type": "Edge Router",
            "device": member_name,
            "port": "Router uplink / LAN edge",
            "state": member_state,
            "confidence": 99,
            "recommended_action": "Verify router power, interfaces, routing, and WAN/LAN connectivity."
        }

    if member_name == switch_name:
        return {
            "type": "Core Switch",
            "device": member_name,
            "port": "Switch core / VLAN access",
            "state": member_state,
            "confidence": 99,
            "recommended_action": "Verify switch power, uplinks, VLAN 422, and switch management reachability."
        }

    if switch_link and link_state not in ["UP", "SLEEPING", "MAINTENANCE", "PROVISIONING"]:
        return {
            "type": "Switch Port",
            "device": switch_name,
            "port": switch_link.get("port", "Unknown Port"),
            "state": link_state,
            "confidence": 98,
            "recommended_action": f"Check {member_name} cable, NIC, and Cisco switch port {switch_link.get('port', 'Unknown Port')}."
        }

    if switch_link and link_raw_state not in ["UP", "", "UNKNOWN"] and member_state == "DOWN":
        return {
            "type": "Switch Port",
            "device": switch_name,
            "port": switch_link.get("port", "Unknown Port"),
            "state": link_raw_state,
            "confidence": 96,
            "recommended_action": f"Check the physical link for {member_name} on {switch_link.get('port', 'Unknown Port')}."
        }

    return {
        "type": "Endpoint Device",
        "device": member_name,
        "port": switch_link.get("port", "Not mapped") if switch_link else "Not mapped",
        "state": member_state,
        "confidence": 90,
        "recommended_action": f"Verify {member_name} power, network adapter, sleep state, IP address, and local connectivity."
    }


def choose_primary_root_cause(root_causes):
    """Choose the highest-confidence and most useful root cause."""
    if not root_causes:
        return {
            "type": "None",
            "device": "No active root cause",
            "port": "None",
            "state": "UP",
            "confidence": 100,
            "recommended_action": "No action required."
        }

    priority = {
        "Internet / ISP Link": 1,
        "Modem / Gateway": 2,
        "Edge Router": 3,
        "Core Switch": 4,
        "Switch Port": 5,
        "Endpoint Device": 6
    }

    return sorted(
        root_causes,
        key=lambda item: (priority.get(item.get("type", "Endpoint Device"), 99), -int(item.get("confidence", 0)))
    )[0]


def build_service_impact_drilldown(service_impact=None):
    """
    Phase 13B converts service impact into operator-ready details.

    It explains:
    - which services are impacted
    - which members are affected
    - what root cause is most likely
    - what to fix first
    """
    cfg = get_service_drilldown_config()

    if not cfg.get("enabled", True):
        return {
            "enabled": False,
            "phase": cfg.get("phase", "13B"),
            "title": cfg.get("title", "Service Impact Drill Down"),
            "summary": "Service Impact Drill Down is disabled.",
            "items": [],
            "counts": {"impacted_services": 0, "affected_members": 0},
            "last_updated": now()
        }

    if service_impact is None:
        service_impact = build_service_impact_awareness()

    healthy_states = {
        clean_ascii(item).upper()
        for item in get_service_impact_config().get("healthy_states", ["UP", "SLEEPING", "MAINTENANCE", "PROVISIONING"])
    }

    drilldown_items = []

    for svc in service_impact.get("services", []):
        service_state = clean_ascii(svc.get("state", "UNKNOWN")).upper() or "UNKNOWN"
        if service_state == "UP":
            continue

        required_devices = svc.get("required_devices", []) if isinstance(svc.get("required_devices"), list) else []
        optional_devices = svc.get("optional_devices", []) if isinstance(svc.get("optional_devices"), list) else []
        service_members = required_devices + optional_devices

        affected_required = [
            item for item in required_devices
            if clean_ascii(item.get("state", "UNKNOWN")).upper() not in healthy_states
        ]
        affected_optional = [
            item for item in optional_devices
            if clean_ascii(item.get("state", "UNKNOWN")).upper() not in healthy_states
        ]

        affected_members = affected_required + affected_optional
        unaffected_members = [
            item for item in service_members
            if clean_ascii(item.get("state", "UNKNOWN")).upper() in healthy_states
        ]

        root_causes = [infer_service_member_root_cause(item) for item in affected_members]
        primary_root_cause = choose_primary_root_cause(root_causes)

        affected_count = len(affected_members)

        # PHASE 13B.3 - Impact Scope Accuracy Fix
        # Optional devices are true service members/endpoints. Required devices
        # are core dependencies. When only optional members are affected, show
        # the scope against the optional member count only. This prevents Work
        # From Home from showing 1 of 9 when the real service membership is 1
        # of 5 endpoints. If required dependencies are affected, report those
        # separately because that is a dependency failure, not a member-count
        # failure.
        if affected_required and affected_optional:
            total_members = len(optional_devices)
            impact_scope = (
                f"{len(affected_required)} of {len(required_devices)} required dependencies affected; "
                f"{len(affected_optional)} of {len(optional_devices)} members affected"
            )
        elif affected_required:
            total_members = len(required_devices)
            dependency_word = "dependency" if len(required_devices) == 1 else "dependencies"
            impact_scope = f"{len(affected_required)} of {len(required_devices)} required {dependency_word} affected"
        elif optional_devices:
            total_members = len(optional_devices)
            impact_scope = f"{len(affected_optional)} of {len(optional_devices)} members affected"
        else:
            total_members = len(service_members)
            if total_members > 0:
                impact_scope = f"{affected_count} of {total_members} members affected"
            else:
                impact_scope = "No service members configured"

        affected_names = [clean_ascii(item.get("name", "Unknown")) for item in affected_members]
        unaffected_names = [clean_ascii(item.get("name", "Unknown")) for item in unaffected_members]

        drilldown_items.append({
            "service": clean_ascii(svc.get("name", "Unknown Service")),
            "status": service_state,
            "status_class": service_state.lower(),
            "priority": clean_ascii(svc.get("priority", "standard")).lower() or "standard",
            "reason": clean_ascii(svc.get("reason", "Service is impacted.")),
            "affected_members": affected_names,
            "unaffected_members": unaffected_names,
            "affected_count": affected_count,
            "total_members": total_members,
            "impact_scope": impact_scope,
            "root_cause": primary_root_cause,
            "all_root_causes": root_causes,
            "recommended_action": primary_root_cause.get("recommended_action", "Review affected service members."),
            "confidence": f"{primary_root_cause.get('confidence', 0)}%"
        })

    impacted_services = len(drilldown_items)
    affected_members_total = sum(item.get("affected_count", 0) for item in drilldown_items)

    if impacted_services:
        summary = f"{impacted_services} impacted service(s) with {affected_members_total} affected member(s)."
    else:
        summary = "No impacted services detected. All monitored services are operating normally."

    return {
        "enabled": True,
        "phase": cfg.get("phase", "13B"),
        "title": cfg.get("title", "Service Impact Drill Down"),
        "summary": summary,
        "items": drilldown_items,
        "counts": {
            "impacted_services": impacted_services,
            "affected_members": affected_members_total
        },
        "last_updated": now()
    }


# ======================================================
# PHASE 13C.1 / 13C.2 / 13C.3 - DEPENDENCY VISUALIZATION + DYNAMIC PHYSICAL TOPOLOGY ENGINE
# ======================================================
def get_dependency_visualization_config():
    """Return Phase 13C Dependency Visualization config with safe defaults.

    Phase 13C.5B deduplicates root-cause and impacted-node counts so
    one physical failure is counted once even when it affects multiple service paths.
    """
    cfg = config.get("dependency_visualization", {})
    if not isinstance(cfg, dict):
        cfg = {}

    return {
        "enabled": cfg.get("enabled", True),
        "phase": cfg.get("phase", "13C.1 / 13C.2 / 13C.3 / 13C.4 / 13C.5A / 13C.5B"),
        "title": cfg.get("title", "Dependency Visualization"),
        "show_when_healthy": cfg.get("show_when_healthy", True),
        "max_paths": int(cfg.get("max_paths", 4) or 4)
    }


def normalize_dependency_state(state):
    """Normalize a raw device/link state into a dashboard-friendly dependency state."""
    state = clean_ascii(state).upper() or "UNKNOWN"
    if state in ["ROOT_CAUSE", "ROOT CAUSE"]:
        return "ROOT_CAUSE"
    if state in ["IMPACTED", "IMPACTED_DEVICE", "IMPACTED DEVICE"]:
        return "IMPACTED"
    if state in ["UP", "OK", "ONLINE"]:
        return "UP"
    if state in ["DOWN", "ERROR", "OFFLINE", "LINK_DOWN"]:
        return "DOWN"
    if state in ["DEGRADED", "WARNING"]:
        return "DEGRADED"
    if state == get_maintenance_state_label():
        return "MAINTENANCE"
    if state == get_provisioning_state_label():
        return "PROVISIONING"
    if state == get_sleep_status_label():
        return "SLEEPING"
    return state or "UNKNOWN"


def dependency_state_class(state):
    state = normalize_dependency_state(state)
    if state == "UP":
        return "up"
    if state == "ROOT_CAUSE":
        return "root-cause"
    if state == "IMPACTED":
        return "impacted"
    if state in ["DOWN", "ERROR", "OFFLINE", "LINK_DOWN"]:
        return "down"
    if state in ["DEGRADED", "WARNING"]:
        return "degraded"
    if state == "MAINTENANCE":
        return "maintenance"
    if state == "PROVISIONING":
        return "provisioning"
    if state == "SLEEPING":
        return "sleeping"
    return "unknown"




def build_dependency_node(label, node_type, state, detail="", ip="", role=""):
    state = normalize_dependency_state(state)
    return {
        "label": clean_ascii(label),
        "type": clean_ascii(node_type),
        "state": state,
        "state_class": dependency_state_class(state),
        "detail": clean_ascii(detail),
        "ip": clean_ascii(ip),
        "role": clean_ascii(role),
        "icon": get_dependency_icon(node_type)
    }


def get_device_dependency_state(device_name):
    """Return current dashboard state for a dependency device."""
    device_name = clean_ascii(device_name)
    info = status.get(device_name, {})
    state_value = clean_ascii(info.get("state", "UNKNOWN")) or "UNKNOWN"
    ip_value = clean_ascii(info.get("ip", DEVICES.get(device_name, "")))
    return state_value, ip_value




def get_physical_topology_config():
    """Return editable physical topology links from config.json.

    Phase 13C.7 rule:
    - No fallback topology is created in code.
    - The topology map is built only from config["infrastructure_links"].
    - If the list is empty, the map is empty until the user adds links.
    """
    links = config.get("infrastructure_links", [])
    if not isinstance(links, list):
        links = []

    normalized = []
    for idx, item in enumerate(links):
        if not isinstance(item, dict):
            continue

        from_device = clean_ascii(item.get("from", item.get("from_device", item.get("source_device", ""))))
        to_device = clean_ascii(item.get("to", item.get("to_device", item.get("target_device", ""))))
        if not from_device or not to_device:
            continue

        source_interface = clean_ascii(item.get("source_interface", item.get("from_interface", "")))
        target_interface = clean_ascii(item.get("target_interface", item.get("to_interface", "")))

        source_port_index = clean_ascii(item.get("source_port_index", ""))
        target_port_index = clean_ascii(item.get("target_port_index", ""))
        switch_port = clean_ascii(item.get("switch_port", item.get("port_index", "")))
        port_label = clean_ascii(item.get("port_label", item.get("port", "")))

        # Backward compatibility for older Phase 13C infrastructure_links.
        # The older format stored only one switch_port/port_label for the switch end.
        if switch_port:
            if not port_label:
                port_label = get_dynamic_switch_port_label(switch_port)

            from_type = detect_map_device_type(from_device, DEVICES.get(from_device, ""))
            to_type = detect_map_device_type(to_device, DEVICES.get(to_device, ""))

            if from_type.lower() == "switch" and not source_interface:
                source_interface = port_label
                source_port_index = source_port_index or switch_port

            if to_type.lower() == "switch" and not target_interface:
                target_interface = port_label
                target_port_index = target_port_index or switch_port

        normalized.append({
            "id": clean_ascii(item.get("id", f"link-{idx}")) or f"link-{idx}",
            "from": from_device,
            "to": to_device,
            "source_interface": source_interface,
            "target_interface": target_interface,
            "source_port_index": source_port_index,
            "target_port_index": target_port_index,
            "switch_port": switch_port,
            "port_label": port_label,
            "link_type": clean_ascii(item.get("link_type", item.get("type", "Physical Link"))) or "Physical Link",
            "label": clean_ascii(item.get("label", ""))
        })

    return normalized

def get_physical_topology_root():
    infra = config.get("infrastructure", {}) if isinstance(config.get("infrastructure", {}), dict) else {}
    return get_infrastructure_name("internet")


def get_physical_topology_primary_switch():
    infra = config.get("infrastructure", {}) if isinstance(config.get("infrastructure", {}), dict) else {}
    return get_infrastructure_name("main_switch")




def is_core_topology_device(device_name):
    device_name = clean_ascii(device_name)

    if not device_name:
        return False

    device_type = clean_ascii(
        DEVICE_TYPES.get(
            device_name,
            detect_map_device_type(device_name, DEVICES.get(device_name, ""))
        )
    ).lower()

    if device_type in get_core_topology_type_names():
        return True

    infra = config.get("infrastructure", {}) if isinstance(config.get("infrastructure", {}), dict) else {}

    return device_name in {
        clean_ascii(value)
        for value in infra.values()
        if isinstance(value, str) and clean_ascii(value)
    }


def is_endpoint_topology_link(link):
    """Return True when a topology link connects the switch to a normal endpoint.

    This lets the Network Map keep its current style:
    - core chain at the top
    - endpoint cards at the bottom
    while still keeping endpoint links in config["infrastructure_links"].
    """
    if not isinstance(link, dict):
        return False

    from_device = clean_ascii(link.get("from", ""))
    to_device = clean_ascii(link.get("to", ""))

    if not from_device or not to_device:
        return False

    from_is_switch = is_topology_switch(from_device)
    to_is_switch = is_topology_switch(to_device)

    if not (from_is_switch or to_is_switch):
        return False

    other_device = to_device if from_is_switch else from_device

    if not other_device or is_core_topology_device(other_device):
        return False

    return True


def remove_endpoint_topology_links_for_device(device_name):
    """Remove auto/device endpoint links tied to a device.

    Used when a device is deleted, edited, or remapped.
    Core infrastructure links are preserved.
    """
    device_name = clean_ascii(device_name)
    if not device_name:
        return 0

    links = get_physical_topology_config()
    remaining = []
    removed = 0

    for link in links:
        link_from = clean_ascii(link.get("from", ""))
        link_to = clean_ascii(link.get("to", ""))

        if device_name in [link_from, link_to] and is_endpoint_topology_link(link):
            removed += 1
            continue

        remaining.append(link)

    config["infrastructure_links"] = remaining
    return removed


def remove_all_endpoint_topology_links():
    """Remove endpoint topology links while keeping core infrastructure links."""
    links = get_physical_topology_config()
    remaining = []
    removed = 0

    for link in links:
        if is_endpoint_topology_link(link):
            removed += 1
            continue
        remaining.append(link)

    config["infrastructure_links"] = remaining
    return removed


def ensure_endpoint_topology_link_for_switch_port(device_name, port_index):
    """Create/update the inventory-driven endpoint topology link.

    This is the key Phase 13E rule:
    Add Device / Assign Port -> inventory + switch_ports + topology link.
    Delete Device / Remove Port -> topology link is removed.
    """
    device_name = clean_ascii(device_name)
    port_index = clean_ascii(port_index)

    if not device_name or not port_index:
        return None

    if device_name not in config.get("devices", {}):
        return None

    if port_index not in get_selectable_switch_ports():
        return None

    if get_enterprise_category(device_name) != "physical":
        return None

    switch_name = get_physical_topology_primary_switch()
    if not switch_name or switch_name not in config.get("devices", {}):
        return None

    if device_name == switch_name:
        return None

    port_label = get_switch_port_label(port_index)
    safe_name = re.sub(r"[^a-zA-Z0-9]+", "-", device_name.lower()).strip("-") or "device"
    link_id = f"auto-endpoint-{port_index}-{safe_name}"

    remove_endpoint_topology_links_for_device(device_name)

    links = get_physical_topology_config()
    record = {
        "id": link_id,
        "from": switch_name,
        "to": device_name,
        "source_interface": port_label,
        "target_interface": "eth0",
        "source_port_index": port_index,
        "target_port_index": "",
        "switch_port": port_index,
        "port_label": port_label,
        "link_type": "Endpoint Link",
        "label": "Auto-created from Enterprise Inventory"
    }

    # Also clear any older auto link for this same switch port.
    links = [
        link for link in links
        if clean_ascii(link.get("id", "")) != link_id
        and not (
            clean_ascii(link.get("switch_port", "")) == port_index
            and is_endpoint_topology_link(link)
        )
    ]

    links.append(record)
    config["infrastructure_links"] = links
    return record


def rebuild_endpoint_topology_links_from_switch_ports():
    """Synchronize endpoint topology links with current switch_ports."""
    remove_all_endpoint_topology_links()

    created = 0
    for port_index, device_name in list(config.get("switch_ports", {}).items()):
        if ensure_endpoint_topology_link_for_switch_port(device_name, port_index):
            created += 1

    return created



def find_physical_path(start_device, target_device):
    """Find a physical path using config["infrastructure_links"]."""
    start_device = clean_ascii(start_device)
    target_device = clean_ascii(target_device)
    if not start_device or not target_device:
        return []
    if start_device == target_device:
        return []

    links = get_physical_topology_config()
    graph = {}
    for link in links:
        graph.setdefault(link.get("from"), []).append(link)

    queue = [(start_device, [])]
    visited = set()
    while queue:
        current, path = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for link in graph.get(current, []):
            new_path = path + [link]
            if link.get("to") == target_device:
                return new_path
            queue.append((link.get("to"), new_path))
    return []


def get_switch_port_dependency_state(port_index, force_down=False):
    port_index = clean_ascii(port_index)
    if force_down:
        return "DOWN"
    link_info = switch_links.get(port_index, {}) if isinstance(switch_links, dict) else {}
    return clean_ascii(link_info.get("state", "UNKNOWN")) or "UNKNOWN"


def is_root_cause_switch_port(root_cause, port_index="", port_label=""):
    if not isinstance(root_cause, dict):
        return False
    rc_type = clean_ascii(root_cause.get("type", "")).lower()
    rc_port = clean_ascii(root_cause.get("port", root_cause.get("path", ""))).lower()
    port_index = clean_ascii(port_index).lower()
    port_label = clean_ascii(port_label).lower()
    return rc_type == "switch port" and (rc_port in [port_index, port_label] or port_label in rc_port)




def find_physical_link_root_cause_for_device(device_name):
    """Phase 13C.4: identify the failed physical link before a device.

    If a device is down because the switch port feeding it is down, the port
    is the root cause and the device is the impacted object.
    """
    device_name = clean_ascii(device_name)
    if not device_name:
        return {}

    root_name = get_physical_topology_root()
    path_links = find_physical_path(root_name, device_name)
    for link in path_links:
        switch_port = clean_ascii(link.get("switch_port", ""))
        port_label = clean_ascii(link.get("port_label", ""))
        if not switch_port and not port_label:
            continue

        link_state = get_switch_port_dependency_state(switch_port)
        if clean_ascii(link_state).upper() not in ["UP", "", "UNKNOWN", "MAINTENANCE", "PROVISIONING"]:
            failed_to = clean_ascii(link.get("to", device_name))
            failed_from = clean_ascii(link.get("from", get_primary_switch_name()))
            label = port_label or get_dynamic_switch_port_label(switch_port, switch_port)
            return {
                "type": "Switch Port",
                "root_type": "Physical Switch Port",
                "device": failed_from,
                "port": label,
                "state": "DOWN",
                "confidence": 99,
                "failure_type": "Physical Link Failure",
                "affected_device": failed_to,
                "impacted_device": failed_to,
                "physical_path": f"{failed_from} -> {label} -> {failed_to}",
                "recommended_action": f"Check Cisco switch port {label}, the Ethernet cable, and the connected interface on {failed_to}."
            }

    return {}


def find_active_physical_link_root_cause(active_alerts=None):
    """Phase 13C.4: find the first down physical topology link impacting alerts."""
    active_alerts = active_alerts or []
    alert_text = " ".join([
        f"{clean_ascii(item.get('device', ''))} {clean_ascii(item.get('problem', ''))}"
        for item in active_alerts if isinstance(item, dict)
    ]).lower()

    for link in get_physical_topology_config():
        switch_port = clean_ascii(link.get("switch_port", ""))
        port_label = clean_ascii(link.get("port_label", ""))
        if not switch_port and not port_label:
            continue

        link_state = get_switch_port_dependency_state(switch_port)
        if clean_ascii(link_state).upper() in ["UP", "", "UNKNOWN", "MAINTENANCE", "PROVISIONING"]:
            continue

        to_device = clean_ascii(link.get("to", ""))
        from_device = clean_ascii(link.get("from", get_primary_switch_name()))
        to_state = clean_ascii(status.get(to_device, {}).get("state", "UNKNOWN")).upper()
        label = port_label or get_dynamic_switch_port_label(switch_port, switch_port)

        if to_state in ["DOWN", "ERROR", "UNKNOWN", "TESTING"] or to_device.lower() in alert_text or label.lower() in alert_text:
            return {
                "type": "Switch Port",
                "root_type": "Physical Switch Port",
                "device": from_device,
                "port": label,
                "state": "DOWN",
                "confidence": 99,
                "failure_type": "Physical Link Failure",
                "affected_device": to_device,
                "impacted_device": to_device,
                "physical_path": f"{from_device} -> {label} -> {to_device}",
                "recommended_action": f"Check Cisco switch port {label}, the Ethernet cable, and the connected interface on {to_device}."
            }

    return {}

def build_physical_topology_link_node(link, root_cause=None):
    """Build an optional switch-port node for a physical link."""
    switch_port = clean_ascii(link.get("switch_port", ""))
    port_label = clean_ascii(link.get("port_label", ""))
    if not switch_port and not port_label:
        return None

    force_down = is_root_cause_switch_port(root_cause or {}, switch_port, port_label)
    state_value = get_switch_port_dependency_state(switch_port, force_down=force_down)
    label = port_label or get_dynamic_switch_port_label(switch_port, switch_port)
    detail = clean_ascii(link.get("label", "")) or f"{clean_ascii(link.get('from'))} to {clean_ascii(link.get('to'))}"
    return build_dependency_node(label, "Switch Port", state_value, detail, "", clean_ascii(link.get("link_type", "Physical link")))


def build_device_dependency_node_by_name(device_name, role=""):
    device_name = clean_ascii(device_name)
    state_value, ip_value = get_device_dependency_state(device_name)
    device_type = clean_ascii(DEVICE_TYPES.get(device_name, detect_map_device_type(device_name, ip_value))) or "Device"
    return build_dependency_node(device_name, device_type, state_value, role or device_type, ip_value, role or device_type)


def build_dynamic_physical_dependency_nodes(target_device="", root_cause=None):
    """Build dependency nodes using the dynamic physical topology model.

    This is Phase 13C.3.  It follows the physical connection table instead of
    a fixed Internet -> Modem -> Router -> Switch assumption.
    """
    target_device = clean_ascii(target_device)
    root_cause = root_cause if isinstance(root_cause, dict) else {}
    root_name = get_physical_topology_root()
    primary_switch = get_physical_topology_primary_switch()

    # Infrastructure device target: follow the configured physical path to it.
    if target_device and target_device in DEVICES:
        path_links = find_physical_path(root_name, target_device)
    else:
        path_links = []

    # Endpoint target: path to the primary switch, then access port, then endpoint.
    endpoint_port_node = None
    if target_device and not path_links:
        path_links = find_physical_path(root_name, primary_switch)
        endpoint_port_node = find_switch_dependency_node(target_device)
        if endpoint_port_node and is_root_cause_switch_port(root_cause, port_label=endpoint_port_node.get("label", "")):
            endpoint_port_node["state"] = "DOWN"
            endpoint_port_node["state_class"] = "down"

    nodes = []
    seen_devices = set()

    def add_device_node(device_name, role=""):
        name = clean_ascii(device_name)
        if not name or name.lower() in seen_devices:
            return
        seen_devices.add(name.lower())
        nodes.append(build_device_dependency_node_by_name(name, role))

    add_device_node(root_name, "Topology root")

    for link in path_links:
        port_node = build_physical_topology_link_node(link, root_cause=root_cause)
        if port_node:
            nodes.append(port_node)
        add_device_node(link.get("to", ""), link.get("link_type", "Physical link"))

    if endpoint_port_node:
        nodes.append(endpoint_port_node)

    # For VM/child devices, include the host before the child if not already present.
    relationship = DEVICE_RELATIONSHIPS.get(target_device, {}) if isinstance(DEVICE_RELATIONSHIPS, dict) else {}
    parent_name = clean_ascii(relationship.get("parent", ""))
    if parent_name and parent_name.lower() not in seen_devices:
        parent_state, parent_ip = get_device_dependency_state(parent_name)
        parent_type = clean_ascii(DEVICE_TYPES.get(parent_name, "Parent Device")) or "Parent Device"
        nodes.append(build_dependency_node(parent_name, parent_type, parent_state, relationship.get("relationship", "Parent dependency"), parent_ip, "Parent dependency"))
        seen_devices.add(parent_name.lower())

    if target_device and target_device.lower() not in seen_devices:
        device_state, device_ip = get_device_dependency_state(target_device)
        effective = get_service_device_state(target_device)
        if clean_ascii(effective.get("state", "")).upper() == "LINK_DOWN":
            device_state = "DOWN"
        device_type = clean_ascii(DEVICE_TYPES.get(target_device, detect_map_device_type(target_device, device_ip))) or "Endpoint Device"
        nodes.append(build_dependency_node(target_device, device_type, device_state, "Affected endpoint", device_ip, "Service member"))

    # PHASE 13C.4 - Physical Root Cause Engine
    # Separate the object that failed from the device that is merely impacted.
    root_port = clean_ascii(root_cause.get("port", "")).lower()
    impacted_device = clean_ascii(root_cause.get("affected_device", root_cause.get("impacted_device", ""))).lower()
    root_seen = False
    for node in nodes:
        label = clean_ascii(node.get("label", "")).lower()
        node_type = clean_ascii(node.get("type", "")).lower()
        if root_port and root_port == label and "port" in node_type:
            node["state"] = "ROOT CAUSE"
            node["state_class"] = "root-cause"
            node["detail"] = clean_ascii(node.get("detail", "Physical link failure")) or "Physical link failure"
            node["role"] = "Physical root cause"
            root_seen = True
            continue
        if root_seen and impacted_device and label == impacted_device:
            node["state"] = "IMPACTED"
            node["state_class"] = "impacted"
            node["role"] = "Impacted device"
            if not clean_ascii(node.get("detail", "")):
                node["detail"] = "Impacted by upstream physical link failure"

    return nodes


def build_infrastructure_dependency_nodes():
    """Build the core dependency chain from the dynamic physical topology model."""
    links = get_physical_topology_config()
    root_name = get_physical_topology_root()
    nodes = []
    seen = set()

    def add_device(name, role=""):
        name = clean_ascii(name)
        if not name or name.lower() in seen:
            return
        seen.add(name.lower())
        nodes.append(build_device_dependency_node_by_name(name, role or "Infrastructure"))

    add_device(root_name, "Topology root")
    for link in links:
        if clean_ascii(link.get("from")) in [node.get("label") for node in nodes] or not nodes:
            port_node = build_physical_topology_link_node(link)
            if port_node:
                nodes.append(port_node)
            add_device(link.get("to", ""), link.get("link_type", "Physical link"))
    return nodes



def find_switch_dependency_node(device_name):
    """Return a dependency node for a device's switch port if it is mapped."""
    link = find_switch_link_for_device(device_name)
    if not link:
        return None

    port = clean_ascii(link.get("port", link.get("index", "Unknown Port"))) or "Unknown Port"
    link_state = clean_ascii(link.get("state", "UNKNOWN")).upper() or "UNKNOWN"
    return build_dependency_node(
        port,
        "Switch Port",
        link_state,
        f"Connected to {clean_ascii(device_name)}",
        "",
        "Physical access port"
    )


def build_dependency_path_for_device(device_name, service_name="", root_cause=None):
    """Build one visual dependency path using the dynamic physical topology engine."""
    device_name = clean_ascii(device_name)
    root_cause = root_cause if isinstance(root_cause, dict) else {}

    nodes = build_dynamic_physical_dependency_nodes(device_name, root_cause=root_cause)

    # PHASE 13C.5A - Dependency Visualization Accuracy Fix
    # ROOT_CAUSE and IMPACTED are not healthy. They must influence the
    # path state, counts, and summary even when the raw device ping state
    # is still UP or when the impacted object is classified separately.
    root_cause_nodes = [node for node in nodes if node.get("state_class") == "root-cause"]
    impacted_nodes = [node for node in nodes if node.get("state_class") == "impacted"]
    down_nodes = [node for node in nodes if node.get("state_class") == "down"]
    degraded_nodes = [node for node in nodes if node.get("state_class") == "degraded"]

    if root_cause_nodes:
        path_state = "ROOT CAUSE"
    elif down_nodes:
        path_state = "DOWN"
    elif impacted_nodes:
        path_state = "IMPACTED"
    elif degraded_nodes:
        path_state = "DEGRADED"
    else:
        path_state = "UP"

    root_label = "No active root cause"
    if root_cause:
        root_label = clean_ascii(root_cause.get("device", ""))
        if root_cause.get("port"):
            root_label = f"{root_label} • {clean_ascii(root_cause.get('port'))}"

    title = device_name if not service_name else f"{service_name} → {device_name}"

    return {
        "title": title,
        "service": clean_ascii(service_name),
        "target": device_name,
        "state": path_state,
        "state_class": dependency_state_class(path_state),
        "root_cause": root_label,
        "nodes": nodes,
        "node_count": len(nodes),
        "down_count": len(down_nodes),
        "degraded_count": len(degraded_nodes),
        "root_cause_count": len(root_cause_nodes),
        "impacted_count": len(impacted_nodes),
        "affected_count": len(root_cause_nodes) + len(impacted_nodes) + len(down_nodes) + len(degraded_nodes)
    }


def build_default_dependency_path():
    """Show the core infrastructure path when no active service impact exists."""
    nodes = build_infrastructure_dependency_nodes()
    root_cause_count = sum(1 for node in nodes if node.get("state_class") == "root-cause")
    impacted_count = sum(1 for node in nodes if node.get("state_class") == "impacted")
    down_count = sum(1 for node in nodes if node.get("state_class") == "down")
    degraded_count = sum(1 for node in nodes if node.get("state_class") == "degraded")
    if root_cause_count:
        path_state = "ROOT CAUSE"
    elif down_count:
        path_state = "DOWN"
    elif impacted_count:
        path_state = "IMPACTED"
    elif degraded_count:
        path_state = "DEGRADED"
    else:
        path_state = "UP"
    return {
        "title": "Core Network Path",
        "service": "Infrastructure",
        "target": "Core Network",
        "state": path_state,
        "state_class": dependency_state_class(path_state),
        "root_cause": "No active service-impact root cause" if path_state == "UP" else "Core infrastructure issue detected",
        "nodes": nodes,
        "node_count": len(nodes),
        "down_count": down_count,
        "degraded_count": degraded_count,
        "root_cause_count": root_cause_count,
        "impacted_count": impacted_count,
        "affected_count": root_cause_count + impacted_count + down_count + degraded_count
    }


def build_dependency_visualization(service_impact_drilldown=None):
    """
    Phase 13C.1 / 13C.2 converts root-cause intelligence into visual paths.

    C.1 = Dependency Path Viewer
    C.2 = Dependency Health Coloring
    """
    cfg = get_dependency_visualization_config()

    if not cfg.get("enabled", True):
        return {
            "enabled": False,
            "phase": cfg.get("phase", "13C"),
            "title": cfg.get("title", "Dependency Visualization"),
            "summary": "Dependency Visualization is disabled.",
            "paths": [],
            "counts": {"paths": 0, "nodes": 0, "down_nodes": 0, "degraded_nodes": 0},
            "last_updated": now()
        }

    if service_impact_drilldown is None:
        service_impact_drilldown = build_service_impact_drilldown()

    paths = []
    max_paths = max(1, int(cfg.get("max_paths", 4) or 4))

    for item in service_impact_drilldown.get("items", []):
        members = item.get("affected_members", []) if isinstance(item.get("affected_members", []), list) else []
        root = item.get("root_cause", {}) if isinstance(item.get("root_cause", {}), dict) else {}
        for member_name in members:
            if len(paths) >= max_paths:
                break
            paths.append(build_dependency_path_for_device(member_name, item.get("service", ""), root))
        if len(paths) >= max_paths:
            break

    if not paths and cfg.get("show_when_healthy", True):
        paths.append(build_default_dependency_path())

    # PHASE 13C.5B - Root Cause Deduplication Engine
    # Count unique physical failures and impacted devices, not the number of
    # service views that display the same failure.  Example: discovered uplink interface affects
    # Internet Access, Remote Administration, and Work From Home, but it is
    # still one root cause and one impacted router.
    down_nodes = sum(path.get("down_count", 0) for path in paths)
    degraded_nodes = sum(path.get("degraded_count", 0) for path in paths)
    total_nodes = sum(path.get("node_count", 0) for path in paths)

    unique_root_causes = {}
    unique_impacted_nodes = {}
    unique_down_nodes = {}
    unique_degraded_nodes = {}

    for path in paths:
        for node in path.get("nodes", []):
            node_state_class = clean_ascii(node.get("state_class", "")).lower()
            node_label = clean_ascii(node.get("label", ""))
            node_type = clean_ascii(node.get("type", ""))
            node_role = clean_ascii(node.get("role", ""))
            node_key = f"{node_state_class}|{node_type}|{node_label}".lower()

            if node_state_class == "root-cause":
                unique_root_causes[node_key] = node
            elif node_state_class == "impacted":
                unique_impacted_nodes[node_key] = node
            elif node_state_class == "down":
                unique_down_nodes[node_key] = node
            elif node_state_class == "degraded":
                unique_degraded_nodes[node_key] = node

    root_cause_nodes = len(unique_root_causes)
    impacted_nodes = len(unique_impacted_nodes)
    unique_down_count = len(unique_down_nodes)
    unique_degraded_count = len(unique_degraded_nodes)
    affected_nodes = root_cause_nodes + impacted_nodes + unique_down_count + unique_degraded_count
    affected_paths = sum(1 for path in paths if path.get("affected_count", 0) > 0 or path.get("state_class") in ["down", "degraded", "root-cause", "impacted"])
    healthy_paths = max(0, len(paths) - affected_paths)

    if not paths:
        summary = "No dependency paths to display."
        overall_state = "UNKNOWN"
    elif root_cause_nodes:
        root_word = "root cause" if root_cause_nodes == 1 else "root causes"
        impacted_word = "impacted node" if impacted_nodes == 1 else "impacted nodes"
        path_word = "service path" if affected_paths == 1 else "service paths"
        summary = (
            f"Dependency issue detected. {root_cause_nodes} unique {root_word} and "
            f"{impacted_nodes} unique {impacted_word} affecting {affected_paths} {path_word}."
        )
        overall_state = "ROOT CAUSE"
    elif unique_down_count:
        node_word = "down node" if unique_down_count == 1 else "down nodes"
        path_word = "affected path" if affected_paths == 1 else "affected paths"
        summary = f"Dependency issue detected. {unique_down_count} unique {node_word} found across {affected_paths} {path_word}."
        overall_state = "DOWN"
    elif impacted_nodes:
        node_word = "impacted node" if impacted_nodes == 1 else "impacted nodes"
        path_word = "affected path" if affected_paths == 1 else "affected paths"
        summary = f"Dependency impact detected. {impacted_nodes} unique {node_word} found across {affected_paths} {path_word}."
        overall_state = "IMPACTED"
    elif unique_degraded_count:
        node_word = "degraded node" if unique_degraded_count == 1 else "degraded nodes"
        path_word = "affected path" if affected_paths == 1 else "affected paths"
        summary = f"Dependency path degraded. {unique_degraded_count} unique {node_word} need attention across {affected_paths} {path_word}."
        overall_state = "DEGRADED"
    else:
        summary = "All displayed dependency paths are healthy."
        overall_state = "UP"

    return {
        "enabled": True,
        "phase": cfg.get("phase", "13C.1 / 13C.2 / 13C.3 / 13C.4 / 13C.5A / 13C.5B"),
        "title": cfg.get("title", "Dependency Visualization"),
        "summary": summary,
        "overall_state": overall_state,
        "overall_class": dependency_state_class(overall_state),
        "paths": paths,
        "counts": {
            "paths": len(paths),
            "nodes": total_nodes,
            "affected_paths": affected_paths,
            "healthy_paths": healthy_paths,
            "affected_nodes": affected_nodes,
            "root_cause_nodes": root_cause_nodes,
            "impacted_nodes": impacted_nodes,
            "down_nodes": unique_down_count,
            "degraded_nodes": unique_degraded_count,
            "raw_down_nodes": down_nodes,
            "raw_degraded_nodes": degraded_nodes,
            "unique_root_causes": list(unique_root_causes.keys()),
            "unique_impacted_nodes": list(unique_impacted_nodes.keys())
        },
        "last_updated": now()
    }



# ======================================================
# PHASE 14A-D - INTERFACE-AWARE DEPENDENCY + SERVICE IMPACT ENGINE
# ======================================================
def phase14_clean_state(value):
    state = clean_ascii(value).upper()
    return state if state else "UNKNOWN"


def phase14_is_intentional_state(state):
    state = phase14_clean_state(state)
    return state in [
        get_maintenance_state_label().upper(),
        get_provisioning_state_label().upper(),
        get_sleep_status_label().upper(),
        "SLEEPING",
        "MAINTENANCE",
        "PROVISIONING"
    ]


def phase14_is_healthy_state(state):
    state = phase14_clean_state(state)
    return state == "UP" or phase14_is_intentional_state(state)


def phase14_port_sort_key(index_value):
    value = clean_ascii(index_value)
    try:
        return int(value)
    except Exception:
        numbers = re.findall(r"\d+", value)
        if numbers:
            return int(numbers[-1])
    return 999999


def phase14_get_core_names():
    infra = config.get("infrastructure", {}) if isinstance(config, dict) else {}
    return {
        "internet": get_infrastructure_name("internet"),
        "modem": get_infrastructure_name("internet_gateway"),
        "router": get_infrastructure_name("edge_router"),
        "switch": get_infrastructure_name("main_switch")
    }


def phase14_get_device_state(device_name):
    device_name = clean_ascii(device_name)
    info = status.get(device_name, {}) if isinstance(status, dict) else {}
    return {
        "name": device_name,
        "ip": clean_ascii(info.get("ip", DEVICES.get(device_name, ""))),
        "state": phase14_clean_state(info.get("state", "UNKNOWN")),
        "raw_state": phase14_clean_state(info.get("raw_state", info.get("state", "UNKNOWN"))),
        "latency": clean_ascii(info.get("latency", "")),
        "last_checked": clean_ascii(info.get("last_checked", "")),
        "last_change": clean_ascii(info.get("last_change", ""))
    }


def phase14_get_virtual_children(parent_device):
    parent_device = clean_ascii(parent_device).lower()
    children = []

    for child_name, relationship in DEVICE_RELATIONSHIPS.items():
        if not isinstance(relationship, dict):
            continue
        parent = clean_ascii(relationship.get("parent", "")).lower()
        child_type = clean_ascii(DEVICE_TYPES.get(child_name, ""))
        if parent == parent_device and "virtual" in child_type.lower():
            children.append(clean_ascii(child_name))

    return children


def phase14_get_switch_endpoint_names(include_infrastructure=False):
    core = phase14_get_core_names()
    core_names = {v.lower() for v in core.values() if v}
    endpoint_names = []

    for index, device_name in sorted(SWITCH_PORTS.items(), key=lambda item: phase14_port_sort_key(item[0])):
        clean_name = clean_ascii(device_name)
        if not clean_name:
            continue
        if not include_infrastructure and clean_name.lower() in core_names:
            continue
        if clean_name not in endpoint_names:
            endpoint_names.append(clean_name)

    return endpoint_names


def phase14_downstream_devices_from(root_name):
    core = phase14_get_core_names()
    root_name = clean_ascii(root_name)
    endpoint_names = phase14_get_switch_endpoint_names(include_infrastructure=False)

    downstream = []

    if root_name == core.get("internet"):
        downstream = [core.get("modem"), core.get("router"), core.get("switch")] + endpoint_names
    elif root_name == core.get("modem"):
        downstream = [core.get("router"), core.get("switch")] + endpoint_names
    elif root_name == core.get("router"):
        downstream = [core.get("switch")] + endpoint_names
    elif root_name == core.get("switch"):
        downstream = endpoint_names[:]
    elif root_name in endpoint_names:
        downstream = [root_name]
    else:
        downstream = []

    expanded = []
    for name in downstream:
        name = clean_ascii(name)
        if name and name not in expanded:
            expanded.append(name)
        for child in phase14_get_virtual_children(name):
            if child and child not in expanded:
                expanded.append(child)

    return expanded


def phase14_find_switch_link_for_device(device_name):
    device_name = clean_ascii(device_name)
    for index, mapped_device in SWITCH_PORTS.items():
        if clean_ascii(mapped_device).lower() != device_name.lower():
            continue

        link = switch_links.get(index, switch_links.get(str(index), {})) if isinstance(switch_links, dict) else {}
        return {
            "index": clean_ascii(index),
            "port": clean_ascii(link.get("port", get_dynamic_switch_port_label(index))),
            "full_port": clean_ascii(link.get("full_port", link.get("port", ""))),
            "device": device_name,
            "state": phase14_clean_state(link.get("state", "UNKNOWN")),
            "raw_state": phase14_clean_state(link.get("raw_state", link.get("state", "UNKNOWN"))),
            "last_checked": clean_ascii(link.get("last_checked", "")),
            "maintenance_mode": bool(link.get("maintenance_mode")),
            "provisioning_grace": bool(link.get("provisioning_grace"))
        }
    return {}


def phase14_build_switch_port_correlations():
    rows = []
    core = phase14_get_core_names()
    core_names = {v.lower() for v in core.values() if v}

    for index, mapped_device in sorted(SWITCH_PORTS.items(), key=lambda item: phase14_port_sort_key(item[0])):
        device_name = clean_ascii(mapped_device)
        if not device_name or device_name.lower() in core_names:
            continue

        link = phase14_find_switch_link_for_device(device_name)
        device_state = phase14_get_device_state(device_name)
        link_state = phase14_clean_state(link.get("state", "UNKNOWN"))
        raw_link_state = phase14_clean_state(link.get("raw_state", link_state))
        endpoint_state = phase14_clean_state(device_state.get("state", "UNKNOWN"))
        virtual_children = phase14_get_virtual_children(device_name)

        if link_state == "DOWN" or raw_link_state == "DOWN":
            correlation = "Switch port down -> endpoint impacted"
            root_cause = f"{link.get('port', index)} physical link"
            action = f"Inspect cable, NIC, and Cisco switch port {link.get('port', index)} for {device_name}."
            severity = "CRITICAL" if device_name in config.get("intelligent_alert_classification", {}).get("critical_device_names", []) else "WARNING"
            impact_state = "DOWN"
        elif phase14_is_intentional_state(link_state) or phase14_is_intentional_state(endpoint_state):
            correlation = "Intentional lifecycle state"
            root_cause = "Maintenance / provisioning / sleep policy"
            action = "No outage action required unless this lifecycle state is unexpected."
            severity = "INFO"
            impact_state = link_state if phase14_is_intentional_state(link_state) else endpoint_state
        elif not phase14_is_healthy_state(endpoint_state):
            correlation = "Endpoint issue; switch port is not the confirmed root cause"
            root_cause = device_name
            action = f"Check {device_name} power, OS, network adapter, IP address, and local firewall."
            severity = "WARNING"
            impact_state = endpoint_state
        else:
            correlation = "Healthy"
            root_cause = "None"
            action = "No action required."
            severity = "OK"
            impact_state = "UP"

        affected = [device_name] + virtual_children if impact_state not in ["UP", "INFO"] and not phase14_is_intentional_state(impact_state) else []

        rows.append({
            "index": clean_ascii(index),
            "port": clean_ascii(link.get("port", get_dynamic_switch_port_label(index))),
            "full_port": clean_ascii(link.get("full_port", "")),
            "device": device_name,
            "device_ip": clean_ascii(device_state.get("ip", "")),
            "device_type": clean_ascii(DEVICE_TYPES.get(device_name, "Endpoint")),
            "device_state": endpoint_state,
            "link_state": link_state,
            "raw_link_state": raw_link_state,
            "correlation": correlation,
            "root_cause": root_cause,
            "recommended_action": action,
            "severity": severity,
            "impact_state": impact_state,
            "affected_devices": affected,
            "affected_count": len(affected),
            "virtual_children": virtual_children,
            "last_checked": clean_ascii(link.get("last_checked", device_state.get("last_checked", "")))
        })

    return rows


def phase14_build_router_interface_impacts():
    core = phase14_get_core_names()
    impacted_rows = []

    for index, iface in sorted(router_interfaces.items(), key=lambda item: phase14_port_sort_key(item[0])):
        state = phase14_clean_state(iface.get("state", "UNKNOWN"))
        short_name = clean_ascii(iface.get("short_name", iface.get("name", index)))
        full_name = clean_ascii(iface.get("name", short_name))

        if phase14_is_healthy_state(state):
            role = "Monitored router interface healthy"
            affected = []
            impact = "None"
            action = "No action required."
            severity = "OK"
        else:
            # A monitored router interface can be WAN or LAN depending on cabling.
            # In this environment it is the critical modem/router/switch edge path,
            # so downstream devices are treated as potentially affected.
            role = "Router edge interface"
            affected = phase14_downstream_devices_from(core.get("router", get_primary_router_name()))
            impact = "Core routing path may be unavailable or degraded"
            action = f"Inspect Cisco router interface {short_name}, modem/router handoff, router/switch uplink, VLAN/routing, and cabling."
            severity = "CRITICAL"

        impacted_rows.append({
            "index": clean_ascii(index),
            "interface": short_name,
            "full_name": full_name,
            "state": state,
            "role": role,
            "impact": impact,
            "severity": severity,
            "affected_devices": affected,
            "affected_count": len(affected),
            "recommended_action": action,
            "last_checked": clean_ascii(iface.get("last_checked", ""))
        })

    return impacted_rows


def phase14_build_infrastructure_impacts():
    core = phase14_get_core_names()
    impacts = []

    labels = [
        ("Internet / ISP", core.get("internet")),
        ("Modem / Gateway", core.get("modem")),
        ("Router", core.get("router")),
        ("Switch", core.get("switch"))
    ]

    for role, device_name in labels:
        if not device_name:
            continue
        device_state = phase14_get_device_state(device_name)
        state = phase14_clean_state(device_state.get("state", "UNKNOWN"))
        if phase14_is_healthy_state(state):
            continue

        affected = phase14_downstream_devices_from(device_name)
        action = "Review upstream connectivity and power."
        if role == "Internet / ISP":
            action = "Verify ISP outage status, modem WAN signal, and external target reachability."
        elif "Modem" in role:
            action = "Check modem power, coax/WAN signal, and Ethernet handoff to the Cisco router."
        elif "Router" in role:
            action = "Check Cisco router power, WAN/LAN interfaces, routing table, and uplink cabling."
        elif "Switch" in role:
            action = "Check Cisco switch power, management reachability, uplink, VLAN 422, and affected access ports."

        impacts.append({
            "role": role,
            "device": device_name,
            "state": state,
            "severity": "CRITICAL",
            "affected_devices": affected,
            "affected_count": len(affected),
            "recommended_action": action,
            "last_checked": clean_ascii(device_state.get("last_checked", ""))
        })

    return impacts


def phase14_choose_primary_incident(infrastructure_impacts, router_impacts, switch_correlations):
    router_problem_rows = [row for row in router_impacts if row.get("severity") == "CRITICAL"]
    switch_problem_rows = [row for row in switch_correlations if row.get("impact_state") == "DOWN" or row.get("raw_link_state") == "DOWN"]

    if infrastructure_impacts:
        item = sorted(infrastructure_impacts, key=lambda row: -int(row.get("affected_count", 0)))[0]
        return {
            "type": item.get("role", "Infrastructure"),
            "root_cause": item.get("device", "Infrastructure"),
            "state": item.get("state", "UNKNOWN"),
            "affected_count": item.get("affected_count", 0),
            "affected_devices": item.get("affected_devices", []),
            "recommended_action": item.get("recommended_action", "Review infrastructure."),
            "severity": item.get("severity", "CRITICAL")
        }

    if router_problem_rows:
        item = sorted(router_problem_rows, key=lambda row: -int(row.get("affected_count", 0)))[0]
        return {
            "type": "Router Interface",
            "root_cause": item.get("interface", "Router Interface"),
            "state": item.get("state", "UNKNOWN"),
            "affected_count": item.get("affected_count", 0),
            "affected_devices": item.get("affected_devices", []),
            "recommended_action": item.get("recommended_action", "Check router interface."),
            "severity": item.get("severity", "CRITICAL")
        }

    if switch_problem_rows:
        item = sorted(switch_problem_rows, key=lambda row: -int(row.get("affected_count", 0)))[0]
        return {
            "type": "Switch Port",
            "root_cause": f"{item.get('device')} {item.get('port')}",
            "state": item.get("impact_state", item.get("link_state", "DOWN")),
            "affected_count": item.get("affected_count", 0),
            "affected_devices": item.get("affected_devices", []),
            "recommended_action": item.get("recommended_action", "Check switch port."),
            "severity": item.get("severity", "WARNING")
        }

    return {
        "type": "None",
        "root_cause": "No active interface-aware root cause",
        "state": "UP",
        "affected_count": 0,
        "affected_devices": [],
        "recommended_action": "No action required.",
        "severity": "OK"
    }


def build_phase14_dependency_engine(service_impact=None):
    """
    Phase 14 brings interface awareness into the NOC layer.

    It correlates:
    - router interface state
    - switch port state
    - mapped endpoint state
    - virtual-machine host relationships
    - service impact drilldown
    """
    cfg = config.get("phase14_dependency_engine", {}) if isinstance(config, dict) else {}
    enabled = cfg.get("enabled", True)

    if service_impact is None:
        try:
            service_impact = build_service_impact_awareness()
        except Exception:
            service_impact = {}

    infrastructure_impacts = phase14_build_infrastructure_impacts()
    router_impacts = phase14_build_router_interface_impacts()
    switch_correlations = phase14_build_switch_port_correlations()
    primary = phase14_choose_primary_incident(infrastructure_impacts, router_impacts, switch_correlations)

    impacted_ports = [row for row in switch_correlations if row.get("impact_state") == "DOWN" or row.get("raw_link_state") == "DOWN"]
    degraded_ports = [row for row in switch_correlations if row.get("severity") in ["WARNING", "CRITICAL"] and row not in impacted_ports]
    router_down = [row for row in router_impacts if row.get("severity") == "CRITICAL"]

    affected_device_names = set(primary.get("affected_devices", []))
    for row in impacted_ports:
        for item in row.get("affected_devices", []):
            affected_device_names.add(item)
    for row in infrastructure_impacts:
        for item in row.get("affected_devices", []):
            affected_device_names.add(item)
    for row in router_down:
        for item in row.get("affected_devices", []):
            affected_device_names.add(item)

    service_counts = service_impact.get("counts", {}) if isinstance(service_impact, dict) else {}
    impacted_services = int(service_counts.get("down", 0) or 0) + int(service_counts.get("degraded", 0) or 0)

    if not enabled:
        overall_state = "DISABLED"
        overall_class = "disabled"
        summary = "Phase 14 dependency engine is disabled in config.json."
    elif primary.get("severity") == "CRITICAL":
        overall_state = "CRITICAL"
        overall_class = "critical"
        summary = f"{primary.get('type')} issue detected: {primary.get('root_cause')}. {primary.get('affected_count')} downstream device(s) may be affected."
    elif impacted_ports or degraded_ports:
        overall_state = "WARNING"
        overall_class = "warning"
        summary = f"{len(impacted_ports) + len(degraded_ports)} interface/port correlation issue(s) detected."
    else:
        overall_state = "HEALTHY"
        overall_class = "ok"
        summary = "No interface-aware dependency issues detected. Router interfaces, switch ports, and mapped endpoints are aligned."

    return {
        "enabled": enabled,
        "phase": cfg.get("phase", "14A-D"),
        "title": cfg.get("title", "Interface-Aware Dependency Engine"),
        "overall_state": overall_state,
        "overall_class": overall_class,
        "summary": summary,
        "primary_incident": primary,
        "root_cause": primary.get("root_cause", "No active root cause"),
        "root_type": primary.get("type", "None"),
        "recommended_action": primary.get("recommended_action", "No action required."),
        "affected_devices": sorted(affected_device_names),
        "affected_device_count": len(affected_device_names),
        "affected_service_count": impacted_services,
        "infrastructure_impacts": infrastructure_impacts,
        "router_interfaces": router_impacts,
        "router_interface_count": len(router_impacts),
        "router_interface_issues": len(router_down),
        "switch_port_correlations": switch_correlations,
        "switch_port_count": len(switch_correlations),
        "switch_port_issues": len(impacted_ports),
        "endpoint_correlation_count": len(switch_correlations),
        "last_updated": now()
    }



# ======================================================
# This Is end of first half of APP.PY file
# ======================================================

def build_phase14_device_dependency_lookup(phase14_dependency=None):
    if phase14_dependency is None:
        phase14_dependency = build_phase14_dependency_engine()

    lookup = {}

    for row in phase14_dependency.get("switch_port_correlations", []):
        device = clean_ascii(row.get("device", ""))
        if not device:
            continue
        lookup[device] = row

        for child_name in row.get("virtual_children", []):
            child_state = phase14_get_device_state(child_name)
            child_row = dict(row)
            child_row.update({
                "device": child_name,
                "device_ip": child_state.get("ip", ""),
                "device_type": DEVICE_TYPES.get(child_name, "Virtual Machine"),
                "correlation": f"Virtual machine hosted by {device}",
                "root_cause": f"Host path: {device} / {row.get('port', '')}",
                "recommended_action": f"Check host {device}, VM network adapter, and inherited switch path {row.get('port', '')}."
            })
            lookup[child_name] = child_row

    return lookup


def build_dashboard_api_data():
    refresh_runtime_data()

    active_alerts = get_active_alerts()

    total = len(status)
    up = sum(1 for d in status.values() if d.get("state") == "UP")
    sleeping = sum(1 for d in status.values() if d.get("state") == get_sleep_status_label())
    maintenance = sum(1 for d in status.values() if d.get("state") == get_maintenance_state_label())
    provisioning = sum(1 for d in status.values() if d.get("state") == get_provisioning_state_label())
    down = sum(1 for d in status.values() if d.get("state") == "DOWN")
    error = sum(1 for d in status.values() if d.get("state") == "ERROR")
    health = round(((up + sleeping + maintenance + provisioning) / total) * 100) if total > 0 else 0

    switch_up = sum(1 for d in switch_links.values() if d.get("state") == "UP")
    switch_down = sum(1 for d in switch_links.values() if d.get("state") == "DOWN")
    router_up = sum(1 for d in router_interfaces.values() if d.get("state") == "UP")
    router_down = sum(1 for d in router_interfaces.values() if d.get("state") == "DOWN")

    critical_count = sum(1 for a in active_alerts if a.get("severity") == "CRITICAL")
    uptime_stats = get_uptime_dashboard_stats()
    availability_report = get_internet_availability_report()
    network_intelligence = build_network_intelligence()
    network_intelligence_html = build_network_intelligence_html(network_intelligence)
    phase10c = build_phase10c_predictive_intelligence(network_intelligence)
    phase10c_html = build_phase10c_html(phase10c)
    lan_internet_health = build_lan_internet_health_split()
    device_classification = build_device_classification_engine()
    device_classification_html = build_device_classification_html(device_classification)
    sleep_detection = build_sleep_detection_engine()
    sleep_detection_html = build_sleep_detection_html(sleep_detection)
    noc_correlation = build_noc_correlation_engine()
    noc_correlation_html = build_noc_correlation_html(noc_correlation)
    unified_incident = build_unified_incident_engine(active_alerts)
    service_impact = build_service_impact_awareness()
    service_impact_drilldown = build_service_impact_drilldown(service_impact)
    dependency_visualization = build_dependency_visualization(service_impact_drilldown)
    phase14_dependency_engine = build_phase14_dependency_engine(service_impact)
    phase14_device_dependency_lookup = build_phase14_device_dependency_lookup(phase14_dependency_engine)
    alert_transition = get_alert_transition_api_state()

    latest_transition = alert_transition.get("latest_event")
    if latest_transition:
        unified_incident["transition_event_id"] = latest_transition.get("event_id", "")
        unified_incident["transition_event_type"] = latest_transition.get("event_type", "")
        unified_incident["transition_voice_message"] = latest_transition.get("voice_message", "")
        unified_incident["new_alert"] = latest_transition.get("event_type") == "ALERT"
        unified_incident["alert_resolved"] = latest_transition.get("event_type") == "RESOLVED"
        unified_incident["transition_time"] = latest_transition.get("time", "")
    else:
        unified_incident["transition_event_id"] = ""
        unified_incident["transition_event_type"] = ""
        unified_incident["transition_voice_message"] = ""
        unified_incident["new_alert"] = False
        unified_incident["alert_resolved"] = False
        unified_incident["transition_time"] = ""

    system_good = down == 0 and error == 0 and switch_down == 0 and router_down == 0

    device_rows = ""
    for name, info in status.items():
        state = info.get("state", "UNKNOWN")
        device_rows += f"<tr><td>{name}</td><td>{info.get('ip','')}</td><td class='status {state}'>{state}</td><td>{info.get('latency','')}</td><td>{info.get('last_checked','')}</td></tr>"

    router_rows = ""
    for idx, iface in router_interfaces.items():
        state = iface.get("state", "UNKNOWN")
        router_rows += f"<tr><td>{iface.get('short_name', idx)}</td><td class='status {state}'>{state}</td></tr>"

    switch_rows = ""
    for idx, link in switch_links.items():
        state = link.get("state", "UNKNOWN")
        switch_rows += f"<tr><td>{link.get('port', idx)}</td><td>{link.get('device','Unknown')}</td><td class='status {state}'>{state}</td></tr>"

    cisco_event_rows = ""
    cisco_events = read_cisco_events()
    if cisco_events:
        for event in cisco_events:
            cisco_event_rows += f"<tr><td>{event.get('time','')}</td><td>{event.get('device','')}</td><td>{event.get('event','')}</td><td>{event.get('interface','')}</td><td>{event.get('user','')}</td></tr>"
    else:
        cisco_event_rows = "<tr><td colspan='5'>No Cisco events found yet.</td></tr>"

    recent_events = read_recent_events()
    recent_event_items = "<ul>" + "".join([f"<li>{event}</li>" for event in recent_events]) + "</ul>" if recent_events else "<p>No events recorded yet.</p>"

    recent_internet_rows = ""
    for item in get_recent_internet_history():
        badge = "<span class='severity-badge critical'>Active</span>" if item.get("status") == "ACTIVE" else "<span class='severity-badge normal'>Resolved</span>"
        recent_internet_rows += f"<tr><td>{item.get('start_time','')}</td><td>{item.get('end_time','')}</td><td>{item.get('duration','')}</td><td>{badge}</td><td>{item.get('targets','')}</td></tr>"
    if not recent_internet_rows:
        recent_internet_rows = "<tr><td colspan='5'>No Internet outages recorded yet.</td></tr>"

    alert_rows = ""
    for alert in active_alerts[:6]:
        severity = alert.get("severity", "INFO")
        if severity == "CRITICAL":
            badge = "<span class='severity-badge critical'>🔴 Critical</span>"
        elif severity == "WARNING":
            badge = "<span class='severity-badge warning'>🟡 Warning</span>"
        else:
            badge = "<span class='severity-badge info'>🔵 Info</span>"
        alert_rows += f"<tr class='dashboard-alert-row {severity.lower()}'><td>{badge}</td><td>{alert.get('device','')}</td><td>{alert.get('problem','')}</td><td>{alert.get('time','')}</td></tr>"
    if not alert_rows:
        alert_rows = "<tr><td colspan='4'>No active alerts.</td></tr>"

    return {
        "last_full_scan": last_full_scan,
        "system_good": system_good,
        "health": health,
        "up": up,
        "sleeping": sleeping,
        "down": down,
        "error": error,
        "switch_up": switch_up,
        "switch_down": switch_down,
        "router_up": router_up,
        "router_down": router_down,
        "total_alerts": total_alerts,
        "critical_count": critical_count,
        "diagnosis": diagnose_network(),
        "uptime_stats": uptime_stats,
        "availability_report": availability_report,
        "network_intelligence": network_intelligence,
        "network_intelligence_html": network_intelligence_html,
        "phase10c": phase10c,
        "phase10c_html": phase10c_html,
        "lan_internet_health": lan_internet_health,
        "device_classification": device_classification,
        "device_classification_html": device_classification_html,
        "sleep_detection": sleep_detection,
        "sleep_detection_html": sleep_detection_html,
        "lifecycle_summary": build_lifecycle_summary(),
        "scheduled_maintenance": build_scheduled_maintenance_summary(),
        "noc_command_center": build_noc_command_center(),
        "executive_operations_center": build_executive_operations_center(),
        "guided_diagnostic_engine": build_guided_diagnostic_engine(),
        "root_cause_correlation": build_root_cause_correlation_engine(),
        "operations_layer": build_operations_layer_summary(),
        "noc_recommendations": build_noc_recommendations(),
        "noc_historical": build_noc_historical_intelligence(),
        "noc_correlation": noc_correlation,
        "noc_correlation_html": noc_correlation_html,
        "unified_incident": unified_incident,
        "service_impact": service_impact,
        "service_impact_drilldown": service_impact_drilldown,
        "dependency_visualization": dependency_visualization,
        "alert_transition": alert_transition,
        "new_alert": alert_transition.get("new_alert", False),
        "alert_resolved": alert_transition.get("alert_resolved", False),
        "latest_alert_event_id": alert_transition.get("latest_event_id", ""),
        "latest_voice_message": alert_transition.get("latest_voice_message", ""),
        "device_rows": device_rows,
        "router_rows": router_rows,
        "switch_rows": switch_rows,
        "cisco_event_rows": cisco_event_rows,
        "recent_event_items": recent_event_items,
        "recent_internet_rows": recent_internet_rows,
        "alert_rows": alert_rows
    }



@app.route("/api/provisioning-hosts")
def api_provisioning_hosts():
    load_config()
    return jsonify({
        "hosts": get_provisioning_host_candidates()
    })


@app.route("/api/provisioning-validation")
def api_provisioning_validation():
    load_config()

    device_name = clean_ascii(request.args.get("device_name", ""))
    ip_address = clean_ascii(request.args.get("ip_address", ""))

    issues = []

    if device_name and device_name in config.get("devices", {}):
        issues.append(f"Device name already exists: {device_name}")

    duplicate_ip_owner = get_existing_ip_owner(ip_address)
    if ip_address and duplicate_ip_owner:
        issues.append(f"IP address {ip_address} already belongs to {duplicate_ip_owner}")

    if ip_address and is_reserved_provisioning_ip(ip_address):
        issues.append(f"IP address {ip_address} is reserved for infrastructure or network use")

    return jsonify({
        "valid": len(issues) == 0,
        "issues": issues
    })


# ======================================================
# PHASE 16A.2A - INFRASTRUCTURE REGISTRY PAGE
# ======================================================

# ======================================================
# PHASE 16A.2D + 16A.3A - INTERFACE CLASSIFICATION AND PORT OWNERSHIP DISPLAY
# ======================================================
def is_advanced_infrastructure_interface(interface_name, role=""):
    """Return True for Cisco/internal interfaces that should be hidden in the default view."""
    name = clean_ascii(interface_name).lower()

    advanced_keywords = [
        "embedded-service-engine",
        "backplane",
        "stacksub",
        "stackport",
        "loopback",
        "null",
        "vlan",
        "tunnel",
        "nvi",
        "port-channel",
        "portchannel"
    ]

    return any(keyword in name for keyword in advanced_keywords)


def classify_infrastructure_interface(interface_record, role=""):
    """Classify an SNMP interface for the Infrastructure Registry UI."""
    role = normalize_infrastructure_role(role)
    name = clean_ascii(interface_record.get("name", ""))
    short_name = clean_ascii(interface_record.get("short_name", ""))
    text = f"{name} {short_name}".lower()

    if is_advanced_infrastructure_interface(name, role):
        return "ADVANCED_INTERFACE"

    physical_keywords = [
        "gigabitethernet",
        "fastethernet",
        "tengigabitethernet",
        "ethernet",
        "gi",
        "fa",
        "te",
        "eth"
    ]

    if any(keyword in text for keyword in physical_keywords):
        if role == "Router":
            return "ROUTER_USER_INTERFACE"
        if role == "Switch":
            return "SWITCH_USER_INTERFACE"
        return "USER_INTERFACE"

    return "ADVANCED_INTERFACE"


def normalize_port_ownership_entry(entry):
    """Normalize old and new port ownership records into one structure."""
    if isinstance(entry, dict):
        return {
            "device": clean_ascii(entry.get("device", "")),
            "role": clean_ascii(entry.get("role", entry.get("port_role", "Endpoint"))) or "Endpoint",
            "description": clean_ascii(entry.get("description", "")),
            "source": clean_ascii(entry.get("source", "port_ownership")) or "port_ownership"
        }

    return {
        "device": clean_ascii(entry),
        "role": "Endpoint",
        "description": "",
        "source": "legacy_switch_ports"
    }


def infer_port_ownership_role(device_name):
    """Infer a friendly ownership role from device type/name."""
    device_name = clean_ascii(device_name)
    device_type = clean_ascii(config.get("device_types", {}).get(device_name, ""))
    text = f"{device_name} {device_type}".lower()

    if "router" in text:
        return "Router Uplink"
    if "switch" in text:
        return "Switch Uplink"
    if "server" in text or "nas" in text:
        return "Server"
    if "virtual" in text or "vm" in text:
        return "Virtual Machine"
    if "mac" in text or "windows" in text or "pc" in text or "laptop" in text or "chromebook" in text:
        return "Workstation"
    if "access point" in text or "ap" == text.strip():
        return "Access Point"
    if "printer" in text:
        return "Printer"

    return "Endpoint"


def ensure_port_ownership_registry():
    """
    Phase 16A.3 ownership registry.

    Creates config['port_ownership'] and safely migrates existing switch_ports
    mappings into the new per-infrastructure-device structure.
    """
    config.setdefault("port_ownership", {})

    main_switch_name = clean_ascii(config.get("infrastructure", {}).get("main_switch", "switch"))
    if main_switch_name:
        config["port_ownership"].setdefault(main_switch_name, {})

        for port_index, device_name in config.get("switch_ports", {}).items():
            port_index = clean_ascii(port_index)
            device_name = clean_ascii(device_name)
            if not port_index or not device_name:
                continue

            existing = config["port_ownership"][main_switch_name].get(port_index, {})
            normalized = normalize_port_ownership_entry(existing) if existing else {}

            config["port_ownership"][main_switch_name][port_index] = {
                "device": normalized.get("device", device_name) or device_name,
                "role": normalized.get("role", infer_port_ownership_role(device_name)) or infer_port_ownership_role(device_name),
                "description": normalized.get("description", ""),
                "source": normalized.get("source", "switch_ports_migration") or "switch_ports_migration"
            }

    return config.get("port_ownership", {})


def build_port_ownership_lookup(device_name):
    """Build a lookup that can match an interface by index, full name, or short name."""
    ownership = ensure_port_ownership_registry()
    device_ownership = ownership.get(clean_ascii(device_name), {})
    lookup = {}

    for key, entry in device_ownership.items():
        normalized = normalize_port_ownership_entry(entry)
        key = clean_ascii(key)
        if key:
            lookup[key] = normalized

    return lookup


def classify_port_owner_category(device_name, owner_role=""):
    """Return a friendly display category for the device attached to an infrastructure port."""
    device_name = clean_ascii(device_name)
    owner_role = clean_ascii(owner_role)
    device_type = clean_ascii(config.get("device_types", {}).get(device_name, ""))
    text = f"{device_name} {owner_role} {device_type}".lower()

    if any(keyword in text for keyword in ["router", "switch", "firewall", "modem", "gateway", "access point", "ap", "ups"]):
        return "Infrastructure"
    if any(keyword in text for keyword in ["server", "nas", "file server"]):
        return "Server"
    if any(keyword in text for keyword in ["virtual", "vm"]):
        return "Virtual Machine"
    if any(keyword in text for keyword in ["mac", "windows", "pc", "laptop", "chromebook", "workstation"]):
        return "Workstation"
    if "printer" in text:
        return "Printer"

    return "Endpoint" if device_name else "Unassigned"


def normalize_owner_category_class(category):
    """CSS-safe class name for ownership category badges."""
    category = clean_ascii(category).lower()
    category = re.sub(r"[^a-z0-9]+", "-", category).strip("-")
    return category or "unassigned"


def get_interface_ownership(device_name, interface_record):
    """Return ownership details for one interface record.

    Phase 16A.3A adds owner type and owner category so the Infrastructure
    Registry can display who is connected to each port, what kind of device
    it is, and whether the port is infrastructure, server, VM, workstation,
    or unassigned.
    """
    lookup = build_port_ownership_lookup(device_name)
    keys = [
        clean_ascii(interface_record.get("index", "")),
        clean_ascii(interface_record.get("name", "")),
        clean_ascii(interface_record.get("short_name", ""))
    ]

    ownership = {}
    matched_key = ""
    for key in keys:
        if key and key in lookup:
            ownership = lookup[key]
            matched_key = key
            break

    owner_device = clean_ascii(ownership.get("device", ""))
    owner_role = clean_ascii(ownership.get("role", "")) or "Unassigned"
    owner_type = clean_ascii(config.get("device_types", {}).get(owner_device, "")) if owner_device else ""
    owner_ip = clean_ascii(config.get("devices", {}).get(owner_device, "")) if owner_device else ""
    owner_status = clean_ascii(status.get(owner_device, {}).get("state", "UNKNOWN")) if owner_device else "UNASSIGNED"
    owner_category = classify_port_owner_category(owner_device, owner_role)

    return {
        "device": owner_device,
        "role": owner_role,
        "device_type": owner_type or "Unknown",
        "category": owner_category,
        "category_class": normalize_owner_category_class(owner_category),
        "ip": owner_ip,
        "status": owner_status,
        "matched_key": matched_key,
        "source": clean_ascii(ownership.get("source", "")),
        "description": clean_ascii(ownership.get("description", "")),
        "assigned": bool(owner_device)
    }



# ======================================================
# PHASE 16A.3C - INFRASTRUCTURE RELATIONSHIP ENGINE
# ======================================================


def infer_relationship_criticality(device_name):
    """Infer relationship criticality from existing alert classification and device type."""
    device_name = clean_ascii(device_name)
    device_type = clean_ascii(config.get("device_types", {}).get(device_name, ""))
    critical_names = config.get("intelligent_alert_classification", {}).get("critical_device_names", [])
    critical_types = config.get("intelligent_alert_classification", {}).get("critical_device_types", [])

    if device_name in critical_names or device_type in critical_types:
        return "Critical"

    category = classify_port_owner_category(device_name, infer_port_ownership_role(device_name))
    if category in ["Infrastructure", "Server", "Virtual Machine"]:
        return "High"

    return "Normal"


def ensure_infrastructure_relationship_registry():
    """
    Phase 16A.3C Infrastructure Relationship Engine.

    Builds a clean parent/child dependency registry from:
    - existing device_relationships
    - infrastructure role settings
    - port ownership mappings

    This gives Phase 16A.4 Root Cause Analysis a reliable dependency tree.
    """
    config.setdefault("infrastructure_relationships", {})
    relationships = {}

    # Start with existing manually configured relationships.
    for child, entry in config.get("device_relationships", {}).items():
        child = clean_ascii(child)
        normalized = normalize_relationship_entry(entry)
        if child and normalized.get("parent"):
            relationships[child] = normalized

    # Build infrastructure dependencies from reconciled physical topology only.
    registry = get_infrastructure_devices()
    infrastructure_names = set(registry.keys())
    physical = reconcile_phase26_infrastructure_topology(
        get_physical_topology_config(), infrastructure_names, registry
    )
    for link in physical.get("relationships", []):
        child = clean_ascii(link.get("to", ""))
        parent = clean_ascii(link.get("from", ""))
        if child and parent:
            relationships[child] = {
                "parent": parent,
                "relationship": clean_ascii(link.get("link_type", "Physical Link")) or "Physical Link",
                "source": "reconciled_physical_topology",
                "criticality": infer_relationship_criticality(child)
            }

    # Use port ownership to connect endpoints and servers to the switch they are plugged into.
    ownership = ensure_port_ownership_registry()
    for infrastructure_device, ports in ownership.items():
        infrastructure_device = clean_ascii(infrastructure_device)
        if not infrastructure_device or not isinstance(ports, dict):
            continue

        for port_key, port_entry in ports.items():
            normalized = normalize_port_ownership_entry(port_entry)
            child_device = clean_ascii(normalized.get("device", ""))
            port_role = clean_ascii(normalized.get("role", "Endpoint")) or "Endpoint"

            if not child_device or child_device == infrastructure_device:
                continue

            # Do not overwrite a known upstream infrastructure relationship.
            # Example: the router may appear as an owned switch port, but its
            # dependency parent should remain the modem, not the switch.
            if child_device in relationships:
                continue

            relationships[child_device] = {
                "parent": infrastructure_device,
                "relationship": port_role,
                "source": f"port_ownership:{clean_ascii(port_key)}",
                "criticality": infer_relationship_criticality(child_device)
            }

    # Preserve any existing 16A.3C relationship that was manually added but not rebuilt above.
    for child, entry in config.get("infrastructure_relationships", {}).items():
        child = clean_ascii(child)
        normalized = normalize_relationship_entry(entry)
        if child and normalized.get("parent") and child not in relationships:
            relationships[child] = normalized

    config["infrastructure_relationships"] = relationships
    return relationships


def get_relationship_children_map(relationships=None):
    """Return parent -> children mapping for the infrastructure dependency tree."""
    relationships = relationships if isinstance(relationships, dict) else ensure_infrastructure_relationship_registry()
    children = {}

    for child, entry in relationships.items():
        normalized = normalize_relationship_entry(entry)
        parent = clean_ascii(normalized.get("parent", ""))
        child = clean_ascii(child)
        if not parent or not child:
            continue
        children.setdefault(parent, []).append(child)

    for parent in list(children.keys()):
        children[parent] = sorted(children[parent], key=lambda item: item.lower())

    return children


def build_device_dependency_path(device_name, relationships=None):
    """Return dependency path from root to a device, avoiding loops."""
    relationships = relationships if isinstance(relationships, dict) else ensure_infrastructure_relationship_registry()
    device_name = clean_ascii(device_name)

    if not device_name:
        return []

    path = [device_name]
    visited = {device_name}
    current = device_name

    for _ in range(25):
        entry = relationships.get(current, {})
        parent = clean_ascii(normalize_relationship_entry(entry).get("parent", "")) if entry else ""
        if not parent or parent in visited:
            break
        path.append(parent)
        visited.add(parent)
        current = parent

    return list(reversed(path))


def build_dependency_path_text(path):
    """Create a readable dependency path string for UI data attributes."""
    if not path:
        return "No dependency path"
    return " -> ".join([clean_ascii(item) for item in path if clean_ascii(item)])


def build_relationship_tree_nodes(relationships=None):
    """Build nested tree nodes for the Infrastructure Registry relationship panel."""
    relationships = relationships if isinstance(relationships, dict) else ensure_infrastructure_relationship_registry()
    children_map = get_relationship_children_map(relationships)

    known_devices = set(config.get("devices", {}).keys())
    known_devices.update(config.get("infrastructure_devices", {}).keys())
    known_devices.update(relationships.keys())
    for entry in relationships.values():
        parent = clean_ascii(normalize_relationship_entry(entry).get("parent", ""))
        if parent:
            known_devices.add(parent)

    children = set(relationships.keys())
    roots = sorted([device for device in known_devices if device and device not in children], key=lambda item: item.lower())

    # Prefer true infrastructure roots first.
    internet_root = clean_ascii(config.get("infrastructure", {}).get("internet", ""))
    if internet_root in roots:
        roots.remove(internet_root)
        roots.insert(0, internet_root)

    def make_node(name, depth=0, visited=None):
        visited = set(visited or [])
        clean_name = clean_ascii(name)
        if clean_name in visited:
            return {
                "name": clean_name,
                "ip": clean_ascii(config.get("devices", {}).get(clean_name, "")),
                "type": clean_ascii(config.get("device_types", {}).get(clean_name, "Unknown")),
                "depth": depth,
                "relationship": "Loop Detected",
                "children": []
            }

        visited.add(clean_name)
        entry = normalize_relationship_entry(relationships.get(clean_name, {})) if clean_name in relationships else {}
        return {
            "name": clean_name,
            "ip": clean_ascii(config.get("devices", {}).get(clean_name, "")),
            "type": clean_ascii(config.get("device_types", {}).get(clean_name, "Unknown")),
            "depth": depth,
            "relationship": clean_ascii(entry.get("relationship", "Root")) if entry else "Root",
            "criticality": clean_ascii(entry.get("criticality", infer_relationship_criticality(clean_name))) if entry else infer_relationship_criticality(clean_name),
            "children": [make_node(child, depth + 1, visited) for child in children_map.get(clean_name, [])]
        }

    return [make_node(root) for root in roots if root]


def flatten_relationship_tree(nodes):
    """Flatten nested relationship tree nodes for simple Jinja rendering."""
    flat = []

    def walk(node):
        flat.append(node)
        for child in node.get("children", []):
            walk(child)

    for node in nodes:
        walk(node)

    return flat


def count_downstream_dependents(device_name, children_map=None):
    """Count all downstream devices that depend on a selected device."""
    device_name = clean_ascii(device_name)
    children_map = children_map if isinstance(children_map, dict) else get_relationship_children_map()
    visited = set()

    def walk(parent):
        total = 0
        for child in children_map.get(parent, []):
            if child in visited:
                continue
            visited.add(child)
            total += 1
            total += walk(child)
        return total

    return walk(device_name)


def build_infrastructure_relationship_summary(relationships=None):
    """Build a compact summary for Phase 16A.3C relationship health and readiness."""
    relationships = relationships if isinstance(relationships, dict) else ensure_infrastructure_relationship_registry()
    children_map = get_relationship_children_map(relationships)
    tree = build_relationship_tree_nodes(relationships)
    flat_tree = flatten_relationship_tree(tree)

    infrastructure_links = 0
    endpoint_links = 0
    max_depth = 0

    for child, entry in relationships.items():
        parent = clean_ascii(normalize_relationship_entry(entry).get("parent", ""))
        child_category = classify_port_owner_category(child, infer_port_ownership_role(child))
        parent_category = classify_port_owner_category(parent, infer_port_ownership_role(parent))

        if child_category == "Infrastructure" or parent_category == "Infrastructure":
            infrastructure_links += 1
        else:
            endpoint_links += 1

        path = build_device_dependency_path(child, relationships)
        if len(path) > max_depth:
            max_depth = len(path)

    return {
        "phase": "16A.3C",
        "relationships": relationships,
        "children_map": children_map,
        "tree": tree,
        "flat_tree": flat_tree,
        "total_relationships": len(relationships),
        "infrastructure_links": infrastructure_links,
        "endpoint_links": endpoint_links,
        "root_devices": len(tree),
        "dependency_chains": len([item for item in relationships.keys() if build_device_dependency_path(item, relationships)]),
        "max_depth": max_depth,
        "last_updated": now()
    }

def build_infrastructure_registry_page_data():
    """
    Phase 16A.3C - Infrastructure Relationship Engine

    Builds the visible Infrastructure Registry page payload.

    16A.2D keeps Cisco/internal interfaces hidden by default.
    16A.3A displays port ownership on interface rows.
    16A.3B adds compact port tables, owned/unassigned port panels, and
    detail drawer data so the page is easier to use in small business / NOC views.
    16A.3C adds parent/child infrastructure relationships, upstream paths,
    and relationship summaries for Root Cause Analysis readiness.
    """
    load_config()
    ensure_port_ownership_registry()
    relationships = ensure_infrastructure_relationship_registry()
    relationship_summary = build_infrastructure_relationship_summary(relationships)
    relationship_children_map = relationship_summary.get("children_map", {})

    registry = get_infrastructure_devices()
    discovery_inventory = load_infrastructure_interface_inventory()

    role_order = [
        "Internet",
        "Modem",
        "Router",
        "Switch",
        "Firewall",
        "Access Point",
        "VPN Gateway",
        "DNS Server",
        "DHCP Server",
        "UPS",
        "Infrastructure"
    ]

    role_counts = {role: 0 for role in role_order}
    snmp_enabled_count = 0
    snmp_disabled_count = 0
    discovered_device_count = 0
    discovered_interface_count = 0
    user_interface_count = 0
    advanced_interface_count = 0
    mapped_interface_count = 0
    owned_user_interface_count = 0
    unassigned_user_interface_count = 0
    up_interface_count = 0
    down_interface_count = 0
    unknown_interface_count = 0
    latest_discovery = ""
    devices = []

    for device_name, info in registry.items():
        role = normalize_infrastructure_role(info.get("role", "Infrastructure"))
        if role not in role_counts:
            role_counts[role] = 0
        role_counts[role] += 1

        snmp_enabled = bool(info.get("snmp_enabled", False))
        if snmp_enabled:
            snmp_enabled_count += 1
        else:
            snmp_disabled_count += 1

        discovery_record = discovery_inventory.get(device_name, {})
        raw_interfaces = discovery_record.get("interfaces", {})
        interface_records = []
        user_interface_records = []
        advanced_interface_records = []
        owned_port_records = []
        unassigned_port_records = []

        if isinstance(raw_interfaces, dict):
            for index, interface_info in sorted(raw_interfaces.items(), key=interface_sort_key):
                if not isinstance(interface_info, dict):
                    continue

                interface_record = normalize_interface_record(
                    index,
                    interface_info,
                    source=interface_info.get("source", "snmp")
                )

                interface_class = classify_infrastructure_interface(interface_record, role)
                is_advanced = interface_class == "ADVANCED_INTERFACE"
                ownership = get_interface_ownership(device_name, interface_record)

                port_label = clean_ascii(interface_record.get("short_name", "")) or clean_ascii(interface_record.get("name", ""))
                interface_state = clean_ascii(interface_record.get("state", "UNKNOWN")).upper()
                owner_device = ownership.get("device", "")
                owner_ip = ownership.get("ip", "")
                owner_status = ownership.get("status", "UNASSIGNED")
                owner_type = ownership.get("device_type", "Unknown")
                owner_role = ownership.get("role", "Unassigned")
                owner_category = ownership.get("category", "Unassigned")
                has_owner = bool(ownership.get("assigned"))

                interface_record["interface_class"] = interface_class
                interface_record["is_advanced"] = is_advanced
                interface_record["view_group"] = "Advanced" if is_advanced else "User"
                interface_record["port_label"] = port_label
                interface_record["ownership"] = ownership
                interface_record["owner_device"] = owner_device or "Unassigned"
                interface_record["owner_role"] = owner_role
                interface_record["owner_type"] = owner_type
                interface_record["owner_category"] = owner_category
                interface_record["owner_category_class"] = ownership.get("category_class", "unassigned")
                interface_record["owner_ip"] = owner_ip
                interface_record["owner_status"] = owner_status
                interface_record["owner_mapping_key"] = ownership.get("matched_key", "")
                interface_record["owner_source"] = ownership.get("source", "")
                interface_record["owner_description"] = ownership.get("description", "")
                interface_record["has_owner"] = has_owner
                interface_record["detail_title"] = f"{device_name} | {port_label}"
                interface_record["detail_owner_line"] = owner_device if has_owner else "Unassigned Port"
                interface_record["detail_status_line"] = f"{interface_state} | {owner_status if has_owner else 'NO OWNER'}"

                owner_dependency_path = build_device_dependency_path(owner_device, relationships) if has_owner else []
                infrastructure_dependency_path = build_device_dependency_path(device_name, relationships)
                interface_record["owner_dependency_path"] = owner_dependency_path
                interface_record["owner_dependency_path_text"] = build_dependency_path_text(owner_dependency_path)
                interface_record["infrastructure_dependency_path"] = infrastructure_dependency_path
                interface_record["infrastructure_dependency_path_text"] = build_dependency_path_text(infrastructure_dependency_path)
                interface_record["relationship_parent"] = clean_ascii(normalize_relationship_entry(relationships.get(owner_device, {})).get("parent", "")) if has_owner else ""
                interface_record["relationship_type"] = clean_ascii(normalize_relationship_entry(relationships.get(owner_device, {})).get("relationship", "")) if has_owner else ""
                interface_record["relationship_criticality"] = clean_ascii(normalize_relationship_entry(relationships.get(owner_device, {})).get("criticality", "")) if has_owner else ""

                # Default dashboard counts focus on user-facing interfaces only.
                if not is_advanced:
                    if interface_state == "UP":
                        up_interface_count += 1
                    elif interface_state == "DOWN":
                        down_interface_count += 1
                    else:
                        unknown_interface_count += 1

                if is_advanced:
                    advanced_interface_count += 1
                    advanced_interface_records.append(interface_record)
                else:
                    user_interface_count += 1
                    user_interface_records.append(interface_record)
                    if has_owner:
                        owned_port_records.append(interface_record)
                    else:
                        unassigned_port_records.append(interface_record)

                if has_owner:
                    mapped_interface_count += 1

                if not is_advanced:
                    if has_owner:
                        owned_user_interface_count += 1
                    else:
                        unassigned_user_interface_count += 1

                interface_records.append(interface_record)

        total_interfaces_found = len(interface_records)
        default_interfaces_found = len(user_interface_records)

        if not total_interfaces_found:
            total_interfaces_found = int(discovery_record.get("interfaces_found", 0) or 0)

        last_discovery = clean_ascii(discovery_record.get("last_discovery", ""))

        if discovery_record:
            discovered_device_count += 1
            discovered_interface_count += int(default_interfaces_found or 0)
            discovery_status = clean_ascii(discovery_record.get("status", "")) or "SUCCESS"
            interfaces_display = default_interfaces_found
            last_discovery_display = last_discovery or "Not recorded"
        elif should_discover_infrastructure_role(role) and snmp_enabled:
            discovery_status = "Pending Phase 16A.3B"
            interfaces_display = "Pending"
            last_discovery_display = "Not run yet"
        elif role in ["Internet", "Modem"]:
            discovery_status = "Skipped"
            interfaces_display = "N/A"
            last_discovery_display = "Not required"
        else:
            discovery_status = "SNMP Disabled"
            interfaces_display = "N/A"
            last_discovery_display = "Not required"

        if last_discovery > latest_discovery:
            latest_discovery = last_discovery

        owned_port_records = sorted(owned_port_records, key=interface_sort_key)
        unassigned_port_records = sorted(unassigned_port_records, key=interface_sort_key)

        relationship_entry = normalize_relationship_entry(relationships.get(device_name, {})) if device_name in relationships else {}
        dependency_path = build_device_dependency_path(device_name, relationships)
        relationship_children = relationship_children_map.get(device_name, [])
        downstream_dependents = count_downstream_dependents(device_name, relationship_children_map)

        devices.append({
            "name": clean_ascii(device_name),
            "ip": clean_ascii(info.get("ip", DEVICES.get(device_name, ""))),
            "role": role,
            "snmp_enabled": snmp_enabled,
            "source": clean_ascii(info.get("source", "registry")),
            "registered_at": clean_ascii(info.get("registered_at", "")),
            "updated_at": clean_ascii(info.get("updated_at", "")),
            "status": clean_ascii(status.get(device_name, {}).get("state", "UNKNOWN")),
            "relationship_parent": clean_ascii(relationship_entry.get("parent", "")) or "Root Device",
            "relationship_type": clean_ascii(relationship_entry.get("relationship", "Root")) or "Root",
            "relationship_source": clean_ascii(relationship_entry.get("source", "")),
            "relationship_criticality": clean_ascii(relationship_entry.get("criticality", infer_relationship_criticality(device_name))),
            "relationship_children": relationship_children,
            "relationship_children_count": len(relationship_children),
            "downstream_dependents": downstream_dependents,
            "dependency_path": dependency_path,
            "dependency_path_text": build_dependency_path_text(dependency_path),
            "discovery_status": discovery_status,
            "interfaces_found": interfaces_display,
            "total_interfaces_found": total_interfaces_found,
            "user_interfaces_found": len(user_interface_records),
            "advanced_interfaces_found": len(advanced_interface_records),
            "mapped_interfaces_found": len([item for item in interface_records if item.get("has_owner")]),
            "owned_user_interfaces_found": len(owned_port_records),
            "unassigned_user_interfaces_found": len(unassigned_port_records),
            "last_discovery": last_discovery_display,
            "interfaces": interface_records,
            "user_interfaces": user_interface_records,
            "advanced_interfaces": advanced_interface_records,
            "owned_ports": owned_port_records,
            "unassigned_ports": unassigned_port_records,
            "has_interfaces": bool(interface_records),
            "has_user_interfaces": bool(user_interface_records),
            "has_advanced_interfaces": bool(advanced_interface_records),
            "has_owned_ports": bool(owned_port_records),
            "has_unassigned_ports": bool(unassigned_port_records)
        })

    devices = sorted(devices, key=lambda item: (item.get("role", ""), item.get("name", "").lower()))

    return {
        "phase": "16A.3C",
        "devices": devices,
        "relationships": relationship_summary,
        "role_counts": role_counts,
        "port_ownership": config.get("port_ownership", {}),
        "summary": {
            "total": len(devices),
            "routers": role_counts.get("Router", 0),
            "switches": role_counts.get("Switch", 0),
            "firewalls": role_counts.get("Firewall", 0),
            "access_points": role_counts.get("Access Point", 0),
            "snmp_enabled": snmp_enabled_count,
            "snmp_disabled": snmp_disabled_count,
            "devices_discovered": discovered_device_count,
            "interfaces_found": discovered_interface_count,
            "user_interfaces": user_interface_count,
            "advanced_interfaces": advanced_interface_count,
            "mapped_interfaces": mapped_interface_count,
            "owned_interfaces": owned_user_interface_count,
            "unassigned_interfaces": unassigned_user_interface_count,
            "total_relationships": relationship_summary.get("total_relationships", 0),
            "infrastructure_links": relationship_summary.get("infrastructure_links", 0),
            "endpoint_links": relationship_summary.get("endpoint_links", 0),
            "root_devices": relationship_summary.get("root_devices", 0),
            "dependency_chains": relationship_summary.get("dependency_chains", 0),
            "max_dependency_depth": relationship_summary.get("max_depth", 0),
            "interfaces_up": up_interface_count,
            "interfaces_down": down_interface_count,
            "interfaces_unknown": unknown_interface_count,
            "last_discovery": latest_discovery or "Not run yet",
            "last_updated": now()
        }
    }


@app.route("/infrastructure-registry")
def infrastructure_registry():
    payload = build_infrastructure_registry_page_data()
    active_alerts = get_active_alerts()

    return render_template(
        "infrastructure_registry.html",
        registry=payload,
        last_full_scan=last_full_scan,
        active_alert_count=len(active_alerts)
    )


@app.route("/api/infrastructure-registry")
def api_infrastructure_registry():
    return jsonify(build_infrastructure_registry_page_data())


@app.route("/api/infrastructure-relationships")
def api_infrastructure_relationships():
    load_config()
    ensure_port_ownership_registry()
    relationships = ensure_infrastructure_relationship_registry()
    return jsonify(build_infrastructure_relationship_summary(relationships))


@app.route("/api/infrastructure-discovery")
def api_infrastructure_discovery():
    load_config()
    discover_infrastructure_interfaces(force=True)
    return jsonify(build_infrastructure_discovery_summary())


@app.route("/api/dashboard-data")
def api_dashboard_data():
    return jsonify(build_dashboard_api_data())



# PHASE 8C - SMART NETWORK MAP
def detect_map_device_type(name, ip=""):
    if name in DEVICE_TYPES:
        return DEVICE_TYPES[name]

    text = f"{name} {ip}".lower()

    if "internet" in text:
        return "Internet"

    if "cox" in text or "modem" in text:
        return "Modem"

    if "router" in text or "2901" in text:
        return "Router"

    if "switch" in text:
        return "Switch"

    if "omv" in text or "file server" in text or "nas" in text:
        return "Server / NAS"

    if "ubuntu" in text or "server" in text or "terminal" in text:
        return "Server"

    if "mac" in text or "apple" in text or "alicia" in text or "azero" in text:
        return "Mac"

    if "vm" in text or "virtual" in text:
        return "Virtual Machine"

    if "laptop" in text:
        return "Laptop"

    if "windows" in text or "desktop" in text or "pc" in text:
        return "Desktop PC"

    if "printer" in text:
        return "Printer"

    if "bose" in text or "speaker" in text:
        return "Audio Device"

    return "Endpoint"







# PHASE 9A - ENTERPRISE INVENTORY ENGINE
def get_infrastructure_name(role, fallback=""):
    """Resolve infrastructure by registry role without relying on device names.

    Legacy pointers in config["infrastructure"] are honored only when they still
    reference an existing inventory device. Otherwise the Infrastructure Registry
    is searched by normalized role. The optional fallback is retained only for
    compatibility with older callers and is never used to invent a device.
    """
    role_key = clean_ascii(role)
    pointer = clean_ascii(config.get("infrastructure", {}).get(role_key, ""))
    if pointer and pointer in config.get("devices", {}):
        return pointer

    role_aliases = {
        "internet": "Internet",
        "internet_gateway": "Modem",
        "edge_router": "Router",
        "main_switch": "Switch",
    }
    wanted_role = normalize_infrastructure_role(role_aliases.get(role_key, role_key))
    matches = sorted(
        name for name, info in get_infrastructure_devices().items()
        if normalize_infrastructure_role(info.get("role", "")) == wanted_role
        and name in config.get("devices", {})
    )
    if matches:
        return matches[0]

    fallback = clean_ascii(fallback)
    return fallback if fallback in config.get("devices", {}) else ""


def get_infrastructure_names_by_role(role):
    wanted_role = normalize_infrastructure_role(role)
    return sorted(
        name for name, info in get_infrastructure_devices().items()
        if normalize_infrastructure_role(info.get("role", "")) == wanted_role
        and name in config.get("devices", {})
    )


def get_all_infrastructure_names():
    return set(get_infrastructure_devices().keys())


def get_internet_service_name():
    return get_infrastructure_name("internet")


def get_primary_router_name():
    return get_infrastructure_name("edge_router")


def get_dynamic_switch_port_label(port_index, fallback=""):
    port_index = clean_ascii(port_index)
    interfaces = get_primary_switch_interfaces()
    info = interfaces.get(port_index, {}) if isinstance(interfaces, dict) else {}
    label = clean_ascii(info.get("short_name", "")) or clean_ascii(info.get("name", ""))
    return label or clean_ascii(fallback) or f"Index {port_index}"


def get_device_status_by_name_or_ip(preferred_name="", ip_address=""):
    device_name = preferred_name
    device_ip = DEVICES.get(preferred_name, ip_address)

    if preferred_name in status:
        return device_name, device_ip, status.get(preferred_name, {})

    for name, info in status.items():
        if str(info.get("ip", "")) == str(device_ip):
            return name, device_ip, info

    return device_name, device_ip, {}


def build_core_node(role, fallback_name, fallback_ip, device_type, icon, port_label):
    official_name = get_infrastructure_name(role, fallback_name)
    device_name, device_ip, status_info = get_device_status_by_name_or_ip(official_name, fallback_ip)
    state = status_info.get("state", "UNKNOWN")

    return {
        "name": device_name,
        "ip": device_ip,
        "state": state,
        "status_class": get_map_status_class(state),
        "type": device_type,
        "icon": icon,
        "port": port_label,
        "latency": status_info.get("latency", "N/A"),
        "last_checked": status_info.get("last_checked", "Starting...")
    }


def is_virtual_child_device(device_name):
    """Return True only for VM/virtual child relationships, not physical infrastructure links."""
    device_name = clean_ascii(device_name)
    if not device_name:
        return False

    relationship = DEVICE_RELATIONSHIPS.get(device_name, {})
    if not isinstance(relationship, dict):
        return False

    device_type = clean_ascii(DEVICE_TYPES.get(device_name, "")).lower()
    relationship_type = clean_ascii(relationship.get("relationship", "")).lower()
    hosted_by = clean_ascii(relationship.get("hosted_by", ""))
    parent = clean_ascii(relationship.get("parent", ""))

    virtual_device_types = {
        "virtual machine",
        "vm",
        "virtual server",
        "container",
        "docker container",
        "lxc container",
        "child device",
    }

    virtual_relationship_types = {
        "virtual machine",
        "vm",
        "hosted vm",
        "hosted virtual machine",
        "virtual child",
        "guest",
        "container",
    }

    if device_type in virtual_device_types:
        return bool(hosted_by or parent)

    if relationship_type in virtual_relationship_types:
        return bool(hosted_by or parent)

    return False


def is_child_device(device_name):
    return device_name in DEVICE_RELATIONSHIPS


def get_child_devices(parent_name):
    children = []

    for child_name, rel in DEVICE_RELATIONSHIPS.items():
        if not isinstance(rel, dict):
            continue

        if rel.get("parent") != parent_name:
            continue

        if child_name not in DEVICES:
            continue

        child_type = DEVICE_TYPES.get(
            child_name,
            detect_map_device_type(child_name, DEVICES.get(child_name, ""))
        )

        # Phase 9C.2 rule:
        # Only true virtual/child devices display underneath endpoint cards.
        if child_type not in ["Virtual Machine", "VM", "Child Device"]:
            continue

        child_status = status.get(child_name, {})
        state = child_status.get("state", "UNKNOWN")

        children.append({
            "name": child_name,
            "ip": DEVICES.get(child_name, ""),
            "type": child_type,
            "icon": get_map_icon(child_type),
            "state": state,
            "status_class": get_map_status_class(state),
            "latency": child_status.get("latency", "N/A"),
            "last_checked": child_status.get("last_checked", "Starting..."),
            "parent": parent_name,
            "relationship": rel.get("relationship", "Child Device")
        })

    return sorted(children, key=lambda item: item["name"].lower())





# ======================================================
# PHASE 13C.7 - EDITABLE PHYSICAL TOPOLOGY MANAGER
# ======================================================
def is_topology_switch(device_name):
    device_type = detect_map_device_type(device_name, DEVICES.get(device_name, ""))
    return clean_ascii(device_type).lower() == "switch"


def is_topology_router(device_name):
    device_type = detect_map_device_type(device_name, DEVICES.get(device_name, ""))
    return clean_ascii(device_type).lower() == "router"


def get_used_topology_interfaces(exclude_link_id=""):
    """Return interfaces already consumed by saved topology/mapping data.

    Phase 16B fix:
    A port/interface becomes unavailable as soon as it is used in a saved
    topology link. Legacy Enterprise Inventory switch-port assignments are also
    treated as consumed on the primary switch so the same switch port cannot be
    mapped again.
    """
    used = {}

    for link in get_physical_topology_config():
        link_id = clean_ascii(link.get("id", ""))
        if exclude_link_id and link_id == exclude_link_id:
            continue

        from_device = clean_ascii(link.get("from", ""))
        to_device = clean_ascii(link.get("to", ""))

        source_interface = clean_ascii(link.get("source_interface", ""))
        target_interface = clean_ascii(link.get("target_interface", ""))

        if from_device and source_interface:
            used.setdefault(from_device, set()).add(source_interface)
            # Also add the short version so Gi0/0 and GigabitEthernet0/0 match.
            used[from_device].add(short_interface_name(source_interface))

        if to_device and target_interface:
            used.setdefault(to_device, set()).add(target_interface)
            used[to_device].add(short_interface_name(target_interface))

    # Legacy switch_ports assignments still represent real consumed switch ports.
    primary_switch = clean_ascii(get_physical_topology_primary_switch())
    if primary_switch:
        for port_index, mapped_device in config.get("switch_ports", {}).items():
            port_index = clean_ascii(port_index)
            if not port_index or not mapped_device:
                continue

            label = clean_ascii(get_switch_port_label(port_index))
            used.setdefault(primary_switch, set()).add(port_index)
            if label:
                used[primary_switch].add(label)
                used[primary_switch].add(short_interface_name(label))

    return used


def get_available_interfaces_for_topology_device(device_name, exclude_link_id=""):
    """Return unused interfaces for topology mapping.

    Phase 16B fix:
    The topology mapper is now universal for SNMP-managed infrastructure.
    Routers, switches, firewalls, and access points all expose usable
    SNMP-discovered interfaces. Once an interface is saved in a topology link,
    it is removed from future dropdowns for that device.
    """
    device_name = clean_ascii(device_name)
    used = get_used_topology_interfaces(exclude_link_id).get(device_name, set())

    if is_network_infrastructure_device(device_name):
        labels = get_interface_labels_for_device(device_name)
        available = []
        for label in labels:
            label = clean_ascii(label)
            if not label:
                continue
            possible = {label, short_interface_name(label)}
            if possible.intersection(used):
                continue
            available.append(label)
        return available

    return []


def build_topology_editor_payload(edit_link_id=""):
    links = get_physical_topology_config()
    editable_links = []
    used_interfaces = get_used_topology_interfaces(edit_link_id)

    for link in links:
        from_device = link.get("from", "")
        to_device = link.get("to", "")
        editable_links.append({
            **link,
            "from_ip": DEVICES.get(from_device, ""),
            "to_ip": DEVICES.get(to_device, ""),
            "from_type": detect_map_device_type(from_device, DEVICES.get(from_device, "")),
            "to_type": detect_map_device_type(to_device, DEVICES.get(to_device, "")),
        })

    return {
        "enabled": True,
        "phase": "16B",
        "devices": [
            {
                "name": name,
                "ip": ip,
                "type": detect_map_device_type(name, ip),
                "is_switch": is_topology_switch(name),
                "is_router": is_topology_router(name),
                "available_interfaces": get_available_interfaces_for_topology_device(name, edit_link_id)
            }
            for name, ip in sorted(DEVICES.items(), key=lambda item: item[0].lower())
        ],
        "links": editable_links,
        "link_count": len(editable_links),
        "used_interfaces": {
            name: sorted(list(values)) for name, values in used_interfaces.items()
        },
        "edit_link_id": edit_link_id
    }


def normalize_topology_link_record(raw, link_id=""):
    from_device = clean_ascii(raw.get("from_device", raw.get("from", "")))
    to_device = clean_ascii(raw.get("to_device", raw.get("to", "")))
    source_interface = clean_ascii(raw.get("source_interface", raw.get("from_interface", "")))
    target_interface = clean_ascii(raw.get("target_interface", raw.get("to_interface", "")))
    link_type = clean_ascii(raw.get("link_type", "Physical Link")) or "Physical Link"
    label = clean_ascii(raw.get("label", ""))

    if not from_device or not to_device:
        raise ValueError("Device A and Device B are required")

    if from_device == to_device:
        raise ValueError("Device A and Device B cannot be the same device")

    if from_device not in DEVICES:
        raise ValueError(f"Device A is not in inventory: {from_device}")

    if to_device not in DEVICES:
        raise ValueError(f"Device B is not in inventory: {to_device}")

    if not source_interface:
        source_interface = "eth0"

    if not target_interface:
        target_interface = "eth0"

    used = get_used_topology_interfaces(link_id)

    if source_interface in used.get(from_device, set()):
        raise ValueError(f"{source_interface} is already used on {from_device}")

    if target_interface in used.get(to_device, set()):
        raise ValueError(f"{target_interface} is already used on {to_device}")

    source_port_index = ""
    target_port_index = ""

    if is_topology_switch(from_device) or is_topology_router(from_device):
        source_port_index = find_interface_index_for_device(from_device, source_interface)

    if is_topology_switch(to_device) or is_topology_router(to_device):
        target_port_index = find_interface_index_for_device(to_device, target_interface)

    # Backward-compatible switch_port field for existing root-cause and SNMP link logic.
    # For switch-to-router links this stores the switch-side SNMP index when available.
    switch_port = ""
    if is_topology_switch(from_device):
        switch_port = source_port_index
    elif is_topology_switch(to_device):
        switch_port = target_port_index

    port_label = ""
    if is_topology_switch(from_device):
        port_label = source_interface
    elif is_topology_switch(to_device):
        port_label = target_interface
    else:
        port_label = source_interface or target_interface

    if not link_id:
        link_id = f"link-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"

    return {
        "id": link_id,
        "from": from_device,
        "to": to_device,
        "source_interface": source_interface,
        "target_interface": target_interface,
        "source_port_index": source_port_index,
        "target_port_index": target_port_index,
        "switch_port": switch_port,
        "port_label": port_label,
        "link_type": link_type,
        "label": label
    }


def save_topology_links(links):
    config["infrastructure_links"] = links
    config.setdefault("dynamic_physical_topology", {})
    config["dynamic_physical_topology"].update({
        "enabled": True,
        "phase": "16F",
        "source": "infrastructure_links + SNMP interface inventory",
        "auto_rebuild": True,
        "editable": True,
        "description": "Topology is created only by inventory devices and user-saved infrastructure links. Infrastructure devices are filtered out of endpoint cards and placed only by Physical Topology links."
    })
    save_config()
    refresh_runtime_data()


def is_infrastructure_topology_device(device_name):
    """True when a device should be placed by Physical Topology links, not Port Mapper.

    Phase 16F fix:
    Routers, switches, firewalls, access points, modems, and internet nodes are
    infrastructure. They must never be auto-rendered under the primary switch
    from endpoint switch_ports mappings.
    """
    device_name = clean_ascii(device_name)
    if not device_name:
        return False

    role = normalize_infrastructure_role(
        detect_map_device_type(device_name, DEVICES.get(device_name, config.get("devices", {}).get(device_name, "")))
    )

    return role in [
        "Internet",
        "Modem",
        "Router",
        "Switch",
        "Firewall",
        "Access Point",
        "UPS",
        "DNS Server",
        "DHCP Server",
        "VPN Gateway"
    ]


def cleanup_endpoint_mapping_for_infrastructure_device(device_name):
    """Remove endpoint/Port Mapper mappings for infrastructure devices.

    Phase 16F fix:
    When a router is connected through the Physical Topology Builder, any old
    Port Mapper assignment must be removed so the map does not keep drawing
    the router below the switch as an endpoint.
    """
    device_name = clean_ascii(device_name)
    if not device_name or not is_infrastructure_topology_device(device_name):
        return {"removed_ports": 0, "removed_links": 0}

    removed_ports = 0
    config.setdefault("switch_ports", {})
    for port_index, mapped_device in list(config["switch_ports"].items()):
        if clean_ascii(mapped_device) == device_name:
            config["switch_ports"].pop(port_index, None)
            removed_ports += 1

    removed_links = remove_endpoint_topology_links_for_device(device_name)
    return {"removed_ports": removed_ports, "removed_links": removed_links}


def sync_relationship_from_topology_link(record):
    """Phase 27B: save topology-builder links through RelationshipManager first."""
    child = clean_ascii(record.get("to", ""))
    parent = clean_ascii(record.get("from", ""))
    if not child or not parent or child == parent:
        return {"success": False, "reason": "invalid_topology_link"}

    link_type = clean_ascii(record.get("link_type", "Physical Link")) or "Physical Link"
    evidence_sources = list(record.get("evidence_sources", []) or [])
    source = clean_ascii(record.get("source", "physical_topology")) or "physical_topology"
    if not evidence_sources:
        evidence_sources = ["MANUAL"]

    return phase27_write_relationship(
        parent=parent,
        child=child,
        parent_interface=record.get("source_interface", ""),
        child_interface=record.get(
            "target_interface",
            record.get("destination_interface", ""),
        ),
        relationship_type="PHYSICAL",
        relationship_state=record.get("relationship_state", "MANUAL"),
        confidence=record.get("confidence", 100),
        currently_verified=bool(record.get("currently_verified", False)),
        active=bool(record.get("active", True)),
        evidence_sources=evidence_sources,
        evidence_id=record.get("evidence_id", record.get("id", "")),
        source=source,
        state_details=link_type,
        metadata={
            "phase": "27B",
            "topology_link_id": record.get("id", ""),
            "manager_first_write": True,
        },
        legacy_relationship=link_type,
        selection_source=record.get("selection_source", "explicit_saved_link"),
        save=False,
    )


def add_or_update_topology_link(form_data):
    load_config()

    link_id = clean_ascii(form_data.get("link_id", ""))
    links = get_physical_topology_config()
    record = normalize_topology_link_record(form_data, link_id)

    if link_id:
        updated = False
        for index, link in enumerate(links):
            if clean_ascii(link.get("id", "")) == link_id:
                links[index] = record
                updated = True
                break
        if not updated:
            links.append(record)
        action = "UPDATED"
    else:
        links.append(record)
        action = "ADDED"

    # Phase 16E: Infrastructure devices are placed by topology links, not by
    # Port Mapper endpoint mappings. Clean stale endpoint mappings for both
    # sides before saving so routers do not continue to appear under the switch.
    cleanup_a = cleanup_endpoint_mapping_for_infrastructure_device(record.get("from", ""))
    cleanup_b = cleanup_endpoint_mapping_for_infrastructure_device(record.get("to", ""))
    sync_relationship_from_topology_link(record)

    save_topology_links(links)
    write_event(
        f"CONFIG | TOPOLOGY LINK {action} | {record['from']} {record['source_interface']} -> {record['target_interface']} {record['to']} | "
        f"endpoint cleanup ports: {cleanup_a.get('removed_ports', 0) + cleanup_b.get('removed_ports', 0)} | "
        f"endpoint links: {cleanup_a.get('removed_links', 0) + cleanup_b.get('removed_links', 0)}"
    )
    return record


def delete_topology_link(link_id):
    load_config()

    link_id = clean_ascii(link_id)
    links = get_physical_topology_config()
    remaining = [link for link in links if clean_ascii(link.get("id", "")) != link_id]

    if len(remaining) == len(links):
        raise ValueError("Topology link not found")

    save_topology_links(remaining)
    write_event(f"CONFIG | TOPOLOGY LINK DELETED | {link_id}")
    return True


def build_dynamic_physical_topology_data():
    """Phase 21A: build one validated, authoritative relationship graph.

    Sources:
    - infrastructure_links for infrastructure parent/child links
    - port ownership for switch -> endpoint links
    - device_relationships for host -> child/VM links

    Guarantees:
    - one canonical node record per inventory device
    - one parent per child
    - no duplicate relationship pairs
    - cycles are rejected
    - infrastructure can never be attached as an endpoint
    """
    inventory = config.get("devices", {}) if isinstance(config.get("devices", {}), dict) else {}

    def canonical_name(value):
        raw = clean_ascii(value)
        if not raw:
            return ""
        if raw in inventory:
            return raw
        normalized = raw.replace("+", " ").replace("_", " ")
        normalized = re.sub(r"\s+", " ", normalized).strip().lower()
        for candidate in inventory:
            check = clean_ascii(candidate).replace("+", " ").replace("_", " ")
            check = re.sub(r"\s+", " ", check).strip().lower()
            if check == normalized:
                return candidate
        return raw

    def node_record(name):
        name = canonical_name(name)
        ip = inventory.get(name, DEVICES.get(name, ""))
        info = status.get(name, {}) if isinstance(status, dict) else {}
        state_value = info.get("state", "UNKNOWN")
        maintenance_info = get_device_maintenance_info(name)
        if maintenance_info:
            state_value = get_maintenance_state_label()
        device_type = detect_map_device_type(name, ip)
        return {
            "name": name,
            "ip": ip,
            "type": device_type,
            "role": normalize_infrastructure_role(device_type),
            "icon": get_map_icon(device_type),
            "state": state_value,
            "status_class": get_map_status_class(state_value),
            "latency": info.get("latency", "N/A"),
            "last_checked": info.get("last_checked", "Starting..."),
            "maintenance_mode": bool(maintenance_info),
            "maintenance_badge": get_phase26b7_maintenance_badge() if maintenance_info else "",
            "maintenance_reason": maintenance_info.get("reason", "") if maintenance_info else "",
            "maintenance_start": maintenance_info.get("start", "") if maintenance_info else "",
            "maintenance_until": maintenance_info.get("until", "") if maintenance_info else "",
            "maintenance_remaining": format_maintenance_remaining(maintenance_info.get("remaining_seconds", -1)) if maintenance_info else "",
            "physical_state": clean_ascii(info.get("physical_state", info.get("state", "UNKNOWN"))) or "UNKNOWN"
        }

    candidate_relationships = []

    # 1. Infrastructure links are the authority for infrastructure placement.
    for raw_link in get_physical_topology_config():
        if not isinstance(raw_link, dict):
            continue
        parent = canonical_name(raw_link.get("from", ""))
        child = canonical_name(raw_link.get("to", ""))
        if not parent or not child or parent == child:
            continue
        if raw_link.get("is_endpoint_link"):
            continue
        if clean_ascii(raw_link.get("link_type", "")).lower() in ["endpoint link", "endpoint bus link"]:
            continue
        candidate_relationships.append({
            "from": parent,
            "to": child,
            "kind": "infrastructure",
            "link_type": clean_ascii(raw_link.get("link_type", "Physical Link")) or "Physical Link",
            "label": clean_ascii(raw_link.get("port_label", "")) or clean_ascii(raw_link.get("label", "")) or "Physical Link",
            "source_interface": clean_ascii(raw_link.get("source_interface", "")),
            "target_interface": clean_ascii(raw_link.get("target_interface", "")),
            "state": clean_ascii(raw_link.get("state", "UP")) or "UP",
            "status_class": clean_ascii(raw_link.get("status_class", "map-up")) or "map-up"
        })

    # 2. Port ownership is the only authority for switch -> endpoint placement.
    for switch_name, port_map in (ensure_port_ownership_registry() or {}).items():
        switch_name = canonical_name(switch_name)
        if not switch_name or not isinstance(port_map, dict):
            continue
        for port_index, ownership_entry in port_map.items():
            normalized_owner = normalize_port_ownership_entry(ownership_entry)
            child = canonical_name(normalized_owner.get("device", ""))
            if not child or child not in inventory:
                continue
            if is_infrastructure_topology_device(child) or is_child_device(child):
                continue
            port_index = clean_ascii(port_index)
            link_info = switch_links.get(port_index, {}) if isinstance(switch_links, dict) else {}
            state_value = clean_ascii(link_info.get("state", "UNKNOWN")) or "UNKNOWN"
            candidate_relationships.append({
                "from": switch_name,
                "to": child,
                "kind": "endpoint",
                "link_type": "Switch Port",
                "label": clean_ascii(link_info.get("port", "")) or get_dynamic_switch_port_label(port_index, port_index),
                "port_index": port_index,
                "state": state_value,
                "status_class": get_map_status_class(state_value)
            })

    # 3. Explicit device relationships place VMs/children under their host.
    for child_name, rel in config.get("device_relationships", {}).items():
        if not isinstance(rel, dict):
            continue
        child = canonical_name(child_name)
        parent = canonical_name(rel.get("parent", ""))
        if not child or not parent or child == parent:
            continue
        # Infrastructure placement already comes from physical links only.
        if is_infrastructure_topology_device(child):
            continue
        candidate_relationships.append({
            "from": parent,
            "to": child,
            "kind": "child",
            "link_type": clean_ascii(rel.get("relationship", "Child Device")) or "Child Device",
            "label": clean_ascii(rel.get("relationship", "Child Device")) or "Child Device",
            "state": status.get(child, {}).get("state", "UNKNOWN"),
            "status_class": get_map_status_class(status.get(child, {}).get("state", "UNKNOWN"))
        })

    # Stable priority: infrastructure > endpoint > child.
    priority = {"infrastructure": 0, "endpoint": 1, "child": 2}
    candidate_relationships.sort(key=lambda x: (priority.get(x.get("kind"), 9), x.get("from", "").lower(), x.get("to", "").lower()))

    relationships = []
    pair_seen = set()
    parent_by_child = {}
    warnings = []

    def would_create_cycle(parent, child):
        cursor = parent
        visited = set()
        while cursor:
            if cursor == child:
                return True
            if cursor in visited:
                return True
            visited.add(cursor)
            cursor = parent_by_child.get(cursor, "")
        return False

    for rel in candidate_relationships:
        parent = rel["from"]
        child = rel["to"]
        pair = (parent.lower(), child.lower())
        if pair in pair_seen:
            continue
        if child in parent_by_child and parent_by_child[child] != parent:
            warnings.append(f"Rejected second parent for {child}: {parent}; using {parent_by_child[child]}")
            continue
        if would_create_cycle(parent, child):
            warnings.append(f"Rejected cycle: {parent} -> {child}")
            continue
        pair_seen.add(pair)
        parent_by_child[child] = parent
        relationships.append(rel)

    node_names = set()
    for rel in relationships:
        node_names.add(rel["from"])
        node_names.add(rel["to"])
    for name in inventory:
        node_names.add(canonical_name(name))

    nodes = [node_record(name) for name in sorted(node_names, key=lambda x: x.lower()) if name]
    nodes_by_name = {item["name"]: item for item in nodes}

    roots = sorted(
        [name for name in nodes_by_name if name not in parent_by_child],
        key=lambda name: (
            0 if normalize_infrastructure_role(nodes_by_name[name].get("role", "")) == "Internet" else
            1 if normalize_infrastructure_role(nodes_by_name[name].get("role", "")) == "Modem" else 2,
            name.lower()
        )
    )

    return {
        "enabled": True,
        "phase": "21A",
        "mode": "validated_relationship_tree",
        "source": "infrastructure_links + port ownership + device relationships",
        "nodes": nodes,
        "relationships": relationships,
        "roots": roots,
        "parent_by_child": parent_by_child,
        "validation": {
            "valid": len(warnings) == 0,
            "warnings": warnings,
            "node_count": len(nodes),
            "relationship_count": len(relationships),
            "duplicate_pairs_removed": len(candidate_relationships) - len(relationships),
            "single_parent_enforced": True,
            "cycle_detection": True
        },
        "last_updated": last_full_scan
    }


def build_network_map_data():
    """Phase 21A network map payload using one validated relationship tree."""
    refresh_runtime_data()
    topology = build_dynamic_physical_topology_data()

    endpoint_nodes = [
        node for node in topology.get("nodes", [])
        if not is_infrastructure_topology_device(node.get("name", ""))
        and not is_child_device(node.get("name", ""))
    ]

    up_count = sum(1 for item in endpoint_nodes if item.get("state") == "UP")
    down_count = sum(1 for item in endpoint_nodes if item.get("state") == "DOWN")
    maintenance_count = sum(1 for item in endpoint_nodes if item.get("maintenance_mode"))
    warning_count = sum(1 for item in endpoint_nodes if item.get("state") not in ["UP", "DOWN", get_maintenance_state_label()])

    return {
        "topology": topology,
        # Compatibility alias for existing consumers during migration.
        "physical_topology": topology,
        "endpoints": endpoint_nodes,
        "router_interfaces": [],
        "infrastructure_uplinks": [],
        "summary": {
            "phase": "26B.7",
            "total_devices": len(endpoint_nodes),
            "maintenance": maintenance_count,
            "inventory_devices": len(config.get("devices", {})),
            "up": up_count,
            "down": down_count,
            "warnings": warning_count,
            "relationship_count": len(topology.get("relationships", [])),
            "physical_links": len(topology.get("relationships", [])),
            "last_updated": last_full_scan,
            "empty": not bool(topology.get("nodes")),
            "relationship_driven": True,
            "layout_engine": "Phase 21A validated recursive relationship tree",
            "validation_warnings": len(topology.get("validation", {}).get("warnings", []))
        }
    }


# PHASE 10E - SMART DEVICE PROVISIONING ENGINE
# PHASE 10E.9 - SMART PROVISIONING COMPLETION ENGINE

def get_existing_ip_owner(ip_address):
    ip_address = clean_ascii(ip_address)

    for device_name, existing_ip in config.get("devices", {}).items():
        if clean_ascii(existing_ip) == ip_address:
            return device_name

    return ""


def get_reserved_provisioning_ips():
    """Return only addresses that are unsafe or explicitly reserved.

    Infrastructure addresses such as .1 are not permanently blocked. Duplicate
    ownership is handled separately by get_existing_ip_owner(), allowing a
    blank installation to use any valid host address needed by the new site.
    """
    reserved_ips = set()

    for ip_address in config.get("provisioning_reserved_ips", []):
        clean_ip = clean_ascii(ip_address)
        if clean_ip:
            reserved_ips.add(clean_ip)

    for ip_address in config.get("devices", {}).values():
        try:
            ip_obj = ipaddress.ip_address(clean_ascii(ip_address))
            if ip_obj.version == 4:
                parts = clean_ascii(ip_address).split(".")
                if len(parts) == 4:
                    reserved_ips.add(".".join(parts[:3] + ["0"]))
                    reserved_ips.add(".".join(parts[:3] + ["255"]))
        except Exception:
            continue

    return sorted(reserved_ips)


def is_reserved_provisioning_ip(ip_address):
    return clean_ascii(ip_address) in get_reserved_provisioning_ips()


def get_switch_port_for_device(device_name):
    for port_index, mapped_device in config.get("switch_ports", {}).items():
        if mapped_device == device_name:
            return {
                "index": port_index,
                "label": get_dynamic_switch_port_label(port_index, port_index)
            }

    return {
        "index": "",
        "label": "No physical switch port"
    }


def get_inherited_switch_port_for_virtual_device(device_name):
    relationship = config.get("device_relationships", {}).get(device_name, {})
    parent_name = relationship.get("parent", "")

    if not parent_name:
        return {
            "parent": "",
            "index": "",
            "label": "No inherited host port"
        }

    port_info = get_switch_port_for_device(parent_name)
    port_info["parent"] = parent_name

    if not port_info.get("index"):
        port_info["label"] = f"Inherited from {parent_name}: no physical port mapped"
    else:
        port_info["label"] = f"Inherited from {parent_name}: {port_info.get('label')}"

    return port_info






# ======================================================
# PHASE 26B.7 - MAINTENANCE MODE INTELLIGENCE
# ======================================================
def get_phase26b7_settings():
    settings = config.setdefault("phase26b7_maintenance_intelligence", {})
    defaults = {
        "enabled": True,
        "phase": "26B.7",
        "visual_badge": "🔧 MAINTENANCE",
        "preserve_physical_port_state": True,
        "suppress_root_cause_candidates": True,
        "suppress_downstream_maintenance_impact": True,
        "track_history": True,
        "history_limit": 200,
        "status": "ACTIVE"
    }
    for key, value in defaults.items():
        settings.setdefault(key, value)
    config.setdefault("phase26b7_maintenance_history", [])
    return settings


def record_phase26b7_maintenance_event(device_name, action, record=None):
    settings = get_phase26b7_settings()
    if not settings.get("track_history", True):
        return
    history = config.setdefault("phase26b7_maintenance_history", [])
    if not isinstance(history, list):
        history = []
    record = record if isinstance(record, dict) else {}
    history.append({
        "id": "maint-" + datetime.now().strftime("%Y%m%d%H%M%S%f"),
        "phase": "26B.7",
        "time": now(),
        "device": clean_ascii(device_name),
        "action": clean_ascii(action).upper(),
        "reason": clean_ascii(record.get("reason", "Maintenance")),
        "start": clean_ascii(record.get("start", "")),
        "until": clean_ascii(record.get("until", "MANUAL")) or "MANUAL"
    })
    try:
        limit = max(25, int(settings.get("history_limit", 200) or 200))
    except Exception:
        limit = 200
    config["phase26b7_maintenance_history"] = history[-limit:]


def get_phase26b7_maintenance_badge():
    return clean_ascii(get_phase26b7_settings().get("visual_badge", "🔧 MAINTENANCE")) or "🔧 MAINTENANCE"


def get_phase26b7_maintenance_history(limit=25):
    history = config.get("phase26b7_maintenance_history", [])
    if not isinstance(history, list):
        return []
    try:
        limit = max(1, int(limit))
    except Exception:
        limit = 25
    return list(reversed(history[-limit:]))

# PHASE 11A - MAINTENANCE MODE ENGINE
def get_maintenance_state_label():
    return config.get("maintenance_mode", {}).get("state_label", "MAINTENANCE")


def get_active_maintenance_records():
    active = config.get("maintenance_mode", {}).get("active", {})
    if not isinstance(active, dict):
        return {}

    return active


def cleanup_expired_maintenance():
    active = get_active_maintenance_records()
    changed = False

    for device_name in list(active.keys()):
        record = active.get(device_name, {})
        until_text = clean_ascii(record.get("until", ""))

        # Manual maintenance has no expiration.
        if not until_text or until_text.upper() == "MANUAL":
            continue

        until_dt = parse_timestamp(until_text)

        if not until_dt or datetime.now() >= until_dt:
            active.pop(device_name, None)
            write_event(f"CONFIG | MAINTENANCE ENDED | {device_name} automatic maintenance window expired")
            changed = True

    if changed:
        config.setdefault("maintenance_mode", {})
        config["maintenance_mode"]["active"] = active

    return changed


def get_device_maintenance_info(device_name):
    active = get_active_maintenance_records()
    record = active.get(device_name, {})

    if not record:
        return {}

    until_text = clean_ascii(record.get("until", ""))

    if until_text and until_text.upper() != "MANUAL":
        until_dt = parse_timestamp(until_text)

        if not until_dt or datetime.now() >= until_dt:
            return {}

        remaining_seconds = max(0, int((until_dt - datetime.now()).total_seconds()))
    else:
        remaining_seconds = -1

    return {
        "state": get_maintenance_state_label(),
        "start": record.get("start", ""),
        "until": until_text or "MANUAL",
        "reason": record.get("reason", "Maintenance"),
        "duration_minutes": record.get("duration_minutes", "manual"),
        "remaining_seconds": remaining_seconds
    }


def is_device_in_maintenance(device_name):
    return bool(get_device_maintenance_info(device_name))


def format_maintenance_remaining(seconds):
    try:
        seconds = int(seconds)
    except Exception:
        return "Unknown"

    if seconds < 0:
        return "Manual"

    return format_duration_seconds(seconds)


def build_maintenance_summary():
    active = []

    for device_name, record in get_active_maintenance_records().items():
        info = get_device_maintenance_info(device_name)

        if not info:
            continue

        active.append({
            "device": device_name,
            "badge": get_phase26b7_maintenance_badge(),
            "phase": "26B.7",
            "ip": DEVICES.get(device_name, ""),
            "reason": info.get("reason", "Maintenance"),
            "start": info.get("start", ""),
            "until": info.get("until", "MANUAL"),
            "remaining": format_maintenance_remaining(info.get("remaining_seconds", -1)),
            "remaining_seconds": info.get("remaining_seconds", -1)
        })

    active = sorted(active, key=lambda item: item.get("device", "").lower())

    return {
        "enabled": config.get("maintenance_mode", {}).get("enabled", True),
        "active_count": len(active),
        "active": active,
        "state_label": get_maintenance_state_label(),
        "badge": get_phase26b7_maintenance_badge(),
        "phase": "26B.7",
        "history": get_phase26b7_maintenance_history(10),
        "preserve_physical_port_state": bool(get_phase26b7_settings().get("preserve_physical_port_state", True)),
        "alerts_suppressed": bool(config.get("maintenance_mode", {}).get("suppress_device_alerts", True))
    }


def start_device_maintenance(device_name, duration_minutes, reason):
    config.setdefault("maintenance_mode", {})
    config["maintenance_mode"].setdefault("active", {})

    start_time = datetime.now()

    duration_text = clean_ascii(duration_minutes).lower()

    if duration_text in ["manual", "until_manual", "until disabled", "0", ""]:
        until_text = "MANUAL"
        duration_value = "manual"
    else:
        try:
            duration_value = int(duration_minutes)
        except Exception:
            duration_value = 60

        until_text = (start_time + timedelta(minutes=duration_value)).strftime("%Y-%m-%d %H:%M:%S")

    config["maintenance_mode"]["active"][device_name] = {
        "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "until": until_text,
        "duration_minutes": duration_value,
        "reason": clean_ascii(reason) or "Maintenance"
    }
    record_phase26b7_maintenance_event(device_name, "STARTED", config["maintenance_mode"]["active"][device_name])


def end_device_maintenance(device_name):
    active = get_active_maintenance_records()

    if device_name in active:
        previous_record = dict(active.get(device_name, {}))
        active.pop(device_name, None)
        record_phase26b7_maintenance_event(device_name, "ENDED", previous_record)
        config.setdefault("maintenance_mode", {})
        config["maintenance_mode"]["active"] = active
        return True

    return False


# PHASE 10E.9b - PROVISIONING GRACE PERIOD ENGINE
def get_provisioning_grace_seconds():
    try:
        return int(config.get("provisioning_grace", {}).get("grace_seconds", 15))
    except Exception:
        return 15


def get_provisioning_state_label():
    return config.get("provisioning_grace", {}).get("state_label", "PROVISIONING")


def mark_device_provisioning_grace(device_name):
    config.setdefault("provisioning_grace", {})
    config.setdefault("provisioning_grace_devices", {})

    grace_seconds = get_provisioning_grace_seconds()
    start_time = datetime.now()
    end_time = start_time + timedelta(seconds=grace_seconds)

    config["provisioning_grace_devices"][device_name] = {
        "state": get_provisioning_state_label(),
        "start": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "until": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "grace_seconds": grace_seconds
    }


def get_device_provisioning_grace(device_name):
    grace_info = config.get("provisioning_grace_devices", {}).get(device_name, {})

    if not grace_info:
        return {}

    until_text = grace_info.get("until", "")
    until_dt = parse_timestamp(until_text)

    if not until_dt:
        return {}

    current_time = datetime.now()

    if current_time >= until_dt:
        return {}

    remaining_seconds = max(0, int((until_dt - current_time).total_seconds()))

    return {
        "state": get_provisioning_state_label(),
        "start": grace_info.get("start", ""),
        "until": until_text,
        "remaining_seconds": remaining_seconds,
        "grace_seconds": grace_info.get("grace_seconds", get_provisioning_grace_seconds())
    }


def is_device_in_provisioning_grace(device_name):
    return bool(get_device_provisioning_grace(device_name))


def cleanup_expired_provisioning_grace():
    changed = False

    for device_name in list(config.get("provisioning_grace_devices", {}).keys()):
        grace_info = config.get("provisioning_grace_devices", {}).get(device_name, {})
        until_dt = parse_timestamp(grace_info.get("until", ""))

        if not until_dt or datetime.now() >= until_dt:
            config.get("provisioning_grace_devices", {}).pop(device_name, None)
            changed = True

    return changed


def get_provisioning_host_candidates():
    candidates = []

    for device_name, ip_address in DEVICES.items():
        device_type = clean_ascii(DEVICE_TYPES.get(device_name, "")).lower()
        name_text = clean_ascii(device_name).lower()

        if device_name in INFRASTRUCTURE.values():
            continue

        if "virtual" in device_type or "vm" in device_type:
            continue

        if any(keyword in device_type for keyword in ["internet", "modem", "router", "switch", "firewall", "access point", "ups"]):
            continue

        # Phase 10E.9a:
        # Any real physical endpoint can be a VM host if it is not infrastructure or another VM.
        host_keywords = [
            "server", "host", "windows", "pc", "desktop", "workstation",
            "omv", "terminal", "nas", "linux", "ubuntu", "mac"
        ]

        if any(keyword in device_type for keyword in host_keywords) or any(keyword in name_text for keyword in host_keywords):
            port_info = get_switch_port_for_device(device_name)

            candidates.append({
                "name": device_name,
                "ip": ip_address,
                "type": DEVICE_TYPES.get(device_name, "Unknown"),
                "switch_port": port_info.get("label", "No physical switch port"),
                "switch_port_index": port_info.get("index", ""),
                "eligible": True
            })

    return sorted(candidates, key=lambda item: item.get("name", "").lower())



def get_provisioning_summary():
    physical_count = 0
    virtual_count = 0
    infrastructure_count = 0

    for device_name in DEVICES.keys():
        device_type = clean_ascii(DEVICE_TYPES.get(device_name, "")).lower()

        if device_name in INFRASTRUCTURE.values():
            infrastructure_count += 1
        elif "virtual" in device_type or "vm" in device_type:
            virtual_count += 1
        else:
            physical_count += 1

    host_candidates = get_provisioning_host_candidates()
    available_ports = get_available_ports()

    architecture_score = 100

    if len(host_candidates) == 0:
        architecture_score -= 15

    if len(available_ports) == 0:
        architecture_score -= 10

    if virtual_count > 0 and len(host_candidates) == 0:
        architecture_score -= 20

    if infrastructure_count < 4:
        architecture_score -= 10

    if len(get_reserved_provisioning_ips()) == 0:
        architecture_score -= 5

    architecture_score = max(0, min(100, architecture_score))

    if architecture_score >= 95:
        architecture_label = "Excellent"
    elif architecture_score >= 85:
        architecture_label = "Strong"
    elif architecture_score >= 70:
        architecture_label = "Good"
    else:
        architecture_label = "Needs Review"

    return {
        "physical": physical_count,
        "virtual": virtual_count,
        "infrastructure": infrastructure_count,
        "available_ports": len(available_ports),
        "host_candidates": len(host_candidates),
        "architecture_score": architecture_score,
        "architecture_label": architecture_label,
        "reserved_ips": len(get_reserved_provisioning_ips())
    }


def normalize_provisioning_type(value):
    value = clean_ascii(value).lower()

    if value in ["virtual", "virtual_machine", "vm"]:
        return "virtual"

    if value in ["infrastructure", "infra"]:
        return "infrastructure"

    return "physical"


def provisioning_redirect(status_value, message_value, device_name="", ip_address="", device_type="", connection=""):
    return redirect(
        url_for(
            "provisioning_page",
            provision_status=clean_ascii(status_value),
            provision_message=clean_ascii(message_value),
            provision_device=clean_ascii(device_name),
            provision_ip=clean_ascii(ip_address),
            provision_type=clean_ascii(device_type),
            provision_connection=clean_ascii(connection)
        )
    )


def load_provisioning_audit():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(PROVISIONING_AUDIT_FILE):
        with open(PROVISIONING_AUDIT_FILE, "w") as f:
            json.dump([], f, indent=4)
        return []

    try:
        with open(PROVISIONING_AUDIT_FILE, "r") as f:
            audit = json.load(f)
        return audit if isinstance(audit, list) else []
    except Exception as e:
        write_event(f"ERROR | PROVISIONING AUDIT LOAD FAILED | {e}")
        return []


def save_provisioning_audit(audit):
    os.makedirs("data", exist_ok=True)
    with open(PROVISIONING_AUDIT_FILE, "w") as f:
        json.dump(audit[-500:], f, indent=4)


def write_provisioning_audit(action, status_value, device_name, ip_address, details):
    audit = load_provisioning_audit()
    audit.append({
        "time": now(),
        "actor": "ON WATCH USER",
        "action": clean_ascii(action),
        "status": clean_ascii(status_value),
        "device": clean_ascii(device_name),
        "ip": clean_ascii(ip_address),
        "details": clean_ascii(details)
    })
    save_provisioning_audit(audit)









# PHASE 12B.4 - ROOT CAUSE CORRELATION ENGINE
def build_root_cause_correlation_engine(active_alerts=None):
    if active_alerts is None:
        active_alerts = get_active_alerts()

    def safe(value, default=""):
        cleaned = clean_ascii(value)
        return cleaned if cleaned else default

    def base_device_name(value):
        text = safe(value)
        if "(" in text and ")" in text:
            return safe(text.split("(")[0])
        return text

    def extract_port(value):
        text = safe(value)
        match = re.search(r"(Gi\d+/\d+/\d+|Gi\d+/\d+|Fa\d+/\d+/\d+|Fa\d+/\d+)", text)
        if match:
            return match.group(1)
        return ""

    def result(
        state,
        root_cause,
        affected_device="",
        affected_port="",
        root_type="",
        confidence="0%",
        operator_action="No action required.",
        affected_devices=None,
        suppressed_alerts=None,
        selected_alert=None
    ):
        affected_devices = affected_devices or []
        suppressed_alerts = suppressed_alerts or []
        selected_alert = selected_alert or {}

        return {
            "enabled": True,
            "phase": "12B.4",
            "state": safe(state, "Healthy"),
            "root_cause": safe(root_cause, "No active root cause"),
            "root_type": safe(root_type, "None"),
            "affected_device": safe(affected_device, "None"),
            "affected_port": safe(affected_port, "None"),
            "affected_devices": affected_devices,
            "affected_devices_count": len(affected_devices),
            "suppressed_alerts": suppressed_alerts,
            "suppressed_alerts_count": len(suppressed_alerts),
            "confidence": safe(confidence, "100%"),
            "operator_action": safe(operator_action, "No action required."),
            "selected_alert_id": safe(selected_alert.get("id", "")),
            "selected_alert_severity": safe(selected_alert.get("severity", "INFO")).upper(),
            "selected_alert_problem": safe(selected_alert.get("problem", "")),
            "last_updated": now()
        }

    if not active_alerts:
        return result(
            "Healthy",
            "No active root cause",
            confidence="100%",
            operator_action="No action required. On Watch is not detecting an active alert.",
            root_type="Healthy"
        )

    severity_rank = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    sorted_alerts = sorted(
        active_alerts,
        key=lambda item: severity_rank.get(item.get("severity", "INFO"), 3)
    )

    selected_alert = sorted_alerts[0]
    selected_device = safe(selected_alert.get("device", "Unknown Device"))
    selected_problem = safe(selected_alert.get("problem", "Unknown problem"))
    selected_text = f"{selected_device} {selected_problem} {safe(selected_alert.get('device_type', ''))}".lower()

    # 1) Internet root cause overrides downstream noise.
    internet_name = get_infrastructure_name("internet")
    internet_state = status.get(internet_name, {}).get("state")
    internet_alerts = [
        alert for alert in active_alerts
        if base_device_name(alert.get("device", "")) == internet_name or "internet" in f"{alert.get('device','')} {alert.get('problem','')}".lower() or "cox link" in f"{alert.get('device','')} {alert.get('problem','')}".lower()
    ]

    if internet_state == "DOWN" or internet_alerts:
        affected = []
        for name, info in status.items():
            if name == internet_name:
                continue
            if info.get("state") in ["DOWN", "ERROR", "UNKNOWN", "TESTING"]:
                affected.append(name)

        suppressed = [
            safe(alert.get("device", "Unknown"))
            for alert in active_alerts
            if base_device_name(alert.get("device", "")) != internet_name
        ]

        return result(
            "Root Cause Detected",
            internet_name,
            affected_device=", ".join(affected[:3]) if affected else "Network path",
            affected_port="WAN / Internet",
            root_type="Internet / ISP",
            confidence="98%" if internet_state == "DOWN" else "90%",
            operator_action="Troubleshoot the internet link first before checking endpoints.",
            affected_devices=affected,
            suppressed_alerts=suppressed,
            selected_alert=internet_alerts[0] if internet_alerts else selected_alert
        )

    # 2) Phase 13C.4 - Physical link root cause before blaming the downstream device.
    physical_root = find_active_physical_link_root_cause(active_alerts)
    if physical_root:
        affected_device = safe(physical_root.get("affected_device", "Downstream device"))
        affected = [affected_device] if affected_device else []
        for name, info in status.items():
            if name == affected_device:
                continue
            if info.get("state") in ["DOWN", "ERROR", "UNKNOWN", "TESTING"]:
                affected.append(name)

        suppressed = [
            safe(alert.get("device", "Unknown"))
            for alert in active_alerts
            if affected_device and affected_device.lower() in f"{alert.get('device','')} {alert.get('problem','')}".lower()
        ]

        return result(
            "Root Cause Detected",
            f"Switch Port {physical_root.get('port')}",
            affected_device=affected_device,
            affected_port=physical_root.get("port", "Unknown port"),
            root_type="Physical Switch Port",
            confidence="99%",
            operator_action=physical_root.get("recommended_action", "Check the affected switch port and Ethernet path."),
            affected_devices=affected,
            suppressed_alerts=suppressed,
            selected_alert=selected_alert
        )

    # 3) Core infrastructure root causes.
    infrastructure_order = []
    role_actions = {
        "Modem": ("Modem / Gateway", "Check modem power and physical handoff before troubleshooting downstream devices."),
        "Firewall": ("Firewall", "Troubleshoot the firewall and its upstream/downstream interfaces first."),
        "Router": ("Router", "Troubleshoot the router first. Downstream alerts may be symptoms."),
        "Switch": ("Switch", "Troubleshoot the switch first. Wired endpoint alerts may be downstream symptoms."),
    }
    for role, (root_type, action) in role_actions.items():
        infrastructure_order.extend((name, root_type, action) for name in get_infrastructure_names_by_role(role))

    for infra_name, root_type, action in infrastructure_order:
        infra_state = status.get(infra_name, {}).get("state")
        infra_alerts = [
            alert for alert in active_alerts
            if base_device_name(alert.get("device", "")) == infra_name or infra_name.lower() in f"{alert.get('device','')} {alert.get('problem','')}".lower()
        ]

        if infra_state == "DOWN" or infra_alerts:
            affected = []
            for name, info in status.items():
                if name == infra_name:
                    continue
                if info.get("state") in ["DOWN", "ERROR", "UNKNOWN", "TESTING"]:
                    affected.append(name)

            suppressed = [
                safe(alert.get("device", "Unknown"))
                for alert in active_alerts
                if base_device_name(alert.get("device", "")) != infra_name
            ]

            return result(
                "Root Cause Detected",
                infra_name,
                affected_device=", ".join(affected[:3]) if affected else "Downstream network",
                affected_port=root_type,
                root_type=root_type,
                confidence="95%",
                operator_action=action,
                affected_devices=affected,
                suppressed_alerts=suppressed,
                selected_alert=infra_alerts[0] if infra_alerts else selected_alert
            )

    # 3) Router monitored interface root cause.
    for idx, iface in router_interfaces.items():
        if iface.get("state") == "DOWN":
            port_name = safe(iface.get("short_name", iface.get("name", idx)))
            affected = [safe(alert.get("device", "Unknown")) for alert in active_alerts]
            return result(
                "Root Cause Detected",
                f"Router Interface {port_name}",
                affected_device=", ".join(affected[:3]) if affected else "Router path",
                affected_port=port_name,
                root_type="Router Interface",
                confidence="96%",
                operator_action=f"Check the cable and connected device on router interface {port_name}.",
                affected_devices=affected,
                suppressed_alerts=[],
                selected_alert=selected_alert
            )

    # 4) Physical switch port root cause.
    switch_link_alerts = []
    for alert in active_alerts:
        text = f"{alert.get('device','')} {alert.get('problem','')}".lower()
        if "switch link" in text or "gi" in text or "fa" in text:
            switch_link_alerts.append(alert)

    if switch_link_alerts:
        alert = switch_link_alerts[0]
        endpoint_label = safe(alert.get("device", "Unknown"))
        affected_device = base_device_name(endpoint_label)
        affected_port = extract_port(endpoint_label)

        if not affected_port:
            for idx, link in switch_links.items():
                if base_device_name(link.get("device", "")) == affected_device and link.get("state") == "DOWN":
                    affected_port = safe(link.get("port", idx))
                    break

        root_cause = f"Switch Port {affected_port}" if affected_port else "Switch Port"
        operator_action = (
            f"Locate {affected_port} on the Cisco switch, reseat the Ethernet cable, and verify {affected_device} is powered on."
            if affected_port and affected_device
            else "Check the affected switch port, Ethernet cable, adapter, and endpoint power."
        )

        suppressed = [
            safe(other.get("device", "Unknown"))
            for other in active_alerts
            if other.get("id") != alert.get("id") and base_device_name(other.get("device", "")) == affected_device
        ]

        return result(
            "Root Cause Detected",
            root_cause,
            affected_device=affected_device,
            affected_port=affected_port or "Unknown port",
            root_type="Physical Switch Port",
            confidence="98%" if affected_port else "88%",
            operator_action=operator_action,
            affected_devices=[affected_device] if affected_device else [],
            suppressed_alerts=suppressed,
            selected_alert=alert
        )

    # 5) Endpoint root cause.
    affected_device = base_device_name(selected_device)
    affected_port = extract_port(selected_device)

    if not affected_port and affected_device:
        for idx, link in switch_links.items():
            if base_device_name(link.get("device", "")) == affected_device:
                affected_port = safe(link.get("port", idx))
                break

    return result(
        "Single Device Issue",
        affected_device,
        affected_device=affected_device,
        affected_port=affected_port or "No switch port matched",
        root_type="Endpoint",
        confidence="82%",
        operator_action=f"Check {affected_device} power, sleep state, Ethernet cable, and network adapter.",
        affected_devices=[affected_device] if affected_device else [],
        suppressed_alerts=[],
        selected_alert=selected_alert
    )



# PHASE 12B.5 - UNIFIED INCIDENT PRESENTATION ENGINE
def build_unified_incident_engine(active_alerts=None):
    """
    Creates one normalized incident object used by all dashboard layers.

    Purpose:
    - Present the same primary incident wording across the EOC, NOC Command Center,
      Guided Diagnostic Engine, Root Cause Correlation Engine, and NOC Intelligence.
    - Avoid showing the same event with conflicting labels.
    - Keep root cause, affected device, affected port, severity, likely cause,
      operator action, and simple instructions together as one incident record.
    """

    if active_alerts is None:
        active_alerts = get_active_alerts()

    def safe(value, default=""):
        cleaned = clean_ascii(value)
        return cleaned if cleaned else default

    def base_device_name(value):
        text = safe(value)
        if "(" in text and ")" in text:
            return safe(text.split("(")[0])
        return text

    def normalize_severity(value):
        value = safe(value, "INFO").upper()
        if value not in ["CRITICAL", "WARNING", "INFO"]:
            value = "INFO"
        return value

    def simple_steps(root_type, primary_title, affected_device, affected_port):
        root_type = safe(root_type)
        affected_device = safe(affected_device)
        affected_port = safe(affected_port)

        if root_type == "Physical Switch Port":
            return [
                f"Locate {affected_port} on the Cisco switch." if affected_port and affected_port != "None" else "Locate the affected switch port.",
                "Make sure the Ethernet cable is clicked in tightly on the switch side.",
                f"Check the cable, adapter, and power on {affected_device}." if affected_device and affected_device != "None" else "Check the cable, adapter, and endpoint power.",
                "If this is a Mac, laptop, or Chromebook, wake the device and reconnect the adapter if needed.",
                "Refresh On Watch after 1 to 2 minutes."
            ]

        if root_type in ["Internet / ISP", "Modem / Gateway"]:
            return [
                "Check the modem power and online lights.",
                "Make sure the coax and Ethernet cables are tight.",
                "Restart the modem by unplugging power for 30 seconds, then plug it back in.",
                "Wait about 5 minutes for the modem to reconnect.",
                "If still offline, check the ISP app for an outage."
            ]

        if root_type in ["Router", "Router Interface"]:
            return [
                "Check the Cisco router power and link lights.",
                "Verify the connected Ethernet cable is seated tightly.",
                "Check the connected modem or switch side of the same cable.",
                "Refresh On Watch after 1 to 2 minutes.",
                "If the router is still down, review router logs or restart during a safe maintenance window."
            ]

        if root_type == "Switch":
            return [
                "Check the Cisco switch power and uplink lights.",
                "Verify the uplink cable between the router and switch is seated tightly.",
                "Check whether multiple wired devices are affected.",
                "Refresh On Watch after 1 to 2 minutes.",
                "If needed, restart the switch during a safe maintenance window."
            ]

        if root_type == "Endpoint":
            return [
                f"Check whether {affected_device} is powered on." if affected_device and affected_device != "None" else "Check whether the affected device is powered on.",
                "Wake the device if it is a laptop, Mac, or Chromebook.",
                "Check the Ethernet cable or USB-C Ethernet adapter.",
                "Verify the device is connected to the correct network.",
                "Refresh On Watch after 1 to 2 minutes."
            ]

        return ["No action required."]

    if not active_alerts:
        return {
            "enabled": True,
            "phase": "12B.5",
            "status": "Healthy",
            "severity": "INFO",
            "primary_title": "No active incident",
            "incident_label": "No Active Incident",
            "incident_type": "Healthy",
            "root_cause": "No active root cause",
            "root_type": "Healthy",
            "affected_device": "None",
            "affected_port": "None",
            "likely_cause": "System healthy",
            "operator_action": "No action required.",
            "summary": "No active incident detected. On Watch is tracking the network normally.",
            "guidance": "No operator action required.",
            "active_alert_count": 0,
            "affected_devices_count": 0,
            "suppressed_alerts_count": 0,
            "confidence": "100%",
            "instructions": ["No action required."],
            "last_updated": now()
        }

    root = build_root_cause_correlation_engine(active_alerts)

    severity_rank = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    selected_alert = sorted(
        active_alerts,
        key=lambda item: severity_rank.get(item.get("severity", "INFO"), 3)
    )[0]

    selected_device = safe(selected_alert.get("device", "Unknown Device"))
    selected_problem = safe(selected_alert.get("problem", "Unknown problem"))
    severity = normalize_severity(root.get("selected_alert_severity") or selected_alert.get("severity", "INFO"))

    root_type = safe(root.get("root_type", "Endpoint"), "Endpoint")
    root_cause = safe(root.get("root_cause", selected_device), selected_device)
    affected_device = safe(root.get("affected_device", base_device_name(selected_device)), base_device_name(selected_device))
    affected_port = safe(root.get("affected_port", "None"), "None")
    confidence = safe(root.get("confidence", "80%"), "80%")
    operator_action = safe(root.get("operator_action", "Review the affected device or link."), "Review the affected device or link.")

    primary_title = root_cause
    incident_type = root_type
    likely_cause = "The device may be offline, asleep, powered off, or disconnected."

    if root_type == "Physical Switch Port":
        primary_title = f"Switch Port {affected_port} Link Down" if affected_port and affected_port != "None" else "Switch Port Link Down"
        incident_type = "Switch Port / Cable Down"
        likely_cause = "The Ethernet cable, network adapter, switch port, or connected device may be unplugged, asleep, or powered off."

    elif root_type == "Internet / ISP":
        primary_title = f"{affected_device or get_internet_service_name() or 'Internet service'} Down"
        incident_type = "Internet / ISP Outage"
        likely_cause = "The internet service, modem, or outside internet path may be unavailable."

    elif root_type == "Modem / Gateway":
        primary_title = f"{affected_device or 'Modem / Gateway'} Down"
        incident_type = "Modem / Gateway Problem"
        likely_cause = "The modem may be offline, rebooting, disconnected, or not responding."

    elif root_type == "Router":
        primary_title = f"{affected_device or 'Router'} Down"
        incident_type = "Router Problem"
        likely_cause = "The router, router power, or router uplink may be unavailable."

    elif root_type == "Router Interface":
        primary_title = f"Router Interface {affected_port} Down" if affected_port and affected_port != "None" else "Router Interface Down"
        incident_type = "Router Interface Down"
        likely_cause = "The router interface cable or connected device may be disconnected."

    elif root_type == "Switch":
        primary_title = f"{affected_device or 'Switch'} Down"
        incident_type = "Switch Problem"
        likely_cause = "The switch, switch power, or uplink may be unavailable."

    elif root_type == "Endpoint":
        primary_title = f"{affected_device} Device Issue" if affected_device and affected_device != "None" else f"{selected_device}: {selected_problem}"
        incident_type = "Endpoint Issue"
        likely_cause = "The endpoint may be asleep, powered off, unplugged, or disconnected from the network."

    active_count = len(active_alerts)
    affected_count = int(root.get("affected_devices_count", 0) or 0)
    suppressed_count = int(root.get("suppressed_alerts_count", 0) or 0)

    summary = (
        f"{primary_title}. Affected device: {affected_device}."
        if affected_device and affected_device != "None"
        else f"{primary_title}."
    )

    if affected_port and affected_port != "None":
        summary += f" Affected path: {affected_port}."

    guidance = operator_action
    instructions = simple_steps(root_type, primary_title, affected_device, affected_port)

    return {
        "enabled": True,
        "phase": "12B.5",
        "status": "Incident Active" if active_count else "Healthy",
        "severity": severity,
        "primary_title": safe(primary_title, "Active incident"),
        "incident_label": safe(incident_type, "Incident"),
        "incident_type": safe(incident_type, "Incident"),
        "root_cause": safe(root_cause, primary_title),
        "root_type": safe(root_type, "Endpoint"),
        "affected_device": safe(affected_device, "None"),
        "affected_port": safe(affected_port, "None"),
        "likely_cause": safe(likely_cause),
        "operator_action": safe(operator_action),
        "summary": safe(summary),
        "guidance": safe(guidance),
        "active_alert_count": active_count,
        "affected_devices_count": affected_count if affected_count else (1 if affected_device and affected_device != "None" else 0),
        "suppressed_alerts_count": suppressed_count,
        "confidence": confidence,
        "instructions": instructions,
        "last_updated": now()
    }


# PHASE 12B.3 - LIVE ALERT INTEGRATION ENGINE
def build_guided_diagnostic_engine():
    active_alerts = get_active_alerts()

    def clean_steps(steps):
        return [clean_ascii(step) for step in steps if clean_ascii(step)]

    def build_result(
        scenario,
        issue,
        likely_cause,
        confidence,
        instructions,
        severity="INFO",
        device="",
        problem="",
        active_alert_count=0,
        selected_alert_id="",
        selected_alert_time="",
        selected_alert_type="",
        live_status="No active alerts"
    ):
        return {
            "enabled": True,
            "phase": "12B.3",
            "title": "Guided Diagnostics",
            "scenario": clean_ascii(scenario),
            "issue": clean_ascii(issue),
            "likely_cause": clean_ascii(likely_cause),
            "confidence": clean_ascii(confidence),
            "instructions": clean_steps(instructions),
            "severity": clean_ascii(severity).upper() or "INFO",
            "device": clean_ascii(device),
            "problem": clean_ascii(problem),
            "active_alert_count": active_alert_count,
            "selected_alert_id": clean_ascii(selected_alert_id),
            "selected_alert_time": clean_ascii(selected_alert_time),
            "selected_alert_type": clean_ascii(selected_alert_type),
            "live_status": clean_ascii(live_status),
            "last_updated": now()
        }

    if not active_alerts:
        return build_result(
            "Healthy",
            "No active issue",
            "System healthy",
            "100%",
            ["No action required."],
            active_alert_count=0,
            live_status="Live alert feed connected - no active alerts"
        )

    severity_rank = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    alert = sorted(
        active_alerts,
        key=lambda item: severity_rank.get(item.get("severity", "INFO"), 3)
    )[0]

    device = clean_ascii(alert.get("device", "Unknown Device"))
    problem = clean_ascii(alert.get("problem", "Unknown problem"))
    severity = clean_ascii(alert.get("severity", "INFO")).upper()
    device_type = clean_ascii(alert.get("device_type", ""))
    alert_time = clean_ascii(alert.get("time", now()))
    alert_id_value = clean_ascii(alert.get("id", alert_id(device, problem)))

    issue = f"{device}: {problem}"
    text = f"{device} {problem} {device_type}".lower()

    scenario = "General Device Alert"
    likely_cause = "The device may be offline, asleep, powered off, or disconnected."
    confidence = "70%"
    instructions = [
        "Check if the device is powered on.",
        "If it is a laptop, Mac, or Chromebook, try waking it up.",
        "Check that the network cable or adapter is firmly connected.",
        "Refresh On Watch after 1 to 2 minutes."
    ]

    def set_result(name, cause, score, steps):
        return name, cause, score, steps

    if "maintenance" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Maintenance Active",
            "This device is intentionally in maintenance mode.",
            "95%",
            [
                "No troubleshooting is needed right now.",
                "Wait for the maintenance window to end.",
                "If maintenance was turned on by mistake, open Maintenance and end it.",
                "Refresh On Watch after maintenance is cleared."
            ]
        )

    elif "provision" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Provisioning Grace",
            "The device is newly added or being adjusted, so alerts are being softened temporarily.",
            "90%",
            [
                "Wait for the provisioning grace period to finish.",
                "Make sure the device name, IP address, and switch port are correct.",
                "Refresh On Watch after a few minutes.",
                "If it still shows a problem, check power and cable."
            ]
        )

    elif "internet" in text or "cox link" in text or "external internet" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            f"{affected_device or get_internet_service_name() or 'Internet service'} Down",
            "The internet service, modem, or outside internet path may be unavailable.",
            "90%",
            [
                "Look at the modem and make sure the power light is on.",
                "Check if the Online or Internet light is blinking or off.",
                "Unplug the modem power for 30 seconds, then plug it back in.",
                "Wait 5 minutes for the modem to fully reconnect.",
                "If still offline, check the ISP app for an outage."
            ]
        )

    elif "cox modem" in text or "modem" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Modem / Gateway Problem",
            "The modem may be offline, rebooting, not responding to ping, or disconnected.",
            "85%",
            [
                "Check that the modem power light is on.",
                "Make sure the coax cable and Ethernet cable are connected tightly.",
                "Restart the modem by unplugging it for 30 seconds.",
                "Wait 5 minutes, then refresh On Watch.",
                "If the modem lights look wrong, check the ISP app or contact ISP support."
            ]
        )

    elif "router interface" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Router Interface Down",
            "A monitored router interface is down or disconnected.",
            "85%",
            [
                "Check the cable connected to the Cisco router interface listed in the alert.",
                "Make sure the other end of the cable is plugged into the correct device.",
                "Do not restart everything unless multiple devices are affected.",
                "If the link stays down, contact the person who manages the router."
            ]
        )

    elif "router" in text or "cisco edge" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Router Offline",
            "The router may be offline, rebooting, or disconnected from the modem or switch.",
            "85%",
            [
                "Check that the Cisco router has power.",
                "Check the Ethernet cable from the modem to the Cisco router.",
                "Check the Ethernet cable from the Cisco router to the Cisco switch.",
                "Restart the router only if the power looks normal but it remains offline.",
                "Wait 3 minutes, then refresh On Watch."
            ]
        )

    elif "switch link" in text or "gi1/" in text or "gi0/" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Switch Port / Cable Down",
            "The cable, network adapter, or connected device may be unplugged or powered off.",
            "80%",
            [
                "Find the device listed in the alert.",
                "Check that the Ethernet cable is clicked in tightly on both ends.",
                "If the device uses a USB-C Ethernet adapter, unplug the adapter and plug it back in.",
                "Wake the device if it is a laptop, Mac, or Chromebook.",
                "Refresh On Watch after 1 to 2 minutes."
            ]
        )

    elif "switch" in text or "cisco main" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Switch Offline",
            "The main switch may be powered off or disconnected from the router.",
            "85%",
            [
                "Check that the Cisco switch has power.",
                "Check the cable between the router and switch.",
                "If multiple wired devices are offline, the switch may be the cause.",
                "Restart the switch only if needed.",
                "Wait 2 minutes, then refresh On Watch."
            ]
        )

    elif "omv" in text or "file server" in text or "server / nas" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "File Server Offline",
            "The OMV file server may be powered off, disconnected, or rebooting.",
            "85%",
            [
                "Check that the file server is powered on.",
                "Check the Ethernet cable going to the file server.",
                "Look for drive or power lights on the server.",
                "If safe, restart the server.",
                "Refresh On Watch after 3 to 5 minutes."
            ]
        )

    elif "monitoring server" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Monitoring Server Issue",
            "The On Watch monitoring server may be offline or disconnected.",
            "90%",
            [
                "Check that the monitoring server has power.",
                "Check the Ethernet cable connected to the monitoring server.",
                "Restart the monitoring server if the dashboard stops responding.",
                "Wait 2 minutes, then reload the browser."
            ]
        )

    elif "terminal server" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Terminal Server Offline",
            "The terminal server may be powered off, rebooting, or disconnected.",
            "80%",
            [
                "Check that the terminal server is powered on.",
                "Check the network cable.",
                "Restart it only if it is not being used.",
                "Refresh On Watch after 2 to 3 minutes."
            ]
        )

    elif "chromebook" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Chromebook Offline or Sleeping",
            "The Chromebook is most likely asleep, powered off, or its USB-C Ethernet adapter disconnected.",
            "85%",
            [
                "Open the Chromebook lid.",
                "Press a key or the power button to wake it.",
                "Check the USB-C Ethernet adapter and make sure it is plugged in firmly.",
                "Make sure the Ethernet cable is connected to the adapter.",
                "Refresh On Watch after 1 to 2 minutes."
            ]
        )

    elif "mac" in text or "macbook" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Mac Offline or Sleeping",
            "The Mac may be asleep, powered off, disconnected from Ethernet, or the adapter may be unplugged.",
            "82%",
            [
                "Move the mouse or press a key to wake the Mac.",
                "Check that the Mac is powered on.",
                "Check the Ethernet cable or USB-C Ethernet adapter.",
                "If needed, restart the Mac.",
                "Refresh On Watch after it reconnects."
            ]
        )

    elif "laptop" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Laptop Offline or Sleeping",
            "The laptop may be sleeping, shut down, unplugged, or disconnected from the network.",
            "82%",
            [
                "Open the laptop lid.",
                "Press a key or power button to wake it.",
                "Check that the charger is connected if the battery may be dead.",
                "Check the network cable or adapter.",
                "Refresh On Watch after 1 to 2 minutes."
            ]
        )

    elif "desktop" in text or "windows" in text or "pc" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Desktop Offline",
            "The desktop may be powered off, sleeping, disconnected, or shut down for the day.",
            "80%",
            [
                "Check if the desktop computer is powered on.",
                "Check the monitor and keyboard to see if it is asleep.",
                "Make sure the Ethernet cable is connected.",
                "Restart the computer if needed.",
                "Refresh On Watch after it boots up."
            ]
        )

    elif "printer" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Printer Offline",
            "The printer may be asleep, powered off, or disconnected from the network.",
            "75%",
            [
                "Check that the printer has power.",
                "Press the power or home button to wake it.",
                "Restart the printer if it does not respond.",
                "Wait 1 minute.",
                "Refresh On Watch."
            ]
        )

    elif "multiple" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "Multiple Devices Offline",
            "This may be an upstream issue with the modem, router, switch, or power.",
            "88%",
            [
                "Check the modem first.",
                "Check the Cisco router second.",
                "Check the Cisco switch third.",
                "If many devices are down, do not troubleshoot one laptop first.",
                "Fix the upstream device before checking individual devices."
            ]
        )

    elif "latency" in text or "slow" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "High Latency",
            "The device or internet path may be slow or overloaded.",
            "70%",
            [
                "Check if anyone is downloading, streaming, or backing up large files.",
                "Restart the affected device if only one device is slow.",
                "If all devices are slow, restart the modem and router.",
                "Wait 5 minutes.",
                "Refresh On Watch."
            ]
        )

    elif "dns" in text:
        scenario, likely_cause, confidence, instructions = set_result(
            "DNS Problem",
            "Name lookup may not be working.",
            "75%",
            [
                "Try opening a common website from a computer.",
                "If websites do not load but internet is connected, restart the modem and router.",
                "Wait 5 minutes.",
                "Refresh On Watch."
            ]
        )

    live_status = f"Live alert feed connected - diagnosing {severity} alert"
    return build_result(
        scenario,
        issue,
        likely_cause,
        confidence,
        instructions,
        severity=severity,
        device=device,
        problem=problem,
        active_alert_count=len(active_alerts),
        selected_alert_id=alert_id_value,
        selected_alert_time=alert_time,
        selected_alert_type=device_type,
        live_status=live_status
    )


def build_dashboard_context():
    refresh_runtime_data()

    total = len(status)
    up = sum(1 for d in status.values() if d["state"] == "UP")
    maintenance_count = sum(1 for d in status.values() if d["state"] == get_maintenance_state_label())
    provisioning_count = sum(1 for d in status.values() if d["state"] == get_provisioning_state_label())
    sleeping_count = sum(1 for d in status.values() if d["state"] == get_sleep_status_label())
    down = sum(1 for d in status.values() if d["state"] == "DOWN")
    error = sum(1 for d in status.values() if d["state"] == "ERROR")
    health = round(((up + maintenance_count + provisioning_count + sleeping_count) / total) * 100) if total > 0 else 0

    switch_up = sum(1 for d in switch_links.values() if d["state"] == "UP")
    switch_down = sum(1 for d in switch_links.values() if d["state"] == "DOWN")

    router_up = sum(1 for d in router_interfaces.values() if d["state"] == "UP")
    router_down = sum(1 for d in router_interfaces.values() if d["state"] == "DOWN")
    network_intelligence = build_network_intelligence()
    network_intelligence_html = build_network_intelligence_html(network_intelligence)
    phase10c = build_phase10c_predictive_intelligence(network_intelligence)
    phase10c_html = build_phase10c_html(phase10c)
    lan_internet_health = build_lan_internet_health_split()
    device_classification = build_device_classification_engine()
    device_classification_html = build_device_classification_html(device_classification)
    sleep_detection = build_sleep_detection_engine()
    sleep_detection_html = build_sleep_detection_html(sleep_detection)
    noc_correlation = build_noc_correlation_engine()
    noc_correlation_html = build_noc_correlation_html(noc_correlation)
    unified_incident = build_unified_incident_engine()
    service_impact = build_service_impact_awareness()
    service_impact_drilldown = build_service_impact_drilldown(service_impact)
    dependency_visualization = build_dependency_visualization(service_impact_drilldown)
    phase14_dependency_engine = build_phase14_dependency_engine(service_impact)
    phase14_device_dependency_lookup = build_phase14_device_dependency_lookup(phase14_dependency_engine)

    return dict(
        alerts=get_active_alerts(),
        status=status,
        diagnosis=diagnose_network(),
        last_full_scan=last_full_scan,
        up=up,
        down=down,
        error=error,
        total=total,
        health=health,
        uptime_stats=get_uptime_dashboard_stats(),
        availability_report=get_internet_availability_report(),
        network_intelligence=network_intelligence,
        network_intelligence_html=network_intelligence_html,
        phase10c=phase10c,
        phase10c_html=phase10c_html,
        lan_internet_health=lan_internet_health,
        device_classification=device_classification,
        device_classification_html=device_classification_html,
        sleep_detection=sleep_detection,
        sleep_detection_html=sleep_detection_html,
        noc_correlation=noc_correlation,
        noc_correlation_html=noc_correlation_html,
        unified_incident=unified_incident,
        service_impact=service_impact,
        service_impact_drilldown=service_impact_drilldown,
        dependency_visualization=dependency_visualization,
        phase14_dependency_engine=phase14_dependency_engine,
        phase14_device_dependency_lookup=phase14_device_dependency_lookup,
        topology_editor=build_topology_editor_payload(),
        dynamic_physical_topology=build_dynamic_physical_topology_data(),
        recent_internet_history=get_recent_internet_history(),
        total_alerts=total_alerts,
        total_recoveries=total_recoveries,
        recent_events=read_recent_events(),
        cisco_events=read_cisco_events(),
        router_interfaces=router_interfaces,
        all_router_interfaces=get_all_router_interfaces(),
        router_monitored_interfaces=ROUTER_MONITORED_INTERFACES,
        switch_links=switch_links,
        switch_up=switch_up,
        switch_down=switch_down,
        router_up=router_up,
        router_down=router_down,
        available_ports=get_available_ports(),
        provisioning_hosts=get_provisioning_host_candidates(),
        provisioning_summary=get_provisioning_summary(),
        infrastructure_registry=build_infrastructure_registry_summary(),
        provision_status=request.args.get("provision_status", ""),
        provision_message=request.args.get("provision_message", ""),
        provision_device=request.args.get("provision_device", ""),
        provision_ip=request.args.get("provision_ip", ""),
        provision_type=request.args.get("provision_type", ""),
        provision_connection=request.args.get("provision_connection", ""),
        provisioning_reserved_ips=get_reserved_provisioning_ips(),
        maintenance_summary=build_maintenance_summary(),
        scheduled_maintenance=build_scheduled_maintenance_summary(),
        noc_command_center=build_noc_command_center(),
        executive_operations_center=build_executive_operations_center(),
        noc_tools_center=build_noc_tools_center(),
        operations_layer=build_operations_layer_summary(),
        guided_diagnostic_engine=build_guided_diagnostic_engine(),
        root_cause_correlation=build_root_cause_correlation_engine(),
        noc_recommendations=build_noc_recommendations(),
        noc_historical=build_noc_historical_intelligence(),
        lifecycle_summary=build_lifecycle_summary(),
        device_types=DEVICE_TYPES,
        device_relationships=DEVICE_RELATIONSHIPS,
        all_devices=DEVICES,
        all_switch_ports=SWITCH_PORTS,
        managed_ports=get_selectable_switch_ports()
    )






# ======================================================
# PHASE 16A.6A - NOC TOOLS CENTER
# Safe read-only diagnostics + metadata-based SSH launch
# ======================================================
def sanitize_noc_target(value):
    """Allow only simple hostnames, FQDNs, IPv4, IPv6, dash, dot, colon."""
    value = clean_ascii(value).strip()
    if not value:
        return ""
    if len(value) > 255:
        return ""
    if not re.match(r"^[A-Za-z0-9_.:-]+$", value):
        return ""
    return value


def get_noc_tools_settings():
    load_config()
    defaults = {
        "enabled": True,
        "phase": "16A.6A",
        "title": "NOC Tools Center",
        "safe_mode": True,
        "command_timeout_seconds": 12,
        "max_output_chars": 12000,
        "allowed_tools": ["ping", "traceroute", "dns_lookup", "reverse_dns"],
        "ssh_launch_enabled": True,
        "copy_command_enabled": True
    }
    settings = config.get("noc_tools_center", {})
    if isinstance(settings, dict):
        defaults.update(settings)
    return defaults


def resolve_device_ssh_profile(device_name):
    """Build SSH launch metadata from global defaults and per-device overrides."""
    load_config()
    device_name = clean_ascii(device_name)
    ip_address = clean_ascii(DEVICES.get(device_name, ""))
    global_defaults = config.get("global_ssh_defaults", {}) if isinstance(config.get("global_ssh_defaults", {}), dict) else {}
    metadata_all = config.get("device_metadata", {}) if isinstance(config.get("device_metadata", {}), dict) else {}
    metadata = metadata_all.get(device_name, {}) if isinstance(metadata_all.get(device_name, {}), dict) else {}

    ssh_enabled = bool(metadata.get("ssh_enabled", False)) and bool(global_defaults.get("enabled", True))
    ssh_user = clean_ascii(metadata.get("ssh_user_override", "")) or clean_ascii(global_defaults.get("ssh_user", "root")) or "root"
    ssh_port = clean_ascii(str(metadata.get("ssh_port_override", ""))) or clean_ascii(str(global_defaults.get("ssh_port", 22))) or "22"
    key_path = clean_ascii(global_defaults.get("key_path", ""))

    command_parts = ["ssh"]
    if ssh_port and ssh_port != "22":
        command_parts.extend(["-p", ssh_port])
    if key_path:
        # Display only. The dashboard does not execute SSH.
        command_parts.extend(["-i", key_path])
    if ip_address:
        command_parts.append(f"{ssh_user}@{ip_address}")
    ssh_command = " ".join(command_parts) if ip_address else ""

    return {
        "enabled": ssh_enabled,
        "device": device_name,
        "ip": ip_address,
        "ssh_user": ssh_user,
        "ssh_port": ssh_port,
        "key_path": key_path,
        "command": ssh_command,
        "launch_mode": "copy_and_launch_from_terminal",
        "note": "SSH is not executed in the browser. Copy this command into Terminal."
    }


def build_noc_tools_device_inventory():
    """Create dropdown inventory for the NOC Tools Center."""
    load_config()
    devices = []
    for device_name, ip_address in DEVICES.items():
        device_name = clean_ascii(device_name)
        ip_address = clean_ascii(ip_address)
        device_type = clean_ascii(DEVICE_TYPES.get(device_name, detect_map_device_type(device_name, ip_address)))
        status_info = status.get(device_name, {}) if isinstance(status.get(device_name, {}), dict) else {}
        ssh_profile = resolve_device_ssh_profile(device_name)
        devices.append({
            "name": device_name,
            "ip": ip_address,
            "type": device_type,
            "status": clean_ascii(status_info.get("state", "UNKNOWN")),
            "latency": clean_ascii(status_info.get("latency", "N/A")),
            "ssh_enabled": ssh_profile.get("enabled", False),
            "ssh_command": ssh_profile.get("command", ""),
            "ssh_user": ssh_profile.get("ssh_user", "root"),
            "ssh_port": ssh_profile.get("ssh_port", "22")
        })
    return sorted(devices, key=lambda item: (not item.get("ssh_enabled", False), item.get("name", "").lower()))


def build_noc_tools_center():
    settings = get_noc_tools_settings()
    devices = build_noc_tools_device_inventory()
    ssh_enabled_count = len([item for item in devices if item.get("ssh_enabled")])
    return {
        "enabled": settings.get("enabled", True),
        "phase": settings.get("phase", "16A.6A"),
        "title": settings.get("title", "NOC Tools Center"),
        "safe_mode": settings.get("safe_mode", True),
        "devices": devices,
        "allowed_tools": settings.get("allowed_tools", []),
        "summary": {
            "total_devices": len(devices),
            "ssh_enabled": ssh_enabled_count,
            "diagnostic_tools": len(settings.get("allowed_tools", [])),
            "last_updated": now()
        }
    }


def run_noc_tool(tool_name, target):
    """Run safe read-only diagnostics only. No shell=True is used."""
    settings = get_noc_tools_settings()
    allowed = set(settings.get("allowed_tools", []))
    tool_name = clean_ascii(tool_name).strip().lower()
    target = sanitize_noc_target(target)

    if tool_name not in allowed:
        return {"success": False, "error": "Tool is not allowed by NOC Tools Center safe mode.", "output": ""}
    if not target:
        return {"success": False, "error": "Invalid or empty target.", "output": ""}

    timeout = int(settings.get("command_timeout_seconds", 12))
    max_output = int(settings.get("max_output_chars", 12000))

    if tool_name == "ping":
        cmd = ["ping", "-c", "4", "-W", "2", target]
        label = "Ping"
    elif tool_name == "traceroute":
        traceroute_bin = shutil.which("traceroute") or shutil.which("tracepath")
        if not traceroute_bin:
            return {"success": False, "error": "traceroute/tracepath is not installed on this server.", "output": ""}
        cmd = [traceroute_bin, target]
        label = "Traceroute"
    elif tool_name == "dns_lookup":
        if shutil.which("dig"):
            cmd = ["dig", "+short", target]
        elif shutil.which("nslookup"):
            cmd = ["nslookup", target]
        else:
            return {"success": False, "error": "dig/nslookup is not installed on this server.", "output": ""}
        label = "DNS Lookup"
    elif tool_name == "reverse_dns":
        try:
            output = socket.gethostbyaddr(target)[0]
            return {
                "success": True,
                "tool": tool_name,
                "label": "Reverse DNS",
                "target": target,
                "command": f"socket.gethostbyaddr({target})",
                "output": output,
                "returncode": 0,
                "timestamp": now()
            }
        except Exception as exc:
            return {"success": False, "tool": tool_name, "label": "Reverse DNS", "target": target, "error": str(exc), "output": "", "timestamp": now()}
    else:
        return {"success": False, "error": "Unsupported tool.", "output": ""}

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        output = (completed.stdout or "") + (completed.stderr or "")
        if len(output) > max_output:
            output = output[:max_output] + "\n... output trimmed by NOC Tools Center safe mode ..."
        return {
            "success": completed.returncode == 0,
            "tool": tool_name,
            "label": label,
            "target": target,
            "command": " ".join(cmd),
            "output": output.strip() or "No output returned.",
            "returncode": completed.returncode,
            "timestamp": now()
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "tool": tool_name, "target": target, "error": f"Command timed out after {timeout} seconds.", "output": "", "timestamp": now()}
    except Exception as exc:
        return {"success": False, "tool": tool_name, "target": target, "error": str(exc), "output": "", "timestamp": now()}



# ======================================================
# PHASE 7D - NOC TOOLS SAFE READ-ONLY DISCOVERY HELPERS
# Tools added: Port Scan, ARP Table, MAC Address Table, Network Scan
# ======================================================
NOC_SAFE_PORTS = [22, 23, 53, 80, 123, 161, 443, 445, 3389, 5050]
NOC_SAFE_PORT_LABELS = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5050: "Dashboard"
}




# ======================================================
# IEEE REGISTRATION AUTHORITY MAC VENDOR LOOKUP
# ======================================================
# No manufacturer names are hard-coded. Vendor names come from locally cached
# copies of the official IEEE MA-L, MA-M, MA-S and IAB CSV registries.
IEEE_OUI_CACHE_DIR = os.path.join(PROJECT_DIR, "data", "ieee_oui")
IEEE_OUI_CACHE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
IEEE_OUI_DOWNLOAD_TIMEOUT_SECONDS = 25
IEEE_OUI_REGISTRIES = (
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", "oui.csv"),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", "mam.csv"),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", "oui36.csv"),
    ("IAB", "https://standards-oui.ieee.org/iab/iab.csv", "iab.csv"),
)
IEEE_OUI_LOCK = threading.RLock()
IEEE_OUI_INDEX = None
IEEE_OUI_INDEX_LOADED_AT = 0.0
IEEE_OUI_REFRESH_THREAD = None


def _mac_hex(value):
    """Return exactly 12 uppercase hexadecimal MAC characters or an empty string."""
    normalized = normalize_mac_address(value)
    compact = re.sub(r"[^0-9A-Fa-f]", "", normalized).upper()
    return compact if len(compact) == 12 else ""


def _atomic_write_bytes(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_path = path + ".tmp"
    with open(temporary_path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary_path, path)


def _download_ieee_registry(url, destination):
    request_object = urllib.request.Request(
        url,
        headers={"User-Agent": "On-Watch-Network-Monitor/Phase26"}
    )
    with urllib.request.urlopen(
        request_object,
        timeout=IEEE_OUI_DOWNLOAD_TIMEOUT_SECONDS
    ) as response:
        payload = response.read()

    # Reject error pages or unexpectedly small files so a good cache is never
    # replaced by a broken download.
    if len(payload) < 100 or b"Assignment" not in payload[:4096]:
        raise ValueError("Downloaded IEEE registry did not contain valid CSV data")

    _atomic_write_bytes(destination, payload)


def _ieee_cache_needs_refresh(path):
    try:
        return (time.time() - os.path.getmtime(path)) > IEEE_OUI_CACHE_MAX_AGE_SECONDS
    except OSError:
        return True


def refresh_ieee_oui_cache(force=False):
    """
    Download official IEEE registration CSV files into the local cache.

    Existing valid files remain untouched when a download fails. The function
    returns a status dictionary and never substitutes guessed vendor names.
    """
    os.makedirs(IEEE_OUI_CACHE_DIR, exist_ok=True)
    downloaded = []
    retained = []
    errors = []

    for registry_name, url, filename in IEEE_OUI_REGISTRIES:
        destination = os.path.join(IEEE_OUI_CACHE_DIR, filename)
        if not force and not _ieee_cache_needs_refresh(destination):
            retained.append(registry_name)
            continue
        try:
            _download_ieee_registry(url, destination)
            downloaded.append(registry_name)
        except Exception as exc:
            if os.path.exists(destination) and os.path.getsize(destination) > 100:
                retained.append(registry_name)
            errors.append(f"{registry_name}: {exc}")

    global IEEE_OUI_INDEX, IEEE_OUI_INDEX_LOADED_AT
    with IEEE_OUI_LOCK:
        IEEE_OUI_INDEX = None
        IEEE_OUI_INDEX_LOADED_AT = 0.0

    return {
        "success": bool(downloaded or retained),
        "downloaded": downloaded,
        "retained": retained,
        "errors": errors,
        "cache_directory": IEEE_OUI_CACHE_DIR
    }


def _refresh_ieee_oui_cache_background():
    global IEEE_OUI_REFRESH_THREAD
    try:
        refresh_ieee_oui_cache(force=False)
    finally:
        with IEEE_OUI_LOCK:
            IEEE_OUI_REFRESH_THREAD = None


def _schedule_ieee_oui_refresh_if_needed():
    global IEEE_OUI_REFRESH_THREAD
    needs_refresh = any(
        _ieee_cache_needs_refresh(os.path.join(IEEE_OUI_CACHE_DIR, filename))
        for _, _, filename in IEEE_OUI_REGISTRIES
    )
    if not needs_refresh:
        return

    with IEEE_OUI_LOCK:
        if IEEE_OUI_REFRESH_THREAD and IEEE_OUI_REFRESH_THREAD.is_alive():
            return
        IEEE_OUI_REFRESH_THREAD = threading.Thread(
            target=_refresh_ieee_oui_cache_background,
            name="ieee-oui-refresh",
            daemon=True
        )
        IEEE_OUI_REFRESH_THREAD.start()


def _parse_ieee_registry_file(path, registry_name):
    entries = {}
    if not os.path.exists(path):
        return entries

    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            assignment = re.sub(
                r"[^0-9A-Fa-f]",
                "",
                str(row.get("Assignment", ""))
            ).upper()
            organization = clean_ascii(
                row.get("Organization Name", "")
                or row.get("Organization", "")
            ).strip()
            if not assignment or not organization:
                continue
            entries[assignment] = {
                "vendor": organization,
                "source": f"IEEE {registry_name}",
                "prefix": assignment,
                "prefix_bits": len(assignment) * 4
            }
    return entries


def load_ieee_oui_index():
    """Load official cached IEEE assignments and return a longest-prefix index."""
    global IEEE_OUI_INDEX, IEEE_OUI_INDEX_LOADED_AT

    with IEEE_OUI_LOCK:
        if IEEE_OUI_INDEX is not None:
            return IEEE_OUI_INDEX

        index = {9: {}, 7: {}, 6: {}}
        for registry_name, _, filename in IEEE_OUI_REGISTRIES:
            path = os.path.join(IEEE_OUI_CACHE_DIR, filename)
            try:
                parsed = _parse_ieee_registry_file(path, registry_name)
            except Exception:
                parsed = {}
            for prefix, details in parsed.items():
                if len(prefix) in index:
                    index[len(prefix)][prefix] = details

        IEEE_OUI_INDEX = index
        IEEE_OUI_INDEX_LOADED_AT = time.time()

    _schedule_ieee_oui_refresh_if_needed()
    return IEEE_OUI_INDEX


def get_mac_vendor_info(mac_address):
    """
    Resolve a MAC using official IEEE registries with longest-prefix matching.

    MA-S/IAB (36-bit) is checked first, then MA-M (28-bit), then MA-L (24-bit).
    Locally administered and multicast addresses are classified from address
    bits rather than assigned a guessed manufacturer.
    """
    mac = normalize_mac_address(mac_address)
    compact = _mac_hex(mac)
    if not compact:
        return {
            "vendor": "Invalid MAC address",
            "source": "Validation",
            "prefix": "",
            "prefix_bits": 0,
            "locally_administered": False,
            "multicast": False
        }

    first_octet = int(compact[:2], 16)
    multicast = bool(first_octet & 0x01)
    locally_administered = bool(first_octet & 0x02)

    if multicast:
        return {
            "vendor": "Multicast / group address",
            "source": "MAC address flags",
            "prefix": "",
            "prefix_bits": 0,
            "locally_administered": locally_administered,
            "multicast": True
        }

    if locally_administered:
        return {
            "vendor": "Locally administered / randomized MAC",
            "source": "MAC address flags",
            "prefix": "",
            "prefix_bits": 0,
            "locally_administered": True,
            "multicast": False
        }

    index = load_ieee_oui_index()
    for prefix_length in (9, 7, 6):
        match = index.get(prefix_length, {}).get(compact[:prefix_length])
        if match:
            result = dict(match)
            result.update({
                "locally_administered": False,
                "multicast": False
            })
            return result

    return {
        "vendor": "Unknown vendor",
        "source": "No IEEE registry match",
        "prefix": compact[:6],
        "prefix_bits": 24,
        "locally_administered": False,
        "multicast": False
    }


def get_mac_vendor_guess(mac_address):
    """Compatibility wrapper returning the authoritative IEEE vendor label."""
    return get_mac_vendor_info(mac_address).get("vendor", "Unknown vendor")


def resolve_inventory_name_by_ip(ip_address):
    load_config()
    for device_name, device_ip in DEVICES.items():
        if str(device_ip) == str(ip_address):
            return device_name
    return ""


def resolve_inventory_name_by_mac(mac_address):
    """Match a MAC address to a known inventory device using the local ARP table."""
    wanted_mac = normalize_mac_address(mac_address)
    if not wanted_mac:
        return ""

    try:
        for row in get_arp_table_entries():
            if normalize_mac_address(row.get("mac", "")) == wanted_mac:
                return row.get("device", "") or resolve_inventory_name_by_ip(row.get("ip", ""))
    except Exception:
        return ""

    return ""


def build_port_to_device_lookup():
    """Build lookup tables so switch MAC entries can show friendly device names."""
    lookup = {}

    try:
        current_ports = get_current_switch_ports()
    except Exception:
        current_ports = {}

    try:
        interfaces = get_primary_switch_interfaces()
    except Exception:
        interfaces = {}

    for port_id, device_name in current_ports.items():
        interface_name = get_dynamic_switch_port_label(str(port_id), str(port_id))

        for key in [str(port_id), str(interface_name)]:
            if key:
                lookup[key] = device_name

        for ifindex, iface in interfaces.items():
            if not isinstance(iface, dict):
                continue

            if (
                iface.get("name") == interface_name
                or iface.get("short_name") == interface_name
                or str(iface.get("index", "")) == str(port_id)
            ):
                for key in [
                    str(ifindex),
                    str(iface.get("index", "")),
                    str(iface.get("name", "")),
                    str(iface.get("short_name", "")),
                ]:
                    if key:
                        lookup[key] = device_name

    return lookup


def resolve_device_name_for_mac_entry(mac_address, port_name, ifindex):
    """Prefer configured switch-port mapping, then fall back to ARP/inventory MAC match."""
    port_lookup = build_port_to_device_lookup()

    for key in [str(port_name or ""), str(ifindex or "")]:
        if key in port_lookup:
            return port_lookup[key]

    by_mac = resolve_inventory_name_by_mac(mac_address)
    if by_mac:
        return by_mac

    return ""


def get_arp_table_entries():
    """Read the monitoring server ARP/neighbor table. No network changes."""
    commands = []
    if shutil.which("ip"):
        commands.append(["ip", "neigh", "show"])
    if shutil.which("arp"):
        commands.append(["arp", "-a"])

    rows = []
    seen = set()

    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                shell=False
            )
            text = (completed.stdout or "") + (completed.stderr or "")

            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue

                ip_address = ""
                mac_address = ""
                state = "UNKNOWN"
                interface = ""

                # ip neigh format:
                # 192.168.0.1 dev enp0s3 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                if cmd[:2] == ["ip", "neigh"]:
                    parts = line.split()
                    if parts:
                        ip_address = parts[0]
                    if "dev" in parts:
                        try:
                            interface = parts[parts.index("dev") + 1]
                        except Exception:
                            interface = ""
                    if "lladdr" in parts:
                        try:
                            mac_address = parts[parts.index("lladdr") + 1]
                        except Exception:
                            mac_address = ""
                    if parts:
                        state = parts[-1]

                # arp -a format:
                # hostname (192.168.0.1) at aa:bb:cc:dd:ee:ff [ether] on enp0s3
                else:
                    ip_match = re.search(r"\(([^)]+)\)", line)
                    mac_match = re.search(r" at ([0-9A-Fa-f:\-]+) ", line)
                    on_match = re.search(r" on (\S+)", line)
                    if ip_match:
                        ip_address = ip_match.group(1)
                    if mac_match:
                        mac_address = mac_match.group(1)
                    if on_match:
                        interface = on_match.group(1)
                    state = "LEARNED"

                if not ip_address or not mac_address or mac_address.lower() == "(incomplete)":
                    continue

                mac_address = normalize_mac_address(mac_address)
                key = (ip_address, mac_address)
                if key in seen:
                    continue
                seen.add(key)

                rows.append({
                    "ip": ip_address,
                    "mac": mac_address,
                    "vendor": get_mac_vendor_guess(mac_address),
                    "interface": interface,
                    "state": state,
                    "device": resolve_inventory_name_by_ip(ip_address)
                })

        except Exception:
            continue

    return sorted(rows, key=lambda item: tuple(int(part) if part.isdigit() else 999 for part in item.get("ip", "0.0.0.0").split(".")))


def scan_tcp_port(target, port, timeout=0.8):
    try:
        with socket.create_connection((target, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def run_safe_port_scan(target):
    target = sanitize_noc_target(target)
    if not target:
        return []

    rows = []
    for port in NOC_SAFE_PORTS:
        is_open = scan_tcp_port(target, port)
        rows.append({
            "port": port,
            "service": NOC_SAFE_PORT_LABELS.get(port, "Unknown"),
            "status": "OPEN" if is_open else "CLOSED"
        })
    return rows


def run_safe_network_scan(cidr="192.168.0.0/24"):
    """Read-only ping sweep. Limited to /24 or smaller networks."""
    cidr = clean_ascii(str(cidr or "192.168.0.0/24")).strip()

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        network = ipaddress.ip_network("192.168.0.0/24", strict=False)

    if network.prefixlen < 24:
        network = ipaddress.ip_network(f"{network.network_address}/24", strict=False)

    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > 254:
        hosts = hosts[:254]

    arp_lookup = {row.get("ip"): row for row in get_arp_table_entries()}

    def ping_host(ip_address):
        try:
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_address],
                capture_output=True,
                text=True,
                timeout=2,
                shell=False
            )
            up = completed.returncode == 0
        except Exception:
            up = False

        arp = arp_lookup.get(ip_address, {})
        return {
            "ip": ip_address,
            "device": resolve_inventory_name_by_ip(ip_address),
            "status": "UP" if up else "DOWN",
            "mac": arp.get("mac", ""),
            "vendor": arp.get("vendor", ""),
            "source": "ping"
        }

    rows = []
    try:
        with ThreadPoolExecutor(max_workers=48) as pool:
            futures = [pool.submit(ping_host, ip) for ip in hosts]
            for future in as_completed(futures):
                row = future.result()
                if row.get("status") == "UP" or row.get("device") or row.get("mac"):
                    rows.append(row)
    except Exception:
        rows = []

    return sorted(rows, key=lambda item: tuple(int(part) if part.isdigit() else 999 for part in item.get("ip", "0.0.0.0").split(".")))






def get_switch_mac_address_table():
    """
    Read the Cisco switch MAC address table using SNMP.

    Cisco Catalyst switches often require VLAN-indexed SNMP community strings
    for the forwarding database. Example: public@422. This function tries the
    base community first, then VLAN-indexed communities, and returns whatever
    read-only MAC table entries the switch provides.
    """
    load_config()

    snmp_settings = config.get("snmp", {}) if isinstance(config.get("snmp", {}), dict) else {}
    switch_ip = snmp_settings.get("switch_ip", "")
    community = snmp_settings.get("community", "public")

    if not shutil.which("snmpwalk"):
        return {
            "success": False,
            "error": "snmpwalk is not installed on the monitoring server.",
            "rows": []
        }

    interfaces = get_primary_switch_interfaces()

    vlan_candidates = []

    # Pull VLANs from config when available.
    for key in ["vlans", "switch_vlans", "vlan_ids", "monitored_vlans"]:
        value = config.get(key)
        if isinstance(value, dict):
            vlan_candidates.extend(str(v) for v in value.keys())
        elif isinstance(value, list):
            vlan_candidates.extend(str(v) for v in value)

    # Common local VLANs for this dashboard/switch environment.
    vlan_candidates.extend(["1", "422", "555"])

    # Keep clean unique VLAN IDs only.
    clean_vlans = []
    for vlan in vlan_candidates:
        vlan = str(vlan).strip()
        if vlan.isdigit() and vlan not in clean_vlans:
            clean_vlans.append(vlan)

    community_candidates = [str(community)]
    for vlan in clean_vlans:
        community_candidates.append(f"{community}@{vlan}")

    rows = []
    seen = set()
    errors = []
    port_device_lookup = build_port_to_device_lookup()

    arp_mac_lookup = {}
    try:
        for arp_row in get_arp_table_entries():
            mac_key = normalize_mac_address(arp_row.get("mac", ""))
            if mac_key:
                arp_mac_lookup[mac_key] = arp_row.get("device", "") or resolve_inventory_name_by_ip(arp_row.get("ip", ""))
    except Exception:
        arp_mac_lookup = {}

    for community_to_try in community_candidates:

        # Bridge port -> ifIndex
        bridge_to_ifindex = {}
        bridge_oid = "1.3.6.1.2.1.17.1.4.1.2"
        bridge_text = run_snmpwalk_oid_readonly(
            switch_ip,
            community_to_try,
            bridge_oid,
            timeout_seconds=10
        )

        for line in bridge_text.splitlines():
            # Examples:
            # SNMPv2-SMI::mib-2.17.1.4.1.2.2 = INTEGER: 10102
            # iso.3.6.1.2.1.17.1.4.1.2.2 = INTEGER: 10102
            m = re.search(r"\.([0-9]+)\s*=\s*INTEGER:\s*([0-9]+)", line)
            if m:
                bridge_to_ifindex[m.group(1)] = m.group(2)

        # MAC address suffix -> bridge port
        fdb_port_oid = "1.3.6.1.2.1.17.4.3.1.2"
        fdb_text = run_snmpwalk_oid_readonly(
            switch_ip,
            community_to_try,
            fdb_port_oid,
            timeout_seconds=10
        )

        if not fdb_text.strip():
            errors.append(f"No FDB entries returned using community {community_to_try}")
            continue

        vlan_label = ""
        if "@" in community_to_try:
            vlan_label = community_to_try.split("@", 1)[1]

        for line in fdb_text.splitlines():
            # Example:
            # SNMPv2-SMI::mib-2.17.4.3.1.2.100.75.240.32.104.0 = INTEGER: 3
            m = re.search(
                r"\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*=\s*INTEGER:\s*([0-9]+)",
                line
            )
            if not m:
                continue

            mac_decimal = m.group(1)
            bridge_port = m.group(2)

            try:
                mac_address = ":".join(
                    f"{int(part):02X}" for part in mac_decimal.split(".")
                )
            except Exception:
                mac_address = mac_decimal

            # Skip common CPU/control multicast/static MACs that are not endpoint devices.
            normalized_mac = normalize_mac_address(mac_address)
            if normalized_mac.startswith("01:00:0C") or normalized_mac.startswith("01:80:C2"):
                continue
            if normalized_mac == "FF:FF:FF:FF:FF:FF":
                continue

            ifindex = bridge_to_ifindex.get(str(bridge_port), str(bridge_port))
            iface = interfaces.get(str(ifindex), {}) if isinstance(interfaces, dict) else {}
            port_name = iface.get("short_name") or iface.get("name") or str(ifindex)

            key = (normalized_mac, vlan_label, port_name)
            if key in seen:
                continue
            seen.add(key)

            device_name = (
                port_device_lookup.get(str(port_name))
                or port_device_lookup.get(str(ifindex))
                or arp_mac_lookup.get(normalized_mac, "")
            )

            vendor_info = get_mac_vendor_info(normalized_mac)
            rows.append({
                "vlan": vlan_label or "Unknown",
                "mac": normalized_mac,
                "device": device_name or "",
                "vendor": vendor_info.get("vendor", "Unknown vendor"),
                "vendor_source": vendor_info.get("source", "No IEEE registry match"),
                "vendor_prefix": vendor_info.get("prefix", ""),
                "vendor_prefix_bits": vendor_info.get("prefix_bits", 0),
                "bridge_port": str(bridge_port),
                "ifindex": str(ifindex),
                "port": port_name,
                "state": iface.get("state", "UNKNOWN"),
                "source": community_to_try
            })

    return {
        "success": True,
        "error": "" if rows else "; ".join(errors[-5:]),
        "rows": sorted(
            rows,
            key=lambda item: (
                str(item.get("vlan", "")),
                str(item.get("port", "")),
                str(item.get("mac", ""))
            )
        )
    }


# Phase 26.2: short-lived cache for switch forwarding database data.
# The Network Map refreshes every 20 seconds, so we do not run multiple SNMP
# forwarding-table walks on every browser refresh.
_PHASE26_MAC_TABLE_CACHE = {
    "timestamp": 0.0,
    "result": {"success": False, "error": "Not loaded", "rows": []}
}
_PHASE26_MAC_TABLE_CACHE_LOCK = threading.Lock()


def get_cached_switch_mac_address_table(max_age_seconds=60):
    """Return the switch MAC table with a short cache suitable for the map."""
    now_epoch = time.time()

    with _PHASE26_MAC_TABLE_CACHE_LOCK:
        cache_age = now_epoch - float(_PHASE26_MAC_TABLE_CACHE.get("timestamp", 0.0) or 0.0)
        cached_result = _PHASE26_MAC_TABLE_CACHE.get("result", {})
        if cache_age < max_age_seconds and isinstance(cached_result, dict):
            return cached_result

        result = get_switch_mac_address_table()
        _PHASE26_MAC_TABLE_CACHE["timestamp"] = now_epoch
        _PHASE26_MAC_TABLE_CACHE["result"] = result
        return result




def get_switch_port_utilization_statistics():
    """Return read-only interface counters for active/mapped switch ports."""
    load_config()

    snmp_settings = config.get("snmp", {}) if isinstance(config.get("snmp", {}), dict) else {}
    switch_ip = snmp_settings.get("switch_ip", "")
    community = snmp_settings.get("community", "public")

    if not shutil.which("snmpwalk"):
        return {
            "success": False,
            "error": "snmpwalk is not installed on the monitoring server.",
            "rows": []
        }

    interfaces = get_primary_switch_interfaces()
    port_lookup = build_port_to_device_lookup()

    oid_map = {
        "in_octets": "1.3.6.1.2.1.2.2.1.10",
        "out_octets": "1.3.6.1.2.1.2.2.1.16",
        "in_errors": "1.3.6.1.2.1.2.2.1.14",
        "out_errors": "1.3.6.1.2.1.2.2.1.20",
        "in_discards": "1.3.6.1.2.1.2.2.1.13",
        "out_discards": "1.3.6.1.2.1.2.2.1.19",
        "speed": "1.3.6.1.2.1.2.2.1.5",
    }

    counters = {}
    errors = []

    for label, oid in oid_map.items():
        text = run_snmpwalk_oid_readonly(switch_ip, community, oid, timeout_seconds=10)
        parsed = parse_snmpwalk_oid_integer_map(text)
        counters[label] = parsed
        if not parsed:
            errors.append(f"No SNMP data returned for {label}")

    rows = []

    for ifindex, iface in interfaces.items():
        if not isinstance(iface, dict):
            continue

        port_name = iface.get("short_name") or iface.get("name") or str(ifindex)

        # Keep the output useful: include mapped ports and active ports.
        is_mapped = str(ifindex) in port_lookup or str(port_name) in port_lookup
        is_up = str(iface.get("state", "")).upper() == "UP"
        if not is_mapped and not is_up:
            continue

        device_name = port_lookup.get(str(ifindex)) or port_lookup.get(str(port_name)) or ""

        in_octets = counters.get("in_octets", {}).get(str(ifindex), 0)
        out_octets = counters.get("out_octets", {}).get(str(ifindex), 0)
        in_errors = counters.get("in_errors", {}).get(str(ifindex), 0)
        out_errors = counters.get("out_errors", {}).get(str(ifindex), 0)
        in_discards = counters.get("in_discards", {}).get(str(ifindex), 0)
        out_discards = counters.get("out_discards", {}).get(str(ifindex), 0)
        speed = counters.get("speed", {}).get(str(ifindex), 0)

        rows.append({
            "port": port_name,
            "device": device_name,
            "ifindex": str(ifindex),
            "state": iface.get("state", "UNKNOWN"),
            "speed_bps": speed,
            "rx_bytes": in_octets,
            "tx_bytes": out_octets,
            "rx_mb": round(in_octets / 1024 / 1024, 2),
            "tx_mb": round(out_octets / 1024 / 1024, 2),
            "input_errors": in_errors,
            "output_errors": out_errors,
            "input_discards": in_discards,
            "output_discards": out_discards,
            "total_errors": in_errors + out_errors,
            "total_discards": in_discards + out_discards,
        })

    return {
        "success": True,
        "error": "" if rows else "; ".join(errors[-5:]),
        "rows": sorted(rows, key=lambda item: str(item.get("port", "")))
    }

# ======================================================
# PHASE 13D.1 - DASHBOARD CLEANUP PAGE ROUTES
# New pages reuse the same dashboard context so nothing breaks.
# ======================================================
# PHASE 28.5 - MODULAR DASHBOARD PAGE ROUTES
register_dashboard_routes(app, build_dashboard_context)

# PHASE 28.6 - CORE API ROUTES
register_api_routes(app)













@app.route("/reset-network-design", methods=["POST"])
def reset_network_design():
    load_config()

    confirmation = clean_ascii(request.form.get("confirmation", "")).upper()
    if confirmation != "RESET":
        return provisioning_redirect(
            "error",
            "Network design was not reset. Type RESET in the confirmation box."
        )

    result = reset_network_design_state()
    return provisioning_redirect(
        "success",
        result.get("message", "Network design reset complete.")
    )


@app.route("/api/infrastructure-auto-linking")
def api_infrastructure_auto_linking():
    load_config()
    discover_cdp_neighbors(force=True)
    discover_lldp_neighbors(force=True)
    build_link_confidence_database(force=True)
    result = rebuild_auto_infrastructure_links()
    save_config()
    return jsonify({
        "success": True,
        "phase": "26B.8",
        "settings": config.get("infrastructure_auto_linking", {}),
        "result": result,
        "links": config.get("infrastructure_links", []),
        "relationships": config.get("device_relationships", {})
    })

@app.route("/api/noc-tools")
def api_noc_tools():
    return jsonify(build_noc_tools_center())


@app.route("/api/noc-tools/ssh-profile/<path:device_name>")
def api_noc_tools_ssh_profile(device_name):
    return jsonify(resolve_device_ssh_profile(device_name))



def build_router_interface_status_rows():
    """Return read-only router interface status rows for the NOC Infrastructure panel."""
    rows = []

    try:
        interfaces = get_all_router_interfaces()
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "rows": []
        }

    for index, iface in interfaces.items():
        if not isinstance(iface, dict):
            continue

        name = iface.get("name") or str(index)
        short_name = iface.get("short_name") or short_interface_name(name) or name
        state = str(iface.get("state", "UNKNOWN")).upper()

        rows.append({
            "index": str(iface.get("index", index)),
            "interface": short_name,
            "name": name,
            "description": iface.get("description", "") or iface.get("alias", ""),
            "ip": iface.get("ip", "") or iface.get("ip_address", "") or iface.get("address", ""),
            "state": state,
            "source": iface.get("source", "snmp"),
            "last_checked": iface.get("last_checked", now())
        })

    rows = sorted(
        rows,
        key=lambda item: (
            0 if item.get("state") == "UP" else 1,
            str(item.get("interface", ""))
        )
    )

    return {
        "success": True,
        "error": "",
        "rows": rows
    }


def build_wan_status_rows():
    """Return read-only WAN/internet health rows for the NOC Infrastructure panel."""
    rows = []

    try:
        router_name = get_infrastructure_name("edge_router")
        router_ip = ROUTER_IP or DEVICES.get(router_name, "")

        if router_ip:
            router_state, router_latency = check_device(router_ip)
            rows.append({
                "name": "Edge Router Reachability",
                "target": router_ip,
                "state": router_state,
                "latency": router_latency
            })

        gateway_name = get_infrastructure_name("internet_gateway")
        gateway_ip = DEVICES.get(gateway_name, "")

        if gateway_ip:
            gateway_state, gateway_latency = check_device(gateway_ip)
            rows.append({
                "name": "Internet Gateway",
                "target": gateway_ip,
                "state": gateway_state,
                "latency": gateway_latency
            })

        internet_state, internet_results = check_internet_targets()

        rows.append({
            "name": "External Internet",
            "target": ", ".join(INTERNET_CHECK_TARGETS),
            "state": internet_state,
            "latency": "Multi-target"
        })

        for target, info in internet_results.items():
            rows.append({
                "name": "WAN Test Target",
                "target": target,
                "state": info.get("state", "UNKNOWN"),
                "latency": info.get("latency", "N/A")
            })

        return {
            "success": True,
            "error": "",
            "rows": rows
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "rows": rows
        }


def build_noc_network_infrastructure_status():
    """Build Router Interface Status, Switch Port Status, and WAN Status together."""
    router_status = build_router_interface_status_rows()
    wan_status = build_wan_status_rows()

    switch_rows = []

    try:
        current_ports = get_current_switch_ports()
        interfaces = get_primary_switch_interfaces()

        for port_id, device_name in current_ports.items():
            interface_name = get_dynamic_switch_port_label(
                str(port_id),
                str(port_id)
            )

            state = "DOWN"

            for _, iface in interfaces.items():
                if not isinstance(iface, dict):
                    continue

                if (
                    iface.get("name") == interface_name
                    or iface.get("short_name") == interface_name
                    or str(iface.get("index", "")) == str(port_id)
                ):
                    state = str(iface.get("state", "DOWN")).upper()
                    break

            switch_rows.append({
                "port": interface_name,
                "device": device_name,
                "status": state
            })

        switch_status = {
            "success": True,
            "error": "",
            "rows": switch_rows
        }

    except Exception as e:
        switch_status = {
            "success": False,
            "error": str(e),
            "rows": []
        }

    return {
        "success": True,
        "router_interfaces": router_status.get("rows", []),
        "router_error": router_status.get("error", ""),
        "switch_ports": switch_status.get("rows", []),
        "switch_error": switch_status.get("error", ""),
        "wan_status": wan_status.get("rows", []),
        "wan_error": wan_status.get("error", ""),
        "counts": {
            "router_interfaces": len(router_status.get("rows", [])),
            "switch_ports": len(switch_status.get("rows", [])),
            "wan_checks": len(wan_status.get("rows", []))
        },
        "timestamp": now()
    }


@app.route("/api/noc-tools/infrastructure-status")
def api_noc_tools_infrastructure_status():
    try:
        return jsonify(build_noc_network_infrastructure_status())
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "router_interfaces": [],
            "switch_ports": [],
            "wan_status": [],
            "counts": {
                "router_interfaces": 0,
                "switch_ports": 0,
                "wan_checks": 0
            },
            "timestamp": now()
        })

@app.route("/api/noc-tools/port-status")
def api_noc_tools_port_status():
    rows = []

    try:
        current_ports = get_current_switch_ports()
        interfaces = get_primary_switch_interfaces()

        for port_id, device_name in current_ports.items():

            interface_name = get_dynamic_switch_port_label(
                str(port_id),
                str(port_id)
            )

            state = "DOWN"

            for _, iface in interfaces.items():

                if not isinstance(iface, dict):
                    continue

                if (
                    iface.get("name") == interface_name
                    or iface.get("short_name") == interface_name
                    or str(iface.get("index", "")) == str(port_id)
                ):
                    state = str(
                        iface.get("state", "DOWN")
                    ).upper()
                    break

            rows.append({
                "port": interface_name,
                "device": device_name,
                "status": state
            })

        return jsonify({
            "success": True,
            "ports": rows,
            "count": len(rows),
            "timestamp": now()
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "ports": []
        })


@app.route("/api/noc-tools/interfaces")
def api_noc_tools_interfaces():

    try:

        interfaces = get_primary_switch_interfaces()

        return jsonify({
            "success": True,
            "interfaces": interfaces,
            "count": len(interfaces),
            "timestamp": now()
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e),
            "interfaces": {}
        })


@app.route("/api/noc-tools/port-scan", methods=["POST"])
def api_noc_tools_port_scan():
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "")

    try:
        rows = run_safe_port_scan(target)
        return jsonify({
            "success": True,
            "target": sanitize_noc_target(target),
            "ports": rows,
            "count": len(rows),
            "timestamp": now()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "ports": [],
            "timestamp": now()
        })


@app.route("/api/noc-tools/arp-table")
def api_noc_tools_arp_table():
    try:
        rows = get_arp_table_entries()
        return jsonify({
            "success": True,
            "rows": rows,
            "count": len(rows),
            "timestamp": now()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "rows": [],
            "timestamp": now()
        })


@app.route("/api/noc-tools/mac-address-table")
def api_noc_tools_mac_address_table():
    try:
        result = get_switch_mac_address_table()
        return jsonify({
            "success": result.get("success", False),
            "error": result.get("error", ""),
            "rows": result.get("rows", []),
            "count": len(result.get("rows", [])),
            "timestamp": now()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "rows": [],
            "timestamp": now()
        })


@app.route("/api/noc-tools/network-scan", methods=["POST"])
def api_noc_tools_network_scan():
    payload = request.get_json(silent=True) or {}
    cidr = payload.get("cidr", "192.168.0.0/24")

    try:
        rows = run_safe_network_scan(cidr)
        return jsonify({
            "success": True,
            "cidr": cidr,
            "rows": rows,
            "count": len(rows),
            "timestamp": now()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "rows": [],
            "timestamp": now()
        })


@app.route("/api/noc-tools/port-utilization")
def api_noc_tools_port_utilization():
    try:
        result = get_switch_port_utilization_statistics()
        return jsonify({
            "success": result.get("success", False),
            "error": result.get("error", ""),
            "rows": result.get("rows", []),
            "count": len(result.get("rows", [])),
            "timestamp": now()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "rows": [],
            "timestamp": now()
        })


@app.route("/api/noc-tools/run", methods=["POST"])
def api_noc_tools_run():
    payload = request.get_json(silent=True) or {}
    tool_name = payload.get("tool", "")
    target = payload.get("target", "")
    return jsonify(run_noc_tool(tool_name, target))




def get_current_switch_ports():
    load_config()
    return config.get("switch_ports", {})



# PHASE 8C.1.2 - ENTERPRISE LIVE REFRESH CORE
runtime_refresh_version = 0
runtime_last_refresh = "Starting..."


def bump_runtime_refresh_version():
    global runtime_refresh_version, runtime_last_refresh
    runtime_refresh_version += 1
    runtime_last_refresh = now()


def refresh_runtime_data():
    """
    Reload config.json and immediately rebuild live router/switch link data.
    This keeps Dashboard, Network Map, and Port Mapper synchronized after
    any inventory or port-mapping change without waiting for the monitor loop.
    """
    global router_interfaces, switch_links

    load_config()

    try:
        router_interfaces = get_router_interfaces()
    except Exception as e:
        write_event(f"ERROR | RUNTIME REFRESH | Router refresh failed: {e}")

    try:
        switch_links = get_switch_links()
    except Exception as e:
        write_event(f"ERROR | RUNTIME REFRESH | Switch refresh failed: {e}")

    bump_runtime_refresh_version()


def get_current_switch_ports():
    load_config()
    return config.get("switch_ports", {})



# PHASE 9C.2 ERROR FIX - RESTORED INVENTORY / UPLINK HELPERS
# These helpers are required by Network Map and Port Mapper after Phase 9C.2.

def is_infrastructure_uplink_device(device_name):
    """True when a device belongs to the core/infrastructure topology path.

    Phase 13E: endpoint topology links are allowed in config, but they should not
    make normal endpoint devices disappear from the endpoint grid.
    """
    device_name = clean_ascii(device_name)

    if not device_name:
        return False

    return is_core_topology_device(device_name) and device_name != get_physical_topology_primary_switch()


def build_infrastructure_uplink_list():
    """Build uplink cards from core physical topology links only."""
    uplinks = []

    for link in get_physical_topology_config():
        if is_endpoint_topology_link(link):
            continue

        switch_port = clean_ascii(link.get("switch_port", ""))
        if not switch_port:
            continue

        # Pick the non-switch side as the displayed infrastructure device when possible.
        from_device = clean_ascii(link.get("from", ""))
        to_device = clean_ascii(link.get("to", ""))

        if is_topology_switch(from_device) and to_device:
            mapped_device = to_device
        elif is_topology_switch(to_device) and from_device:
            mapped_device = from_device
        else:
            mapped_device = to_device or from_device

        if not mapped_device:
            continue

        link_info = switch_links.get(switch_port, {}) if isinstance(switch_links, dict) else {}
        ip_address = DEVICES.get(mapped_device, "")
        status_info = status.get(mapped_device, {})
        device_type = detect_map_device_type(mapped_device, ip_address)

        device_state = status_info.get("state", link_info.get("state", "UNKNOWN"))
        link_state = link_info.get("state", "UNKNOWN")
        port_label = clean_ascii(link.get("port_label", "")) or get_dynamic_switch_port_label(
            switch_port,
            link_info.get("port", f"Index {switch_port}")
        )

        uplinks.append({
            "name": mapped_device,
            "from": from_device,
            "to": to_device,
            "ip": ip_address,
            "type": device_type,
            "icon": get_map_icon(device_type),
            "port": port_label,
            "port_index": switch_port,
            "link_type": clean_ascii(link.get("link_type", "Physical Link")),
            "state": device_state,
            "link_state": link_state,
            "status_class": get_map_status_class(device_state),
            "link_status_class": get_map_status_class(link_state),
            "latency": status_info.get("latency", "N/A"),
            "last_checked": status_info.get("last_checked", link_info.get("last_checked", "Starting..."))
        })

    return sorted(uplinks, key=lambda item: item.get("port_index", ""))


def get_device_port_mapping():
    load_config()

    mapping = {}

    for port_index, device_name in config.get("switch_ports", {}).items():
        mapping[device_name] = {
            "port_index": port_index,
            "port_label": get_dynamic_switch_port_label(port_index)
        }

    return mapping


def get_parent_port_for_child(child_name):
    relationship = DEVICE_RELATIONSHIPS.get(child_name, {})

    if not isinstance(relationship, dict):
        return {
            "parent": "",
            "relationship": "",
            "parent_port_index": "",
            "parent_port_label": "N/A"
        }

    parent_name = relationship.get("parent", "")
    device_port_map = get_device_port_mapping()
    parent_port = device_port_map.get(parent_name, {})

    return {
        "parent": parent_name,
        "relationship": relationship.get("relationship", "Child Device"),
        "parent_port_index": parent_port.get("port_index", ""),
        "parent_port_label": parent_port.get("port_label", "No mapped parent port")
    }


def build_device_inventory():
    load_config()

    inventory = []
    device_port_map = get_device_port_mapping()

    for device_name, ip_address in DEVICES.items():
        if is_child_device(device_name):
            continue

        category = get_enterprise_category(device_name)
        if category == "virtual":
            continue

        status_info = status.get(device_name, {})
        device_type = DEVICE_TYPES.get(
            device_name,
            detect_map_device_type(device_name, ip_address)
        )
        port_info = device_port_map.get(device_name, {})

        inventory.append({
            "name": device_name,
            "ip": ip_address,
            "type": device_type,
            "category": category,
            "icon": get_map_icon(device_type),
            "state": status_info.get("state", "UNKNOWN"),
            "latency": status_info.get("latency", "N/A"),
            "last_checked": status_info.get("last_checked", "Starting..."),
            "port_index": port_info.get("port_index", ""),
            "port_label": port_info.get("port_label", "No mapped switch port"),
            "has_port": bool(port_info.get("port_index", ""))
        })

    return sorted(inventory, key=lambda item: item.get("name", "").lower())


def get_relationship_inventory():
    load_config()

    relationships = []

    for child_name, relationship in DEVICE_RELATIONSHIPS.items():
        if not isinstance(relationship, dict):
            continue

        child_ip = DEVICES.get(child_name, "")
        child_type = DEVICE_TYPES.get(
            child_name,
            detect_map_device_type(child_name, child_ip)
        )
        child_status = status.get(child_name, {})
        parent_port = get_parent_port_for_child(child_name)

        relationships.append({
            "name": child_name,
            "ip": child_ip,
            "type": child_type,
            "icon": get_map_icon(child_type),
            "state": child_status.get("state", "UNKNOWN"),
            "latency": child_status.get("latency", "N/A"),
            "last_checked": child_status.get("last_checked", "Starting..."),
            "parent": relationship.get("parent", ""),
            "relationship": relationship.get("relationship", "Child Device"),
            "parent_port_index": parent_port.get("parent_port_index", ""),
            "parent_port_label": parent_port.get("parent_port_label", "N/A")
        })

    return sorted(relationships, key=lambda item: item.get("name", "").lower())


def assign_device_switch_port(device_name, port_index):
    load_config()

    device_name = clean_ascii(device_name)
    port_index = clean_ascii(port_index)

    if not device_name:
        raise ValueError("Device name is required")

    if not port_index:
        raise ValueError("Switch port is required")

    if device_name not in config.get("devices", {}):
        raise ValueError(f"Device not found: {device_name}")

    if is_child_device(device_name):
        raise ValueError("Virtual / child devices cannot be assigned directly to switch ports")

    if port_index not in get_selectable_switch_ports():
        raise ValueError(f"Invalid SNMP-discovered switch port: {port_index}")

    config.setdefault("switch_ports", {})
    config.setdefault("infrastructure_links", [])

    # Remove this device from any old port first.
    for existing_port, existing_device in list(config["switch_ports"].items()):
        if existing_device == device_name:
            config["switch_ports"].pop(existing_port, None)

    config["switch_ports"][port_index] = device_name
    ensure_endpoint_topology_link_for_switch_port(device_name, port_index)

    save_config()
    refresh_runtime_data()

    write_event(
        f"CONFIG | ENTERPRISE INVENTORY | {device_name} mapped to {get_switch_port_label(port_index)} | topology link synced"
    )


def remove_device_switch_mapping(device_name):
    load_config()

    device_name = clean_ascii(device_name)

    if not device_name:
        raise ValueError("Device name is required")

    removed = False
    config.setdefault("switch_ports", {})
    config.setdefault("infrastructure_links", [])

    for port_index, mapped_device in list(config["switch_ports"].items()):
        if mapped_device == device_name:
            config["switch_ports"].pop(port_index, None)
            removed = True

    removed_links = remove_endpoint_topology_links_for_device(device_name)

    if not removed and removed_links == 0:
        raise ValueError(f"No switch port mapping found for {device_name}")

    save_config()
    refresh_runtime_data()

    write_event(
        f"CONFIG | ENTERPRISE INVENTORY | Removed switch port mapping for {device_name} | removed {removed_links} topology link(s)"
    )


# PHASE 9C.2 - ENTERPRISE DEVICE INVENTORY ENGINE
def get_enterprise_category(device_name):
    device_name = clean_ascii(device_name)
    device_type = clean_ascii(DEVICE_TYPES.get(device_name, ""))
    if device_name in get_all_infrastructure_names() or is_infrastructure_topology_device(device_name):
        return "infrastructure"
    if is_virtual_child_device(device_name) or device_type.lower() in {"virtual machine", "vm", "child device"}:
        return "virtual"
    return "physical"


def build_enterprise_inventory_categories():
    load_config()

    categories = {
        "infrastructure": [],
        "physical": [],
        "virtual": []
    }

    device_port_map = get_device_port_mapping()

    for device_name, ip_address in DEVICES.items():
        status_info = status.get(device_name, {})
        device_type = DEVICE_TYPES.get(
            device_name,
            detect_map_device_type(device_name, ip_address)
        )
        category = get_enterprise_category(device_name)
        port_info = device_port_map.get(device_name, {})
        relationship = DEVICE_RELATIONSHIPS.get(device_name, {})
        parent_name = relationship.get("parent", "") if isinstance(relationship, dict) else ""

        if category == "virtual":
            parent_port = get_parent_port_for_child(device_name)
        else:
            parent_port = {
                "parent": "",
                "relationship": "",
                "parent_port_index": "",
                "parent_port_label": "N/A"
            }

        item = {
            "name": device_name,
            "ip": ip_address,
            "type": device_type,
            "category": category,
            "icon": get_map_icon(device_type),
            "state": status_info.get("state", "UNKNOWN"),
            "latency": status_info.get("latency", "N/A"),
            "last_checked": status_info.get("last_checked", "Starting..."),
            "port_index": port_info.get("port_index", ""),
            "port_label": port_info.get("port_label", "No mapped switch port"),
            "has_port": bool(port_info.get("port_index", "")),
            "parent": parent_name,
            "relationship": relationship.get("relationship", "") if isinstance(relationship, dict) else "",
            "parent_port_index": parent_port.get("parent_port_index", ""),
            "parent_port_label": parent_port.get("parent_port_label", "N/A"),
            "is_mappable": category == "physical"
        }

        categories[category].append(item)

    for category, items in categories.items():
        categories[category] = sorted(
            items,
            key=lambda item: item.get("name", "").lower()
        )

    return categories


def get_enterprise_inventory_counts(categories):
    infrastructure_count = len(categories.get("infrastructure", []))
    physical_count = len(categories.get("physical", []))
    virtual_count = len(categories.get("virtual", []))

    mapped_physical = sum(1 for item in categories.get("physical", []) if item.get("has_port"))
    unmapped_physical = sum(1 for item in categories.get("physical", []) if not item.get("has_port"))

    return {
        "infrastructure_count": infrastructure_count,
        "physical_count": physical_count,
        "virtual_count": virtual_count,
        "mapped_count": mapped_physical,
        "unmapped_count": unmapped_physical,
        "total_devices": infrastructure_count + physical_count + virtual_count
    }



def get_enterprise_inventory_payload():
    refresh_runtime_data()

    inventory = build_device_inventory()
    relationship_inventory = get_relationship_inventory()
    inventory_categories = build_enterprise_inventory_categories()
    counts = get_enterprise_inventory_counts(inventory_categories)

    return {
        "runtime_refresh_version": runtime_refresh_version,
        "runtime_last_refresh": runtime_last_refresh,
        "inventory": inventory,
        "relationship_inventory": relationship_inventory,
        "inventory_categories": inventory_categories,
        "switch_ports": get_current_switch_ports(),
        "selectable_ports": get_selectable_switch_ports(),
        "mapped_count": counts["mapped_count"],
        "unmapped_count": counts["unmapped_count"],
        "relationship_count": counts["virtual_count"],
        "infrastructure_count": counts["infrastructure_count"],
        "physical_count": counts["physical_count"],
        "virtual_count": counts["virtual_count"],
        "total_devices": counts["total_devices"]
    }


@app.route("/api/port-mapper-data")
def api_port_mapper_data():
    return jsonify(get_enterprise_inventory_payload())


@app.route("/enterprise-inventory")
@app.route("/port-mapper")
def port_mapper():
    payload = get_enterprise_inventory_payload()
    active_alerts = get_active_alerts()

    return render_template(
        "port_mapper.html",
        last_full_scan=last_full_scan,
        inventory=payload["inventory"],
        inventory_categories=payload.get("inventory_categories", {}),
        selectable_ports=payload.get("selectable_ports", {}),
        switch_ports=payload["switch_ports"],
        active_alert_count=len(active_alerts),
        mapped_count=payload["mapped_count"],
        unmapped_count=payload["unmapped_count"],
        total_devices=payload["total_devices"],
        relationship_inventory=payload.get("relationship_inventory", []),
        relationship_count=payload.get("relationship_count", 0),
        infrastructure_count=payload.get("infrastructure_count", 0),
        physical_count=payload.get("physical_count", 0),
        virtual_count=payload.get("virtual_count", 0),
        runtime_refresh_version=payload["runtime_refresh_version"],
        runtime_last_refresh=payload["runtime_last_refresh"],
        all_devices=DEVICES,
        managed_ports=get_selectable_switch_ports()
    )


@app.route("/update-port-mapping", methods=["POST"])
def update_port_mapping():
    device_name = request.form.get("device_name", "").strip()
    port_index = request.form.get("port_index", "").strip()

    try:
        assign_device_switch_port(device_name, port_index)
    except Exception as e:
        write_event(f"ERROR | PORT MAPPER | Failed to map {device_name}: {e}")

    return redirect(url_for("port_mapper"))


@app.route("/remove-port-mapping", methods=["POST"])
def remove_port_mapping():
    device_name = request.form.get("device_name", "").strip()

    try:
        remove_device_switch_mapping(device_name)
    except Exception as e:
        write_event(f"ERROR | PORT MAPPER | Failed to remove mapping for {device_name}: {e}")

    return redirect(url_for("port_mapper"))




@app.route("/api/assign-device-port", methods=["POST"])
def api_assign_device_port():
    data = request.get_json(silent=True) or request.form
    device_name = str(data.get("device_name", "")).strip()
    switch_port = str(data.get("switch_port", data.get("port_index", ""))).strip()

    try:
        assign_device_switch_port(device_name, switch_port)
        return jsonify({
            "success": True,
            "message": f"{device_name} mapped to {get_switch_port_label(switch_port)}",
            "data": get_enterprise_inventory_payload()
        })
    except Exception as e:
        write_event(f"ERROR | PORT MAPPER API | Failed to map {device_name}: {e}")
        return jsonify({"success": False, "message": str(e)}), 400


@app.route("/api/remove-device-port", methods=["POST"])
def api_remove_device_port():
    data = request.get_json(silent=True) or request.form
    device_name = str(data.get("device_name", "")).strip()

    try:
        remove_device_switch_mapping(device_name)
        return jsonify({
            "success": True,
            "message": f"Switch port mapping removed for {device_name}",
            "data": get_enterprise_inventory_payload()
        })
    except Exception as e:
        write_event(f"ERROR | PORT MAPPER API | Failed to remove mapping for {device_name}: {e}")
        return jsonify({"success": False, "message": str(e)}), 400


@app.route("/api/update-port-mapping", methods=["POST"])
def api_update_port_mapping():
    data = request.get_json(silent=True) or request.form
    device_name = str(data.get("device_name", "")).strip()
    port_index = str(data.get("port_index", "")).strip()

    try:
        assign_device_switch_port(device_name, port_index)
        payload = get_enterprise_inventory_payload()
        return jsonify({
            "success": True,
            "message": f"{device_name} mapped to {get_switch_port_label(port_index)}",
            "data": payload
        })
    except Exception as e:
        write_event(f"ERROR | PORT MAPPER API | Failed to map {device_name}: {e}")
        return jsonify({"success": False, "message": str(e)}), 400


@app.route("/api/remove-port-mapping", methods=["POST"])
def api_remove_port_mapping():
    data = request.get_json(silent=True) or request.form
    device_name = str(data.get("device_name", "")).strip()

    try:
        remove_device_switch_mapping(device_name)
        payload = get_enterprise_inventory_payload()
        return jsonify({
            "success": True,
            "message": f"Switch port mapping removed for {device_name}",
            "data": payload
        })
    except Exception as e:
        write_event(f"ERROR | PORT MAPPER API | Failed to remove mapping for {device_name}: {e}")
        return jsonify({"success": False, "message": str(e)}), 400

@app.route("/reset-all-port-mappings", methods=["POST"])
def reset_all_port_mappings():
    load_config()

    old_count = len(config.get("switch_ports", {}))
    config["switch_ports"] = {}
    removed_links = remove_all_endpoint_topology_links()

    save_config()
    refresh_runtime_data()

    write_event(
        f"CONFIG | ENTERPRISE INVENTORY | All switch port mappings cleared ({old_count} removed) | endpoint topology links removed: {removed_links}"
    )

    return redirect(url_for("port_mapper"))




@app.route("/save-topology-link", methods=["POST"])
def save_topology_link_route():
    try:
        add_or_update_topology_link(request.form)
    except Exception as e:
        write_event(f"ERROR | TOPOLOGY MANAGER | Save failed: {e}")
    return redirect(url_for("provisioning_page"))


@app.route("/delete-topology-link", methods=["POST"])
def delete_topology_link_route():
    link_id = clean_ascii(request.form.get("link_id", ""))
    try:
        delete_topology_link(link_id)
    except Exception as e:
        write_event(f"ERROR | TOPOLOGY MANAGER | Delete failed: {e}")
    return redirect(url_for("provisioning_page"))


@app.route("/api/topology-editor-data")
def api_topology_editor_data():
    return jsonify(build_topology_editor_payload())


@app.route("/network-map")
def network_map():
    map_data = build_network_map_data()
    active_alerts = get_active_alerts()

    return render_template(
        "network_map.html",
        last_full_scan=last_full_scan,
        map_data=map_data,
        alerts=active_alerts,
        active_alert_count=len(active_alerts)
    )


@app.route("/api/network-map-data")
def api_network_map_data():
    return jsonify(build_network_map_data())


@app.route("/api/cdp-neighbors")
def api_cdp_neighbors():
    return jsonify(build_cdp_discovery_summary())


@app.route("/api/cdp-neighbors/discover", methods=["POST"])
def api_cdp_neighbors_discover():
    load_config()
    discover_cdp_neighbors(force=True)
    return jsonify(build_cdp_discovery_summary())


@app.route("/api/lldp-neighbors")
def api_lldp_neighbors():
    return jsonify(build_lldp_discovery_summary())


@app.route("/api/lldp-neighbors/discover", methods=["POST"])
def api_lldp_neighbors_discover():
    load_config()
    discover_lldp_neighbors(force=True)
    return jsonify(build_lldp_discovery_summary())

@app.route("/api/link-confidence")
def api_link_confidence():
    return jsonify(build_link_confidence_summary())


@app.route("/api/link-confidence/rebuild", methods=["POST"])
def api_link_confidence_rebuild():
    load_config()
    discover_cdp_neighbors(force=True)
    discover_lldp_neighbors(force=True)
    build_link_confidence_database(force=True)
    return jsonify(build_link_confidence_summary())



@app.route("/router-monitoring")
def router_monitoring():
    load_config()

    all_interfaces = get_all_router_interfaces()
    mapped_indexes = get_router_topology_mapped_interface_indexes(all_interfaces)
    effective_indexes = get_effective_router_monitored_interface_indexes(all_interfaces)

    # PHASE 15B.1 - Router Monitoring UI Improvement
    # Keep the existing single-router backend, but show the router name, IP,
    # interface totals, and monitored count above the discovered ports.
    router_name = get_primary_router_name()
    router_ip = clean_ascii(DEVICES.get(router_name, "")) or clean_ascii(ROUTER_IP) or "Unknown"
    router_type = clean_ascii(DEVICE_TYPES.get(router_name, "Router")) or "Router"
    router_state = clean_ascii(status.get(router_name, {}).get("state", "UNKNOWN")) or "UNKNOWN"

    interface_total = len(all_interfaces)
    interface_up = 0
    interface_down = 0

    for iface in all_interfaces.values():
        iface_state = clean_ascii(iface.get("state", "UNKNOWN")).upper()
        if iface_state == "UP":
            interface_up += 1
        elif iface_state == "DOWN":
            interface_down += 1

    router_summary = {
        "name": router_name,
        "ip": router_ip,
        "type": router_type,
        "state": router_state,
        "discovered_count": interface_total,
        "monitored_count": len(effective_indexes),
        "mapped_count": len(mapped_indexes),
        "up_count": interface_up,
        "down_count": interface_down
    }

    return render_template(
        "router_monitoring.html",
        all_router_interfaces=all_interfaces,
        router_monitored_interfaces=sorted(effective_indexes, key=str),
        router_mapped_interfaces=sorted(mapped_indexes, key=str),
        router_summary=router_summary,
        last_full_scan=last_full_scan
    )


@app.route("/update-router-monitoring", methods=["POST"])
def update_router_monitoring():
    load_config()

    selected_interfaces = {clean_ascii(index) for index in request.form.getlist("router_interfaces")}
    all_interfaces = get_all_router_interfaces()
    discovered_indexes = {clean_ascii(index) for index in all_interfaces.keys()}

    # Save what the admin selected, but only for interfaces currently discovered
    # by SNMP. Mapping is intentionally NOT required here.
    allowed_interfaces = selected_interfaces.intersection(discovered_indexes)

    config["router_monitored_interfaces"] = sorted(allowed_interfaces, key=str)

    save_config()
    refresh_runtime_data()

    message = (", ".join(config["router_monitored_interfaces"]) if config["router_monitored_interfaces"] else "No router interfaces selected")
    write_event("CONFIG | ROUTER MONITORING UPDATED | " + message)

    return redirect(url_for("router_monitoring"))


def run_phase16b_interface_discovery_for_device(device_name):
    """Discover and cache interfaces immediately after provisioning.

    This makes a newly provisioned router/switch/firewall/AP ready for the
    Physical Topology Builder without editing app.py or restarting discovery.
    """
    device_name = clean_ascii(device_name)
    if not device_name:
        return 0

    if not is_network_infrastructure_device(device_name):
        return 0

    try:
        interfaces = discover_device_interfaces(device_name, force_live=True)
        count = len(interfaces or {})
        write_event(
            f"CONFIG | PHASE 16B INTERFACE DISCOVERY | {device_name} | Interfaces discovered: {count}"
        )
        return count
    except Exception as e:
        write_event(f"ERROR | PHASE 16B INTERFACE DISCOVERY | {device_name} | {e}")
        return 0


@app.route("/add-device", methods=["POST"])
def add_device():
    load_config()

    original_config = json.loads(json.dumps(config))

    device_name = clean_ascii(request.form.get("device_name", "").strip())
    ip_address = clean_ascii(request.form.get("ip_address", "").strip())
    provisioning_type = normalize_provisioning_type(request.form.get("provisioning_type", "physical"))
    switch_port = clean_ascii(request.form.get("switch_port", "").strip())
    hosted_by = clean_ascii(request.form.get("hosted_by", "").strip())
    infrastructure_role = clean_ascii(request.form.get("infrastructure_role", "").strip())
    physical_device_type = clean_ascii(request.form.get("physical_device_type", "Endpoint").strip())

    try:
        if not device_name or not ip_address:
            write_event("ERROR | SMART PROVISIONING | Missing device name or IP address")
            write_provisioning_audit("ADD DEVICE", "FAILED", device_name, ip_address, "Missing device name or IP address")
            return provisioning_redirect("error", "Missing device name or IP address.")

        if not validate_ip(ip_address):
            write_event(f"ERROR | SMART PROVISIONING | Invalid IP address: {ip_address}")
            write_provisioning_audit("ADD DEVICE", "FAILED", device_name, ip_address, "Invalid IP address")
            return provisioning_redirect("error", f"Invalid IP address: {ip_address}")

        if is_reserved_provisioning_ip(ip_address):
            write_event(f"ERROR | SMART PROVISIONING | Reserved IP blocked: {ip_address}")
            write_provisioning_audit("ADD DEVICE", "FAILED", device_name, ip_address, "Reserved IP blocked")
            return provisioning_redirect("error", f"Reserved IP blocked: {ip_address}")

        if device_name in config.get("devices", {}):
            write_event(f"ERROR | SMART PROVISIONING | Device already exists: {device_name}")
            write_provisioning_audit("ADD DEVICE", "FAILED", device_name, ip_address, "Duplicate device name")
            return provisioning_redirect("error", f"Device name already exists: {device_name}")

        duplicate_ip_owner = get_existing_ip_owner(ip_address)

        if duplicate_ip_owner:
            write_event(
                f"ERROR | SMART PROVISIONING | IP {ip_address} already assigned to {duplicate_ip_owner}"
            )
            write_provisioning_audit("ADD DEVICE", "FAILED", device_name, ip_address, f"Duplicate IP owned by {duplicate_ip_owner}")
            return provisioning_redirect(
                "error",
                f"IP address {ip_address} already belongs to {duplicate_ip_owner}."
            )

        config.setdefault("devices", {})
        config.setdefault("device_types", {})
        config.setdefault("device_relationships", {})
        config.setdefault("switch_ports", {})
        config.setdefault("infrastructure", {})
        config.setdefault("infrastructure_devices", {})
        config.setdefault("sleep_detection", {})
        config.setdefault("provisioned_virtual_inheritance", {})
        config["sleep_detection"].setdefault("sleep_allowed_devices", [])

        if provisioning_type == "physical":
            if not switch_port:
                write_event(f"ERROR | SMART PROVISIONING | Physical device requires switch port: {device_name}")
                write_provisioning_audit("ADD PHYSICAL", "FAILED", device_name, ip_address, "Missing switch port")
                return provisioning_redirect("error", "Physical devices require an available switch port.")

            if switch_port not in get_available_ports():
                write_event(f"ERROR | SMART PROVISIONING | Switch port is not available from SNMP: {switch_port}")
                write_provisioning_audit("ADD PHYSICAL", "FAILED", device_name, ip_address, f"SNMP switch port not available: {switch_port}")
                return provisioning_redirect("error", f"Switch port {switch_port} is not available from SNMP discovery.")

            if switch_port in config.get("switch_ports", {}):
                write_event(f"ERROR | SMART PROVISIONING | Switch port already assigned: {switch_port}")
                write_provisioning_audit("ADD PHYSICAL", "FAILED", device_name, ip_address, f"Switch port already assigned: {switch_port}")
                return provisioning_redirect("error", f"Switch port {switch_port} is already assigned.")

            config["devices"][device_name] = ip_address
            config["device_types"][device_name] = physical_device_type or "Physical Device"
            config["switch_ports"][switch_port] = device_name

            endpoint_topology_link = ensure_endpoint_topology_link_for_switch_port(device_name, switch_port)

            port_label = get_switch_port_label(switch_port)
            connection_label = port_label

            write_event(
                f"CONFIG | SMART PROVISIONING | Physical device added | {device_name} | IP {ip_address} | Port {port_label} | topology link auto-created"
            )

            success_message = f"Physical device provisioned: {device_name} ({ip_address}) on {port_label}"
            write_provisioning_audit("ADD PHYSICAL", "SUCCESS", device_name, ip_address, f"Port {port_label}")

        elif provisioning_type == "virtual":
            if not hosted_by:
                write_event(f"ERROR | SMART PROVISIONING | Virtual machine requires hosted-by parent: {device_name}")
                write_provisioning_audit("ADD VIRTUAL", "FAILED", device_name, ip_address, "Missing host device")
                return provisioning_redirect("error", "Virtual machines require a host device.")

            if hosted_by not in config.get("devices", {}):
                write_event(f"ERROR | SMART PROVISIONING | VM host not found: {hosted_by}")
                write_provisioning_audit("ADD VIRTUAL", "FAILED", device_name, ip_address, f"Host not found: {hosted_by}")
                return provisioning_redirect("error", f"VM host not found: {hosted_by}")

            if hosted_by == device_name:
                write_event(f"ERROR | SMART PROVISIONING | Device cannot host itself: {device_name}")
                write_provisioning_audit("ADD VIRTUAL", "FAILED", device_name, ip_address, "Self-hosting blocked")
                return provisioning_redirect("error", "A device cannot be hosted by itself.")

            hosted_by_type = clean_ascii(config.get("device_types", {}).get(hosted_by, "")).lower()

            if "virtual" in hosted_by_type or "vm" in hosted_by_type:
                write_event(f"ERROR | SMART PROVISIONING | VM host cannot be another VM: {hosted_by}")
                write_provisioning_audit("ADD VIRTUAL", "FAILED", device_name, ip_address, f"VM host is not eligible: {hosted_by}")
                return provisioning_redirect("error", "A virtual machine cannot be used as the VM host.")

            config["devices"][device_name] = ip_address
            config["device_types"][device_name] = "Virtual Machine"
            virtual_relationship_name = config.get(
                "provisioning_defaults", {}
            ).get(
                "virtual_relationship",
                "Hosted Virtual Machine",
            )
            phase27_write_relationship(
                parent=hosted_by,
                child=device_name,
                relationship_type="VIRTUAL",
                relationship_state="MANUAL",
                confidence=100,
                currently_verified=True,
                active=True,
                evidence_sources=["PROVISIONING"],
                evidence_id=f"provisioning:{hosted_by}:{device_name}",
                source="PROVISIONING",
                state_details=virtual_relationship_name,
                metadata={
                    "phase": "27B",
                    "provisioning_type": "virtual",
                    "manager_first_write": True,
                },
                legacy_relationship=virtual_relationship_name,
                selection_source="smart_provisioning",
                save=False,
            )

            inherited_port = get_switch_port_for_device(hosted_by)
            config["provisioned_virtual_inheritance"][device_name] = {
                "host": hosted_by,
                "inherited_switch_port_index": inherited_port.get("index", ""),
                "inherited_switch_port_label": inherited_port.get("label", "No physical host port mapped")
            }

            connection_label = f"Hosted by {hosted_by} | Inherited Port: {inherited_port.get('label', 'No physical host port mapped')}"

            write_event(
                f"CONFIG | SMART PROVISIONING | Virtual machine added | {device_name} | IP {ip_address} | Hosted By {hosted_by} | Inherited Port {inherited_port.get('label')}"
            )

            success_message = f"Virtual machine provisioned: {device_name} ({ip_address}) hosted by {hosted_by}"
            write_provisioning_audit("ADD VIRTUAL", "SUCCESS", device_name, ip_address, connection_label)

        elif provisioning_type == "infrastructure":
            if not infrastructure_role:
                write_event(f"ERROR | SMART PROVISIONING | Infrastructure device requires role: {device_name}")
                write_provisioning_audit("ADD INFRASTRUCTURE", "FAILED", device_name, ip_address, "Missing infrastructure role")
                return provisioning_redirect("error", "Infrastructure devices require a role.")

            role_type_map = {
                "internet": "Internet",
                "modem": "Modem",
                "router": "Router",
                "switch": "Switch",
                "firewall": "Firewall",
                "access_point": "Access Point",
                "ups": "UPS",
                "dns": "DNS Server",
                "dhcp": "DHCP Server",
                "vpn": "VPN Gateway"
            }

            config["devices"][device_name] = ip_address
            config["device_types"][device_name] = role_type_map.get(infrastructure_role, "Infrastructure")
            connection_label = role_type_map.get(infrastructure_role, infrastructure_role)

            register_infrastructure_device(
                device_name,
                ip_address,
                connection_label,
                is_snmp_capable_infrastructure_role(connection_label)
            )

            rebuild_auto_infrastructure_links()
            auto_parent = clean_ascii(
                config.get("device_relationships", {})
                .get(device_name, {})
                .get("parent", "")
            )
            if auto_parent:
                connection_label = f"{connection_label} | Parent: {auto_parent}"

            write_event(
                f"CONFIG | SMART PROVISIONING | Infrastructure device added | {device_name} | IP {ip_address} | Role {infrastructure_role}"
            )

            success_message = f"Infrastructure device provisioned: {device_name} ({ip_address}) as {connection_label}"
            write_provisioning_audit("ADD INFRASTRUCTURE", "SUCCESS", device_name, ip_address, connection_label)

        else:
            write_event(f"ERROR | SMART PROVISIONING | Unknown provisioning type: {provisioning_type}")
            write_provisioning_audit("ADD DEVICE", "FAILED", device_name, ip_address, f"Unknown type: {provisioning_type}")
            return provisioning_redirect("error", "Unknown provisioning type selected.")

        mark_device_provisioning_grace(device_name)

        # Phase 16B: save, reload runtime globals, then immediately discover
        # interfaces for SNMP-managed infrastructure devices. This is what makes
        # a newly provisioned router show Gi/Fa/Te interfaces in the topology
        # builder right away.
        save_config()
        load_config()
        discovered_interface_count = run_phase16b_interface_discovery_for_device(device_name)
        refresh_runtime_data()

        if discovered_interface_count:
            success_message = f"{success_message} | SNMP interfaces discovered: {discovered_interface_count}"

        return provisioning_redirect(
            "success",
            success_message,
            device_name,
            ip_address,
            provisioning_type.title(),
            connection_label
        )

    except Exception as e:
        config.clear()
        config.update(original_config)
        save_config()
        write_event(f"ERROR | SMART PROVISIONING ROLLBACK | {device_name} ({ip_address}) | {e}")
        write_provisioning_audit("ADD DEVICE", "ROLLBACK", device_name, ip_address, str(e))
        refresh_runtime_data()
        return provisioning_redirect("error", f"Provisioning failed and was rolled back: {e}")





@app.route("/scheduled-maintenance/add", methods=["POST"])
def scheduled_maintenance_add():
    load_config()

    device_name = clean_ascii(request.form.get("scheduled_device_name", "")) or clean_ascii(request.form.get("device_name", ""))
    days = request.form.getlist("days")
    start_time = clean_ascii(request.form.get("start_time", ""))
    end_time = clean_ascii(request.form.get("end_time", ""))
    reason = clean_ascii(request.form.get("reason", "Scheduled Maintenance"))

    if not device_name or device_name not in config.get("devices", {}):
        write_event(f"ERROR | SCHEDULED MAINTENANCE | Device not found: {device_name}")
        return redirect(url_for("dashboard"))

    if not normalize_schedule_days(days):
        write_event(f"ERROR | SCHEDULED MAINTENANCE | No valid days selected for {device_name}")
        return redirect(url_for("dashboard"))

    if not parse_hhmm(start_time) or not parse_hhmm(end_time):
        write_event(f"ERROR | SCHEDULED MAINTENANCE | Invalid time window for {device_name}")
        return redirect(url_for("dashboard"))

    schedule = create_scheduled_maintenance(
        device_name,
        days,
        start_time,
        end_time,
        reason
    )

    if is_now_inside_schedule(schedule):
        apply_scheduled_maintenance()

    save_config()
    refresh_runtime_data()

    write_event(
        f"CONFIG | SCHEDULED MAINTENANCE CREATED | {device_name} | "
        f"{', '.join(schedule.get('days', []))} {start_time}-{end_time} | Reason {reason}"
    )

    return redirect(url_for("dashboard"))


@app.route("/scheduled-maintenance/delete", methods=["POST"])
def scheduled_maintenance_delete():
    load_config()

    schedule_id = clean_ascii(request.form.get("schedule_id", ""))

    if delete_scheduled_maintenance(schedule_id):
        save_config()
        refresh_runtime_data()
        write_event(f"CONFIG | SCHEDULED MAINTENANCE DELETED | Schedule {schedule_id}")
    else:
        write_event(f"ERROR | SCHEDULED MAINTENANCE DELETE | Schedule not found: {schedule_id}")

    return redirect(url_for("dashboard"))

@app.route("/maintenance/start", methods=["POST"])
def maintenance_start():
    load_config()

    device_name = clean_ascii(request.form.get("device_name", ""))
    duration_minutes = clean_ascii(request.form.get("duration_minutes", "60"))
    reason = clean_ascii(request.form.get("reason", "Maintenance"))

    if not device_name or device_name not in config.get("devices", {}):
        write_event(f"ERROR | MAINTENANCE START | Device not found: {device_name}")
        return redirect(url_for("dashboard"))

    cleanup_expired_maintenance()
    start_device_maintenance(device_name, duration_minutes, reason)

    save_config()
    refresh_runtime_data()

    write_event(f"CONFIG | MAINTENANCE STARTED | {device_name} | Duration {duration_minutes} | Reason {reason}")

    return redirect(url_for("dashboard"))


@app.route("/maintenance/end", methods=["POST"])
def maintenance_end():
    load_config()

    device_name = clean_ascii(request.form.get("device_name", ""))

    if not device_name:
        write_event("ERROR | MAINTENANCE END | No device selected")
        return redirect(url_for("dashboard"))

    if end_device_maintenance(device_name):
        save_config()
        refresh_runtime_data()
        write_event(f"CONFIG | MAINTENANCE ENDED | {device_name} manually returned to monitoring")
    else:
        write_event(f"ERROR | MAINTENANCE END | Device was not in maintenance: {device_name}")

    return redirect(url_for("dashboard"))


@app.route("/api/maintenance-intelligence")
def api_maintenance_intelligence():
    load_config()
    cleanup_expired_maintenance()
    return jsonify({
        "success": True,
        "phase": "26B.7",
        "settings": get_phase26b7_settings(),
        "summary": build_maintenance_summary(),
        "history": get_phase26b7_maintenance_history(50)
    })


@app.route("/edit-device", methods=["POST"])
def edit_device():
    load_config()

    old_name = clean_ascii(request.form.get("old_name", "").strip())
    new_ip = clean_ascii(request.form.get("new_ip", "").strip())
    new_port = clean_ascii(request.form.get("new_port", "").strip())

    # Phase 13E safety rule:
    # Device names remain locked inventory keys. Editing updates IP and port only.
    if not old_name or not new_ip:
        write_event("ERROR | EDIT DEVICE | Missing required field")
        return redirect("/enterprise-inventory#device-management")

    if old_name not in config.get("devices", {}):
        write_event(f"ERROR | EDIT DEVICE | Device not found: {old_name}")
        return redirect("/enterprise-inventory#device-management")

    if not validate_ip(new_ip):
        write_event(f"ERROR | EDIT DEVICE | Invalid IP address: {new_ip}")
        return redirect("/enterprise-inventory#device-management")

    config.setdefault("switch_ports", {})
    config.setdefault("infrastructure_links", [])

    old_port = ""

    for port_index, port_device in list(config["switch_ports"].items()):
        if port_device == old_name:
            old_port = port_index
            config["switch_ports"].pop(port_index, None)

    remove_endpoint_topology_links_for_device(old_name)

    config["devices"][old_name] = new_ip

    if new_port:
        if new_port not in get_selectable_switch_ports():
            write_event(f"ERROR | EDIT DEVICE | Invalid switch port: {new_port}")
            return redirect("/enterprise-inventory#device-management")

        current_device_on_port = config["switch_ports"].get(new_port)
        if current_device_on_port and current_device_on_port != old_name:
            write_event(
                f"ERROR | EDIT DEVICE | Port {new_port} already assigned to {current_device_on_port}"
            )
            return redirect("/enterprise-inventory#device-management")

        config["switch_ports"][new_port] = old_name
        ensure_endpoint_topology_link_for_switch_port(old_name, new_port)

    save_config()
    refresh_runtime_data()

    write_event(
        f"CONFIG | DEVICE UPDATED | {old_name} | IP {new_ip} | Port {get_switch_port_label(new_port) if new_port else 'No mapped port'} | topology synced"
    )

    return redirect("/enterprise-inventory#device-management")


@app.route("/remove-device", methods=["POST"])
def remove_device():
    load_config()

    device_name = clean_ascii(request.form.get("device_name", "").strip())

    if not device_name:
        write_event("ERROR | REMOVE DEVICE | No device selected")
        return redirect("/enterprise-inventory#device-management")

    cleanup_result = cleanup_deleted_device_everywhere(device_name)

    save_config()
    refresh_runtime_data()

    write_event(
        f"CONFIG | DEVICE REMOVED | {device_name} | "
        f"ports removed: {cleanup_result.get('removed_ports', 0)} | "
        f"topology links removed: {cleanup_result.get('removed_links', 0)} | "
        "Phase 16D full cleanup complete"
    )

    return redirect("/enterprise-inventory#device-management")


@app.route("/clear-cisco-logs", methods=["POST"])
def clear_cisco_logs():
    try:
        with open(CISCO_LOG_FILE, "w") as f:
            f.truncate(0)

        write_event("CONFIG | CISCO EVENTS CLEARED")

    except Exception as e:
        write_event(f"ERROR | CLEAR CISCO EVENTS | {e}")

    return redirect(url_for("dashboard"))




# PHASE 10D.2 - ENTERPRISE EVENT LOG CENTER
# This page powers the left-side Dashboard link: /event-log
# It reads the Monitor Server log file: logs/events.log

def read_event_log_entries(limit=500):
    events = []

    if not os.path.exists(EVENT_LOG):
        return events

    try:
        with open(EVENT_LOG, "r", errors="ignore") as log:
            lines = log.readlines()[-limit:]
    except Exception as e:
        return [{
            "time": now(),
            "category": "ERROR",
            "level": "ERROR",
            "message": f"Unable to read event log: {e}",
            "raw": f"Unable to read event log: {e}",
            "css_class": "event-error"
        }]

    for line in reversed(lines):
        clean_line = clean_ascii(line.strip())

        if not clean_line:
            continue

        parts = clean_line.split(" | ", 2)

        if len(parts) >= 3:
            event_time = parts[0]
            category = parts[1]
            message = parts[2]
        elif len(parts) == 2:
            event_time = parts[0]
            category = "SYSTEM"
            message = parts[1]
        else:
            event_time = ""
            category = "SYSTEM"
            message = clean_line

        upper_line = clean_line.upper()

        if "ALERT" in upper_line:
            level = "ALERT"
            css_class = "event-alert"
        elif "RECOVERY" in upper_line or "WAKE" in upper_line:
            level = "RECOVERY"
            css_class = "event-recovery"
        elif "SLEEP" in upper_line or "SLEEPING" in upper_line:
            level = "SLEEP"
            css_class = "event-sleep"
        elif "CONFIG" in upper_line or "RESET CENTER" in upper_line:
            level = "CONFIG"
            css_class = "event-config"
        elif "ERROR" in upper_line:
            level = "ERROR"
            css_class = "event-error"
        elif "INTERNET" in upper_line:
            level = "INTERNET"
            css_class = "event-internet"
        else:
            level = "SYSTEM"
            css_class = "event-system"

        events.append({
            "time": event_time,
            "category": category,
            "level": level,
            "message": message,
            "raw": clean_line,
            "css_class": css_class
        })

    return events


@app.route("/event-log")
def event_log():
    events = read_event_log_entries(500)

    counts = {
        "total": len(events),
        "alerts": len([event for event in events if event.get("level") == "ALERT"]),
        "recoveries": len([event for event in events if event.get("level") == "RECOVERY"]),
        "config": len([event for event in events if event.get("level") == "CONFIG"]),
        "sleep": len([event for event in events if event.get("level") == "SLEEP"]),
        "errors": len([event for event in events if event.get("level") == "ERROR"]),
        "internet": len([event for event in events if event.get("level") == "INTERNET"]),
        "system": len([event for event in events if event.get("level") == "SYSTEM"])
    }

    return render_template(
        "event-log.html",
        events=events,
        counts=counts,
        last_full_scan=last_full_scan
    )


@app.route("/clear-event-log", methods=["POST"])
def clear_event_log():
    try:
        os.makedirs("logs", exist_ok=True)

        with open(EVENT_LOG, "w") as f:
            f.truncate(0)

    except Exception as e:
        print(f"Error clearing event log: {e}")

    return redirect(url_for("dashboard"))


@app.route("/alerts")
def alerts_page():
    active_alerts = get_active_alerts()
    history = sync_alert_history(active_alerts)

    active_history = [
        item for item in history
        if item.get("status") == "ACTIVE"
    ]

    resolved_history = [
        item for item in history
        if item.get("status") == "RESOLVED"
    ]

    critical_count = sum(1 for a in active_alerts if a["severity"] == "CRITICAL")
    warning_count = sum(1 for a in active_alerts if a["severity"] == "WARNING")
    info_count = sum(1 for a in active_alerts if a["severity"] == "INFO")

    acknowledged_count = sum(1 for a in active_alerts if a.get("acknowledged"))
    unacknowledged_count = sum(1 for a in active_alerts if not a.get("acknowledged"))

    return render_template(
        "alerts.html",
        alerts=active_alerts,
        active_history=active_history,
        resolved_history=list(reversed(resolved_history[-20:])),
        critical_count=critical_count,
        warning_count=warning_count,
        info_count=info_count,
        acknowledged_count=acknowledged_count,
        unacknowledged_count=unacknowledged_count,
        last_full_scan=last_full_scan
    )


@app.route("/acknowledge-alert/<path:alert_id_value>", methods=["POST"])
def acknowledge_alert(alert_id_value):
    history = load_alert_history()

    for item in history:
        if item.get("id") == alert_id_value and item.get("status") == "ACTIVE":
            item["acknowledged"] = True
            write_event(
                f"CONFIG | ALERT ACKNOWLEDGED | {item.get('device')} | {item.get('problem')}"
            )

    save_alert_history(history)

    return redirect(url_for("alerts_page"))


@app.route("/clear-resolved-alerts", methods=["POST"])
def clear_resolved_alerts():
    history = load_alert_history()

    active_only = [
        item for item in history
        if item.get("status") == "ACTIVE"
    ]

    save_alert_history(active_only)

    write_event("CONFIG | RESOLVED ALERT HISTORY CLEARED")

    return redirect(url_for("alerts_page"))




def reset_notification_settings_to_safe_defaults():
    load_config()

    config["notifications"] = {
        "sms_enabled": False,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "email_sender": "",
        "email_app_password": "",
        "sms_recipient": ""
    }

    save_config()
    refresh_runtime_data()


@app.route("/internet-history")
def internet_history():
    load_config()

    history = load_internet_history()
    active_outages = load_uptime_stats().get("active_outages", {})

    active_history = []

    for outage in active_outages.values():
        start_time = outage.get("start_time", "")
        start_dt = parse_timestamp(start_time)
        duration_seconds = 0

        if start_dt:
            duration_seconds = max(
                0,
                int((datetime.now() - start_dt).total_seconds())
            )

        active_history.append({
            "start_time": start_time,
            "end_time": "Active",
            "duration": format_duration_seconds(duration_seconds),
            "duration_seconds": duration_seconds,
            "status": "ACTIVE",
            "targets": ", ".join(INTERNET_CHECK_TARGETS)
        })

    return render_template(
        "internet_uptime_history.html",
        last_full_scan=last_full_scan,
        active_history=active_history,
        history=history,
        total_history=len(history),
        internet_targets=INTERNET_CHECK_TARGETS,
        availability_report=get_internet_availability_report()
    )



@app.route("/reset-internet-availability", methods=["POST"])
def reset_internet_availability():
    reset_internet_availability_data()
    write_event("CONFIG | RESET CENTER | Internet availability reporting data reset")
    return redirect(url_for("reset_center"))


@app.route("/reset-internet-history", methods=["POST"])
def reset_internet_history():
    clear_internet_history()

    write_event("CONFIG | RESET CENTER | Internet uptime history cleared")

    return redirect(url_for("reset_center"))



@app.route("/backup-center")
def backup_center():
    backups = list_backup_files()
    restore_history = load_restore_audit()

    return render_template(
        "backup_center.html",
        last_full_scan=last_full_scan,
        backups=backups,
        backup_count=len(backups),
        backup_dir=BACKUP_DIR,
        restore_history=restore_history
    )


@app.route("/create-monitor-backup", methods=["POST"])
def create_monitor_backup_route():
    version_label = request.form.get("version_label", "phase7f").strip()
    description_label = request.form.get("description_label", "backupcenter").strip()

    try:
        filename = create_monitor_backup(version_label, description_label)
        write_event(f"CONFIG | BACKUP CENTER | Backup created: {filename}")

    except Exception as e:
        write_event(f"ERROR | BACKUP CENTER | Backup failed: {e}")

    return redirect(url_for("backup_center"))


@app.route("/download-backup/<path:filename>")
def download_backup(filename):
    safe_name = safe_backup_filename(filename)

    if not safe_name:
        write_event(f"ERROR | BACKUP CENTER | Invalid backup download request: {filename}")
        return redirect(url_for("backup_center"))

    backup_path = os.path.join(BACKUP_DIR, safe_name)

    if not os.path.exists(backup_path):
        write_event(f"ERROR | BACKUP CENTER | Backup file not found: {safe_name}")
        return redirect(url_for("backup_center"))

    return send_file(
        backup_path,
        as_attachment=True,
        download_name=safe_name
    )


@app.route("/delete-backup/<path:filename>", methods=["POST"])
def delete_backup(filename):
    safe_name = safe_backup_filename(filename)

    if not safe_name:
        write_event(f"ERROR | BACKUP CENTER | Invalid backup delete request: {filename}")
        return redirect(url_for("backup_center"))

    backup_path = os.path.join(BACKUP_DIR, safe_name)

    if os.path.exists(backup_path):
        os.remove(backup_path)
        write_event(f"CONFIG | BACKUP CENTER | Backup deleted: {safe_name}")

    return redirect(url_for("backup_center"))



@app.route("/restore-backup/<path:filename>", methods=["POST"])
def restore_backup_route(filename):
    """Phase 12C.1 route: start a background restore execution job."""
    safe_name = safe_backup_filename(filename)
    confirm_text = request.form.get("confirm_restore", "").strip().upper()

    if not safe_name:
        write_event(f"ERROR | RESTORE CENTER | Invalid restore request: {filename}")
        return redirect(url_for("backup_center"))

    if confirm_text != "RESTORE":
        write_event(f"ERROR | RESTORE CENTER | Restore confirmation failed for: {safe_name}")
        return redirect(url_for("backup_center"))

    try:
        result = restore_monitor_backup_async(safe_name, requested_by="Backup Center")
        write_event(f"CONFIG | RESTORE CENTER | Phase 12C.1 restore execution started for {safe_name}")
        add_restore_audit_entry(result)

    except Exception as e:
        write_event(f"ERROR | RESTORE CENTER | Restore route failed for {safe_name}: {e}")

    return redirect(url_for("backup_center"))


@app.route("/restore-status")
def restore_status():
    """JSON endpoint for the current Restore Execution Engine state."""
    history = load_restore_audit()
    latest = history[0] if history else None
    execution = load_restore_status()

    return jsonify({
        "restore_center": "enabled",
        "phase": "12C.1",
        "engine": "Restore Execution Engine",
        "execution": execution,
        "latest": latest,
        "history": history[:10]
    })



@app.route("/reset-center")
def reset_center():
    load_config()

    uptime_stats = load_uptime_stats()
    alert_history = load_alert_history()
    knowledge_notes = load_knowledge_base()
    notification_settings = get_notification_settings()

    active_alerts = [
        item for item in alert_history
        if item.get("status") == "ACTIVE"
    ]

    resolved_alerts = [
        item for item in alert_history
        if item.get("status") == "RESOLVED"
    ]

    return render_template(
        "reset_center.html",
        last_full_scan=last_full_scan,
        uptime_stats=uptime_stats,
        availability_report=get_internet_availability_report(),
        active_alert_count=len(active_alerts),
        resolved_alert_count=len(resolved_alerts),
        total_alerts=total_alerts,
        total_recoveries=total_recoveries,
        knowledge_note_count=len(knowledge_notes),
        sms_enabled=notification_settings.get("sms_enabled", False),
        internet_history_count=len(load_internet_history())
    )


@app.route("/reset-internet-uptime", methods=["POST"])
def reset_internet_uptime():
    fresh_stats = create_fresh_uptime_stats()
    save_uptime_stats(fresh_stats)

    write_event("CONFIG | RESET CENTER | Internet uptime statistics reset")

    return redirect(url_for("reset_center"))


@app.route("/reset-event-log", methods=["POST"])
def reset_event_log():
    try:
        os.makedirs("logs", exist_ok=True)

        with open(EVENT_LOG, "w") as f:
            f.truncate(0)

        write_event("CONFIG | RESET CENTER | Event log cleared")

    except Exception as e:
        write_event(f"ERROR | RESET CENTER | Event log clear failed: {e}")

    return redirect(url_for("reset_center"))


@app.route("/reset-cisco-events", methods=["POST"])
def reset_cisco_events():
    try:
        with open(CISCO_LOG_FILE, "w") as f:
            f.truncate(0)

        write_event("CONFIG | RESET CENTER | Cisco events cleared")

    except Exception as e:
        write_event(f"ERROR | RESET CENTER | Cisco events clear failed: {e}")

    return redirect(url_for("reset_center"))


@app.route("/reset-resolved-alerts", methods=["POST"])
def reset_resolved_alerts():
    history = load_alert_history()

    active_only = [
        item for item in history
        if item.get("status") == "ACTIVE"
    ]

    save_alert_history(active_only)

    write_event("CONFIG | RESET CENTER | Resolved alerts cleared")

    return redirect(url_for("reset_center"))



@app.route("/reset-alert-counters", methods=["POST"])
def reset_alert_counters():
    global total_alerts
    global total_recoveries

    total_alerts = 0
    total_recoveries = 0

    write_event("CONFIG | RESET CENTER | Total alert and recovery counters reset")

    return redirect(url_for("reset_center"))


@app.route("/reset-all-alert-history", methods=["POST"])
def reset_all_alert_history():
    save_alert_history([])

    write_event("CONFIG | RESET CENTER | Active and resolved alert history reset")

    return redirect(url_for("reset_center"))


@app.route("/reset-knowledge-base", methods=["POST"])
def reset_knowledge_base():
    save_knowledge_base([])

    write_event("CONFIG | RESET CENTER | Knowledge base notes reset")

    return redirect(url_for("reset_center"))


@app.route("/reset-notification-settings", methods=["POST"])
def reset_notification_settings():
    reset_notification_settings_to_safe_defaults()

    write_event("CONFIG | RESET CENTER | Notification settings reset to safe defaults")

    return redirect(url_for("reset_center"))




KB_CATEGORIES = [
    "Cisco",
    "Linux",
    "OpenMediaVault",
    "Mac",
    "Windows",
    "Network",
    "Dashboard",
    "General"
]


def normalize_knowledge_base_notes(notes):
    changed = False

    for note in notes:
        if "favorite" not in note:
            note["favorite"] = False
            changed = True

        if "created" not in note:
            note["created"] = now()
            changed = True

        if "category" not in note:
            note["category"] = "General"
            changed = True

        if "title" not in note:
            note["title"] = "Untitled Note"
            changed = True

        if "content" not in note:
            note["content"] = ""
            changed = True

    if changed:
        save_knowledge_base(notes)

    return notes


def filter_knowledge_base_notes(notes, search_query="", category_filter="All"):
    search_query = (search_query or "").strip().lower()
    category_filter = (category_filter or "All").strip()

    filtered = []

    for index, note in enumerate(notes):
        title = note.get("title", "")
        category = note.get("category", "General")
        content = note.get("content", "")

        matches_category = (
            category_filter == "All" or
            category == category_filter
        )

        searchable_text = f"{title} {category} {content}".lower()
        matches_search = (
            not search_query or
            search_query in searchable_text
        )

        if matches_category and matches_search:
            item = dict(note)
            item["index"] = index
            filtered.append(item)

    pinned_notes = [
        item for item in filtered
        if item.get("favorite", False)
    ]

    regular_notes = [
        item for item in filtered
        if not item.get("favorite", False)
    ]

    return pinned_notes, regular_notes


@app.route("/knowledge-base")
def knowledge_base():
    notes = normalize_knowledge_base_notes(load_knowledge_base())

    search_query = request.args.get("q", default="", type=str).strip()
    category_filter = request.args.get("category", default="All", type=str).strip()

    if not category_filter:
        category_filter = "All"

    edit_index = request.args.get("edit", default=None, type=int)
    edit_note = None

    if edit_index is not None and 0 <= edit_index < len(notes):
        edit_note = notes[edit_index]

    pinned_notes, regular_notes = filter_knowledge_base_notes(
        notes,
        search_query,
        category_filter
    )

    return render_template(
        "knowledge_base.html",
        notes=notes,
        pinned_notes=pinned_notes,
        regular_notes=regular_notes,
        search_query=search_query,
        category_filter=category_filter,
        categories=KB_CATEGORIES,
        total_notes=len(notes),
        result_count=len(pinned_notes) + len(regular_notes),
        pinned_count=sum(1 for note in notes if note.get("favorite", False)),
        last_full_scan=last_full_scan,
        edit_index=edit_index,
        edit_note=edit_note
    )


@app.route("/cisco-links")
def cisco_links():
    load_config()

    router_up = sum(1 for d in router_interfaces.values() if d["state"] == "UP")
    router_down = sum(1 for d in router_interfaces.values() if d["state"] == "DOWN")

    switch_up = sum(1 for d in switch_links.values() if d["state"] == "UP")
    switch_down = sum(1 for d in switch_links.values() if d["state"] == "DOWN")

    total_links = router_up + router_down + switch_up + switch_down
    total_up = router_up + switch_up
    total_down = router_down + switch_down
    link_health = round((total_up / total_links) * 100) if total_links > 0 else 0

    phase14_dependency_engine = build_phase14_dependency_engine()

    return render_template(
        "cisco_links.html",
        alerts=get_active_alerts(),
        phase14_dependency_engine=phase14_dependency_engine,
        router_interfaces=router_interfaces,
        switch_links=switch_links,
        router_up=router_up,
        router_down=router_down,
        switch_up=switch_up,
        switch_down=switch_down,
        total_links=total_links,
        total_up=total_up,
        total_down=total_down,
        link_health=link_health,
        last_full_scan=last_full_scan
    )


@app.route("/device-status")
def device_status():
    load_config()

    total = len(status)
    up = sum(1 for d in status.values() if d["state"] == "UP")
    down = sum(1 for d in status.values() if d["state"] == "DOWN")
    error = sum(1 for d in status.values() if d["state"] == "ERROR")
    health = round((up / total) * 100) if total > 0 else 0
    phase14_dependency_engine = build_phase14_dependency_engine()
    phase14_device_dependency_lookup = build_phase14_device_dependency_lookup(phase14_dependency_engine)

    return render_template(
        "device_status.html",
        alerts=get_active_alerts(),
        phase14_dependency_engine=phase14_dependency_engine,
        phase14_device_dependency_lookup=phase14_device_dependency_lookup,
        status=status,
        total=total,
        up=up,
        down=down,
        error=error,
        health=health,
        last_full_scan=last_full_scan
    )


@app.route("/add-note", methods=["POST"])
def add_note():
    notes = normalize_knowledge_base_notes(load_knowledge_base())

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()
    favorite = request.form.get("favorite") == "on"

    if not title or not category or not content:
        write_event("ERROR | KNOWLEDGE BASE | Missing required field")
        return redirect(url_for("knowledge_base"))

    notes.append({
        "title": title,
        "category": category,
        "content": content,
        "created": now(),
        "updated": "",
        "favorite": favorite
    })

    save_knowledge_base(notes)

    write_event(f"CONFIG | KNOWLEDGE BASE NOTE ADDED | {title}")

    return redirect(url_for("knowledge_base"))


@app.route("/update-note/<int:index>", methods=["POST"])
def update_note(index):
    notes = normalize_knowledge_base_notes(load_knowledge_base())

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()
    favorite = request.form.get("favorite") == "on"

    if not title or not category or not content:
        write_event("ERROR | KNOWLEDGE BASE | Edit note missing required field")
        return redirect(url_for("knowledge_base", edit=index))

    if 0 <= index < len(notes):
        original_created = notes[index].get("created", now())

        notes[index] = {
            "title": title,
            "category": category,
            "content": content,
            "created": original_created,
            "updated": now(),
            "favorite": favorite
        }

        save_knowledge_base(notes)
        write_event(f"CONFIG | KNOWLEDGE BASE NOTE UPDATED | {title}")

    return redirect(url_for("knowledge_base"))


@app.route("/delete-note/<int:index>", methods=["GET", "POST"])
def delete_note(index):
    notes = normalize_knowledge_base_notes(load_knowledge_base())

    if 0 <= index < len(notes):
        removed = notes.pop(index)
        save_knowledge_base(notes)
        write_event(f"CONFIG | KNOWLEDGE BASE NOTE REMOVED | {removed.get('title', 'Unknown')}")

    return redirect(url_for("knowledge_base"))


@app.route("/toggle-note-pin/<int:index>", methods=["GET", "POST"])
def toggle_note_pin(index):
    notes = normalize_knowledge_base_notes(load_knowledge_base())

    if 0 <= index < len(notes):
        notes[index]["favorite"] = not notes[index].get("favorite", False)
        save_knowledge_base(notes)

        state = "PINNED" if notes[index].get("favorite", False) else "UNPINNED"
        write_event(f"CONFIG | KNOWLEDGE BASE NOTE {state} | {notes[index].get('title', 'Unknown')}")

    return redirect(request.referrer or url_for("knowledge_base"))


@app.route("/export-knowledge-base")
def export_knowledge_base():
    notes = normalize_knowledge_base_notes(load_knowledge_base())

    backup_data = json.dumps(notes, indent=4)

    filename = "knowledge_base_backup.json"

    return app.response_class(
        backup_data,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@app.route("/import-knowledge-base", methods=["POST"])
def import_knowledge_base():
    uploaded_file = request.files.get("knowledge_base_file")

    if not uploaded_file or uploaded_file.filename == "":
        write_event("ERROR | KNOWLEDGE BASE IMPORT | No file selected")
        return redirect(url_for("knowledge_base"))

    try:
        imported_data = json.load(uploaded_file)

        if not isinstance(imported_data, list):
            write_event("ERROR | KNOWLEDGE BASE IMPORT | Invalid backup format")
            return redirect(url_for("knowledge_base"))

        imported_data = normalize_knowledge_base_notes(imported_data)
        save_knowledge_base(imported_data)

        write_event(f"CONFIG | KNOWLEDGE BASE IMPORTED | {len(imported_data)} notes restored")

    except Exception as e:
        write_event(f"ERROR | KNOWLEDGE BASE IMPORT FAILED | {e}")

    return redirect(url_for("knowledge_base"))









# PHASE 11E - NOC COMMAND CENTER


# PHASE 12A - EXECUTIVE OPERATIONS CENTER (EOC)


# PHASE 12A.1 - EXECUTIVE LAYER REFINEMENT
def build_operations_layer_summary():
    """
    Phase 12A.1 <-> 12B.4 Synchronization Fix

    The NOC Command Center now gets its root cause, incident, and investigation
    counts from the synchronized NOC Correlation Engine and 12B.4 Root Cause
    Correlation Engine. This prevents the Command Center from showing:
        Root Causes = 0
    when the Root Cause Correlation Engine has already detected a live root cause.
    """

    active_alerts = get_active_alerts()
    maintenance = build_maintenance_summary()
    scheduled = build_scheduled_maintenance_summary()
    noc_correlation = build_noc_correlation_engine()
    root_engine = noc_correlation.get("root_cause_engine", build_root_cause_correlation_engine(active_alerts))
    lifecycle = build_lifecycle_summary()

    critical_count = sum(
        1 for alert in active_alerts
        if alert.get("severity") == "CRITICAL"
    )

    warning_count = sum(
        1 for alert in active_alerts
        if alert.get("severity") == "WARNING"
    )

    info_count = sum(
        1 for alert in active_alerts
        if alert.get("severity") == "INFO"
    )

    counts = lifecycle.get("counts", {})

    sleeping_count = int(counts.get("SLEEPING", 0))
    maintenance_count = int(counts.get("MAINTENANCE", 0))
    provisioning_count = int(counts.get("PROVISIONING", 0))

    root_state = clean_ascii(root_engine.get("state", "Healthy"))
    root_cause_name = clean_ascii(root_engine.get("root_cause", ""))
    root_type = clean_ascii(root_engine.get("root_type", ""))

    root_cause_detected = (
        root_state in ["Root Cause Detected", "Single Device Issue"] and
        root_cause_name and
        root_cause_name != "No active root cause" and
        root_type not in ["Healthy", "None", ""]
    )

    root_causes = int(noc_correlation.get("root_cause_count", 0))

    if root_cause_detected and root_causes < 1:
        root_causes = 1

    endpoint_issues = int(noc_correlation.get("endpoint_issue_count", 0))

    # One correlated root cause represents one active incident, even if it
    # affects a downstream endpoint. Endpoint issues only add additional
    # incidents when there is no correlated root cause suppressing them.
    if root_causes > 0:
        open_incidents = root_causes
    else:
        open_incidents = endpoint_issues + critical_count + warning_count

    investigating = open_incidents

    operator_actions = 0

    if root_causes > 0:
        operator_actions += 1

    if warning_count > 0:
        operator_actions += 1

    if maintenance_count > 0:
        operator_actions += 1

    if scheduled.get("active_count", 0) > 0:
        operator_actions += 1

    if sleeping_count > 0:
        operator_actions += 1

    if root_causes > 0:
        operations_state = "Root Cause Detected"
        next_action = (
            root_engine.get("operator_action") or
            "Investigate the correlated root cause before troubleshooting downstream devices."
        )

    elif warning_count > 0:
        operations_state = "Watch Warnings"
        next_action = (
            "Review endpoint warnings and decide if action is needed."
        )

    elif maintenance_count > 0:
        operations_state = "Maintenance Active"
        next_action = (
            "Monitor the maintenance window until it clears."
        )

    elif scheduled.get("active_count", 0) > 0:
        operations_state = "Scheduled Work"
        next_action = (
            "Scheduled maintenance is currently active."
        )

    elif sleeping_count > 0:
        operations_state = "Operational Context"
        next_action = (
            "Sleep-aware devices are being tracked."
        )

    else:
        operations_state = "Normal Operations"
        next_action = (
            "No operator action required."
        )

    return {
        "phase": "12A.1",
        "sync_phase": "12A.1-12B.4",
        "operations_state": operations_state,
        "root_causes": root_causes,
        "open_incidents": open_incidents,
        "investigating": investigating,
        "scheduled_work": scheduled.get("active_count", 0),
        "operator_actions": operator_actions,
        "endpoint_issues": endpoint_issues,
        "critical_alerts": critical_count,
        "warning_alerts": warning_count,
        "info_alerts": info_count,
        "maintenance_active": maintenance.get("active_count", 0),
        "sleeping": sleeping_count,
        "provisioning": provisioning_count,
        "root_cause_name": root_cause_name,
        "root_cause_type": root_type,
        "next_action": next_action
    }

def build_executive_operations_center():
    settings = config.get("executive_operations_center", {})
    active_alerts = get_active_alerts()
    command = build_noc_command_center()
    lifecycle = build_lifecycle_summary()
    maintenance = build_maintenance_summary()
    scheduled = build_scheduled_maintenance_summary()
    uptime_stats = get_uptime_dashboard_stats()
    availability_report = get_internet_availability_report()
    noc_correlation = build_noc_correlation_engine()

    critical_count = sum(1 for alert in active_alerts if alert.get("severity") == "CRITICAL")
    warning_count = sum(1 for alert in active_alerts if alert.get("severity") == "WARNING")
    info_count = sum(1 for alert in active_alerts if alert.get("severity") == "INFO")

    counts = lifecycle.get("counts", {})
    devices_total = len(DEVICES)
    devices_healthy = int(command.get("devices_healthy", 0))
    devices_up = int(command.get("devices_up", 0))
    sleeping = int(counts.get("SLEEPING", 0))
    maintenance_count = int(command.get("active_maintenance", 0))
    scheduled_active = int(scheduled.get("active_count", 0))
    health_percent = int(command.get("health_percent", 100))

    if critical_count > 0:
        eoc_state = "Critical"
        eoc_class = "critical"
        eoc_summary = "Critical infrastructure attention required."
    elif warning_count > 0:
        eoc_state = "Watch"
        eoc_class = "watch"
        eoc_summary = "Warning conditions detected. Review non-critical endpoint or link alerts."
    elif maintenance_count > 0 or scheduled_active > 0:
        eoc_state = "Maintenance"
        eoc_class = "maintenance"
        eoc_summary = "Maintenance activity is active or scheduled."
    elif sleeping > 0:
        eoc_state = "Operational"
        eoc_class = "operational"
        eoc_summary = "Sleep-aware devices are being handled as operational context."
    else:
        eoc_state = "Healthy"
        eoc_class = "healthy"
        eoc_summary = "Network is operating normally."

    top_issue = "No active issue"
    if active_alerts:
        top = sorted(
            active_alerts,
            key=lambda item: {"CRITICAL": 0, "WARNING": 1, "INFO": 2}.get(item.get("severity", "INFO"), 3)
        )[0]
        top_issue = f"{top.get('device', 'Unknown')}: {top.get('problem', 'Unknown')}"

    recommendations = command.get("recommendations", [])
    top_recommendation = command.get("top_recommendation", "No action required.")
    if recommendations:
        top_recommendation = recommendations[0].get("message", top_recommendation)

    historical = command.get("historical", {})
    top_history = historical.get("summary", "No actionable recurring historical issue detected.")

    uptime_ticker_items = [
        {
            "label": "Internet",
            "value": uptime_stats.get("network_uptime", "N/A")
        },
        {
            "label": "Today Outages",
            "value": uptime_stats.get("today_outages", "0")
        },
        {
            "label": "Last Outage",
            "value": uptime_stats.get("last_outage", "None")
        },
        {
            "label": "Availability Today",
            "value": availability_report.get("today", {}).get("availability", "N/A")
        },
        {
            "label": "Correlation",
            "value": f"{noc_correlation.get('health_score', 100)}%"
        },
        {
            "label": "Maintenance",
            "value": str(maintenance_count)
        }
    ]

    return {
        "enabled": settings.get("enabled", True),
        "phase": "12A",
        "name": "Executive Operations Center",
        "state": eoc_state,
        "state_class": eoc_class,
        "summary": eoc_summary,
        "health_percent": health_percent,
        "devices_total": devices_total,
        "devices_healthy": devices_healthy,
        "devices_up": devices_up,
        "critical_alerts": critical_count,
        "warning_alerts": warning_count,
        "info_alerts": info_count,
        "maintenance_count": maintenance_count,
        "scheduled_active": scheduled_active,
        "scheduled_total": scheduled.get("total", 0),
        "correlation_score": noc_correlation.get("health_score", 100),
        "correlation_state": noc_correlation.get("state_label", "Normal"),
        "sleeping": sleeping,
        "top_issue": top_issue,
        "top_recommendation": top_recommendation,
        "top_history": top_history,
        "top_device": historical.get("top_device", "N/A"),
        "last_full_scan": last_full_scan,
        "uptime_ticker_items": uptime_ticker_items
    }


def build_noc_command_center():
    active_alerts = get_active_alerts()
    lifecycle = build_lifecycle_summary()
    maintenance = build_maintenance_summary()
    scheduled = build_scheduled_maintenance_summary()
    noc_correlation = build_noc_correlation_engine()
    recommendations = build_noc_recommendations()
    historical = build_noc_historical_intelligence()

    counts = lifecycle.get("counts", {})
    total_devices = len(DEVICES)
    up_count = int(counts.get("UP", 0))
    sleeping_count = int(counts.get("SLEEPING", 0))
    maintenance_count = int(counts.get("MAINTENANCE", 0))
    provisioning_count = int(counts.get("PROVISIONING", 0))
    down_count = int(counts.get("DOWN", 0))
    offline_count = int(counts.get("OFFLINE", 0))

    critical_count = sum(1 for alert in active_alerts if alert.get("severity") == "CRITICAL")
    warning_count = sum(1 for alert in active_alerts if alert.get("severity") == "WARNING")

    network_state = "Healthy"
    state_class = "good"

    if critical_count > 0 or down_count > 0:
        network_state = "Attention"
        state_class = "critical"
    elif warning_count > 0 or offline_count > 0:
        network_state = "Watch"
        state_class = "warning"
    elif maintenance_count > 0 or scheduled.get("active_count", 0) > 0:
        network_state = "Maintenance"
        state_class = "maintenance"
    elif sleeping_count > 0 or provisioning_count > 0:
        network_state = "Operational"
        state_class = "info"

    healthy_count = up_count + sleeping_count + maintenance_count + provisioning_count
    health_percent = round((healthy_count / total_devices) * 100) if total_devices else 100

    if critical_count > 0:
        recommendation = "Review active critical alerts immediately."
    elif down_count > 0:
        recommendation = "Investigate down devices and check NOC Correlation for root cause."
    elif maintenance_count > 0:
        recommendation = "Maintenance is active. Monitor the active maintenance window."
    elif scheduled.get("total", 0) > 0:
        recommendation = "Scheduled maintenance is configured. No immediate action required."
    elif sleeping_count > 0:
        recommendation = "Sleep-aware devices are being tracked. No action required."
    else:
        recommendation = "No action required. Network operating normally."

    return {
        "enabled": config.get("noc_command_center", {}).get("enabled", True),
        "network_state": network_state,
        "state_class": state_class,
        "health_percent": health_percent,
        "devices_total": total_devices,
        "devices_up": up_count,
        "devices_healthy": healthy_count,
        "critical_alerts": critical_count,
        "warning_alerts": warning_count,
        "active_maintenance": maintenance.get("active_count", 0),
        "scheduled_total": scheduled.get("total", 0),
        "scheduled_active": scheduled.get("active_count", 0),
        "sleeping": sleeping_count,
        "provisioning": provisioning_count,
        "down": down_count,
        "offline": offline_count,
        "correlation_score": noc_correlation.get("health_score", 100),
        "correlation_state": noc_correlation.get("state_label", "Normal"),
        "top_recommendation": recommendation,
        "correlation_recommendation": noc_correlation.get("recommendation", ""),
        "recommendations": recommendations,
        "historical": historical
    }


# PHASE 11D - SCHEDULED MAINTENANCE ENGINE
def get_scheduled_maintenance_config():
    return config.setdefault("scheduled_maintenance", {
        "enabled": True,
        "schedules": []
    })


def normalize_schedule_days(days):
    if isinstance(days, str):
        days = [days]

    normalized = []

    valid_days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    for day in days or []:
        clean_day = clean_ascii(day).title()
        if clean_day in valid_days and clean_day not in normalized:
            normalized.append(clean_day)

    return normalized


def parse_hhmm(value):
    value = clean_ascii(value)

    try:
        return datetime.strptime(value, "%H:%M").time()
    except Exception:
        return None


def is_now_inside_schedule(schedule):
    if not schedule.get("enabled", True):
        return False

    current = datetime.now()
    current_day = current.strftime("%A")
    current_time = current.time()

    days = normalize_schedule_days(schedule.get("days", []))

    if current_day not in days:
        return False

    start_time = parse_hhmm(schedule.get("start_time", ""))
    end_time = parse_hhmm(schedule.get("end_time", ""))

    if not start_time or not end_time:
        return False

    # Same-day window, example 02:00 to 03:00
    if start_time <= end_time:
        return start_time <= current_time < end_time

    # Overnight window, example 23:00 to 02:00
    return current_time >= start_time or current_time < end_time


def get_schedule_by_id(schedule_id):
    for schedule in get_scheduled_maintenance_config().get("schedules", []):
        if clean_ascii(schedule.get("id", "")) == clean_ascii(schedule_id):
            return schedule

    return {}


def schedule_device_is_active(device_name, schedule_id):
    active_record = get_active_maintenance_records().get(device_name, {})

    return clean_ascii(active_record.get("source", "")) == "scheduled" and clean_ascii(active_record.get("schedule_id", "")) == clean_ascii(schedule_id)


def start_scheduled_maintenance(schedule):
    device_name = clean_ascii(schedule.get("device_name", ""))

    if not device_name or device_name not in config.get("devices", {}):
        return False

    if is_device_in_maintenance(device_name):
        return False

    config.setdefault("maintenance_mode", {})
    config["maintenance_mode"].setdefault("active", {})

    schedule_id = clean_ascii(schedule.get("id", ""))
    reason = clean_ascii(schedule.get("reason", "")) or "Scheduled Maintenance"

    config["maintenance_mode"]["active"][device_name] = {
        "start": now(),
        "until": "MANUAL",
        "duration_minutes": "scheduled",
        "reason": reason,
        "source": "scheduled",
        "schedule_id": schedule_id
    }

    write_event(f"CONFIG | SCHEDULED MAINTENANCE STARTED | {device_name} | Schedule {schedule_id} | Reason {reason}")
    return True


def end_scheduled_maintenance(schedule):
    device_name = clean_ascii(schedule.get("device_name", ""))
    schedule_id = clean_ascii(schedule.get("id", ""))

    if not device_name:
        return False

    active_record = get_active_maintenance_records().get(device_name, {})

    if clean_ascii(active_record.get("source", "")) != "scheduled":
        return False

    if clean_ascii(active_record.get("schedule_id", "")) != schedule_id:
        return False

    if end_device_maintenance(device_name):
        write_event(f"CONFIG | SCHEDULED MAINTENANCE ENDED | {device_name} | Schedule {schedule_id}")
        return True

    return False


def apply_scheduled_maintenance():
    scheduled_config = get_scheduled_maintenance_config()

    if not scheduled_config.get("enabled", True):
        return False

    changed = False

    for schedule in scheduled_config.get("schedules", []):
        device_name = clean_ascii(schedule.get("device_name", ""))
        schedule_id = clean_ascii(schedule.get("id", ""))

        if not device_name or not schedule_id:
            continue

        inside_window = is_now_inside_schedule(schedule)
        scheduled_active = schedule_device_is_active(device_name, schedule_id)

        if inside_window and not is_device_in_maintenance(device_name):
            if start_scheduled_maintenance(schedule):
                changed = True

        elif not inside_window and scheduled_active:
            if end_scheduled_maintenance(schedule):
                changed = True

    return changed


def build_scheduled_maintenance_summary():
    schedules = []

    for schedule in get_scheduled_maintenance_config().get("schedules", []):
        device_name = clean_ascii(schedule.get("device_name", ""))
        schedule_id = clean_ascii(schedule.get("id", ""))
        inside_window = is_now_inside_schedule(schedule)
        active = schedule_device_is_active(device_name, schedule_id)

        schedules.append({
            "id": schedule_id,
            "device_name": device_name,
            "ip": DEVICES.get(device_name, ""),
            "days": ", ".join(normalize_schedule_days(schedule.get("days", []))),
            "start_time": clean_ascii(schedule.get("start_time", "")),
            "end_time": clean_ascii(schedule.get("end_time", "")),
            "reason": clean_ascii(schedule.get("reason", "Scheduled Maintenance")),
            "enabled": bool(schedule.get("enabled", True)),
            "inside_window": inside_window,
            "active": active
        })

    active_count = sum(1 for item in schedules if item.get("active"))
    enabled_count = sum(1 for item in schedules if item.get("enabled"))

    return {
        "enabled": get_scheduled_maintenance_config().get("enabled", True),
        "total": len(schedules),
        "enabled_count": enabled_count,
        "active_count": active_count,
        "schedules": schedules
    }


def create_scheduled_maintenance(device_name, days, start_time, end_time, reason):
    scheduled_config = get_scheduled_maintenance_config()
    scheduled_config.setdefault("schedules", [])

    schedule_id = datetime.now().strftime("%Y%m%d%H%M%S")

    schedule = {
        "id": schedule_id,
        "enabled": True,
        "device_name": clean_ascii(device_name),
        "days": normalize_schedule_days(days),
        "start_time": clean_ascii(start_time),
        "end_time": clean_ascii(end_time),
        "reason": clean_ascii(reason) or "Scheduled Maintenance"
    }

    scheduled_config["schedules"].append(schedule)

    return schedule


def delete_scheduled_maintenance(schedule_id):
    scheduled_config = get_scheduled_maintenance_config()
    schedules = scheduled_config.get("schedules", [])
    target = get_schedule_by_id(schedule_id)

    if target:
        end_scheduled_maintenance(target)

    new_schedules = [
        schedule for schedule in schedules
        if clean_ascii(schedule.get("id", "")) != clean_ascii(schedule_id)
    ]

    changed = len(new_schedules) != len(schedules)
    scheduled_config["schedules"] = new_schedules

    return changed


# PHASE 11C - NOC INTELLIGENCE CORRELATION ENGINE
def get_switch_port_for_device_name(device_name):
    for index, mapped_name in SWITCH_PORTS.items():
        if clean_ascii(mapped_name).lower() == clean_ascii(device_name).lower():
            link_info = switch_links.get(index, {})
            return {
                "index": index,
                "port": get_dynamic_switch_port_label(index, link_info.get("port", index)),
                "state": link_info.get("state", "UNKNOWN"),
                "raw_state": link_info.get("raw_state", link_info.get("state", "UNKNOWN")),
                "last_checked": link_info.get("last_checked", "Starting...")
            }

    return {}


def get_device_parent_path(device_name):
    """Build a parent path from reconciled physical topology and VM relationships."""
    device_name = clean_ascii(device_name)
    topology = config.get("phase26b4_topology", {})
    parent_by_child = topology.get("parent_by_child", {}) if isinstance(topology, dict) else {}
    if not parent_by_child:
        reconciled = reconcile_phase26_infrastructure_topology(
            get_physical_topology_config(),
            set(get_all_infrastructure_names()),
            get_infrastructure_devices(),
        )
        parent_by_child = reconciled.get("parent_by_child", {})

    relationship = DEVICE_RELATIONSHIPS.get(device_name, {})
    virtual_parent = clean_ascii(relationship.get("parent", relationship.get("hosted_by", ""))) if is_virtual_child_device(device_name) else ""
    current = virtual_parent or clean_ascii(parent_by_child.get(device_name, ""))
    path = []
    seen = {device_name}
    while current and current not in seen:
        seen.add(current)
        path.append(current)
        current = clean_ascii(parent_by_child.get(current, ""))
    path.reverse()
    return path


def classify_noc_correlation(device_name, lifecycle_state):
    switch_port = get_switch_port_for_device_name(device_name)
    device_class = get_device_classification(device_name)
    relationship = DEVICE_RELATIONSHIPS.get(device_name, {})
    hosted_by = relationship.get("hosted_by", "")

    if lifecycle_state == "MAINTENANCE":
        return {
            "category": "Maintenance",
            "severity": "INFO",
            "root_cause": device_name,
            "recommendation": "No action required. Device is intentionally in maintenance mode.",
            "evidence": "Maintenance Mode is active."
        }

    if lifecycle_state == "PROVISIONING":
        return {
            "category": "Provisioning",
            "severity": "INFO",
            "root_cause": device_name,
            "recommendation": "No action required. Device is still inside the provisioning grace period.",
            "evidence": "Provisioning grace period is active."
        }

    if lifecycle_state == "SLEEPING":
        return {
            "category": "Sleep State",
            "severity": "INFO",
            "root_cause": device_name,
            "recommendation": "No action required. Device appears to be sleeping and is sleep-aware.",
            "evidence": "Sleep Detection Engine classified the device as sleeping."
        }

    if lifecycle_state == "UP":
        return {
            "category": "Healthy",
            "severity": "OK",
            "root_cause": "None",
            "recommendation": "No action required.",
            "evidence": "Device is responding."
        }

    if device_name in get_all_infrastructure_names():
        return {
            "category": "Infrastructure Failure",
            "severity": "CRITICAL",
            "root_cause": device_name,
            "recommendation": f"Investigate {device_name} first. This may affect downstream devices.",
            "evidence": "Core infrastructure device is not healthy."
        }

    if hosted_by:
        host_state = status.get(hosted_by, {}).get("state", "UNKNOWN")
        if host_state != "UP":
            return {
                "category": "Dependent System",
                "severity": "WARNING",
                "root_cause": hosted_by,
                "recommendation": f"Check host system {hosted_by}. This device depends on that host.",
                "evidence": f"Hosted by {hosted_by}; host state is {host_state}."
            }

    if switch_port:
        port_state = switch_port.get("state", "UNKNOWN")
        if port_state == "UP":
            return {
                "category": "Endpoint Issue",
                "severity": "WARNING",
                "root_cause": device_name,
                "recommendation": f"Switch port {switch_port.get('port')} is up, but {device_name} is not responding. Check the endpoint.",
                "evidence": f"Device state is {lifecycle_state}; switch port {switch_port.get('port')} is UP."
            }

        if port_state == "DOWN":
            return {
                "category": "Cable / Port Issue",
                "severity": "WARNING",
                "root_cause": switch_port.get("port", "Unknown Port"),
                "recommendation": f"Check cable, power, or switch port {switch_port.get('port')} for {device_name}.",
                "evidence": f"Device state is {lifecycle_state}; switch port {switch_port.get('port')} is DOWN."
            }

    return {
        "category": "Unmapped Endpoint Issue",
        "severity": "WARNING",
        "root_cause": device_name,
        "recommendation": f"Check {device_name}. No switch-port relationship was found.",
        "evidence": f"Device state is {lifecycle_state}; no mapped port was found."
    }


def build_noc_correlation_engine():
    """
    Phase 12A.1 <-> 12B.4 Engine Synchronization Fix

    This version keeps the older Phase 11C NOC Intelligence table,
    but synchronizes its counters with the Phase 12B.4 Root Cause
    Correlation Engine so all dashboard layers agree.

    Main sync behavior:
    - If 12B.4 detects a true root cause, NOC Intelligence reports 1 root cause.
    - Downstream endpoint alerts are treated as affected devices, not duplicate incidents.
    - Operational states such as maintenance, sleep, and provisioning still display as context.
    """

    lifecycle = build_lifecycle_summary()
    active_alerts = get_active_alerts()
    root_cause_engine = build_root_cause_correlation_engine(active_alerts)

    findings = []

    root_state = clean_ascii(root_cause_engine.get("state", "Healthy"))
    root_cause_name = clean_ascii(root_cause_engine.get("root_cause", ""))
    root_type = clean_ascii(root_cause_engine.get("root_type", ""))
    affected_device = clean_ascii(root_cause_engine.get("affected_device", ""))
    affected_port = clean_ascii(root_cause_engine.get("affected_port", ""))
    operator_action = clean_ascii(root_cause_engine.get("operator_action", ""))
    selected_severity = clean_ascii(root_cause_engine.get("selected_alert_severity", "INFO")).upper()

    root_causes = []
    endpoint_issues = []
    operational_states = []

    true_root_detected = (
        root_state in ["Root Cause Detected", "Single Device Issue"] and
        root_cause_name and
        root_cause_name != "No active root cause" and
        root_type not in ["Healthy", "None", ""]
    )

    if true_root_detected:
        if root_type in ["Physical Switch Port", "Router Interface"]:
            category = "Cable / Port Issue"
        elif root_type in ["Internet / ISP", "Modem / Gateway", "Router", "Switch"]:
            category = "Infrastructure Failure"
        elif root_type == "Endpoint":
            category = "Endpoint Issue"
        else:
            category = "Root Cause"

        root_finding = {
            "device": affected_device if affected_device not in ["", "None"] else root_cause_name,
            "ip": DEVICES.get(affected_device, ""),
            "state": root_state,
            "category": category,
            "severity": selected_severity if selected_severity in ["CRITICAL", "WARNING", "INFO"] else "WARNING",
            "root_cause": root_cause_name,
            "recommendation": operator_action or "Investigate the correlated root cause first.",
            "evidence": f"Affected port: {affected_port}" if affected_port and affected_port != "None" else root_type,
            "path": root_cause_name
        }

        findings.append(root_finding)

        if category in ["Infrastructure Failure", "Cable / Port Issue", "Root Cause"]:
            root_causes.append(root_finding)
        else:
            endpoint_issues.append(root_finding)

    for item in lifecycle.get("devices", []):
        device_name = item.get("device", "")
        lifecycle_state = item.get("state", "UNKNOWN")

        correlation = classify_noc_correlation(device_name, lifecycle_state)
        category = correlation.get("category", "Unknown")

        if category in ["Healthy"]:
            continue

        # If 12B.4 already identified the true root cause, do not double-count
        # the same affected endpoint as a second endpoint incident.
        if true_root_detected:
            affected_devices = root_cause_engine.get("affected_devices", [])
            if device_name == affected_device or device_name in affected_devices:
                if category not in ["Sleep State", "Maintenance", "Provisioning"]:
                    continue

        finding = {
            "device": device_name,
            "ip": DEVICES.get(device_name, ""),
            "state": lifecycle_state,
            "category": category,
            "severity": correlation.get("severity", "INFO"),
            "root_cause": correlation.get("root_cause", device_name),
            "recommendation": correlation.get("recommendation", ""),
            "evidence": correlation.get("evidence", ""),
            "path": " → ".join(get_device_parent_path(device_name) + [device_name])
        }

        findings.append(finding)

        if category in ["Infrastructure Failure", "Cable / Port Issue"]:
            root_causes.append(finding)
        elif category in ["Endpoint Issue", "Unmapped Endpoint Issue", "Dependent System"]:
            endpoint_issues.append(finding)
        elif category in ["Sleep State", "Maintenance", "Provisioning"]:
            operational_states.append(finding)

    cascading_events = 0
    infrastructure_names = sorted(get_all_infrastructure_names())

    for infra_name in infrastructure_names:
        infra_state = status.get(infra_name, {}).get("state", "UNKNOWN")
        if infra_state in ["DOWN", "ERROR", "UNKNOWN"]:
            affected = [
                name for name in DEVICES.keys()
                if infra_name in get_device_parent_path(name)
            ]
            cascading_events += len(affected)

    health_score = 100
    health_score -= len(root_causes) * 15
    health_score -= len(endpoint_issues) * 7
    health_score -= cascading_events * 3
    health_score = max(0, min(100, health_score))

    if root_causes:
        top = root_causes[0]
        recommendation = top.get("recommendation", "Investigate root cause candidate.")
        state_label = "Root Cause Detected"
    elif endpoint_issues:
        top = endpoint_issues[0]
        recommendation = top.get("recommendation", "Investigate endpoint issue.")
        state_label = "Endpoint Attention"
    elif operational_states:
        recommendation = "No critical issue detected. Operational states are being tracked."
        state_label = "Operational Awareness"
    else:
        recommendation = "No action required. No correlated issues detected."
        state_label = "Normal"

    return {
        "state_label": state_label,
        "health_score": health_score,
        "root_cause_count": len(root_causes),
        "endpoint_issue_count": len(endpoint_issues),
        "operational_state_count": len(operational_states),
        "cascading_event_count": cascading_events,
        "recommendation": recommendation,
        "findings": findings[:8],
        "root_cause_engine": root_cause_engine,
        "sync_phase": "12A.1-12B.4"
    }

def build_noc_correlation_html(noc_data):
    rows = ""

    for item in noc_data.get("findings", []):
        severity_class = clean_ascii(item.get("severity", "INFO")).lower()
        rows += (
            f"<tr>"
            f"<td><span class='noc-severity {severity_class}'>{item.get('severity', '')}</span></td>"
            f"<td>{item.get('device', '')}</td>"
            f"<td>{item.get('category', '')}</td>"
            f"<td>{item.get('root_cause', '')}</td>"
            f"<td>{item.get('recommendation', '')}<br><small>{item.get('evidence', '')}</small></td>"
            f"</tr>"
        )

    if not rows:
        rows = "<tr><td colspan='5'>No correlated issues detected.</td></tr>"

    return {
        "rows": rows
    }


# PHASE 11B - DEVICE LIFECYCLE ENGINE
LIFECYCLE_STATES = [
    "UP",
    "SLEEPING",
    "PROVISIONING",
    "MAINTENANCE",
    "DOWN",
    "OFFLINE",
    "DECOMMISSIONED"
]


def get_device_lifecycle_state(device_name):
    info = status.get(device_name, {})
    state = info.get("state", "UNKNOWN")

    if state == get_sleep_status_label():
        return "SLEEPING"

    if state == get_provisioning_state_label():
        return "PROVISIONING"

    if state == get_maintenance_state_label():
        return "MAINTENANCE"

    if state in ["UP", "DOWN", "OFFLINE", "DECOMMISSIONED"]:
        return state

    return "DOWN"


def build_lifecycle_summary():
    counts = {state_name: 0 for state_name in LIFECYCLE_STATES}
    devices = []

    for device_name in DEVICES.keys():
        lifecycle = get_device_lifecycle_state(device_name)

        if lifecycle not in counts:
            counts[lifecycle] = 0

        counts[lifecycle] += 1

        devices.append({
            "device": device_name,
            "ip": DEVICES.get(device_name, ""),
            "state": lifecycle,
            "status": status.get(device_name, {})
        })

    return {
        "counts": counts,
        "devices": sorted(devices, key=lambda item: item.get("device", "").lower())
    }





# PHASE 13C.5C - HISTORICAL INTELLIGENCE NOISE SUPPRESSION
# Suppress downstream SNMP timeout noise when a physical root cause already explains it.
def get_device_name_by_ip(ip_address):
    ip_address = clean_ascii(ip_address)
    if not ip_address:
        return ""
    for device_name, device_ip in DEVICES.items():
        if clean_ascii(device_ip) == ip_address:
            return clean_ascii(device_name)
    return ""


def extract_ip_from_text(text):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean_ascii(text))
    return match.group(0) if match else ""


def get_active_physical_root_context():
    """Return the current physical root cause context, if one is active."""
    try:
        active_alerts = get_active_alerts()
        physical_root = find_active_physical_link_root_cause(active_alerts)
        if physical_root:
            impacted = clean_ascii(physical_root.get("affected_device", physical_root.get("impacted_device", "")))
            port = clean_ascii(physical_root.get("port", ""))
            device = clean_ascii(physical_root.get("device", get_primary_switch_name()))
            return {
                "active": True,
                "root_cause": f"Switch Port {port}" if port else "Switch Port",
                "root_device": device,
                "port": port,
                "impacted_device": impacted,
                "impacted_ip": clean_ascii(DEVICES.get(impacted, "")),
                "reason": f"Known physical root cause {device} {port} impacting {impacted}".strip()
            }
    except Exception:
        pass

    return {"active": False}




def should_suppress_historical_line_due_to_root_cause(line):
    """Suppress SNMP timeout/log noise when the target is already impacted by a known physical root cause."""
    clean_line = clean_ascii(line)
    if not is_snmp_noise_event(clean_line):
        return False, ""

    context = get_active_physical_root_context()
    if not context.get("active"):
        return False, ""

    impacted_device = clean_ascii(context.get("impacted_device", ""))
    impacted_ip = clean_ascii(context.get("impacted_ip", ""))
    line_ip = extract_ip_from_text(clean_line)
    line_device = get_device_name_by_ip(line_ip)

    line_lower = clean_line.lower()
    impacted_match = False

    if impacted_device and impacted_device.lower() in line_lower:
        impacted_match = True
    if impacted_ip and impacted_ip == line_ip:
        impacted_match = True
    if impacted_device and line_device and impacted_device.lower() == line_device.lower():
        impacted_match = True

    if impacted_match:
        reason = (
            f"SNMP noise suppressed because {impacted_device or impacted_ip} is already impacted by "
            f"{context.get('root_cause', 'known physical root cause')}."
        )
        return True, reason

    return False, ""


# PHASE 11G - NOC HISTORICAL INTELLIGENCE ENGINE
def get_historical_intelligence_config():
    return config.setdefault("noc_historical_intelligence", {
        "enabled": True,
        "phase": "11G",
        "max_log_lines": 500,
        "max_devices": 5,
        "show_in_command_center": True,
        "trend_threshold": 3
    })


def read_historical_event_lines(limit=None):
    settings = get_historical_intelligence_config()

    if limit is None:
        try:
            limit = int(settings.get("max_log_lines", 500))
        except Exception:
            limit = 500

    if not os.path.exists(EVENT_LOG):
        return []

    try:
        with open(EVENT_LOG, "r") as log:
            lines = log.readlines()
    except Exception:
        return []

    return [line.strip() for line in lines[-limit:] if line.strip()]


def classify_historical_event(line):
    text = clean_ascii(line).lower()

    if "maintenance started" in text or "maintenance start" in text:
        return "Maintenance Started"
    if "maintenance ended" in text or "maintenance end" in text:
        return "Maintenance Ended"
    if "scheduled maintenance" in text:
        return "Scheduled Maintenance"
    if "switch link down" in text or "interface link down" in text or "line protocol down" in text:
        return "Link Down"
    if "switch link up" in text or "interface link up" in text or "line protocol up" in text:
        return "Link Up"
    if "sleep" in text or "sleeping" in text:
        return "Sleep Event"
    if "critical" in text or "down" in text or "failed" in text:
        return "Failure Event"
    if "recovered" in text or "up" in text:
        return "Recovery Event"

    return "General Event"


def extract_historical_device(line):
    clean_line = clean_ascii(line)

    # Prefer exact configured device names.
    for device_name in sorted(DEVICES.keys(), key=len, reverse=True):
        if device_name and device_name.lower() in clean_line.lower():
            return device_name

    # Phase 13C.5C: map raw IP-only SNMP messages back to the device name.
    ip_address = extract_ip_from_text(clean_line)
    ip_device = get_device_name_by_ip(ip_address)
    if ip_device:
        return ip_device

    # Fall back to common Cisco port identifiers.
    port_match = re.search(r"(Gi\d+/\d+/\d+|Fa\d+/\d+|GigabitEthernet\d+/\d+/\d+|FastEthernet\d+/\d+)", clean_line, re.I)
    if port_match:
        return port_match.group(1)

    # Fall back to text after pipe separators.
    parts = [part.strip() for part in clean_line.split("|")]
    if len(parts) >= 3:
        return parts[2]

    return "Network"



def get_historical_context_state(device_name):
    try:
        current = status.get(device_name, {})
        current_state = clean_ascii(current.get("state", "")).upper()

        if current_state == clean_ascii(get_maintenance_state_label()).upper():
            return "MAINTENANCE"
        if current_state == clean_ascii(get_sleep_status_label()).upper():
            return "SLEEPING"
        if current_state == clean_ascii(get_provisioning_state_label()).upper():
            return "PROVISIONING"

        if is_device_in_maintenance(device_name):
            return "MAINTENANCE"

    except Exception:
        pass

    return "NORMAL"


def should_suppress_historical_alert(device_name, pattern):
    try:
        settings = get_historical_intelligence_config()
        context_state = get_historical_context_state(device_name)

        if context_state == "MAINTENANCE" and settings.get("suppress_maintenance_devices", True):
            return True, "Device is currently in maintenance. Historical alert is suppressed."

        if context_state == "SLEEPING" and settings.get("suppress_sleep_devices", True):
            return True, "Device is currently sleeping. Historical alert is suppressed."

        if context_state == "PROVISIONING" and settings.get("suppress_provisioning_devices", True):
            return True, "Device is currently provisioning. Historical alert is suppressed."

    except Exception:
        pass

    return False, ""

def build_noc_historical_intelligence():
    settings = get_historical_intelligence_config()

    if not settings.get("enabled", True):
        return {
            "enabled": False,
            "summary": "Historical Intelligence disabled.",
            "total_events": 0,
            "trend_count": 0,
            "top_device": "N/A",
            "top_device_events": 0,
            "event_type_counts": {},
            "category_counts": {},
            "timeline": [],
            "trends": [],
            "rows_html": "<tr><td colspan='4'>Historical Intelligence disabled.</td></tr>",
            "trend_html": "<div class='noc-history-empty'>Historical Intelligence disabled.</div>"
        }

    lines = read_historical_event_lines()
    suppressed_noise_count = 0
    suppressed_noise_reasons = {}

    try:
        max_devices = int(settings.get("max_devices", 5))
    except Exception:
        max_devices = 5

    try:
        trend_threshold = int(settings.get("trend_threshold", 3))
    except Exception:
        trend_threshold = 3

    category_counts = {
        "Critical Alerts": 0,
        "Link Down": 0,
        "Link Up / Recovery": 0,
        "Maintenance": 0,
        "Scheduled Maintenance": 0,
        "Sleep": 0,
        "Provisioning": 0,
        "Recoveries": 0,
        "Other": 0
    }

    device_category_counts = {}
    timeline = []

    def refined_category(line, event_type):
        text = clean_ascii(line).lower()

        if "critical" in text or "critical alert" in text:
            return "Critical Alerts"
        if "switch link down" in text or "link down" in text or "from up to down" in text:
            return "Link Down"
        if "switch link up" in text or "link up" in text or "from down to up" in text:
            return "Link Up / Recovery"
        if "maintenance" in text and "scheduled" in text:
            return "Scheduled Maintenance"
        if "maintenance" in text:
            return "Maintenance"
        if "sleep" in text or "sleeping" in text or "woke" in text:
            return "Sleep"
        if "provision" in text:
            return "Provisioning"
        if "recovery" in text or "changed from checking to up" in text:
            return "Recoveries"

        if event_type in category_counts:
            return event_type

        return "Other"

    for line in reversed(lines):
        suppressed_line, suppressed_reason = should_suppress_historical_line_due_to_root_cause(line)
        if suppressed_line:
            suppressed_noise_count += 1
            suppressed_noise_reasons[suppressed_reason] = suppressed_noise_reasons.get(suppressed_reason, 0) + 1
            continue

        event_type = classify_historical_event(line)
        category = refined_category(line, event_type)
        device_name = extract_historical_device(line)
        timestamp = line.split(" | ")[0] if " | " in line else "Unknown"

        category_counts[category] = category_counts.get(category, 0) + 1

        if device_name not in device_category_counts:
            device_category_counts[device_name] = {
                "device": device_name,
                "total": 0,
                "critical": 0,
                "link_down": 0,
                "maintenance": 0,
                "scheduled": 0,
                "sleep": 0,
                "recovery": 0,
                "provisioning": 0,
                "other": 0
            }

        rec = device_category_counts[device_name]
        rec["total"] += 1

        if category == "Critical Alerts":
            rec["critical"] += 1
        elif category == "Link Down":
            rec["link_down"] += 1
        elif category == "Maintenance":
            rec["maintenance"] += 1
        elif category == "Scheduled Maintenance":
            rec["scheduled"] += 1
        elif category == "Sleep":
            rec["sleep"] += 1
        elif category == "Recoveries" or category == "Link Up / Recovery":
            rec["recovery"] += 1
        elif category == "Provisioning":
            rec["provisioning"] += 1
        else:
            rec["other"] += 1

        if len(timeline) < 8:
            timeline.append({
                "time": timestamp,
                "device": device_name,
                "event_type": category,
                "detail": line
            })

    insights = []
    suppressed_insights = []

    for device_name, data in device_category_counts.items():
        context_state = get_historical_context_state(device_name)

        actionable_score = (
            data.get("critical", 0) * 5 +
            data.get("link_down", 0) * 3 +
            data.get("other", 0)
        )

        operational_score = (
            data.get("maintenance", 0) +
            data.get("scheduled", 0) +
            data.get("sleep", 0) +
            data.get("provisioning", 0)
        )

        if data.get("critical", 0) > 0:
            pattern = "Critical alert pattern"
            recommendation = f"{device_name} has critical alert history. Review the alert center and related switch/device events."
            severity = "HIGH"
            display_count = data.get("critical", 0)
            suppressible = False
        elif data.get("link_down", 0) >= trend_threshold:
            pattern = "Repeated disconnect pattern"
            recommendation = f"{device_name} has repeated link-down events. Inspect cable, endpoint power, and switch port."
            severity = "MEDIUM"
            display_count = data.get("link_down", 0)
            suppressible = True
        elif data.get("maintenance", 0) >= trend_threshold or data.get("scheduled", 0) >= trend_threshold:
            pattern = "Maintenance pattern"
            recommendation = f"{device_name} is frequently in maintenance. No action required if this is expected."
            severity = "INFO"
            display_count = data.get("maintenance", 0) + data.get("scheduled", 0)
            suppressible = False
        elif data.get("sleep", 0) >= trend_threshold:
            pattern = "Sleep pattern"
            recommendation = f"{device_name} frequently enters sleep/wake states. No action required for sleep-aware devices."
            severity = "INFO"
            display_count = data.get("sleep", 0)
            suppressible = False
        elif actionable_score >= trend_threshold:
            pattern = "Recurring attention pattern"
            recommendation = f"{device_name} appears in actionable history. Review recent changes if this continues."
            severity = "LOW"
            display_count = actionable_score
            suppressible = True
        else:
            continue

        suppressed, suppression_reason = should_suppress_historical_alert(device_name, pattern) if suppressible else (False, "")

        item = {
            "device": device_name,
            "count": display_count,
            "total": data.get("total", 0),
            "pattern": pattern,
            "recommendation": recommendation,
            "severity": severity,
            "critical": data.get("critical", 0),
            "link_down": data.get("link_down", 0),
            "maintenance": data.get("maintenance", 0),
            "sleep": data.get("sleep", 0),
            "recovery": data.get("recovery", 0),
            "operational_score": operational_score,
            "actionable_score": actionable_score,
            "context_state": context_state,
            "suppressed": suppressed,
            "suppression_reason": suppression_reason
        }

        if suppressed:
            item["severity"] = "INFO"
            item["pattern"] = f"{context_state.title()} context"
            item["recommendation"] = suppression_reason
            suppressed_insights.append(item)
        else:
            insights.append(item)

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    insights = sorted(
        insights,
        key=lambda item: (
            severity_rank.get(item.get("severity", "INFO"), 3),
            -item.get("count", 0),
            -item.get("total", 0)
        )
    )

    display_insights = insights + suppressed_insights[:2]

    top_device = insights[0]["device"] if insights else (suppressed_insights[0]["device"] if suppressed_insights else "N/A")
    top_device_events = insights[0]["count"] if insights else (suppressed_insights[0]["count"] if suppressed_insights else 0)

    if insights:
        top = insights[0]
        summary = f"{top.get('pattern')}: {top.get('device')} has {top.get('count')} relevant event(s)."
    elif suppressed_noise_count > 0:
        summary = f"Incident consolidation active. {suppressed_noise_count} downstream event(s) consolidated into the primary root-cause incident."
    elif suppressed_insights:
        summary = "No actionable historical issue detected. Context suppression is active."
    elif lines:
        summary = "No actionable recurring problem pattern detected. Operational history is being tracked."
    else:
        summary = "No historical events recorded yet."

    rows_html = ""
    for item in timeline:
        rows_html += (
            f"<tr>"
            f"<td>{item.get('time','')}</td>"
            f"<td>{item.get('device','')}</td>"
            f"<td>{item.get('event_type','')}</td>"
            f"<td>{item.get('detail','')}</td>"
            f"</tr>"
        )

    if not rows_html:
        rows_html = "<tr><td colspan='4'>No historical events recorded yet.</td></tr>"

    trend_html = ""
    for trend in display_insights[:3]:
        trend_html += (
            f"<div class='noc-history-trend-item noc-history-{clean_ascii(trend.get('severity','info')).lower()}'>"
            f"<strong>{trend.get('device','')}</strong>"
            f"<span>{trend.get('pattern','')}</span>"
            f"<em>{trend.get('count',0)} relevant event(s)</em>"
            f"<small>{trend.get('recommendation','')}</small>"
            f"</div>"
        )

    # PHASE 13C.5D - INCIDENT CONSOLIDATION METRICS
    # Convert suppressed downstream SNMP noise into an operator-friendly consolidation metric.
    if suppressed_noise_count > 0:
        primary_incidents = 1 if get_active_physical_root_context().get("active") else max(1, len(insights))
        total_consolidated_scope = suppressed_noise_count + primary_incidents
        try:
            noise_reduction = round((suppressed_noise_count / total_consolidated_scope) * 100, 1)
        except Exception:
            noise_reduction = 0.0

        top_reason = sorted(suppressed_noise_reasons.items(), key=lambda item: item[1], reverse=True)[0][0] if suppressed_noise_reasons else "Known downstream alerts automatically merged into the primary incident."

        reduction_ratio = f"{suppressed_noise_count}:1" if primary_incidents <= 1 else f"{round(suppressed_noise_count / primary_incidents, 1)}:1"
        if noise_reduction >= 99:
            efficiency_score = "EXCELLENT"
        elif noise_reduction >= 95:
            efficiency_score = "GOOD"
        elif noise_reduction >= 90:
            efficiency_score = "FAIR"
        else:
            efficiency_score = "NEEDS ATTENTION"

        trend_html += (
            f"<div class='noc-history-trend-item noc-history-info noc-history-consolidation noc-history-consolidation-executive'>"
            f"<strong>Incident Consolidation Intelligence</strong>"
            f"<span>Known root cause propagation</span>"
            f"<em>{suppressed_noise_count} events consolidated</em>"
            f"<div class='incident-consolidation-kpi-grid'>"
            f"<div><span>Events Consolidated</span><strong>{suppressed_noise_count}</strong></div>"
            f"<div><span>Noise Reduction</span><strong>{noise_reduction}%</strong></div>"
            f"<div><span>Primary Incidents</span><strong>{primary_incidents}</strong></div>"
            f"<div><span>Reduction Ratio</span><strong>{reduction_ratio}</strong></div>"
            f"<div><span>Correlation Efficiency</span><strong>{efficiency_score}</strong></div>"
            f"</div>"
            f"<small>{suppressed_noise_count} downstream events were automatically consolidated into {primary_incidents} actionable incident. The NOC Correlation Engine reduced operator noise by {noise_reduction}%.</small>"
            f"<small>{top_reason}</small>"
            f"</div>"
        )

    if not trend_html:
        trend_html = "<div class='noc-history-empty'>No actionable recurring trend detected.</div>"

    return {
        "enabled": True,
        "summary": summary,
        "total_events": len(lines),
        "trend_count": min(len(insights), 3),
        "suppressed_count": len(suppressed_insights) + suppressed_noise_count,
        "suppressed_noise_count": suppressed_noise_count,
        "suppressed_noise_reasons": suppressed_noise_reasons,
        "incident_consolidation": {
            "enabled": suppressed_noise_count > 0,
            "events_consolidated": suppressed_noise_count,
            "primary_incident_count": 1 if suppressed_noise_count > 0 else 0,
            "suppressed_events": suppressed_noise_count,
            "noise_reduction": round((suppressed_noise_count / (suppressed_noise_count + 1)) * 100, 1) if suppressed_noise_count > 0 else 0.0,
            "reduction_ratio": f"{suppressed_noise_count}:1" if suppressed_noise_count > 0 else "0:0",
            "efficiency_score": "EXCELLENT" if (round((suppressed_noise_count / (suppressed_noise_count + 1)) * 100, 1) if suppressed_noise_count > 0 else 0.0) >= 99 else ("GOOD" if (round((suppressed_noise_count / (suppressed_noise_count + 1)) * 100, 1) if suppressed_noise_count > 0 else 0.0) >= 95 else ("FAIR" if (round((suppressed_noise_count / (suppressed_noise_count + 1)) * 100, 1) if suppressed_noise_count > 0 else 0.0) >= 90 else "NEEDS ATTENTION"))
        },
        "top_device": top_device,
        "top_device_events": top_device_events,
        "event_type_counts": category_counts,
        "category_counts": category_counts,
        "timeline": timeline,
        "trends": display_insights[:max_devices],
        "actionable_trends": insights[:max_devices],
        "suppressed_trends": suppressed_insights[:max_devices],
        "rows_html": rows_html,
        "trend_html": trend_html
    }


# PHASE 11F - NOC RECOMMENDATIONS ENGINE
# PHASE 11F.1 - INTEGRATED INTO NOC COMMAND CENTER
def build_noc_recommendations():
    recommendations = []
    active_alerts = get_active_alerts()
    lifecycle = build_lifecycle_summary()
    maintenance = build_maintenance_summary()
    scheduled = build_scheduled_maintenance_summary()
    noc_correlation = build_noc_correlation_engine()

    counts = lifecycle.get("counts", {})
    active_maintenance_items = maintenance.get("active", []) or []

    critical_alerts = [a for a in active_alerts if a.get("severity") == "CRITICAL"]
    warning_alerts = [a for a in active_alerts if a.get("severity") == "WARNING"]

    if critical_alerts:
        first = critical_alerts[0]
        device = clean_ascii(first.get("device", "Unknown device"))
        problem = clean_ascii(first.get("problem", "Critical issue"))
        message = f"{device} reports {problem}. Check the endpoint, cable, and assigned switch port first."
        if "Switch Link DOWN" in problem:
            message = f"{device} has a switch link down. Verify Ethernet cable, endpoint power, and the Cisco switch port."
        recommendations.append({
            "priority": "HIGH",
            "badge": "CRITICAL",
            "icon": "🔴",
            "title": "Critical Alert Detected",
            "message": message
        })

    if counts.get("DOWN", 0) > 0 and not critical_alerts:
        recommendations.append({
            "priority": "HIGH",
            "badge": "DOWN",
            "icon": "🔴",
            "title": "Device Down",
            "message": f"{counts.get('DOWN', 0)} device is down. Use NOC Correlation to confirm if this is endpoint-only or upstream."
        })

    if active_maintenance_items:
        names = ", ".join([clean_ascii(item.get("device", "Device")) for item in active_maintenance_items[:2]])
        recommendations.append({
            "priority": "MEDIUM",
            "badge": "MAINTENANCE",
            "icon": "🔵",
            "title": "Maintenance Active",
            "message": f"{names} is intentionally in maintenance. Alerts for that device are suppressed."
        })

    if scheduled.get("active_count", 0) > 0:
        recommendations.append({
            "priority": "MEDIUM",
            "badge": "SCHEDULED",
            "icon": "📅",
            "title": "Scheduled Maintenance Active",
            "message": "A scheduled maintenance window is currently active. Monitor until the window closes."
        })
    elif scheduled.get("total", 0) > 0:
        recommendations.append({
            "priority": "LOW",
            "badge": "SCHEDULED",
            "icon": "📅",
            "title": "Scheduled Maintenance Ready",
            "message": f"{scheduled.get('total', 0)} scheduled maintenance window is configured."
        })

    if warning_alerts and not critical_alerts:
        first = warning_alerts[0]
        recommendations.append({
            "priority": "MEDIUM",
            "badge": "WARNING",
            "icon": "🟡",
            "title": "Warning Condition",
            "message": f"Review {clean_ascii(first.get('device', 'device'))}: {clean_ascii(first.get('problem', 'warning detected'))}."
        })

    if counts.get("SLEEPING", 0) > 0:
        recommendations.append({
            "priority": "LOW",
            "badge": "SLEEP",
            "icon": "🌙",
            "title": "Sleep-Aware Device",
            "message": f"{counts.get('SLEEPING', 0)} device is sleeping. No action required unless it stays unreachable outside the grace behavior."
        })

    # Use NOC correlation as a final operator hint when there is a real issue.
    if noc_correlation.get("state_label") not in ["Normal", "Operational Awareness"]:
        recommendations.append({
            "priority": "MEDIUM",
            "badge": "CORRELATION",
            "icon": "🧠",
            "title": "Correlation Insight",
            "message": clean_ascii(noc_correlation.get("recommendation", "Review correlated issue."))
        })

    if not recommendations:
        recommendations.append({
            "priority": "OK",
            "badge": "HEALTHY",
            "icon": "🟢",
            "title": "Healthy Network",
            "message": "No action required. Network operating normally."
        })

    max_recommendations = int(config.get("noc_command_center", {}).get("max_recommendations", 3))
    return recommendations[:max_recommendations]



# ======================================================
# PHASE 12C.2 - REMOTE RESTORE ENGINE ROUTES
# ======================================================
def remote_restore_available():
    return all([
        get_remote_restore_config,
        get_remote_servers,
        get_remote_groups,
        load_remote_deployment_history,
        test_remote_server_connection,
        test_remote_group_connections,
        deploy_backup_to_remote_targets,
        build_remote_restore_summary
    ])


@app.route("/remote-restore")
def remote_restore_center():
    """Phase 12C.2 Remote Restore / DR Deployment dashboard."""
    load_config()
    backups = list_backup_files()

    if not remote_restore_available():
        summary = {
            "enabled": False,
            "phase": "12C.2",
            "server_count": 0,
            "group_count": 0,
            "history_count": 0,
            "last_deployment": None,
            "error": "remote_restore_engine.py could not be imported"
        }
        servers = []
        groups = []
        history = []
        remote_restore_config = {}
    else:
        remote_restore_config = get_remote_restore_config(config)
        servers = get_remote_servers(config)
        groups = get_remote_groups(config)
        history = load_remote_deployment_history()
        summary = build_remote_restore_summary(config)

    return render_template(
        "remote_restore.html",
        last_full_scan=last_full_scan,
        backups=backups,
        backup_count=len(backups),
        backup_dir=BACKUP_DIR,
        remote_restore_config=remote_restore_config,
        remote_servers=servers,
        remote_groups=groups,
        deployment_history=history,
        summary=summary
    )


@app.route("/api/remote-servers")
def api_remote_servers():
    load_config()
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available", "servers": []}), 500
    return jsonify({"ok": True, "servers": get_remote_servers(config)})


@app.route("/api/remote-deployment-groups")
def api_remote_deployment_groups():
    load_config()
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available", "groups": []}), 500
    return jsonify({"ok": True, "groups": get_remote_groups(config)})


@app.route("/api/test-remote-server/<server_name>", methods=["GET", "POST"])
def api_test_remote_server(server_name):
    load_config()
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available"}), 500

    result = test_remote_server_connection(config, server_name)
    if result.get("ok"):
        write_event(f"CONFIG | REMOTE RESTORE | SSH test successful for {server_name}")
    else:
        write_event(f"ERROR | REMOTE RESTORE | SSH test failed for {server_name}: {result.get('error', 'unknown error')}")
    return jsonify(result)


@app.route("/api/test-remote-group/<group_name>", methods=["GET", "POST"])
def api_test_remote_group(group_name):
    load_config()
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available"}), 500

    result = test_remote_group_connections(config, group_name)
    write_event(f"CONFIG | REMOTE RESTORE | Group SSH test completed for {group_name} | Success: {result.get('success_count', 0)} | Failed: {result.get('failure_count', 0)}")
    return jsonify(result)


@app.route("/api/deploy-backup", methods=["POST"])
def api_deploy_backup():
    load_config()
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available"}), 500

    payload = request.get_json(silent=True) or request.form.to_dict()
    backup_filename = payload.get("backup_filename", "")
    target_type = payload.get("target_type", "server")
    target_name = payload.get("target_name", "")
    requested_by = payload.get("requested_by", "On Watch Dashboard")

    options = {
        "create_snapshot_before_restore": str(payload.get("create_snapshot_before_restore", "")).lower() in ["1", "true", "yes", "on"],
        "restart_services_after_restore": str(payload.get("restart_services_after_restore", "")).lower() in ["1", "true", "yes", "on"],
        "verify_after_restore": str(payload.get("verify_after_restore", "")).lower() in ["1", "true", "yes", "on"],
        "rollback_on_failure": str(payload.get("rollback_on_failure", "")).lower() in ["1", "true", "yes", "on"]
    }

    # Empty options inherit defaults from config.
    options = {key: value for key, value in options.items() if str(payload.get(key, "")).strip() != ""}

    safe_name = safe_backup_filename(backup_filename)
    if not safe_name:
        return jsonify({"ok": False, "error": "Invalid backup filename"}), 400

    backup_path = os.path.join(BACKUP_DIR, safe_name)
    if not os.path.exists(backup_path):
        return jsonify({"ok": False, "error": "Backup file not found"}), 404

    try:
        result = deploy_backup_to_remote_targets(
            config=config,
            backup_path=backup_path,
            target_type=target_type,
            target_name=target_name,
            requested_by=requested_by,
            options=options
        )
        write_event(
            f"CONFIG | REMOTE RESTORE | Deployment completed | Backup: {safe_name} | Target: {target_type}:{target_name} | Success: {result.get('success_count', 0)} | Failed: {result.get('failure_count', 0)}"
        )
        return jsonify(result)

    except Exception as e:
        write_event(f"ERROR | REMOTE RESTORE | Deployment failed | Backup: {safe_name} | Target: {target_type}:{target_name} | Error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/remote-deployment-history")
def api_remote_deployment_history():
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available", "history": []}), 500
    history = load_remote_deployment_history()
    return jsonify({"ok": True, "history": history})


@app.route("/api/remote-restore-summary")
def api_remote_restore_summary():
    load_config()
    if not remote_restore_available():
        return jsonify({"ok": False, "error": "remote_restore_engine.py is not available"}), 500
    return jsonify({"ok": True, "summary": build_remote_restore_summary(config)})




# ======================================================
# PHASE 25 - TRUE SWITCH PORT GRID / QUICK PROVISIONING
# ======================================================
def build_phase25_map_management_payload():
    """Return SNMP-discovered switch ports and quick-provisioning choices.

    This payload never invents switch ports. The primary switch interface
    inventory discovered through SNMP remains the source of truth.
    """
    load_config()
    refresh_runtime_data()

    main_switch = clean_ascii(config.get("infrastructure", {}).get("main_switch", ""))
    edge_router = clean_ascii(config.get("infrastructure", {}).get("edge_router", ""))

    discovered_ports = get_selectable_switch_ports()
    ownership = ensure_port_ownership_registry().get(main_switch, {})
    occupied_by_index = {}

    # Backward-compatible ownership from switch_ports.
    for port_index, device_name in config.get("switch_ports", {}).items():
        occupied_by_index[clean_ascii(port_index)] = clean_ascii(device_name)

    # Phase 16 ownership registry is authoritative when present.
    for port_index, raw_entry in ownership.items():
        entry = normalize_port_ownership_entry(raw_entry)
        device_name = clean_ascii(entry.get("device", ""))
        if device_name:
            occupied_by_index[clean_ascii(port_index)] = device_name

    child_lookup = {}
    for child_name, relationship in config.get("device_relationships", {}).items():
        if not isinstance(relationship, dict):
            continue
        parent_name = clean_ascii(relationship.get("parent", ""))
        if parent_name:
            child_lookup.setdefault(parent_name, []).append(clean_ascii(child_name))

    ports = []
    for port_index, port_label in discovered_ports.items():
        port_index = clean_ascii(port_index)
        device_name = occupied_by_index.get(port_index, "")
        node_status = status.get(device_name, {}) if device_name else {}
        device_type = clean_ascii(config.get("device_types", {}).get(device_name, ""))
        virtual_children = []

        for child_name in child_lookup.get(device_name, []):
            child_type = clean_ascii(config.get("device_types", {}).get(child_name, "Virtual Machine"))
            child_status = status.get(child_name, {})
            virtual_children.append({
                "name": child_name,
                "ip": clean_ascii(config.get("devices", {}).get(child_name, "")),
                "type": child_type,
                "icon": get_map_icon(child_type),
                "state": clean_ascii(child_status.get("state", "UNKNOWN")) or "UNKNOWN",
                "status_class": get_map_status_class(child_status.get("state", "UNKNOWN"))
            })

        ports.append({
            "index": port_index,
            "label": clean_ascii(port_label) or port_index,
            "occupied": bool(device_name),
            "device": device_name,
            "ip": clean_ascii(config.get("devices", {}).get(device_name, "")),
            "type": device_type,
            "icon": get_map_icon(device_type) if device_name else "＋",
            "state": clean_ascii(node_status.get("state", "UNKNOWN")) if device_name else "AVAILABLE",
            "status_class": get_map_status_class(node_status.get("state", "UNKNOWN")) if device_name else "map-available",
            "virtual_children": virtual_children
        })

    mapped_devices = {item.get("device", "") for item in ports if item.get("occupied")}
    unmapped_devices = []
    for device_name, ip_address in config.get("devices", {}).items():
        if device_name in mapped_devices:
            continue
        if is_infrastructure_topology_device(device_name) or is_child_device(device_name):
            continue
        unmapped_devices.append({
            "name": clean_ascii(device_name),
            "ip": clean_ascii(ip_address),
            "type": clean_ascii(config.get("device_types", {}).get(device_name, "Physical Device"))
        })

    topology = build_dynamic_physical_topology_data()
    relationships = topology.get("relationships", [])
    node_by_name = {node.get("name"): node for node in topology.get("nodes", [])}

    routers = []
    for relationship in relationships:
        if clean_ascii(relationship.get("from", "")) != edge_router:
            continue
        child_name = clean_ascii(relationship.get("to", ""))
        child_node = node_by_name.get(child_name, {})
        role = normalize_infrastructure_role(child_node.get("role", child_node.get("type", "")))
        if role != "Router":
            continue
        routers.append({
            **child_node,
            "link_label": clean_ascii(relationship.get("label", "")) or clean_ascii(relationship.get("source_interface", "")),
            "source_interface": clean_ascii(relationship.get("source_interface", "")),
            "target_interface": clean_ascii(relationship.get("target_interface", ""))
        })

    infrastructure_choices = []
    for device_name, info in get_infrastructure_devices().items():
        infrastructure_choices.append({
            "name": clean_ascii(device_name),
            "ip": clean_ascii(info.get("ip", config.get("devices", {}).get(device_name, ""))),
            "role": normalize_infrastructure_role(info.get("role", "Infrastructure"))
        })

    interface_inventory = load_infrastructure_interface_inventory()
    parent_interfaces = {}
    for device_name, inventory in interface_inventory.items():
        interfaces = inventory.get("interfaces", {}) if isinstance(inventory, dict) else {}
        parent_interfaces[device_name] = [
            {
                "index": clean_ascii(index),
                "name": clean_ascii(item.get("short_name", "")) or clean_ascii(item.get("name", "")) or clean_ascii(index)
            }
            for index, item in interfaces.items()
            if isinstance(item, dict)
        ]

    return {
        "success": True,
        "phase": "25",
        "main_switch": main_switch,
        "edge_router": edge_router,
        "ports": ports,
        "port_count": len(ports),
        "free_port_count": sum(1 for item in ports if not item.get("occupied")),
        "occupied_port_count": sum(1 for item in ports if item.get("occupied")),
        "unmapped_devices": sorted(unmapped_devices, key=lambda item: item.get("name", "").lower()),
        "routers": routers,
        "infrastructure_choices": sorted(infrastructure_choices, key=lambda item: item.get("name", "").lower()),
        "parent_interfaces": parent_interfaces,
        "physical_device_types": [
            "Desktop PC", "Laptop", "Server", "NAS", "Printer",
            "Security Camera", "Smart Device", "Phone", "Other Physical Device"
        ],
        "infrastructure_roles": ["Internet Service", "Modem / Gateway", "Router", "Switch", "Firewall", "Access Point"],
        "last_updated": now()
    }


@app.route("/api/network-map-management")
def api_network_map_management():
    try:
        return jsonify(build_phase25_map_management_payload())
    except Exception as e:
        write_event(f"ERROR | PHASE 25 MANAGEMENT PAYLOAD | {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/network-map/quick-provision", methods=["POST"])
def api_network_map_quick_provision():
    """Quick provisioning from the map using the same config structures as Phase 16B."""
    load_config()
    data = request.get_json(silent=True) or request.form
    action = clean_ascii(data.get("action", "")).lower()
    original_config = json.loads(json.dumps(config))

    try:
        if action == "map_existing":
            device_name = clean_ascii(data.get("device_name", ""))
            port_index = clean_ascii(data.get("switch_port", ""))
            switch_device = clean_ascii(data.get("switch_device", "")) or clean_ascii(
                config.get("infrastructure", {}).get("main_switch", "")
            )
            if not device_name or not port_index or not switch_device:
                raise ValueError("An existing device, parent switch, and switch interface are required.")
            if device_name not in config.get("devices", {}):
                raise ValueError("The selected device is not in inventory.")
            if switch_device not in get_switch_devices():
                raise ValueError("The selected parent device is not a registered switch.")
            if is_infrastructure_topology_device(device_name) or is_child_device(device_name):
                raise ValueError("Only unmapped physical endpoints can use a switch interface card.")

            inventory_record = load_infrastructure_interface_inventory().get(switch_device, {})
            valid_interfaces = inventory_record.get("interfaces", {}) if isinstance(inventory_record, dict) else {}
            if port_index not in valid_interfaces:
                raise ValueError(f"{port_index} is not an SNMP-discovered interface on {switch_device}.")

            config.setdefault("port_ownership", {}).setdefault(switch_device, {})[port_index] = {
                "device": device_name,
                "role": infer_port_ownership_role(device_name),
                "description": clean_ascii(config.get("device_types", {}).get(device_name, "Physical Device")),
                "source": "phase26_quick_map"
            }

            main_switch = clean_ascii(config.get("infrastructure", {}).get("main_switch", ""))
            if switch_device == main_switch:
                config.setdefault("switch_ports", {})[port_index] = device_name

            save_config()
            refresh_runtime_data()
            interface_name = clean_ascii(valid_interfaces.get(port_index, {}).get("short_name", "")) or clean_ascii(
                valid_interfaces.get(port_index, {}).get("name", "")
            ) or port_index
            write_provisioning_audit(
                "PHASE 26 MAP EXISTING",
                "SUCCESS",
                device_name,
                config.get("devices", {}).get(device_name, ""),
                f"Mapped from Network Map to {switch_device} {interface_name}"
            )
            return jsonify({
                "success": True,
                "message": f"{device_name} mapped to {switch_device} {interface_name}.",
                "management": build_phase25_map_management_payload()
            })

        device_name = clean_ascii(data.get("device_name", ""))
        ip_address = clean_ascii(data.get("ip_address", ""))

        if not device_name or not ip_address:
            raise ValueError("Device name and IP address are required.")
        if not validate_ip(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")
        if is_reserved_provisioning_ip(ip_address):
            raise ValueError(f"Reserved IP address cannot be provisioned: {ip_address}")
        if device_name in config.get("devices", {}):
            raise ValueError(f"Device name already exists: {device_name}")
        duplicate_owner = get_existing_ip_owner(ip_address)
        if duplicate_owner:
            raise ValueError(f"IP address {ip_address} already belongs to {duplicate_owner}.")

        config.setdefault("devices", {})
        config.setdefault("device_types", {})
        config.setdefault("device_relationships", {})
        config.setdefault("switch_ports", {})
        config.setdefault("infrastructure_devices", {})
        config.setdefault("sleep_detection", {})
        config.setdefault("provisioned_virtual_inheritance", {})
        config["sleep_detection"].setdefault("sleep_allowed_devices", [])

        if action == "new_physical":
            switch_port = clean_ascii(data.get("switch_port", ""))
            switch_device = clean_ascii(data.get("switch_device", "")) or clean_ascii(
                config.get("infrastructure", {}).get("main_switch", "")
            )
            physical_type = clean_ascii(data.get("physical_device_type", "Physical Device")) or "Physical Device"

            if not switch_port or not switch_device:
                raise ValueError("A parent switch and SNMP-discovered interface are required.")
            if switch_device not in get_switch_devices():
                raise ValueError("The selected parent device is not a registered switch.")

            inventory_record = load_infrastructure_interface_inventory().get(switch_device, {})
            valid_interfaces = inventory_record.get("interfaces", {}) if isinstance(inventory_record, dict) else {}
            if switch_port not in valid_interfaces:
                raise ValueError(f"{switch_port} is not an SNMP-discovered interface on {switch_device}.")

            existing_owner = normalize_port_ownership_entry(
                config.get("port_ownership", {}).get(switch_device, {}).get(switch_port, {})
            ).get("device", "")
            if existing_owner:
                raise ValueError(f"{switch_device} interface {switch_port} is already assigned to {existing_owner}.")

            config["devices"][device_name] = ip_address
            config["device_types"][device_name] = physical_type
            config.setdefault("port_ownership", {}).setdefault(switch_device, {})[switch_port] = {
                "device": device_name,
                "role": infer_port_ownership_role(device_name),
                "description": physical_type,
                "source": "phase26_quick_provision"
            }

            main_switch = clean_ascii(config.get("infrastructure", {}).get("main_switch", ""))
            if switch_device == main_switch:
                config.setdefault("switch_ports", {})[switch_port] = device_name
                ensure_endpoint_topology_link_for_switch_port(device_name, switch_port)

            save_config()
            refresh_runtime_data()
            interface_name = clean_ascii(valid_interfaces.get(switch_port, {}).get("short_name", "")) or clean_ascii(
                valid_interfaces.get(switch_port, {}).get("name", "")
            ) or switch_port
            write_event(
                f"CONFIG | PHASE 26 QUICK PROVISION | Physical | {device_name} | {ip_address} | {switch_device} {interface_name}"
            )
            write_provisioning_audit(
                "PHASE 26 ADD PHYSICAL",
                "SUCCESS",
                device_name,
                ip_address,
                f"Provisioned and mapped to {switch_device} {interface_name}"
            )

        elif action == "new_infrastructure":
            role = normalize_infrastructure_role(data.get("infrastructure_role", "Router"))
            parent_name = clean_ascii(data.get("parent_device", ""))
            source_interface = clean_ascii(data.get("source_interface", ""))
            target_interface = clean_ascii(data.get("target_interface", ""))

            if role not in ["Internet", "Modem", "Router", "Switch", "Firewall", "Access Point"]:
                raise ValueError("Unsupported infrastructure role.")

            # Internet is a logical monitored service. It does not require a
            # physical parent/interface link. All other infrastructure roles do.
            if role != "Internet":
                if not parent_name or parent_name not in config.get("devices", {}):
                    raise ValueError("A valid parent infrastructure device is required.")
                if not source_interface or not target_interface:
                    raise ValueError("Both parent and new-device interfaces are required.")

            config["devices"][device_name] = ip_address
            config["device_types"][device_name] = role
            register_infrastructure_device(
                device_name,
                ip_address,
                role,
                is_snmp_capable_infrastructure_role(role)
            )
            save_config()
            refresh_runtime_data()

            if role != "Internet":
                add_or_update_topology_link({
                    "from_device": parent_name,
                    "to_device": device_name,
                    "source_interface": source_interface,
                    "target_interface": target_interface,
                    "link_type": "Physical Link",
                    "label": f"{parent_name} to {device_name}"
                })

            if is_snmp_capable_infrastructure_role(role):
                run_phase16b_interface_discovery_for_device(device_name)
            write_event(
                f"CONFIG | PHASE 25 QUICK PROVISION | Infrastructure | {role} | {device_name} | {ip_address}"
            )
            write_provisioning_audit(
                "PHASE 25 ADD INFRASTRUCTURE",
                "SUCCESS",
                device_name,
                ip_address,
                f"{role} linked to {parent_name}: {source_interface} -> {target_interface}"
            )
        else:
            raise ValueError("Unknown quick-provisioning action.")

        return jsonify({
            "success": True,
            "message": f"{device_name} was provisioned successfully.",
            "management": build_phase25_map_management_payload()
        })

    except Exception as e:
        config.clear()
        config.update(original_config)
        try:
            save_config()
            refresh_runtime_data()
        except Exception:
            pass
        write_event(f"ERROR | PHASE 25 QUICK PROVISION | {action} | {e}")
        write_provisioning_audit(
            "PHASE 25 QUICK PROVISION",
            "FAILED",
            clean_ascii(data.get("device_name", "")),
            clean_ascii(data.get("ip_address", "")),
            str(e)
        )
        return jsonify({"success": False, "message": str(e)}), 400


# ======================================================
# PHASE 26 - SCALABLE SNMP INFRASTRUCTURE TREE
# ======================================================

def reconcile_phase26_infrastructure_topology(physical_links, infrastructure_names, registry):
    """Orient saved physical links into one deterministic parent/child forest.

    Phase 26A rules:
    - config["infrastructure_links"] remains the physical source of truth.
    - Links are treated as physical, bidirectional edges for tree placement.
    - The preferred root order is Internet, Modem, Switch, Router, Firewall,
      Access Point, then all other infrastructure roles.
    - Every infrastructure child receives at most one parent.
    - Duplicate links and cycles are suppressed without deleting saved links.
    - Interface names/indexes are swapped when a saved link is traversed in
      the opposite direction, so card-level interface correlation stays correct.
    """
    infrastructure_names = {clean_ascii(name) for name in infrastructure_names if clean_ascii(name)}
    adjacency = {name: [] for name in infrastructure_names}
    duplicate_edges = 0
    rejected_links = []
    seen_edges = set()

    def role_for(name):
        info = registry.get(name, {}) if isinstance(registry.get(name, {}), dict) else {}
        ip_address = clean_ascii(info.get("ip", config.get("devices", {}).get(name, "")))
        return normalize_infrastructure_role(info.get("role", detect_map_device_type(name, ip_address)))

    role_priority = {
        "Internet": 0,
        "Modem": 1,
        "Switch": 2,
        "Router": 3,
        "Firewall": 4,
        "Access Point": 5,
        "UPS": 6,
        "DNS Server": 7,
        "DHCP Server": 8,
        "VPN Gateway": 9,
    }

    def node_sort_key(name):
        return (role_priority.get(role_for(name), 50), name.lower())

    for raw_link in physical_links:
        if not isinstance(raw_link, dict):
            continue
        parent = clean_ascii(raw_link.get("from", ""))
        child = clean_ascii(raw_link.get("to", ""))
        if not parent or not child or parent == child:
            rejected_links.append(f"Ignored invalid topology link: {parent or '?'} -> {child or '?'}")
            continue
        if raw_link.get("is_endpoint_link"):
            continue
        if clean_ascii(raw_link.get("link_type", "")).lower() in ["endpoint link", "endpoint bus link"]:
            continue
        if parent not in infrastructure_names or child not in infrastructure_names:
            continue

        edge_key = tuple(sorted((parent.lower(), child.lower())))
        if edge_key in seen_edges:
            duplicate_edges += 1
            continue
        seen_edges.add(edge_key)
        adjacency.setdefault(parent, []).append((child, raw_link, True))
        adjacency.setdefault(child, []).append((parent, raw_link, False))

    relationships = []
    parent_by_child = {}
    children_by_parent = {}
    roots = []
    visited = set()
    cycle_edges = 0

    def orient_relationship(parent, child, raw_link, forward):
        if forward:
            source_interface = clean_ascii(raw_link.get("source_interface", ""))
            target_interface = clean_ascii(raw_link.get("target_interface", ""))
            source_port_index = clean_ascii(raw_link.get("source_port_index", ""))
            target_port_index = clean_ascii(raw_link.get("target_port_index", ""))
        else:
            source_interface = clean_ascii(raw_link.get("target_interface", ""))
            target_interface = clean_ascii(raw_link.get("source_interface", ""))
            source_port_index = clean_ascii(raw_link.get("target_port_index", ""))
            target_port_index = clean_ascii(raw_link.get("source_port_index", ""))

        relationship_state = clean_ascii(
            raw_link.get("relationship_state", "CONFIGURED")
        ).upper() or "CONFIGURED"
        relationship_state_details = (
            dict(raw_link.get("relationship_state_details", {}))
            if isinstance(raw_link.get("relationship_state_details"), dict)
            else _relationship_state_details(
                relationship_state,
                raw_link.get("confidence", 0),
                raw_link.get("source", raw_link.get("selection_source", "")),
                raw_link.get("last_verified_at", ""),
            )
        )

        return {
            "id": clean_ascii(raw_link.get("id", "")),
            "from": parent,
            "to": child,
            "parent": parent,
            "child": child,
            "source_interface": source_interface,
            "target_interface": target_interface,
            "destination_interface": target_interface,
            "source_port_index": source_port_index,
            "target_port_index": target_port_index,
            "link_type": clean_ascii(raw_link.get("link_type", "Physical Link")) or "Physical Link",
            "label": clean_ascii(raw_link.get("label", raw_link.get("port_label", ""))),
            "source": clean_ascii(raw_link.get("source", "")),
            "selection_source": clean_ascii(raw_link.get("selection_source", "")),
            "confidence": int(raw_link.get("confidence", 0) or 0),
            "evidence_sources": list(raw_link.get("evidence_sources", []) or []),
            "evidence_id": clean_ascii(raw_link.get("evidence_id", "")),
            "relationship_state": relationship_state,
            "relationship_state_details": relationship_state_details,
            "currently_verified": bool(raw_link.get("currently_verified", False)),
            "last_verified_at": clean_ascii(raw_link.get("last_verified_at", "")),
            "active": bool(raw_link.get("active", True)),
            "reconciled": True,
            "saved_direction_reversed": not forward,
        }

    remaining = set(infrastructure_names)
    while remaining:
        component = set()
        seed = min(remaining, key=node_sort_key)
        stack = [seed]
        while stack:
            current = stack.pop()
            if current in component:
                continue
            component.add(current)
            for neighbor, _raw, _forward in adjacency.get(current, []):
                if neighbor not in component:
                    stack.append(neighbor)

        root = min(component, key=node_sort_key)
        roots.append(root)
        queue = [root]
        visited.add(root)

        while queue:
            parent = queue.pop(0)
            neighbors = sorted(adjacency.get(parent, []), key=lambda item: node_sort_key(item[0]))
            for child, raw_link, forward in neighbors:
                if child in visited:
                    if parent_by_child.get(parent) != child and parent_by_child.get(child) != parent:
                        cycle_edges += 1
                    continue
                visited.add(child)
                parent_by_child[child] = parent
                children_by_parent.setdefault(parent, []).append(child)
                relationships.append(orient_relationship(parent, child, raw_link, forward))
                queue.append(child)

        remaining -= component

    for parent, children in children_by_parent.items():
        children.sort(key=node_sort_key)
    roots.sort(key=node_sort_key)

    warnings = list(rejected_links)
    if duplicate_edges:
        warnings.append(f"Suppressed {duplicate_edges} duplicate physical link(s).")
    if cycle_edges:
        warnings.append(f"Suppressed {cycle_edges} non-tree/cycle edge(s) while building the display tree.")
    if len(roots) > 1:
        warnings.append(
            f"Topology contains {len(roots)} disconnected infrastructure components. "
            "Add the missing physical link(s) to produce one root."
        )

    return {
        "relationships": relationships,
        "parent_by_child": parent_by_child,
        "children_by_parent": children_by_parent,
        "roots": roots,
        "validation": {
            "valid": len(roots) <= 1 and not rejected_links,
            "warnings": warnings,
            "root_count": len(roots),
            "relationship_count": len(relationships),
            "duplicate_links_suppressed": duplicate_edges,
            "cycle_edges_suppressed": cycle_edges,
            "source": 'config["infrastructure_links"]',
            "mode": "Phase 26A dynamic topology reconciliation",
        },
    }


def build_phase26_infrastructure_payload():
    """Build a scalable router/switch topology using SNMP interfaces.

    Design rules:
    - Routers and switches both use SNMP-discovered interfaces as truth.
    - Cached SNMP inventory is fallback only.
    - Infrastructure placement comes from infrastructure_links.
    - Each router/switch owns its own interface grid.
    - Physical endpoints occupy switch interfaces through port_ownership.
    - Virtual machines remain nested under their physical host.
    """
    load_config()
    refresh_runtime_data()

    topology = build_dynamic_physical_topology_data()
    topology_nodes = {
        clean_ascii(node.get("name", "")): node
        for node in topology.get("nodes", [])
        if clean_ascii(node.get("name", ""))
    }

    registry = get_infrastructure_devices()
    interface_inventory = load_infrastructure_interface_inventory()
    port_ownership = ensure_port_ownership_registry()
    self_building_topology = build_self_building_topology(force=False)

    # PHASE 26B.8O - NETWORK MAP TREE SYNCHRONIZATION
    #
    # Phase 26B.8 is the authoritative infrastructure-link lifecycle engine.
    # It combines preserved explicit links, verified CDP/LLDP links, and
    # role-based fallback links into config["infrastructure_links"].
    #
    # The previous map builder preferred Phase 26B.4 generated_links whenever
    # that list was non-empty. Phase 26B.4 contains only merged discovery
    # evidence, so logical/provisioned links such as:
    #
    #   Internet -> Modem -> Switch
    #
    # were omitted even though Phase 26B.8 had correctly saved them. This made
    # those devices appear as separate roots and removed their connector lines.
    #
    # Rebuild Phase 26B.8 before rendering and always reconcile the complete
    # saved infrastructure-link set.
    auto_link_result = rebuild_auto_infrastructure_links()
    physical_links = get_physical_topology_config()
    topology_source = (
        "Phase 26B.8 authoritative infrastructure links "
        "(explicit, verified CDP/LLDP, and role fallback)"
    )

    # Phase 26.4: Internet is a logical monitored service, not an SNMP device.
    # Keep its external reachability targets visible on the map as service checks.
    internet_state, internet_results = check_internet_targets()

    # Build dynamic infrastructure candidates used to correlate an SNMP interface
    # description/alias with a known infrastructure device. No device name, IP, or
    # port is hard-coded here.
    infrastructure_candidates = {}
    for candidate_name in set(registry.keys()) | {
        clean_ascii(item.get("from", "")) for item in physical_links if isinstance(item, dict)
    } | {
        clean_ascii(item.get("to", "")) for item in physical_links if isinstance(item, dict)
    }:
        candidate_name = clean_ascii(candidate_name)
        if not candidate_name:
            continue
        candidate_info = registry.get(candidate_name, {}) if isinstance(registry.get(candidate_name, {}), dict) else {}
        candidate_ip = clean_ascii(
            candidate_info.get(
                "ip",
                config.get("devices", {}).get(
                    candidate_name,
                    topology_nodes.get(candidate_name, {}).get("ip", "")
                )
            )
        )
        infrastructure_candidates[candidate_name] = {
            "name": candidate_name,
            "ip": candidate_ip,
            "role": normalize_infrastructure_role(candidate_info.get("role", detect_map_device_type(candidate_name, candidate_ip)))
        }

    # Phase 26.2: enrich live, unmapped switch ports with MAC/vendor details.
    # The forwarding database currently comes from the configured primary Cisco
    # switch. SNMP remains read-only, and a 60-second cache prevents the 20-second
    # map refresh from repeatedly walking the switch.
    primary_switch_name = clean_ascii(get_physical_topology_primary_switch())
    mac_table_result = get_cached_switch_mac_address_table(max_age_seconds=60)
    mac_rows_by_port = {}

    if mac_table_result.get("success"):
        for mac_row in mac_table_result.get("rows", []):
            if not isinstance(mac_row, dict):
                continue
            row_keys = {
                clean_ascii(mac_row.get("port", "")).lower(),
                clean_ascii(mac_row.get("ifindex", "")).lower(),
                short_interface_name(clean_ascii(mac_row.get("port", ""))).lower()
            }
            row_keys.discard("")
            for row_key in row_keys:
                mac_rows_by_port.setdefault(row_key, []).append(mac_row)

    child_lookup = {}
    for child_name, relationship in config.get("device_relationships", {}).items():
        if not isinstance(relationship, dict):
            continue
        parent_name = clean_ascii(relationship.get("parent", ""))
        child_name = clean_ascii(child_name)
        if parent_name and child_name and not is_infrastructure_topology_device(child_name):
            child_lookup.setdefault(parent_name, []).append(child_name)

    infrastructure_names = set(registry.keys())
    for link in physical_links:
        parent_name = clean_ascii(link.get("from", ""))
        child_name = clean_ascii(link.get("to", ""))
        if parent_name and is_core_topology_device(parent_name):
            infrastructure_names.add(parent_name)
        if child_name and is_core_topology_device(child_name):
            infrastructure_names.add(child_name)
    infrastructure_names.discard("")

    # Phase 26A: treat saved infrastructure links as bidirectional physical
    # edges, then reconcile them into one deterministic rooted tree/forest.
    # This prevents link-entry direction from creating duplicate or incorrect
    # roots such as a router appearing beside its upstream switch.
    reconciled_topology = reconcile_phase26_infrastructure_topology(
        physical_links, infrastructure_names, registry
    )
    infrastructure_relationships = reconciled_topology["relationships"]
    relationship_lookup = {}
    if isinstance(infrastructure_relationships, list):
        for rel in infrastructure_relationships:
            if not isinstance(rel, dict):
                continue
            child = clean_ascii(rel.get("to", rel.get("child", "")))
            if child:
                relationship_lookup[child] = rel
    parent_by_child = reconciled_topology["parent_by_child"]
    connected_interfaces = {}

    # Tree placement uses one authoritative parent per child, but interface
    # correlation must preserve every saved physical infrastructure link.
    # Example: switch remains under router in the tree,
    # while discovered gateway interface can still be linked to modem gateway.
    for link in physical_links:
        if not isinstance(link, dict):
            continue

        parent = clean_ascii(link.get("from", ""))
        child = clean_ascii(link.get("to", ""))
        if not parent or not child or parent == child:
            continue
        if not (is_core_topology_device(parent) or is_core_topology_device(child)):
            continue

        source_interface = clean_ascii(link.get("source_interface", ""))
        target_interface = clean_ascii(link.get("target_interface", ""))
        source_port_index = clean_ascii(link.get("source_port_index", ""))
        target_port_index = clean_ascii(link.get("target_port_index", ""))

        # Phase 26A.1: interface direction comes from the reconciled tree,
        # not from the direction in which the physical link was originally
        # saved. A peer that is this device's parent is UPSTREAM; a peer that
        # is this device's child is DOWNSTREAM. This keeps labels correct even
        # when a topology link was entered in reverse order.
        def relationship_direction(device_name, peer_name):
            if parent_by_child.get(device_name) == peer_name:
                return "upstream"
            if parent_by_child.get(peer_name) == device_name:
                return "downstream"
            return "connected"

        if source_interface or source_port_index:
            connected_interfaces.setdefault(parent, []).append({
                "peer": child,
                "interface": source_interface,
                "index": source_port_index,
                "direction": relationship_direction(parent, child),
                "source": "Reconciled topology link"
            })

        if target_interface or target_port_index:
            connected_interfaces.setdefault(child, []).append({
                "peer": parent,
                "interface": target_interface,
                "index": target_port_index,
                "direction": relationship_direction(child, parent),
                "source": "Reconciled topology link"
            })

    def interface_connection(device_name, index, full_name, short_name):
        candidates = connected_interfaces.get(device_name, [])
        values = {
            clean_ascii(index).lower(),
            clean_ascii(full_name).lower(),
            clean_ascii(short_name).lower()
        }
        values.discard("")
        for item in candidates:
            checks = {
                clean_ascii(item.get("index", "")).lower(),
                clean_ascii(item.get("interface", "")).lower(),
                short_interface_name(clean_ascii(item.get("interface", ""))).lower()
            }
            checks.discard("")
            if values.intersection(checks):
                return item
        return None

    def infer_infrastructure_connection(device_name, interface_description):
        """Infer a physical infrastructure peer from the live SNMP description.

        This is used only when no explicit infrastructure link exists. A match is
        accepted only when exactly one known infrastructure device name or IP is
        present in the interface description.
        """
        description = clean_ascii(interface_description)
        description_lower = description.lower()
        if not description_lower:
            return None

        matches = []
        for candidate_name, candidate in infrastructure_candidates.items():
            if candidate_name == device_name:
                continue
            candidate_ip = clean_ascii(candidate.get("ip", ""))
            name_match = candidate_name.lower() in description_lower
            ip_match = bool(candidate_ip and candidate_ip in description)
            if name_match or ip_match:
                matches.append(candidate)

        unique = {item["name"]: item for item in matches}
        if len(unique) != 1:
            return None

        peer = next(iter(unique.values()))
        return {
            "peer": peer.get("name", ""),
            "interface": description,
            "index": "",
            "direction": "upstream",
            "source": "SNMP interface description",
            "inferred": True
        }

    def endpoint_for_interface(device_name, index, full_name, short_name):
        ownership = port_ownership.get(device_name, {}) if isinstance(port_ownership, dict) else {}
        lookup_values = [clean_ascii(index), clean_ascii(full_name), clean_ascii(short_name)]
        for key in lookup_values:
            if not key:
                continue
            if key in ownership:
                return normalize_port_ownership_entry(ownership[key])
        for key, raw_entry in ownership.items():
            key_text = clean_ascii(key).lower()
            if key_text in {value.lower() for value in lookup_values if value}:
                return normalize_port_ownership_entry(raw_entry)
        return {}

    def detected_macs_for_interface(device_name, index, full_name, short_name):
        """Return unique forwarding-table entries for one primary-switch port."""
        if not primary_switch_name or clean_ascii(device_name) != primary_switch_name:
            return []

        lookup_values = {
            clean_ascii(index).lower(),
            clean_ascii(full_name).lower(),
            clean_ascii(short_name).lower(),
            short_interface_name(clean_ascii(full_name)).lower()
        }
        lookup_values.discard("")

        matches = []
        seen_macs = set()
        for lookup_value in lookup_values:
            for row in mac_rows_by_port.get(lookup_value, []):
                mac_address = normalize_mac_address(row.get("mac", ""))
                if not mac_address or mac_address in seen_macs:
                    continue
                seen_macs.add(mac_address)
                matches.append({
                    "mac": mac_address,
                    "vendor": clean_ascii(row.get("vendor", "")) or "Unknown vendor",
                    "vendor_source": clean_ascii(row.get("vendor_source", "")) or "No IEEE registry match",
                    "vendor_prefix": clean_ascii(row.get("vendor_prefix", "")),
                    "vendor_prefix_bits": row.get("vendor_prefix_bits", 0),
                    "device_guess": clean_ascii(row.get("device", "")),
                    "vlan": clean_ascii(row.get("vlan", "")),
                    "source": clean_ascii(row.get("source", "SNMP FDB")) or "SNMP FDB"
                })

        return sorted(matches, key=lambda item: item.get("mac", ""))

    devices = {}
    for device_name in sorted(infrastructure_names, key=lambda value: value.lower()):
        registry_info = registry.get(device_name, {}) if isinstance(registry.get(device_name, {}), dict) else {}
        node = topology_nodes.get(device_name, {})
        role = normalize_infrastructure_role(
            registry_info.get("role", node.get("role", detect_map_device_type(device_name, config.get("devices", {}).get(device_name, ""))))
        )
        ip_address = clean_ascii(
            registry_info.get("ip", config.get("devices", {}).get(device_name, node.get("ip", "")))
        )
        state_value = clean_ascii(status.get(device_name, {}).get("state", node.get("state", "UNKNOWN"))) or "UNKNOWN"

        cached_record = interface_inventory.get(device_name, {}) if isinstance(interface_inventory, dict) else {}
        raw_interfaces = cached_record.get("interfaces", {}) if isinstance(cached_record, dict) else {}
        interfaces = []

        if isinstance(raw_interfaces, dict):
            for index, info in sorted(raw_interfaces.items(), key=interface_sort_key):
                if not isinstance(info, dict):
                    continue
                full_name = clean_ascii(info.get("name", ""))
                short_name = clean_ascii(info.get("short_name", "")) or short_interface_name(full_name)

                # Internal stack-control interfaces are retained by SNMP discovery,
                # but they are not physical endpoint-provisioning ports and should
                # not clutter the Phase 26 map.
                interface_identity = f"{full_name} {short_name}".lower()
                if "stacksub" in interface_identity or "stackport" in interface_identity:
                    continue

                interface_state = clean_ascii(info.get("state", "UNKNOWN")) or "UNKNOWN"
                interface_description = clean_ascii(
                    info.get("description", info.get("alias", info.get("ifalias", "")))
                )
                connection = interface_connection(device_name, index, full_name, short_name)
                if not connection:
                    connection = infer_infrastructure_connection(device_name, interface_description)
                owner = endpoint_for_interface(device_name, index, full_name, short_name)
                endpoint_name = clean_ascii(owner.get("device", ""))
                endpoint = None

                if endpoint_name and not is_infrastructure_topology_device(endpoint_name):
                    endpoint_status = status.get(endpoint_name, {})
                    endpoint_type = clean_ascii(config.get("device_types", {}).get(endpoint_name, "Physical Device"))
                    virtual_children = []
                    for child_name in sorted(child_lookup.get(endpoint_name, []), key=lambda value: value.lower()):
                        child_type = clean_ascii(config.get("device_types", {}).get(child_name, "Virtual Machine"))
                        child_state = clean_ascii(status.get(child_name, {}).get("state", "UNKNOWN")) or "UNKNOWN"
                        virtual_children.append({
                            "name": child_name,
                            "ip": clean_ascii(config.get("devices", {}).get(child_name, "")),
                            "type": child_type,
                            "icon": get_map_icon(child_type),
                            "state": child_state,
                            "status_class": get_map_status_class(child_state)
                        })
                    endpoint_state = clean_ascii(endpoint_status.get("state", "UNKNOWN")) or "UNKNOWN"
                    endpoint = {
                        "name": endpoint_name,
                        "ip": clean_ascii(config.get("devices", {}).get(endpoint_name, "")),
                        "type": endpoint_type,
                        "icon": get_map_icon(endpoint_type),
                        "state": endpoint_state,
                        "status_class": get_map_status_class(endpoint_state),
                        "virtual_children": virtual_children
                    }

                detected_macs = detected_macs_for_interface(
                    device_name, index, full_name, short_name
                )

                interfaces.append({
                    "index": clean_ascii(index),
                    "name": full_name,
                    "short_name": short_name or clean_ascii(index),
                    "state": interface_state,
                    "status_class": get_map_status_class(interface_state),
                    "source": clean_ascii(info.get("source", "snmp")) or "snmp",
                    "description": interface_description,
                    "connection": connection,
                    "endpoint": endpoint,
                    "detected_macs": detected_macs,
                    "detected_mac_count": len(detected_macs),
                    "available": not bool(connection or endpoint)
                })

        devices[device_name] = {
            "name": device_name,
            "ip": ip_address,
            "role": role,
            "icon": get_map_icon(role),
            "state": state_value,
            "status_class": get_map_status_class(state_value),
            "parent": parent_by_child.get(device_name, ""),
            "relationship": (
                relationship_lookup.get(device_name)
                if isinstance(relationship_lookup.get(device_name), dict)
                else (
                    config.get("device_relationships", {}).get(device_name, {})
                    if isinstance(config.get("device_relationships", {}).get(device_name, {}), dict)
                    else {}
                )
            ),
            "interfaces": interfaces,
            "interface_count": len(interfaces),
            "snmp_status": clean_ascii(cached_record.get("status", "NOT DISCOVERED")) if isinstance(cached_record, dict) else "NOT DISCOVERED",
            "last_discovery": clean_ascii(cached_record.get("last_discovery", "")) if isinstance(cached_record, dict) else "",
            "snmp_source": "SNMP live inventory with cached fallback",
            "monitoring_type": "snmp" if role in {"Router", "Switch", "Firewall", "Access Point"} else ("internet_reachability" if role == "Internet" else "reachability"),
            "service_checks": ([
                {
                    "name": f"Internet target {target}",
                    "target": target,
                    "state": clean_ascii(result.get("state", "UNKNOWN")) or "UNKNOWN",
                    "latency": clean_ascii(result.get("latency", "N/A")) or "N/A",
                    "status_class": get_map_status_class(clean_ascii(result.get("state", "UNKNOWN")) or "UNKNOWN")
                }
                for target, result in internet_results.items()
            ] if role == "Internet" else []),
            "service_check_summary": (
                f"{sum(1 for result in internet_results.values() if result.get('state') == 'UP')} of {len(internet_results)} targets reachable"
                if role == "Internet" else ""
            )
        }

        if role == "Internet":
            devices[device_name]["state"] = internet_state
            devices[device_name]["status_class"] = get_map_status_class(internet_state)
            devices[device_name]["ip"] = ", ".join(INTERNET_CHECK_TARGETS) or clean_ascii(ip_address)
            devices[device_name]["interface_count"] = 0
            devices[device_name]["interfaces"] = []
            devices[device_name]["snmp_status"] = "NOT APPLICABLE"
            devices[device_name]["snmp_source"] = "External multi-target reachability monitoring"
        elif role == "Modem":
            devices[device_name]["snmp_source"] = "Ping/ARP reachability; SNMP not required"

    children_by_parent = reconciled_topology["children_by_parent"]
    roots = [name for name in reconciled_topology["roots"] if name in devices]

    # Include any registered device that was added after reconciliation input
    # was assembled. This is a safety fallback; normally every device is already
    # represented by the reconciler.
    for name in devices:
        if name not in parent_by_child and name not in roots:
            roots.append(name)

    role_order = {"Internet": 0, "Modem": 1, "Switch": 2, "Router": 3, "Firewall": 4, "Access Point": 5}
    roots.sort(key=lambda name: (role_order.get(devices[name].get("role", ""), 9), name.lower()))

    return {
        "success": True,
        "phase": "26B.8O",
        "topology_change_detection": build_topology_change_summary().get("settings", {}),
        "source_of_truth": f"{topology_source}; Phase 26B.5 change detection and auto-reconciliation; Phase 26B.6 root cause topology intelligence; SNMP-discovered interfaces for ports with cached SNMP fallback only",
        "self_building_topology": self_building_topology.get("summary", {}),
        "auto_infrastructure_linking": auto_link_result,
        "devices": devices,
        "roots": roots,
        "children_by_parent": children_by_parent,
        "relationships": infrastructure_relationships,
        "topology_validation": reconciled_topology["validation"],
        "unmapped_devices": build_phase25_map_management_payload().get("unmapped_devices", []),
        "physical_device_types": build_phase25_map_management_payload().get("physical_device_types", []),
        "infrastructure_roles": ["Internet Service", "Modem / Gateway", "Router", "Switch", "Firewall", "Access Point"],
        "infrastructure_choices": build_phase25_map_management_payload().get("infrastructure_choices", []),
        "parent_interfaces": build_phase25_map_management_payload().get("parent_interfaces", {}),
        "summary": {
            "infrastructure_devices": len(devices),
            "routers": sum(1 for item in devices.values() if item.get("role") == "Router"),
            "switches": sum(1 for item in devices.values() if item.get("role") == "Switch"),
            "interfaces": sum(item.get("interface_count", 0) for item in devices.values()),
            "roots": len(roots),
            "topology_valid": reconciled_topology["validation"].get("valid", False),
            "last_updated": now()
        }
    }


# PHASE 29.8 - Compatibility endpoint for topology change summaries.
# The lifecycle route module exposes topology change operations, while this
# stable read-only alias preserves the dashboard/API validation path.
@app.route("/api/topology-change-summary")
def api_topology_change_summary():
    return jsonify(build_topology_change_summary())


# PHASE 28.8 - TOPOLOGY LIFECYCLE API ROUTES
register_topology_lifecycle_api_routes(
    app,
    build_self_building_topology_summary=build_self_building_topology_summary,
    build_self_building_topology=build_self_building_topology,
    build_topology_change_summary=build_topology_change_summary,
    check_topology_changes=check_topology_changes,
    discover_cdp_neighbors=discover_cdp_neighbors,
    discover_lldp_neighbors=discover_lldp_neighbors,
    build_link_confidence_database=build_link_confidence_database,
    build_snapshot=_phase26b5_snapshot,
    topology_change_settings=_phase26b5_settings,
    save_config=save_config,
    write_event=write_event,
    now=now,
    config=config,
)












# PHASE 28.7 - TOPOLOGY INTELLIGENCE API ROUTES
register_topology_intelligence_api_routes(
    app,
    relationship_summary=phase27_relationship_engine_summary,
    root_cause_summary=build_root_cause_topology_summary,
    analyze_root_cause=analyze_root_cause_topology,
    infrastructure_payload=build_phase26_infrastructure_payload,
    write_event=write_event,
)







if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    load_config()
    load_uptime_stats()

    for name, ip in DEVICES.items():
        status[name] = {
            "ip": ip,
            "state": "CHECKING",
            "latency": "N/A",
            "last_checked": "Starting...",
            "last_change": "Starting..."
        }
        previous_status[name] = None

    write_event("SYSTEM | Network Monitor Dashboard started")
    if RELATIONSHIP_ENGINE_READY:
        write_event(
            f"SYSTEM | PHASE 27B RELATIONSHIP ENGINE READY | "
            f"Relationships: {RELATIONSHIP_STORE.count() if RELATIONSHIP_STORE else 0}"
        )
    else:
        write_event(
            f"WARNING | PHASE 27B RELATIONSHIP ENGINE NOT READY | "
            f"{RELATIONSHIP_MIGRATION}"
        )

    build_link_confidence_database(force=True)
    rebuild_auto_infrastructure_links()
    build_self_building_topology(force=True)
    check_topology_changes(force=True)
    analyze_root_cause_topology(force=True)

    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()

    app.run(host="0.0.0.0", port=5050)


