"""Relationship and dependency presentation helpers."""

from __future__ import annotations

from utils.common import clean_ascii


def _relationship_state_details(state, confidence, source, last_verified=""):
    """Return consistent relationship-state metadata for links and devices."""
    normalized_state = clean_ascii(state).upper() or "CONFIGURED"
    try:
        normalized_confidence = max(0, min(100, int(confidence or 0)))
    except (TypeError, ValueError):
        normalized_confidence = 0

    return {
        "state": normalized_state,
        "confidence": normalized_confidence,
        "source": clean_ascii(source),
        "last_verified": clean_ascii(last_verified),
    }



def get_dependency_icon(node_type):
    node_type = clean_ascii(node_type).lower()
    if "internet" in node_type:
        return "🌐"
    if "modem" in node_type or "gateway" in node_type:
        return "📡"
    if "router" in node_type:
        return "🛜"
    if "switch" in node_type:
        return "🔀"
    if "port" in node_type:
        return "🔌"
    if "server" in node_type or "nas" in node_type:
        return "🖥️"
    if "virtual" in node_type or "vm" in node_type:
        return "🧩"
    if "mac" in node_type or "laptop" in node_type or "windows" in node_type or "chromebook" in node_type:
        return "💻"
    return "📦"



def normalize_relationship_entry(entry):
    """Normalize parent/child relationship records into one predictable structure."""
    if not isinstance(entry, dict):
        return {
            "parent": clean_ascii(entry),
            "relationship": "Depends On",
            "source": "legacy_relationship",
            "criticality": "Normal"
        }

    return {
        "parent": clean_ascii(entry.get("parent", "")),
        "relationship": clean_ascii(entry.get("relationship", "Depends On")) or "Depends On",
        "source": clean_ascii(entry.get("source", "device_relationships")) or "device_relationships",
        "criticality": clean_ascii(entry.get("criticality", "Normal")) or "Normal"
    }
