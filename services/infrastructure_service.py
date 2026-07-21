"""Infrastructure role and link helpers for On Watch Network Monitor."""

from __future__ import annotations

import re

from utils.common import clean_ascii


AUTO_INFRASTRUCTURE_LINK_SOURCE = "auto_infrastructure_link_engine"

LEGACY_AUTO_INFRASTRUCTURE_LINK_SOURCES = {
    "auto_role_hierarchy",
    "auto_infrastructure_link_engine",
}


def normalize_infrastructure_role(value):
    """Normalize infrastructure roles so provisioning and discovery use one model."""
    value = clean_ascii(value).lower().replace("-", "_").replace(" ", "_")

    role_map = {
        "internet": "Internet",
        "internet_service": "Internet",
        "internet_link": "Internet",
        "modem": "Modem",
        "gateway": "Modem",
        "modem_gateway": "Modem",
        "router": "Router",
        "switch": "Switch",
        "firewall": "Firewall",
        "access_point": "Access Point",
        "ap": "Access Point",
        "ups": "UPS",
        "power": "UPS",
        "dns": "DNS Server",
        "dns_server": "DNS Server",
        "dhcp": "DHCP Server",
        "dhcp_server": "DHCP Server",
        "vpn": "VPN Gateway",
        "vpn_gateway": "VPN Gateway"
    }

    return role_map.get(value, clean_ascii(value).title() if value else "Infrastructure")



def is_snmp_capable_infrastructure_role(role):
    """Roles Phase 16 will query with SNMP during infrastructure discovery."""
    return normalize_infrastructure_role(role) in [
        "Router",
        "Switch",
        "Firewall",
        "Access Point",
        "UPS",
        "DNS Server",
        "DHCP Server",
        "VPN Gateway"
    ]



def _infrastructure_registry_order(item):
    device_name, info = item
    info = info if isinstance(info, dict) else {}
    return (
        clean_ascii(info.get("registered_at", "")),
        clean_ascii(device_name).lower(),
    )



def _infrastructure_role_rank(role):
    ranks = {
        "Internet": 0,
        "Modem": 10,
        "Firewall": 20,
        "VPN Gateway": 25,
        "Router": 30,
        "Switch": 40,
        "Access Point": 50,
        "DNS Server": 60,
        "DHCP Server": 60,
        "UPS": 70,
    }
    return ranks.get(normalize_infrastructure_role(role), 100)



def _stable_auto_infrastructure_link_id(parent_name, child_name):
    raw = f"{parent_name}|{child_name}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return f"auto-physical-{slug}"[:180]



def _is_generated_infrastructure_link(link):
    if not isinstance(link, dict):
        return False
    source = clean_ascii(link.get("source", "")).lower()
    link_id = clean_ascii(link.get("id", "")).lower()
    selection = clean_ascii(link.get("selection_source", "")).lower()
    generated = bool(link.get("auto_generated", False))
    return (
        generated
        or source in LEGACY_AUTO_INFRASTRUCTURE_LINK_SOURCES
        or link_id.startswith("auto-role-")
        or link_id.startswith("auto-physical-")
        or selection in {"role_hierarchy", "verified_physical_link", "discovered_physical_link"}
    )



def _is_explicit_saved_infrastructure_link(link):
    """Identify user-provisioned links, including legacy root links.

    Phase 26B.7M stored the manually provisioned Internet/Modem path with an
    auto source. During migration, a MANUAL-only evidence set is therefore
    treated as explicit. A CDP/LLDP link is never promoted to explicit merely
    because older confidence data also included MANUAL.
    """
    if not isinstance(link, dict):
        return False
    selection = clean_ascii(link.get("selection_source", "")).lower()
    source = clean_ascii(link.get("source", "")).lower()
    evidence = {clean_ascii(item).upper() for item in (link.get("evidence_sources", []) or []) if clean_ascii(item)}
    if selection == "explicit_saved_link":
        return True
    if source and source not in LEGACY_AUTO_INFRASTRUCTURE_LINK_SOURCES:
        return True
    if evidence and evidence.issubset({"MANUAL"}):
        return True
    return not _is_generated_infrastructure_link(link)
