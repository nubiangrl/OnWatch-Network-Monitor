"""Topology construction helpers for On Watch Network Monitor."""

from __future__ import annotations

import json
import re


def _confidence_physical_key(a, b):
    left = f"{a['device_token']}|{a['interface_token']}"
    right = f"{b['device_token']}|{b['interface_token']}"
    ordered = sorted([left, right])
    return "physical-" + re.sub(r"[^a-z0-9]+", "-", "--".join(ordered)).strip("-")[:170]



def _phase26b5_snapshot_key(snapshot):
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"))



def get_core_topology_type_names():
    """Types that participate in the main infrastructure path.

    Phase 13E rule:
    - Core path is determined by inventory/type data.
    - Endpoint links are not rendered as core topology chain links.
    - No specific endpoint names are hard-coded here.
    """
    return {
        "internet",
        "modem",
        "router",
        "switch",
        "firewall",
        "access point",
        "wireless access point",
        "ups",
        "power",
        "dns server",
        "dhcp server",
        "vpn gateway",
        "infrastructure"
    }
