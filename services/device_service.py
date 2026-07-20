"""Device-related validation and presentation helpers."""

from __future__ import annotations

import ipaddress
import re

from utils.common import clean_ascii


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False



def is_lan_ip(ip_value):
    try:
        ip_text = str(ip_value).split(",")[0].strip()
        return ipaddress.ip_address(ip_text).is_private
    except Exception:
        return False



def get_map_icon(device_type):
    icons = {
        "Internet": "🌎",
        "Modem": "📡",
        "Router": "🛜",
        "Switch": "🔀",
        "Server / NAS": "🗄️",
        "Server": "🖥️",
        "Desktop PC": "🖥️",
        "Windows PC": "🖥️",
        "Laptop": "💻",
        "Mac": "💻",
        "Chromebook": "💻",
        "Printer": "🖨️",
        "Camera": "📷",
        "TV": "📺",
        "Gaming Console": "🎮",
        "Mobile Device": "📱",
        "IoT Device": "🏠",
        "Audio Device": "🔊",
        "Virtual Machine": "🧩",
        "Other Endpoint": "💻",
        "Endpoint": "💻"
    }

    return icons.get(device_type, "💻")



def get_map_status_class(state):
    state = (state or "UNKNOWN").upper()

    if state == "UP":
        return "map-up"

    if state == "DOWN":
        return "map-down"

    if state in ["ERROR", "WARNING"]:
        return "map-warning"

    return "map-unknown"



def normalize_mac_address(value):
    """Return MAC address in AA:BB:CC:DD:EE:FF format when possible."""
    value = clean_ascii(str(value or "")).strip()
    if not value:
        return ""

    value = value.replace("-", ":").replace(".", "")

    if ":" in value:
        parts = [p.zfill(2) for p in value.split(":") if p]
        if len(parts) == 6:
            return ":".join(p.upper()[-2:] for p in parts)

    hex_only = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(hex_only) == 12:
        return ":".join(hex_only[i:i+2].upper() for i in range(0, 12, 2))

    return value.upper()
