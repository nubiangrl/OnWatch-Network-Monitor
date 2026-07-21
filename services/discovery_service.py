"""CDP and LLDP discovery parsing helpers for On Watch Network Monitor."""

from __future__ import annotations

import re

from utils.common import clean_ascii
from services.snmp_service import _snmp_value_from_line


def _cdp_oid_suffix(line):
    """Extract (local_ifindex, remote_device_index) from a CDP cache row."""
    left = clean_ascii(line).split("=", 1)[0].strip()
    numbers = re.findall(r"\.(\d+)", left)
    if len(numbers) < 2:
        return None
    return numbers[-2], numbers[-1]



def _parse_cdp_walk(lines):
    parsed = {}
    for line in lines or []:
        key = _cdp_oid_suffix(line)
        if key:
            parsed[key] = _snmp_value_from_line(line)
    return parsed



def _decode_cdp_address(raw_value):
    """Decode cdpCacheAddress returned as IPADDRESS, dotted bytes, or hex bytes."""
    raw = clean_ascii(raw_value).strip()
    if not raw:
        return ""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
        return raw
    hex_bytes = re.findall(r"\b[0-9A-Fa-f]{2}\b", raw)
    if len(hex_bytes) == 4:
        return ".".join(str(int(item, 16)) for item in hex_bytes)
    return ""



def _stable_discovered_link_id(local_device, local_ifindex, remote_device, remote_port):
    raw = f"{local_device}|{local_ifindex}|{remote_device}|{remote_port}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return f"cdp-{slug}"[:180]



def _lldp_remote_oid_suffix(line):
    """Extract (time_mark, local_port_num, remote_index) from an LLDP row."""
    left = clean_ascii(line).split("=", 1)[0].strip()
    numbers = re.findall(r"\.(\d+)", left)
    if len(numbers) < 3:
        return None
    return numbers[-3], numbers[-2], numbers[-1]



def _lldp_local_oid_suffix(line):
    """Extract localPortNum from an LLDP local-port table row."""
    left = clean_ascii(line).split("=", 1)[0].strip()
    numbers = re.findall(r"\.(\d+)", left)
    return numbers[-1] if numbers else None



def _parse_lldp_remote_walk(lines):
    parsed = {}
    for line in lines or []:
        key = _lldp_remote_oid_suffix(line)
        if key:
            parsed[key] = _snmp_value_from_line(line)
    return parsed



def _parse_lldp_local_walk(lines):
    parsed = {}
    for line in lines or []:
        key = _lldp_local_oid_suffix(line)
        if key:
            parsed[str(key)] = _snmp_value_from_line(line)
    return parsed



def _stable_lldp_link_id(local_device, local_port_num, remote_device, remote_port):
    raw = f"{local_device}|{local_port_num}|{remote_device}|{remote_port}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return f"lldp-{slug}"[:180]
