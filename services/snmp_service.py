"""Reusable SNMP command, parsing, and filtering helpers."""

from __future__ import annotations

import re
import shutil
import subprocess

from utils.common import clean_ascii


def _snmp_value_from_line(line):
    """Return a clean value from a normal net-snmp output line."""
    text = clean_ascii(line)
    if "=" not in text:
        return ""
    value = text.split("=", 1)[1].strip()
    if ":" in value:
        value_type, possible_value = value.split(":", 1)
        if value_type.strip().upper() in {
            "STRING", "HEX-STRING", "INTEGER", "INTEGER32", "IPADDRESS",
            "OID", "TIMETICKS", "GAUGE32", "COUNTER32", "COUNTER64"
        }:
            value = possible_value.strip()
    return value.strip().strip('"')



def is_usable_snmp_interface(name):
    """Keep physical/router/switch interfaces; suppress virtual management-only interfaces."""
    name = clean_ascii(name)
    if not name or name.lower() == "unknown":
        return False

    lower = name.lower()

    ignored_prefixes = [
        "null", "loopback", "lo", "vlan", "bvi", "nvi", "tunnel", "tun",
        "port-channel", "po", "stackport", "control-plane", "voip-null",
        "async", "virtual", "template", "dialer", "cellular", "wlan-ap"
    ]

    for prefix in ignored_prefixes:
        if lower == prefix or lower.startswith(prefix):
            return False

    return True



def run_snmpwalk_readonly(host, community, oid, timeout_seconds=10):
    if not shutil.which("snmpwalk"):
        return ""
    try:
        completed = subprocess.run(
            ["snmpwalk", "-v2c", "-c", str(community), "-Oqv", str(host), str(oid)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False
        )
        return completed.stdout or ""
    except Exception:
        return ""



def run_snmpwalk_oid_readonly(host, community, oid, timeout_seconds=10):
    if not shutil.which("snmpwalk"):
        return ""
    try:
        completed = subprocess.run(
            ["snmpwalk", "-v2c", "-c", str(community), str(host), str(oid)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False
        )
        return completed.stdout or ""
    except Exception:
        return ""



def parse_snmpwalk_oid_integer_map(text):
    rows = {}
    for line in str(text or "").splitlines():
        m = re.search(r"\.([0-9]+)\s*=\s*(?:Counter32|Counter64|Gauge32|INTEGER):\s*([0-9]+)", line)
        if m:
            rows[m.group(1)] = int(m.group(2))
    return rows



def is_snmp_noise_event(line):
    text = clean_ascii(line).lower()
    return "snmp failed" in text or "snmpwalk" in text or "snmp timeout" in text
