"""Monitoring and health-check helpers for On Watch Network Monitor."""

from __future__ import annotations

from datetime import datetime

from ping3 import ping

from utils.time_helpers import parse_timestamp


def check_device(ip):
    try:
        response = ping(ip, timeout=2)

        if response is None:
            return "DOWN", "N/A"

        return "UP", f"{round(response * 1000, 2)} ms"

    except Exception:
        return "ERROR", "N/A"



def status_number_to_text(value):
    if value == 1:
        return "UP"
    if value == 2:
        return "DOWN"
    if value == 3:
        return "TESTING"
    return "UNKNOWN"



def parse_latency_ms(latency_value):
    if latency_value is None:
        return None

    text = str(latency_value).replace("ms", "").strip()

    try:
        return float(text)
    except Exception:
        return None



def get_device_down_minutes(last_change_text):
    last_change_time = parse_timestamp(last_change_text)
    if not last_change_time:
        return 0

    return max(0, int((datetime.now() - last_change_time).total_seconds() / 60))
