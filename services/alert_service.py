"""Alert, event-log, and alert-history helpers for On Watch Network Monitor."""

from __future__ import annotations

from datetime import datetime
import json
import os
import re

from utils.common import clean_ascii, now
from utils.time_helpers import parse_timestamp


EVENT_LOG = "logs/events.log"
ALERTS_FILE = "data/alerts.json"


def write_event(message):
    os.makedirs("logs", exist_ok=True)

    with open(EVENT_LOG, "a") as log:
        log.write(f"{now()} | {message}\n")



def normalize_transition_key(source, device, problem, port=""):
    """Create a stable key so one active incident only speaks once."""
    source = clean_ascii(source).lower()
    device = clean_ascii(device).lower()
    problem = clean_ascii(problem).lower()
    port = clean_ascii(port).lower()
    raw_key = f"{source}|{device}|{problem}|{port}"
    raw_key = re.sub(r"\s+", " ", raw_key).strip()
    return raw_key



def read_recent_events(limit=12):
    if not os.path.exists(EVENT_LOG):
        return []

    with open(EVENT_LOG, "r") as log:
        lines = log.readlines()

    return list(reversed(lines[-limit:]))



def load_alert_history():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "w") as f:
            json.dump([], f, indent=4)
        return []

    try:
        with open(ALERTS_FILE, "r") as f:
            return json.load(f)

    except Exception as e:
        write_event(f"ERROR | ALERT HISTORY LOAD FAILED | {e}")
        return []



def save_alert_history(alerts):
    os.makedirs("data", exist_ok=True)

    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)



def alert_id(device, problem):
    return f"{device}|{problem}"



def normalize_alert_severity(value):
    severity = clean_ascii(value).upper()

    if severity in ["CRITICAL", "WARNING", "INFO"]:
        return severity

    if severity in ["INFORMATION", "INFORMATIONAL"]:
        return "INFO"

    return "WARNING"



def get_event_log_lines(limit=1000):
    if not os.path.exists(EVENT_LOG):
        return []

    try:
        with open(EVENT_LOG, "r", errors="ignore") as log:
            return log.readlines()[-limit:]
    except Exception:
        return []



def normalize_event_device_name(raw_device_name):
    text = clean_ascii(raw_device_name)

    if "(" in text:
        text = text.split("(", 1)[0].strip()

    return text.strip()



def parse_event_timestamp_from_line(line):
    try:
        timestamp_text = line.split(" | ", 1)[0].strip()
        return parse_timestamp(timestamp_text)
    except Exception:
        return None



def event_age_weight(event_time):
    if not event_time:
        return 0.05

    age_hours = max(
        0,
        (datetime.now() - event_time).total_seconds() / 3600
    )

    age_days = age_hours / 24

    # Phase 10C.3 Event Aging Engine:
    # Recent events matter most. Older events fade automatically.
    if age_hours <= 6:
        return 1.0

    if age_hours <= 24:
        return 0.85

    if age_days <= 3:
        return 0.55

    if age_days <= 7:
        return 0.30

    if age_days <= 14:
        return 0.15

    if age_days <= 30:
        return 0.08

    return 0.03



def event_age_bucket(event_time):
    if not event_time:
        return "unknown"

    age_hours = max(
        0,
        (datetime.now() - event_time).total_seconds() / 3600
    )

    age_days = age_hours / 24

    if age_hours <= 6:
        return "0-6h"

    if age_hours <= 24:
        return "6-24h"

    if age_days <= 3:
        return "1-3d"

    if age_days <= 7:
        return "4-7d"

    if age_days <= 14:
        return "8-14d"

    if age_days <= 30:
        return "15-30d"

    return "30d+"



def get_event_severity_weight(clean_line):
    if "ALERT | INTERNET OUTAGE" in clean_line:
        return 1.25

    if "ALERT | ROUTER LINK |" in clean_line:
        return 1.15

    if "ALERT | SWITCH LINK |" in clean_line:
        return 1.10

    if "ALERT | DEVICE |" in clean_line:
        return 1.0

    return 1.0
