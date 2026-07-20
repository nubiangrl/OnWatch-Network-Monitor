"""Shared date and duration helpers for On Watch Network Monitor."""

from datetime import datetime


def parse_timestamp(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None



def format_duration_seconds(total_seconds):
    try:
        total_seconds = int(total_seconds)
    except Exception:
        return ""

    if total_seconds < 0:
        return ""

    days = total_seconds // 86400
    total_seconds %= 86400

    hours = total_seconds // 3600
    total_seconds %= 3600

    minutes = total_seconds // 60
    seconds = total_seconds % 60

    parts = []

    if days:
        parts.append(f"{days}d")

    if hours:
        parts.append(f"{hours}h")

    if minutes:
        parts.append(f"{minutes}m")

    if seconds or not parts:
        parts.append(f"{seconds}s")

    return " ".join(parts)



def calculate_overlap_seconds(start_a, end_a, start_b, end_b):
    overlap_start = max(start_a, start_b)
    overlap_end = min(end_a, end_b)
    if overlap_end <= overlap_start:
        return 0
    return max(0, int((overlap_end - overlap_start).total_seconds()))



def format_time_ago(timestamp_value):
    timestamp = parse_timestamp(timestamp_value)

    if not timestamp:
        return "N/A"

    seconds = int((datetime.now() - timestamp).total_seconds())

    if seconds < 60:
        return f"{seconds}s ago"

    minutes = seconds // 60

    if minutes < 60:
        return f"{minutes}m ago"

    hours = minutes // 60

    if hours < 24:
        return f"{hours}h ago"

    days = hours // 24
    return f"{days}d ago"



def calculate_alert_duration(alert_time, resolved_time):
    start = parse_timestamp(alert_time)
    end = parse_timestamp(resolved_time)

    if not start or not end:
        return ""

    return format_duration_seconds((end - start).total_seconds())
