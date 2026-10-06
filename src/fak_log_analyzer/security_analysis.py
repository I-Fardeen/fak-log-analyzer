from collections import Counter, defaultdict
from datetime import datetime

from fak_log_analyzer.models import LogEntry, SecurityStats
from fak_log_analyzer.security_rules import (
    SENSITIVE_PATH_PREFIXES,
    SENSITIVE_PATHS,
)


def _request_path(path: str) -> str:

    return path.split("?", 1)[0].split("#", 1)[0] or "/"


def is_sensitive_path(path: str) -> bool:

    normalized = _request_path(path)

    if normalized in SENSITIVE_PATHS:
        return True

    return any(
        normalized == prefix.rstrip("/") or normalized.startswith(prefix)
        for prefix in SENSITIVE_PATH_PREFIXES
    )


def calculate_security_stats(entries: list[LogEntry]) -> SecurityStats:

    authentication_failures_by_ip: Counter[str] = Counter()
    authentication_failures_by_path: Counter[str] = Counter()
    not_found_by_ip: Counter[str] = Counter()
    not_found_paths_by_ip: dict[str, set[str]] = defaultdict(set)
    sensitive_path_counts: Counter[str] = Counter()
    sensitive_path_ips: Counter[str] = Counter()

    # A minute bucket is intentionally aligned with the existing traffic
    # analysis rather than introducing a separate time-window abstraction.
    requests_per_minute_by_ip: dict[tuple[str, datetime], int] = defaultdict(int)

    for entry in entries:
        normalized_path = _request_path(entry.path)
        minute = entry.timestamp.replace(second=0, microsecond=0)

        requests_per_minute_by_ip[(entry.ip_address, minute)] += 1

        if entry.status_code == 401:
            authentication_failures_by_ip[entry.ip_address] += 1
            authentication_failures_by_path[normalized_path] += 1

        if entry.status_code == 404:
            not_found_by_ip[entry.ip_address] += 1
            not_found_paths_by_ip[entry.ip_address].add(normalized_path)

        if is_sensitive_path(entry.path):
            sensitive_path_counts[normalized_path] += 1
            sensitive_path_ips[entry.ip_address] += 1

    peak_requests_per_minute_by_ip: dict[str, tuple[datetime, int]] = {}

    for (ip, timestamp), count in requests_per_minute_by_ip.items():
        current = peak_requests_per_minute_by_ip.get(ip)

        if current is None or count > current[1]:
            peak_requests_per_minute_by_ip[ip] = (timestamp, count)

    unique_not_found_paths_by_ip = {
        ip: len(paths) for ip, paths in not_found_paths_by_ip.items()
    }

    return SecurityStats(
        authentication_failures_by_ip=authentication_failures_by_ip,
        authentication_failures_by_path=authentication_failures_by_path,
        not_found_by_ip=not_found_by_ip,
        unique_not_found_paths_by_ip=unique_not_found_paths_by_ip,
        sensitive_path_counts=sensitive_path_counts,
        sensitive_path_ips=sensitive_path_ips,
        peak_requests_per_minute_by_ip=peak_requests_per_minute_by_ip,
    )
