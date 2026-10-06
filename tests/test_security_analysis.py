"""Tests for security-oriented analysis."""

from datetime import datetime, timedelta, timezone

from fak_log_analyzer.models import LogEntry
from fak_log_analyzer.security_analysis import (
    calculate_security_stats,
    is_sensitive_path,
)


def make_entry(
    ip: str,
    path: str,
    status: int = 200,
    timestamp: datetime | None = None,
) -> LogEntry:
    """Create a test log entry."""

    return LogEntry(
        ip_address=ip,
        timestamp=timestamp or datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=100,
    )


def test_sensitive_path_matching():
    """Configured sensitive paths should be recognized."""

    assert is_sensitive_path("/.env")
    assert is_sensitive_path("/.git/config")
    assert is_sensitive_path("/wp-admin/")
    assert is_sensitive_path("/wp-admin/admin-ajax.php")
    assert is_sensitive_path("/admin?next=/dashboard")
    assert not is_sensitive_path("/about")


def test_authentication_failures_are_aggregated():
    """401 responses should be counted by IP and normalized path."""

    entries = [
        make_entry("10.0.0.1", "/login", 401),
        make_entry("10.0.0.1", "/login?next=/", 401),
        make_entry("10.0.0.2", "/login", 401),
    ]

    stats = calculate_security_stats(entries)

    assert stats.authentication_failures_by_ip["10.0.0.1"] == 2
    assert stats.authentication_failures_by_path["/login"] == 3


def test_404_paths_are_counted_and_deduplicated():
    """404 analysis should track total requests and distinct paths."""

    entries = [
        make_entry("10.0.0.1", "/missing-a", 404),
        make_entry("10.0.0.1", "/missing-b", 404),
        make_entry("10.0.0.1", "/missing-a?x=1", 404),
    ]

    stats = calculate_security_stats(entries)

    assert stats.not_found_by_ip["10.0.0.1"] == 3
    assert stats.unique_not_found_paths_by_ip["10.0.0.1"] == 2


def test_peak_requests_per_minute_by_ip():
    """The highest one-minute request bucket should be retained per IP."""

    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = [
        make_entry("10.0.0.1", "/", timestamp=start + timedelta(seconds=5)),
        make_entry("10.0.0.1", "/", timestamp=start + timedelta(seconds=20)),
        make_entry("10.0.0.1", "/", timestamp=start + timedelta(seconds=40)),
        make_entry("10.0.0.1", "/", timestamp=start + timedelta(minutes=1)),
    ]

    stats = calculate_security_stats(entries)

    timestamp, count = stats.peak_requests_per_minute_by_ip["10.0.0.1"]

    assert timestamp == start
    assert count == 3
