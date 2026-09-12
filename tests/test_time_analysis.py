"""Tests for time-based analysis."""

from datetime import datetime, timedelta, timezone

from fak_log_analyzer.models import LogEntry
from fak_log_analyzer.time_analysis import (
    calculate_requests_per_minute,
    calculate_time_stats,
)


def create_entry(timestamp: datetime) -> LogEntry:
    """Create a test log entry with the given timestamp."""
    return LogEntry(
        ip_address="192.168.1.10",
        timestamp=timestamp,
        method="GET",
        path="/",
        protocol="HTTP/1.1",
        status_code=200,
        response_size=100,
    )


def test_time_stats():
    """Time statistics should be calculated correctly."""
    start = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)

    entries = [
        create_entry(start),
        create_entry(start + timedelta(seconds=30)),
        create_entry(start + timedelta(minutes=1)),
    ]

    stats = calculate_time_stats(entries)

    assert stats.start_time == start
    assert stats.end_time == start + timedelta(minutes=1)
    assert stats.duration_seconds == 60.0
    assert stats.requests_per_minute == 3.0
    assert stats.requests_per_hour == 180.0


def test_time_stats_unsorted_entries():
    """Time statistics should work with unsorted entries."""
    start = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)

    entries = [
        create_entry(start + timedelta(minutes=2)),
        create_entry(start),
        create_entry(start + timedelta(minutes=1)),
    ]

    stats = calculate_time_stats(entries)

    assert stats.start_time == start
    assert stats.end_time == start + timedelta(minutes=2)
    assert stats.duration_seconds == 120.0
    assert stats.requests_per_minute == 1.5
    assert stats.requests_per_hour == 90.0


def test_time_stats_empty():
    """Empty entries should return zero-valued time statistics."""
    stats = calculate_time_stats([])

    assert stats.start_time is None
    assert stats.end_time is None
    assert stats.duration_seconds == 0.0
    assert stats.requests_per_minute == 0.0
    assert stats.requests_per_hour == 0.0


def test_time_stats_same_timestamp():
    """Entries with the same timestamp should not cause division by zero."""
    timestamp = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)

    entries = [
        create_entry(timestamp),
        create_entry(timestamp),
        create_entry(timestamp),
    ]

    stats = calculate_time_stats(entries)

    assert stats.start_time == timestamp
    assert stats.end_time == timestamp
    assert stats.duration_seconds == 0.0
    assert stats.requests_per_minute == 0.0
    assert stats.requests_per_hour == 0.0


def test_requests_per_minute():
    """Requests should be grouped into one-minute buckets."""
    start = datetime(
        2026,
        9,
        11,
        10,
        15,
        32,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(start),
        create_entry(start + timedelta(seconds=8)),
        create_entry(start + timedelta(seconds=28)),
        create_entry(start + timedelta(minutes=1)),
        create_entry(start + timedelta(minutes=1, seconds=20)),
    ]

    buckets = calculate_requests_per_minute(entries)

    assert buckets == {
        datetime(
            2026,
            9,
            11,
            10,
            15,
            tzinfo=timezone.utc,
        ): 2,
        datetime(
            2026,
            9,
            11,
            10,
            16,
            tzinfo=timezone.utc,
        ): 3,
    }


def test_requests_per_minute_empty():
    """Empty entries should return no time buckets."""
    buckets = calculate_requests_per_minute([])

    assert buckets == {}
