"""Tests for the log analyzer."""

from datetime import datetime, timedelta, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry


def create_entry(
    ip: str,
    method: str,
    path: str,
    status: int,
    size: int,
    timestamp: datetime | None = None,
) -> LogEntry:
    """Create a test log entry."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    return LogEntry(
        ip_address=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=size,
    )


def test_analyze_requests():
    """Analyzer should correctly count requests."""
    entries = [
        create_entry("10.0.0.1", "GET", "/", 200, 1000),
        create_entry("10.0.0.2", "GET", "/about", 200, 500),
        create_entry("10.0.0.1", "POST", "/login", 401, 250),
    ]

    result = analyze(entries)

    assert result.total_requests == 3
    assert result.method_counts["GET"] == 2
    assert result.method_counts["POST"] == 1


def test_analyze_status_codes():
    """Analyzer should correctly count HTTP status codes."""
    entries = [
        create_entry("10.0.0.1", "GET", "/", 200, 100),
        create_entry("10.0.0.2", "GET", "/", 200, 200),
        create_entry("10.0.0.3", "GET", "/", 404, 300),
        create_entry("10.0.0.4", "GET", "/", 500, 400),
    ]

    result = analyze(entries)

    assert result.status_counts[200] == 2
    assert result.status_counts[404] == 1
    assert result.status_counts[500] == 1


def test_analyze_ip_addresses():
    """Analyzer should identify request frequency by IP."""
    entries = [
        create_entry("10.0.0.1", "GET", "/", 200, 100),
        create_entry("10.0.0.1", "GET", "/about", 200, 100),
        create_entry("10.0.0.2", "GET", "/", 200, 100),
    ]

    result = analyze(entries)

    assert result.ip_counts["10.0.0.1"] == 2
    assert result.ip_counts["10.0.0.2"] == 1


def test_analyze_paths():
    """Analyzer should count requested paths."""
    entries = [
        create_entry("10.0.0.1", "GET", "/", 200, 100),
        create_entry("10.0.0.2", "GET", "/", 200, 100),
        create_entry("10.0.0.3", "GET", "/login", 200, 100),
    ]

    result = analyze(entries)

    assert result.path_counts["/"] == 2
    assert result.path_counts["/login"] == 1


def test_error_rate():
    """Analyzer should calculate the HTTP error rate."""
    entries = [
        create_entry("10.0.0.1", "GET", "/", 200, 100),
        create_entry("10.0.0.2", "GET", "/", 200, 100),
        create_entry("10.0.0.3", "GET", "/", 404, 100),
        create_entry("10.0.0.4", "GET", "/", 500, 100),
    ]

    result = analyze(entries)

    assert result.error_count == 2
    assert result.error_rate == 50.0


def test_average_response_size():
    """Analyzer should calculate average response size."""
    entries = [
        create_entry("10.0.0.1", "GET", "/", 200, 100),
        create_entry("10.0.0.2", "GET", "/", 200, 300),
    ]

    result = analyze(entries)

    assert result.total_bytes == 400
    assert result.average_response_size == 200.0


def test_empty_analysis():
    """Analyzer should handle an empty log file."""
    result = analyze([])

    assert result.total_requests == 0
    assert result.error_count == 0
    assert result.error_rate == 0.0
    assert result.average_response_size == 0.0


def test_time_stats_are_included():
    """Analyzer should include time statistics in the result."""
    entries = [
        LogEntry(
            ip_address="10.0.0.1",
            timestamp=datetime(
                2026,
                9,
                11,
                10,
                0,
                tzinfo=timezone.utc,
            ),
            method="GET",
            path="/",
            protocol="HTTP/1.1",
            status_code=200,
            response_size=100,
        ),
        LogEntry(
            ip_address="10.0.0.2",
            timestamp=datetime(
                2026,
                9,
                11,
                10,
                2,
                tzinfo=timezone.utc,
            ),
            method="GET",
            path="/api",
            protocol="HTTP/1.1",
            status_code=200,
            response_size=200,
        ),
    ]

    result = analyze(entries)

    assert result.time_stats.start_time == entries[0].timestamp
    assert result.time_stats.end_time == entries[1].timestamp
    assert result.time_stats.duration_seconds == 120


def test_peak_traffic():
    """Peak traffic should return the busiest minute."""
    start = datetime(
        2026,
        9,
        11,
        10,
        0,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(
            "192.168.1.1",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.2",
            "GET",
            "/",
            200,
            100,
            start + timedelta(seconds=10),
        ),
        create_entry(
            "192.168.1.3",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
        create_entry(
            "192.168.1.4",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1, seconds=10),
        ),
        create_entry(
            "192.168.1.5",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1, seconds=20),
        ),
    ]

    result = analyze(entries)

    peak_time, peak_count = result.peak_traffic

    assert peak_time == start + timedelta(minutes=1)
    assert peak_count == 3


def test_traffic_trend():
    """Traffic trend should be classified correctly."""
    start = datetime(
        2026,
        9,
        11,
        10,
        0,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(
            "192.168.1.1",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.2",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
        create_entry(
            "192.168.1.3",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
        create_entry(
            "192.168.1.4",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
    ]

    result = analyze(entries)

    assert result.traffic_trend == "increasing"


def test_traffic_trend_increasing():
    """Traffic trend should detect increasing traffic."""
    start = datetime(
        2026,
        9,
        11,
        10,
        0,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(
            "192.168.1.1",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.2",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
        create_entry(
            "192.168.1.3",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
    ]

    result = analyze(entries)

    assert result.traffic_trend == "increasing"


def test_traffic_trend_decreasing():
    """Traffic trend should detect decreasing traffic."""
    start = datetime(
        2026,
        9,
        11,
        10,
        0,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(
            "192.168.1.1",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.2",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.3",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.4",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
    ]

    result = analyze(entries)

    assert result.traffic_trend == "decreasing"


def test_traffic_trend_stable():
    """Traffic trend should detect stable traffic."""
    start = datetime(
        2026,
        9,
        11,
        10,
        0,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(
            "192.168.1.1",
            "GET",
            "/",
            200,
            100,
            start,
        ),
        create_entry(
            "192.168.1.2",
            "GET",
            "/",
            200,
            100,
            start + timedelta(minutes=1),
        ),
    ]

    result = analyze(entries)

    assert result.traffic_trend == "stable"


def test_traffic_trend_with_single_bucket():
    """Traffic trend should be stable with one time bucket."""
    timestamp = datetime(
        2026,
        9,
        11,
        10,
        0,
        tzinfo=timezone.utc,
    )

    entries = [
        create_entry(
            "192.168.1.1",
            "GET",
            "/",
            200,
            100,
            timestamp,
        ),
        create_entry(
            "192.168.1.2",
            "GET",
            "/",
            200,
            100,
            timestamp + timedelta(seconds=20),
        ),
    ]

    result = analyze(entries)

    assert result.traffic_trend == "stable"
