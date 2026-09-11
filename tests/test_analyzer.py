"""Tests for the log analyzer."""

from datetime import datetime, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry


def create_entry(
    ip: str,
    method: str,
    path: str,
    status: int,
    size: int,
) -> LogEntry:
    """Create a test log entry."""
    return LogEntry(
        ip_address=ip,
        timestamp=datetime.now(timezone.utc),
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
