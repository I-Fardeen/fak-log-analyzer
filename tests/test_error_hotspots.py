"""Tests for operational error hotspot analysis."""

from datetime import datetime, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry, ReportConfig
from fak_log_analyzer.reporters.csv import CsvReporter
from fak_log_analyzer.reporters.json import JsonReporter

"""Tests for operational error hotspot analysis."""


def create_entry(
    ip: str,
    path: str,
    status: int,
) -> LogEntry:
    """Create a test log entry."""

    return LogEntry(
        ip_address=ip,
        timestamp=datetime(
            2026,
            9,
            11,
            10,
            0,
            0,
            tzinfo=timezone.utc,
        ),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=100,
    )


def test_error_path_counts():
    """Analyzer should count errors by requested path."""

    entries = [
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 404),
        create_entry("10.0.0.2", "/login", 401),
        create_entry("10.0.0.3", "/index.html", 200),
    ]

    result = analyze(entries)

    assert result.error_path_counts["/api/users"] == 2
    assert result.error_path_counts["/login"] == 1
    assert "/index.html" not in result.error_path_counts


def test_error_ip_counts():
    """Analyzer should count errors by client IP."""

    entries = [
        create_entry("10.0.0.1", "/a", 500),
        create_entry("10.0.0.1", "/b", 404),
        create_entry("10.0.0.2", "/c", 401),
        create_entry("10.0.0.3", "/d", 200),
    ]

    result = analyze(entries)

    assert result.error_ip_counts["10.0.0.1"] == 2
    assert result.error_ip_counts["10.0.0.2"] == 1
    assert "10.0.0.3" not in result.error_ip_counts


def test_error_status_counts():
    """Analyzer should count only 4xx and 5xx status codes."""

    entries = [
        create_entry("10.0.0.1", "/a", 500),
        create_entry("10.0.0.2", "/b", 500),
        create_entry("10.0.0.3", "/c", 404),
        create_entry("10.0.0.4", "/d", 200),
        create_entry("10.0.0.5", "/e", 301),
    ]

    result = analyze(entries)

    assert result.error_status_counts[500] == 2
    assert result.error_status_counts[404] == 1
    assert 200 not in result.error_status_counts
    assert 301 not in result.error_status_counts


def test_json_contains_error_hotspots():
    """JSON output should expose error hotspot information."""

    entries = [
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 404),
        create_entry("10.0.0.2", "/login", 401),
    ]

    result = analyze(entries)

    output = JsonReporter().render(result, ReportConfig())

    assert '"error_hotspots"' in output
    assert '"/api/users": 2' in output
    assert '"10.0.0.1": 2' in output
    assert '"500": 1' in output


def test_csv_contains_error_hotspots():
    """CSV output should expose error hotspot information."""

    entries = [
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 404),
        create_entry("10.0.0.2", "/login", 401),
    ]

    result = analyze(entries)

    output = CsvReporter().render(result, ReportConfig())

    assert "error_path,/api/users,2" in output
    assert "error_ip,10.0.0.1,2" in output
    assert "error_status,404,1" in output
    assert "error_status,500,1" in output


def test_json_contains_findings():
    """JSON output should expose operational findings."""

    entries = [
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.2", "/", 200),
    ]

    result = analyze(entries)

    output = JsonReporter().render(result, ReportConfig())

    assert '"findings"' in output
    assert '"severity": "HIGH"' in output
    assert '"category": "errors"' in output


def test_csv_contains_findings():
    """CSV output should expose operational findings."""

    entries = [
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.2", "/", 200),
    ]

    result = analyze(entries)

    output = CsvReporter().render(result, ReportConfig())

    assert "finding,HIGH:errors" in output
    assert "finding,MEDIUM:error_path" in output
