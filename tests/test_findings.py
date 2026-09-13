"""Tests for automated operational findings."""

from datetime import datetime, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.findings import Severity, generate_findings
from fak_log_analyzer.models import LogEntry


def create_entry(
    ip: str,
    path: str,
    status: int,
) -> LogEntry:
    """Create a test log entry."""
    return LogEntry(
        ip_address=ip,
        timestamp=datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=100,
    )


def test_high_error_rate_finding():
    """A very high error rate should generate a HIGH finding."""

    entries = [
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.2", "/api", 500),
        create_entry("10.0.0.3", "/api", 404),
        create_entry("10.0.0.4", "/", 200),
    ]

    findings = generate_findings(analyze(entries))

    assert findings[0].severity == Severity.HIGH
    assert findings[0].category == "errors"
    assert "75.00%" in findings[0].message


def test_medium_error_rate_finding():
    """An elevated error rate should generate a MEDIUM finding."""

    entries = [
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.2", "/", 200),
        create_entry("10.0.0.3", "/", 200),
        create_entry("10.0.0.4", "/", 200),
        create_entry("10.0.0.5", "/", 200),
    ]

    findings = generate_findings(analyze(entries))

    error_findings = [finding for finding in findings if finding.category == "errors"]

    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.MEDIUM
    assert "20.00%" in error_findings[0].message


def test_server_error_finding():
    """5xx responses should generate a server error finding."""

    entries = [
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.2", "/api", 500),
        create_entry("10.0.0.3", "/", 200),
        create_entry("10.0.0.4", "/", 200),
        create_entry("10.0.0.5", "/", 200),
    ]

    findings = generate_findings(analyze(entries))

    server_findings = [
        finding for finding in findings if finding.category == "server_errors"
    ]

    assert len(server_findings) == 1
    assert server_findings[0].severity == Severity.HIGH
    assert "2 request(s) returned 5xx responses" in server_findings[0].message


def test_error_path_hotspot():
    """Repeated errors on one path should generate a hotspot finding."""

    entries = [
        create_entry("10.0.0.1", "/api/users", 500),
        create_entry("10.0.0.2", "/api/users", 500),
        create_entry("10.0.0.3", "/api/users", 500),
        create_entry("10.0.0.4", "/", 200),
    ]

    findings = generate_findings(analyze(entries))

    path_findings = [
        finding for finding in findings if finding.category == "error_path"
    ]

    assert len(path_findings) == 1
    assert path_findings[0].severity == Severity.MEDIUM
    assert "/api/users generated 3 HTTP errors." in path_findings[0].message


def test_error_ip_hotspot():
    """Repeated errors from one IP should generate a client finding."""

    entries = [
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.1", "/login", 401),
        create_entry("10.0.0.1", "/admin", 403),
        create_entry("10.0.0.2", "/", 200),
    ]

    findings = generate_findings(analyze(entries))

    ip_findings = [finding for finding in findings if finding.category == "error_ip"]

    assert len(ip_findings) == 1
    assert ip_findings[0].severity == Severity.MEDIUM
    assert "10.0.0.1 generated 3 HTTP errors." in ip_findings[0].message


def test_no_errors_generates_info_finding():
    """A clean log should explicitly report the absence of errors."""

    entries = [
        create_entry("10.0.0.1", "/", 200),
        create_entry("10.0.0.2", "/about", 200),
    ]

    findings = generate_findings(analyze(entries))

    error_findings = [finding for finding in findings if finding.category == "errors"]

    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.INFO
    assert error_findings[0].title == "No HTTP errors detected"
    assert "successful or non-error responses" in error_findings[0].message


def test_empty_log_generates_info_finding():
    """An empty log should generate an informational finding."""

    findings = generate_findings(analyze([]))

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].category == "traffic"
    assert findings[0].title == "No requests analyzed"


def test_findings_are_sorted_by_severity():
    """Findings should be ordered from highest to lowest severity."""

    entries = [
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.1", "/api", 500),
        create_entry("10.0.0.2", "/", 200),
    ]

    findings = generate_findings(analyze(entries))

    severities = [finding.severity for finding in findings]

    severity_order = {
        Severity.HIGH: 0,
        Severity.MEDIUM: 1,
        Severity.LOW: 2,
        Severity.INFO: 3,
    }

    numeric_order = [severity_order[severity] for severity in severities]

    assert numeric_order == sorted(numeric_order)
