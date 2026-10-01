"""Tests for security findings."""

from datetime import datetime, timedelta, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.findings import Severity, generate_findings
from fak_log_analyzer.models import LogEntry


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


def test_repeated_authentication_failures_medium():
    """Five authentication failures should produce a MEDIUM finding."""

    entries = [make_entry("10.0.0.1", "/login", 401) for _ in range(5)]

    findings = generate_findings(analyze(entries))

    matches = [
        finding for finding in findings if finding.category == "security_authentication"
    ]

    assert len(matches) == 1
    assert matches[0].severity == Severity.MEDIUM
    assert "5 HTTP 401" in matches[0].message


def test_repeated_authentication_failures_high():
    """Twenty authentication failures should produce a HIGH finding."""

    entries = [make_entry("10.0.0.1", "/login", 401) for _ in range(20)]

    findings = generate_findings(analyze(entries))

    matches = [
        finding for finding in findings if finding.category == "security_authentication"
    ]

    assert len(matches) == 1
    assert matches[0].severity == Severity.HIGH


def test_path_enumeration_requires_distinct_paths():
    """404 volume alone should not trigger enumeration without diversity."""

    entries = [make_entry("10.0.0.1", "/missing", 404) for _ in range(12)]

    findings = generate_findings(analyze(entries))

    assert not any(finding.category == "security_enumeration" for finding in findings)


def test_path_enumeration_finding():
    """Many distinct 404 paths should produce an enumeration finding."""

    entries = [make_entry("10.0.0.1", f"/missing-{index}", 404) for index in range(10)]

    findings = generate_findings(analyze(entries))

    matches = [
        finding for finding in findings if finding.category == "security_enumeration"
    ]

    assert len(matches) == 1
    assert matches[0].severity == Severity.MEDIUM
    assert "10 HTTP 404" in matches[0].message


def test_sensitive_path_finding():
    """Configured sensitive paths should generate security findings."""

    entries = [
        make_entry("10.0.0.1", "/.env"),
        make_entry("10.0.0.1", "/.env"),
        make_entry("10.0.0.1", "/.env"),
    ]

    findings = generate_findings(analyze(entries))

    matches = [
        finding for finding in findings if finding.category == "security_sensitive_path"
    ]

    assert len(matches) == 1
    assert matches[0].severity == Severity.HIGH


def test_request_burst_finding():
    """A large one-minute request burst should generate a HIGH finding."""

    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = [
        make_entry(
            "10.0.0.1",
            "/api",
            timestamp=start + timedelta(seconds=index % 60),
        )
        for index in range(120)
    ]

    findings = generate_findings(analyze(entries))

    matches = [
        finding for finding in findings if finding.category == "security_request_burst"
    ]

    assert len(matches) == 1
    assert matches[0].severity == Severity.HIGH


def test_normal_traffic_has_no_security_finding():
    """Normal low-volume traffic should not trigger security heuristics."""

    entries = [
        make_entry("10.0.0.1", "/", 200),
        make_entry("10.0.0.2", "/about", 200),
    ]

    findings = generate_findings(analyze(entries))

    assert not any(finding.category.startswith("security_") for finding in findings)
