from datetime import datetime

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.findings import Severity, generate_findings
from fak_log_analyzer.models import LogEntry


def make_entry(path: str, latency: float) -> LogEntry:
    return LogEntry(
        ip_address="127.0.0.1",
        timestamp=datetime.fromisoformat("2026-09-13T10:00:00+05:30"),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=200,
        response_size=100,
        response_time_ms=latency,
    )


def test_high_latency_finding():
    entries = [
        make_entry("/api/search", 1200),
        make_entry("/api/search", 1400),
        make_entry("/api/search", 1600),
        make_entry("/api/search", 1800),
    ]

    result = analyze(entries)
    findings = generate_findings(result)

    assert any(
        finding.category == "latency" and finding.severity == Severity.HIGH
        for finding in findings
    )


def test_slow_endpoint_finding():
    entries = [
        make_entry("/api/orders", 600),
        make_entry("/api/orders", 700),
        make_entry("/api/orders", 800),
        make_entry("/api/orders", 900),
    ]

    result = analyze(entries)
    findings = generate_findings(result)

    assert any(
        finding.category == "latency_path" and finding.severity == Severity.MEDIUM
        for finding in findings
    )


def test_very_slow_endpoint_finding():
    entries = [
        make_entry("/api/search", 1200),
        make_entry("/api/search", 1400),
        make_entry("/api/search", 1600),
        make_entry("/api/search", 1800),
    ]

    result = analyze(entries)
    findings = generate_findings(result)

    assert any(
        finding.category == "latency_path" and finding.severity == Severity.HIGH
        for finding in findings
    )


def test_latency_finding_requires_multiple_requests_for_endpoint():
    result = analyze([make_entry("/slow", 2000)])
    findings = generate_findings(result)

    assert not any(finding.category == "latency_path" for finding in findings)
