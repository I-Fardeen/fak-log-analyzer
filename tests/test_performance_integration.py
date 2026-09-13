"""Integration and edge-case tests for v0.5 performance intelligence."""

import json
from datetime import datetime

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.findings import Severity, generate_findings
from fak_log_analyzer.models import LogEntry, ReportConfig
from fak_log_analyzer.parser import parse_line
from fak_log_analyzer.reporters.csv import CsvReporter
from fak_log_analyzer.reporters.json import JsonReporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


def make_entry(
    path: str,
    latency: float | None,
    status_code: int = 200,
) -> LogEntry:
    """Create a test log entry."""

    return LogEntry(
        ip_address="127.0.0.1",
        timestamp=datetime.fromisoformat("2026-09-13T10:00:00+05:30"),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status_code,
        response_size=100,
        response_time_ms=latency,
    )


def make_config() -> ReportConfig:
    """Create a standard report configuration."""

    return ReportConfig(
        top_ips=5,
        top_paths=5,
    )


def test_500ms_latency_is_medium():
    """Exactly 500 ms should trigger a MEDIUM latency finding."""

    entries = [
        make_entry("/slow", 500),
        make_entry("/slow", 500),
    ]

    result = analyze(entries)
    findings = generate_findings(result)

    assert any(
        finding.category == "latency" and finding.severity == Severity.MEDIUM
        for finding in findings
    )


def test_1000ms_latency_is_high():
    """Exactly 1000 ms should trigger a HIGH latency finding."""

    entries = [
        make_entry("/slow", 1000),
        make_entry("/slow", 1000),
    ]

    result = analyze(entries)
    findings = generate_findings(result)

    assert any(
        finding.category == "latency" and finding.severity == Severity.HIGH
        for finding in findings
    )


def test_499ms_latency_has_no_latency_finding():
    """Latency below 500 ms should not trigger a latency finding."""

    entries = [
        make_entry("/fast", 499),
        make_entry("/fast", 499),
    ]

    result = analyze(entries)
    findings = generate_findings(result)

    assert not any(finding.category == "latency" for finding in findings)


def test_no_latency_data_is_unavailable():
    """Logs without latency data should report unavailable performance."""

    entries = [
        make_entry("/api/users", None),
        make_entry("/api/orders", None),
    ]

    result = analyze(entries)

    assert result.performance_stats is not None
    assert result.performance_stats.available is False
    assert result.performance_stats.requests_with_latency == 0
    assert result.performance_stats.latency_coverage == 0.0
    assert result.performance_stats.p95_response_time_ms is None


def test_partial_latency_coverage():
    """Partial latency data should report accurate coverage."""

    entries = [
        make_entry("/api/users", 100),
        make_entry("/api/users", None),
        make_entry("/api/orders", 200),
        make_entry("/api/orders", None),
    ]

    result = analyze(entries)

    assert result.performance_stats is not None
    assert result.performance_stats.available is True
    assert result.performance_stats.requests_with_latency == 2
    assert result.performance_stats.latency_coverage == 50.0


def test_standard_clf_entries_have_no_latency():
    """Standard CLF entries should remain compatible with v0.5."""

    line = (
        '127.0.0.1 - - [13/Sep/2026:10:15:01 +0530] "GET /api/users HTTP/1.1" 200 1234'
    )

    entry = parse_line(line)

    assert entry is not None
    assert entry.response_time_ms is None


def test_json_report_contains_performance_data():
    """JSON reporting should expose v0.5 performance metrics."""

    entries = [
        make_entry("/api/search", 100),
        make_entry("/api/search", 200),
        make_entry("/api/search", 300),
    ]

    result = analyze(entries)

    reporter = JsonReporter()
    output = reporter.render(result, make_config())

    data = json.loads(output)

    assert "performance" in data
    assert data["performance"]["available"] is True
    assert data["performance"]["requests_with_latency"] == 3
    assert data["performance"]["p95_response_time_ms"] == 290.0

    assert "performance_hotspots" in data
    assert "/api/search" in data["performance_hotspots"]


def test_csv_report_contains_performance_data():
    """CSV reporting should expose performance records."""

    entries = [
        make_entry("/api/search", 100),
        make_entry("/api/search", 200),
        make_entry("/api/search", 300),
    ]

    result = analyze(entries)

    reporter = CsvReporter()
    output = reporter.render(result, make_config())

    assert "performance" in output
    assert "latency_path" in output
    assert "/api/search" in output


def test_terminal_report_contains_performance_sections(capsys):
    """Terminal display should include performance sections."""

    entries = [
        make_entry("/api/search", 1200),
        make_entry("/api/search", 1400),
        make_entry("/api/search", 1600),
    ]

    result = analyze(entries)

    reporter = TerminalReporter()
    reporter.display(result, make_config())

    captured = capsys.readouterr()

    assert "Performance Analysis" in captured.out
    assert "Performance Hotspots" in captured.out
    assert "/api/search" in captured.out
