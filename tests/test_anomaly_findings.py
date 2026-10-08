"""Tests for statistical anomaly findings and reporter integration."""

from datetime import datetime, timedelta, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.findings import Severity, generate_findings
from fak_log_analyzer.models import LogEntry


def make_entry(
    ip: str,
    timestamp: datetime,
    status: int = 200,
    response_time: float | None = None,
) -> LogEntry:
    return LogEntry(
        ip_address=ip,
        timestamp=timestamp,
        method="GET",
        path="/api",
        protocol="HTTP/1.1",
        status_code=status,
        response_size=100,
        response_time_ms=response_time,
    )


def test_statistical_anomaly_finding_contains_evidence():
    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = []

    for minute in range(6):
        count = 5 if minute < 5 else 40
        for request in range(count):
            entries.append(
                make_entry(
                    f"10.0.0.{request + 1}",
                    start + timedelta(minutes=minute, seconds=request % 50),
                )
            )

    findings = generate_findings(analyze(entries))
    matches = [
        finding for finding in findings if finding.category == "statistical_anomaly"
    ]

    assert matches
    assert any(
        finding.severity in {Severity.HIGH, Severity.MEDIUM} for finding in matches
    )
    assert any("baseline mean" in finding.message for finding in matches)
    assert any("method:" in finding.message for finding in matches)


def test_latency_statistical_finding_uses_timestamp_and_context():
    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = [
        make_entry(
            f"10.0.0.{index}",
            start + timedelta(seconds=index),
            response_time=100,
        )
        for index in range(8)
    ]
    anomaly_time = start + timedelta(minutes=1)
    entries.append(
        make_entry(
            "10.0.0.99",
            anomaly_time,
            status=503,
            response_time=1000,
        )
    )

    findings = generate_findings(analyze(entries))
    matches = [
        finding
        for finding in findings
        if finding.category == "statistical_anomaly" and "1000.00" in finding.message
    ]

    assert matches
    assert anomaly_time.isoformat() in matches[0].message
    assert "path /api" in matches[0].message
    assert "IP 10.0.0.99" in matches[0].message
    assert "status 503" in matches[0].message
