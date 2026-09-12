"""Tests for JSON reporting."""

import json
from datetime import datetime, timedelta, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry, ReportConfig
from fak_log_analyzer.reporters.json import JsonReporter


def create_entry(
    ip: str,
    method: str,
    path: str,
    status: int,
    size: int,
    timestamp: datetime,
) -> LogEntry:
    """Create a test log entry."""
    return LogEntry(
        ip_address=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=size,
    )


def test_json_report():
    """JSON reporter should produce valid JSON."""
    start = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)

    result = analyze(
        [
            create_entry(
                "10.0.0.1",
                "GET",
                "/",
                200,
                100,
                start,
            ),
            create_entry(
                "10.0.0.2",
                "POST",
                "/login",
                401,
                200,
                start + timedelta(minutes=1),
            ),
        ]
    )

    output = JsonReporter().render(result, ReportConfig())
    data = json.loads(output)

    assert data["summary"]["total_requests"] == 2
    assert data["summary"]["error_count"] == 1
    assert data["summary"]["error_rate"] == 50.0

    assert data["time"]["start_time"] == "2026-09-11T10:00:00+00:00"
    assert data["time"]["end_time"] == "2026-09-11T10:01:00+00:00"
    assert data["time"]["duration_seconds"] == 60.0
    assert data["time"]["requests_per_minute"] == 2.0
    assert data["time"]["requests_per_hour"] == 120.0
    assert data["traffic"]["requests_per_minute"] == {
        "2026-09-11T10:00:00+00:00": 1,
        "2026-09-11T10:01:00+00:00": 1,
    }
    assert data["traffic"]["peak"]["timestamp"] == ("2026-09-11T10:00:00+00:00")
    assert data["traffic"]["peak"]["requests"] == 1
    assert data["traffic"]["trend"] == "stable"
