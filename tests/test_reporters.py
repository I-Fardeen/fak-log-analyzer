"""Tests for output reporters."""

import json
from datetime import datetime, timedelta, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry, ReportConfig
from fak_log_analyzer.reporters import get_reporter
from fak_log_analyzer.reporters.csv import CsvReporter
from fak_log_analyzer.reporters.json import JsonReporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


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
        timestamp = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)

    return LogEntry(
        ip_address=ip,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=size,
    )


def test_json_reporter():
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

    reporter = JsonReporter()
    output = reporter.render(result, ReportConfig())

    data = json.loads(output)

    assert data["summary"]["total_requests"] == 2
    assert data["summary"]["error_count"] == 1
    assert data["time"]["duration_seconds"] == 60.0
    assert data["time"]["requests_per_minute"] == 2.0
    assert data["time"]["requests_per_hour"] == 120.0
    assert data["status_classes"]["2xx"] == 1
    assert data["status_classes"]["4xx"] == 1


def test_csv_reporter():
    """CSV reporter should produce CSV output."""
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

    reporter = CsvReporter()
    output = reporter.render(result, ReportConfig())

    assert "category,name,value" in output
    assert "summary,total_requests,2" in output
    assert "method,GET,1" in output
    assert "status,200,1" in output
    assert "time,start_time,2026-09-11T10:00:00+00:00" in output
    assert "time,end_time,2026-09-11T10:01:00+00:00" in output
    assert "time,duration_seconds,60.0" in output
    assert "time,requests_per_minute,2.0" in output
    assert "time,requests_per_hour,120.0" in output
    assert "traffic,2026-09-11T10:00:00+00:00,1" in output
    assert "traffic,2026-09-11T10:01:00+00:00,1" in output
    assert "traffic_peak,timestamp,2026-09-11T10:00:00+00:00" in output
    assert "traffic_peak,requests,1" in output
    assert "traffic,trend,stable" in output
    assert "status_class,2xx,1" in output
    assert "status_class,4xx,1" in output


def test_reporter_factory():
    """Factory should return the correct reporter."""
    assert isinstance(get_reporter("json"), JsonReporter)
    assert isinstance(get_reporter("csv"), CsvReporter)
    assert isinstance(get_reporter("terminal"), TerminalReporter)
