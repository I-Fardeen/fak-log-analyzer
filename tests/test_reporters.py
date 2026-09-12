"""Tests for output reporters."""

import json
from datetime import datetime, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry, ReportConfig
from fak_log_analyzer.reporters import get_reporter
from fak_log_analyzer.reporters.json import JsonReporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


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


def test_json_reporter():
    """JSON reporter should produce valid JSON."""
    result = analyze(
        [
            create_entry("10.0.0.1", "GET", "/", 200, 100),
            create_entry("10.0.0.2", "POST", "/login", 401, 200),
        ]
    )

    reporter = JsonReporter()
    output = reporter.render(result, ReportConfig())

    data = json.loads(output)

    assert data["summary"]["total_requests"] == 2
    assert data["summary"]["error_count"] == 1


def test_reporter_factory():
    """Factory should return the correct reporter."""
    assert isinstance(get_reporter("json"), JsonReporter)
    assert isinstance(get_reporter("terminal"), TerminalReporter)
