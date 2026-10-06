"""Integration tests for v0.6 security intelligence."""

import json
from datetime import datetime, timezone

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import LogEntry, ReportConfig
from fak_log_analyzer.reporters.csv import CsvReporter
from fak_log_analyzer.reporters.json import JsonReporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


def make_entry(ip: str, path: str, status: int = 200) -> LogEntry:
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


def make_config() -> ReportConfig:
    """Create a standard report configuration."""

    return ReportConfig(top_ips=5, top_paths=5)


def test_json_contains_security_section():
    """JSON output should expose security intelligence."""

    entries = [
        make_entry("10.0.0.1", "/.env", 404),
        make_entry("10.0.0.1", "/login", 401),
    ]

    output = JsonReporter().render(analyze(entries), make_config())
    data = json.loads(output)

    assert "security" in data
    assert "authentication_failures" in data["security"]
    assert "sensitive_paths" in data["security"]


def test_csv_contains_security_rows():
    """CSV output should expose security intelligence."""

    entries = [
        make_entry("10.0.0.1", "/.env", 404),
        make_entry("10.0.0.1", "/login", 401),
    ]

    output = CsvReporter().render(analyze(entries), make_config())

    assert "security_auth_ip" in output
    assert "security_sensitive_path" in output


def test_terminal_render_contract_is_preserved():
    """Terminal render should remain non-printing."""

    entries = [make_entry("10.0.0.1", "/.env", 404)]

    assert TerminalReporter().render(analyze(entries), make_config()) == ""
