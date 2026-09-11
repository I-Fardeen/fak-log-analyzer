"""Tests for the log parser."""

from fak_log_analyzer.parser import parse_file, parse_line


def test_parse_valid_log_line():
    """A valid log line should produce a LogEntry."""
    line = (
        "192.168.1.10 - - [11/Sep/2026:10:15:32 +0530] "
        '"GET /index.html HTTP/1.1" 200 1532'
    )

    entry = parse_line(line)

    assert entry is not None
    assert entry.ip_address == "192.168.1.10"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status_code == 200
    assert entry.response_size == 1532


def test_parse_invalid_log_line():
    """An invalid log line should return None."""
    entry = parse_line("this is not a valid log line")

    assert entry is None


def test_parse_file_counts_malformed_lines(tmp_path):
    """Parser should count malformed lines in a file."""
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "192.168.1.10 - - [11/Sep/2026:10:15:32 +0530] "
        '"GET /index.html HTTP/1.1" 200 1532\n'
        "this is malformed\n",
        encoding="utf-8",
    )

    entries, malformed_lines = parse_file(str(log_file))

    assert len(entries) == 1
    assert malformed_lines == 1
