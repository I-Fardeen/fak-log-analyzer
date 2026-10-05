from fak_log_analyzer.parser import parse_line


def test_parse_valid_log_line():
    """Test that a standard log line parses into correct LogEntry attributes."""
    log_line = (
        '192.168.1.50 - - [04/Oct/2026:17:00:00 +0000] '
        '"GET /login HTTP/1.1" 200 512'
    )
    parsed = parse_line(log_line)

    assert parsed is not None
    assert parsed.ip_address == "192.168.1.50"
    assert parsed.method == "GET"
    assert parsed.path == "/login"
    assert parsed.status_code == 200
    assert parsed.response_size == 512
