from fak_log_analyzer.parser import parse_line


def test_parse_extended_log_with_integer_response_time():
    line = (
        "192.168.1.10 - - [13/Sep/2026:10:15:01 +0530] "
        '"GET /api/users HTTP/1.1" 200 2048 125'
    )

    result = parse_line(line)

    assert result is not None
    assert result.response_time_ms == 125.0


def test_parse_extended_log_with_decimal_response_time():
    line = (
        "192.168.1.10 - - [13/Sep/2026:10:15:01 +0530] "
        '"GET /api/users HTTP/1.1" 200 2048 125.5'
    )

    result = parse_line(line)

    assert result is not None
    assert result.response_time_ms == 125.5


def test_parse_standard_clf_without_response_time():
    line = (
        "192.168.1.10 - - [13/Sep/2026:10:15:01 +0530] "
        '"GET /api/users HTTP/1.1" 200 2048'
    )

    result = parse_line(line)

    assert result is not None
    assert result.response_time_ms is None


def test_invalid_response_time_makes_line_malformed():
    line = (
        "192.168.1.10 - - [13/Sep/2026:10:15:01 +0530] "
        '"GET /api/users HTTP/1.1" 200 2048 abc'
    )

    result = parse_line(line)

    assert result is None
