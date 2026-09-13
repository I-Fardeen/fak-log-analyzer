from datetime import datetime

from fak_log_analyzer.models import LogEntry
from fak_log_analyzer.performance_analysis import (
    calculate_path_performance,
    calculate_performance_stats,
)


def make_entry(path: str, latency: float | None) -> LogEntry:
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


def test_performance_without_latency_data():
    result = calculate_performance_stats(
        [
            make_entry("/", None),
            make_entry("/api/users", None),
        ]
    )

    assert result.available is False
    assert result.requests_with_latency == 0
    assert result.latency_coverage == 0.0
    assert result.p95_response_time_ms is None


def test_performance_with_complete_latency_data():
    result = calculate_performance_stats(
        [
            make_entry("/", 100),
            make_entry("/", 200),
            make_entry("/", 300),
            make_entry("/", 400),
            make_entry("/", 500),
        ]
    )

    assert result.available is True
    assert result.requests_with_latency == 5
    assert result.latency_coverage == 100.0
    assert result.min_response_time_ms == 100
    assert result.max_response_time_ms == 500
    assert result.average_response_time_ms == 300
    assert result.median_response_time_ms == 300
    assert result.p50_response_time_ms == 300
    assert result.p90_response_time_ms == 460
    assert result.p95_response_time_ms == 480
    assert result.p99_response_time_ms == 496


def test_performance_with_partial_latency_data():
    result = calculate_performance_stats(
        [
            make_entry("/", 100),
            make_entry("/", None),
            make_entry("/", 300),
            make_entry("/", None),
        ]
    )

    assert result.available is True
    assert result.requests_with_latency == 2
    assert result.latency_coverage == 50.0
    assert result.average_response_time_ms == 200


def test_single_latency_value():
    result = calculate_performance_stats([make_entry("/", 250)])

    assert result.p50_response_time_ms == 250
    assert result.p95_response_time_ms == 250
    assert result.p99_response_time_ms == 250


def test_path_performance():
    result = calculate_path_performance(
        [
            make_entry("/fast", 100),
            make_entry("/fast", 200),
            make_entry("/slow", 800),
            make_entry("/slow", 1200),
        ]
    )

    assert result["/fast"].request_count == 2
    assert result["/fast"].average_ms == 150
    assert result["/slow"].request_count == 2
    assert result["/slow"].average_ms == 1000
    assert result["/slow"].p95_ms == 1180


def test_path_performance_ignores_missing_latency():
    result = calculate_path_performance(
        [
            make_entry("/api/users", 100),
            make_entry("/api/users", None),
            make_entry("/api/users", 200),
        ]
    )

    assert result["/api/users"].request_count == 2
    assert result["/api/users"].average_ms == 150


def test_path_performance_is_sorted_by_p95():
    result = calculate_path_performance(
        [
            make_entry("/fast", 100),
            make_entry("/fast", 200),
            make_entry("/slow", 800),
            make_entry("/slow", 1200),
        ]
    )

    assert list(result.keys()) == ["/slow", "/fast"]
