"""Tests for statistical anomaly analysis."""

from datetime import datetime, timedelta, timezone

from fak_log_analyzer.models import LogEntry
from fak_log_analyzer.statistical_analysis import (
    MIN_SAMPLE_SIZE,
    calculate_statistical_stats,
)


def make_entry(
    ip: str,
    path: str = "/",
    status: int = 200,
    timestamp: datetime | None = None,
    response_time: float | None = None,
) -> LogEntry:
    return LogEntry(
        ip_address=ip,
        timestamp=timestamp or datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=100,
        response_time_ms=response_time,
    )


def test_small_input_does_not_produce_statistical_baseline():
    entries = [make_entry(f"10.0.0.{index}") for index in range(MIN_SAMPLE_SIZE - 1)]

    stats = calculate_statistical_stats(entries)

    assert stats.available is False
    assert stats.metrics == {}
    assert stats.anomalies == []


def test_requests_per_ip_detects_outlier_with_iqr():
    entries = []
    for index in range(6):
        entries.append(make_entry("10.0.0.1"))
        entries.append(make_entry(f"10.0.0.{index + 2}"))

    for _ in range(12):
        entries.append(make_entry("10.0.0.99"))

    stats = calculate_statistical_stats(entries)

    assert stats.available is True
    assert "requests_per_ip" in stats.metrics
    matches = [
        anomaly
        for anomaly in stats.anomalies
        if anomaly.metric == "requests_per_ip" and anomaly.key == "10.0.0.99"
    ]
    assert matches
    assert matches[0].method in {"IQR", "z-score+IQR"}
    assert matches[0].severity == "HIGH"


def test_error_rate_per_minute_detects_outlier():
    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = []

    for minute in range(6):
        for request in range(10):
            entries.append(
                make_entry(
                    f"10.0.0.{request + 1}",
                    timestamp=start + timedelta(minutes=minute, seconds=request),
                )
            )

    for request in range(10):
        entries.append(
            make_entry(
                f"10.0.1.{request + 1}",
                status=500,
                timestamp=start + timedelta(minutes=6, seconds=request),
            )
        )

    stats = calculate_statistical_stats(entries)

    matches = [
        anomaly
        for anomaly in stats.anomalies
        if anomaly.metric == "error_rate_per_minute"
        and anomaly.key.startswith("2026-09-13T10:06")
    ]
    assert matches
    assert matches[0].observed == 100.0
    assert matches[0].severity == "HIGH"


def test_latency_outlier_is_detected():
    entries = [
        make_entry(
            "10.0.0.1",
            response_time=100,
            timestamp=datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
            + timedelta(seconds=index),
        )
        for index in range(8)
    ]
    entries.append(
        make_entry(
            "10.0.0.9",
            response_time=1000,
            timestamp=datetime(2026, 9, 13, 10, 1, tzinfo=timezone.utc),
        )
    )

    stats = calculate_statistical_stats(entries)

    matches = [
        anomaly
        for anomaly in stats.anomalies
        if anomaly.metric == "response_time_ms" and anomaly.observed == 1000
    ]
    assert matches
    assert matches[0].severity == "HIGH"


def test_uniform_distribution_has_no_anomalies():
    entries = [
        make_entry(
            f"10.0.0.{index}",
            timestamp=datetime(2026, 9, 13, 10, index, tzinfo=timezone.utc),
            response_time=100,
        )
        for index in range(1, 7)
    ]

    stats = calculate_statistical_stats(entries)

    assert stats.available is True
    assert stats.anomalies == []


def test_latency_anomaly_preserves_request_context():
    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = [
        make_entry(
            f"10.0.0.{index}",
            path="/api/normal",
            timestamp=start + timedelta(seconds=index),
            response_time=100,
        )
        for index in range(8)
    ]
    anomaly_time = start + timedelta(minutes=1, seconds=5)
    entries.append(
        make_entry(
            "10.0.0.99",
            path="/api/slow",
            status=503,
            timestamp=anomaly_time,
            response_time=1000,
        )
    )

    stats = calculate_statistical_stats(entries)
    matches = [
        anomaly
        for anomaly in stats.anomalies
        if anomaly.metric == "response_time_ms" and anomaly.observed == 1000
    ]

    assert matches
    anomaly = matches[0]
    assert anomaly.key == anomaly_time.isoformat()
    assert anomaly.observation_time == anomaly_time
    assert anomaly.path == "/api/slow"
    assert anomaly.ip_address == "10.0.0.99"
    assert anomaly.status_code == 503
    assert anomaly.observed == 1000
    assert anomaly.baseline < anomaly.observed
    assert anomaly.z_score is not None
    assert anomaly.z_score > 0


def test_time_anomalies_use_timestamp_as_observation_reference():
    start = datetime(2026, 9, 13, 10, 0, tzinfo=timezone.utc)
    entries = []

    for minute in range(6):
        count = 5 if minute < 5 else 40
        for request in range(count):
            entries.append(
                make_entry(
                    f"10.0.0.{request + 1}",
                    timestamp=start + timedelta(minutes=minute, seconds=request),
                )
            )

    stats = calculate_statistical_stats(entries)
    matches = [
        anomaly
        for anomaly in stats.anomalies
        if anomaly.metric == "requests_per_minute"
        and anomaly.observation_time == start + timedelta(minutes=5)
    ]

    assert matches
    assert matches[0].key == (start + timedelta(minutes=5)).isoformat()
