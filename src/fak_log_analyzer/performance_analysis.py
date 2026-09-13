"""Performance analysis functionality for FAK Log Analyzer."""

from collections import defaultdict
from collections.abc import Iterable

from fak_log_analyzer.models import LogEntry, PathPerformance, PerformanceStats


def _percentile(values: list[float], percentile: float) -> float:
    """Calculate a percentile using linear interpolation."""

    if not values:
        raise ValueError("Cannot calculate percentile from empty data.")

    if not 0 <= percentile <= 100:
        raise ValueError("Percentile must be between 0 and 100.")

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * (percentile / 100)

    lower_index = int(position)
    upper_index = min(
        lower_index + 1,
        len(ordered) - 1,
    )

    fraction = position - lower_index

    lower_value = ordered[lower_index]
    upper_value = ordered[upper_index]

    return lower_value + ((upper_value - lower_value) * fraction)


def calculate_performance_stats(
    entries: Iterable[LogEntry],
) -> PerformanceStats:
    """Calculate overall response-time statistics."""

    entries = list(entries)

    latency_values = [
        float(entry.response_time_ms)
        for entry in entries
        if entry.response_time_ms is not None
    ]

    requests_with_latency = len(latency_values)

    if not latency_values:
        return PerformanceStats(
            available=False,
            requests_with_latency=0,
            latency_coverage=0.0,
            min_response_time_ms=None,
            max_response_time_ms=None,
            average_response_time_ms=None,
            median_response_time_ms=None,
            p50_response_time_ms=None,
            p90_response_time_ms=None,
            p95_response_time_ms=None,
            p99_response_time_ms=None,
        )

    total_requests = len(entries)

    latency_coverage = (
        (requests_with_latency / total_requests) * 100 if total_requests else 0.0
    )

    average = sum(latency_values) / requests_with_latency

    return PerformanceStats(
        available=True,
        requests_with_latency=requests_with_latency,
        latency_coverage=latency_coverage,
        min_response_time_ms=min(latency_values),
        max_response_time_ms=max(latency_values),
        average_response_time_ms=average,
        median_response_time_ms=_percentile(
            latency_values,
            50,
        ),
        p50_response_time_ms=_percentile(
            latency_values,
            50,
        ),
        p90_response_time_ms=_percentile(
            latency_values,
            90,
        ),
        p95_response_time_ms=_percentile(
            latency_values,
            95,
        ),
        p99_response_time_ms=_percentile(
            latency_values,
            99,
        ),
    )


def calculate_path_performance(
    entries: Iterable[LogEntry],
) -> dict[str, PathPerformance]:
    """Calculate response-time statistics grouped by path."""

    path_values: dict[str, list[float]] = defaultdict(list)

    for entry in entries:
        if entry.response_time_ms is not None:
            path_values[entry.path].append(float(entry.response_time_ms))

    result: dict[str, PathPerformance] = {}

    for path, values in path_values.items():
        result[path] = PathPerformance(
            request_count=len(values),
            average_ms=sum(values) / len(values),
            median_ms=_percentile(values, 50),
            p95_ms=_percentile(values, 95),
            max_ms=max(values),
        )

    return dict(
        sorted(
            result.items(),
            key=lambda item: item[1].p95_ms,
            reverse=True,
        )
    )
