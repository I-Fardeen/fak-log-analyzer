"""Statistical anomaly detection for FAK Log Analyzer."""

from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from statistics import mean, median, stdev

from fak_log_analyzer.models import (
    LogEntry,
    StatisticalAnomaly,
    StatisticalMetric,
    StatisticalStats,
)

MIN_SAMPLE_SIZE = 4
MEDIUM_Z_SCORE = 2.0
HIGH_Z_SCORE = 3.0
IQR_MEDIUM_MULTIPLIER = 1.5
IQR_HIGH_MULTIPLIER = 3.0
MAX_ANOMALIES_PER_METRIC = 20


def _percentile(values: list[float], percentile: float) -> float:
    """Return a linearly interpolated percentile."""
    if not values:
        raise ValueError("percentile requires at least one value")

    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _metric(values: list[float]) -> StatisticalMetric | None:
    """Build a statistical baseline when enough observations exist."""
    if len(values) < MIN_SAMPLE_SIZE:
        return None

    q1 = _percentile(values, 0.25)
    q3 = _percentile(values, 0.75)
    iqr = q3 - q1
    deviation = stdev(values) if len(values) >= 2 else 0.0

    return StatisticalMetric(
        sample_size=len(values),
        mean=mean(values),
        median=median(values),
        standard_deviation=deviation,
        q1=q1,
        q3=q3,
        iqr=iqr,
        lower_fence=q1 - IQR_MEDIUM_MULTIPLIER * iqr,
        upper_fence=q3 + IQR_MEDIUM_MULTIPLIER * iqr,
    )


def _classify(
    value: float,
    baseline: StatisticalMetric,
) -> tuple[bool, str, str, float | None]:
    """Determine whether a value is anomalous and explain the method."""
    z_score = None
    z_medium = False
    z_high = False

    if baseline.standard_deviation > 0:
        z_score = (value - baseline.mean) / baseline.standard_deviation
        z_medium = abs(z_score) >= MEDIUM_Z_SCORE
        z_high = abs(z_score) >= HIGH_Z_SCORE

    if baseline.iqr == 0:
        iqr_medium = value != baseline.q1
        iqr_high = iqr_medium
    else:
        iqr_medium = value < baseline.lower_fence or value > baseline.upper_fence
        high_lower = baseline.q1 - IQR_HIGH_MULTIPLIER * baseline.iqr
        high_upper = baseline.q3 + IQR_HIGH_MULTIPLIER * baseline.iqr
        iqr_high = value < high_lower or value > high_upper

    if not (z_medium or iqr_medium):
        return False, "", "", z_score

    high = z_high or iqr_high
    if z_medium and iqr_medium:
        method = "z-score+IQR"
    elif z_medium:
        method = "z-score"
    else:
        method = "IQR"

    severity = "HIGH" if high else "MEDIUM"
    return True, method, severity, z_score


def _add_anomalies(
    anomalies: list[StatisticalAnomaly],
    metric_name: str,
    scope: str,
    observations: list[tuple[str, float]],
    baseline: StatisticalMetric | None,
) -> None:
    """Append statistically unusual observations for one metric."""
    if baseline is None:
        return

    candidates: list[StatisticalAnomaly] = []
    for key, value in observations:
        is_anomaly, method, severity, z_score = _classify(value, baseline)
        if not is_anomaly:
            continue

        observation_time = None
        if scope == "time":
            try:
                observation_time = datetime.fromisoformat(key)
            except ValueError:
                observation_time = None

        candidates.append(
            StatisticalAnomaly(
                metric=metric_name,
                scope=scope,
                key=key,
                observed=value,
                baseline=baseline.mean,
                standard_deviation=baseline.standard_deviation,
                z_score=z_score,
                lower_fence=baseline.lower_fence,
                upper_fence=baseline.upper_fence,
                method=method,
                severity=severity,
                observation_time=observation_time,
            )
        )

    severity_rank = {"HIGH": 0, "MEDIUM": 1}
    candidates.sort(
        key=lambda item: (
            severity_rank[item.severity],
            -(abs(item.z_score) if item.z_score is not None else 0.0),
            -abs(item.observed - item.baseline),
        )
    )
    anomalies.extend(candidates[:MAX_ANOMALIES_PER_METRIC])


def calculate_statistical_stats(entries: Iterable[LogEntry]) -> StatisticalStats:
    """Calculate deterministic statistical anomalies from parsed log entries."""
    entries = list(entries)
    if len(entries) < MIN_SAMPLE_SIZE:
        return StatisticalStats(available=False)

    minute_total: Counter = Counter()
    minute_errors: Counter = Counter()
    ip_counts: Counter[str] = Counter()
    path_counts: Counter[str] = Counter()
    latency_values: list[float] = []
    latency_observations: list[tuple[str, float, datetime, str, str, int]] = []

    for entry in entries:
        minute = entry.timestamp.replace(second=0, microsecond=0)
        minute_total[minute] += 1
        if entry.status_code >= 400:
            minute_errors[minute] += 1

        ip_counts[entry.ip_address] += 1
        path_counts[entry.path] += 1

        if entry.response_time_ms is not None:
            latency_values.append(entry.response_time_ms)
            latency_observations.append(
                (
                    entry.timestamp.isoformat(),
                    entry.response_time_ms,
                    entry.timestamp,
                    entry.path,
                    entry.ip_address,
                    entry.status_code,
                )
            )

    traffic_observations = [
        (timestamp.isoformat(), float(count))
        for timestamp, count in sorted(minute_total.items())
    ]

    error_rate_observations = [
        (
            timestamp.isoformat(),
            (minute_errors[timestamp] / count) * 100,
        )
        for timestamp, count in sorted(minute_total.items())
        if count > 0
    ]

    ip_observations = [(ip, float(count)) for ip, count in ip_counts.items()]
    path_observations = [(path, float(count)) for path, count in path_counts.items()]

    metrics: dict[str, StatisticalMetric] = {}
    anomalies: list[StatisticalAnomaly] = []

    metric_inputs = {
        "requests_per_minute": traffic_observations,
        "error_rate_per_minute": error_rate_observations,
        "requests_per_ip": ip_observations,
        "requests_per_path": path_observations,
    }

    for name, observations in metric_inputs.items():
        baseline = _metric([value for _, value in observations])
        if baseline is not None:
            metrics[name] = baseline
            scope = (
                "time"
                if name.endswith("per_minute")
                else "ip"
                if name.endswith("per_ip")
                else "path"
            )
            _add_anomalies(anomalies, name, scope, observations, baseline)

    latency_baseline = _metric(latency_values)
    if latency_baseline is not None:
        metrics["response_time_ms"] = latency_baseline
        latency_candidates: list[StatisticalAnomaly] = []
        for (
            key,
            value,
            timestamp,
            path,
            ip_address,
            status_code,
        ) in latency_observations:
            is_anomaly, method, severity, z_score = _classify(value, latency_baseline)
            if not is_anomaly:
                continue

            latency_candidates.append(
                StatisticalAnomaly(
                    metric="response_time_ms",
                    scope="request",
                    key=key,
                    observed=value,
                    baseline=latency_baseline.mean,
                    standard_deviation=latency_baseline.standard_deviation,
                    z_score=z_score,
                    lower_fence=latency_baseline.lower_fence,
                    upper_fence=latency_baseline.upper_fence,
                    method=method,
                    severity=severity,
                    observation_time=timestamp,
                    path=path,
                    ip_address=ip_address,
                    status_code=status_code,
                )
            )

        severity_rank = {"HIGH": 0, "MEDIUM": 1}
        latency_candidates.sort(
            key=lambda item: (
                severity_rank[item.severity],
                -(abs(item.z_score) if item.z_score is not None else 0.0),
                -abs(item.observed - item.baseline),
            )
        )
        anomalies.extend(latency_candidates[:MAX_ANOMALIES_PER_METRIC])

    anomalies.sort(
        key=lambda item: (
            0 if item.severity == "HIGH" else 1,
            item.metric,
            -(abs(item.z_score) if item.z_score is not None else 0.0),
        )
    )

    return StatisticalStats(
        available=bool(metrics),
        metrics=metrics,
        anomalies=anomalies,
    )
