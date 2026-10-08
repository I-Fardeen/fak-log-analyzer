from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LogEntry:
    """Represent a single parsed log entry."""

    ip_address: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status_code: int
    response_size: int
    response_time_ms: float | None = None


@dataclass
class TimeStats:
    """Represent time-based statistics for analyzed log entries."""

    start_time: datetime | None
    end_time: datetime | None
    duration_seconds: float
    requests_per_minute: float
    requests_per_hour: float


@dataclass
class PathPerformance:
    """Represent performance statistics for a requested path."""

    request_count: int
    average_ms: float
    median_ms: float
    p95_ms: float
    max_ms: float


@dataclass
class PerformanceStats:
    """Represent overall response-time statistics."""

    available: bool
    requests_with_latency: int
    latency_coverage: float
    min_response_time_ms: float | None
    max_response_time_ms: float | None
    average_response_time_ms: float | None
    median_response_time_ms: float | None
    p50_response_time_ms: float | None
    p90_response_time_ms: float | None
    p95_response_time_ms: float | None
    p99_response_time_ms: float | None


@dataclass
class SecurityStats:
    """Represent deterministic security-oriented log statistics."""

    authentication_failures_by_ip: Counter[str] = field(default_factory=Counter)
    authentication_failures_by_path: Counter[str] = field(default_factory=Counter)
    not_found_by_ip: Counter[str] = field(default_factory=Counter)
    unique_not_found_paths_by_ip: dict[str, int] = field(default_factory=dict)
    sensitive_path_counts: Counter[str] = field(default_factory=Counter)
    sensitive_path_ips: Counter[str] = field(default_factory=Counter)
    peak_requests_per_minute_by_ip: dict[str, tuple[datetime, int]] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class StatisticalMetric:
    """Describe the statistical baseline for one analyzed metric."""

    sample_size: int
    mean: float
    median: float
    standard_deviation: float
    q1: float
    q3: float
    iqr: float
    lower_fence: float
    upper_fence: float


@dataclass(frozen=True)
class StatisticalAnomaly:
    """Represent a statistically unusual observation with evidence context."""

    metric: str
    scope: str
    key: str
    observed: float
    baseline: float
    standard_deviation: float
    z_score: float | None
    lower_fence: float
    upper_fence: float
    method: str
    severity: str
    observation_time: datetime | None = None
    path: str | None = None
    ip_address: str | None = None
    status_code: int | None = None


@dataclass
class StatisticalStats:
    """Represent statistical anomaly-analysis results."""

    available: bool
    metrics: dict[str, StatisticalMetric] = field(default_factory=dict)
    anomalies: list[StatisticalAnomaly] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Represent the results of analyzing a collection of log entries."""

    total_requests: int
    method_counts: Counter[str]
    status_counts: Counter[int]
    status_class_counts: Counter[str]
    ip_counts: Counter[str]
    path_counts: Counter[str]
    total_bytes: int
    time_stats: TimeStats
    requests_per_minute: dict[datetime, int]
    malformed_lines: int = 0

    # Operational intelligence
    error_path_counts: Counter[str] = field(default_factory=Counter)
    error_ip_counts: Counter[str] = field(default_factory=Counter)
    error_status_counts: Counter[int] = field(default_factory=Counter)

    # Performance intelligence
    performance_stats: PerformanceStats | None = None
    path_performance: dict[str, PathPerformance] = field(default_factory=dict)

    # Security intelligence
    security_stats: SecurityStats = field(default_factory=SecurityStats)

    # Statistical anomaly intelligence
    statistical_stats: StatisticalStats | None = None

    @property
    def error_count(self) -> int:
        """Return the number of HTTP 4xx and 5xx responses."""
        return sum(
            count for status, count in self.status_counts.items() if status >= 400
        )

    @property
    def error_rate(self) -> float:
        """Return the percentage of requests resulting in an error."""
        if self.total_requests == 0:
            return 0.0

        return (self.error_count / self.total_requests) * 100

    @property
    def average_response_size(self) -> float:
        """Return the average response size in bytes."""
        if self.total_requests == 0:
            return 0.0

        return self.total_bytes / self.total_requests

    @property
    def peak_traffic(self) -> tuple[datetime | None, int]:
        """Return the busiest minute and its request count."""
        if not self.requests_per_minute:
            return None, 0

        timestamp, count = max(
            self.requests_per_minute.items(),
            key=lambda item: item[1],
        )

        return timestamp, count

    @property
    def traffic_trend(self) -> str:
        """Return the overall traffic trend."""
        counts = list(self.requests_per_minute.values())

        if len(counts) < 2:
            return "stable"

        first = counts[0]
        last = counts[-1]

        if last > first:
            return "increasing"

        if last < first:
            return "decreasing"

        return "stable"


@dataclass
class ReportConfig:
    """Configure how analysis results are displayed."""

    top_ips: int = 10
    top_paths: int = 10
