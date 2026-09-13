"""Data models used by FAK Log Analyzer."""

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


@dataclass
class TimeStats:
    """Represent time-based statistics for analyzed log entries."""

    start_time: datetime | None
    end_time: datetime | None
    duration_seconds: float
    requests_per_minute: float
    requests_per_hour: float


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
