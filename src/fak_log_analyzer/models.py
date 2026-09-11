"""Data models used by FAK Log Analyzer."""

from collections import Counter
from dataclasses import dataclass
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
class AnalysisResult:
    """Represent the results of analyzing a collection of log entries."""

    total_requests: int
    method_counts: Counter[str]
    status_counts: Counter[int]
    ip_counts: Counter[str]
    path_counts: Counter[str]
    total_bytes: int
    malformed_lines: int = 0

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
