"""Core log analysis functionality for FAK Log Analyzer."""

from collections import Counter
from collections.abc import Iterable

from fak_log_analyzer.models import AnalysisResult, LogEntry
from fak_log_analyzer.performance_analysis import (
    calculate_path_performance,
    calculate_performance_stats,
)
from fak_log_analyzer.time_analysis import (
    calculate_requests_per_minute,
    calculate_time_stats,
)


def analyze(
    entries: Iterable[LogEntry],
    malformed_lines: int = 0,
) -> AnalysisResult:
    """Analyze parsed log entries and return aggregated results."""

    entries = list(entries)

    total_requests = len(entries)

    method_counts = Counter(entry.method for entry in entries)

    status_counts = Counter(entry.status_code for entry in entries)

    status_class_counts = Counter(f"{entry.status_code // 100}xx" for entry in entries)

    ip_counts = Counter(entry.ip_address for entry in entries)

    path_counts = Counter(entry.path for entry in entries)

    total_bytes = sum(entry.response_size for entry in entries)

    error_path_counts = Counter(
        entry.path for entry in entries if entry.status_code >= 400
    )

    error_ip_counts = Counter(
        entry.ip_address for entry in entries if entry.status_code >= 400
    )

    error_status_counts = Counter(
        entry.status_code for entry in entries if entry.status_code >= 400
    )

    time_stats = calculate_time_stats(entries)

    requests_per_minute = calculate_requests_per_minute(entries)

    performance_stats = calculate_performance_stats(entries)

    path_performance = calculate_path_performance(entries)

    return AnalysisResult(
        total_requests=total_requests,
        method_counts=method_counts,
        status_counts=status_counts,
        status_class_counts=status_class_counts,
        ip_counts=ip_counts,
        path_counts=path_counts,
        total_bytes=total_bytes,
        time_stats=time_stats,
        requests_per_minute=requests_per_minute,
        malformed_lines=malformed_lines,
        error_path_counts=error_path_counts,
        error_ip_counts=error_ip_counts,
        error_status_counts=error_status_counts,
        performance_stats=performance_stats,
        path_performance=path_performance,
    )
