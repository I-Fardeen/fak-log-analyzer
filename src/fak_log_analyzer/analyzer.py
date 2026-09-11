"""Log analysis functionality for FAK Log Analyzer."""

from collections import Counter
from collections.abc import Iterable

from fak_log_analyzer.models import AnalysisResult, LogEntry


def analyze(
    entries: Iterable[LogEntry],
    malformed_lines: int = 0,
) -> AnalysisResult:
    """Analyze parsed log entries and return aggregate statistics."""

    entries = list(entries)

    method_counts = Counter(entry.method for entry in entries)
    status_counts = Counter(entry.status_code for entry in entries)
    ip_counts = Counter(entry.ip_address for entry in entries)
    path_counts = Counter(entry.path for entry in entries)

    total_bytes = sum(entry.response_size for entry in entries)

    return AnalysisResult(
        total_requests=len(entries),
        method_counts=method_counts,
        status_counts=status_counts,
        ip_counts=ip_counts,
        path_counts=path_counts,
        total_bytes=total_bytes,
        malformed_lines=malformed_lines,
    )
