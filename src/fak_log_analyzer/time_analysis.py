"""Time-based analysis functionality for FAK Log Analyzer."""

from collections import Counter
from collections.abc import Iterable
from datetime import datetime

from fak_log_analyzer.models import LogEntry, TimeStats


def calculate_time_stats(entries: Iterable[LogEntry]) -> TimeStats:
    """Calculate time-based statistics for log entries."""

    entries = list(entries)

    if not entries:
        return TimeStats(
            start_time=None,
            end_time=None,
            duration_seconds=0.0,
            requests_per_minute=0.0,
            requests_per_hour=0.0,
        )

    timestamps = [entry.timestamp for entry in entries]

    start_time = min(timestamps)
    end_time = max(timestamps)

    duration_seconds = (end_time - start_time).total_seconds()

    if duration_seconds > 0:
        requests_per_minute = len(entries) / (duration_seconds / 60)
        requests_per_hour = len(entries) / (duration_seconds / 3600)
    else:
        requests_per_minute = 0.0
        requests_per_hour = 0.0

    return TimeStats(
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
    )


def calculate_requests_per_minute(
    entries: Iterable[LogEntry],
) -> dict[datetime, int]:
    """Count requests grouped into one-minute time buckets."""

    buckets: Counter[datetime] = Counter()

    for entry in entries:
        bucket = entry.timestamp.replace(second=0, microsecond=0)
        buckets[bucket] += 1

    return dict(sorted(buckets.items()))
