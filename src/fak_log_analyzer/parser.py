"""Log parsing functionality for FAK Log Analyzer."""

import re
from datetime import datetime

from fak_log_analyzer.models import LogEntry

LOG_PATTERN = re.compile(
    r"(?P<ip>\S+) "
    r"\S+ "
    r"\S+ "
    r"\[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status>\d{3}) "
    r"(?P<size>\d+)"
    r"(?: (?P<response_time>[0-9]+(?:\.[0-9]+)?))?"
    r"$"
)


def parse_line(line: str) -> LogEntry | None:
    """Parse a Common Log Format or extended timed log line.

    The optional final field represents response time in milliseconds.
    """

    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z",
        )
    except ValueError:
        return None

    response_time = data["response_time"]

    return LogEntry(
        ip_address=data["ip"],
        timestamp=timestamp,
        method=data["method"],
        path=data["path"],
        protocol=data["protocol"],
        status_code=int(data["status"]),
        response_size=int(data["size"]),
        response_time_ms=(float(response_time) if response_time is not None else None),
    )


def parse_file(filepath: str) -> tuple[list[LogEntry], int]:
    """Parse a log file and return entries and malformed line count."""

    entries: list[LogEntry] = []
    malformed_lines = 0

    with open(filepath, encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            entry = parse_line(line)

            if entry is None:
                malformed_lines += 1
            else:
                entries.append(entry)

    return entries, malformed_lines
