"""Reporters for FAK Log Analyzer."""

from fak_log_analyzer.reporters.base import Reporter
from fak_log_analyzer.reporters.csv import CsvReporter
from fak_log_analyzer.reporters.json import JsonReporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


def get_reporter(format_name: str) -> Reporter:
    """Return a reporter for the requested output format."""

    reporters = {
        "terminal": TerminalReporter,
        "json": JsonReporter,
        "csv": CsvReporter,
    }

    try:
        reporter_class = reporters[format_name]
    except KeyError as error:
        raise ValueError(f"Unsupported output format: {format_name}") from error

    return reporter_class()
