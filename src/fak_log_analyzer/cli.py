"""Command-line interface for FAK Log Analyzer."""

import argparse
from pathlib import Path

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.parser import parse_file
from fak_log_analyzer.report import print_report


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="fak-log-analyzer",
        description="Analyze web server log files.",
    )

    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to the log file to analyze.",
    )

    return parser


def main() -> None:
    """Run the FAK Log Analyzer command-line application."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.logfile.exists():
        parser.error(f"Log file not found: {args.logfile}")

    if not args.logfile.is_file():
        parser.error(f"Path is not a file: {args.logfile}")

    try:
        entries, malformed_lines = parse_file(args.logfile)
    except PermissionError:
        parser.error(f"Permission denied: {args.logfile}")
    except UnicodeDecodeError:
        parser.error(f"File is not valid UTF-8: {args.logfile}")

    result = analyze(entries, malformed_lines)

    print_report(result)


if __name__ == "__main__":
    main()
