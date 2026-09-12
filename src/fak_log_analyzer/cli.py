"""Command-line interface for FAK Log Analyzer."""

import argparse
from pathlib import Path

from fak_log_analyzer.analyzer import analyze
from fak_log_analyzer.models import ReportConfig
from fak_log_analyzer.parser import parse_file
from fak_log_analyzer.reporters import get_reporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


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

    parser.add_argument(
        "--top-ips",
        type=int,
        default=10,
        help="Number of top IP addresses to display.",
    )

    parser.add_argument(
        "--top-paths",
        type=int,
        default=10,
        help="Number of top requested paths to display.",
    )

    parser.add_argument(
        "--format",
        choices=["terminal", "json", "csv"],
        default="terminal",
        help="Output format.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Write the report to a file instead of standard output.",
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

    config = ReportConfig(
        top_ips=args.top_ips,
        top_paths=args.top_paths,
    )

    reporter = get_reporter(args.format)

    if isinstance(reporter, TerminalReporter):
        if args.output:
            parser.error("The terminal format cannot be written to a file.")

        reporter.display(result, config)
    else:
        output = reporter.render(result, config)

        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output)


if __name__ == "__main__":
    main()
