"""Command Line Interface for the Fak Log Analyzer."""

import argparse
import sys
from typing import Optional

from fak_log_analyzer.analyzer import LogAnalyzer
from fak_log_analyzer.parser import LogParser
from fak_log_analyzer.reporters.csv import CSVReporter
from fak_log_analyzer.reporters.json import JSONReporter
from fak_log_analyzer.reporters.terminal import TerminalReporter


def display_live_threats(active_threats: dict) -> None:
    """Display active threats in a formatted table to the terminal."""
    if not active_threats:
        return

    print("\n" + "=" * 65)
    print("🚨 LIVE THREAT MONITORING ALERT 🚨")
    print("=" * 65)
    print(
        f"{'IP ADDRESS':<18} | {'LAST LOGIN TIME':<20} | "
        f"{'REQUESTS':<10} | {'WINDOW'}"
    )
    print("-" * 65)
    for threat_ip, data in active_threats.items():
        print(
            f"{threat_ip:<18} | {data['login_time']:<20} | "
            f"{data['request_count']:<10} | {data['window_seconds']}s"
        )
    print("-" * 65 + "\n")


def handle_live_monitoring(
    analyzer: LogAnalyzer, args: argparse.Namespace
) -> None:
    """Handle live monitoring mode for detecting threats in real-time."""
    print(f"[*] Starting live threat monitoring on log file: {args.live}")
    print(f"[*] Window: {args.window}s | Threshold: {args.threshold} requests")
    print("[*] Press Ctrl+C to stop monitoring and generate final report.\n")

    try:
        active_threats = analyzer.monitor_live(
            filepath=args.live,
            window_seconds=args.window,
            threshold=args.threshold,
        )

        display_live_threats(active_threats)

        if active_threats:
            default_ext = (
                args.format if args.format in ["json", "csv"] else "csv"
            )
            output_file = args.output or f"live_threat_report.{default_ext}"
            export_format = (
                args.format if args.format in ["json", "csv"] else "csv"
            )

            print(
                f"[*] Exporting live threat report to '{output_file}' "
                f"({export_format.upper()})..."
            )

            if export_format == "json":
                reporter = JSONReporter()
            else:
                reporter = CSVReporter()

            report_data = {
                "monitoring_window_seconds": args.window,
                "threshold": args.threshold,
                "active_threats": active_threats,
            }
            reporter.generate(report_data, output_file)
            print(f"[+] Report successfully saved to {output_file}")
        else:
            print(
                "[*] No threats were detected during this monitoring session. "
                "No report generated."
            )

    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")
    except FileNotFoundError:
        print(
            f"[!] Error: Log file not found at '{args.live}'",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(
            f"[!] Unexpected error during live monitoring: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


def main(argv: Optional[list[str]] = None) -> None:
    """Parse command line arguments and run the log analyzer."""
    parser = argparse.ArgumentParser(
        description=(
            "Fak Log Analyzer - Analyze server access logs "
            "for insights and threats."
        )
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        help="Path to the log file to analyze",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "csv"],
        default="terminal",
        help="Output format for the analysis report",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to save the output report (for json/csv formats)",
    )
    parser.add_argument(
        "--live",
        help="Path to log file to monitor live for threat patterns",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Time window in seconds for live threat detection (default: 60)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help=(
            "Request threshold within the window to flag a threat "
            "(default: 10)"
        ),
    )

    args = parser.parse_args(argv)

    analyzer = LogAnalyzer()

    if args.live:
        handle_live_monitoring(analyzer, args)
        return

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    try:
        log_parser = LogParser()
        entries = log_parser.parse_file(args.logfile)
        analysis_results = analyzer.analyze(entries)

        if args.format == "json":
            reporter = JSONReporter()
        elif args.format == "csv":
            reporter = CSVReporter()
        else:
            reporter = TerminalReporter()

        if args.output:
            reporter.generate(analysis_results, args.output)
            print(f"[+] Report successfully saved to {args.output}")
        else:
            reporter.generate(analysis_results, sys.stdout)

    except FileNotFoundError:
        print(
            f"[!] Error: Log file not found at '{args.logfile}'",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error analyzing log file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
