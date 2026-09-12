"""Terminal reporter."""

from rich.console import Console
from rich.table import Table

from fak_log_analyzer.models import AnalysisResult, ReportConfig
from fak_log_analyzer.reporters.base import Reporter


class TerminalReporter(Reporter):
    """Render analysis results for terminal users."""

    def render(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> str:
        """Render the analysis result for terminal output."""

        # Rich renders directly to the terminal, so this method
        # is handled separately through display().
        return ""

    def display(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> None:
        """Display the analysis result using Rich."""

        console = Console()

        console.print("\n[bold]FAK Log Analyzer[/bold]\n")

        summary = Table(title="Summary")

        summary.add_column("Metric")
        summary.add_column("Value", justify="right")

        summary.add_row("Total requests", str(result.total_requests))
        summary.add_row("Malformed lines", str(result.malformed_lines))
        summary.add_row("Total response bytes", f"{result.total_bytes:,}")
        summary.add_row(
            "Average response size",
            f"{result.average_response_size:,.2f} bytes",
        )
        summary.add_row("Error count", str(result.error_count))
        summary.add_row("Error rate", f"{result.error_rate:.2f}%")

        console.print(summary)

        time_stats = result.time_stats

        time_table = Table(title="Time Analysis")

        time_table.add_column("Metric")
        time_table.add_column("Value", justify="right")

        time_table.add_row(
            "Start time",
            (time_stats.start_time.isoformat() if time_stats.start_time else "N/A"),
        )
        time_table.add_row(
            "End time",
            (time_stats.end_time.isoformat() if time_stats.end_time else "N/A"),
        )
        time_table.add_row(
            "Duration",
            f"{time_stats.duration_seconds:.2f} seconds",
        )
        time_table.add_row(
            "Requests per minute",
            f"{time_stats.requests_per_minute:.2f}",
        )
        time_table.add_row(
            "Requests per hour",
            f"{time_stats.requests_per_hour:.2f}",
        )
        peak_timestamp, peak_requests = result.peak_traffic

        time_table.add_row(
            "Peak traffic",
            (
                f"{peak_requests} requests at "
                f"{peak_timestamp.strftime('%Y-%m-%d %H:%M')}"
                if peak_timestamp
                else "N/A"
            ),
        )
        time_table.add_row(
            "Traffic trend",
            result.traffic_trend,
        )

        console.print(time_table)

        traffic = Table(title="Requests Per Minute")

        traffic.add_column("Time")
        traffic.add_column("Requests", justify="right")

        for timestamp, count in result.requests_per_minute.items():
            traffic.add_row(
                timestamp.strftime("%Y-%m-%d %H:%M"),
                str(count),
            )

        console.print(traffic)

        methods = Table(title="HTTP Methods")
        methods.add_column("Method")
        methods.add_column("Requests", justify="right")

        for method, count in result.method_counts.most_common():
            methods.add_row(method, str(count))

        console.print(methods)

        statuses = Table(title="HTTP Status Codes")
        statuses.add_column("Status")
        statuses.add_column("Requests", justify="right")

        for status, count in sorted(result.status_counts.items()):
            statuses.add_row(str(status), str(count))

        console.print(statuses)

        ips = Table(title="Top IP Addresses")
        ips.add_column("IP Address")
        ips.add_column("Requests", justify="right")

        for ip, count in result.ip_counts.most_common(config.top_ips):
            ips.add_row(ip, str(count))

        console.print(ips)

        paths = Table(title="Top Paths")
        paths.add_column("Path")
        paths.add_column("Requests", justify="right")

        for path, count in result.path_counts.most_common(config.top_paths):
            paths.add_row(path, str(count))

        console.print(paths)
