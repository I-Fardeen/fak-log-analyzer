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
