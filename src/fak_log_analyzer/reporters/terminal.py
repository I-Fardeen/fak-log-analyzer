from rich.console import Console
from rich.table import Table

from fak_log_analyzer.findings import generate_findings
from fak_log_analyzer.models import AnalysisResult, ReportConfig
from fak_log_analyzer.reporters.base import Reporter
from fak_log_analyzer.security_rules import (
    AUTH_FAILURE_HIGH_THRESHOLD,
    AUTH_FAILURE_MEDIUM_THRESHOLD,
    NOT_FOUND_DISTINCT_PATH_THRESHOLD,
    NOT_FOUND_HIGH_THRESHOLD,
    NOT_FOUND_MEDIUM_THRESHOLD,
    REQUEST_BURST_HIGH_THRESHOLD,
    REQUEST_BURST_MEDIUM_THRESHOLD,
    SENSITIVE_PATH_HIGH_THRESHOLD,
)


class TerminalReporter(Reporter):
    """Render analysis results for terminal users."""

    def render(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> str:
        """Render the analysis result for terminal output."""
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

        time_table.add_row("Traffic trend", result.traffic_trend)

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

        performance = result.performance_stats

        performance_table = Table(title="Performance Analysis")
        performance_table.add_column("Metric")
        performance_table.add_column("Value", justify="right")

        if performance is None or not performance.available:
            performance_table.add_row(
                "Response-time data",
                "Not available",
            )
        else:
            performance_table.add_row(
                "Requests with latency",
                str(performance.requests_with_latency),
            )
            performance_table.add_row(
                "Latency coverage",
                f"{performance.latency_coverage:.2f}%",
            )
            performance_table.add_row(
                "Minimum",
                f"{performance.min_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "Maximum",
                f"{performance.max_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "Average",
                f"{performance.average_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "Median",
                f"{performance.median_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "P50",
                f"{performance.p50_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "P90",
                f"{performance.p90_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "P95",
                f"{performance.p95_response_time_ms:.2f} ms",
            )
            performance_table.add_row(
                "P99",
                f"{performance.p99_response_time_ms:.2f} ms",
            )

        console.print(performance_table)

        performance_hotspots = Table(title="Performance Hotspots")
        performance_hotspots.add_column("Path")
        performance_hotspots.add_column("Requests", justify="right")
        performance_hotspots.add_column("Average", justify="right")
        performance_hotspots.add_column("P95", justify="right")
        performance_hotspots.add_column("Maximum", justify="right")

        for path, stats in list(result.path_performance.items())[: config.top_paths]:
            performance_hotspots.add_row(
                path,
                str(stats.request_count),
                f"{stats.average_ms:.2f} ms",
                f"{stats.p95_ms:.2f} ms",
                f"{stats.max_ms:.2f} ms",
            )

        if not result.path_performance:
            performance_hotspots.add_row(
                "None",
                "0",
                "N/A",
                "N/A",
                "N/A",
            )

        console.print(performance_hotspots)

        # ------------------------------------------------------------------
        # Statistical Anomaly Detection
        # ------------------------------------------------------------------

        statistical = result.statistical_stats
        statistical_table = Table(title="Statistical Anomaly Detection")
        statistical_table.add_column("Metric")
        statistical_table.add_column("Sample", justify="right")
        statistical_table.add_column("Mean", justify="right")
        statistical_table.add_column("Std Dev", justify="right")
        statistical_table.add_column("IQR", justify="right")

        if statistical is None or not statistical.available:
            statistical_table.add_row(
                "Statistical baseline", "N/A", "N/A", "N/A", "N/A"
            )
        else:
            for name, metric in statistical.metrics.items():
                statistical_table.add_row(
                    name,
                    str(metric.sample_size),
                    f"{metric.mean:.2f}",
                    f"{metric.standard_deviation:.2f}",
                    f"{metric.iqr:.2f}",
                )

        console.print(statistical_table)

        anomaly_table = Table(title="Statistical Anomalies")
        anomaly_table.add_column("Severity")
        anomaly_table.add_column("Metric")
        anomaly_table.add_column("Reference")
        anomaly_table.add_column("Observed", justify="right")
        anomaly_table.add_column("Baseline", justify="right")
        anomaly_table.add_column("Z-score", justify="right")
        anomaly_table.add_column("Context")
        anomaly_table.add_column("Method")

        if statistical is not None and statistical.anomalies:
            for anomaly in statistical.anomalies[: config.top_paths * 2]:
                if (
                    anomaly.metric
                    in {
                        "requests_per_minute",
                        "error_rate_per_minute",
                        "response_time_ms",
                    }
                    and anomaly.observation_time is not None
                ):
                    reference = anomaly.observation_time.isoformat()
                else:
                    reference = anomaly.key

                context_parts = []
                if anomaly.path is not None:
                    context_parts.append(f"path={anomaly.path}")
                if anomaly.ip_address is not None:
                    context_parts.append(f"ip={anomaly.ip_address}")
                if anomaly.status_code is not None:
                    context_parts.append(f"status={anomaly.status_code}")
                context = "; ".join(context_parts) if context_parts else "-"

                anomaly_table.add_row(
                    anomaly.severity,
                    anomaly.metric,
                    reference,
                    f"{anomaly.observed:.2f}",
                    f"{anomaly.baseline:.2f}",
                    (
                        f"{anomaly.z_score:.2f}"
                        if anomaly.z_score is not None
                        else "N/A"
                    ),
                    context,
                    anomaly.method,
                )
        else:
            anomaly_table.add_row(
                "INFO",
                "statistical",
                "No statistical anomalies detected",
                "N/A",
                "N/A",
                "N/A",
                "N/A",
                "N/A",
            )

        console.print(anomaly_table)

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

        status_classes = Table(title="HTTP Status Classes")
        status_classes.add_column("Class")
        status_classes.add_column("Requests", justify="right")
        status_classes.add_column("Percentage", justify="right")

        for status_class in ("2xx", "3xx", "4xx", "5xx"):
            count = result.status_class_counts.get(status_class, 0)

            percentage = (
                (count / result.total_requests) * 100 if result.total_requests else 0.0
            )

            status_classes.add_row(
                status_class,
                str(count),
                f"{percentage:.2f}%",
            )

        console.print(status_classes)

        error_hotspots = Table(title="Error Hotspots")
        error_hotspots.add_column("Category")
        error_hotspots.add_column("Value")
        error_hotspots.add_column("Errors", justify="right")

        for path, count in result.error_path_counts.most_common(config.top_paths):
            error_hotspots.add_row(
                "Path",
                path,
                str(count),
            )

        for ip, count in result.error_ip_counts.most_common(config.top_ips):
            error_hotspots.add_row(
                "IP",
                ip,
                str(count),
            )

        for status, count in sorted(result.error_status_counts.items()):
            error_hotspots.add_row(
                "Status",
                str(status),
                str(count),
            )

        if (
            not result.error_path_counts
            and not result.error_ip_counts
            and not result.error_status_counts
        ):
            error_hotspots.add_row(
                "None",
                "No HTTP errors detected",
                "0",
            )

        console.print(error_hotspots)

        # ------------------------------------------------------------------
        # Security Intelligence
        # ------------------------------------------------------------------

        security = result.security_stats

        security_summary = Table(title="Security Intelligence — Overview")
        security_summary.add_column("Security Signal")
        security_summary.add_column("Observed", justify="right")
        security_summary.add_column("Threshold / Context")

        auth_total = sum(security.authentication_failures_by_ip.values())
        auth_ips = len(security.authentication_failures_by_ip)
        auth_paths = len(security.authentication_failures_by_path)

        security_summary.add_row(
            "HTTP 401 authentication failures",
            str(auth_total),
            (
                f"MEDIUM ≥ {AUTH_FAILURE_MEDIUM_THRESHOLD}; "
                f"HIGH ≥ {AUTH_FAILURE_HIGH_THRESHOLD}"
            ),
        )
        security_summary.add_row(
            "Clients with authentication failures",
            str(auth_ips),
            f"{auth_paths} affected request path(s)",
        )

        not_found_total = sum(security.not_found_by_ip.values())
        enumeration_ips = sum(
            1
            for ip, count in security.not_found_by_ip.items()
            if count >= NOT_FOUND_MEDIUM_THRESHOLD
            and security.unique_not_found_paths_by_ip.get(ip, 0)
            >= NOT_FOUND_DISTINCT_PATH_THRESHOLD
        )

        security_summary.add_row(
            "HTTP 404 responses",
            str(not_found_total),
            (
                f"Enumeration requires ≥ {NOT_FOUND_MEDIUM_THRESHOLD} "
                f"404s and ≥ {NOT_FOUND_DISTINCT_PATH_THRESHOLD} distinct paths"
            ),
        )
        security_summary.add_row(
            "Clients matching enumeration heuristic",
            str(enumeration_ips),
            f"HIGH ≥ {NOT_FOUND_HIGH_THRESHOLD} 404s",
        )

        sensitive_total = sum(security.sensitive_path_counts.values())
        sensitive_ips = len(security.sensitive_path_ips)

        security_summary.add_row(
            "Sensitive-path requests",
            str(sensitive_total),
            f"HIGH ≥ {SENSITIVE_PATH_HIGH_THRESHOLD} requests per path",
        )
        security_summary.add_row(
            "Clients accessing sensitive paths",
            str(sensitive_ips),
            "Based on configured security rules",
        )

        max_burst = max(
            (count for _, count in security.peak_requests_per_minute_by_ip.values()),
            default=0,
        )
        burst_ips = sum(
            1
            for _, (_, count) in security.peak_requests_per_minute_by_ip.items()
            if count >= REQUEST_BURST_MEDIUM_THRESHOLD
        )

        security_summary.add_row(
            "Peak per-IP request burst",
            str(max_burst),
            (
                f"MEDIUM ≥ {REQUEST_BURST_MEDIUM_THRESHOLD}; "
                f"HIGH ≥ {REQUEST_BURST_HIGH_THRESHOLD} per minute"
            ),
        )
        security_summary.add_row(
            "Clients matching burst heuristic",
            str(burst_ips),
            "One-minute request buckets",
        )

        console.print(security_summary)

        # Authentication failures by client.
        auth_ip_table = Table(title="Security Detail — Authentication Failures by IP")
        auth_ip_table.add_column("Client IP")
        auth_ip_table.add_column("401 Failures", justify="right")
        auth_ip_table.add_column("Signal")

        for ip, count in security.authentication_failures_by_ip.most_common(
            config.top_ips
        ):
            if count >= AUTH_FAILURE_HIGH_THRESHOLD:
                signal = "HIGH threshold reached"
            elif count >= AUTH_FAILURE_MEDIUM_THRESHOLD:
                signal = "MEDIUM threshold reached"
            else:
                signal = "Below finding threshold"

            auth_ip_table.add_row(
                ip,
                str(count),
                signal,
            )

        if not security.authentication_failures_by_ip:
            auth_ip_table.add_row("None", "0", "No 401 failures observed")

        console.print(auth_ip_table)

        # Authentication failures by endpoint.
        auth_path_table = Table(
            title="Security Detail — Authentication Failures by Path"
        )
        auth_path_table.add_column("Endpoint")
        auth_path_table.add_column("401 Failures", justify="right")

        for path, count in security.authentication_failures_by_path.most_common(
            config.top_paths
        ):
            auth_path_table.add_row(path, str(count))

        if not security.authentication_failures_by_path:
            auth_path_table.add_row("None", "0")

        console.print(auth_path_table)

        # 404 enumeration detail.
        enumeration_table = Table(title="Security Detail — 404 Enumeration")
        enumeration_table.add_column("Client IP")
        enumeration_table.add_column("404s", justify="right")
        enumeration_table.add_column("Distinct Paths", justify="right")
        enumeration_table.add_column("Signal")

        for ip, count in security.not_found_by_ip.most_common(config.top_ips):
            distinct = security.unique_not_found_paths_by_ip.get(ip, 0)

            if (
                count >= NOT_FOUND_HIGH_THRESHOLD
                and distinct >= NOT_FOUND_DISTINCT_PATH_THRESHOLD
            ):
                signal = "HIGH threshold reached"
            elif (
                count >= NOT_FOUND_MEDIUM_THRESHOLD
                and distinct >= NOT_FOUND_DISTINCT_PATH_THRESHOLD
            ):
                signal = "MEDIUM threshold reached"
            else:
                signal = "Below enumeration threshold"

            enumeration_table.add_row(
                ip,
                str(count),
                str(distinct),
                signal,
            )

        if not security.not_found_by_ip:
            enumeration_table.add_row("None", "0", "0", "No 404 activity observed")

        console.print(enumeration_table)

        # Sensitive paths and the clients requesting them.
        sensitive_path_table = Table(title="Security Detail — Sensitive Paths")
        sensitive_path_table.add_column("Path")
        sensitive_path_table.add_column("Requests", justify="right")
        sensitive_path_table.add_column("Signal")

        for path, count in security.sensitive_path_counts.most_common(config.top_paths):
            signal = (
                "HIGH threshold reached"
                if count >= SENSITIVE_PATH_HIGH_THRESHOLD
                else "Sensitive-path rule matched"
            )
            sensitive_path_table.add_row(path, str(count), signal)

        if not security.sensitive_path_counts:
            sensitive_path_table.add_row("None", "0", "No configured sensitive paths")

        console.print(sensitive_path_table)

        sensitive_ip_table = Table(
            title="Security Detail — Clients Accessing Sensitive Paths"
        )
        sensitive_ip_table.add_column("Client IP")
        sensitive_ip_table.add_column("Requests", justify="right")

        for ip, count in security.sensitive_path_ips.most_common(config.top_ips):
            sensitive_ip_table.add_row(ip, str(count))

        if not security.sensitive_path_ips:
            sensitive_ip_table.add_row("None", "0")

        console.print(sensitive_ip_table)

        # Per-IP request bursts.
        burst_table = Table(title="Security Detail — Request Bursts")
        burst_table.add_column("Client IP")
        burst_table.add_column("Requests / Minute", justify="right")
        burst_table.add_column("Minute")
        burst_table.add_column("Signal")

        for ip, (timestamp, count) in sorted(
            security.peak_requests_per_minute_by_ip.items(),
            key=lambda item: item[1][1],
            reverse=True,
        )[: config.top_ips]:
            if count >= REQUEST_BURST_HIGH_THRESHOLD:
                signal = "HIGH threshold reached"
            elif count >= REQUEST_BURST_MEDIUM_THRESHOLD:
                signal = "MEDIUM threshold reached"
            else:
                signal = "Below burst threshold"

            burst_table.add_row(
                ip,
                str(count),
                timestamp.strftime("%Y-%m-%d %H:%M"),
                signal,
            )

        if not security.peak_requests_per_minute_by_ip:
            burst_table.add_row("None", "0", "N/A", "No request activity")

        console.print(burst_table)

        # Security-only findings provide the same evidence-oriented view as
        # the JSON findings while keeping the terminal report readable.
        security_findings = [
            finding
            for finding in generate_findings(result)
            if finding.category.startswith("security_")
        ]

        security_findings_table = Table(title="Security Findings")
        security_findings_table.add_column("Severity")
        security_findings_table.add_column("Category")
        security_findings_table.add_column("Finding")

        for finding in security_findings:
            security_findings_table.add_row(
                finding.severity.value,
                finding.category,
                finding.message,
            )

        if not security_findings:
            security_findings_table.add_row(
                "INFO",
                "security",
                "No security finding thresholds were triggered.",
            )

        console.print(security_findings_table)

        findings = Table(title="Operational Findings")
        findings.add_column("Severity")
        findings.add_column("Category")
        findings.add_column("Finding")

        for finding in generate_findings(result):
            findings.add_row(
                finding.severity.value,
                finding.category,
                finding.message,
            )

        console.print(findings)

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
