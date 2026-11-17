"""Markdown reporter."""

from fak_log_analyzer.findings import generate_findings
from fak_log_analyzer.models import AnalysisResult, ReportConfig
from fak_log_analyzer.reporters.base import Reporter


class MarkdownReporter(Reporter):
    """Render analysis results as Markdown."""

    def render(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> str:
        """Render the analysis result as Markdown."""

        lines: list[str] = []

        # ---- Summary ----
        lines.append("# FAK Log Analysis Report")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")
        lines.append(f"| Total Requests | {result.total_requests} |")
        lines.append(f"| Malformed Lines | {result.malformed_lines} |")
        lines.append(f"| Total Bytes | {result.total_bytes} |")
        lines.append(
            f"| Average Response Size | {result.average_response_size:.2f} bytes |"
        )
        lines.append(f"| Error Count | {result.error_count} |")
        lines.append(f"| Error Rate | {result.error_rate:.2f}% |")

        # ---- Time Analysis ----
        time_stats = result.time_stats
        lines.append("")
        lines.append("## Time Analysis")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| --- | --- |")

        start = time_stats.start_time.isoformat() if time_stats.start_time else "N/A"
        end = time_stats.end_time.isoformat() if time_stats.end_time else "N/A"

        lines.append(f"| Start Time | {start} |")
        lines.append(f"| End Time | {end} |")
        lines.append(f"| Duration (seconds) | {time_stats.duration_seconds} |")
        lines.append(f"| Requests per Minute | {time_stats.requests_per_minute:.2f} |")
        lines.append(f"| Requests per Hour | {time_stats.requests_per_hour:.2f} |")

        # ---- Traffic ----
        lines.append("")
        lines.append("## Traffic")
        lines.append("")

        if result.requests_per_minute:
            lines.append("| Minute | Requests |")
            lines.append("| --- | --- |")
            for timestamp, count in result.requests_per_minute.items():
                lines.append(f"| {timestamp.isoformat()} | {count} |")

        peak_timestamp, peak_requests = result.peak_traffic
        lines.append("")

        if peak_timestamp:
            lines.append(
                f"**Peak Traffic:** {peak_requests} requests "
                f"at {peak_timestamp.isoformat()}"
            )
        else:
            lines.append("**Peak Traffic:** N/A")

        lines.append("")
        lines.append(f"**Traffic Trend:** {result.traffic_trend}")

        # ---- HTTP Methods ----
        lines.append("")
        lines.append("## HTTP Methods")
        lines.append("")
        lines.append("| Method | Count |")
        lines.append("| --- | --- |")
        for method, count in result.method_counts.most_common():
            lines.append(f"| {method} | {count} |")

        # ---- Status Codes ----
        lines.append("")
        lines.append("## Status Codes")
        lines.append("")
        lines.append("| Status | Count |")
        lines.append("| --- | --- |")
        for status, count in sorted(result.status_counts.items()):
            lines.append(f"| {status} | {count} |")

        lines.append("")
        lines.append("### Status Classes")
        lines.append("")
        lines.append("| Class | Count |")
        lines.append("| --- | --- |")
        for status_class, count in sorted(result.status_class_counts.items()):
            lines.append(f"| {status_class} | {count} |")

        # ---- Top IPs ----
        lines.append("")
        lines.append("## Top IP Addresses")
        lines.append("")
        lines.append("| IP Address | Requests |")
        lines.append("| --- | --- |")
        for ip, count in result.ip_counts.most_common(config.top_ips):
            lines.append(f"| {ip} | {count} |")

        # ---- Top Paths ----
        lines.append("")
        lines.append("## Top Requested Paths")
        lines.append("")
        lines.append("| Path | Requests |")
        lines.append("| --- | --- |")
        for path, count in result.path_counts.most_common(config.top_paths):
            lines.append(f"| {path} | {count} |")

        # ---- Error Hotspots ----
        lines.append("")
        lines.append("## Error Hotspots")
        lines.append("")

        if result.error_path_counts:
            lines.append("### By Path")
            lines.append("")
            lines.append("| Path | Errors |")
            lines.append("| --- | --- |")
            for path, count in result.error_path_counts.most_common(config.top_paths):
                lines.append(f"| {path} | {count} |")
            lines.append("")

        if result.error_ip_counts:
            lines.append("### By IP")
            lines.append("")
            lines.append("| IP Address | Errors |")
            lines.append("| --- | --- |")
            for ip, count in result.error_ip_counts.most_common(config.top_ips):
                lines.append(f"| {ip} | {count} |")
            lines.append("")

        if result.error_status_counts:
            lines.append("### By Status Code")
            lines.append("")
            lines.append("| Status | Count |")
            lines.append("| --- | --- |")
            for status, count in sorted(result.error_status_counts.items()):
                lines.append(f"| {status} | {count} |")

        # ---- Performance ----
        lines.append("")
        lines.append("## Performance")
        lines.append("")

        performance = result.performance_stats

        if performance and performance.available:
            lines.append("| Metric | Value |")
            lines.append("| --- | --- |")
            lines.append(
                f"| Requests with Latency | {performance.requests_with_latency} |"
            )
            lines.append(f"| Latency Coverage | {performance.latency_coverage:.2f}% |")
            lines.append(
                f"| Min Response Time | {performance.min_response_time_ms:.2f} ms |"
            )
            lines.append(
                f"| Max Response Time | {performance.max_response_time_ms:.2f} ms |"
            )
            lines.append(
                f"| Average Response Time | "
                f"{performance.average_response_time_ms:.2f} ms |"
            )
            lines.append(
                f"| Median Response Time | "
                f"{performance.median_response_time_ms:.2f} ms |"
            )
            lines.append(f"| P50 | {performance.p50_response_time_ms:.2f} ms |")
            lines.append(f"| P90 | {performance.p90_response_time_ms:.2f} ms |")
            lines.append(f"| P95 | {performance.p95_response_time_ms:.2f} ms |")
            lines.append(f"| P99 | {performance.p99_response_time_ms:.2f} ms |")
        else:
            lines.append("Performance data unavailable.")

        # ---- Performance Hotspots ----
        if result.path_performance:
            lines.append("")
            lines.append("## Performance Hotspots")
            lines.append("")
            lines.append(
                "| Path | Requests | Avg (ms) | Median (ms) | P95 (ms) | Max (ms) |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- |")
            for path, stats in list(result.path_performance.items())[
                : config.top_paths
            ]:
                lines.append(
                    f"| {path} | {stats.request_count} "
                    f"| {stats.average_ms:.2f} | {stats.median_ms:.2f} "
                    f"| {stats.p95_ms:.2f} | {stats.max_ms:.2f} |"
                )

        # ---- Statistical Anomalies ----
        lines.append("")
        lines.append("## Statistical Anomalies")
        lines.append("")

        statistical = result.statistical_stats

        if statistical is not None and statistical.available:
            lines.append(
                "| Severity | Metric | Observation | Observed "
                "| Baseline | Z-score | Method |"
            )
            lines.append("| --- | --- | --- | --- | --- | --- | --- |")
            for anomaly in statistical.anomalies:
                z_score = (
                    f"{anomaly.z_score:.2f}" if anomaly.z_score is not None else "N/A"
                )
                lines.append(
                    f"| {anomaly.severity} | {anomaly.metric} "
                    f"| {anomaly.key} | {anomaly.observed:.2f} "
                    f"| {anomaly.baseline:.2f} | {z_score} "
                    f"| {anomaly.method} |"
                )
        else:
            lines.append("No statistical anomalies detected.")

        # ---- Security ----
        lines.append("")
        lines.append("## Security Intelligence")
        lines.append("")

        security = result.security_stats

        if security.authentication_failures_by_ip:
            lines.append("### Authentication Failures by IP")
            lines.append("")
            lines.append("| IP Address | Failures |")
            lines.append("| --- | --- |")
            for ip, count in security.authentication_failures_by_ip.most_common(
                config.top_ips
            ):
                lines.append(f"| {ip} | {count} |")
            lines.append("")

        if security.authentication_failures_by_path:
            lines.append("### Authentication Failures by Path")
            lines.append("")
            lines.append("| Path | Failures |")
            lines.append("| --- | --- |")
            for path, count in security.authentication_failures_by_path.most_common(
                config.top_paths
            ):
                lines.append(f"| {path} | {count} |")
            lines.append("")

        if security.not_found_by_ip:
            lines.append("### 404 Not Found by IP")
            lines.append("")
            lines.append("| IP Address | Requests | Distinct Paths |")
            lines.append("| --- | --- | --- |")
            for ip, count in security.not_found_by_ip.most_common(config.top_ips):
                distinct = security.unique_not_found_paths_by_ip.get(ip, 0)
                lines.append(f"| {ip} | {count} | {distinct} |")
            lines.append("")

        if security.sensitive_path_counts:
            lines.append("### Sensitive Path Access")
            lines.append("")
            lines.append("| Path | Requests |")
            lines.append("| --- | --- |")
            for path, count in security.sensitive_path_counts.most_common(
                config.top_paths
            ):
                lines.append(f"| {path} | {count} |")
            lines.append("")

        if security.peak_requests_per_minute_by_ip:
            lines.append("### Request Bursts")
            lines.append("")
            lines.append("| IP Address | Timestamp | Requests |")
            lines.append("| --- | --- | --- |")
            for ip, (timestamp, count) in sorted(
                security.peak_requests_per_minute_by_ip.items(),
                key=lambda item: item[1][1],
                reverse=True,
            )[: config.top_ips]:
                lines.append(f"| {ip} | {timestamp.isoformat()} | {count} |")

        # ---- Findings ----
        findings = generate_findings(result)

        lines.append("")
        lines.append("## Findings")
        lines.append("")

        if findings:
            lines.append("| Severity | Category | Title | Message |")
            lines.append("| --- | --- | --- | --- |")
            for finding in findings:
                lines.append(
                    f"| {finding.severity.value} | {finding.category} "
                    f"| {finding.title} | {finding.message} |"
                )
        else:
            lines.append("No findings.")

        lines.append("")

        return "\n".join(lines)
