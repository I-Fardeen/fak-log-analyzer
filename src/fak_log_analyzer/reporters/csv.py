"""CSV reporter."""

import csv
import io

from fak_log_analyzer.findings import generate_findings
from fak_log_analyzer.models import AnalysisResult, ReportConfig
from fak_log_analyzer.reporters.base import Reporter


class CsvReporter(Reporter):
    """Render analysis results as CSV."""

    def render(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> str:
        """Render the analysis result as CSV."""

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["category", "name", "value"])

        writer.writerow(["summary", "total_requests", result.total_requests])
        writer.writerow(["summary", "malformed_lines", result.malformed_lines])
        writer.writerow(["summary", "total_bytes", result.total_bytes])
        writer.writerow(
            [
                "summary",
                "average_response_size",
                result.average_response_size,
            ]
        )
        writer.writerow(["summary", "error_count", result.error_count])
        writer.writerow(["summary", "error_rate", result.error_rate])

        time_stats = result.time_stats

        writer.writerow(
            [
                "time",
                "start_time",
                (time_stats.start_time.isoformat() if time_stats.start_time else ""),
            ]
        )
        writer.writerow(
            [
                "time",
                "end_time",
                (time_stats.end_time.isoformat() if time_stats.end_time else ""),
            ]
        )
        writer.writerow(
            [
                "time",
                "duration_seconds",
                time_stats.duration_seconds,
            ]
        )
        writer.writerow(
            [
                "time",
                "requests_per_minute",
                time_stats.requests_per_minute,
            ]
        )
        writer.writerow(
            [
                "time",
                "requests_per_hour",
                time_stats.requests_per_hour,
            ]
        )

        for timestamp, count in result.requests_per_minute.items():
            writer.writerow(
                [
                    "traffic",
                    timestamp.isoformat(),
                    count,
                ]
            )

        peak_timestamp, peak_requests = result.peak_traffic

        writer.writerow(
            [
                "traffic_peak",
                "timestamp",
                (peak_timestamp.isoformat() if peak_timestamp else ""),
            ]
        )

        writer.writerow(
            [
                "traffic_peak",
                "requests",
                peak_requests,
            ]
        )

        writer.writerow(
            [
                "traffic",
                "trend",
                result.traffic_trend,
            ]
        )

        for method, count in result.method_counts.most_common():
            writer.writerow(["method", method, count])

        for status, count in sorted(result.status_counts.items()):
            writer.writerow(["status", status, count])

        for status_class, count in sorted(result.status_class_counts.items()):
            writer.writerow(["status_class", status_class, count])

        for ip, count in result.ip_counts.most_common(config.top_ips):
            writer.writerow(["ip", ip, count])

        for path, count in result.path_counts.most_common(config.top_paths):
            writer.writerow(["path", path, count])

        for path, count in result.error_path_counts.most_common(config.top_paths):
            writer.writerow(["error_path", path, count])

        for ip, count in result.error_ip_counts.most_common(config.top_ips):
            writer.writerow(["error_ip", ip, count])

        for status, count in sorted(result.error_status_counts.items()):
            writer.writerow(["error_status", status, count])

        for finding in generate_findings(result):
            writer.writerow(
                [
                    "finding",
                    f"{finding.severity.value}:{finding.category}",
                    finding.message,
                ]
            )

        return output.getvalue()
