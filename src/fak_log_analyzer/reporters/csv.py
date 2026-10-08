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
                time_stats.end_time.isoformat() if time_stats.end_time else "",
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
                peak_timestamp.isoformat() if peak_timestamp else "",
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

        performance = result.performance_stats

        if performance and performance.available:
            writer.writerow(
                [
                    "performance",
                    "available",
                    True,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "requests_with_latency",
                    performance.requests_with_latency,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "latency_coverage",
                    performance.latency_coverage,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "min_response_time_ms",
                    performance.min_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "max_response_time_ms",
                    performance.max_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "average_response_time_ms",
                    performance.average_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "median_response_time_ms",
                    performance.median_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "p50_response_time_ms",
                    performance.p50_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "p90_response_time_ms",
                    performance.p90_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "p95_response_time_ms",
                    performance.p95_response_time_ms,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "p99_response_time_ms",
                    performance.p99_response_time_ms,
                ]
            )
        else:
            writer.writerow(
                [
                    "performance",
                    "available",
                    False,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "requests_with_latency",
                    0,
                ]
            )
            writer.writerow(
                [
                    "performance",
                    "latency_coverage",
                    0.0,
                ]
            )

        for path, stats in list(result.path_performance.items())[: config.top_paths]:
            writer.writerow(
                [
                    "latency_path",
                    path,
                    (
                        f"requests={stats.request_count};"
                        f"average_ms={stats.average_ms:.2f};"
                        f"median_ms={stats.median_ms:.2f};"
                        f"p95_ms={stats.p95_ms:.2f};"
                        f"max_ms={stats.max_ms:.2f}"
                    ),
                ]
            )

        statistical = result.statistical_stats

        if statistical is not None:
            writer.writerow(["statistical", "available", statistical.available])

            for name, metric in statistical.metrics.items():
                writer.writerow(
                    [
                        "statistical_metric",
                        name,
                        (
                            f"sample_size={metric.sample_size};"
                            f"mean={metric.mean:.4f};"
                            f"median={metric.median:.4f};"
                            f"standard_deviation={metric.standard_deviation:.4f};"
                            f"q1={metric.q1:.4f};"
                            f"q3={metric.q3:.4f};"
                            f"iqr={metric.iqr:.4f};"
                            f"lower_fence={metric.lower_fence:.4f};"
                            f"upper_fence={metric.upper_fence:.4f}"
                        ),
                    ]
                )

            for anomaly in statistical.anomalies:
                z_score = "" if anomaly.z_score is None else f"{anomaly.z_score:.4f}"

                observation_time = (
                    anomaly.observation_time.isoformat()
                    if anomaly.observation_time
                    else ""
                )

                status_code = (
                    str(anomaly.status_code) if anomaly.status_code is not None else ""
                )

                writer.writerow(
                    [
                        "statistical_anomaly",
                        f"{anomaly.severity}:{anomaly.metric}",
                        (
                            f"scope={anomaly.scope};"
                            f"key={anomaly.key};"
                            f"observed={anomaly.observed:.4f};"
                            f"baseline={anomaly.baseline:.4f};"
                            f"standard_deviation="
                            f"{anomaly.standard_deviation:.4f};"
                            f"z_score={z_score};"
                            f"method={anomaly.method};"
                            f"observation_time={observation_time};"
                            f"path={anomaly.path or ''};"
                            f"ip_address={anomaly.ip_address or ''};"
                            f"status_code={status_code}"
                        ),
                    ]
                )

        security = result.security_stats

        for ip, count in security.authentication_failures_by_ip.most_common(
            config.top_ips
        ):
            writer.writerow(["security_auth_ip", ip, count])

        for path, count in security.authentication_failures_by_path.most_common(
            config.top_paths
        ):
            writer.writerow(["security_auth_path", path, count])

        for ip, count in security.not_found_by_ip.most_common(config.top_ips):
            distinct = security.unique_not_found_paths_by_ip.get(ip, 0)
            writer.writerow(
                [
                    "security_404_ip",
                    ip,
                    f"requests={count};distinct_paths={distinct}",
                ]
            )

        for path, count in security.sensitive_path_counts.most_common(config.top_paths):
            writer.writerow(["security_sensitive_path", path, count])

        for ip, count in security.sensitive_path_ips.most_common(config.top_ips):
            writer.writerow(["security_sensitive_ip", ip, count])

        for ip, (timestamp, count) in sorted(
            security.peak_requests_per_minute_by_ip.items(),
            key=lambda item: item[1][1],
            reverse=True,
        )[: config.top_ips]:
            writer.writerow(
                [
                    "security_request_burst",
                    ip,
                    f"timestamp={timestamp.isoformat()};requests={count}",
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
