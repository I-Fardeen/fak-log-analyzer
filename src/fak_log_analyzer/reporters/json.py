"""JSON reporter."""

import json

from fak_log_analyzer.findings import generate_findings
from fak_log_analyzer.models import AnalysisResult, ReportConfig
from fak_log_analyzer.reporters.base import Reporter


class JsonReporter(Reporter):
    """Render analysis results as JSON."""

    def render(
        self,
        result: AnalysisResult,
        config: ReportConfig,
    ) -> str:
        """Render the analysis result as JSON."""

        time_stats = result.time_stats
        peak_timestamp, peak_requests = result.peak_traffic
        performance = result.performance_stats

        if performance and performance.available:
            performance_data = {
                "available": True,
                "requests_with_latency": performance.requests_with_latency,
                "latency_coverage": performance.latency_coverage,
                "min_response_time_ms": (performance.min_response_time_ms),
                "max_response_time_ms": (performance.max_response_time_ms),
                "average_response_time_ms": (performance.average_response_time_ms),
                "median_response_time_ms": (performance.median_response_time_ms),
                "p50_response_time_ms": (performance.p50_response_time_ms),
                "p90_response_time_ms": (performance.p90_response_time_ms),
                "p95_response_time_ms": (performance.p95_response_time_ms),
                "p99_response_time_ms": (performance.p99_response_time_ms),
            }
        else:
            performance_data = {
                "available": False,
                "requests_with_latency": 0,
                "latency_coverage": 0.0,
                "min_response_time_ms": None,
                "max_response_time_ms": None,
                "average_response_time_ms": None,
                "median_response_time_ms": None,
                "p50_response_time_ms": None,
                "p90_response_time_ms": None,
                "p95_response_time_ms": None,
                "p99_response_time_ms": None,
            }

        path_performance = {
            path: {
                "requests": stats.request_count,
                "average_ms": stats.average_ms,
                "median_ms": stats.median_ms,
                "p95_ms": stats.p95_ms,
                "max_ms": stats.max_ms,
            }
            for path, stats in list(result.path_performance.items())[: config.top_paths]
        }

        statistical = result.statistical_stats
        if statistical is not None:
            statistical_data = {
                "available": statistical.available,
                "metrics": {
                    name: {
                        "sample_size": metric.sample_size,
                        "mean": metric.mean,
                        "median": metric.median,
                        "standard_deviation": metric.standard_deviation,
                        "q1": metric.q1,
                        "q3": metric.q3,
                        "iqr": metric.iqr,
                        "lower_fence": metric.lower_fence,
                        "upper_fence": metric.upper_fence,
                    }
                    for name, metric in statistical.metrics.items()
                },
                "anomalies": [
                    {
                        "metric": anomaly.metric,
                        "scope": anomaly.scope,
                        "key": anomaly.key,
                        "observed": anomaly.observed,
                        "baseline": anomaly.baseline,
                        "standard_deviation": anomaly.standard_deviation,
                        "z_score": anomaly.z_score,
                        "lower_fence": anomaly.lower_fence,
                        "upper_fence": anomaly.upper_fence,
                        "method": anomaly.method,
                        "severity": anomaly.severity,
                        "observation_time": (
                            anomaly.observation_time.isoformat()
                            if anomaly.observation_time
                            else None
                        ),
                        "path": anomaly.path,
                        "ip_address": anomaly.ip_address,
                        "status_code": anomaly.status_code,
                    }
                    for anomaly in statistical.anomalies
                ],
            }
        else:
            statistical_data = {
                "available": False,
                "metrics": {},
                "anomalies": [],
            }

        security = result.security_stats

        security_data = {
            "authentication_failures": {
                "by_ip": dict(
                    security.authentication_failures_by_ip.most_common(config.top_ips)
                ),
                "by_path": dict(
                    security.authentication_failures_by_path.most_common(
                        config.top_paths
                    )
                ),
            },
            "not_found": {
                "by_ip": dict(security.not_found_by_ip.most_common(config.top_ips)),
                "unique_paths_by_ip": dict(
                    sorted(
                        security.unique_not_found_paths_by_ip.items(),
                        key=lambda item: item[1],
                        reverse=True,
                    )[: config.top_ips]
                ),
            },
            "sensitive_paths": {
                "paths": dict(
                    security.sensitive_path_counts.most_common(config.top_paths)
                ),
                "ips": dict(security.sensitive_path_ips.most_common(config.top_ips)),
            },
            "request_bursts": [
                {
                    "ip": ip,
                    "timestamp": timestamp.isoformat(),
                    "requests": count,
                }
                for ip, (timestamp, count) in sorted(
                    security.peak_requests_per_minute_by_ip.items(),
                    key=lambda item: item[1][1],
                    reverse=True,
                )[: config.top_ips]
            ],
        }

        data = {
            "summary": {
                "total_requests": result.total_requests,
                "malformed_lines": result.malformed_lines,
                "total_bytes": result.total_bytes,
                "average_response_size": result.average_response_size,
                "error_count": result.error_count,
                "error_rate": result.error_rate,
            },
            "time": {
                "start_time": (
                    time_stats.start_time.isoformat() if time_stats.start_time else None
                ),
                "end_time": (
                    time_stats.end_time.isoformat() if time_stats.end_time else None
                ),
                "duration_seconds": time_stats.duration_seconds,
                "requests_per_minute": time_stats.requests_per_minute,
                "requests_per_hour": time_stats.requests_per_hour,
            },
            "traffic": {
                "requests_per_minute": {
                    timestamp.isoformat(): count
                    for timestamp, count in result.requests_per_minute.items()
                },
                "peak": {
                    "timestamp": (
                        peak_timestamp.isoformat() if peak_timestamp else None
                    ),
                    "requests": peak_requests,
                },
                "trend": result.traffic_trend,
            },
            "performance": performance_data,
            "performance_hotspots": path_performance,
            "statistical_anomalies": statistical_data,
            "security": security_data,
            "methods": dict(result.method_counts),
            "status_codes": {
                str(status): count for status, count in result.status_counts.items()
            },
            "status_classes": dict(result.status_class_counts),
            "top_ips": dict(result.ip_counts.most_common(config.top_ips)),
            "top_paths": dict(result.path_counts.most_common(config.top_paths)),
            "error_hotspots": {
                "paths": dict(result.error_path_counts.most_common(config.top_paths)),
                "ips": dict(result.error_ip_counts.most_common(config.top_ips)),
                "status_codes": {
                    str(status): count
                    for status, count in result.error_status_counts.items()
                },
            },
            "findings": [
                {
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "title": finding.title,
                    "message": finding.message,
                }
                for finding in generate_findings(result)
            ],
        }

        return json.dumps(data, indent=2)
