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
