"""JSON reporter."""

import json

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
                        result.peak_traffic[0].isoformat()
                        if result.peak_traffic[0]
                        else None
                    ),
                    "requests": result.peak_traffic[1],
                },
                "trend": result.traffic_trend,
            },
            "methods": dict(result.method_counts),
            "status_codes": {
                str(status): count for status, count in result.status_counts.items()
            },
            "top_ips": dict(result.ip_counts.most_common(config.top_ips)),
            "top_paths": dict(result.path_counts.most_common(config.top_paths)),
        }

        return json.dumps(data, indent=2)
