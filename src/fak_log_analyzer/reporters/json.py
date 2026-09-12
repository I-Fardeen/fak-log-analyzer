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

        data = {
            "summary": {
                "total_requests": result.total_requests,
                "malformed_lines": result.malformed_lines,
                "total_bytes": result.total_bytes,
                "average_response_size": result.average_response_size,
                "error_count": result.error_count,
                "error_rate": result.error_rate,
            },
            "methods": dict(result.method_counts),
            "status_codes": {
                str(status): count for status, count in result.status_counts.items()
            },
            "top_ips": dict(result.ip_counts.most_common(config.top_ips)),
            "top_paths": dict(result.path_counts.most_common(config.top_paths)),
        }

        return json.dumps(data, indent=2)
