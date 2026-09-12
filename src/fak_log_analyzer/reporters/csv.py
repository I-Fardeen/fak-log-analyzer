"""CSV reporter."""

import csv
import io

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

        for method, count in result.method_counts.most_common():
            writer.writerow(["method", method, count])

        for status, count in sorted(result.status_counts.items()):
            writer.writerow(["status", status, count])

        for ip, count in result.ip_counts.most_common(config.top_ips):
            writer.writerow(["ip", ip, count])

        for path, count in result.path_counts.most_common(config.top_paths):
            writer.writerow(["path", path, count])

        return output.getvalue()
