from dataclasses import dataclass
from enum import Enum

from fak_log_analyzer.models import AnalysisResult
from fak_log_analyzer.security_rules import (
    AUTH_FAILURE_HIGH_THRESHOLD,
    AUTH_FAILURE_MEDIUM_THRESHOLD,
    NOT_FOUND_DISTINCT_PATH_THRESHOLD,
    NOT_FOUND_HIGH_THRESHOLD,
    NOT_FOUND_MEDIUM_THRESHOLD,
    REQUEST_BURST_HIGH_THRESHOLD,
    REQUEST_BURST_MEDIUM_THRESHOLD,
    SENSITIVE_PATH_HIGH_THRESHOLD,
    SENSITIVE_PATH_MEDIUM_THRESHOLD,
)


class Severity(str, Enum):
    """Severity levels for operational findings."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    """Represent an actionable operational finding."""

    severity: Severity
    category: str
    title: str
    message: str


def generate_findings(result: AnalysisResult) -> list[Finding]:
    """Generate deterministic operational findings from analysis results."""

    findings: list[Finding] = []

    if result.total_requests == 0:
        return [
            Finding(
                severity=Severity.INFO,
                category="traffic",
                title="No requests analyzed",
                message=("The log contained no valid requests to analyze."),
            )
        ]

    # ------------------------------------------------------------------
    # Overall error rate
    # ------------------------------------------------------------------

    if result.error_rate >= 50:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                category="errors",
                title="High error rate",
                message=(f"{result.error_rate:.2f}% of requests returned HTTP errors."),
            )
        )
    elif result.error_rate >= 20:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category="errors",
                title="Elevated error rate",
                message=(f"{result.error_rate:.2f}% of requests returned HTTP errors."),
            )
        )
    elif result.error_rate > 0:
        findings.append(
            Finding(
                severity=Severity.LOW,
                category="errors",
                title="HTTP errors detected",
                message=(f"{result.error_rate:.2f}% of requests returned HTTP errors."),
            )
        )
    else:
        findings.append(
            Finding(
                severity=Severity.INFO,
                category="errors",
                title="No HTTP errors detected",
                message=(
                    "All analyzed requests returned successful or non-error responses."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Server-side failures
    # ------------------------------------------------------------------

    server_errors = sum(
        count for status, count in result.status_counts.items() if 500 <= status < 600
    )

    if server_errors:
        server_error_rate = (server_errors / result.total_requests) * 100

        severity = Severity.HIGH if server_error_rate >= 10 else Severity.MEDIUM

        findings.append(
            Finding(
                severity=severity,
                category="server_errors",
                title="Server errors detected",
                message=(
                    f"{server_errors} request(s) returned 5xx responses "
                    f"({server_error_rate:.2f}% of all requests)."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Error path hotspots
    # ------------------------------------------------------------------

    for path, count in result.error_path_counts.most_common():
        if count < 3:
            break

        severity = Severity.HIGH if count >= 5 else Severity.MEDIUM

        findings.append(
            Finding(
                severity=severity,
                category="error_path",
                title="Error hotspot detected",
                message=f"{path} generated {count} HTTP errors.",
            )
        )

    # ------------------------------------------------------------------
    # Error-producing IP hotspots
    # ------------------------------------------------------------------

    for ip, count in result.error_ip_counts.most_common():
        if count < 3:
            break

        severity = Severity.MEDIUM if count < 5 else Severity.HIGH

        findings.append(
            Finding(
                severity=severity,
                category="error_ip",
                title="Error-producing client detected",
                message=f"{ip} generated {count} HTTP errors.",
            )
        )

    # ------------------------------------------------------------------
    # Performance intelligence
    # ------------------------------------------------------------------

    performance = result.performance_stats

    if performance is not None and performance.available:
        p95 = performance.p95_response_time_ms

        if p95 is not None:
            if p95 >= 1000:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="latency",
                        title="High response latency",
                        message=(f"Overall P95 response time is {p95:.2f} ms."),
                    )
                )
            elif p95 >= 500:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="latency",
                        title="Elevated response latency",
                        message=(f"Overall P95 response time is {p95:.2f} ms."),
                    )
                )

        # Endpoint-level latency findings.
        for path, stats in result.path_performance.items():
            # Avoid declaring a single slow request an endpoint-level
            # performance problem.
            if stats.request_count < 2:
                continue

            if stats.p95_ms >= 1000:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        category="latency_path",
                        title="Very slow endpoint detected",
                        message=(
                            f"{path} has a P95 response time of {stats.p95_ms:.2f} ms."
                        ),
                    )
                )
            elif stats.p95_ms >= 500:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="latency_path",
                        title="Slow endpoint detected",
                        message=(
                            f"{path} has a P95 response time of {stats.p95_ms:.2f} ms."
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Security intelligence
    # ------------------------------------------------------------------

    security = result.security_stats

    # Repeated authentication failures are a useful security signal, but
    # the finding deliberately describes the evidence rather than claiming
    # that an attack occurred.
    for ip, count in security.authentication_failures_by_ip.most_common():
        if count < AUTH_FAILURE_MEDIUM_THRESHOLD:
            break

        if count >= AUTH_FAILURE_HIGH_THRESHOLD:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                severity=severity,
                category="security_authentication",
                title="Repeated authentication failures",
                message=(
                    f"{ip} generated {count} HTTP 401 responses, "
                    "which may indicate repeated authentication failures."
                ),
            )
        )

    # A high number of distinct 404 paths from one client is a transparent
    # heuristic for resource/path enumeration.
    for ip, count in security.not_found_by_ip.most_common():
        distinct_paths = security.unique_not_found_paths_by_ip.get(ip, 0)

        if (
            count < NOT_FOUND_MEDIUM_THRESHOLD
            or distinct_paths < NOT_FOUND_DISTINCT_PATH_THRESHOLD
        ):
            continue

        if count >= NOT_FOUND_HIGH_THRESHOLD:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                severity=severity,
                category="security_enumeration",
                title="Potential path enumeration",
                message=(
                    f"{ip} generated {count} HTTP 404 responses across "
                    f"{distinct_paths} distinct paths."
                ),
            )
        )

    # Sensitive paths are configurable in security_rules.py. A match is
    # reported as evidence, not as proof of malicious activity.
    for path, count in security.sensitive_path_counts.most_common():
        if count < SENSITIVE_PATH_MEDIUM_THRESHOLD:
            continue

        severity = (
            Severity.HIGH if count >= SENSITIVE_PATH_HIGH_THRESHOLD else Severity.MEDIUM
        )

        findings.append(
            Finding(
                severity=severity,
                category="security_sensitive_path",
                title="Sensitive path access observed",
                message=(
                    f"{path} was requested {count} time(s) and matches a "
                    "configured sensitive-path rule."
                ),
            )
        )

    # Per-IP request bursts use the same one-minute buckets as the traffic
    # analysis. Statistical anomaly detection is implemented separately
    # so these security heuristics remain transparent and independently
    # interpretable.
    for ip, (timestamp, count) in sorted(
        security.peak_requests_per_minute_by_ip.items(),
        key=lambda item: item[1][1],
        reverse=True,
    ):
        if count < REQUEST_BURST_MEDIUM_THRESHOLD:
            break

        severity = (
            Severity.HIGH if count >= REQUEST_BURST_HIGH_THRESHOLD else Severity.MEDIUM
        )

        findings.append(
            Finding(
                severity=severity,
                category="security_request_burst",
                title="Request burst observed",
                message=(
                    f"{ip} generated {count} requests in the minute "
                    f"starting {timestamp.isoformat()}."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Statistical anomaly intelligence
    # ------------------------------------------------------------------

    statistical = result.statistical_stats

    if statistical is not None and statistical.available:
        for anomaly in statistical.anomalies:
            severity = Severity.HIGH if anomaly.severity == "HIGH" else Severity.MEDIUM

            if anomaly.metric == "requests_per_minute":
                title = "Statistical traffic anomaly"
                description = "request volume in a time bucket"
            elif anomaly.metric == "error_rate_per_minute":
                title = "Statistical error-rate anomaly"
                description = "error rate in a time bucket"
            elif anomaly.metric == "response_time_ms":
                title = "Statistical latency anomaly"
                description = "response time"
            elif anomaly.metric == "requests_per_ip":
                title = "Statistical client-volume anomaly"
                description = "request volume for a client IP"
            else:
                title = "Statistical endpoint-volume anomaly"
                description = "request volume for an endpoint"

            z_score = (
                f"; z-score {anomaly.z_score:.2f}"
                if anomaly.z_score is not None
                else ""
            )

            context_parts = []
            if anomaly.path is not None:
                context_parts.append(f"path {anomaly.path}")
            if anomaly.ip_address is not None:
                context_parts.append(f"IP {anomaly.ip_address}")
            if anomaly.status_code is not None:
                context_parts.append(f"status {anomaly.status_code}")

            context = f" ({', '.join(context_parts)})" if context_parts else ""
            reference = (
                anomaly.observation_time.isoformat()
                if anomaly.observation_time is not None
                else anomaly.key
            )

            findings.append(
                Finding(
                    severity=severity,
                    category="statistical_anomaly",
                    title=title,
                    message=(
                        f"{reference} has an unusual {description}: "
                        f"observed {anomaly.observed:.2f} versus baseline "
                        f"mean {anomaly.baseline:.2f}{context} "
                        f"(method: {anomaly.method}{z_score})."
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Traffic trend
    # ------------------------------------------------------------------

    if result.traffic_trend == "increasing":
        findings.append(
            Finding(
                severity=Severity.INFO,
                category="traffic",
                title="Traffic is increasing",
                message=(
                    "Request volume increased between the first "
                    "and last observed time buckets."
                ),
            )
        )
    elif result.traffic_trend == "decreasing":
        findings.append(
            Finding(
                severity=Severity.INFO,
                category="traffic",
                title="Traffic is decreasing",
                message=(
                    "Request volume decreased between the first "
                    "and last observed time buckets."
                ),
            )
        )

    # ------------------------------------------------------------------
    # Severity ordering
    # ------------------------------------------------------------------

    severity_order = {
        Severity.HIGH: 0,
        Severity.MEDIUM: 1,
        Severity.LOW: 2,
        Severity.INFO: 3,
    }

    return sorted(
        findings,
        key=lambda finding: severity_order[finding.severity],
    )
