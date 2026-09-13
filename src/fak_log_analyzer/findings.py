"""Operational findings for FAK Log Analyzer."""

from dataclasses import dataclass
from enum import Enum

from fak_log_analyzer.models import AnalysisResult


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
