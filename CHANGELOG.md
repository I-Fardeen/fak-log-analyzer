# Changelog

All notable changes to FAK Log Analyzer are documented in this file.

The format follows the general principles of [Keep a Changelog](https://keepachangelog.com/).

## [0.5.0] - 2026-09-13

### Added

- Response-time parsing for extended access-log entries.
- Backward-compatible support for standard Common Log Format entries without latency data.
- Overall response-time performance analysis.
- Minimum, maximum, average, median, P50, P90, P95, and P99 latency metrics.
- Latency coverage reporting for logs containing partial response-time data.
- Per-path performance analysis with request count, average, median, P95, and maximum response time.
- Slow endpoint detection based on P95 response time.
- Overall latency findings based on deterministic P95 thresholds.
- Performance analysis in terminal, JSON, and CSV reports.
- Expanded test coverage for latency parsing, performance calculations, threshold boundaries, unavailable latency data, partial coverage, and reporter integration.

### Changed

- Extended the log parser to optionally consume response time in milliseconds.
- Extended `LogEntry` with optional `response_time_ms`.
- Extended `AnalysisResult` with overall and per-path performance information.
- Operational findings now include response-latency intelligence.
- Performance hotspot reports are ordered by P95 latency.

### Notes

- Latency thresholds are heuristic defaults intended for operational triage, not universal performance guarantees.
- Percentiles use linear interpolation.
- Endpoint latency findings require at least two requests for the endpoint.
- Logs without response-time data report performance as unavailable rather than treating latency as zero.

## [0.4.0] - 2026-09-13

### Added

- HTTP status-class analysis for `2xx`, `3xx`, `4xx`, and `5xx` responses.
- Error hotspot analysis by requested path, client IP address, and HTTP status code.
- Automated operational findings with deterministic severity levels:
  - `HIGH`
  - `MEDIUM`
  - `LOW`
  - `INFO`
- Detection of high and elevated HTTP error rates.
- Detection of server-side `5xx` failures.
- Detection of repeated error-producing paths.
- Detection of repeated error-producing client IP addresses.
- Traffic trend findings based on observed request buckets.
- Operational findings in terminal, JSON, and CSV reports.
- Expanded test coverage for status classes, error hotspots, and automated findings.

### Improved

- Terminal reports now include HTTP status classes, error hotspots, and operational findings.
- JSON reports now expose status classes, error hotspots, and structured findings.
- CSV reports now include status-class, error-hotspot, and finding records.
- Analysis results now expose reusable error counters for downstream reporting.
- Project positioning now emphasizes operational intelligence and incident triage.

## [0.3.0] - 2026-09-12

### Added

- Time-based log analysis with start time, end time, and duration.
- Requests-per-minute and requests-per-hour metrics.
- Per-minute traffic distribution.
- Peak traffic detection.
- Traffic trend classification.
- Peak traffic and trend information in terminal, JSON, and CSV reports.

### Improved

- Terminal reports now include peak traffic and traffic trend.
- JSON reports expose structured traffic analytics.
- CSV reports include traffic analytics suitable for further processing.
- Expanded test coverage for time and traffic analysis.

## [0.2.0] - 2026-09-12

### Added

* Configurable number of top IP addresses with `--top-ips`
* Configurable number of top requested paths with `--top-paths`
* JSON output format
* CSV output format
* File output through `--output`
* Reporter abstraction for extensible output formats
* Terminal reporter
* JSON reporter
* CSV reporter
* Reporter factory
* Additional reporter tests
* CLI error handling for:
  * Missing files
  * Directory paths
  * Permission errors
  * Invalid UTF-8 input
* Detailed CLI usage documentation

### Changed

* Replaced the original reporting implementation with the extensible reporter architecture
* Improved CLI output-format handling
* Improved command-line input validation
* Updated tests to use the new reporter architecture
* Expanded project documentation

### Removed

* Legacy `report.py` reporting implementation

## [0.1.0] - Initial Release

### Added

* Apache/Common Log Format parser
* Log entry data model
* Log analysis engine
* Total request statistics
* HTTP method statistics
* HTTP status-code statistics
* IP address statistics
* Requested path statistics
* Error count and error-rate calculation
* Total response-byte calculation
* Average response-size calculation
* Malformed-line detection
* Rich terminal reporting
* Initial unit test suite
* Python package configuration
* CLI entry point
* Development tooling with pytest and Ruff

[0.5.0]: https://github.com/I-Fardeen/fak-log-analyzer/releases/tag/v0.5.0
[0.4.0]: https://github.com/I-Fardeen/fak-log-analyzer/releases/tag/v0.4.0
[0.3.0]: https://github.com/I-Fardeen/fak-log-analyzer/releases/tag/v0.3.0
[0.2.0]: https://github.com/I-Fardeen/fak-log-analyzer/releases/tag/v0.2.0
[0.1.0]: https://github.com/I-Fardeen/fak-log-analyzer/releases/tag/v0.1.0