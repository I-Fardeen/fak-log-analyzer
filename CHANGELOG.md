# Changelog

All notable changes to FAK Log Analyzer are documented in this file.

The format follows the general principles of [Keep a Changelog](https://keepachangelog.com/).

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

[0.2.0]: https://github.com/<username>/fak-log-analyzer/releases/tag/v0.2.0
[0.1.0]: https://github.com/<username>/fak-log-analyzer/releases/tag/v0.1.0
