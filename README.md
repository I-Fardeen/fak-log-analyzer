# FAK Log Analyzer

A lightweight Python command-line tool for analyzing web server log files.

FAK Log Analyzer parses Apache/Common Log Format logs and produces useful request, error, traffic, response-size, and performance statistics.

[![Tests](https://github.com/I-Fardeen/fak-log-analyzer/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/I-Fardeen/fak-log-analyzer/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Release](https://img.shields.io/github/v/release/I-Fardeen/fak-log-analyzer)](https://github.com/I-Fardeen/fak-log-analyzer/releases)
[![License](https://img.shields.io/github/license/I-Fardeen/fak-log-analyzer)](https://github.com/I-Fardeen/fak-log-analyzer/blob/master/LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22735054-blue)](https://doi.org/10.5281/zenodo.22735054)

## Features

* Parse Apache/Common Log Format logs
* Parse extended access-log entries with response-time data
* Count total requests
* Detect malformed log lines
* Analyze HTTP methods
* Analyze HTTP status codes
* Classify HTTP status codes into `2xx`, `3xx`, `4xx`, and `5xx`
* Calculate error count and error rate
* Calculate total and average response size
* Identify top IP addresses
* Identify top requested paths
* Limit the number of top IPs and paths displayed
* Analyze log time ranges
* Calculate requests per minute and requests per hour
* Identify peak traffic
* Classify traffic trends
* Identify error hotspots by path
* Identify error-producing client IP addresses
* Identify server-side `5xx` failures
* Generate deterministic operational findings
* Analyze overall response-time performance
* Calculate minimum, maximum, average, median, P50, P90, P95, and P99 latency
* Calculate latency coverage for partial performance data
* Identify performance hotspots by requested path
* Detect slow endpoints using P95 response time
* Terminal reports with Rich
* JSON output
* CSV output
* Save JSON or CSV reports to files
* Clean command-line error handling

## Requirements

* Python 3.11 or newer

## Installation

Clone the repository and install it:

```bash
git clone https://github.com/I-Fardeen/fak-log-analyzer.git
cd fak-log-analyzer
pip install -e .
````

For development:

```bash
pip install -e ".[dev]"
```

## Command-Line Usage

FAK Log Analyzer is designed as a lightweight command-line tool for analyzing web server access logs.

### Basic Usage

```bash
fak-log-analyzer <logfile>
```

Example:

```bash
fak-log-analyzer tests/sample.log
```

By default, the analyzer displays a human-readable terminal report containing:

* Total requests
* Malformed log lines
* Total response bytes
* Average response size
* HTTP error count
* HTTP error rate
* Log start and end time
* Analysis duration
* Requests per minute
* Requests per hour
* Peak traffic
* Traffic trend
* HTTP method distribution
* HTTP status-code distribution
* Top IP addresses
* Top requested paths
* Overall response-time performance
* Performance hotspots
* Operational findings

### Command-Line Options

```text
usage: fak-log-analyzer [-h] [--top-ips TOP_IPS] [--top-paths TOP_PATHS]
                        [--format {terminal,json,csv}] [--output OUTPUT]
                        logfile
```

#### Positional Arguments

| Argument  | Description                                |
| --------- | ------------------------------------------ |
| `logfile` | Path to the web server log file to analyze |

#### Options

| Option            | Description                                                   | Default    |
| ----------------- | ------------------------------------------------------------- | ---------- |
| `-h`, `--help`    | Show the command-line help message                            | —          |
| `--top-ips N`     | Display the top N IP addresses                                | `10`       |
| `--top-paths N`   | Display the top N requested paths                             | `10`       |
| `--format FORMAT` | Select the output format: `terminal`, `json`, or `csv`        | `terminal` |
| `--output FILE`   | Write JSON or CSV output to a file instead of standard output | —          |

### Examples

#### Analyze a log file

```bash
fak-log-analyzer access.log
```

#### Show the top 5 IP addresses

```bash
fak-log-analyzer access.log --top-ips 5
```

#### Show the top 20 requested paths

```bash
fak-log-analyzer access.log --top-paths 20
```

#### Generate JSON output

```bash
fak-log-analyzer access.log --format json
```

#### Generate CSV output

```bash
fak-log-analyzer access.log --format csv
```

#### Save a JSON report

```bash
fak-log-analyzer access.log \
    --format json \
    --output report.json
```

#### Save a CSV report

```bash
fak-log-analyzer access.log \
    --format csv \
    --output report.csv
```

> **Note:** The terminal format is intended for interactive display and cannot be written to a file using `--output`. Use JSON or CSV when a report needs to be saved or processed by another tool.

## Supported Log Formats

### Standard Common Log Format

FAK Log Analyzer supports standard Apache/Common Log Format entries:

```text
127.0.0.1 - - [13/Sep/2026:10:15:01 +0530] "GET /api/users HTTP/1.1" 200 1234
```

For standard CLF entries, response-time information is unavailable.

### Extended Timed Access Logs

Version 0.5.0 adds support for an optional response-time field:

```text
127.0.0.1 - - [13/Sep/2026:10:15:01 +0530] "GET /api/users HTTP/1.1" 200 1234 125
```

The final value represents **response time in milliseconds**.

Decimal response times are also supported:

```text
127.0.0.1 - - [13/Sep/2026:10:15:01 +0530] "GET /api/search HTTP/1.1" 200 2048 125.5
```

Response-time data is optional. Standard CLF entries remain fully supported and are represented with unavailable latency rather than zero.

## Traffic Analysis

Version 0.3.0 introduced time- and traffic-oriented analysis.

The analyzer groups requests into one-minute buckets and reports the resulting traffic distribution:

```text
10:15 → 3 requests
10:16 → 3 requests
10:17 → 3 requests
10:18 → 1 request
```

It also identifies the busiest minute:

```text
Peak traffic → 3 requests at 2026-09-11 10:15
```

and classifies the overall traffic trend as:

* `increasing`
* `decreasing`
* `stable`

These traffic metrics are available through the terminal, JSON, and CSV reporters.

## Performance Intelligence

Version 0.5.0 introduces response-time analysis for extended access logs.

### Overall Performance Metrics

When response-time data is available, FAK Log Analyzer calculates:

* Minimum response time
* Maximum response time
* Average response time
* Median response time
* P50
* P90
* P95
* P99
* Requests with latency data
* Latency coverage

Percentiles use linear interpolation.

### Latency Coverage

Logs may contain response-time data for only some requests.

For example:

```text
Requests with latency → 50
Latency coverage      → 50.00%
```

This allows partially instrumented logs to remain useful for performance analysis.

When no response-time data is available, performance is reported as unavailable rather than treating latency as `0 ms`.

### Performance Hotspots

Performance statistics are calculated per requested path:

* Request count
* Average response time
* Median response time
* P95 response time
* Maximum response time

Performance hotspots are ordered by P95 latency.

### Automated Latency Findings

Latency findings use deterministic P95-based thresholds:

| P95 response time | Severity           |
| ----------------- | ------------------ |
| `< 500 ms`        | No latency finding |
| `>= 500 ms`       | MEDIUM             |
| `>= 1000 ms`      | HIGH               |

Endpoint latency findings require at least two requests for an endpoint.

> **Note:** These thresholds are heuristic defaults intended for operational triage, not universal performance guarantees.

## Operational Intelligence

Version 0.4.0 introduced an operational-intelligence layer on top of the core log statistics. Version 0.5.0 extends this layer with response-time intelligence.

The analyzer generates deterministic findings from observed log patterns.

Current findings include:

* High HTTP error rates
* Elevated HTTP error rates
* Server-side `5xx` failures
* Repeated error-producing paths
* Repeated error-producing client IP addresses
* Increasing traffic
* Decreasing traffic
* High overall response latency
* Slow endpoints

Findings are assigned one of four severity levels:

```text
HIGH
MEDIUM
LOW
INFO
```

The finding engine is deterministic: the same input data produces the same findings.

## Error Analysis

HTTP responses with status codes in the `4xx` and `5xx` ranges are treated as HTTP errors.

The analyzer provides:

* Overall error rate
* Error counts by status code
* Error counts by path
* Error counts by client IP
* Server-side `5xx` counts

Repeated error sources are surfaced as operational findings.

## Output Formats

### Terminal

Designed for human-readable interactive analysis:

```bash
fak-log-analyzer access.log
```

The terminal report includes:

* Summary statistics
* Time and traffic analysis
* HTTP status information
* Top IP addresses
* Top requested paths
* Error hotspots
* Performance analysis
* Performance hotspots
* Operational findings

### JSON

Designed for APIs, automation, scripting, and machine processing:

```bash
fak-log-analyzer access.log --format json
```

The JSON report contains structured sections for:

```text
summary
time
traffic
methods
status_codes
top_ips
top_paths
errors
performance
performance_hotspots
findings
```

Traffic data includes per-minute request counts and peak traffic information.

Performance data includes overall response-time statistics and latency coverage when available.

Performance hotspots contain per-path response-time statistics ordered by P95 latency.

### CSV

Designed for spreadsheets, data analysis, and downstream processing:

```bash
fak-log-analyzer access.log --format csv
```

CSV output contains categorized records for:

* Summary statistics
* Time analysis
* Traffic data
* HTTP methods
* Status codes
* IP addresses
* Requested paths
* Error hotspots
* Performance statistics
* Per-path performance
* Operational findings

## Project Structure

```text
fak-log-analyzer/
├── .github/
│   └── workflows/
│       └── tests.yml
├── src/
│   └── fak_log_analyzer/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── cli.py
│       ├── findings.py
│       ├── models.py
│       ├── parser.py
│       ├── performance_analysis.py
│       ├── time_analysis.py
│       └── reporters/
│           ├── __init__.py
│           ├── base.py
│           ├── csv.py
│           ├── json.py
│           └── terminal.py
├── tests/
│   ├── sample.log
│   ├── test_analyzer.py
│   ├── test_error_hotspots.py
│   ├── test_findings.py
│   ├── test_parser.py
│   ├── test_performance_analysis.py
│   ├── test_performance_findings.py
│   ├── test_performance_integration.py
│   ├── test_performance_parser.py
│   ├── test_report.py
│   ├── test_reporters.py
│   └── test_time_analysis.py
├── docs/
│   └── usage.md
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
└── pyproject.toml
```

## Architecture

The application is organized into several layers:

```text
Log File
   │
   ▼
Parser
   │
   ▼
LogEntry Models
   │
   ▼
Analyzer
   │
   ├── Time Analysis
   │
   ├── Error Analysis
   │
   └── Performance Analysis
   │
   ▼
AnalysisResult
   │
   ▼
Operational Findings
   │
   ▼
Reporter Factory
   │
   ├── Terminal Reporter
   ├── JSON Reporter
   └── CSV Reporter
```

The parser converts raw log lines into structured `LogEntry` objects.

The analyzer transforms parsed entries into an `AnalysisResult` containing aggregated request, status, traffic, error, and performance information.

The findings layer derives deterministic operational intelligence from the analysis results.

The reporter-based architecture makes it easier to add new output formats without modifying the core analysis engine.

## Development

Install the development dependencies:

```bash
pip install -e ".[dev]"
```

Run the complete test suite:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

Check code formatting:

```bash
ruff format --check .
```

Format the code:

```bash
ruff format .
```

## Testing

The project includes **67 tests** covering:

* Log parsing
* Standard Common Log Format parsing
* Extended response-time parsing
* Invalid and malformed input
* File parsing
* Request statistics
* HTTP status statistics
* HTTP status classes
* IP statistics
* Path statistics
* Error-rate calculation
* Error hotspots
* Response-size calculation
* Empty input
* Time analysis
* Traffic analysis
* Traffic trend classification
* Performance statistics
* Percentile calculations
* Latency coverage
* Per-path performance analysis
* Performance threshold boundaries
* Performance findings
* Performance reporter integration
* JSON reporting
* CSV reporting
* Reporter factory behavior

Run all tests with:

```bash
pytest
```

## Roadmap

### v0.3 — Time & Traffic Analytics

* Time-range analysis
* Requests-per-minute and requests-per-hour metrics
* Traffic distribution by minute
* Peak traffic detection
* Traffic trend classification
* Enhanced terminal, JSON, and CSV reporting

### v0.4 — Operational Intelligence

* HTTP status-class analysis
* Error hotspot analysis
* Operational findings
* Deterministic severity classification
* Server-side failure detection
* Error-producing client detection
* Traffic trend findings
* Enhanced terminal, JSON, and CSV reporting

### v0.5 — Performance Intelligence

* Response-time parsing
* Overall latency statistics
* Median and percentile analysis
* P50, P90, P95, and P99 metrics
* Latency coverage reporting
* Per-path performance analysis
* Performance hotspots
* Slow endpoint detection
* P95-based latency findings
* Performance reporting across terminal, JSON, and CSV formats

### v0.6 — Security Intelligence

* Security-oriented log analysis
* Suspicious request detection
* Suspicious IP detection
* Authentication failure analysis
* Potential scanning and probing detection
* Security-oriented operational findings

### v0.7 — Statistical Anomaly Detection

* Statistical traffic anomaly detection
* Latency anomaly detection
* Error-rate anomaly detection
* Baseline-based analysis
* Outlier identification

### v0.8 — Incident Correlation

* Cross-signal correlation
* Error and latency correlation
* Traffic and performance correlation
* Incident-oriented findings
* Improved operational triage

### v0.9 — Format Expansion

* Additional access-log formats
* Configurable parsing
* Expanded timestamp handling
* Additional web-server log formats

### v1.0 — Production Release

* Stable Python API
* Stable CLI behavior
* Strong automated test coverage
* Documented input formats
* Predictable output schemas
* Semantic versioning
* Formal release process
* Performance benchmarks
* Security review
* Contribution documentation

## Contributing

Contributions are welcome.

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and contribution instructions.

## Security

For security-related issues, please see [SECURITY.md](SECURITY.md).

Please do not publicly disclose sensitive security vulnerabilities before they can be responsibly addressed.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Citation

If you use **FAK Log Analyzer** in your research, teaching, software project, or other work, please cite the software.

### Recommended Citation

Khan, F. A. (2026). *FAK Log Analyzer* (Version 0.5.1) [Computer software]. Zenodo.  
https://doi.org/10.5281/zenodo.22735054

### BibTeX

```bibtex
@software{khan_fak_log_analyzer_2026,
  author       = {Fardeen Ahmad Khan},
  title        = {FAK Log Analyzer},
  year         = {2026},
  version      = {0.5.1},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.22735054},
  url          = {https://doi.org/10.5281/zenodo.22735054},
  license      = {MIT}
}
````

### APA

Khan, F. A. (2026). *FAK Log Analyzer* (Version 0.5.1) [Computer software]. Zenodo.
[https://doi.org/10.5281/zenodo.22735054](https://doi.org/10.5281/zenodo.22735054)

### IEEE

F. A. Khan, “FAK Log Analyzer,” version 0.5.1, Zenodo, 2026. [Online]. Available:
[https://doi.org/10.5281/zenodo.22735054](https://doi.org/10.5281/zenodo.22735054)

### Harvard

Khan, F.A., 2026. *FAK Log Analyzer*, version 0.5.1. Zenodo. Available at:
[https://doi.org/10.5281/zenodo.22735054](https://doi.org/10.5281/zenodo.22735054)

### Plain Text

Fardeen Ahmad Khan. FAK Log Analyzer. Version 0.5.1. 2026.
Zenodo. DOI: 10.5281/zenodo.22735054

### RIS

```text
TY  - COMP
AU  - Khan, Fardeen Ahmad
TI  - FAK Log Analyzer
PY  - 2026
DA  - 2026-09-13
ET  - 0.5.1
PB  - Zenodo
DO  - 10.5281/zenodo.22735054
UR  - https://doi.org/10.5281/zenodo.22735054
LA  - en
ER  -
```

### Software Identity

**Author:** Fardeen Ahmad Khan
**Affiliation:** MJP Rohilkhand University
**ORCID:** [https://orcid.org/0009-0004-8726-6836](https://orcid.org/0009-0004-8726-6836)
**GitHub:** [https://github.com/I-Fardeen/fak-log-analyzer](https://github.com/I-Fardeen/fak-log-analyzer)
**DOI:** [https://doi.org/10.5281/zenodo.22735054](https://doi.org/10.5281/zenodo.22735054)

### Version-Specific Citation

The DOI above identifies the archived **v0.5.1** release. When citing results or research based on a specific software version, use the DOI associated with that version.

For the latest version of the software, refer to the project's GitHub repository:

[https://github.com/I-Fardeen/fak-log-analyzer](https://github.com/I-Fardeen/fak-log-analyzer)

FAK Log Analyzer is an open-source project focused on practical log analysis, DevOps tooling, observability, operational intelligence, and performance-oriented software engineering.
