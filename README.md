# FAK Log Analyzer

A lightweight Python command-line tool for analyzing web server log files.

FAK Log Analyzer parses Apache/Common Log Format logs and produces useful request, error, traffic, response-size, and operational-intelligence statistics for lightweight incident triage.

## Features

* Parse Apache/Common Log Format logs
* Count total requests
* Detect malformed log lines
* Analyze HTTP methods
* Analyze HTTP status codes
* Classify HTTP status codes into `2xx`, `3xx`, `4xx`, and `5xx`
* Calculate error count and error rate
* Identify server-side `5xx` failures
* Identify error hotspots by requested path
* Identify error-producing client IP addresses
* Calculate total and average response size
* Identify top IP addresses
* Identify top requested paths
* Analyze traffic over time
* Calculate requests per minute and requests per hour
* Detect peak traffic
* Classify traffic trends
* Generate automated operational findings with severity levels
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
git clone <repository-url>
cd fak-log-analyzer
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Command-Line Usage

FAK Log Analyzer is designed as a lightweight command-line tool for analyzing web server access logs and identifying useful operational signals without requiring external infrastructure.

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
* HTTP status-class distribution
* Error hotspots
* Automated operational findings
* Top IP addresses
* Top requested paths

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

## Operational Intelligence

Version 0.4.0 introduces an operational-intelligence layer on top of the core log statistics.

### HTTP Status Classes

Responses are grouped into standard HTTP status classes:

* `2xx` — successful responses
* `3xx` — redirects
* `4xx` — client errors
* `5xx` — server errors

This provides a higher-level view of application behavior than individual status-code counts alone.

### Error Hotspots

The analyzer identifies where HTTP errors are concentrated by reporting:

* Requested paths producing repeated errors
* Client IP addresses producing repeated errors
* Individual error status codes

This helps narrow an investigation toward the most problematic endpoint or client.

### Automated Findings

The findings engine applies deterministic rules to the analysis result and produces structured operational findings.

Examples include:

* High or elevated overall error rates
* Significant `5xx` server-side failures
* Repeated errors on a specific path
* Repeated errors from a specific client IP
* Increasing or decreasing request volume

Each finding contains:

* Severity
* Category
* Title
* Operational message

Findings are ordered by severity so the most important signals appear first.

The rules are intentionally deterministic and transparent. They are designed to assist incident triage rather than replace a full monitoring or observability platform.

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

## Output Formats

### Terminal

Designed for human-readable interactive analysis:

```bash
fak-log-analyzer access.log
```

The terminal report includes summary statistics, time analysis, traffic distribution, HTTP methods, status codes and classes, error hotspots, operational findings, top IP addresses, and top requested paths.

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
status_classes
top_ips
top_paths
error_hotspots
findings
```

### CSV

Designed for spreadsheets, data analysis, and downstream processing:

```bash
fak-log-analyzer access.log --format csv
```

CSV output contains categorized records for summary statistics, time analysis, traffic data, methods, status codes and classes, IP addresses, requested paths, error hotspots, and operational findings.

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
│       ├── time_analysis.py
│       └── reporters/
│           ├── __init__.py
│           ├── base.py
│           ├── csv.py
│           ├── json.py
│           └── terminal.py
├── tests/
├── docs/
├── .env.example
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
   ▼
AnalysisResult
   │
   ├── Time & Traffic Analysis
   │
   ├── Error Hotspot Analysis
   │
   └── Operational Findings
   │
   ▼
Reporter Factory
   │
   ├── Terminal Reporter
   ├── JSON Reporter
   └── CSV Reporter
```

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

The project includes unit tests covering:

* Log parsing
* Invalid and malformed input
* File parsing
* Request statistics
* HTTP status statistics
* HTTP status classes
* IP statistics
* Path statistics
* Error-rate calculation
* Error hotspots
* Automated operational findings
* Response-size calculation
* Time and traffic analysis
* Peak traffic detection
* Traffic trend classification
* Empty input
* JSON reporting
* CSV reporting
* Reporter factory behavior

The current test suite contains **43 tests**.

## Roadmap

### v0.1 — Core Log Analysis

* Common Log Format parsing
* Request, status, IP, path, error, and response-size statistics
* Rich terminal reporting

### v0.2 — Reporting Architecture

* Configurable top IP/path output
* JSON and CSV reporters
* File output
* Extensible reporter architecture
* Improved CLI validation

### v0.3 — Time & Traffic Analytics

* Time-range analysis
* Requests-per-minute and requests-per-hour metrics
* Traffic distribution by minute
* Peak traffic detection
* Traffic trend classification
* Enhanced terminal, JSON, and CSV reporting

### v0.4 — Operational Intelligence

* HTTP status-class analysis
* Error hotspot detection
* Error analysis by path, client IP, and status code
* Automated operational findings
* Severity-based findings
* Operational findings in terminal, JSON, and CSV reports
* Expanded automated test coverage

### v0.5+

* Response-time metrics
* More advanced anomaly detection
* Security-oriented log analysis
* Suspicious IP/request detection
* Additional log formats
* Further incident-triage capabilities

## Contributing

Contributions are welcome.

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and contribution instructions.

## Security

For security-related issues, please see [SECURITY.md](SECURITY.md).

Please do not publicly disclose sensitive security vulnerabilities before they can be responsibly addressed.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Author

**Fardeen Ahmad Khan**

---

FAK Log Analyzer is an open-source project focused on practical log analysis, DevOps tooling, operational intelligence, and observability-oriented software engineering.
