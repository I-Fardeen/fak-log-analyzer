# FAK Log Analyzer

A lightweight Python command-line tool for analyzing web server log files.

FAK Log Analyzer parses Apache/Common Log Format logs and produces useful request, error, traffic, and response-size statistics.

## Features

* Parse Apache/Common Log Format logs
* Count total requests
* Detect malformed log lines
* Analyze HTTP methods
* Analyze HTTP status codes
* Calculate error count and error rate
* Calculate total and average response size
* Identify top IP addresses
* Identify top requested paths
* Limit the number of top IPs and paths displayed
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

### Traffic Analysis

Version 0.3.0 introduces time- and traffic-oriented analysis.

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

### Output Formats

#### Terminal

Designed for human-readable interactive analysis:

```bash
fak-log-analyzer access.log
```

#### JSON

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
```

Traffic data includes both per-minute request counts and peak traffic information.

#### CSV

Designed for spreadsheets, data analysis, and downstream processing:

```bash
fak-log-analyzer access.log --format csv
```

CSV output contains categorized records for summary statistics, time analysis, traffic data, methods, status codes, IP addresses, and requested paths.

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
│       ├── models.py
│       ├── parser.py
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
   ▼
Reporter Factory
   │
   ├── Terminal Reporter
   ├── JSON Reporter
   └── CSV Reporter
```

This reporter-based architecture makes it easier to add new output formats without modifying the core analysis engine.

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
* IP statistics
* Path statistics
* Error-rate calculation
* Response-size calculation
* Empty input
* JSON reporting
* CSV reporting
* Reporter factory behavior

## Roadmap

### v0.3 — Time & Traffic Analytics

- Time-range analysis
- Requests-per-minute and requests-per-hour metrics
- Traffic distribution by minute
- Peak traffic detection
- Traffic trend classification
- Enhanced terminal, JSON, and CSV reporting


### v0.4

* Docker support
* GitHub Actions / CI improvements
* Automated release workflow

### v0.5+

* Time-based request analysis
* Response-time metrics
* Traffic trends
* Anomaly detection
* Security-oriented log analysis
* Suspicious IP/request detection
* Additional log formats

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

FAK Log Analyzer is an open-source project focused on practical log analysis, DevOps tooling, and observability-oriented software engineering.
