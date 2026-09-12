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

## Usage

### Basic Analysis

Analyze a log file:

```bash
fak-log-analyzer tests/sample.log
```

### Limit Top IP Addresses

```bash
fak-log-analyzer tests/sample.log --top-ips 5
```

### Limit Top Requested Paths

```bash
fak-log-analyzer tests/sample.log --top-paths 5
```

Both options can be used together:

```bash
fak-log-analyzer tests/sample.log --top-ips 5 --top-paths 5
```

## Output Formats

FAK Log Analyzer currently supports three output formats:

| Format     | Terminal | File |
| ---------- | -------: | ---: |
| `terminal` |      Yes |   No |
| `json`     |      Yes |  Yes |
| `csv`      |      Yes |  Yes |

### Terminal

The default format uses Rich to display a readable terminal report:

```bash
fak-log-analyzer tests/sample.log
```

### JSON

Generate JSON output:

```bash
fak-log-analyzer tests/sample.log --format json
```

### CSV

Generate CSV output:

```bash
fak-log-analyzer tests/sample.log --format csv
```

### Save JSON to a File

```bash
fak-log-analyzer tests/sample.log \
  --format json \
  --output report.json
```

### Save CSV to a File

```bash
fak-log-analyzer tests/sample.log \
  --format csv \
  --output report.csv
```

The terminal format cannot currently be written using `--output`.

## Analysis Metrics

The analyzer currently reports:

* Total requests
* Malformed lines
* Total response bytes
* Average response size
* Error count
* Error rate
* HTTP method distribution
* HTTP status-code distribution
* Top IP addresses
* Top requested paths

HTTP responses with status codes `400` and above are counted as errors.

## Supported Log Format

The current parser supports Apache/Common Log Format.

Example:

```text
192.168.1.10 - - [11/Sep/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1532
```

The parser extracts the following fields:

| Field          | Example                      |
| -------------- | ---------------------------- |
| IP address     | `192.168.1.10`               |
| Timestamp      | `11/Sep/2026:10:15:32 +0530` |
| HTTP method    | `GET`                        |
| Requested path | `/index.html`                |
| Protocol       | `HTTP/1.1`                   |
| Status code    | `200`                        |
| Response size  | `1532`                       |

Malformed non-empty lines are skipped and counted in the report.

Blank lines are ignored.

## Example

Given a log file containing:

```text
192.168.1.10 - - [11/Sep/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1532
192.168.1.11 - - [11/Sep/2026:10:15:35 +0530] "GET /style.css HTTP/1.1" 200 821
192.168.1.10 - - [11/Sep/2026:10:15:40 +0530] "GET /missing.html HTTP/1.1" 404 512
```

FAK Log Analyzer parses each request and aggregates the information into a report.

Example terminal output:

```text
Summary
────────────────────────────────
Total requests             3
Malformed lines            0
Total response bytes       2,865
Average response size      955.00 bytes
Error count                1
Error rate                 33.33%
```

## Command-Line Reference

```text
usage: fak-log-analyzer [-h] [--top-ips TOP_IPS] [--top-paths TOP_PATHS]
                        [--format {terminal,json,csv}] [--output OUTPUT]
                        logfile
```

### Arguments

| Argument          | Description                                 |
| ----------------- | ------------------------------------------- |
| `logfile`         | Path to the log file to analyze             |
| `--top-ips N`     | Number of top IP addresses to display       |
| `--top-paths N`   | Number of top requested paths to display    |
| `--format FORMAT` | Output format: `terminal`, `json`, or `csv` |
| `--output FILE`   | Write JSON or CSV output to a file          |

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
