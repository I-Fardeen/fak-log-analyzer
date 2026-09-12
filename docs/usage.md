# Usage Guide

## Basic Analysis

Run the analyzer against a log file:

```bash
fak-log-analyzer tests/sample.log
```

The default output format is a Rich terminal report.

## Command-Line Options

### `--top-ips`

Controls how many top IP addresses are displayed.

```bash
fak-log-analyzer tests/sample.log --top-ips 5
```

Default:

```text
10
```

### `--top-paths`

Controls how many top requested paths are displayed.

```bash
fak-log-analyzer tests/sample.log --top-paths 5
```

Default:

```text
10
```

Both options can be used together:

```bash
fak-log-analyzer tests/sample.log --top-ips 5 --top-paths 5
```

## Output Formats

The `--format` option controls how the analysis results are presented.

### Terminal

Terminal output is the default:

```bash
fak-log-analyzer tests/sample.log
```

You can also specify it explicitly:

```bash
fak-log-analyzer tests/sample.log --format terminal
```

The terminal reporter uses Rich for formatted tables and is intended for interactive use.

### JSON

Generate machine-readable JSON:

```bash
fak-log-analyzer tests/sample.log --format json
```

Example:

```json
{
  "summary": {
    "total_requests": 10,
    "malformed_lines": 0,
    "total_bytes": 14308,
    "average_response_size": 1330.8,
    "error_count": 4,
    "error_rate": 40.0
  }
}
```

### CSV

Generate CSV output:

```bash
fak-log-analyzer tests/sample.log --format csv
```

The CSV output uses the following structure:

```text
category,name,value
summary,total_requests,10
summary,malformed_lines,0
summary,total_bytes,14308
```

## Writing Reports to Files

The `--output` option writes JSON or CSV reports to a file.

### JSON

```bash
fak-log-analyzer tests/sample.log \
  --format json \
  --output report.json
```

### CSV

```bash
fak-log-analyzer tests/sample.log \
  --format csv \
  --output report.csv
```

The output file is created or overwritten using UTF-8 encoding.

The terminal format cannot be written using `--output`.

For example:

```bash
fak-log-analyzer tests/sample.log \
  --format terminal \
  --output report.txt
```

will produce a command-line error.

## Analysis Metrics

FAK Log Analyzer currently calculates the following metrics.

### Total Requests

The number of successfully parsed log entries.

### Malformed Lines

The number of non-empty log lines that could not be parsed.

Malformed lines are skipped rather than terminating the analysis.

### Total Response Bytes

The sum of the response sizes reported by all successfully parsed requests.

### Average Response Size

Calculated as:

```text
total response bytes / total requests
```

If the input contains no valid requests, the average response size is `0`.

### Error Count

Responses with HTTP status codes of `400` or greater are counted as errors.

This includes:

* `4xx` client errors
* `5xx` server errors

### Error Rate

Calculated as:

```text
(error count / total requests) × 100
```

If there are no valid requests, the error rate is `0%`.

### HTTP Methods

The analyzer counts requests by HTTP method, such as:

* `GET`
* `POST`
* `PUT`
* `DELETE`

### HTTP Status Codes

The analyzer counts each HTTP status code independently.

Examples:

```text
200
301
400
401
403
404
500
```

### Top IP Addresses

The analyzer identifies the IP addresses responsible for the largest number of requests.

Control the number displayed with:

```bash
--top-ips N
```

### Top Requested Paths

The analyzer identifies the most frequently requested paths.

Control the number displayed with:

```bash
--top-paths N
```

## Supported Log Format

The current parser supports Apache/Common Log Format.

Example:

```text
192.168.1.10 - - [11/Sep/2026:10:15:32 +0530] "GET /index.html HTTP/1.1" 200 1532
```

The parser extracts:

| Field          | Example                      |
| -------------- | ---------------------------- |
| IP address     | `192.168.1.10`               |
| Timestamp      | `11/Sep/2026:10:15:32 +0530` |
| HTTP method    | `GET`                        |
| Requested path | `/index.html`                |
| Protocol       | `HTTP/1.1`                   |
| Status code    | `200`                        |
| Response size  | `1532`                       |

## Malformed Input

Malformed non-empty lines do not terminate the analysis.

For example:

```text
this is not a valid log line
192.168.1.10 - - [invalid timestamp] "GET / HTTP/1.1" 200 100
```

These lines are skipped and included in the `malformed_lines` count.

Blank lines are ignored.

## File Validation

The CLI performs basic input validation before analysis.

It reports an error when:

* The specified log file does not exist.
* The specified path is a directory rather than a file.
* The log file cannot be read because of permissions.
* The log file is not valid UTF-8.

## Combining Options

Options can be combined to create focused reports.

For example:

```bash
fak-log-analyzer tests/sample.log \
  --top-ips 3 \
  --top-paths 5 \
  --format json \
  --output report.json
```

This generates a JSON report containing the top three IP addresses and top five requested paths.

## Development

Install development dependencies:

```bash
pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

Check formatting:

```bash
ruff format --check .
```

Automatically format the project:

```bash
ruff format .
```
