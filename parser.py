import re


def parse_line(line: str) -> dict | None:
    """Parses a single log line into a structured dictionary.

    Expected format example:
    192.168.1.10 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
    """
    pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<endpoint>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d+) (?P<size>\S+)'
    )

    match = pattern.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    try:
        data["status"] = int(data["status"])
        data["size"] = int(data["size"]) if data["size"] != "-" else 0
    except ValueError:
        pass

    return data


def parse_file(filepath: str) -> tuple[list[dict], int]:
    """Parses a log file line by line, returning a list of valid entries

    and the count of malformed or skipped lines.
    """
    valid_entries = []
    malformed_lines = 0

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                parsed = parse_line(line)
                if parsed:
                    valid_entries.append(parsed)
                else:
                    malformed_lines += 1
    except FileNotFoundError:
        print(f"[!] Error: The file '{filepath}' was not found.")
    except Exception as e:
        print(f"[!] Error reading file: {e}")

    return valid_entries, malformed_lines
