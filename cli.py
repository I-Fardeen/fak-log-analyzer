import sys
import time
from collections import defaultdict, deque
from datetime import datetime

def run_live_terminal_monitor(log_file, threshold=3, window_seconds=10):
    print("==================================================")
    print("       DDOS ATTACK MONITOR (Active Threats)       ")
    print("==================================================")
    print(f"  IP ADDRESS      | LAST LOGIN TIME     | REQUESTS | WINDOW")
    print("------------------+---------------------+----------+--------")
    
    # Track requests per IP within a sliding time window
    ip_tracker = defaultdict(deque)

    print("\n[+] Live traffic feed (Press Ctrl+C to stop)...")

    with open(log_file, "r", encoding="utf-8") as f:
        # Move pointer to end of file to read live incoming appends
        f.seek(0, 2)
        
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    continue

                line_str = line.strip()
                if not line_str:
                    continue

                now = datetime.now()
                now_str = now.strftime("%Y-%m-%d %H:%M:%S")

                # Parse basic info (or call your existing parse_line function)
                # Example expectation: line contains IP and endpoint path
                parsed = parse_single_line(line_str)  # Adjust to your parser
                
                if parsed:
                    ip = parsed.get("ip", "UNKNOWN")
                    path = parsed.get("path", "/")

                    # Track window requests
                    ip_tracker[ip].append(now)
                    # Remove timestamps outside the sliding window
                    while ip_tracker[ip] and (now - ip_tracker[ip][0]).total_seconds() > window_seconds:
                        ip_tracker[ip].popleft()

                    request_count = len(ip_tracker[ip])

                    # Flag DDoS or print normal traffic feed
                    if request_count >= threshold:
                        print(f"[!] DDoS burst from botnet IP: {ip}")
                        print(f"    {ip} | {now_str} | {request_count} | {window_seconds}s")
                    else:
                        print(f"[+] Normal traffic: {ip} -> {path}")

                sys.stdout.flush()

        except KeyboardInterrupt:
            print("\n[*] Stopped live traffic monitor.")
