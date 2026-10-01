import random
import time
from datetime import datetime

LOG_FILE = "tests/sample.log"

normal_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "172.16.0.8"]
# Multiple attacker IPs simulating a botnet / distributed DDoS attack
attacker_ips = ["203.0.113.66", "198.51.100.42", "203.0.113.99"]
paths = ["/index.html", "/api/v1/data", "/login", "/about", "/contact"]
methods = ["GET", "POST"]
status_codes = [200, 404, 302, 500]


def generate_log_line(ip, path, method="GET", status=200):
    timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.randint(150, 4096)
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size}\n'


def main():
    print(f"[*] Starting Multi-IP DDoS simulator targeting '{LOG_FILE}'...")
    print("[*] Press Ctrl+C to stop the simulator at any time.\n")

    try:
        while True:
            is_attack = random.choice([True, False])

            if is_attack:
                # Pick a random attacker from our botnet pool
                active_attacker = random.choice(attacker_ips)
                print(f"[!] Simulating DDoS burst from botnet IP: {active_attacker}")
                for _ in range(4):
                    line = generate_log_line(
                        active_attacker, "/login", method="POST", status=401
                    )
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(line)
                    time.sleep(0.2)
            else:
                ip = random.choice(normal_ips)
                path = random.choice(paths)
                status = random.choice(status_codes)
                line = generate_log_line(ip, path, method="GET", status=status)
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(line)
                print(f"[+] Normal traffic: {ip} -> {path}")

            time.sleep(1.5)

    except KeyboardInterrupt:
        print("\n[!] Simulator stopped.")


if __name__ == "__main__":
    main()
