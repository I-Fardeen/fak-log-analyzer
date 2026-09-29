import time
from collections import defaultdict, deque
from datetime import datetime
from fak_log_analyzer.parser import parse_line

class LiveMonitor:
    def __init__(self, log_path, request_threshold=50, time_window=10, alert_callback=None):
        self.log_path = log_path
        self.request_threshold = request_threshold  
        self.time_window = time_window              
        self.alert_callback = alert_callback
        self.ip_history = defaultdict(deque)

    def start(self):
        print(f"[*] Starting live monitoring on {self.log_path}...")
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                # Move to the end of the file to read only new live logs
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    
                    entry = parse_line(line.strip())
                    if entry:
                        self._analyze_entry(entry)
        except KeyboardInterrupt:
            print("\n[!] Live monitoring stopped by user.")

    def _analyze_entry(self, entry):
        # Use ip_address property from your LogEntry model
        ip = getattr(entry, "ip_address", None)
        current_time = time.time()
        
        if not ip:
            return

        # Track timestamps for this IP
        timestamps = self.ip_history[ip]
        timestamps.append(current_time)

        # Remove timestamps outside the sliding window
        while timestamps and current_time - timestamps[0] > self.time_window:
            timestamps.popleft()

        # Check for DoS / DDoS threshold breach
        if len(timestamps) >= self.request_threshold:
            alert_data = {
                "timestamp": datetime.now().isoformat(),
                "severity": "HIGH",
                "threat_type": "Potential DoS / DDoS Attack",
                "source_ip": ip,
                "request_count": len(timestamps),
                "window_seconds": self.time_window
            }
            if self.alert_callback:
                self.alert_callback(alert_data)
            else:
                print(f"[ALERT] DDoS/DoS detected from IP {ip}: {len(timestamps)} requests in {self.time_window}s")
