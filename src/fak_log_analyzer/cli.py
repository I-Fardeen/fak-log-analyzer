import argparse
import sys
from collections import Counter
from fak_log_analyzer.parser import parse_file
from fak_log_analyzer.monitor import LiveMonitor

def main():
    parser = argparse.ArgumentParser(description="Fak Log Analyzer with Live Threat Detection")
    
    # Core Arguments
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("--live", action="store_true", help="Monitor live server logs for DoS/DDoS attacks")
    parser.add_argument("-t", "--threshold", type=int, default=50, help="Request threshold for DDoS alert")
    parser.add_argument("-w", "--window", type=int, default=10, help="Time window in seconds")
    
    # Static Analysis Arguments
    parser.add_argument("--top-ips", type=int, default=5, help="Top IPs count")
    parser.add_argument("--top-paths", type=int, default=5, help="Top paths count")
    parser.add_argument("--format", choices=["terminal", "json", "csv"], default="terminal")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    # 1. Live Monitoring Mode with Multi-IP DDoS Tracking & Report Export
    if args.live:
        import csv
        import json
        import time

        active_threats = {}

        def handle_alert(alert):
            ip = alert['source_ip']
            active_threats[ip] = alert
            
            # Clear terminal screen and redraw active threats dashboard cleanly
            sys.stdout.write("\033[H\033[J")
            print("=" * 65)
            print(f"       🚨 LIVE DDoS ATTACK MONITOR (Active Threats) 🚨       ")
            print("=" * 65)
            print(f"{'IP ADDRESS':<18} | {'LAST LOGIN TIME':<20} | {'REQUESTS':<10} | {'WINDOW'}")
            print("-" * 65)
            
            for threat_ip, data in active_threats.items():
                print(f"{threat_ip:<18} | {data['login_time']:<20} | {data['request_count']:<10} | {data['window_seconds']}s")
            
            print("=" * 65)
            print("[*] Monitoring live traffic... Press Ctrl+C to stop and save report.\n")
            sys.stdout.flush()

        monitor = LiveMonitor(
            log_path=args.logfile,
            request_threshold=args.threshold,
            time_window=args.window,
            alert_callback=handle_alert
        )

        try:
            monitor.start()
        except KeyboardInterrupt:
            print("\n\n[!] Live monitoring stopped by user.")
            
            if active_threats:
                output_file = args.output or f"live_threat_report.{args.format if args.format in ['json', 'csv'] else 'csv'}"
                export_format = args.format if args.format in ['json', 'csv'] else 'csv'
                
                print(f"[*] Exporting live threat report to '{output_file}' ({export_format.upper()})...")
                
                threat_list = list(active_threats.values())
                
                if export_format == 'json':
                    with open(output_file, 'w', encoding='utf-8') as jf:
                        json.dump(threat_list, jf, indent=4)
                else:  # CSV format
                    with open(output_file, 'w', newline='', encoding='utf-8') as cf:
                        writer = csv.DictWriter(cf, fieldnames=["threat_type", "source_ip", "login_time", "request_count", "window_seconds"])
                        writer.writeheader()
                        for row in threat_list:
                            writer.writerow(row)
                            
                print(f"[+] Report successfully saved to {output_file}")
            else:
                print("[*] No threats were detected during this monitoring session. No report generated.")
                
        sys.exit(0)

    # 2. Original Static Analysis Mode
    print(f"Running static analysis on {args.logfile}...")
    entries, malformed_lines = parse_file(args.logfile)
    
    print(f"\n==============================")
    print(f"     STATIC ANALYSIS REPORT   ")
    print(f"==============================\n")
    print(f"Total Valid Entries : {len(entries)}")
    print(f"Malformed Lines     : {malformed_lines}")
    
    if entries:
        ip_counts = Counter(getattr(e, 'ip_address', 'unknown') for e in entries)
        path_counts = Counter(getattr(e, 'path', 'unknown') for e in entries)
        
        print(f"\nTop {args.top_ips} IP Addresses:")
        for ip, count in ip_counts.most_common(args.top_ips):
            print(f"  - {ip}: {count} requests")
            
        print(f"\nTop {args.top_paths} Requested Paths:")
        for path, count in path_counts.most_common(args.top_paths):
            print(f"  - {path}: {count} hits")
    else:
        print("\n[!] No valid log entries found to analyze.")

if __name__ == "__main__":
    main()
