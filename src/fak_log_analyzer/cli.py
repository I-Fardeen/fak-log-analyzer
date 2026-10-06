import argparse
import sys

from fak_log_analyzer.monitor import LiveMonitor

VERSION = "0.6.0"


def handle_alert(alert_data):
    """Callback function to render the live DDoS attack monitor dashboard table."""
    print("=" * 70)
    print("=== LIVE DDOS ATTACK MONITOR (Active Threats) ===")
    print("=" * 70)
    print(
        f"{'IP ADDRESS':<18} | {'LAST LOG TIME':<20} | {'REQUESTS':<10} | {'WINDOW':<8}"
    )
    print("-" * 70)

    print(
        f"{alert_data['source_ip']:<18} | "
        f"{alert_data['login_time']:<20} | "
        f"{alert_data['request_count']:<10} | "
        f"{alert_data['window_seconds']}s"
    )
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="FAK Log Analyzer CLI")
    parser.add_argument(
        "--live",
        type=str,
        help="Path to log file for real-time live monitoring",
    )
    parser.add_argument("--window", type=int, default=10, help="Time window in seconds")
    parser.add_argument("--threshold", type=int, default=3, help="Request threshold")

    args = parser.parse_args()

    if args.live:
        try:
            print(
                "[*] Monitoring live traffic... Press Ctrl+C to stop and save report.\n"
            )

            monitor = LiveMonitor(
                log_path=args.live,
                request_threshold=args.threshold,
                time_window=args.window,
                alert_callback=handle_alert,
            )
            monitor.start()
        except KeyboardInterrupt:
            print("\n[!] Live monitoring stopped by user.")
            sys.exit(0)
    else:
        print("Please specify an option like --live <logfile>")


if __name__ == "__main__":
    main()
