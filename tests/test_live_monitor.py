from fak_log_analyzer.monitor import LiveMonitor


def test_live_monitor_alert_formatting():
    """Test that LiveMonitor correctly processes entries

    and passes expected alert data.
    """
    captured_alerts = []

    def mock_alert_callback(alert_data):
        captured_alerts.append(alert_data)

    # Initialize monitor with a low threshold for quick testing
    monitor = LiveMonitor(
        log_path="tests/sample.log",
        request_threshold=3,
        time_window=10,
        alert_callback=mock_alert_callback,
    )

    # Simulate entries crossing the threshold for a specific IP
    test_ip = "203.0.113.66"
    for _ in range(3):
        entry = {
            "ip": test_ip,
            "timestamp": "2026-09-27 10:46:27",
            "method": "GET",
            "endpoint": "/login",
            "protocol": "HTTP/1.1",
            "status": 200,
            "size": 512,
        }
        monitor._analyze_entry(entry)

    # Verify that an alert was triggered
    assert len(captured_alerts) == 1

    alert = captured_alerts[0]
    assert alert["threat_type"] == "DoS / DDoS Attack"
    assert alert["source_ip"] == test_ip
    assert alert["request_count"] == 3
    assert alert["window_seconds"] == 10
    assert "login_time" in alert
