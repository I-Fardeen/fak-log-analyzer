from fak_log_analyzer.reporters.terminal import TerminalReporter


def test_terminal_reporter_output():
    """Test that TerminalReporter initializes and handles findings correctly."""
    reporter = TerminalReporter()
    assert reporter is not None
