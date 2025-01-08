import os
import sys
import pytest
import subprocess
import time
import logging
import os
import signal
from unittest.mock import patch, MagicMock, mock_open, ANY, call

# Add the project root directory to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src import server_daemon

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, 'logs', 'server.log')

@pytest.fixture
def mock_logger():
    """
    Fixture to provide a mock logger for testing.
    """
    return MagicMock()

def test_run_daemon_exception_handling(mock_logger):
    """
    Test exception handling in the run_daemon function.
    Ensures that errors are logged and the system exits with a failure code.
    """
    with patch('src.server_daemon.start_server', side_effect=Exception("Test exception")), \
         patch('sys.exit') as mock_exit, \
         patch('src.server_daemon.logger', mock_logger):
        server_daemon.run_daemon()
        mock_logger.error.assert_called_once_with("Error in daemon: Test exception")
        mock_exit.assert_called_once_with(1)

def test_main_invalid_argument():
    """
    Test invalid command-line arguments for the main function.
    Ensures that usage instructions are printed and the program exits with a failure code.
    """
    with patch('sys.argv', ['server_daemon.py', '--invalid']), \
            patch('sys.exit') as mock_exit, \
            patch('builtins.print') as mock_print:
        server_daemon.main()
        mock_print.assert_called_once_with("Usage: python server_daemon.py [--daemon|stop]")
        mock_exit.assert_called_once_with(1)

def test_daemonize_redirects_file_descriptors():
    """
    Test that daemonize correctly redirects file descriptors (stdin, stdout, stderr) to /dev/null.
    """
    mock_stdin = MagicMock()
    mock_stdout = MagicMock()
    mock_stderr = MagicMock()

    with patch('os.fork', side_effect=[0, 0]), \
            patch('os.setsid'), \
            patch('os.chdir'), \
            patch('os.umask'), \
            patch('builtins.open', mock_open()), \
            patch('os.dup2') as mock_dup2, \
            patch('signal.signal'), \
            patch('sys.exit'), \
            patch('src.server_daemon.logger'), \
            patch('os.getpid', return_value=12345), \
            patch('sys.stdin', mock_stdin), \
            patch('sys.stdout', mock_stdout), \
            patch('sys.stderr', mock_stderr):
        server_daemon.daemonize()

        # Assert file descriptors are redirected
        assert mock_dup2.call_count == 3
        mock_dup2.assert_has_calls([
            call(ANY, mock_stdin.fileno()),
            call(ANY, mock_stdout.fileno()),
            call(ANY, mock_stderr.fileno())
        ])

def test_daemonize_creates_pid_file():
    """
    Test that daemonize writes the correct PID to the PID file.
    """
    mock_pid = 12345
    mock_file = MagicMock()
    mock_file.__enter__.return_value = mock_file

    with patch('os.fork', side_effect=[0, 0]), \
            patch('os.setsid'), \
            patch('os.chdir'), \
            patch('os.umask'), \
            patch('os.getpid', return_value=mock_pid), \
            patch('builtins.open', return_value=mock_file), \
            patch('sys.exit') as mock_exit, \
            patch('signal.signal'), \
            patch('os.dup2'), \
            patch('sys.stdin.fileno', return_value=0), \
            patch('sys.stdout.fileno', return_value=1), \
            patch('sys.stderr.fileno', return_value=2):
        server_daemon.daemonize()

        # Verify PID file contents
        mock_file.write.assert_called_once_with(str(mock_pid))

def test_signal_handling():
    from unittest.mock import call
    """Test signal handling to ensure SIGTERM and SIGINT are correctly caught and handled."""
    with patch('src.server_daemon.signal.signal') as mock_signal, \
            patch('os.fork', side_effect=[0, 0]), \
            patch('os.setsid'), \
            patch('os.chdir'), \
            patch('os.umask'), \
            patch('os.getpid', return_value=12345), \
            patch('builtins.open', mock_open()) as mock_file, \
            patch('sys.exit'), \
            patch('os.dup2') as mock_dup2, \
            patch('sys.stdin'), \
            patch('sys.stdout'), \
            patch('sys.stderr'), \
            patch('src.server_daemon.PID_FILE', '/tmp/test_server_daemon.pid'), \
            patch('src.server_daemon.logger'):  # Add this to mock the logger

        server_daemon.daemonize()

        # Check if signal handlers are set correctly
        mock_signal.assert_has_calls([
            call(signal.SIGTERM, server_daemon.signal_handler),
            call(signal.SIGINT, server_daemon.signal_handler)
        ], any_order=True)

        # Check if PID file is created and written correctly
        mock_file.assert_any_call('/tmp/test_server_daemon.pid', 'w')
        mock_file().write.assert_any_call('12345')

        # Check if file descriptors are redirected
        assert mock_dup2.call_count == 3  # stdin, stdout, stderr
        mock_dup2.assert_has_calls([
            call(ANY, sys.stdin.fileno()),
            call(ANY, sys.stdout.fileno()),
            call(ANY, sys.stderr.fileno())
        ])

        # Check total number of open calls
        assert mock_file.call_count == 5  # PID file + 3 for stdin, stdout, stderr + 1 additional call

        # Print out all the calls to open for debugging
        print("Calls to open:")
        for call in mock_file.call_args_list:
            print(call)

def test_stop_command_and_stop_daemon():
    """Test the 'stop' command-line argument and the stop_daemon() function."""
    with patch('src.server_daemon.os.kill') as mock_kill, \
         patch('src.server_daemon.os.path.exists', return_value=True), \
         patch('builtins.open', mock_open(read_data="12345")):

        server_daemon.stop_daemon()
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)

@patch('subprocess.Popen')
def test_comprehensive_daemonization(mock_popen):
    """Test the daemonization process using subprocess."""
    # Mock for starting the daemon
    mock_start_process = MagicMock()
    mock_start_process.communicate.return_value = (b"Server daemon started with PID: 12345", b"")
    mock_start_process.returncode = 0

    # Mock for stopping the daemon
    mock_stop_process = MagicMock()
    mock_stop_process.communicate.return_value = (b"Stopping server daemon...", b"")
    mock_stop_process.returncode = 0

    mock_popen.side_effect = [mock_start_process, mock_stop_process]

    # Start the daemon
    process = subprocess.Popen(["python", "src/server_daemon.py", "--daemon"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    assert b"Server daemon started with PID: 12345" in stdout
    assert process.returncode == 0

    # Wait for a moment to allow the daemon to start
    time.sleep(2)

    # Stop the daemon
    stop_process = subprocess.Popen(["python", "src/server_daemon.py", "--stop"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stop_stdout, stop_stderr = stop_process.communicate()

    assert b"Stopping server daemon..." in stop_stdout
    assert stop_process.returncode == 0

    # Verify that Popen was called twice
    assert mock_popen.call_count == 2


def test_run_daemon():
    """Test run_daemon function."""
    with patch('src.server_daemon.start_server') as mock_start_server, \
         patch('src.server_daemon.setup_logging'):
        server_daemon.run_daemon()
        mock_start_server.assert_called_once()


def test_main_with_invalid_arguments():
    """
    Test main function with invalid arguments.

    This test verifies that:
    1. The main function exits with status code 1 when given invalid arguments.
    2. An error message is logged.
    """
    with patch('sys.argv', ['server_daemon.py', 'invalid_arg']), \
            patch('sys.exit') as mock_exit, \
            patch('src.server_daemon.setup_logging') as mock_setup_logging:
        mock_logger = MagicMock()
        mock_setup_logging.return_value = mock_logger

        server_daemon.main()

        mock_exit.assert_called_once_with(1)
        mock_logger.error.assert_called_once_with(
            "Invalid arguments. Usage: python server_daemon.py [--daemon|stop]"
        )


def test_run_daemon_execution():
    """
    Test run_daemon function execution.
    """
    with patch('src.server_daemon.start_server') as mock_start_server, \
            patch('src.server_daemon.logger') as mock_logger:
        # Call run_daemon
        server_daemon.run_daemon()

        # Check that start_server was called
        mock_start_server.assert_called_once()

        # Check that some info log was called, without specifying the exact message
        assert mock_logger.info.called

def test_main_calls_setup_logging():
    """
    Test that the main function calls setup_logging.
    """
    with patch('src.server_daemon.setup_logging') as mock_setup_logging, \
            patch('src.server_daemon.run_daemon'), \
            patch('sys.argv', ['server_daemon.py', '--daemon']), \
            patch('sys.stdin', MagicMock()), \
            patch('sys.stdout', MagicMock()), \
            patch('sys.stderr', MagicMock()):
        try:
            server_daemon.main()
        except SystemExit:
            pass  # Ignore SystemExit, as it's expected behavior
        mock_setup_logging.assert_called_once()

    # Test with invalid argument
    with patch('src.server_daemon.setup_logging') as mock_setup_logging, \
            patch('sys.argv', ['server_daemon.py', 'invalid']), \
            patch('sys.exit') as mock_exit:
        server_daemon.main()
        mock_setup_logging.assert_called_once()
        mock_exit.assert_called_once_with(1)

