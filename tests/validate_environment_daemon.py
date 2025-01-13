import os
import unittest
import inspect
from unittest.mock import patch, MagicMock

# Example directories for testing
DEFAULT_CONFIG_DIR = os.getenv("CONFIG_DIR", "/path/to/config")
DEFAULT_LOG_DIR = os.getenv("LOG_DIR", "/path/to/logs")
DEFAULT_PID_DIR = os.getenv("PID_DIR", "/path/to/pids")

# Mock logger for testing
logger = MagicMock()

def validate_environment():
    """
    Validate the existence of critical directories required for the application.

    Logs a warning for any missing directories. Handles dynamic paths seamlessly.

    Returns:
        None
    """
    dynamic_paths = [
        (os.getenv("DYNAMIC_DIR_1", "/dynamic/dir/1"), "Dynamic directory 1"),
        (os.getenv("DYNAMIC_DIR_2", "/dynamic/dir/2"), "Dynamic directory 2"),
    ]

    paths_to_check = [
        (DEFAULT_CONFIG_DIR, "Configuration directory"),
        (DEFAULT_LOG_DIR, "Log directory"),
        (DEFAULT_PID_DIR, "PID directory"),
    ] + dynamic_paths

    for path, description in paths_to_check:
        if not os.path.exists(path):
            logger.warning(f"{description} does not exist: {path}")


class TestValidateEnvironment(unittest.TestCase):
    """Unit tests for the validate_environment function."""

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment_missing_paths(self, mock_path_exists, mock_warning):
        """
        Test validate_environment for proper logging of missing directories.
        """
        mock_path_exists.side_effect = lambda path: {
            DEFAULT_CONFIG_DIR: False,
            DEFAULT_LOG_DIR: True,
            DEFAULT_PID_DIR: False,
        }.get(path, True)

        validate_environment()

        mock_warning.assert_any_call(
            f"Configuration directory does not exist: {DEFAULT_CONFIG_DIR}"
        )
        mock_warning.assert_any_call(
            f"PID directory does not exist: {DEFAULT_PID_DIR}"
        )
        self.assertEqual(mock_warning.call_count, 2)

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment_all_paths_present(self, mock_path_exists, mock_warning):
        """
        Test validate_environment when all directories exist.
        """
        mock_path_exists.return_value = True

        validate_environment()

        mock_warning.assert_not_called()

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment_with_dynamic_paths(self, mock_path_exists, mock_warning):
        """
        Test validate_environment with dynamically added paths.
        """
        dynamic_paths = [
            (os.getenv("DYNAMIC_DIR_1", "/dynamic/dir/1"), "Dynamic directory 1"),
            (os.getenv("DYNAMIC_DIR_2", "/dynamic/dir/2"), "Dynamic directory 2"),
        ]

        mock_path_exists.side_effect = lambda path: {
            DEFAULT_CONFIG_DIR: True,
            DEFAULT_LOG_DIR: True,
            DEFAULT_PID_DIR: True,
            dynamic_paths[0][0]: False,
            dynamic_paths[1][0]: True,
        }.get(path, True)

        validate_environment()

        mock_warning.assert_any_call(
            f"Dynamic directory 1 does not exist: {dynamic_paths[0][0]}"
        )
        self.assertEqual(mock_warning.call_count, 1)

    def test_no_hardcoded_paths(self):
        """
        Test to ensure no hardcoded paths exist in the server_daemon.py file.
        """
        hardcoded_keywords = ["/path/to", "/dynamic/dir"]
        
        # Get the path to server_daemon.py
        current_dir = os.path.dirname(os.path.abspath(__file__))
        server_daemon_path = os.path.join(current_dir, '..', 'src', 'server_daemon.py')
        
        # Read the contents of server_daemon.py
        with open(server_daemon_path, 'r') as file:
            source_code = file.read()

        for keyword in hardcoded_keywords:
            self.assertNotIn(
                keyword,
                source_code,
                f"Hardcoded path detected in server_daemon.py: {keyword}",
            )

if __name__ == "__main__":
    unittest.main()
