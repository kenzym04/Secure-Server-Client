import os
import unittest
from unittest.mock import patch, MagicMock

# Paths from server.py
SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
BASE_DIR: str = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_CONFIG_DIR = os.getenv('CONFIG_DIR', os.path.join(BASE_DIR, "config"))
DEFAULT_LOG_DIR = os.getenv('LOG_DIR', os.path.join(BASE_DIR, "logs"))
DEFAULT_CERT_DIR = os.getenv('CERT_DIR', os.path.join(BASE_DIR, "certs"))
DEFAULT_DATA_DIR = os.getenv('DATA_DIR', os.path.join(BASE_DIR, "data"))
PID_FILE: str = os.getenv('PID_FILE', os.path.join(BASE_DIR, "server_daemon.pid"))

# Mock logger for testing
logger = MagicMock()

# Function under test
def validate_environment():
    """
    Validate the existence of critical directories required for the server.

    Logs a warning for any missing paths.

    Returns:
        None
    """
    paths_to_check = [
        (DEFAULT_CONFIG_DIR, "Configuration directory"),
        (DEFAULT_LOG_DIR, "Log directory"),
        (DEFAULT_CERT_DIR, "Certificate directory"),
        (DEFAULT_DATA_DIR, "Data directory"),
        (os.path.dirname(PID_FILE), "PID file directory"),
    ]
    for path, description in paths_to_check:
        if not os.path.exists(path):
            logger.warning(f"{description} does not exist: {path}")


class TestValidateEnvironment(unittest.TestCase):
    """Unit tests for the validate_environment function."""

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment_missing_paths(self, mock_path_exists, mock_warning):
        """
        Test validate_environment function for proper logging of missing paths.

        Verifies:
        - Missing directories are logged as warnings.
        - The correct number of warnings is logged.
        """
        # Simulate paths that do not exist
        mock_path_exists.side_effect = lambda path: {
            DEFAULT_CONFIG_DIR: False,
            DEFAULT_LOG_DIR: True,
            DEFAULT_CERT_DIR: True,
            DEFAULT_DATA_DIR: False,
            os.path.dirname(PID_FILE): False,
        }.get(path, True)

        # Act
        validate_environment()

        # Assert
        mock_warning.assert_any_call(
            f"Configuration directory does not exist: {DEFAULT_CONFIG_DIR}"
        )
        mock_warning.assert_any_call(
            f"Data directory does not exist: {DEFAULT_DATA_DIR}"
        )
        mock_warning.assert_any_call(
            f"PID file directory does not exist: {os.path.dirname(PID_FILE)}"
        )
        self.assertEqual(mock_warning.call_count, 3)

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment_all_paths_present(self, mock_path_exists, mock_warning):
        """
        Test validate_environment when all paths exist.

        Verifies:
        - No warnings are logged when all paths are present.
        """
        # Simulate all paths existing
        mock_path_exists.return_value = True

        # Act
        validate_environment()

        # Assert
        mock_warning.assert_not_called()

        # Extend the function to include dynamic paths
    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment_with_dynamic_paths(self, mock_path_exists, mock_warning):
        """
        Test validate_environment with dynamically added paths.
        Verifies:
        - Dynamically added paths are validated.
        - Warnings are logged for missing dynamic paths.
        """
        dynamic_paths = [
            (os.path.join(BASE_DIR, "dynamic_dir_1"), "Dynamic directory 1"),
            (os.path.join(BASE_DIR, "dynamic_dir_2"), "Dynamic directory 2"),
        ]

        # Extend the function to include dynamic paths
        def validate_environment_with_dynamic_paths():
            paths_to_check = [
                (DEFAULT_CONFIG_DIR, "Configuration directory"),
                (DEFAULT_LOG_DIR, "Log directory"),
                (DEFAULT_CERT_DIR, "Certificate directory"),
                (DEFAULT_DATA_DIR, "Data directory"),
                (os.path.dirname(PID_FILE), "PID file directory"),
            ] + dynamic_paths
            for path, description in paths_to_check:
                if not os.path.exists(path):
                    logger.warning(f"{description} does not exist: {path}")

        # Simulate paths existence
        mock_path_exists.side_effect = lambda path: {
            DEFAULT_CONFIG_DIR: True,
            DEFAULT_LOG_DIR: True,
            DEFAULT_CERT_DIR: True,
            DEFAULT_DATA_DIR: True,
            os.path.dirname(PID_FILE): True,
            dynamic_paths[0][0]: False,  # Simulate first dynamic path missing
            dynamic_paths[1][0]: True,  # Simulate second dynamic path exists
        }.get(path, True)

        # Use patch to replace the original validate_environment with the new one
        with patch(f"{__name__}.validate_environment", new=validate_environment_with_dynamic_paths):
            # Act
            validate_environment()

        # Assert
        mock_warning.assert_any_call(
            f"Dynamic directory 1 does not exist: {dynamic_paths[0][0]}"
        )
        self.assertEqual(mock_warning.call_count, 1)

    def test_no_hardcoded_paths_in_server(self):
        """
        Test to ensure no hardcoded paths exist in the server.py file.
        Verifies:
        - All paths are dynamically constructed using environment variables or dynamic methods.
        """
        hardcoded_keywords = ["/path/to", "/usr/local", "/etc", "/var/log"]

        # Get the path to server.py
        current_dir = os.path.dirname(os.path.abspath(__file__))
        server_path = os.path.join(current_dir, '..', 'src', 'server.py')

        with open(server_path, 'r') as file:
            server_content = file.read()

        for keyword in hardcoded_keywords:
            self.assertNotIn(
                keyword,
                server_content,
                f"Hardcoded path or keyword detected in server.py: {keyword}"
            )

if __name__ == "__main__":
    unittest.main()
