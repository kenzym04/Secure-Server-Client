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

def validate_environment():
    """
    Validate the existence of critical directories required for the server.

    Logs a warning for any missing paths.

    Returns:
        None
    """
    for path, description in [
        (DEFAULT_CONFIG_DIR, "Configuration directory"),
        (DEFAULT_LOG_DIR, "Log directory"),
        (DEFAULT_CERT_DIR, "Certificate directory"),
        (DEFAULT_DATA_DIR, "Data directory"),
        (os.path.dirname(PID_FILE), "PID file directory"),
    ]:
        if not os.path.exists(path):
            logger.warning(f"{description} does not exist: {path}")


class TestValidateEnvironment(unittest.TestCase):
    """Unit test for the validate_environment function."""

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment(self, mock_path_exists, mock_warning):
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


if __name__ == "__main__":
    unittest.main()
