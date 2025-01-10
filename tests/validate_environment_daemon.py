import os
import unittest
from unittest.mock import patch, MagicMock

# Example directories for testing
DEFAULT_CONFIG_DIR = "/path/to/config"
DEFAULT_LOG_DIR = "/path/to/logs"
DEFAULT_PID_DIR = "/path/to/pids"

# Mock logger for testing
logger = MagicMock()


def validate_environment():
    """
    Validate the existence of critical directories required for the application.

    This function checks the presence of essential directories such as
    configuration, log, and PID directories. If any directory is missing,
    a warning is logged indicating the missing directory and its purpose.

    Directories validated:
        - Configuration directory
        - Log directory
        - PID directory

    Logging:
        Logs a warning for each missing directory.

    Returns:
        None
    """
    for path, description in [
        (DEFAULT_CONFIG_DIR, "Configuration directory"),
        (DEFAULT_LOG_DIR, "Log directory"),
        (DEFAULT_PID_DIR, "PID directory"),
    ]:
        if not os.path.exists(path):
            logger.warning(f"{description} does not exist: {path}")


class TestValidateEnvironment(unittest.TestCase):
    """Unit test for the validate_environment function."""

    @patch.object(logger, "warning")
    @patch("os.path.exists")
    def test_validate_environment(self, mock_path_exists, mock_warning):
        """
        Test validate_environment function for proper logging of missing directories.

        This test verifies that:
        - Missing directories are logged as warnings.
        - The correct number of warnings is logged.
        """
        # Simulate paths that do not exist
        mock_path_exists.side_effect = lambda path: {
            DEFAULT_CONFIG_DIR: False,
            DEFAULT_LOG_DIR: True,
            DEFAULT_PID_DIR: False,
        }.get(path, True)

        # Act
        validate_environment()

        # Assert
        mock_warning.assert_any_call(
            f"Configuration directory does not exist: {DEFAULT_CONFIG_DIR}"
        )
        mock_warning.assert_any_call(
            f"PID directory does not exist: {DEFAULT_PID_DIR}"
        )
        self.assertEqual(mock_warning.call_count, 2)


if __name__ == "__main__":
    unittest.main()
