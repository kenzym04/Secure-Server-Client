import os
import unittest
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.client import DEFAULT_CONFIG_DIR, DEFAULT_LOG_DIR, DEFAULT_DATA_DIR, PID_FILE, validate_environment

# Mock logger for testing
logger = MagicMock()

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
            DEFAULT_DATA_DIR: False,
            os.path.dirname(PID_FILE): False,
        }.get(path, True)

        # Act
        validate_environment()

        # Assert
        mock_warning.assert_any_call(
            f"Configuration file does not exist: {DEFAULT_CONFIG_DIR}"
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
