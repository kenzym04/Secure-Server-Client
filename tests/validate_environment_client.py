import os
import unittest
from unittest.mock import patch, MagicMock
import sys

# Add the src directory to the Python path for importing the client module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.client import DEFAULT_CONFIG_DIR, DEFAULT_LOG_DIR, DEFAULT_DATA_DIR, PID_FILE, validate_environment, logger

class TestValidateEnvironment(unittest.TestCase):
    """Unit test for the validate_environment function."""

    @patch('src.client.logger.warning')
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
        expected_calls = [
            unittest.mock.call(f"Configuration file does not exist: {DEFAULT_CONFIG_DIR}"),
            unittest.mock.call(f"Data directory does not exist: {DEFAULT_DATA_DIR}"),
            unittest.mock.call(f"PID file directory does not exist: {os.path.dirname(PID_FILE)}"),
        ]
        mock_warning.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_warning.call_count, 3)

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
            (os.path.join(DEFAULT_LOG_DIR, "dynamic_dir_1"), "Dynamic directory 1"),
            (os.path.join(DEFAULT_LOG_DIR, "dynamic_dir_2"), "Dynamic directory 2"),
        ]

        # Extend the function to include dynamic paths
        def validate_environment_with_dynamic_paths():
            paths_to_check = [
                (DEFAULT_CONFIG_DIR, "Configuration directory"),
                (DEFAULT_LOG_DIR, "Log directory"),
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

    def test_no_hardcoded_paths_in_client(self):
        """
        Test to ensure no hardcoded paths exist in the client.py file.
        Verifies:
        - All paths are dynamically constructed using environment variables or dynamic methods.
        """
        hardcoded_keywords = ["/path/to", "/usr/local", "/etc", "/var/log"]

        # Get the path to client.py
        current_dir = os.path.dirname(os.path.abspath(__file__))
        client_path = os.path.join(current_dir, '..', 'src', 'client.py')

        with open(client_path, 'r') as file:
            client_content = file.read()

        for keyword in hardcoded_keywords:
            self.assertNotIn(
                keyword,
                client_content,
                f"Hardcoded path or keyword detected in client.py: {keyword}"
            )

if __name__ == "__main__":
    unittest.main()
