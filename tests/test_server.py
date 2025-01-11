import logging
import pytest
import os
import sys
import socket
import configparser
from unittest.mock import patch, MagicMock

# Add the src directory to the Python path for importing the server module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import server
from src.server import (setup_logging, DEFAULT_CERT_DIR, DEFAULT_DATA_DIR, logger, LOG_FILE, PID_FILE)

@pytest.fixture
def mock_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config['server'] = {
        'host': '127.0.0.1',
        'port': '44444',
        'ssl': 'true',
        'cert_file': os.path.join(DEFAULT_CERT_DIR, 'server.crt'),
        'key_file': os.path.join(DEFAULT_CERT_DIR, 'server.key'),
        'file_path': os.path.join(DEFAULT_DATA_DIR, '200k.txt'),
        'reread_on_query': 'false',
        'token_bucket_capacity': '100',
        'token_bucket_fill_rate': '10.0',
    }
    return config

def test_load_and_validate_config(mock_config):
    with patch('src.server.load_config', return_value=mock_config):
        with patch('os.path.exists', return_value=True):  # Mock file existence
            config = server.load_and_validate_config()
            assert config['host'] == '127.0.0.1'
            assert config['port'] == 44444
            assert config['ssl'] is True
            assert config['cert_file'] == os.path.join(DEFAULT_CERT_DIR, 'server.crt')
            assert config['key_file'] == os.path.join(DEFAULT_CERT_DIR, 'server.key')
            assert config['file_path'] == os.path.join(DEFAULT_DATA_DIR, '200k.txt')
            assert config['reread_on_query'] is False
            assert config['token_bucket_capacity'] == 100
            assert config['token_bucket_fill_rate'] == 10.0


@pytest.fixture
def mock_logger():
    """
    Fixture to provide a fresh logger for each test.
    """
    logger = logging.getLogger('TestLogger')
    logger.handlers = []  # Clear handlers to avoid duplicate logs
    return logger

def test_setup_logging():
    """
    Test the setup_logging function to ensure it configures the logger correctly.
    """
    # Create a mock for the logger
    mock_logger = MagicMock()

    # Patch 'logging.getLogger' to return the mock logger when called
    with patch('logging.getLogger', return_value=mock_logger):
        # Patch the global logger in the server module
        with patch('src.server.logger', mock_logger):
            server.setup_logging()  # Call setup_logging

            # Debugging: Check if mock_logger has the correct handlers
            print(f"Handlers in mock_logger: {mock_logger.addHandler.call_args_list}")

            # Assert that the mock_logger's level was set to DEBUG
            mock_logger.setLevel.assert_called_with(logging.DEBUG)

            # Assert that the correct number of handlers were added to the logger
            assert mock_logger.addHandler.call_count == 2

            # Check if the handlers added are of the expected types
            handlers = [call.args[0] for call in mock_logger.addHandler.call_args_list]
            assert any(isinstance(handler, logging.handlers.RotatingFileHandler) for handler in handlers), f"Expected RotatingFileHandler, got {handlers}"
            assert any(isinstance(handler, logging.StreamHandler) for handler in handlers), f"Expected StreamHandler, got {handlers}"

def test_create_ssl_context(mock_config):
    with patch('ssl.create_default_context') as mock_create_context:
        mock_context = MagicMock()
        mock_create_context.return_value = mock_context
        with patch('src.server.load_and_validate_config', return_value=mock_config):
            with patch('os.path.join', return_value='mocked_path'):
                context = server.create_ssl_context()
                mock_context.load_cert_chain.assert_called_once_with(
                    certfile='mocked_path',
                    keyfile='mocked_path'
                )
                assert isinstance(context, MagicMock)

# Rate-limiting tests
def test_token_bucket_initialization():
    """
    Test TokenBucket initialization to ensure capacity and fill rate are set correctly.
    """
    bucket = server.TokenBucket(capacity=100, fill_rate=10)
    assert bucket.capacity == 100
    assert bucket.fill_rate == 10
    assert bucket.tokens == 100


def test_token_bucket_consume_success():
    """
    Test TokenBucket to ensure tokens are consumed correctly when available.
    """
    bucket = server.TokenBucket(capacity=10, fill_rate=5)
    assert bucket.consume(1)  # Consume 1 token
    assert bucket.tokens == 9  # Remaining tokens

def test_token_bucket_consume_failure():
    """
    Test TokenBucket to ensure consumption fails when tokens are unavailable.
    """
    bucket = server.TokenBucket(capacity=1, fill_rate=1)
    assert bucket.consume(1)  # Consume the only token
    assert not bucket.consume(1)  # Should fail as no tokens are left

def test_load_config():
    with patch('configparser.ConfigParser.read') as mock_read:
        with patch('os.path.exists', return_value=True):
            config = server.load_config('fake_path')
            mock_read.assert_called_once_with('fake_path')
            assert isinstance(config, configparser.ConfigParser)

def test_setup_server_socket():
    with patch('socket.socket') as mock_socket:
        with patch('src.server.create_ssl_context') as mock_create_ssl_context:
            mock_context = MagicMock()
            mock_create_ssl_context.return_value = mock_context

            result = server.setup_server_socket('127.0.0.1', 44444, True)

            mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            mock_socket.return_value.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            mock_socket.return_value.bind.assert_called_once_with(('127.0.0.1', 44444))
            mock_socket.return_value.listen.assert_called_once_with(5)
            mock_context.wrap_socket.assert_called_once_with(mock_socket.return_value, server_side=True)

            assert result == mock_context.wrap_socket.return_value

if __name__ == '__main__':
    pytest.main()