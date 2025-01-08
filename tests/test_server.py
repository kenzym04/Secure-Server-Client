from datetime import time

import pytest
import os
import sys
import socket
import configparser
import threading
import unittest
import signal
from unittest.mock import patch, MagicMock, mock_open

# Add the src directory to the Python path for importing the client module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.server import start_server, stop_daemon, signal_handler

# Add the parent directory to the Python path for importing the server module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# Import the TokenBucket module to be tested
from src.server import TokenBucket
# Import the server module to be tested
from src import server
from src.server import handle_client


@pytest.fixture
def mock_config():
    """
    Fixture to provide a mock configuration object.

    Returns:
        configparser.ConfigParser: A mock configuration with server settings.
    """
    config = configparser.ConfigParser()
    config['server'] = {
        'host': '127.0.0.1',
        'port': '44444',
        'ssl': 'true',
        'cert_file': 'certs/server.crt',
        'key_file': 'certs/server.key'
    }
    return config


@pytest.fixture
def mock_logger():
    """
    Fixture to provide a mock logger object.

    Returns:
        MagicMock: A mock logger object for testing logging functionality.
    """
    return MagicMock()


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

def test_setup_logging(mock_logger):
    with patch('logging.getLogger', return_value=mock_logger):
        logger = server.setup_logging()
        assert logger == mock_logger
        mock_logger.setLevel.assert_called_with(server.logging.DEBUG)
        assert mock_logger.addHandler.call_count == 2


def test_load_config():
    with patch('configparser.ConfigParser.read') as mock_read:
        with patch('os.path.exists', return_value=True):
            config = server.load_config('fake_path')
            mock_read.assert_called_once_with('fake_path')
            assert isinstance(config, configparser.ConfigParser)


def test_load_and_validate_config(mock_config):
    with patch('src.server.load_config', return_value=mock_config):
        config = server.load_and_validate_config()
        assert config['host'] == '127.0.0.1'
        assert config['port'] == 44444
        assert config['ssl'] is True
        assert config['cert_file'] == 'certs/server.crt'
        assert config['key_file'] == 'certs/server.key'


def test_create_ssl_context(mock_config):
    with patch('ssl.create_default_context') as mock_create_context:
        mock_context = MagicMock()
        mock_create_context.return_value = mock_context
        with patch('src.server.load_and_validate_config', return_value=mock_config):
            server.config = mock_config['server']  # Patch the global config
            context = server.create_ssl_context()
            mock_context.load_cert_chain.assert_called_once_with(
                certfile=os.path.join(server.BASE_DIR, mock_config['server']['cert_file']),
                keyfile=os.path.join(server.BASE_DIR, mock_config['server']['key_file'])
            )
            assert isinstance(context, MagicMock)

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