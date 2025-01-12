import logging
import pytest
import os
import sys
import socket
import configparser
from mmap import mmap as mmap_func
from unittest.mock import mock_open
from unittest.mock import patch, mock_open as mock_open_function

# Add the src directory to the Python path for importing the server module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import server
from src.server import (DEFAULT_CERT_DIR, DEFAULT_DATA_DIR, logger, TokenBucket,
                        handle_client, config, PID_FILE, stop_daemon, load_and_validate_config, optimized_read_file)

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

def test_load_and_validate_config():
    mock_config = configparser.ConfigParser()
    mock_config['server'] = {
        'host': '127.0.0.1',
        'port': '44444',
        'ssl': 'true',
        'cert_file': 'server.crt',
        'key_file': 'server.key',
        'linuxpath': '/path/to/file',
        'reread_on_query': 'false',
        'token_bucket_capacity': '100',
        'token_bucket_fill_rate': '10.0',
        'file_path': '200k.txt',
        'log_file': 'server.log',
        'pid_file': 'server_daemon.pid'
    }

    with patch('src.server.load_config', return_value=mock_config):
        with patch('os.path.exists', return_value=True):  # Mock file existence
            config = server.load_and_validate_config()
            assert config['host'] == '127.0.0.1'
            assert config['port'] == 44444
            assert config['ssl'] is True
            assert config['cert_file'] == 'server.crt'
            assert config['key_file'] == 'server.key'
            assert config['linuxpath'] == '/path/to/file'
            assert config['reread_on_query'] is False
            assert config['token_bucket_capacity'] == 100
            assert config['token_bucket_fill_rate'] == 10.0
            assert config['file_path'] == '200k.txt'
            assert config['log_file'] == 'server.log'
            assert config['pid_file'] == 'server_daemon.pid'

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
    mock_logger = MagicMock()

    with patch('logging.getLogger', return_value=mock_logger):
        with patch('src.server.logger', mock_logger):
            server.setup_logging()

            mock_logger.setLevel.assert_called_with(logging.DEBUG)
            assert mock_logger.addHandler.call_count == 2

            handlers = [call.args[0] for call in mock_logger.addHandler.call_args_list]
            handler_types = [type(handler) for handler in handlers]

            assert any(issubclass(handler_type, logging.handlers.RotatingFileHandler) for handler_type in
                       handler_types), f"Expected RotatingFileHandler, got {handler_types}"
            assert any(issubclass(handler_type, logging.StreamHandler) for handler_type in
                       handler_types), f"Expected StreamHandler, got {handler_types}"

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

@pytest.fixture
def test_validate_environment():
    """
    Test the validate_environment function to ensure it logs warnings for missing directories.
    """
    with patch('os.path.exists', side_effect=lambda path: path != "missing_path"):
        with patch.object(logger, 'warning') as mock_warning:
            server.validate_environment()
            mock_warning.assert_called()  # Ensure warnings are logged
            mock_warning.assert_any_call("Configuration directory does not exist: missing_path")

def initialize_set_mmap() -> None:
    """
    Initialize global file_set and file_mmap for efficient file content access.
    """
    global file_set, file_mmap
    try:
        linuxpath = config['linuxpath']
        if not isinstance(linuxpath, str):
            raise TypeError("linuxpath must be a string")

        with open(linuxpath, 'r+b') as f:
            file_size = os.path.getsize(linuxpath)
            file_mmap = mmap_func(f.fileno(), file_size)
            file_content = file_mmap[:]
            file_lines = file_content.decode('utf-8').splitlines()
            file_set = set(line.strip() for line in file_lines)
    except Exception as e:
        logger.error(f"Error initializing set and mmap: {str(e)}")
        file_set = set()
        file_mmap = None

def test_search_query():
    """
    Test the search_query function for both reread_on_query True and False.
    """
    # Test case for reread_on_query = True
    with patch.dict(server.config, {'reread_on_query': True}), \
            patch('src.server.initialize_set_mmap') as mock_init, \
            patch('src.server.file_mmap') as mock_file_mmap, \
            patch('src.server.logger') as mock_logger:
        mock_file_mmap.__getitem__.return_value = b"test_query\nother_line"

        result = server.search_query("test_query")
        assert result == "STRING EXISTS"

        result = server.search_query("non_existent")
        assert result == "STRING NOT FOUND"

    # Test case for reread_on_query = False
    with patch.dict(server.config, {'reread_on_query': False}), \
            patch('src.server.initialize_set_mmap') as mock_init, \
            patch('src.server.file_set', {'test_query', 'other_line'}), \
            patch('src.server.logger') as mock_logger:
        result = server.search_query("test_query")
        assert result == "STRING EXISTS"

        result = server.search_query("non_existent")
        assert result == "STRING NOT FOUND"

    # Test error cases
    with patch.dict(server.config, {'reread_on_query': True}), \
            patch('src.server.initialize_set_mmap') as mock_init, \
            patch('src.server.file_mmap', None), \
            patch('src.server.logger') as mock_logger:
        result = server.search_query("test_query")
        assert result == "ERROR: Unable to initialize memory-mapped file"

    with patch.dict(server.config, {'reread_on_query': False}), \
            patch('src.server.initialize_set_mmap') as mock_init, \
            patch('src.server.file_set', None), \
            patch('src.server.logger') as mock_logger:
        result = server.search_query("test_query")
        assert result == "ERROR: Unable to initialize file set"

def test_cleanup_resources():
    """
    Test the cleanup_resources function to ensure proper cleanup.
    """
    server.file_mmap = MagicMock()
    server.file_set = {"line1"}
    server.cleanup_resources()
    assert server.file_mmap is None
    assert server.file_set is None

def test_handle_client():
    """
    Test the handle_client function for correct client handling.
    """
    # Mock the socket behavior
    mock_socket = MagicMock()
    # Simulate receiving a query and then an empty string to close the connection
    mock_socket.recv.side_effect = [b"test_query\n", b""]
    mock_socket.sendall = MagicMock()

    with patch('src.server.search_query', return_value="STRING EXISTS"):
        # Call the function under test
        handle_client(mock_socket, ("127.0.0.1", 44444))

        # Verify the response was sent back to the client
        mock_socket.sendall.assert_called_with(b"STRING EXISTS\n")

    # Ensure recv was called twice (once for query, once for disconnect)
    assert mock_socket.recv.call_count == 2

def test_token_bucket():
    """
    Test the TokenBucket class for rate-limiting functionality.
    """
    bucket = TokenBucket(10, 1.0)
    assert bucket.consume(1)
    assert not bucket.consume(11)

def test_ssl_context_creation():
    """
    Test SSL context creation to ensure certificates are loaded.
    """
    with patch('ssl.create_default_context') as mock_create_context:
        mock_context = MagicMock()
        mock_create_context.return_value = mock_context
        context = server.create_ssl_context()
        assert mock_context.load_cert_chain.called

def test_initialize_set_mmap_invalid_content():
    mock_mmap = MagicMock()
    mock_mmap.__getitem__.return_value = b'\xff\xfe'  # Invalid UTF-8

    with patch('builtins.open', mock_open(read_data=b'\xff\xfe')), \
            patch('src.server.mmap_func', return_value=mock_mmap), \
            patch('os.path.getsize', return_value=2):
        server.initialize_set_mmap()
        assert server.file_set == set()
        assert server.file_mmap is None

def test_initialize_set_mmap_file_not_found():
    with patch.dict(server.config, {'linuxpath': 'non_existent_file'}):
        with patch('os.path.exists', return_value=False):
            with pytest.raises(FileNotFoundError):
                server.initialize_set_mmap()

def test_initialize_set_mmap_permission_error():
    with patch.dict(server.config, {'linuxpath': 'existing_file'}):
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', side_effect=PermissionError):
                with pytest.raises(PermissionError):
                    server.initialize_set_mmap()

@pytest.fixture
def mock_server_socket():
    mock_socket = MagicMock()
    mock_client_socket = MagicMock()
    mock_client_address = ('127.0.0.1', 12345)
    mock_socket.accept.side_effect = [
        (mock_client_socket, mock_client_address),
        Exception("Stop the loop")
    ]
    return mock_socket

from unittest.mock import patch, MagicMock, call
import signal
from src.server import start_server, signal_handler

def test_start_server():
    mock_server_socket = MagicMock()
    mock_config = {
        'host': 'localhost',
        'port': 8000,
        'ssl': False,
        'linuxpath': '/path/to/file',
        'reread_on_query': True
    }

    with patch('src.server.setup_logging') as mock_setup_logging, \
         patch('src.server.signal.signal') as mock_signal, \
         patch('src.server.setup_server_socket', return_value=mock_server_socket) as mock_setup_socket, \
         patch('src.server.threading.Thread') as mock_thread, \
         patch('src.server.config', mock_config), \
         patch('src.server.logger') as mock_logger:

        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # Simulate an exception to exit the loop
        mock_server_socket.accept.side_effect = Exception("Stop the loop")

        start_server()

        mock_setup_logging.assert_called_once()
        mock_signal.assert_has_calls([
            call(signal.SIGTERM, signal_handler),
            call(signal.SIGINT, signal_handler)
        ])
        mock_setup_socket.assert_called_once_with('localhost', 8000, False)
        mock_logger.info.assert_has_calls([
            call("Server started on localhost:8000"),
            call("Using file: /path/to/file"),
            call("Reread on query: True")
        ])
        mock_logger.error.assert_called_once_with("Error in main server loop: Stop the loop")
        mock_server_socket.close.assert_called_once()

def test_stop_daemon():
    with patch('src.server.os.path.exists', return_value=True) as mock_exists, \
         patch('src.server.open', mock_open(read_data="12345")) as mock_open_file, \
         patch('src.server.os.kill') as mock_kill, \
         patch('src.server.time.sleep') as mock_sleep, \
         patch('src.server.os.remove') as mock_remove, \
         patch('src.server.logger') as mock_logger:

        mock_kill.side_effect = [None, OSError()]

        stop_daemon()

        mock_exists.assert_called_once_with(PID_FILE)
        mock_open_file.assert_called_once_with(PID_FILE, 'r')
        mock_kill.assert_has_calls([
            call(12345, signal.SIGTERM),
            call(12345, 0)
        ])
        mock_sleep.assert_called_once_with(1)
        mock_remove.assert_called_once_with(PID_FILE)
        mock_logger.info.assert_has_calls([
            call("Stopping server daemon..."),
            call("Sent SIGTERM to process 12345")
        ])

def test_stop_daemon_no_pid_file():
    with patch('src.server.os.path.exists', return_value=False) as mock_exists, \
         patch('src.server.logger') as mock_logger:

        stop_daemon()

        mock_exists.assert_called_once_with(PID_FILE)
        mock_logger.warning.assert_called_once_with("PID file not found. Is the daemon running?")

def test_invalid_configuration():
    """Test that invalid configuration raises ValueError"""
    invalid_config = configparser.ConfigParser()
    invalid_config['server'] = {'host': '127.0.0.1'}  # Missing required fields

    with patch('src.server.load_config', return_value=invalid_config):
        with patch('os.path.exists', return_value=False):  # Simulate file not found
            with pytest.raises(FileNotFoundError):
                server.load_and_validate_config()

def test_search_query_reread_false():
    """Test search_query function when reread_on_query is False"""
    server.config['reread_on_query'] = False
    server.file_set = set(['test_query', 'another_query'])

    assert server.search_query('test_query') == "STRING EXISTS"
    assert server.search_query('non_existent') == "STRING NOT FOUND"

if __name__ == '__main__':
    pytest.main()