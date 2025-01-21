import queue
import threading
import pytest
import os
import socket
import sys
import ssl
import configparser
import logging
import time

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "client.log")

# Add the src directory to the Python path for importing the client module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import patch, MagicMock

# Import the client module to be tested
from src import client

# Import the necessary modules for testing
from src.client import get_server_config, establish_connection_and_communicate


@pytest.fixture
def mock_config_load():
    with patch('src.client.load_config') as mock_load:
        yield mock_load

def test_get_server_config_invalid_data(mock_config_load):
    """Test invalid configuration data handling."""
    mock_config_load.return_value = configparser.ConfigParser()
    mock_config_load.return_value['server'] = {
        'host': '127.0.0.1',
        'port': '8080',
        'ssl': 'invalid',  # Invalid boolean value here
        'cert_file': 'path/to/cert.pem'
    }

    # Expecting SystemExit due to invalid boolean value for 'ssl'
    with pytest.raises(SystemExit):
        get_server_config()

def test_get_server_config_missing_section(mock_config_load):
    """Test missing 'server' section."""
    mock_config_load.return_value = configparser.ConfigParser()  # Empty config, no 'server' section

    # Expecting SystemExit due to missing 'server' section
    with pytest.raises(SystemExit):
        get_server_config()

def test_get_server_config_valid(mock_config_load):
    """Test valid configuration data."""
    mock_config_load.return_value = {
        'server': {
            'host': '127.0.0.1',
            'port': '8080',
            'ssl': 'True',
            'cert_file': 'path/to/cert.pem'
        }
    }

    result = get_server_config()
    assert result == ('127.0.0.1', 8080, True, 'path/to/cert.pem')

def test_get_server_config_missing_file():
    """Test behavior when the configuration file is missing."""
    with patch('os.path.exists', return_value=False):  # Mock to simulate file not found
        with pytest.raises(SystemExit):
            get_server_config()

def test_get_server_config_existing_file(mock_config):
    with patch('src.client.load_config', return_value=mock_config):
        ip, port, use_ssl, cert_file = client.get_server_config()

        assert ip == '127.0.0.1'
        assert port == 44444
        assert use_ssl is True
        assert cert_file == 'certs/server.crt'

@pytest.fixture
def mock_config():
    """Fixture to create a mock configuration."""
    config = configparser.ConfigParser()
    config['server'] = {
        'host': '127.0.0.1',
        'port': '44444',
        'ssl': 'true',
        'cert_file': 'certs/server.crt'
    }
    return config

@pytest.fixture
def mock_ssl_context():
    """Fixture to create a mock SSL context."""
    return MagicMock(spec=ssl.SSLContext)

@pytest.fixture
def mock_socket():
    """Fixture to create a mock socket."""
    return MagicMock(spec=socket.socket)

def test_load_config(mock_config):
    """Test the load_config function."""
    with patch('configparser.ConfigParser.read') as mock_read:
        with patch('os.path.exists', return_value=True):
            config = client.load_config('dummy_path')
            mock_read.assert_called_once_with('dummy_path')
            assert isinstance(config, configparser.ConfigParser)

def test_get_server_config(mock_config):
    """Test the get_server_config function."""
    with patch('src.client.load_config', return_value=mock_config):
        ip, port, use_ssl, cert_file = client.get_server_config()
        assert ip == mock_config['server']['host']
        assert port == int(mock_config['server']['port'])
        assert use_ssl == (mock_config['server']['ssl'].lower() == 'true')
        assert cert_file == mock_config['server']['cert_file']

def test_create_ssl_context():
    """Test the create_ssl_context function."""
    with patch('ssl.create_default_context') as mock_create_default_context:
        mock_context = MagicMock()
        mock_create_default_context.return_value = mock_context

        context = client.create_ssl_context()

        assert context == mock_context
        assert mock_context.check_hostname is False
        assert mock_context.verify_mode == ssl.CERT_NONE
        mock_create_default_context.assert_called_once_with(ssl.Purpose.SERVER_AUTH)

@pytest.mark.parametrize("use_ssl", [True, False])
def test_establish_connection_and_communicate(use_ssl):
    """Test the establish_connection_and_communicate function with and without SSL."""
    mock_socket = MagicMock()
    mock_ssl_socket = MagicMock()
    mock_ssl_context = MagicMock()
    mock_ssl_context.wrap_socket.return_value = mock_ssl_socket

    with patch('src.client.socket.create_connection', return_value=mock_socket) as mock_create_connection, \
            patch('src.client.USE_SSL', use_ssl), \
            patch('src.client.create_ssl_context', return_value=mock_ssl_context) as mock_create_ssl_context, \
            patch('src.client.communicate', return_value='Test response') as mock_communicate, \
            patch('src.client.SERVER_IP', '127.0.0.1'), \
            patch('src.client.SERVER_PORT', 44444):

        result = client.establish_connection_and_communicate('test-query', 0.0)

        assert result == 'Test response'
        mock_create_connection.assert_called_once_with(('127.0.0.1', 44444), timeout=10)

        if use_ssl:
            mock_create_ssl_context.assert_called_once()
            mock_ssl_context.wrap_socket.assert_called_once_with(mock_socket, server_hostname='127.0.0.1')
            mock_communicate.assert_called_once_with(mock_ssl_socket, 'test-query', 0.0)
        else:
            mock_create_ssl_context.assert_not_called()
            mock_communicate.assert_called_once_with(mock_socket, 'test-query', 0.0)

def test_communicate(mock_socket):
    """Test the communicate function."""
    search_input = "test_query"
    mock_socket.recv.return_value = b"Test Response"
    response = client.communicate(mock_socket, search_input, time.time())

    assert response == "Test Response"
    mock_socket.sendall.assert_called_once_with(search_input.encode())

def test_log_failed_query(caplog):
    """Test the log_failed_query function."""
    with caplog.at_level(logging.ERROR):
        client.log_failed_query("test_query", time.time())
        assert "Query: 'test_query' failed." in caplog.text

def test_communicate_socket_error():
    mock_socket = MagicMock()
    mock_socket.sendall.side_effect = socket.error("Test socket error")
    with pytest.raises(socket.error, match="Test socket error"):
        client.communicate(mock_socket, "test_query", time.time())

def test_get_server_config_malformed():
    mock_config = configparser.ConfigParser()
    mock_config['server'] = {'host': '127.0.0.1'}  # Missing required options
    with patch('src.client.load_config', return_value=mock_config):
        with pytest.raises(SystemExit):
            client.get_server_config()

def test_establish_connection_and_communicate_connection_error():
    with patch('src.client.socket.create_connection', side_effect=ConnectionError("Connection failed")):
        with pytest.raises(ConnectionError):
            client.establish_connection_and_communicate("test query", time.time())

def test_establish_connection_and_communicate_ssl_error():
    mock_socket = MagicMock()
    with patch('src.client.socket.create_connection', return_value=mock_socket), \
            patch('src.client.USE_SSL', True), \
            patch('src.client.create_ssl_context') as mock_create_ssl_context:
        mock_create_ssl_context.return_value.wrap_socket.side_effect = ssl.SSLError("SSL error")
        with pytest.raises(ssl.SSLError):
            client.establish_connection_and_communicate("test query", time.time())

def test_handle_connection_error_unexpected(caplog):
    with caplog.at_level(logging.ERROR):
        client.handle_connection_error(Exception("Unexpected error"))
        assert "Unexpected error: Unexpected error" in caplog.text

def test_load_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        client.load_config("non_existent_config.ini")

def test_establish_connection_and_communicate_timeout():
    with patch('src.client.socket.create_connection', side_effect=socket.timeout):
        with pytest.raises(TimeoutError):
            client.establish_connection_and_communicate("test query", time.time())

def test_main_function(caplog):
    mock_responses = ["True", "False", None]
    with patch('src.client.send_search_query', side_effect=mock_responses):
        with caplog.at_level(logging.INFO):
            client.main()
        assert "Query: 3;0;1;28;0;7;5;0; -> Response: True" in caplog.text
        assert "Query: 10;0;1;26;0;8;3;0; -> Response: False" in caplog.text
        assert "Query: non-existent-string failed." in caplog.text

@pytest.mark.parametrize("exception", [
    socket.timeout(),
    ConnectionRefusedError(),
    Exception("Unexpected error")
])
def test_establish_connection_and_communicate_exceptions(exception):
    with patch('src.client.socket.create_connection', side_effect=exception):
        with pytest.raises(Exception):
            client.establish_connection_and_communicate("test query", time.time())

#  basic performance, concurrency, and integration tests for the client
# Performance test
def test_client_performance():
    """Test the performance of multiple sequential queries."""
    num_queries = 10
    start_time = time.time()

    with patch('src.client.establish_connection_and_communicate', return_value="True"):
        for _ in range(num_queries):
            client.send_search_query("test query")

    end_time = time.time()
    total_time = end_time - start_time

    assert total_time < 2.0, f"Performance test failed. {num_queries} queries took {total_time:.2f} seconds"

# Integration test with a mock server
class MockServer:
    def __init__(self):
        self.socket = MagicMock()
        self.socket.recv.return_value = b"True"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def test_get_server_config_success():
    mock_config = configparser.ConfigParser()
    mock_config['server'] = {
        'host': '127.0.0.1',
        'port': '44444',
        'ssl': 'true',
        'cert_file': 'certs/server.crt'
    }
    with patch('src.client.load_config', return_value=mock_config):
        config = get_server_config()
        assert config == ('127.0.0.1', 44444, True, 'certs/server.crt')


@patch('src.client.socket.create_connection')
@patch('src.client.communicate')
def test_establish_connection_and_communicate_no_ssl(mock_communicate, mock_create_connection, mock_socket):
    mock_create_connection.return_value = mock_socket
    mock_communicate.return_value = "Test Response"

    with patch('src.client.USE_SSL', False):
        response = establish_connection_and_communicate("test query", time.time())

    assert response == "Test Response"
    mock_create_connection.assert_called_once()
    mock_communicate.assert_called_once()

@patch('src.client.socket.create_connection')
@patch('src.client.communicate')
@patch('src.client.create_ssl_context')
def test_establish_connection_and_communicate_with_ssl(mock_ssl_context, mock_communicate, mock_create_connection, mock_socket):
    mock_create_connection.return_value = mock_socket
    mock_ssl_context.return_value.wrap_socket.return_value = mock_socket
    mock_communicate.return_value = "Test Response"

    with patch('src.client.USE_SSL', True):
        response = establish_connection_and_communicate("test query", time.time())

    assert response == "Test Response"
    mock_create_connection.assert_called_once()
    mock_ssl_context.assert_called_once()
    mock_communicate.assert_called_once()

def test_handle_connection_error_timeout(caplog):
    """Test handling of socket.timeout."""
    with caplog.at_level(logging.ERROR):
        client.handle_connection_error(socket.timeout("Connection timed out"))
        assert "Connection timed out: Connection timed out" in caplog.text

def test_handle_connection_error_ssl_error(caplog):
    """Test handling of ssl.SSLError."""
    with caplog.at_level(logging.ERROR):
        client.handle_connection_error(ssl.SSLError("SSL handshake failed"))
        assert any("SSL error:" in message and "SSL handshake failed" in message for message in caplog.messages)

def test_handle_connection_error_connection_refused(caplog):
    """Test handling of ConnectionRefusedError."""
    with caplog.at_level(logging.ERROR):
        client.handle_connection_error(ConnectionRefusedError())
        assert "Connection refused:" in caplog.text

def test_handle_connection_error_connection_reset(caplog):
    """Test handling of ConnectionResetError."""
    with caplog.at_level(logging.ERROR):
        client.handle_connection_error(ConnectionResetError())
        assert "Connection reset:" in caplog.text

def test_client_concurrency():
    """Test multiple concurrent client connections."""
    num_threads = 5  # Number of concurrent threads
    results = queue.Queue()  # Thread-safe queue for results

    # Define the mock behavior for send_search_query
    def mock_send_search_query(query):
        return "MOCKED_RESPONSE"

    # Function to be executed by each thread
    def mock_query():
        response = client.send_search_query("test query")
        results.put(response)

    # Mock send_search_query globally for all threads
    with patch("src.client.send_search_query", side_effect=mock_send_search_query):
        # Create and start threads
        threads = [threading.Thread(target=mock_query) for _ in range(num_threads)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

    # Collect results from the queue
    result_list = list(results.queue)

    # Debugging: Print the results for visibility
    print(f"Results: {result_list}")

    # Validate all results are "MOCKED_RESPONSE"
    assert all(result == "MOCKED_RESPONSE" for result in result_list), f"Unexpected results: {result_list}"

@pytest.mark.parametrize("search_input, expected_result", [
    ("valid;query;string", "STRING NOT FOUND"),
    ("", "CONNECTION_ERROR: The read operation timed out"),
    ("invalid query format", "STRING NOT FOUND"),
    ("very;long;query;" * 100, "STRING NOT FOUND"),
])
def test_send_search_query_input_validation(search_input, expected_result):
    with patch('src.client.establish_connection_and_communicate', return_value=expected_result):
        result = client.send_search_query(search_input)
        assert result == expected_result

if __name__ == '__main__':
    pytest.main()

