"""
Client Module for Server Interaction

This module defines a client for connecting to a server, sending search queries,
and handling responses. It includes the following features:

1. SSL/TLS support for secure communications.
2. Configurable settings via an external configuration file.
3. Logging of query execution and responses.
4. Comprehensive error handling and reporting.

Supports both SSL and non-SSL connections, detailed logging for performance analysis,
and robust error handling.
"""

import os
import sys
import time
import ssl
import logging
import socket
import configparser
from typing import Tuple, Optional
from logging.handlers import RotatingFileHandler

# Initialize configuration parser
config = configparser.ConfigParser()

# Define dynamic paths
SCRIPT_DIR: str = os.path.dirname(
    os.path.abspath(__file__)
)
BASE_DIR: str = os.path.dirname(SCRIPT_DIR)
DEFAULT_LOG_DIR = os.getenv(
    'LOG_DIR',
    os.path.join(BASE_DIR, "logs")
)
DEFAULT_CONFIG_DIR = os.getenv(
    'CONFIG_PATH',
    os.path.join(BASE_DIR, "config")
)
DEFAULT_DATA_DIR = os.getenv(
    'DATA_DIR',
    os.path.join(BASE_DIR,
                 "data")
)

# Configuration file path
CONFIG_PATH = os.getenv(
    'CONFIG_PATH',
    os.path.join(DEFAULT_CONFIG_DIR,
                 "config.ini")
)
if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(
        f"Configuration file not found: {CONFIG_PATH}"
    )

config.read(CONFIG_PATH)

# Log file path
LOG_FILE = os.getenv(
    'LOG_FILE',
    os.path.join(
        DEFAULT_LOG_DIR,
        "client.log")
)

# Data file path
linuxpath = os.getenv(
    'LINUX_PATH',
    config.get(
        'server',
        'linuxpath',
        fallback=os.path.join(
            DEFAULT_DATA_DIR,
            "200k.txt"))
)

# PID file path
PID_FILE = os.getenv(
    'PID_FILE',
    os.path.join(
        BASE_DIR,
        "server_daemon.pid")
)

# Ensure required directories exist
os.makedirs(DEFAULT_LOG_DIR, exist_ok=True)
os.makedirs(DEFAULT_CONFIG_DIR, exist_ok=True)
os.makedirs(DEFAULT_DATA_DIR, exist_ok=True)

def validate_environment() -> None:
    """
    Validate the existence of critical directories required for the client.

    Logs a warning for any missing paths.

    Returns:
        None
    """
    for path, description in [
        (DEFAULT_CONFIG_DIR, "Configuration file"),
        (DEFAULT_LOG_DIR, "Log directory"),
        (DEFAULT_DATA_DIR, "Data directory"),
        (os.path.dirname(PID_FILE), "PID file directory"),
    ]:
        if not os.path.exists(path):
            logger.warning(f"{description} does not exist: {path}")

def setup_logging() -> logging.Logger:
    """
    Configure logging for the client.

    Returns:
        logging.Logger: A logger instance configured for file and console output.
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)



    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger = setup_logging()

def load_config(
        config_path: str
) -> configparser.ConfigParser:
    """
    Load configuration from a file.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        configparser.ConfigParser: Loaded configuration parser object.

    Raises:
        FileNotFoundError: If the configuration file is not found.
    """
    config_parser = configparser.ConfigParser()
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )
    config_parser.read(config_path)
    return config_parser

def get_server_config() -> Tuple[str, int, bool, str]:
    """
        Load and return server configuration.

        Returns:
            Tuple[str, int, bool, str]: Server IP, port, SSL flag, and certificate file path.

        Raises:
            SystemExit: If there's an error loading the configuration.
        """
    try:
        config = load_config(CONFIG_PATH)

        if 'server' not in config:
            raise configparser.NoSectionError('server')

        server_config = config['server']
        host = server_config.get('host')
        port = server_config.get('port')
        ssl_str = server_config.get('ssl')
        cert_file = server_config.get('cert_file')

        if not all([host, port, ssl_str, cert_file]):
            raise ValueError("Missing required configuration values")

        try:
            port = int(port)
        except ValueError:
            raise ValueError(f"Invalid port number: {port}")

        if ssl_str.lower() not in ['true', 'false']:
            raise ValueError(f"Invalid SSL value: {ssl_str}")

        use_ssl = ssl_str.lower() == 'true'
        return host, port, use_ssl, cert_file
    except (configparser.Error, ValueError, AttributeError) as e:
        logger.error(f"Error in configuration: {str(e)}")
        raise SystemExit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise SystemExit(1)

SERVER_IP, SERVER_PORT, USE_SSL, CERT_FILE = get_server_config()

def create_ssl_context() -> ssl.SSLContext:
    """
    Create and return an SSL context.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Accept self-signed cert
    return context

def send_search_query(search_input: str) -> Optional[str]:
    """Sends a search query to the server and returns its response.

    Args:
        search_input (str): The search query to send.

    Returns:
        Optional[str]: The server's response, or None if the query failed.
    """
    start_time = time.time()
    response = None
    try:
        response = establish_connection_and_communicate(
            search_input, start_time
        )
    except Exception as error:
        handle_connection_error(error)
    finally:
        if response is None:
            log_failed_query(search_input, start_time)

    return response

def establish_connection_and_communicate(
        search_input: str, start_time: float) -> Optional[str]:
    """
    Establish a connection to the server and communicate the search query.

    Args:
        search_input (str): The search query to send.
        start_time (float): The start time of the query.

    Returns:
        Optional[str]: The server's response, or None if the communication failed.

    Raises:
        TimeoutError: If the connection times out.
        ConnectionRefusedError: If the connection is refused.
        Exception: For any other unexpected errors.
    """
    try:
        sock = socket.create_connection((
            SERVER_IP, SERVER_PORT), timeout=10
        )

        if USE_SSL:
            context = create_ssl_context()
            sock = context.wrap_socket(sock, server_hostname=SERVER_IP)

        return communicate(sock, search_input, start_time)

    except socket.timeout:
        logger.error("Connection timed out")
        raise TimeoutError("Connection timed out")
    except ConnectionRefusedError:
        logger.error("Connection refused")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise
    finally:
        if 'sock' in locals():
            sock.close()

def handle_connection_error(error: Exception) -> None:
    """
    Handle and log various connection errors.

    Args:
        error (Exception): The caught exception.
    """
    if isinstance(error, socket.timeout):
        logger.error(f"Connection timed out: {str(error)}")
    elif isinstance(error, ssl.SSLError):
        logger.error(f"SSL error: {str(error)}")
    elif isinstance(error, ConnectionRefusedError):
        logger.error(f"Connection refused: {str(error)}")
    elif isinstance(error, ConnectionResetError):
        logger.error(f"Connection reset: {str(error)}")
    else:
        logger.error(f"Unexpected error: {str(error)}")

def communicate(
        sock: socket.socket, search_input: str, start_time: float) -> str:
    """
    Handle communication with the server.

    Args:
        sock (socket.socket): The socket connection to the server.
        search_input (str): The search query to send.
        start_time (float): The start time of the query.

    Returns:
        str: The server's response.

    Raises:
        socket.error: If a socket error occurs during communication.
    """
    try:
        logger.debug(f"Sending query: {search_input}")
        sock.sendall(search_input.encode('utf-8'))
        server_reply = sock.recv(1024).decode('utf-8').strip()
        end_time = time.time()
        round_trip_time = (end_time - start_time) * 1000  # Convert to milliseconds
        logger.info(
            f"Query: '{search_input}', "
            f"Response: '{server_reply}', "
            f"Client-round-trip Time: {round_trip_time:.6f} ms"
        )
        return server_reply
    except socket.error as e:
        logger.error(f"Socket error during communication: {str(e)}")
        raise  # Re-raise the socket.error

def log_failed_query(search_input: str, start_time: float) -> None:
    """
    Log information for a failed query.

    Args:
        search_input (str): The search query that failed.
        start_time (float): The start time of the query.
    """
    end_time = time.time()
    round_trip_time = (end_time - start_time) * 1000
    logger.error(
        f"Query: '{search_input}' failed. "
        f"Time Taken: {round_trip_time:.2f} ms"
    )

def main() -> None:
    """
    Main function to run test queries.
    """
    test_search_queries = ['3;0;1;28;0;7;5;0;',
                           '10;0;1;26;0;8;3;0;',
                           'non-existent-string'
                           ]

    for current_query in test_search_queries:
        current_response = send_search_query(current_query)
        if current_response is None:
            logger.warning(f"Query: {current_query} failed.")
        else:
            logger.info(f"Query: {current_query} -> Response: {current_response}")

if __name__ == '__main__':
    main()