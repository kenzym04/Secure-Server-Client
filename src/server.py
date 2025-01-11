"""
Server Module for Secure, Concurrent, and Efficient Text-Based Query Processing

This module implements a robust server that supports multiple concurrent client connections
and processes text-based search queries with high efficiency. Key features include:

Features:
    - Secure Communication: Utilizes SSL/TLS for encrypted client-server communication,
      ensuring data privacy and integrity.
    - Configurable Settings: Allows easy customization through an external config.ini file,
      enabling flexible configuration of server parameters.
    - Multithreading: Handles multiple client connections concurrently, ensuring scalability
      and responsiveness.
    - Dynamic File Reload: Offers an option to reload file contents on each query based on the
      REREAD_ON_QUERY configuration, accommodating dynamic file changes.
    - Daemon Mode: Supports running the server as a background process, enabling seamless
      integration into production environments.
    - Rotating Logs: Maintains detailed server and client activity logs with automatic size-based
      rotation to prevent log file overflow.
    - File Searching: Executes text-based search queries against a preloaded text file, ensuring
      results are returned only for full line matches of the query, with no partial match counts.
    - Rate Limiting: Implements a Token Bucket mechanism to regulate the frequency of client
      requests, preventing abuse and ensuring fair resource usage.
    - Unlimited Concurrent Connections: Designed to handle an unlimited number of concurrent
      client connections, ensuring robustness under heavy load.
    - Efficient Caching: Utilizes in-memory caching of file contents for fast query responses,
      significantly reducing file access latency when REREAD_ON_QUERY is disabled.

This module adheres to best practices for Python development, ensuring maintainability, clarity,
and performance.
"""

import configparser
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
from mmap import mmap as mmap_func
from logging.handlers import RotatingFileHandler
from typing import Set, Dict, Any, Tuple, Optional

# Dynamic Path and Directory Configuration
SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
BASE_DIR: str = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_CONFIG_DIR = os.getenv('CONFIG_DIR', os.path.join(BASE_DIR, "config"))
DEFAULT_LOG_DIR = os.getenv('LOG_DIR', os.path.join(BASE_DIR, "logs"))
DEFAULT_CERT_DIR = os.getenv('CERT_DIR', os.path.join(BASE_DIR, "certs"))
DEFAULT_DATA_DIR = os.getenv('DATA_DIR', os.path.join(BASE_DIR, "data"))
FILE_RELATIVE_PATH: str = os.getenv('FILE_PATH', os.path.join(DEFAULT_DATA_DIR, "200k.txt"))
CONFIG_PATH: str = os.path.join(BASE_DIR, "config", "config.ini")
PID_FILE: str = os.getenv('PID_FILE', os.path.join(BASE_DIR, "server_daemon.pid"))
LOG_FILE: str = os.path.join(BASE_DIR, "logs", "server.log")

logger = logging.getLogger('Server')

# Locks
connection_lock: threading.Lock = threading.Lock()
file_lock: threading.Lock = threading.Lock()
connection_count_lock = threading.Lock()
connection_count = 0

# File size and log constraints
MAX_PAYLOAD_SIZE: int = 1024
MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB
MAX_LOG_SIZE: int = 10 * 1024 * 1024  # 10 MB
MAX_LOG_BACKUPS: int = 5

# Rate limiting constants
MAX_CLIENT_TOKENS: int = 10
CLIENT_TOKEN_REFILL_RATE: float = 1.0  # 1 token per second

# Global variables
cached_file_contents: Set[str] = set()
client_token_buckets: Dict[str, 'TokenBucket'] = {}
file_set = None
file_mmap = None

def validate_environment():
    """
    Validate the existence of critical directories required for the server.

    This function checks the presence of directories and files needed for
    the server's operation. If any path is missing, it logs a warning with
    the corresponding description.

    Paths validated:
        - Configuration directory
        - Log directory
        - Certificate directory
        - Data directory
        - PID file directory

    Logging:
        Logs a warning for each missing path.

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

class TokenBucket:
    """
    Implements a token bucket algorithm to control the rate of requests.

    The token bucket accumulates tokens over time at a specified rate,
    allowing controlled consumption for rate limiting.
    """

    def __init__(self, capacity: int, fill_rate: float):
        """
        Initialize the TokenBucket.

        Args:
            capacity (int): The maximum number of tokens the bucket can hold.
            fill_rate (float): The rate at which tokens are added to the
                               bucket (tokens per second).
        """
        self.capacity: int = capacity
        self.fill_rate: float = fill_rate
        self.tokens: float = capacity
        self.last_fill: float = time.time()
        self.lock: threading.Lock = threading.Lock()

    def consume(self, tokens: int) -> bool:
        """
        Attempt to consume a specified number of tokens from the bucket.

        Args:
            tokens (int): The number of tokens to consume.

        Returns:
            bool: True if the tokens were successfully consumed, False otherwise.
        """
        with self.lock:
            now = time.time()
            time_passed = now - self.last_fill
            self.tokens = min(
                self.capacity,
                int(self.tokens + time_passed * self.fill_rate)
            )
            self.last_fill = now

            if tokens <= self.tokens:
                self.tokens -= tokens
                return True
            return False

TOKEN_BUCKET = TokenBucket(capacity=100, fill_rate=10)  # 100 tokens, refills at 10 tokens/sec

def setup_logging() -> None:
    """
    Configure the server's logging system.

    Sets up a rotating file handler and console handler to log messages.
    Logs are written to a predefined log file with DEBUG level by default.
    """
    global logger

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s: %(message)s'
    )

    # File handler
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=MAX_LOG_BACKUPS
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    if not hasattr(file_handler, "filters"):
        file_handler.filters = []  # Ensure compatibility with custom setups

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    if not hasattr(console_handler, "filters"):
        console_handler.filters = []  # Ensure compatibility with custom setups

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.debug(f"Using LOG_FILE: {LOG_FILE}")
    logger.debug(f"Using PID_FILE: {PID_FILE}")


def load_config(config_path: str) -> configparser.ConfigParser:
    """
    Load the configuration from the specified file path.

    Args:
        config_path (str): The path to the configuration file.

    Returns:
        configparser.ConfigParser: A ConfigParser object containing the loaded configuration.
    """
    config = configparser.ConfigParser()
    config.read(config_path)
    return config

def load_and_validate_config() -> Dict[str, Any]:
    """
    Load and validate the server configuration from the config file.

    Returns:
        Dict[str, Any]: A dictionary containing the validated server configuration.

    Raises:
        FileNotFoundError: If SSL certificates or specified file path are not found.
        ValueError: If configuration values are invalid.
    """

    config = load_config(CONFIG_PATH)

    server_config: Dict[str, Any] = {
        'host': config.get('server', 'host', fallback='127.0.0.1'),
        'port': config.getint('server', 'port', fallback=44444),
        'ssl': config.getboolean('server', 'ssl', fallback=False),
        'cert_file': config.get(
            'server', 'cert_file',
            fallback='certs/server.crt'
        ),
        'key_file': config.get(
            'server',
            'key_file',
            fallback='certs/server.key'
        ),
        'linuxpath': str(config.get(
            'server', 'linuxpath',
            fallback=FILE_RELATIVE_PATH
        )),
        'reread_on_query': config.getboolean(
            'server',
            'reread_on_query',
            fallback=False
        ),
        'token_bucket_capacity': config.getint(
            'server', 'token_bucket_capacity',
            fallback=100
        ),
        'token_bucket_fill_rate': config.getfloat(
            'server', 'token_bucket_fill_rate',
            fallback=10.0
        ),
        'file_path': config.get('server', 'file_path', fallback=FILE_RELATIVE_PATH),
        'log_file': config.get('server', 'log_file', fallback=LOG_FILE),
        'pid_file': config.get('server', 'pid_file', fallback='server_daemon.pid'),
    }

    # Type checking
    if not isinstance(server_config['port'], int):
        raise TypeError("Port must be an integer")
    if not isinstance(server_config['file_path'], str):
        raise TypeError("File path must be a string")
    if not isinstance(server_config['log_file'], str):
        raise TypeError("Log file path must be a string")
    if not isinstance(server_config['linuxpath'], str):
        raise TypeError("Linux path must be a string")
    if not isinstance(server_config['token_bucket_capacity'], int):
        raise TypeError("Token bucket capacity must be an integer")
    if not isinstance(server_config['token_bucket_fill_rate'], float):
        raise TypeError("Token bucket fill rate must be a float")

    # Validate token bucket parameters
    if server_config['token_bucket_capacity'] <= 0:
        raise ValueError("Token bucket capacity must be positive")
    if server_config['token_bucket_fill_rate'] <= 0:
        raise ValueError("Token bucket fill rate must be positive")

    # Validate host
    if not server_config['host']:
        raise ValueError("Host cannot be empty")

    # Validate port
    if not 1 <= server_config['port'] <= 65535:
        raise ValueError(f"Invalid port number: {server_config['port']}")

    # Validate SSL configuration
    if server_config['ssl']:
        cert_path = os.path.join(DEFAULT_CERT_DIR, server_config['cert_file'])
        key_path = os.path.join(DEFAULT_CERT_DIR, server_config['key_file'])
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            raise FileNotFoundError(
                f"SSL certificate or key file not found. "
                f"Cert path: {cert_path}, Key path: {key_path}")

    # Validate linuxpath
    if not os.path.exists(server_config['linuxpath']):
        raise FileNotFoundError(
            f"File not found: {server_config['linuxpath']}"
        )

    # Validate token bucket parameters
    if server_config['token_bucket_capacity'] <= 0:
        raise ValueError("Token bucket capacity must be positive")
    if server_config['token_bucket_fill_rate'] <= 0:
        raise ValueError("Token bucket fill rate must be positive")

    return server_config

config: Dict[str, Any] = load_and_validate_config()

def get_client_bucket(ip: str) -> TokenBucket:
    """
    Retrieve or create a TokenBucket for a given client IP address.

    Args:
        ip (str): The IP address of the client.

    Returns:
        TokenBucket: A TokenBucket instance for the specified client IP.
    """
    if ip not in client_token_buckets:
        client_token_buckets[ip] = TokenBucket(
            capacity=MAX_CLIENT_TOKENS,
            fill_rate=CLIENT_TOKEN_REFILL_RATE
        )
    return client_token_buckets[ip]

def optimized_read_file(query: str) -> bool:
    """
    Perform an optimized search for a query string in the configured file.

    Args:
        query (str): The string to search for in the file.

    Returns:
        bool: True if the query is found in the file, False otherwise.
    """
    global file_set, file_mmap
    try:
        # Ensure linuxpath is a string
        file_path = str(config['linuxpath'])
        with open(file_path, 'r') as f:
            return query in f.read().splitlines()
    except Exception as e:
        logger.error(f"Error in optimized_read_file: {str(e)}")
        return False

def initialize_set_mmap() -> None:
    """
    Initialize global file_set and file_mmap for efficient file content access.

    This function uses memory mapping to read the file specified in the configuration,
    creating a set of all lines for quick lookups. It performs the following:

    1. Opens the file in binary read-write mode.
    2. Creates a memory-mapped object of the file.
    3. Reads and decodes the entire content to UTF-8.
    4. Splits the content into lines and creates a set of stripped lines.

    Global variables:
        file_set (Set[str]): Set containing all stripped lines from the file.
        file_mmap (mmap): Memory-mapped object of the file.

    Raises:
        Exception: Logs any error during initialization and sets file_set to an
                   empty set and file_mmap to None.
    """
    global file_set, file_mmap
    try:
        linuxpath = config['linuxpath']
        if not isinstance(linuxpath, str):
            raise TypeError("linuxpath must be a string")

        with open(config['linuxpath'], 'r+b') as f:
            file_mmap = mmap_func(f.fileno(), 0)
            # Convert mmap object to bytes, then decode to string
            file_content = file_mmap[:]  # This creates a bytes object from mmap
            file_lines = file_content.decode('utf-8').splitlines()
            file_set = set(line.strip() for line in file_lines)
    except Exception as e:
        logger.error(f"Error initializing set and mmap: {str(e)}")
        file_set = set()
        file_mmap = None

def search_query(query: str) -> str:
    """
    Search for an exact match of the query in the file or cached data structures.

    Args:
        query (str): The string to search for.

    Returns:
        str: A string indicating whether the exact query was found or not.
    """
    global file_set, file_mmap

    # Ensure initialization is outside of timing
    if config['reread_on_query']:
        if file_mmap is None:
            initialize_set_mmap()

        if file_mmap is None:
            logger.error("Failed to initialize memory-mapped file")
            return "ERROR: Unable to initialize memory-mapped file"

        try:
            # Measure execution time only for the search operation
            start_time = time.perf_counter_ns()
            file_content = file_mmap[:]
            file_lines = file_content.decode('utf-8').splitlines()
            result = "STRING EXISTS" if query in file_lines else "STRING NOT FOUND"
            end_time = time.perf_counter_ns()
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            return "ERROR: Unable to read file"
    else:
        if file_set is None:
            initialize_set_mmap()

        if file_set is None:
            logger.error("Failed to initialize file set")
            return "ERROR: Unable to initialize file set"

        # Measure execution time only for the search operation
        start_time = time.perf_counter_ns()
        result = "STRING EXISTS" if query in file_set else "STRING NOT FOUND"
        end_time = time.perf_counter_ns()

    execution_time_ms = (end_time - start_time) / 1_000_000  # Convert ns to ms

    logger.info(f"Search query: {query} - {result} Server Execution Time: {execution_time_ms:.2f} ms")

    return result

cleanup_lock = threading.Lock()
cleanup_done = False

def cleanup_resources() -> None:
    """
    Clean up global resources used by the server.

    This function performs the following cleanup tasks:
    - Closes the memory-mapped file if it exists
    - Resets the file set
    - Clears the client token buckets
    - Releases any other resources that need cleanup

    It uses a lock to ensure thread-safety and a flag to prevent multiple cleanups.

    Global variables affected:
        file_mmap (mmap.mmap): Memory-mapped file object
        file_set (Set[str]): Set containing file contents
        cleanup_done (bool): Flag to track if cleanup has been performed
        client_token_buckets (Dict): Dictionary of client token buckets

    Note:
        This function should be called before server shutdown or when resources
        need to be freed.
    """
    global file_mmap, file_set, cleanup_done, client_token_buckets

    with cleanup_lock:
        if cleanup_done:
            logger.info("Cleanup already performed. Skipping.")
            return

        if file_mmap is not None:
            try:
                file_mmap.close()
            except Exception as e:
                logger.error(f"Error closing file_mmap: {str(e)}")
            finally:
                file_mmap = None

        file_set = None
        client_token_buckets.clear()

        cleanup_done = True
        logger.info("Resources cleaned up successfully.")

def handle_client(
        client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
    """
    Handle a client connection and process requests.
    Args:
        client_socket (socket.socket): The connected client socket.
        client_address (Tuple[str, int]): Client's IP address and port.
    This function:
    - Increments the global connection count.
    - Receives and processes client queries.
    - Sends responses back to the client.
    - Logs query details and execution times.
    - Handles exceptions and closes the connection.
    - Decrements the connection count upon completion.
    Affects global: connection_count
    """
    global connection_count
    with connection_count_lock:
        connection_count += 1
    logger.debug(
        f"New connection from {client_address[0]}:{client_address[1]}. "
        f"Total connections: {connection_count}"
    )

    try:
        while True:
            try:
                query = client_socket.recv(MAX_PAYLOAD_SIZE).decode('utf-8').strip()
                if not query:
                    break
                # check for rate limiting
                if not TOKEN_BUCKET.consume(1):
                    client_socket.sendall("RATE_LIMITED\n".encode('utf-8'))
                    continue

                start_time = time.perf_counter_ns()
                result = search_query(query)
                round_trip_time = (time.perf_counter_ns() - start_time) / 1_000_000  # Convert ns to ms = time.perf_counter_ns()

                response = f"{result}\n"
                client_socket.sendall(response.encode('utf-8'))

                logger.debug(
                    f"Query: '{query}', "
                    f"IP: {client_address[0]}:{client_address[1]}, "
                    f"Server Round-trip Execution Time: {round_trip_time:.6f} ms"
                )
            except socket.error as e:
                logger.error(f"Socket error while receiving data: {str(e)}")
                break
            except UnicodeDecodeError as e:
                logger.error(f"Error decoding received data: {str(e)}")
                continue
    except Exception as e:
        logger.error(f"Error handling client {client_address}: {str(e)}")
    finally:
        client_socket.close()
        with connection_count_lock:
            connection_count -= 1
        logger.debug(
            f"Connection from "
            f"{client_address[0]}:{client_address[1]} closed. "
            f"Total connections: {connection_count}")

def start_server(daemon_logger: Optional[logging.Logger] = None) -> None:
    """
    Initialize and run the server, handling client connections.

    Args:
        daemon_logger: Optional logger for daemon mode. If None, sets up a new logger.

    This function:
    - Sets up logging and initializes resources.
    - Configures signal handlers for graceful shutdown.
    - Creates and binds the server socket.
    - Enters a loop to accept and handle client connections in separate threads.
    - Performs cleanup on exit.

    Raises:
        Logs any exceptions occurring in the main server loop.
    """
    global logger
    if daemon_logger:
        logger = daemon_logger
    else:
        setup_logging()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    server_socket = setup_server_socket(config['host'],
                                        config['port'], config['ssl']
                                        )
    logger.info(f"Server started on {config['host']}:{config['port']}")
    logger.info(f"Using file: {config['linuxpath']}")
    logger.info(f"Reread on query: {config['reread_on_query']}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.start()
    except Exception as e:
        logger.error(f"Error in main server loop: {str(e)}")
    finally:
        cleanup_resources()
        server_socket.close()
        logger.info("Server shutting down.")

def create_ssl_context() -> ssl.SSLContext:
    cert_file = os.getenv('SSL_CERT_FILE', os.path.join(DEFAULT_CERT_DIR, "server.crt"))
    key_file = os.getenv('SSL_KEY_FILE', os.path.join(DEFAULT_CERT_DIR, "server.key"))

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context

def setup_server_socket(ip: str, port: int, use_ssl: bool) -> socket.socket:
    """
    Set up and return a server socket, optionally with SSL.

    Args:
        ip (str): IP address to bind.
        port (int): Port number to bind.
        use_ssl (bool): Whether to use SSL.

    Returns:
        socket.socket: Configured server socket.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((ip, port))
    server_socket.listen(5)

    if use_ssl:
        context = create_ssl_context()
        server_socket = context.wrap_socket(server_socket, server_side=True)

    return server_socket

def signal_handler(signum: int, _: Any) -> None:
    """
    Handle termination signals gracefully.
    """
    logger.info(f"Received signal {signum} to terminate. Shutting down...")
    cleanup_resources()
    logger.info("Server shutdown complete.")
    sys.exit(0)

def stop_daemon() -> None:
    global logger
    logger.info("Stopping server daemon...")
    try:
        if os.path.exists(PID_FILE):
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to process {pid}")
            # Wait for the process to terminate
            for _ in range(10):  # Wait up to 10 seconds
                time.sleep(1)
                try:
                    os.kill(pid, 0)  # Check if process still exists
                except OSError:
                    break
            else:
                logger.warning(f"Process {pid} did not terminate after 10 seconds")
            # Remove PID file
            os.remove(PID_FILE)
        else:
            logger.warning("PID file not found. Is the daemon running?")
    except Exception as e:
        logger.error(f"Error stopping daemon: {str(e)}")

if __name__ == "__main__":
    start_server()