import configparser
import signal
import ssl
import threading
import sys
import time
import logging
import socket
import os
from mmap import mmap as mmap_func
from typing import Set, Dict, Any, Tuple
from logging.handlers import RotatingFileHandler

# Locks
connection_lock: threading.Lock = threading.Lock()
file_lock: threading.Lock = threading.Lock()
connection_count_lock = threading.Lock()
connection_count = 0

# Directory and file paths
SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))
BASE_DIR: str = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
FILE_RELATIVE_PATH: str = os.path.join(BASE_DIR, "200k.txt")
CONFIG_PATH: str = os.path.join(BASE_DIR, "config", "config.ini")
PID_FILE: str = os.path.join(BASE_DIR, "server_daemon.pid")
LOG_FILE: str = os.path.join(BASE_DIR, "logs", "server.log")
SQLITE_DB_PATH: str = os.path.join(BASE_DIR, "search_index.db")

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

class TokenBucket:
    """
    Implements a token bucket algorithm for rate limiting.

    This class manages a token bucket with a specified capacity and fill rate,
    allowing for controlled consumption of tokens over time.
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

logger = logging.getLogger('Server')

def setup_logging() -> logging.Logger:
    """
    Set up and configure the logger for the server.

    Returns:
        logging.Logger: Configured logger instance.
    """
    log_file = os.path.join(BASE_DIR, 'logs', 'server.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger('Server')
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s: %(message)s'
    )

    # File handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=MAX_LOG_SIZE,
        backupCount=MAX_LOG_BACKUPS
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

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
    """
    config = load_config(CONFIG_PATH)
    server_config = {
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
        'linuxpath': config.get(
            'server', 'linuxpath',
            fallback=FILE_RELATIVE_PATH
        ),
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
    }

    if server_config['ssl']:
        cert_path = os.path.join(BASE_DIR, server_config['cert_file'])
        key_path = os.path.join(BASE_DIR, server_config['key_file'])
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            raise FileNotFoundError(
                f"SSL certificate or key file not found. "
                f"Cert path: {cert_path}, Key path: {key_path}")

    if not os.path.exists(server_config['linuxpath']):
        raise FileNotFoundError(
            f"File not found: {server_config['linuxpath']}"
        )

    return server_config

config = load_and_validate_config()

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
    with open(config['linuxpath'], 'r') as f:
        return query in f.read().splitlines()

def initialize_set_mmap():
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
    Search for the query in the file or cached data structures.

    Args:
        query (str): The string to search for.

    Returns:
        Tuple[str, float]: A tuple containing the result string
        and the execution time in milliseconds.
    """
    global file_set, file_mmap

    start_time = time.perf_counter_ns()

    if config['reread_on_query']:
        try:
            if file_mmap is None:
                initialize_set_mmap()

            if file_mmap is None:
                raise RuntimeError("Failed to initialize memory-mapped file")

            # Re-read the file contents using mmap
            file_content = file_mmap[:]
            file_lines = file_content.decode('utf-8').splitlines()
            result = "STRING EXISTS" if query in file_lines else "STRING NOT FOUND"
        except Exception as e:
            logger.error(f"Error reading file: {str(e)}")
            result = "ERROR: Unable to read file"
    else:
        if file_set is None:
            initialize_set_mmap()

        if file_set is None:
            result = "ERROR: Unable to initialize file set"
        else:
            result = "STRING EXISTS" if query in file_set else "STRING NOT FOUND"

    return result

cleanup_lock = threading.Lock()
cleanup_done = False

def cleanup_resources():
    """
    Clean up global resources used by the server.

    This function closes the memory-mapped file if it exists and resets the file set.
    It uses a lock to ensure thread-safety and a flag to prevent multiple cleanups.
    """
    global file_mmap, file_set, cleanup_done

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
            start_time = time.perf_counter_ns()
            query = client_socket.recv(MAX_PAYLOAD_SIZE).decode('utf-8').strip()
            if not query:
                break
            # check for rate limiting
            if not TOKEN_BUCKET.consume(1):
                client_socket.sendall("RATE_LIMITED\n".encode('utf-8'))
                continue
                
            result = search_query(query)
            execution_time = (time.perf_counter_ns() - start_time) / 1_000_000  # Convert ns to ms
            response = f"{result}\n"
            client_socket.sendall(response.encode('utf-8'))
            end_time = time.perf_counter_ns()

            round_trip_time = (end_time - start_time) / 1_000_000  # Convert ns to ms
            logger.debug(
                f"Query: '{query}', "
                f"IP: {client_address[0]}:{client_address[1]}, "
                f"Result: '{result}', Execution-Time: {execution_time:.6f} ms, "
                f"Round-trip: {round_trip_time:.6f} ms"
            )

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

def start_server(daemon_logger=None) -> None:
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
        logger = setup_logging()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    server_socket = setup_server_socket(config['host'],
                                        config['port'], config['ssl']
                                        )
    logger.info(f"Server started on {config['host']}:{config['port']}")

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
    """
    Create and configure an SSL context for secure server connections.

    Returns:
        ssl.SSLContext: Configured SSL context with loaded certificate chain.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=os.path.join(BASE_DIR, config['cert_file']),
                            keyfile=os.path.join(BASE_DIR, config['key_file']))
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
    logger.info("Received signal to terminate. Shutting down...")
    cleanup_resources()
    sys.exit(0)

def stop_daemon() -> None:
    """
    Stop the daemon process.
    """
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        logger.info(f"Sent SIGTERM to process {pid}")
    except FileNotFoundError:
        logger.error("PID file not found. Is the daemon running?")
    except ProcessLookupError:
        logger.error(f"No process found with PID {pid}")
    except Exception as e:
        logger.error(f"Error stopping daemon: {str(e)}")


if __name__ == "__main__":
    start_server()