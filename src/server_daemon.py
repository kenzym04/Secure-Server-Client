"""
Daemonize the current process to run in the background.

Steps:
1. Forks twice to detach from the terminal.
2. Changes the working directory and sets umask.
3. Writes the PID to a file.
4. Redirects standard I/O to /dev/null.
5. Configures signal handlers for termination.

Raises:
    OSError: On fork failure.
    IOError: On PID file write failure.
"""

import os
import socket
import sys
import signal
import time
import logging
import threading
from typing import Any
from logging.handlers import RotatingFileHandler

# Logger setup
logger = logging.getLogger('Server Daemon')

# Add the project root directory to the Python path
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

try:
    from src.server import (
        start_server,
        stop_daemon,
        search_query,
        TOKEN_BUCKET as rate_limiter
    )
except ImportError:
    raise ImportError("Failed to import server module.")

# Constants
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DEFAULT_CONFIG_DIR = os.getenv(
    'CONFIG_DIR', os.path.join(BASE_DIR, "config"))
DEFAULT_LOG_DIR = os.getenv(
    'LOG_DIR', os.path.join(BASE_DIR, "logs")
)
DEFAULT_PID_DIR = os.getenv('PID_DIR', BASE_DIR)
SERVER_HOST = os.getenv('SERVER_HOST', '127.0.0.1')
SERVER_PORT = os.getenv('SERVER_PORT')
if SERVER_PORT is None:
    SERVER_PORT = 44444
    logger.info("SERVER_PORT not set; defaulting to 44444")
SERVER_PORT = int(SERVER_PORT)
PID_FILE = os.getenv(
    'PID_FILE',
    os.path.join(DEFAULT_PID_DIR,
                 "server_daemon.pid")
)
LOG_FILE = os.getenv(
    'LOG_FILE',
    os.path.join(DEFAULT_LOG_DIR,
                 "server_daemon.log")
)

# Global variables
connection_count = 0
connection_lock = threading.Lock()


def validate_environment() -> None:
    """
    Validates critical directories and logs warnings for any missing paths.
    """
    paths_to_check = [
        (DEFAULT_CONFIG_DIR, "Configuration directory"),
        (DEFAULT_LOG_DIR, "Log directory"),
        (DEFAULT_PID_DIR, "PID directory"),
    ]
    for path, description in paths_to_check:
        if not os.path.exists(path):
            logger.warning(f"{description} does not exist: {path}")

def setup_logging() -> logging.Logger:
    """
    Configure logging for the server daemon.

    Returns:
        logging.Logger: Configured logger.
    """
    logger.handlers.clear()

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5)
    console_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.debug(f"Using LOG_FILE: {LOG_FILE}")
    logger.debug(f"Using PID_FILE: {PID_FILE}")
    return logger

def signal_handler(signum: int, _: Any) -> None:
    """
    Handles termination signals to shut down the server daemon.

    Args:
        signum (int): Signal number (e.g., SIGTERM).
        _ (Any): Unused frame argument.
    """
    logger.info(f"Received signal {signum}. Shutting down...")
    sys.exit(0)

# Helper function to redirect standard file descriptors
def redirect_standard_io() -> None:
    """
    Redirect standard I/O streams to /dev/null.
    This is used to detach the daemon process from the terminal.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, 'r') as si, \
         open(os.devnull, 'a+') as so, \
         open(os.devnull, 'a+') as se:
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

def daemonize() -> None:
    """Daemonize the current process, turning it into a background daemon.

    This function performs the following steps:
    1. Forks twice to detach from the terminal.
    2. Changes working directory and sets umask.
    3. Writes PID to a file for management.
    4. Redirects standard I/O to /dev/null.
    5. Sets up signal handlers for graceful termination.

    Raises:
        OSError: If fork operations fail.
        IOError: If writing to the PID file fails.
    """
    global logger
    if logger is None:
        logger = setup_logging()

    # Do first fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork failed: {e.errno} ({e.strerror})")
        sys.exit(1)

    # Decouple from parent environment
    os.chdir(BASE_DIR)
    os.setsid()
    os.umask(0)

    # Do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        logger.error(
            f"Second fork failed: {e.errno} ({e.strerror})"
        )
        sys.exit(1)

    redirect_standard_io()

    # Write PID file
    pid = os.getpid()
    with open(PID_FILE, 'w') as f:
        f.write(str(pid))

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

def run_daemon() -> None:
    """
    Daemonize the current process.
    """
    pid = os.getpid()
    logger.info(f"Starting server in daemon mode | PID: {pid}")
    try:
        start_server(logger)
    except Exception as e:
        logger.error(f"Error in daemon: {str(e)}")
        sys.exit(1)

def handle_request(client_socket: socket.socket) -> None:
    """Handle incoming client requests and manage the client connection.

    Args:
        client_socket (socket.socket): The connected client socket object.

    This function tracks active connections, processes client queries with
    rate limiting, performs search queries, and sends results back to the
    client. It logs various events including new connections, queries, and
    errors, and closes the connection when the client disconnects.
    """
    global connection_count
    client_address = client_socket.getpeername()

    with connection_lock:
        connection_count += 1
        current_count = connection_count

    logger.info(
        f"New connection from {client_address[0]}:{client_address[1]}. "
        f"Total connections: {current_count}")

    while True:
        data = client_socket.recv(1024).decode('utf-8').strip()
        if not data:
            break
        start_time = time.time()

        if rate_limiter.consume(1):
            logger.debug(
                f"Request accepted from {client_address[0]}:{client_address[1]}")
            try:
                result = search_query(data)
                end_time = time.time()
                query_time = end_time - start_time
                logger.debug(
                    f"DEBUG: Query: '{data}', "
                    f"IP: {client_address[0]}:{client_address[1]}, "
                    f"Time: {query_time:.6f}s, "
                    f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                client_socket.send(result.encode('utf-8'))
            except Exception as e:
                logger.error(
                    f"Error handling client {client_address[0]}"
                    f":{client_address[1]}"
                    f": {str(e)}")
        else:
            logger.warning(
                f"Rate limit exceeded for {client_address[0]}:{client_address[1]}")
            client_socket.send(b"Rate limit exceeded. Please try again later.")

    with connection_lock:
        connection_count -= 1
        logger.info(
            f"Connection closed. Total connections: {connection_count}"
        )


def main() -> None:
    """
    Entry point for starting or
    stopping the daemon based on command-line arguments.
    """
    global logger
    logger = setup_logging()

    if len(sys.argv) != 2 or sys.argv[1] not in ['--daemon', 'stop']:
        logger.error(
            "Invalid arguments. Usage: python server_daemon.py [--daemon|stop]"
        )
        print("Usage: python server_daemon.py [--daemon|stop]")
        sys.exit(1)

    if sys.argv[1] == 'stop':
        logger.info("Stopping server daemon...")
        stop_daemon()
    elif sys.argv[1] == '--daemon':
        try:
            # Try to bind to the port to check if it's already in use
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((SERVER_HOST, SERVER_PORT))  # Use the same port as in your server configuration
        except socket.error as e:
            if e.errno == 98:  # Address already in use
                print("Error: Server daemon is already running...")
                sys.exit(1)
            else:
                print(f"Error: {str(e)}")
                sys.exit(1)

        print("Starting server daemon...")
        logger.info("Starting server daemon...")
        daemonize()
        run_daemon()

if __name__ == "__main__":
    main()