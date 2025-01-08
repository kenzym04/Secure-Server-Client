"""
Server Daemon Module

This module provides functionality to run the server as a daemon process in a
Unix-like environment. It encapsulates the complexities of daemon management,
including process forking, signal handling, logging, and server lifecycle
management.

Key Features:
- Daemonization: Forks the process to run in the background, detached from the
  terminal.
- Logging: Configures rotating log files for persistent logging of daemon
  activities.
- Signal Handling: Manages graceful shutdown on receiving termination signals.
- Server Management: Handles starting, stopping, and running the server process.
- Rate Limiting: Implements request rate limiting inherited from the main server
  module.

Main Components:
- setup_logging: Configures the logging system for the daemon.
- signal_handler: Manages termination signals for graceful shutdown.
- daemonize: Performs the process of turning the current process into a daemon.
- run_daemon: Executes the main server logic in daemon mode.
- handle_request: Processes individual client requests with rate limiting.
- main: Entry point for starting or stopping the daemon based on command-line
  arguments.

Usage:
    To start the daemon: python server_daemon.py --daemon
    To stop the daemon:  python server_daemon.py stop

Note: This module is designed to work in conjunction with the main server module,
inheriting core server functionality while adding daemon-specific features.
"""

import os
import socket
import sys
import signal
import time
import logging
from logging.handlers import RotatingFileHandler
import threading
from typing import Any, NoReturn

# Add the project root directory to the Python path
project_root = os.path.abspath(
    os.path.join(os.path.dirname(__file__),
                 '..')
)
sys.path.insert(0, project_root)

try:
    from .server import (start_server,
                         stop_daemon,
                         handle_client,
                         search_query,
                         TOKEN_BUCKET as rate_limiter
                         )
except ImportError:
    from src.server import (start_server,
                            stop_daemon,
                            handle_client,
                            search_query,
                            TOKEN_BUCKET as rate_limiter
                            )

# Constants
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
PID_FILE = os.path.join(BASE_DIR, "server_daemon.pid")
LOG_FILE = os.path.join(BASE_DIR, "logs", "server_daemon.log")

# Global variables
logger = None
connection_count: int = 0
connection_lock: threading.Lock = threading.Lock()

def setup_logging() -> logging.Logger:
    """Set up logging for the server daemon with file and console handlers.

    Returns:
        logging.Logger: Configured logger object for use throughout the application.

    This function configures a logger named 'ServerDaemon' with the following:
    - A rotating file handler (max size 10MB, 5 backups) logging to LOG_FILE.
    - A console handler for immediate output during development or debugging.
    - Logging level set to DEBUG for comprehensive logging.
    - A formatter including timestamp, logger name, log level, and message.

    The log directory is created if it doesn't exist.
    """
    logger = logging.getLogger('ServerDaemon')
    logger.handlers.clear()  # Clear any existing handlers
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024,
        backupCount=5)
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

def signal_handler(signum: int, _: Any) -> NoReturn:
    """Handle termination signals for graceful shutdown of the server daemon.

    Args:
        signum (int): The signal number received (e.g., 15 for SIGTERM).
        _ (Any): Unused frame argument (convention for signal handlers).

    This function logs the shutdown process and exits the program when the
    daemon receives a termination signal (e.g., SIGTERM, SIGINT).
    """
    global logger
    if logger is not None:
        logger.info(f"Received signal {signum}. Shutting down...")
        logger.info("Server daemon stopped.")
    sys.exit(0)

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
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork failed: {e.errno} ({e.strerror})")
        sys.exit(1)

    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # Do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        logger.error(f"Second fork failed: {e.errno} ({e.strerror})")
        sys.exit(1)

    # Write PID file
    pid = os.getpid()
    with open(PID_FILE, 'w') as f:
        f.write(str(pid))

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    with (open(os.devnull, 'r') as si,
          open(os.devnull, 'a+') as so,
          open(os.devnull, 'a+') as se):
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

def run_daemon() -> None:
    """Run the server as a daemon process.

    This function logs the start of the daemon process with its PID and
    attempts to start the server using the start_server function. It handles
    any exceptions that occur during server execution.

    The function will run indefinitely until stopped if the server starts
    successfully. If an exception occurs, it logs the error and exits.
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
                logger.debug(f"DEBUG: Query: '{data}', "
                             f"IP: {client_address[0]}:{client_address[1]}, "
                             f"Time: {query_time:.6f}s, "
                             f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                client_socket.send(result.encode('utf-8'))
            except Exception as e:
                logger.error(
                    f"Error handling client {client_address[0]}"
                    f":{client_address[1]}"
                    f": {str(e)}")
        else:
            logger.warning(
                f"Rate limit exceeded, request from {client_address[0]}"
                f":{client_address[1]} rejected")
            client_socket.send(b"Rate limit exceeded. Please try again later.")

    with connection_lock:
        connection_count -= 1
        logger.info(f"Connection closed. Total connections: {connection_count}")


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
                s.bind(('127.0.0.1', 44444))  # Use the same port as in your server configuration
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