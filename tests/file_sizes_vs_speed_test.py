import sys
import threading
import unittest
import os
import time
import random
import string
import socket
import csv
from configparser import ConfigParser

# Add the src directory to the Python path for importing the client module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.server import start_server, stop_daemon, load_and_validate_config, setup_logging
from src import client

# Load dynamic paths from configuration
CONFIG_FILE = os.getenv("CONFIG_PATH", "src/config/config.ini")
config = ConfigParser()
config.read(CONFIG_FILE)

BASE_DIR = os.path.abspath(os.path.dirname(CONFIG_FILE))
DATA_DIR = config.get("paths", "data_dir", fallback="src/data")
RESULTS_DIR = os.path.join(BASE_DIR, DATA_DIR, "results")
RESULTS_CSV = os.path.join(RESULTS_DIR, "speed_test_results.csv")


class TestServer(unittest.TestCase):
    """
    Base class for server tests. Sets up and tears down the test server.
    """

    @classmethod
    def setUpClass(cls):
        """
        Start the server in a separate thread before all tests.
        """
        cls.config = load_and_validate_config()
        cls.logger = setup_logging()
        cls.server_thread = threading.Thread(target=start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(2)  # Allow server to start
        print("Server started for testing.")

    @classmethod
    def tearDownClass(cls):
        """
        Stop the server and clean up after all tests.
        """
        stop_daemon()
        cls.server_thread.join(timeout=5)
        print("Server stopped after testing.")

    @staticmethod
    def generate_test_file(size_in_lines, line_length=10):
        """
        Generate a test file with the specified number of lines.

        Args:
            size_in_lines (int): Number of lines in the file.
            line_length (int): Length of each line (default is 10).

        Returns:
            str: Path to the generated test file.
        """
        filename = os.path.join(DATA_DIR, f"test_file_{size_in_lines}.txt")
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(filename, "w") as f:
            for _ in range(size_in_lines):
                f.write(
                    "".join(
                        random.choices(string.ascii_lowercase + string.digits, k=line_length)
                    )
                    + "\n"
                )
        return filename

    def send_query(self, query):
        """
        Send a query to the server and return the response.

        Args:
            query (str): The query string.

        Returns:
            str: Response from the server.
        """
        try:
            with socket.create_connection((self.config["host"], self.config["port"])) as sock:
                if self.config.getboolean("ssl", fallback=False):
                    context = client.create_ssl_context()
                    with context.wrap_socket(sock) as secure_sock:
                        secure_sock.sendall(query.encode("utf-8"))
                        return secure_sock.recv(1024).decode("utf-8")
                else:
                    sock.sendall(query.encode("utf-8"))
                    return sock.recv(1024).decode("utf-8")
        except Exception as e:
            return f"CONNECTION_ERROR: {str(e)}"

    def save_results_to_csv(self, results, filename=RESULTS_CSV):
        """
        Save test results to a CSV file.

        Args:
            results (dict): Dictionary of results to save.
            filename (str): Path to the output CSV file.
        """
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", newline="") as csvfile:
            fieldnames = ["File Size (lines)", "Max QPS"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for file_size, max_qps in results.items():
                writer.writerow({"File Size (lines)": file_size, "Max QPS": max_qps})


class TestServerPerformance(TestServer):
    """
    Test server performance for various file sizes and query loads.
    """

    def test_file_sizes_vs_qps(self):
        """
        Test QPS for different file sizes and save the results to a CSV file.
        """
        file_sizes = [10_000, 100_000, 250_000, 500_000, 1_000_000, 10_000_000, 100_000_000, 500_000_000, 1_000_000_000]
        max_queries = 1000
        results = {}

        for file_size in file_sizes:
            print(f"\nTesting file size: {file_size} lines")
            filename = self.generate_test_file(file_size)
            self.config["linuxpath"] = filename
            self.config["reread_on_query"] = "False"

            query_times = []
            for i in range(1, max_queries + 1):
                start_time = time.time()
                for _ in range(i):
                    self.send_query("test_query")
                total_time = time.time() - start_time
                qps = i / total_time
                query_times.append((i, qps))
                if i % 100 == 0:
                    print(f"  Progress: {i}/{max_queries} queries", end='\r')
                if total_time > 1.0:
                    print(f"Server unable to handle more than {i} queries per second for file size {file_size}.")
                    break

            os.remove(filename)

            max_qps = max(query_times, key=lambda x: x[1])[1]
            results[file_size] = max_qps
            print(f"Maximum QPS achieved for file size {file_size}: {max_qps:.2f}")

        # Save results to CSV
        self.save_results_to_csv(results)
