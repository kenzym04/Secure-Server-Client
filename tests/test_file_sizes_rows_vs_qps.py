import random
import string
import ssl
import sys
import os
import socket
import time
import unittest
import threading

# Add the parent directory to sys.path to allow importing from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.server import start_server, stop_daemon, load_and_validate_config, setup_logging
from src import client

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = load_and_validate_config()
        cls.logger = setup_logging()
        cls.server_thread = threading.Thread(target=start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(2)  # Give the server time to start
        print("Server started for testing.")

    @classmethod
    def tearDownClass(cls):
        stop_daemon()
        cls.server_thread.join(timeout=5)
        print("Server stopped after testing.")

    def setUp(self):
        sys.stdout.write(f"\n\nRunning test: {self._testMethodName}\n")
        sys.stdout.flush()

    def tearDown(self):
        sys.stdout.write(f"Finished test: {self._testMethodName}\n")
        sys.stdout.flush()

    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def create_client_socket(self):
        sock = socket.create_connection((self.config['host'], self.config['port']))
        if self.config['ssl']:
            context = self.create_ssl_context()
            return context.wrap_socket(sock)
        return sock

    def send_query(self, query):
        try:
            with socket.create_connection((self.config['host'], self.config['port'])) as sock:
                if self.config['ssl']:
                    context = self.create_ssl_context()
                    with context.wrap_socket(sock) as secure_sock:
                        secure_sock.sendall(query.encode('utf-8'))
                        return secure_sock.recv(1024).decode('utf-8')
                else:
                    sock.sendall(query.encode('utf-8'))
                    return sock.recv(1024).decode('utf-8')
        except Exception as e:
            return f"CONNECTION_ERROR: {str(e)}"

    @staticmethod
    def generate_test_file(size):
        filename = f"test_file_{size}.txt"
        with open(filename, 'w') as f:
            for _ in range(size):
                f.write(''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '\n')
        return filename


class TestServerPerformance(TestServer):
    def test_queries_per_second(self):
        file_size = 250_000
        filename = self.generate_test_file(file_size)
        self.config['linuxpath'] = filename
        self.config['reread_on_query'] = False

        max_queries = 10000
        query_times = []

        for i in range(1, max_queries + 1):
            start_time = time.time()
            for _ in range(i):
                self.send_query('test_query')
            total_time = time.time() - start_time
            qps = i / total_time
            query_times.append((i, qps))
            print(f"Queries: {i} | QPS: {qps:.2f}")
            if total_time > 1.0:  # Stop if query execution exceeds 1 second
                print("Server unable to handle additional load.")
    def test_file_sizes_vs_qps(self):
        file_sizes = [10_000, 100_000, 250_000, 500_000, 1_000_000, 100_000_000, 500_000_000, 1_000_000_000]
        max_queries = 1000
        results = {}

        for file_size in file_sizes:
            print(f"\nTesting file size: {file_size} lines")
            filename = self.generate_test_file(file_size)
            self.config['linuxpath'] = filename
            self.config['reread_on_query'] = False

            query_times = []

            for i in range(1, max_queries + 1):
                start_time = time.time()
                for _ in range(i):
                    self.send_query('test_query')
                total_time = time.time() - start_time
                qps = i / total_time
                query_times.append((i, qps))
                print(f"Queries: {i} | QPS: {qps:.2f}")
                if total_time > 1.0:  # Stop if query execution exceeds 1 second
                    print(f"Server unable to handle more than {i} queries per second for file size {file_size}.")
                    break

            os.remove(filename)

            max_qps = max(query_times, key=lambda x: x[1])[1]
            results[file_size] = max_qps
            print(f"Maximum QPS achieved for file size {file_size}: {max_qps:.2f}")

        # Assertions
        for file_size, max_qps in results.items():
            self.assertGreater(max_qps, 0, f"QPS should be greater than 0 for file size {file_size}")

        # Check if larger file sizes generally result in lower QPS
        qps_values = list(results.values())
        self.assertTrue(all(qps_values[i] >= qps_values[i+1] for i in range(len(qps_values)-1)),
                        "QPS should generally decrease as file size increases")

        # Print summary
        print("\nSummary of File Sizes vs QPS:")
        for file_size, max_qps in results.items():
            print(f"File size: {file_size} lines | Max QPS: {max_qps:.2f}")


if __name__ == '__main__':
    unittest.main(verbosity=2)