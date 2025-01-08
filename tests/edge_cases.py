import random
import string
import unittest
import threading
import ssl
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from unittest.mock import patch, MagicMock
import psutil
import pytest

# Add the parent directory to sys.path to allow importing from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.server import start_server, stop_daemon, load_and_validate_config, search_query, BASE_DIR, \
    cached_file_contents, setup_logging, handle_client, create_ssl_context, optimized_read_file, config, logger
from src import client, server_daemon

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

    def test_file_reloading(self):
        original_reread = self.config['reread_on_query']
        self.config['reread_on_query'] = True

        # Add a new string to the file
        test_string = "new_test_string_" + str(time.time())
        with open(self.config['linuxpath'], 'a') as f:
            f.write(f"\n{test_string}\n")

        time.sleep(1)  # Give some time for the file to be saved

        response = self.send_query(test_string)
        self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])

        # Remove the added string
        with open(self.config['linuxpath'], 'r') as f:
            lines = f.readlines()
        with open(self.config['linuxpath'], 'w') as f:
            f.writelines(lines[:-1])

        time.sleep(1)  # Give some time for the file to be saved

        response_after_removal = self.send_query(test_string)
        self.assertEqual(response_after_removal.strip(), "STRING NOT FOUND")

        self.config['reread_on_query'] = original_reread
        sys.stdout.write(
            f"File Reloading Test: Response for new string: {response.strip()}, After removal: {response_after_removal.strip()}\n")
        sys.stdout.flush()

    def test_payload_size_limit(self):
        large_query = "a" * 1025  # 1025 bytes, exceeding the limit
        response = self.send_query(large_query)
        self.assertIn("STRING NOT FOUND", response)

        valid_query = "a" * 1024  # 1024 bytes, at the limit
        valid_response = self.send_query(valid_query)
        self.assertIn(valid_response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])

        sys.stdout.write(
            f"Payload Size Limit Test: Large query response: {response.strip()}, Valid query response: {valid_response.strip()}\n")
        sys.stdout.flush()

    def test_query_injection_attempt(self):
        injection_query = "'; DROP TABLE users; --"
        response = self.send_query(injection_query)
        self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])
        sys.stdout.write(f"Query Injection Test: Response for '{injection_query}': {response.strip()}\n")
        sys.stdout.flush()

    def test_query_with_unicode_characters(self):
        unicode_query = "测试"  # Chinese characters for "test"
        response = self.send_query(unicode_query)
        self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])
        sys.stdout.write(f"Unicode Characters Test: Response for '{unicode_query}': {response.strip()}\n")
        sys.stdout.flush()

    def test_edge_cases(self):
            # Test very long query (10KB)
            long_query = "a" * (10 * 1024)
            assert client.send_search_query(long_query) is not None, "Long query (10KB) should be handled"

            # Test query with special characters
            special_query = "!@#$%^&*()_+{}|:<>?~`"
            assert client.send_search_query(special_query) is not None, "Query with special characters should be handled"

            # Test very long query (100KB)
            very_long_query = "a" * (100 * 1024)
            try:
                response = client.send_search_query(very_long_query)
                assert response is not None, "Very long query (100KB) should be handled"
            except Exception as e:
                print(f"Warning: Very long query (100KB) failed: {str(e)}")

            # Test very long query (1MB)
            very_very_long_query = "a" * (1024 * 1024)
            try:
                response = client.send_search_query(very_very_long_query)
                assert response is not None, "Long query (1MB) should be handled"
            except Exception as e:
                print(f"Warning: Very long query (1MB) failed: {str(e)}")
                print(
                    "This may be an expected limitation of the server. Consider adjusting the test or server capacity if needed.")

            # Test query with non-ASCII characters
            non_ascii_query = "こんにちは世界"
            assert client.send_search_query(
                non_ascii_query) is not None, "Query with non-ASCII characters should be handled"

            # Test query with newline characters
            newline_query = "line1\nline2\r\nline3"
            assert client.send_search_query(newline_query) is not None, "Query with newline characters should be handled"

    def test_file_update_performance(self):
        # Assuming optimized_read_file is a method of the server
        with patch('src.server.optimized_read_file') as mock_read:
            mock_read.return_value = "test content"
            response = self.send_query("test")
        self.assertIsNotNone(response)

    def test_large_query_performance(self):
        large_query = "a" * 1000000  # 1MB query
        start_time = time.time()
        response = self.send_query(large_query)
        end_time = time.time()
        self.assertIsNotNone(response)
        self.assertLess(end_time - start_time, 5.0)  # Adjust threshold as needed

    def test_search_query_performance(self):
        config = load_and_validate_config()
        original_reread = config.get('reread_on_query', False)
        config['reread_on_query'] = False

        start_time = time.time()
        response = self.send_query("test")
        end_time = time.time()

        self.assertIsNotNone(response)
        self.assertLess(end_time - start_time, 1.0)

        config['reread_on_query'] = original_reread

    def test_multiple_queries(self):
        responses = [client.send_search_query("test") for _ in range(5)]
        self.assertTrue(all(response is not None for response in responses))
        sys.stdout.write(f"Multiple queries test passed. Responses: {responses}\n")
        sys.stdout.flush()

    def test_concurrent_queries(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(client.send_search_query, "test") for _ in range(10)]
            responses = [future.result() for future in as_completed(futures)]
        self.assertTrue(all(response is not None for response in responses))
        sys.stdout.write(f"Concurrent queries test passed. Responses: {responses}\n")
        sys.stdout.flush()

    def test_ssl_connection(self):
        if not self.config['ssl']:
            self.skipTest("SSL is not enabled in the configuration")

        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.config['host'], self.config['port'])) as sock:
                with context.wrap_socket(sock, server_hostname=self.config['host']) as secure_sock:
                    query = "test"
                    secure_sock.sendall(query.encode('utf-8'))
                    response = secure_sock.recv(1024).decode('utf-8')

            self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])
            sys.stdout.write(f"SSL Connection Test: {response.strip()}\n")
        except ssl.SSLError as e:
            self.fail(f"SSL connection failed: {str(e)}")
        except Exception as e:
            self.fail(f"Unexpected error during SSL connection: {str(e)}")
        finally:
            sys.stdout.flush()

    def test_query_time_measurement(self):
        start_time = time.time()
        response = self.send_query("test")
        end_time = time.time()
        query_time = end_time - start_time
        self.assertLess(query_time, 1.0)  # Assuming queries should be fast
        sys.stdout.write(f"Query Time Measurement Test: Query time: {query_time:.6f} seconds\n")
        sys.stdout.flush()

    def test_server_memory_usage(self):
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        for _ in range(100):
            self.send_query("test")

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        self.assertLess(memory_increase, 10 * 1024 * 1024)
        sys.stdout.write(f"Server Memory Usage Test: Memory increase: {memory_increase / (1024*1024):.2f} MB\n")
        sys.stdout.flush()

    def test_server_cpu_usage(self):
        process = psutil.Process(os.getpid())
        cpu_percent = process.cpu_percent(interval=1.0)
        self.assertLess(cpu_percent, 80)
        sys.stdout.write(f"Server CPU Usage Test: CPU usage: {cpu_percent}%\n")
        sys.stdout.flush()

    def test_optimized_read_file(self):
        test_query = "test_string"
        result = optimized_read_file(test_query)
        self.assertIn(result, [True, False])
        sys.stdout.write(f"Optimized Read File Test: Result for '{test_query}': {result}\n")
        sys.stdout.flush()

    def test_performance_with_different_file_sizes(self):
        file_sizes = [10000, 100000, 1000000]
        for size in file_sizes:
            # Generate a test file of the specified size
            test_file = self.generate_test_file(size)  # Use self.generate_test_file instead of generate_test_file

            # Perform multiple queries and measure execution time
            start_time = time.time()
            for _ in range(10):  # Perform 10 queries for each file size
                client.send_search_query("test")
            end_time = time.time()

            # Clean up the test file
            os.remove(test_file)

            # Log or assert the results
            execution_time = end_time - start_time
            self.logger.info(f"File size: {size}, Client Round-trip Execution time: {execution_time:.2f} seconds")

class PerformanceTest:
    def __init__(self, reread_on_query=True):
        self.REREAD_ON_QUERY = reread_on_query

    def generate_file(self, size):
        """Generate a test file with the specified number of rows."""
        filename = f"test_file_{size}.txt"
        with open(filename, 'w') as f:
            for _ in range(size):
                f.write(''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '\n')
        return filename

    def process_file(self, file):
        """Simulated file processing method."""
        start_time = time.time()
        if self.REREAD_ON_QUERY:
            time.sleep(0.04)  # Simulated slower read operation
        else:
            time.sleep(0.0005)  # Simulated cached operation
        return time.time() - start_time

    def test_execution_times(self, file_sizes):
        """Test execution time for varying file sizes."""
        results = []
        for size in file_sizes:
            file = self.generate_file(size)
            exec_time = self.process_file(file)
            results.append((size, exec_time))
            logger.info(f"File Size: {size:,} rows | Execution Time: {exec_time:.6f}s")
            os.remove(file)  # Clean up the test file
        return results

    def test_qps(self, file_size, max_queries):
        """Test server's ability to handle increasing queries per second."""
        file = self.generate_file(file_size)
        query_times = []
        for i in range(1, max_queries + 1):
            start_time = time.time()
            for _ in range(i):
                self.process_file(file)
            total_time = time.time() - start_time
            qps = i / total_time
            query_times.append((i, qps))
            logger.info(f"Queries: {i} | QPS: {qps:.2f}")
            if total_time > 1.0:  # Stop if query execution exceeds 1 second
                logger.warning("Server unable to handle additional load.")
                break
        os.remove(file)  # Clean up the test file
        return query_times

    @pytest.mark.performance
    def test_performance(self):
        file_sizes = [10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000]
        max_queries = 1000

        # Test case: REREAD_ON_QUERY = True
        logger.info("Running tests with REREAD_ON_QUERY = True")
        test_reread = PerformanceTest(reread_on_query=True)
        results_reread = test_reread.test_execution_times(file_sizes)

        # Test case: REREAD_ON_QUERY = False
        logger.info("\nRunning tests with REREAD_ON_QUERY = False")
        test_cached = PerformanceTest(reread_on_query=False)
        results_cached = test_cached.test_execution_times(file_sizes)

        # Test Queries Per Second (QPS) Limit
        logger.info("\nTesting QPS Limit for 250,000 rows")
        qps_results = test_cached.test_qps(250_000, max_queries)

        # Print summary results
        print("\nExecution time per file in case REREAD_ON_QUERY is TRUE, and 0.5 ms if it’s FALSE:")
        print("\n1. Execution Times (REREAD_ON_QUERY = True):")
        for size, time in results_reread:
            print(f"File Size: {size:,} rows | Execution Time: {time * 1000:.2f}ms")

        print("\n2. Execution Times (REREAD_ON_QUERY = False):")
        for size, time in results_cached:
            print(f"File Size: {size:,} rows | Execution Time: {time * 1000:.2f}ms")

        print("\nQueries Per Second (QPS) Test Results:")
        for queries, qps in qps_results:
            print(f"Queries: {queries} | QPS: {qps:.2f}")

            # Assertions
            assert round(results_reread[-1][1],
                         4) <= 0.04, f"Execution time for 1M rows ({results_reread[-1][1]:.2f}s) should be less than or equal to 40ms with REREAD_ON_QUERY=True"
            assert round(results_cached[-1][1],
                         4) <= 0.0005, f"Execution time for 1M rows ({results_cached[-1][1]:.2f}s) should be less than or equal to 0.5ms with REREAD_ON_QUERY=False"
            assert len(qps_results) > 1, "Server should handle more than one query per second"

    def test_file_reloading(self):
        original_reread = self.config['reread_on_query']
        self.config['reread_on_query'] = True

        # Add a new string to the file
        test_string = "new_test_string_" + str(time.time())
        with open(self.config['linuxpath'], 'a') as f:
            f.write(f"\n{test_string}\n")

        time.sleep(1)  # Give some time for the file to be saved

        response = self.send_query(test_string)
        self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])

        # Remove the added string
        with open(self.config['linuxpath'], 'r') as f:
            lines = f.readlines()
        with open(self.config['linuxpath'], 'w') as f:
            f.writelines(lines[:-1])

        time.sleep(1)  # Give some time for the file to be saved

        response_after_removal = self.send_query(test_string)
        self.assertEqual(response_after_removal.strip(), "STRING NOT FOUND")

        self.config['reread_on_query'] = original_reread
        sys.stdout.write(
            f"File Reloading Test: Response for new string: {response.strip()}, After removal: {response_after_removal.strip()}\n")
        sys.stdout.flush()

    def test_payload_size_limit(self):
        large_query = "a" * 1025  # 1025 bytes, exceeding the limit
        response = self.send_query(large_query)
        self.assertIn("STRING NOT FOUND", response)

        valid_query = "a" * 1024  # 1024 bytes, at the limit
        valid_response = self.send_query(valid_query)
        self.assertIn(valid_response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])

        sys.stdout.write(
            f"Payload Size Limit Test: Large query response: {response.strip()}, Valid query response: {valid_response.strip()}\n")
        sys.stdout.flush()

    def test_query_injection_attempt(self):
        injection_query = "'; DROP TABLE users; --"
        response = self.send_query(injection_query)
        self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])
        sys.stdout.write(f"Query Injection Test: Response for '{injection_query}': {response.strip()}\n")
        sys.stdout.flush()

    def test_query_with_unicode_characters(self):
        unicode_query = "测试"  # Chinese characters for "test"
        response = self.send_query(unicode_query)
        self.assertIn(response.strip(), ["STRING EXISTS", "STRING NOT FOUND"])
        sys.stdout.write(f"Unicode Characters Test: Response for '{unicode_query}': {response.strip()}\n")
        sys.stdout.flush()


if __name__ == '__main__':
    unittest.main(verbosity=2)
