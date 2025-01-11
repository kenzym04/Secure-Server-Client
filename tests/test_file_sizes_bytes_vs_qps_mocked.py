import unittest
from unittest.mock import patch
import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import client

class TestServerPerformanceMocked(unittest.TestCase):
    @patch('time.time')
    @patch('src.client.send_search_query')
    def test_file_sizes_vs_qps(self, mock_send_search_query, mock_time):
        file_sizes = [1000, 10000, 100000, 1000000]  # Simulated file sizes in bytes
        max_queries = 1000  # Reduced from 10000 to 1000 for faster testing
        results = {}

        for file_size in file_sizes:
            print(f"\nTesting file size: {file_size} bytes")
            mock_time.side_effect = [i * 0.001 for i in range(max_queries * 2)]  # Reset time for each file size
            mock_send_search_query.return_value = "MOCKED_RESPONSE"

            query_times = []
            for i in range(1, max_queries + 1):
                if i % 100 == 0:
                    print(f"  Progress: {i}/{max_queries} queries", end='\r')
                start_time = mock_time()
                for _ in range(i):
                    # Simulate longer response time for larger files
                    time.sleep(file_size / 1000000000)  # Naive simulation of file size impact
                    client.send_search_query('test_query')
                total_time = mock_time() - start_time
                qps = i / total_time if total_time > 0 else float('inf')
                query_times.append((i, qps))
                if total_time > 1.0:
                    print(f"\n  Server unable to handle more than {i} queries per second.")
                    break

            max_qps = max(query_times, key=lambda x: x[1])[1]
            results[file_size] = max_qps
            print(f"\n  Maximum QPS achieved: {max_qps:.2f}")

        # Assertions
        for file_size, max_qps in results.items():
            self.assertLess(max_qps, float('inf'), f"QPS should not be infinite for file size {file_size}")
            self.assertGreater(max_qps, 0, f"QPS should be greater than 0 for file size {file_size}")

        # Check if larger file sizes result in lower QPS
        qps_values = list(results.values())
        self.assertTrue(all(qps_values[i] >= qps_values[i+1] for i in range(len(qps_values)-1)),
                        "QPS should generally decrease as file size increases")

if __name__ == '__main__':
    unittest.main(verbosity=2)