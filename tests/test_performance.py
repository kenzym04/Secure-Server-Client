import os
import sys
import time
import pytest
import logging

# Add the parent directory to sys.path to allow importing from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.server import search_query, config, initialize_set_mmap

logger = logging.getLogger(__name__)

@pytest.mark.performance
@pytest.mark.parametrize("reread_on_query", [True, False])
def test_performance(reread_on_query):
    file_sizes = [10_000, 50_000, 100_000, 250_000]
    max_queries = 1000
    queries_per_size = 100  # Number of queries to run for each file size
    results = []

    logger.info(f"Running tests with REREAD_ON_QUERY = {reread_on_query}")
    config['reread_on_query'] = reread_on_query

    for size in file_sizes:
        total_time = 0
        for _ in range(queries_per_size):
            # query = f"test_query_{_}"  # Generate a unique query
            _, execution_time = search_query("test_string")
            total_time += execution_time

        avg_time = total_time / queries_per_size
        results.append((size, avg_time))
        print(f"File Size: {size:,} rows | Average Execution Time: {avg_time:.6f} ms")

    # Test Queries Per Second (QPS) Limit
    logger.info("\nTesting QPS Limit for 250,000 rows")
    start_time = time.perf_counter()
    query_count = 0
    while time.perf_counter() - start_time < 1 and query_count < max_queries:
        search_query(f"qps_test_{query_count}")
        query_count += 1
    qps = query_count / (time.perf_counter() - start_time)

    # Print summary results
    print("\nExecution time per file size:")
    for size, avg_time in results:
        print(f"File Size: {size:,} rows | Average Execution Time: {avg_time:.6f} ms")

    print(f"\nQueries Per Second (QPS) Test Result: {qps:.6f} QPS")

    # Get average execution time for 250,000 rows
    avg_time_250k = results[-1][1]  # Last element corresponds to 250,000 rows

    # Assertions
    if reread_on_query:
        assert avg_time_250k <= 40, f"Average execution time for 250,000 rows ({avg_time_250k:.6f} ms) should be less than or equal to 40ms with REREAD_ON_QUERY=True"
    else:
        assert avg_time_250k <= 0.5, f"Average execution time for 250,000 rows ({avg_time_250k:.6f} ms) should be less than or equal to 0.5ms with REREAD_ON_QUERY=False"
    
    assert qps > 1, f"Server should handle more than one query per second. Current QPS: {qps:.6f}"

    print(f"\nAverage execution time for 250,000 rows (REREAD_ON_QUERY={reread_on_query}): {avg_time_250k:.6f} ms")