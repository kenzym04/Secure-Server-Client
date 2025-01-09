# Server Application

This is a Python server application that handles client connections and responds to search queries against a preloaded text file. It can run as a regular process or as a Linux daemon for background execution.

## Features
- **Secure Communication:** Uses SSL/TLS for secure client-server communication.
- **Configurable Settings:** Uses an external `config.ini` file for easy customization.
- **Multithreading:** Handles multiple clients concurrently.
- **Dynamic File Reload:** Optionally reloads file contents on each query (controlled by `REREAD_ON_QUERY` configuration).
- **Daemon Mode:** Can run as a background process.
- **Rotating Logs:** Maintains server and client activity logs with size-based rotation.
- **File Searching:** Processes text-based search queries against a preloaded text file. Ensures searches return results only for full line matches of the query in the file, disregarding any partial matches.
- **Rate Limiting:** Uses a Token Bucket mechanism to regulate client request frequency.
- **Unlimited Concurrent Connections:** Handles an unlimited number of concurrent client connections.
- **Efficient Caching:** Uses in-memory caching of file contents for fast query responses.

## Code Quality
This project uses static type checking with `mypy` to ensure type correctness. Run the below command to confirm:

````bash
mypy src/
````
The latest validation result shows: `Success: no issues found in 4 source files`

---
## Prerequisites
- **Python**: 3.6+
- **Pip**: Python package installer

---
## Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd intro_task
```

### 2. Create and Activate a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```
---
## Configuration

### 1. Navigate to the Configuration Directory

```bash
cd config
```

### 2. Edit the `config.ini` File
Configure the following:
- Server IP and port
- SSL usage and certificate paths
- File paths and operational flags (e.g., `REREAD_ON_QUERY`)
- Rate limiting parameters

Example `config.ini`:

```
[server]
host = 127.0.0.1
port = 44444
ssl = false
cert_file = certs/server.crt
key_file = certs/server.key
REREAD_ON_QUERY = True
linuxpath=/mnt/d/Algorithmic_Sciences/Revised_Intro_Task_v3/src/data/200k.txt
max_payload = 1024
token_bucket_capacity = 10000
token_bucket_fill_rate = 100.0
```

Note: The server is designed to handle an unlimited number of concurrent connections, so there's no need for a `max_connections` setting.

### 3. Set Up SSL Certificates
To enable secure communication between the client and server, you'll need to create SSL/TLS certificates.

#### Steps to Create SSL Certificates
1. Navigate to the `certs/` directory:

   ```bash
   mkdir -p certs
   cd certs
   ```

2. Create a self-signed SSL certificate and private key using the OpenSSL command:

   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
   ```

3. Provide the necessary information when prompted.

4. Ensure the generated `server.crt` and `server.key` files are correctly referenced in the `config.ini` file.

---

### 4. Performance Expectations

- **Concurrent Connections:**  
  The server supports **unlimited concurrent connections**, leveraging multithreading for parallel request handling.

- **Rate Limiting:**  
  Configurable via the `config.ini` file:  
  - **Capacity:** Default 10,000 tokens.  
  - **Fill Rate:** Default 1,000 tokens/second.  

- **Response Times:**  
  - **Server Execution Time:** Server execution time has been cross-checked with a profiling tool (cProfile) 
  To cross-check:
  
  1. Start the server as shown below
  ````
  python3 -m cProfile -s time src/server.py
  ````
  2. Send search requests
   ````
  python3 src/client.py
  ````
  3. To Cross-Check Across File Sizes use: `test_performance.py`
  
  - **REREAD_ON_QUERY = True:**  
    Execution times average **~40ms** for dynamic queries across file sizes up to 1,000,000 rows. The file is re-read for each query to ensure real-time accuracy.  
  - **REREAD_ON_QUERY = False:**  
    Execution times average **~0.5ms** using cached in-memory data structures for faster lookups, minimizing disk I/O.

- **Benchmarks:**  
  - Tested with files ranging from 10,000 to 1,000,000 rows.  
  - Query execution times remain consistent and efficient, achieving **maximum QPS of ~7,213.97** for 250,000-row files in optimal conditions.  
  - Server sustains up to **356 queries per second** for 10,000-row files and scales proportionally for larger files.

- **Caching:**  
  - When `REREAD_ON_QUERY` is disabled, the server caches file contents in memory, providing **O(1)** average lookup times for subsequent queries.  
  - Caching significantly enhances performance, especially for repeated queries in high-traffic environments.

- **Security:**  
  - The server uses SSL/TLS for secure communication, supporting both self-signed certificates and configurable authentication.  
  - Security measures include robust exception handling, buffer overflow protection, and strict payload size validation (maximum 1024 bytes).

- **Scalability:**  
  The server is designed to handle files up to **1,000,000 rows** and beyond, with resource-efficient performance across dynamic and static modes.

The server meets all specifications for performance, security, and scalability, ensuring reliable operation in high-demand environments. 
Detailed benchmarks and test results are included in the speed report.

---

### 5. Running the Server

#### - Regular Mode
Run the server manually:

```bash
python3 src/server.py
```

#### - Daemon Mode
Start the server as a daemon:

```bash
python3 src/server_daemon.py --daemon
```

Stop the server daemon:

```bash
python3 src/server_daemon.py stop
```

---
### 6. Running Tests
Run all tests with coverage reporting:

```bash
pytest --cov=src --cov-report=term-missing
```
To run all the tests in the `tests` directory:

```bash
pytest tests/
```
For specific tests (Ensure the server is running before executing these tests):

```bash
pytest tests/test_server.py
pytest tests/test_server_daemon.py
pytest tests/test_client.py
pytest tests/edge_cases.py
pytest tests/test_file_sizes_rows_vs_qps.py
pytest tests/test_performance.py (NOTE: To run this particular test, replace the `search_query` function with the one below)
```
### 7. Troubleshooting
1. **Permission Issues:** Ensure proper write permissions for log and PID files.
2. **SSL Problems:** Verify correct placement and permissions of certificate files.
3. **Rate Limiting:** Check `rate_limit_capacity` and `rate_limit_fill_rate` in `config.ini`.
4. **Resource Management:** While the server can handle unlimited connections, be aware of system resource limitations (e.g., available memory, file descriptors) that may affect performance under extremely high loads.
5. **Caching:** If changes to the source file are not immediately reflected, check if REREAD_ON_QUERY is set to True in the configuration. If not, restart the server to reload the file contents into the cache.

`Search Query` Function:

```bash
def search_query(query: str) -> str | tuple[str, float]:
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

    logger.info(f"Search query: {query} - {result} (Server Execution Time: {execution_time_ms:.2f} ms)")
    return result, execution_time_ms
```
