# Server Application

This is a Python server application that handles client connections and responds to search queries against a preloaded text file. It can run as a regular process or as a Linux daemon for background execution.

## Features
- **Secure Communication:** Supports SSL/TLS for secure client-server communication.
- **Configurable Settings:** External `config.ini` for easy customization.
- **Multithreading:** Handles multiple clients concurrently.
- **Dynamic File Reload:** Option to reload file contents on each query (`REREAD_ON_QUERY` configuration).
- **Daemon Mode:** Runs as a background process.
- **Rotating Logs:** Maintains server and client activity logs with rotation upon reaching size limits.
- **File Searching:** Responds to text-based search queries using a preloaded text file.
- **Rate Limiting:** Implements a Token Bucket mechanism to regulate the frequency of client requests.
- **Unlimited Concurrent Connections:** The server can handle an unlimited number of concurrent client connections.
- **Efficient Caching:** Implements in-memory caching of file contents for fast query responses.

## Code Quality
This project uses static type checking with mypy to ensure type correctness. The latest validation result shows:

````bash
mypy src/
````
Success: no issues found in 4 source files

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
```ini
[server]
host = 127.0.0.1
port = 44444
ssl = false
cert_file = certs/server.crt
key_file = certs/server.key
REREAD_ON_QUERY = True
linuxpath=/mnt/c/Users/Admin/Documents/Workspace/Intro_Task/intro_task/200k.txt
linuxpath_large=/mnt/c/Users/Admin/Documents/Workspace/Intro_Task/intro_task/2001k.txt
max_payload = 1024
token_bucket_capacity = 100
token_bucket_fill_rate = 10.0
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
## Using the File Searching Functionality

The server processes search queries against a preloaded text file. Queries must adhere to the following format:
- **Expected Query Format:** Plain text or simple regex patterns.
- **Case Sensitivity:** By default, queries are case-insensitive unless specified otherwise in the configuration.
- **Response:** The server returns "STRING EXISTS" if the query is found, or "STRING NOT FOUND" if it isn't.

---
## Performance Expectations

- **Concurrent Connections:** The server can handle an unlimited number of concurrent connections.
- **Rate Limiting:**
  - Capacity: 100 tokens (configurable)
  - Fill Rate: 10 tokens/second (configurable)
- **Benchmarks:**
  - Response time for a single query: ~50ms (depending on file size).
- **Caching:**
  - File contents are cached in memory for fast query responses.
  - Caching significantly reduces disk I/O and improves response times for repeated queries.

---
## Running the Server

### Regular Mode
Run the server manually:
```bash
python3 src/server.py
```

### Daemon Mode
Start the server as a daemon:
```bash
python3 src/server_daemon.py --daemon
```

Stop the server daemon:
```bash
python3 src/server_daemon.py stop
```

---
## Running Tests

Run all tests with coverage reporting:
```bash
pytest --cov=src --cov-report=term-missing
```
For all tests in the tests directory:
```bash
pytest tests/.
```
For specific tests (Make sure the server is running before running tests):
```bash
pytest tests/test_server.py
pytest tests/test_server_daemon.py
pytest tests/test_client.py
pytest tests/edge_cases.py
pytest tests/test_file_sizes_rows_vs_qps.py
pytest tests/test_performance.py (NOTE: To run this particular test, replace the search_query function with the one below)
```
## Troubleshooting

1. **Permission Issues:** Ensure proper write permissions for log and PID files.
2. **SSL Problems:** Verify correct placement and permissions of certificate files.
3. **Rate Limiting:** Check `rate_limit_capacity` and `rate_limit_fill_rate` in `config.ini`.
4. **Resource Management:** While the server can handle unlimited connections, be aware of system resource limitations (e.g., available memory, file descriptors) that may affect performance under extremely high loads.
5. **Caching:** If changes to the source file are not reflected immediately, check if `REREAD_ON_QUERY` is set to `True` in the configuration. If not, restart the server to reload the file contents into the cache.

Search Query Function
```bash
def search_query(query: str) -> Tuple[str, float]:
    """
    Search for the query in the file or cached data structures.

    Args:
        query (str): The string to search for.

    Returns:
        Tuple[str, float]: A tuple containing the result string and the execution time in milliseconds.
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

    end_time = time.perf_counter_ns()
    search_time = (end_time - start_time) / 1_000_000  # Convert ns to ms
    search_time_formatted = round(search_time, 6)  # Round to 6 decimal places

    return result, search_time_formatted
```
