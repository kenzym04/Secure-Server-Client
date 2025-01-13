# Server Application

This is a Python server application that handles client connections and responds to search queries against a preloaded text file. It can run as a regular process or as a Linux daemon for background execution.

## Features
- **Secure Communication**:
    - Utilizes SSL/TLS for encrypted client-server communication, ensuring data privacy and integrity.
    - Configurable SSL settings via `config.ini` for flexibility (supports turning SSL on/off).
- **Configurable Settings**:
    - Parameters such as host, port, file paths, rate limiting, and REREAD_ON_QUERY are customizable via an external configuration file (`config.ini`).
- **Multithreading**:
    - Handles unlimited concurrent client connections using threads for scalability and responsiveness.
- **Dynamic File Reload**:
    - Optionally reloads file contents on each query (if `REREAD_ON_QUERY=True`) to accommodate real-time file changes.
    - Reads the file once and caches its contents when `REREAD_ON_QUERY=False`, ensuring faster performance for static data.
- **Efficient File Searching**:
    - Searches for exact string matches (no partial matches) within the file.
    - Supports large files up to 250,000 rows with consistent performance.
- **Rate Limiting**:
    - Implements a Token Bucket algorithm to regulate client request rates, preventing abuse and ensuring fair resource usage.
- **Unlimited Concurrent Connections**:
    - Designed to manage an unlimited number of client connections, ensuring reliability under heavy traffic.
- **Rotating Logs**:
    - Maintains detailed server logs (e.g., queries, IPs, execution times) with automatic rotation to prevent log overflow.
- **Daemon Mode**:
    - Can be run as a Linux service or background process using `server_daemon.py` for production readiness.
- **Thread Safety**:
    - Ensures safe access to shared resources using locks (e.g., connection counts, file access).
- **Error Handling**:
    - Robust exception handling for socket errors, file operations, and invalid queries to maintain server stability.
- **Efficient Caching**:
    - Uses in-memory caching for file data when `REREAD_ON_QUERY=False`, minimizing disk I/O latency.
- **Performance**:
    - Achieves an average query execution time of ~40ms with `REREAD_ON_QUERY=True` and ~0.5ms with `REREAD_ON_QUERY=False`.

This module adheres to PEP8 and PEP20 standards, is fully statically typed, and includes comprehensive logging and exception handling to ensure maintainability, clarity, and high performance.

## System Design Architecture Diagram

![System Design.png](src%2Fdata%2Fimage%2FSystem%20Design.png)

## Code Quality
This project uses static type checking with `mypy` to ensure type correctness. Run the below command to confirm:

````bash
mypy src/
````
![mypy.png](src%2Fdata%2Fimage%2Fmypy.png)

---
## Prerequisites
- **Python**: 3.6+
- **Pip**: Python package installer

---
## Setup

### 1. Create and Activate a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

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

Configure the following settings in the `config.ini` file to customize the server's behavior:

- **Server IP and Port**: Set the server's host and port for client connections.
- **SSL Usage and Certificate Paths**: Enable or disable SSL and configure paths for certificates.
- **File Paths and Operational Flags**: Specify file paths, control dynamic file reload with `REREAD_ON_QUERY`, and configure operational settings like payload limits.
- **Rate Limiting Parameters**: Adjust the token bucket capacity and fill rate for controlling request rates.
- **Logging and Process Management**: Define paths for log files and PID files.

#### Default `config.ini`:

```
[server]
host = 127.0.0.1
port = 44444
ssl = false
cert_file = server.crt
key_file = server.key
REREAD_ON_QUERY = false
linuxpath = /mnt/d/Algorithmic_Sciences/Revised_Intro_Task_v3/src/data/200k.txt
max_payload = 1024
token_bucket_capacity = 10000
token_bucket_fill_rate = 1000
pid_file = server_daemon.pid

[paths]
config_dir = config
log_dir = logs
cert_dir = certs
data_dir = data
file_path = src/data/200k.txt
config_path = ${config_dir}/config.ini
pid_file = ${log_dir}/server.pid
log_file = ${log_dir}/server.log
```

---

### Explanation of Key Configurations:

1. **[server] Section**:
   - `host`: IP address where the server will listen for connections.
   - `port`: Port number for client communication.
   - `ssl`: Enables (`true`) or disables (`false`) SSL/TLS encryption.
   - `cert_file` and `key_file`: Paths to the SSL certificate and private key files.
   - `REREAD_ON_QUERY`: 
     - `true`: Reloads the file for every query (suitable for dynamic file changes).
     - `false`: Caches the file in memory for faster performance.
   - `linuxpath`: Path to the file used for text-based query processing.
   - `max_payload`: Maximum size of incoming payloads (in bytes).
   - `token_bucket_capacity`: Maximum number of tokens in the rate-limiting bucket.
   - `token_bucket_fill_rate`: Rate (tokens per second) at which the bucket refills.
   - `pid_file`: Path to the PID file for process management.

2. **[paths] Section**:
   - `config_dir`: Directory for configuration files.
   - `log_dir`: Directory for storing logs.
   - `cert_dir`: Directory for SSL certificates.
   - `data_dir`: Directory for data files.
   - `file_path`: Specific file path for the data file used in searches.
   - `config_path`: Full path to the configuration file.
   - `pid_file`: Path to the PID file used by the server daemon.
   - `log_file`: Path to the server's main log file.

Note: The server is designed to handle an unlimited number of concurrent connections, so there's no need for a `max_connections` setting.

---

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

### 4. Comprehensive Test Validation Overview
This section provides a summary of how various features and functionalities of the server implementation project have been validated using test scripts under the `tests` directory. 
It outlines the test scripts, the key aspects they validate, and their relevance to the system's performance, reliability, and scalability.  
    
For specific test result metrics, refer to the **Comprehensive Speed Report**. For detailed test coverage information, consult the **Comprehensive Test Coverage Report**.

 ### **Test Scripts and Their Validations**

 1. **`tests/test_server.py`**  
    - Validates core server functionalities, including:
      - Configuration loading and validation.
      - Logging setup correctness.
      - SSL context creation.
      - Query processing with `REREAD_ON_QUERY` enabled and disabled.
      - Rate limiting via the Token Bucket mechanism.
      - File handling, including edge cases like invalid paths and permission errors.
      - Multithreaded client handling.

    2. **`tests/test_client.py`**  
       - Validates client functionalities, such as:
         - Configuration handling (valid and invalid cases).
         - Connection establishment (SSL and non-SSL modes).
         - Query sending and response processing.
         - Error handling for connection timeouts, SSL issues, and malformed responses.
         - Logging for query success/failure and connection errors.
         - Performance testing for query handling under load.

    3. **`tests/test_server_daemon.py`**  
       - Validates server daemon functionalities, including:
         - Daemonization process (PID creation, signal handling, I/O redirection).
         - Logging setup and exception handling.
         - Lifecycle management (`start`, `stop`, `restart`).
         - Argument validation and invalid input handling.

    4. **`tests/edge_cases.py`**  
       - Covers edge cases such as:
         - File reloading and size variations.
         - Handling of payload limits, long queries, Unicode, and special characters.
         - SQL injection-like queries to test security robustness.
         - Concurrency and rate-limiting under simultaneous client requests.
         - SSL and secure connection tests.

    5. **`tests/test_performance.py`**  
       - Validates system performance, including:
         - Execution times for `REREAD_ON_QUERY=True` and `REREAD_ON_QUERY=False`.
         - Queries per second (QPS) under different file sizes.
         - Analysis of caching efficiency and dynamic file reload impact.

    6. **`tests/test_file_sizes_rows_vs_qps.py`**  
       - Tests QPS across varying file sizes:
         - Files ranging from 10,000 to 1,000,000,000 rows.
         - Measures the server's ability to handle increasing query loads and performance degradation trends.

    7. **`tests/test_file_sizes_bytes_vs_qps_mocked.py`**  
       - Simulates QPS performance for varying file sizes:
         - Uses mocked functions to emulate server behavior with file sizes from 1,000 to 1,000,000 bytes.
         - Focuses on server response times and scalability under simulated workloads.

    8. **`tests/validate_environment_server.py`**  
       - Validates critical environment paths for `server.py`:
         - Ensures all required directories (e.g., logs, config, data) exist.
         - Prevents hardcoded paths and enforces dynamic path configurations.

    9. **`tests/validate_environment_daemon.py`**  
       - Validates environment settings for `server_daemon.py`:
         - Ensures proper handling of dynamic and static paths.
         - Verifies no hardcoded paths exist.
         - Checks logging and PID file configurations.

    10. **`tests/validate_environment_client.py`**  
        - Validates the client environment:
          - Checks for dynamic and static paths.
          - Ensures proper logging and path validation for client configurations.
          - Prevents hardcoded path usage.

### **Summary of Validation Coverage**
- **Performance**: Verified through tests like `tests/test_performance.py` and `tests/test_file_sizes_rows_vs_qps.py`, focusing on execution times, QPS, and caching efficiency.  
- **Edge Cases**: Addressed comprehensively in `tests/edge_cases.py`, ensuring the system's robustness under various challenging scenarios.  
- **Environment Validation**: Ensured by `validate_environment_server.py`, `validate_environment_daemon.py`, and `validate_environment_client.py` to support deployment in dynamic environments.  
- **Daemonization**: Fully validated in `tests/test_server_daemon.py`, ensuring seamless integration into production as a Linux service.  
- **Security**: Validated in `tests/test_server.py` and `tests/test_client.py` through SSL/TLS communication and buffer overflow protections.  
- **Scalability**: Tested across file sizes and query loads in `tests/test_performance.py` and `tests/test_file_sizes_rows_vs_qps.py`.

---

### **Conclusion**
The test scripts under the `tests` directory ensure comprehensive validation of the server's functionalities, covering performance, security, scalability, and edge cases. For further details on test results and metrics, consult the **Comprehensive Speed Report** and the **Comprehensive Test Coverage Report**.

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
For specific tests: (Ensure the server is running before executing: tests/test_server, tests/test_daemon and tests/test_client):

```bash
pytest tests/test_server.py
pytest tests/test_server_daemon.py
pytest tests/test_client.py
pytest tests/edge_cases.py
pytest tests/test_file_sizes_rows_vs_qps.py
pytest tests/test_performance.py
pytest tests/test_file_sizes_bytes_vs_qps_mocked.py
pytest tests/validate_environment_server.py
pytest tests/validate_environment_daemon.py
pytest tests/validate_environment_client.py

```
### 7. Troubleshooting
1. **Permission Issues:** Ensure proper write permissions for log and PID files.
2. **SSL Problems:** Verify correct placement and permissions of certificate files.
3. **Rate Limiting:** Check `rate_limit_capacity` and `rate_limit_fill_rate` in `config.ini`.
4. **Resource Management:** While the server can handle unlimited connections, be aware of system resource limitations (e.g., available memory, file descriptors) that may affect performance under extremely high loads.
5. **Caching:** If changes to the source file are not immediately reflected, check if REREAD_ON_QUERY is set to True in the configuration. If not, restart the server to reload the file contents into the cache.
