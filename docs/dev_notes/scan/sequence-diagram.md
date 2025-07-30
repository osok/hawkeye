# Scan Command Sequence Diagram

## Overview

This document provides comprehensive sequence diagrams illustrating the HawkEye scan command workflow from CLI input to final results. The scanning process involves multiple components working together to enumerate targets, perform concurrent port scanning, and aggregate results for display and output.

## Main Components

### Core Components
- **CLI Command Handler** (`src/hawkeye/cli/scan_commands.py`)
- **Target Enumerator** (`src/hawkeye/scanner/target_enum.py`)
- **TCP Scanner** (`src/hawkeye/scanner/tcp_scanner.py`)
- **UDP Scanner** (`src/hawkeye/scanner/udp_scanner.py`)
- **Connection Pool** (`src/hawkeye/scanner/connection_pool.py`)
- **Result Aggregator** (`src/hawkeye/cli/scan_commands.py`)

### Supporting Components
- **Base Scanner** (`src/hawkeye/scanner/base.py`)
- **Scan Target** (`src/hawkeye/scanner/base.py`)
- **Scan Result** (`src/hawkeye/scanner/base.py`)
- **Progress Display** (Rich library integration)
- **Output Manager** (JSON/CSV/XML formatting)

## Sequence Diagrams

### 1. Main Scan Command Flow

```mermaid
sequenceDiagram
    participant User
    participant CLI as CLI Handler
    participant Enum as TargetEnumerator
    participant TCPScan as TCPScanner
    participant UDPScan as UDPScanner
    participant Pool as ConnectionPool
    participant Progress as ProgressBar
    participant Display as ResultDisplay
    participant Output as OutputManager

    User->>CLI: hawkeye scan -t target -p ports
    
    Note over CLI: Parse command options
    CLI->>CLI: validate_target(target)
    CLI->>CLI: parse_ports(ports)
    CLI->>CLI: create scan settings
    
    Note over CLI: Initialize components
    CLI->>Enum: TargetEnumerator()
    CLI->>TCPScan: TCPScanner(settings)
    CLI->>UDPScan: UDPScanner(settings)
    CLI->>Progress: Progress()
    
    Note over CLI,Enum: Target enumeration phase
    CLI->>Enum: enumerate_targets(target)
    Enum->>Enum: detect_target_type(target)
    alt CIDR Network
        Enum->>Enum: enumerate_from_cidr(target)
    else IP Range
        Enum->>Enum: enumerate_from_range(start, end)
    else Single Host
        Enum->>Enum: enumerate_single_host(target)
    end
    Enum-->>CLI: List[target_hosts]
    
    CLI->>Progress: start progress tracking
    
    Note over CLI,Pool: TCP scanning phase
    alt TCP enabled
        CLI->>TCPScan: scan_target(scan_target)
        
        loop For each target host
            TCPScan->>Pool: submit_scan_tasks(target, ports)
            
            loop For each port
                Pool->>Pool: _execute_scan_task(task)
                Pool->>TCPScan: scan_port(target, port)
                TCPScan->>TCPScan: _create_tcp_socket()
                TCPScan->>TCPScan: connect(host, port)
                TCPScan-->>Pool: ScanResult
                Pool->>Progress: advance(1)
            end
            
            Pool-->>TCPScan: List[ScanResult]
        end
        
        TCPScan-->>CLI: tcp_results
    end
    
    Note over CLI,Pool: UDP scanning phase
    alt UDP enabled
        CLI->>UDPScan: scan_target(scan_target)
        
        loop For each target host
            UDPScan->>Pool: submit_scan_tasks(target, ports)
            
            loop For each port
                Pool->>Pool: _execute_scan_task(task)
                Pool->>UDPScan: scan_port(target, port)
                UDPScan->>UDPScan: _create_udp_socket()
                UDPScan->>UDPScan: sendto(probe_data)
                UDPScan->>UDPScan: recvfrom(timeout)
                UDPScan-->>Pool: ScanResult
                Pool->>Progress: advance(1)
            end
            
            Pool-->>UDPScan: List[ScanResult]
        end
        
        UDPScan-->>CLI: udp_results
    end
    
    CLI->>Progress: complete()
    
    Note over CLI,Display: Result processing phase
    CLI->>CLI: combine_results(tcp_results, udp_results)
    CLI->>Display: display_scan_results(results)
    Display->>Display: filter_open_ports(results)
    Display->>Display: create_results_table()
    Display->>User: formatted table output
    
    Note over CLI,Output: Output phase
    alt Output file specified
        CLI->>Output: save_scan_results(results, file, format)
        Output->>Output: format_results(results, format)
        Output->>Output: write_to_file(formatted_data)
        Output-->>CLI: success confirmation
        CLI->>User: "Results saved to file"
    end
```

### 2. Target Enumeration Sequence

```mermaid
sequenceDiagram
    participant CLI as CLI Handler
    participant Enum as TargetEnumerator
    participant DNS as DNS Resolver
    participant Network as Network Utils

    CLI->>Enum: enumerate_targets(target_spec)
    
    Note over Enum: Detect target type
    Enum->>Enum: _detect_target_type(target_spec)
    
    alt CIDR Network (e.g., 192.168.1.0/24)
        Enum->>Network: IPv4Network(target_spec)
        Network-->>Enum: network_object
        
        loop For each IP in network
            Enum->>Enum: yield str(ip)
        end
        
    else IP Range (e.g., 192.168.1.1-192.168.1.100)
        Enum->>Enum: parse_ip_range(target_spec)
        Enum->>Network: IPv4Address(start_ip)
        Enum->>Network: IPv4Address(end_ip)
        
        loop From start_ip to end_ip
            Enum->>Enum: yield str(current_ip)
        end
        
    else Hostname (e.g., example.com)
        Enum->>DNS: resolve_host(hostname)
        DNS-->>Enum: resolved_ips[]
        
        loop For each resolved IP
            Enum->>Enum: yield resolved_ip
        end
        
    else Single IP (e.g., 192.168.1.100)
        Enum->>Network: IPv4Address(target_spec)
        Network-->>Enum: validated_ip
        Enum->>Enum: yield str(validated_ip)
    end
    
    Enum-->>CLI: List[target_hosts]
```

### 3. Concurrent Port Scanning Sequence

```mermaid
sequenceDiagram
    participant Scanner as TCP/UDP Scanner
    participant Pool as ConnectionPool
    participant Executor as ThreadPoolExecutor
    participant Worker1 as Worker Thread 1
    participant Worker2 as Worker Thread 2
    participant WorkerN as Worker Thread N
    participant Target as Target System

    Scanner->>Pool: submit_scan_tasks(targets, ports)
    
    Note over Pool: Initialize thread pool
    Pool->>Executor: ThreadPoolExecutor(max_workers)
    Pool->>Pool: create_scan_tasks(targets, ports)
    
    loop For each target/port combination
        Pool->>Pool: create ScanTask(target, port, scanner_func)
        Pool->>Executor: submit(task)
        Executor->>Pool: Future object
        Pool->>Pool: store active_task[task_id] = future
    end
    
    Note over Pool,Target: Concurrent execution
    par Worker Thread 1
        Executor->>Worker1: execute_task(task1)
        Worker1->>Scanner: scan_port(target1, port1)
        Scanner->>Target: connect(target1:port1)
        Target-->>Scanner: connection result
        Scanner-->>Worker1: ScanResult
        Worker1->>Pool: task_completed(task1, result)
    and Worker Thread 2
        Executor->>Worker2: execute_task(task2)
        Worker2->>Scanner: scan_port(target2, port2)
        Scanner->>Target: connect(target2:port2)
        Target-->>Scanner: connection result
        Scanner-->>Worker2: ScanResult
        Worker2->>Pool: task_completed(task2, result)
    and Worker Thread N
        Executor->>WorkerN: execute_task(taskN)
        WorkerN->>Scanner: scan_port(targetN, portN)
        Scanner->>Target: connect(targetN:portN)
        Target-->>Scanner: connection result
        Scanner-->>WorkerN: ScanResult
        WorkerN->>Pool: task_completed(taskN, result)
    end
    
    Note over Pool: Collect results
    Pool->>Pool: wait_for_completion()
    Pool->>Pool: aggregate_results()
    Pool-->>Scanner: List[ScanResult]
```

### 4. TCP Port Scanning Detail

```mermaid
sequenceDiagram
    participant Pool as ConnectionPool
    participant TCP as TCPScanner
    participant Socket as TCP Socket
    participant Target as Target System

    Pool->>TCP: scan_port(target, port)
    
    Note over TCP: Initialize scan
    TCP->>TCP: start_time = time.time()
    TCP->>TCP: _create_tcp_socket(target)
    
    alt IPv6 Target
        TCP->>Socket: socket(AF_INET6, SOCK_STREAM)
    else IPv4 Target
        TCP->>Socket: socket(AF_INET, SOCK_STREAM)
    end
    
    TCP->>Socket: settimeout(timeout_seconds)
    TCP->>Socket: setsockopt(SO_REUSEADDR, 1)
    
    Note over TCP,Target: Connection attempt
    TCP->>Socket: connect((host, port))
    
    alt Connection Successful
        Socket->>Target: TCP SYN
        Target-->>Socket: TCP SYN-ACK
        Socket->>Target: TCP ACK
        Target-->>TCP: Connection established
        
        TCP->>TCP: response_time = time.time() - start_time
        TCP->>Socket: close()
        
        TCP->>TCP: create ScanResult(OPEN, response_time)
        
    else Connection Refused
        Target-->>Socket: TCP RST
        TCP->>TCP: response_time = time.time() - start_time
        TCP->>Socket: close()
        
        TCP->>TCP: create ScanResult(CLOSED, response_time)
        
    else Connection Timeout
        Socket-->>TCP: socket.timeout exception
        TCP->>TCP: response_time = time.time() - start_time
        TCP->>Socket: close()
        
        TCP->>TCP: create ScanResult(FILTERED, response_time)
        
    else Network Error
        Socket-->>TCP: socket.error exception
        TCP->>TCP: response_time = time.time() - start_time
        TCP->>Socket: close()
        
        TCP->>TCP: create ScanResult(UNKNOWN, error_message)
    end
    
    TCP-->>Pool: ScanResult
```

### 5. UDP Port Scanning Detail

```mermaid
sequenceDiagram
    participant Pool as ConnectionPool
    participant UDP as UDPScanner
    participant Socket as UDP Socket
    participant Target as Target System

    Pool->>UDP: scan_port(target, port)
    
    Note over UDP: Initialize scan
    UDP->>UDP: start_time = time.time()
    UDP->>UDP: _create_udp_socket(target)
    
    alt IPv6 Target
        UDP->>Socket: socket(AF_INET6, SOCK_DGRAM)
    else IPv4 Target
        UDP->>Socket: socket(AF_INET, SOCK_DGRAM)
    end
    
    UDP->>Socket: settimeout(timeout_seconds)
    
    Note over UDP,Target: UDP probe
    UDP->>Socket: sendto(probe_data, (host, port))
    Socket->>Target: UDP packet
    
    Note over UDP,Target: Response handling
    UDP->>Socket: recvfrom(1024)
    
    alt Response Received
        Target-->>Socket: UDP response
        Socket-->>UDP: (response_data, addr)
        
        UDP->>UDP: response_time = time.time() - start_time
        UDP->>Socket: close()
        
        UDP->>UDP: create ScanResult(OPEN, response_time, response_data)
        
    else ICMP Port Unreachable
        Target-->>Socket: ICMP error
        Socket-->>UDP: socket.error (port unreachable)
        
        UDP->>UDP: response_time = time.time() - start_time
        UDP->>Socket: close()
        
        UDP->>UDP: create ScanResult(CLOSED, response_time)
        
    else Timeout (No Response)
        Socket-->>UDP: socket.timeout exception
        UDP->>UDP: response_time = time.time() - start_time
        UDP->>Socket: close()
        
        Note over UDP: UDP timeout means open|filtered
        UDP->>UDP: create ScanResult(FILTERED, response_time)
        
    else Network Error
        Socket-->>UDP: socket.error exception
        UDP->>UDP: response_time = time.time() - start_time
        UDP->>Socket: close()
        
        UDP->>UDP: create ScanResult(UNKNOWN, error_message)
    end
    
    UDP-->>Pool: ScanResult
```

### 6. Result Aggregation and Display

```mermaid
sequenceDiagram
    participant CLI as CLI Handler
    participant Display as ResultDisplay
    participant Table as Rich Table
    participant Output as OutputManager
    participant File as Output File

    CLI->>CLI: combine_results(tcp_results, udp_results)
    CLI->>Display: display_scan_results(combined_results)
    
    Note over Display: Filter and process results
    Display->>Display: filter_open_ports(results)
    
    alt No open ports found
        Display->>CLI: print("[yellow]No open ports found[/yellow]")
    else Open ports found
        Display->>Table: Table(title="Scan Results")
        Display->>Table: add_column("Host", "Port", "Protocol", etc.)
        
        loop For each open port result
            Display->>Display: extract_service_info(result)
            Display->>Table: add_row(host, port, protocol, state, service, time)
        end
        
        Display->>CLI: console.print(table)
        Display->>CLI: print(summary_statistics)
    end
    
    Note over CLI,File: Output file handling
    alt Output file specified
        CLI->>Output: save_scan_results(results, file_path, format)
        
        alt JSON format
            Output->>Output: format_as_json(results)
        else CSV format
            Output->>Output: format_as_csv(results)
        else XML format
            Output->>Output: format_as_xml(results)
        end
        
        Output->>File: write_formatted_data(file_path)
        Output-->>CLI: success_confirmation
        CLI->>CLI: print("[green]Results saved to {file_path}[/green]")
    end
```

### 7. Error Handling and Recovery

```mermaid
sequenceDiagram
    participant CLI as CLI Handler
    participant Component as Scanner/Enumerator
    participant Error as ErrorHandler
    participant User as User

    CLI->>Component: execute_operation()
    
    alt Validation Error
        Component-->>CLI: ValidationError
        CLI->>Error: handle_validation_error(error)
        Error->>User: click.UsageError(message)
        
    else Network Error
        Component-->>CLI: NetworkError
        CLI->>Error: log_error(error)
        CLI->>CLI: continue_with_remaining_targets()
        
    else Timeout Error
        Component-->>CLI: TimeoutError
        CLI->>Error: log_warning(error)
        CLI->>CLI: mark_target_as_filtered()
        
    else Configuration Error
        Component-->>CLI: ConfigurationError
        CLI->>Error: handle_config_error(error)
        Error->>User: click.ClickException(message)
        
    else Unknown Error
        Component-->>CLI: Exception
        CLI->>Error: log_error(error)
        CLI->>Error: handle_graceful_degradation()
        Error->>User: click.ClickException("Scan failed: {error}")
    end
```

## Key Workflow Patterns

### 1. Command Initialization Pattern
```
CLI Input → Parameter Validation → Component Initialization → Settings Configuration
```

### 2. Target Enumeration Pattern
```
Target Specification → Type Detection → Enumeration Strategy → Host List Generation
```

### 3. Concurrent Scanning Pattern
```
Task Creation → Thread Pool Submission → Parallel Execution → Result Aggregation
```

### 4. Progressive Disclosure Pattern
```
Basic Scan → Service Detection → Protocol Verification → Detailed Analysis
```

### 5. Result Processing Pattern
```
Raw Results → Filtering → Formatting → Display/Output
```

## Performance Characteristics

### Threading Model
- **Thread Pool Size**: Configurable (default: 50 threads)
- **Task Distribution**: Round-robin assignment to available workers
- **Load Balancing**: Automatic based on thread availability
- **Resource Management**: Context manager pattern for cleanup

### Memory Management
- **Result Streaming**: Results processed as they arrive
- **Memory Pool**: Reusable result objects
- **Garbage Collection**: Explicit cleanup of large result sets
- **Memory Monitoring**: Optional memory profiling for large scans

### Network Optimization
- **Connection Reuse**: Socket pooling for repeated scans
- **Timeout Management**: Adaptive timeouts based on network conditions
- **Rate Limiting**: Configurable request rate limits
- **Retry Logic**: Exponential backoff for transient failures

## Error Recovery Strategies

### 1. Graceful Degradation
- Individual target failures don't stop the entire scan
- Timeout errors result in "filtered" state rather than failure
- Network errors are logged but don't terminate scanning

### 2. Partial Results
- Successfully scanned targets are displayed even if others fail
- Progress tracking continues despite individual failures
- Summary statistics include both successful and failed attempts

### 3. Resource Cleanup
- Automatic socket cleanup on errors
- Thread pool shutdown on interruption
- Memory cleanup for large result sets

## Integration Points

### 1. Configuration System
- Settings loaded from configuration files
- Environment variable overrides
- Command-line parameter precedence

### 2. Logging System
- Structured logging with correlation IDs
- Configurable log levels per component
- Performance metrics collection

### 3. Output System
- Multiple format support (JSON, CSV, XML)
- Streaming output for large results
- Template-based formatting

## Usage Examples

### 1. Single Host Scan
```bash
hawkeye scan -t 192.168.1.100
```

**Sequence**: CLI → Target Enumeration (single IP) → TCP Scan → Result Display

### 2. Network Range Scan
```bash
hawkeye scan -t 192.168.1.0/24 -p 80,443,3000-3010
```

**Sequence**: CLI → CIDR Enumeration → Port List Generation → Concurrent Scanning → Aggregated Results

### 3. Mixed Protocol Scan
```bash
hawkeye scan -t example.com --tcp --udp --threads 100
```

**Sequence**: CLI → DNS Resolution → TCP + UDP Scanning → Combined Results → Display

### 4. Output to File
```bash
hawkeye scan -t targets.txt -o results.json -f json
```

**Sequence**: CLI → File-based Target Enumeration → Scanning → JSON Formatting → File Output

## Conclusion

The HawkEye scan command implements a sophisticated workflow that efficiently handles target enumeration, concurrent port scanning, and result aggregation. The sequence diagrams above illustrate the complex interactions between components while maintaining clear separation of concerns and robust error handling.

Key architectural strengths:
- **Scalability**: Thread pool-based concurrent execution
- **Flexibility**: Multiple target specification formats
- **Reliability**: Comprehensive error handling and recovery
- **Usability**: Rich progress indication and formatted output
- **Extensibility**: Pluggable scanner and output format architecture 