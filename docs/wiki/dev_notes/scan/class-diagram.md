# Scan Command Class Diagram

## Overview

The HawkEye scan command implements a sophisticated network scanning architecture with multiple scanner types, connection management, rate limiting, and service fingerprinting capabilities. This document provides detailed class diagrams and architectural analysis of the scanner module components.

## High-Level Architecture

The scanner module follows a layered architecture with clear separation of concerns:

1. **Scanner Layer**: Abstract base class and concrete scanner implementations
2. **Management Layer**: Connection pooling, rate limiting, and task management
3. **Service Layer**: Service fingerprinting and target enumeration
4. **Data Layer**: Scan results, targets, and configuration data structures

```mermaid
classDiagram
    class BaseScanner {
        <<abstract>>
        #settings
        #logger
        #_results: List[ScanResult]
        #_scan_stats: Dict
        +__init__(settings)
        +scan_port(target, port)* ScanResult
        +scan_target(target) List[ScanResult]
        +scan_ports(target, ports) List[ScanResult]
        +get_results() List[ScanResult]
        +get_statistics() Dict
        +clear_results() None
        #_update_stats(result) None
        #_validate_target(target) bool
    }
    
    class TCPScanner {
        +__init__(settings)
        +scan_port(target, port) ScanResult
        +_connect_scan(target, port) ScanResult
        +_syn_scan(target, port) ScanResult
        +_fin_scan(target, port) ScanResult
        +get_scan_type() ScanType
    }
    
    class UDPScanner {
        +__init__(settings)
        +scan_port(target, port) ScanResult
        +_udp_probe(target, port) ScanResult
        +_icmp_probe(target, port) ScanResult
        +_service_probe(target, port) ScanResult
        +get_scan_type() ScanType
    }
    
    class ConnectionPool {
        -max_workers: int
        -executor: ThreadPoolExecutor
        -active_tasks: Dict[str, Future]
        -completed_tasks: List[ScanResult]
        -failed_tasks: List[tuple]
        -stats: Dict
        -_lock: Lock
        -_shutdown: bool
        +__init__(settings)
        +start() None
        +shutdown(wait) None
        +submit_task(task) Future
        +submit_batch(tasks) List[Future]
        +wait_for_completion(timeout) bool
        +get_results() List[ScanResult]
        +get_statistics() Dict
    }
    
    class RateLimiter {
        -config: RateLimitConfig
        -token_bucket: TokenBucket
        -request_times: deque
        -_lock: Lock
        +__init__(config)
        +acquire(tokens) bool
        +wait_for_permit(timeout) bool
        +get_current_rate() float
        +reset() None
        +get_statistics() Dict
    }
    
    class ServiceFingerprinter {
        -signatures: List[ServiceSignature]
        +__init__(settings)
        +fingerprint_service(target, port, banner) ServiceInfo
        +get_banner(target, port) str
        +analyze_banner(banner) ServiceInfo
        +_load_signatures() None
        +_match_signature(banner, signature) bool
    }
    
    class TargetEnumerator {
        +__init__(settings)
        +enumerate_targets(target, ports) List[str]
        +enumerate_from_cidr(cidr, ports) Iterator[ScanTarget]
        +enumerate_from_range(range_spec, ports) Iterator[ScanTarget]
        +_resolve_host(hostname) List[str]
        +_validate_target(target) bool
        +_get_enabled_scan_types() List[ScanType]
    }
    
    BaseScanner <|-- TCPScanner
    BaseScanner <|-- UDPScanner
    BaseScanner --> ConnectionPool : uses
    BaseScanner --> RateLimiter : uses
    BaseScanner --> ServiceFingerprinter : uses
    BaseScanner --> TargetEnumerator : uses
```

## Core Data Structures

### Scan Target and Result Models

```mermaid
classDiagram
    class ScanTarget {
        +host: str
        +ports: List[int]
        +scan_types: List[ScanType]
        +timeout: float
        +retries: int
        +__init__(host, ports, scan_types)
        +__str__() str
        +to_dict() Dict
        +is_valid() bool
    }
    
    class ScanResult {
        +target: ScanTarget
        +port: int
        +state: PortState
        +scan_type: ScanType
        +timestamp: float
        +response_time: Optional[float]
        +service_info: Optional[ServiceInfo]
        +error: Optional[str]
        +raw_data: Dict[str, str]
        +is_open() bool
        +has_service_info() bool
        +to_dict() Dict
    }
    
    class ServiceInfo {
        +name: str
        +version: Optional[str]
        +banner: Optional[str]
        +product: Optional[str]
        +extra_info: Optional[str]
        +confidence: float
        +__str__() str
    }
    
    class PortState {
        <<enumeration>>
        OPEN
        CLOSED
        FILTERED
        UNKNOWN
    }
    
    class ScanType {
        <<enumeration>>
        TCP_CONNECT
        TCP_SYN
        TCP_FIN
        UDP
        UDP_CONNECT
    }
    
    ScanResult --> ScanTarget : contains
    ScanResult --> ServiceInfo : contains
    ScanResult --> PortState : uses
    ScanResult --> ScanType : uses
    ScanTarget --> ScanType : uses
```

### Task Management Data Structures

```mermaid
classDiagram
    class ScanTask {
        +target: ScanTarget
        +port: int
        +scanner_func: Callable
        +task_id: str
        +__post_init__() None
    }
    
    class RateLimitConfig {
        +requests_per_second: float
        +burst_size: int
        +window_size: float
        +__post_init__() None
    }
    
    class TokenBucket {
        -rate: float
        -capacity: int
        -tokens: float
        -last_update: float
        -_lock: Lock
        +__init__(rate, capacity)
        +consume(tokens) bool
        +wait_for_tokens(tokens, timeout) bool
        +get_tokens() float
        +refill() None
    }
    
    class ServiceSignature {
        +name: str
        +pattern: str
        +confidence: float
        +version_pattern: Optional[str]
        +product_pattern: Optional[str]
        +ports: List[int]
        +compiled_pattern: Pattern
        +compiled_version: Pattern
        +compiled_product: Pattern
        +__post_init__() None
        +match(banner) bool
        +extract_version(banner) Optional[str]
        +extract_product(banner) Optional[str]
    }
    
    ConnectionPool --> ScanTask : manages
    RateLimiter --> RateLimitConfig : uses
    RateLimiter --> TokenBucket : uses
    ServiceFingerprinter --> ServiceSignature : uses
```

## Inheritance Hierarchy Analysis

### BaseScanner Abstract Base Class

```mermaid
classDiagram
    class BaseScanner {
        <<abstract>>
        #settings: Settings
        #logger: Logger
        #_results: List[ScanResult]
        #_scan_stats: Dict[str, Any]
        
        +__init__(settings: Optional[Settings])
        +scan_port(target: ScanTarget, port: int)* ScanResult
        +scan_target(target: ScanTarget) List[ScanResult]
        +scan_ports(target: ScanTarget, ports: List[int]) List[ScanResult]
        +get_results() List[ScanResult]
        +get_statistics() Dict[str, Any]
        +clear_results() None
        +set_timeout(timeout: float) None
        +set_retries(retries: int) None
        
        #_update_stats(result: ScanResult) None
        #_validate_target(target: ScanTarget) bool
        #_create_scan_result(target: ScanTarget, port: int, **kwargs) ScanResult
        #_handle_scan_error(target: ScanTarget, port: int, error: Exception) ScanResult
    }
    
    note for BaseScanner "Abstract base class defining\ncommon scanning interface\nand shared functionality"
```

**Key Design Patterns**:
- **Template Method Pattern**: `scan_target()` and `scan_ports()` define the scanning algorithm structure
- **Strategy Pattern**: Different concrete scanners implement different scanning strategies
- **Factory Method Pattern**: `_create_scan_result()` creates appropriate result objects

### TCPScanner Implementation

```mermaid
classDiagram
    class TCPScanner {
        +__init__(settings: Optional[Settings])
        +scan_port(target: ScanTarget, port: int) ScanResult
        +get_scan_type() ScanType
        
        +_connect_scan(target: ScanTarget, port: int) ScanResult
        +_syn_scan(target: ScanTarget, port: int) ScanResult
        +_fin_scan(target: ScanTarget, port: int) ScanResult
        +_null_scan(target: ScanTarget, port: int) ScanResult
        +_xmas_scan(target: ScanTarget, port: int) ScanResult
        
        -_create_socket(family: int, type: int) socket
        -_set_socket_options(sock: socket) None
        -_perform_connect(sock: socket, address: tuple) bool
        -_analyze_tcp_response(response: bytes) PortState
        -_handle_tcp_error(error: Exception) PortState
    }
    
    BaseScanner <|-- TCPScanner
    
    note for TCPScanner "Implements TCP scanning methods:\n- Connect() scan (default)\n- SYN scan (stealthy)\n- FIN/NULL/Xmas scans\n- Advanced TCP techniques"
```

**TCP Scanning Methods**:
1. **Connect Scan**: Full TCP three-way handshake
2. **SYN Scan**: Half-open scanning (stealth)
3. **FIN Scan**: Uses FIN packets to probe ports
4. **NULL Scan**: Sends packets with no flags set
5. **Xmas Scan**: Sends packets with FIN, PSH, and URG flags

### UDPScanner Implementation

```mermaid
classDiagram
    class UDPScanner {
        +__init__(settings: Optional[Settings])
        +scan_port(target: ScanTarget, port: int) ScanResult
        +get_scan_type() ScanType
        
        +_udp_probe(target: ScanTarget, port: int) ScanResult
        +_icmp_probe(target: ScanTarget, port: int) ScanResult
        +_service_probe(target: ScanTarget, port: int) ScanResult
        +_payload_probe(target: ScanTarget, port: int, payload: bytes) ScanResult
        
        -_create_udp_socket() socket
        -_send_udp_packet(sock: socket, address: tuple, payload: bytes) None
        -_receive_udp_response(sock: socket, timeout: float) Optional[bytes]
        -_analyze_icmp_response(response: bytes) PortState
        -_get_service_payload(port: int) Optional[bytes]
        -_handle_udp_timeout() PortState
    }
    
    BaseScanner <|-- UDPScanner
    
    note for UDPScanner "Implements UDP scanning methods:\n- Basic UDP probes\n- ICMP response analysis\n- Service-specific payloads\n- Timeout-based inference"
```

**UDP Scanning Challenges**:
- **Connectionless Protocol**: No reliable way to determine port state
- **ICMP Responses**: Must analyze ICMP port unreachable messages
- **Service-Specific Probes**: Use known payloads for common services
- **Timeout Inference**: Open ports often don't respond

## Composition Relationships

### Connection Pool Management

```mermaid
classDiagram
    class ConnectionPool {
        -max_workers: int
        -executor: ThreadPoolExecutor
        -active_tasks: Dict[str, Future]
        -completed_tasks: List[ScanResult]
        -failed_tasks: List[tuple]
        -stats: Dict[str, Any]
        -_lock: threading.Lock
        -_shutdown: bool
        
        +__init__(settings: Optional[Settings])
        +__enter__() ConnectionPool
        +__exit__(exc_type, exc_val, exc_tb) None
        +start() None
        +shutdown(wait: bool) None
        +submit_task(task: ScanTask) Future
        +submit_batch(tasks: List[ScanTask]) List[Future]
        +wait_for_completion(timeout: Optional[float]) bool
        +get_results() List[ScanResult]
        +get_failed_tasks() List[tuple]
        +get_statistics() Dict[str, Any]
        +is_running() bool
        +cancel_all_tasks() None
        
        -_process_completed_tasks() None
        -_cleanup_futures() None
        -_update_statistics() None
    }
    
    class ScanTask {
        +target: ScanTarget
        +port: int
        +scanner_func: Callable
        +task_id: str
        +priority: int
        +timeout: float
        +retries: int
        +__post_init__() None
        +execute() ScanResult
        +__str__() str
    }
    
    ConnectionPool --> ScanTask : manages
    ConnectionPool --> ThreadPoolExecutor : uses
    ConnectionPool --> Future : manages
    
    note for ConnectionPool "Manages concurrent scanning\noperations using thread pools\nwith proper resource cleanup"
```

**Key Features**:
- **Thread Pool Management**: Configurable number of worker threads
- **Task Scheduling**: Priority-based task execution
- **Resource Management**: Proper startup/shutdown procedures
- **Statistics Tracking**: Performance metrics and monitoring
- **Error Handling**: Failed task tracking and recovery

### Rate Limiting System

```mermaid
classDiagram
    class RateLimiter {
        -config: RateLimitConfig
        -token_bucket: TokenBucket
        -request_times: deque
        -_lock: threading.Lock
        -_stats: Dict[str, Any]
        
        +__init__(config: RateLimitConfig)
        +acquire(tokens: int) bool
        +wait_for_permit(timeout: Optional[float]) bool
        +get_current_rate() float
        +reset() None
        +get_statistics() Dict[str, Any]
        +is_rate_limited() bool
        
        -_sliding_window_check() bool
        -_update_request_times() None
        -_cleanup_old_requests() None
    }
    
    class TokenBucket {
        -rate: float
        -capacity: int
        -tokens: float
        -last_update: float
        -_lock: threading.Lock
        
        +__init__(rate: float, capacity: int)
        +consume(tokens: int) bool
        +wait_for_tokens(tokens: int, timeout: Optional[float]) bool
        +get_tokens() float
        +get_capacity() int
        +get_rate() float
        +refill() None
        +is_empty() bool
        +is_full() bool
    }
    
    class RateLimitConfig {
        +requests_per_second: float
        +burst_size: int
        +window_size: float
        +adaptive: bool
        +backoff_multiplier: float
        +__post_init__() None
        +validate() None
    }
    
    RateLimiter --> TokenBucket : uses
    RateLimiter --> RateLimitConfig : uses
    
    note for RateLimiter "Implements token bucket algorithm\nwith sliding window validation\nfor precise rate control"
```

**Rate Limiting Algorithms**:
1. **Token Bucket**: Primary rate limiting mechanism
2. **Sliding Window**: Additional validation layer
3. **Adaptive Backoff**: Dynamic rate adjustment
4. **Burst Control**: Handles traffic spikes

### Service Fingerprinting Engine

```mermaid
classDiagram
    class ServiceFingerprinter {
        -signatures: List[ServiceSignature]
        -cache: Dict[str, ServiceInfo]
        -stats: Dict[str, Any]
        
        +__init__(settings: Optional[Settings])
        +fingerprint_service(target: ScanTarget, port: int, banner: Optional[str]) ServiceInfo
        +get_banner(target: ScanTarget, port: int, timeout: float) str
        +analyze_banner(banner: str, port: int) ServiceInfo
        +add_signature(signature: ServiceSignature) None
        +get_statistics() Dict[str, Any]
        +clear_cache() None
        
        -_load_signatures() None
        -_match_signature(banner: str, signature: ServiceSignature) Optional[Match]
        -_extract_service_info(banner: str, signature: ServiceSignature) ServiceInfo
        -_probe_service(target: ScanTarget, port: int) Optional[str]
        -_cache_result(key: str, service_info: ServiceInfo) None
    }
    
    class ServiceSignature {
        +name: str
        +pattern: str
        +confidence: float
        +version_pattern: Optional[str]
        +product_pattern: Optional[str]
        +ports: List[int]
        +probes: List[str]
        +compiled_pattern: Pattern
        +compiled_version: Optional[Pattern]
        +compiled_product: Optional[Pattern]
        
        +__post_init__() None
        +match(banner: str) bool
        +extract_version(banner: str) Optional[str]
        +extract_product(banner: str) Optional[str]
        +get_confidence(banner: str) float
    }
    
    ServiceFingerprinter --> ServiceSignature : uses
    ServiceFingerprinter --> ServiceInfo : creates
    
    note for ServiceFingerprinter "Identifies services through\nbanner analysis and pattern\nmatching with confidence scoring"
```

**Fingerprinting Process**:
1. **Banner Grabbing**: Connect and retrieve service banners
2. **Pattern Matching**: Apply regex patterns to identify services
3. **Version Extraction**: Parse version information from banners
4. **Confidence Scoring**: Rate identification accuracy
5. **Caching**: Store results for performance optimization

### Target Enumeration System

```mermaid
classDiagram
    class TargetEnumerator {
        -dns_cache: Dict[str, List[str]]
        -stats: Dict[str, Any]
        
        +__init__(settings: Optional[Settings])
        +enumerate_targets(target: str, ports: Optional[List[int]]) List[str]
        +enumerate_from_cidr(cidr: str, ports: Optional[List[int]]) Iterator[ScanTarget]
        +enumerate_from_range(range_spec: str, ports: Optional[List[int]]) Iterator[ScanTarget]
        +enumerate_from_file(filepath: str, ports: Optional[List[int]]) Iterator[ScanTarget]
        +get_statistics() Dict[str, Any]
        +clear_dns_cache() None
        
        -_resolve_host(hostname: str, timeout: float) List[str]
        -_validate_target(target: str) bool
        -_parse_ip_range(range_spec: str) Iterator[str]
        -_get_enabled_scan_types() List[ScanType]
        -_cache_dns_result(hostname: str, ips: List[str]) None
    }
    
    class IPRange {
        +start_ip: Union[IPv4Address, IPv6Address]
        +end_ip: Union[IPv4Address, IPv6Address]
        +__init__(start: str, end: str)
        +__iter__() Iterator[str]
        +__len__() int
        +contains(ip: str) bool
    }
    
    class CIDRNetwork {
        +network: Union[IPv4Network, IPv6Network]
        +__init__(cidr: str)
        +hosts() Iterator[str]
        +num_addresses() int
        +network_address() str
        +broadcast_address() str
    }
    
    TargetEnumerator --> IPRange : creates
    TargetEnumerator --> CIDRNetwork : creates
    TargetEnumerator --> ScanTarget : creates
    
    note for TargetEnumerator "Converts various target formats\n(CIDR, ranges, hostnames)\ninto scannable target objects"
```

**Target Format Support**:
- **Single IPs**: `192.168.1.1`
- **CIDR Notation**: `192.168.1.0/24`
- **IP Ranges**: `192.168.1.1-192.168.1.100`
- **Hostnames**: `example.com`
- **File Lists**: Text files with target lists

## Component Interaction Flow

### Scan Execution Sequence

```mermaid
sequenceDiagram
    participant CLI as CLI Command
    participant Scanner as BaseScanner
    participant Pool as ConnectionPool
    participant Limiter as RateLimiter
    participant Enum as TargetEnumerator
    participant Finger as ServiceFingerprinter
    
    CLI->>Enum: enumerate_targets(target_spec)
    Enum->>CLI: List[ScanTarget]
    
    CLI->>Scanner: scan_targets(targets)
    Scanner->>Pool: start()
    Scanner->>Limiter: acquire(tokens)
    Limiter-->>Scanner: permit_granted
    
    loop For each target and port
        Scanner->>Pool: submit_task(scan_task)
        Pool->>Pool: execute_in_thread(scan_port)
        Pool->>Scanner: ScanResult
        
        alt Port is open
            Scanner->>Finger: fingerprint_service(target, port)
            Finger->>Scanner: ServiceInfo
            Scanner->>Scanner: update_scan_result(service_info)
        end
    end
    
    Scanner->>Pool: wait_for_completion()
    Pool-->>Scanner: all_tasks_complete
    Scanner->>Pool: shutdown()
    Scanner->>CLI: List[ScanResult]
```

### Error Handling and Recovery

```mermaid
stateDiagram-v2
    [*] --> Scanning
    Scanning --> Success : Scan Complete
    Scanning --> NetworkError : Connection Failed
    Scanning --> TimeoutError : Timeout Exceeded
    Scanning --> RateLimited : Rate Limit Hit
    
    NetworkError --> Retry : Retry Available
    TimeoutError --> Retry : Retry Available
    NetworkError --> Failed : Max Retries
    TimeoutError --> Failed : Max Retries
    
    RateLimited --> WaitForTokens
    WaitForTokens --> Scanning : Tokens Available
    WaitForTokens --> Failed : Wait Timeout
    
    Retry --> Scanning
    Success --> [*]
    Failed --> [*]
```

## Performance Characteristics

### Concurrency Model

```mermaid
graph TD
    A[Main Thread] --> B[ConnectionPool]
    B --> C[Worker Thread 1]
    B --> D[Worker Thread 2]
    B --> E[Worker Thread N]
    
    C --> F[TCP Scanner]
    D --> G[UDP Scanner]
    E --> H[Service Fingerprinter]
    
    F --> I[Rate Limiter]
    G --> I
    H --> I
    
    I --> J[Network Operations]
    
    subgraph "Thread Safety"
        K[Shared State]
        L[Locks & Synchronization]
        M[Thread-Safe Collections]
    end
    
    subgraph "Resource Management"
        N[Connection Limits]
        O[Memory Management]
        P[Cleanup Procedures]
    end
```

**Performance Optimizations**:
- **Thread Pool**: Configurable worker threads for concurrent scanning
- **Connection Reuse**: Socket pooling for TCP connections
- **Rate Limiting**: Prevents network congestion and detection
- **Caching**: DNS resolution and service fingerprint caching
- **Batch Processing**: Efficient handling of large target lists

### Memory Management

```python
class MemoryOptimizedScanner:
    """Memory-efficient scanner implementation."""
    
    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._result_buffer_size = self.settings.scan.result_buffer_size
        self._result_buffer = deque(maxlen=self._result_buffer_size)
        self._memory_threshold = self.settings.scan.memory_threshold
    
    def scan_with_streaming(self, targets: Iterator[ScanTarget]) -> Iterator[ScanResult]:
        """Stream scan results to minimize memory usage."""
        
        for target in targets:
            # Check memory usage
            if self._get_memory_usage() > self._memory_threshold:
                self._flush_results()
            
            result = self.scan_target(target)
            yield result
    
    def _flush_results(self):
        """Flush buffered results to storage."""
        if self._result_buffer:
            self._save_results_to_disk(list(self._result_buffer))
            self._result_buffer.clear()
```

## Configuration and Extensibility

### Scanner Configuration

```mermaid
classDiagram
    class ScanConfig {
        +max_threads: int
        +timeout: float
        +retries: int
        +rate_limit: float
        +burst_size: int
        +default_ports: List[int]
        +tcp_connect_timeout: float
        +udp_timeout: float
        +banner_timeout: float
        +dns_timeout: float
        +result_buffer_size: int
        +memory_threshold: int
    }
    
    class PortConfig {
        +common_ports: List[int]
        +tcp_ports: List[int]
        +udp_ports: List[int]
        +custom_ports: Dict[str, List[int]]
        +port_ranges: List[tuple]
    }
    
    class FingerprintConfig {
        +signature_files: List[str]
        +custom_signatures: List[ServiceSignature]
        +confidence_threshold: float
        +cache_size: int
        +probe_timeout: float
    }
    
    ScanConfig --> PortConfig : includes
    ScanConfig --> FingerprintConfig : includes
    BaseScanner --> ScanConfig : uses
```

### Plugin Architecture

```python
from abc import ABC, abstractmethod

class ScannerPlugin(ABC):
    """Plugin interface for extending scanner functionality."""
    
    @abstractmethod
    def get_plugin_name(self) -> str:
        """Return plugin name."""
        pass
    
    @abstractmethod
    def initialize(self, scanner: BaseScanner) -> None:
        """Initialize plugin with scanner instance."""
        pass
    
    @abstractmethod
    def pre_scan_hook(self, target: ScanTarget) -> Optional[ScanTarget]:
        """Called before scanning a target."""
        pass
    
    @abstractmethod
    def post_scan_hook(self, result: ScanResult) -> Optional[ScanResult]:
        """Called after scanning completes."""
        pass

class PluginManager:
    """Manages scanner plugins."""
    
    def __init__(self):
        self.plugins: List[ScannerPlugin] = []
    
    def register_plugin(self, plugin: ScannerPlugin) -> None:
        """Register a new plugin."""
        self.plugins.append(plugin)
    
    def apply_pre_scan_hooks(self, target: ScanTarget) -> ScanTarget:
        """Apply all pre-scan hooks."""
        for plugin in self.plugins:
            target = plugin.pre_scan_hook(target) or target
        return target
    
    def apply_post_scan_hooks(self, result: ScanResult) -> ScanResult:
        """Apply all post-scan hooks."""
        for plugin in self.plugins:
            result = plugin.post_scan_hook(result) or result
        return result
```

## Testing Strategy

### Unit Test Architecture

```mermaid
classDiagram
    class BaseScannerTest {
        <<test>>
        +test_scan_port_success()
        +test_scan_port_failure()
        +test_scan_target_multiple_ports()
        +test_statistics_tracking()
        +test_result_management()
    }
    
    class TCPScannerTest {
        <<test>>
        +test_connect_scan()
        +test_syn_scan()
        +test_timeout_handling()
        +test_connection_refused()
        +test_filtered_ports()
    }
    
    class UDPScannerTest {
        <<test>>
        +test_udp_probe()
        +test_icmp_response_handling()
        +test_timeout_inference()
        +test_service_probes()
        +test_payload_responses()
    }
    
    class ConnectionPoolTest {
        <<test>>
        +test_thread_pool_management()
        +test_task_submission()
        +test_concurrent_execution()
        +test_error_handling()
        +test_shutdown_procedures()
    }
    
    class MockNetworkInterface {
        <<mock>>
        +mock_socket_connect()
        +mock_socket_send()
        +mock_socket_recv()
        +simulate_network_conditions()
        +inject_network_errors()
    }
    
    BaseScannerTest --> MockNetworkInterface : uses
    TCPScannerTest --> MockNetworkInterface : uses
    UDPScannerTest --> MockNetworkInterface : uses
```

### Integration Testing

```python
class ScannerIntegrationTest:
    """Integration tests for scanner module."""
    
    def test_end_to_end_tcp_scan(self):
        """Test complete TCP scanning workflow."""
        
        # Setup test environment
        targets = ["127.0.0.1"]
        ports = [22, 80, 443, 8080]
        
        # Initialize scanner with test configuration
        scanner = TCPScanner(test_settings)
        
        # Execute scan
        results = []
        for target in targets:
            scan_target = ScanTarget(host=target, ports=ports)
            target_results = scanner.scan_target(scan_target)
            results.extend(target_results)
        
        # Validate results
        assert len(results) == len(targets) * len(ports)
        assert all(isinstance(r, ScanResult) for r in results)
        assert any(r.is_open for r in results)  # At least one port should be open
        
        # Check statistics
        stats = scanner.get_statistics()
        assert stats['total_scans'] == len(results)
        assert stats['successful_scans'] + stats['failed_scans'] == len(results)
    
    def test_concurrent_scanning_performance(self):
        """Test concurrent scanning performance and correctness."""
        
        # Large target list
        targets = [f"192.168.1.{i}" for i in range(1, 255)]
        ports = [22, 80, 443]
        
        # Test with different thread counts
        for thread_count in [1, 5, 10, 20]:
            settings = create_test_settings(max_threads=thread_count)
            scanner = TCPScanner(settings)
            
            start_time = time.time()
            results = scanner.scan_multiple_targets(targets, ports)
            duration = time.time() - start_time
            
            # Validate performance improvement with more threads
            assert len(results) == len(targets) * len(ports)
            self.performance_results[thread_count] = duration
        
        # Ensure parallelization improves performance
        assert self.performance_results[10] < self.performance_results[1]
```

## Conclusion

The HawkEye scan command architecture demonstrates a well-designed, modular approach to network scanning with the following key strengths:

**Design Patterns**:
- **Abstract Base Class Pattern**: Provides consistent interface across scanner types
- **Template Method Pattern**: Defines scanning workflow with customization points
- **Strategy Pattern**: Allows different scanning techniques
- **Composition Pattern**: Modular components for connection management, rate limiting, and service detection

**Architecture Benefits**:
- **Modularity**: Clear separation of concerns between scanning, management, and service detection
- **Extensibility**: Plugin architecture supports custom scanners and fingerprinting rules
- **Performance**: Concurrent execution with configurable thread pools and rate limiting
- **Reliability**: Comprehensive error handling and retry mechanisms
- **Maintainability**: Clean interfaces and well-defined component responsibilities

**Key Components**:
1. **Scanner Hierarchy**: BaseScanner → TCPScanner/UDPScanner with specialized scanning methods
2. **Connection Management**: ThreadPoolExecutor-based concurrent execution
3. **Rate Limiting**: Token bucket algorithm with sliding window validation
4. **Service Detection**: Pattern-based fingerprinting with confidence scoring
5. **Target Enumeration**: Flexible target specification with DNS resolution

The architecture provides a solid foundation for network reconnaissance while maintaining good performance characteristics and extensibility for future enhancements. 