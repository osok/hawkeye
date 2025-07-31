# Scanner API Documentation

## Overview

The Scanner API provides comprehensive network scanning capabilities for detecting MCP servers within network infrastructure. The scanner supports TCP and UDP scanning, service fingerprinting, and concurrent operations with rate limiting.

## Core Classes

### TCPScanner

Main class for TCP port scanning operations.

```python
from hawkeye.scanner.tcp_scanner import TCPScanner
from hawkeye.config.settings import ScanSettings

# Initialize with default settings
scanner = TCPScanner()

# Initialize with custom settings
settings = ScanSettings(max_threads=100, timeout_seconds=10)
scanner = TCPScanner(settings)
```

#### Methods

##### `scan(target: str, ports: List[int]) -> List[ScanResult]`

Performs TCP port scanning on specified target and ports.

**Parameters:**
- `target`: IP address or hostname to scan
- `ports`: List of ports to scan

**Returns:**
- `List[ScanResult]`: Results for each scanned port

**Example:**
```python
results = scanner.scan("192.168.1.100", [3000, 8000, 8080])
for result in results:
    if result.is_open:
        print(f"Open port: {result.port}, Service: {result.service}")
```

##### `scan_range(target: str, start_port: int, end_port: int) -> List[ScanResult]`

Scans a range of ports on the target.

##### `batch_scan(targets: List[str], ports: List[int]) -> Dict[str, List[ScanResult]]`

Scans multiple targets concurrently.

### UDPScanner

Class for UDP port scanning with service-specific probes.

```python
from hawkeye.scanner.udp_scanner import UDPScanner

scanner = UDPScanner()
results = scanner.scan("192.168.1.100", [53, 161, 123])
```

### ServiceFingerprinter

Service identification and banner grabbing functionality.

```python
from hawkeye.scanner.fingerprint import ServiceFingerprinter

fingerprinter = ServiceFingerprinter()
service_info = fingerprinter.identify_service("192.168.1.100", 3000)
```

## Data Models

### ScanResult

Represents the result of a port scan.

```python
@dataclass
class ScanResult:
    target: str
    port: int
    protocol: str
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)
```

### ServiceInfo

Contains detailed service information.

```python
@dataclass
class ServiceInfo:
    name: str
    version: Optional[str]
    banner: Optional[str]
    confidence: float
    additional_info: Dict[str, Any]
```

## Usage Examples

### Basic TCP Scan

```python
from hawkeye.scanner.tcp_scanner import TCPScanner

scanner = TCPScanner()
results = scanner.scan("192.168.1.100", [3000, 8000, 8080, 9000])

for result in results:
    if result.is_open:
        print(f"Found open port {result.port} - {result.service}")
```

### Network Range Scan

```python
from hawkeye.scanner.target_enum import TargetEnumerator

enumerator = TargetEnumerator()
targets = enumerator.enumerate_targets("192.168.1.0/24")

scanner = TCPScanner()
for target in targets:
    results = scanner.scan(target, [3000, 8000])
```

### Service Fingerprinting

```python
from hawkeye.scanner.fingerprint import ServiceFingerprinter

fingerprinter = ServiceFingerprinter()
service = fingerprinter.identify_service("192.168.1.100", 3000)

if service and service.name == "http":
    print(f"HTTP service detected: {service.version}")
```

## Configuration

Scanner behavior is controlled by `ScanSettings`:

```python
from hawkeye.config.settings import ScanSettings

settings = ScanSettings(
    max_threads=100,
    timeout_seconds=10,
    retry_attempts=3,
    rate_limit_requests=50
)
```

## Error Handling

The scanner includes comprehensive error handling:

```python
from hawkeye.scanner.tcp_scanner import TCPScanner
from hawkeye.scanner.exceptions import ScanError, TimeoutError

scanner = TCPScanner()

try:
    results = scanner.scan("invalid-host", [3000])
except ScanError as e:
    print(f"Scan failed: {e}")
except TimeoutError as e:
    print(f"Scan timed out: {e}")
```

## Performance Considerations

- Use connection pooling for better performance with multiple targets
- Implement rate limiting to avoid network congestion
- Configure appropriate timeouts based on network conditions
- Use threading efficiently with max_threads setting 