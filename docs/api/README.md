# HawkEye API Documentation

## Overview

HawkEye provides a comprehensive API for MCP (Model Context Protocol) security reconnaissance and assessment. The API is organized into several core modules, each handling specific aspects of the security analysis workflow.

## Quick Start

```python
from hawkeye import HawkEye
from hawkeye.config.settings import HawkEyeSettings

# Initialize HawkEye with default settings
hawkeye = HawkEye()

# Scan for MCP servers
results = hawkeye.scan_network("192.168.1.0/24")

# Generate security report
report = hawkeye.generate_report(results, format="html")
```

## API Modules

### 1. Scanner API
**File:** [scanner.md](scanner.md)

Network scanning capabilities for discovering MCP servers.

**Key Classes:**
- `TCPScanner` - TCP port scanning
- `UDPScanner` - UDP port scanning  
- `ServiceFingerprinter` - Service identification
- `TargetEnumerator` - Target enumeration

**Common Use Cases:**
- Network discovery
- Port scanning
- Service fingerprinting
- Batch scanning operations

### 2. Detection API
**File:** [detection.md](detection.md)

MCP-specific detection and introspection capabilities.

**Key Classes:**
- `MCPDetector` - Main detection engine
- `MCPIntrospector` - Advanced introspection
- `ProcessEnumerator` - Process discovery
- `ConfigDiscovery` - Configuration discovery

**Common Use Cases:**
- Local MCP server detection
- Remote MCP verification
- Server capability analysis
- Configuration discovery

### 3. MCP Introspection API
**File:** [mcp_introspection.md](mcp_introspection.md)

Deep introspection and analysis of MCP servers.

**Key Classes:**
- `MCPIntrospector` - Core introspection engine
- `TransportFactory` - Transport layer management
- `RiskAnalyzer` - Security risk assessment
- `CapabilityAssessment` - Capability analysis

**Common Use Cases:**
- Tool and resource discovery
- Security risk assessment  
- Protocol version compatibility
- Transport layer analysis

### 4. Assessment API
**File:** assessment.md (TODO)

Security assessment and risk analysis functionality.

**Key Classes:**
- `SecurityAssessor` - Main assessment engine
- `CVSSScorer` - Vulnerability scoring
- `ComplianceChecker` - Policy compliance
- `RiskCalculator` - Risk calculation

### 5. Reporting API
**File:** reporting.md (TODO)

Report generation and output formatting.

**Key Classes:**
- `ReportGenerator` - Main reporting engine
- `HTMLReporter` - HTML report generation
- `JSONReporter` - JSON output
- `ExecutiveSummary` - Executive reporting

## Configuration

All HawkEye components are configured through the settings system:

```python
from hawkeye.config.settings import HawkEyeSettings, ScanSettings

# Load configuration
settings = HawkEyeSettings()

# Customize scan settings  
settings.scan.max_threads = 100
settings.scan.timeout_seconds = 10

# Customize detection settings
settings.detection.enable_docker_inspect = True
settings.detection.max_depth = 5

# Customize MCP introspection
settings.mcp_introspection.connection_timeout = 30.0
settings.mcp_introspection.enable_caching = True
```

## Data Models

### Core Models

#### ScanResult
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
```

#### MCPServerInfo
```python
@dataclass
class MCPServerInfo:
    name: str
    host: str
    port: Optional[int]
    protocol: str
    transport_type: str
    process_id: Optional[int]
    config_path: Optional[str]
```

#### MCPCapabilities
```python
@dataclass
class MCPCapabilities:
    server_name: str
    server_version: str
    protocol_version: str
    tools: List[MCPTool]
    resources: List[MCPResource]
    capabilities: Dict[str, Any]
```

## Integration Examples

### Complete Workflow Example

```python
from hawkeye import HawkEye
from hawkeye.config.settings import HawkEyeSettings

# Initialize HawkEye
settings = HawkEyeSettings()
settings.scan.max_threads = 50
settings.mcp_introspection.enable_caching = True

hawkeye = HawkEye(settings)

# 1. Network scanning
print("🔍 Scanning network for MCP servers...")
scan_results = hawkeye.scan_network("192.168.1.0/24", ports=[3000, 8000])

# 2. MCP detection and verification
print("🎯 Detecting MCP servers...")
mcp_servers = []
for result in scan_results:
    if result.is_open:
        server = hawkeye.detect_mcp_server(result.target, result.port)
        if server:
            mcp_servers.append(server)

# 3. Introspection and capability analysis
print("🔬 Analyzing server capabilities...")
detailed_results = []
for server in mcp_servers:
    capabilities = hawkeye.introspect_server(server)
    if capabilities:
        detailed_results.append(capabilities)

# 4. Security assessment
print("🛡️ Performing security assessment...")
assessment_results = []
for capabilities in detailed_results:
    assessment = hawkeye.assess_security(capabilities)
    assessment_results.append(assessment)

# 5. Report generation
print("📊 Generating reports...")
hawkeye.generate_report(
    assessment_results,
    format="html",
    output_file="security_report.html"
)

print("✅ Security reconnaissance complete!")
```

### Local System Analysis

```python
from hawkeye.detection.base import MCPDetector
from hawkeye.detection.mcp_introspection import MCPIntrospector

# Detect local MCP servers
detector = MCPDetector()
local_servers = detector.detect_local_servers()

# Analyze each server
introspector = MCPIntrospector()
for server in local_servers:
    print(f"\n🔍 Analyzing server: {server.name}")
    
    # Get process information
    process_info = detector.get_process_info(server.process_id)
    
    # Perform introspection
    capabilities = introspector.introspect_server(server, process_info)
    
    if capabilities:
        print(f"  📊 Tools: {capabilities.tool_count}")
        print(f"  📁 Resources: {len(capabilities.resources)}")
        print(f"  ⚠️ Risk Level: {capabilities.highest_risk_level}")
        
        # Show high-risk tools
        high_risk_tools = [t for t in capabilities.tools if t.risk_level == "HIGH"]
        if high_risk_tools:
            print(f"  ⚠️ High-risk tools: {[t.name for t in high_risk_tools]}")
```

## Error Handling

All HawkEye APIs include comprehensive error handling:

```python
from hawkeye.exceptions import (
    HawkEyeError,
    ScanError,
    DetectionError,
    IntrospectionError,
    AssessmentError
)

try:
    results = hawkeye.scan_network("192.168.1.0/24")
except ScanError as e:
    print(f"Scan failed: {e}")
except DetectionError as e:
    print(f"Detection failed: {e}")
except IntrospectionError as e:
    print(f"Introspection failed: {e}")
except HawkEyeError as e:
    print(f"General error: {e}")
```

## Performance Considerations

### Threading and Concurrency
- Configure appropriate thread counts based on system resources
- Use connection pooling for better performance
- Enable caching for repeated operations

### Memory Management
- Monitor memory usage during large network scans
- Use streaming for large datasets
- Clean up resources properly

### Network Courtesy
- Implement rate limiting to avoid network disruption
- Use appropriate timeouts
- Respect target system resources

## Security Considerations

### Ethical Usage
- Only scan networks you own or have permission to test
- Follow responsible disclosure practices
- Maintain audit trails for compliance

### Data Protection
- Secure storage of scan results
- Encrypt sensitive data in transit and at rest
- Follow data retention policies

## Contributing

To contribute to the HawkEye API:

1. Review the existing API structure
2. Follow Python coding conventions
3. Add comprehensive documentation
4. Include unit tests
5. Update API documentation

## License

HawkEye API is released under the MIT License. See LICENSE file for details. 