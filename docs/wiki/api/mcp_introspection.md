# MCP Introspection API Documentation

## Overview

The MCP Introspection API provides comprehensive functionality for discovering, analyzing, and assessing MCP (Model Context Protocol) servers. This API has been completely rewritten in Python, replacing the previous Node.js script generation approach with direct MCP client connections for improved reliability and performance.

## Architecture

The MCP Introspection system is organized into several key components:

- **Core Introspection**: Main entry point and orchestration
- **Transport Layer**: Protocol communication (stdio, SSE, HTTP)
- **Discovery**: Server capability, tool, and resource discovery
- **Risk Analysis**: Security assessment and threat modeling
- **Optimization**: Performance, caching, and scaling

## Core Classes

### MCPIntrospector

The main entry point for MCP server introspection operations.

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector, IntrospectionConfig

# Initialize with default configuration
introspector = MCPIntrospector()

# Initialize with custom configuration
config = IntrospectionConfig(
    timeout=30.0,
    max_concurrent_connections=5,
    enable_caching=True
)
introspector = MCPIntrospector(config)
```

#### Methods

##### `introspect_server(server_info: MCPServerInfo, process_info: ProcessInfo) -> Optional[MCPCapabilities]`

Performs comprehensive introspection of a single MCP server.

**Parameters:**
- `server_info`: Server identification and connection information
- `process_info`: Process details for local servers

**Returns:**
- `MCPCapabilities`: Complete server capabilities or `None` if introspection fails

**Example:**
```python
capabilities = introspector.introspect_server(server_info, process_info)
if capabilities:
    print(f"Found {capabilities.tool_count} tools")
    print(f"Risk level: {capabilities.highest_risk_level}")
```

##### `introspect_multiple_servers(server_list: List[Tuple[MCPServerInfo, ProcessInfo]]) -> List[Optional[MCPCapabilities]]`

Introspects multiple MCP servers concurrently.

**Parameters:**
- `server_list`: List of (server_info, process_info) tuples

**Returns:**
- `List[Optional[MCPCapabilities]]`: Results for each server

##### `introspect_with_risk_analysis(server_info: MCPServerInfo, process_info: ProcessInfo) -> Optional[Dict[str, Any]]`

Performs introspection with comprehensive risk analysis.

**Returns:**
- Dictionary containing capabilities, risk assessment, and security recommendations

##### Discovery Methods

- `discover_tools_only(server_info, process_info) -> List[MCPTool]`
- `discover_resources_only(server_info, process_info) -> List[MCPResource]`
- `discover_capabilities_only(server_info, process_info) -> Dict[str, Any]`

##### Statistics and Monitoring

- `get_transport_statistics() -> Dict[str, Any]`
- `get_discovery_statistics() -> Dict[str, Any]`
- `get_comprehensive_statistics() -> Dict[str, Any]`

## Data Models

### MCPServerInfo

Enhanced server information with introspection data.

```python
@dataclass
class MCPServerInfo(BaseModel):
    server_id: str
    server_url: Optional[str]
    discovery_timestamp: datetime
    tools: List[MCPTool]
    resources: List[MCPResource]
    capabilities: List[MCPCapability]
    security_risks: List[SecurityRisk]
    overall_risk_level: RiskLevel
    metadata: Dict[str, Any]
```

#### Methods
- `get_tool_count() -> int`
- `get_resource_count() -> int`
- `get_capability_count() -> int`
- `get_high_risk_tools() -> List[MCPTool]`

### MCPTool

Represents an MCP tool with security analysis.

```python
class MCPTool(BaseModel):
    name: str
    description: str
    parameters: List[MCPToolParameter]
    input_schema: Dict[str, Any]
    metadata: Dict[str, Any]
    
    # Risk analysis properties
    risk_categories: List[RiskCategory]
    risk_level: RiskLevel
    security_implications: List[str]
```

### MCPResource

Represents an MCP resource.

```python
class MCPResource(BaseModel):
    uri: str
    name: str
    description: str
    mime_type: Optional[str]
    metadata: Dict[str, Any]
    
    # Security properties
    access_level: str
    data_sensitivity: str
```

### MCPCapabilities

Legacy compatibility class for server capabilities.

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

#### Properties
- `tool_count: int`
- `resource_count: int`
- `capability_categories: List[str]`
- `highest_risk_level: str`
- `has_external_access: bool`
- `has_file_access: bool`
- `has_code_execution: bool`

## Transport Layer

### TransportFactory

Creates appropriate transport handlers based on server configuration.

```python
from hawkeye.detection.mcp_introspection.transport.factory import TransportFactory

factory = TransportFactory()
transport = factory.create_transport(server_config)
```

### Transport Types

#### StdioTransportHandler

For local MCP servers using standard I/O communication.

```python
from hawkeye.detection.mcp_introspection.transport.stdio import StdioTransportHandler

transport = StdioTransportHandler(config)
result = transport.connect(server_config)
```

#### SSETransportHandler

For HTTP-based MCP servers using Server-Sent Events.

```python
from hawkeye.detection.mcp_introspection.transport.sse import SSETransportHandler

transport = SSETransportHandler(config)
result = transport.connect(server_config)
```

#### HTTPTransportHandler

For production MCP servers using HTTP transport.

```python
from hawkeye.detection.mcp_introspection.transport.http import HTTPTransportHandler

transport = HTTPTransportHandler(config)
result = transport.connect(server_config)
```

## Discovery Components

### ToolDiscovery

Discovers available tools from MCP servers.

```python
from hawkeye.detection.mcp_introspection.discovery.tools import ToolDiscovery

discovery = ToolDiscovery(config)
tools = discovery.discover_tools(server_config)
```

### ResourceDiscovery

Discovers available resources from MCP servers.

```python
from hawkeye.detection.mcp_introspection.discovery.resources import ResourceDiscovery

discovery = ResourceDiscovery(config)
resources = discovery.discover_resources(server_config)
```

### CapabilityDiscovery

Discovers server capabilities via the initialize protocol.

```python
from hawkeye.detection.mcp_introspection.discovery.capabilities import CapabilityDiscovery

discovery = CapabilityDiscovery(config)
capabilities = discovery.discover_capabilities(server_config)
```

### ServerInfoAggregator

Aggregates discovery results into comprehensive server information.

```python
from hawkeye.detection.mcp_introspection.discovery.aggregator import ServerInfoAggregator

aggregator = ServerInfoAggregator()
server_info = aggregator.aggregate_server_info(tools, resources, capabilities)
```

## Risk Analysis

### ToolRiskAnalyzer

Analyzes tools for security risks using pattern matching and schema analysis.

```python
from hawkeye.detection.mcp_introspection.risk.tool_analyzer import ToolRiskAnalyzer

analyzer = ToolRiskAnalyzer()
risk_assessment = analyzer.analyze_tool(tool)
```

#### Features
- 521+ comprehensive risk patterns
- CWE (Common Weakness Enumeration) mapping
- Parameter validation analysis
- Confidence scoring

### ThreatModelAnalyzer

Performs capability-based threat modeling.

```python
from hawkeye.detection.mcp_introspection.risk.threat_model import ThreatModelAnalyzer

threat_analyzer = ThreatModelAnalyzer()
threats = threat_analyzer.analyze_threats(server_info)
```

### RiskCategorizer

Categorizes risks into standardized categories.

```python
from hawkeye.detection.mcp_introspection.risk.categorizer import RiskCategorizer

categorizer = RiskCategorizer()
categories = categorizer.categorize_risks(risk_list)
```

#### Risk Categories
- `FILE_SYSTEM`: File system operations
- `NETWORK_ACCESS`: Network communications
- `CODE_EXECUTION`: Code execution capabilities
- `DATA_ACCESS`: Data access and manipulation
- `SYSTEM_MODIFICATION`: System configuration changes
- `AUTHENTICATION`: Authentication mechanisms
- `ENCRYPTION`: Cryptographic operations
- `EXTERNAL_API`: External service integrations
- `DATABASE`: Database operations
- `CLOUD_SERVICES`: Cloud platform integrations

### RiskScorer

Calculates composite risk scores using multiple methodologies.

```python
from hawkeye.detection.mcp_introspection.risk.scoring import RiskScorer

scorer = RiskScorer()
score = scorer.calculate_composite_score(risks)
```

#### Scoring Methods
- CVSS-like scoring
- Weighted average scoring  
- Maximum risk scoring
- Custom policy-based scoring

### RiskReporter

Generates comprehensive risk assessment reports.

```python
from hawkeye.detection.mcp_introspection.risk.reporter import RiskReporter

reporter = RiskReporter()
report = reporter.generate_report(server_info, format='html')
```

#### Supported Formats
- JSON: Machine-readable format
- HTML: Interactive web reports
- Markdown: Documentation-friendly format
- CSV: Spreadsheet-compatible format

## Optimization

### Connection Pooling

Manages connection pools for improved performance.

```python
from hawkeye.detection.mcp_introspection.optimization.pooling import ConnectionPoolManager

pool_manager = ConnectionPoolManager(max_connections=10)
```

### Caching

Provides result caching with configurable TTL.

```python
from hawkeye.detection.mcp_introspection.optimization.caching import ResultCache

cache = ResultCache(ttl_seconds=300)
cached_result = cache.get(server_id)
```

### Memory Management

Optimizes memory usage for large-scale operations.

```python
from hawkeye.detection.mcp_introspection.optimization.memory import MemoryOptimizer

optimizer = MemoryOptimizer()
optimizer.cleanup_unused_resources()
```

### Scaling

Provides scaling optimizations for concurrent operations.

```python
from hawkeye.detection.mcp_introspection.optimization.scaling import ScalingManager

scaling = ScalingManager(max_concurrent=20)
```

## Configuration

### IntrospectionConfig

Main configuration class for the introspection system.

```python
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

config = IntrospectionConfig(
    # Connection settings
    timeout=30.0,
    max_retries=3,
    retry_delay=1.0,
    
    # Concurrency settings
    max_concurrent_connections=5,
    connection_pool_size=10,
    
    # Caching settings
    enable_caching=True,
    cache_ttl=300,
    
    # Risk analysis settings
    enable_risk_analysis=True,
    risk_threshold='medium',
    
    # Performance settings
    enable_optimization=True,
    memory_limit_mb=100
)
```

## Error Handling

The MCP Introspection API uses structured exception handling:

### Exception Hierarchy

```python
MCPIntrospectionError
├── TransportError
│   ├── ConnectionError
│   ├── TimeoutError
│   └── ProtocolError
├── DiscoveryError
│   ├── ToolDiscoveryError
│   ├── ResourceDiscoveryError
│   └── CapabilityDiscoveryError
└── RiskAnalysisError
    ├── ThreatModelError
    └── ScoringError
```

### Error Handling Example

```python
try:
    capabilities = introspector.introspect_server(server_info, process_info)
except TransportError as e:
    logger.error(f"Transport failed: {e.message}")
except DiscoveryError as e:
    logger.warning(f"Discovery incomplete: {e.message}")
except MCPIntrospectionError as e:
    logger.error(f"Introspection failed: {e.message}")
```

## Performance Considerations

### Timeout Management
- Default timeout: 30 seconds
- Configurable per-operation timeouts
- Connection pooling with cleanup

### Memory Usage
- Automatic resource cleanup
- Configurable memory limits
- Result streaming for large operations

### Concurrency
- Configurable concurrent connections
- Thread pool management
- Rate limiting support

## Security Considerations

### Safe Operations
- Non-intrusive scanning methodology
- Read-only discovery operations
- Sandboxed execution environment

### Risk Assessment
- Comprehensive threat modeling
- 521+ security risk patterns
- CWE mapping and CVSS-like scoring

### Data Protection
- Sensitive data filtering
- Audit trail generation
- Secure communication protocols

## Migration from Node.js

The new Python-based system provides backward compatibility with the previous Node.js approach:

### Legacy Compatibility
- `MCPCapabilities` class maintains original interface
- Tool and Resource objects support legacy properties
- Existing code continues to work without changes

### Migration Benefits
- Improved reliability and error handling
- Better performance with connection pooling
- Enhanced security analysis capabilities
- Simplified deployment (no Node.js dependency)

## Examples

### Basic Introspection

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector

introspector = MCPIntrospector()
capabilities = introspector.introspect_server(server_info, process_info)

if capabilities:
    print(f"Server: {capabilities.server_name}")
    print(f"Tools: {capabilities.tool_count}")
    print(f"Resources: {capabilities.resource_count}")
    print(f"Risk Level: {capabilities.highest_risk_level}")
```

### Risk Analysis

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector

introspector = MCPIntrospector()
analysis = introspector.introspect_with_risk_analysis(server_info, process_info)

if analysis:
    print(f"Overall Risk: {analysis['risk_summary']['overall_risk']}")
    print(f"High Risk Tools: {len(analysis['high_risk_tools'])}")
    print(f"Security Recommendations: {len(analysis['recommendations'])}")
```

### Batch Processing

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector

introspector = MCPIntrospector()
server_list = [(server_info1, process_info1), (server_info2, process_info2)]
results = introspector.introspect_multiple_servers(server_list)

for i, capabilities in enumerate(results):
    if capabilities:
        print(f"Server {i+1}: {capabilities.tool_count} tools")
```

### Custom Transport

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector

introspector = MCPIntrospector()
capabilities = introspector.introspect_with_specific_transport(
    server_info, 
    process_info, 
    force_transport='stdio'
)
```

## API Reference Summary

### Core Classes
- `MCPIntrospector`: Main introspection interface
- `MCPServerInfo`: Enhanced server information
- `MCPCapabilities`: Legacy compatibility class
- `IntrospectionConfig`: Configuration management

### Transport Layer
- `TransportFactory`: Transport creation
- `StdioTransportHandler`: Local server communication
- `SSETransportHandler`: HTTP/SSE communication
- `HTTPTransportHandler`: HTTP communication

### Discovery Components
- `ToolDiscovery`: Tool discovery
- `ResourceDiscovery`: Resource discovery
- `CapabilityDiscovery`: Capability discovery
- `ServerInfoAggregator`: Result aggregation

### Risk Analysis
- `ToolRiskAnalyzer`: Tool security analysis
- `ThreatModelAnalyzer`: Threat modeling
- `RiskCategorizer`: Risk categorization
- `RiskScorer`: Risk scoring
- `RiskReporter`: Report generation

### Optimization
- `ConnectionPoolManager`: Connection pooling
- `ResultCache`: Result caching
- `MemoryOptimizer`: Memory management
- `ScalingManager`: Scaling optimization

This API provides comprehensive MCP server introspection capabilities with enhanced security analysis, performance optimization, and reliable Python-based implementation.