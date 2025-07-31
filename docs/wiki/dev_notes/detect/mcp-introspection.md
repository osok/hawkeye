# MCP Introspection System Documentation

## Overview

The MCP Introspection System provides comprehensive analysis and discovery capabilities for Model Context Protocol (MCP) servers. This system enables dynamic discovery, capability assessment, and security analysis of MCP servers through direct protocol communication, replacing the previous Node.js script-based approach with native Python implementation.

## System Architecture

### Core Components

The MCP introspection system consists of five main architectural layers:

1. **Introspection Orchestrator** - Central coordination and caching
2. **Transport Layer** - Protocol-agnostic communication abstraction
3. **Discovery Engine** - Multi-faceted server analysis
4. **MCP Client** - Direct MCP protocol implementation
5. **Data Models** - Comprehensive information representation

### High-Level Architecture

```mermaid
classDiagram
    class MCPIntrospection {
        +IntrospectionConfig config
        +TransportFactory transport_factory
        +ServerInfoAggregator aggregator
        +SyncMCPClient mcp_client
        +Dict introspection_cache
        
        +introspect_server(server_config) IntrospectionResult
        +batch_introspect(configs) List[IntrospectionResult]
        +get_cached_result(server_id) IntrospectionResult
        +clear_cache()
    }
    
    class TransportFactory {
        +Dict handlers_registry
        
        +create_handler(transport_type) BaseTransportHandler
        +auto_detect_transport(config) TransportType
        +create_from_config(config) BaseTransportHandler
    }
    
    class ServerInfoAggregator {
        +ToolDiscovery tool_discovery
        +ResourceDiscovery resource_discovery
        +CapabilityAssessment capability_assessment
        
        +aggregate_server_info(server_config) MCPServerInfo
        +sequential_discovery(server_config) Dict[DiscoveryResult]
        +aggregate_results(discovery_results) MCPServerInfo
    }
    
    class SyncMCPClient {
        +MCPClientConfig config
        +Dict connected_servers
        
        +connect_to_server(server_id, config) bool
        +list_tools(server_id) List[Tool]
        +list_resources(server_id) List[Resource]
        +introspect_server(server_config) IntrospectionResult
    }
    
    MCPIntrospection --> TransportFactory
    MCPIntrospection --> ServerInfoAggregator  
    MCPIntrospection --> SyncMCPClient
    ServerInfoAggregator --> ToolDiscovery
    ServerInfoAggregator --> ResourceDiscovery
    ServerInfoAggregator --> CapabilityAssessment
```

## Transport Layer Architecture

### Transport Abstraction

The transport layer provides a unified interface for communicating with MCP servers across different protocols while handling connection management, retry logic, and error recovery.

```mermaid
classDiagram
    class BaseTransportHandler {
        <<abstract>>
        +float timeout
        +int max_retries
        +float retry_delay
        +Logger logger
        +ClientSession session
        +bool connected
        
        +create_session(**kwargs)* ClientSession
        +cleanup_session()*
        +connect(**kwargs) ClientSession
        +disconnect()
        +send_request(request) Any
        +is_healthy() bool
    }
    
    class StdioTransportHandler {
        +Popen process
        +StdioServerParameters server_params
        
        +create_session(**kwargs) ClientSession
        +cleanup_session()
        +terminate_process()
        +get_process_info() Dict
    }
    
    class StreamableHTTPTransportHandler {
        +str base_url
        +Dict headers
        +Dict auth
        +TCPConnector session_connector
        +bool streaming_enabled
        
        +create_session(**kwargs) ClientSession
        +cleanup_session()
        +prepare_auth_headers(auth) Dict
        +validate_url(url) bool
        +test_connectivity() bool
    }
    
    class SSETransportHandler {
        +str sse_url
        +Dict headers
        +Dict auth
        +ClientSession aiohttp_session
        +EventSource event_source
        
        +create_session(**kwargs) ClientSession
        +cleanup_session()
        +setup_sse_connection() EventSource
        +handle_sse_events()
        +process_server_sent_event(event) Any
    }
    
    class TransportFactory {
        +Dict handlers_registry
        
        +create_handler(transport_type) BaseTransportHandler
        +auto_detect_transport(config) TransportType
        +register_handler(transport_type, handler_class)
    }
    
    BaseTransportHandler <|-- StdioTransportHandler
    BaseTransportHandler <|-- StreamableHTTPTransportHandler
    BaseTransportHandler <|-- SSETransportHandler
    TransportFactory --> BaseTransportHandler
```

### Transport-Specific Implementations

#### Stdio Transport
- **Purpose**: Communication with local MCP servers via standard input/output
- **Use Case**: Development, testing, and local server introspection
- **Key Features**:
  - Process management and lifecycle control
  - Command-line argument and environment variable handling
  - Graceful process termination with signal handling
  - Process health monitoring and restart capabilities

#### HTTP Transport
- **Purpose**: Production server communication via RESTful HTTP APIs
- **Use Case**: Production deployments and cloud-hosted MCP servers
- **Key Features**:
  - Connection pooling and keep-alive management
  - Authentication header management (Bearer, API Key)
  - SSL/TLS verification and proxy support
  - Request/response streaming for large payloads

#### SSE Transport
- **Purpose**: Real-time communication via Server-Sent Events
- **Use Case**: Streaming updates and real-time server monitoring
- **Key Features**:
  - Persistent event stream management
  - Automatic reconnection with exponential backoff
  - Event filtering and message routing
  - Connection health monitoring

## Discovery Engine Architecture

### Multi-Faceted Discovery System

The discovery engine employs a modular approach to comprehensively analyze MCP servers across multiple dimensions.

```mermaid
classDiagram
    class ToolDiscovery {
        +ToolDiscoveryConfig config
        +ErrorHandler error_handler
        +Dict discovery_cache
        
        +discover_tools(server_config) DiscoveryResult
        +list_tools_with_retry(server_config) List[Tool]
        +convert_tool(tool_data) MCPTool
        +assess_tool_risks(tool) List[SecurityRisk]
        +analyze_tool_parameters(tool) ParameterAnalysis
    }
    
    class ResourceDiscovery {
        +ResourceDiscoveryConfig config
        +ErrorHandler error_handler
        +Dict discovery_cache
        
        +discover_resources(server_config) DiscoveryResult
        +list_resources_with_retry(server_config) List[Resource]
        +convert_resource(resource_data) MCPResource
        +assess_resource_risks(resource) List[SecurityRisk]
        +analyze_resource_schemas(resource) SchemaAnalysis
    }
    
    class CapabilityAssessment {
        +CapabilityAssessmentConfig config
        +ErrorHandler error_handler
        +Dict capability_cache
        
        +assess_capabilities(server_config) DiscoveryResult
        +perform_initialize_handshake(server_config) MCPCapabilities
        +detect_experimental_features(capabilities) Dict
        +assess_security_implications(capabilities) List[SecurityRisk]
        +analyze_protocol_compliance(server_config) ComplianceResult
    }
    
    class ServerInfoAggregator {
        +AggregatorConfig config
        +ToolDiscovery tool_discovery
        +ResourceDiscovery resource_discovery
        +CapabilityAssessment capability_assessment
        
        +aggregate_server_info(server_config) MCPServerInfo
        +sequential_discovery(server_config) Dict[DiscoveryResult]
        +parallel_discovery(server_config) Dict[DiscoveryResult]
        +aggregate_results(results) MCPServerInfo
        +calculate_overall_risk(results) RiskLevel
    }
    
    ServerInfoAggregator --> ToolDiscovery
    ServerInfoAggregator --> ResourceDiscovery
    ServerInfoAggregator --> CapabilityAssessment
```

### Discovery Process Flow

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Aggregator as ServerInfoAggregator
    participant ToolDisc as ToolDiscovery
    participant ResDisc as ResourceDiscovery
    participant CapAssess as CapabilityAssessment
    participant Transport as TransportHandler
    participant Server as MCP Server
    
    Client->>Aggregator: aggregate_server_info(server_config)
    
    Note over Aggregator: Sequential Discovery Phase
    
    Aggregator->>ToolDisc: discover_tools(server_config)
    ToolDisc->>Transport: create_session()
    Transport->>Server: tools/list request
    Server-->>Transport: tools/list response
    Transport-->>ToolDisc: tools data
    ToolDisc->>ToolDisc: assess_tool_risks()
    ToolDisc-->>Aggregator: DiscoveryResult[tools]
    
    Aggregator->>ResDisc: discover_resources(server_config)
    ResDisc->>Transport: send_request(resources/list)
    Transport->>Server: resources/list request
    Server-->>Transport: resources/list response
    Transport-->>ResDisc: resources data
    ResDisc->>ResDisc: assess_resource_risks()
    ResDisc-->>Aggregator: DiscoveryResult[resources]
    
    Aggregator->>CapAssess: assess_capabilities(server_config)
    CapAssess->>Transport: send_request(initialize)
    Transport->>Server: initialize handshake
    Server-->>Transport: initialize response
    Transport-->>CapAssess: capabilities data
    CapAssess->>CapAssess: assess_security_implications()
    CapAssess-->>Aggregator: DiscoveryResult[capabilities]
    
    Note over Aggregator: Result Aggregation Phase
    
    Aggregator->>Aggregator: aggregate_results(discovery_results)
    Aggregator->>Aggregator: calculate_overall_risk()
    Aggregator-->>Client: MCPServerInfo
```

## Data Models and Information Architecture

### Core Data Structures

The introspection system uses comprehensive data models to represent all aspects of MCP server information and analysis results.

```mermaid
classDiagram
    class MCPServerInfo {
        +str server_id
        +str endpoint_url
        +str host
        +int port
        +TransportType transport_type
        +str version
        +List[MCPCapability] capabilities
        +List[MCPTool] tools
        +List[MCPResource] resources
        +Dict security_config
        +str server_type
        +bool has_authentication
        +bool is_secure
        +RiskLevel overall_risk_level
        +List[SecurityRisk] security_risks
        +datetime discovery_time
        +Dict metadata
    }
    
    class MCPTool {
        +str name
        +str description
        +Dict input_schema
        +List[MCPToolParameter] parameters
        +List[str] dangerous_patterns
        +RiskLevel risk_level
        +List[SecurityRisk] security_risks
        +Dict metadata
        
        +has_dangerous_patterns() bool
        +get_parameter_count() int
        +is_high_risk() bool
    }
    
    class MCPResource {
        +str uri
        +str name
        +str description
        +str mime_type
        +Dict metadata
        +List[SecurityRisk] security_risks
        +RiskLevel risk_level
        
        +is_sensitive_resource() bool
        +get_resource_type() str
    }
    
    class MCPCapabilities {
        +bool supports_tools
        +bool supports_resources
        +bool supports_prompts
        +bool supports_logging
        +bool supports_completion
        +bool supports_sampling
        +Dict experimental_capabilities
        +Dict custom_capabilities
        +str protocol_version
        +str server_version
        
        +get_capability_count() int
        +has_dangerous_capabilities() bool
        +has_capability(capability) bool
    }
    
    class SecurityRisk {
        +str risk_id
        +RiskLevel severity
        +RiskCategory category
        +str title
        +str description
        +str affected_component
        +List[str] attack_vectors
        +List[str] mitigations
        +float cvss_score
        +Dict metadata
    }
    
    class IntrospectionResult {
        +MCPServerInfo server_info
        +bool success
        +str error_message
        +float execution_time
        +Dict performance_metrics
        +datetime timestamp
        +Dict metadata
    }
    
    MCPServerInfo --> MCPTool
    MCPServerInfo --> MCPResource
    MCPServerInfo --> MCPCapabilities
    MCPServerInfo --> SecurityRisk
    IntrospectionResult --> MCPServerInfo
```

## Protocol Implementation

### MCP Client Architecture

The system includes both asynchronous and synchronous MCP client implementations to handle different use cases and integration requirements.

```mermaid
classDiagram
    class MCPClient {
        +MCPClientConfig config
        +Dict connected_servers
        +Logger logger
        
        +connect_to_server(server_id, config) bool
        +disconnect_from_server(server_id) bool
        +list_tools(server_id) List[Tool]
        +list_resources(server_id) List[Resource]
        +call_tool(tool_name, params) Any
        +get_resource(uri) Resource
        +introspect_server(server_config) IntrospectionResult
    }
    
    class SyncMCPClient {
        +MCPClientConfig config
        +Dict connected_servers
        
        +connect_to_server(server_id, config) bool
        +list_tools_from_server(server_id) List[Tool]
        +convert_tool_to_internal(tool_data) MCPTool
        +assess_tool_security_risks(tool) List[SecurityRisk]
        +calculate_risk_level(risks, tools, resources) RiskLevel
    }
    
    class MCPClientConfig {
        +float timeout
        +int max_retries
        +bool enable_tool_testing
        +bool enable_resource_enumeration
        +bool enable_capability_detection
        +Dict transport_config
        +Dict auth_config
    }
    
    MCPClient --> MCPClientConfig
    SyncMCPClient --> MCPClientConfig
    SyncMCPClient --|> MCPClient : inherits_from
```

### Protocol Communication Flow

```mermaid
sequenceDiagram
    participant Introspector as MCPIntrospection
    participant Client as SyncMCPClient
    participant Transport as BaseTransportHandler
    participant Server as MCP Server
    
    Note over Introspector, Server: Server Introspection Flow
    
    Introspector->>Client: introspect_server(server_config)
    Client->>Transport: create_session(transport_config)
    Transport->>Server: Connection establishment
    Server-->>Transport: Connection acknowledged
    Transport-->>Client: ClientSession created
    
    Note over Client, Server: MCP Initialize Handshake
    
    Client->>Server: initialize request
    Server-->>Client: initialize response (capabilities)
    
    Note over Client, Server: Tool Discovery
    
    Client->>Server: tools/list request
    Server-->>Client: tools/list response
    Client->>Client: convert_tool_to_internal()
    Client->>Client: assess_tool_security_risks()
    
    Note over Client, Server: Resource Discovery
    
    Client->>Server: resources/list request
    Server-->>Client: resources/list response
    Client->>Client: convert_resource_to_internal()
    Client->>Client: assess_resource_security_risks()
    
    Note over Client: Risk Assessment
    
    Client->>Client: calculate_risk_level()
    Client->>Client: create_server_info()
    Client-->>Introspector: IntrospectionResult
```

## Security and Risk Assessment

### Security Analysis Framework

The introspection system includes comprehensive security analysis capabilities to identify potential risks and vulnerabilities in MCP servers.

#### Risk Categories
- **File System Access**: Tools that can read, write, or execute files
- **Network Access**: Tools that can make external network requests
- **Code Execution**: Tools that can execute arbitrary code or commands
- **Data Access**: Tools that can access sensitive data or databases
- **System Modification**: Tools that can modify system configuration
- **Authentication**: Tools that handle authentication or credentials
- **External APIs**: Tools that interact with external services

#### Risk Assessment Process

```mermaid
flowchart TD
    A[Tool/Resource Discovery] --> B[Pattern Analysis]
    B --> C{Dangerous Patterns<br/>Detected?}
    C -->|Yes| D[High Risk Classification]
    C -->|No| E[Parameter Analysis]
    E --> F{Requires Sensitive<br/>Parameters?}
    F -->|Yes| G[Medium Risk Classification]
    F -->|No| H[Capability Analysis]
    H --> I{Has Dangerous<br/>Capabilities?}
    I -->|Yes| J[Medium Risk Classification]
    I -->|No| K[Low Risk Classification]
    
    D --> L[Generate Security Risks]
    G --> L
    J --> L
    K --> L
    L --> M[Calculate CVSS Score]
    M --> N[Assign Overall Risk Level]
```

### Security Risk Data Model

```mermaid
classDiagram
    class SecurityRisk {
        +str risk_id
        +RiskLevel severity
        +RiskCategory category
        +str title
        +str description
        +str affected_component
        +List[str] attack_vectors
        +List[str] mitigations
        +float cvss_score
        +Dict metadata
        
        +calculate_cvss_score() float
        +get_mitigation_priority() int
        +is_exploitable() bool
    }
    
    class RiskLevel {
        <<enumeration>>
        CRITICAL
        HIGH
        MEDIUM
        LOW
        MINIMAL
        UNKNOWN
    }
    
    class RiskCategory {
        <<enumeration>>
        FILE_SYSTEM
        NETWORK_ACCESS
        CODE_EXECUTION
        DATA_ACCESS
        SYSTEM_MODIFICATION
        AUTHENTICATION
        ENCRYPTION
        EXTERNAL_API
        DATABASE
        CLOUD_SERVICES
        UNKNOWN
    }
    
    SecurityRisk --> RiskLevel
    SecurityRisk --> RiskCategory
```

## Performance and Optimization

### Caching Strategy

The introspection system implements multi-layer caching to optimize performance and reduce redundant operations:

1. **Result Caching**: Complete introspection results with TTL
2. **Discovery Caching**: Individual discovery results (tools, resources, capabilities)
3. **Transport Caching**: Connection sessions and authentication tokens

### Optimization Features

- **Connection Pooling**: Reuse transport connections across multiple operations
- **Batch Processing**: Support for introspecting multiple servers simultaneously
- **Retry Logic**: Exponential backoff with circuit breaker patterns
- **Memory Management**: Automatic cache cleanup and memory optimization
- **Performance Metrics**: Detailed timing and resource usage tracking

## Configuration and Extensibility

### Configuration Hierarchy

```mermaid
classDiagram
    class IntrospectionConfig {
        +float timeout
        +int max_concurrent_servers
        +bool enable_detailed_analysis
        +bool enable_risk_assessment
        +AggregatorConfig aggregator_config
        +int max_retries
        +bool enable_caching
        +bool enable_fallback
    }
    
    class AggregatorConfig {
        +ToolDiscoveryConfig tool_config
        +ResourceDiscoveryConfig resource_config
        +CapabilityAssessmentConfig capability_config
        +float timeout
        +bool enable_parallel_discovery
        +int max_discovery_workers
    }
    
    class ToolDiscoveryConfig {
        +float timeout
        +int max_retries
        +float retry_delay
        +bool enable_schema_analysis
        +bool enable_risk_assessment
        +Set[str] dangerous_patterns
    }
    
    IntrospectionConfig --> AggregatorConfig
    AggregatorConfig --> ToolDiscoveryConfig
```

## Error Handling and Resilience

### Error Handling Strategy

The system implements comprehensive error handling at multiple levels:

1. **Transport Level**: Connection failures, timeouts, protocol errors
2. **Discovery Level**: Malformed responses, missing data, analysis failures
3. **Client Level**: Authentication failures, permission errors, server unavailability
4. **System Level**: Resource exhaustion, configuration errors, unexpected exceptions

### Fallback Mechanisms

- **Transport Fallback**: Automatic transport type detection and switching
- **Discovery Fallback**: Graceful degradation when specific discovery types fail
- **Analysis Fallback**: Default risk assessments when detailed analysis fails
- **Configuration Fallback**: Default configurations when custom configs are invalid

## Integration Points

### Integration with Detection Pipeline

The MCP introspection system integrates seamlessly with the broader detection pipeline:

1. **MCPDetector Integration**: Provides detailed server analysis for detected servers
2. **Risk Assessment Integration**: Feeds into overall security risk calculations
3. **Reporting Integration**: Comprehensive introspection data in reports
4. **Caching Integration**: Shared caching infrastructure with other detection components

### Extension Points

The system provides several extension points for customization:

1. **Custom Transport Handlers**: Support for new transport protocols
2. **Custom Discovery Modules**: Additional server analysis capabilities
3. **Custom Risk Assessment**: Specialized security analysis rules
4. **Custom Data Models**: Extended server information representation

## Usage Examples

### Basic Server Introspection

```python
from hawkeye.detection.mcp_introspection import MCPIntrospection
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType

# Configure introspection
config = IntrospectionConfig(
    timeout=60.0,
    enable_detailed_analysis=True,
    enable_risk_assessment=True
)

# Initialize introspection system
introspector = MCPIntrospection(config)

# Configure server
server_config = MCPServerConfig(
    server_id="example_server",
    transport_type=TransportType.STDIO,
    command="node",
    args=["server.js"]
)

# Perform introspection
result = introspector.introspect_server(server_config)

# Access results
if result.success:
    server_info = result.server_info
    print(f"Server: {server_info.server_id}")
    print(f"Tools: {len(server_info.tools)}")
    print(f"Risk Level: {server_info.overall_risk_level}")
```

### Batch Server Analysis

```python
# Configure multiple servers
servers = [
    MCPServerConfig(server_id="server1", transport_type=TransportType.STDIO, command="node", args=["server1.js"]),
    MCPServerConfig(server_id="server2", transport_type=TransportType.HTTP, base_url="http://localhost:3000"),
    MCPServerConfig(server_id="server3", transport_type=TransportType.SSE, sse_url="http://localhost:3001/events")
]

# Perform batch introspection
results = introspector.batch_introspect(servers)

# Analyze results
for result in results:
    if result.success:
        print(f"Server {result.server_info.server_id}: {result.server_info.overall_risk_level}")
    else:
        print(f"Failed to analyze server: {result.error_message}")
```

## Future Enhancements

### Planned Improvements

1. **Real-time Monitoring**: Continuous server health and capability monitoring
2. **Advanced Analytics**: Machine learning-based risk prediction and anomaly detection
3. **Distributed Introspection**: Support for introspecting server clusters and load-balanced deployments
4. **Compliance Frameworks**: Integration with security compliance standards (SOC2, ISO27001)
5. **Performance Profiling**: Detailed performance analysis of MCP server implementations

### Extension Roadmap

1. **WebSocket Transport**: Support for WebSocket-based MCP communication
2. **gRPC Transport**: Support for gRPC-based MCP implementations
3. **Cloud Provider Integration**: Native support for cloud-hosted MCP services
4. **Container Runtime Integration**: Direct integration with container orchestration platforms
5. **API Gateway Integration**: Support for API gateway-mediated MCP services 