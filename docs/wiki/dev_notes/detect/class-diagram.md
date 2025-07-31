# Detect Command Class Diagram

## Overview

The Detection Module provides comprehensive MCP server discovery capabilities through multiple detection methods. It implements an abstract base class pattern with concrete detector implementations, orchestrated by a unified detection pipeline with enhanced MCP introspection capabilities.

## Core Architecture

```mermaid
classDiagram
    class MCPDetector {
        <<abstract>>
        +settings: ScanSettings
        +logger: Logger
        +_results: List[DetectionResult]
        +_detection_stats: Dict[str, Any]
        +detect(target_host: str, **kwargs) DetectionResult*
        +get_detection_method() DetectionMethod*
        +detect_multiple(targets: List[str]) List[DetectionResult]
        +get_results() List[DetectionResult]
        +get_statistics() Dict[str, Any]
        +clear_results()
        #_create_mcp_server_info() MCPServerInfo
        #_update_statistics()
    }

    class ProcessEnumerator {
        +mcp_keywords: List[str]
        +node_executables: List[str]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_enumerate_processes() List[ProcessInfo]
        -_analyze_node_process() Optional[MCPServerInfo]
        -_extract_environment_vars() Dict[str, str]
        -_detect_mcp_indicators() bool
        -_analyze_command_line() Dict[str, Any]
    }

    class ConfigFileDiscovery {
        +config_patterns: List[str]
        +mcp_patterns: List[str]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_discover_config_files() List[ConfigFileInfo]
        -_analyze_package_json() Dict[str, Any]
        -_analyze_mcp_config() Dict[str, Any]
        -_extract_dependencies() List[str]
        -_check_mcp_dependencies() bool
    }

    class ProtocolVerifier {
        +supported_transports: List[TransportType]
        +common_ports: List[int]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_verify_http_mcp() Optional[MCPServerInfo]
        -_verify_websocket_mcp() Optional[MCPServerInfo]
        -_perform_mcp_handshake() bool
        -_test_mcp_protocol() Dict[str, Any]
        -_validate_mcp_response() bool
    }

    class TransportDetector {
        +transport_patterns: Dict[TransportType, List[str]]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_detect_http_transport() Optional[TransportType]
        -_detect_websocket_transport() Optional[TransportType]
        -_detect_stdio_transport() Optional[TransportType]
        -_analyze_network_traffic() Dict[str, Any]
        -_check_port_services() List[int]
    }

    class NPXDetector {
        +npx_packages: List[str]
        +package_patterns: List[str]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_discover_npx_packages() List[str]
        -_analyze_package_info() Dict[str, Any]
        -_check_mcp_package() bool
        -_extract_package_metadata() Dict[str, Any]
        -_validate_mcp_server() bool
    }

    class DockerInspector {
        +docker_patterns: List[str]
        +image_patterns: List[str]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_inspect_containers() List[Dict[str, Any]]
        -_analyze_container_config() Dict[str, Any]
        -_check_mcp_indicators() bool
        -_extract_environment() Dict[str, str]
        -_analyze_dockerfile() Optional[Dict[str, Any]]
    }

    class EnvironmentAnalyzer {
        +env_patterns: List[str]
        +system_paths: List[str]
        +detect(target_host: str, **kwargs) DetectionResult
        +get_detection_method() DetectionMethod
        -_analyze_system_environment() Dict[str, Any]
        -_check_path_variables() List[str]
        -_scan_system_directories() List[str]
        -_detect_node_installations() List[str]
        -_analyze_runtime_environment() Dict[str, Any]
    }

    MCPDetector <|-- ProcessEnumerator
    MCPDetector <|-- ConfigFileDiscovery
    MCPDetector <|-- ProtocolVerifier
    MCPDetector <|-- TransportDetector
    MCPDetector <|-- NPXDetector
    MCPDetector <|-- DockerInspector
    MCPDetector <|-- EnvironmentAnalyzer
```

## Detection Pipeline Architecture

```mermaid
classDiagram
    class DetectionPipeline {
        +config: PipelineConfig
        +settings: ScanSettings
        +detectors: Dict[DetectionMethod, MCPDetector]
        +introspector: MCPIntrospector
        +stats: Dict[str, Any]
        +execute_pipeline(target_host: str, **kwargs) PipelineResult
        +execute_detection_batch(targets: List[str]) List[PipelineResult]
        +get_pipeline_statistics() Dict[str, Any]
        -_init_detectors()
        -_init_introspection()
        -_execute_detection_phase() List[DetectionResult]
        -_execute_introspection_phase() List[IntrospectionResult]
        -_merge_results() PipelineResult
        -_filter_results() List[DetectionResult]
        -_validate_results() bool
    }

    class PipelineConfig {
        +enable_process_enumeration: bool
        +enable_config_discovery: bool
        +enable_protocol_verification: bool
        +enable_transport_detection: bool
        +enable_npx_detection: bool
        +enable_docker_inspection: bool
        +enable_environment_analysis: bool
        +enable_mcp_introspection: bool
        +introspection_timeout: float
        +enable_detailed_analysis: bool
        +enable_risk_assessment: bool
        +fail_fast: bool
        +parallel_detection: bool
        +max_concurrent_detections: int
        +min_confidence_threshold: float
        +include_failed_detections: bool
    }

    class PipelineResult {
        +target_host: str
        +pipeline_config: PipelineConfig
        +execution_start_time: float
        +execution_end_time: float
        +total_duration: float
        +detection_results: List[DetectionResult]
        +introspection_results: List[IntrospectionResult]
        +mcp_servers_found: List[MCPServerInfo]
        +success_count: int
        +failure_count: int
        +confidence_scores: List[float]
        +average_confidence: float
        +warnings: List[str]
        +raw_data: Dict[str, Any]
        +to_dict() Dict[str, Any]
        +get_high_confidence_results() List[DetectionResult]
        +get_summary() Dict[str, Any]
    }

    DetectionPipeline --> PipelineConfig : uses
    DetectionPipeline --> PipelineResult : creates
    DetectionPipeline --> MCPDetector : orchestrates
```

## MCP Introspection System

```mermaid
classDiagram
    class MCPIntrospector {
        +config: IntrospectionConfig
        +client_factory: MCPClientFactory
        +risk_assessor: RiskAssessor
        +logger: Logger
        +introspect_server(server_info: MCPServerInfo) IntrospectionResult
        +introspect_multiple_servers() List[IntrospectionResult]
        +get_introspection_statistics() Dict[str, Any]
        -_create_client_config() MCPClientConfig
        -_perform_capability_discovery() MCPCapabilities
        -_perform_tool_discovery() List[MCPTool]
        -_perform_resource_discovery() List[MCPResource]
        -_perform_risk_assessment() List[SecurityRisk]
        -_validate_mcp_server() bool
    }

    class MCPClient {
        +config: MCPClientConfig
        +transport: Transport
        +session: MCPSession
        +connect() bool
        +disconnect()
        +list_tools() List[MCPTool]
        +list_resources() List[MCPResource]
        +get_capabilities() MCPCapabilities
        +call_tool(name: str, arguments: Dict) ToolResult
        +read_resource(uri: str) ResourceResult
        +send_request(method: str, params: Dict) Dict
        -_validate_response() bool
        -_handle_error() MCPError
    }

    class SyncMCPClient {
        +timeout: float
        +max_retries: int
        +connect_sync() bool
        +list_tools_sync() List[MCPTool]
        +list_resources_sync() List[MCPResource]
        +get_capabilities_sync() MCPCapabilities
        +call_tool_sync() ToolResult
        +read_resource_sync() ResourceResult
        -_execute_with_timeout() Any
        -_retry_on_failure() Any
    }

    class IntrospectionConfig {
        +timeout: float
        +enable_detailed_analysis: bool
        +enable_risk_assessment: bool
        +enable_capability_discovery: bool
        +enable_tool_discovery: bool
        +enable_resource_discovery: bool
        +max_connection_attempts: int
        +connection_timeout: float
        +request_timeout: float
        +enable_security_analysis: bool
        +risk_assessment_depth: RiskDepth
    }

    class IntrospectionResult {
        +server_info: MCPServerInfo
        +capabilities: Optional[MCPCapabilities]
        +tools: List[MCPTool]
        +resources: List[MCPResource]
        +security_risks: List[SecurityRisk]
        +connection_successful: bool
        +introspection_duration: float
        +error_message: Optional[str]
        +confidence_score: float
        +raw_responses: Dict[str, Any]
        +to_dict() Dict[str, Any]
        +get_risk_summary() Dict[str, Any]
    }

    MCPIntrospector --> IntrospectionConfig : uses
    MCPIntrospector --> IntrospectionResult : creates
    MCPIntrospector --> MCPClient : uses
    MCPClient <|-- SyncMCPClient
```

## Data Models and Enumerations

```mermaid
classDiagram
    class DetectionResult {
        +target_host: str
        +detection_method: DetectionMethod
        +success: bool
        +confidence: float
        +mcp_server_info: Optional[MCPServerInfo]
        +process_info: Optional[ProcessInfo]
        +config_info: Optional[ConfigFileInfo]
        +error: Optional[str]
        +scan_duration: float
        +timestamp: float
        +additional_info: Dict[str, Any]
        +to_dict() Dict[str, Any]
        +is_high_confidence() bool
        +has_mcp_server() bool
    }

    class MCPServerInfo {
        +host: str
        +port: Optional[int]
        +transport_type: TransportType
        +server_type: MCPServerType
        +process_info: Optional[ProcessInfo]
        +config_info: Optional[ConfigFileInfo]
        +capabilities: List[str]
        +tools: List[str]
        +resources: List[str]
        +version: Optional[str]
        +authentication: Optional[Dict]
        +security_config: Dict[str, Any]
        +docker_info: Optional[Dict]
        +metadata: Dict[str, Any]
        +to_dict() Dict[str, Any]
        +get_endpoint_url() str
        +is_secure() bool
    }

    class ProcessInfo {
        +pid: int
        +name: str
        +cmdline: List[str]
        +cwd: Optional[str]
        +env_vars: Dict[str, str]
        +user: Optional[str]
        +create_time: Optional[float]
        +cpu_percent: Optional[float]
        +memory_percent: Optional[float]
        +is_node_process: bool
        +has_mcp_indicators: bool
        +get_node_version() Optional[str]
        +get_command_args() List[str]
    }

    class ConfigFileInfo {
        +path: Path
        +file_type: str
        +content: Dict[str, Any]
        +mcp_config: Dict[str, Any]
        +dependencies: List[str]
        +scripts: Dict[str, str]
        +has_mcp_dependencies: bool
        +has_mcp_scripts: bool
        +get_mcp_servers() List[Dict]
        +extract_server_config() Dict[str, Any]
    }

    class DetectionMethod {
        <<enumeration>>
        PROCESS_ENUMERATION
        CONFIG_FILE_DISCOVERY
        PROTOCOL_HANDSHAKE
        TRANSPORT_DETECTION
        NPX_PACKAGE_DETECTION
        DOCKER_INSPECTION
        ENVIRONMENT_ANALYSIS
    }

    class TransportType {
        <<enumeration>>
        STDIO
        HTTP
        WEBSOCKET
        UNKNOWN
    }

    class MCPServerType {
        <<enumeration>>
        STANDALONE
        NPX_PACKAGE
        DOCKER_CONTAINER
        EMBEDDED
        UNKNOWN
    }

    DetectionResult --> MCPServerInfo : contains
    DetectionResult --> ProcessInfo : contains
    DetectionResult --> ConfigFileInfo : contains
    DetectionResult --> DetectionMethod : uses
    MCPServerInfo --> TransportType : uses
    MCPServerInfo --> MCPServerType : uses
    MCPServerInfo --> ProcessInfo : contains
    MCPServerInfo --> ConfigFileInfo : contains
```

## Discovery and Analysis Components

```mermaid
classDiagram
    class ToolDiscovery {
        +config: ToolDiscoveryConfig
        +logger: Logger
        +discover_tools(client: MCPClient) List[MCPTool]
        +analyze_tool_capabilities() Dict[str, Any]
        +categorize_tools() Dict[str, List[MCPTool]]
        +assess_tool_risks() List[SecurityRisk]
        -_validate_tool_schema() bool
        -_extract_tool_metadata() Dict[str, Any]
        -_analyze_parameters() Dict[str, Any]
    }

    class ResourceDiscovery {
        +config: ResourceDiscoveryConfig
        +logger: Logger
        +discover_resources(client: MCPClient) List[MCPResource]
        +analyze_resource_types() Dict[str, Any]
        +categorize_resources() Dict[str, List[MCPResource]]
        +assess_resource_risks() List[SecurityRisk]
        -_validate_resource_schema() bool
        -_extract_resource_metadata() Dict[str, Any]
        -_analyze_access_patterns() Dict[str, Any]
    }

    class CapabilityDiscovery {
        +config: CapabilityDiscoveryConfig
        +logger: Logger
        +discover_capabilities(client: MCPClient) MCPCapabilities
        +analyze_capability_matrix() Dict[str, Any]
        +assess_capability_risks() List[SecurityRisk]
        +categorize_capabilities() Dict[str, Any]
        -_validate_capabilities() bool
        -_extract_metadata() Dict[str, Any]
        -_analyze_security_implications() List[SecurityRisk]
    }

    class RiskAssessment {
        +config: RiskAssessmentConfig
        +tool_analyzer: ToolRiskAnalyzer
        +schema_analyzer: SchemaAnalyzer
        +assess_server_risks(introspection_result: IntrospectionResult) List[SecurityRisk]
        +assess_tool_risks() List[SecurityRisk]
        +assess_resource_risks() List[SecurityRisk]
        +categorize_risks() Dict[RiskLevel, List[SecurityRisk]]
        +generate_risk_report() Dict[str, Any]
        -_calculate_risk_score() float
        -_validate_security_config() bool
    }

    ToolDiscovery --> MCPTool : discovers
    ResourceDiscovery --> MCPResource : discovers
    CapabilityDiscovery --> MCPCapabilities : discovers
    RiskAssessment --> SecurityRisk : generates
```

## Error Handling Hierarchy

```mermaid
classDiagram
    class DetectionError {
        <<abstract>>
        +message: str
        +error_code: str
        +timestamp: float
        +context: Dict[str, Any]
        +get_error_details() Dict[str, Any]
    }

    class MCPDetectionError {
        +detector_type: DetectionMethod
        +target_host: str
        +detection_phase: str
    }

    class ProcessDetectionError {
        +process_id: Optional[int]
        +process_name: Optional[str]
        +enumeration_phase: str
    }

    class ConfigDetectionError {
        +config_file_path: Optional[Path]
        +parsing_error: Optional[str]
        +discovery_phase: str
    }

    class ProtocolDetectionError {
        +protocol_type: Optional[str]
        +transport_type: Optional[TransportType]
        +handshake_phase: str
        +network_error: Optional[str]
    }

    class IntrospectionError {
        +client_error: Optional[str]
        +connection_error: Optional[str]
        +timeout_error: Optional[str]
        +protocol_error: Optional[str]
    }

    DetectionError <|-- MCPDetectionError
    DetectionError <|-- ProcessDetectionError
    DetectionError <|-- ConfigDetectionError
    DetectionError <|-- ProtocolDetectionError
    DetectionError <|-- IntrospectionError
```

## Transport Layer Architecture

```mermaid
classDiagram
    class Transport {
        <<abstract>>
        +config: TransportConfig
        +logger: Logger
        +connect() bool*
        +disconnect()*
        +send_message(message: Dict) Dict*
        +receive_message() Dict*
        +is_connected() bool*
        +get_connection_info() Dict[str, Any]*
    }

    class HTTPTransport {
        +base_url: str
        +session: requests.Session
        +headers: Dict[str, str]
        +timeout: float
        +connect() bool
        +disconnect()
        +send_message(message: Dict) Dict
        +receive_message() Dict
        -_build_request() requests.Request
        -_handle_response() Dict
        -_validate_http_response() bool
    }

    class WebSocketTransport {
        +websocket_url: str
        +websocket: WebSocket
        +ping_interval: float
        +connect() bool
        +disconnect()
        +send_message(message: Dict) Dict
        +receive_message() Dict
        -_establish_websocket() bool
        -_handle_websocket_message() Dict
        -_send_ping() bool
    }

    class StdioTransport {
        +process: subprocess.Popen
        +stdin: IO
        +stdout: IO
        +stderr: IO
        +connect() bool
        +disconnect()
        +send_message(message: Dict) Dict
        +receive_message() Dict
        -_start_process() bool
        -_read_from_stdout() str
        -_write_to_stdin() bool
    }

    class TransportFactory {
        +create_transport(transport_type: TransportType, config: Dict) Transport
        +get_supported_transports() List[TransportType]
        +validate_transport_config() bool
        -_create_http_transport() HTTPTransport
        -_create_websocket_transport() WebSocketTransport
        -_create_stdio_transport() StdioTransport
    }

    Transport <|-- HTTPTransport
    Transport <|-- WebSocketTransport
    Transport <|-- StdioTransport
    TransportFactory --> Transport : creates
```

## Detection Statistics and Metrics

```mermaid
classDiagram
    class DetectionMetrics {
        +total_detections: int
        +successful_detections: int
        +failed_detections: int
        +mcp_servers_found: int
        +average_detection_time: float
        +detection_method_stats: Dict[DetectionMethod, Dict]
        +confidence_distribution: List[float]
        +error_distribution: Dict[str, int]
        +update_metrics(result: DetectionResult)
        +get_success_rate() float
        +get_method_performance() Dict[str, Any]
        +generate_report() Dict[str, Any]
    }

    class PipelineMetrics {
        +pipeline_executions: int
        +successful_pipelines: int
        +failed_pipelines: int
        +average_pipeline_duration: float
        +detection_phase_stats: Dict[str, Any]
        +introspection_phase_stats: Dict[str, Any]
        +resource_utilization: Dict[str, float]
        +update_pipeline_metrics(result: PipelineResult)
        +get_phase_performance() Dict[str, Any]
        +generate_performance_report() Dict[str, Any]
    }

    class IntrospectionMetrics {
        +total_introspections: int
        +successful_connections: int
        +failed_connections: int
        +timeout_errors: int
        +protocol_errors: int
        +average_introspection_time: float
        +capability_discovery_stats: Dict[str, Any]
        +tool_discovery_stats: Dict[str, Any]
        +resource_discovery_stats: Dict[str, Any]
        +update_introspection_metrics(result: IntrospectionResult)
        +get_connection_reliability() float
        +generate_introspection_report() Dict[str, Any]
    }

    DetectionMetrics --> DetectionResult : analyzes
    PipelineMetrics --> PipelineResult : analyzes
    IntrospectionMetrics --> IntrospectionResult : analyzes
```

## Key Relationships

### Inheritance Relationships
- **MCPDetector** (Abstract Base Class)
  - **ProcessEnumerator**: Process-based detection
  - **ConfigFileDiscovery**: Configuration file analysis
  - **ProtocolVerifier**: Protocol-level verification
  - **TransportDetector**: Transport layer detection
  - **NPXDetector**: NPX package-based detection
  - **DockerInspector**: Container-based detection
  - **EnvironmentAnalyzer**: System environment analysis

### Composition Relationships
- **DetectionPipeline** orchestrates multiple **MCPDetector** instances
- **DetectionPipeline** integrates **MCPIntrospector** for enhanced analysis
- **MCPIntrospector** uses **MCPClient** for server communication
- **DetectionResult** contains **MCPServerInfo**, **ProcessInfo**, and **ConfigFileInfo**

### Aggregation Relationships
- **PipelineResult** aggregates multiple **DetectionResult** and **IntrospectionResult**
- **MCPServerInfo** aggregates **ProcessInfo** and **ConfigFileInfo**
- **IntrospectionResult** aggregates **MCPCapabilities**, **MCPTool**, and **MCPResource**

## Design Patterns Implemented

### 1. Abstract Base Class (ABC) Pattern
- **MCPDetector** defines the interface for all detection methods
- Ensures consistent behavior across different detection strategies
- Enables polymorphic treatment of detectors in the pipeline

### 2. Strategy Pattern
- Different detection methods implement various strategies
- **DetectionPipeline** can dynamically select and configure detectors
- Enables runtime switching of detection approaches

### 3. Factory Pattern
- **TransportFactory** creates appropriate transport implementations
- **DetectionPipeline** factory method `create_detection_pipeline()`
- Abstracts object creation complexity

### 4. Template Method Pattern
- **MCPDetector** provides template methods for common operations
- Subclasses implement specific detection logic
- Ensures consistent statistics tracking and error handling

### 5. Facade Pattern
- **DetectionPipeline** provides simplified interface to complex detection subsystem
- **MCPIntrospector** facades the introspection subsystem
- Hides complexity from clients

### 6. Observer Pattern (Implicit)
- Detection metrics collection observes detection results
- Pipeline statistics track execution phases
- Enables monitoring and analysis capabilities

## Component Responsibilities

### Detection Components
- **ProcessEnumerator**: Discovers Node.js processes with MCP indicators
- **ConfigFileDiscovery**: Locates and analyzes MCP configuration files
- **ProtocolVerifier**: Validates MCP protocol implementations
- **TransportDetector**: Identifies MCP transport mechanisms
- **NPXDetector**: Discovers NPX-based MCP server packages
- **DockerInspector**: Analyzes containerized MCP deployments
- **EnvironmentAnalyzer**: Examines system environment for MCP indicators

### Orchestration Components
- **DetectionPipeline**: Coordinates multiple detection methods
- **PipelineConfig**: Configures pipeline behavior and detector settings
- **PipelineResult**: Aggregates and presents detection results

### Enhanced Capabilities
- **MCPIntrospector**: Performs deep MCP server analysis
- **MCPClient**: Handles MCP protocol communication
- **ToolDiscovery**: Discovers and analyzes MCP tools
- **ResourceDiscovery**: Discovers and analyzes MCP resources
- **RiskAssessment**: Evaluates security risks and vulnerabilities

### Data Models
- **DetectionResult**: Encapsulates single detection outcome
- **MCPServerInfo**: Comprehensive MCP server information
- **ProcessInfo**: Process-specific information
- **ConfigFileInfo**: Configuration file details
- **IntrospectionResult**: Enhanced introspection findings

This architecture provides a comprehensive, extensible, and maintainable foundation for MCP server detection with both traditional discovery methods and advanced introspection capabilities. 