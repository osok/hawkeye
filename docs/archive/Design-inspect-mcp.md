# MCP Introspection System Design

## Overview

This document outlines the design for implementing a Python-based MCP (Model Context Protocol) introspection system for HawkEye. The system will replace the current Node.js script generation approach with direct Python MCP client connections to dynamically discover and analyze MCP server capabilities.

## Current State

The existing `src/hawkeye/detection/mcp_introspection.py` module uses a Node.js script generation approach:
- Generates temporary Node.js scripts to query MCP servers
- Requires `@modelcontextprotocol/sdk` dependency
- Complex subprocess management
- Limited error handling and reliability

## Proposed Solution

Replace the Node.js approach with the official Python MCP SDK (`mcp` package) for direct server communication.

## Architecture

### Core Components

1. **MCPIntrospector Class** (Enhanced)
   - Direct Python MCP client integration
   - Support for multiple transport types (stdio, SSE, HTTP)
   - Robust error handling and timeout management
   - Capability analysis and risk assessment

2. **Transport Handlers**
   - `StdioTransportHandler`: For local server processes
   - `SSETransportHandler`: For HTTP-based servers
   - `StreamableHTTPTransportHandler`: For production deployments

3. **Capability Analyzer**
   - Dynamic tool discovery via `tools/list`
   - Resource discovery via `resources/list`
   - Server capability assessment via `initialize`
   - Risk level calculation based on discovered capabilities

4. **Result Caching**
   - Cache introspection results to avoid repeated queries
   - Configurable cache TTL
   - Persistent cache storage option

### Data Models

```python
@dataclass
class MCPServerInfo:
    """Enhanced server information with introspection data"""
    name: str
    command: str
    args: List[str]
    transport_type: str  # 'stdio', 'sse', 'http'
    capabilities: MCPCapabilities
    tools: List[MCPTool]
    resources: List[MCPResource]
    risk_level: str
    introspection_timestamp: datetime
    error_message: Optional[str] = None

@dataclass
class MCPCapabilities:
    """Server capabilities discovered via initialize"""
    supports_tools: bool
    supports_resources: bool
    supports_prompts: bool
    supports_logging: bool
    supports_completion: bool
    experimental_capabilities: Dict[str, Any]
    
@dataclass
class MCPTool:
    """Tool information from tools/list"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    risk_categories: List[str]  # e.g., ['file_system', 'network_access']
    
@dataclass
class MCPResource:
    """Resource information from resources/list"""
    uri: str
    name: str
    description: str
    mime_type: Optional[str]
    risk_categories: List[str]
```

## Implementation Plan

### Phase 1: Core Infrastructure (5 days)

1. **Install and Configure MCP SDK**
   ```bash
   pip install mcp
   ```

2. **Create Transport Handlers**
   - Implement `BaseTransportHandler` abstract class
   - Create `StdioTransportHandler` for local servers
   - Add connection pooling and timeout management

3. **Update MCPIntrospector Class**
   - Replace Node.js script generation with direct MCP client calls
   - Implement async/await pattern for better performance
   - Add comprehensive error handling

### Phase 2: Discovery Implementation (7 days)

1. **Tool Discovery**
   ```python
   async def discover_tools(self, session: ClientSession) -> List[MCPTool]:
       """Discover available tools via tools/list"""
       try:
           response = await session.list_tools()
           return [self._analyze_tool(tool) for tool in response.tools]
       except Exception as e:
           self.logger.error(f"Tool discovery failed: {e}")
           return []
   ```

2. **Resource Discovery**
   ```python
   async def discover_resources(self, session: ClientSession) -> List[MCPResource]:
       """Discover available resources via resources/list"""
       try:
           response = await session.list_resources()
           return [self._analyze_resource(resource) for resource in response.resources]
       except Exception as e:
           self.logger.error(f"Resource discovery failed: {e}")
           return []
   ```

3. **Capability Assessment**
   ```python
   async def assess_capabilities(self, session: ClientSession) -> MCPCapabilities:
       """Assess server capabilities via initialize response"""
       # Analyze server capabilities from initialization
       # Determine supported features and experimental capabilities
   ```

### Phase 3: Risk Analysis Enhancement (5 days)

1. **Dynamic Risk Assessment**
   - Analyze tool schemas for dangerous operations
   - Categorize tools by risk type (file_system, network, code_execution)
   - Calculate composite risk scores

2. **Capability-Based Threat Modeling**
   ```python
   def analyze_tool_risk(self, tool: MCPTool) -> List[str]:
       """Analyze tool for security risks based on schema and description"""
       risk_categories = []
       
       # Analyze input schema for dangerous parameters
       if self._has_file_operations(tool.input_schema):
           risk_categories.append('file_system')
       
       if self._has_network_operations(tool.input_schema):
           risk_categories.append('network_access')
           
       if self._has_code_execution(tool.description, tool.input_schema):
           risk_categories.append('code_execution')
           
       return risk_categories
   ```

### Phase 4: Integration and Testing (8 days)

1. **Update Detection Pipeline**
   - Integrate new introspector with existing detection workflow
   - Update report generation to use dynamic introspection data
   - Maintain backward compatibility

2. **Performance Optimization**
   - Implement connection pooling
   - Add result caching
   - Optimize for large-scale scans

3. **Comprehensive Testing**
   - Unit tests for all transport handlers
   - Integration tests with real MCP servers
   - Performance benchmarks
   - Error scenario testing

## Technical Specifications

### Dependencies

```python
# Add to requirements.txt
mcp>=1.0.0  # Official Python MCP SDK
aiofiles>=0.8.0  # Async file operations
asyncio-timeout>=4.0.0  # Timeout management
```

### Configuration

```yaml
# config/introspection.yaml
mcp_introspection:
  timeout_seconds: 30
  max_concurrent_connections: 5
  cache_ttl_hours: 24
  supported_transports:
    - stdio
    - sse
    - http
  risk_analysis:
    enable_dynamic_assessment: true
    threat_categories:
      - file_system
      - network_access
      - code_execution
      - data_access
      - system_modification
```

### Error Handling Strategy

1. **Connection Failures**
   - Retry logic with exponential backoff
   - Graceful degradation to static analysis
   - Detailed error logging

2. **Timeout Management**
   - Per-operation timeouts
   - Global session timeouts
   - Resource cleanup on timeout

3. **Protocol Errors**
   - Handle malformed responses
   - Version compatibility checks
   - Fallback to basic detection

## Benefits of New Approach

### Immediate Benefits
- **No External Dependencies**: Eliminates Node.js requirement
- **Better Error Handling**: Native Python exception handling
- **Improved Performance**: Direct async connections vs subprocess overhead
- **Enhanced Reliability**: Robust connection management and retry logic

### Long-term Benefits
- **Extensibility**: Easy to add new transport types
- **Maintainability**: Pure Python codebase
- **Scalability**: Connection pooling and async operations
- **Integration**: Seamless integration with existing Python ecosystem

## Migration Strategy

### Phase 1: Parallel Implementation
- Implement new Python-based introspector alongside existing system
- Add feature flag to switch between implementations
- Comprehensive testing with both approaches

### Phase 2: Gradual Migration
- Default to new implementation for new detections
- Migrate existing configurations gradually
- Monitor performance and reliability metrics

### Phase 3: Legacy Removal
- Remove Node.js script generation code
- Clean up temporary file handling
- Update documentation and examples

## Risk Mitigation

### Technical Risks
- **MCP SDK Compatibility**: Pin specific SDK version, test with multiple MCP server implementations
- **Performance Regression**: Benchmark against current implementation, optimize critical paths
- **Memory Usage**: Implement connection pooling and resource cleanup

### Operational Risks
- **Breaking Changes**: Maintain backward compatibility, provide migration tools
- **Deployment Complexity**: Simplify dependency management, provide clear upgrade path

## Success Metrics

### Performance Metrics
- Introspection time per server: < 5 seconds
- Memory usage: < 100MB for 50 concurrent connections
- Error rate: < 1% for valid MCP servers

### Quality Metrics
- Test coverage: > 90%
- Documentation coverage: 100% of public APIs
- Zero critical security vulnerabilities

### User Experience Metrics
- Setup time reduction: 50% faster than Node.js approach
- Error message clarity: User-friendly error descriptions
- Configuration simplicity: Single Python environment

## Timeline

**Total Estimated Time: 25 days (5 weeks)**

- **Week 1**: Core infrastructure and transport handlers
- **Week 2**: Discovery implementation and capability assessment
- **Week 3**: Risk analysis enhancement and dynamic threat modeling
- **Week 4**: Integration, testing, and performance optimization
- **Week 5**: Documentation, migration tools, and final testing

## Conclusion

The migration to a Python-based MCP introspection system will significantly improve HawkEye's reliability, performance, and maintainability. By leveraging the official MCP SDK, we eliminate external dependencies while gaining access to a robust, well-tested client implementation.

The new system will provide more accurate threat analysis through dynamic capability discovery and enable HawkEye to scale to analyze the growing ecosystem of MCP servers without the limitations of the current hardcoded approach. 