# Detection API Documentation

## Overview

The Detection API provides specialized MCP (Model Context Protocol) server detection capabilities. It includes process enumeration, configuration discovery, protocol verification, and comprehensive introspection functionality.

## Core Classes

### MCPDetector

Main class for MCP server detection operations.

```python
from hawkeye.detection.base import MCPDetector
from hawkeye.config.settings import DetectionSettings

# Initialize with default settings
detector = MCPDetector()

# Initialize with custom settings
settings = DetectionSettings(enable_docker_inspect=True, max_depth=5)
detector = MCPDetector(settings)
```

#### Methods

##### `detect_local_servers() -> List[MCPServerInfo]`

Detects MCP servers running on the local system.

**Returns:**
- `List[MCPServerInfo]`: List of detected MCP servers

**Example:**
```python
servers = detector.detect_local_servers()
for server in servers:
    print(f"Found MCP server: {server.name} (PID: {server.process_id})")
```

##### `detect_remote_server(target: str, port: int) -> Optional[MCPServerInfo]`

Detects MCP server on remote target.

##### `verify_mcp_protocol(server_info: MCPServerInfo) -> bool`

Verifies if a detected service is actually an MCP server.

### ProcessEnumerator

Enumerates Node.js processes that might be MCP servers.

```python
from hawkeye.detection.process_enum import ProcessEnumerator

enumerator = ProcessEnumerator()
processes = enumerator.find_nodejs_processes()
```

### ConfigDiscovery

Discovers MCP configuration files and settings.

```python
from hawkeye.detection.config_discovery import ConfigDiscovery

discovery = ConfigDiscovery()
configs = discovery.find_mcp_configs("/path/to/search")
```

### MCPIntrospector

Advanced MCP server introspection and capability discovery.

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector

introspector = MCPIntrospector()
capabilities = introspector.introspect_server(server_info, process_info)
```

## Data Models

### MCPServerInfo

Contains information about a detected MCP server.

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
    command_line: List[str]
    environment: Dict[str, str]
    timestamp: datetime
```

### ProcessInfo

Information about a system process.

```python
@dataclass
class ProcessInfo:
    pid: int
    name: str
    cmdline: List[str]
    cwd: str
    environ: Dict[str, str]
    create_time: float
```

### MCPCapabilities

Comprehensive MCP server capabilities.

```python
@dataclass
class MCPCapabilities:
    server_name: str
    server_version: str
    protocol_version: str
    tools: List[MCPTool]
    resources: List[MCPResource]
    capabilities: Dict[str, Any]
    
    @property
    def tool_count(self) -> int:
        return len(self.tools)
    
    @property
    def has_file_access(self) -> bool:
        return any(tool.has_file_access for tool in self.tools)
```

## MCP Introspection System

### IntrospectionConfig

Configuration for MCP introspection operations.

```python
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

config = IntrospectionConfig(
    timeout=30.0,
    max_retries=3,
    enable_caching=True,
    enable_risk_analysis=True
)
```

### Transport Types

Different transport mechanisms for MCP communication.

#### StdioTransport

For local MCP servers using standard I/O.

```python
from hawkeye.detection.mcp_introspection.transport.stdio import StdioTransportHandler

transport = StdioTransportHandler(config)
result = transport.connect(server_config)
```

#### SSETransport

For Server-Sent Events based MCP servers.

```python
from hawkeye.detection.mcp_introspection.transport.sse import SSETransportHandler

transport = SSETransportHandler(config)
result = transport.connect(server_config)
```

## Usage Examples

### Local MCP Detection

```python
from hawkeye.detection.base import MCPDetector

detector = MCPDetector()
servers = detector.detect_local_servers()

for server in servers:
    print(f"Server: {server.name}")
    print(f"Process ID: {server.process_id}")
    print(f"Command: {' '.join(server.command_line)}")
    print(f"Transport: {server.transport_type}")
```

### MCP Server Introspection

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.base import ProcessInfo, MCPServerInfo

# Create server and process info
server_info = MCPServerInfo(host="localhost")
process_info = ProcessInfo(
    pid=1234,
    name="node",
    cmdline=["node", "server.js"],
    cwd="/path/to/server"
)

# Perform introspection
introspector = MCPIntrospector()
capabilities = introspector.introspect_server(server_info, process_info)

if capabilities:
    print(f"Server: {capabilities.server_name}")
    print(f"Tools: {capabilities.tool_count}")
    print(f"Resources: {len(capabilities.resources)}")
    print(f"Risk Level: {capabilities.highest_risk_level}")
```

### Configuration Discovery

```python
from hawkeye.detection.config_discovery import ConfigDiscovery

discovery = ConfigDiscovery()
configs = discovery.find_mcp_configs("/home/user/projects")

for config in configs:
    print(f"Config file: {config.path}")
    print(f"Server name: {config.server_name}")
    print(f"Transport: {config.transport}")
```

### Process Enumeration

```python
from hawkeye.detection.process_enum import ProcessEnumerator

enumerator = ProcessEnumerator()
processes = enumerator.find_nodejs_processes()

mcp_processes = []
for process in processes:
    if enumerator.is_likely_mcp_server(process):
        mcp_processes.append(process)
        print(f"Potential MCP server: PID {process.pid}")
```

## Advanced Features

### Risk Analysis

The introspection system includes automated risk analysis:

```python
capabilities = introspector.introspect_server(server_info, process_info)

if capabilities:
    # Check for high-risk tools
    high_risk_tools = [tool for tool in capabilities.tools 
                      if tool.risk_level == "HIGH"]
    
    # Check for external access
    if capabilities.has_external_access:
        print("⚠️ Server has external access capabilities")
    
    # Check for file system access
    if capabilities.has_file_access:
        print("⚠️ Server has file system access")
```

### Multi-Server Operations

```python
server_list = [
    (server_info_1, process_info_1),
    (server_info_2, process_info_2),
    (server_info_3, process_info_3)
]

results = introspector.introspect_multiple_servers(server_list)

for i, capabilities in enumerate(results):
    if capabilities:
        print(f"Server {i+1}: {capabilities.server_name}")
    else:
        print(f"Server {i+1}: Introspection failed")
```

## Error Handling

```python
from hawkeye.detection.exceptions import DetectionError, ConnectionError

try:
    servers = detector.detect_local_servers()
except DetectionError as e:
    print(f"Detection failed: {e}")

try:
    capabilities = introspector.introspect_server(server_info, process_info)
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

## Performance Tips

- Enable caching for repeated introspection operations
- Use appropriate timeouts based on network conditions
- Configure max_retries for unreliable connections
- Use concurrent operations for multiple servers
- Enable risk analysis only when needed 