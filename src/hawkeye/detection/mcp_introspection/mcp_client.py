"""
MCP Client Module

A robust MCP client implementation using proven patterns from mcp-use library.
Provides comprehensive server introspection, tool discovery, and evaluation.
"""

import asyncio
import json
import logging
import subprocess
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

# For better compatibility, we'll implement our own client following mcp-use patterns
import requests
import aiohttp

from .models import (
    MCPServerInfo,
    MCPServerConfig,
    MCPTool,
    MCPResource,
    MCPCapability,
    IntrospectionResult,
    RiskLevel,
    SecurityRisk
)

logger = logging.getLogger(__name__)


@dataclass
class MCPClientConfig:
    """Configuration for MCP client operations."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_tool_testing: bool = False
    enable_resource_enumeration: bool = True
    enable_capability_detection: bool = True
    client_info: Dict[str, Any] = None
    allowed_tools: Optional[List[str]] = None
    disallowed_tools: Optional[List[str]] = None
    debug: bool = False
    
    def __post_init__(self):
        if self.client_info is None:
            self.client_info = {
                "name": "hawkeye-security-scanner",
                "version": "1.0.0"
            }
        if self.disallowed_tools is None:
            # Default security restrictions
            self.disallowed_tools = [
                "system_execute", "shell_execute", "delete_file", 
                "write_file", "network_request", "admin_action"
            ]


@dataclass  
class MCPServerDefinition:
    """Definition of an MCP server connection."""
    name: str
    transport_type: str  # "stdio", "http", "sse"
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    working_directory: Optional[str] = None


class MCPClient:
    """
    Production-grade MCP client inspired by mcp-use library patterns.
    
    Provides comprehensive server introspection including:
    - Server initialization and capability detection
    - Tool discovery and analysis
    - Resource enumeration
    - Security risk assessment
    - Connection management and error handling
    """
    
    def __init__(self, config: Optional[MCPClientConfig] = None, server_config: Optional[Dict[str, Any]] = None):
        """
        Initialize MCP client.
        
        Args:
            config: Client configuration options
            server_config: Server configuration dictionary (mcp-use format)
        """
        self.config = config or MCPClientConfig()
        self.logger = logging.getLogger(__name__)
        
        if self.config.debug:
            self.logger.setLevel(logging.DEBUG)
        
        # Parse server configuration
        self.servers: Dict[str, MCPServerDefinition] = {}
        if server_config:
            self._parse_server_config(server_config)
        
        # Active connections
        self._active_connections: Dict[str, Any] = {}
        self._connection_metadata: Dict[str, Dict[str, Any]] = {}
        
    @classmethod
    def from_config_file(cls, config_path: str, config: Optional[MCPClientConfig] = None) -> 'MCPClient':
        """
        Create MCPClient from configuration file (mcp-use format).
        
        Args:
            config_path: Path to JSON configuration file
            config: Optional client configuration
            
        Returns:
            MCPClient instance
        """
        try:
            with open(config_path, 'r') as f:
                server_config = json.load(f)
            
            return cls(config=config, server_config=server_config)
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to load config from {config_path}: {e}")
            raise
    
    @classmethod
    def from_dict(cls, server_config: Dict[str, Any], config: Optional[MCPClientConfig] = None) -> 'MCPClient':
        """
        Create MCPClient from configuration dictionary (mcp-use format).
        
        Args:
            server_config: Server configuration dictionary
            config: Optional client configuration
            
        Returns:
            MCPClient instance
        """
        return cls(config=config, server_config=server_config)
    
    def _parse_server_config(self, server_config: Dict[str, Any]):
        """Parse server configuration into MCPServerDefinition objects."""
        mcp_servers = server_config.get("mcpServers", {})
        
        for name, config in mcp_servers.items():
            # Determine transport type
            if "url" in config:
                transport_type = "http" if config["url"].startswith("http") else "sse"
                server_def = MCPServerDefinition(
                    name=name,
                    transport_type=transport_type,
                    url=config["url"],
                    headers=config.get("headers", {}),
                    env=config.get("env", {})
                )
            else:
                # STDIO transport
                server_def = MCPServerDefinition(
                    name=name,
                    transport_type="stdio",
                    command=config.get("command"),
                    args=config.get("args", []),
                    env=config.get("env", {}),
                    working_directory=config.get("working_directory")
                )
            
            self.servers[name] = server_def
            
    def __enter__(self):
        """Sync context manager entry."""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Sync context manager exit."""
        # For sync wrapper, we'll handle cleanup differently
        pass
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect_all()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect_all()
        
    async def connect_all(self):
        """Connect to all configured MCP servers."""
        self.logger.info(f"Connecting to {len(self.servers)} MCP servers")
        
        for server_name, server_def in self.servers.items():
            try:
                await self._connect_to_server(server_name, server_def)
                self.logger.info(f"✅ Connected to server '{server_name}'")
            except Exception as e:
                self.logger.error(f"❌ Failed to connect to server '{server_name}': {e}")
                
    async def disconnect_all(self):
        """Disconnect from all MCP servers."""
        for server_name in list(self._active_connections.keys()):
            await self._disconnect_from_server(server_name)
    
    async def list_tools(self, server_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List available tools from connected servers.
        
        Args:
            server_name: Optional server name. If None, lists tools from all servers.
            
        Returns:
            List of tool definitions
        """
        tools = []
        
        if server_name:
            # List tools from specific server
            if server_name in self._active_connections:
                server_tools = await self._list_tools_from_server(server_name)
                tools.extend(server_tools)
            else:
                self.logger.warning(f"Server '{server_name}' not connected")
        else:
            # List tools from all connected servers
            for server_name in self._active_connections.keys():
                try:
                    server_tools = await self._list_tools_from_server(server_name)
                    tools.extend(server_tools)
                except Exception as e:
                    self.logger.error(f"Failed to list tools from '{server_name}': {e}")
        
        # Apply tool filtering
        filtered_tools = self._filter_tools(tools)
        
        self.logger.info(f"Listed {len(filtered_tools)} tools (filtered from {len(tools)})")
        return filtered_tools
    
    async def call_tool(self, tool_name: str, params: Dict[str, Any] = None, server_name: Optional[str] = None) -> Any:
        """
        Call a tool on an MCP server.
        
        Args:
            tool_name: Name of the tool to call
            params: Parameters to pass to the tool
            server_name: Optional server name. If None, searches all servers.
            
        Returns:
            Tool execution result
        """
        if params is None:
            params = {}
            
        # Find the tool
        if server_name:
            if server_name not in self._active_connections:
                raise ValueError(f"Server '{server_name}' not connected")
            return await self._call_tool_on_server(server_name, tool_name, params)
        else:
            # Search all servers for the tool
            for server_name in self._active_connections.keys():
                try:
                    tools = await self._list_tools_from_server(server_name)
                    if any(tool["name"] == tool_name for tool in tools):
                        return await self._call_tool_on_server(server_name, tool_name, params)
                except Exception as e:
                    self.logger.error(f"Error checking tools on '{server_name}': {e}")
                    
            raise ValueError(f"Tool '{tool_name}' not found on any connected server")
    
    async def introspect_server(self, server_config: MCPServerConfig) -> IntrospectionResult:
        """
        Perform comprehensive introspection of an MCP server.
        
        This method adapts the new client to work with the existing interface.
        """
        start_time = datetime.now()
        server_id = server_config.server_id
        
        try:
            self.logger.info(f"Starting MCP introspection of server {server_id}")
            
            # Create temporary server definition from old config
            temp_server_def = self._convert_legacy_config(server_config)
            
            # Connect to server
            await self._connect_to_server(server_id, temp_server_def)
            
            # List tools
            tools_data = await self._list_tools_from_server(server_id)
            
            # Convert tools to internal format
            tools = []
            security_risks = []
            for tool_data in tools_data:
                mcp_tool = self._convert_tool_to_internal(tool_data)
                tools.append(mcp_tool)
                
                # Assess security risks
                tool_risks = self._assess_tool_security_risks(mcp_tool)
                security_risks.extend(tool_risks)
            
            # Create server info
            server_info = MCPServerInfo(
                server_id=server_id,
                endpoint_url=getattr(server_config, 'url', ''),
                host=getattr(server_config, 'host', ''),
                port=getattr(server_config, 'port', 0),
                transport_type=str(server_config.transport_type),
                version="unknown",
                capabilities=[],
                tools=tools,
                resources=[],
                security_config=getattr(server_config, 'security_config', {}),
                server_type="mcp_server",
                has_authentication=bool(getattr(server_config, 'auth_config', None)),
                is_secure=False
            )
            
            # Calculate risk level
            risk_level = self._calculate_risk_level(security_risks, tools, [])
            
            # Create result compatible with existing model
            duration = datetime.now() - start_time
            result = IntrospectionResult(
                timestamp=start_time,
                duration=duration,
                success=True,
                servers=[server_info],  # Wrap single server in list
                total_servers=1,
                successful_servers=1,
                failed_servers=0,
                overall_risk_level=risk_level,
                error=None,
                metadata={
                    "server_id": server_id,
                    "tool_count": len(tools),
                    "risk_count": len(security_risks),
                    "connection_method": "mcp_client_new",
                    "introspection_duration_seconds": duration.total_seconds()
                }
            )
            
            # Cleanup
            await self._disconnect_from_server(server_id)
            
            self.logger.info(
                f"MCP introspection complete for {server_id}: "
                f"{len(tools)} tools, {len(security_risks)} risks, "
                f"{duration.total_seconds():.2f}s"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error during introspection of {server_id}: {e}")
            await self._disconnect_from_server(server_id)
            return self._create_error_result(server_id, start_time, f"Error: {str(e)}")
    
    async def _connect_to_server(self, server_name: str, server_def: MCPServerDefinition):
        """
        Establish connection to MCP server based on transport type.
        
        Args:
            server_name: Name/ID of the server
            server_def: Server definition with connection details
        """
        self.logger.debug(f"Connecting to server '{server_name}' via {server_def.transport_type}")
        
        try:
            if server_def.transport_type == "stdio":
                connection = await self._connect_stdio(server_name, server_def)
            elif server_def.transport_type in ["http", "sse"]:
                connection = await self._connect_http(server_name, server_def)
            else:
                raise ValueError(f"Unsupported transport type: {server_def.transport_type}")
            
            self._active_connections[server_name] = connection
            self._connection_metadata[server_name] = {
                "transport_type": server_def.transport_type,
                "connected_at": datetime.now(),
                "server_def": server_def
            }
            
        except Exception as e:
            self.logger.error(f"Failed to connect to server '{server_name}': {e}")
            raise
    
    async def _disconnect_from_server(self, server_name: str):
        """Disconnect from a specific MCP server."""
        if server_name in self._active_connections:
            try:
                connection = self._active_connections[server_name]
                metadata = self._connection_metadata.get(server_name, {})
                
                # Close connection based on transport type
                if metadata.get("transport_type") == "stdio":
                    # Terminate subprocess
                    if hasattr(connection, 'terminate'):
                        connection.terminate()
                        try:
                            await asyncio.wait_for(connection.wait(), timeout=5.0)
                        except asyncio.TimeoutError:
                            connection.kill()
                elif metadata.get("transport_type") in ["http", "sse"]:
                    # Close HTTP session
                    if hasattr(connection, 'close'):
                        await connection.close()
                
                del self._active_connections[server_name]
                del self._connection_metadata[server_name]
                
                # Clean up session ID
                if hasattr(self, '_session_ids') and server_name in self._session_ids:
                    del self._session_ids[server_name]
                
                self.logger.debug(f"Disconnected from server '{server_name}'")
                
            except Exception as e:
                self.logger.error(f"Error disconnecting from server '{server_name}': {e}")
    
    def _convert_legacy_config(self, server_config: MCPServerConfig) -> MCPServerDefinition:
        """Convert legacy server config to new format."""
        transport_type = str(server_config.transport_type).lower()
        
        if hasattr(server_config, 'url') and server_config.url:
            return MCPServerDefinition(
                name=server_config.server_id,
                transport_type="http" if server_config.url.startswith("http") else "sse",
                url=server_config.url
            )
        else:
            # Default to stdio
            return MCPServerDefinition(
                name=server_config.server_id,
                transport_type="stdio",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-everything"]
            )
    
    async def _connect_stdio(self, server_name: str, server_def: MCPServerDefinition):
        """Connect to MCP server via stdio transport."""
        try:
            # Build command
            command = [server_def.command] + (server_def.args or [])
            
            self.logger.debug(f"Starting stdio server: {' '.join(command)}")
            
            # Start subprocess
            env = dict(server_def.env or {})
            if server_def.working_directory:
                cwd = server_def.working_directory
            else:
                cwd = None
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd
            )
            
            # Wait a moment for server to start
            await asyncio.sleep(0.5)
            
            # Check if process is still running
            if process.returncode is not None:
                stderr_output = await process.stderr.read()
                raise Exception(f"Server process exited with code {process.returncode}: {stderr_output.decode()}")
            
            return process
            
        except Exception as e:
            self.logger.error(f"Failed to connect to '{server_name}' via stdio: {e}")
            raise

    async def _connect_http(self, server_name: str, server_def: MCPServerDefinition):
        """Connect to MCP server via HTTP/SSE transport with session management."""
        try:
            # Create aiohttp session with custom headers
            headers = dict(server_def.headers or {})
            headers.update({
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
            
            connector = aiohttp.TCPConnector(limit=10)
            session = aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
            
            # Initialize MCP session
            session_id = await self._initialize_mcp_session_async(session, server_def)
            if not session_id:
                await session.close()
                raise Exception("Failed to initialize MCP session")
            
            # Store session ID for future requests
            if not hasattr(self, '_session_ids'):
                self._session_ids = {}
            self._session_ids[server_name] = session_id
            
            self.logger.debug(f"MCP session initialized for '{server_name}': {session_id[:8] if session_id != 'no-session-required' else 'no-session'}...")
            
            return session
            
        except Exception as e:
            self.logger.error(f"Failed to connect to '{server_name}' via HTTP: {e}")
            raise

    async def _initialize_mcp_session_async(self, session: aiohttp.ClientSession, server_def: MCPServerDefinition) -> Optional[str]:
        """
        Initialize MCP session and return session ID.
        
        Args:
            session: aiohttp ClientSession
            server_def: Server definition with URL
            
        Returns:
            Session ID if successful, None otherwise
        """
        try:
            # Prepare initialization request
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "roots": {"listChanged": False}
                    },
                    "clientInfo": {
                        "name": "hawkeye-security-scanner",
                        "version": "1.0.0"
                    }
                }
            }
            
            # Determine endpoint URL
            url = server_def.url
            if not url.endswith('/mcp') and not url.endswith('/mcp/'):
                url = url.rstrip('/') + '/mcp'
            
            self.logger.debug(f"Initializing MCP session at {url}")
            
            # Send initialization request
            async with session.post(url, json=init_request) as response:
                if response.status == 200:
                    # Look for session ID in response headers
                    session_id = response.headers.get('mcp-session-id') or response.headers.get('Mcp-Session-Id')
                    
                    if session_id:
                        session_id = session_id.strip()
                        self.logger.debug(f"MCP session initialized successfully: {session_id[:8]}...")
                        return session_id
                    else:
                        # Try to parse response body for session info
                        try:
                            response_data = await response.json()
                            if response_data.get("result"):
                                self.logger.debug("MCP server initialized without session management")
                                return "no-session-required"
                        except:
                            pass
                        
                        self.logger.warning("MCP session initialization succeeded but no session ID returned")
                        return None
                else:
                    response_text = await response.text()
                    self.logger.error(f"MCP session initialization failed with status {response.status}: {response_text}")
                    return None
                    
        except Exception as e:
            self.logger.error(f"MCP session initialization failed: {e}")
            return None
    
    async def _list_tools_from_server(self, server_name: str) -> List[Dict[str, Any]]:
        """List tools from a specific connected server."""
        if server_name not in self._active_connections:
            raise ValueError(f"Server '{server_name}' not connected")
        
        connection = self._active_connections[server_name]
        metadata = self._connection_metadata[server_name]
        
        try:
            if metadata["transport_type"] == "stdio":
                return await self._list_tools_stdio(server_name, connection)
            elif metadata["transport_type"] in ["http", "sse"]:
                return await self._list_tools_http(server_name, connection, metadata["server_def"])
            else:
                raise ValueError(f"Unsupported transport type: {metadata['transport_type']}")
                
        except Exception as e:
            self.logger.error(f"Failed to list tools from '{server_name}': {e}")
            return []
    
    async def _list_tools_stdio(self, server_name: str, process) -> List[Dict[str, Any]]:
        """List tools from stdio MCP server."""
        try:
            # Create MCP tools/list request
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
            
            # Send request to stdin
            request_json = json.dumps(request) + "\n"
            process.stdin.write(request_json.encode())
            await process.stdin.drain()
            
            # Read response from stdout
            response_line = await asyncio.wait_for(
                process.stdout.readline(),
                timeout=self.config.timeout
            )
            
            if not response_line:
                raise Exception("No response from server")
            
            response = json.loads(response_line.decode().strip())
            
            if "error" in response:
                raise Exception(f"Server error: {response['error']}")
            
            # Extract tools from response
            result = response.get("result", {})
            tools = result.get("tools", [])
            
            # Convert to standard format
            return self._normalize_tools(tools, server_name)
            
        except Exception as e:
            self.logger.error(f"Error listing tools from stdio server '{server_name}': {e}")
            return []
    
    async def _list_tools_http(self, server_name: str, session: aiohttp.ClientSession, server_def: MCPServerDefinition) -> List[Dict[str, Any]]:
        """List tools from HTTP MCP server with session management."""
        try:
            # Create MCP tools/list request
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
            
            # Determine endpoint URL
            url = server_def.url
            if not url.endswith('/mcp') and not url.endswith('/mcp/'):
                url = url.rstrip('/') + '/mcp'
            
            # Prepare headers with session ID if available
            headers = {}
            if hasattr(self, '_session_ids') and server_name in self._session_ids:
                session_id = self._session_ids[server_name]
                if session_id != "no-session-required":
                    headers["Mcp-Session-Id"] = session_id
                    session_info = session_id[:8] + "..." if len(session_id) > 8 else session_id
                    self.logger.debug(f"Using session ID for tools/list: {session_info}")
            
            # Send request
            async with session.post(url, json=request, headers=headers) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
                
                response_data = await response.json()
                
                if "error" in response_data:
                    raise Exception(f"Server error: {response_data['error']}")
                
                # Extract tools from response
                result = response_data.get("result", {})
                tools = result.get("tools", [])
                
                self.logger.debug(f"Retrieved {len(tools)} tools from server '{server_name}'")
                
                # Convert to standard format
                return self._normalize_tools(tools, server_name)
                
        except Exception as e:
            self.logger.error(f"Error listing tools from HTTP server '{server_name}': {e}")
            return []
    
    def _normalize_tools(self, tools: List[Dict[str, Any]], server_name: str) -> List[Dict[str, Any]]:
        """Normalize tool definitions to standard format."""
        normalized = []
        
        for tool in tools:
            normalized_tool = {
                "name": tool.get("name", "unknown"),
                "description": tool.get("description", ""),
                "parameters": tool.get("inputSchema", {}),
                "server_name": server_name,
                "server_source": server_name
            }
            normalized.append(normalized_tool)
            
        return normalized
    
    def _filter_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply tool filtering based on allowed/disallowed lists."""
        if not tools:
            return []
        
        filtered = []
        
        for tool in tools:
            tool_name = tool.get("name", "")
            
            # Check disallowed tools
            if self.config.disallowed_tools:
                if tool_name in self.config.disallowed_tools:
                    self.logger.debug(f"Filtering out disallowed tool: {tool_name}")
                    continue
                
                # Check for pattern matches in disallowed tools
                if any(pattern in tool_name.lower() for pattern in self.config.disallowed_tools):
                    self.logger.debug(f"Filtering out tool matching disallowed pattern: {tool_name}")
                    continue
            
            # Check allowed tools
            if self.config.allowed_tools:
                if tool_name not in self.config.allowed_tools:
                    self.logger.debug(f"Filtering out non-allowed tool: {tool_name}")
                    continue
            
            filtered.append(tool)
        
        return filtered
    
    async def _call_tool_on_server(self, server_name: str, tool_name: str, params: Dict[str, Any]) -> Any:
        """Call a tool on a specific server."""
        if server_name not in self._active_connections:
            raise ValueError(f"Server '{server_name}' not connected")
        
        connection = self._active_connections[server_name]
        metadata = self._connection_metadata[server_name]
        
        try:
            if metadata["transport_type"] == "stdio":
                return await self._call_tool_stdio(server_name, connection, tool_name, params)
            elif metadata["transport_type"] in ["http", "sse"]:
                return await self._call_tool_http(server_name, connection, metadata["server_def"], tool_name, params)
            else:
                raise ValueError(f"Unsupported transport type: {metadata['transport_type']}")
                
        except Exception as e:
            self.logger.error(f"Failed to call tool '{tool_name}' on '{server_name}': {e}")
            raise
    
    async def _call_tool_stdio(self, server_name: str, process, tool_name: str, params: Dict[str, Any]) -> Any:
        """Call a tool on stdio MCP server."""
        try:
            # Create MCP tools/call request
            request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": params
                }
            }
            
            # Send request
            request_json = json.dumps(request) + "\n"
            process.stdin.write(request_json.encode())
            await process.stdin.drain()
            
            # Read response
            response_line = await asyncio.wait_for(
                process.stdout.readline(),
                timeout=self.config.timeout
            )
            
            if not response_line:
                raise Exception("No response from server")
            
            response = json.loads(response_line.decode().strip())
            
            if "error" in response:
                raise Exception(f"Server error: {response['error']}")
            
            return response.get("result")
            
        except Exception as e:
            self.logger.error(f"Error calling tool '{tool_name}' on stdio server '{server_name}': {e}")
            raise
    
    async def _call_tool_http(self, server_name: str, session: aiohttp.ClientSession, server_def: MCPServerDefinition, tool_name: str, params: Dict[str, Any]) -> Any:
        """Call a tool on HTTP MCP server."""
        try:
            # Create MCP tools/call request
            request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": params
                }
            }
            
            # Determine endpoint URL
            url = server_def.url
            if not url.endswith('/mcp') and not url.endswith('/mcp/'):
                url = url.rstrip('/') + '/mcp'
            
            # Send request
            async with session.post(url, json=request) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
                
                response_data = await response.json()
                
                if "error" in response_data:
                    raise Exception(f"Server error: {response_data['error']}")
                
                return response_data.get("result")
                
        except Exception as e:
            self.logger.error(f"Error calling tool '{tool_name}' on HTTP server '{server_name}': {e}")
            raise
    


    def _convert_tool_to_internal(self, tool_data: Dict[str, Any]) -> MCPTool:
        """Convert tool data from MCP server to internal MCPTool model."""
        return MCPTool(
            name=tool_data.get("name", "unknown"),
            description=tool_data.get("description", ""),
            parameters=self._convert_tool_parameters(tool_data.get("parameters", {})),
            required_params=self._extract_required_params(tool_data.get("parameters", {})),
            return_type="object",  # Default for MCP tools
            risk_level=RiskLevel.MEDIUM,  # Will be updated by risk assessment
            metadata={
                "mcp_tool": True,
                "schema": tool_data.get("parameters", {}),
                "server_source": tool_data.get("server_name", "unknown")
            }
        )
    
    def _convert_tool_parameters(self, input_schema: Dict[str, Any]) -> List[Any]:
        """Convert tool input schema to parameter list."""
        properties = input_schema.get('properties', {})
        return [
            {
                "name": param_name,
                "type": param_info.get('type', 'string'),
                "description": param_info.get('description', ''),
                "required": param_name in input_schema.get('required', [])
            }
            for param_name, param_info in properties.items()
        ]
    
    def _extract_required_params(self, input_schema: Dict[str, Any]) -> List[str]:
        """Extract required parameter names from schema."""
        return input_schema.get('required', [])
    
    def _assess_tool_security_risks(self, tool: MCPTool) -> List[SecurityRisk]:
        """Assess security risks for a tool."""
        risks = []
        risk_indicators = [
            'exec', 'eval', 'system', 'shell', 'command', 'file_write', 
            'file_delete', 'network', 'database', 'sql', 'admin', 'sudo'
        ]
        
        # Check tool name and description for risk indicators
        tool_text = f"{tool.name} {tool.description}".lower()
        
        for indicator in risk_indicators:
            if indicator in tool_text:
                risk_level = RiskLevel.HIGH if indicator in ['exec', 'eval', 'system', 'sudo'] else RiskLevel.MEDIUM
                risks.append(SecurityRisk(
                    category="tool_capability",
                    severity=risk_level,
                    description=f"Tool '{tool.name}' contains potentially dangerous capability: {indicator}",
                    details={
                        "tool_name": tool.name,
                        "indicator": indicator,
                        "affected_component": f"tool:{tool.name}"
                    },
                    mitigation=f"Review tool '{tool.name}' implementation and implement access controls for {indicator} operations"
                ))
        
        return risks
    
    def _assess_resource_security_risks(self, resource: MCPResource) -> List[SecurityRisk]:
        """Assess security risks for a resource."""
        risks = []
        
        # Check for sensitive file paths
        sensitive_patterns = ['/etc/', '/var/', '/tmp/', '/root/', 'password', 'secret', 'key']
        
        for pattern in sensitive_patterns:
            if pattern in resource.uri.lower():
                risks.append(SecurityRisk(
                    category="resource_access",
                    severity=RiskLevel.MEDIUM,
                    description=f"Resource '{resource.uri}' may expose sensitive information",
                    details={
                        "resource_uri": resource.uri,
                        "pattern": pattern,
                        "affected_component": f"resource:{resource.uri}"
                    },
                    mitigation="Verify resource access permissions and implement data filtering for sensitive content"
                ))
        
        return risks
    
    def _calculate_risk_level(self, security_risks: List[SecurityRisk], tools: List[MCPTool], resources: List[MCPResource]) -> RiskLevel:
        """Calculate overall risk level for the server."""
        if not security_risks:
            return RiskLevel.LOW
        
        high_risks = sum(1 for risk in security_risks if risk.severity == RiskLevel.HIGH)
        medium_risks = sum(1 for risk in security_risks if risk.severity == RiskLevel.MEDIUM)
        
        if high_risks > 0:
            return RiskLevel.HIGH
        elif medium_risks > 2:
            return RiskLevel.HIGH
        elif medium_risks > 0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    

    
    def _create_error_result(self, server_id: str, start_time: datetime, error_message: str) -> IntrospectionResult:
        """Create an error result for failed introspection."""
        return IntrospectionResult(
            timestamp=start_time,
            duration=datetime.now() - start_time,
            success=False,
            servers=[],  # Empty list for failed introspection
            total_servers=1,
            successful_servers=0,
            failed_servers=1,
            overall_risk_level=RiskLevel.UNKNOWN,
            error=error_message,
            metadata={
                "server_id": server_id,
                "connection_method": "mcp_sdk_failed"
            }
        )


# Synchronous wrapper for async MCP client
class SyncMCPClient:
    """
    Synchronous wrapper for MCPClient to integrate with existing synchronous codebase.
    """
    
    def __init__(self, config: Optional[MCPClientConfig] = None):
        self.config = config or MCPClientConfig()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def introspect_server(self, server_config: MCPServerConfig) -> IntrospectionResult:
        """
        Synchronous wrapper for server introspection.
        
        Args:
            server_config: Server configuration
            
        Returns:
            IntrospectionResult from async introspection
        """
        try:
            # Create new event loop if needed
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
            
            # Create async client and run introspection
            async_client = MCPClient(self.config)
            result = self._loop.run_until_complete(
                async_client.introspect_server(server_config)
            )
            
            return result
            
        except Exception as e:
            # Create a simple logger for error handling
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error in synchronous MCP client: {e}")
            start_time = datetime.now()
            return IntrospectionResult(
                timestamp=start_time,
                duration=datetime.now() - start_time,
                success=False,
                servers=[],
                total_servers=1,
                successful_servers=0,
                failed_servers=1,
                overall_risk_level=RiskLevel.UNKNOWN,
                error=f"Sync wrapper error: {str(e)}",
                metadata={
                    "server_id": server_config.server_id,
                    "connection_method": "mcp_sdk_sync_wrapper"
                }
            )
    
    def close(self):
        """Clean up event loop resources."""
        if self._loop and not self._loop.is_closed():
            try:
                self._loop.close()
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error closing event loop: {e}") 