"""
Tool Discovery Module

Implements tool discovery via MCP tools/list endpoint.
Provides comprehensive tool enumeration, schema analysis, and risk assessment.
Uses synchronous subprocess communication to avoid async complexity.
"""

import json
import logging
import subprocess
import time
import requests
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urljoin

from ..models import (
    MCPTool, 
    MCPToolParameter,
    RiskLevel,
    SecurityRisk,
    DiscoveryResult,
    MCPServerConfig
)
from ..utils import ErrorHandler


logger = logging.getLogger(__name__)


@dataclass
class ToolDiscoveryConfig:
    """Configuration for tool discovery operations."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_schema_analysis: bool = True
    enable_risk_assessment: bool = True
    dangerous_patterns: Set[str] = None
    
    def __post_init__(self):
        if self.dangerous_patterns is None:
            self.dangerous_patterns = {
                'exec', 'eval', 'system', 'shell', 'command',
                'file_write', 'file_delete', 'network_request',
                'database', 'sql', 'admin', 'sudo', 'root'
            }


class ToolDiscovery:
    """
    Discovers and analyzes MCP tools via direct communication.
    
    Provides comprehensive tool enumeration with schema analysis,
    risk assessment, and security evaluation using synchronous methods.
    Supports both subprocess and HTTP transport communication.
    """
    
    def __init__(self, config: Optional[ToolDiscoveryConfig] = None):
        """
        Initialize tool discovery.
        
        Args:
            config: Discovery configuration options
        """
        self.config = config or ToolDiscoveryConfig()
        self.error_handler = ErrorHandler()
        self._discovery_cache: Dict[str, DiscoveryResult] = {}
        
    def discover_tools(
        self,
        server_config: MCPServerConfig,
        server_id: Optional[str] = None
    ) -> DiscoveryResult:
        """
        Discover tools from an MCP server.
        
        Args:
            server_config: Server configuration for connection
            server_id: Optional server identifier (uses config.server_id if not provided)
            
        Returns:
            DiscoveryResult containing discovered tools and metadata
        """
        if server_id is None:
            server_id = server_config.server_id
            
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting tool discovery for server {server_id}")
            
            # Check cache first
            cache_key = f"tools_{server_id}"
            if cache_key in self._discovery_cache:
                cached_result = self._discovery_cache[cache_key]
                if self._is_cache_valid(cached_result):
                    logger.debug(f"Using cached tool discovery for {server_id}")
                    return cached_result
            
            # Discover tools with timeout
            start_discovery = time.time()
            tools_data = self._list_tools_with_retry(server_config)
            
            # Check timeout
            if time.time() - start_discovery > self.config.timeout:
                raise TimeoutError("Tool discovery timeout")
            
            # Process discovered tools
            mcp_tools = []
            security_risks = []
            
            if tools_data and isinstance(tools_data, list):
                for tool_data in tools_data:
                    try:
                        # Convert to internal model
                        mcp_tool = self._convert_tool(tool_data)
                        mcp_tools.append(mcp_tool)
                        
                        # Perform risk assessment if enabled
                        if self.config.enable_risk_assessment:
                            risks = self._assess_tool_risks(mcp_tool)
                            security_risks.extend(risks)
                            
                    except Exception as e:
                        logger.warning(f"Failed to process tool {tool_data.get('name', 'unknown')}: {e}")
                        continue
            
            # Create discovery result
            discovery_time = datetime.now() - start_time
            result = DiscoveryResult(
                server_id=server_id,
                discovery_type="tools",
                timestamp=start_time,
                duration=discovery_time,
                success=True,
                tools=mcp_tools,
                security_risks=security_risks,
                metadata={
                    "tool_count": len(mcp_tools),
                    "risk_count": len(security_risks),
                    "discovery_method": f"{server_config.transport_type}_communication",
                    "schema_analysis": self.config.enable_schema_analysis,
                    "risk_assessment": self.config.enable_risk_assessment
                }
            )
            
            # Cache result
            self._discovery_cache[cache_key] = result
            
            logger.info(
                f"Tool discovery complete for {server_id}: "
                f"{len(mcp_tools)} tools, {len(security_risks)} risks, "
                f"{discovery_time.total_seconds():.2f}s"
            )
            
            return result
            
        except TimeoutError:
            logger.error(f"Tool discovery timeout for server {server_id}")
            return self._create_error_result(
                server_id, start_time, "Discovery timeout"
            )
            
        except Exception as e:
            logger.error(f"Unexpected error during tool discovery for {server_id}: {e}")
            return self._create_error_result(
                server_id, start_time, f"Unexpected error: {str(e)}"
            )

    def _list_tools_with_retry(self, server_config: MCPServerConfig) -> Optional[List[Dict[str, Any]]]:
        """
        List tools with retry logic using appropriate communication method.
        
        Args:
            server_config: Server configuration for connection
            
        Returns:
            List of discovered tools or None
        """
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                logger.debug(f"Tool discovery attempt {attempt + 1} using {server_config.transport_type} transport")
                
                # Create MCP request for tools/list
                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }
                
                # Choose communication method based on transport type
                if server_config.transport_type.value in ["http", "sse"]:
                    result = self._communicate_via_http(server_config, request)
                else:
                    # Default to subprocess communication for stdio
                    server_command = self._build_server_command(server_config)
                    result = self._communicate_with_server(server_command, request)
                
                if result and "result" in result:
                    tools = result["result"].get("tools", [])
                    logger.debug(f"Successfully discovered {len(tools)} tools via {server_config.transport_type}")
                    return tools
                elif result and "error" in result:
                    raise Exception(f"MCP error: {result['error']}")
                else:
                    logger.debug(f"No tools returned from server {server_config.server_id}")
                    return []
                    
            except Exception as e:
                last_error = e
                logger.warning(f"Tool discovery attempt {attempt + 1} failed: {e}")
                
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2 ** attempt))
                    
        # All retries failed
        logger.error(f"Tool discovery failed after all retries: {last_error}")
        return None

    def _communicate_via_http(self, server_config: MCPServerConfig, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Communicate with MCP server via HTTP with session management.
        
        Args:
            server_config: Server configuration with URL and headers
            request: JSON-RPC request to send
            
        Returns:
            Server response or None
        """
        try:
            url = server_config.url
            if not url:
                logger.error("No URL configured for HTTP transport")
                return None
            
            # Ensure URL has /mcp endpoint if it doesn't already
            if not url.endswith('/mcp') and not url.endswith('/mcp/'):
                url = urljoin(url.rstrip('/') + '/', 'mcp')
            
            # Initialize session first if needed
            session_id = self._initialize_mcp_session(url, server_config)
            if not session_id:
                logger.error("Failed to initialize MCP session")
                return None
            
            # Prepare headers with session ID (if required)
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Add session ID header if required
            if session_id != "no-session-required":
                headers["Mcp-Session-Id"] = session_id
            
            # Add any additional headers from transport config
            if hasattr(server_config, 'transport_config') and server_config.transport_config:
                config_headers = server_config.transport_config.get('headers', {})
                headers.update(config_headers)
            
            session_info = session_id[:8] + "..." if session_id != "no-session-required" else "no-session"
            logger.debug(f"Sending HTTP request to {url} with session {session_info}")
            
            # Send HTTP POST request with session
            response = requests.post(
                url,
                json=request,
                headers=headers,
                timeout=self.config.timeout
            )
            
            # Check response status
            if response.status_code == 200:
                try:
                    result = response.json()
                    logger.debug(f"HTTP response received successfully from {url}")
                    return result
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse HTTP response JSON: {e}")
                    logger.debug(f"Raw response: {response.text}")
                    return None
            else:
                logger.warning(f"HTTP request failed with status {response.status_code}: {response.text}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"HTTP communication failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in HTTP communication: {e}")
            return None

    def _initialize_mcp_session(self, url: str, server_config: MCPServerConfig) -> Optional[str]:
        """
        Initialize MCP session and return session ID.
        
        Args:
            url: MCP server URL
            server_config: Server configuration
            
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
            
            # Prepare basic headers
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Add any additional headers from transport config
            if hasattr(server_config, 'transport_config') and server_config.transport_config:
                config_headers = server_config.transport_config.get('headers', {})
                headers.update(config_headers)
            
            logger.debug(f"Initializing MCP session at {url}")
            
            # Send initialization request
            response = requests.post(
                url,
                json=init_request,
                headers=headers,
                timeout=self.config.timeout
            )
            
            # Check if initialization was successful
            if response.status_code == 200:
                # Look for session ID in response headers
                session_id = None
                for header_name, header_value in response.headers.items():
                    if header_name.lower() == 'mcp-session-id':
                        session_id = header_value.strip()
                        break
                
                if session_id:
                    logger.debug(f"MCP session initialized successfully: {session_id[:8]}...")
                    return session_id
                else:
                    logger.warning("MCP session initialization succeeded but no session ID returned")
                    # Try to parse response body for session info
                    try:
                        response_data = response.json()
                        if response_data.get("result"):
                            logger.debug("MCP server initialized without session management")
                            return "no-session-required"
                    except:
                        pass
                    return None
            else:
                logger.error(f"MCP session initialization failed with status {response.status_code}: {response.text}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"MCP session initialization failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during MCP session initialization: {e}")
            return None

    def _build_server_command(self, server_config: MCPServerConfig) -> List[str]:
        """
        Build server command from configuration.
        
        Args:
            server_config: Server configuration
            
        Returns:
            Command list to start the server
        """
        if server_config.command:
            return server_config.command
        elif server_config.executable:
            command = [server_config.executable]
            if server_config.args:
                command.extend(server_config.args)
            return command
        else:
            # Fallback command
            return ['mcp-server', server_config.server_id]
    
    def _communicate_with_server(self, server_command: List[str], request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Communicate with MCP server via subprocess.
        
        Args:
            server_command: Command to start the server
            request: JSON-RPC request to send
            
        Returns:
            Server response or None
        """
        try:
            # Start the server process
            process = subprocess.Popen(
                server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            
            # Send request
            request_json = json.dumps(request) + "\n"
            stdout, stderr = process.communicate(input=request_json, timeout=self.config.timeout)
            
            # Parse response
            if stdout.strip():
                try:
                    response = json.loads(stdout.strip())
                    return response
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse server response: {e}")
                    logger.debug(f"Raw response: {stdout}")
                    return None
            else:
                logger.warning(f"No response from server. stderr: {stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Server communication timeout")
            if process:
                process.kill()
            return None
        except Exception as e:
            logger.error(f"Server communication failed: {e}")
            return None
    
    def _convert_tool(self, tool_data: Dict[str, Any]) -> MCPTool:
        """
        Convert tool data to internal MCPTool model.
        
        Args:
            tool_data: Raw tool data from server
            
        Returns:
            MCPTool instance
        """
        # Extract parameters from schema
        parameters = []
        input_schema = tool_data.get('inputSchema', {})
        if input_schema and self.config.enable_schema_analysis:
            parameters = self._extract_parameters(input_schema)
        
        return MCPTool(
            name=tool_data.get('name', ''),
            description=tool_data.get('description', ''),
            parameters=parameters,
            input_schema=input_schema,
            metadata={
                "discovery_method": "subprocess_communication",
                "has_schema": bool(input_schema),
                "parameter_count": len(parameters)
            }
        )
    
    def _extract_parameters(self, schema: Dict[str, Any]) -> List[MCPToolParameter]:
        """
        Extract parameters from JSON schema.
        
        Args:
            schema: JSON schema for tool input
            
        Returns:
            List of MCPToolParameter instances
        """
        parameters = []
        
        if not isinstance(schema, dict):
            return parameters
            
        properties = schema.get('properties', {})
        required = schema.get('required', [])
        
        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue
                
            parameter = MCPToolParameter(
                name=param_name,
                type=param_schema.get('type', 'unknown'),
                description=param_schema.get('description', ''),
                required=param_name in required,
                default=param_schema.get('default'),
                enum=param_schema.get('enum'),
                metadata={
                    "schema": param_schema,
                    "has_constraints": bool(
                        param_schema.get('minimum') or 
                        param_schema.get('maximum') or
                        param_schema.get('pattern') or
                        param_schema.get('enum')
                    )
                }
            )
            parameters.append(parameter)
            
        return parameters
    
    def _assess_tool_risks(self, tool: MCPTool) -> List[SecurityRisk]:
        """
        Assess security risks for a tool.
        
        Args:
            tool: MCPTool to assess
            
        Returns:
            List of identified security risks
        """
        risks = []
        
        # Check for dangerous patterns in tool name
        tool_name_lower = tool.name.lower()
        for pattern in self.config.dangerous_patterns:
            if pattern in tool_name_lower:
                risks.append(SecurityRisk(
                    category="dangerous_tool_name",
                    severity=RiskLevel.HIGH,
                    description=f"Tool name contains dangerous pattern: {pattern}",
                    details={
                        "tool_name": tool.name,
                        "pattern": pattern,
                        "location": "tool_name"
                    },
                    mitigation="Review tool functionality and restrict access if necessary"
                ))
        
        # Check for dangerous patterns in description
        if tool.description:
            desc_lower = tool.description.lower()
            for pattern in self.config.dangerous_patterns:
                if pattern in desc_lower:
                    risks.append(SecurityRisk(
                        category="dangerous_tool_description",
                        severity=RiskLevel.MEDIUM,
                        description=f"Tool description mentions dangerous pattern: {pattern}",
                        details={
                            "tool_name": tool.name,
                            "pattern": pattern,
                            "location": "description"
                        },
                        mitigation="Review tool description and functionality"
                    ))
        
        # Check for file system access parameters
        for param in tool.parameters:
            param_name_lower = param.name.lower()
            if any(fs_pattern in param_name_lower for fs_pattern in ['path', 'file', 'directory', 'folder']):
                risks.append(SecurityRisk(
                    category="file_system_access",
                    severity=RiskLevel.MEDIUM,
                    description=f"Tool parameter suggests file system access: {param.name}",
                    details={
                        "tool_name": tool.name,
                        "parameter": param.name,
                        "parameter_type": param.type
                    },
                    mitigation="Validate file paths and restrict access to safe directories"
                ))
        
        # Check for network access parameters
        for param in tool.parameters:
            param_name_lower = param.name.lower()
            if any(net_pattern in param_name_lower for net_pattern in ['url', 'host', 'endpoint', 'api']):
                risks.append(SecurityRisk(
                    category="network_access",
                    severity=RiskLevel.MEDIUM,
                    description=f"Tool parameter suggests network access: {param.name}",
                    details={
                        "tool_name": tool.name,
                        "parameter": param.name,
                        "parameter_type": param.type
                    },
                    mitigation="Validate URLs and restrict network access to trusted domains"
                ))
        
        return risks
    
    def _is_cache_valid(self, result: DiscoveryResult) -> bool:
        """
        Check if cached discovery result is still valid.
        
        Args:
            result: Cached discovery result
            
        Returns:
            True if cache is valid, False otherwise
        """
        # Cache valid for 5 minutes
        cache_ttl = timedelta(minutes=5)
        return datetime.now() - result.timestamp < cache_ttl
    
    def _create_error_result(
        self,
        server_id: str,
        start_time: datetime,
        error_message: str
    ) -> DiscoveryResult:
        """
        Create error discovery result.
        
        Args:
            server_id: Server identifier
            start_time: Discovery start time
            error_message: Error description
            
        Returns:
            DiscoveryResult with error information
        """
        return DiscoveryResult(
            server_id=server_id,
            discovery_type="tools",
            timestamp=start_time,
            duration=datetime.now() - start_time,
            success=False,
            error=error_message,
            tools=[],
            security_risks=[],
            metadata={
                "error": True,
                "error_message": error_message
            }
        )
    
    def clear_cache(self, server_id: Optional[str] = None):
        """
        Clear discovery cache.
        
        Args:
            server_id: Specific server to clear, or None for all
        """
        if server_id:
            cache_key = f"tools_{server_id}"
            self._discovery_cache.pop(cache_key, None)
            logger.debug(f"Cleared tool discovery cache for {server_id}")
        else:
            self._discovery_cache.clear()
            logger.debug("Cleared all tool discovery cache") 