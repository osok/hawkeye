"""
Backward Compatibility Layer for MCP Introspection

This module provides backward compatibility with the old Node.js-based
introspection approach while using the new Python-based system underneath.
"""

import json
import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ..base import MCPServerInfo, ProcessInfo
from .introspection import MCPIntrospection, IntrospectionConfig
from .models import MCPServerConfig, MCPServerInfo as NewMCPServerInfo
from ...utils.logging import get_logger


logger = get_logger(__name__)


@dataclass
class LegacyIntrospectionResult:
    """Legacy format for introspection results."""
    success: bool
    server_name: str
    server_version: str
    protocol_version: str
    tools: List[Dict[str, Any]]
    resources: List[Dict[str, Any]]
    capabilities: Dict[str, Any]
    error_message: Optional[str] = None
    execution_time: Optional[float] = None


class NodeJSCompatibilityLayer:
    """
    Provides compatibility with the old Node.js-based introspection approach.
    
    This class mimics the behavior of the old Node.js script generation
    while using the new Python-based introspection system underneath.
    """
    
    def __init__(self, config: Optional[IntrospectionConfig] = None):
        """Initialize the compatibility layer."""
        self.logger = get_logger(__name__)
        self.config = config or IntrospectionConfig()
        self.introspection_system = MCPIntrospection(self.config)
        
        self.logger.info("NodeJS compatibility layer initialized")
    
    def generate_introspection_script(self, server_info: MCPServerInfo, 
                                    process_info: ProcessInfo) -> str:
        """Generate a Node.js introspection script (legacy compatibility)."""
        try:
            transport_type = self._determine_transport_type(server_info, process_info)
            
            script_content = f'''
const {{ Client }} = require('@modelcontextprotocol/sdk/client/index.js');

async function introspectServer() {{
    // Legacy script for {server_info.name} ({transport_type})
    // This is now handled by Python introspection system
    console.log(JSON.stringify({{
        success: true,
        serverName: '{server_info.name}',
        message: 'Using Python introspection system'
    }}));
}}

introspectServer().catch(console.error);
'''
            
            self.logger.debug(f"Generated {transport_type} introspection script for {server_info.name}")
            return script_content
            
        except Exception as e:
            self.logger.error(f"Failed to generate introspection script: {e}")
            return 'console.log(JSON.stringify({success: false, error: "Script generation failed"}));'
    
    def execute_introspection_script(self, script_content: str, 
                                   server_info: MCPServerInfo,
                                   process_info: ProcessInfo) -> LegacyIntrospectionResult:
        """Execute introspection script (legacy compatibility)."""
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing introspection for {server_info.name} (PID: {process_info.pid})")
            
            # Convert to new format and use Python introspection
            server_config = self._convert_to_server_config(server_info, process_info)
            
            # Perform introspection using the new system
            result = self.introspection_system.introspect_server(server_config)
            
            execution_time = time.time() - start_time
            
            if result.success and result.servers:
                new_server_info = result.servers[0]
                return self._convert_to_legacy_result(new_server_info, execution_time)
            else:
                error_msg = result.metadata.get('error', 'Unknown error')
                return LegacyIntrospectionResult(
                    success=False,
                    server_name=server_info.name,
                    server_version="unknown",
                    protocol_version="unknown",
                    tools=[],
                    resources=[],
                    capabilities={},
                    error_message=error_msg,
                    execution_time=execution_time
                )
                
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Introspection execution failed: {e}")
            return LegacyIntrospectionResult(
                success=False,
                server_name=server_info.name,
                server_version="unknown",
                protocol_version="unknown",
                tools=[],
                resources=[],
                capabilities={},
                error_message=str(e),
                execution_time=execution_time
            )
    
    def introspect_server_legacy(self, server_info: MCPServerInfo, 
                               process_info: ProcessInfo) -> LegacyIntrospectionResult:
        """Perform server introspection using legacy interface."""
        try:
            # Step 1: Generate script (for compatibility)
            script_content = self.generate_introspection_script(server_info, process_info)
            
            # Step 2: Execute script (actually uses Python introspection)
            result = self.execute_introspection_script(script_content, server_info, process_info)
            
            self.logger.info(
                f"Legacy introspection completed for {server_info.name}: "
                f"success={result.success}, tools={len(result.tools)}, "
                f"resources={len(result.resources)}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Legacy introspection failed for {server_info.name}: {e}")
            return LegacyIntrospectionResult(
                success=False,
                server_name=server_info.name,
                server_version="unknown",
                protocol_version="unknown",
                tools=[],
                resources=[],
                capabilities={},
                error_message=str(e)
            )
    
    def _determine_transport_type(self, server_info: MCPServerInfo, 
                                process_info: ProcessInfo) -> str:
        """Determine the transport type based on server information."""
        # Check for HTTP/HTTPS URLs
        if hasattr(server_info, 'url') and server_info.url:
            if 'sse' in server_info.url.lower() or 'events' in server_info.url.lower():
                return "sse"
            else:
                return "http"
        
        # Check for command line arguments that suggest HTTP
        if hasattr(server_info, 'args') and server_info.args:
            args_str = ' '.join(str(arg) for arg in server_info.args)
            if '--port' in args_str or '--http' in args_str:
                return "http"
            if '--sse' in args_str or '--events' in args_str:
                return "sse"
        
        # Default to stdio for local processes
        return "stdio"
    
    def _convert_to_server_config(self, server_info: MCPServerInfo, 
                                process_info: ProcessInfo) -> MCPServerConfig:
        """Convert legacy server info to new server config format."""
        transport_type = self._determine_transport_type(server_info, process_info)
        
        config_data = {
            "name": server_info.name,
            "transport_type": transport_type,
            "timeout": self.config.timeout
        }
        
        if transport_type == "stdio":
            config_data.update({
                "command": getattr(server_info, 'path', ''),
                "args": getattr(server_info, 'args', []),
                "env": getattr(server_info, 'env', {}),
                "cwd": getattr(server_info, 'cwd', None)
            })
        elif transport_type in ["http", "sse"]:
            config_data.update({
                "url": getattr(server_info, 'url', f"http://localhost:8000"),
                "headers": getattr(server_info, 'headers', {}),
                "auth": getattr(server_info, 'auth', None)
            })
        
        return MCPServerConfig(**config_data)
    
    def _convert_to_legacy_result(self, new_server_info: NewMCPServerInfo, 
                                execution_time: float) -> LegacyIntrospectionResult:
        """Convert new server info to legacy result format."""
        # Convert tools to legacy format
        legacy_tools = []
        for tool in new_server_info.tools:
            legacy_tools.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema
            })
        
        # Convert resources to legacy format
        legacy_resources = []
        for resource in new_server_info.resources:
            legacy_resources.append({
                "uri": resource.uri,
                "name": resource.name,
                "description": resource.description,
                "mimeType": resource.mime_type
            })
        
        return LegacyIntrospectionResult(
            success=True,
            server_name=new_server_info.server_name,
            server_version=new_server_info.server_version,
            protocol_version=new_server_info.protocol_version,
            tools=legacy_tools,
            resources=legacy_resources,
            capabilities=new_server_info.capabilities,
            execution_time=execution_time
        )


class LegacyMCPIntrospector:
    """
    Legacy wrapper for the MCPIntrospector class.
    
    This class provides the exact same interface as the old MCPIntrospector
    but uses the new Python-based system underneath.
    """
    
    def __init__(self, config: Optional[IntrospectionConfig] = None):
        """Initialize the legacy introspector."""
        self.logger = get_logger(__name__)
        self.compat_layer = NodeJSCompatibilityLayer(config)
        
        self.logger.info("Legacy MCPIntrospector initialized")
    
    def introspect_server(self, server_info: MCPServerInfo, 
                         process_info: ProcessInfo) -> Optional[Dict[str, Any]]:
        """Introspect server using legacy interface."""
        result = self.compat_layer.introspect_server_legacy(server_info, process_info)
        
        if result.success:
            return {
                "server_name": result.server_name,
                "server_version": result.server_version,
                "protocol_version": result.protocol_version,
                "tools": result.tools,
                "resources": result.resources,
                "capabilities": result.capabilities,
                "execution_time": result.execution_time
            }
        else:
            self.logger.error(f"Legacy introspection failed: {result.error_message}")
            return None
    
    def generate_script(self, server_info: MCPServerInfo, 
                       process_info: ProcessInfo) -> str:
        """Generate introspection script (legacy compatibility)."""
        return self.compat_layer.generate_introspection_script(server_info, process_info)
    
    def execute_script(self, script_content: str, server_info: MCPServerInfo,
                      process_info: ProcessInfo) -> Optional[Dict[str, Any]]:
        """Execute introspection script (legacy compatibility)."""
        result = self.compat_layer.execute_introspection_script(
            script_content, server_info, process_info
        )
        
        if result.success:
            return {
                "server_name": result.server_name,
                "server_version": result.server_version,
                "protocol_version": result.protocol_version,
                "tools": result.tools,
                "resources": result.resources,
                "capabilities": result.capabilities,
                "execution_time": result.execution_time
            }
        else:
            return None


# Convenience functions for backward compatibility
def create_legacy_introspector(config: Optional[IntrospectionConfig] = None) -> LegacyMCPIntrospector:
    """Create a legacy introspector instance."""
    return LegacyMCPIntrospector(config)


def introspect_server_legacy(server_info: MCPServerInfo, process_info: ProcessInfo,
                           config: Optional[IntrospectionConfig] = None) -> Optional[Dict[str, Any]]:
    """Perform legacy server introspection."""
    introspector = create_legacy_introspector(config)
    return introspector.introspect_server(server_info, process_info) 