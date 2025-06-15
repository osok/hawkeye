"""
Mock MCP Servers for Testing.

This module provides mock MCP servers that implement the MCP protocol
for controlled testing scenarios. These servers can simulate various
capabilities, error conditions, and edge cases.
"""

import json
import sys
import time
import threading
import subprocess
import tempfile
import signal
import os
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import uuid


class MockServerType(Enum):
    """Types of mock servers available."""
    BASIC = "basic"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    CODE_EXECUTION = "code_execution"
    HIGH_RISK = "high_risk"
    ERROR_PRONE = "error_prone"
    SLOW_RESPONSE = "slow_response"
    RESOURCE_HEAVY = "resource_heavy"
    MINIMAL = "minimal"


@dataclass
class MockTool:
    """Mock MCP tool definition."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    risk_level: str = "low"
    
    def to_mcp_format(self) -> Dict[str, Any]:
        """Convert to MCP protocol format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema
        }


@dataclass
class MockResource:
    """Mock MCP resource definition."""
    uri: str
    name: str
    description: str
    mime_type: Optional[str] = None
    
    def to_mcp_format(self) -> Dict[str, Any]:
        """Convert to MCP protocol format."""
        resource = {
            "uri": self.uri,
            "name": self.name,
            "description": self.description
        }
        if self.mime_type:
            resource["mimeType"] = self.mime_type
        return resource


@dataclass
class MockServerConfig:
    """Configuration for mock MCP server."""
    name: str
    version: str
    protocol_version: str = "2024-11-05"
    tools: List[MockTool] = None
    resources: List[MockResource] = None
    capabilities: Dict[str, Any] = None
    delay_ms: int = 0
    error_rate: float = 0.0
    memory_leak: bool = False
    
    def __post_init__(self):
        if self.tools is None:
            self.tools = []
        if self.resources is None:
            self.resources = []
        if self.capabilities is None:
            self.capabilities = {
                "tools": {"listChanged": True},
                "resources": {"listChanged": True}
            }


class MockMCPServer:
    """Base class for mock MCP servers."""
    
    def __init__(self, config: MockServerConfig):
        self.config = config
        self.message_id = 0
        self.running = False
        
    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP message."""
        method = message.get("method")
        msg_id = message.get("id", 0)
        
        # Simulate delay if configured
        if self.config.delay_ms > 0:
            time.sleep(self.config.delay_ms / 1000.0)
        
        # Simulate errors if configured
        if self.config.error_rate > 0:
            import random
            if random.random() < self.config.error_rate:
                return self._error_response(msg_id, -32603, "Internal error (simulated)")
        
        # Route message to handler
        if method == "initialize":
            return self._handle_initialize(msg_id, message.get("params", {}))
        elif method == "tools/list":
            return self._handle_tools_list(msg_id)
        elif method == "resources/list":
            return self._handle_resources_list(msg_id)
        elif method == "tools/call":
            return self._handle_tool_call(msg_id, message.get("params", {}))
        elif method == "resources/read":
            return self._handle_resource_read(msg_id, message.get("params", {}))
        else:
            return self._error_response(msg_id, -32601, f"Method not found: {method}")
    
    def _handle_initialize(self, msg_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": self.config.protocol_version,
                "capabilities": self.config.capabilities,
                "serverInfo": {
                    "name": self.config.name,
                    "version": self.config.version
                }
            }
        }
    
    def _handle_tools_list(self, msg_id: int) -> Dict[str, Any]:
        """Handle tools/list request."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [tool.to_mcp_format() for tool in self.config.tools]
            }
        }
    
    def _handle_resources_list(self, msg_id: int) -> Dict[str, Any]:
        """Handle resources/list request."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "resources": [resource.to_mcp_format() for resource in self.config.resources]
            }
        }
    
    def _handle_tool_call(self, msg_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request."""
        tool_name = params.get("name")
        # Simple mock implementation - just echo the call
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Mock response from tool '{tool_name}'"
                    }
                ]
            }
        }
    
    def _handle_resource_read(self, msg_id: int, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle resources/read request."""
        uri = params.get("uri")
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": f"Mock content for resource {uri}"
                    }
                ]
            }
        }
    
    def _error_response(self, msg_id: int, code: int, message: str) -> Dict[str, Any]:
        """Create error response."""
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message
            }
        }
    
    def run_stdio(self):
        """Run server using stdio transport."""
        self.running = True
        
        try:
            while self.running:
                line = sys.stdin.readline()
                if not line:
                    break
                
                try:
                    message = json.loads(line.strip())
                    response = self.handle_message(message)
                    print(json.dumps(response), flush=True)
                    
                    # Simulate memory leak if configured
                    if self.config.memory_leak:
                        # Create some data that won't be garbage collected
                        setattr(self, f"leak_{uuid.uuid4()}", [0] * 1000)
                        
                except json.JSONDecodeError:
                    continue
                except KeyboardInterrupt:
                    break
                    
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False


class MockServerFactory:
    """Factory for creating pre-configured mock servers."""
    
    @staticmethod
    def create_basic_server() -> MockServerConfig:
        """Create a basic mock server with minimal capabilities."""
        return MockServerConfig(
            name="basic-mock-server",
            version="1.0.0",
            tools=[
                MockTool(
                    name="echo",
                    description="Echo back the input",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Message to echo"
                            }
                        },
                        "required": ["message"]
                    },
                    risk_level="low"
                )
            ],
            resources=[
                MockResource(
                    uri="test://basic-resource",
                    name="Basic Resource",
                    description="A basic test resource",
                    mime_type="text/plain"
                )
            ]
        )
    
    @staticmethod
    def create_filesystem_server() -> MockServerConfig:
        """Create a mock filesystem server with file operations."""
        return MockServerConfig(
            name="filesystem-mock-server",
            version="1.2.0",
            tools=[
                MockTool(
                    name="read_file",
                    description="Read contents of a file",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file"
                            }
                        },
                        "required": ["path"]
                    },
                    risk_level="high"
                ),
                MockTool(
                    name="write_file",
                    description="Write contents to a file",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["path", "content"]
                    },
                    risk_level="high"
                ),
                MockTool(
                    name="list_directory",
                    description="List directory contents",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"}
                        },
                        "required": ["path"]
                    },
                    risk_level="medium"
                )
            ],
            resources=[
                MockResource(
                    uri="file:///tmp/test.txt",
                    name="Test File",
                    description="A test file",
                    mime_type="text/plain"
                ),
                MockResource(
                    uri="file:///home/user/documents",
                    name="Documents Directory",
                    description="User documents directory",
                    mime_type="inode/directory"
                )
            ]
        )
    
    @staticmethod
    def create_high_risk_server() -> MockServerConfig:
        """Create a mock server with multiple high-risk capabilities."""
        return MockServerConfig(
            name="high-risk-mock-server",
            version="3.0.0-beta",
            tools=[
                MockTool(
                    name="system_admin",
                    description="Perform system administration tasks",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "action": {"type": "string"},
                            "parameters": {"type": "object"}
                        },
                        "required": ["action"]
                    },
                    risk_level="critical"
                )
            ],
            resources=[
                MockResource(
                    uri="system://admin",
                    name="System Administration",
                    description="System administration interface",
                    mime_type="application/x-system"
                )
            ]
        )


def get_mock_server_configs() -> Dict[str, MockServerConfig]:
    """Get all available mock server configurations."""
    return {
        MockServerType.BASIC.value: MockServerFactory.create_basic_server(),
        MockServerType.FILESYSTEM.value: MockServerFactory.create_filesystem_server(),
        MockServerType.HIGH_RISK.value: MockServerFactory.create_high_risk_server(),
    }


# Main entry point for running mock servers directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run mock MCP server")
    parser.add_argument("--type", choices=[t.value for t in MockServerType], 
                       default=MockServerType.BASIC.value,
                       help="Type of mock server to run")
    
    args = parser.parse_args()
    
    # Create and run server
    configs = get_mock_server_configs()
    config = configs[args.type]
    server = MockMCPServer(config)
    
    try:
        server.run_stdio()
    except KeyboardInterrupt:
        pass 