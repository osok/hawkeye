"""
MCP Introspection Module

This module provides Python-based MCP (Model Context Protocol) introspection
capabilities to replace the Node.js script generation approach with direct
Python MCP client connections for dynamic discovery and analysis of MCP
server capabilities.
"""

from .models import MCPServerInfo, MCPCapabilities, MCPTool, MCPResource
from .introspection import MCPIntrospection, IntrospectionConfig

# Import MCPIntrospector from the main module
import sys
from pathlib import Path

# Add the parent directory to the path to import MCPIntrospector
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

try:
    from mcp_introspection import MCPIntrospector
except ImportError:
    # Fallback: create a mock class for testing
    class MCPIntrospector:
        def __init__(self, config=None):
            pass
        
        def introspect_server(self, name, command, args):
            return None

__all__ = [
    "MCPServerInfo",
    "MCPCapabilities", 
    "MCPTool",
    "MCPResource",
    "MCPIntrospection",
    "IntrospectionConfig",
    "MCPIntrospector",
] 