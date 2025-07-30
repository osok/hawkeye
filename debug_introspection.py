#!/usr/bin/env python3
"""
Debug script to test MCP introspection directly
"""

import asyncio
import logging
from src.hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType
from src.hawkeye.detection.mcp_introspection.mcp_client import MCPClient, MCPClientConfig

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def debug_introspection():
    """Debug MCP introspection with filesystem server"""
    
    # Create server config for filesystem MCP server
    server_config = MCPServerConfig(
        server_id="filesystem-debug",
        transport_type=TransportType.HTTP,
        url="http://192.168.100.3:3001",
        host="192.168.100.3",
        port=3001
    )
    
    print(f"Testing introspection of server: {server_config.server_id}")
    print(f"URL: {server_config.url}")
    print(f"Transport: {server_config.transport_type}")
    
    # Create MCP client
    client_config = MCPClientConfig(
        timeout=30.0,
        max_retries=3,
        enable_tool_testing=False,
        enable_resource_enumeration=True,
        enable_capability_detection=True
    )
    
    client = MCPClient(client_config)
    
    try:
        # Test introspection
        print("\n=== Starting Introspection ===")
        result = await client.introspect_server(server_config)
        
        print(f"Introspection result: {result}")
        print(f"Success: {result.success}")
        
        if result.success and result.servers:
            server_info = result.servers[0]
            print(f"Server info: {server_info}")
            print(f"Tools found: {len(server_info.tools)}")
            
            for i, tool in enumerate(server_info.tools):
                print(f"  Tool {i+1}: {tool.name} - {tool.description}")
        else:
            print(f"Introspection failed. Error: {result.metadata}")
        
    except Exception as e:
        print(f"Exception during introspection: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        await client.disconnect_all()

if __name__ == "__main__":
    asyncio.run(debug_introspection()) 