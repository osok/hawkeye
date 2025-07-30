#!/usr/bin/env python3
"""
Debug script to test server config conversion from detection results
"""

import logging
from src.hawkeye.detection.mcp_introspection import MCPIntrospector
from src.hawkeye.detection.base import MCPServerInfo, ProcessInfo, TransportType

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Enable debug logging for the introspection system  
logging.getLogger('src.hawkeye.detection.mcp_introspection').setLevel(logging.DEBUG)
logging.getLogger('hawkeye.hawkeye.detection.mcp_introspection').setLevel(logging.DEBUG)
logging.getLogger().setLevel(logging.DEBUG)

def debug_server_config_conversion():
    """Debug server config conversion"""
    
    # Create mock detection result using the legacy MCPServerInfo from detection/base.py
    server_info = MCPServerInfo(
        host="192.168.100.3",
        port=3001,
        transport_type=TransportType.HTTP,
        version="2024-11-05",
        capabilities=[],
        tools=[],
        resources=[],
        security_config={}
    )
    
    # Create mock process info
    process_info = ProcessInfo(
        pid=12345,
        name="node",
        cmdline=["node", "server.js"],
        cwd="/tmp",
        env_vars={}
    )
    
    print(f"=== Debug Server Config Conversion ===")
    print(f"Legacy Server Info:")
    print(f"  host: {server_info.host}")
    print(f"  port: {server_info.port}")
    print(f"  transport_type: {server_info.transport_type}")
    print(f"  Available attributes: {list(server_info.__dict__.keys())}")
    print()
    
    # Create introspector and test conversion
    introspector = MCPIntrospector()
    
    print(f"MCPIntrospector methods: {[method for method in dir(introspector) if not method.startswith('__')]}")
    print(f"MCPIntrospector class: {introspector.__class__}")
    print(f"MCPIntrospector module: {introspector.__class__.__module__}")
    print()
    
    try:
        # Test the introspect_server method instead 
        print("Trying introspect_server method...")
        
        # Add more debugging
        print(f"  server_info type: {type(server_info)}")
        print(f"  process_info type: {type(process_info)}")
        print(f"  server_info.host: {getattr(server_info, 'host', 'MISSING')}")
        print(f"  server_info.port: {getattr(server_info, 'port', 'MISSING')}")
        print(f"  process_info.pid: {getattr(process_info, 'pid', 'MISSING')}")
        
        result = introspector.introspect_server(server_info, process_info)
        
        print(f"Introspection Result:")
        print(f"  Success: {result is not None}")
        if result:
            print(f"  Result type: {type(result)}")
            print(f"  Result details: {result}")
        else:
            print("  Result is None")
            
    except Exception as e:
        print(f"❌ Introspection failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_server_config_conversion() 