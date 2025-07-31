#!/usr/bin/env python3

import asyncio
import sys
import os
sys.path.append('src')

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.base import MCPServerInfo, ProcessInfo

async def test_introspection():
    """Test MCP introspection with the filesystem server."""
    
    # Create a test process info for the filesystem server
    process_info = ProcessInfo(
        pid=1460340,
        name='node',
        cmdline=['node', '/usr/bin/mcp-server-filesystem', '/ai/work/cursor/mcp-hunt'],
        cwd='/ai/work/agents'
    )

    server_info = MCPServerInfo(host='localhost')

    introspector = MCPIntrospector()
    print("🔍 Testing MCP Server Introspection...")
    print(f"Target: {' '.join(process_info.cmdline)}")
    print()
    
    try:
        capabilities = await introspector.introspect_server(server_info, process_info)
        
        if capabilities:
            print('✅ MCP Server Introspection Results')
            print('=' * 50)
            print(f'Server Name: {capabilities.server_name}')
            print(f'Version: {capabilities.server_version}')
            print(f'Protocol: {capabilities.protocol_version}')
            print(f'Tool Count: {capabilities.tool_count}')
            print(f'Resource Count: {capabilities.resource_count}')
            print(f'Capability Categories: {", ".join(capabilities.capability_categories)}')
            print(f'Highest Risk Level: {capabilities.highest_risk_level}')
            print(f'Has External Access: {capabilities.has_external_access}')
            print(f'Has File Access: {capabilities.has_file_access}')
            print(f'Has Code Execution: {capabilities.has_code_execution}')
            print()
            
            print('🛠️  Available Tools:')
            for i, tool in enumerate(capabilities.tools, 1):
                print(f'  {i:2d}. {tool.name}')
                print(f'      Description: {tool.description}')
                print(f'      Category: {tool.capability_category}')
                print(f'      Risk Level: {tool.risk_level}')
                print()
            
            if capabilities.resources:
                print('📁 Available Resources:')
                for i, resource in enumerate(capabilities.resources, 1):
                    print(f'  {i:2d}. {resource.name}')
                    print(f'      URI: {resource.uri}')
                    print(f'      Description: {resource.description}')
                    print(f'      MIME Type: {resource.mime_type}')
                    print()
            
            # Generate summary for reporting
            summary = introspector.generate_server_summary(capabilities)
            print('📊 Summary for Reporting:')
            print(f'  - Server can be categorized as: {summary["risk_level"]} risk')
            print(f'  - Primary capabilities: {", ".join(summary["capability_categories"])}')
            print(f'  - Security concerns: {"External access" if summary["has_external_access"] else "Local only"}, {"File access" if summary["has_file_access"] else "No file access"}, {"Code execution" if summary["has_code_execution"] else "No code execution"}')
            
        else:
            print('❌ Introspection failed - could not discover server capabilities')
            
    except Exception as e:
        print(f'❌ Error during introspection: {e}')

if __name__ == '__main__':
    asyncio.run(test_introspection()) 