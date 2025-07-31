#!/usr/bin/env python3
"""
Test script for synchronous MCP introspection system.

This script tests the new synchronous implementation without async dependencies.
"""

import sys
import logging
from dataclasses import dataclass
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, 'src')

from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection, IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


@dataclass
class TestServerConfig:
    """Test server configuration."""
    server_id: str
    command: List[str]
    url: Optional[str] = None


def test_basic_introspection():
    """Test basic introspection functionality."""
    logger.info("Testing basic MCP introspection...")
    
    # Create introspection system
    config = IntrospectionConfig(
        timeout=30.0,
        enable_detailed_analysis=True,
        enable_risk_assessment=True
    )
    introspector = MCPIntrospection(config)
    
    # Create test server config
    server_config = TestServerConfig(
        server_id="test-server",
        command=["echo", '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":true}}}']
    )
    
    try:
        # Perform introspection
        result = introspector.introspect_server(server_config)
        
        logger.info(f"Introspection result:")
        logger.info(f"  Success: {result.success}")
        logger.info(f"  Duration: {result.duration.total_seconds():.2f}s")
        logger.info(f"  Servers: {result.total_servers}")
        logger.info(f"  Successful: {result.successful_servers}")
        logger.info(f"  Failed: {result.failed_servers}")
        logger.info(f"  Overall risk: {result.overall_risk_level.value}")
        
        if result.servers:
            server_info = result.servers[0]
            logger.info(f"  Server ID: {server_info.server_id}")
            logger.info(f"  Tools: {len(server_info.tools)}")
            logger.info(f"  Resources: {len(server_info.resources)}")
            logger.info(f"  Capabilities: {len(server_info.capabilities)}")
            logger.info(f"  Security risks: {len(server_info.security_risks)}")
        
        return True
        
    except Exception as e:
        logger.error(f"Introspection failed: {e}")
        return False


def test_multiple_servers():
    """Test multiple server introspection."""
    logger.info("Testing multiple server introspection...")
    
    # Create introspection system
    introspector = MCPIntrospection()
    
    # Create multiple test server configs
    server_configs = [
        TestServerConfig(
            server_id="test-server-1",
            command=["echo", '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":true}}}']
        ),
        TestServerConfig(
            server_id="test-server-2", 
            command=["echo", '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"resources":true}}}']
        ),
        TestServerConfig(
            server_id="test-server-3",
            command=["false"]  # This will fail
        )
    ]
    
    try:
        # Perform multi-server introspection
        result = introspector.introspect_multiple_servers(server_configs)
        
        logger.info(f"Multi-server introspection result:")
        logger.info(f"  Success: {result.success}")
        logger.info(f"  Duration: {result.duration.total_seconds():.2f}s")
        logger.info(f"  Total servers: {result.total_servers}")
        logger.info(f"  Successful: {result.successful_servers}")
        logger.info(f"  Failed: {result.failed_servers}")
        logger.info(f"  Overall risk: {result.overall_risk_level.value}")
        
        for i, server_info in enumerate(result.servers):
            logger.info(f"  Server {i+1}: {server_info.server_id}")
            logger.info(f"    Error: {server_info.metadata.get('error', False)}")
            if server_info.metadata.get('error'):
                logger.info(f"    Error message: {server_info.metadata.get('error_message', 'Unknown')}")
        
        return True
        
    except Exception as e:
        logger.error(f"Multi-server introspection failed: {e}")
        return False


def test_discovery_components():
    """Test individual discovery components."""
    logger.info("Testing individual discovery components...")
    
    from hawkeye.detection.mcp_introspection.discovery.tools import ToolDiscovery
    from hawkeye.detection.mcp_introspection.discovery.resources import ResourceDiscovery
    from hawkeye.detection.mcp_introspection.discovery.capabilities import CapabilityAssessment
    
    try:
        # Test tool discovery
        tool_discovery = ToolDiscovery()
        tools_result = tool_discovery.discover_tools(
            server_command=["echo", '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"test_tool","description":"A test tool"}]}}'],
            server_id="test-tools"
        )
        logger.info(f"Tool discovery: {tools_result.success}, {len(tools_result.tools)} tools")
        
        # Test resource discovery
        resource_discovery = ResourceDiscovery()
        resources_result = resource_discovery.discover_resources(
            server_command=["echo", '{"jsonrpc":"2.0","id":1,"result":{"resources":[{"uri":"file:///test","name":"test_resource"}]}}'],
            server_id="test-resources"
        )
        logger.info(f"Resource discovery: {resources_result.success}, {len(resources_result.resources)} resources")
        
        # Test capability assessment
        capability_assessment = CapabilityAssessment()
        capabilities_result = capability_assessment.assess_capabilities(
            server_command=["echo", '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{"tools":true,"resources":true}}}'],
            server_id="test-capabilities"
        )
        logger.info(f"Capability assessment: {capabilities_result.success}, {len(capabilities_result.capabilities)} capabilities")
        
        return True
        
    except Exception as e:
        logger.error(f"Discovery component test failed: {e}")
        return False


def main():
    """Run all tests."""
    logger.info("Starting synchronous MCP introspection tests...")
    
    tests = [
        ("Basic Introspection", test_basic_introspection),
        ("Multiple Servers", test_multiple_servers),
        ("Discovery Components", test_discovery_components)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        logger.info(f"\n{'='*50}")
        logger.info(f"Running test: {test_name}")
        logger.info(f"{'='*50}")
        
        try:
            if test_func():
                logger.info(f"✅ {test_name} PASSED")
                passed += 1
            else:
                logger.error(f"❌ {test_name} FAILED")
        except Exception as e:
            logger.error(f"❌ {test_name} FAILED with exception: {e}")
    
    logger.info(f"\n{'='*50}")
    logger.info(f"Test Results: {passed}/{total} tests passed")
    logger.info(f"{'='*50}")
    
    if passed == total:
        logger.info("🎉 All tests passed! Synchronous implementation is working.")
        return 0
    else:
        logger.error("❌ Some tests failed. Check the logs above.")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 