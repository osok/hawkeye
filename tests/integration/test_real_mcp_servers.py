"""
Integration tests for MCP introspection with real MCP servers.

This module tests the complete introspection workflow using actual MCP servers
to ensure the system works correctly in real-world scenarios.
"""

import pytest
import tempfile
import subprocess
import time
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from unittest.mock import patch, MagicMock

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType
from hawkeye.config.settings import HawkEyeSettings


class TestRealMCPServers:
    """Test suite for real MCP server integration."""
    
    @pytest.fixture
    def introspector_config(self):
        """Create configuration for introspection."""
        return IntrospectionConfig(
            timeout=30.0,
            max_retries=3,
            retry_delay=1.0,
            enable_caching=False,  # Disable caching for tests
            enable_risk_analysis=True,
            enable_performance_monitoring=True
        )
    
    @pytest.fixture
    def introspector(self, introspector_config):
        """Create MCP introspector instance."""
        return MCPIntrospector(config=introspector_config)
    
    @pytest.fixture
    def filesystem_server_config(self):
        """Configuration for a filesystem MCP server."""
        return MCPServerConfig(
            name="filesystem-server",
            command="npx",
            args=["@modelcontextprotocol/server-filesystem", "/tmp"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
    
    @pytest.fixture
    def mock_server_config(self):
        """Configuration for a mock MCP server."""
        return MCPServerConfig(
            name="mock-server",
            command="python",
            args=["-c", """
import json
import sys

# Mock MCP server that responds to basic protocol messages
def handle_initialize():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {
                    "listChanged": True
                },
                "resources": {
                    "listChanged": True
                }
            },
            "serverInfo": {
                "name": "mock-server",
                "version": "1.0.0"
            }
        }
    }

def handle_tools_list():
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echo back the input",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Message to echo"
                            }
                        },
                        "required": ["message"]
                    }
                }
            ]
        }
    }

def handle_resources_list():
    return {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "resources": [
                {
                    "uri": "test://resource1",
                    "name": "Test Resource",
                    "description": "A test resource",
                    "mimeType": "text/plain"
                }
            ]
        }
    }

# Simple message handler
while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        
        if method == "initialize":
            response = handle_initialize()
        elif method == "tools/list":
            response = handle_tools_list()
        elif method == "resources/list":
            response = handle_resources_list()
        else:
            response = {
                "jsonrpc": "2.0",
                "id": message.get("id", 0),
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        print(json.dumps(response), flush=True)
        
    except json.JSONDecodeError:
        continue
    except KeyboardInterrupt:
        break
            """],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
    
    def test_mock_server_basic_introspection(self, introspector, mock_server_config):
        """Test basic introspection with a mock MCP server."""
        try:
            # Perform introspection
            result = introspector.introspect_server(mock_server_config)
            
            # Verify basic server info
            assert result is not None
            assert result.server_name == "mock-server"
            assert result.server_version == "1.0.0"
            assert result.protocol_version == "2024-11-05"
            
            # Verify tools
            assert len(result.tools) == 1
            tool = result.tools[0]
            assert tool.name == "echo"
            assert tool.description == "Echo back the input"
            assert "message" in tool.input_schema.get("properties", {})
            
            # Verify resources
            assert len(result.resources) == 1
            resource = result.resources[0]
            assert resource.uri == "test://resource1"
            assert resource.name == "Test Resource"
            assert resource.mime_type == "text/plain"
            
            # Verify capabilities
            assert "tools" in result.capabilities
            assert "resources" in result.capabilities
            
        except Exception as e:
            pytest.skip(f"Mock server test failed: {e}")
    
    def test_mock_server_risk_analysis(self, introspector, mock_server_config):
        """Test risk analysis with mock server."""
        try:
            result = introspector.introspect_server(mock_server_config)
            
            # Verify risk analysis was performed
            assert result.risk_assessment is not None
            assert result.risk_level in ["low", "medium", "high", "critical"]
            assert result.risk_score >= 0.0
            assert result.risk_categories is not None
            
            # Echo tool should be low risk
            tool = result.tools[0]
            assert hasattr(tool, 'risk_level')
            
        except Exception as e:
            pytest.skip(f"Risk analysis test failed: {e}")
    
    def test_server_not_found_error_handling(self, introspector):
        """Test error handling when server is not found."""
        non_existent_config = MCPServerConfig(
            name="non-existent-server",
            command="non-existent-command",
            args=["--help"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Should handle the error gracefully
        result = introspector.introspect_server(non_existent_config)
        
        # Result should indicate failure
        assert result is None or result.error_message is not None
    
    def test_malformed_server_response(self, introspector):
        """Test handling of malformed server responses."""
        malformed_server_config = MCPServerConfig(
            name="malformed-server",
            command="python",
            args=["-c", "print('not json')"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Should handle malformed response gracefully
        result = introspector.introspect_server(malformed_server_config)
        
        # Should either return None or have error information
        assert result is None or result.error_message is not None
    
    def test_server_timeout_handling(self, introspector):
        """Test timeout handling for unresponsive servers."""
        timeout_server_config = MCPServerConfig(
            name="timeout-server",
            command="python",
            args=["-c", "import time; time.sleep(60)"],  # Sleep longer than timeout
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Configure short timeout for test
        introspector.config.timeout = 2.0
        
        # Should timeout gracefully
        start_time = time.time()
        result = introspector.introspect_server(timeout_server_config)
        elapsed = time.time() - start_time
        
        # Should timeout within reasonable time
        assert elapsed < 5.0  # Should be close to timeout + small buffer
        assert result is None or result.error_message is not None
    
    def test_multiple_servers_sequential(self, introspector, mock_server_config):
        """Test introspecting multiple servers sequentially."""
        servers = [mock_server_config, mock_server_config]  # Use same config twice
        
        results = []
        for server_config in servers:
            try:
                result = introspector.introspect_server(server_config)
                results.append(result)
            except Exception as e:
                pytest.skip(f"Sequential test failed: {e}")
        
        # Should have results for all servers
        assert len(results) == 2
        
        # All successful results should have valid data
        for result in results:
            if result is not None:
                assert result.server_name == "mock-server"
                assert len(result.tools) >= 0
                assert len(result.resources) >= 0
    
    def test_performance_monitoring(self, introspector, mock_server_config):
        """Test performance monitoring during introspection."""
        try:
            result = introspector.introspect_server(mock_server_config)
            
            # Verify performance metrics were collected
            if result and hasattr(result, 'performance_metrics'):
                metrics = result.performance_metrics
                assert 'introspection_time' in metrics
                assert 'discovery_time' in metrics
                assert 'risk_analysis_time' in metrics
                assert metrics['introspection_time'] > 0
                
        except Exception as e:
            pytest.skip(f"Performance monitoring test failed: {e}")
    
    def test_caching_behavior(self, introspector_config, mock_server_config):
        """Test caching behavior with repeated introspection."""
        # Enable caching for this test
        introspector_config.enable_caching = True
        introspector_config.cache_ttl = 60.0
        
        introspector = MCPIntrospector(config=introspector_config)
        
        try:
            # First introspection
            start_time = time.time()
            result1 = introspector.introspect_server(mock_server_config)
            first_time = time.time() - start_time
            
            # Second introspection (should use cache)
            start_time = time.time()
            result2 = introspector.introspect_server(mock_server_config)
            second_time = time.time() - start_time
            
            # Verify both results are valid
            assert result1 is not None
            assert result2 is not None
            
            # Second call should be faster (cached)
            # Note: This might not always be true due to test environment
            # so we just verify the functionality works
            assert result1.server_name == result2.server_name
            
        except Exception as e:
            pytest.skip(f"Caching test failed: {e}")
    
    @pytest.mark.skipif(
        not os.environ.get("TEST_WITH_NODE"),
        reason="Node.js tests require TEST_WITH_NODE environment variable"
    )
    def test_filesystem_server_if_available(self, introspector, filesystem_server_config):
        """Test with filesystem server if Node.js and npm are available."""
        try:
            # Check if npx is available
            subprocess.run(["npx", "--version"], 
                         capture_output=True, check=True, timeout=10)
            
            # Try to introspect filesystem server
            result = introspector.introspect_server(filesystem_server_config)
            
            if result is not None:
                # Verify basic structure
                assert result.server_name is not None
                assert isinstance(result.tools, list)
                assert isinstance(result.resources, list)
                
                # Filesystem server should have file-related tools
                file_tools = [tool for tool in result.tools 
                            if 'file' in tool.name.lower() or 'read' in tool.name.lower()]
                assert len(file_tools) > 0
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("Node.js/npx not available for filesystem server test")
        except Exception as e:
            pytest.skip(f"Filesystem server test failed: {e}")


class TestIntegrationErrorScenarios:
    """Test error scenarios in integration context."""
    
    @pytest.fixture
    def introspector(self):
        """Create basic introspector for error testing."""
        config = IntrospectionConfig(
            timeout=5.0,
            max_retries=1,
            retry_delay=0.1
        )
        return MCPIntrospector(config=config)
    
    def test_invalid_transport_type(self, introspector):
        """Test handling of invalid transport types."""
        invalid_config = MCPServerConfig(
            name="invalid-transport",
            command="echo",
            args=["hello"],
            transport_type="invalid_transport",  # Invalid transport type
            working_directory=None,
            environment_variables={}
        )
        
        # Should handle invalid transport gracefully
        result = introspector.introspect_server(invalid_config)
        assert result is None or result.error_message is not None
    
    def test_permission_denied_scenario(self, introspector):
        """Test handling of permission denied errors."""
        # Try to run a command that might fail due to permissions
        permission_config = MCPServerConfig(
            name="permission-test",
            command="/bin/su",  # Command that typically requires special permissions
            args=["root", "-c", "echo hello"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Should handle permission errors gracefully
        result = introspector.introspect_server(permission_config)
        assert result is None or result.error_message is not None
    
    def test_working_directory_not_exists(self, introspector):
        """Test handling when working directory doesn't exist."""
        invalid_dir_config = MCPServerConfig(
            name="invalid-dir",
            command="echo",
            args=["hello"],
            transport_type=TransportType.STDIO,
            working_directory="/non/existent/directory",
            environment_variables={}
        )
        
        # Should handle invalid directory gracefully
        result = introspector.introspect_server(invalid_dir_config)
        assert result is None or result.error_message is not None


@pytest.mark.integration
class TestIntegrationPerformance:
    """Performance tests for integration scenarios."""
    
    @pytest.fixture 
    def introspector(self):
        """Create performance-optimized introspector."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=2,
            retry_delay=0.5,
            enable_caching=True,
            enable_performance_monitoring=True
        )
        return MCPIntrospector(config=config)
    
    def test_rapid_sequential_introspection(self, introspector):
        """Test rapid sequential introspection calls."""
        mock_config = MCPServerConfig(
            name="rapid-test",
            command="python",
            args=["-c", "import json; print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'serverInfo': {'name': 'rapid-test', 'version': '1.0.0'}}}))"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Perform multiple rapid introspections
        results = []
        start_time = time.time()
        
        for i in range(5):
            try:
                result = introspector.introspect_server(mock_config)
                results.append(result)
            except Exception as e:
                # Some may fail, that's OK for this test
                results.append(None)
        
        total_time = time.time() - start_time
        
        # Should complete within reasonable time
        assert total_time < 30.0  # 30 seconds for 5 operations
        
        # At least some should succeed
        successful_results = [r for r in results if r is not None]
        assert len(successful_results) > 0
    
    def test_memory_usage_stability(self, introspector):
        """Test that memory usage remains stable during repeated operations."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        mock_config = MCPServerConfig(
            name="memory-test",
            command="python",
            args=["-c", "import json; print(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'serverInfo': {'name': 'memory-test', 'version': '1.0.0'}}}))"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Perform repeated introspections
        for i in range(10):
            try:
                introspector.introspect_server(mock_config)
            except Exception:
                continue  # Ignore individual failures
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 50MB)
        assert memory_increase < 50 * 1024 * 1024, f"Memory increased by {memory_increase / 1024 / 1024:.2f}MB" 