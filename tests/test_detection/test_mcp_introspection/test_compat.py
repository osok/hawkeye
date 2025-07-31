"""
Unit tests for MCP introspection backward compatibility layer.

Tests the compatibility layer that provides backward compatibility
with the old Node.js-based introspection approach.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection.compat import (
    LegacyIntrospectionResult, NodeJSCompatibilityLayer,
    LegacyMCPIntrospector, create_legacy_introspector,
    introspect_server_legacy
)
from src.hawkeye.detection.base import MCPServerInfo, ProcessInfo
from src.hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from src.hawkeye.detection.mcp_introspection.models import (
    MCPServerInfo as NewMCPServerInfo,
    MCPTool as NewMCPTool,
    MCPResource as NewMCPResource
)


class TestLegacyIntrospectionResult:
    """Test the LegacyIntrospectionResult class."""
    
    def test_result_creation_success(self):
        """Test creating a successful introspection result."""
        result = LegacyIntrospectionResult(
            success=True,
            server_name="test_server",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            tools=[{"name": "test_tool"}],
            resources=[{"uri": "file:///test.txt"}],
            capabilities={"notifications": {}},
            execution_time=1.5
        )
        
        assert result.success is True
        assert result.server_name == "test_server"
        assert result.server_version == "1.0.0"
        assert len(result.tools) == 1
        assert len(result.resources) == 1
        assert result.execution_time == 1.5
    
    def test_result_creation_failure(self):
        """Test creating a failed introspection result."""
        result = LegacyIntrospectionResult(
            success=False,
            server_name="failed_server",
            server_version="unknown",
            protocol_version="unknown",
            tools=[],
            resources=[],
            capabilities={},
            error_message="Connection failed"
        )
        
        assert result.success is False
        assert result.error_message == "Connection failed"
        assert len(result.tools) == 0


class TestNodeJSCompatibilityLayer:
    """Test the NodeJSCompatibilityLayer class."""
    
    @pytest.fixture
    def compat_layer(self):
        """Create a compatibility layer for testing."""
        config = IntrospectionConfig(timeout=30.0)
        return NodeJSCompatibilityLayer(config)
    
    @pytest.fixture
    def sample_server_info(self):
        """Create sample server info for testing."""
        return MCPServerInfo(
            name="test_server",
            path="/usr/bin/test-server"
        )
    
    @pytest.fixture
    def sample_process_info(self):
        """Create sample process info for testing."""
        return ProcessInfo(
            pid=12345,
            name="test-server",
            cmdline=["/usr/bin/test-server"],
            cwd="/home/user/test",
            environ={}
        )
    
    def test_compatibility_layer_initialization(self, compat_layer):
        """Test compatibility layer initialization."""
        assert compat_layer.config is not None
        assert compat_layer.introspection_system is not None
        assert compat_layer.config.timeout == 30.0
    
    def test_generate_introspection_script(self, compat_layer, sample_server_info, sample_process_info):
        """Test generating introspection script."""
        script = compat_layer.generate_introspection_script(sample_server_info, sample_process_info)
        
        assert isinstance(script, str)
        assert len(script) > 0
        assert "test_server" in script
    
    def test_determine_transport_type_stdio(self, compat_layer, sample_server_info, sample_process_info):
        """Test transport type determination for stdio."""
        transport_type = compat_layer._determine_transport_type(sample_server_info, sample_process_info)
        
        # Should default to stdio for local processes
        assert transport_type == "stdio"
    
    def test_determine_transport_type_http(self, compat_layer, sample_process_info):
        """Test transport type determination for HTTP."""
        http_server_info = MCPServerInfo(
            name="http_server",
            args=["--port", "8000", "--http"]
        )
        
        transport_type = compat_layer._determine_transport_type(http_server_info, sample_process_info)
        
        assert transport_type == "http"
    
    def test_determine_transport_type_sse(self, compat_layer, sample_process_info):
        """Test transport type determination for SSE."""
        sse_server_info = MCPServerInfo(
            name="sse_server",
            url="http://localhost:8000/sse"
        )
        
        transport_type = compat_layer._determine_transport_type(sse_server_info, sample_process_info)
        
        assert transport_type == "sse"
    
    def test_convert_to_server_config_stdio(self, compat_layer, sample_server_info, sample_process_info):
        """Test converting to server config for stdio transport."""
        config = compat_layer._convert_to_server_config(sample_server_info, sample_process_info)
        
        assert config.name == "test_server"
        assert config.transport_type == "stdio"
        assert config.timeout == 30.0
        assert hasattr(config, 'command')
        assert hasattr(config, 'args')
    
    def test_convert_to_server_config_http(self, compat_layer, sample_process_info):
        """Test converting to server config for HTTP transport."""
        http_server_info = MCPServerInfo(
            name="http_server",
            url="http://localhost:8000",
            args=["--http"]
        )
        
        config = compat_layer._convert_to_server_config(http_server_info, sample_process_info)
        
        assert config.name == "http_server"
        assert config.transport_type == "http"
        assert hasattr(config, 'url')
    
    def test_convert_to_legacy_result(self, compat_layer):
        """Test converting new server info to legacy result format."""
        new_tools = [
            NewMCPTool("tool1", "First tool", {"type": "object"}),
            NewMCPTool("tool2", "Second tool", {"type": "string"})
        ]
        new_resources = [
            NewMCPResource("file:///test1.txt", "test1", "Test file 1"),
            NewMCPResource("file:///test2.txt", "test2", "Test file 2")
        ]
        
        new_server_info = NewMCPServerInfo(
            server_name="test_server",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            tools=new_tools,
            resources=new_resources,
            capabilities={"notifications": {}},
            risk_assessment=None
        )
        
        legacy_result = compat_layer._convert_to_legacy_result(new_server_info, 1.5)
        
        assert legacy_result.success is True
        assert legacy_result.server_name == "test_server"
        assert legacy_result.server_version == "1.0.0"
        assert legacy_result.protocol_version == "2024-11-05"
        assert len(legacy_result.tools) == 2
        assert len(legacy_result.resources) == 2
        assert legacy_result.execution_time == 1.5
        
        # Check tool format
        tool = legacy_result.tools[0]
        assert tool["name"] == "tool1"
        assert tool["description"] == "First tool"
        assert tool["inputSchema"] == {"type": "object"}
        
        # Check resource format
        resource = legacy_result.resources[0]
        assert resource["uri"] == "file:///test1.txt"
        assert resource["name"] == "test1"
        assert resource["description"] == "Test file 1"
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.MCPIntrospection')
    def test_execute_introspection_script_success(self, mock_introspection_class, compat_layer,
                                                 sample_server_info, sample_process_info):
        """Test executing introspection script successfully."""
        # Mock the introspection result
        mock_result = Mock()
        mock_result.success = True
        mock_result.servers = [
            NewMCPServerInfo(
                server_name="test_server",
                server_version="1.0.0",
                protocol_version="2024-11-05",
                tools=[NewMCPTool("test_tool", "A test tool", {})],
                resources=[NewMCPResource("file:///test.txt", "test", "Test file")],
                capabilities={"notifications": {}},
                risk_assessment=None
            )
        ]
        mock_result.metadata = {}
        
        # Configure the mock
        mock_introspection_instance = Mock()
        mock_introspection_instance.introspect_server.return_value = mock_result
        compat_layer.introspection_system = mock_introspection_instance
        
        # Execute introspection
        script_content = "mock script content"
        result = compat_layer.execute_introspection_script(
            script_content, sample_server_info, sample_process_info
        )
        
        # Verify result
        assert result.success is True
        assert result.server_name == "test_server"
        assert len(result.tools) == 1
        assert len(result.resources) == 1
        assert result.execution_time is not None
        assert result.execution_time > 0
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.MCPIntrospection')
    def test_execute_introspection_script_failure(self, mock_introspection_class, compat_layer,
                                                 sample_server_info, sample_process_info):
        """Test executing introspection script with failure."""
        # Mock the introspection result
        mock_result = Mock()
        mock_result.success = False
        mock_result.servers = []
        mock_result.metadata = {"error": "Connection failed"}
        
        # Configure the mock
        mock_introspection_instance = Mock()
        mock_introspection_instance.introspect_server.return_value = mock_result
        compat_layer.introspection_system = mock_introspection_instance
        
        # Execute introspection
        script_content = "mock script content"
        result = compat_layer.execute_introspection_script(
            script_content, sample_server_info, sample_process_info
        )
        
        # Verify result
        assert result.success is False
        assert result.error_message == "Connection failed"
        assert len(result.tools) == 0
        assert len(result.resources) == 0
        assert result.execution_time is not None
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.MCPIntrospection')
    def test_introspect_server_legacy_success(self, mock_introspection_class, compat_layer,
                                            sample_server_info, sample_process_info):
        """Test legacy server introspection with success."""
        # Mock the introspection result
        mock_result = Mock()
        mock_result.success = True
        mock_result.servers = [
            NewMCPServerInfo(
                server_name="test_server",
                server_version="1.0.0",
                protocol_version="2024-11-05",
                tools=[NewMCPTool("test_tool", "A test tool", {})],
                resources=[],
                capabilities={},
                risk_assessment=None
            )
        ]
        mock_result.metadata = {}
        
        # Configure the mock
        mock_introspection_instance = Mock()
        mock_introspection_instance.introspect_server.return_value = mock_result
        compat_layer.introspection_system = mock_introspection_instance
        
        # Perform legacy introspection
        result = compat_layer.introspect_server_legacy(sample_server_info, sample_process_info)
        
        # Verify result
        assert result.success is True
        assert result.server_name == "test_server"
        assert len(result.tools) == 1
        assert result.execution_time is not None
    
    def test_introspect_server_legacy_exception(self, compat_layer, sample_server_info, sample_process_info):
        """Test legacy server introspection with exception."""
        # Mock the introspection system to raise an exception
        compat_layer.introspection_system = Mock()
        compat_layer.introspection_system.introspect_server.side_effect = Exception("Test exception")
        
        # Perform legacy introspection
        result = compat_layer.introspect_server_legacy(sample_server_info, sample_process_info)
        
        # Verify result
        assert result.success is False
        assert "Test exception" in result.error_message
        assert len(result.tools) == 0
        assert len(result.resources) == 0


class TestLegacyMCPIntrospector:
    """Test the LegacyMCPIntrospector class."""
    
    @pytest.fixture
    def legacy_introspector(self):
        """Create a legacy introspector for testing."""
        config = IntrospectionConfig(timeout=30.0)
        return LegacyMCPIntrospector(config)
    
    @pytest.fixture
    def sample_server_info(self):
        """Create sample server info for testing."""
        return MCPServerInfo(
            name="test_server",
            path="/usr/bin/test-server"
        )
    
    @pytest.fixture
    def sample_process_info(self):
        """Create sample process info for testing."""
        return ProcessInfo(
            pid=12345,
            name="test-server",
            cmdline=["/usr/bin/test-server"],
            cwd="/home/user/test",
            environ={}
        )
    
    def test_legacy_introspector_initialization(self, legacy_introspector):
        """Test legacy introspector initialization."""
        assert legacy_introspector.compat_layer is not None
        assert isinstance(legacy_introspector.compat_layer, NodeJSCompatibilityLayer)
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.NodeJSCompatibilityLayer')
    def test_introspect_server_success(self, mock_compat_layer_class, legacy_introspector,
                                     sample_server_info, sample_process_info):
        """Test successful server introspection through legacy interface."""
        # Mock the compatibility layer result
        mock_result = LegacyIntrospectionResult(
            success=True,
            server_name="test_server",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            tools=[{"name": "test_tool", "description": "A test tool", "inputSchema": {}}],
            resources=[{"uri": "file:///test.txt", "name": "test", "description": "Test file"}],
            capabilities={"notifications": {}},
            execution_time=1.5
        )
        
        # Configure the mock
        mock_compat_layer_instance = Mock()
        mock_compat_layer_instance.introspect_server_legacy.return_value = mock_result
        legacy_introspector.compat_layer = mock_compat_layer_instance
        
        # Perform introspection
        result = legacy_introspector.introspect_server(sample_server_info, sample_process_info)
        
        # Verify result
        assert result is not None
        assert isinstance(result, dict)
        assert result["server_name"] == "test_server"
        assert result["server_version"] == "1.0.0"
        assert result["protocol_version"] == "2024-11-05"
        assert len(result["tools"]) == 1
        assert len(result["resources"]) == 1
        assert result["execution_time"] == 1.5
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.NodeJSCompatibilityLayer')
    def test_introspect_server_failure(self, mock_compat_layer_class, legacy_introspector,
                                     sample_server_info, sample_process_info):
        """Test failed server introspection through legacy interface."""
        # Mock the compatibility layer result
        mock_result = LegacyIntrospectionResult(
            success=False,
            server_name="test_server",
            server_version="unknown",
            protocol_version="unknown",
            tools=[],
            resources=[],
            capabilities={},
            error_message="Connection failed"
        )
        
        # Configure the mock
        mock_compat_layer_instance = Mock()
        mock_compat_layer_instance.introspect_server_legacy.return_value = mock_result
        legacy_introspector.compat_layer = mock_compat_layer_instance
        
        # Perform introspection
        result = legacy_introspector.introspect_server(sample_server_info, sample_process_info)
        
        # Verify result
        assert result is None
    
    def test_generate_script(self, legacy_introspector, sample_server_info, sample_process_info):
        """Test script generation through legacy interface."""
        script = legacy_introspector.generate_script(sample_server_info, sample_process_info)
        
        assert isinstance(script, str)
        assert len(script) > 0
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.NodeJSCompatibilityLayer')
    def test_execute_script_success(self, mock_compat_layer_class, legacy_introspector,
                                   sample_server_info, sample_process_info):
        """Test script execution through legacy interface with success."""
        # Mock the compatibility layer result
        mock_result = LegacyIntrospectionResult(
            success=True,
            server_name="test_server",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            tools=[],
            resources=[],
            capabilities={},
            execution_time=1.0
        )
        
        # Configure the mock
        mock_compat_layer_instance = Mock()
        mock_compat_layer_instance.execute_introspection_script.return_value = mock_result
        legacy_introspector.compat_layer = mock_compat_layer_instance
        
        # Execute script
        script_content = "mock script"
        result = legacy_introspector.execute_script(script_content, sample_server_info, sample_process_info)
        
        # Verify result
        assert result is not None
        assert isinstance(result, dict)
        assert result["server_name"] == "test_server"
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.NodeJSCompatibilityLayer')
    def test_execute_script_failure(self, mock_compat_layer_class, legacy_introspector,
                                   sample_server_info, sample_process_info):
        """Test script execution through legacy interface with failure."""
        # Mock the compatibility layer result
        mock_result = LegacyIntrospectionResult(
            success=False,
            server_name="test_server",
            server_version="unknown",
            protocol_version="unknown",
            tools=[],
            resources=[],
            capabilities={},
            error_message="Execution failed"
        )
        
        # Configure the mock
        mock_compat_layer_instance = Mock()
        mock_compat_layer_instance.execute_introspection_script.return_value = mock_result
        legacy_introspector.compat_layer = mock_compat_layer_instance
        
        # Execute script
        script_content = "mock script"
        result = legacy_introspector.execute_script(script_content, sample_server_info, sample_process_info)
        
        # Verify result
        assert result is None


class TestConvenienceFunctions:
    """Test convenience functions for backward compatibility."""
    
    def test_create_legacy_introspector(self):
        """Test creating legacy introspector through convenience function."""
        config = IntrospectionConfig(timeout=60.0)
        introspector = create_legacy_introspector(config)
        
        assert isinstance(introspector, LegacyMCPIntrospector)
        assert introspector.compat_layer.config.timeout == 60.0
    
    def test_create_legacy_introspector_default_config(self):
        """Test creating legacy introspector with default config."""
        introspector = create_legacy_introspector()
        
        assert isinstance(introspector, LegacyMCPIntrospector)
        assert introspector.compat_layer.config is not None
    
    @patch('src.hawkeye.detection.mcp_introspection.compat.LegacyMCPIntrospector')
    def test_introspect_server_legacy_function(self, mock_introspector_class):
        """Test legacy introspection through convenience function."""
        # Mock the introspector
        mock_introspector_instance = Mock()
        mock_introspector_instance.introspect_server.return_value = {
            "server_name": "test_server",
            "tools": [],
            "resources": []
        }
        mock_introspector_class.return_value = mock_introspector_instance
        
        # Create test data
        server_info = MCPServerInfo("test_server", "/usr/bin/test")
        process_info = ProcessInfo(12345, "test", [], "/", {})
        config = IntrospectionConfig(timeout=30.0)
        
        # Perform introspection
        result = introspect_server_legacy(server_info, process_info, config)
        
        # Verify result
        assert result is not None
        assert result["server_name"] == "test_server"
        
        # Verify introspector was created and called correctly
        mock_introspector_class.assert_called_once_with(config)
        mock_introspector_instance.introspect_server.assert_called_once_with(server_info, process_info)


class TestIntegrationScenarios:
    """Test integration scenarios for backward compatibility."""
    
    def test_end_to_end_compatibility(self):
        """Test end-to-end compatibility workflow."""
        # Create components
        config = IntrospectionConfig(timeout=30.0)
        compat_layer = NodeJSCompatibilityLayer(config)
        
        server_info = MCPServerInfo("test_server", "/usr/bin/test")
        process_info = ProcessInfo(12345, "test", [], "/", {})
        
        # Test script generation
        script = compat_layer.generate_introspection_script(server_info, process_info)
        assert isinstance(script, str)
        assert len(script) > 0
        
        # Test transport type determination
        transport_type = compat_layer._determine_transport_type(server_info, process_info)
        assert transport_type in ["stdio", "http", "sse"]
        
        # Test server config conversion
        server_config = compat_layer._convert_to_server_config(server_info, process_info)
        assert server_config.name == "test_server"
        assert server_config.transport_type == transport_type
    
    def test_error_handling_robustness(self):
        """Test error handling robustness across compatibility layer."""
        config = IntrospectionConfig(timeout=1.0)  # Short timeout for testing
        compat_layer = NodeJSCompatibilityLayer(config)
        
        # Test with invalid server info
        invalid_server = MCPServerInfo("invalid", "/nonexistent/path")
        invalid_process = ProcessInfo(99999, "invalid", [], "/", {})
        
        # Should handle gracefully
        script = compat_layer.generate_introspection_script(invalid_server, invalid_process)
        assert isinstance(script, str)
        
        transport_type = compat_layer._determine_transport_type(invalid_server, invalid_process)
        assert transport_type in ["stdio", "http", "sse"]
        
        # Execution may fail, but should return proper error result
        result = compat_layer.introspect_server_legacy(invalid_server, invalid_process)
        assert isinstance(result, LegacyIntrospectionResult)
        # Result may be success or failure depending on actual execution


if __name__ == "__main__":
    pytest.main([__file__]) 