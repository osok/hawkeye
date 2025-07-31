"""
MCP Version Compatibility Testing.

This module tests compatibility of the MCP introspection system across different
MCP protocol versions, ensuring backward compatibility and graceful handling
of version differences.
"""

import pytest
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType


class MCPVersionMockServer:
    """Mock server that can simulate different MCP protocol versions."""
    
    PROTOCOL_VERSIONS = {
        "2024-11-05": {
            "name": "Current Version",
            "features": ["tools", "resources", "prompts", "completion", "logging"],
            "experimental": ["sampling"]
        },
        "2024-10-07": {
            "name": "Previous Version",
            "features": ["tools", "resources", "prompts"],
            "experimental": ["completion"]
        },
        "2024-06-25": {
            "name": "Older Version", 
            "features": ["tools", "resources"],
            "experimental": []
        },
        "1.0.0": {
            "name": "Legacy Version",
            "features": ["tools"],
            "experimental": []
        }
    }
    
    @classmethod
    def create_version_script(cls, protocol_version: str, 
                            include_optional_features: bool = True,
                            include_experimental: bool = False) -> str:
        """Create a mock server script for a specific protocol version."""
        
        version_info = cls.PROTOCOL_VERSIONS.get(protocol_version, cls.PROTOCOL_VERSIONS["1.0.0"])
        features = version_info["features"]
        experimental = version_info["experimental"] if include_experimental else []
        
        # Build capabilities based on version
        capabilities = {}
        
        if "tools" in features:
            capabilities["tools"] = {"listChanged": True}
        
        if "resources" in features:
            capabilities["resources"] = {"listChanged": True, "subscribe": True}
        
        if "prompts" in features:
            capabilities["prompts"] = {"listChanged": True}
        
        if "completion" in features or "completion" in experimental:
            capabilities["completion"] = {"completionTypes": ["text"]}
        
        if "logging" in features:
            capabilities["logging"] = {}
        
        if "sampling" in experimental:
            capabilities["experimental/sampling"] = {}
        
        # Create tools based on version capabilities
        tools = []
        if "tools" in features:
            tools = [
                {
                    "name": "version_info",
                    "description": f"Get version info for {version_info['name']}",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "format": {"type": "string", "enum": ["json", "text"]}
                        }
                    }
                }
            ]
            
            # Add more tools for newer versions
            if protocol_version >= "2024-06-25":
                tools.append({
                    "name": "enhanced_feature",
                    "description": "Enhanced feature available in newer versions",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "input": {"type": "string"}
                        }
                    }
                })
        
        # Create resources based on version capabilities
        resources = []
        if "resources" in features:
            resources = [
                {
                    "uri": f"version://{protocol_version}/info",
                    "name": f"{version_info['name']} Info",
                    "description": f"Information about {version_info['name']}",
                    "mimeType": "application/json"
                }
            ]
        
        return f'''
import json
import sys

protocol_version = "{protocol_version}"
capabilities = {json.dumps(capabilities)}
tools = {json.dumps(tools)}
resources = {json.dumps(resources)}

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            # Handle version-specific initialization
            client_version = message.get("params", {{}}).get("protocolVersion", "unknown")
            
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{
                    "protocolVersion": protocol_version,
                    "capabilities": capabilities,
                    "serverInfo": {{
                        "name": "version-test-server",
                        "version": "1.0.0",
                        "protocolVersion": protocol_version,
                        "clientVersion": client_version
                    }}
                }}
            }}
            
        elif method == "tools/list":
            if "tools" not in capabilities:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {{
                        "code": -32601,
                        "message": "Method not supported in this version"
                    }}
                }}
            else:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {{"tools": tools}}
                }}
                
        elif method == "resources/list":
            if "resources" not in capabilities:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {{
                        "code": -32601,
                        "message": "Method not supported in this version"
                    }}
                }}
            else:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {{"resources": resources}}
                }}
                
        elif method == "prompts/list":
            if "prompts" not in capabilities:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {{
                        "code": -32601,
                        "message": "Method not supported in this version"
                    }}
                }}
            else:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {{"prompts": []}}
                }}
                
        elif method.startswith("experimental/"):
            if not any(exp in method for exp in {json.dumps(experimental)}):
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {{
                        "code": -32601,
                        "message": "Experimental method not supported"
                    }}
                }}
            else:
                response = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {{"experimental": True}}
                }}
                
        else:
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {{
                    "code": -32601,
                    "message": f"Method not found: {{method}}"
                }}
            }}
        
        print(json.dumps(response), flush=True)
        
    except json.JSONDecodeError:
        continue
    except KeyboardInterrupt:
        break
    except Exception as e:
        error_response = {{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {{
                "code": -32603,
                "message": f"Internal error: {{str(e)}}"
            }}
        }}
        print(json.dumps(error_response), flush=True)
'''


@pytest.mark.compatibility
class TestMCPVersionCompatibility:
    """Test compatibility across different MCP protocol versions."""
    
    @pytest.fixture
    def compatibility_introspector(self):
        """Create introspector for compatibility testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=2,
            retry_delay=0.2,
            enable_version_negotiation=True,
            fallback_to_older_versions=True
        )
        return MCPIntrospector(config=config)
    
    @pytest.mark.parametrize("protocol_version", [
        "2024-11-05",  # Current version
        "2024-10-07",  # Previous version 
        "2024-06-25",  # Older version
        "1.0.0"        # Legacy version
    ])
    def test_version_compatibility(self, compatibility_introspector, protocol_version):
        """Test compatibility with different protocol versions."""
        server_config = MCPServerConfig(
            name=f"version-test-{protocol_version}",
            command="python",
            args=["-c", MCPVersionMockServer.create_version_script(protocol_version)],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = compatibility_introspector.introspect_server(server_config)
        
        # Should successfully introspect regardless of version
        assert result is not None, f"Failed to introspect server with protocol version {protocol_version}"
        assert result.protocol_version == protocol_version
        assert result.server_name == "version-test-server"
        
        # Version-specific assertions
        version_info = MCPVersionMockServer.PROTOCOL_VERSIONS[protocol_version]
        
        if "tools" in version_info["features"]:
            assert len(result.tools) > 0, f"Expected tools for version {protocol_version}"
        else:
            assert len(result.tools) == 0, f"Unexpected tools for version {protocol_version}"
            
        if "resources" in version_info["features"]:
            assert len(result.resources) > 0, f"Expected resources for version {protocol_version}"
        else:
            assert len(result.resources) == 0, f"Unexpected resources for version {protocol_version}"
    
    def test_version_negotiation(self, compatibility_introspector):
        """Test version negotiation between client and server."""
        # Test with current version server
        current_version_config = MCPServerConfig(
            name="current-version-server",
            command="python",
            args=["-c", MCPVersionMockServer.create_version_script("2024-11-05")],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = compatibility_introspector.introspect_server(current_version_config)
        
        assert result is not None
        assert result.protocol_version == "2024-11-05"
        # Should have all modern features
        assert len(result.tools) > 0
        assert len(result.resources) > 0
    
    def test_backward_compatibility(self, compatibility_introspector):
        """Test backward compatibility with older versions."""
        # Test with legacy version
        legacy_config = MCPServerConfig(
            name="legacy-server",
            command="python", 
            args=["-c", MCPVersionMockServer.create_version_script("1.0.0")],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = compatibility_introspector.introspect_server(legacy_config)
        
        assert result is not None
        assert result.protocol_version == "1.0.0"
        
        # Should work with limited features
        assert len(result.tools) > 0  # Legacy should have basic tools
        # Resources might not be available in legacy versions
    
    def test_forward_compatibility(self, compatibility_introspector):
        """Test forward compatibility with future versions."""
        # Simulate a future version with unknown features
        future_version_script = '''
import json
import sys

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2025-12-31",  # Future version
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"listChanged": True},
                        "future_feature": {"enabled": True},
                        "experimental/quantum_tools": {"enabled": True}
                    },
                    "serverInfo": {
                        "name": "future-version-server",
                        "version": "2.0.0"
                    }
                }
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "future_tool",
                            "description": "A tool from the future",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "quantum_input": {"type": "string"}
                                }
                            }
                        }
                    ]
                }
            }
        elif method == "resources/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"resources": []}
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"}
            }
        
        print(json.dumps(response), flush=True)
        
    except Exception:
        break
'''
        
        future_config = MCPServerConfig(
            name="future-version-server",
            command="python",
            args=["-c", future_version_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = compatibility_introspector.introspect_server(future_config)
        
        # Should handle future versions gracefully
        assert result is not None
        assert result.protocol_version == "2025-12-31"
        assert result.server_name == "future-version-server"
        
        # Should still parse known features
        assert len(result.tools) > 0


@pytest.mark.compatibility
class TestFeatureCompatibility:
    """Test compatibility of specific features across versions."""
    
    @pytest.fixture
    def feature_test_introspector(self):
        """Create introspector for feature testing."""
        config = IntrospectionConfig(
            timeout=8.0,
            max_retries=1,
            retry_delay=0.1,
            enable_feature_detection=True
        )
        return MCPIntrospector(config=config)
    
    def test_tools_feature_evolution(self, feature_test_introspector):
        """Test evolution of tools feature across versions."""
        test_cases = [
            ("1.0.0", True, "Basic tools support"),
            ("2024-06-25", True, "Enhanced tools support"),
            ("2024-10-07", True, "Advanced tools support"),
            ("2024-11-05", True, "Current tools support")
        ]
        
        for version, should_have_tools, description in test_cases:
            server_config = MCPServerConfig(
                name=f"tools-test-{version}",
                command="python",
                args=["-c", MCPVersionMockServer.create_version_script(version)],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            )
            
            result = feature_test_introspector.introspect_server(server_config)
            
            assert result is not None, f"Failed to introspect {description}"
            
            if should_have_tools:
                assert len(result.tools) > 0, f"Expected tools in {description}"
                # Verify tool structure is valid
                for tool in result.tools:
                    assert tool.name is not None
                    assert tool.description is not None
                    assert tool.input_schema is not None
    
    def test_resources_feature_evolution(self, feature_test_introspector):
        """Test evolution of resources feature across versions."""
        test_cases = [
            ("1.0.0", False, "Legacy version - no resources"),
            ("2024-06-25", True, "Basic resources support"),
            ("2024-10-07", True, "Enhanced resources support"),
            ("2024-11-05", True, "Current resources support")
        ]
        
        for version, should_have_resources, description in test_cases:
            server_config = MCPServerConfig(
                name=f"resources-test-{version}",
                command="python",
                args=["-c", MCPVersionMockServer.create_version_script(version)],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            )
            
            result = feature_test_introspector.introspect_server(server_config)
            
            assert result is not None, f"Failed to introspect {description}"
            
            if should_have_resources:
                assert len(result.resources) > 0, f"Expected resources in {description}"
                # Verify resource structure is valid
                for resource in result.resources:
                    assert resource.uri is not None
                    assert resource.name is not None
                    assert resource.description is not None
            else:
                assert len(result.resources) == 0, f"Unexpected resources in {description}"
    
    def test_experimental_features_handling(self, feature_test_introspector):
        """Test handling of experimental features."""
        # Create server with experimental features
        experimental_script = '''
import json
import sys

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "experimental/sampling": {"enabled": True},
                        "experimental/future_feature": {"beta": True}
                    },
                    "serverInfo": {
                        "name": "experimental-server",
                        "version": "1.0.0-beta"
                    }
                }
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "experimental_tool",
                            "description": "An experimental tool",
                            "inputSchema": {"type": "object", "properties": {}},
                            "experimental": True
                        }
                    ]
                }
            }
        elif method.startswith("experimental/"):
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"experimental": True, "feature": method}
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"}
            }
        
        print(json.dumps(response), flush=True)
        
    except Exception:
        break
'''
        
        experimental_config = MCPServerConfig(
            name="experimental-server",
            command="python",
            args=["-c", experimental_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = feature_test_introspector.introspect_server(experimental_config)
        
        # Should handle experimental features gracefully
        assert result is not None
        assert result.server_name == "experimental-server"
        
        # Should still parse standard features
        assert len(result.tools) > 0
        
        # Experimental features should not break introspection


@pytest.mark.compatibility
class TestErrorHandlingCompatibility:
    """Test error handling across different versions."""
    
    @pytest.fixture
    def error_test_introspector(self):
        """Create introspector for error testing."""
        config = IntrospectionConfig(
            timeout=5.0,
            max_retries=1,
            retry_delay=0.1,
            enable_graceful_degradation=True
        )
        return MCPIntrospector(config=config)
    
    def test_unsupported_method_handling(self, error_test_introspector):
        """Test handling of unsupported methods in different versions."""
        # Create server that only supports basic initialize
        minimal_server_script = '''
import json
import sys

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "1.0.0",
                    "capabilities": {},  # No capabilities
                    "serverInfo": {
                        "name": "minimal-server",
                        "version": "1.0.0"
                    }
                }
            }
        else:
            # All other methods return "not found"
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        print(json.dumps(response), flush=True)
        
    except Exception:
        break
'''
        
        minimal_config = MCPServerConfig(
            name="minimal-server",
            command="python",
            args=["-c", minimal_server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = error_test_introspector.introspect_server(minimal_config)
        
        # Should handle missing methods gracefully
        assert result is not None
        assert result.server_name == "minimal-server"
        assert result.protocol_version == "1.0.0"
        
        # Should have empty tools/resources due to unsupported methods
        assert len(result.tools) == 0
        assert len(result.resources) == 0
    
    def test_malformed_version_handling(self, error_test_introspector):
        """Test handling of malformed version responses."""
        malformed_version_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())

# Return malformed version info
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "invalid.version.format",
        "capabilities": "not_an_object",  # Should be object
        "serverInfo": {
            "name": 123,  # Should be string
            "version": None  # Should be string
        }
    }
}
print(json.dumps(response))
'''
        
        malformed_config = MCPServerConfig(
            name="malformed-version-server",
            command="python",
            args=["-c", malformed_version_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = error_test_introspector.introspect_server(malformed_config)
        
        # Should handle malformed responses gracefully
        # Either succeeds with sanitized data or fails gracefully
        if result is not None:
            # If it succeeds, data should be sanitized
            assert isinstance(result.server_name, str)
            assert isinstance(result.protocol_version, str)
        # If result is None, that's also acceptable for malformed data
    
    def test_version_mismatch_handling(self, error_test_introspector):
        """Test handling of significant version mismatches."""
        # Simulate a very old version that uses different structure
        old_format_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())

# Return response in old format (simulated)
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "version": "0.1.0",  # Different field name
        "features": ["basic_tools"],  # Different structure
        "server": {  # Different nesting
            "name": "old-format-server",
            "build": "alpha"
        }
    }
}
print(json.dumps(response))
'''
        
        old_format_config = MCPServerConfig(
            name="old-format-server",
            command="python",
            args=["-c", old_format_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = error_test_introspector.introspect_server(old_format_config)
        
        # Should attempt to parse what it can or fail gracefully
        # This tests the robustness of the parsing logic
        if result is not None:
            # Should extract what information is available
            assert result.server_name is not None
        # If parsing fails completely, that's also acceptable


@pytest.mark.compatibility 
class TestCapabilityNegotiation:
    """Test capability negotiation across versions."""
    
    @pytest.fixture
    def negotiation_introspector(self):
        """Create introspector for capability negotiation testing."""
        config = IntrospectionConfig(
            timeout=8.0,
            max_retries=1,
            retry_delay=0.1,
            enable_capability_negotiation=True,
            prefer_latest_features=True
        )
        return MCPIntrospector(config=config)
    
    def test_capability_detection(self, negotiation_introspector):
        """Test detection of server capabilities."""
        # Create server with specific capabilities
        capability_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())

capabilities = {
    "tools": {"listChanged": True},
    "resources": {"listChanged": True, "subscribe": False},
    "prompts": {"listChanged": True},
    "completion": {"completionTypes": ["text"]},
    "experimental/sampling": {}
}

response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": capabilities,
        "serverInfo": {
            "name": "capability-test-server",
            "version": "1.0.0"
        }
    }
}
print(json.dumps(response))
'''
        
        capability_config = MCPServerConfig(
            name="capability-test-server",
            command="python",
            args=["-c", capability_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = negotiation_introspector.introspect_server(capability_config)
        
        assert result is not None
        assert result.server_name == "capability-test-server"
        
        # Should detect and use available capabilities
        # The exact behavior depends on implementation details
        if hasattr(result, 'capabilities'):
            assert isinstance(result.capabilities, dict)
    
    def test_graceful_capability_degradation(self, negotiation_introspector):
        """Test graceful degradation when capabilities are limited."""
        # Create server with minimal capabilities
        limited_capability_script = '''
import json
import sys

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-06-25",
                    "capabilities": {
                        "tools": {"listChanged": False}  # Limited capability
                    },
                    "serverInfo": {
                        "name": "limited-capability-server",
                        "version": "1.0.0"
                    }
                }
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "basic_tool",
                            "description": "A basic tool",
                            "inputSchema": {"type": "object"}
                        }
                    ]
                }
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"}
            }
        
        print(json.dumps(response), flush=True)
        
    except Exception:
        break
'''
        
        limited_config = MCPServerConfig(
            name="limited-capability-server",
            command="python",
            args=["-c", limited_capability_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = negotiation_introspector.introspect_server(limited_config)
        
        # Should work despite limited capabilities
        assert result is not None
        assert result.server_name == "limited-capability-server"
        
        # Should still get basic information
        assert len(result.tools) > 0


if __name__ == "__main__":
    # Allow running compatibility tests directly
    pytest.main([__file__, "-v", "-m", "compatibility"]) 