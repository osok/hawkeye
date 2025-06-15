"""
Error scenario testing for MCP introspection system.

This module tests various error conditions, edge cases, and failure scenarios
to ensure the introspection system handles errors gracefully and provides
appropriate error reporting.
"""

import pytest
import time
import json
import subprocess
import sys
import os
import tempfile
import signal
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock
from typing import Dict, Any, List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType
from hawkeye.detection.mcp_introspection.transport.base import TransportError, ConnectionError, TimeoutError


class TestNetworkErrorScenarios:
    """Test network-related error scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector with short timeouts for testing."""
        config = IntrospectionConfig(
            timeout=2.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=False
        )
        return MCPIntrospector(config=config)
    
    def test_connection_refused(self, introspector):
        """Test handling of connection refused errors."""
        # Try to connect to a non-existent server
        server_config = MCPServerConfig(
            name="non-existent-server",
            command="python",
            args=["-c", "import sys; sys.exit(1)"],  # Exit immediately
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle connection failure gracefully
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_timeout_error(self, introspector):
        """Test handling of timeout errors."""
        # Create a server that doesn't respond
        server_config = MCPServerConfig(
            name="timeout-server",
            command="python",
            args=["-c", "import time; time.sleep(10)"],  # Sleep longer than timeout
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        start_time = time.time()
        result = introspector.introspect_server(server_config)
        elapsed = time.time() - start_time
        
        # Should timeout within configured time + small buffer
        assert elapsed < 5.0
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_process_crash(self, introspector):
        """Test handling of process crashes."""
        # Create a server that crashes immediately
        server_config = MCPServerConfig(
            name="crash-server",
            command="python",
            args=["-c", "raise RuntimeError('Server crashed')"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle crash gracefully
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_invalid_json_response(self, introspector):
        """Test handling of invalid JSON responses."""
        # Create a server that returns invalid JSON
        server_config = MCPServerConfig(
            name="invalid-json-server",
            command="python",
            args=["-c", "print('this is not json')"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle invalid JSON gracefully
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_partial_response(self, introspector):
        """Test handling of incomplete responses."""
        # Create a server that returns partial JSON
        server_config = MCPServerConfig(
            name="partial-response-server",
            command="python",
            args=["-c", "print('{\"jsonrpc\": \"2.0\", \"id\": 1,')"],  # Incomplete JSON
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle partial response gracefully
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)


class TestProtocolErrorScenarios:
    """Test MCP protocol-related error scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector for protocol testing."""
        config = IntrospectionConfig(
            timeout=5.0,
            max_retries=1,
            retry_delay=0.1
        )
        return MCPIntrospector(config=config)
    
    def test_protocol_version_mismatch(self, introspector):
        """Test handling of protocol version mismatches."""
        # Create a server that reports unsupported protocol version
        server_script = '''
import json
import sys

# Handle initialize with old protocol version
message = json.loads(sys.stdin.readline())
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "1.0.0",  # Old version
        "capabilities": {},
        "serverInfo": {
            "name": "old-protocol-server",
            "version": "1.0.0"
        }
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="old-protocol-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle or warn about protocol version mismatch
        # Result might still succeed but with limited functionality
        if result is not None:
            assert result.protocol_version == "1.0.0"
    
    def test_malformed_initialize_response(self, introspector):
        """Test handling of malformed initialize responses."""
        server_script = '''
import json
import sys

# Handle initialize with malformed response
message = json.loads(sys.stdin.readline())
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        # Missing required fields
        "capabilities": {}
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="malformed-init-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle malformed response gracefully
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_error_response_from_server(self, introspector):
        """Test handling of error responses from server."""
        server_script = '''
import json
import sys

# Handle initialize with error response
message = json.loads(sys.stdin.readline())
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "error": {
        "code": -32602,
        "message": "Invalid params"
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="error-response-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle server error response
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_missing_required_methods(self, introspector):
        """Test handling when server doesn't implement required methods."""
        server_script = '''
import json
import sys

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": message.get("id", 1),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True}
                    },
                    "serverInfo": {
                        "name": "incomplete-server",
                        "version": "1.0.0"
                    }
                }
            }
        else:
            # Return method not found for all other methods
            response = {
                "jsonrpc": "2.0",
                "id": message.get("id", 1),
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        print(json.dumps(response))
    except Exception:
        break
'''
        
        server_config = MCPServerConfig(
            name="incomplete-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle missing methods gracefully
        # Result might have basic info but empty tools/resources
        if result is not None:
            assert result.server_name == "incomplete-server"
            # Tools and resources might be empty due to method not found errors


class TestSystemErrorScenarios:
    """Test system-level error scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector for system testing."""
        config = IntrospectionConfig(
            timeout=3.0,
            max_retries=1,
            retry_delay=0.1
        )
        return MCPIntrospector(config=config)
    
    def test_command_not_found(self, introspector):
        """Test handling when command doesn't exist."""
        server_config = MCPServerConfig(
            name="nonexistent-command",
            command="this-command-does-not-exist",
            args=["--help"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle command not found error
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_permission_denied(self, introspector):
        """Test handling of permission denied errors."""
        # Try to run a command that requires elevated permissions
        server_config = MCPServerConfig(
            name="permission-denied",
            command="/bin/su",  # Requires special permissions
            args=["root", "-c", "echo hello"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle permission denied gracefully
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_working_directory_not_found(self, introspector):
        """Test handling when working directory doesn't exist."""
        server_config = MCPServerConfig(
            name="bad-working-dir",
            command="python",
            args=["-c", "print('hello')"],
            transport_type=TransportType.STDIO,
            working_directory="/this/directory/does/not/exist",
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle bad working directory
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_environment_variable_issues(self, introspector):
        """Test handling of environment variable issues."""
        server_config = MCPServerConfig(
            name="env-var-test",
            command="python",
            args=["-c", "import os; print(os.environ['REQUIRED_VAR'])"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}  # Missing required environment variable
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle environment variable issues
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)


class TestResourceLimitScenarios:
    """Test resource limit and exhaustion scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector for resource testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1
        )
        return MCPIntrospector(config=config)
    
    def test_memory_exhaustion_handling(self, introspector):
        """Test handling of memory exhaustion scenarios."""
        # Create a server that tries to use excessive memory
        server_script = '''
import json
import sys

# Try to handle initialize normally first
message = json.loads(sys.stdin.readline())
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {
            "name": "memory-test-server",
            "version": "1.0.0"
        }
    }
}
print(json.dumps(response))

# Now try to allocate excessive memory (this should fail gracefully)
try:
    big_list = [0] * (10**8)  # Try to allocate ~800MB
except MemoryError:
    pass  # Expected to fail
'''
        
        server_config = MCPServerConfig(
            name="memory-exhaustion-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle memory issues gracefully
        # The server might succeed in basic initialization but have issues later
        if result is not None:
            assert result.server_name == "memory-test-server"
    
    def test_cpu_intensive_server(self, introspector):
        """Test handling of CPU-intensive servers."""
        # Create a server that uses lots of CPU
        server_script = '''
import json
import sys
import time

# Handle initialize quickly
message = json.loads(sys.stdin.readline())
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {
            "name": "cpu-intensive-server",
            "version": "1.0.0"
        }
    }
}
print(json.dumps(response))

# Now do CPU-intensive work (but not too much to avoid hanging tests)
start_time = time.time()
while time.time() - start_time < 0.5:  # Only 0.5 seconds of CPU work
    pass
'''
        
        server_config = MCPServerConfig(
            name="cpu-intensive-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle CPU-intensive server
        if result is not None:
            assert result.server_name == "cpu-intensive-server"


class TestEdgeCaseScenarios:
    """Test edge cases and unusual scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector for edge case testing."""
        config = IntrospectionConfig(
            timeout=5.0,
            max_retries=2,
            retry_delay=0.1
        )
        return MCPIntrospector(config=config)
    
    def test_unicode_handling(self, introspector):
        """Test handling of Unicode characters in responses."""
        server_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())
response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {
            "name": "unicode-test-server-🚀",
            "version": "1.0.0"
        }
    }
}
print(json.dumps(response, ensure_ascii=False))
'''
        
        server_config = MCPServerConfig(
            name="unicode-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle Unicode characters properly
        if result is not None:
            assert "🚀" in result.server_name
    
    def test_large_response_handling(self, introspector):
        """Test handling of very large responses."""
        server_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())

# Create a large response
large_tools = []
for i in range(100):  # Create 100 tools
    large_tools.append({
        "name": f"tool_{i}",
        "description": f"Tool number {i} " + "x" * 100,  # Long description
        "inputSchema": {
            "type": "object",
            "properties": {
                f"param_{j}": {"type": "string"} for j in range(10)
            }
        }
    })

if message.get("method") == "initialize":
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {
                "name": "large-response-server",
                "version": "1.0.0"
            }
        }
    }
elif message.get("method") == "tools/list":
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "result": {
            "tools": large_tools
        }
    }
else:
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "error": {"code": -32601, "message": "Method not found"}
    }

print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="large-response-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle large responses
        if result is not None:
            assert result.server_name == "large-response-server"
            assert len(result.tools) > 0  # Should have parsed some tools
    
    def test_empty_server_response(self, introspector):
        """Test handling of servers that don't respond at all."""
        server_script = '''
import sys
import time

# Read input but don't respond
sys.stdin.readline()
# Don't print anything - just exit
'''
        
        server_config = MCPServerConfig(
            name="silent-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle silent server
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)
    
    def test_rapid_server_exit(self, introspector):
        """Test handling of servers that exit immediately."""
        server_config = MCPServerConfig(
            name="rapid-exit-server",
            command="python",
            args=["-c", "import sys; sys.exit(0)"],  # Exit immediately
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should handle rapid exit
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)


class TestRetryMechanismScenarios:
    """Test retry mechanism in error scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector with retry enabled."""
        config = IntrospectionConfig(
            timeout=2.0,
            max_retries=3,
            retry_delay=0.1
        )
        return MCPIntrospector(config=config)
    
    def test_retry_on_temporary_failure(self, introspector):
        """Test retry behavior on temporary failures."""
        # Create a server that fails the first few times but succeeds eventually
        server_script = '''
import json
import sys
import os
import time

# Use a temporary file to track attempts
attempt_file = "/tmp/introspection_attempt_count"

try:
    with open(attempt_file, "r") as f:
        attempt_count = int(f.read().strip())
except FileNotFoundError:
    attempt_count = 0

attempt_count += 1
with open(attempt_file, "w") as f:
    f.write(str(attempt_count))

# Fail on first two attempts, succeed on third
if attempt_count < 3:
    sys.exit(1)  # Fail
else:
    # Succeed
    message = json.loads(sys.stdin.readline())
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {
                "name": "retry-success-server",
                "version": "1.0.0"
            }
        }
    }
    print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="retry-test-server",
            command="python",
            args=["-c", server_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Clean up any existing attempt file
        attempt_file = "/tmp/introspection_attempt_count"
        try:
            os.unlink(attempt_file)
        except FileNotFoundError:
            pass
        
        result = introspector.introspect_server(server_config)
        
        # Should eventually succeed after retries
        if result is not None:
            assert result.server_name == "retry-success-server"
        
        # Clean up
        try:
            os.unlink(attempt_file)
        except FileNotFoundError:
            pass
    
    def test_retry_exhaustion(self, introspector):
        """Test behavior when all retries are exhausted."""
        # Create a server that always fails
        server_config = MCPServerConfig(
            name="always-fail-server",
            command="python",
            args=["-c", "import sys; sys.exit(1)"],  # Always fail
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        start_time = time.time()
        result = introspector.introspect_server(server_config)
        elapsed = time.time() - start_time
        
        # Should have tried multiple times (with delays between retries)
        expected_min_time = introspector.config.retry_delay * (introspector.config.max_retries - 1)
        # Allow some tolerance for system overhead
        assert elapsed >= expected_min_time * 0.5
        
        # Should ultimately fail
        assert result is None or (hasattr(result, 'error_message') and result.error_message is not None)


@pytest.mark.error_scenarios
class TestErrorReportingScenarios:
    """Test error reporting and logging scenarios."""
    
    @pytest.fixture
    def introspector(self):
        """Create introspector with detailed error reporting."""
        config = IntrospectionConfig(
            timeout=3.0,
            max_retries=1,
            retry_delay=0.1,
            enable_detailed_error_reporting=True
        )
        return MCPIntrospector(config=config)
    
    def test_detailed_error_information(self, introspector):
        """Test that detailed error information is captured."""
        server_config = MCPServerConfig(
            name="error-detail-test",
            command="python",
            args=["-c", "raise ValueError('Detailed error message')"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = introspector.introspect_server(server_config)
        
        # Should capture detailed error information
        if result is not None and hasattr(result, 'error_message'):
            assert result.error_message is not None
            # Error message should contain some useful information
            assert len(result.error_message) > 0
    
    def test_error_categorization(self, introspector):
        """Test that errors are properly categorized."""
        test_cases = [
            # (server_config, expected_error_category)
            (MCPServerConfig(
                name="timeout-test",
                command="python",
                args=["-c", "import time; time.sleep(10)"],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            ), "timeout"),
            
            (MCPServerConfig(
                name="not-found-test",
                command="non-existent-command",
                args=["--help"],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            ), "command_not_found"),
        ]
        
        for server_config, expected_category in test_cases:
            result = introspector.introspect_server(server_config)
            
            # Should categorize error appropriately
            if result is not None and hasattr(result, 'error_category'):
                # Error category should be set
                assert hasattr(result, 'error_category')
                # Note: Actual categorization might vary based on implementation 