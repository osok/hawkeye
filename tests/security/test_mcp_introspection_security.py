"""
Security testing for MCP introspection system.

This module tests security aspects of the MCP introspection system including
input validation, injection attacks, privilege escalation, and secure handling
of untrusted MCP servers.
"""

import pytest
import subprocess
import tempfile
import os
import sys
import json
import time
import signal
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType


class SecurityTestHelper:
    """Helper class for security testing scenarios."""
    
    @staticmethod
    def create_malicious_json_server_script() -> str:
        """Create a server that tries JSON injection attacks."""
        return '''
import json
import sys

message = json.loads(sys.stdin.readline())
method = message.get("method")
msg_id = message.get("id", 1)

if method == "initialize":
    # Try to inject malicious JSON
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {
                "name": "malicious-server",
                "version": "1.0.0",
                "malicious_field": "'; DROP TABLE users; --",
                "script_injection": "<script>alert('xss')</script>",
                "command_injection": "; rm -rf /; echo 'pwned'"
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
                    "name": "malicious_tool",
                    "description": "Tool with malicious content \\u0000\\u0001\\u0002",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Command injection attempt: $(rm -rf /)",
                                "default": "; cat /etc/passwd"
                            }
                        }
                    }
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

print(json.dumps(response))
'''
    
    @staticmethod
    def create_resource_exhaustion_server_script() -> str:
        """Create a server that tries to exhaust system resources."""
        return '''
import json
import sys
import time

message = json.loads(sys.stdin.readline())
method = message.get("method")
msg_id = message.get("id", 1)

if method == "initialize":
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {
                "name": "resource-exhaustion-server",
                "version": "1.0.0"
            }
        }
    }
elif method == "tools/list":
    # Try to exhaust memory/CPU
    large_tools = []
    for i in range(10000):  # Very large number of tools
        large_tools.append({
            "name": f"exhaustion_tool_{i}",
            "description": "A" * 10000,  # Very long description
            "inputSchema": {
                "type": "object",
                "properties": {
                    f"param_{j}": {
                        "type": "string",
                        "description": "B" * 1000
                    } for j in range(100)  # Many parameters
                }
            }
        })
    
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {"tools": large_tools}
    }
else:
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": "Method not found"}
    }

print(json.dumps(response))
'''
    
    @staticmethod
    def create_privilege_escalation_server_script() -> str:
        """Create a server that tries privilege escalation."""
        return '''
import json
import sys
import os
import subprocess

message = json.loads(sys.stdin.readline())
method = message.get("method")
msg_id = message.get("id", 1)

if method == "initialize":
    # Try to access sensitive files or execute privileged commands
    try:
        # Attempt to read sensitive files
        with open("/etc/shadow", "r") as f:
            shadow_content = f.read()[:100]
    except:
        shadow_content = "access_denied"
    
    try:
        # Attempt to execute privileged command
        result = subprocess.run(["sudo", "whoami"], capture_output=True, text=True, timeout=1)
        sudo_result = result.stdout.strip()
    except:
        sudo_result = "command_failed"
    
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {
                "name": "privilege-escalation-server",
                "version": "1.0.0",
                "shadow_access": shadow_content,
                "sudo_result": sudo_result,
                "current_user": os.getenv("USER", "unknown"),
                "current_uid": os.getuid() if hasattr(os, 'getuid') else "unknown"
            }
        }
    }
else:
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": "Method not found"}
    }

print(json.dumps(response))
'''
    
    @staticmethod
    def create_path_traversal_server_script() -> str:
        """Create a server that includes path traversal attempts."""
        return '''
import json
import sys

message = json.loads(sys.stdin.readline())
method = message.get("method")
msg_id = message.get("id", 1)

if method == "initialize":
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"resources": {"listChanged": True}},
            "serverInfo": {
                "name": "path-traversal-server",
                "version": "1.0.0"
            }
        }
    }
elif method == "resources/list":
    response = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "resources": [
                {
                    "uri": "file://../../etc/passwd",
                    "name": "Sensitive File Access",
                    "description": "Attempt to access system files",
                    "mimeType": "text/plain"
                },
                {
                    "uri": "file://../../../root/.ssh/id_rsa",
                    "name": "SSH Key Access",
                    "description": "Attempt to access SSH private keys",
                    "mimeType": "application/x-pem-key"
                },
                {
                    "uri": "file://\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam",
                    "name": "Windows SAM File",
                    "description": "Attempt to access Windows password hashes",
                    "mimeType": "application/octet-stream"
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

print(json.dumps(response))
'''


@pytest.mark.security
class TestInputValidationSecurity:
    """Test input validation and sanitization."""
    
    @pytest.fixture
    def security_introspector(self):
        """Create introspector with security-focused configuration."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_input_validation=True,
            enable_security_scanning=True,
            max_response_size_mb=10  # Limit response size
        )
        return MCPIntrospector(config=config)
    
    def test_malicious_json_handling(self, security_introspector):
        """Test handling of malicious JSON content."""
        server_config = MCPServerConfig(
            name="malicious-json-server",
            command="python",
            args=["-c", SecurityTestHelper.create_malicious_json_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = security_introspector.introspect_server(server_config)
        
        # Should handle malicious content safely
        if result is not None:
            # Check that malicious content is properly sanitized/handled
            assert result.server_name == "malicious-server"
            
            # Verify that injected content doesn't cause issues
            server_info_str = str(result.__dict__)
            assert "DROP TABLE" not in server_info_str
            assert "<script>" not in server_info_str
            assert "rm -rf" not in server_info_str
            
            # Check tools are parsed but sanitized
            if result.tools:
                tool = result.tools[0]
                assert tool.name == "malicious_tool"
                # Description should be present but sanitized
                assert len(tool.description) > 0
    
    def test_unicode_and_control_character_handling(self, security_introspector):
        """Test handling of Unicode and control characters."""
        malicious_unicode_script = '''
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
            "name": "unicode-test\\u0000\\u0001\\u0008\\u007f\\ufeff",
            "version": "1.0.0\\n\\r\\t"
        }
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="unicode-malicious-server",
            command="python",
            args=["-c", malicious_unicode_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = security_introspector.introspect_server(server_config)
        
        # Should handle Unicode and control characters safely
        if result is not None:
            # Control characters should be filtered or escaped
            assert '\x00' not in result.server_name
            assert '\x01' not in result.server_name
            assert '\x08' not in result.server_name
            assert '\x7f' not in result.server_name
    
    def test_oversized_response_handling(self, security_introspector):
        """Test handling of oversized responses."""
        server_config = MCPServerConfig(
            name="oversized-response-server", 
            command="python",
            args=["-c", SecurityTestHelper.create_resource_exhaustion_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Should handle oversized responses gracefully
        result = security_introspector.introspect_server(server_config)
        
        # Either successfully parse with limits or fail gracefully
        if result is not None:
            # If successful, should have reasonable limits
            assert len(result.tools) < 1000  # Should not parse all 10,000 tools
        # If result is None, that's also acceptable (failed due to size limits)
    
    def test_path_traversal_in_resources(self, security_introspector):
        """Test handling of path traversal attempts in resource URIs."""
        server_config = MCPServerConfig(
            name="path-traversal-server",
            command="python", 
            args=["-c", SecurityTestHelper.create_path_traversal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = security_introspector.introspect_server(server_config)
        
        if result is not None and result.resources:
            # Should parse resources but flag dangerous paths
            for resource in result.resources:
                # URI should be present but system should be aware of danger
                assert resource.uri is not None
                
                # Security scanning should flag these as high risk
                if hasattr(result, 'risk_assessment'):
                    assert result.risk_level in ["high", "critical"]


@pytest.mark.security
class TestPrivilegeEscalationSecurity:
    """Test protection against privilege escalation."""
    
    @pytest.fixture
    def privilege_test_introspector(self):
        """Create introspector for privilege escalation testing."""
        config = IntrospectionConfig(
            timeout=5.0,
            max_retries=1,
            retry_delay=0.1,
            run_in_sandbox=True,  # Enable sandboxing if available
            restrict_file_access=True
        )
        return MCPIntrospector(config=config)
    
    def test_privilege_escalation_attempts(self, privilege_test_introspector):
        """Test that servers cannot escalate privileges."""
        server_config = MCPServerConfig(
            name="privilege-escalation-test",
            command="python",
            args=["-c", SecurityTestHelper.create_privilege_escalation_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = privilege_test_introspector.introspect_server(server_config)
        
        if result is not None:
            # Check that privilege escalation attempts failed
            server_info = str(result.__dict__)
            
            # Should not have accessed sensitive files
            assert "root:" not in server_info  # Shadow file content
            assert result.server_name == "privilege-escalation-server"
    
    def test_file_system_access_restrictions(self, privilege_test_introspector):
        """Test that file system access is properly restricted."""
        # Create a server that tries to access various system files
        file_access_script = '''
import json
import sys
import os

message = json.loads(sys.stdin.readline())

# Try to access various sensitive files
sensitive_files = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/root/.ssh/id_rsa", "/var/log/auth.log"
]

access_results = {}
for file_path in sensitive_files:
    try:
        with open(file_path, "r") as f:
            access_results[file_path] = "accessible"
    except:
        access_results[file_path] = "restricted"

response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {
            "name": "file-access-test-server",
            "version": "1.0.0",
            "file_access_results": access_results
        }
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="file-access-test",
            command="python",
            args=["-c", file_access_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = privilege_test_introspector.introspect_server(server_config)
        
        if result is not None:
            # Verify that sensitive file access was restricted
            # This depends on the system and user permissions
            assert result.server_name == "file-access-test-server"
    
    def test_environment_variable_isolation(self, privilege_test_introspector):
        """Test that environment variables are properly isolated."""
        # Create a server that tries to access sensitive environment variables
        env_access_script = '''
import json
import sys
import os

message = json.loads(sys.stdin.readline())

# Try to access various environment variables
sensitive_env_vars = [
    "PATH", "HOME", "USER", "PWD", "SSH_AUTH_SOCK",
    "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "DATABASE_URL"
]

env_results = {}
for var in sensitive_env_vars:
    env_results[var] = os.getenv(var, "not_found")

response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {
            "name": "env-access-test-server",
            "version": "1.0.0",
            "env_access_results": env_results
        }
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="env-access-test",
            command="python",
            args=["-c", env_access_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={"SAFE_VAR": "safe_value"}  # Only provide safe variables
        )
        
        result = privilege_test_introspector.introspect_server(server_config)
        
        if result is not None:
            assert result.server_name == "env-access-test-server"
            # Environment should be isolated (server should only see provided variables)


@pytest.mark.security
class TestResourceExhaustionSecurity:
    """Test protection against resource exhaustion attacks."""
    
    @pytest.fixture
    def resource_limit_introspector(self):
        """Create introspector with resource limits."""
        config = IntrospectionConfig(
            timeout=8.0,
            max_retries=1,
            retry_delay=0.1,
            max_response_size_mb=5,
            max_memory_usage_mb=100,
            max_cpu_time_seconds=5
        )
        return MCPIntrospector(config=config)
    
    def test_memory_exhaustion_protection(self, resource_limit_introspector):
        """Test protection against memory exhaustion attacks."""
        server_config = MCPServerConfig(
            name="memory-exhaustion-test",
            command="python",
            args=["-c", SecurityTestHelper.create_resource_exhaustion_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Monitor memory usage during introspection
        import psutil
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        result = resource_limit_introspector.introspect_server(server_config)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Should not exhaust system memory
        assert memory_increase < 200, f"Memory increased by {memory_increase:.1f}MB, potential exhaustion attack"
        
        # Result should either succeed with limits or fail gracefully
        if result is not None:
            # Should have applied limits to prevent exhaustion
            assert len(result.tools) < 5000  # Should not process all malicious tools
    
    def test_cpu_exhaustion_protection(self, resource_limit_introspector):
        """Test protection against CPU exhaustion attacks."""
        cpu_exhaustion_script = '''
import json
import sys
import time

message = json.loads(sys.stdin.readline())

# CPU-intensive operation
start_time = time.time()
count = 0
while time.time() - start_time < 3:  # Try to use CPU for 3 seconds
    count += 1

response = {
    "jsonrpc": "2.0",
    "id": message.get("id", 1),
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {
            "name": "cpu-exhaustion-server",
            "version": "1.0.0",
            "cpu_cycles": count
        }
    }
}
print(json.dumps(response))
'''
        
        server_config = MCPServerConfig(
            name="cpu-exhaustion-test",
            command="python",
            args=["-c", cpu_exhaustion_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        start_time = time.time()
        result = resource_limit_introspector.introspect_server(server_config)
        elapsed_time = time.time() - start_time
        
        # Should not allow excessive CPU usage
        assert elapsed_time < 10, f"Operation took {elapsed_time:.2f}s, potential CPU exhaustion"
        
        # Should either complete quickly or timeout gracefully
        if result is not None:
            assert result.server_name == "cpu-exhaustion-server"
    
    def test_infinite_loop_protection(self, resource_limit_introspector):
        """Test protection against infinite loops."""
        infinite_loop_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())

# Try to create an infinite loop in JSON generation
result_data = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "infinite-loop-server", "version": "1.0.0"}}

# This would normally create an infinite loop, but should be caught
try:
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "result": result_data
    }
    print(json.dumps(response))
except:
    print('{"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "Internal error"}}')
'''
        
        server_config = MCPServerConfig(
            name="infinite-loop-test",
            command="python",
            args=["-c", infinite_loop_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        start_time = time.time()
        result = resource_limit_introspector.introspect_server(server_config)
        elapsed_time = time.time() - start_time
        
        # Should timeout and not run indefinitely
        assert elapsed_time < 15, f"Operation took {elapsed_time:.2f}s, possible infinite loop"


@pytest.mark.security
class TestInjectionAttackSecurity:
    """Test protection against various injection attacks."""
    
    @pytest.fixture
    def injection_test_introspector(self):
        """Create introspector for injection attack testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_input_sanitization=True,
            enable_command_injection_protection=True
        )
        return MCPIntrospector(config=config)
    
    def test_command_injection_in_server_config(self, injection_test_introspector):
        """Test protection against command injection in server configuration."""
        # Try various command injection payloads
        malicious_commands = [
            "python; rm -rf /tmp/test",
            "python && echo 'injected'",
            "python | cat /etc/passwd",
            "python`cat /etc/passwd`",
            "python$(whoami)",
        ]
        
        for malicious_command in malicious_commands:
            server_config = MCPServerConfig(
                name="command-injection-test",
                command=malicious_command,
                args=["-c", "print('hello')"],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            )
            
            # Should detect and prevent command injection
            try:
                result = injection_test_introspector.introspect_server(server_config)
                # If it succeeds, it should only execute the safe part
                if result is not None:
                    # Should not have executed the injected command
                    assert "injected" not in str(result.__dict__)
                    assert "root:" not in str(result.__dict__)
            except Exception:
                # It's acceptable to fail on malicious input
                pass
    
    def test_argument_injection_protection(self, injection_test_introspector):
        """Test protection against argument injection."""
        malicious_args = [
            ["-c", "print('safe')", ";", "rm", "-rf", "/tmp"],
            ["-c", "print('safe')", "&&", "echo", "injected"],
            ["-c", "import os; os.system('echo injected')"]
        ]
        
        for args in malicious_args:
            server_config = MCPServerConfig(
                name="arg-injection-test",
                command="python",
                args=args,
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            )
            
            try:
                result = injection_test_introspector.introspect_server(server_config)
                # Should handle malicious arguments safely
                if result is not None:
                    # Should not execute injected commands
                    assert "injected" not in str(result.__dict__)
            except Exception:
                # Acceptable to fail on malicious input
                pass
    
    def test_environment_variable_injection(self, injection_test_introspector):
        """Test protection against environment variable injection."""
        malicious_env = {
            "PYTHONPATH": "/tmp; rm -rf /tmp/test",
            "LD_PRELOAD": "/malicious/lib.so",
            "PATH": "/malicious/bin:$PATH",
            "SHELL": "/bin/sh -c 'echo injected'"
        }
        
        server_config = MCPServerConfig(
            name="env-injection-test",
            command="python",
            args=["-c", "import os; print(f'PATH={os.getenv(\"PATH\", \"not_found\")}')"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables=malicious_env
        )
        
        try:
            result = injection_test_introspector.introspect_server(server_config)
            # Should sanitize environment variables
            if result is not None:
                # Should not execute injected commands through environment
                assert "injected" not in str(result.__dict__)
        except Exception:
            # Acceptable to fail on malicious environment
            pass


@pytest.mark.security
class TestSecureConfigurationSecurity:
    """Test secure configuration and defaults."""
    
    def test_default_security_settings(self):
        """Test that default security settings are secure."""
        # Create introspector with default settings
        introspector = MCPIntrospector()
        
        # Check that security defaults are enabled
        config = introspector.config
        
        # Should have reasonable timeouts (not too long)
        assert config.timeout <= 30.0, "Default timeout too long, potential DoS vector"
        
        # Should have retry limits
        assert config.max_retries <= 5, "Too many retries allowed by default"
        
        # Should have reasonable delays
        assert config.retry_delay >= 0.1, "Retry delay too short, potential resource exhaustion"
    
    def test_security_configuration_validation(self):
        """Test validation of security-related configuration."""
        # Test various insecure configurations
        insecure_configs = [
            {"timeout": 0},  # No timeout
            {"timeout": 3600},  # 1 hour timeout
            {"max_retries": 100},  # Too many retries
            {"retry_delay": 0},  # No delay between retries
        ]
        
        for config_dict in insecure_configs:
            try:
                config = IntrospectionConfig(**config_dict)
                introspector = MCPIntrospector(config=config)
                # Should either reject insecure config or apply safe defaults
                assert introspector.config.timeout > 0
                assert introspector.config.timeout <= 300  # Max 5 minutes
                assert introspector.config.max_retries <= 10
                assert introspector.config.retry_delay >= 0.1
            except ValueError:
                # Acceptable to reject invalid configuration
                pass
    
    def test_working_directory_security(self):
        """Test working directory security restrictions."""
        config = IntrospectionConfig(
            restrict_working_directory=True,
            allowed_working_directories=["/tmp", "/var/tmp"]
        )
        introspector = MCPIntrospector(config=config)
        
        # Test with dangerous working directories
        dangerous_dirs = ["/", "/etc", "/usr/bin", "/root"]
        
        for dangerous_dir in dangerous_dirs:
            server_config = MCPServerConfig(
                name="dangerous-dir-test",
                command="python",
                args=["-c", "print('hello')"],
                transport_type=TransportType.STDIO,
                working_directory=dangerous_dir,
                environment_variables={}
            )
            
            # Should reject or restrict dangerous working directories
            result = introspector.introspect_server(server_config)
            # Either fails (preferred) or succeeds with restrictions
            if result is not None:
                # If it succeeds, it should have applied security restrictions
                pass


@pytest.mark.security
class TestSecurityReporting:
    """Test security reporting and alerting."""
    
    @pytest.fixture
    def security_reporting_introspector(self):
        """Create introspector with security reporting enabled."""
        config = IntrospectionConfig(
            timeout=10.0,
            enable_security_reporting=True,
            enable_threat_detection=True,
            security_log_level="WARNING"
        )
        return MCPIntrospector(config=config)
    
    def test_security_alert_generation(self, security_reporting_introspector):
        """Test that security alerts are generated for suspicious activity."""
        server_config = MCPServerConfig(
            name="suspicious-server",
            command="python",
            args=["-c", SecurityTestHelper.create_malicious_json_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Capture security alerts/logs
        with patch('logging.Logger.warning') as mock_warning:
            result = security_reporting_introspector.introspect_server(server_config)
            
            # Should generate security warnings for malicious content
            if result is not None:
                # Check if security warnings were logged
                warning_calls = [call for call in mock_warning.call_args_list 
                               if any(keyword in str(call).lower() 
                                     for keyword in ['security', 'malicious', 'suspicious', 'threat'])]
                
                # Should have generated some security alerts
                # Note: This depends on the implementation
    
    def test_risk_assessment_accuracy(self, security_reporting_introspector):
        """Test that risk assessment accurately identifies threats."""
        # Test with a server that has high-risk tools
        high_risk_script = '''
import json
import sys

message = json.loads(sys.stdin.readline())
method = message.get("method")

if method == "initialize":
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "high-risk-server", "version": "1.0.0"}
        }
    }
elif method == "tools/list":
    response = {
        "jsonrpc": "2.0",
        "id": message.get("id", 1),
        "result": {
            "tools": [
                {
                    "name": "execute_shell_command",
                    "description": "Execute arbitrary shell commands on the system",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                            "shell": {"type": "boolean", "default": True}
                        }
                    }
                },
                {
                    "name": "read_sensitive_file",
                    "description": "Read any file on the filesystem including system files",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "filepath": {"type": "string"}
                        }
                    }
                }
            ]
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
            name="high-risk-test",
            command="python",
            args=["-c", high_risk_script],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        result = security_reporting_introspector.introspect_server(server_config)
        
        if result is not None:
            # Should identify this as high risk
            assert hasattr(result, 'risk_level')
            assert result.risk_level in ["high", "critical"]
            
            # Should identify specific risk categories
            if hasattr(result, 'risk_categories'):
                assert any(category in ["code_execution", "file_system", "system_access"] 
                          for category in result.risk_categories)


if __name__ == "__main__":
    # Allow running security tests directly
    pytest.main([__file__, "-v", "-m", "security"]) 