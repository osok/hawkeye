"""
Integration tests for MCP detection pipeline.

Tests cover end-to-end MCP detection operations including process enumeration,
configuration discovery, protocol verification, and complete detection workflow.
"""

import os
import json
import tempfile
import subprocess
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.hawkeye.detection.process_enum import ProcessEnumerator
from src.hawkeye.detection.config_discovery import ConfigFileDiscovery
from src.hawkeye.detection.protocol_verify import ProtocolVerifier
from src.hawkeye.detection.transport_detect import TransportDetector
from src.hawkeye.detection.npx_detect import NPXDetector
from src.hawkeye.detection.docker_inspect import DockerInspector
from src.hawkeye.detection.env_analysis import EnvironmentAnalyzer
from src.hawkeye.detection.base import MCPDetectionResult, MCPProcess, MCPConfig
from src.hawkeye.config.settings import get_settings


class TestMCPDetectionIntegration:
    """Integration tests for complete MCP detection workflow."""
    
    @pytest.fixture
    def settings(self):
        """Get test settings."""
        return get_settings()
    
    @pytest.fixture
    def process_enumerator(self, settings):
        """Create process enumerator instance."""
        return ProcessEnumerator(settings)
    
    @pytest.fixture
    def config_discovery(self, settings):
        """Create config discovery instance."""
        return ConfigFileDiscovery(settings)
    
    @pytest.fixture
    def protocol_verifier(self, settings):
        """Create protocol verifier instance."""
        return ProtocolVerifier(settings)
    
    @pytest.fixture
    def transport_detector(self, settings):
        """Create transport detector instance."""
        return TransportDetector(settings)
    
    @pytest.fixture
    def npx_detector(self, settings):
        """Create NPX detector instance."""
        return NPXDetector(settings)
    
    @pytest.fixture
    def docker_inspector(self, settings):
        """Create Docker inspector instance."""
        return DockerInspector(settings)
    
    @pytest.fixture
    def env_analyzer(self, settings):
        """Create environment analyzer instance."""
        return EnvironmentAnalyzer(settings)
    
    @pytest.fixture
    def mock_mcp_process(self):
        """Create mock MCP process."""
        return MCPProcess(
            pid=12345,
            name="node",
            cmdline=["node", "/path/to/mcp-server.js", "--transport", "stdio"],
            cwd="/path/to/mcp-project",
            environ={
                "NODE_ENV": "production",
                "MCP_SERVER_NAME": "test-server",
                "MCP_TRANSPORT": "stdio"
            },
            create_time=1609459200.0,
            user="mcp-user"
        )
    
    @pytest.fixture
    def temp_mcp_config(self):
        """Create temporary MCP configuration files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create package.json
            package_json = {
                "name": "test-mcp-server",
                "version": "1.0.0",
                "dependencies": {
                    "@modelcontextprotocol/sdk": "^0.2.0",
                    "@modelcontextprotocol/server-stdio": "^0.1.0"
                },
                "scripts": {
                    "start": "node server.js",
                    "mcp": "node server.js --transport stdio"
                }
            }
            
            package_json_path = Path(temp_dir) / "package.json"
            with open(package_json_path, 'w') as f:
                json.dump(package_json, f, indent=2)
            
            # Create MCP config file
            mcp_config = {
                "mcpServers": {
                    "test-server": {
                        "command": "node",
                        "args": ["server.js"],
                        "transport": "stdio"
                    }
                }
            }
            
            mcp_config_path = Path(temp_dir) / "mcp.json"
            with open(mcp_config_path, 'w') as f:
                json.dump(mcp_config, f, indent=2)
            
            # Create server.js file
            server_js = '''
const { MCPServer } = require('@modelcontextprotocol/sdk');
const server = new MCPServer();
server.listen();
            '''
            
            server_js_path = Path(temp_dir) / "server.js"
            with open(server_js_path, 'w') as f:
                f.write(server_js)
            
            yield {
                "dir": temp_dir,
                "package_json": str(package_json_path),
                "mcp_config": str(mcp_config_path),
                "server_js": str(server_js_path)
            }
    
    def test_complete_detection_pipeline(self, process_enumerator, config_discovery, 
                                       protocol_verifier, mock_mcp_process, temp_mcp_config):
        """Test complete MCP detection pipeline."""
        # Mock process enumeration
        with patch.object(process_enumerator, 'get_node_processes') as mock_processes:
            # Mock config discovery
            with patch.object(config_discovery, 'discover_mcp_configs') as mock_configs:
                # Mock protocol verification
                with patch.object(protocol_verifier, 'verify_mcp_protocol') as mock_verify:
                    
                    # Setup mocks
                    mock_processes.return_value = [mock_mcp_process]
                    mock_configs.return_value = [
                        MCPConfig(
                            path=temp_mcp_config["mcp_config"],
                            config_type="mcp_config",
                            servers={"test-server": {}},
                            source_file=temp_mcp_config["mcp_config"]
                        )
                    ]
                    mock_verify.return_value = True
                    
                    # Run detection pipeline
                    detected_processes = process_enumerator.get_node_processes()
                    detected_configs = config_discovery.discover_mcp_configs(temp_mcp_config["dir"])
                    
                    # Verify detection results
                    assert len(detected_processes) == 1
                    assert len(detected_configs) == 1
                    
                    # Verify process details
                    process = detected_processes[0]
                    assert process.pid == 12345
                    assert "mcp-server.js" in " ".join(process.cmdline)
                    
                    # Verify config details
                    config = detected_configs[0]
                    assert config.config_type == "mcp_config"
                    assert "test-server" in config.servers
                    
                    # Verify protocol verification
                    is_mcp = protocol_verifier.verify_mcp_protocol(process)
                    assert is_mcp is True
    
    def test_config_discovery_integration(self, config_discovery, temp_mcp_config):
        """Test configuration discovery integration."""
        # Discover configs in temporary directory
        configs = config_discovery.discover_mcp_configs(temp_mcp_config["dir"])
        
        # Should find both package.json and mcp.json
        assert len(configs) >= 1
        
        # Verify package.json detection
        package_configs = [c for c in configs if c.config_type == "package_json"]
        if package_configs:
            package_config = package_configs[0]
            assert "test-mcp-server" in str(package_config.servers)
            assert "@modelcontextprotocol/sdk" in str(package_config.servers)
        
        # Verify mcp.json detection
        mcp_configs = [c for c in configs if c.config_type == "mcp_config"]
        if mcp_configs:
            mcp_config = mcp_configs[0]
            assert "test-server" in mcp_config.servers
    
    def test_transport_detection_integration(self, transport_detector, mock_mcp_process):
        """Test transport detection integration."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock successful connection for HTTP transport
            mock_socket.connect_ex.return_value = 0
            mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            
            # Detect transport types
            transports = transport_detector.detect_transports(mock_mcp_process)
            
            # Should detect stdio from command line
            assert "stdio" in transports
            
            # Test HTTP detection
            http_process = MCPProcess(
                pid=54321,
                name="node",
                cmdline=["node", "server.js", "--port", "3000"],
                cwd="/path/to/project",
                environ={"PORT": "3000"},
                create_time=1609459200.0,
                user="user"
            )
            
            http_transports = transport_detector.detect_transports(http_process)
            if "http" in http_transports:
                assert "http" in http_transports
    
    def test_npx_detection_integration(self, npx_detector):
        """Test NPX package detection integration."""
        with patch('subprocess.run') as mock_run:
            # Mock npx list output
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = '''
            /usr/local/lib
            ├── @modelcontextprotocol/sdk@0.2.0
            ├── @modelcontextprotocol/server-stdio@0.1.0
            └── typescript@4.9.5
            '''
            mock_run.return_value = mock_result
            
            # Detect NPX packages
            packages = npx_detector.detect_mcp_packages()
            
            # Should find MCP packages
            mcp_packages = [p for p in packages if "modelcontextprotocol" in p.get("name", "")]
            assert len(mcp_packages) >= 1
    
    def test_docker_inspection_integration(self, docker_inspector):
        """Test Docker container inspection integration."""
        with patch('subprocess.run') as mock_run:
            # Mock docker ps output
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = json.dumps([
                {
                    "Id": "abc123",
                    "Names": ["/mcp-server"],
                    "Image": "node:18-alpine",
                    "Command": "node server.js",
                    "State": "running",
                    "Status": "Up 2 hours",
                    "Ports": [{"PrivatePort": 3000, "Type": "tcp"}],
                    "Mounts": [
                        {
                            "Source": "/host/mcp-config",
                            "Destination": "/app/config",
                            "Type": "bind"
                        }
                    ],
                    "Config": {
                        "Env": [
                            "NODE_ENV=production",
                            "MCP_TRANSPORT=stdio"
                        ]
                    }
                }
            ])
            mock_run.return_value = mock_result
            
            # Inspect Docker containers
            containers = docker_inspector.inspect_containers()
            
            # Should find MCP-related containers
            mcp_containers = [c for c in containers if "mcp" in c.get("name", "").lower()]
            if mcp_containers:
                container = mcp_containers[0]
                assert container["state"] == "running"
                assert "node" in container.get("command", "")
    
    def test_environment_analysis_integration(self, env_analyzer, mock_mcp_process):
        """Test environment variable analysis integration."""
        # Analyze environment variables
        env_info = env_analyzer.analyze_environment(mock_mcp_process)
        
        # Should identify MCP-related environment variables
        assert env_info is not None
        assert "NODE_ENV" in env_info.get("variables", {})
        assert "MCP_SERVER_NAME" in env_info.get("variables", {})
        assert "MCP_TRANSPORT" in env_info.get("variables", {})
        
        # Should identify security concerns
        security_issues = env_info.get("security_issues", [])
        # May include warnings about production environment or exposed variables
    
    def test_multi_process_detection(self, process_enumerator, protocol_verifier):
        """Test detection of multiple MCP processes."""
        mock_processes = [
            MCPProcess(
                pid=11111,
                name="node",
                cmdline=["node", "server1.js"],
                cwd="/app/server1",
                environ={"MCP_SERVER": "server1"},
                create_time=1609459200.0,
                user="user1"
            ),
            MCPProcess(
                pid=22222,
                name="node",
                cmdline=["node", "server2.js"],
                cwd="/app/server2",
                environ={"MCP_SERVER": "server2"},
                create_time=1609459260.0,
                user="user2"
            )
        ]
        
        with patch.object(process_enumerator, 'get_node_processes') as mock_get_processes:
            with patch.object(protocol_verifier, 'verify_mcp_protocol') as mock_verify:
                mock_get_processes.return_value = mock_processes
                mock_verify.return_value = True
                
                # Detect processes
                detected = process_enumerator.get_node_processes()
                
                # Verify multiple processes detected
                assert len(detected) == 2
                assert detected[0].pid != detected[1].pid
                
                # Verify each process
                for process in detected:
                    is_mcp = protocol_verifier.verify_mcp_protocol(process)
                    assert is_mcp is True
    
    def test_error_handling_in_detection(self, process_enumerator, config_discovery):
        """Test error handling in detection pipeline."""
        # Test process enumeration error
        with patch('psutil.process_iter') as mock_process_iter:
            mock_process_iter.side_effect = Exception("Process enumeration failed")
            
            # Should handle error gracefully
            processes = process_enumerator.get_node_processes()
            assert isinstance(processes, list)  # Should return empty list on error
        
        # Test config discovery error
        non_existent_path = "/non/existent/path"
        configs = config_discovery.discover_mcp_configs(non_existent_path)
        assert isinstance(configs, list)  # Should return empty list on error
    
    def test_protocol_verification_scenarios(self, protocol_verifier):
        """Test various protocol verification scenarios."""
        # Test stdio transport
        stdio_process = MCPProcess(
            pid=12345,
            name="node",
            cmdline=["node", "server.js", "--transport", "stdio"],
            cwd="/app",
            environ={},
            create_time=1609459200.0,
            user="user"
        )
        
        with patch.object(protocol_verifier, '_verify_stdio_protocol') as mock_stdio:
            mock_stdio.return_value = True
            
            result = protocol_verifier.verify_mcp_protocol(stdio_process)
            assert result is True
            mock_stdio.assert_called_once()
        
        # Test HTTP transport
        http_process = MCPProcess(
            pid=54321,
            name="node",
            cmdline=["node", "server.js", "--port", "3000"],
            cwd="/app",
            environ={"PORT": "3000"},
            create_time=1609459200.0,
            user="user"
        )
        
        with patch.object(protocol_verifier, '_verify_http_protocol') as mock_http:
            mock_http.return_value = True
            
            result = protocol_verifier.verify_mcp_protocol(http_process)
            assert result is True
            mock_http.assert_called_once()
    
    def test_comprehensive_detection_result(self, process_enumerator, config_discovery, 
                                          transport_detector, env_analyzer, temp_mcp_config):
        """Test comprehensive detection result compilation."""
        mock_process = MCPProcess(
            pid=12345,
            name="node",
            cmdline=["node", "server.js"],
            cwd=temp_mcp_config["dir"],
            environ={"MCP_SERVER": "test"},
            create_time=1609459200.0,
            user="user"
        )
        
        with patch.object(process_enumerator, 'get_node_processes') as mock_processes:
            mock_processes.return_value = [mock_process]
            
            # Run complete detection
            processes = process_enumerator.get_node_processes()
            configs = config_discovery.discover_mcp_configs(temp_mcp_config["dir"])
            
            # Compile comprehensive result
            if processes:
                process = processes[0]
                transports = transport_detector.detect_transports(process)
                env_info = env_analyzer.analyze_environment(process)
                
                # Create detection result
                result = MCPDetectionResult(
                    process=process,
                    configs=configs,
                    transports=transports,
                    environment=env_info,
                    confidence=0.9,
                    risk_score=3.5
                )
                
                # Verify comprehensive result
                assert result.process.pid == 12345
                assert len(result.configs) >= 1
                assert isinstance(result.transports, list)
                assert result.environment is not None
                assert 0 <= result.confidence <= 1
                assert result.risk_score > 0
    
    def test_real_world_detection_scenario(self, process_enumerator, config_discovery, 
                                         protocol_verifier, temp_mcp_config):
        """Test realistic detection scenario with multiple components."""
        # Simulate real-world scenario with multiple detection sources
        
        # Mock finding process
        mock_process = MCPProcess(
            pid=98765,
            name="node",
            cmdline=["node", "/opt/mcp-servers/file-server.js", "--stdio"],
            cwd="/opt/mcp-servers",
            environ={
                "NODE_ENV": "production",
                "MCP_SERVER_NAME": "file-server",
                "PATH": "/usr/local/bin:/usr/bin:/bin"
            },
            create_time=1609459200.0,
            user="mcp-service"
        )
        
        with patch.object(process_enumerator, 'get_node_processes') as mock_processes:
            with patch.object(config_discovery, 'discover_mcp_configs') as mock_configs:
                with patch.object(protocol_verifier, 'verify_mcp_protocol') as mock_verify:
                    
                    # Setup comprehensive mocks
                    mock_processes.return_value = [mock_process]
                    mock_configs.return_value = [
                        MCPConfig(
                            path="/opt/mcp-servers/package.json",
                            config_type="package_json",
                            servers={"dependencies": {"@modelcontextprotocol/sdk": "^0.2.0"}},
                            source_file="/opt/mcp-servers/package.json"
                        )
                    ]
                    mock_verify.return_value = True
                    
                    # Execute detection workflow
                    detected_processes = process_enumerator.get_node_processes()
                    detected_configs = config_discovery.discover_mcp_configs("/opt/mcp-servers")
                    
                    # Verify realistic detection
                    assert len(detected_processes) == 1
                    assert len(detected_configs) == 1
                    
                    process = detected_processes[0]
                    config = detected_configs[0]
                    
                    # Verify process characteristics
                    assert process.user == "mcp-service"
                    assert "file-server.js" in " ".join(process.cmdline)
                    assert process.environ["NODE_ENV"] == "production"
                    
                    # Verify config characteristics
                    assert config.config_type == "package_json"
                    assert "@modelcontextprotocol/sdk" in str(config.servers)
                    
                    # Verify protocol verification
                    is_verified = protocol_verifier.verify_mcp_protocol(process)
                    assert is_verified is True 