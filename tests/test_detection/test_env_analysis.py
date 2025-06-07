"""
Unit tests for environment variable analysis functionality.
"""

import os
import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List

from src.hawkeye.detection.env_analysis import EnvironmentAnalyzer, create_environment_analyzer
from src.hawkeye.detection.base import (
    DetectionMethod, MCPServerType, TransportType
)


class TestEnvironmentAnalyzer:
    """Test cases for EnvironmentAnalyzer class."""
    
    @pytest.fixture
    def analyzer(self):
        """Create EnvironmentAnalyzer instance for testing."""
        return EnvironmentAnalyzer()
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        settings = Mock()
        settings.detection = Mock()
        settings.detection.timeout = 30
        return settings
    
    def test_init(self, mock_settings):
        """Test EnvironmentAnalyzer initialization."""
        analyzer = EnvironmentAnalyzer(mock_settings)
        
        assert analyzer.settings == mock_settings
        assert len(analyzer.mcp_env_patterns) > 0
        assert len(analyzer.known_mcp_env_vars) > 0
        assert len(analyzer.mcp_value_patterns) > 0
        assert len(analyzer.port_patterns) > 0
        assert len(analyzer.common_mcp_ports) > 0
        assert len(analyzer.transport_indicators) > 0
    
    def test_get_detection_method(self, analyzer):
        """Test detection method identifier."""
        assert analyzer.get_detection_method() == DetectionMethod.ENVIRONMENT_ANALYSIS
    
    def test_is_mcp_related_env_var_known_vars(self, analyzer):
        """Test MCP environment variable detection for known variables."""
        # Known MCP environment variables
        assert analyzer._is_mcp_related_env_var('MCP_SERVER_PORT', '3000')
        assert analyzer._is_mcp_related_env_var('MCP_SERVER_HOST', 'localhost')
        assert analyzer._is_mcp_related_env_var('MCP_TRANSPORT_TYPE', 'http')
        assert analyzer._is_mcp_related_env_var('MODEL_CONTEXT_PROTOCOL_PORT', '8000')
        
        # Non-MCP variables
        assert not analyzer._is_mcp_related_env_var('PATH', '/usr/bin')
        assert not analyzer._is_mcp_related_env_var('HOME', '/home/user')
        assert not analyzer._is_mcp_related_env_var('PORT', '80')
    
    def test_is_mcp_related_env_var_patterns(self, analyzer):
        """Test MCP environment variable detection using patterns."""
        # Key patterns
        assert analyzer._is_mcp_related_env_var('MY_MCP_CONFIG', 'config.json')
        assert analyzer._is_mcp_related_env_var('APP_MCP_SERVER_PORT', '3000')
        assert analyzer._is_mcp_related_env_var('MCP_WEBSOCKET_PORT', '8080')
        
        # Value patterns
        assert analyzer._is_mcp_related_env_var('COMMAND', 'npx @modelcontextprotocol/server-filesystem')
        assert analyzer._is_mcp_related_env_var('SERVER_CMD', 'node mcp-server.js')
        assert analyzer._is_mcp_related_env_var('URL', 'http://localhost:3000/mcp')
        
        # Non-matching patterns
        assert not analyzer._is_mcp_related_env_var('DATABASE_URL', 'postgresql://localhost:5432/db')
        assert not analyzer._is_mcp_related_env_var('REDIS_HOST', 'localhost')
    
    def test_extract_host_from_env(self, analyzer):
        """Test host extraction from environment variables."""
        # Explicit host variables
        env_vars = {'MCP_SERVER_HOST': 'example.com'}
        assert analyzer._extract_host_from_env(env_vars) == 'example.com'
        
        env_vars = {'HOST': 'localhost'}
        assert analyzer._extract_host_from_env(env_vars) == 'localhost'
        
        # Host in other variables
        env_vars = {'API_HOST': '192.168.1.100'}
        assert analyzer._extract_host_from_env(env_vars) == '192.168.1.100'
        
        # No host found
        env_vars = {'PORT': '3000'}
        assert analyzer._extract_host_from_env(env_vars) is None
    
    def test_extract_port_from_env(self, analyzer):
        """Test port extraction from environment variables."""
        # Explicit port variables
        env_vars = {'MCP_SERVER_PORT': '3000'}
        assert analyzer._extract_port_from_env(env_vars) == 3000
        
        env_vars = {'PORT': '8080'}
        assert analyzer._extract_port_from_env(env_vars) == 8080
        
        # Port in other variables
        env_vars = {'API_PORT': '9000'}
        assert analyzer._extract_port_from_env(env_vars) == 9000
        
        # Port in URL format
        env_vars = {'SERVER_URL': 'http://localhost:3001/api'}
        assert analyzer._extract_port_from_env(env_vars) == 3001
        
        # Invalid port
        env_vars = {'PORT': 'invalid'}
        assert analyzer._extract_port_from_env(env_vars) is None
        
        # No port found
        env_vars = {'HOST': 'localhost'}
        assert analyzer._extract_port_from_env(env_vars) is None
    
    def test_extract_transport_from_env(self, analyzer):
        """Test transport type extraction from environment variables."""
        # Explicit transport variables
        env_vars = {'MCP_TRANSPORT_TYPE': 'websocket'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.WEBSOCKET
        
        env_vars = {'MCP_TRANSPORT': 'http'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.HTTP
        
        env_vars = {'TRANSPORT_TYPE': 'stdio'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.STDIO
        
        # Inferred from values
        env_vars = {'SERVER_URL': 'ws://localhost:3000'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.WEBSOCKET
        
        env_vars = {'API_ENDPOINT': 'https://api.example.com'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.HTTP
        
        # Default with port
        env_vars = {'PORT': '3000'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.HTTP
        
        # Default without port
        env_vars = {'MCP_CONFIG': 'config.json'}
        assert analyzer._extract_transport_from_env(env_vars) == TransportType.STDIO
    
    def test_determine_server_type_from_env(self, analyzer):
        """Test server type determination from environment variables."""
        # Docker container
        env_vars = {'CONTAINER_ID': 'abc123'}
        assert analyzer._determine_server_type_from_env(env_vars, 'docker_container') == MCPServerType.DOCKER_CONTAINER
        
        # NPX package
        env_vars = {'COMMAND': 'npx @modelcontextprotocol/server-filesystem'}
        assert analyzer._determine_server_type_from_env(env_vars, 'system') == MCPServerType.NPX_PACKAGE
        
        # Node.js application (treated as standalone)
        env_vars = {'NODE_ENV': 'production', 'npm_package_name': 'mcp-server'}
        assert analyzer._determine_server_type_from_env(env_vars, 'system') == MCPServerType.STANDALONE
        
        # Standalone server
        env_vars = {'MCP_SERVER_PORT': '3000'}
        assert analyzer._determine_server_type_from_env(env_vars, 'system') == MCPServerType.STANDALONE
    
    def test_extract_env_indicators(self, analyzer):
        """Test environment variable indicator extraction."""
        env_vars = {
            'MCP_SERVER_PORT': '3000',
            'MCP_TRANSPORT_TYPE': 'http',
            'MCP_AUTH_TOKEN': 'secret123',
            'MCP_TOOLS_CONFIG': 'tools.json',
            'SERVER_CONFIG': 'config.json',
            'API_PORT': '8080'
        }
        
        indicators = analyzer._extract_env_indicators(env_vars)
        
        assert len(indicators['mcp_vars']) >= 4  # MCP_* variables
        assert len(indicators['transport_vars']) >= 1  # Transport variables
        assert len(indicators['port_vars']) >= 2  # Port variables
        assert len(indicators['auth_vars']) >= 1  # Auth variables
        assert len(indicators['config_vars']) >= 1  # Config variables
        assert len(indicators['tool_vars']) >= 1  # Tool variables
    
    def test_calculate_process_env_confidence(self, analyzer):
        """Test process environment confidence calculation."""
        # High confidence process
        env_vars = {
            'MCP_SERVER_PORT': '3000',
            'MCP_TRANSPORT_TYPE': 'http',
            'MCP_AUTH_TOKEN': 'secret'
        }
        cmdline = ['node', 'mcp-server.js', '--port', '3000']
        confidence = analyzer._calculate_process_env_confidence(env_vars, cmdline)
        assert confidence >= 0.8
        
        # Medium confidence process
        env_vars = {'MY_MCP_CONFIG': 'config.json'}
        cmdline = ['node', 'server.js']
        confidence = analyzer._calculate_process_env_confidence(env_vars, cmdline)
        assert 0.3 <= confidence < 0.8
        
        # Low confidence process
        env_vars = {'SOME_VAR': '@modelcontextprotocol/server'}
        cmdline = ['python', 'app.py']
        confidence = analyzer._calculate_process_env_confidence(env_vars, cmdline)
        assert confidence < 0.6
    
    def test_get_env_var_confidence(self, analyzer):
        """Test environment variable confidence calculation."""
        # Known MCP variable
        confidence = analyzer._get_env_var_confidence('MCP_SERVER_PORT', '3000')
        assert confidence >= 0.6
        
        # Pattern in key
        confidence = analyzer._get_env_var_confidence('MY_MCP_CONFIG', 'config.json')
        assert confidence >= 0.4
        
        # Pattern in value
        confidence = analyzer._get_env_var_confidence('COMMAND', 'npx @modelcontextprotocol/server-filesystem')
        assert confidence >= 0.2
        
        # No MCP relation
        confidence = analyzer._get_env_var_confidence('PATH', '/usr/bin')
        assert confidence == 0.0
    
    def test_extract_servers_from_env(self, analyzer):
        """Test MCP server extraction from environment variables."""
        env_vars = {
            'MCP_SERVER_HOST': 'localhost',
            'MCP_SERVER_PORT': '3000',
            'MCP_TRANSPORT_TYPE': 'http'
        }
        
        servers = analyzer._extract_servers_from_env(env_vars, 'system')
        
        assert len(servers) == 1
        server = servers[0]
        assert server.host == 'localhost'
        assert server.port == 3000
        assert server.transport_type == TransportType.HTTP
        assert server.server_type == MCPServerType.STANDALONE
        assert server.environment_info is not None
    
    @patch('os.environ', {
        'MCP_SERVER_PORT': '3000',
        'MCP_TRANSPORT_TYPE': 'http',
        'PATH': '/usr/bin',
        'HOME': '/home/user'
    })
    def test_analyze_system_environment(self, analyzer):
        """Test system environment analysis."""
        env_vars = analyzer._analyze_system_environment()
        
        assert 'MCP_SERVER_PORT' in env_vars
        assert 'MCP_TRANSPORT_TYPE' in env_vars
        assert 'PATH' not in env_vars  # Not MCP-related
        assert 'HOME' not in env_vars  # Not MCP-related
    
    @patch('psutil.process_iter')
    def test_analyze_process_environments(self, mock_process_iter, analyzer):
        """Test process environment analysis."""
        # Mock process with MCP environment variables
        mock_proc = Mock()
        mock_proc.info = {
            'pid': 1234,
            'name': 'node',
            'cmdline': ['node', 'mcp-server.js']
        }
        mock_proc.environ.return_value = {
            'MCP_SERVER_PORT': '3000',
            'MCP_TRANSPORT_TYPE': 'http',
            'PATH': '/usr/bin'
        }
        
        mock_process_iter.return_value = [mock_proc]
        
        process_envs = analyzer._analyze_process_environments()
        
        assert len(process_envs) == 1
        proc_env = process_envs[0]
        assert proc_env['pid'] == 1234
        assert proc_env['name'] == 'node'
        assert 'MCP_SERVER_PORT' in proc_env['env_vars']
        assert 'PATH' not in proc_env['env_vars']  # Not MCP-related
        assert proc_env['confidence'] > 0
    
    @patch('psutil.process_iter')
    def test_analyze_process_environments_access_denied(self, mock_process_iter, analyzer):
        """Test process environment analysis with access denied."""
        import psutil
        
        # Mock process that raises AccessDenied
        mock_proc = Mock()
        mock_proc.info = {
            'pid': 1234,
            'name': 'node',
            'cmdline': ['node', 'server.js']
        }
        mock_proc.environ.side_effect = psutil.AccessDenied()
        
        mock_process_iter.return_value = [mock_proc]
        
        process_envs = analyzer._analyze_process_environments()
        
        assert len(process_envs) == 0  # Should skip processes with access denied
    
    def test_analyze_process_environments_no_psutil(self, analyzer):
        """Test process environment analysis without psutil."""
        # Simulate ImportError for psutil
        with patch('builtins.__import__', side_effect=lambda name, *args: ImportError() if name == 'psutil' else __import__(name, *args)):
            process_envs = analyzer._analyze_process_environments()
            assert len(process_envs) == 0
    
    def test_extract_mcp_indicators(self, analyzer):
        """Test MCP indicator extraction."""
        detection_data = {
            'system_env_vars': {
                'MCP_SERVER_PORT': '3000'
            },
            'process_env_vars': [
                {
                    'pid': 1234,
                    'name': 'node',
                    'env_vars': {
                        'MCP_TRANSPORT_TYPE': 'http'
                    }
                }
            ]
        }
        
        indicators = analyzer._extract_mcp_indicators(detection_data)
        
        assert len(indicators) == 2
        assert indicators[0]['source'] == 'system'
        assert indicators[0]['key'] == 'MCP_SERVER_PORT'
        assert indicators[1]['source'] == 'process_1234'
        assert indicators[1]['key'] == 'MCP_TRANSPORT_TYPE'
    
    def test_extract_transport_indicators(self, analyzer):
        """Test transport indicator extraction."""
        detection_data = {
            'system_env_vars': {
                'MCP_TRANSPORT_TYPE': 'websocket',
                'API_URL': 'https://api.example.com'
            },
            'process_env_vars': [
                {
                    'env_vars': {
                        'SERVER_MODE': 'stdio'
                    }
                }
            ]
        }
        
        indicators = analyzer._extract_transport_indicators(detection_data)
        
        assert len(indicators) >= 3  # websocket, https, stdio
        transport_types = [ind['transport_type'] for ind in indicators]
        assert 'websocket' in transport_types
        assert 'http' in transport_types
        assert 'stdio' in transport_types
    
    def test_extract_port_indicators(self, analyzer):
        """Test port indicator extraction."""
        detection_data = {
            'system_env_vars': {
                'MCP_SERVER_PORT': '3000',
                'API_PORT': '8080'
            },
            'process_env_vars': [
                {
                    'env_vars': {
                        'WEBSOCKET_PORT': '9000'
                    }
                }
            ]
        }
        
        indicators = analyzer._extract_port_indicators(detection_data)
        
        assert len(indicators) == 3
        ports = [ind['port'] for ind in indicators]
        assert 3000 in ports
        assert 8080 in ports
        assert 9000 in ports
        
        # Check if common MCP port is identified
        mcp_port_indicators = [ind for ind in indicators if ind['is_common_mcp_port']]
        assert len(mcp_port_indicators) >= 1  # 3000 is a common MCP port
    
    def test_extract_security_indicators(self, analyzer):
        """Test security indicator extraction."""
        detection_data = {
            'system_env_vars': {
                'MCP_AUTH_TOKEN': 'secret123',
                'API_KEY': 'key456',
                'SSL_CERT': '/path/to/cert'
            },
            'process_env_vars': [
                {
                    'env_vars': {
                        'HTTPS_PORT': '443'
                    }
                }
            ]
        }
        
        indicators = analyzer._extract_security_indicators(detection_data)
        
        assert len(indicators) >= 4
        security_types = [ind['security_type'] for ind in indicators]
        assert 'token_authentication' in security_types
        assert 'api_key' in security_types
        assert 'ssl_tls' in security_types
        assert 'https_transport' in security_types
    
    def test_select_best_mcp_server(self, analyzer):
        """Test MCP server selection logic."""
        from src.hawkeye.detection.base import MCPServerInfo
        
        # Test empty list
        assert analyzer._select_best_mcp_server([]) is None
        
        # Create test servers with different confidence levels
        high_confidence_server = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.STANDALONE,
            environment_info={
                'env_vars': {
                    'MCP_SERVER_PORT': '3000',
                    'MCP_TRANSPORT_TYPE': 'http'
                }
            }
        )
        
        low_confidence_server = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.STANDALONE,
            environment_info={
                'env_vars': {
                    'SOME_VAR': '@modelcontextprotocol/server'
                }
            }
        )
        
        # Should select high confidence server
        best = analyzer._select_best_mcp_server([low_confidence_server, high_confidence_server])
        assert best == high_confidence_server
    
    def test_calculate_confidence(self, analyzer):
        """Test confidence calculation."""
        from src.hawkeye.detection.base import MCPServerInfo
        
        server = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.STANDALONE,
            environment_info={'env_vars': {}}
        )
        
        detection_data = {
            'mcp_indicators': [
                {'confidence': 0.8},
                {'confidence': 0.6}
            ],
            'transport_indicators': [{'transport_type': 'http'}],
            'port_indicators': [{'port': 3000, 'is_common_mcp_port': True}],
            'security_indicators': [{'security_type': 'token_authentication'}]
        }
        
        confidence = analyzer._calculate_confidence(server, detection_data)
        
        # Should include base (0.2) + indicators (0.28) + transport (0.1) + port (0.2) + security (0.1)
        assert confidence >= 0.8
    
    @patch.object(EnvironmentAnalyzer, '_analyze_system_environment')
    @patch.object(EnvironmentAnalyzer, '_analyze_process_environments')
    def test_detect_success(self, mock_process_env, mock_system_env, analyzer):
        """Test successful environment detection."""
        # Mock environment analysis
        mock_system_env.return_value = {
            'MCP_SERVER_PORT': '3000',
            'MCP_TRANSPORT_TYPE': 'http'
        }
        
        mock_process_env.return_value = [
            {
                'pid': 1234,
                'name': 'node',
                'cmdline': ['node', 'mcp-server.js'],
                'env_vars': {
                    'MCP_SERVER_HOST': 'localhost'
                },
                'confidence': 0.8
            }
        ]
        
        result = analyzer.detect('localhost')
        
        assert result.success
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.ENVIRONMENT_ANALYSIS
        assert result.mcp_server is not None
        assert result.confidence > 0
        assert 'system_env_vars' in result.raw_data
        assert 'process_env_vars' in result.raw_data
    
    @patch.object(EnvironmentAnalyzer, '_analyze_system_environment')
    @patch.object(EnvironmentAnalyzer, '_analyze_process_environments')
    def test_detect_no_servers(self, mock_process_env, mock_system_env, analyzer):
        """Test environment detection with no servers found."""
        # Mock empty results
        mock_system_env.return_value = {}
        mock_process_env.return_value = []
        
        result = analyzer.detect('localhost')
        
        assert not result.success
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.ENVIRONMENT_ANALYSIS
        assert result.mcp_server is None
        assert result.confidence == 0.0
    
    @patch.object(EnvironmentAnalyzer, '_analyze_system_environment')
    def test_detect_exception(self, mock_system_env, analyzer):
        """Test environment detection with exception."""
        mock_system_env.side_effect = Exception("Test error")
        
        result = analyzer.detect('localhost')
        
        assert not result.success
        assert result.error == "Test error"
    
    def test_create_environment_analyzer(self):
        """Test environment analyzer factory function."""
        analyzer = create_environment_analyzer()
        assert isinstance(analyzer, EnvironmentAnalyzer)
        
        mock_settings = Mock()
        analyzer = create_environment_analyzer(mock_settings)
        assert isinstance(analyzer, EnvironmentAnalyzer)
        assert analyzer.settings == mock_settings


if __name__ == '__main__':
    pytest.main([__file__])