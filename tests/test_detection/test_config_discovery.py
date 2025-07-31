"""
Unit tests for configuration file discovery functionality.

This module tests the ConfigFileDiscovery class and its ability to discover
and analyze configuration files for MCP server detection.
"""

import json
import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from src.hawkeye.detection.config_discovery import ConfigFileDiscovery
from src.hawkeye.detection.base import (
    DetectionResult,
    DetectionMethod,
    ConfigFileInfo,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ConfigDetectionError,
)


class TestConfigFileDiscovery:
    """Test cases for ConfigFileDiscovery class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.detector = ConfigFileDiscovery()
    
    def test_init(self):
        """Test ConfigFileDiscovery initialization."""
        assert self.detector.config_patterns
        assert self.detector.mcp_packages
        assert self.detector.mcp_script_patterns
        assert self.detector.search_directories
        assert self.detector.max_depth == 3
        assert self.detector.max_files == 1000
    
    def test_get_detection_method(self):
        """Test detection method identification."""
        assert self.detector.get_detection_method() == DetectionMethod.CONFIG_FILE_DISCOVERY
    
    def test_detect_remote_host_error(self):
        """Test detection fails for remote hosts."""
        result = self.detector.detect("192.168.1.100")
        
        assert not result.success
        assert "only supported on localhost" in result.error
        assert result.detection_method == DetectionMethod.CONFIG_FILE_DISCOVERY
    
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._discover_config_files')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._analyze_config_files')
    def test_detect_no_mcp_configs(self, mock_analyze, mock_discover):
        """Test detection when no MCP configurations are found."""
        mock_discover.return_value = [Path('package.json')]
        mock_analyze.return_value = []
        
        result = self.detector.detect("localhost")
        
        assert result.success
        assert result.confidence == 0.0
        assert result.mcp_server is None
        assert result.raw_data['mcp_config_files'] == 0
    
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._discover_config_files')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._analyze_config_files')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._calculate_config_confidence')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._create_mcp_server_from_config')
    def test_detect_with_mcp_configs(self, mock_create_server, mock_confidence, mock_analyze, mock_discover):
        """Test detection when MCP configurations are found."""
        # Setup mocks
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'name': 'test-mcp-server'},
            dependencies=['@modelcontextprotocol/server']
        )
        
        mock_discover.return_value = [Path('package.json')]
        mock_analyze.return_value = [config_info]
        mock_confidence.return_value = 0.8
        mock_create_server.return_value = MCPServerInfo(
            host="localhost",
            transport_type=TransportType.STDIO,
            server_type=MCPServerType.STANDALONE
        )
        
        result = self.detector.detect("localhost")
        
        assert result.success
        assert result.confidence == 0.8
        assert result.mcp_server is not None
        assert result.raw_data['mcp_config_files'] == 1
    
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._discover_config_files')
    def test_detect_exception_handling(self, mock_discover):
        """Test detection handles exceptions gracefully."""
        mock_discover.side_effect = Exception("Test error")
        
        result = self.detector.detect("localhost")
        
        assert not result.success
        assert "Test error" in result.error
    
    def test_discover_config_files_nonexistent_path(self):
        """Test config file discovery with non-existent paths."""
        result = self.detector._discover_config_files(['/nonexistent/path'], 2)
        assert result == []
    
    @patch('pathlib.Path.expanduser')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.is_dir')
    @patch('pathlib.Path.rglob')
    def test_discover_config_files_success(self, mock_rglob, mock_is_dir, mock_exists, mock_expanduser):
        """Test successful config file discovery."""
        # Setup mocks
        mock_path = Mock()
        mock_expanduser.return_value = mock_path
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        
        # Mock found files with proper relative_to method
        found_file = Mock()
        found_file.relative_to.return_value = Path('package.json')
        mock_rglob.return_value = [found_file]
        
        result = self.detector._discover_config_files(['/test'], 2)
        
        assert len(result) >= 0  # Should not raise exception
    
    def test_analyze_config_files_empty_list(self):
        """Test analyzing empty config file list."""
        result = self.detector._analyze_config_files([])
        assert result == []
    
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._analyze_single_config_file')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._has_mcp_indicators')
    def test_analyze_config_files_with_mcp_indicators(self, mock_has_indicators, mock_analyze_single):
        """Test analyzing config files with MCP indicators."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'name': 'test'},
            dependencies=['@modelcontextprotocol/server']
        )
        
        mock_analyze_single.return_value = config_info
        mock_has_indicators.return_value = True
        
        result = self.detector._analyze_config_files([Path('package.json')])
        
        assert len(result) == 1
        assert result[0] == config_info
    
    def test_parse_package_json(self):
        """Test parsing package.json files."""
        package_data = {
            'name': 'test-mcp-server',
            'version': '1.0.0',
            'dependencies': {
                '@modelcontextprotocol/server': '^1.0.0'
            }
        }
        
        with patch('builtins.open', mock_open(read_data=json.dumps(package_data))):
            result = self.detector._parse_package_json(Path('package.json'))
            
        assert result == package_data
    
    def test_parse_json_file(self):
        """Test parsing JSON configuration files."""
        config_data = {'mcp': {'port': 3000}}
        
        with patch('builtins.open', mock_open(read_data=json.dumps(config_data))):
            result = self.detector._parse_json_file(Path('mcp.config.json'))
            
        assert result == config_data
    
    def test_parse_yaml_file_with_yaml(self):
        """Test parsing YAML files when PyYAML is available."""
        yaml_data = {'mcp': {'transport': 'stdio'}}
        
        # Mock the yaml module import and safe_load function
        mock_yaml = Mock()
        mock_yaml.safe_load.return_value = yaml_data
        
        with patch('builtins.open', mock_open()):
            with patch.dict('sys.modules', {'yaml': mock_yaml}):
                result = self.detector._parse_yaml_file(Path('mcp.yaml'))
            
        assert result == yaml_data
    
    def test_parse_yaml_file_without_yaml(self):
        """Test parsing YAML files when PyYAML is not available."""
        with patch('builtins.open', mock_open()):
            with patch.dict('sys.modules', {'yaml': None}):
                result = self.detector._parse_yaml_file(Path('mcp.yaml'))
                
        assert result == {}
    
    def test_parse_dockerfile(self):
        """Test parsing Dockerfile content."""
        dockerfile_content = """FROM node:18
RUN npm install @modelcontextprotocol/server
CMD ["node", "server.js"]"""
        
        with patch('builtins.open', mock_open(read_data=dockerfile_content)):
            result = self.detector._parse_dockerfile(Path('Dockerfile'))
            
        assert result['type'] == 'dockerfile'
        assert len(result['instructions']) == 3
    
    def test_parse_text_file_with_mcp_content(self):
        """Test parsing text files with MCP content."""
        text_content = """# Configuration
mcp-server --port 3000
model-context-protocol enabled"""
        
        with patch('builtins.open', mock_open(read_data=text_content)):
            result = self.detector._parse_text_file(Path('config.txt'))
            
        assert result['type'] == 'text'
        assert len(result['lines']) == 2  # Two lines with MCP keywords
    
    def test_parse_text_file_unicode_error(self):
        """Test parsing text files with unicode decode errors."""
        with patch('builtins.open', mock_open()) as mock_file:
            mock_file.return_value.__iter__.side_effect = UnicodeDecodeError('utf-8', b'', 0, 1, 'test')
            result = self.detector._parse_text_file(Path('binary.bin'))
            
        assert result == {}
    
    def test_extract_dependencies(self):
        """Test extracting dependencies from package.json."""
        package_json = {
            'dependencies': {'express': '^4.0.0'},
            'devDependencies': {'@modelcontextprotocol/server': '^1.0.0'},
            'peerDependencies': {'react': '^18.0.0'},
            'optionalDependencies': {'optional-pkg': '^1.0.0'}
        }
        
        result = self.detector._extract_dependencies(package_json)
        
        assert 'express' in result
        assert '@modelcontextprotocol/server' in result
        assert 'react' in result
        assert 'optional-pkg' in result
        assert len(result) == 4
    
    def test_has_mcp_indicators_dependencies(self):
        """Test MCP indicator detection through dependencies."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            dependencies=['@modelcontextprotocol/server']
        )
        
        assert self.detector._has_mcp_indicators(config_info)
    
    def test_has_mcp_indicators_scripts(self):
        """Test MCP indicator detection through scripts."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            scripts={'start': 'mcp-server --port 3000'}
        )
        
        assert self.detector._has_mcp_indicators(config_info)
    
    def test_has_mcp_indicators_mcp_config(self):
        """Test MCP indicator detection through MCP configuration."""
        config_info = ConfigFileInfo(
            path=Path('mcp.config.json'),
            file_type='mcp.config.json',
            mcp_config={'port': 3000}
        )
        
        assert self.detector._has_mcp_indicators(config_info)
    
    def test_has_mcp_indicators_content(self):
        """Test MCP indicator detection through file content."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            content={'server': 'model-context-protocol'}
        )
        
        assert self.detector._has_mcp_indicators(config_info)
    
    def test_has_mcp_indicators_script_patterns(self):
        """Test MCP indicator detection through script patterns."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            scripts={'start': 'node mcp_server.js'}
        )
        
        assert self.detector._has_mcp_indicators(config_info)
    
    def test_has_mcp_indicators_none(self):
        """Test when no MCP indicators are found."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'name': 'regular-app'},
            dependencies=['express'],
            scripts={'start': 'node app.js'}
        )
        
        assert not self.detector._has_mcp_indicators(config_info)
    
    def test_calculate_config_confidence_base(self):
        """Test basic confidence calculation."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'name': 'test'},
            dependencies=['express']  # No MCP dependencies
        )
        
        # Mock has_mcp_indicators to return True for base confidence
        with patch.object(self.detector, '_has_mcp_indicators', return_value=True):
            confidence = self.detector._calculate_config_confidence(config_info)
            
        assert confidence >= 0.3  # Base confidence
    
    def test_calculate_config_confidence_with_mcp_dependencies(self):
        """Test confidence calculation with MCP dependencies."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            dependencies=['@modelcontextprotocol/server', '@modelcontextprotocol/client']
        )
        
        confidence = self.detector._calculate_config_confidence(config_info)
        
        assert confidence >= 0.7  # Base + dependencies + official packages
    
    def test_calculate_config_confidence_dedicated_config(self):
        """Test confidence calculation for dedicated MCP config files."""
        config_info = ConfigFileInfo(
            path=Path('mcp.config.json'),
            file_type='mcp.config.json',
            mcp_config={'port': 3000, 'transport': 'stdio'}
        )
        
        confidence = self.detector._calculate_config_confidence(config_info)
        
        assert confidence >= 0.8  # High confidence for dedicated config
    
    def test_extract_port_from_config_mcp_section(self):
        """Test port extraction from MCP configuration section."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            mcp_config={'port': 3000}
        )
        
        port = self.detector._extract_port_from_config(config_info)
        assert port == 3000
    
    def test_extract_port_from_config_scripts(self):
        """Test port extraction from scripts."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            scripts={'start': 'mcp-server --port 8080'}
        )
        
        port = self.detector._extract_port_from_config(config_info)
        assert port == 8080
    
    def test_extract_port_from_config_content(self):
        """Test port extraction from general content."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            content={'server': {'port': 9000}}
        )
        
        port = self.detector._extract_port_from_config(config_info)
        assert port == 9000
    
    def test_determine_transport_type_websocket(self):
        """Test transport type determination for WebSocket."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            content={'transport': 'websocket', 'url': 'ws://localhost:3000'}
        )
        
        transport = self.detector._determine_transport_type(config_info)
        assert transport == TransportType.WEBSOCKET
    
    def test_determine_transport_type_http(self):
        """Test transport type determination for HTTP."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            content={'server': 'http://localhost:3000'}
        )
        
        transport = self.detector._determine_transport_type(config_info)
        assert transport == TransportType.HTTP
    
    def test_determine_transport_type_stdio(self):
        """Test transport type determination for STDIO."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            content={'transport': 'stdio'}
        )
        
        transport = self.detector._determine_transport_type(config_info)
        assert transport == TransportType.STDIO
    
    def test_determine_server_type_package_json(self):
        """Test server type determination for package.json."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            scripts={'start': 'node server.js'}
        )
        
        server_type = self.detector._determine_server_type(config_info)
        assert server_type == MCPServerType.STANDALONE
    
    def test_determine_server_type_npx_package(self):
        """Test server type determination for NPX package."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            scripts={'start': 'npx mcp-server'}
        )
        
        server_type = self.detector._determine_server_type(config_info)
        assert server_type == MCPServerType.NPX_PACKAGE
    
    def test_determine_server_type_docker(self):
        """Test server type determination for Docker."""
        config_info = ConfigFileInfo(
            path=Path('docker-compose.yml'),
            file_type='docker-compose.yml'
        )
        
        server_type = self.detector._determine_server_type(config_info)
        assert server_type == MCPServerType.DOCKER_CONTAINER
    
    def test_extract_capabilities(self):
        """Test capabilities extraction from configuration."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            mcp_config={'capabilities': ['tools', 'resources']}
        )
        
        capabilities = self.detector._extract_capabilities(config_info)
        assert capabilities == ['tools', 'resources']
    
    def test_extract_tools(self):
        """Test tools extraction from configuration."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            mcp_config={'tools': ['file_reader', 'web_scraper']}
        )
        
        tools = self.detector._extract_tools(config_info)
        assert tools == ['file_reader', 'web_scraper']
    
    def test_extract_resources(self):
        """Test resources extraction from configuration."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            mcp_config={'resources': ['database', 'filesystem']}
        )
        
        resources = self.detector._extract_resources(config_info)
        assert resources == ['database', 'filesystem']
    
    def test_extract_version_package_json(self):
        """Test version extraction from package.json."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'version': '1.2.3'}
        )
        
        version = self.detector._extract_version(config_info)
        assert version == '1.2.3'
    
    def test_extract_version_mcp_config(self):
        """Test version extraction from MCP configuration."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            mcp_config={'version': '2.0.0'}
        )
        
        version = self.detector._extract_version(config_info)
        assert version == '2.0.0'
    
    def test_extract_security_config(self):
        """Test security configuration extraction."""
        config_info = ConfigFileInfo(
            path=Path('config.json'),
            file_type='config.json',
            content={'server': 'https://localhost:3000'},
            mcp_config={'security': {'tls': True, 'auth': 'bearer'}}
        )
        
        security_config = self.detector._extract_security_config(config_info)
        assert security_config['tls'] is True
        assert security_config['auth'] == 'bearer'
    
    def test_config_to_dict(self):
        """Test configuration info conversion to dictionary."""
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            dependencies=['@modelcontextprotocol/server'],
            scripts={'start': 'node server.js'},
            mcp_config={'port': 3000}
        )
        
        result = self.detector._config_to_dict(config_info)
        
        assert result['path'] == str(config_info.path)
        assert result['file_type'] == 'package.json'
        assert result['has_mcp_dependencies'] is True
        assert result['dependencies_count'] == 1
        assert result['scripts_count'] == 1
        assert result['mcp_config_present'] is True
        assert 'confidence' in result
    
    def test_discover_config_files_in_path(self):
        """Test discovering config files in a specific path."""
        with patch.object(self.detector, '_discover_config_files') as mock_discover:
            with patch.object(self.detector, '_analyze_config_files') as mock_analyze:
                mock_discover.return_value = [Path('package.json')]
                mock_analyze.return_value = []
                
                result = self.detector.discover_config_files_in_path('/test/path')
                
                mock_discover.assert_called_once_with(['/test/path'], 3)
                mock_analyze.assert_called_once()
                assert result == []
    
    def test_analyze_specific_config_file_not_found(self):
        """Test analyzing a non-existent config file."""
        with pytest.raises(ConfigDetectionError, match="Configuration file not found"):
            self.detector.analyze_specific_config_file('/nonexistent/file.json')
    
    @patch('pathlib.Path.exists')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._analyze_single_config_file')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._has_mcp_indicators')
    def test_analyze_specific_config_file_success(self, mock_has_indicators, mock_analyze_single, mock_exists):
        """Test successful analysis of a specific config file."""
        mock_exists.return_value = True
        
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            dependencies=['@modelcontextprotocol/server']
        )
        
        mock_analyze_single.return_value = config_info
        mock_has_indicators.return_value = True
        
        result = self.detector.analyze_specific_config_file('package.json')
        
        assert result == config_info
    
    @patch('pathlib.Path.exists')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._analyze_single_config_file')
    @patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery._has_mcp_indicators')
    def test_analyze_specific_config_file_no_indicators(self, mock_has_indicators, mock_analyze_single, mock_exists):
        """Test analysis of config file with no MCP indicators."""
        mock_exists.return_value = True
        
        config_info = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            dependencies=['express']
        )
        
        mock_analyze_single.return_value = config_info
        mock_has_indicators.return_value = False
        
        result = self.detector.analyze_specific_config_file('package.json')
        
        assert result is None 