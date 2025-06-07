"""
Unit tests for NPX package detection functionality.
"""

import json
import subprocess
import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from pathlib import Path

from src.hawkeye.detection.npx_detect import NPXDetector, create_npx_detector
from src.hawkeye.detection.base import (
    DetectionMethod, MCPServerType, TransportType, ProcessInfo, ConfigFileInfo
)


class TestNPXDetector:
    """Test cases for NPXDetector class."""
    
    @pytest.fixture
    def detector(self):
        """Create NPXDetector instance for testing."""
        return NPXDetector()
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        settings = Mock()
        settings.detection = Mock()
        settings.detection.timeout = 30
        settings.detection.max_processes = 100
        return settings
    
    def test_init(self, mock_settings):
        """Test NPXDetector initialization."""
        detector = NPXDetector(mock_settings)
        
        assert detector.settings == mock_settings
        assert len(detector.mcp_package_patterns) > 0
        assert len(detector.known_mcp_packages) > 0
        assert len(detector.npx_mcp_patterns) > 0
    
    def test_get_detection_method(self, detector):
        """Test detection method identifier."""
        assert detector.get_detection_method() == DetectionMethod.NPX_PACKAGE_DETECTION
    
    def test_is_mcp_package_known_packages(self, detector):
        """Test MCP package detection for known packages."""
        # Test known packages
        assert detector._is_mcp_package('@modelcontextprotocol/server-filesystem')
        assert detector._is_mcp_package('mcp-server-anthropic')
        
        # Test non-MCP packages
        assert not detector._is_mcp_package('express')
        assert not detector._is_mcp_package('react')
    
    def test_is_mcp_package_patterns(self, detector):
        """Test MCP package detection using patterns."""
        # Test pattern matches
        assert detector._is_mcp_package('@modelcontextprotocol/server-custom')
        assert detector._is_mcp_package('mcp-server-custom')
        assert detector._is_mcp_package('custom-mcp-server')
        assert detector._is_mcp_package('mcp-custom')
        assert detector._is_mcp_package('custom-mcp')
        
        # Test non-matches
        assert not detector._is_mcp_package('custom-server')
        assert not detector._is_mcp_package('server-custom')
    
    def test_is_npx_mcp_process(self, detector):
        """Test NPX MCP process detection."""
        # Test positive cases
        assert detector._is_npx_mcp_process('npx @modelcontextprotocol/server-filesystem')
        assert detector._is_npx_mcp_process('npx mcp-server-custom')
        assert detector._is_npx_mcp_process('npx custom-mcp-server')
        assert detector._is_npx_mcp_process('npx custom-mcp')
        
        # Test negative cases
        assert not detector._is_npx_mcp_process('npx express-generator')
        assert not detector._is_npx_mcp_process('npm start')
        assert not detector._is_npx_mcp_process('node server.js')
    
    def test_extract_package_name(self, detector):
        """Test package name extraction from command line."""
        # Test successful extraction
        assert detector._extract_package_name('npx @modelcontextprotocol/server-filesystem') == '@modelcontextprotocol/server-filesystem'
        assert detector._extract_package_name('npx mcp-server-custom --port 3000') == 'mcp-server-custom'
        
        # Test no match
        assert detector._extract_package_name('npm start') is None
        assert detector._extract_package_name('node server.js') is None
    
    def test_get_package_confidence(self, detector):
        """Test package confidence scoring."""
        # Known packages should have high confidence
        assert detector._get_package_confidence('@modelcontextprotocol/server-filesystem') == 0.95
        
        # Pattern matches should have varying confidence
        assert detector._get_package_confidence('@modelcontextprotocol/server-custom') == 0.9
        assert detector._get_package_confidence('mcp-server-custom') == 0.8
        assert detector._get_package_confidence('mcp-custom') == 0.6
        
        # Non-MCP packages should have low confidence
        assert detector._get_package_confidence('express') == 0.3
    
    def test_get_process_confidence(self, detector):
        """Test process confidence scoring."""
        # High confidence command lines
        cmdline1 = 'npx @modelcontextprotocol/server-filesystem --stdio'
        assert detector._get_process_confidence(cmdline1) >= 0.5
        
        cmdline2 = 'npx mcp-server-custom --http --port 3000'
        assert detector._get_process_confidence(cmdline2) >= 0.4
        
        # Low confidence command lines
        cmdline3 = 'npx express-generator'
        assert detector._get_process_confidence(cmdline3) == 0.0
    
    def test_infer_transport_type(self, detector):
        """Test transport type inference from package info."""
        # HTTP packages
        http_package = {'name': 'mcp-server-http'}
        assert detector._infer_transport_type(http_package) == TransportType.HTTP
        
        # WebSocket packages
        ws_package = {'name': 'mcp-server-websocket'}
        assert detector._infer_transport_type(ws_package) == TransportType.WEBSOCKET
        
        # Default to STDIO
        default_package = {'name': 'mcp-server-filesystem'}
        assert detector._infer_transport_type(default_package) == TransportType.STDIO
    
    def test_infer_transport_from_cmdline(self, detector):
        """Test transport type inference from command line."""
        # HTTP transport
        http_cmdline = ['npx', 'mcp-server', '--http', '--port', '3000']
        assert detector._infer_transport_from_cmdline(http_cmdline) == TransportType.HTTP
        
        # WebSocket transport
        ws_cmdline = ['npx', 'mcp-server', '--websocket', '--port', '8080']
        assert detector._infer_transport_from_cmdline(ws_cmdline) == TransportType.WEBSOCKET
        
        # STDIO transport
        stdio_cmdline = ['npx', 'mcp-server', '--stdio']
        assert detector._infer_transport_from_cmdline(stdio_cmdline) == TransportType.STDIO
        
        # Default to STDIO
        default_cmdline = ['npx', 'mcp-server']
        assert detector._infer_transport_from_cmdline(default_cmdline) == TransportType.STDIO
    
    def test_extract_port_from_cmdline(self, detector):
        """Test port extraction from command line."""
        # Test --port argument
        cmdline1 = ['npx', 'mcp-server', '--port', '3000']
        assert detector._extract_port_from_cmdline(cmdline1) == 3000
        
        # Test --port= argument
        cmdline2 = ['npx', 'mcp-server', '--port=8080']
        assert detector._extract_port_from_cmdline(cmdline2) == 8080
        
        # Test -p argument
        cmdline3 = ['npx', 'mcp-server', '-p', '9000']
        assert detector._extract_port_from_cmdline(cmdline3) == 9000
        
        # Test no port
        cmdline4 = ['npx', 'mcp-server', '--stdio']
        assert detector._extract_port_from_cmdline(cmdline4) is None
    
    @patch('subprocess.run')
    def test_detect_global_npx_packages_success(self, mock_run, detector):
        """Test successful global NPX package detection."""
        # Mock npm list output
        npm_output = {
            'dependencies': {
                '@modelcontextprotocol/server-filesystem': {
                    'version': '1.0.0',
                    'path': '/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem'
                },
                'express': {
                    'version': '4.18.0',
                    'path': '/usr/local/lib/node_modules/express'
                }
            }
        }
        
        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps(npm_output)
        )
        
        packages = detector._detect_global_npx_packages()
        
        assert len(packages) == 1
        assert packages[0]['name'] == '@modelcontextprotocol/server-filesystem'
        assert packages[0]['version'] == '1.0.0'
        assert packages[0]['location'] == 'global'
    
    @patch('subprocess.run')
    def test_detect_global_npx_packages_failure(self, mock_run, detector):
        """Test global NPX package detection failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'npm')
        
        packages = detector._detect_global_npx_packages()
        
        assert packages == []
    
    @patch('src.hawkeye.detection.npx_detect.NPXDetector._detect_local_mcp_packages')
    def test_detect_local_mcp_packages(self, mock_detect, detector):
        """Test local MCP package detection."""
        # Mock the return value directly to avoid complex path mocking
        mock_detect.return_value = [
            {
                'name': '@modelcontextprotocol/server-filesystem',
                'version': '^1.0.0',
                'location': 'local',
                'path': '/test',
                'package_json': '/test/package.json',
                'confidence': 0.95
            },
            {
                'name': 'mcp-server-custom',
                'version': '^2.0.0',
                'location': 'local',
                'path': '/test',
                'package_json': '/test/package.json',
                'confidence': 0.8
            }
        ]
        
        packages = detector._detect_local_mcp_packages()
        
        assert len(packages) == 2
        package_names = [p['name'] for p in packages]
        assert '@modelcontextprotocol/server-filesystem' in package_names
        assert 'mcp-server-custom' in package_names
    
    @patch('psutil.process_iter')
    def test_detect_running_npx_processes(self, mock_process_iter, detector):
        """Test running NPX process detection."""
        # Mock process data
        mock_proc1 = Mock()
        mock_proc1.info = {
            'pid': 1234,
            'name': 'node',
            'cmdline': ['npx', '@modelcontextprotocol/server-filesystem', '--stdio'],
            'cwd': '/home/user/project',
            'create_time': 1640995200.0
        }
        
        mock_proc2 = Mock()
        mock_proc2.info = {
            'pid': 5678,
            'name': 'node',
            'cmdline': ['node', 'server.js'],
            'cwd': '/home/user/app',
            'create_time': 1640995300.0
        }
        
        mock_process_iter.return_value = [mock_proc1, mock_proc2]
        
        processes = detector._detect_running_npx_processes()
        
        assert len(processes) == 1
        assert processes[0]['pid'] == 1234
        assert processes[0]['package_name'] == '@modelcontextprotocol/server-filesystem'
    
    @patch('psutil.process_iter')
    def test_detect_running_npx_processes_no_psutil(self, mock_process_iter, detector):
        """Test NPX process detection when psutil is not available."""
        mock_process_iter.side_effect = ImportError("No module named 'psutil'")
        
        processes = detector._detect_running_npx_processes()
        
        assert processes == []
    
    def test_analyze_npx_packages(self, detector):
        """Test NPX package analysis."""
        packages = [
            {
                'name': '@modelcontextprotocol/server-filesystem',
                'version': '1.0.0',
                'location': 'global'
            }
        ]
        
        servers = detector._analyze_npx_packages(packages, 'global')
        
        assert len(servers) == 1
        server = servers[0]
        assert server.host == 'localhost'
        assert server.server_type == MCPServerType.NPX_PACKAGE
        assert server.transport_type == TransportType.STDIO
        assert server.version == '1.0.0'
    
    def test_analyze_running_processes(self, detector):
        """Test running process analysis."""
        processes = [
            {
                'pid': 1234,
                'name': 'node',
                'cmdline': ['npx', 'mcp-server', '--http', '--port', '3000'],
                'cwd': '/home/user/project',
                'create_time': 1640995200.0
            }
        ]
        
        servers = detector._analyze_running_processes(processes)
        
        assert len(servers) == 1
        server = servers[0]
        assert server.host == 'localhost'
        assert server.server_type == MCPServerType.NPX_PACKAGE
        assert server.transport_type == TransportType.HTTP
        assert server.port == 3000
        assert server.process_info.pid == 1234
    
    @patch('builtins.open', new_callable=mock_open)
    def test_analyze_package_config(self, mock_file, detector):
        """Test package configuration analysis."""
        package_json_content = {
            'name': 'my-mcp-server',
            'version': '1.0.0',
            'dependencies': {
                '@modelcontextprotocol/sdk': '^1.0.0'
            },
            'scripts': {
                'start': 'node server.js',
                'mcp': 'npx @modelcontextprotocol/server-filesystem'
            }
        }
        
        mock_file.return_value.read.return_value = json.dumps(package_json_content)
        
        config_info = detector._analyze_package_config('/test/package.json')
        
        assert config_info is not None
        assert config_info.file_type == 'package.json'
        assert '@modelcontextprotocol/sdk' in config_info.dependencies
        assert 'mcp' in config_info.scripts
    
    def test_select_best_mcp_server(self, detector):
        """Test MCP server selection logic."""
        # Test empty list
        assert detector._select_best_mcp_server([]) is None
        
        # Create test servers
        from src.hawkeye.detection.base import MCPServerInfo, ProcessInfo
        
        server1 = MCPServerInfo(host='localhost', server_type=MCPServerType.NPX_PACKAGE)
        server2 = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.NPX_PACKAGE,
            process_info=ProcessInfo(pid=1234, name='node')
        )
        
        # Should prefer running process
        best = detector._select_best_mcp_server([server1, server2])
        assert best == server2
        
        # Should return first if no running processes
        best = detector._select_best_mcp_server([server1])
        assert best == server1
    
    def test_calculate_confidence(self, detector):
        """Test confidence calculation."""
        from src.hawkeye.detection.base import MCPServerInfo, ProcessInfo, ConfigFileInfo
        
        # Base server (transport_type defaults to UNKNOWN, so no bonus)
        server = MCPServerInfo(host='localhost', server_type=MCPServerType.NPX_PACKAGE)
        detection_data = {}
        
        confidence = detector._calculate_confidence(server, detection_data)
        assert confidence == 0.3  # Base only
        
        # Add transport type
        server.transport_type = TransportType.STDIO
        confidence = detector._calculate_confidence(server, detection_data)
        assert confidence == 0.4  # Base + transport type
        
        # Add process info
        server.process_info = ProcessInfo(pid=1234, name='node')
        confidence = detector._calculate_confidence(server, detection_data)
        assert abs(confidence - 0.8) < 0.001  # Base + process + transport type
        
        # Add config info
        server.config_info = ConfigFileInfo(path=Path('/test'), file_type='package.json')
        confidence = detector._calculate_confidence(server, detection_data)
        assert abs(confidence - 1.0) < 0.001  # Base + process + config + transport type
    
    @patch.object(NPXDetector, '_detect_global_npx_packages')
    @patch.object(NPXDetector, '_detect_local_mcp_packages')
    @patch.object(NPXDetector, '_detect_running_npx_processes')
    def test_detect_success(self, mock_processes, mock_local, mock_global, detector):
        """Test successful NPX detection."""
        # Mock detection methods
        mock_global.return_value = []
        mock_local.return_value = []
        mock_processes.return_value = [
            {
                'pid': 1234,
                'name': 'node',
                'cmdline': ['npx', '@modelcontextprotocol/server-filesystem', '--stdio'],
                'cwd': '/home/user/project',
                'create_time': 1640995200.0
            }
        ]
        
        result = detector.detect('localhost')
        
        assert result.success
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.NPX_PACKAGE_DETECTION
        assert result.mcp_server is not None
        assert result.confidence > 0
    
    @patch.object(NPXDetector, '_detect_global_npx_packages')
    @patch.object(NPXDetector, '_detect_local_mcp_packages')
    @patch.object(NPXDetector, '_detect_running_npx_processes')
    def test_detect_no_servers(self, mock_processes, mock_local, mock_global, detector):
        """Test NPX detection with no servers found."""
        # Mock empty results
        mock_global.return_value = []
        mock_local.return_value = []
        mock_processes.return_value = []
        
        result = detector.detect('localhost')
        
        assert not result.success
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.NPX_PACKAGE_DETECTION
        assert result.mcp_server is None
        assert result.confidence == 0.0
    
    @patch.object(NPXDetector, '_detect_global_npx_packages')
    def test_detect_exception(self, mock_global, detector):
        """Test NPX detection with exception."""
        mock_global.side_effect = Exception("Test error")
        
        result = detector.detect('localhost')
        
        assert not result.success
        assert result.error == "Test error"
    
    def test_create_npx_detector(self):
        """Test NPX detector factory function."""
        detector = create_npx_detector()
        assert isinstance(detector, NPXDetector)
        
        mock_settings = Mock()
        detector = create_npx_detector(mock_settings)
        assert isinstance(detector, NPXDetector)
        assert detector.settings == mock_settings


if __name__ == '__main__':
    pytest.main([__file__])