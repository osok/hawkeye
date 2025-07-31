"""
Unit tests for Transport Layer Detection.

This module tests the TransportDetector class functionality including
HTTP, WebSocket, and STDIO transport identification.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.hawkeye.detection.transport_detect import TransportDetector
from src.hawkeye.detection.base import (
    DetectionResult,
    DetectionMethod,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ProcessInfo,
    ConfigFileInfo,
)


class TestTransportDetector(unittest.TestCase):
    """Test cases for TransportDetector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = TransportDetector()
        
        # Sample process info for testing
        self.sample_process_http = ProcessInfo(
            pid=1234,
            name='node',
            cmdline=['node', 'server.js', '--port', '3000'],
            cwd='/home/user/mcp-server'
        )
        
        self.sample_process_stdio = ProcessInfo(
            pid=1235,
            name='node',
            cmdline=['npx', '@modelcontextprotocol/server-filesystem'],
            cwd='/home/user/mcp-tools'
        )
        
        self.sample_process_websocket = ProcessInfo(
            pid=1236,
            name='node',
            cmdline=['node', 'ws-server.js', '--websocket', '--port', '8080'],
            cwd='/home/user/ws-server'
        )
        
        # Sample config info for testing
        self.sample_config_http = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'scripts': {'start': 'node server.js --port 3000'}},
            dependencies=['express']
        )
        
        self.sample_config_websocket = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'scripts': {'start': 'node server.js --websocket'}},
            dependencies=['ws', 'socket.io']
        )
    
    def test_get_detection_method(self):
        """Test detection method identification."""
        method = self.detector.get_detection_method()
        self.assertEqual(method, DetectionMethod.TRANSPORT_DETECTION)
    
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._analyze_all_transports')
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._select_best_transport')
    def test_detect_success(self, mock_select, mock_analyze):
        """Test successful transport detection."""
        # Setup mocks
        transport_results = [
            {
                'transport_type': TransportType.HTTP,
                'port': 3000,
                'confidence': 0.8,
                'details': {'port_open': True},
                'security_config': {'tls': False}
            }
        ]
        mock_analyze.return_value = transport_results
        mock_select.return_value = transport_results[0]
        
        # Test detection
        result = self.detector.detect("localhost", port=3000, process_info=self.sample_process_http)
        
        # Verify
        self.assertTrue(result.success)
        self.assertEqual(result.confidence, 0.8)
        self.assertIsNotNone(result.mcp_server)
        self.assertEqual(result.mcp_server.transport_type, TransportType.HTTP)
        self.assertEqual(result.mcp_server.port, 3000)
    
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._analyze_all_transports')
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._select_best_transport')
    def test_detect_no_transport_found(self, mock_select, mock_analyze):
        """Test detection when no transport is found."""
        # Setup mocks
        mock_analyze.return_value = []
        mock_select.return_value = None
        
        # Test detection
        result = self.detector.detect("localhost")
        
        # Verify
        self.assertFalse(result.success)
        self.assertIn("No MCP transport layer detected", result.error)
    
    def test_detect_with_exception(self):
        """Test detection with exception handling."""
        with patch('src.hawkeye.detection.transport_detect.TransportDetector._analyze_all_transports') as mock_analyze:
            mock_analyze.side_effect = Exception("Network error")
            
            result = self.detector.detect("localhost")
            
            self.assertFalse(result.success)
            self.assertIn("Network error", result.error)
    
    def test_analyze_all_transports_localhost_with_process(self):
        """Test transport analysis for localhost with process info."""
        with patch.object(self.detector, '_analyze_stdio_transport') as mock_stdio, \
             patch.object(self.detector, '_analyze_http_transport') as mock_http, \
             patch.object(self.detector, '_analyze_websocket_transport') as mock_ws, \
             patch.object(self.detector, '_get_candidate_http_ports') as mock_http_ports, \
             patch.object(self.detector, '_get_candidate_websocket_ports') as mock_ws_ports:
            
            # Setup mocks
            mock_stdio.return_value = {'transport_type': TransportType.STDIO, 'confidence': 0.8}
            mock_http.return_value = {'transport_type': TransportType.HTTP, 'confidence': 0.6}
            mock_ws.return_value = {'transport_type': TransportType.WEBSOCKET, 'confidence': 0.4}
            mock_http_ports.return_value = [3000]
            mock_ws_ports.return_value = [3000]
            
            # Test analysis
            results = self.detector._analyze_all_transports(
                "localhost", None, self.sample_process_stdio, None
            )
            
            # Verify STDIO was analyzed
            mock_stdio.assert_called_once()
            # Verify HTTP and WebSocket were analyzed
            mock_http.assert_called_once()
            mock_ws.assert_called_once()
            
            # Should have 3 results (all with confidence > 0)
            self.assertEqual(len(results), 3)
    
    def test_analyze_all_transports_remote_host(self):
        """Test transport analysis for remote host (no STDIO)."""
        with patch.object(self.detector, '_analyze_stdio_transport') as mock_stdio, \
             patch.object(self.detector, '_analyze_http_transport') as mock_http, \
             patch.object(self.detector, '_analyze_websocket_transport') as mock_ws, \
             patch.object(self.detector, '_get_candidate_http_ports') as mock_http_ports, \
             patch.object(self.detector, '_get_candidate_websocket_ports') as mock_ws_ports:
            
            # Setup mocks
            mock_http.return_value = {'transport_type': TransportType.HTTP, 'confidence': 0.6}
            mock_ws.return_value = {'transport_type': TransportType.WEBSOCKET, 'confidence': 0.0}
            mock_http_ports.return_value = [3000]
            mock_ws_ports.return_value = [3000]
            
            # Test analysis
            results = self.detector._analyze_all_transports(
                "remote-host", None, self.sample_process_http, None
            )
            
            # Verify STDIO was NOT analyzed
            mock_stdio.assert_not_called()
            # Verify HTTP was analyzed
            mock_http.assert_called_once()
            # Should have 1 result (only HTTP with confidence > 0)
            self.assertEqual(len(results), 1)
    
    def test_analyze_stdio_transport_with_npx(self):
        """Test STDIO transport analysis with NPX process."""
        result = self.detector._analyze_stdio_transport(self.sample_process_stdio, None)
        
        self.assertEqual(result['transport_type'], TransportType.STDIO)
        self.assertGreater(result['confidence'], 0.5)  # Should be high confidence for NPX
        self.assertTrue(result['details']['npx_execution'])
        self.assertTrue(result['security_config']['secure'])
    
    def test_analyze_stdio_transport_no_process(self):
        """Test STDIO transport analysis without process info."""
        result = self.detector._analyze_stdio_transport(None, None)
        
        self.assertEqual(result['transport_type'], TransportType.STDIO)
        self.assertEqual(result['confidence'], 0.0)
        self.assertIn('error', result['details'])
    
    def test_analyze_stdio_transport_with_config(self):
        """Test STDIO transport analysis with configuration reference."""
        config = ConfigFileInfo(
            path=Path('config.json'),
            file_type='json',
            content={'transport': 'stdio'},
            dependencies=[]
        )
        
        result = self.detector._analyze_stdio_transport(self.sample_process_stdio, config)
        
        self.assertGreater(result['confidence'], 0.6)
        self.assertTrue(result['details']['config_stdio_reference'])
    
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._is_port_open')
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._test_http_connectivity')
    def test_analyze_http_transport_success(self, mock_http_test, mock_port_open):
        """Test successful HTTP transport analysis."""
        # Setup mocks
        mock_port_open.return_value = True
        mock_http_test.return_value = {
            'success': True,
            'details': {'protocol': 'http', 'status_code': 200},
            'security': {'tls': False}
        }
        
        result = self.detector._analyze_http_transport(
            "localhost", 3000, self.sample_process_http, self.sample_config_http
        )
        
        self.assertEqual(result['transport_type'], TransportType.HTTP)
        self.assertEqual(result['port'], 3000)
        self.assertGreater(result['confidence'], 0.7)  # Port open + HTTP response + indicators
        self.assertTrue(result['details']['port_open'])
        self.assertTrue(result['details']['port_in_cmdline'])
    
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._is_port_open')
    def test_analyze_http_transport_port_closed(self, mock_port_open):
        """Test HTTP transport analysis with closed port."""
        mock_port_open.return_value = False
        
        result = self.detector._analyze_http_transport(
            "localhost", 3000, self.sample_process_http, None
        )
        
        self.assertEqual(result['transport_type'], TransportType.HTTP)
        # Should still have some confidence from process indicators
        self.assertGreater(result['confidence'], 0.0)
        self.assertLess(result['confidence'], 0.5)
    
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._is_port_open')
    @patch('src.hawkeye.detection.transport_detect.TransportDetector._test_websocket_connectivity')
    def test_analyze_websocket_transport_success(self, mock_ws_test, mock_port_open):
        """Test successful WebSocket transport analysis."""
        # Setup mocks
        mock_port_open.return_value = True
        mock_ws_test.return_value = {
            'success': True,
            'details': {'protocol': 'ws', 'upgrade_response': True},
            'security': {'secure': False}
        }
        
        result = self.detector._analyze_websocket_transport(
            "localhost", 8080, self.sample_process_websocket, self.sample_config_websocket
        )
        
        self.assertEqual(result['transport_type'], TransportType.WEBSOCKET)
        self.assertEqual(result['port'], 8080)
        self.assertGreater(result['confidence'], 0.7)  # Port open + WS response + indicators
        self.assertTrue(result['details']['port_open'])
        self.assertTrue(result['details']['cmdline_websocket'])
    
    def test_get_candidate_http_ports_with_process(self):
        """Test HTTP port candidate extraction from process."""
        ports = self.detector._get_candidate_http_ports(self.sample_process_http, None)
        
        # Should include the port from command line (3000) plus common ports
        self.assertIn(3000, ports)
        self.assertIn(8000, ports)  # Common port
        self.assertIn(443, ports)   # HTTPS port
    
    def test_get_candidate_http_ports_with_config(self):
        """Test HTTP port candidate extraction from config."""
        ports = self.detector._get_candidate_http_ports(None, self.sample_config_http)
        
        # Should include the port from config (3000) plus common ports
        self.assertIn(3000, ports)
        self.assertIn(8000, ports)  # Common port
    
    def test_extract_ports_from_cmdline_various_formats(self):
        """Test port extraction from various command line formats."""
        # Test --port=3000 format
        cmdline1 = ['node', 'server.js', '--port=3000']
        ports = self.detector._extract_ports_from_cmdline(cmdline1)
        self.assertIn(3000, ports)
        
        # Test --port 8080 format
        cmdline2 = ['node', 'server.js', '--port', '8080']
        ports = self.detector._extract_ports_from_cmdline(cmdline2)
        self.assertIn(8080, ports)
        
        # Test -p 9000 format
        cmdline3 = ['node', 'server.js', '-p', '9000']
        ports = self.detector._extract_ports_from_cmdline(cmdline3)
        self.assertIn(9000, ports)
        
        # Test standalone number
        cmdline4 = ['node', 'server.js', '3001']
        ports = self.detector._extract_ports_from_cmdline(cmdline4)
        self.assertIn(3001, ports)
    
    def test_extract_ports_from_config_json(self):
        """Test port extraction from JSON configuration."""
        config = ConfigFileInfo(
            path=Path('config.json'),
            file_type='json',
            content={'port': 4000, 'listen': 5000},
            dependencies=[]
        )
        
        ports = self.detector._extract_ports_from_config(config)
        
        self.assertIn(4000, ports)
        self.assertIn(5000, ports)
    
    @patch('socket.create_connection')
    def test_is_port_open_success(self, mock_connection):
        """Test successful port connectivity check."""
        mock_connection.return_value.__enter__ = Mock()
        mock_connection.return_value.__exit__ = Mock()
        
        result = self.detector._is_port_open("localhost", 3000)
        
        self.assertTrue(result)
        mock_connection.assert_called_once_with(("localhost", 3000), timeout=2.0)
    
    @patch('socket.create_connection')
    def test_is_port_open_failure(self, mock_connection):
        """Test failed port connectivity check."""
        mock_connection.side_effect = ConnectionError("Connection refused")
        
        result = self.detector._is_port_open("localhost", 3000)
        
        self.assertFalse(result)
    
    @patch('requests.Session.get')
    def test_test_http_connectivity_success(self, mock_get):
        """Test successful HTTP connectivity test."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'Express/4.18.0', 'Content-Type': 'application/json'}
        mock_get.return_value = mock_response
        
        result = self.detector._test_http_connectivity("localhost", 3000)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['details']['protocol'], 'http')
        self.assertEqual(result['details']['status_code'], 200)
        self.assertEqual(result['details']['framework'], 'express')
        self.assertFalse(result['security']['tls'])
    
    @patch('requests.Session.get')
    def test_test_http_connectivity_https(self, mock_get):
        """Test HTTPS connectivity test."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'nginx/1.18.0'}
        mock_get.return_value = mock_response
        
        result = self.detector._test_http_connectivity("localhost", 443)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['details']['protocol'], 'https')
        self.assertTrue(result['security']['tls'])
    
    @patch('requests.Session.get')
    def test_test_http_connectivity_failure(self, mock_get):
        """Test failed HTTP connectivity test."""
        from requests.exceptions import RequestException
        mock_get.side_effect = RequestException("Connection refused")
        
        result = self.detector._test_http_connectivity("localhost", 3000)
        
        self.assertFalse(result['success'])
    
    @patch('requests.Session.get')
    def test_test_websocket_connectivity_upgrade_response(self, mock_get):
        """Test WebSocket connectivity with upgrade response."""
        # Setup mock response with WebSocket upgrade
        mock_response = Mock()
        mock_response.status_code = 101
        mock_response.headers = {'Connection': 'Upgrade', 'Upgrade': 'websocket'}
        mock_get.return_value = mock_response
        
        result = self.detector._test_websocket_connectivity("localhost", 3000)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['details']['protocol'], 'ws')
        self.assertTrue(result['details']['upgrade_response'])
        self.assertFalse(result['security']['secure'])
    
    @patch('requests.Session.get')
    def test_test_websocket_connectivity_wss(self, mock_get):
        """Test secure WebSocket connectivity."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 101
        mock_response.headers = {'Connection': 'Upgrade', 'Upgrade': 'websocket'}
        mock_get.return_value = mock_response
        
        result = self.detector._test_websocket_connectivity("localhost", 443)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['details']['protocol'], 'wss')
        self.assertTrue(result['security']['secure'])
    
    def test_select_best_transport_highest_confidence(self):
        """Test selection of transport with highest confidence."""
        transport_results = [
            {'transport_type': TransportType.HTTP, 'confidence': 0.6},
            {'transport_type': TransportType.STDIO, 'confidence': 0.8},
            {'transport_type': TransportType.WEBSOCKET, 'confidence': 0.4}
        ]
        
        best = self.detector._select_best_transport(transport_results)
        
        self.assertIsNotNone(best)
        self.assertEqual(best['transport_type'], TransportType.STDIO)
        self.assertEqual(best['confidence'], 0.8)
    
    def test_select_best_transport_below_threshold(self):
        """Test selection when all transports are below confidence threshold."""
        transport_results = [
            {'transport_type': TransportType.HTTP, 'confidence': 0.2},
            {'transport_type': TransportType.WEBSOCKET, 'confidence': 0.1}
        ]
        
        best = self.detector._select_best_transport(transport_results)
        
        self.assertIsNone(best)  # All below 0.3 threshold
    
    def test_select_best_transport_empty_list(self):
        """Test selection with empty transport list."""
        best = self.detector._select_best_transport([])
        
        self.assertIsNone(best)
    
    def test_determine_server_type_npx(self):
        """Test server type determination for NPX package."""
        server_type = self.detector._determine_server_type(self.sample_process_stdio, None)
        
        self.assertEqual(server_type, MCPServerType.NPX_PACKAGE)
    
    def test_determine_server_type_docker_process(self):
        """Test server type determination for Docker process."""
        docker_process = ProcessInfo(
            pid=1237,
            name='node',
            cmdline=['docker', 'run', 'mcp-server'],
            cwd='/home/user'
        )
        
        server_type = self.detector._determine_server_type(docker_process, None)
        
        self.assertEqual(server_type, MCPServerType.DOCKER_CONTAINER)
    
    def test_determine_server_type_docker_config(self):
        """Test server type determination for Docker config."""
        docker_config = ConfigFileInfo(
            path=Path('Dockerfile'),
            file_type='dockerfile',
            content={},
            dependencies=[]
        )
        
        server_type = self.detector._determine_server_type(None, docker_config)
        
        self.assertEqual(server_type, MCPServerType.DOCKER_CONTAINER)
    
    def test_determine_server_type_standalone(self):
        """Test server type determination for standalone server."""
        server_type = self.detector._determine_server_type(self.sample_process_http, None)
        
        self.assertEqual(server_type, MCPServerType.STANDALONE)
    
    def test_analyze_transport_security_stdio(self):
        """Test security analysis for STDIO transport."""
        security = self.detector.analyze_transport_security(TransportType.STDIO, "localhost")
        
        self.assertTrue(security['secure'])
        self.assertTrue(security['encryption'])
        self.assertTrue(security['authentication'])
        self.assertEqual(len(security['vulnerabilities']), 0)
        self.assertIn('process isolation', security['recommendations'][0])
    
    def test_analyze_transport_security_http_insecure(self):
        """Test security analysis for insecure HTTP transport."""
        security = self.detector.analyze_transport_security(TransportType.HTTP, "localhost", 3000)
        
        self.assertFalse(security['secure'])
        self.assertFalse(security['encryption'])
        self.assertIn('Unencrypted HTTP transport', security['vulnerabilities'])
        self.assertIn('Use HTTPS instead of HTTP', security['recommendations'])
    
    def test_analyze_transport_security_https_secure(self):
        """Test security analysis for secure HTTPS transport."""
        security = self.detector.analyze_transport_security(TransportType.HTTP, "localhost", 443)
        
        self.assertTrue(security['secure'])
        self.assertTrue(security['encryption'])
    
    def test_analyze_transport_security_websocket_insecure(self):
        """Test security analysis for insecure WebSocket transport."""
        security = self.detector.analyze_transport_security(TransportType.WEBSOCKET, "localhost", 3000)
        
        self.assertFalse(security['secure'])
        self.assertFalse(security['encryption'])
        self.assertIn('Unencrypted WebSocket transport', security['vulnerabilities'])
        self.assertIn('Use WSS instead of WS', security['recommendations'])
    
    def test_analyze_transport_security_websocket_secure(self):
        """Test security analysis for secure WebSocket transport."""
        security = self.detector.analyze_transport_security(TransportType.WEBSOCKET, "localhost", 443)
        
        self.assertTrue(security['secure'])
        self.assertTrue(security['encryption'])


if __name__ == '__main__':
    unittest.main()