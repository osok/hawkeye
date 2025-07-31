"""
Unit tests for MCP Protocol Handshake Verification.

This module tests the ProtocolVerifier class functionality including
HTTP, WebSocket, and STDIO transport verification.
"""

import json
import unittest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import asyncio
from pathlib import Path

from src.hawkeye.detection.protocol_verify import ProtocolVerifier
from src.hawkeye.detection.base import (
    DetectionResult,
    DetectionMethod,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ProcessInfo,
    ConfigFileInfo,
)


class TestProtocolVerifier(unittest.TestCase):
    """Test cases for ProtocolVerifier class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.verifier = ProtocolVerifier()
        
        # Sample process info for testing
        self.sample_process = ProcessInfo(
            pid=1234,
            name='node',
            cmdline=['npx', '@modelcontextprotocol/server-filesystem', '--port', '3000'],
            cwd='/home/user/mcp-server'
        )
        
        # Sample config info for testing
        self.sample_config = ConfigFileInfo(
            path=Path('package.json'),
            file_type='package.json',
            content={'name': 'test-mcp-server'},
            dependencies=['@modelcontextprotocol/server']
        )
    
    def test_get_detection_method(self):
        """Test detection method identification."""
        method = self.verifier.get_detection_method()
        self.assertEqual(method, DetectionMethod.PROTOCOL_HANDSHAKE)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_transport')
    def test_detect_with_specific_transport(self, mock_verify):
        """Test detection with specific transport type."""
        # Setup mock
        expected_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            confidence=0.9
        )
        mock_verify.return_value = expected_result
        
        # Test detection
        result = self.verifier.detect(
            "localhost", 
            port=3000, 
            transport_type=TransportType.HTTP
        )
        
        # Verify
        self.assertTrue(result.success)
        self.assertEqual(result.confidence, 0.9)
        mock_verify.assert_called_once_with(
            "localhost", 3000, TransportType.HTTP
        )
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._auto_detect_and_verify')
    def test_detect_auto_detection(self, mock_auto_detect):
        """Test detection with auto transport detection."""
        # Setup mock
        expected_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            confidence=0.8
        )
        mock_auto_detect.return_value = expected_result
        
        # Test detection
        result = self.verifier.detect("localhost", port=3000)
        
        # Verify
        self.assertTrue(result.success)
        self.assertEqual(result.confidence, 0.8)
        mock_auto_detect.assert_called_once_with("localhost", 3000)
    
    def test_detect_with_exception(self):
        """Test detection with exception handling."""
        with patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._auto_detect_and_verify') as mock_auto:
            mock_auto.side_effect = Exception("Network error")
            
            result = self.verifier.detect("localhost", port=3000)
            
            self.assertFalse(result.success)
            self.assertIn("Network error", result.error)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_transport')
    def test_auto_detect_and_verify_with_port(self, mock_verify):
        """Test auto detection with port specified."""
        # Setup mocks for different transport attempts
        http_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            confidence=0.9
        )
        
        mock_verify.return_value = http_result
        
        # Test auto detection
        result = self.verifier._auto_detect_and_verify("localhost", 3000)
        
        # Verify HTTP was tried first and succeeded
        self.assertTrue(result.success)
        self.assertEqual(result.confidence, 0.9)
        mock_verify.assert_called_with("localhost", 3000, TransportType.HTTP)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_transport')
    def test_auto_detect_with_process_info(self, mock_verify):
        """Test auto detection with process information."""
        # Setup mock for STDIO transport
        stdio_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            confidence=0.8
        )
        
        mock_verify.return_value = stdio_result
        
        # Test with process info
        result = self.verifier._auto_detect_and_verify(
            "localhost", 
            None, 
            process_info=self.sample_process
        )
        
        # Verify STDIO was attempted
        self.assertTrue(result.success)
        mock_verify.assert_called()
    
    def test_auto_detect_no_success(self):
        """Test auto detection when no transport succeeds."""
        with patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_transport') as mock_verify:
            # All transport attempts fail
            mock_verify.return_value = DetectionResult(
                target_host="localhost",
                detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
                success=False
            )
            
            result = self.verifier._auto_detect_and_verify("localhost", 3000)
            
            self.assertFalse(result.success)
            self.assertIn("No MCP protocol detected", result.error)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_http_transport')
    def test_verify_transport_http(self, mock_http):
        """Test transport verification for HTTP."""
        expected_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True
        )
        mock_http.return_value = expected_result
        
        result = self.verifier._verify_transport("localhost", 3000, TransportType.HTTP)
        
        self.assertTrue(result.success)
        mock_http.assert_called_once_with("localhost", 3000)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_websocket_transport')
    def test_verify_transport_websocket(self, mock_ws):
        """Test transport verification for WebSocket."""
        expected_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True
        )
        mock_ws.return_value = expected_result
        
        result = self.verifier._verify_transport("localhost", 3000, TransportType.WEBSOCKET)
        
        self.assertTrue(result.success)
        mock_ws.assert_called_once_with("localhost", 3000)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._verify_stdio_transport')
    def test_verify_transport_stdio(self, mock_stdio):
        """Test transport verification for STDIO."""
        expected_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True
        )
        mock_stdio.return_value = expected_result
        
        result = self.verifier._verify_transport("localhost", None, TransportType.STDIO)
        
        self.assertTrue(result.success)
        mock_stdio.assert_called_once_with("localhost")
    
    def test_verify_transport_unsupported(self):
        """Test verification with unsupported transport type."""
        result = self.verifier._verify_transport("localhost", 3000, TransportType.UNKNOWN)
        
        self.assertFalse(result.success)
        self.assertIn("Unsupported transport type", result.error)
    
    @patch('requests.Session.post')
    def test_verify_http_transport_success(self, mock_post):
        """Test successful HTTP transport verification."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"listChanged": True}
                },
                "serverInfo": {"name": "test-server"}
            }
        }
        mock_post.return_value = mock_response
        
        # Test HTTP verification
        result = self.verifier._verify_http_transport("localhost", 3000)
        
        # Verify success
        self.assertTrue(result.success)
        self.assertIsNotNone(result.mcp_server)
        self.assertEqual(result.mcp_server.transport_type, TransportType.HTTP)
        self.assertEqual(result.mcp_server.port, 3000)
        self.assertGreater(result.confidence, 0.8)
    
    def test_verify_http_transport_no_port(self):
        """Test HTTP verification without port."""
        result = self.verifier._verify_http_transport("localhost", None)
        
        self.assertFalse(result.success)
        self.assertIn("Port required", result.error)
    
    @patch('requests.Session.post')
    def test_verify_http_transport_failure(self, mock_post):
        """Test HTTP transport verification failure."""
        # Setup mock to raise exception
        mock_post.side_effect = Exception("Connection refused")
        
        result = self.verifier._verify_http_transport("localhost", 3000)
        
        self.assertFalse(result.success)
        self.assertIn("No MCP protocol detected", result.error)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._attempt_websocket_handshake')
    def test_verify_websocket_transport_success(self, mock_handshake):
        """Test successful WebSocket transport verification."""
        # Setup mock handshake result
        mock_handshake.return_value = {
            'success': True,
            'confidence': 0.9,
            'response': {'jsonrpc': '2.0', 'result': {}},
            'capabilities': [],
            'tools': [],
            'resources': [],
            'version': '2024-11-05'
        }
        
        result = self.verifier._verify_websocket_transport("localhost", 3000)
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.mcp_server)
        self.assertEqual(result.mcp_server.transport_type, TransportType.WEBSOCKET)
        self.assertEqual(result.confidence, 0.9)
    
    def test_verify_websocket_transport_no_port(self):
        """Test WebSocket verification without port."""
        result = self.verifier._verify_websocket_transport("localhost", None)
        
        self.assertFalse(result.success)
        self.assertIn("Port required", result.error)
    
    def test_verify_stdio_transport_not_localhost(self):
        """Test STDIO verification on non-localhost."""
        result = self.verifier._verify_stdio_transport("remote-host")
        
        self.assertFalse(result.success)
        self.assertIn("only supported on localhost", result.error)
    
    def test_verify_stdio_transport_no_process_info(self):
        """Test STDIO verification without process info."""
        result = self.verifier._verify_stdio_transport("localhost")
        
        self.assertFalse(result.success)
        self.assertIn("Process information required", result.error)
    
    @patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier._attempt_stdio_handshake')
    def test_verify_stdio_transport_success(self, mock_handshake):
        """Test successful STDIO transport verification."""
        # Setup mock handshake result
        mock_handshake.return_value = {
            'success': True,
            'confidence': 0.8,
            'response': 'MCP server detected',
            'capabilities': [],
            'tools': [],
            'resources': [],
            'version': None
        }
        
        result = self.verifier._verify_stdio_transport(
            "localhost", 
            process_info=self.sample_process
        )
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.mcp_server)
        self.assertEqual(result.mcp_server.transport_type, TransportType.STDIO)
        self.assertEqual(result.confidence, 0.8)
    
    @patch('requests.Session.post')
    def test_attempt_http_handshake_valid_response(self, mock_post):
        """Test HTTP handshake with valid MCP response."""
        # Setup valid MCP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "test-server"}
            }
        }
        mock_post.return_value = mock_response
        
        result = self.verifier._attempt_http_handshake("http://localhost:3000/mcp")
        
        self.assertTrue(result['success'])
        self.assertEqual(result['confidence'], 0.9)
        self.assertIn('capabilities', result)
    
    @patch('requests.Session.post')
    def test_attempt_http_handshake_mcp_indicators(self, mock_post):
        """Test HTTP handshake with MCP indicators in response."""
        # Setup response with MCP indicators
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_response.text = "This is an MCP server endpoint"
        mock_post.return_value = mock_response
        
        result = self.verifier._attempt_http_handshake("http://localhost:3000/mcp")
        
        self.assertTrue(result['success'])
        self.assertEqual(result['confidence'], 0.6)
    
    @patch('requests.Session.post')
    def test_attempt_http_handshake_failure(self, mock_post):
        """Test HTTP handshake failure."""
        import requests
        mock_post.side_effect = requests.exceptions.RequestException("Connection error")
        
        result = self.verifier._attempt_http_handshake("http://localhost:3000/mcp")
        
        self.assertFalse(result['success'])
        self.assertEqual(result['confidence'], 0.0)
    
    @patch('asyncio.new_event_loop')
    @patch('asyncio.set_event_loop')
    def test_attempt_websocket_handshake(self, mock_set_loop, mock_new_loop):
        """Test WebSocket handshake attempt."""
        # Setup mock event loop
        mock_loop = Mock()
        mock_new_loop.return_value = mock_loop
        mock_loop.run_until_complete.return_value = {
            'success': True,
            'confidence': 0.9,
            'response': {'jsonrpc': '2.0'}
        }
        
        result = self.verifier._attempt_websocket_handshake("ws://localhost:3000/mcp")
        
        self.assertTrue(result['success'])
        self.assertEqual(result['confidence'], 0.9)
        mock_loop.close.assert_called_once()
    
    @patch('subprocess.run')
    def test_test_npx_mcp_command_success(self, mock_run):
        """Test NPX MCP command testing success."""
        # Setup mock subprocess result
        mock_result = Mock()
        mock_result.stdout = "MCP server tools and resources available"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        cmdline = ['npx', '@modelcontextprotocol/server-filesystem', '--port', '3000']
        result = self.verifier._test_npx_mcp_command(cmdline)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['confidence'], 0.7)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_test_npx_mcp_command_no_indicators(self, mock_run):
        """Test NPX command testing without MCP indicators."""
        # Setup mock subprocess result
        mock_result = Mock()
        mock_result.stdout = "Generic help output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result
        
        cmdline = ['npx', 'some-package', '--help']
        result = self.verifier._test_npx_mcp_command(cmdline)
        
        self.assertFalse(result['success'])
        self.assertEqual(result['confidence'], 0.0)
    
    def test_test_npx_mcp_command_no_npx(self):
        """Test NPX command testing without NPX in command line."""
        cmdline = ['node', 'server.js']
        result = self.verifier._test_npx_mcp_command(cmdline)
        
        self.assertFalse(result['success'])
        self.assertEqual(result['confidence'], 0.0)
    
    def test_analyze_stdio_process_heuristically_high_confidence(self):
        """Test heuristic STDIO analysis with high confidence."""
        process = ProcessInfo(
            pid=1234,
            name='node',
            cmdline=['npx', '@modelcontextprotocol/server-filesystem'],
            cwd='/home/user/mcp-tools'
        )
        
        result = self.verifier._analyze_stdio_process_heuristically(process)
        
        self.assertTrue(result['success'])
        self.assertGreater(result['confidence'], 0.8)
        self.assertIn('official_mcp_package', result['response'])
    
    def test_analyze_stdio_process_heuristically_low_confidence(self):
        """Test heuristic STDIO analysis with low confidence."""
        process = ProcessInfo(
            pid=1234,
            name='node',
            cmdline=['node', 'app.js'],
            cwd='/home/user/app'
        )
        
        result = self.verifier._analyze_stdio_process_heuristically(process)
        
        self.assertFalse(result['success'])
        self.assertLess(result['confidence'], 0.5)
    
    def test_is_valid_mcp_response_valid(self):
        """Test valid MCP response validation."""
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test"}
            }
        }
        
        self.assertTrue(self.verifier._is_valid_mcp_response(response))
    
    def test_is_valid_mcp_response_invalid_structure(self):
        """Test invalid MCP response validation."""
        # Missing jsonrpc
        response1 = {"id": 1, "result": {}}
        self.assertFalse(self.verifier._is_valid_mcp_response(response1))
        
        # Wrong jsonrpc version
        response2 = {"jsonrpc": "1.0", "id": 1, "result": {}}
        self.assertFalse(self.verifier._is_valid_mcp_response(response2))
        
        # Missing result and error
        response3 = {"jsonrpc": "2.0", "id": 1}
        self.assertFalse(self.verifier._is_valid_mcp_response(response3))
        
        # Non-dict response
        self.assertFalse(self.verifier._is_valid_mcp_response("invalid"))
    
    def test_extract_tools_from_response(self):
        """Test tool extraction from MCP response."""
        response = {
            "result": {
                "capabilities": {
                    "tools": {"listChanged": True}
                }
            }
        }
        
        tools = self.verifier._extract_tools_from_response(response)
        
        self.assertIn('tools_capability', tools)
    
    def test_extract_resources_from_response(self):
        """Test resource extraction from MCP response."""
        response = {
            "result": {
                "capabilities": {
                    "resources": {"listChanged": True}
                }
            }
        }
        
        resources = self.verifier._extract_resources_from_response(response)
        
        self.assertIn('resources_capability', resources)
    
    def test_determine_server_type_npx(self):
        """Test server type determination for NPX package."""
        process = ProcessInfo(
            pid=1234,
            name='node',
            cmdline=['npx', '@modelcontextprotocol/server-filesystem']
        )
        
        server_type = self.verifier._determine_server_type(process_info=process)
        
        self.assertEqual(server_type, MCPServerType.NPX_PACKAGE)
    
    def test_determine_server_type_docker(self):
        """Test server type determination for Docker container."""
        config = ConfigFileInfo(
            path=Path('Dockerfile'),
            file_type='dockerfile',
            content={}
        )
        
        server_type = self.verifier._determine_server_type(config_info=config)
        
        self.assertEqual(server_type, MCPServerType.DOCKER_CONTAINER)
    
    def test_determine_server_type_standalone(self):
        """Test server type determination for standalone server."""
        process = ProcessInfo(
            pid=1234,
            name='node',
            cmdline=['node', 'server.js']
        )
        
        server_type = self.verifier._determine_server_type(process_info=process)
        
        self.assertEqual(server_type, MCPServerType.STANDALONE)


if __name__ == '__main__':
    unittest.main()