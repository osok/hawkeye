"""
MCP Protocol Handshake Verification for MCP Detection.

This module provides functionality to verify MCP servers by attempting
protocol handshakes and analyzing responses to confirm MCP implementation.
"""

import json
import socket
import subprocess
import time
import asyncio
import websockets
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import logging

# Suppress urllib3 warnings to provide cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

from .base import (
    MCPDetector,
    DetectionResult,
    DetectionMethod,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ProtocolDetectionError,
)


class ProtocolVerifier(MCPDetector):
    """Detector for verifying MCP servers through protocol handshake."""
    
    def __init__(self, settings=None):
        """Initialize the protocol verifier."""
        super().__init__(settings)
        self.handshake_timeout = getattr(settings.detection, 'handshake_timeout', 10) if settings else 10
        self.mcp_version = "2024-11-05"
        
        # Setup HTTP session with retries (suppress retry warnings)
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,  # Don't raise exceptions on status codes
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Further suppress requests/urllib3 logging for cleaner output
        logging.getLogger("requests.packages.urllib3.connectionpool").setLevel(logging.ERROR)
        logging.getLogger("urllib3.util.retry").setLevel(logging.ERROR)
    
    def get_detection_method(self) -> DetectionMethod:
        """Get the detection method."""
        return DetectionMethod.PROTOCOL_HANDSHAKE
    
    def _is_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if a port is open before attempting HTTP requests.
        
        Args:
            host: Target host
            port: Port to check
            timeout: Connection timeout in seconds
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def detect(self, target_host: str, port: Optional[int] = None, 
               transport_type: Optional[TransportType] = None, **kwargs) -> DetectionResult:
        """
        Verify MCP server through protocol handshake.
        
        Args:
            target_host: Target host to verify
            port: Port number (required for HTTP/WebSocket)
            transport_type: Transport type to test (if known)
            **kwargs: Additional parameters (process_info, config_info)
            
        Returns:
            DetectionResult: Result of the verification operation
        """
        start_time = time.time()
        
        try:
            # If transport type is specified, test only that transport
            if transport_type:
                result = self._verify_transport(target_host, port, transport_type, **kwargs)
            else:
                # Try to detect transport type and verify
                result = self._auto_detect_and_verify(target_host, port, **kwargs)
            
            result.scan_duration = time.time() - start_time
            return result
            
        except Exception as e:
            self.logger.error(f"Protocol verification failed for {target_host}:{port}: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=f"Protocol verification error: {str(e)}",
                scan_duration=time.time() - start_time
            )
    
    def _auto_detect_and_verify(self, target_host: str, port: Optional[int], **kwargs) -> DetectionResult:
        """
        Auto-detect transport type and verify MCP protocol.
        
        Args:
            target_host: Target host
            port: Port number
            **kwargs: Additional parameters
            
        Returns:
            DetectionResult: Verification result
        """
        # Try different transport types in order of likelihood
        transport_attempts = []
        
        if port:
            # Try HTTP first (most common for network services)
            transport_attempts.extend([
                (TransportType.HTTP, port),
                (TransportType.WEBSOCKET, port),
            ])
        
        # Try STDIO if we have process information
        if kwargs.get('process_info'):
            transport_attempts.append((TransportType.STDIO, None))
        
        # If no port specified but we have process info, try common MCP ports from settings
        if not port and not kwargs.get('process_info'):
            # Get ports from settings configuration
            from ..config.settings import get_settings
            settings = get_settings()
            common_ports = settings.scan.default_ports
            for common_port in common_ports:
                transport_attempts.extend([
                    (TransportType.HTTP, common_port),
                    (TransportType.WEBSOCKET, common_port),
                ])
        
        best_result = None
        highest_confidence = 0.0
        
        for transport_type, test_port in transport_attempts:
            try:
                result = self._verify_transport(target_host, test_port, transport_type, **kwargs)
                
                if result.success and result.confidence > highest_confidence:
                    best_result = result
                    highest_confidence = result.confidence
                    
                    # If we found a high-confidence match, stop searching
                    if result.confidence >= 0.8:
                        break
                        
            except Exception as e:
                self.logger.debug(f"Transport {transport_type.value} verification failed: {e}")
                continue
        
        if best_result:
            return best_result
        
        # No successful verification
        return DetectionResult(
            target_host=target_host,
            detection_method=self.get_detection_method(),
            success=False,
            error="No MCP protocol detected on any transport",
            raw_data={'attempted_transports': [t.value for t, _ in transport_attempts]}
        )
    
    def _verify_transport(self, target_host: str, port: Optional[int], 
                         transport_type: TransportType, **kwargs) -> DetectionResult:
        """
        Verify MCP protocol on specific transport.
        
        Args:
            target_host: Target host
            port: Port number
            transport_type: Transport type to verify
            **kwargs: Additional parameters
            
        Returns:
            DetectionResult: Verification result
        """
        if transport_type == TransportType.HTTP:
            return self._verify_http_transport(target_host, port, **kwargs)
        elif transport_type == TransportType.WEBSOCKET:
            return self._verify_websocket_transport(target_host, port, **kwargs)
        elif transport_type == TransportType.STDIO:
            return self._verify_stdio_transport(target_host, **kwargs)
        else:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=f"Unsupported transport type: {transport_type.value}"
            )
    
    def _verify_http_transport(self, target_host: str, port: int, **kwargs) -> DetectionResult:
        """
        Verify MCP protocol over HTTP transport.
        
        Args:
            target_host: Target host
            port: Port number
            **kwargs: Additional parameters
            
        Returns:
            DetectionResult: Verification result
        """
        if not port:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="Port required for HTTP transport verification"
            )
        
        # First check if port is open - skip endpoint testing if port is closed
        self.logger.info(f"  Scanning {target_host}:{port} : checking port connectivity...")
        
        if not self._is_port_open(target_host, port, timeout=2.0):
            self.logger.info(f"  Scanning {target_host}:{port} : port closed, skipping")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=f"Port {port} is not open"
            )
        
        self.logger.info(f"  Scanning {target_host}:{port} : port open, testing endpoints...")
        
        # Try both HTTP and HTTPS
        protocols = ['http', 'https'] if port in [443, 8443] else ['http']
        
        for protocol in protocols:
            try:
                base_url = f"{protocol}://{target_host}:{port}"
                
                # Try common MCP endpoints
                endpoints = [
                    '/mcp',
                    '/api/mcp',
                    '/rpc',
                    '/',
                ]
                
                for endpoint in endpoints:
                    url = f"{base_url}{endpoint}"
                    
                    # Log scanning attempt in clean format
                    self.logger.info(f"  Scanning {target_host}:{port} : {endpoint} : checking...")
                    
                    # Attempt MCP handshake
                    handshake_result = self._attempt_http_handshake(url)
                    
                    # Log result in clean format
                    if handshake_result['success']:
                        self.logger.info(f"  Scanning {target_host}:{port} : {endpoint} : found MCP server")
                    else:
                        self.logger.info(f"  Scanning {target_host}:{port} : {endpoint} : none found")
                    
                    if handshake_result['success']:
                        # Create MCP server info
                        mcp_server = MCPServerInfo(
                            host=target_host,
                            port=port,
                            transport_type=TransportType.HTTP,
                            server_type=self._determine_server_type(**kwargs),
                            process_info=kwargs.get('process_info'),
                            config_info=kwargs.get('config_info'),
                            capabilities=handshake_result.get('capabilities', []),
                            tools=handshake_result.get('tools', []),
                            resources=handshake_result.get('resources', []),
                            version=handshake_result.get('version'),
                            security_config={'tls': protocol == 'https'},
                        )
                        
                        return DetectionResult(
                            target_host=target_host,
                            detection_method=self.get_detection_method(),
                            success=True,
                            mcp_server=mcp_server,
                            confidence=handshake_result['confidence'],
                            raw_data={
                                'endpoint': url,
                                'protocol': protocol,
                                'handshake_response': handshake_result['response']
                            }
                        )
                        
            except Exception as e:
                self.logger.debug(f"HTTP verification failed for {protocol}://{target_host}:{port}: {e}")
                continue
        
        return DetectionResult(
            target_host=target_host,
            detection_method=self.get_detection_method(),
            success=False,
            error=f"No MCP protocol detected on HTTP transport at port {port}"
        )
    
    def _verify_websocket_transport(self, target_host: str, port: int, **kwargs) -> DetectionResult:
        """
        Verify MCP protocol over WebSocket transport.
        
        Args:
            target_host: Target host
            port: Port number
            **kwargs: Additional parameters
            
        Returns:
            DetectionResult: Verification result
        """
        if not port:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="Port required for WebSocket transport verification"
            )
        
        # Try both WS and WSS
        protocols = ['wss', 'ws'] if port in [443, 8443] else ['ws']
        
        for protocol in protocols:
            try:
                # Try common WebSocket endpoints
                endpoints = [
                    '/mcp',
                    '/ws',
                    '/websocket',
                    '/',
                ]
                
                for endpoint in endpoints:
                    url = f"{protocol}://{target_host}:{port}{endpoint}"
                    
                    # Attempt WebSocket MCP handshake
                    handshake_result = self._attempt_websocket_handshake(url)
                    
                    if handshake_result['success']:
                        # Create MCP server info
                        mcp_server = MCPServerInfo(
                            host=target_host,
                            port=port,
                            transport_type=TransportType.WEBSOCKET,
                            server_type=self._determine_server_type(**kwargs),
                            process_info=kwargs.get('process_info'),
                            config_info=kwargs.get('config_info'),
                            capabilities=handshake_result.get('capabilities', []),
                            tools=handshake_result.get('tools', []),
                            resources=handshake_result.get('resources', []),
                            version=handshake_result.get('version'),
                            security_config={'secure': protocol == 'wss'},
                        )
                        
                        return DetectionResult(
                            target_host=target_host,
                            detection_method=self.get_detection_method(),
                            success=True,
                            mcp_server=mcp_server,
                            confidence=handshake_result['confidence'],
                            raw_data={
                                'endpoint': url,
                                'protocol': protocol,
                                'handshake_response': handshake_result['response']
                            }
                        )
                        
            except Exception as e:
                self.logger.debug(f"WebSocket verification failed for {protocol}://{target_host}:{port}: {e}")
                continue
        
        return DetectionResult(
            target_host=target_host,
            detection_method=self.get_detection_method(),
            success=False,
            error=f"No MCP protocol detected on WebSocket transport at port {port}"
        )
    
    def _verify_stdio_transport(self, target_host: str, **kwargs) -> DetectionResult:
        """
        Verify MCP protocol over STDIO transport.
        
        Args:
            target_host: Target host (must be localhost for STDIO)
            **kwargs: Additional parameters (must include process_info)
            
        Returns:
            DetectionResult: Verification result
        """
        if target_host not in ['localhost', '127.0.0.1', '::1']:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="STDIO transport verification only supported on localhost"
            )
        
        process_info = kwargs.get('process_info')
        if not process_info:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="Process information required for STDIO transport verification"
            )
        
        try:
            # Attempt to communicate with the process via STDIO
            handshake_result = self._attempt_stdio_handshake(process_info)
            
            if handshake_result['success']:
                # Create MCP server info
                mcp_server = MCPServerInfo(
                    host=target_host,
                    transport_type=TransportType.STDIO,
                    server_type=self._determine_server_type(**kwargs),
                    process_info=process_info,
                    config_info=kwargs.get('config_info'),
                    capabilities=handshake_result.get('capabilities', []),
                    tools=handshake_result.get('tools', []),
                    resources=handshake_result.get('resources', []),
                    version=handshake_result.get('version'),
                    security_config={'secure': True},  # STDIO is inherently secure
                )
                
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    mcp_server=mcp_server,
                    confidence=handshake_result['confidence'],
                    raw_data={
                        'transport': 'stdio',
                        'process_pid': process_info.pid,
                        'handshake_response': handshake_result['response']
                    }
                )
            
        except Exception as e:
            self.logger.debug(f"STDIO verification failed for process {process_info.pid}: {e}")
        
        return DetectionResult(
            target_host=target_host,
            detection_method=self.get_detection_method(),
            success=False,
            error="No MCP protocol detected on STDIO transport"
        )
    
    def _attempt_http_handshake(self, url: str) -> Dict[str, Any]:
        """
        Attempt MCP handshake over HTTP.
        
        Args:
            url: HTTP endpoint URL
            
        Returns:
            Dict: Handshake result with success status and response data
        """
        try:
            # Temporarily suppress all requests logging for this operation
            requests_logger = logging.getLogger("requests")
            urllib3_logger = logging.getLogger("urllib3")
            original_requests_level = requests_logger.level
            original_urllib3_level = urllib3_logger.level
            requests_logger.setLevel(logging.ERROR)
            urllib3_logger.setLevel(logging.ERROR)
            # Create MCP initialize request
            initialize_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": self.mcp_version,
                    "capabilities": {
                        "roots": {"listChanged": True},
                        "sampling": {}
                    },
                    "clientInfo": {
                        "name": "HawkEye-Scanner",
                        "version": "1.0.0"
                    }
                }
            }
            
            # Send POST request with MCP handshake
            response = self.session.post(
                url,
                json=initialize_request,
                timeout=self.handshake_timeout,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'HawkEye-MCP-Scanner/1.0'
                }
            )
            
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    
                    # Check for valid MCP response
                    if self._is_valid_mcp_response(response_data):
                        return {
                            'success': True,
                            'confidence': 0.9,
                            'response': response_data,
                            'capabilities': response_data.get('result', {}).get('capabilities', {}),
                            'version': response_data.get('result', {}).get('protocolVersion'),
                            'tools': self._extract_tools_from_response(response_data),
                            'resources': self._extract_resources_from_response(response_data),
                        }
                        
                except json.JSONDecodeError:
                    pass
            
            # Check for MCP-like indicators in response
            response_text = response.text.lower()
            if any(indicator in response_text for indicator in ['mcp', 'model-context-protocol', 'jsonrpc']):
                return {
                    'success': True,
                    'confidence': 0.6,
                    'response': response.text,
                    'capabilities': [],
                    'tools': [],
                    'resources': [],
                }
            
        except requests.exceptions.RequestException as e:
            # Silently handle connection errors - they're expected during scanning
            pass
        except Exception as e:
            self.logger.debug(f"HTTP request failed: {e}")
        finally:
            # Restore original logging levels
            try:
                requests_logger.setLevel(original_requests_level)
                urllib3_logger.setLevel(original_urllib3_level)
            except:
                pass
        
        return {'success': False, 'confidence': 0.0}
    
    def _attempt_websocket_handshake(self, url: str) -> Dict[str, Any]:
        """
        Attempt MCP handshake over WebSocket.
        
        Args:
            url: WebSocket endpoint URL
            
        Returns:
            Dict: Handshake result with success status and response data
        """
        try:
            # Use asyncio to handle WebSocket connection
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                result = loop.run_until_complete(self._websocket_handshake_async(url))
                return result
            finally:
                loop.close()
                
        except Exception as e:
            self.logger.debug(f"WebSocket handshake failed: {e}")
            return {'success': False, 'confidence': 0.0}
    
    async def _websocket_handshake_async(self, url: str) -> Dict[str, Any]:
        """
        Async WebSocket handshake implementation.
        
        Args:
            url: WebSocket endpoint URL
            
        Returns:
            Dict: Handshake result
        """
        try:
            async with websockets.connect(
                url,
                timeout=self.handshake_timeout,
                extra_headers={'User-Agent': 'HawkEye-MCP-Scanner/1.0'}
            ) as websocket:
                
                # Send MCP initialize message
                initialize_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": self.mcp_version,
                        "capabilities": {
                            "roots": {"listChanged": True},
                            "sampling": {}
                        },
                        "clientInfo": {
                            "name": "HawkEye-Scanner",
                            "version": "1.0.0"
                        }
                    }
                }
                
                await websocket.send(json.dumps(initialize_request))
                
                # Wait for response
                response = await asyncio.wait_for(
                    websocket.recv(),
                    timeout=self.handshake_timeout
                )
                
                try:
                    response_data = json.loads(response)
                    
                    # Check for valid MCP response
                    if self._is_valid_mcp_response(response_data):
                        return {
                            'success': True,
                            'confidence': 0.9,
                            'response': response_data,
                            'capabilities': response_data.get('result', {}).get('capabilities', {}),
                            'version': response_data.get('result', {}).get('protocolVersion'),
                            'tools': self._extract_tools_from_response(response_data),
                            'resources': self._extract_resources_from_response(response_data),
                        }
                        
                except json.JSONDecodeError:
                    pass
                
                # Check for MCP-like indicators
                if any(indicator in response.lower() for indicator in ['mcp', 'model-context-protocol', 'jsonrpc']):
                    return {
                        'success': True,
                        'confidence': 0.6,
                        'response': response,
                        'capabilities': [],
                        'tools': [],
                        'resources': [],
                    }
                    
        except Exception as e:
            self.logger.debug(f"WebSocket async handshake failed: {e}")
        
        return {'success': False, 'confidence': 0.0}
    
    def _attempt_stdio_handshake(self, process_info) -> Dict[str, Any]:
        """
        Attempt MCP handshake over STDIO.
        
        Args:
            process_info: Process information
            
        Returns:
            Dict: Handshake result with success status and response data
        """
        try:
            # For STDIO, we can't easily inject into an existing process
            # Instead, we'll try to start a new instance if possible
            if any('npx' in arg for arg in process_info.cmdline):
                # Try to run the same NPX command to test MCP protocol
                return self._test_npx_mcp_command(process_info.cmdline)
            
            # For other processes, we'll use heuristic analysis
            # This is less reliable but safer than trying to inject into running processes
            return self._analyze_stdio_process_heuristically(process_info)
            
        except Exception as e:
            self.logger.debug(f"STDIO handshake failed: {e}")
            return {'success': False, 'confidence': 0.0}
    
    def _test_npx_mcp_command(self, cmdline: List[str]) -> Dict[str, Any]:
        """
        Test NPX MCP command by running it with --help or similar.
        
        Args:
            cmdline: Original command line
            
        Returns:
            Dict: Test result
        """
        try:
            # Extract NPX package name
            npx_package = None
            for i, arg in enumerate(cmdline):
                if arg == 'npx' and i + 1 < len(cmdline):
                    npx_package = cmdline[i + 1]
                    break
            
            if not npx_package:
                return {'success': False, 'confidence': 0.0}
            
            # Try to get help information
            help_cmd = ['npx', npx_package, '--help']
            
            result = subprocess.run(
                help_cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout + result.stderr
            
            # Check for MCP indicators in help output
            if any(indicator in output.lower() for indicator in [
                'mcp', 'model-context-protocol', 'server', 'client', 'tools', 'resources'
            ]):
                return {
                    'success': True,
                    'confidence': 0.7,
                    'response': output,
                    'capabilities': [],
                    'tools': [],
                    'resources': [],
                }
                
        except Exception as e:
            self.logger.debug(f"NPX command test failed: {e}")
        
        return {'success': False, 'confidence': 0.0}
    
    def _analyze_stdio_process_heuristically(self, process_info) -> Dict[str, Any]:
        """
        Analyze STDIO process using heuristics.
        
        Args:
            process_info: Process information
            
        Returns:
            Dict: Analysis result
        """
        confidence = 0.0
        indicators = []
        
        # Check command line for MCP indicators
        cmdline_str = ' '.join(process_info.cmdline).lower()
        
        if '@modelcontextprotocol' in cmdline_str:
            confidence += 0.8
            indicators.append('official_mcp_package')
        elif 'mcp-server' in cmdline_str or 'mcp-client' in cmdline_str:
            confidence += 0.7
            indicators.append('mcp_naming')
        elif 'mcp' in cmdline_str:
            confidence += 0.5
            indicators.append('mcp_keyword')
        
        # Check for server-like patterns
        if 'server' in cmdline_str:
            confidence += 0.2
            indicators.append('server_pattern')
        
        # Check working directory
        if process_info.cwd and 'mcp' in process_info.cwd.lower():
            confidence += 0.1
            indicators.append('mcp_directory')
        
        if confidence >= 0.5:
            return {
                'success': True,
                'confidence': min(confidence, 1.0),
                'response': f"Heuristic analysis: {', '.join(indicators)}",
                'capabilities': [],
                'tools': [],
                'resources': [],
            }
        
        return {'success': False, 'confidence': confidence}
    
    def _is_valid_mcp_response(self, response_data: Dict[str, Any]) -> bool:
        """
        Check if response is a valid MCP initialize response.
        
        Args:
            response_data: Response data to validate
            
        Returns:
            bool: True if valid MCP response
        """
        # Check for JSON-RPC structure
        if not isinstance(response_data, dict):
            return False
        
        # Must have jsonrpc field
        if response_data.get('jsonrpc') != '2.0':
            return False
        
        # Must have result or error
        if 'result' not in response_data and 'error' not in response_data:
            return False
        
        # If result exists, check for MCP-specific fields
        if 'result' in response_data:
            result = response_data['result']
            if isinstance(result, dict):
                # Look for MCP-specific fields
                mcp_fields = ['protocolVersion', 'capabilities', 'serverInfo']
                if any(field in result for field in mcp_fields):
                    return True
        
        return False
    
    def _extract_tools_from_response(self, response_data: Dict[str, Any]) -> List[str]:
        """Extract tool names from MCP response."""
        tools = []
        
        if 'result' in response_data:
            result = response_data['result']
            if isinstance(result, dict):
                # Check capabilities for tools
                capabilities = result.get('capabilities', {})
                if 'tools' in capabilities:
                    tools_info = capabilities['tools']
                    if isinstance(tools_info, dict) and 'listChanged' in tools_info:
                        # This indicates tools capability is available
                        tools.append('tools_capability')
        
        return tools
    
    def _extract_resources_from_response(self, response_data: Dict[str, Any]) -> List[str]:
        """Extract resource names from MCP response."""
        resources = []
        
        if 'result' in response_data:
            result = response_data['result']
            if isinstance(result, dict):
                # Check capabilities for resources
                capabilities = result.get('capabilities', {})
                if 'resources' in capabilities:
                    resources_info = capabilities['resources']
                    if isinstance(resources_info, dict) and 'listChanged' in resources_info:
                        # This indicates resources capability is available
                        resources.append('resources_capability')
        
        return resources
    
    def _determine_server_type(self, **kwargs) -> MCPServerType:
        """
        Determine server type based on available information.
        
        Args:
            **kwargs: Additional context (process_info, config_info)
            
        Returns:
            MCPServerType: Determined server type
        """
        process_info = kwargs.get('process_info')
        config_info = kwargs.get('config_info')
        
        if process_info:
            cmdline_str = ' '.join(process_info.cmdline).lower()
            if 'npx' in cmdline_str:
                return MCPServerType.NPX_PACKAGE
            elif 'docker' in cmdline_str:
                return MCPServerType.DOCKER_CONTAINER
        
        if config_info:
            if 'docker' in config_info.file_type.lower():
                return MCPServerType.DOCKER_CONTAINER
        
        return MCPServerType.STANDALONE