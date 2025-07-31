"""
Transport Layer Identification for MCP Detection.

This module provides functionality to identify and analyze the transport
mechanisms used by MCP servers, including stdio, HTTP, and WebSocket transports.
"""

import socket
import time
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from .base import (
    MCPDetector,
    DetectionResult,
    DetectionMethod,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ProcessInfo,
    ConfigFileInfo,
)


class TransportDetector(MCPDetector):
    """Detector for identifying MCP server transport layers."""
    
    def __init__(self, settings=None):
        """Initialize the transport detector."""
        super().__init__(settings)
        
        # Common MCP ports for different transports
        # Use expanded port list from settings
        self.common_http_ports = settings.scan.default_ports if settings else [
            3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010,
            4000, 5000, 8000, 8001, 8080, 8081, 8888, 9000, 9001, 9002
        ]
        self.common_websocket_ports = self.common_http_ports
        self.common_https_ports = [443, 8443, 9443]
        self.common_wss_ports = [443, 8443, 9443]
        
        # Transport detection patterns
        self.http_indicators = [
            'http://', 'https://', '--port', '-p', 'express', 'fastify', 'koa'
        ]
        self.websocket_indicators = [
            'ws://', 'wss://', 'websocket', 'socket.io', 'ws'
        ]
        self.stdio_indicators = [
            'stdio', 'stdin', 'stdout', 'pipe', 'npx'
        ]
        
        # Setup HTTP session for testing
        self.session = requests.Session()
        self.session.timeout = 5
    
    def get_detection_method(self) -> DetectionMethod:
        """Get the detection method."""
        return DetectionMethod.TRANSPORT_DETECTION
    
    def detect(self, target_host: str, port: Optional[int] = None, 
               process_info: Optional[ProcessInfo] = None,
               config_info: Optional[ConfigFileInfo] = None, **kwargs) -> DetectionResult:
        """
        Detect MCP server transport layers.
        
        Args:
            target_host: Target host to analyze
            port: Specific port to test (optional)
            process_info: Process information (optional)
            config_info: Configuration file information (optional)
            **kwargs: Additional parameters
            
        Returns:
            DetectionResult: Result of the transport detection
        """
        start_time = time.time()
        
        try:
            # Collect all available transport information
            transport_results = self._analyze_all_transports(
                target_host, port, process_info, config_info
            )
            
            # Find the best transport match
            best_transport = self._select_best_transport(transport_results)
            
            if best_transport:
                # Create MCP server info with detected transport
                mcp_server = MCPServerInfo(
                    host=target_host,
                    port=best_transport.get('port'),
                    transport_type=best_transport['transport_type'],
                    server_type=self._determine_server_type(process_info, config_info),
                    process_info=process_info,
                    config_info=config_info,
                    security_config=best_transport.get('security_config', {}),
                )
                
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    mcp_server=mcp_server,
                    confidence=best_transport['confidence'],
                    raw_data={
                        'detected_transport': best_transport['transport_type'].value,
                        'all_transports': transport_results,
                        'detection_details': best_transport.get('details', {})
                    },
                    scan_duration=time.time() - start_time
                )
            
            # No transport detected
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="No MCP transport layer detected",
                raw_data={'attempted_transports': [r['transport_type'].value for r in transport_results]},
                scan_duration=time.time() - start_time
            )
            
        except Exception as e:
            self.logger.error(f"Transport detection failed for {target_host}: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=f"Transport detection error: {str(e)}",
                scan_duration=time.time() - start_time
            )
    
    def _analyze_all_transports(self, target_host: str, port: Optional[int],
                               process_info: Optional[ProcessInfo],
                               config_info: Optional[ConfigFileInfo]) -> List[Dict[str, Any]]:
        """
        Analyze all possible transport types for the target.
        
        Args:
            target_host: Target host
            port: Specific port (optional)
            process_info: Process information (optional)
            config_info: Configuration information (optional)
            
        Returns:
            List[Dict]: List of transport analysis results
        """
        results = []
        
        # Analyze STDIO transport (localhost only)
        if target_host in ['localhost', '127.0.0.1', '::1'] and process_info:
            stdio_result = self._analyze_stdio_transport(process_info, config_info)
            if stdio_result['confidence'] > 0:
                results.append(stdio_result)
        
        # Analyze HTTP transport
        http_ports = [port] if port else self._get_candidate_http_ports(process_info, config_info)
        for test_port in http_ports:
            http_result = self._analyze_http_transport(target_host, test_port, process_info, config_info)
            if http_result['confidence'] > 0:
                results.append(http_result)
        
        # Analyze WebSocket transport
        ws_ports = [port] if port else self._get_candidate_websocket_ports(process_info, config_info)
        for test_port in ws_ports:
            ws_result = self._analyze_websocket_transport(target_host, test_port, process_info, config_info)
            if ws_result['confidence'] > 0:
                results.append(ws_result)
        
        return results
    
    def _analyze_stdio_transport(self, process_info: ProcessInfo,
                                config_info: Optional[ConfigFileInfo]) -> Dict[str, Any]:
        """
        Analyze STDIO transport indicators.
        
        Args:
            process_info: Process information
            config_info: Configuration information (optional)
            
        Returns:
            Dict: STDIO transport analysis result
        """
        confidence = 0.0
        details = {}
        
        if not process_info:
            return {
                'transport_type': TransportType.STDIO,
                'confidence': 0.0,
                'details': {'error': 'No process information available'}
            }
        
        cmdline_str = ' '.join(process_info.cmdline).lower()
        
        # Check for STDIO indicators in command line
        stdio_score = 0
        for indicator in self.stdio_indicators:
            if indicator in cmdline_str:
                stdio_score += 1
                details[f'cmdline_{indicator}'] = True
        
        # NPX packages typically use STDIO
        if 'npx' in cmdline_str:
            stdio_score += 2
            details['npx_execution'] = True
        
        # Check for absence of network indicators
        has_network_indicators = any(
            indicator in cmdline_str 
            for indicator in self.http_indicators + self.websocket_indicators
        )
        
        if not has_network_indicators:
            stdio_score += 1
            details['no_network_indicators'] = True
        
        # Check configuration for STDIO preferences
        if config_info:
            config_content = str(config_info.content).lower()
            if 'stdio' in config_content:
                stdio_score += 1
                details['config_stdio_reference'] = True
        
        # Calculate confidence
        confidence = min(stdio_score * 0.2, 1.0)
        
        return {
            'transport_type': TransportType.STDIO,
            'confidence': confidence,
            'details': details,
            'security_config': {'secure': True}  # STDIO is inherently secure
        }
    
    def _analyze_http_transport(self, target_host: str, port: int,
                               process_info: Optional[ProcessInfo],
                               config_info: Optional[ConfigFileInfo]) -> Dict[str, Any]:
        """
        Analyze HTTP transport indicators.
        
        Args:
            target_host: Target host
            port: Port to test
            process_info: Process information (optional)
            config_info: Configuration information (optional)
            
        Returns:
            Dict: HTTP transport analysis result
        """
        confidence = 0.0
        details = {}
        security_config = {}
        
        # Test if port is open and responsive
        if self._is_port_open(target_host, port):
            confidence += 0.3
            details['port_open'] = True
            
            # Test HTTP connectivity
            http_response = self._test_http_connectivity(target_host, port)
            if http_response['success']:
                confidence += 0.4
                details.update(http_response['details'])
                security_config.update(http_response['security'])
        
        # Check process indicators
        if process_info:
            cmdline_str = ' '.join(process_info.cmdline).lower()
            
            # Look for HTTP-related indicators
            http_score = 0
            for indicator in self.http_indicators:
                if indicator in cmdline_str:
                    http_score += 1
                    details[f'cmdline_{indicator}'] = True
            
            # Check for specific port in command line
            if str(port) in cmdline_str:
                http_score += 1
                details['port_in_cmdline'] = True
            
            confidence += min(http_score * 0.1, 0.3)
        
        # Check configuration indicators
        if config_info:
            config_content = str(config_info.content).lower()
            
            # Look for HTTP configuration
            if any(indicator in config_content for indicator in ['http', 'express', 'fastify']):
                confidence += 0.1
                details['config_http_reference'] = True
            
            # Check for port configuration
            if str(port) in config_content:
                confidence += 0.1
                details['port_in_config'] = True
        
        return {
            'transport_type': TransportType.HTTP,
            'port': port,
            'confidence': min(confidence, 1.0),
            'details': details,
            'security_config': security_config
        }
    
    def _analyze_websocket_transport(self, target_host: str, port: int,
                                   process_info: Optional[ProcessInfo],
                                   config_info: Optional[ConfigFileInfo]) -> Dict[str, Any]:
        """
        Analyze WebSocket transport indicators.
        
        Args:
            target_host: Target host
            port: Port to test
            process_info: Process information (optional)
            config_info: Configuration information (optional)
            
        Returns:
            Dict: WebSocket transport analysis result
        """
        confidence = 0.0
        details = {}
        security_config = {}
        
        # Test if port is open
        if self._is_port_open(target_host, port):
            confidence += 0.2
            details['port_open'] = True
            
            # Test WebSocket connectivity
            ws_response = self._test_websocket_connectivity(target_host, port)
            if ws_response['success']:
                confidence += 0.5
                details.update(ws_response['details'])
                security_config.update(ws_response['security'])
        
        # Check process indicators
        if process_info:
            cmdline_str = ' '.join(process_info.cmdline).lower()
            
            # Look for WebSocket-related indicators
            ws_score = 0
            for indicator in self.websocket_indicators:
                if indicator in cmdline_str:
                    ws_score += 1
                    details[f'cmdline_{indicator}'] = True
            
            confidence += min(ws_score * 0.1, 0.3)
        
        # Check configuration indicators
        if config_info:
            config_content = str(config_info.content).lower()
            
            # Look for WebSocket configuration
            if any(indicator in config_content for indicator in self.websocket_indicators):
                confidence += 0.1
                details['config_websocket_reference'] = True
        
        return {
            'transport_type': TransportType.WEBSOCKET,
            'port': port,
            'confidence': min(confidence, 1.0),
            'details': details,
            'security_config': security_config
        }
    
    def _get_candidate_http_ports(self, process_info: Optional[ProcessInfo],
                                 config_info: Optional[ConfigFileInfo]) -> List[int]:
        """Get candidate HTTP ports to test."""
        ports = set()
        
        # Add common HTTP ports
        ports.update(self.common_http_ports)
        ports.update(self.common_https_ports)
        
        # Extract ports from process command line
        if process_info:
            extracted_ports = self._extract_ports_from_cmdline(process_info.cmdline)
            ports.update(extracted_ports)
        
        # Extract ports from configuration
        if config_info:
            extracted_ports = self._extract_ports_from_config(config_info)
            ports.update(extracted_ports)
        
        return sorted(list(ports))[:10]  # Limit to 10 ports for efficiency
    
    def _get_candidate_websocket_ports(self, process_info: Optional[ProcessInfo],
                                      config_info: Optional[ConfigFileInfo]) -> List[int]:
        """Get candidate WebSocket ports to test."""
        ports = set()
        
        # Add common WebSocket ports
        ports.update(self.common_websocket_ports)
        ports.update(self.common_wss_ports)
        
        # Extract ports from process and config (same as HTTP)
        if process_info:
            extracted_ports = self._extract_ports_from_cmdline(process_info.cmdline)
            ports.update(extracted_ports)
        
        if config_info:
            extracted_ports = self._extract_ports_from_config(config_info)
            ports.update(extracted_ports)
        
        return sorted(list(ports))[:10]  # Limit to 10 ports for efficiency
    
    def _extract_ports_from_cmdline(self, cmdline: List[str]) -> Set[int]:
        """Extract port numbers from command line arguments."""
        ports = set()
        
        for i, arg in enumerate(cmdline):
            # Look for --port=XXXX or -p=XXXX
            if '=' in arg and any(port_flag in arg for port_flag in ['--port', '-p']):
                try:
                    port = int(arg.split('=')[1])
                    if 1 <= port <= 65535:
                        ports.add(port)
                except (ValueError, IndexError):
                    pass
            
            # Look for --port XXXX or -p XXXX
            elif arg in ['--port', '-p'] and i + 1 < len(cmdline):
                try:
                    port = int(cmdline[i + 1])
                    if 1 <= port <= 65535:
                        ports.add(port)
                except ValueError:
                    pass
            
            # Look for standalone numbers that might be ports
            elif arg.isdigit():
                port = int(arg)
                if 1000 <= port <= 65535:  # Reasonable port range
                    ports.add(port)
        
        return ports
    
    def _extract_ports_from_config(self, config_info: ConfigFileInfo) -> Set[int]:
        """Extract port numbers from configuration content."""
        ports = set()
        
        if not config_info.content:
            return ports
        
        # Convert content to string for searching
        content_str = str(config_info.content)
        
        # Look for port patterns in JSON/YAML
        port_patterns = [
            r'"port":\s*(\d+)',
            r"'port':\s*(\d+)",
            r'port:\s*(\d+)',
            r'PORT:\s*(\d+)',
            r'"listen":\s*(\d+)',
            r"'listen':\s*(\d+)",
            r'listen:\s*(\d+)',
            r'server.*?port.*?(\d+)',
        ]
        
        for pattern in port_patterns:
            matches = re.findall(pattern, content_str, re.IGNORECASE)
            for match in matches:
                try:
                    port = int(match)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except ValueError:
                    pass
        
        return ports
    
    def _is_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Test if a port is open and accepting connections."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.error, socket.timeout):
            return False
    
    def _test_http_connectivity(self, host: str, port: int) -> Dict[str, Any]:
        """Test HTTP connectivity and gather information."""
        result = {
            'success': False,
            'details': {},
            'security': {}
        }
        
        # Try both HTTP and HTTPS
        protocols = ['https', 'http'] if port in self.common_https_ports else ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{host}:{port}/"
                response = self.session.get(url, timeout=3, verify=False)
                
                result['success'] = True
                result['details']['protocol'] = protocol
                result['details']['status_code'] = response.status_code
                result['details']['headers'] = dict(response.headers)
                result['security']['tls'] = (protocol == 'https')
                
                # Look for server information
                server_header = response.headers.get('Server', '')
                if server_header:
                    result['details']['server'] = server_header
                
                # Check for common web frameworks
                if 'express' in server_header.lower():
                    result['details']['framework'] = 'express'
                elif 'nginx' in server_header.lower():
                    result['details']['framework'] = 'nginx'
                
                break  # Success, no need to try other protocols
                
            except RequestException:
                continue
        
        return result
    
    def _test_websocket_connectivity(self, host: str, port: int) -> Dict[str, Any]:
        """Test WebSocket connectivity."""
        result = {
            'success': False,
            'details': {},
            'security': {}
        }
        
        # For now, we'll do a basic HTTP upgrade test
        # A full WebSocket test would require the websockets library
        try:
            # Test if the port responds to HTTP with upgrade headers
            headers = {
                'Connection': 'Upgrade',
                'Upgrade': 'websocket',
                'Sec-WebSocket-Version': '13',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='
            }
            
            protocols = ['wss', 'ws'] if port in self.common_wss_ports else ['ws', 'wss']
            
            for protocol in protocols:
                try:
                    # Convert to HTTP for the upgrade test
                    http_protocol = 'https' if protocol == 'wss' else 'http'
                    url = f"{http_protocol}://{host}:{port}/"
                    
                    response = self.session.get(url, headers=headers, timeout=3, verify=False)
                    
                    # Check for WebSocket upgrade response
                    if (response.status_code == 101 or 
                        'upgrade' in response.headers.get('Connection', '').lower() or
                        'websocket' in response.headers.get('Upgrade', '').lower()):
                        
                        result['success'] = True
                        result['details']['protocol'] = protocol
                        result['details']['upgrade_response'] = True
                        result['security']['secure'] = (protocol == 'wss')
                        break
                        
                except RequestException:
                    continue
                    
        except Exception as e:
            result['details']['error'] = str(e)
        
        return result
    
    def _select_best_transport(self, transport_results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Select the best transport from analysis results.
        
        Args:
            transport_results: List of transport analysis results
            
        Returns:
            Optional[Dict]: Best transport result or None
        """
        if not transport_results:
            return None
        
        # Sort by confidence score (highest first)
        sorted_results = sorted(transport_results, key=lambda x: x['confidence'], reverse=True)
        
        # Return the highest confidence result if it's above threshold
        best_result = sorted_results[0]
        if best_result['confidence'] >= 0.3:  # Minimum confidence threshold
            return best_result
        
        return None
    
    def _determine_server_type(self, process_info: Optional[ProcessInfo],
                              config_info: Optional[ConfigFileInfo]) -> MCPServerType:
        """Determine server type based on available information."""
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
    
    def analyze_transport_security(self, transport_type: TransportType, 
                                  host: str, port: Optional[int] = None) -> Dict[str, Any]:
        """
        Analyze security aspects of a detected transport.
        
        Args:
            transport_type: Type of transport to analyze
            host: Target host
            port: Port number (for network transports)
            
        Returns:
            Dict: Security analysis results
        """
        security_analysis = {
            'transport_type': transport_type.value,
            'secure': False,
            'encryption': False,
            'authentication': False,
            'vulnerabilities': [],
            'recommendations': []
        }
        
        if transport_type == TransportType.STDIO:
            security_analysis.update({
                'secure': True,
                'encryption': True,  # Local communication is inherently secure
                'authentication': True,  # Process-level authentication
                'recommendations': ['Ensure proper process isolation']
            })
            
        elif transport_type == TransportType.HTTP:
            if port in self.common_https_ports:
                security_analysis['encryption'] = True
                security_analysis['secure'] = True
            else:
                security_analysis['vulnerabilities'].append('Unencrypted HTTP transport')
                security_analysis['recommendations'].append('Use HTTPS instead of HTTP')
            
        elif transport_type == TransportType.WEBSOCKET:
            if port in self.common_wss_ports:
                security_analysis['encryption'] = True
                security_analysis['secure'] = True
            else:
                security_analysis['vulnerabilities'].append('Unencrypted WebSocket transport')
                security_analysis['recommendations'].append('Use WSS instead of WS')
        
        return security_analysis