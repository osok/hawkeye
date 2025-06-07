"""
UDP port scanner implementation for HawkEye.

This module provides UDP port scanning capabilities with proper handling
of UDP's connectionless nature and ICMP responses.
"""

import socket
import time
from typing import Optional

from .base import BaseScanner, ScanResult, ScanTarget, PortState, ScanType
from ..utils.logging import get_logger


class UDPScanner(BaseScanner):
    """UDP port scanner with timeout-based detection."""
    
    def __init__(self, settings=None):
        """Initialize UDP scanner."""
        super().__init__(settings)
        self.logger = get_logger(self.__class__.__name__)
    
    def scan_port(self, target: ScanTarget, port: int) -> ScanResult:
        """
        Scan a single UDP port.
        
        UDP scanning is inherently unreliable due to the connectionless nature
        of UDP. This implementation uses a combination of techniques:
        1. Send UDP packet and wait for response
        2. Check for ICMP port unreachable messages
        3. Use timeout to infer port state
        
        Args:
            target: The target to scan
            port: The port number to scan
            
        Returns:
            ScanResult: Result of the UDP scan
        """
        start_time = time.time()
        
        try:
            # Create UDP socket
            sock = self._create_udp_socket(target)
            
            try:
                # Send UDP packet to the port
                test_data = b"HawkEye UDP Probe"
                sock.sendto(test_data, (target.host, port))
                
                # Try to receive response
                try:
                    sock.settimeout(self.settings.scan.timeout_seconds)
                    response, addr = sock.recvfrom(1024)
                    response_time = time.time() - start_time
                    
                    # Got a response - port is likely open
                    self.logger.debug(f"UDP port {target.host}:{port} responded")
                    return ScanResult(
                        target=target,
                        port=port,
                        state=PortState.OPEN,
                        scan_type=ScanType.UDP,
                        response_time=response_time,
                        raw_data={'response': response.decode('utf-8', errors='ignore')[:100]}
                    )
                    
                except socket.timeout:
                    # No response - could be open|filtered or closed
                    response_time = time.time() - start_time
                    self.logger.debug(f"UDP port {target.host}:{port} no response (timeout)")
                    
                    # For UDP, no response typically means open|filtered
                    return ScanResult(
                        target=target,
                        port=port,
                        state=PortState.FILTERED,  # Could be open or filtered
                        scan_type=ScanType.UDP,
                        response_time=response_time,
                        raw_data={'status': 'no_response'}
                    )
                
            finally:
                sock.close()
                
        except socket.error as e:
            response_time = time.time() - start_time
            
            # Check if it's an ICMP port unreachable error
            if "port unreachable" in str(e).lower() or e.errno == 111:
                self.logger.debug(f"UDP port {target.host}:{port} is CLOSED (ICMP unreachable)")
                return ScanResult(
                    target=target,
                    port=port,
                    state=PortState.CLOSED,
                    scan_type=ScanType.UDP,
                    response_time=response_time,
                    raw_data={'icmp_error': str(e)}
                )
            else:
                self.logger.error(f"UDP scan error for {target.host}:{port}: {e}")
                return ScanResult(
                    target=target,
                    port=port,
                    state=PortState.UNKNOWN,
                    scan_type=ScanType.UDP,
                    response_time=response_time,
                    error=f"Socket error: {e}"
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            self.logger.error(f"Unexpected error scanning UDP {target.host}:{port}: {e}")
            
            return ScanResult(
                target=target,
                port=port,
                state=PortState.UNKNOWN,
                scan_type=ScanType.UDP,
                response_time=response_time,
                error=f"Scan error: {e}"
            )
    
    def get_scan_type(self) -> ScanType:
        """Get the scan type for UDP scans."""
        return ScanType.UDP
    
    def _create_udp_socket(self, target: ScanTarget) -> socket.socket:
        """
        Create a UDP socket appropriate for the target.
        
        Args:
            target: The scan target
            
        Returns:
            socket.socket: Configured UDP socket
        """
        if target.is_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Set socket timeout
        sock.settimeout(self.settings.scan.timeout_seconds)
        
        return sock
    
    def scan_with_service_probe(self, target: ScanTarget, port: int) -> ScanResult:
        """
        Scan UDP port with service-specific probes.
        
        This method sends service-specific UDP packets to common services
        to increase the accuracy of UDP port detection.
        
        Args:
            target: The target to scan
            port: The port number to scan
            
        Returns:
            ScanResult: Enhanced UDP scan result
        """
        # Get service-specific probe data
        probe_data = self._get_service_probe(port)
        
        start_time = time.time()
        
        try:
            sock = self._create_udp_socket(target)
            
            try:
                # Send service-specific probe
                sock.sendto(probe_data, (target.host, port))
                
                # Wait for response
                try:
                    response, addr = sock.recvfrom(4096)
                    response_time = time.time() - start_time
                    
                    # Analyze the response
                    service_info = self._analyze_udp_response(response, port)
                    
                    result = ScanResult(
                        target=target,
                        port=port,
                        state=PortState.OPEN,
                        scan_type=ScanType.UDP,
                        response_time=response_time,
                        service_info=service_info,
                        raw_data={'response': response.hex()[:200]}
                    )
                    
                    self.logger.debug(f"UDP service detected on {target.host}:{port}: {service_info}")
                    return result
                    
                except socket.timeout:
                    # Fall back to basic UDP scan
                    return self.scan_port(target, port)
                
            finally:
                sock.close()
                
        except Exception as e:
            # Fall back to basic UDP scan
            self.logger.debug(f"Service probe failed for UDP {target.host}:{port}, falling back: {e}")
            return self.scan_port(target, port)
    
    def _get_service_probe(self, port: int) -> bytes:
        """
        Get service-specific probe data for common UDP services.
        
        Args:
            port: The port number
            
        Returns:
            bytes: Probe data for the service
        """
        # Common UDP service probes
        probes = {
            53: b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',  # DNS query
            67: b'\x01\x01\x06\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP discover
            69: b'\x00\x01test.txt\x00netascii\x00',  # TFTP read request
            123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # NTP request
            161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP get request
            514: b'<14>HawkEye test message',  # Syslog message
        }
        
        return probes.get(port, b'HawkEye UDP Service Probe')
    
    def _analyze_udp_response(self, response: bytes, port: int) -> Optional['ServiceInfo']:
        """
        Analyze UDP response to identify service.
        
        Args:
            response: The UDP response data
            port: The port number
            
        Returns:
            Optional[ServiceInfo]: Service information if identified
        """
        from .base import ServiceInfo
        
        # Basic service identification based on port and response
        if port == 53 and len(response) > 12:
            # DNS response
            return ServiceInfo(
                name="dns",
                product="DNS Server",
                confidence=0.9,
                extra_info={"protocol": "UDP"}
            )
        elif port == 123 and len(response) >= 48:
            # NTP response
            return ServiceInfo(
                name="ntp",
                product="NTP Server", 
                confidence=0.9,
                extra_info={"protocol": "UDP"}
            )
        elif port == 161 and response.startswith(b'\x30'):
            # SNMP response
            return ServiceInfo(
                name="snmp",
                product="SNMP Agent",
                confidence=0.8,
                extra_info={"protocol": "UDP"}
            )
        elif port == 67 and len(response) > 240:
            # DHCP response
            return ServiceInfo(
                name="dhcp",
                product="DHCP Server",
                confidence=0.8,
                extra_info={"protocol": "UDP"}
            )
        else:
            # Generic UDP service
            return ServiceInfo(
                name="unknown",
                product="UDP Service",
                confidence=0.5,
                extra_info={"protocol": "UDP", "response_length": str(len(response))}
            ) 