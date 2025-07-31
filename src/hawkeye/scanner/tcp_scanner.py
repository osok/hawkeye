"""
TCP port scanner implementation for HawkEye.

This module provides TCP port scanning capabilities using connect() scans
with proper timeout handling and connection management.
"""

import socket
import time
from typing import Optional

from .base import BaseScanner, ScanResult, ScanTarget, PortState, ScanType, ScanTimeoutError
from ..utils.logging import get_logger


class TCPScanner(BaseScanner):
    """TCP port scanner using connect() method."""
    
    def __init__(self, settings=None):
        """Initialize TCP scanner."""
        super().__init__(settings)
        self.logger = get_logger(self.__class__.__name__)
    
    def scan_port(self, target: ScanTarget, port: int) -> ScanResult:
        """
        Scan a single TCP port using connect() method.
        
        Args:
            target: The target to scan
            port: The port number to scan
            
        Returns:
            ScanResult: Result of the TCP scan
        """
        start_time = time.time()
        
        try:
            # Create socket for the target
            sock = self._create_socket(target)
            
            try:
                # Attempt to connect
                result = sock.connect_ex((target.host, port))
                response_time = time.time() - start_time
                
                if result == 0:
                    # Connection successful - port is open
                    self.logger.debug(f"TCP port {target.host}:{port} is OPEN")
                    state = PortState.OPEN
                else:
                    # Connection failed - port is closed or filtered
                    self.logger.debug(f"TCP port {target.host}:{port} is CLOSED (errno: {result})")
                    state = PortState.CLOSED
                
                return ScanResult(
                    target=target,
                    port=port,
                    state=state,
                    scan_type=ScanType.TCP_CONNECT,
                    response_time=response_time,
                    raw_data={'errno': str(result)}
                )
                
            finally:
                sock.close()
                
        except socket.timeout:
            response_time = time.time() - start_time
            self.logger.debug(f"TCP port {target.host}:{port} timed out")
            
            return ScanResult(
                target=target,
                port=port,
                state=PortState.FILTERED,
                scan_type=ScanType.TCP_CONNECT,
                response_time=response_time,
                error="Connection timeout"
            )
            
        except socket.gaierror as e:
            response_time = time.time() - start_time
            self.logger.error(f"DNS resolution failed for {target.host}: {e}")
            
            return ScanResult(
                target=target,
                port=port,
                state=PortState.UNKNOWN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=response_time,
                error=f"DNS resolution failed: {e}"
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            self.logger.error(f"Unexpected error scanning {target.host}:{port}: {e}")
            
            return ScanResult(
                target=target,
                port=port,
                state=PortState.UNKNOWN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=response_time,
                error=f"Scan error: {e}"
            )
    
    def get_scan_type(self) -> ScanType:
        """Get the scan type for TCP connect scans."""
        return ScanType.TCP_CONNECT
    
    def grab_banner(self, target: ScanTarget, port: int, timeout: Optional[float] = None) -> Optional[str]:
        """
        Attempt to grab a service banner from an open TCP port.
        
        Args:
            target: The target to connect to
            port: The port number to connect to
            timeout: Optional timeout override
            
        Returns:
            Optional[str]: Service banner if available, None otherwise
        """
        if timeout is None:
            timeout = self.settings.scan.timeout_seconds
        
        try:
            sock = self._create_socket(target)
            sock.settimeout(timeout)
            
            try:
                # Connect to the port
                result = sock.connect_ex((target.host, port))
                if result != 0:
                    return None
                
                # Try to receive banner data
                banner_data = sock.recv(1024)
                if banner_data:
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                    self.logger.debug(f"Grabbed banner from {target.host}:{port}: {banner[:100]}...")
                    return banner
                
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.debug(f"Failed to grab banner from {target.host}:{port}: {e}")
        
        return None
    
    def test_http_service(self, target: ScanTarget, port: int) -> Optional[str]:
        """
        Test if a port is running an HTTP service.
        
        Args:
            target: The target to test
            port: The port number to test
            
        Returns:
            Optional[str]: HTTP response if service detected, None otherwise
        """
        try:
            sock = self._create_socket(target)
            
            try:
                # Connect to the port
                result = sock.connect_ex((target.host, port))
                if result != 0:
                    return None
                
                # Send HTTP GET request
                http_request = f"GET / HTTP/1.1\r\nHost: {target.host}\r\nConnection: close\r\n\r\n"
                sock.send(http_request.encode())
                
                # Receive response
                response = sock.recv(4096)
                if response:
                    response_str = response.decode('utf-8', errors='ignore')
                    if response_str.startswith('HTTP/'):
                        self.logger.debug(f"HTTP service detected on {target.host}:{port}")
                        return response_str
                
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.debug(f"HTTP test failed for {target.host}:{port}: {e}")
        
        return None
    
    def scan_with_banner_grab(self, target: ScanTarget, port: int) -> ScanResult:
        """
        Scan a port and attempt to grab service banner if open.
        
        Args:
            target: The target to scan
            port: The port number to scan
            
        Returns:
            ScanResult: Enhanced scan result with banner information
        """
        # First perform the basic port scan
        result = self.scan_port(target, port)
        
        # If port is open, try to grab banner
        if result.is_open:
            banner = self.grab_banner(target, port)
            if banner:
                # Create service info from banner
                from .fingerprint import ServiceFingerprinter
                fingerprinter = ServiceFingerprinter()
                service_info = fingerprinter.analyze_banner(banner, port)
                result.service_info = service_info
                result.raw_data['banner'] = banner
            
            # Also test for HTTP service
            http_response = self.test_http_service(target, port)
            if http_response:
                result.raw_data['http_response'] = http_response[:500]  # Truncate for storage
        
        return result 