"""
Base classes and interfaces for network scanning operations.

This module defines the core abstractions and data models used throughout
the HawkEye network scanning engine.
"""

import socket
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Union
from ipaddress import IPv4Address, IPv6Address, AddressValueError

from ..config.settings import get_settings
from ..utils.logging import get_logger


class PortState(Enum):
    """Enumeration of possible port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class ScanType(Enum):
    """Enumeration of scan types."""
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    UDP = "udp"
    SERVICE_DETECTION = "service_detection"


@dataclass
class ScanTarget:
    """Represents a target for network scanning."""
    
    host: str
    ports: List[int] = field(default_factory=list)
    scan_types: Set[ScanType] = field(default_factory=lambda: {ScanType.TCP_CONNECT})
    
    def __post_init__(self):
        """Validate the target after initialization."""
        self._validate_host()
        self._validate_ports()
    
    def _validate_host(self) -> None:
        """Validate the host address."""
        try:
            # Try to parse as IP address
            if ':' in self.host:
                IPv6Address(self.host)
            else:
                IPv4Address(self.host)
        except AddressValueError:
            # If not an IP, validate as hostname
            if not self.host or len(self.host) > 253:
                raise ValueError(f"Invalid hostname: {self.host}")
            
            # Basic hostname validation
            if self.host.startswith('-') or self.host.endswith('-'):
                raise ValueError(f"Invalid hostname: {self.host}")
    
    def _validate_ports(self) -> None:
        """Validate port numbers."""
        for port in self.ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"Invalid port number: {port}")
    
    @property
    def is_ipv6(self) -> bool:
        """Check if the target is an IPv6 address."""
        try:
            IPv6Address(self.host)
            return True
        except AddressValueError:
            return False
    
    @property
    def is_ipv4(self) -> bool:
        """Check if the target is an IPv4 address."""
        try:
            IPv4Address(self.host)
            return True
        except AddressValueError:
            return False


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    
    name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    extra_info: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0  # 0.0 to 1.0
    
    def __str__(self) -> str:
        """String representation of service info."""
        parts = []
        if self.name:
            parts.append(self.name)
        if self.version:
            parts.append(f"v{self.version}")
        if self.product:
            parts.append(f"({self.product})")
        
        result = " ".join(parts) if parts else "Unknown Service"
        if self.confidence < 1.0:
            result += f" [confidence: {self.confidence:.2f}]"
        
        return result


@dataclass
class ScanResult:
    """Result of a port scan operation."""
    
    target: ScanTarget
    port: int
    state: PortState
    scan_type: ScanType
    timestamp: float = field(default_factory=time.time)
    response_time: Optional[float] = None
    service_info: Optional[ServiceInfo] = None
    error: Optional[str] = None
    raw_data: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_open(self) -> bool:
        """Check if the port is open."""
        return self.state == PortState.OPEN
    
    @property
    def has_service_info(self) -> bool:
        """Check if service information is available."""
        return self.service_info is not None
    
    def to_dict(self) -> Dict:
        """Convert scan result to dictionary."""
        result = {
            'host': self.target.host,
            'port': self.port,
            'state': self.state.value,
            'scan_type': self.scan_type.value,
            'timestamp': self.timestamp,
            'response_time': self.response_time,
            'error': self.error,
            'raw_data': self.raw_data,
        }
        
        if self.service_info:
            result['service'] = {
                'name': self.service_info.name,
                'version': self.service_info.version,
                'banner': self.service_info.banner,
                'product': self.service_info.product,
                'extra_info': self.service_info.extra_info,
                'confidence': self.service_info.confidence,
            }
        
        return result


class BaseScanner(ABC):
    """Abstract base class for network scanners."""
    
    def __init__(self, settings=None):
        """Initialize the scanner with configuration settings."""
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        self._results: List[ScanResult] = []
        self._scan_stats = {
            'total_scans': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'start_time': None,
            'end_time': None,
        }
    
    @abstractmethod
    def scan_port(self, target: ScanTarget, port: int) -> ScanResult:
        """
        Scan a single port on a target.
        
        Args:
            target: The target to scan
            port: The port number to scan
            
        Returns:
            ScanResult: Result of the scan operation
        """
        pass
    
    def scan_target(self, target: ScanTarget) -> List[ScanResult]:
        """
        Scan all specified ports on a target.
        
        Args:
            target: The target to scan
            
        Returns:
            List[ScanResult]: Results of all scan operations
        """
        self.logger.info(f"Starting scan of {target.host} on {len(target.ports)} ports")
        self._scan_stats['start_time'] = time.time()
        
        results = []
        for port in target.ports:
            try:
                result = self.scan_port(target, port)
                results.append(result)
                self._results.append(result)
                self._scan_stats['successful_scans'] += 1
                
                if result.is_open:
                    self.logger.info(f"Found open port: {target.host}:{port}")
                
            except Exception as e:
                self.logger.error(f"Error scanning {target.host}:{port} - {e}")
                error_result = ScanResult(
                    target=target,
                    port=port,
                    state=PortState.UNKNOWN,
                    scan_type=self.get_scan_type(),
                    error=str(e)
                )
                results.append(error_result)
                self._results.append(error_result)
                self._scan_stats['failed_scans'] += 1
            
            self._scan_stats['total_scans'] += 1
        
        self._scan_stats['end_time'] = time.time()
        self.logger.info(f"Completed scan of {target.host}: {len(results)} results")
        
        return results
    
    @abstractmethod
    def get_scan_type(self) -> ScanType:
        """
        Get the scan type implemented by this scanner.
        
        Returns:
            ScanType: The type of scan this scanner performs
        """
        pass
    
    def get_results(self) -> List[ScanResult]:
        """Get all scan results."""
        return self._results.copy()
    
    def get_open_ports(self) -> List[ScanResult]:
        """Get only the results for open ports."""
        return [result for result in self._results if result.is_open]
    
    def get_scan_statistics(self) -> Dict:
        """Get scanning statistics."""
        stats = self._scan_stats.copy()
        if stats['start_time'] and stats['end_time']:
            stats['duration'] = stats['end_time'] - stats['start_time']
            if stats['duration'] > 0:
                stats['scans_per_second'] = stats['total_scans'] / stats['duration']
        
        return stats
    
    def clear_results(self) -> None:
        """Clear all stored results and statistics."""
        self._results.clear()
        self._scan_stats = {
            'total_scans': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'start_time': None,
            'end_time': None,
        }
    
    def _create_socket(self, target: ScanTarget) -> socket.socket:
        """
        Create a socket appropriate for the target.
        
        Args:
            target: The scan target
            
        Returns:
            socket.socket: Configured socket
        """
        if target.is_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set socket timeout
        sock.settimeout(self.settings.scan.timeout_seconds)
        
        return sock
    
    def _resolve_hostname(self, hostname: str) -> List[str]:
        """
        Resolve hostname to IP addresses.
        
        Args:
            hostname: The hostname to resolve
            
        Returns:
            List[str]: List of resolved IP addresses
        """
        try:
            # Get address info for the hostname
            addr_info = socket.getaddrinfo(
                hostname, None, 
                socket.AF_UNSPEC, 
                socket.SOCK_STREAM
            )
            
            # Extract unique IP addresses
            ips = list(set(info[4][0] for info in addr_info))
            self.logger.debug(f"Resolved {hostname} to {ips}")
            return ips
            
        except socket.gaierror as e:
            self.logger.error(f"Failed to resolve hostname {hostname}: {e}")
            raise ValueError(f"Cannot resolve hostname: {hostname}")


class ScannerError(Exception):
    """Base exception for scanner-related errors."""
    pass


class ScanTimeoutError(ScannerError):
    """Exception raised when a scan operation times out."""
    pass


class InvalidTargetError(ScannerError):
    """Exception raised when a scan target is invalid."""
    pass 