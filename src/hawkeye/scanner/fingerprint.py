"""
Service fingerprinting for network scanning operations.

This module provides functionality to identify services running on open ports
through banner analysis, protocol detection, and service-specific probes.
"""

import re
import socket
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from .base import ServiceInfo, ScanTarget
from ..config.settings import get_settings
from ..utils.logging import get_logger


@dataclass
class ServiceSignature:
    """Represents a service signature for identification."""
    
    name: str
    pattern: str
    confidence: float
    version_pattern: Optional[str] = None
    product_pattern: Optional[str] = None
    ports: List[int] = None
    
    def __post_init__(self):
        """Compile regex patterns after initialization."""
        self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        if self.version_pattern:
            self.compiled_version = re.compile(self.version_pattern, re.IGNORECASE)
        if self.product_pattern:
            self.compiled_product = re.compile(self.product_pattern, re.IGNORECASE)


class ServiceFingerprinter:
    """Service fingerprinting engine for banner analysis."""
    
    def __init__(self, settings=None):
        """Initialize service fingerprinter."""
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        self._load_signatures()
    
    def _load_signatures(self) -> None:
        """Load service signatures for identification."""
        self.signatures = [
            # HTTP Services
            ServiceSignature(
                name="http",
                pattern=r"HTTP/\d\.\d",
                confidence=0.9,
                version_pattern=r"HTTP/(\d\.\d)",
                product_pattern=r"Server:\s*([^\r\n]+)",
                ports=[80, 8080, 8000, 8443, 443]
            ),
            ServiceSignature(
                name="nginx",
                pattern=r"nginx",
                confidence=0.95,
                version_pattern=r"nginx/(\d+\.\d+\.\d+)",
                ports=[80, 443, 8080]
            ),
            ServiceSignature(
                name="apache",
                pattern=r"Apache",
                confidence=0.95,
                version_pattern=r"Apache/(\d+\.\d+\.\d+)",
                ports=[80, 443, 8080]
            ),
            
            # SSH Services
            ServiceSignature(
                name="ssh",
                pattern=r"SSH-\d\.\d",
                confidence=0.98,
                version_pattern=r"SSH-(\d\.\d)",
                product_pattern=r"SSH-\d\.\d-([^\r\n\s]+)",
                ports=[22]
            ),
            ServiceSignature(
                name="openssh",
                pattern=r"OpenSSH",
                confidence=0.95,
                version_pattern=r"OpenSSH_(\d+\.\d+)",
                ports=[22]
            ),
            
            # FTP Services
            ServiceSignature(
                name="ftp",
                pattern=r"220.*FTP",
                confidence=0.9,
                version_pattern=r"220.*FTP.*?(\d+\.\d+)",
                product_pattern=r"220\s+([^\r\n]+)",
                ports=[21]
            ),
            ServiceSignature(
                name="vsftpd",
                pattern=r"vsftpd",
                confidence=0.95,
                version_pattern=r"vsftpd\s+(\d+\.\d+\.\d+)",
                ports=[21]
            ),
            
            # SMTP Services
            ServiceSignature(
                name="smtp",
                pattern=r"220.*SMTP",
                confidence=0.9,
                product_pattern=r"220\s+([^\r\n]+)",
                ports=[25, 587, 465]
            ),
            ServiceSignature(
                name="postfix",
                pattern=r"Postfix",
                confidence=0.95,
                ports=[25, 587]
            ),
            
            # Database Services
            ServiceSignature(
                name="mysql",
                pattern=r"mysql",
                confidence=0.9,
                version_pattern=r"(\d+\.\d+\.\d+)",
                ports=[3306]
            ),
            ServiceSignature(
                name="postgresql",
                pattern=r"PostgreSQL",
                confidence=0.95,
                version_pattern=r"PostgreSQL\s+(\d+\.\d+)",
                ports=[5432]
            ),
            
            # Node.js and MCP-related Services
            ServiceSignature(
                name="nodejs",
                pattern=r"Node\.js|node\.js",
                confidence=0.8,
                version_pattern=r"Node\.js\s+v?(\d+\.\d+\.\d+)",
                ports=[3000, 8000, 8080, 9000]
            ),
            ServiceSignature(
                name="express",
                pattern=r"Express",
                confidence=0.8,
                version_pattern=r"Express/(\d+\.\d+\.\d+)",
                ports=[3000, 8000, 8080]
            ),
            ServiceSignature(
                name="mcp-server",
                pattern=r"mcp|model.context.protocol",
                confidence=0.7,
                ports=[3000, 8000, 8080, 9000]
            ),
            
            # Other Common Services
            ServiceSignature(
                name="telnet",
                pattern=r"telnet",
                confidence=0.8,
                ports=[23]
            ),
            ServiceSignature(
                name="dns",
                pattern=r"DNS|BIND",
                confidence=0.9,
                version_pattern=r"BIND\s+(\d+\.\d+\.\d+)",
                ports=[53]
            ),
            ServiceSignature(
                name="redis",
                pattern=r"Redis",
                confidence=0.95,
                version_pattern=r"Redis\s+server\s+v=(\d+\.\d+\.\d+)",
                ports=[6379]
            ),
        ]
    
    def analyze_banner(self, banner: str, port: int) -> Optional[ServiceInfo]:
        """
        Analyze a service banner to identify the service.
        
        Args:
            banner: The service banner text
            port: The port number where the banner was captured
            
        Returns:
            Optional[ServiceInfo]: Service information if identified
        """
        if not banner:
            return None
        
        self.logger.debug(f"Analyzing banner for port {port}: {banner[:100]}...")
        
        best_match = None
        best_confidence = 0.0
        
        for signature in self.signatures:
            # Check if port matches (if specified)
            if signature.ports and port not in signature.ports:
                continue
            
            # Check if pattern matches
            match = signature.compiled_pattern.search(banner)
            if match:
                confidence = signature.confidence
                
                # Boost confidence if port matches expected ports
                if signature.ports and port in signature.ports:
                    confidence += 0.1
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = signature
        
        if best_match:
            return self._extract_service_info(best_match, banner, port)
        
        # If no specific match, create generic service info
        return ServiceInfo(
            name="unknown",
            banner=banner[:200],  # Truncate long banners
            confidence=0.3,
            extra_info={"port": str(port)}
        )
    
    def _extract_service_info(self, signature: ServiceSignature, banner: str, port: int) -> ServiceInfo:
        """
        Extract detailed service information using the matched signature.
        
        Args:
            signature: The matched service signature
            banner: The service banner
            port: The port number
            
        Returns:
            ServiceInfo: Detailed service information
        """
        service_info = ServiceInfo(
            name=signature.name,
            banner=banner[:200],
            confidence=signature.confidence,
            extra_info={"port": str(port)}
        )
        
        # Extract version if pattern is available
        if signature.version_pattern and hasattr(signature, 'compiled_version'):
            version_match = signature.compiled_version.search(banner)
            if version_match:
                service_info.version = version_match.group(1)
        
        # Extract product if pattern is available
        if signature.product_pattern and hasattr(signature, 'compiled_product'):
            product_match = signature.compiled_product.search(banner)
            if product_match:
                service_info.product = product_match.group(1).strip()
        
        self.logger.debug(f"Identified service: {service_info}")
        return service_info
    
    def probe_http_service(self, target: ScanTarget, port: int) -> Optional[ServiceInfo]:
        """
        Probe for HTTP service with detailed analysis.
        
        Args:
            target: The target to probe
            port: The port to probe
            
        Returns:
            Optional[ServiceInfo]: HTTP service information if detected
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.settings.scan.timeout_seconds)
            
            try:
                # Connect to the service
                result = sock.connect_ex((target.host, port))
                if result != 0:
                    return None
                
                # Send HTTP request
                http_request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target.host}\r\n"
                    f"User-Agent: HawkEye/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.send(http_request.encode())
                
                # Receive response
                response = sock.recv(4096).decode('utf-8', errors='ignore')
                
                if response.startswith('HTTP/'):
                    return self._analyze_http_response(response, port)
                
            finally:
                sock.close()
                
        except Exception as e:
            self.logger.debug(f"HTTP probe failed for {target.host}:{port}: {e}")
        
        return None
    
    def _analyze_http_response(self, response: str, port: int) -> ServiceInfo:
        """
        Analyze HTTP response for detailed service information.
        
        Args:
            response: The HTTP response
            port: The port number
            
        Returns:
            ServiceInfo: HTTP service information
        """
        service_info = ServiceInfo(
            name="http",
            banner=response[:200],
            confidence=0.9,
            extra_info={"port": str(port), "protocol": "HTTP"}
        )
        
        # Extract HTTP version
        version_match = re.search(r'HTTP/(\d\.\d)', response)
        if version_match:
            service_info.extra_info["http_version"] = version_match.group(1)
        
        # Extract server information
        server_match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
        if server_match:
            server_info = server_match.group(1).strip()
            service_info.product = server_info
            
            # Check for specific server types
            if 'nginx' in server_info.lower():
                service_info.name = "nginx"
                service_info.confidence = 0.95
                version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_info)
                if version_match:
                    service_info.version = version_match.group(1)
            elif 'apache' in server_info.lower():
                service_info.name = "apache"
                service_info.confidence = 0.95
                version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_info)
                if version_match:
                    service_info.version = version_match.group(1)
            elif 'express' in server_info.lower():
                service_info.name = "express"
                service_info.confidence = 0.8
        
        # Check for Node.js indicators
        if 'x-powered-by' in response.lower():
            powered_by_match = re.search(r'X-Powered-By:\s*([^\r\n]+)', response, re.IGNORECASE)
            if powered_by_match:
                powered_by = powered_by_match.group(1).strip()
                service_info.extra_info["powered_by"] = powered_by
                
                if 'express' in powered_by.lower():
                    service_info.name = "express"
                    service_info.confidence = 0.85
        
        # Check for potential MCP server indicators
        if any(indicator in response.lower() for indicator in ['mcp', 'model-context-protocol', 'anthropic']):
            service_info.extra_info["mcp_indicators"] = "true"
            service_info.confidence = min(service_info.confidence + 0.1, 1.0)
        
        return service_info
    
    def identify_service_by_port(self, port: int) -> Optional[ServiceInfo]:
        """
        Identify service based on well-known port numbers.
        
        Args:
            port: The port number
            
        Returns:
            Optional[ServiceInfo]: Service information based on port
        """
        well_known_ports = {
            21: ("ftp", "FTP Server"),
            22: ("ssh", "SSH Server"),
            23: ("telnet", "Telnet Server"),
            25: ("smtp", "SMTP Server"),
            53: ("dns", "DNS Server"),
            80: ("http", "HTTP Server"),
            110: ("pop3", "POP3 Server"),
            143: ("imap", "IMAP Server"),
            443: ("https", "HTTPS Server"),
            993: ("imaps", "IMAP over SSL"),
            995: ("pop3s", "POP3 over SSL"),
            3306: ("mysql", "MySQL Database"),
            5432: ("postgresql", "PostgreSQL Database"),
            6379: ("redis", "Redis Database"),
            # MCP common ports
            3000: ("http", "HTTP Server (Node.js)"),
            8000: ("http", "HTTP Server (Development)"),
            8080: ("http", "HTTP Server (Alternative)"),
            9000: ("http", "HTTP Server (Alternative)"),
        }
        
        if port in well_known_ports:
            name, product = well_known_ports[port]
            return ServiceInfo(
                name=name,
                product=product,
                confidence=0.6,  # Lower confidence for port-only identification
                extra_info={"port": str(port), "identification_method": "port_based"}
            )
        
        return None 