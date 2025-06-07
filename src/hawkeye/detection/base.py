"""
Base classes and interfaces for MCP detection operations.

This module defines the core abstractions and data models used throughout
the HawkEye MCP detection engine.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Union, Any
from pathlib import Path

from ..config.settings import get_settings
from ..utils.logging import get_logger


class TransportType(Enum):
    """Enumeration of MCP transport types."""
    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class DetectionMethod(Enum):
    """Enumeration of detection methods."""
    PROCESS_ENUMERATION = "process_enumeration"
    CONFIG_FILE_DISCOVERY = "config_file_discovery"
    PROTOCOL_HANDSHAKE = "protocol_handshake"
    TRANSPORT_DETECTION = "transport_detection"
    NPX_PACKAGE_DETECTION = "npx_package_detection"
    DOCKER_INSPECTION = "docker_inspection"
    ENVIRONMENT_ANALYSIS = "environment_analysis"


class MCPServerType(Enum):
    """Enumeration of MCP server types."""
    STANDALONE = "standalone"
    NPX_PACKAGE = "npx_package"
    DOCKER_CONTAINER = "docker_container"
    EMBEDDED = "embedded"
    UNKNOWN = "unknown"


@dataclass
class ProcessInfo:
    """Information about a detected process."""
    
    pid: int
    name: str
    cmdline: List[str] = field(default_factory=list)
    cwd: Optional[str] = None
    env_vars: Dict[str, str] = field(default_factory=dict)
    user: Optional[str] = None
    create_time: Optional[float] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    
    @property
    def is_node_process(self) -> bool:
        """Check if this is a Node.js process."""
        return 'node' in self.name.lower() or any('node' in arg.lower() for arg in self.cmdline)
    
    @property
    def has_mcp_indicators(self) -> bool:
        """Check if process has MCP-related indicators."""
        mcp_keywords = ['mcp', 'model-context-protocol', '@modelcontextprotocol']
        cmdline_str = ' '.join(self.cmdline).lower()
        
        return any(keyword in cmdline_str for keyword in mcp_keywords)


@dataclass
class ConfigFileInfo:
    """Information about a detected configuration file."""
    
    path: Path
    file_type: str  # package.json, mcp.config.js, etc.
    content: Dict[str, Any] = field(default_factory=dict)
    mcp_config: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)
    
    @property
    def has_mcp_dependencies(self) -> bool:
        """Check if config has MCP-related dependencies."""
        mcp_packages = [
            '@modelcontextprotocol/sdk',
            '@modelcontextprotocol/server',
            '@modelcontextprotocol/client',
            'mcp-server',
            'mcp-client'
        ]
        return any(pkg in self.dependencies for pkg in mcp_packages)
    
    @property
    def has_mcp_scripts(self) -> bool:
        """Check if config has MCP-related scripts."""
        return any('mcp' in script.lower() for script in self.scripts.values())


@dataclass
class MCPServerInfo:
    """Comprehensive information about a detected MCP server."""
    
    host: str
    port: Optional[int] = None
    transport_type: TransportType = TransportType.UNKNOWN
    server_type: MCPServerType = MCPServerType.UNKNOWN
    process_info: Optional[ProcessInfo] = None
    config_info: Optional[ConfigFileInfo] = None
    capabilities: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    version: Optional[str] = None
    authentication: Optional[Dict[str, Any]] = None
    security_config: Dict[str, Any] = field(default_factory=dict)
    docker_info: Optional[Dict[str, Any]] = None
    environment_info: Optional[Dict[str, Any]] = None
    
    @property
    def is_secure(self) -> bool:
        """Check if the server appears to be securely configured."""
        if self.transport_type == TransportType.HTTP and self.port:
            # Check if using HTTPS (port 443 or explicit TLS config)
            return self.port == 443 or self.security_config.get('tls', False)
        elif self.transport_type == TransportType.WEBSOCKET:
            # Check for WSS (secure WebSocket)
            return self.security_config.get('secure', False)
        elif self.transport_type == TransportType.STDIO:
            # STDIO is inherently secure (local communication)
            return True
        return False
    
    @property
    def has_authentication(self) -> bool:
        """Check if authentication is configured."""
        return self.authentication is not None and bool(self.authentication)
    
    @property
    def endpoint_url(self) -> Optional[str]:
        """Get the endpoint URL if applicable."""
        if self.transport_type == TransportType.HTTP and self.port:
            protocol = 'https' if self.is_secure else 'http'
            return f"{protocol}://{self.host}:{self.port}"
        elif self.transport_type == TransportType.WEBSOCKET and self.port:
            protocol = 'wss' if self.is_secure else 'ws'
            return f"{protocol}://{self.host}:{self.port}"
        return None


@dataclass
class DetectionResult:
    """Result of an MCP detection operation."""
    
    target_host: str
    detection_method: DetectionMethod
    timestamp: float = field(default_factory=time.time)
    success: bool = False
    mcp_server: Optional[MCPServerInfo] = None
    confidence: float = 0.0  # 0.0 to 1.0
    error: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    scan_duration: Optional[float] = None
    
    @property
    def is_mcp_detected(self) -> bool:
        """Check if MCP server was detected."""
        return self.success and self.mcp_server is not None
    
    @property
    def risk_level(self) -> str:
        """Assess basic risk level based on detection."""
        if not self.is_mcp_detected:
            return "none"
        
        server = self.mcp_server
        if not server.is_secure or not server.has_authentication:
            return "high"
        elif server.transport_type == TransportType.HTTP:
            return "medium"
        else:
            return "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert detection result to dictionary."""
        result = {
            'target_host': self.target_host,
            'detection_method': self.detection_method.value,
            'timestamp': self.timestamp,
            'success': self.success,
            'confidence': self.confidence,
            'error': self.error,
            'raw_data': self.raw_data,
            'scan_duration': self.scan_duration,
            'risk_level': self.risk_level,
        }
        
        if self.mcp_server:
            result['mcp_server'] = {
                'host': self.mcp_server.host,
                'port': self.mcp_server.port,
                'transport_type': self.mcp_server.transport_type.value,
                'server_type': self.mcp_server.server_type.value,
                'capabilities': self.mcp_server.capabilities,
                'tools': self.mcp_server.tools,
                'resources': self.mcp_server.resources,
                'version': self.mcp_server.version,
                'is_secure': self.mcp_server.is_secure,
                'has_authentication': self.mcp_server.has_authentication,
                'endpoint_url': self.mcp_server.endpoint_url,
                'security_config': self.mcp_server.security_config,
            }
            
            if self.mcp_server.process_info:
                result['mcp_server']['process'] = {
                    'pid': self.mcp_server.process_info.pid,
                    'name': self.mcp_server.process_info.name,
                    'cmdline': self.mcp_server.process_info.cmdline,
                    'cwd': self.mcp_server.process_info.cwd,
                    'user': self.mcp_server.process_info.user,
                }
            
            if self.mcp_server.config_info:
                result['mcp_server']['config'] = {
                    'path': str(self.mcp_server.config_info.path),
                    'file_type': self.mcp_server.config_info.file_type,
                    'has_mcp_dependencies': self.mcp_server.config_info.has_mcp_dependencies,
                    'has_mcp_scripts': self.mcp_server.config_info.has_mcp_scripts,
                    'dependencies': self.mcp_server.config_info.dependencies,
                }
        
        return result


class MCPDetector(ABC):
    """Abstract base class for MCP detection operations."""
    
    def __init__(self, settings=None):
        """Initialize the detector with configuration settings."""
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        self._results: List[DetectionResult] = []
        self._detection_stats = {
            'total_detections': 0,
            'successful_detections': 0,
            'failed_detections': 0,
            'mcp_servers_found': 0,
            'start_time': None,
            'end_time': None,
        }
    
    @abstractmethod
    def detect(self, target_host: str, **kwargs) -> DetectionResult:
        """
        Perform MCP detection on a target.
        
        Args:
            target_host: The target host to analyze
            **kwargs: Additional detection parameters
            
        Returns:
            DetectionResult: Result of the detection operation
        """
        pass
    
    @abstractmethod
    def get_detection_method(self) -> DetectionMethod:
        """
        Get the detection method used by this detector.
        
        Returns:
            DetectionMethod: The detection method
        """
        pass
    
    def detect_multiple(self, targets: List[str], **kwargs) -> List[DetectionResult]:
        """
        Perform detection on multiple targets.
        
        Args:
            targets: List of target hosts to analyze
            **kwargs: Additional detection parameters
            
        Returns:
            List[DetectionResult]: Results of detection operations
        """
        self._detection_stats['start_time'] = time.time()
        results = []
        
        for target in targets:
            try:
                result = self.detect(target, **kwargs)
                results.append(result)
                self._results.append(result)
                
                self._detection_stats['total_detections'] += 1
                if result.success:
                    self._detection_stats['successful_detections'] += 1
                    if result.is_mcp_detected:
                        self._detection_stats['mcp_servers_found'] += 1
                else:
                    self._detection_stats['failed_detections'] += 1
                    
            except Exception as e:
                self.logger.error(f"Detection failed for {target}: {e}")
                error_result = DetectionResult(
                    target_host=target,
                    detection_method=self.get_detection_method(),
                    success=False,
                    error=str(e)
                )
                results.append(error_result)
                self._results.append(error_result)
                self._detection_stats['total_detections'] += 1
                self._detection_stats['failed_detections'] += 1
        
        self._detection_stats['end_time'] = time.time()
        return results
    
    def get_results(self) -> List[DetectionResult]:
        """Get all detection results."""
        return self._results.copy()
    
    def get_mcp_servers(self) -> List[DetectionResult]:
        """Get only results where MCP servers were detected."""
        return [result for result in self._results if result.is_mcp_detected]
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection statistics."""
        stats = self._detection_stats.copy()
        if stats['start_time'] and stats['end_time']:
            stats['total_duration'] = stats['end_time'] - stats['start_time']
        
        if stats['total_detections'] > 0:
            stats['success_rate'] = stats['successful_detections'] / stats['total_detections']
            stats['mcp_detection_rate'] = stats['mcp_servers_found'] / stats['total_detections']
        else:
            stats['success_rate'] = 0.0
            stats['mcp_detection_rate'] = 0.0
        
        return stats
    
    def clear_results(self) -> None:
        """Clear all detection results and reset statistics."""
        self._results.clear()
        self._detection_stats = {
            'total_detections': 0,
            'successful_detections': 0,
            'failed_detections': 0,
            'mcp_servers_found': 0,
            'start_time': None,
            'end_time': None,
        }
        self.logger.info("Detection results and statistics cleared")


# Exception classes for detection operations
class DetectionError(Exception):
    """Base exception for detection operations."""
    pass


class MCPDetectionError(DetectionError):
    """Exception raised during MCP-specific detection operations."""
    pass


class ProcessDetectionError(DetectionError):
    """Exception raised during process detection operations."""
    pass


class ConfigDetectionError(DetectionError):
    """Exception raised during configuration file detection operations."""
    pass


class ProtocolDetectionError(DetectionError):
    """Exception raised during protocol detection operations."""
    pass


class DockerDetectionError(DetectionError):
    """Exception raised during Docker container detection operations."""
    pass 