"""
MCP Detection Engine for HawkEye Security Reconnaissance Tool.

This module provides specialized detection capabilities for identifying
Model Context Protocol (MCP) server deployments within network infrastructure.
"""

from .base import (
    MCPDetector,
    DetectionResult,
    MCPServerInfo,
    TransportType,
    DetectionMethod,
    DetectionError,
    MCPDetectionError,
    ProcessDetectionError,
    ConfigDetectionError,
    ProtocolDetectionError,
)
from .process_enum import ProcessEnumerator
from .config_discovery import ConfigFileDiscovery
from .protocol_verify import ProtocolVerifier
from .transport_detect import TransportDetector
from .npx_detect import NPXDetector
from .docker_inspect import DockerInspector
from .env_analysis import EnvironmentAnalyzer

__all__ = [
    'MCPDetector',
    'DetectionResult', 
    'MCPServerInfo',
    'TransportType',
    'DetectionMethod',
    'DetectionError',
    'MCPDetectionError',
    'ProcessDetectionError',
    'ConfigDetectionError',
    'ProtocolDetectionError',
    'ProcessEnumerator',
    'ConfigFileDiscovery',
    'ProtocolVerifier',
    'TransportDetector',
    'NPXDetector',
    'DockerInspector',
    'EnvironmentAnalyzer',
] 