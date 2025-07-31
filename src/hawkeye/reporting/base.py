"""
Base classes and data models for the HawkEye reporting engine.

This module provides the foundational classes and data structures for
generating comprehensive security reports in multiple formats, including
data aggregation, statistics, and template-based report generation.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

from ..assessment.base import AssessmentResult, RiskLevel, VulnerabilityCategory
from ..detection.base import DetectionResult, TransportType, MCPServerType
from ..detection.pipeline import PipelineResult
from ..detection.mcp_introspection.models import MCPServerInfo, MCPTool, MCPResource, MCPCapabilities
from ..scanner.base import ScanResult, PortState, ScanType
from ..utils.logging import get_logger


class ReportFormat(Enum):
    """Enumeration of supported report formats."""
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"


class ReportType(Enum):
    """Enumeration of report types."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAILED = "technical_detailed"
    VULNERABILITY_REPORT = "vulnerability_report"
    COMPLIANCE_REPORT = "compliance_report"
    SCAN_RESULTS = "scan_results"
    DETECTION_RESULTS = "detection_results"
    RISK_ASSESSMENT = "risk_assessment"
    COMBINED_REPORT = "combined_report"
    THREAT_ANALYSIS = "threat_analysis"
    INTROSPECTION_REPORT = "introspection_report"


@dataclass
class ReportMetadata:
    """Metadata for generated reports."""
    
    title: str
    report_type: ReportType
    format: ReportFormat
    generated_at: float = field(default_factory=time.time)
    generated_by: str = "HawkEye Security Reconnaissance Tool"
    version: str = "1.0.0"
    description: Optional[str] = None
    author: Optional[str] = None
    organization: Optional[str] = None
    classification: str = "Internal"
    retention_period: Optional[str] = None
    
    @property
    def generated_timestamp(self) -> str:
        """Get formatted timestamp."""
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.generated_at))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        # Safe enum to value conversion
        from enum import Enum
        report_type_val = self.report_type.value if isinstance(self.report_type, Enum) else self.report_type
        format_val = self.format.value if isinstance(self.format, Enum) else self.format
        
        return {
            'title': self.title,
            'report_type': report_type_val,
            'format': format_val,
            'generated_at': self.generated_at,
            'generated_timestamp': self.generated_timestamp,
            'generated_by': self.generated_by,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'organization': self.organization,
            'classification': self.classification,
            'retention_period': self.retention_period,
        }


@dataclass
class ScanSummary:
    """Summary statistics for scan operations."""
    
    total_targets: int = 0
    total_ports_scanned: int = 0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    services_detected: int = 0
    scan_duration: Optional[float] = None
    scan_start_time: Optional[float] = None
    scan_end_time: Optional[float] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate scan success rate."""
        if self.total_ports_scanned == 0:
            return 0.0
        return (self.open_ports + self.closed_ports) / self.total_ports_scanned
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            'total_targets': self.total_targets,
            'total_ports_scanned': self.total_ports_scanned,
            'open_ports': self.open_ports,
            'closed_ports': self.closed_ports,
            'filtered_ports': self.filtered_ports,
            'services_detected': self.services_detected,
            'success_rate': self.success_rate,
            'scan_duration': self.scan_duration,
            'scan_start_time': self.scan_start_time,
            'scan_end_time': self.scan_end_time,
        }


@dataclass
class DetectionSummary:
    """Summary statistics for MCP detection operations."""
    
    total_targets: int = 0
    mcp_servers_detected: int = 0
    detection_methods_used: List[str] = field(default_factory=list)
    transport_types_found: Dict[str, int] = field(default_factory=dict)
    server_types_found: Dict[str, int] = field(default_factory=dict)
    secure_servers: int = 0
    insecure_servers: int = 0
    authenticated_servers: int = 0
    unauthenticated_servers: int = 0
    detection_duration: Optional[float] = None
    
    @property
    def detection_rate(self) -> float:
        """Calculate MCP detection rate."""
        if self.total_targets == 0:
            return 0.0
        return self.mcp_servers_detected / self.total_targets
    
    @property
    def security_rate(self) -> float:
        """Calculate security configuration rate."""
        if self.mcp_servers_detected == 0:
            return 0.0
        return self.secure_servers / self.mcp_servers_detected
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            'total_targets': self.total_targets,
            'mcp_servers_detected': self.mcp_servers_detected,
            'detection_rate': self.detection_rate,
            'detection_methods_used': self.detection_methods_used,
            'transport_types_found': self.transport_types_found,
            'server_types_found': self.server_types_found,
            'secure_servers': self.secure_servers,
            'insecure_servers': self.insecure_servers,
            'security_rate': self.security_rate,
            'authenticated_servers': self.authenticated_servers,
            'unauthenticated_servers': self.unauthenticated_servers,
            'detection_duration': self.detection_duration,
        }


@dataclass
class IntrospectionSummary:
    """Summary statistics for MCP introspection operations."""
    
    total_servers_introspected: int = 0
    successful_introspections: int = 0
    failed_introspections: int = 0
    total_tools_discovered: int = 0
    total_resources_discovered: int = 0
    total_capabilities_discovered: int = 0
    
    # Risk distribution
    critical_risk_servers: int = 0
    high_risk_servers: int = 0
    medium_risk_servers: int = 0
    low_risk_servers: int = 0
    minimal_risk_servers: int = 0
    
    # Tool categories
    file_access_tools: int = 0
    network_tools: int = 0
    code_execution_tools: int = 0
    data_access_tools: int = 0
    system_tools: int = 0
    
    # Transport types
    stdio_servers: int = 0
    http_servers: int = 0
    sse_servers: int = 0
    websocket_servers: int = 0
    
    introspection_duration: Optional[float] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate introspection success rate."""
        if self.total_servers_introspected == 0:
            return 0.0
        return self.successful_introspections / self.total_servers_introspected
    
    @property
    def high_risk_rate(self) -> float:
        """Calculate high risk server rate."""
        if self.total_servers_introspected == 0:
            return 0.0
        return (self.critical_risk_servers + self.high_risk_servers) / self.total_servers_introspected
    
    @property
    def average_tools_per_server(self) -> float:
        """Calculate average tools per server."""
        if self.successful_introspections == 0:
            return 0.0
        return self.total_tools_discovered / self.successful_introspections
    
    @property
    def average_resources_per_server(self) -> float:
        """Calculate average resources per server."""
        if self.successful_introspections == 0:
            return 0.0
        return self.total_resources_discovered / self.successful_introspections
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            'total_servers_introspected': self.total_servers_introspected,
            'successful_introspections': self.successful_introspections,
            'failed_introspections': self.failed_introspections,
            'success_rate': self.success_rate,
            'total_tools_discovered': self.total_tools_discovered,
            'total_resources_discovered': self.total_resources_discovered,
            'total_capabilities_discovered': self.total_capabilities_discovered,
            'average_tools_per_server': self.average_tools_per_server,
            'average_resources_per_server': self.average_resources_per_server,
            'critical_risk_servers': self.critical_risk_servers,
            'high_risk_servers': self.high_risk_servers,
            'medium_risk_servers': self.medium_risk_servers,
            'low_risk_servers': self.low_risk_servers,
            'minimal_risk_servers': self.minimal_risk_servers,
            'high_risk_rate': self.high_risk_rate,
            'file_access_tools': self.file_access_tools,
            'network_tools': self.network_tools,
            'code_execution_tools': self.code_execution_tools,
            'data_access_tools': self.data_access_tools,
            'system_tools': self.system_tools,
            'stdio_servers': self.stdio_servers,
            'http_servers': self.http_servers,
            'sse_servers': self.sse_servers,
            'websocket_servers': self.websocket_servers,
            'introspection_duration': self.introspection_duration,
        }


@dataclass
class RiskSummary:
    """Summary statistics for risk assessment operations."""
    
    total_assessments: int = 0
    critical_risk_targets: int = 0
    high_risk_targets: int = 0
    medium_risk_targets: int = 0
    low_risk_targets: int = 0
    no_risk_targets: int = 0
    total_findings: int = 0
    total_vulnerabilities: int = 0
    exploitable_vulnerabilities: int = 0
    unpatched_vulnerabilities: int = 0
    compliance_violations: Dict[str, int] = field(default_factory=dict)
    average_risk_score: float = 0.0
    assessment_duration: Optional[float] = None
    
    @property
    def high_risk_rate(self) -> float:
        """Calculate high risk target rate."""
        if self.total_assessments == 0:
            return 0.0
        return (self.critical_risk_targets + self.high_risk_targets) / self.total_assessments
    
    @property
    def vulnerability_rate(self) -> float:
        """Calculate vulnerability detection rate."""
        if self.total_assessments == 0:
            return 0.0
        return self.total_vulnerabilities / self.total_assessments
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            'total_assessments': self.total_assessments,
            'critical_risk_targets': self.critical_risk_targets,
            'high_risk_targets': self.high_risk_targets,
            'medium_risk_targets': self.medium_risk_targets,
            'low_risk_targets': self.low_risk_targets,
            'no_risk_targets': self.no_risk_targets,
            'high_risk_rate': self.high_risk_rate,
            'total_findings': self.total_findings,
            'total_vulnerabilities': self.total_vulnerabilities,
            'vulnerability_rate': self.vulnerability_rate,
            'exploitable_vulnerabilities': self.exploitable_vulnerabilities,
            'unpatched_vulnerabilities': self.unpatched_vulnerabilities,
            'compliance_violations': self.compliance_violations,
            'average_risk_score': self.average_risk_score,
            'assessment_duration': self.assessment_duration,
        }


@dataclass
class ReportData:
    """Comprehensive data container for report generation."""
    
    metadata: ReportMetadata
    scan_results: List[ScanResult] = field(default_factory=list)
    detection_results: List[DetectionResult] = field(default_factory=list)
    assessment_results: List[AssessmentResult] = field(default_factory=list)
    
    # Enhanced with pipeline results and introspection data
    pipeline_results: List[PipelineResult] = field(default_factory=list)
    introspection_data: Dict[str, MCPCapabilities] = field(default_factory=dict)
    mcp_servers: List[MCPServerInfo] = field(default_factory=list)
    
    scan_summary: Optional[ScanSummary] = None
    detection_summary: Optional[DetectionSummary] = None
    risk_summary: Optional[RiskSummary] = None
    introspection_summary: Optional[IntrospectionSummary] = None
    
    executive_summary: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_targets(self) -> int:
        """Get total number of unique targets."""
        targets = set()
        for result in self.scan_results:
            targets.add(result.target.host)
        for result in self.detection_results:
            targets.add(result.target_host)
        for result in self.assessment_results:
            targets.add(result.target_host)
        for result in self.pipeline_results:
            targets.add(result.target_host)
        return len(targets)
    
    @property
    def has_scan_data(self) -> bool:
        """Check if report contains scan data."""
        return len(self.scan_results) > 0
    
    @property
    def has_detection_data(self) -> bool:
        """Check if report contains detection data."""
        return len(self.detection_results) > 0
    
    @property
    def has_assessment_data(self) -> bool:
        """Check if report contains assessment data."""
        return len(self.assessment_results) > 0
    
    @property
    def has_pipeline_data(self) -> bool:
        """Check if report contains pipeline data."""
        return len(self.pipeline_results) > 0
    
    @property
    def has_introspection_data(self) -> bool:
        """Check if report contains introspection data."""
        return len(self.introspection_data) > 0 or len(self.mcp_servers) > 0
    
    @property
    def critical_findings(self) -> List[Dict[str, Any]]:
        """Get all critical findings across assessments."""
        findings = []
        for assessment in self.assessment_results:
            for finding in assessment.critical_findings:
                findings.append({
                    'target': assessment.target_host,
                    'finding': finding,
                })
        return findings
    
    @property
    def high_risk_targets(self) -> List[str]:
        """Get list of high-risk targets."""
        targets = []
        for assessment in self.assessment_results:
            if assessment.overall_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                targets.append(assessment.target_host)
        return targets
    
    @property
    def introspected_servers(self) -> List[MCPServerInfo]:
        """Get all introspected MCP servers."""
        servers = []
        servers.extend(self.mcp_servers)
        
        # Extract servers from pipeline results
        for pipeline_result in self.pipeline_results:
            if pipeline_result.best_mcp_server:
                servers.append(pipeline_result.best_mcp_server)
        
        return servers
    
    @property
    def total_tools_discovered(self) -> int:
        """Get total number of tools discovered across all servers."""
        total = 0
        for server in self.introspected_servers:
            # Handle different server object types safely
            if hasattr(server, 'get_tool_count'):
                total += server.get_tool_count()
            elif hasattr(server, 'tools'):
                # Fallback to tools attribute if method not available
                total += len(getattr(server, 'tools', []))
            else:
                # Log the issue for debugging
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Server object {type(server)} has no tool count method or attribute")
        return total
    
    @property
    def total_resources_discovered(self) -> int:
        """Get total number of resources discovered across all servers."""
        total = 0
        for server in self.introspected_servers:
            # Handle different server object types safely
            if hasattr(server, 'get_resource_count'):
                total += server.get_resource_count()
            elif hasattr(server, 'resources'):
                # Fallback to resources attribute if method not available
                total += len(getattr(server, 'resources', []))
            else:
                # Log the issue for debugging
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Server object {type(server)} has no resource count method or attribute")
        return total
    
    def get_targets_by_risk_level(self, risk_level: RiskLevel) -> List[str]:
        """Get targets filtered by risk level."""
        return [
            assessment.target_host 
            for assessment in self.assessment_results
            if assessment.overall_risk_level == risk_level
        ]
    
    def get_findings_by_category(self, category: VulnerabilityCategory) -> List[Dict[str, Any]]:
        """Get findings filtered by category."""
        findings = []
        for assessment in self.assessment_results:
            for finding in assessment.get_findings_by_category(category):
                findings.append({
                    'target': assessment.target_host,
                    'finding': finding,
                })
        return findings
    
    def get_servers_by_risk_level(self, risk_level: str) -> List[MCPServerInfo]:
        """Get MCP servers filtered by risk level."""
        return [
            server for server in self.introspected_servers
            if server.overall_risk_level.value == risk_level
        ]
    
    def get_tools_by_category(self, category: str) -> List[MCPTool]:
        """Get tools filtered by category."""
        tools = []
        for server in self.introspected_servers:
            for tool in server.tools:
                # Simple category matching - could be enhanced with proper categorization
                if category.lower() in tool.name.lower() or category.lower() in tool.description.lower():
                    tools.append(tool)
        return tools
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report data to dictionary."""
        return {
            'metadata': self.metadata.to_dict(),
            'summary': {
                'total_targets': self.total_targets,
                'has_scan_data': self.has_scan_data,
                'has_detection_data': self.has_detection_data,
                'has_assessment_data': self.has_assessment_data,
                'has_pipeline_data': self.has_pipeline_data,
                'has_introspection_data': self.has_introspection_data,
                'critical_findings_count': len(self.critical_findings),
                'high_risk_targets_count': len(self.high_risk_targets),
                'total_tools_discovered': self.total_tools_discovered,
                'total_resources_discovered': self.total_resources_discovered,
                'introspected_servers_count': len(self.introspected_servers),
            },
            'scan_summary': self.scan_summary.to_dict() if self.scan_summary else None,
            'detection_summary': self.detection_summary.to_dict() if self.detection_summary else None,
            'risk_summary': self.risk_summary.to_dict() if self.risk_summary else None,
            'introspection_summary': self.introspection_summary.to_dict() if self.introspection_summary else None,
            'scan_results': [result.to_dict() for result in self.scan_results],
            'detection_results': [result.to_dict() for result in self.detection_results],
            'assessment_results': [result.to_dict() for result in self.assessment_results],
            'pipeline_results': [self._pipeline_result_to_dict(result) for result in self.pipeline_results],
            'introspection_data': {k: self._capabilities_to_dict(v) for k, v in self.introspection_data.items()},
            'mcp_servers': [self._server_info_to_dict(server) for server in self.mcp_servers],
            'executive_summary': self.executive_summary,
            'recommendations': self.recommendations,
            'raw_data': self.raw_data,
        }
    
    def _pipeline_result_to_dict(self, result: PipelineResult) -> Dict[str, Any]:
        """Convert PipelineResult to dictionary."""
        return {
            'target_host': result.target_host,
            'start_time': result.start_time.isoformat(),
            'end_time': result.end_time.isoformat(),
            'duration': result.duration,
            'success': result.success,
            'total_detections': result.total_detections,
            'successful_detections': result.successful_detections,
            'failed_detections': result.failed_detections,
            'mcp_servers_found': result.mcp_servers_found,
            'best_mcp_server': self._server_info_to_dict(result.best_mcp_server) if result.best_mcp_server else None,
            'highest_confidence_result': result.highest_confidence_result.to_dict() if result.highest_confidence_result else None,
            'risk_assessment': result.risk_assessment,
            'errors': result.errors,
            'warnings': result.warnings,
            'introspection_results_count': len(result.introspection_results),
        }
    
    def _capabilities_to_dict(self, capabilities: MCPCapabilities) -> Dict[str, Any]:
        """Convert MCPCapabilities to dictionary."""
        return capabilities.dict() if hasattr(capabilities, 'dict') else capabilities.__dict__
    
    def _server_info_to_dict(self, server: MCPServerInfo) -> Dict[str, Any]:
        """Convert MCPServerInfo to dictionary."""
        return server.dict() if hasattr(server, 'dict') else server.__dict__


class BaseReporter(ABC):
    """Abstract base class for report generators."""
    
    def __init__(self, settings=None):
        """Initialize the reporter with configuration settings."""
        from ..config.settings import get_settings
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        self._generation_stats = {
            'reports_generated': 0,
            'successful_generations': 0,
            'failed_generations': 0,
            'total_generation_time': 0.0,
        }
    
    @abstractmethod
    def generate_report(self, data: ReportData, output_path: Optional[Path] = None) -> str:
        """
        Generate a report from the provided data.
        
        Args:
            data: Report data to generate from
            output_path: Optional path to save the report
            
        Returns:
            str: Generated report content or path to saved file
        """
        pass
    
    @abstractmethod
    def get_format(self) -> ReportFormat:
        """
        Get the report format supported by this reporter.
        
        Returns:
            ReportFormat: The format this reporter generates
        """
        pass
    
    def validate_data(self, data: ReportData) -> None:
        """
        Validate report data before generation.
        
        Args:
            data: Report data to validate
            
        Raises:
            ReportingError: If data validation fails
        """
        if not isinstance(data, ReportData):
            raise ReportingError("Invalid data type: expected ReportData")
        
        if not data.metadata:
            raise ReportingError("Report metadata is required")
        
        if not (data.has_scan_data or data.has_detection_data or data.has_assessment_data or 
                data.has_pipeline_data or data.has_introspection_data):
            raise ReportingError("Report must contain at least one type of data")
    
    def get_generation_statistics(self) -> Dict[str, Any]:
        """Get report generation statistics."""
        stats = self._generation_stats.copy()
        if stats['reports_generated'] > 0:
            stats['average_generation_time'] = stats['total_generation_time'] / stats['reports_generated']
            stats['success_rate'] = stats['successful_generations'] / stats['reports_generated']
        else:
            stats['average_generation_time'] = 0.0
            stats['success_rate'] = 0.0
        
        return stats
    
    def clear_statistics(self) -> None:
        """Clear generation statistics."""
        self._generation_stats = {
            'reports_generated': 0,
            'successful_generations': 0,
            'failed_generations': 0,
            'total_generation_time': 0.0,
        }
    
    def _update_statistics(self, success: bool, generation_time: float) -> None:
        """Update generation statistics."""
        self._generation_stats['reports_generated'] += 1
        self._generation_stats['total_generation_time'] += generation_time
        
        if success:
            self._generation_stats['successful_generations'] += 1
        else:
            self._generation_stats['failed_generations'] += 1
    
    def _create_output_path(self, base_path: Optional[Path], data: ReportData) -> Path:
        """Create output path for report file."""
        if base_path is None:
            # Generate default filename
            timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime(data.metadata.generated_at))
            filename = f"hawkeye_report_{timestamp}.{self.get_format().value}"
            base_path = Path(filename)
        
        # Ensure directory exists
        base_path.parent.mkdir(parents=True, exist_ok=True)
        
        return base_path


class ReportingError(Exception):
    """Base exception for reporting operations."""
    pass


class FormatError(ReportingError):
    """Exception raised for report format errors."""
    pass


class TemplateError(ReportingError):
    """Exception raised for template processing errors."""
    pass


class ValidationError(ReportingError):
    """Exception raised for data validation errors."""
    pass 