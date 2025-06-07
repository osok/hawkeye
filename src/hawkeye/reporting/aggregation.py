"""
Data aggregation and statistics module for HawkEye reporting engine.

This module provides comprehensive data aggregation, statistical analysis,
and summarization capabilities for scan results, detection findings,
and risk assessments.
"""

import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from statistics import mean, median, stdev

from .base import (
    ReportData, ScanSummary, DetectionSummary, RiskSummary,
    ReportingError
)
from ..assessment.base import AssessmentResult, RiskLevel, VulnerabilityCategory, ComplianceFramework
from ..detection.base import DetectionResult, TransportType, MCPServerType, DetectionMethod
from ..scanner.base import ScanResult, PortState, ScanType
from ..utils.logging import get_logger


@dataclass
class TimeSeriesData:
    """Time series data for trend analysis."""
    
    timestamps: List[float] = field(default_factory=list)
    values: List[float] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    
    def add_point(self, timestamp: float, value: float, label: str = "") -> None:
        """Add a data point to the time series."""
        self.timestamps.append(timestamp)
        self.values.append(value)
        self.labels.append(label)
    
    def get_trend(self) -> str:
        """Calculate trend direction."""
        if len(self.values) < 2:
            return "insufficient_data"
        
        # Simple linear trend calculation
        first_half = self.values[:len(self.values)//2]
        second_half = self.values[len(self.values)//2:]
        
        first_avg = mean(first_half) if first_half else 0
        second_avg = mean(second_half) if second_half else 0
        
        if second_avg > first_avg * 1.1:
            return "increasing"
        elif second_avg < first_avg * 0.9:
            return "decreasing"
        else:
            return "stable"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamps': self.timestamps,
            'values': self.values,
            'labels': self.labels,
            'trend': self.get_trend(),
            'count': len(self.values),
            'min_value': min(self.values) if self.values else 0,
            'max_value': max(self.values) if self.values else 0,
            'avg_value': mean(self.values) if self.values else 0,
        }


@dataclass
class DistributionData:
    """Distribution data for categorical analysis."""
    
    categories: Dict[str, int] = field(default_factory=dict)
    total_count: int = 0
    
    def add_item(self, category: str, count: int = 1) -> None:
        """Add items to a category."""
        self.categories[category] = self.categories.get(category, 0) + count
        self.total_count += count
    
    def get_percentages(self) -> Dict[str, float]:
        """Get percentage distribution."""
        if self.total_count == 0:
            return {}
        
        return {
            category: (count / self.total_count) * 100
            for category, count in self.categories.items()
        }
    
    def get_top_categories(self, n: int = 5) -> List[Tuple[str, int]]:
        """Get top N categories by count."""
        return sorted(self.categories.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'categories': self.categories,
            'total_count': self.total_count,
            'percentages': self.get_percentages(),
            'top_categories': self.get_top_categories(),
        }


class DataAggregator:
    """Main data aggregation and statistics engine."""
    
    def __init__(self, settings=None):
        """Initialize the data aggregator."""
        from ..config.settings import get_settings
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
    
    def aggregate_report_data(self, data: ReportData) -> ReportData:
        """
        Aggregate and enhance report data with statistics.
        
        Args:
            data: Report data to aggregate
            
        Returns:
            ReportData: Enhanced report data with aggregated statistics
        """
        try:
            # Create enhanced copy of data
            enhanced_data = data
            
            # Generate scan summary if scan data exists
            if data.has_scan_data:
                enhanced_data.scan_summary = self.generate_scan_summary(data.scan_results)
            
            # Generate detection summary if detection data exists
            if data.has_detection_data:
                enhanced_data.detection_summary = self.generate_detection_summary(data.detection_results)
            
            # Generate risk summary if assessment data exists
            if data.has_assessment_data:
                enhanced_data.risk_summary = self.generate_risk_summary(data.assessment_results)
            
            # Generate executive summary
            enhanced_data.executive_summary = self.generate_executive_summary(enhanced_data)
            
            # Generate recommendations
            enhanced_data.recommendations = self.generate_recommendations(enhanced_data)
            
            self.logger.info("Successfully aggregated report data")
            return enhanced_data
            
        except Exception as e:
            self.logger.error(f"Failed to aggregate report data: {e}")
            raise ReportingError(f"Data aggregation failed: {e}")
    
    def generate_scan_summary(self, scan_results: List[ScanResult]) -> ScanSummary:
        """Generate summary statistics for scan results."""
        if not scan_results:
            return ScanSummary()
        
        # Calculate basic statistics
        total_targets = len(set(result.target.host for result in scan_results))
        total_ports_scanned = len(scan_results)
        
        # Count port states
        state_counts = Counter(result.state for result in scan_results)
        open_ports = state_counts.get(PortState.OPEN, 0)
        closed_ports = state_counts.get(PortState.CLOSED, 0)
        filtered_ports = state_counts.get(PortState.FILTERED, 0)
        
        # Count services detected
        services_detected = sum(1 for result in scan_results if result.has_service_info)
        
        # Calculate timing statistics
        timestamps = [result.timestamp for result in scan_results if result.timestamp]
        scan_start_time = min(timestamps) if timestamps else None
        scan_end_time = max(timestamps) if timestamps else None
        scan_duration = (scan_end_time - scan_start_time) if scan_start_time and scan_end_time else None
        
        return ScanSummary(
            total_targets=total_targets,
            total_ports_scanned=total_ports_scanned,
            open_ports=open_ports,
            closed_ports=closed_ports,
            filtered_ports=filtered_ports,
            services_detected=services_detected,
            scan_duration=scan_duration,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
        )
    
    def generate_detection_summary(self, detection_results: List[DetectionResult]) -> DetectionSummary:
        """Generate summary statistics for detection results."""
        if not detection_results:
            return DetectionSummary()
        
        # Calculate basic statistics
        total_targets = len(set(result.target_host for result in detection_results))
        mcp_servers_detected = sum(1 for result in detection_results if result.is_mcp_detected)
        
        # Collect detection methods used
        detection_methods_used = list(set(
            result.detection_method.value for result in detection_results
        ))
        
        # Count transport types and server types
        transport_types_found = defaultdict(int)
        server_types_found = defaultdict(int)
        secure_servers = 0
        insecure_servers = 0
        authenticated_servers = 0
        unauthenticated_servers = 0
        
        for result in detection_results:
            if result.is_mcp_detected and result.mcp_server:
                server = result.mcp_server
                
                # Count transport types
                transport_types_found[server.transport_type.value] += 1
                
                # Count server types
                server_types_found[server.server_type.value] += 1
                
                # Count security configurations
                if server.is_secure:
                    secure_servers += 1
                else:
                    insecure_servers += 1
                
                if server.has_authentication:
                    authenticated_servers += 1
                else:
                    unauthenticated_servers += 1
        
        # Calculate timing statistics
        timestamps = [result.timestamp for result in detection_results if result.timestamp]
        detection_duration = None
        if timestamps:
            detection_duration = max(timestamps) - min(timestamps)
        
        return DetectionSummary(
            total_targets=total_targets,
            mcp_servers_detected=mcp_servers_detected,
            detection_methods_used=detection_methods_used,
            transport_types_found=dict(transport_types_found),
            server_types_found=dict(server_types_found),
            secure_servers=secure_servers,
            insecure_servers=insecure_servers,
            authenticated_servers=authenticated_servers,
            unauthenticated_servers=unauthenticated_servers,
            detection_duration=detection_duration,
        )
    
    def generate_risk_summary(self, assessment_results: List[AssessmentResult]) -> RiskSummary:
        """Generate summary statistics for risk assessment results."""
        if not assessment_results:
            return RiskSummary()
        
        # Calculate basic statistics
        total_assessments = len(assessment_results)
        
        # Count risk levels
        risk_level_counts = Counter(result.overall_risk_level for result in assessment_results)
        critical_risk_targets = risk_level_counts.get(RiskLevel.CRITICAL, 0)
        high_risk_targets = risk_level_counts.get(RiskLevel.HIGH, 0)
        medium_risk_targets = risk_level_counts.get(RiskLevel.MEDIUM, 0)
        low_risk_targets = risk_level_counts.get(RiskLevel.LOW, 0)
        no_risk_targets = risk_level_counts.get(RiskLevel.NONE, 0)
        
        # Count findings and vulnerabilities
        total_findings = sum(len(result.findings) for result in assessment_results)
        total_vulnerabilities = sum(len(result.vulnerabilities) for result in assessment_results)
        exploitable_vulnerabilities = sum(
            len(result.exploitable_vulnerabilities) for result in assessment_results
        )
        unpatched_vulnerabilities = sum(
            len(result.unpatched_vulnerabilities) for result in assessment_results
        )
        
        # Count compliance violations
        compliance_violations = defaultdict(int)
        for result in assessment_results:
            violations = result.get_compliance_violations()
            for framework, findings in violations.items():
                compliance_violations[framework.value] += len(findings)
        
        # Calculate average risk score
        risk_scores = [result.overall_risk_score for result in assessment_results]
        average_risk_score = mean(risk_scores) if risk_scores else 0.0
        
        # Calculate timing statistics
        durations = [result.assessment_duration for result in assessment_results 
                    if result.assessment_duration]
        assessment_duration = sum(durations) if durations else None
        
        return RiskSummary(
            total_assessments=total_assessments,
            critical_risk_targets=critical_risk_targets,
            high_risk_targets=high_risk_targets,
            medium_risk_targets=medium_risk_targets,
            low_risk_targets=low_risk_targets,
            no_risk_targets=no_risk_targets,
            total_findings=total_findings,
            total_vulnerabilities=total_vulnerabilities,
            exploitable_vulnerabilities=exploitable_vulnerabilities,
            unpatched_vulnerabilities=unpatched_vulnerabilities,
            compliance_violations=dict(compliance_violations),
            average_risk_score=average_risk_score,
            assessment_duration=assessment_duration,
        )
    
    def generate_executive_summary(self, data: ReportData) -> str:
        """Generate executive summary text."""
        summary_parts = []
        
        # Header
        summary_parts.append("EXECUTIVE SUMMARY")
        summary_parts.append("=" * 50)
        summary_parts.append("")
        
        # Overview
        summary_parts.append(f"This security reconnaissance assessment examined {data.total_targets} target(s) "
                           f"using the HawkEye security tool to identify potential MCP server deployments "
                           f"and associated security risks.")
        summary_parts.append("")
        
        # Key findings
        if data.has_assessment_data and data.risk_summary:
            risk_summary = data.risk_summary
            
            if risk_summary.critical_risk_targets > 0:
                summary_parts.append(f"🔴 CRITICAL: {risk_summary.critical_risk_targets} target(s) identified "
                                   f"with critical security risks requiring immediate attention.")
            
            if risk_summary.high_risk_targets > 0:
                summary_parts.append(f"🟠 HIGH: {risk_summary.high_risk_targets} target(s) identified "
                                   f"with high security risks requiring prompt remediation.")
            
            if risk_summary.exploitable_vulnerabilities > 0:
                summary_parts.append(f"⚠️  {risk_summary.exploitable_vulnerabilities} exploitable vulnerabilities "
                                   f"detected that could be actively exploited by attackers.")
            
            summary_parts.append("")
        
        # Detection results
        if data.has_detection_data and data.detection_summary:
            detection_summary = data.detection_summary
            summary_parts.append(f"MCP Detection Results:")
            summary_parts.append(f"• {detection_summary.mcp_servers_detected} MCP servers detected")
            summary_parts.append(f"• {detection_summary.secure_servers} servers with secure configuration")
            summary_parts.append(f"• {detection_summary.insecure_servers} servers with insecure configuration")
            summary_parts.append("")
        
        # Scan results
        if data.has_scan_data and data.scan_summary:
            scan_summary = data.scan_summary
            summary_parts.append(f"Network Scan Results:")
            summary_parts.append(f"• {scan_summary.total_ports_scanned} ports scanned")
            summary_parts.append(f"• {scan_summary.open_ports} open ports discovered")
            summary_parts.append(f"• {scan_summary.services_detected} services identified")
            summary_parts.append("")
        
        # Recommendations
        if data.has_assessment_data and data.risk_summary:
            summary_parts.append("Immediate Actions Required:")
            
            if data.risk_summary.critical_risk_targets > 0:
                summary_parts.append("1. Address all critical risk findings immediately")
            
            if data.risk_summary.insecure_servers > 0:
                summary_parts.append("2. Implement security controls for insecure MCP servers")
            
            if data.risk_summary.exploitable_vulnerabilities > 0:
                summary_parts.append("3. Patch or mitigate exploitable vulnerabilities")
            
            summary_parts.append("4. Review and implement security best practices")
            summary_parts.append("5. Establish ongoing security monitoring")
        
        return "\n".join(summary_parts)
    
    def generate_recommendations(self, data: ReportData) -> List[str]:
        """Generate prioritized recommendations based on findings."""
        recommendations = []
        
        # Critical risk recommendations
        if data.has_assessment_data and data.risk_summary:
            risk_summary = data.risk_summary
            
            if risk_summary.critical_risk_targets > 0:
                recommendations.append(
                    f"IMMEDIATE: Address {risk_summary.critical_risk_targets} critical risk target(s) "
                    f"to prevent potential security breaches"
                )
            
            if risk_summary.exploitable_vulnerabilities > 0:
                recommendations.append(
                    f"HIGH PRIORITY: Patch or mitigate {risk_summary.exploitable_vulnerabilities} "
                    f"exploitable vulnerabilities"
                )
            
            if risk_summary.unpatched_vulnerabilities > 0:
                recommendations.append(
                    f"MEDIUM PRIORITY: Apply security patches for {risk_summary.unpatched_vulnerabilities} "
                    f"unpatched vulnerabilities"
                )
        
        # MCP-specific recommendations
        if data.has_detection_data and data.detection_summary:
            detection_summary = data.detection_summary
            
            if detection_summary.insecure_servers > 0:
                recommendations.append(
                    f"Implement secure transport (HTTPS/WSS) for {detection_summary.insecure_servers} "
                    f"insecure MCP server(s)"
                )
            
            if detection_summary.unauthenticated_servers > 0:
                recommendations.append(
                    f"Configure authentication for {detection_summary.unauthenticated_servers} "
                    f"unauthenticated MCP server(s)"
                )
        
        # Network security recommendations
        if data.has_scan_data and data.scan_summary:
            scan_summary = data.scan_summary
            
            if scan_summary.open_ports > 0:
                recommendations.append(
                    f"Review and secure {scan_summary.open_ports} open ports, "
                    f"closing unnecessary services"
                )
        
        # General security recommendations
        recommendations.extend([
            "Implement network segmentation to isolate MCP servers",
            "Establish regular security monitoring and alerting",
            "Conduct periodic security assessments and penetration testing",
            "Develop incident response procedures for security events",
            "Provide security training for development and operations teams"
        ])
        
        return recommendations
    
    def generate_trend_analysis(self, historical_data: List[ReportData]) -> Dict[str, TimeSeriesData]:
        """Generate trend analysis from historical report data."""
        trends = {
            'risk_scores': TimeSeriesData(),
            'vulnerabilities': TimeSeriesData(),
            'mcp_servers': TimeSeriesData(),
            'open_ports': TimeSeriesData(),
        }
        
        for data in historical_data:
            timestamp = data.metadata.generated_at
            
            # Risk score trends
            if data.has_assessment_data and data.risk_summary:
                trends['risk_scores'].add_point(
                    timestamp, 
                    data.risk_summary.average_risk_score,
                    f"Avg Risk: {data.risk_summary.average_risk_score:.2f}"
                )
                
                trends['vulnerabilities'].add_point(
                    timestamp,
                    data.risk_summary.total_vulnerabilities,
                    f"Vulns: {data.risk_summary.total_vulnerabilities}"
                )
            
            # MCP detection trends
            if data.has_detection_data and data.detection_summary:
                trends['mcp_servers'].add_point(
                    timestamp,
                    data.detection_summary.mcp_servers_detected,
                    f"MCP: {data.detection_summary.mcp_servers_detected}"
                )
            
            # Network scan trends
            if data.has_scan_data and data.scan_summary:
                trends['open_ports'].add_point(
                    timestamp,
                    data.scan_summary.open_ports,
                    f"Open: {data.scan_summary.open_ports}"
                )
        
        return trends
    
    def generate_distribution_analysis(self, data: ReportData) -> Dict[str, DistributionData]:
        """Generate distribution analysis for categorical data."""
        distributions = {
            'risk_levels': DistributionData(),
            'vulnerability_categories': DistributionData(),
            'transport_types': DistributionData(),
            'port_states': DistributionData(),
        }
        
        # Risk level distribution
        if data.has_assessment_data:
            for result in data.assessment_results:
                distributions['risk_levels'].add_item(result.overall_risk_level.value)
                
                # Vulnerability category distribution
                for finding in result.findings:
                    distributions['vulnerability_categories'].add_item(finding.category.value)
        
        # Transport type distribution
        if data.has_detection_data:
            for result in data.detection_results:
                if result.is_mcp_detected and result.mcp_server:
                    distributions['transport_types'].add_item(result.mcp_server.transport_type.value)
        
        # Port state distribution
        if data.has_scan_data:
            for result in data.scan_results:
                distributions['port_states'].add_item(result.state.value)
        
        return distributions 