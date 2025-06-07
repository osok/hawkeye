"""
XML report generator for HawkEye security reconnaissance tool.

This module provides XML format report generation with structured markup output,
proper formatting, and comprehensive data serialization for all scan results,
detection findings, and risk assessments.
"""

import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, Optional, List
from xml.dom import minidom

from .base import BaseReporter, ReportData, ReportFormat, ReportingError
from ..assessment.base import RiskLevel, VulnerabilityCategory
from ..detection.base import TransportType, MCPServerType
from ..scanner.base import PortState, ScanType
from ..utils.logging import get_logger


class XMLReporter(BaseReporter):
    """XML format report generator."""
    
    def __init__(self, settings=None, pretty_print: bool = True, encoding: str = 'utf-8'):
        """
        Initialize XML reporter.
        
        Args:
            settings: Configuration settings
            pretty_print: Whether to format XML with indentation
            encoding: XML encoding
        """
        super().__init__(settings)
        self.pretty_print = pretty_print
        self.encoding = encoding
        self.logger = get_logger(self.__class__.__name__)
    
    def get_format(self) -> ReportFormat:
        """Get the report format."""
        return ReportFormat.XML
    
    def generate_report(self, data: ReportData, output_path: Optional[Path] = None) -> str:
        """
        Generate XML report from data.
        
        Args:
            data: Report data to generate from
            output_path: Optional path to save the report
            
        Returns:
            str: Path to generated report file or XML content
            
        Raises:
            ReportingError: If report generation fails
        """
        start_time = time.time()
        success = False
        
        try:
            # Validate input data
            self.validate_data(data)
            
            # Generate XML content
            xml_content = self._generate_xml_content(data)
            
            # Save to file if path provided
            if output_path:
                output_file = self._create_output_path(output_path, data)
                self._save_xml_file(xml_content, output_file)
                result = str(output_file)
                self.logger.info(f"XML report saved to: {output_file}")
            else:
                result = xml_content
                self.logger.info("XML report generated in memory")
            
            success = True
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to generate XML report: {e}")
            raise ReportingError(f"XML report generation failed: {e}")
        
        finally:
            generation_time = time.time() - start_time
            self._update_statistics(success, generation_time)
    
    def _generate_xml_content(self, data: ReportData) -> str:
        """
        Generate XML content from report data.
        
        Args:
            data: Report data to convert
            
        Returns:
            str: XML formatted content
        """
        try:
            # Create root element
            root = ET.Element("hawkeye_report")
            root.set("version", "1.0")
            root.set("schema", "hawkeye-xml-v1")
            
            # Add metadata section
            self._add_metadata_section(root, data.metadata)
            
            # Add summary section
            self._add_summary_section(root, data)
            
            # Add scan results if available
            if data.has_scan_data:
                self._add_scan_results_section(root, data.scan_results)
            
            # Add detection results if available
            if data.has_detection_data:
                self._add_detection_results_section(root, data.detection_results)
            
            # Add assessment results if available
            if data.has_assessment_data:
                self._add_assessment_results_section(root, data.assessment_results)
            
            # Add recommendations if available
            if data.recommendations:
                self._add_recommendations_section(root, data.recommendations)
            
            # Convert to string
            if self.pretty_print:
                return self._prettify_xml(root)
            else:
                return ET.tostring(root, encoding='unicode')
            
        except Exception as e:
            raise ReportingError(f"XML generation failed: {e}")
    
    def _add_metadata_section(self, parent: ET.Element, metadata) -> None:
        """Add metadata section to XML."""
        metadata_elem = ET.SubElement(parent, "metadata")
        
        # Basic metadata
        ET.SubElement(metadata_elem, "title").text = metadata.title
        ET.SubElement(metadata_elem, "report_type").text = metadata.report_type.value
        ET.SubElement(metadata_elem, "format").text = metadata.format.value
        ET.SubElement(metadata_elem, "generated_at").text = str(metadata.generated_at)
        ET.SubElement(metadata_elem, "generated_timestamp").text = metadata.generated_timestamp
        ET.SubElement(metadata_elem, "generated_by").text = metadata.generated_by
        ET.SubElement(metadata_elem, "version").text = metadata.version
        ET.SubElement(metadata_elem, "classification").text = metadata.classification
        
        # Optional metadata
        if metadata.description:
            ET.SubElement(metadata_elem, "description").text = metadata.description
        if metadata.author:
            ET.SubElement(metadata_elem, "author").text = metadata.author
        if metadata.organization:
            ET.SubElement(metadata_elem, "organization").text = metadata.organization
        if metadata.retention_period:
            ET.SubElement(metadata_elem, "retention_period").text = metadata.retention_period
    
    def _add_summary_section(self, parent: ET.Element, data: ReportData) -> None:
        """Add summary section to XML."""
        summary_elem = ET.SubElement(parent, "executive_summary")
        
        # Basic statistics
        stats_elem = ET.SubElement(summary_elem, "statistics")
        ET.SubElement(stats_elem, "total_targets").text = str(data.total_targets)
        ET.SubElement(stats_elem, "has_scan_data").text = str(data.has_scan_data).lower()
        ET.SubElement(stats_elem, "has_detection_data").text = str(data.has_detection_data).lower()
        ET.SubElement(stats_elem, "has_assessment_data").text = str(data.has_assessment_data).lower()
        ET.SubElement(stats_elem, "critical_findings").text = str(len(data.critical_findings))
        ET.SubElement(stats_elem, "high_risk_targets").text = str(len(data.high_risk_targets))
        
        # Scan summary
        if data.scan_summary:
            scan_summary_elem = ET.SubElement(summary_elem, "scan_summary")
            ET.SubElement(scan_summary_elem, "total_ports_scanned").text = str(data.scan_summary.total_ports_scanned)
            ET.SubElement(scan_summary_elem, "open_ports").text = str(data.scan_summary.open_ports)
            ET.SubElement(scan_summary_elem, "services_detected").text = str(data.scan_summary.services_detected)
            ET.SubElement(scan_summary_elem, "success_rate").text = f"{data.scan_summary.success_rate:.4f}"
        
        # Detection summary
        if data.detection_summary:
            detection_summary_elem = ET.SubElement(summary_elem, "detection_summary")
            ET.SubElement(detection_summary_elem, "mcp_servers_detected").text = str(data.detection_summary.mcp_servers_detected)
            ET.SubElement(detection_summary_elem, "detection_rate").text = f"{data.detection_summary.detection_rate:.4f}"
            ET.SubElement(detection_summary_elem, "security_rate").text = f"{data.detection_summary.security_rate:.4f}"
        
        # Risk summary
        if data.risk_summary:
            risk_summary_elem = ET.SubElement(summary_elem, "risk_summary")
            ET.SubElement(risk_summary_elem, "total_assessments").text = str(data.risk_summary.total_assessments)
            ET.SubElement(risk_summary_elem, "critical_risk_targets").text = str(data.risk_summary.critical_risk_targets)
            ET.SubElement(risk_summary_elem, "high_risk_targets").text = str(data.risk_summary.high_risk_targets)
            ET.SubElement(risk_summary_elem, "average_risk_score").text = f"{data.risk_summary.average_risk_score:.4f}"
        
        # Executive summary text
        if data.executive_summary:
            ET.SubElement(summary_elem, "executive_text").text = data.executive_summary
    
    def _add_scan_results_section(self, parent: ET.Element, scan_results) -> None:
        """Add scan results section to XML."""
        scan_section = ET.SubElement(parent, "scan_results")
        scan_section.set("count", str(len(scan_results)))
        
        for result in scan_results:
            result_elem = ET.SubElement(scan_section, "scan_result")
            
            # Basic scan information
            ET.SubElement(result_elem, "host").text = result.target.host
            ET.SubElement(result_elem, "port").text = str(result.port)
            ET.SubElement(result_elem, "state").text = result.state.value
            ET.SubElement(result_elem, "scan_type").text = result.scan_type.value
            ET.SubElement(result_elem, "timestamp").text = str(result.timestamp)
            ET.SubElement(result_elem, "formatted_timestamp").text = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.timestamp)
            )
            
            if result.response_time:
                ET.SubElement(result_elem, "response_time_ms").text = f"{result.response_time * 1000:.2f}"
            
            # Service information
            if result.service_info:
                service_elem = ET.SubElement(result_elem, "service")
                if result.service_info.name:
                    ET.SubElement(service_elem, "name").text = result.service_info.name
                if result.service_info.version:
                    ET.SubElement(service_elem, "version").text = result.service_info.version
                if result.service_info.product:
                    ET.SubElement(service_elem, "product").text = result.service_info.product
                if result.service_info.banner:
                    ET.SubElement(service_elem, "banner").text = result.service_info.banner
                ET.SubElement(service_elem, "confidence").text = f"{result.service_info.confidence:.4f}"
            
            # Error information
            if result.error:
                ET.SubElement(result_elem, "error").text = result.error
    
    def _add_detection_results_section(self, parent: ET.Element, detection_results) -> None:
        """Add detection results section to XML."""
        detection_section = ET.SubElement(parent, "detection_results")
        detection_section.set("count", str(len(detection_results)))
        
        for result in detection_results:
            result_elem = ET.SubElement(detection_section, "detection_result")
            
            # Basic detection information
            ET.SubElement(result_elem, "target_host").text = result.target_host
            ET.SubElement(result_elem, "detection_method").text = result.detection_method.value
            ET.SubElement(result_elem, "timestamp").text = str(result.timestamp)
            ET.SubElement(result_elem, "formatted_timestamp").text = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.timestamp)
            )
            ET.SubElement(result_elem, "success").text = str(result.success).lower()
            ET.SubElement(result_elem, "mcp_detected").text = str(result.is_mcp_detected).lower()
            ET.SubElement(result_elem, "confidence").text = f"{result.confidence:.4f}"
            ET.SubElement(result_elem, "risk_level").text = result.risk_level
            
            # MCP server information
            if result.mcp_server:
                server_elem = ET.SubElement(result_elem, "mcp_server")
                ET.SubElement(server_elem, "transport_type").text = result.mcp_server.transport_type.value
                ET.SubElement(server_elem, "server_type").text = result.mcp_server.server_type.value
                
                if result.mcp_server.port:
                    ET.SubElement(server_elem, "port").text = str(result.mcp_server.port)
                
                ET.SubElement(server_elem, "is_secure").text = str(result.mcp_server.is_secure).lower()
                ET.SubElement(server_elem, "has_authentication").text = str(result.mcp_server.has_authentication).lower()
                
                if result.mcp_server.endpoint_url:
                    ET.SubElement(server_elem, "endpoint_url").text = result.mcp_server.endpoint_url
                
                if result.mcp_server.version:
                    ET.SubElement(server_elem, "version").text = result.mcp_server.version
                
                # Capabilities
                if result.mcp_server.capabilities:
                    capabilities_elem = ET.SubElement(server_elem, "capabilities")
                    for capability in result.mcp_server.capabilities:
                        ET.SubElement(capabilities_elem, "capability").text = capability
                
                # Tools
                if result.mcp_server.tools:
                    tools_elem = ET.SubElement(server_elem, "tools")
                    for tool in result.mcp_server.tools:
                        ET.SubElement(tools_elem, "tool").text = tool
                
                # Resources
                if result.mcp_server.resources:
                    resources_elem = ET.SubElement(server_elem, "resources")
                    for resource in result.mcp_server.resources:
                        ET.SubElement(resources_elem, "resource").text = resource
            
            # Error information
            if result.error:
                ET.SubElement(result_elem, "error").text = result.error
    
    def _add_assessment_results_section(self, parent: ET.Element, assessment_results) -> None:
        """Add assessment results section to XML."""
        assessment_section = ET.SubElement(parent, "assessment_results")
        assessment_section.set("count", str(len(assessment_results)))
        
        for result in assessment_results:
            result_elem = ET.SubElement(assessment_section, "assessment_result")
            
            # Basic assessment information
            ET.SubElement(result_elem, "target_host").text = result.target_host
            ET.SubElement(result_elem, "assessment_timestamp").text = str(result.assessment_timestamp)
            ET.SubElement(result_elem, "formatted_timestamp").text = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.assessment_timestamp)
            )
            ET.SubElement(result_elem, "overall_risk_level").text = result.overall_risk_level.value
            ET.SubElement(result_elem, "overall_risk_score").text = f"{result.overall_risk_score:.4f}"
            
            if result.assessment_duration:
                ET.SubElement(result_elem, "assessment_duration").text = f"{result.assessment_duration:.4f}"
            
            # Statistics
            stats_elem = ET.SubElement(result_elem, "statistics")
            ET.SubElement(stats_elem, "total_findings").text = str(len(result.findings))
            ET.SubElement(stats_elem, "critical_findings").text = str(len(result.critical_findings))
            ET.SubElement(stats_elem, "high_findings").text = str(len(result.high_findings))
            ET.SubElement(stats_elem, "total_vulnerabilities").text = str(len(result.vulnerabilities))
            ET.SubElement(stats_elem, "exploitable_vulnerabilities").text = str(len(result.exploitable_vulnerabilities))
            ET.SubElement(stats_elem, "unpatched_vulnerabilities").text = str(len(result.unpatched_vulnerabilities))
            
            # Findings
            if result.findings:
                findings_elem = ET.SubElement(result_elem, "findings")
                findings_elem.set("count", str(len(result.findings)))
                
                for finding in result.findings:
                    finding_elem = ET.SubElement(findings_elem, "finding")
                    ET.SubElement(finding_elem, "id").text = finding.id
                    ET.SubElement(finding_elem, "title").text = finding.title
                    ET.SubElement(finding_elem, "description").text = finding.description
                    ET.SubElement(finding_elem, "category").text = finding.category.value
                    ET.SubElement(finding_elem, "severity").text = finding.severity.value
                    ET.SubElement(finding_elem, "confidence").text = f"{finding.confidence:.4f}"
                    ET.SubElement(finding_elem, "risk_score").text = f"{finding.risk_score:.4f}"
                    ET.SubElement(finding_elem, "affected_asset").text = finding.affected_asset
                    
                    if finding.remediation:
                        ET.SubElement(finding_elem, "remediation").text = finding.remediation
                    
                    if finding.compliance_violations:
                        violations_elem = ET.SubElement(finding_elem, "compliance_violations")
                        for violation in finding.compliance_violations:
                            ET.SubElement(violations_elem, "violation").text = violation.value
            
            # Vulnerabilities
            if result.vulnerabilities:
                vulns_elem = ET.SubElement(result_elem, "vulnerabilities")
                vulns_elem.set("count", str(len(result.vulnerabilities)))
                
                for vuln in result.vulnerabilities:
                    vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                    ET.SubElement(vuln_elem, "id").text = vuln.id
                    ET.SubElement(vuln_elem, "title").text = vuln.title
                    ET.SubElement(vuln_elem, "description").text = vuln.description
                    ET.SubElement(vuln_elem, "category").text = vuln.category.value
                    ET.SubElement(vuln_elem, "severity").text = vuln.severity.value
                    ET.SubElement(vuln_elem, "is_exploitable").text = str(vuln.is_exploitable).lower()
                    ET.SubElement(vuln_elem, "has_mitigation").text = str(vuln.has_mitigation).lower()
                    
                    if vuln.cvss_score:
                        ET.SubElement(vuln_elem, "cvss_score").text = str(vuln.cvss_score)
                    
                    if vuln.cvss_vector:
                        ET.SubElement(vuln_elem, "cvss_vector").text = vuln.cvss_vector.to_vector_string()
                    
                    if vuln.cwe_id:
                        ET.SubElement(vuln_elem, "cwe_id").text = vuln.cwe_id
            
            # Recommendations
            if result.recommendations:
                recommendations_elem = ET.SubElement(result_elem, "recommendations")
                for recommendation in result.recommendations:
                    ET.SubElement(recommendations_elem, "recommendation").text = recommendation
    
    def _add_recommendations_section(self, parent: ET.Element, recommendations: List[str]) -> None:
        """Add recommendations section to XML."""
        recommendations_elem = ET.SubElement(parent, "recommendations")
        recommendations_elem.set("count", str(len(recommendations)))
        
        for i, recommendation in enumerate(recommendations, 1):
            rec_elem = ET.SubElement(recommendations_elem, "recommendation")
            rec_elem.set("priority", str(i))
            rec_elem.text = recommendation
    
    def _prettify_xml(self, element: ET.Element) -> str:
        """
        Return a pretty-printed XML string for the Element.
        
        Args:
            element: XML element to prettify
            
        Returns:
            str: Pretty-printed XML string
        """
        rough_string = ET.tostring(element, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding=None)
    
    def _save_xml_file(self, content: str, output_path: Path) -> None:
        """
        Save XML content to file.
        
        Args:
            content: XML content to save
            output_path: Path to save file
            
        Raises:
            ReportingError: If file save fails
        """
        try:
            with open(output_path, 'w', encoding=self.encoding) as f:
                f.write(content)
        except IOError as e:
            raise ReportingError(f"Failed to save XML report to {output_path}: {e}")
    
    def validate_xml_output(self, xml_content: str) -> bool:
        """
        Validate generated XML content.
        
        Args:
            xml_content: XML content to validate
            
        Returns:
            bool: True if valid XML
        """
        try:
            ET.fromstring(xml_content)
            return True
        except ET.ParseError:
            return False 