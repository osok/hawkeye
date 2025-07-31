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
            
            # Add pipeline results if available
            if data.has_pipeline_data:
                self._add_pipeline_results_section(root, data.pipeline_results)
            
            # Add introspection data if available
            if data.has_introspection_data:
                self._add_introspection_section(root, data)
            
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
        ET.SubElement(stats_elem, "has_pipeline_data").text = str(data.has_pipeline_data).lower()
        ET.SubElement(stats_elem, "has_introspection_data").text = str(data.has_introspection_data).lower()
        ET.SubElement(stats_elem, "critical_findings").text = str(len(data.critical_findings))
        ET.SubElement(stats_elem, "high_risk_targets").text = str(len(data.high_risk_targets))
        ET.SubElement(stats_elem, "total_tools_discovered").text = str(data.total_tools_discovered)
        ET.SubElement(stats_elem, "total_resources_discovered").text = str(data.total_resources_discovered)
        ET.SubElement(stats_elem, "introspected_servers_count").text = str(len(data.introspected_servers))
        
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
        
        # Introspection summary
        if data.introspection_summary:
            introspection_summary_elem = ET.SubElement(summary_elem, "introspection_summary")
            ET.SubElement(introspection_summary_elem, "total_servers_introspected").text = str(data.introspection_summary.total_servers_introspected)
            ET.SubElement(introspection_summary_elem, "successful_introspections").text = str(data.introspection_summary.successful_introspections)
            ET.SubElement(introspection_summary_elem, "failed_introspections").text = str(data.introspection_summary.failed_introspections)
            ET.SubElement(introspection_summary_elem, "success_rate").text = f"{data.introspection_summary.success_rate:.4f}"
            ET.SubElement(introspection_summary_elem, "total_tools_discovered").text = str(data.introspection_summary.total_tools_discovered)
            ET.SubElement(introspection_summary_elem, "total_resources_discovered").text = str(data.introspection_summary.total_resources_discovered)
            ET.SubElement(introspection_summary_elem, "average_tools_per_server").text = f"{data.introspection_summary.average_tools_per_server:.2f}"
            ET.SubElement(introspection_summary_elem, "average_resources_per_server").text = f"{data.introspection_summary.average_resources_per_server:.2f}"
            ET.SubElement(introspection_summary_elem, "high_risk_rate").text = f"{data.introspection_summary.high_risk_rate:.4f}"
        
        # Executive summary text
        if data.executive_summary:
            ET.SubElement(summary_elem, "executive_text").text = data.executive_summary
    
    def _add_scan_results_section(self, parent: ET.Element, scan_results) -> None:
        """Add scan results section to XML."""
        scan_section = ET.SubElement(parent, "scan_results")
        scan_section.set("count", str(len(scan_results)))
        
        for result in scan_results:
            scan_elem = ET.SubElement(scan_section, "scan_result")
            
            # Target information
            target_elem = ET.SubElement(scan_elem, "target")
            ET.SubElement(target_elem, "host").text = result.target.host
            ET.SubElement(target_elem, "port").text = str(result.target.port)
            
            # Scan details
            ET.SubElement(scan_elem, "scan_type").text = result.scan_type.value
            ET.SubElement(scan_elem, "state").text = result.state.value
            ET.SubElement(scan_elem, "timestamp").text = str(result.timestamp)
            ET.SubElement(scan_elem, "duration").text = str(result.duration)
            
            # Service information
            if result.service_info:
                service_elem = ET.SubElement(scan_elem, "service_info")
                ET.SubElement(service_elem, "name").text = result.service_info.name
                ET.SubElement(service_elem, "version").text = result.service_info.version or ""
                ET.SubElement(service_elem, "banner").text = result.service_info.banner or ""
                
                if result.service_info.fingerprints:
                    fingerprints_elem = ET.SubElement(service_elem, "fingerprints")
                    for fp in result.service_info.fingerprints:
                        fp_elem = ET.SubElement(fingerprints_elem, "fingerprint")
                        ET.SubElement(fp_elem, "pattern").text = fp.pattern
                        ET.SubElement(fp_elem, "confidence").text = str(fp.confidence)
    
    def _add_detection_results_section(self, parent: ET.Element, detection_results) -> None:
        """Add detection results section to XML."""
        detection_section = ET.SubElement(parent, "detection_results")
        detection_section.set("count", str(len(detection_results)))
        
        for result in detection_results:
            detection_elem = ET.SubElement(detection_section, "detection_result")
            
            # Basic detection info
            ET.SubElement(detection_elem, "target_host").text = result.target_host
            ET.SubElement(detection_elem, "detection_method").text = result.detection_method.value
            ET.SubElement(detection_elem, "success").text = str(result.success).lower()
            ET.SubElement(detection_elem, "confidence").text = str(result.confidence)
            ET.SubElement(detection_elem, "timestamp").text = str(result.timestamp)
            ET.SubElement(detection_elem, "is_mcp_detected").text = str(result.is_mcp_detected).lower()
            
            # MCP server information
            if result.mcp_server:
                server_elem = ET.SubElement(detection_elem, "mcp_server")
                ET.SubElement(server_elem, "name").text = result.mcp_server.name
                ET.SubElement(server_elem, "host").text = result.mcp_server.host
                if result.mcp_server.port:
                    ET.SubElement(server_elem, "port").text = str(result.mcp_server.port)
                if result.mcp_server.transport_type:
                    ET.SubElement(server_elem, "transport_type").text = result.mcp_server.transport_type.value
                if result.mcp_server.server_type:
                    ET.SubElement(server_elem, "server_type").text = result.mcp_server.server_type.value
            
            # Process information
            if result.process_info:
                process_elem = ET.SubElement(detection_elem, "process_info")
                ET.SubElement(process_elem, "pid").text = str(result.process_info.pid)
                ET.SubElement(process_elem, "name").text = result.process_info.name
                ET.SubElement(process_elem, "cwd").text = result.process_info.cwd or ""
                
                if result.process_info.cmdline:
                    cmdline_elem = ET.SubElement(process_elem, "cmdline")
                    for arg in result.process_info.cmdline:
                        ET.SubElement(cmdline_elem, "arg").text = arg
            
            # Additional data
            if result.additional_data:
                data_elem = ET.SubElement(detection_elem, "additional_data")
                for key, value in result.additional_data.items():
                    item_elem = ET.SubElement(data_elem, "item")
                    item_elem.set("key", key)
                    item_elem.text = str(value)
    
    def _add_assessment_results_section(self, parent: ET.Element, assessment_results) -> None:
        """Add assessment results section to XML."""
        assessment_section = ET.SubElement(parent, "assessment_results")
        assessment_section.set("count", str(len(assessment_results)))
        
        for result in assessment_results:
            assessment_elem = ET.SubElement(assessment_section, "assessment_result")
            
            # Basic assessment info
            ET.SubElement(assessment_elem, "target_host").text = result.target_host
            ET.SubElement(assessment_elem, "overall_risk_level").text = result.overall_risk_level.value
            ET.SubElement(assessment_elem, "risk_score").text = str(result.risk_score)
            ET.SubElement(assessment_elem, "timestamp").text = str(result.timestamp)
            
            # Findings
            if result.findings:
                findings_elem = ET.SubElement(assessment_elem, "findings")
                findings_elem.set("count", str(len(result.findings)))
                
                for finding in result.findings:
                    finding_elem = ET.SubElement(findings_elem, "finding")
                    ET.SubElement(finding_elem, "title").text = finding.title
                    ET.SubElement(finding_elem, "description").text = finding.description
                    ET.SubElement(finding_elem, "severity").text = finding.severity.value
                    ET.SubElement(finding_elem, "category").text = finding.category.value
                    
                    if finding.remediation:
                        ET.SubElement(finding_elem, "remediation").text = finding.remediation
            
            # Vulnerabilities
            if result.vulnerabilities:
                vulns_elem = ET.SubElement(assessment_elem, "vulnerabilities")
                vulns_elem.set("count", str(len(result.vulnerabilities)))
                
                for vuln in result.vulnerabilities:
                    vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                    ET.SubElement(vuln_elem, "id").text = vuln.id
                    ET.SubElement(vuln_elem, "title").text = vuln.title
                    ET.SubElement(vuln_elem, "description").text = vuln.description
                    ET.SubElement(vuln_elem, "severity").text = vuln.severity.value
                    ET.SubElement(vuln_elem, "cvss_score").text = str(vuln.cvss_score)
                    
                    if vuln.cve_id:
                        ET.SubElement(vuln_elem, "cve_id").text = vuln.cve_id
                    if vuln.remediation:
                        ET.SubElement(vuln_elem, "remediation").text = vuln.remediation
    
    def _add_pipeline_results_section(self, parent: ET.Element, pipeline_results) -> None:
        """Add pipeline results section to XML."""
        pipeline_section = ET.SubElement(parent, "pipeline_results")
        pipeline_section.set("count", str(len(pipeline_results)))
        
        for result in pipeline_results:
            pipeline_elem = ET.SubElement(pipeline_section, "pipeline_result")
            
            # Basic pipeline info
            ET.SubElement(pipeline_elem, "target_host").text = result.target_host
            ET.SubElement(pipeline_elem, "start_time").text = result.start_time.isoformat()
            ET.SubElement(pipeline_elem, "end_time").text = result.end_time.isoformat()
            ET.SubElement(pipeline_elem, "duration").text = str(result.duration)
            ET.SubElement(pipeline_elem, "success").text = str(result.success).lower()
            
            # Detection statistics
            stats_elem = ET.SubElement(pipeline_elem, "statistics")
            ET.SubElement(stats_elem, "total_detections").text = str(result.total_detections)
            ET.SubElement(stats_elem, "successful_detections").text = str(result.successful_detections)
            ET.SubElement(stats_elem, "failed_detections").text = str(result.failed_detections)
            ET.SubElement(stats_elem, "mcp_servers_found").text = str(result.mcp_servers_found)
            ET.SubElement(stats_elem, "introspection_results_count").text = str(len(result.introspection_results))
            
            # Best MCP server
            if result.best_mcp_server:
                best_server_elem = ET.SubElement(pipeline_elem, "best_mcp_server")
                self._add_mcp_server_details(best_server_elem, result.best_mcp_server)
            
            # Risk assessment
            if result.risk_assessment:
                risk_elem = ET.SubElement(pipeline_elem, "risk_assessment")
                for key, value in result.risk_assessment.items():
                    if isinstance(value, list):
                        list_elem = ET.SubElement(risk_elem, key)
                        for item in value:
                            ET.SubElement(list_elem, "item").text = str(item)
                    else:
                        ET.SubElement(risk_elem, key).text = str(value)
            
            # Errors and warnings
            if result.errors:
                errors_elem = ET.SubElement(pipeline_elem, "errors")
                for error in result.errors:
                    ET.SubElement(errors_elem, "error").text = error
            
            if result.warnings:
                warnings_elem = ET.SubElement(pipeline_elem, "warnings")
                for warning in result.warnings:
                    ET.SubElement(warnings_elem, "warning").text = warning
    
    def _add_introspection_section(self, parent: ET.Element, data: ReportData) -> None:
        """Add introspection data section to XML."""
        introspection_section = ET.SubElement(parent, "introspection_data")
        
        # MCP servers
        if data.mcp_servers:
            servers_elem = ET.SubElement(introspection_section, "mcp_servers")
            servers_elem.set("count", str(len(data.mcp_servers)))
            
            for server in data.mcp_servers:
                server_elem = ET.SubElement(servers_elem, "mcp_server")
                self._add_mcp_server_details(server_elem, server)
        
        # Introspection capabilities
        if data.introspection_data:
            capabilities_elem = ET.SubElement(introspection_section, "capabilities")
            capabilities_elem.set("count", str(len(data.introspection_data)))
            
            for server_id, capabilities in data.introspection_data.items():
                cap_elem = ET.SubElement(capabilities_elem, "server_capabilities")
                cap_elem.set("server_id", server_id)
                
                # Handle both dict and object capabilities
                if hasattr(capabilities, 'dict'):
                    cap_dict = capabilities.dict()
                elif isinstance(capabilities, dict):
                    cap_dict = capabilities
                else:
                    cap_dict = capabilities.__dict__ if hasattr(capabilities, '__dict__') else {}
                
                ET.SubElement(cap_elem, "protocol_version").text = cap_dict.get('protocol_version', '')
                ET.SubElement(cap_elem, "server_version").text = cap_dict.get('server_version', '')
                ET.SubElement(cap_elem, "supports_tools").text = str(cap_dict.get('supports_tools', False)).lower()
                ET.SubElement(cap_elem, "supports_resources").text = str(cap_dict.get('supports_resources', False)).lower()
                ET.SubElement(cap_elem, "supports_prompts").text = str(cap_dict.get('supports_prompts', False)).lower()
                
                # Capability count
                capability_count = 0
                if hasattr(capabilities, 'get_capability_count'):
                    capability_count = capabilities.get_capability_count()
                ET.SubElement(cap_elem, "capability_count").text = str(capability_count)
                
                # Dangerous capabilities
                has_dangerous = False
                if hasattr(capabilities, 'has_dangerous_capabilities'):
                    has_dangerous = capabilities.has_dangerous_capabilities()
                ET.SubElement(cap_elem, "has_dangerous_capabilities").text = str(has_dangerous).lower()
    
    def _add_mcp_server_details(self, parent: ET.Element, server) -> None:
        """Add detailed MCP server information to XML element."""
        ET.SubElement(parent, "name").text = getattr(server, 'name', '')
        ET.SubElement(parent, "host").text = getattr(server, 'host', '')
        
        port = getattr(server, 'port', None)
        if port:
            ET.SubElement(parent, "port").text = str(port)
        
        transport_type = getattr(server, 'transport_type', None)
        if transport_type:
            ET.SubElement(parent, "transport_type").text = str(transport_type)
        
        server_type = getattr(server, 'server_type', None)
        if server_type:
            ET.SubElement(parent, "server_type").text = str(server_type)
        
        version = getattr(server, 'version', None)
        if version:
            ET.SubElement(parent, "version").text = version
        
        # Tool and resource counts
        tool_count = 0
        if hasattr(server, 'get_tool_count'):
            tool_count = server.get_tool_count()
        elif hasattr(server, 'tools'):
            tool_count = len(getattr(server, 'tools', []))
        ET.SubElement(parent, "tool_count").text = str(tool_count)
        
        resource_count = 0
        if hasattr(server, 'get_resource_count'):
            resource_count = server.get_resource_count()
        elif hasattr(server, 'resources'):
            resource_count = len(getattr(server, 'resources', []))
        ET.SubElement(parent, "resource_count").text = str(resource_count)
        
        capability_count = 0
        if hasattr(server, 'get_capability_count'):
            capability_count = server.get_capability_count()
        elif hasattr(server, 'capabilities'):
            capability_count = len(getattr(server, 'capabilities', []))
        ET.SubElement(parent, "capability_count").text = str(capability_count)
        
        # Risk information
        risk_level = getattr(server, 'overall_risk_level', None)
        if risk_level:
            ET.SubElement(parent, "overall_risk_level").text = str(risk_level)
        
        risk_score = getattr(server, 'risk_score', None)
        if risk_score is not None:
            ET.SubElement(parent, "risk_score").text = str(risk_score)
        
        security_risks = getattr(server, 'security_risks', [])
        ET.SubElement(parent, "has_security_risks").text = str(len(security_risks) > 0).lower()
        
        discovery_timestamp = getattr(server, 'discovery_timestamp', None)
        if discovery_timestamp:
            ET.SubElement(parent, "discovery_timestamp").text = str(discovery_timestamp)
        
        # Tools
        tools = getattr(server, 'tools', [])
        if tools:
            tools_elem = ET.SubElement(parent, "tools")
            tools_elem.set("count", str(len(tools)))
            
            for tool in tools:
                tool_elem = ET.SubElement(tools_elem, "tool")
                
                if hasattr(tool, 'name'):
                    ET.SubElement(tool_elem, "name").text = tool.name
                elif isinstance(tool, dict):
                    ET.SubElement(tool_elem, "name").text = tool.get('name', 'unknown')
                
                if hasattr(tool, 'description'):
                    ET.SubElement(tool_elem, "description").text = tool.description
                elif isinstance(tool, dict):
                    ET.SubElement(tool_elem, "description").text = tool.get('description', '')
                
                # Parameters
                parameters = None
                if hasattr(tool, 'parameters'):
                    parameters = tool.parameters
                elif isinstance(tool, dict):
                    parameters = tool.get('parameters', {})
                
                if parameters:
                    params_elem = ET.SubElement(tool_elem, "parameters")
                    params_elem.set("count", str(len(parameters)))
                    for param_name, param_info in parameters.items():
                        param_elem = ET.SubElement(params_elem, "parameter")
                        param_elem.set("name", param_name)
                        if isinstance(param_info, dict):
                            for key, value in param_info.items():
                                ET.SubElement(param_elem, key).text = str(value)
        
        # Resources
        resources = getattr(server, 'resources', [])
        if resources:
            resources_elem = ET.SubElement(parent, "resources")
            resources_elem.set("count", str(len(resources)))
            
            for resource in resources:
                resource_elem = ET.SubElement(resources_elem, "resource")
                
                if hasattr(resource, 'uri'):
                    ET.SubElement(resource_elem, "uri").text = resource.uri
                elif isinstance(resource, dict):
                    ET.SubElement(resource_elem, "uri").text = resource.get('uri', 'unknown')
                
                if hasattr(resource, 'name'):
                    ET.SubElement(resource_elem, "name").text = resource.name
                elif isinstance(resource, dict):
                    ET.SubElement(resource_elem, "name").text = resource.get('name', '')
                
                if hasattr(resource, 'description'):
                    ET.SubElement(resource_elem, "description").text = resource.description
                elif isinstance(resource, dict):
                    ET.SubElement(resource_elem, "description").text = resource.get('description', '')
                
                if hasattr(resource, 'mime_type'):
                    ET.SubElement(resource_elem, "mime_type").text = resource.mime_type or ''
                elif isinstance(resource, dict):
                    ET.SubElement(resource_elem, "mime_type").text = resource.get('mime_type', '')
    
    def _add_recommendations_section(self, parent: ET.Element, recommendations: List[str]) -> None:
        """Add recommendations section to XML."""
        recommendations_elem = ET.SubElement(parent, "recommendations")
        recommendations_elem.set("count", str(len(recommendations)))
        
        for i, recommendation in enumerate(recommendations):
            rec_elem = ET.SubElement(recommendations_elem, "recommendation")
            rec_elem.set("id", str(i + 1))
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
        return reparsed.toprettyxml(indent="  ")
    
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
        Validate XML output for well-formedness.
        
        Args:
            xml_content: XML content to validate
            
        Returns:
            bool: True if XML is well-formed
        """
        try:
            ET.fromstring(xml_content)
            return True
        except ET.ParseError:
            return False 