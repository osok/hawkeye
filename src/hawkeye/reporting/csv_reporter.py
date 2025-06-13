"""
CSV report generator for HawkEye security reconnaissance tool.

This module provides CSV format report generation with tabular data output,
proper formatting, and comprehensive data export for all scan results,
detection findings, and risk assessments.
"""

import csv
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from io import StringIO

from .base import BaseReporter, ReportData, ReportFormat, ReportingError
from ..assessment.base import RiskLevel, VulnerabilityCategory
from ..detection.base import TransportType, MCPServerType
from ..scanner.base import PortState, ScanType
from ..utils.logging import get_logger


class CSVReporter(BaseReporter):
    """CSV format report generator."""
    
    def __init__(self, settings=None, delimiter: str = ',', quoting: int = csv.QUOTE_MINIMAL):
        """
        Initialize CSV reporter.
        
        Args:
            settings: Configuration settings
            delimiter: CSV field delimiter
            quoting: CSV quoting style
        """
        super().__init__(settings)
        self.delimiter = delimiter
        self.quoting = quoting
        self.logger = get_logger(self.__class__.__name__)
    
    def get_format(self) -> ReportFormat:
        """Get the report format."""
        return ReportFormat.CSV
    
    def generate_report(self, data: ReportData, output_path: Optional[Path] = None) -> str:
        """
        Generate CSV report from data.
        
        Args:
            data: Report data to generate from
            output_path: Optional path to save the report
            
        Returns:
            str: Path to generated report file or CSV content
            
        Raises:
            ReportingError: If report generation fails
        """
        start_time = time.time()
        success = False
        
        try:
            # Validate input data
            self.validate_data(data)
            
            # Generate CSV content
            csv_content = self._generate_csv_content(data)
            
            # Save to file if path provided
            if output_path:
                output_file = self._create_output_path(output_path, data)
                self._save_csv_file(csv_content, output_file)
                result = str(output_file)
                self.logger.info(f"CSV report saved to: {output_file}")
            else:
                result = csv_content
                self.logger.info("CSV report generated in memory")
            
            success = True
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
            raise ReportingError(f"CSV report generation failed: {e}")
        
        finally:
            generation_time = time.time() - start_time
            self._update_statistics(success, generation_time)
    
    def _generate_csv_content(self, data: ReportData) -> str:
        """
        Generate CSV content from report data.
        
        Args:
            data: Report data to convert
            
        Returns:
            str: CSV formatted content
        """
        output = StringIO()
        
        # Write metadata section
        self._write_metadata_section(output, data.metadata)
        
        # Write summary section
        self._write_summary_section(output, data)
        
        # Write scan results if available
        if data.has_scan_data:
            self._write_scan_results_section(output, data.scan_results)
        
        # Write detection results if available
        if data.has_detection_data:
            self._write_detection_results_section(output, data.detection_results)
        
        # Write assessment results if available
        if data.has_assessment_data:
            self._write_assessment_results_section(output, data.assessment_results)
        
        # Write pipeline results if available
        if data.has_pipeline_data:
            self._write_pipeline_results_section(output, data.pipeline_results)
        
        # Write introspection data if available
        if data.has_introspection_data:
            self._write_introspection_summary_section(output, data.introspection_summary)
            self._write_mcp_servers_section(output, data.mcp_servers)
            self._write_introspection_data_section(output, data.introspection_data)
        
        # Write recommendations if available
        if data.recommendations:
            self._write_recommendations_section(output, data.recommendations)
        
        return output.getvalue()
    
    def _write_metadata_section(self, output: StringIO, metadata) -> None:
        """Write metadata section to CSV."""
        output.write("# REPORT METADATA\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        writer.writerow(["Field", "Value"])
        writer.writerow(["Title", metadata.title])
        writer.writerow(["Report Type", metadata.report_type.value])
        writer.writerow(["Format", metadata.format.value])
        writer.writerow(["Generated At", metadata.generated_timestamp])
        writer.writerow(["Generated By", metadata.generated_by])
        writer.writerow(["Version", metadata.version])
        
        if metadata.description:
            writer.writerow(["Description", metadata.description])
        if metadata.author:
            writer.writerow(["Author", metadata.author])
        if metadata.organization:
            writer.writerow(["Organization", metadata.organization])
        
        writer.writerow(["Classification", metadata.classification])
        
        output.write("\n")
    
    def _write_summary_section(self, output: StringIO, data: ReportData) -> None:
        """Write summary section to CSV."""
        output.write("# EXECUTIVE SUMMARY\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Targets", data.total_targets])
        writer.writerow(["Has Scan Data", data.has_scan_data])
        writer.writerow(["Has Detection Data", data.has_detection_data])
        writer.writerow(["Has Assessment Data", data.has_assessment_data])
        writer.writerow(["Has Pipeline Data", data.has_pipeline_data])
        writer.writerow(["Has Introspection Data", data.has_introspection_data])
        writer.writerow(["Critical Findings", len(data.critical_findings)])
        writer.writerow(["High Risk Targets", len(data.high_risk_targets)])
        
        # Add summary statistics if available
        if data.scan_summary:
            writer.writerow(["Total Ports Scanned", data.scan_summary.total_ports_scanned])
            writer.writerow(["Open Ports", data.scan_summary.open_ports])
            writer.writerow(["Services Detected", data.scan_summary.services_detected])
        
        if data.detection_summary:
            writer.writerow(["MCP Servers Detected", data.detection_summary.mcp_servers_detected])
            writer.writerow(["Detection Rate", f"{data.detection_summary.detection_rate:.2%}"])
            writer.writerow(["Security Rate", f"{data.detection_summary.security_rate:.2%}"])
        
        if data.risk_summary:
            writer.writerow(["Total Assessments", data.risk_summary.total_assessments])
            writer.writerow(["Critical Risk Targets", data.risk_summary.critical_risk_targets])
            writer.writerow(["High Risk Targets", data.risk_summary.high_risk_targets])
            writer.writerow(["Average Risk Score", f"{data.risk_summary.average_risk_score:.2f}"])
        
        # Add introspection summary statistics if available
        if data.introspection_summary:
            writer.writerow(["Total Servers Introspected", data.introspection_summary.total_servers_introspected])
            writer.writerow(["Successful Introspections", data.introspection_summary.successful_introspections])
            writer.writerow(["Failed Introspections", data.introspection_summary.failed_introspections])
            writer.writerow(["Success Rate", f"{data.introspection_summary.success_rate:.2%}"])
            writer.writerow(["Total Tools Discovered", data.introspection_summary.total_tools_discovered])
            writer.writerow(["Total Resources Discovered", data.introspection_summary.total_resources_discovered])
            writer.writerow(["Total Capabilities Discovered", data.introspection_summary.total_capabilities_discovered])
            writer.writerow(["Average Tools per Server", f"{data.introspection_summary.average_tools_per_server:.2f}"])
            writer.writerow(["Average Resources per Server", f"{data.introspection_summary.average_resources_per_server:.2f}"])
        
        output.write("\n")
    
    def _write_scan_results_section(self, output: StringIO, scan_results) -> None:
        """Write scan results section to CSV."""
        output.write("# SCAN RESULTS\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        
        # Write headers
        headers = [
            "Host", "Port", "State", "Scan Type", "Timestamp", "Response Time (ms)",
            "Service Name", "Service Version", "Service Product", "Service Banner",
            "Service Confidence", "Error"
        ]
        writer.writerow(headers)
        
        # Write data rows
        for result in scan_results:
            row = [
                result.target.host,
                result.port,
                result.state.value,
                result.scan_type.value,
                time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.timestamp)),
                f"{result.response_time * 1000:.2f}" if result.response_time else "",
                result.service_info.name if result.service_info else "",
                result.service_info.version if result.service_info else "",
                result.service_info.product if result.service_info else "",
                result.service_info.banner if result.service_info else "",
                f"{result.service_info.confidence:.2f}" if result.service_info else "",
                result.error or ""
            ]
            writer.writerow(row)
        
        output.write("\n")
    
    def _write_detection_results_section(self, output: StringIO, detection_results) -> None:
        """Write detection results section to CSV."""
        output.write("# MCP DETECTION RESULTS\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        
        # Write headers
        headers = [
            "Target Host", "Detection Method", "Timestamp", "Success", "MCP Detected",
            "Confidence", "Transport Type", "Server Type", "Port", "Is Secure",
            "Has Authentication", "Endpoint URL", "Capabilities", "Tools", "Resources",
            "Version", "Risk Level", "Error"
        ]
        writer.writerow(headers)
        
        # Write data rows
        for result in detection_results:
            server = result.mcp_server
            row = [
                result.target_host,
                result.detection_method.value,
                time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.timestamp)),
                result.success,
                result.is_mcp_detected,
                f"{result.confidence:.2f}",
                server.transport_type.value if server else "",
                server.server_type.value if server else "",
                server.port if server else "",
                server.is_secure if server else "",
                server.has_authentication if server else "",
                server.endpoint_url if server else "",
                "; ".join(server.capabilities) if server and server.capabilities else "",
                "; ".join(server.tools) if server and server.tools else "",
                "; ".join(server.resources) if server and server.resources else "",
                server.version if server else "",
                result.risk_level,
                result.error or ""
            ]
            writer.writerow(row)
        
        output.write("\n")
    
    def _write_assessment_results_section(self, output: StringIO, assessment_results) -> None:
        """Write assessment results section to CSV."""
        output.write("# RISK ASSESSMENT RESULTS\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        
        # Write summary headers
        summary_headers = [
            "Target Host", "Assessment Timestamp", "Overall Risk Level", "Overall Risk Score",
            "Total Findings", "Critical Findings", "High Findings", "Total Vulnerabilities",
            "Exploitable Vulnerabilities", "Unpatched Vulnerabilities", "Assessment Duration (s)"
        ]
        writer.writerow(summary_headers)
        
        # Write summary data
        for result in assessment_results:
            row = [
                result.target_host,
                time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.assessment_timestamp)),
                result.overall_risk_level.value,
                f"{result.overall_risk_score:.2f}",
                len(result.findings),
                len(result.critical_findings),
                len(result.high_findings),
                len(result.vulnerabilities),
                len(result.exploitable_vulnerabilities),
                len(result.unpatched_vulnerabilities),
                f"{result.assessment_duration:.2f}" if result.assessment_duration else ""
            ]
            writer.writerow(row)
        
        output.write("\n")
        
        # Write detailed findings
        output.write("# DETAILED FINDINGS\n")
        
        findings_headers = [
            "Target Host", "Finding ID", "Title", "Description", "Category", "Severity",
            "Confidence", "Risk Score", "Affected Asset", "Remediation", "Compliance Violations"
        ]
        writer.writerow(findings_headers)
        
        for result in assessment_results:
            for finding in result.findings:
                row = [
                    result.target_host,
                    finding.id,
                    finding.title,
                    finding.description,
                    finding.category.value,
                    finding.severity.value,
                    f"{finding.confidence:.2f}",
                    f"{finding.risk_score:.2f}",
                    finding.affected_asset,
                    finding.remediation or "",
                    "; ".join([cv.value for cv in finding.compliance_violations])
                ]
                writer.writerow(row)
        
        output.write("\n")
    
    def _write_recommendations_section(self, output: StringIO, recommendations: List[str]) -> None:
        """Write recommendations section to CSV."""
        output.write("# RECOMMENDATIONS\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        writer.writerow(["Priority", "Recommendation"])
        
        for i, recommendation in enumerate(recommendations, 1):
            writer.writerow([i, recommendation])
        
        output.write("\n")
    
    def _write_pipeline_results_section(self, output: StringIO, pipeline_results) -> None:
        """Write pipeline results section to CSV."""
        output.write("# PIPELINE EXECUTION RESULTS\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        
        # Write headers
        headers = [
            "Target Host", "Start Time", "End Time", "Duration (s)", "Success",
            "Total Detections", "Successful Detections", "Failed Detections",
            "MCP Servers Found", "Best Server Host", "Best Server Port",
            "Best Server Transport", "Highest Confidence", "Risk Assessment",
            "Introspection Count", "Errors", "Warnings"
        ]
        writer.writerow(headers)
        
        # Write data rows
        for result in pipeline_results:
            best_server = result.best_mcp_server
            row = [
                result.target_host,
                result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                result.end_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                f"{result.duration:.2f}",
                result.success,
                result.total_detections,
                result.successful_detections,
                result.failed_detections,
                result.mcp_servers_found,
                best_server.host if best_server else "",
                best_server.port if best_server else "",
                best_server.transport_type.value if best_server else "",
                f"{result.highest_confidence_result.confidence:.2f}" if result.highest_confidence_result else "",
                result.risk_assessment or "",
                len(result.introspection_results),
                "; ".join(result.errors) if result.errors else "",
                "; ".join(result.warnings) if result.warnings else ""
            ]
            writer.writerow(row)
        
        output.write("\n")
    
    def _write_introspection_summary_section(self, output: StringIO, introspection_summary) -> None:
        """Write introspection summary section to CSV."""
        if not introspection_summary:
            return
            
        output.write("# INTROSPECTION SUMMARY\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Servers Introspected", introspection_summary.total_servers_introspected])
        writer.writerow(["Successful Introspections", introspection_summary.successful_introspections])
        writer.writerow(["Failed Introspections", introspection_summary.failed_introspections])
        writer.writerow(["Success Rate", f"{introspection_summary.success_rate:.2%}"])
        writer.writerow(["Total Tools Discovered", introspection_summary.total_tools_discovered])
        writer.writerow(["Total Resources Discovered", introspection_summary.total_resources_discovered])
        writer.writerow(["Total Capabilities Discovered", introspection_summary.total_capabilities_discovered])
        writer.writerow(["Average Tools per Server", f"{introspection_summary.average_tools_per_server:.2f}"])
        writer.writerow(["Average Resources per Server", f"{introspection_summary.average_resources_per_server:.2f}"])
        
        # Risk distribution
        writer.writerow(["Critical Risk Servers", introspection_summary.critical_risk_servers])
        writer.writerow(["High Risk Servers", introspection_summary.high_risk_servers])
        writer.writerow(["Medium Risk Servers", introspection_summary.medium_risk_servers])
        writer.writerow(["Low Risk Servers", introspection_summary.low_risk_servers])
        writer.writerow(["Minimal Risk Servers", introspection_summary.minimal_risk_servers])
        writer.writerow(["High Risk Rate", f"{introspection_summary.high_risk_rate:.2%}"])
        
        # Tool categories
        writer.writerow(["File Access Tools", introspection_summary.file_access_tools])
        writer.writerow(["Network Tools", introspection_summary.network_tools])
        writer.writerow(["Code Execution Tools", introspection_summary.code_execution_tools])
        writer.writerow(["Data Access Tools", introspection_summary.data_access_tools])
        writer.writerow(["System Tools", introspection_summary.system_tools])
        
        # Transport distribution
        writer.writerow(["STDIO Servers", introspection_summary.stdio_servers])
        writer.writerow(["HTTP Servers", introspection_summary.http_servers])
        writer.writerow(["SSE Servers", introspection_summary.sse_servers])
        writer.writerow(["WebSocket Servers", introspection_summary.websocket_servers])
        
        if introspection_summary.introspection_duration:
            writer.writerow(["Total Introspection Duration (s)", f"{introspection_summary.introspection_duration:.2f}"])
        
        output.write("\n")
    
    def _write_mcp_servers_section(self, output: StringIO, mcp_servers) -> None:
        """Write MCP servers section to CSV."""
        if not mcp_servers:
            return
            
        output.write("# MCP SERVERS DISCOVERED\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        
        # Write headers
        headers = [
            "Host", "Port", "Transport Type", "Server Type", "Version",
            "Tool Count", "Resource Count", "Capability Count",
            "Overall Risk Level", "Risk Score", "Has Security Risks",
            "Discovery Timestamp", "Capabilities", "Tools", "Resources"
        ]
        writer.writerow(headers)
        
        # Write data rows
        for server in mcp_servers:
            # Extract tools and resources as strings
            tools_str = ""
            if hasattr(server, 'tools') and server.tools:
                tool_names = []
                for tool in server.tools:
                    if hasattr(tool, 'name'):
                        tool_names.append(tool.name)
                    elif isinstance(tool, dict):
                        tool_names.append(tool.get('name', 'unknown'))
                    else:
                        tool_names.append(str(tool))
                tools_str = "; ".join(tool_names)
            
            resources_str = ""
            if hasattr(server, 'resources') and server.resources:
                resource_names = []
                for resource in server.resources:
                    if hasattr(resource, 'uri'):
                        resource_names.append(resource.uri)
                    elif isinstance(resource, dict):
                        resource_names.append(resource.get('uri', 'unknown'))
                    else:
                        resource_names.append(str(resource))
                resources_str = "; ".join(resource_names)
            
            capabilities_str = ""
            if hasattr(server, 'capabilities') and server.capabilities:
                if isinstance(server.capabilities, list):
                    capabilities_str = "; ".join(str(cap) for cap in server.capabilities)
                else:
                    capabilities_str = str(server.capabilities)
            
            row = [
                getattr(server, 'host', ''),
                getattr(server, 'port', ''),
                getattr(server, 'transport_type', ''),
                getattr(server, 'server_type', ''),
                getattr(server, 'version', ''),
                server.get_tool_count() if hasattr(server, 'get_tool_count') else len(getattr(server, 'tools', [])),
                server.get_resource_count() if hasattr(server, 'get_resource_count') else len(getattr(server, 'resources', [])),
                server.get_capability_count() if hasattr(server, 'get_capability_count') else len(getattr(server, 'capabilities', [])),
                getattr(server, 'overall_risk_level', ''),
                getattr(server, 'risk_score', ''),
                len(getattr(server, 'security_risks', [])) > 0,
                getattr(server, 'discovery_timestamp', ''),
                capabilities_str,
                tools_str,
                resources_str
            ]
            writer.writerow(row)
        
        output.write("\n")
    
    def _write_introspection_data_section(self, output: StringIO, introspection_data: Dict[str, Any]) -> None:
        """Write introspection data section to CSV."""
        if not introspection_data:
            return
            
        output.write("# INTROSPECTION CAPABILITIES\n")
        
        writer = csv.writer(output, delimiter=self.delimiter, quoting=self.quoting)
        
        # Write headers
        headers = [
            "Server ID", "Protocol Version", "Server Version", "Supports Tools",
            "Supports Resources", "Supports Prompts", "Capability Count",
            "Has Dangerous Capabilities", "Capabilities"
        ]
        writer.writerow(headers)
        
        # Write data rows
        for server_id, capabilities in introspection_data.items():
            # Handle both dict and object capabilities
            if hasattr(capabilities, 'dict'):
                cap_dict = capabilities.dict()
            elif isinstance(capabilities, dict):
                cap_dict = capabilities
            else:
                cap_dict = capabilities.__dict__ if hasattr(capabilities, '__dict__') else {}
            
            row = [
                server_id,
                cap_dict.get('protocol_version', ''),
                cap_dict.get('server_version', ''),
                cap_dict.get('supports_tools', False),
                cap_dict.get('supports_resources', False),
                cap_dict.get('supports_prompts', False),
                capabilities.get_capability_count() if hasattr(capabilities, 'get_capability_count') else 0,
                capabilities.has_dangerous_capabilities() if hasattr(capabilities, 'has_dangerous_capabilities') else False,
                str(cap_dict.get('capabilities', ''))
            ]
            writer.writerow(row)
        
        output.write("\n")
    
    def _save_csv_file(self, content: str, output_path: Path) -> None:
        """
        Save CSV content to file.
        
        Args:
            content: CSV content to save
            output_path: Path to save file
            
        Raises:
            ReportingError: If file save fails
        """
        try:
            with open(output_path, 'w', encoding='utf-8', newline='') as f:
                f.write(content)
        except IOError as e:
            raise ReportingError(f"Failed to save CSV report to {output_path}: {e}")
    
    def generate_separate_files(self, data: ReportData, base_path: Path) -> List[str]:
        """
        Generate separate CSV files for each data type.
        
        Args:
            data: Report data to generate from
            base_path: Base path for output files
            
        Returns:
            List[str]: List of generated file paths
        """
        generated_files = []
        
        try:
            # Validate input data
            self.validate_data(data)
            
            base_path = Path(base_path)
            base_path.mkdir(parents=True, exist_ok=True)
            
            # Generate metadata file
            metadata_file = base_path / "metadata.csv"
            self._generate_metadata_file(data.metadata, metadata_file)
            generated_files.append(str(metadata_file))
            
            # Generate scan results file
            if data.has_scan_data:
                scan_file = base_path / "scan_results.csv"
                self._generate_scan_results_file(data.scan_results, scan_file)
                generated_files.append(str(scan_file))
            
            # Generate detection results file
            if data.has_detection_data:
                detection_file = base_path / "detection_results.csv"
                self._generate_detection_results_file(data.detection_results, detection_file)
                generated_files.append(str(detection_file))
            
            # Generate assessment results file
            if data.has_assessment_data:
                assessment_file = base_path / "assessment_results.csv"
                self._generate_assessment_results_file(data.assessment_results, assessment_file)
                generated_files.append(str(assessment_file))
            
            self.logger.info(f"Generated {len(generated_files)} CSV files in {base_path}")
            return generated_files
            
        except Exception as e:
            self.logger.error(f"Failed to generate separate CSV files: {e}")
            raise ReportingError(f"Separate CSV file generation failed: {e}")
    
    def _generate_metadata_file(self, metadata, output_path: Path) -> None:
        """Generate metadata CSV file."""
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, delimiter=self.delimiter, quoting=self.quoting)
            writer.writerow(["Field", "Value"])
            writer.writerow(["Title", metadata.title])
            writer.writerow(["Report Type", metadata.report_type.value])
            writer.writerow(["Generated At", metadata.generated_timestamp])
            writer.writerow(["Generated By", metadata.generated_by])
            writer.writerow(["Version", metadata.version])
    
    def _generate_scan_results_file(self, scan_results, output_path: Path) -> None:
        """Generate scan results CSV file."""
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, delimiter=self.delimiter, quoting=self.quoting)
            
            headers = ["Host", "Port", "State", "Scan Type", "Timestamp", "Response Time (ms)",
                      "Service Name", "Service Version", "Error"]
            writer.writerow(headers)
            
            for result in scan_results:
                row = [
                    result.target.host,
                    result.port,
                    result.state.value,
                    result.scan_type.value,
                    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.timestamp)),
                    f"{result.response_time * 1000:.2f}" if result.response_time else "",
                    result.service_info.name if result.service_info else "",
                    result.service_info.version if result.service_info else "",
                    result.error or ""
                ]
                writer.writerow(row)
    
    def _generate_detection_results_file(self, detection_results, output_path: Path) -> None:
        """Generate detection results CSV file."""
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, delimiter=self.delimiter, quoting=self.quoting)
            
            headers = ["Target Host", "Detection Method", "Success", "MCP Detected",
                      "Transport Type", "Port", "Is Secure", "Risk Level"]
            writer.writerow(headers)
            
            for result in detection_results:
                server = result.mcp_server
                row = [
                    result.target_host,
                    result.detection_method.value,
                    result.success,
                    result.is_mcp_detected,
                    server.transport_type.value if server else "",
                    server.port if server else "",
                    server.is_secure if server else "",
                    result.risk_level
                ]
                writer.writerow(row)
    
    def _generate_assessment_results_file(self, assessment_results, output_path: Path) -> None:
        """Generate assessment results CSV file."""
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, delimiter=self.delimiter, quoting=self.quoting)
            
            headers = ["Target Host", "Risk Level", "Risk Score", "Total Findings",
                      "Critical Findings", "High Findings", "Total Vulnerabilities"]
            writer.writerow(headers)
            
            for result in assessment_results:
                row = [
                    result.target_host,
                    result.overall_risk_level.value,
                    f"{result.overall_risk_score:.2f}",
                    len(result.findings),
                    len(result.critical_findings),
                    len(result.high_findings),
                    len(result.vulnerabilities)
                ]
                writer.writerow(row) 