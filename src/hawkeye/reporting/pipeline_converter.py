"""
Pipeline Result to Report Data Converter.

This module provides utilities to convert pipeline execution results
into report data format for comprehensive reporting.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from .base import ReportData, ReportMetadata, ReportType, ReportFormat, IntrospectionSummary
from ..detection.pipeline import PipelineResult
from ..detection.mcp_introspection.models import MCPServerInfo, MCPCapabilities, RiskLevel
from ..utils.logging import get_logger


class PipelineToReportConverter:
    """Converts pipeline results to report data format."""
    
    def __init__(self):
        """Initialize the converter."""
        self.logger = get_logger(__name__)
    
    def convert_pipeline_results(
        self, 
        pipeline_results: List[PipelineResult],
        report_title: str = "MCP Detection and Introspection Report",
        report_type: ReportType = ReportType.COMBINED_REPORT,
        report_format: ReportFormat = ReportFormat.JSON
    ) -> ReportData:
        """
        Convert pipeline results to report data format.
        
        Args:
            pipeline_results: List of pipeline execution results
            report_title: Title for the report
            report_type: Type of report to generate
            report_format: Format of the report
            
        Returns:
            ReportData: Converted report data
        """
        # Create report metadata
        metadata = ReportMetadata(
            title=report_title,
            report_type=report_type,
            format=report_format,
            description=f"Comprehensive MCP detection and introspection report for {len(pipeline_results)} targets"
        )
        
        # Extract data from pipeline results
        detection_results = []
        mcp_servers = []
        introspection_data = {}
        
        # Extract introspected servers and their data
        for pipeline_result in pipeline_results:
            # Extract detection results
            for method, results in pipeline_result.detection_results.items():
                detection_results.extend(results)
            
            # Extract MCP server info with enhanced introspection data
            if pipeline_result.best_mcp_server:
                mcp_servers.append(pipeline_result.best_mcp_server)
            
            # Extract all introspected servers from pipeline results
            for server_id, capabilities in pipeline_result.introspection_results.items():
                introspection_data[f"{pipeline_result.target_host}_{server_id}"] = capabilities
                
                # If we have a best server with introspection data, ensure it's in our list
                if (pipeline_result.best_mcp_server and 
                    pipeline_result.best_mcp_server.server_id == server_id):
                    # Server already added above
                    pass
                else:
                    # Create server info from introspection data if not already present
                    if capabilities and hasattr(capabilities, 'tools'):
                        # This would need to be enhanced based on actual capabilities structure
                        pass
        
        # Generate introspection summary
        introspection_summary = self._generate_introspection_summary(pipeline_results, mcp_servers)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(pipeline_results, mcp_servers)
        
        # Create report data
        report_data = ReportData(
            metadata=metadata,
            pipeline_results=pipeline_results,
            detection_results=detection_results,
            mcp_servers=mcp_servers,
            introspection_data=introspection_data,
            introspection_summary=introspection_summary,
            recommendations=recommendations,
            raw_data={
                'conversion_timestamp': datetime.now().isoformat(),
                'total_targets': len(set(r.target_host for r in pipeline_results)),
                'total_pipeline_duration': sum(r.duration for r in pipeline_results),
            }
        )
        
        self.logger.info(
            f"Converted {len(pipeline_results)} pipeline results to report data: "
            f"{len(detection_results)} detections, {len(mcp_servers)} servers, "
            f"{len(introspection_data)} introspections"
        )
        
        return report_data
    
    def _generate_introspection_summary(
        self, 
        pipeline_results: List[PipelineResult], 
        mcp_servers: List[MCPServerInfo]
    ) -> IntrospectionSummary:
        """Generate introspection summary from pipeline results."""
        
        # Count introspection results
        total_introspected = sum(len(r.introspection_results) for r in pipeline_results)
        successful_introspections = sum(
            1 for r in pipeline_results 
            for capabilities in r.introspection_results.values()
            if capabilities is not None
        )
        failed_introspections = total_introspected - successful_introspections
        
        # Count tools and resources
        total_tools = sum(server.get_tool_count() for server in mcp_servers if hasattr(server, 'get_tool_count'))
        total_resources = sum(server.get_resource_count() for server in mcp_servers if hasattr(server, 'get_resource_count'))
        total_capabilities = sum(server.get_capability_count() for server in mcp_servers if hasattr(server, 'get_capability_count'))
        
        # Count risk levels
        risk_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'minimal': 0
        }
        
        for server in mcp_servers:
            risk_level = getattr(server, 'overall_risk_level', 'low')
            # Check if it's actually an enum before accessing .value
            from enum import Enum
            if isinstance(risk_level, Enum):
                risk_level = risk_level.value
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        # Categorize tools
        tool_categories = {
            'file_access': 0,
            'network': 0,
            'code_execution': 0,
            'data_access': 0,
            'system': 0
        }
        
        for server in mcp_servers:
            for tool in getattr(server, 'tools', []):
                tool_dict = tool.dict() if hasattr(tool, 'dict') else tool.__dict__
                name = tool_dict.get('name', '').lower()
                description = tool_dict.get('description', '').lower()
                
                if any(keyword in name or keyword in description for keyword in ['file', 'read', 'write']):
                    tool_categories['file_access'] += 1
                elif any(keyword in name or keyword in description for keyword in ['http', 'web', 'api']):
                    tool_categories['network'] += 1
                elif any(keyword in name or keyword in description for keyword in ['execute', 'run', 'command']):
                    tool_categories['code_execution'] += 1
                elif any(keyword in name or keyword in description for keyword in ['database', 'sql', 'data']):
                    tool_categories['data_access'] += 1
                elif any(keyword in name or keyword in description for keyword in ['system', 'process', 'service']):
                    tool_categories['system'] += 1
        
        # Calculate total duration
        total_duration = sum(r.duration for r in pipeline_results)
        
        return IntrospectionSummary(
            total_servers_introspected=total_introspected,
            successful_introspections=successful_introspections,
            failed_introspections=failed_introspections,
            total_tools_discovered=total_tools,
            total_resources_discovered=total_resources,
            total_capabilities_discovered=total_capabilities,
            critical_risk_servers=risk_counts['critical'],
            high_risk_servers=risk_counts['high'],
            medium_risk_servers=risk_counts['medium'],
            low_risk_servers=risk_counts['low'],
            minimal_risk_servers=risk_counts['minimal'],
            file_access_tools=tool_categories['file_access'],
            network_tools=tool_categories['network'],
            code_execution_tools=tool_categories['code_execution'],
            data_access_tools=tool_categories['data_access'],
            system_tools=tool_categories['system'],
            introspection_duration=total_duration
        )
    
    def _generate_recommendations(
        self, 
        pipeline_results: List[PipelineResult], 
        mcp_servers: List[MCPServerInfo]
    ) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Check for high-risk servers
        high_risk_servers = [
            server for server in mcp_servers
            if getattr(server, 'overall_risk_level', 'low') in ['high', 'critical']
        ]
        
        if high_risk_servers:
            recommendations.append(
                f"Found {len(high_risk_servers)} high-risk MCP servers. "
                "Review their configurations and restrict access where possible."
            )
        
        # Check for code execution capabilities
        code_execution_tools = []
        for server in mcp_servers:
            for tool in getattr(server, 'tools', []):
                tool_dict = tool.dict() if hasattr(tool, 'dict') else tool.__dict__
                if any(keyword in tool_dict.get('name', '').lower() 
                      for keyword in ['execute', 'run', 'command', 'shell']):
                    code_execution_tools.append(tool_dict.get('name', 'unknown'))
        
        if code_execution_tools:
            recommendations.append(
                f"Found {len(code_execution_tools)} tools with code execution capabilities. "
                "Ensure proper input validation and sandboxing are in place."
            )
        
        # Check for file access tools
        file_access_tools = []
        for server in mcp_servers:
            for tool in getattr(server, 'tools', []):
                tool_dict = tool.dict() if hasattr(tool, 'dict') else tool.__dict__
                if any(keyword in tool_dict.get('name', '').lower() 
                      for keyword in ['file', 'read', 'write', 'directory']):
                    file_access_tools.append(tool_dict.get('name', 'unknown'))
        
        if file_access_tools:
            recommendations.append(
                f"Found {len(file_access_tools)} tools with file system access. "
                "Implement proper access controls and path restrictions."
            )
        
        # Check for failed introspections
        failed_count = sum(len(r.errors) for r in pipeline_results if r.errors)
        if failed_count > 0:
            recommendations.append(
                f"Encountered {failed_count} errors during introspection. "
                "Review server configurations and network connectivity."
            )
        
        # General security recommendations
        if mcp_servers:
            recommendations.extend([
                "Regularly audit MCP server configurations and access permissions.",
                "Implement monitoring and logging for MCP server activities.",
                "Keep MCP servers and their dependencies up to date.",
                "Use network segmentation to isolate MCP servers where appropriate.",
                "Implement authentication and authorization for MCP server access."
            ])
        
        return recommendations


def convert_pipeline_results_to_report(
    pipeline_results: List[PipelineResult],
    report_title: str = "MCP Detection and Introspection Report",
    report_type: ReportType = ReportType.COMBINED_REPORT,
    report_format: ReportFormat = ReportFormat.JSON
) -> ReportData:
    """
    Convenience function to convert pipeline results to report data.
    
    Args:
        pipeline_results: List of pipeline execution results
        report_title: Title for the report
        report_type: Type of report to generate
        report_format: Format of the report
        
    Returns:
        ReportData: Converted report data
    """
    converter = PipelineToReportConverter()
    return converter.convert_pipeline_results(
        pipeline_results, report_title, report_type, report_format
    ) 