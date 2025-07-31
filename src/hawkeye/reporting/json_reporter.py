"""
JSON report generator for HawkEye security reconnaissance tool.

This module provides JSON format report generation with structured data output,
proper formatting, and comprehensive data serialization for all scan results,
detection findings, and risk assessments.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from .base import BaseReporter, ReportData, ReportFormat, ReportingError
from ..utils.logging import get_logger


class JSONReporter(BaseReporter):
    """JSON format report generator."""
    
    def __init__(self, settings=None, indent: int = 2, sort_keys: bool = True):
        """
        Initialize JSON reporter.
        
        Args:
            settings: Configuration settings
            indent: JSON indentation level
            sort_keys: Whether to sort JSON keys
        """
        super().__init__(settings)
        self.indent = indent
        self.sort_keys = sort_keys
        self.logger = get_logger(self.__class__.__name__)
    
    def get_format(self) -> ReportFormat:
        """Get the report format."""
        return ReportFormat.JSON
    
    def generate_report(self, data: ReportData, output_path: Optional[Path] = None) -> str:
        """
        Generate JSON report from data.
        
        Args:
            data: Report data to generate from
            output_path: Optional path to save the report
            
        Returns:
            str: Path to generated report file or JSON content
            
        Raises:
            ReportingError: If report generation fails
        """
        start_time = time.time()
        success = False
        
        try:
            # Validate input data
            self.validate_data(data)
            
            # Generate JSON content
            json_content = self._generate_json_content(data)
            
            # Save to file if path provided
            if output_path:
                output_file = self._create_output_path(output_path, data)
                self._save_json_file(json_content, output_file)
                result = str(output_file)
                self.logger.info(f"JSON report saved to: {output_file}")
            else:
                result = json_content
                self.logger.info("JSON report generated in memory")
            
            success = True
            return result
            
        except Exception as e:
            import traceback
            self.logger.error(f"Failed to generate JSON report: {e}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            raise ReportingError(f"JSON report generation failed: {e}")
        
        finally:
            generation_time = time.time() - start_time
            self._update_statistics(success, generation_time)
    
    def _generate_json_content(self, data: ReportData) -> str:
        """
        Generate JSON content from report data.
        
        Args:
            data: Report data to convert
            
        Returns:
            str: JSON formatted content
        """
        try:
            # Convert data to dictionary
            report_dict = self._prepare_report_data(data)
            
            # Serialize to JSON
            json_content = json.dumps(
                report_dict,
                indent=self.indent,
                sort_keys=self.sort_keys,
                ensure_ascii=False,
                default=self._json_serializer
            )
            
            return json_content
            
        except (TypeError, ValueError) as e:
            raise ReportingError(f"JSON serialization failed: {e}")
    
    def _prepare_report_data(self, data: ReportData) -> Dict[str, Any]:
        """
        Prepare report data for JSON serialization.
        
        Args:
            data: Report data to prepare
            
        Returns:
            Dict: Prepared data dictionary
        """
        # Start with base data dictionary
        report_dict = data.to_dict()
        
        # Add JSON-specific metadata
        report_dict['metadata']['format_version'] = "1.0"
        report_dict['metadata']['schema_version'] = "hawkeye-json-v1"
        
        # Add generation statistics
        report_dict['generation_info'] = {
            'generator': self.__class__.__name__,
            'generation_time': time.time(),
            'format_options': {
                'indent': self.indent,
                'sort_keys': self.sort_keys,
            }
        }
        
        # Enhance scan results with additional metadata
        if data.has_scan_data:
            report_dict['scan_results'] = self._enhance_scan_results(data.scan_results)
        
        # Enhance detection results with additional metadata
        if data.has_detection_data:
            report_dict['detection_results'] = self._enhance_detection_results(data.detection_results)
        
        # Enhance assessment results with additional metadata
        if data.has_assessment_data:
            report_dict['assessment_results'] = self._enhance_assessment_results(data.assessment_results)
        
        # Enhance pipeline results with additional metadata
        if data.has_pipeline_data:
            report_dict['pipeline_results'] = self._enhance_pipeline_results(data.pipeline_results)
        
        # Enhance introspection data with additional metadata
        if data.has_introspection_data:
            report_dict['introspection_data'] = self._enhance_introspection_data(data.introspection_data)
            report_dict['mcp_servers'] = self._enhance_mcp_servers(data.mcp_servers)
        
        # Add aggregated statistics
        report_dict['aggregated_statistics'] = self._generate_aggregated_statistics(data)
        
        return report_dict
    
    def _enhance_scan_results(self, scan_results) -> List[Dict[str, Any]]:
        """Enhance scan results with additional JSON-specific data."""
        enhanced_results = []
        
        for result in scan_results:
            enhanced_result = result.to_dict()
            
            # Add computed fields
            enhanced_result['is_open'] = result.is_open
            enhanced_result['has_service_info'] = result.has_service_info
            
            # Add formatted timestamp
            enhanced_result['formatted_timestamp'] = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", 
                time.gmtime(result.timestamp)
            )
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
    
    def _enhance_detection_results(self, detection_results) -> List[Dict[str, Any]]:
        """Enhance detection results with additional JSON-specific data."""
        enhanced_results = []
        
        for result in detection_results:
            enhanced_result = result.to_dict()
            
            # Add computed fields
            enhanced_result['is_mcp_detected'] = result.is_mcp_detected
            
            # Add formatted timestamp
            enhanced_result['formatted_timestamp'] = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", 
                time.gmtime(result.timestamp)
            )
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
    
    def _enhance_assessment_results(self, assessment_results) -> List[Dict[str, Any]]:
        """Enhance assessment results with additional JSON-specific data."""
        enhanced_results = []
        
        for result in assessment_results:
            enhanced_result = result.to_dict()
            
            # Add computed fields
            enhanced_result['is_high_risk'] = result.overall_risk_level in ['high', 'critical']
            enhanced_result['has_critical_findings'] = len(result.critical_findings) > 0
            
            # Add formatted timestamp
            enhanced_result['formatted_timestamp'] = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", 
                time.gmtime(result.timestamp)
            )
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
    
    def _enhance_pipeline_results(self, pipeline_results) -> List[Dict[str, Any]]:
        """Enhance pipeline results with additional JSON-specific data."""
        enhanced_results = []
        
        for result in pipeline_results:
            enhanced_result = {
                'target_host': result.target_host,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat(),
                'duration': result.duration,
                'success': result.success,
                'total_detections': result.total_detections,
                'successful_detections': result.successful_detections,
                'failed_detections': result.failed_detections,
                'mcp_servers_found': result.mcp_servers_found,
                'errors': result.errors,
                'warnings': result.warnings,
                
                # Computed fields
                'detection_success_rate': (
                    result.successful_detections / result.total_detections 
                    if result.total_detections > 0 else 0.0
                ),
                'has_introspection_data': len(result.introspection_results) > 0,
                'introspection_count': len(result.introspection_results),
                'has_risk_assessment': result.risk_assessment is not None,
                'has_errors': len(result.errors) > 0,
                'has_warnings': len(result.warnings) > 0,
                
                # Formatted timestamps
                'formatted_start_time': result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                'formatted_end_time': result.end_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                'duration_formatted': f"{result.duration:.2f}s",
                
                # Enhanced data
                'best_mcp_server': self._enhance_server_info(result.best_mcp_server) if result.best_mcp_server else None,
                'highest_confidence_result': result.highest_confidence_result.to_dict() if result.highest_confidence_result else None,
                'risk_assessment': result.risk_assessment,
                'introspection_results': self._enhance_introspection_results(result.introspection_results),
            }
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
    
    def _enhance_introspection_results(self, introspection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance introspection results with additional metadata."""
        enhanced_results = {}
        
        for server_id, capabilities in introspection_results.items():
            enhanced_capabilities = {
                'server_id': server_id,
                'capabilities': capabilities.dict() if hasattr(capabilities, 'dict') else capabilities.__dict__,
                
                # Computed fields
                'capability_count': capabilities.get_capability_count() if hasattr(capabilities, 'get_capability_count') else 0,
                'has_dangerous_capabilities': capabilities.has_dangerous_capabilities() if hasattr(capabilities, 'has_dangerous_capabilities') else False,
                'supports_tools': getattr(capabilities, 'supports_tools', False),
                'supports_resources': getattr(capabilities, 'supports_resources', False),
                'supports_prompts': getattr(capabilities, 'supports_prompts', False),
                'protocol_version': getattr(capabilities, 'protocol_version', None),
                'server_version': getattr(capabilities, 'server_version', None),
            }
            
            enhanced_results[server_id] = enhanced_capabilities
        
        return enhanced_results
    
    def _enhance_server_info(self, server_info) -> Dict[str, Any]:
        """Enhance MCP server info with additional metadata."""
        if not server_info:
            return None
        
        enhanced_info = server_info.dict() if hasattr(server_info, 'dict') else server_info.__dict__
        
        # Add computed fields
        enhanced_info.update({
            'tool_count': server_info.get_tool_count() if hasattr(server_info, 'get_tool_count') else len(enhanced_info.get('tools', [])),
            'resource_count': server_info.get_resource_count() if hasattr(server_info, 'get_resource_count') else len(enhanced_info.get('resources', [])),
            'capability_count': server_info.get_capability_count() if hasattr(server_info, 'get_capability_count') else len(enhanced_info.get('capabilities', [])),
            'has_security_risks': len(enhanced_info.get('security_risks', [])) > 0,
            'risk_level': enhanced_info.get('overall_risk_level', 'unknown'),
            'discovery_timestamp_formatted': enhanced_info.get('discovery_timestamp', ''),
        })
        
        # Enhance tools with categorization
        if 'tools' in enhanced_info:
            enhanced_info['tools'] = self._enhance_tools(enhanced_info['tools'])
        
        # Enhance resources with metadata
        if 'resources' in enhanced_info:
            enhanced_info['resources'] = self._enhance_resources(enhanced_info['resources'])
        
        return enhanced_info
    
    def _enhance_tools(self, tools) -> List[Dict[str, Any]]:
        """Enhance tool information with categorization."""
        enhanced_tools = []
        
        for tool in tools:
            # Handle different tool formats
            if isinstance(tool, dict):
                tool_dict = tool.copy()
            elif hasattr(tool, 'dict'):
                tool_dict = tool.dict()
            elif hasattr(tool, '__dict__'):
                tool_dict = tool.__dict__.copy()
            else:
                # Fallback for unknown types
                tool_dict = {'name': str(tool), 'description': ''}
            
            # Add tool categorization
            tool_dict.update({
                'category': self._categorize_tool(tool_dict),
                'risk_level': self._assess_tool_risk(tool_dict),
                'parameter_count': len(tool_dict.get('parameters', [])),
                'has_required_params': any(
                    param.get('required', False) 
                    for param in tool_dict.get('parameters', [])
                ),
            })
            
            enhanced_tools.append(tool_dict)
        
        return enhanced_tools
    
    def _enhance_resources(self, resources) -> List[Dict[str, Any]]:
        """Enhance resource information with metadata."""
        enhanced_resources = []
        
        for resource in resources:
            # Handle different resource formats
            if isinstance(resource, dict):
                resource_dict = resource.copy()
            elif hasattr(resource, 'dict'):
                resource_dict = resource.dict()
            elif hasattr(resource, '__dict__'):
                resource_dict = resource.__dict__.copy()
            else:
                # Fallback for unknown types
                resource_dict = {'uri': str(resource), 'name': str(resource)}
            
            # Add resource categorization
            resource_dict.update({
                'category': self._categorize_resource(resource_dict),
                'is_file_resource': resource_dict.get('uri', '').startswith('file://'),
                'is_http_resource': resource_dict.get('uri', '').startswith('http'),
                'has_mime_type': resource_dict.get('mime_type') is not None,
            })
            
            enhanced_resources.append(resource_dict)
        
        return enhanced_resources
    
    def _categorize_tool(self, tool: Dict[str, Any]) -> str:
        """Categorize a tool based on its name and description."""
        name = tool.get('name', '').lower()
        description = tool.get('description', '').lower()
        
        # File system operations
        if any(keyword in name or keyword in description for keyword in ['file', 'read', 'write', 'directory', 'path']):
            return 'file_system'
        
        # Network operations
        if any(keyword in name or keyword in description for keyword in ['http', 'request', 'url', 'web', 'api']):
            return 'network'
        
        # Code execution
        if any(keyword in name or keyword in description for keyword in ['execute', 'run', 'command', 'shell', 'script']):
            return 'code_execution'
        
        # Database operations
        if any(keyword in name or keyword in description for keyword in ['database', 'sql', 'query', 'db']):
            return 'database'
        
        # System operations
        if any(keyword in name or keyword in description for keyword in ['system', 'process', 'service', 'config']):
            return 'system'
        
        return 'other'
    
    def _assess_tool_risk(self, tool: Dict[str, Any]) -> str:
        """Assess the risk level of a tool."""
        category = self._categorize_tool(tool)
        
        # High-risk categories
        if category in ['code_execution', 'file_system', 'system']:
            return 'high'
        
        # Medium-risk categories
        if category in ['network', 'database']:
            return 'medium'
        
        # Low-risk by default
        return 'low'
    
    def _categorize_resource(self, resource: Dict[str, Any]) -> str:
        """Categorize a resource based on its URI and type."""
        uri = resource.get('uri', '').lower()
        mime_type = resource.get('mime_type', '').lower()
        
        # File resources
        if uri.startswith('file://'):
            return 'file'
        
        # Web resources
        if uri.startswith('http'):
            return 'web'
        
        # Database resources
        if any(keyword in uri for keyword in ['database', 'db', 'sql']):
            return 'database'
        
        # Based on MIME type
        if mime_type:
            if mime_type.startswith('text/'):
                return 'text'
            elif mime_type.startswith('image/'):
                return 'image'
            elif mime_type.startswith('application/'):
                return 'application'
        
        return 'other'
    
    def _enhance_introspection_data(self, introspection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance introspection data with additional metadata."""
        enhanced_data = {}
        
        for server_id, capabilities in introspection_data.items():
            enhanced_data[server_id] = self._enhance_introspection_results({server_id: capabilities})[server_id]
        
        return enhanced_data
    
    def _enhance_mcp_servers(self, mcp_servers) -> List[Dict[str, Any]]:
        """Enhance MCP server list with additional metadata."""
        enhanced_servers = []
        
        for server in mcp_servers:
            enhanced_server = self._enhance_server_info(server)
            if enhanced_server:
                enhanced_servers.append(enhanced_server)
        
        return enhanced_servers
    
    def _generate_aggregated_statistics(self, data: ReportData) -> Dict[str, Any]:
        """Generate aggregated statistics across all data types."""
        stats = {
            'overview': {
                'total_targets': data.total_targets,
                'data_types_present': [],
            },
            'scan_statistics': {},
            'detection_statistics': {},
            'risk_statistics': {},
        }
        
        # Track data types present
        if data.has_scan_data:
            stats['overview']['data_types_present'].append('scan_results')
            stats['scan_statistics'] = self._calculate_scan_statistics(data.scan_results)
        
        if data.has_detection_data:
            stats['overview']['data_types_present'].append('detection_results')
            stats['detection_statistics'] = self._calculate_detection_statistics(data.detection_results)
        
        if data.has_assessment_data:
            stats['overview']['data_types_present'].append('assessment_results')
            stats['risk_statistics'] = self._calculate_risk_statistics(data.assessment_results)
        
        if data.has_pipeline_data:
            stats['overview']['data_types_present'].append('pipeline_results')
            stats['pipeline_statistics'] = self._calculate_pipeline_statistics(data.pipeline_results)
        
        if data.has_introspection_data:
            stats['overview']['data_types_present'].append('introspection_data')
            stats['introspection_statistics'] = self._calculate_introspection_statistics(data)
        
        return stats
    
    def _calculate_scan_statistics(self, scan_results) -> Dict[str, Any]:
        """Calculate statistics for scan results."""
        if not scan_results:
            return {}
        
        open_ports = sum(1 for r in scan_results if r.is_open)
        services_detected = sum(1 for r in scan_results if r.has_service_info)
        
        return {
            'total_scans': len(scan_results),
            'open_ports': open_ports,
            'services_detected': services_detected,
            'open_port_rate': open_ports / len(scan_results) if scan_results else 0.0,
            'service_detection_rate': services_detected / len(scan_results) if scan_results else 0.0,
        }
    
    def _calculate_detection_statistics(self, detection_results) -> Dict[str, Any]:
        """Calculate statistics for detection results."""
        if not detection_results:
            return {}
        
        mcp_detected = sum(1 for r in detection_results if r.is_mcp_detected)
        
        return {
            'total_detections': len(detection_results),
            'mcp_servers_found': mcp_detected,
            'detection_rate': mcp_detected / len(detection_results) if detection_results else 0.0,
        }
    
    def _calculate_risk_statistics(self, assessment_results) -> Dict[str, Any]:
        """Calculate statistics for risk assessment results."""
        if not assessment_results:
            return {}
        
        from ..assessment.base import RiskLevel
        
        risk_counts = {level.value: 0 for level in RiskLevel}
        total_findings = 0
        total_vulnerabilities = 0
        
        for result in assessment_results:
            risk_counts[result.overall_risk_level.value] += 1
            total_findings += len(result.findings)
            total_vulnerabilities += len(result.vulnerabilities)
        
        return {
            'total_assessments': len(assessment_results),
            'risk_level_distribution': risk_counts,
            'total_findings': total_findings,
            'total_vulnerabilities': total_vulnerabilities,
            'average_findings_per_target': total_findings / len(assessment_results) if assessment_results else 0.0,
            'average_vulnerabilities_per_target': total_vulnerabilities / len(assessment_results) if assessment_results else 0.0,
        }
    
    def _calculate_pipeline_statistics(self, pipeline_results) -> Dict[str, Any]:
        """Calculate statistics for pipeline results."""
        if not pipeline_results:
            return {}
        
        successful_pipelines = sum(1 for r in pipeline_results if r.success)
        total_detections = sum(r.total_detections for r in pipeline_results)
        successful_detections = sum(r.successful_detections for r in pipeline_results)
        total_mcp_servers = sum(r.mcp_servers_found for r in pipeline_results)
        total_introspections = sum(len(r.introspection_results) for r in pipeline_results)
        total_duration = sum(r.duration for r in pipeline_results)
        
        return {
            'total_pipelines': len(pipeline_results),
            'successful_pipelines': successful_pipelines,
            'pipeline_success_rate': successful_pipelines / len(pipeline_results) if pipeline_results else 0.0,
            'total_detections': total_detections,
            'successful_detections': successful_detections,
            'detection_success_rate': successful_detections / total_detections if total_detections > 0 else 0.0,
            'total_mcp_servers_found': total_mcp_servers,
            'total_introspections': total_introspections,
            'average_duration': total_duration / len(pipeline_results) if pipeline_results else 0.0,
            'average_servers_per_pipeline': total_mcp_servers / len(pipeline_results) if pipeline_results else 0.0,
            'average_introspections_per_pipeline': total_introspections / len(pipeline_results) if pipeline_results else 0.0,
        }
    
    def _calculate_introspection_statistics(self, data: ReportData) -> Dict[str, Any]:
        """Calculate statistics for introspection data."""
        stats = {
            'total_servers_introspected': len(data.introspected_servers),
            'total_tools_discovered': data.total_tools_discovered,
            'total_resources_discovered': data.total_resources_discovered,
            'tool_categories': {},
            'resource_categories': {},
            'risk_distribution': {},
            'transport_distribution': {},
        }
        
        if not data.introspected_servers:
            return stats
        
        # Analyze tools by category
        tool_categories = {}
        for server in data.introspected_servers:
            for tool in getattr(server, 'tools', []):
                tool_dict = tool.dict() if hasattr(tool, 'dict') else tool.__dict__
                category = self._categorize_tool(tool_dict)
                tool_categories[category] = tool_categories.get(category, 0) + 1
        
        # Analyze resources by category
        resource_categories = {}
        for server in data.introspected_servers:
            for resource in getattr(server, 'resources', []):
                resource_dict = resource.dict() if hasattr(resource, 'dict') else resource.__dict__
                category = self._categorize_resource(resource_dict)
                resource_categories[category] = resource_categories.get(category, 0) + 1
        
        # Analyze risk distribution
        risk_distribution = {}
        for server in data.introspected_servers:
            risk_level = getattr(server, 'overall_risk_level', 'unknown')
            # Check if it's actually an enum before accessing .value
            from enum import Enum
            if isinstance(risk_level, Enum):
                risk_level = risk_level.value
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        stats.update({
            'tool_categories': tool_categories,
            'resource_categories': resource_categories,
            'risk_distribution': risk_distribution,
            'average_tools_per_server': data.total_tools_discovered / len(data.introspected_servers),
            'average_resources_per_server': data.total_resources_discovered / len(data.introspected_servers),
        })
        
        return stats
    
    def _save_json_file(self, content: str, output_path: Path) -> None:
        """
        Save JSON content to file.
        
        Args:
            content: JSON content to save
            output_path: Path to save file
            
        Raises:
            ReportingError: If file save fails
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            raise ReportingError(f"Failed to save JSON report to {output_path}: {e}")
    
    def _json_serializer(self, obj) -> Any:
        """
        Custom JSON serializer for non-standard types.
        
        Args:
            obj: Object to serialize
            
        Returns:
            Serializable representation of object
        """
        try:
            # Handle Path objects
            if isinstance(obj, Path):
                return str(obj)
            
            # Handle enum objects - check explicitly for Enum type
            from enum import Enum
            if isinstance(obj, Enum):
                return obj.value
            
            # Handle dataclass objects
            if hasattr(obj, '__dataclass_fields__'):
                return obj.__dict__
            
            # Fallback to string representation
            return str(obj)
            
        except Exception as e:
            self.logger.error(f"JSON serializer error for object {type(obj)} {repr(obj)}: {e}")
            # Safe fallback
            return str(obj)
    
    def validate_json_output(self, json_content: str) -> bool:
        """
        Validate generated JSON content.
        
        Args:
            json_content: JSON content to validate
            
        Returns:
            bool: True if valid JSON
        """
        try:
            json.loads(json_content)
            return True
        except (json.JSONDecodeError, TypeError):
            return False 