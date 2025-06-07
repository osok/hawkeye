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
            self.logger.error(f"Failed to generate JSON report: {e}")
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
            
            # Add formatted timestamp
            enhanced_result['formatted_timestamp'] = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", 
                time.gmtime(result.assessment_timestamp)
            )
            
            # Add computed statistics
            enhanced_result['statistics'] = {
                'critical_findings_count': len(result.critical_findings),
                'high_findings_count': len(result.high_findings),
                'exploitable_vulnerabilities_count': len(result.exploitable_vulnerabilities),
                'unpatched_vulnerabilities_count': len(result.unpatched_vulnerabilities),
            }
            
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
    
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
        # Handle Path objects
        if isinstance(obj, Path):
            return str(obj)
        
        # Handle enum objects
        if hasattr(obj, 'value'):
            return obj.value
        
        # Handle dataclass objects
        if hasattr(obj, '__dataclass_fields__'):
            return obj.__dict__
        
        # Fallback to string representation
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