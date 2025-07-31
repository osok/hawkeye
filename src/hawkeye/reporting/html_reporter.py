"""
HTML report generator for HawkEye security reconnaissance tool.

This module provides HTML report generation capabilities using a template-based
system for creating professional, formatted HTML reports with interactive elements.
"""

import time
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from .base import BaseReporter, ReportData, ReportFormat, ReportingError
from .templates import (
    TemplateEngine, 
    ExecutiveSummaryTemplate,
    TechnicalReportTemplate,
    VulnerabilityReportTemplate,
    ComplianceReportTemplate,
    MCPSummaryTemplate
)
from .templates.threat_analysis_template import ThreatAnalysisTemplate
from .mcp_analyzer import MCPDataAnalyzer
from .threat_analyzer import ThreatAnalyzer
from ..utils.logging import get_logger


class HTMLReporter(BaseReporter):
    """HTML report generator using template system."""
    
    def __init__(self):
        """Initialize HTML reporter."""
        super().__init__()
        self.logger = get_logger(self.__class__.__name__)
        self.template_engine = TemplateEngine()
        self._register_default_templates()
        self.templates = {
            "technical": TechnicalReportTemplate(),
            "mcp_summary": MCPSummaryTemplate(),
            "threat_analysis": ThreatAnalysisTemplate()
        }
        self.mcp_analyzer = MCPDataAnalyzer()
        self.threat_analyzer = ThreatAnalyzer()
    
    def _register_default_templates(self) -> None:
        """Register default HTML templates."""
        templates = [
            ExecutiveSummaryTemplate(),
            TechnicalReportTemplate(),
            VulnerabilityReportTemplate(),
            ComplianceReportTemplate(),
            MCPSummaryTemplate(),
            ThreatAnalysisTemplate()
        ]
        
        for template in templates:
            self.template_engine.register_template(template)
            self.logger.debug(f"Registered template: {template.template_name}")
    
    def generate_report(self, data: ReportData, output_file: Optional[Path] = None, 
                       template_name: str = "technical_report", **kwargs) -> str:
        """
        Generate HTML report using specified template.
        
        Args:
            data: Report data to include
            output_file: Optional file path to save report
            template_name: Name of template to use
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
            
        Raises:
            ReportingError: If report generation fails
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Generating HTML report using template: {template_name}")
            
            # Validate data
            self.validate_data(data)
            
            # Generate HTML content
            html_content = self.template_engine.render_template(
                template_name, data, **kwargs
            )
            
            # Save to file if specified
            if output_file:
                self._save_to_file(html_content, output_file)
                self.logger.info(f"HTML report saved to: {output_file}")
            
            # Update statistics
            generation_time = time.time() - start_time
            self._update_statistics(True, generation_time)
            
            self.logger.info(f"HTML report generated successfully in {generation_time:.2f}s")
            return html_content
            
        except Exception as e:
            self.logger.error(f"HTML report generation failed: {e}")
            raise ReportingError(f"Failed to generate HTML report: {e}")
    
    def generate_executive_summary(self, data: ReportData, 
                                 output_file: Optional[Path] = None, **kwargs) -> str:
        """
        Generate executive summary HTML report.
        
        Args:
            data: Report data to include
            output_file: Optional file path to save report
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
        """
        return self.generate_report(
            data, output_file, "executive_summary", **kwargs
        )
    
    def generate_technical_report(self, data: ReportData, 
                                output_file: Optional[Path] = None, **kwargs) -> str:
        """
        Generate technical analysis HTML report.
        
        Args:
            data: Report data to include
            output_file: Optional file path to save report
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
        """
        return self.generate_report(
            data, output_file, "technical_report", **kwargs
        )
    
    def generate_vulnerability_report(self, data: ReportData, 
                                    output_file: Optional[Path] = None, **kwargs) -> str:
        """
        Generate vulnerability analysis HTML report.
        
        Args:
            data: Report data to include
            output_file: Optional file path to save report
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
        """
        return self.generate_report(
            data, output_file, "vulnerability_report", **kwargs
        )
    
    def generate_compliance_report(self, data: ReportData, 
                                 output_file: Optional[Path] = None, **kwargs) -> str:
        """
        Generate compliance analysis HTML report.
        
        Args:
            data: Report data to include
            output_file: Optional file path to save report
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
        """
        return self.generate_report(
            data, output_file, "compliance_report", **kwargs
        )
    
    def generate_mcp_summary_report(self, data: ReportData, 
                                  output_file: Optional[Path] = None, **kwargs) -> str:
        """
        Generate MCP-specific summary HTML report.
        
        Args:
            data: Report data to include
            output_file: Optional file path to save report
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
        """
        # Use MCP analyzer to process the data
        analyzer = MCPDataAnalyzer()
        analyzed_data = analyzer.analyze_detection_results(data)
        
        # Merge with any additional kwargs (but remove template_name if present to avoid conflict)
        template_vars = {**analyzed_data, **kwargs}
        template_vars.pop('template_name', None)  # Remove to avoid conflict
        
        return self.generate_report(
            data, output_file, template_name="mcp_summary", **template_vars
        )
    
    def generate_threat_analysis_report(self, data: ReportData, 
                                      output_file: Optional[Path] = None, **kwargs) -> str:
        """
        Generate threat analysis report showing attack scenarios and abuse cases.
        
        Args:
            data: Report data containing MCP detection results
            output_file: Optional file path to save report
            **kwargs: Additional template variables
            
        Returns:
            str: Generated HTML content
        """
        # Use threat analyzer to process the data
        analyzed_data = self.threat_analyzer.analyze_threats(data)
        
        # Merge with any additional kwargs
        template_vars = {**analyzed_data, **kwargs}
        template_vars.pop('template_name', None)  # Remove to avoid conflict
        
        return self.generate_report(
            data, output_file, template_name="threat_analysis", **template_vars
        )
    
    def list_available_templates(self) -> list[str]:
        """
        Get list of available templates.
        
        Returns:
            list[str]: List of template names
        """
        return self.template_engine.list_templates()
    
    def register_custom_template(self, template) -> None:
        """
        Register a custom template.
        
        Args:
            template: Template instance to register
        """
        self.template_engine.register_template(template)
        self.logger.info(f"Registered custom template: {template.template_name}")
    
    def _save_to_file(self, content: str, output_file: Path) -> None:
        """Save HTML content to file."""
        try:
            # Ensure directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write content
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
                
        except Exception as e:
            raise ReportingError(f"Failed to save HTML report to {output_file}: {e}")
    
    def get_supported_formats(self) -> list[ReportFormat]:
        """Get list of supported report formats."""
        return [ReportFormat.HTML]
    
    def get_format(self) -> ReportFormat:
        """Get the report format supported by this reporter."""
        return ReportFormat.HTML 

    def _prepare_technical_data(self, data: ReportData) -> Dict[str, Any]:
        """Prepare data for technical template."""
        # Convert detection results to serializable format
        results_data = []
        for result in data.detection_results:
            result_dict = {
                "detection_method": result.detection_method.value if hasattr(result.detection_method, 'value') else str(result.detection_method),
                "confidence": result.confidence,
                "details": result.details,
                "timestamp": result.timestamp.isoformat() if result.timestamp else None,
                "raw_data": result.raw_data
            }
            results_data.append(result_dict)
        
        return {
            "scan_target": data.target or "Unknown",
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_detections": len(data.detection_results),
            "detection_results": results_data,
            "detection_results_json": json.dumps(results_data, indent=2),
            "template_name": "technical",
            "render_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        } 