"""
HTML report generator for HawkEye security reconnaissance tool.

This module provides HTML report generation capabilities using a template-based
system for creating professional, formatted HTML reports with interactive elements.
"""

import time
from pathlib import Path
from typing import Optional, Dict, Any

from .base import BaseReporter, ReportData, ReportFormat, ReportingError
from .templates import (
    TemplateEngine, 
    ExecutiveSummaryTemplate,
    TechnicalReportTemplate,
    VulnerabilityReportTemplate,
    ComplianceReportTemplate
)
from ..utils.logging import get_logger


class HTMLReporter(BaseReporter):
    """HTML report generator using template system."""
    
    def __init__(self):
        """Initialize HTML reporter."""
        super().__init__()
        self.logger = get_logger(self.__class__.__name__)
        self.template_engine = TemplateEngine()
        self._register_default_templates()
    
    def _register_default_templates(self) -> None:
        """Register default HTML templates."""
        templates = [
            ExecutiveSummaryTemplate(),
            TechnicalReportTemplate(),
            VulnerabilityReportTemplate(),
            ComplianceReportTemplate()
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
            self._validate_data(data)
            
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
            self._update_statistics(
                format_type=ReportFormat.HTML,
                generation_time=generation_time,
                output_size=len(html_content)
            )
            
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