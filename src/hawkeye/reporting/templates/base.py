"""
Base template system for HTML report generation.

This module provides the foundational template engine and base classes
for creating dynamic HTML reports with data binding, conditional rendering,
and template inheritance.
"""

import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from string import Template

from ..base import ReportData, ReportingError
from ...utils.logging import get_logger


class TemplateError(ReportingError):
    """Exception raised for template processing errors."""
    pass


class BaseTemplate(ABC):
    """Abstract base class for report templates."""
    
    def __init__(self, template_name: str):
        """
        Initialize template.
        
        Args:
            template_name: Name of the template
        """
        self.template_name = template_name
        self.logger = get_logger(self.__class__.__name__)
        self._template_content = None
        self._css_content = None
        self._js_content = None
    
    @abstractmethod
    def get_template_content(self) -> str:
        """
        Get the HTML template content.
        
        Returns:
            str: HTML template content
        """
        pass
    
    def get_css_content(self) -> str:
        """
        Get the CSS content for the template.
        
        Returns:
            str: CSS content
        """
        return self._get_default_css()
    
    def get_js_content(self) -> str:
        """
        Get the JavaScript content for the template.
        
        Returns:
            str: JavaScript content
        """
        return self._get_default_js()
    
    def render(self, data: ReportData, **kwargs) -> str:
        """
        Render the template with data.
        
        Args:
            data: Report data to render
            **kwargs: Additional template variables
            
        Returns:
            str: Rendered HTML content
        """
        try:
            # Prepare template variables
            template_vars = self._prepare_template_variables(data, **kwargs)
            
            # Get template content
            template_content = self.get_template_content()
            
            # Render template
            rendered_html = self._render_template(template_content, template_vars)
            
            return rendered_html
            
        except Exception as e:
            self.logger.error(f"Template rendering failed: {e}")
            raise TemplateError(f"Failed to render template {self.template_name}: {e}")
    
    def _prepare_template_variables(self, data: ReportData, **kwargs) -> Dict[str, Any]:
        """Prepare variables for template rendering."""
        variables = {
            # Basic data
            'report_data': data,
            'metadata': data.metadata,
            'scan_results': data.scan_results,
            'detection_results': data.detection_results,
            'assessment_results': data.assessment_results,
            'recommendations': data.recommendations,
            
            # Summaries
            'scan_summary': data.scan_summary,
            'detection_summary': data.detection_summary,
            'risk_summary': data.risk_summary,
            'executive_summary': data.executive_summary,
            
            # Computed values
            'total_targets': data.total_targets,
            'critical_findings': data.critical_findings,
            'high_risk_targets': data.high_risk_targets,
            
            # Template metadata
            'template_name': self.template_name,
            'render_time': time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            'css_content': self.get_css_content(),
            'js_content': self.get_js_content(),
        }
        
        # Add custom variables
        variables.update(kwargs)
        
        return variables
    
    def _render_template(self, template_content: str, variables: Dict[str, Any]) -> str:
        """Render template with variables using simple substitution."""
        try:
            # Use Python's Template class for safe substitution
            template = Template(template_content)
            
            # Convert complex objects to strings for template rendering
            safe_variables = self._make_template_safe(variables)
            
            # Perform substitution
            rendered = template.safe_substitute(safe_variables)
            
            return rendered
            
        except Exception as e:
            raise TemplateError(f"Template substitution failed: {e}")
    
    def _make_template_safe(self, variables: Dict[str, Any]) -> Dict[str, str]:
        """Convert variables to template-safe strings."""
        safe_vars = {}
        
        for key, value in variables.items():
            if isinstance(value, (str, int, float, bool)):
                safe_vars[key] = str(value)
            elif isinstance(value, list):
                safe_vars[key] = self._render_list(value)
            elif isinstance(value, dict):
                safe_vars[key] = self._render_dict(value)
            elif hasattr(value, 'to_dict'):
                safe_vars[key] = self._render_dict(value.to_dict())
            elif hasattr(value, '__dict__'):
                safe_vars[key] = self._render_dict(value.__dict__)
            else:
                safe_vars[key] = str(value)
        
        return safe_vars
    
    def _render_list(self, items: List[Any]) -> str:
        """Render a list as HTML."""
        if not items:
            return "<p>No items found.</p>"
        
        html_items = []
        for item in items:
            if hasattr(item, 'to_dict'):
                html_items.append(self._render_dict(item.to_dict()))
            elif isinstance(item, dict):
                html_items.append(self._render_dict(item))
            else:
                html_items.append(f"<li>{self._escape_html(str(item))}</li>")
        
        return f"<ul>{''.join(html_items)}</ul>"
    
    def _render_dict(self, data: Dict[str, Any]) -> str:
        """Render a dictionary as HTML table."""
        if not data:
            return "<p>No data available.</p>"
        
        rows = []
        for key, value in data.items():
            escaped_key = self._escape_html(str(key))
            escaped_value = self._escape_html(str(value))
            rows.append(f"<tr><td><strong>{escaped_key}</strong></td><td>{escaped_value}</td></tr>")
        
        return f"<table class='data-table'><tbody>{''.join(rows)}</tbody></table>"
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))
    
    def _get_default_css(self) -> str:
        """Get default CSS styles."""
        return """
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header {
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.1em;
            margin-top: 5px;
        }
        
        .section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ecf0f1;
            border-radius: 5px;
        }
        
        .section h2 {
            color: #34495e;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }
        
        .section h3 {
            color: #2c3e50;
            margin-top: 25px;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        
        .data-table th,
        .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .data-table th {
            background-color: #f8f9fa;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .data-table tr:hover {
            background-color: #f5f5f5;
        }
        
        .alert {
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            border-left: 4px solid;
        }
        
        .alert-critical {
            background-color: #f8d7da;
            border-color: #dc3545;
            color: #721c24;
        }
        
        .alert-high {
            background-color: #fff3cd;
            border-color: #ffc107;
            color: #856404;
        }
        
        .alert-medium {
            background-color: #d1ecf1;
            border-color: #17a2b8;
            color: #0c5460;
        }
        
        .alert-low {
            background-color: #d4edda;
            border-color: #28a745;
            color: #155724;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            border: 1px solid #dee2e6;
        }
        
        .stat-card .number {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .stat-card .label {
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .recommendations {
            background-color: #e8f4fd;
            border: 1px solid #bee5eb;
            border-radius: 5px;
            padding: 20px;
        }
        
        .recommendations h3 {
            color: #0c5460;
            margin-top: 0;
        }
        
        .recommendations ol {
            margin: 0;
            padding-left: 20px;
        }
        
        .recommendations li {
            margin-bottom: 10px;
            line-height: 1.5;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
        }
        
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
            .section { break-inside: avoid; }
        }
        """
    
    def _get_default_js(self) -> str:
        """Get default JavaScript functionality."""
        return """
        // HawkEye Report JavaScript
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for expandable sections
            const sections = document.querySelectorAll('.section h2');
            sections.forEach(function(header) {
                header.style.cursor = 'pointer';
                header.addEventListener('click', function() {
                    const content = header.nextElementSibling;
                    if (content) {
                        content.style.display = content.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });
            
            // Add tooltips for risk levels
            const riskElements = document.querySelectorAll('[data-risk-level]');
            riskElements.forEach(function(element) {
                const riskLevel = element.getAttribute('data-risk-level');
                element.title = 'Risk Level: ' + riskLevel.toUpperCase();
            });
            
            // Add print functionality
            if (window.print) {
                const printButton = document.createElement('button');
                printButton.textContent = 'Print Report';
                printButton.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 1000; padding: 10px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;';
                printButton.addEventListener('click', function() {
                    window.print();
                });
                document.body.appendChild(printButton);
            }
        });
        """


class TemplateEngine:
    """Template engine for managing and rendering HTML templates."""
    
    def __init__(self):
        """Initialize the template engine."""
        self.logger = get_logger(self.__class__.__name__)
        self._templates: Dict[str, BaseTemplate] = {}
    
    def register_template(self, template: BaseTemplate) -> None:
        """
        Register a template with the engine.
        
        Args:
            template: Template to register
        """
        self._templates[template.template_name] = template
        self.logger.debug(f"Registered template: {template.template_name}")
    
    def get_template(self, template_name: str) -> Optional[BaseTemplate]:
        """
        Get a registered template by name.
        
        Args:
            template_name: Name of the template
            
        Returns:
            BaseTemplate: Template instance or None if not found
        """
        return self._templates.get(template_name)
    
    def list_templates(self) -> List[str]:
        """
        Get list of registered template names.
        
        Returns:
            List[str]: List of template names
        """
        return list(self._templates.keys())
    
    def render_template(self, template_name: str, data: ReportData, **kwargs) -> str:
        """
        Render a template with data.
        
        Args:
            template_name: Name of the template to render
            data: Report data to render
            **kwargs: Additional template variables
            
        Returns:
            str: Rendered HTML content
            
        Raises:
            TemplateError: If template not found or rendering fails
        """
        template = self.get_template(template_name)
        if not template:
            raise TemplateError(f"Template not found: {template_name}")
        
        return template.render(data, **kwargs)
    
    def clear_templates(self) -> None:
        """Clear all registered templates."""
        self._templates.clear()
        self.logger.debug("Cleared all templates") 