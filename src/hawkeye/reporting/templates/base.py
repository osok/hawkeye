"""
HTML report templates for HawkEye security reconnaissance tool.

This package provides base template classes and the template engine for generating
professional, formatted HTML reports with dynamic content generation capabilities.
"""

import re
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union, Callable
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


class AdaptiveTemplateEngine(TemplateEngine):
    """Enhanced template engine with adaptive templates for dynamic content generation."""
    
    def __init__(self):
        """Initialize the adaptive template engine."""
        super().__init__()
        self.content_generators: Dict[str, Callable] = {}
        self.context_injectors: Dict[str, Callable] = {}
        self.severity_formatters: Dict[str, Dict[str, str]] = {}
        
    def register_content_generator(self, name: str, generator: Callable) -> None:
        """
        Register a content generator function.
        
        Args:
            name: Name of the generator
            generator: Function that generates dynamic content
        """
        self.content_generators[name] = generator
        self.logger.debug(f"Registered content generator: {name}")
    
    def register_context_injector(self, context_type: str, injector: Callable) -> None:
        """
        Register a context injection function.
        
        Args:
            context_type: Type of context (e.g., 'server_specific', 'environment')
            injector: Function that injects context-specific details
        """
        self.context_injectors[context_type] = injector
        self.logger.debug(f"Registered context injector: {context_type}")
    
    def register_severity_formatter(self, severity: str, formats: Dict[str, str]) -> None:
        """
        Register severity-based formatting rules.
        
        Args:
            severity: Severity level (e.g., 'critical', 'high', 'medium', 'low')
            formats: Dictionary of format rules (css_class, color, icon, etc.)
        """
        self.severity_formatters[severity] = formats
        self.logger.debug(f"Registered severity formatter: {severity}")
    
    def select_adaptive_template(self, 
                                base_template_name: str,
                                threat_analysis: Optional[Any] = None,
                                server_capabilities: Optional[List[str]] = None) -> str:
        """
        Select the most appropriate template based on analysis context.
        
        Args:
            base_template_name: Base template name
            threat_analysis: Threat analysis results
            server_capabilities: List of server capabilities
            
        Returns:
            str: Selected template name
        """
        # Determine complexity level
        complexity = self._assess_content_complexity(threat_analysis, server_capabilities)
        
        # Select template variant based on complexity
        if complexity == "high":
            return f"{base_template_name}_detailed"
        elif complexity == "medium":
            return f"{base_template_name}_standard"
        else:
            return f"{base_template_name}_basic"
    
    def generate_dynamic_content(self, 
                               content_type: str,
                               data: ReportData,
                               context: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate dynamic content using registered generators.
        
        Args:
            content_type: Type of content to generate
            data: Report data
            context: Additional context for generation
            
        Returns:
            str: Generated content
        """
        generator = self.content_generators.get(content_type)
        if not generator:
            self.logger.warning(f"No generator found for content type: {content_type}")
            return f"<!-- Dynamic content for {content_type} not available -->"
        
        try:
            return generator(data, context or {})
        except Exception as e:
            self.logger.error(f"Content generation failed for {content_type}: {e}")
            return f"<!-- Content generation error: {e} -->"
    
    def inject_context(self, 
                      template_content: str,
                      context_data: Dict[str, Any]) -> str:
        """
        Inject context-specific details into template content.
        
        Args:
            template_content: Original template content
            context_data: Context data for injection
            
        Returns:
            str: Template content with injected context
        """
        content = template_content
        
        for context_type, injector in self.context_injectors.items():
            if context_type in context_data:
                try:
                    content = injector(content, context_data[context_type])
                except Exception as e:
                    self.logger.error(f"Context injection failed for {context_type}: {e}")
        
        return content
    
    def apply_severity_formatting(self, 
                                 content: str,
                                 severity: str) -> str:
        """
        Apply severity-based formatting to content.
        
        Args:
            content: Content to format
            severity: Severity level
            
        Returns:
            str: Formatted content
        """
        formatter = self.severity_formatters.get(severity.lower())
        if not formatter:
            return content
        
        # Apply formatting rules
        for format_type, format_value in formatter.items():
            placeholder = f"${{{format_type}}}"
            content = content.replace(placeholder, format_value)
        
        return content
    
    def render_adaptive_template(self, 
                               template_name: str,
                               data: ReportData,
                               threat_analysis: Optional[Any] = None,
                               **kwargs) -> str:
        """
        Render a template with adaptive content generation.
        
        Args:
            template_name: Name of the template to render
            data: Report data to render
            threat_analysis: Threat analysis data for adaptation
            **kwargs: Additional template variables
            
        Returns:
            str: Rendered HTML content with dynamic adaptations
        """
        # Select the most appropriate template
        selected_template = self.select_adaptive_template(
            template_name, threat_analysis, 
            kwargs.get('server_capabilities')
        )
        
        # Get template (fallback to base if variant not found)
        template = self.get_template(selected_template)
        if not template:
            template = self.get_template(template_name)
            if not template:
                raise TemplateError(f"Template not found: {template_name}")
        
        # Generate dynamic content
        dynamic_content = {}
        for content_type in ['attack_scenarios', 'mitigation_strategies', 'detection_indicators']:
            dynamic_content[content_type] = self.generate_dynamic_content(
                content_type, data, {'threat_analysis': threat_analysis}
            )
        
        # Merge dynamic content with kwargs
        kwargs.update(dynamic_content)
        
        # Render base template
        content = template.render(data, **kwargs)
        
        # Inject context-specific details
        if threat_analysis:
            context_data = {
                'server_specific': {
                    'threat_analysis': threat_analysis,
                    'server_info': kwargs.get('server_info')
                }
            }
            content = self.inject_context(content, context_data)
        
        # Apply severity-based formatting
        if threat_analysis and hasattr(threat_analysis, 'threat_level'):
            content = self.apply_severity_formatting(
                content, str(threat_analysis.threat_level.value)
            )
        
        return content
    
    def _assess_content_complexity(self, 
                                 threat_analysis: Optional[Any],
                                 server_capabilities: Optional[List[str]]) -> str:
        """
        Assess the complexity level for template selection.
        
        Args:
            threat_analysis: Threat analysis results
            server_capabilities: List of server capabilities
            
        Returns:
            str: Complexity level ('low', 'medium', 'high')
        """
        complexity_score = 0
        
        if threat_analysis:
            # Check threat level
            if hasattr(threat_analysis, 'threat_level'):
                threat_level = str(threat_analysis.threat_level.value).lower()
                if threat_level in ['critical', 'high']:
                    complexity_score += 3
                elif threat_level == 'medium':
                    complexity_score += 2
                else:
                    complexity_score += 1
            
            # Check number of attack vectors
            if hasattr(threat_analysis, 'attack_vectors'):
                complexity_score += min(len(threat_analysis.attack_vectors), 3)
            
            # Check abuse scenarios
            if hasattr(threat_analysis, 'abuse_scenarios'):
                complexity_score += min(len(threat_analysis.abuse_scenarios), 2)
        
        if server_capabilities:
            # More capabilities = higher complexity
            complexity_score += min(len(server_capabilities) // 3, 2)
        
        if complexity_score >= 7:
            return "high"
        elif complexity_score >= 4:
            return "medium"
        else:
            return "low"


class TemplateCapabilityMatcher:
    """Matches templates to specific MCP tool capabilities for adaptive rendering."""
    
    def __init__(self):
        """Initialize the capability matcher."""
        self.capability_templates: Dict[str, str] = {}
        self.capability_patterns: Dict[str, List[str]] = {}
    
    def register_capability_template(self, 
                                   capability: str,
                                   template_name: str,
                                   patterns: Optional[List[str]] = None) -> None:
        """
        Register a template for a specific capability.
        
        Args:
            capability: Capability name (e.g., 'file_system', 'network_access')
            template_name: Template name to use for this capability
            patterns: Optional regex patterns for capability matching
        """
        self.capability_templates[capability] = template_name
        if patterns:
            self.capability_patterns[capability] = patterns
    
    def match_template_for_capabilities(self, 
                                      capabilities: List[str]) -> Optional[str]:
        """
        Find the best template match for given capabilities.
        
        Args:
            capabilities: List of capability names
            
        Returns:
            Optional[str]: Best matching template name
        """
        # Direct capability match
        for capability in capabilities:
            if capability in self.capability_templates:
                return self.capability_templates[capability]
        
        # Pattern matching
        for capability in capabilities:
            for cap_name, patterns in self.capability_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, capability, re.IGNORECASE):
                        return self.capability_templates.get(cap_name)
        
        return None


# Initialize default severity formatters
def initialize_default_severity_formatters(engine: AdaptiveTemplateEngine) -> None:
    """Initialize default severity-based formatters."""
    
    engine.register_severity_formatter('critical', {
        'css_class': 'severity-critical',
        'color': '#dc3545',
        'bg_color': '#f8d7da',
        'icon': '🚨',
        'border_color': '#dc3545'
    })
    
    engine.register_severity_formatter('high', {
        'css_class': 'severity-high',
        'color': '#fd7e14',
        'bg_color': '#fff3cd',
        'icon': '⚠️',
        'border_color': '#fd7e14'
    })
    
    engine.register_severity_formatter('medium', {
        'css_class': 'severity-medium',
        'color': '#ffc107',
        'bg_color': '#fff3cd',
        'icon': '⚡',
        'border_color': '#ffc107'
    })
    
    engine.register_severity_formatter('low', {
        'css_class': 'severity-low',
        'color': '#20c997',
        'bg_color': '#d1ecf1',
        'icon': 'ℹ️',
        'border_color': '#20c997'
    })
    
    engine.register_severity_formatter('minimal', {
        'css_class': 'severity-minimal',
        'color': '#6c757d',
        'bg_color': '#f8f9fa',
        'icon': '✓',
        'border_color': '#6c757d'
    }) 