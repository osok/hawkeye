"""
HTML report templates for HawkEye security reconnaissance tool.

This package contains HTML templates and template management functionality
for generating professional, formatted HTML reports with charts, tables,
and interactive elements.
"""

from .base import (
    BaseTemplate, TemplateEngine, TemplateError,
    AdaptiveTemplateEngine, TemplateCapabilityMatcher,
    initialize_default_severity_formatters
)
from .html_templates import (
    ExecutiveSummaryTemplate,
    TechnicalReportTemplate,
    VulnerabilityReportTemplate,
    ComplianceReportTemplate
)
from .mcp_summary_template import MCPSummaryTemplate
from .threat_analysis_template import ThreatAnalysisTemplate

__all__ = [
    # Base Template Classes
    'BaseTemplate',
    'TemplateEngine',
    'AdaptiveTemplateEngine',
    'TemplateCapabilityMatcher', 
    'TemplateError',
    'initialize_default_severity_formatters',
    
    # HTML Templates
    'ExecutiveSummaryTemplate',
    'TechnicalReportTemplate',
    'VulnerabilityReportTemplate',
    'ComplianceReportTemplate',
    'MCPSummaryTemplate',
    'ThreatAnalysisTemplate',
] 