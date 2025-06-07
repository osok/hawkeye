"""
HTML report templates for HawkEye security reconnaissance tool.

This package contains HTML templates and template management functionality
for generating professional, formatted HTML reports with charts, tables,
and interactive elements.
"""

from .base import BaseTemplate, TemplateEngine, TemplateError
from .html_templates import (
    ExecutiveSummaryTemplate,
    TechnicalReportTemplate,
    VulnerabilityReportTemplate,
    ComplianceReportTemplate
)

__all__ = [
    # Base Template Classes
    'BaseTemplate',
    'TemplateEngine', 
    'TemplateError',
    
    # HTML Templates
    'ExecutiveSummaryTemplate',
    'TechnicalReportTemplate',
    'VulnerabilityReportTemplate',
    'ComplianceReportTemplate',
] 