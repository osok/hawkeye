"""
Reporting engine for HawkEye security reconnaissance tool.

This package provides comprehensive reporting capabilities including multiple
output formats (JSON, CSV, XML, HTML), executive summaries, data aggregation,
and template-based report generation.
"""

from .base import (
    ReportFormat,
    ReportType,
    ReportMetadata,
    ScanSummary,
    DetectionSummary,
    RiskSummary,
    ReportData,
    BaseReporter,
    ReportingError,
    FormatError,
    TemplateError
)
from .json_reporter import JSONReporter
from .csv_reporter import CSVReporter
from .xml_reporter import XMLReporter
from .html_reporter import HTMLReporter
from .aggregation import DataAggregator, TimeSeriesData, DistributionData
from .executive_summary import ExecutiveSummaryGenerator, ExecutiveFinding, ExecutiveMetrics

__all__ = [
    # Base Classes and Data Structures
    'ReportFormat',
    'ReportType', 
    'ReportMetadata',
    'ScanSummary',
    'DetectionSummary',
    'RiskSummary',
    'ReportData',
    'BaseReporter',
    
    # Exceptions
    'ReportingError',
    'FormatError',
    'TemplateError',
    
    # Report Generators
    'JSONReporter',
    'CSVReporter',
    'XMLReporter',
    'HTMLReporter',
    
    # Data Analysis
    'DataAggregator',
    'TimeSeriesData',
    'DistributionData',
    
    # Executive Summary
    'ExecutiveSummaryGenerator',
    'ExecutiveFinding',
    'ExecutiveMetrics',
] 