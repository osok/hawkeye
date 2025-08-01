"""
Concrete HTML template implementations for different report types.

This module provides specialized HTML templates for executive summaries,
technical reports, vulnerability reports, and compliance reports.
"""

from typing import Dict, Any
from .base import BaseTemplate
from ..base import ReportData


class ExecutiveSummaryTemplate(BaseTemplate):
    """Executive summary template for high-level overview reports."""
    
    def __init__(self):
        """Initialize executive summary template."""
        super().__init__("executive_summary")
    
    def get_template_content(self) -> str:
        """Get executive summary HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HawkEye Security Assessment - Executive Summary</title>
    <style>$css_content</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 HawkEye Security Assessment</h1>
            <div class="subtitle">Executive Summary Report</div>
            <div class="subtitle">Generated: $render_time</div>
        </div>
        
        <div class="section">
            <h2>📊 Assessment Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">$total_targets</div>
                    <div class="label">Total Targets Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="number">$critical_findings</div>
                    <div class="label">Critical Findings</div>
                </div>
                <div class="stat-card">
                    <div class="number">$high_risk_targets</div>
                    <div class="label">High Risk Targets</div>
                </div>
                <div class="stat-card">
                    <div class="number">${scan_summary}</div>
                    <div class="label">Scan Duration</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Key Findings</h2>
            <div class="alert alert-critical">
                <h3>Critical Security Issues</h3>
                <p>$critical_findings critical security issues were identified that require immediate attention.</p>
            </div>
            
            <h3>Risk Distribution</h3>
            $risk_summary
        </div>
        
        <div class="section">
            <h2>🔍 Detection Summary</h2>
            $detection_summary
        </div>
        
        <div class="section">
            <h2>📋 Executive Summary</h2>
            $executive_summary
        </div>
        
        <div class="section recommendations">
            <h2>🚀 Priority Recommendations</h2>
            <h3>Immediate Actions Required</h3>
            $recommendations
        </div>
        
        <div class="footer">
            <p>Report generated by HawkEye Security Reconnaissance Tool</p>
            <p>Template: $template_name | Generated: $render_time</p>
        </div>
    </div>
    
    <script>$js_content</script>
</body>
</html>
        """


class TechnicalReportTemplate(BaseTemplate):
    """Technical report template for detailed technical analysis."""
    
    def __init__(self):
        """Initialize technical report template."""
        super().__init__("technical_report")
    
    def get_template_content(self) -> str:
        """Get technical report HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HawkEye Security Assessment - Technical Report</title>
    <style>$css_content</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 HawkEye Security Assessment</h1>
            <div class="subtitle">Technical Analysis Report</div>
            <div class="subtitle">Generated: $render_time</div>
        </div>
        
        <div class="section">
            <h2>📋 Report Metadata</h2>
            $metadata
        </div>
        
        <div class="section">
            <h2>🌐 Network Scan Results</h2>
            <h3>Scan Summary</h3>
            $scan_summary
            
            <h3>Detailed Scan Results</h3>
            $scan_results
        </div>
        
        <div class="section">
            <h2>🔍 MCP Detection Results</h2>
            <h3>Detection Summary</h3>
            $detection_summary
            
            <h3>Detailed Detection Results</h3>
            $detection_results
        </div>
        
        <div class="section">
            <h2>⚠️ Risk Assessment</h2>
            <h3>Risk Summary</h3>
            $risk_summary
            
            <h3>Detailed Assessment Results</h3>
            $assessment_results
        </div>
        
        <div class="section">
            <h2>📊 Statistical Analysis</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">$total_targets</div>
                    <div class="label">Total Targets</div>
                </div>
                <div class="stat-card">
                    <div class="number">$critical_findings</div>
                    <div class="label">Critical Findings</div>
                </div>
                <div class="stat-card">
                    <div class="number">$high_risk_targets</div>
                    <div class="label">High Risk Targets</div>
                </div>
            </div>
        </div>
        
        <div class="section recommendations">
            <h2>🛠️ Technical Recommendations</h2>
            $recommendations
        </div>
        
        <div class="footer">
            <p>Report generated by HawkEye Security Reconnaissance Tool</p>
            <p>Template: $template_name | Generated: $render_time</p>
        </div>
    </div>
    
    <script>$js_content</script>
</body>
</html>
        """


class VulnerabilityReportTemplate(BaseTemplate):
    """Vulnerability report template focused on security issues."""
    
    def __init__(self):
        """Initialize vulnerability report template."""
        super().__init__("vulnerability_report")
    
    def get_template_content(self) -> str:
        """Get vulnerability report HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HawkEye Security Assessment - Vulnerability Report</title>
    <style>$css_content</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 HawkEye Security Assessment</h1>
            <div class="subtitle">Vulnerability Analysis Report</div>
            <div class="subtitle">Generated: $render_time</div>
        </div>
        
        <div class="section">
            <h2>🚨 Critical Vulnerabilities</h2>
            <div class="alert alert-critical">
                <h3>Immediate Action Required</h3>
                <p>$critical_findings critical vulnerabilities detected requiring immediate remediation.</p>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Vulnerability Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">$critical_findings</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="number">$high_risk_targets</div>
                    <div class="label">High Risk</div>
                </div>
                <div class="stat-card">
                    <div class="number">$total_targets</div>
                    <div class="label">Total Targets</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 MCP Server Vulnerabilities</h2>
            <h3>Detection Results</h3>
            $detection_results
            
            <h3>Risk Assessment</h3>
            $assessment_results
        </div>
        
        <div class="section">
            <h2>📈 Risk Analysis</h2>
            $risk_summary
        </div>
        
        <div class="section recommendations">
            <h2>🛡️ Security Recommendations</h2>
            <h3>Priority Actions</h3>
            $recommendations
        </div>
        
        <div class="section">
            <h2>📋 Remediation Checklist</h2>
            <div class="alert alert-medium">
                <h3>Recommended Actions</h3>
                <ol>
                    <li>Address all critical vulnerabilities immediately</li>
                    <li>Implement network segmentation for MCP servers</li>
                    <li>Enable authentication and encryption</li>
                    <li>Monitor for unauthorized MCP deployments</li>
                    <li>Establish security policies for MCP usage</li>
                </ol>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by HawkEye Security Reconnaissance Tool</p>
            <p>Template: $template_name | Generated: $render_time</p>
        </div>
    </div>
    
    <script>$js_content</script>
</body>
</html>
        """


class ComplianceReportTemplate(BaseTemplate):
    """Compliance report template for regulatory requirements."""
    
    def __init__(self):
        """Initialize compliance report template."""
        super().__init__("compliance_report")
    
    def get_template_content(self) -> str:
        """Get compliance report HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HawkEye Security Assessment - Compliance Report</title>
    <style>$css_content</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 HawkEye Security Assessment</h1>
            <div class="subtitle">Compliance Analysis Report</div>
            <div class="subtitle">Generated: $render_time</div>
        </div>
        
        <div class="section">
            <h2>📋 Compliance Overview</h2>
            <p>This report analyzes MCP server deployments for compliance with security standards and regulatory requirements.</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="number">$total_targets</div>
                    <div class="label">Systems Assessed</div>
                </div>
                <div class="stat-card">
                    <div class="number">$critical_findings</div>
                    <div class="label">Compliance Issues</div>
                </div>
                <div class="stat-card">
                    <div class="number">$high_risk_targets</div>
                    <div class="label">High Risk Systems</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Assessment Results</h2>
            <h3>Scan Summary</h3>
            $scan_summary
            
            <h3>Detection Summary</h3>
            $detection_summary
            
            <h3>Risk Assessment</h3>
            $risk_summary
        </div>
        
        <div class="section">
            <h2>⚖️ Compliance Analysis</h2>
            <div class="alert alert-medium">
                <h3>Key Compliance Considerations</h3>
                <ul>
                    <li><strong>Data Protection:</strong> MCP servers may process sensitive data</li>
                    <li><strong>Access Control:</strong> Unauthorized access to AI capabilities</li>
                    <li><strong>Audit Trail:</strong> Logging and monitoring requirements</li>
                    <li><strong>Encryption:</strong> Data in transit and at rest protection</li>
                    <li><strong>Network Security:</strong> Proper network segmentation</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Detailed Findings</h2>
            <h3>Detection Results</h3>
            $detection_results
            
            <h3>Assessment Results</h3>
            $assessment_results
        </div>
        
        <div class="section recommendations">
            <h2>📝 Compliance Recommendations</h2>
            <h3>Required Actions for Compliance</h3>
            $recommendations
            
            <div class="alert alert-low">
                <h3>Best Practices</h3>
                <ol>
                    <li>Implement proper authentication mechanisms</li>
                    <li>Enable comprehensive logging and monitoring</li>
                    <li>Establish data governance policies</li>
                    <li>Regular security assessments and audits</li>
                    <li>Staff training on MCP security requirements</li>
                </ol>
            </div>
        </div>
        
        <div class="section">
            <h2>📄 Executive Summary</h2>
            $executive_summary
        </div>
        
        <div class="footer">
            <p>Report generated by HawkEye Security Reconnaissance Tool</p>
            <p>Template: $template_name | Generated: $render_time</p>
            <p><em>This report is intended for compliance assessment purposes only.</em></p>
        </div>
    </div>
    
    <script>$js_content</script>
</body>
</html>
        """
    
    def get_css_content(self) -> str:
        """Get enhanced CSS for compliance reports."""
        base_css = super().get_css_content()
        compliance_css = """
        
        /* Compliance-specific styles */
        .compliance-section {
            background-color: #f8f9fa;
            border-left: 4px solid #6c757d;
            padding: 20px;
            margin: 20px 0;
        }
        
        .compliance-status {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .compliance-pass {
            background-color: #d4edda;
            color: #155724;
        }
        
        .compliance-fail {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        .compliance-warning {
            background-color: #fff3cd;
            color: #856404;
        }
        
        .requirement-list {
            list-style-type: none;
            padding-left: 0;
        }
        
        .requirement-list li {
            padding: 10px;
            margin: 5px 0;
            border-left: 3px solid #dee2e6;
            background-color: #f8f9fa;
        }
        
        .requirement-list li.critical {
            border-left-color: #dc3545;
        }
        
        .requirement-list li.important {
            border-left-color: #ffc107;
        }
        
        .requirement-list li.recommended {
            border-left-color: #28a745;
        }
        """
        
        return base_css + compliance_css 