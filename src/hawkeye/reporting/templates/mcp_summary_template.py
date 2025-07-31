"""
MCP-specific report template for generating comprehensive, readable summaries.

This template creates detailed analysis reports specifically for MCP server detection
results, including server identification, tool analysis, and security assessments.
"""

from typing import Dict, Any, List
from .base import BaseTemplate
from ..base import ReportData


class MCPSummaryTemplate(BaseTemplate):
    """MCP-specific summary template for detailed analysis reports."""
    
    def __init__(self):
        """Initialize MCP summary template."""
        super().__init__("mcp_summary")
    
    def get_template_content(self) -> str:
        """Get MCP summary HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🦅 HawkEye MCP Detection Summary Report</title>
    <style>$css_content</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 HawkEye MCP Detection Summary Report</h1>
            <div class="subtitle">$scan_target</div>
            <div class="metadata">
                <span><strong>Scan Date:</strong> $scan_date</span> |
                <span><strong>Duration:</strong> $scan_duration</span> |
                <span><strong>Total Detections:</strong> $total_detections</span>
            </div>
        </div>
        
        <div class="section executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card success">
                    <div class="number">$confirmed_mcp_servers</div>
                    <div class="label">Confirmed MCP Servers</div>
                </div>
                <div class="summary-card info">
                    <div class="number">$total_detections</div>
                    <div class="label">Total Detections</div>
                </div>
                <div class="summary-card warning">
                    <div class="number">$false_positives</div>
                    <div class="label">False Positives</div>
                </div>
                <div class="summary-card $security_status_class">
                    <div class="label-large">$security_status</div>
                    <div class="label">Security Posture</div>
                </div>
            </div>
            
            <div class="detection-methods">
                <h3>Detection Methods Used</h3>
                <ul>
                    $detection_methods_list
                </ul>
            </div>
        </div>
        
        <div class="section mcp-servers">
            <h2>🔍 Detailed MCP Server Analysis</h2>
            $mcp_servers_analysis
        </div>
        
        <div class="section false-positives" style="$false_positives_display">
            <h2>🚨 False Positive Detections</h2>
            $false_positives_analysis
        </div>
        
        <div class="section additional-detections" style="$additional_detections_display">
            <h2>🐳 Additional Detections</h2>
            $additional_detections_analysis
        </div>
        
        <div class="section security-assessment">
            <h2>🛡️ Security Assessment</h2>
            <div class="risk-summary">
                <h3>Risk Distribution</h3>
                <div class="risk-grid">
                    <div class="risk-card high">
                        <div class="number">$high_risk_count</div>
                        <div class="label">High Risk</div>
                    </div>
                    <div class="risk-card medium">
                        <div class="number">$medium_risk_count</div>
                        <div class="label">Medium Risk</div>
                    </div>
                    <div class="risk-card low">
                        <div class="number">$low_risk_count</div>
                        <div class="label">Low Risk</div>
                    </div>
                    <div class="risk-card none">
                        <div class="number">$no_risk_count</div>
                        <div class="label">No Risk</div>
                    </div>
                </div>
            </div>
            
            <div class="security-implications">
                <h3>Security Implications</h3>
                $security_implications
            </div>
            
            <div class="recommendations">
                <h3>Recommendations</h3>
                $security_recommendations
            </div>
        </div>
        
        <div class="section performance-metrics">
            <h2>📈 Performance Metrics</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="number">$total_processes_scanned</div>
                    <div class="label">Total Processes Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="number">$nodejs_processes_found</div>
                    <div class="label">Node.js Processes Found</div>
                </div>
                <div class="metric-card">
                    <div class="number">$mcp_indicators_detected</div>
                    <div class="label">MCP Indicators Detected</div>
                </div>
                <div class="metric-card">
                    <div class="number">$scan_efficiency</div>
                    <div class="label">Scan Efficiency</div>
                </div>
            </div>
        </div>
        
        <div class="section technical-details">
            <h2>🔧 Technical Details</h2>
            <div class="tech-summary">
                <div class="tech-section">
                    <h4>Detection Methods</h4>
                    <ul>
                        $technical_detection_methods
                    </ul>
                </div>
                <div class="tech-section">
                    <h4>Transport Protocols</h4>
                    <ul>
                        $transport_protocols
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="section conclusions">
            <h2>💡 Conclusions</h2>
            <div class="conclusion-content">
                $conclusions_content
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
    
    def get_css_content(self) -> str:
        """Get CSS styles for MCP summary template."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px 0;
            border-bottom: 3px solid #007bff;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: #007bff;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 1.2em;
            color: #666;
            margin-bottom: 5px;
        }
        
        .metadata {
            font-size: 0.9em;
            color: #888;
            margin-top: 15px;
        }
        
        .section {
            margin-bottom: 40px;
            padding: 20px;
            border-radius: 8px;
            background: #fff;
            border-left: 4px solid #007bff;
        }
        
        .section h2 {
            color: #007bff;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .section h3 {
            color: #333;
            margin: 20px 0 15px 0;
            font-size: 1.3em;
        }
        
        .section h4 {
            color: #555;
            margin: 15px 0 10px 0;
            font-size: 1.1em;
        }
        
        .summary-grid, .risk-grid, .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .summary-card, .risk-card, .metric-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .summary-card.success { background: linear-gradient(135deg, #28a745, #20c997); color: white; }
        .summary-card.info { background: linear-gradient(135deg, #17a2b8, #007bff); color: white; }
        .summary-card.warning { background: linear-gradient(135deg, #ffc107, #fd7e14); color: white; }
        .summary-card.good { background: linear-gradient(135deg, #28a745, #20c997); color: white; }
        .summary-card.fair { background: linear-gradient(135deg, #ffc107, #fd7e14); color: white; }
        .summary-card.poor { background: linear-gradient(135deg, #dc3545, #e83e8c); color: white; }
        
        .risk-card.high { background: linear-gradient(135deg, #dc3545, #e83e8c); color: white; }
        .risk-card.medium { background: linear-gradient(135deg, #ffc107, #fd7e14); color: white; }
        .risk-card.low { background: linear-gradient(135deg, #17a2b8, #007bff); color: white; }
        .risk-card.none { background: linear-gradient(135deg, #28a745, #20c997); color: white; }
        
        .metric-card {
            background: linear-gradient(135deg, #6f42c1, #007bff);
            color: white;
        }
        
        .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .label-large {
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .mcp-server {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            background: #f8f9fa;
        }
        
        .mcp-server h3 {
            color: #007bff;
            margin-bottom: 15px;
        }
        
        .server-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .detail-item {
            background: white;
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #007bff;
        }
        
        .detail-label {
            font-weight: bold;
            color: #555;
            font-size: 0.9em;
        }
        
        .detail-value {
            color: #333;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .tools-list {
            background: white;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }
        
        .tools-list h4 {
            color: #007bff;
            margin-bottom: 10px;
        }
        
        .tools-list ul {
            list-style: none;
            padding: 0;
        }
        
        .tools-list li {
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }
        
        .tools-list li:last-child {
            border-bottom: none;
        }
        
        .tool-name {
            font-weight: bold;
            color: #007bff;
        }
        
        .tool-description {
            color: #666;
            font-size: 0.9em;
            margin-left: 10px;
        }
        
        .security-note {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 10px;
            margin-top: 10px;
        }
        
        .security-note.high {
            background: #f8d7da;
            border-color: #f5c6cb;
        }
        
        .security-note.low {
            background: #d1ecf1;
            border-color: #bee5eb;
        }
        
        .tech-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .tech-section {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
        }
        
        .conclusion-content {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #dee2e6;
            color: #666;
            font-size: 0.9em;
        }
        
        ul {
            padding-left: 20px;
        }
        
        li {
            margin-bottom: 5px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
        
        .alert.success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .alert.warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        
        .alert.danger {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-grid, .risk-grid, .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .server-details {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def get_js_content(self) -> str:
        """Get JavaScript for interactive features."""
        return """
        // Add interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Add click handlers for expandable sections
            const sections = document.querySelectorAll('.section h2');
            sections.forEach(section => {
                section.style.cursor = 'pointer';
                section.addEventListener('click', function() {
                    const content = this.parentElement.querySelector('.section-content');
                    if (content) {
                        content.style.display = content.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });
            
            // Add tooltips for technical terms
            const tooltips = document.querySelectorAll('[data-tooltip]');
            tooltips.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    const tooltip = document.createElement('div');
                    tooltip.className = 'tooltip';
                    tooltip.textContent = this.getAttribute('data-tooltip');
                    document.body.appendChild(tooltip);
                    
                    const rect = this.getBoundingClientRect();
                    tooltip.style.left = rect.left + 'px';
                    tooltip.style.top = (rect.top - 30) + 'px';
                });
                
                element.addEventListener('mouseleave', function() {
                    const tooltip = document.querySelector('.tooltip');
                    if (tooltip) {
                        tooltip.remove();
                    }
                });
            });
        });
        """ 