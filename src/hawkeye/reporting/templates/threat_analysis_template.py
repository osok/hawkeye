"""
Threat analysis template for showing how detected MCP tools could be abused by attackers.

This template creates detailed security threat analysis reports that help developers
understand potential attack vectors and abuse scenarios for detected MCP servers.
"""

from typing import Dict, Any, List
from .base import BaseTemplate
from ..base import ReportData


class ThreatAnalysisTemplate(BaseTemplate):
    """Threat analysis template for security awareness and attack vector documentation."""
    
    def __init__(self):
        """Initialize threat analysis template."""
        super().__init__("threat_analysis")
    
    def get_template_content(self) -> str:
        """Get threat analysis HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 HawkEye Security Threat Analysis Report</title>
    <style>$css_content</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 HawkEye Security Threat Analysis Report</h1>
            <div class="subtitle">Attack Vector Analysis for Detected MCP Tools</div>
            <div class="warning-banner">
                ⚠️ <strong>SECURITY AWARENESS DOCUMENT</strong> - For Educational and Defense Purposes Only
            </div>
            <div class="metadata">
                <span><strong>Analysis Date:</strong> $scan_date</span> |
                <span><strong>Threat Level:</strong> $overall_threat_level</span>
            </div>
        </div>
        
        <div class="section executive-summary">
            <h2>🎯 Executive Threat Summary</h2>
            <div class="threat-overview">
                <div class="threat-card critical">
                    <div class="number">$critical_threats</div>
                    <div class="label">Critical Attack Vectors</div>
                </div>
                <div class="threat-card high">
                    <div class="number">$high_threats</div>
                    <div class="label">High-Risk Scenarios</div>
                </div>
                <div class="threat-card medium">
                    <div class="number">$medium_threats</div>
                    <div class="label">Medium-Risk Vectors</div>
                </div>
                <div class="threat-card low">
                    <div class="number">$low_threats</div>
                    <div class="label">Low-Risk Scenarios</div>
                </div>
            </div>
            
            <div class="key-findings">
                <h3>🔥 Key Attack Scenarios Identified</h3>
                $key_attack_scenarios
            </div>
        </div>
        
        <div class="section detected-servers">
            <h2>🖥️ Detected Servers and Tools</h2>
            <div class="servers-intro">
                <p>The following MCP servers and their associated tools were discovered during the reconnaissance scan:</p>
            </div>
            $detected_servers_analysis
        </div>
        
        <div class="section attack-vectors">
            <h2>⚔️ Detailed Attack Vector Analysis</h2>
            $attack_vector_analysis
        </div>
        
        <div class="section abuse-scenarios">
            <h2>🎭 Tool Abuse Scenarios</h2>
            $abuse_scenarios_analysis
        </div>
        
        <div class="section attack-chains">
            <h2>🔗 Attack Chain Analysis</h2>
            <div class="attack-chain-intro">
                <p>The following attack chains show how multiple MCP tools could be combined for sophisticated attacks:</p>
            </div>
            $attack_chains_analysis
        </div>
        
        <div class="section mitigation-strategies">
            <h2>🛡️ Mitigation Strategies</h2>
            <div class="mitigation-intro">
                <p>Recommended security controls to prevent or detect the identified attack vectors:</p>
            </div>
            $mitigation_strategies
        </div>
        
        <div class="section detection-indicators">
            <h2>🔍 Attack Detection Indicators</h2>
            <div class="detection-intro">
                <p>Signs that these attack vectors may be actively exploited:</p>
            </div>
            $detection_indicators
        </div>
        
        <div class="section security-recommendations">
            <h2>📋 Security Hardening Recommendations</h2>
            $security_recommendations
        </div>
        
        <div class="section compliance-impact">
            <h2>📊 Compliance and Risk Impact</h2>
            $compliance_impact
        </div>
        
        <div class="footer">
            <div class="disclaimer">
                <h4>⚖️ Legal Disclaimer</h4>
                <p>This threat analysis is provided for educational and defensive security purposes only. 
                Any use of this information for malicious purposes is strictly prohibited and may be illegal. 
                Organizations should use this analysis to improve their security posture and awareness.</p>
            </div>
            <p>Report generated by HawkEye Security Reconnaissance Tool</p>
            <p>Template: $template_name | Generated: $render_time</p>
        </div>
    </div>
    
    <script>$js_content</script>
</body>
</html>
        """
    
    def get_css_content(self) -> str:
        """Get CSS styles for threat analysis template."""
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
            border-bottom: 3px solid #dc3545;
        }
        
        .header h1 {
            font-size: 2.5em;
            color: #dc3545;
            margin-bottom: 10px;
        }
        
        .subtitle {
            font-size: 1.2em;
            color: #666;
            margin-bottom: 15px;
        }
        
        .warning-banner {
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: white;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-weight: bold;
            text-align: center;
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
            border-left: 4px solid #dc3545;
        }
        
        .section h2 {
            color: #dc3545;
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
        
        .threat-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .threat-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            color: white;
        }
        
        .threat-card.critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .threat-card.high { background: linear-gradient(135deg, #e67e22, #d35400); }
        .threat-card.medium { background: linear-gradient(135deg, #f39c12, #e67e22); }
        .threat-card.low { background: linear-gradient(135deg, #3498db, #2980b9); }
        
        .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .attack-vector {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            background: #f8f9fa;
        }
        
        .attack-vector h3 {
            color: #dc3545;
            margin-bottom: 15px;
        }
        
        .threat-level {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .threat-level.critical { background: #e74c3c; color: white; }
        .threat-level.high { background: #e67e22; color: white; }
        .threat-level.medium { background: #f39c12; color: white; }
        .threat-level.low { background: #3498db; color: white; }
        
        .attack-steps {
            background: white;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
        
        .attack-steps h4 {
            color: #dc3545;
            margin-bottom: 10px;
        }
        
        .attack-steps ol {
            padding-left: 20px;
        }
        
        .attack-steps li {
            margin-bottom: 8px;
            padding: 5px 0;
        }
        
        .code-example {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            overflow-x: auto;
        }
        
        .mitigation-item {
            background: #e8f5e8;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .mitigation-item h4 {
            color: #155724;
            margin-bottom: 10px;
        }
        
        .detection-item {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 10px 0;
        }
        
        .detection-item h4 {
            color: #856404;
            margin-bottom: 10px;
        }
        
        .attack-chain {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .attack-chain h4 {
            color: #721c24;
            margin-bottom: 15px;
        }
        
        .chain-steps {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .chain-step {
            background: white;
            padding: 10px 15px;
            border-radius: 4px;
            border: 1px solid #dee2e6;
            flex: 1;
            min-width: 150px;
            text-align: center;
        }
        
        .chain-arrow {
            font-size: 1.5em;
            color: #dc3545;
            font-weight: bold;
        }
        
        .key-findings {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .key-findings h3 {
            color: #0c5460;
            margin-bottom: 15px;
        }
        
        .server-item {
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin: 20px 0;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .server-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f8f9fa;
        }
        
        .server-name {
            font-size: 1.3em;
            font-weight: bold;
            color: #495057;
        }
        
        .server-type {
            background: #6c757d;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            text-transform: uppercase;
        }
        
        .server-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .server-detail {
            padding: 8px 0;
        }
        
        .server-detail strong {
            color: #495057;
        }
        
        .tools-section {
            margin-top: 20px;
        }
        
        .tools-header {
            background: #f8f9fa;
            padding: 10px 15px;
            border-radius: 6px 6px 0 0;
            font-weight: bold;
            color: #495057;
            margin-bottom: 0;
        }
        
        .tools-table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #dee2e6;
            border-radius: 0 0 6px 6px;
            overflow: hidden;
        }
        
        .tools-table th,
        .tools-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .tools-table th {
            background: #f8f9fa;
            font-weight: bold;
            color: #495057;
        }
        
        .tools-table tr:last-child td {
            border-bottom: none;
        }
        
        .tools-table tr:hover {
            background: #f8f9fa;
        }
        
        .no-tools {
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-style: italic;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 0 0 6px 6px;
        }
        
        .disclaimer {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .disclaimer h4 {
            color: #495057;
            margin-bottom: 10px;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #dee2e6;
            color: #666;
            font-size: 0.9em;
        }
        
        .alert {
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
        }
        
        .alert.danger {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .alert.warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        
        .alert.info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        
        ul, ol {
            padding-left: 20px;
        }
        
        li {
            margin-bottom: 5px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .threat-overview {
                grid-template-columns: 1fr;
            }
            
            .chain-steps {
                flex-direction: column;
            }
            
            .chain-arrow {
                transform: rotate(90deg);
            }
            
            .server-details {
                grid-template-columns: 1fr;
            }
            
            .server-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .tools-table {
                font-size: 0.9em;
            }
            
            .tools-table th,
            .tools-table td {
                padding: 8px 10px;
            }
        }
        """
    
    def get_js_content(self) -> str:
        """Get JavaScript for interactive features."""
        return """
        document.addEventListener('DOMContentLoaded', function() {
            // Add expandable sections
            const sections = document.querySelectorAll('.attack-vector h3');
            sections.forEach(section => {
                section.style.cursor = 'pointer';
                section.addEventListener('click', function() {
                    const content = this.parentElement.querySelector('.attack-details');
                    if (content) {
                        content.style.display = content.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });
            
            // Add copy functionality for code examples
            const codeBlocks = document.querySelectorAll('.code-example');
            codeBlocks.forEach(block => {
                const copyBtn = document.createElement('button');
                copyBtn.textContent = 'Copy';
                copyBtn.style.cssText = 'position: absolute; top: 5px; right: 5px; padding: 5px 10px; background: #4a5568; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 0.8em;';
                
                block.style.position = 'relative';
                block.appendChild(copyBtn);
                
                copyBtn.addEventListener('click', function() {
                    navigator.clipboard.writeText(block.textContent.replace('Copy', '').trim());
                    copyBtn.textContent = 'Copied!';
                    setTimeout(() => copyBtn.textContent = 'Copy', 2000);
                });
            });
            
            // Add warning confirmations for dangerous examples
            const dangerousExamples = document.querySelectorAll('.code-example[data-danger="true"]');
            dangerousExamples.forEach(example => {
                example.addEventListener('click', function() {
                    if (!this.dataset.confirmed) {
                        const confirmed = confirm('This example shows potentially dangerous attack techniques. Are you sure you want to view it? (For educational/defensive purposes only)');
                        if (confirmed) {
                            this.dataset.confirmed = 'true';
                        } else {
                            this.style.filter = 'blur(5px)';
                        }
                    }
                });
            });
        });
        """ 