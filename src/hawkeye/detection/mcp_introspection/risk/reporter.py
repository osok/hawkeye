"""
Risk Assessment Reporting for MCP Introspection

Provides comprehensive reporting capabilities for MCP security risk assessments,
generating detailed reports with analysis, recommendations, and visualizations.
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

from ..models import (
    MCPServerInfo, SecurityRisk, RiskLevel, RiskCategory
)
from .threat_model import ThreatModel, ThreatVector, ThreatCategory
from .categorizer import RiskProfile, CategoryAnalysis, RiskCategorizer
from .scoring import CompositeRiskScore, ScoreBreakdown
from .schema_analyzer import SchemaAnalysisResult, SchemaRisk


class ReportFormat(str, Enum):
    """Supported report formats."""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    CSV = "csv"
    PDF = "pdf"


class ReportLevel(str, Enum):
    """Report detail levels."""
    SUMMARY = "summary"
    DETAILED = "detailed"
    COMPREHENSIVE = "comprehensive"


@dataclass
class RiskSummary:
    """Summary of risk assessment results."""
    total_servers: int
    total_risks: int
    critical_risks: int
    high_risks: int
    medium_risks: int
    low_risks: int
    minimal_risks: int
    average_risk_score: float
    highest_risk_server: Optional[str] = None
    most_common_risk_category: Optional[str] = None


@dataclass
class ServerRiskReport:
    """Risk report for a single server."""
    server_id: str
    server_name: Optional[str]
    server_url: Optional[str]
    assessment_timestamp: datetime
    overall_risk_level: RiskLevel
    risk_score: float
    total_risks: int
    risk_breakdown: Dict[RiskLevel, int] = field(default_factory=dict)
    category_breakdown: Dict[RiskCategory, int] = field(default_factory=dict)
    security_risks: List[SecurityRisk] = field(default_factory=list)
    threat_vectors: List[ThreatVector] = field(default_factory=list)
    schema_risks: List[SchemaRisk] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    mitigation_priorities: List[str] = field(default_factory=list)


@dataclass
class ComprehensiveRiskReport:
    """Comprehensive risk assessment report."""
    report_id: str
    generation_timestamp: datetime
    assessment_period: str
    report_level: ReportLevel
    summary: RiskSummary
    server_reports: List[ServerRiskReport] = field(default_factory=list)
    risk_trends: Dict[str, Any] = field(default_factory=dict)
    threat_landscape: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    executive_summary: str = ""
    technical_details: Dict[str, Any] = field(default_factory=dict)


class RiskReporter:
    """
    Generates comprehensive risk assessment reports for MCP introspection.
    
    Combines data from various risk analysis components to create detailed
    reports with actionable insights and recommendations.
    """
    
    def __init__(self):
        """Initialize the risk reporter."""
        self.logger = logging.getLogger(__name__)
        self._categorizer = RiskCategorizer()
    
    def generate_comprehensive_report(self, 
                                    servers: List[MCPServerInfo],
                                    threat_models: Optional[Dict[str, ThreatModel]] = None,
                                    risk_scores: Optional[Dict[str, CompositeRiskScore]] = None,
                                    schema_analyses: Optional[Dict[str, SchemaAnalysisResult]] = None,
                                    report_level: ReportLevel = ReportLevel.DETAILED) -> ComprehensiveRiskReport:
        """
        Generate a comprehensive risk assessment report.
        
        Args:
            servers: List of MCP servers analyzed
            threat_models: Optional threat models by server ID
            risk_scores: Optional composite risk scores by server ID
            schema_analyses: Optional schema analysis results by server ID
            report_level: Level of detail for the report
            
        Returns:
            Comprehensive risk assessment report
        """
        report_id = f"mcp_risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Generate server reports
        server_reports = []
        for server in servers:
            server_report = self._generate_server_report(
                server,
                threat_models.get(server.server_id) if threat_models else None,
                risk_scores.get(server.server_id) if risk_scores else None,
                schema_analyses.get(server.server_id) if schema_analyses else None
            )
            server_reports.append(server_report)
        
        # Generate summary
        summary = self._generate_risk_summary(server_reports)
        
        # Generate threat landscape analysis
        threat_landscape = self._analyze_threat_landscape(threat_models or {})
        
        # Generate risk trends
        risk_trends = self._analyze_risk_trends(server_reports)
        
        # Generate recommendations
        recommendations = self._generate_global_recommendations(server_reports, summary)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(summary, recommendations)
        
        # Generate technical details
        technical_details = self._generate_technical_details(server_reports, report_level)
        
        report = ComprehensiveRiskReport(
            report_id=report_id,
            generation_timestamp=datetime.now(),
            assessment_period=f"Assessment conducted on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            report_level=report_level,
            summary=summary,
            server_reports=server_reports,
            risk_trends=risk_trends,
            threat_landscape=threat_landscape,
            recommendations=recommendations,
            executive_summary=executive_summary,
            technical_details=technical_details
        )
        
        self.logger.info(f"Generated comprehensive risk report '{report_id}' for {len(servers)} servers")
        return report
    
    def export_report(self, report: ComprehensiveRiskReport, 
                     format: ReportFormat = ReportFormat.JSON,
                     output_path: Optional[str] = None) -> str:
        """
        Export report to specified format.
        
        Args:
            report: Risk assessment report to export
            format: Output format
            output_path: Optional output file path
            
        Returns:
            Exported report content or file path
        """
        if format == ReportFormat.JSON:
            return self._export_json(report, output_path)
        elif format == ReportFormat.MARKDOWN:
            return self._export_markdown(report, output_path)
        elif format == ReportFormat.HTML:
            return self._export_html(report, output_path)
        elif format == ReportFormat.CSV:
            return self._export_csv(report, output_path)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def generate_server_summary(self, server_report: ServerRiskReport) -> str:
        """Generate a summary for a single server."""
        summary_lines = [
            f"Server: {server_report.server_name or server_report.server_id}",
            f"Risk Level: {server_report.overall_risk_level.value.upper()}",
            f"Risk Score: {server_report.risk_score:.2f}/10.0",
            f"Total Risks: {server_report.total_risks}",
            ""
        ]
        
        if server_report.risk_breakdown:
            summary_lines.append("Risk Breakdown:")
            for level, count in server_report.risk_breakdown.items():
                if count > 0:
                    summary_lines.append(f"  {level.value.title()}: {count}")
            summary_lines.append("")
        
        if server_report.recommendations:
            summary_lines.append("Top Recommendations:")
            for i, rec in enumerate(server_report.recommendations[:3], 1):
                summary_lines.append(f"  {i}. {rec}")
        
        return "\n".join(summary_lines)
    
    def _generate_server_report(self, server: MCPServerInfo,
                               threat_model: Optional[ThreatModel] = None,
                               risk_score: Optional[CompositeRiskScore] = None,
                               schema_analysis: Optional[SchemaAnalysisResult] = None) -> ServerRiskReport:
        """Generate risk report for a single server."""
        
        # Collect all risks
        all_risks = server.security_risks.copy()
        
        # Calculate risk breakdown
        risk_breakdown = {}
        for level in RiskLevel:
            risk_breakdown[level] = sum(1 for risk in all_risks if risk.severity == level)
        
        # Calculate category breakdown
        category_breakdown = {}
        for risk in all_risks:
            try:
                category = RiskCategory(risk.category)
                category_breakdown[category] = category_breakdown.get(category, 0) + 1
            except ValueError:
                category_breakdown[RiskCategory.UNKNOWN] = category_breakdown.get(RiskCategory.UNKNOWN, 0) + 1
        
        # Determine overall risk level
        overall_risk_level = RiskLevel.MINIMAL
        if risk_score:
            overall_risk_level = risk_score.risk_level
        elif all_risks:
            # Find highest severity
            severities = [risk.severity for risk in all_risks]
            if RiskLevel.CRITICAL in severities:
                overall_risk_level = RiskLevel.CRITICAL
            elif RiskLevel.HIGH in severities:
                overall_risk_level = RiskLevel.HIGH
            elif RiskLevel.MEDIUM in severities:
                overall_risk_level = RiskLevel.MEDIUM
            elif RiskLevel.LOW in severities:
                overall_risk_level = RiskLevel.LOW
        
        # Generate recommendations
        recommendations = self._generate_server_recommendations(
            server, all_risks, threat_model, risk_score, schema_analysis
        )
        
        # Generate mitigation priorities
        mitigation_priorities = self._generate_mitigation_priorities(all_risks)
        
        return ServerRiskReport(
            server_id=server.server_id,
            server_name=getattr(server, 'name', None),
            server_url=getattr(server, 'server_url', None),
            assessment_timestamp=datetime.now(),
            overall_risk_level=overall_risk_level,
            risk_score=risk_score.overall_score if risk_score else 0.0,
            total_risks=len(all_risks),
            risk_breakdown=risk_breakdown,
            category_breakdown=category_breakdown,
            security_risks=all_risks,
            threat_vectors=threat_model.threat_vectors if threat_model else [],
            schema_risks=schema_analysis.schema_risks if schema_analysis else [],
            recommendations=recommendations,
            mitigation_priorities=mitigation_priorities
        )
    
    def _generate_risk_summary(self, server_reports: List[ServerRiskReport]) -> RiskSummary:
        """Generate overall risk summary."""
        total_servers = len(server_reports)
        total_risks = sum(report.total_risks for report in server_reports)
        
        # Count risks by severity
        critical_risks = sum(report.risk_breakdown.get(RiskLevel.CRITICAL, 0) for report in server_reports)
        high_risks = sum(report.risk_breakdown.get(RiskLevel.HIGH, 0) for report in server_reports)
        medium_risks = sum(report.risk_breakdown.get(RiskLevel.MEDIUM, 0) for report in server_reports)
        low_risks = sum(report.risk_breakdown.get(RiskLevel.LOW, 0) for report in server_reports)
        minimal_risks = sum(report.risk_breakdown.get(RiskLevel.MINIMAL, 0) for report in server_reports)
        
        # Calculate average risk score
        risk_scores = [report.risk_score for report in server_reports if report.risk_score > 0]
        average_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        # Find highest risk server
        highest_risk_server = None
        if server_reports:
            highest_risk_report = max(server_reports, key=lambda r: r.risk_score)
            highest_risk_server = highest_risk_report.server_name or highest_risk_report.server_id
        
        # Find most common risk category
        all_categories = []
        for report in server_reports:
            for category, count in report.category_breakdown.items():
                all_categories.extend([category] * count)
        
        most_common_risk_category = None
        if all_categories:
            from collections import Counter
            category_counts = Counter(all_categories)
            most_common_risk_category = category_counts.most_common(1)[0][0].value
        
        return RiskSummary(
            total_servers=total_servers,
            total_risks=total_risks,
            critical_risks=critical_risks,
            high_risks=high_risks,
            medium_risks=medium_risks,
            low_risks=low_risks,
            minimal_risks=minimal_risks,
            average_risk_score=average_risk_score,
            highest_risk_server=highest_risk_server,
            most_common_risk_category=most_common_risk_category
        )
    
    def _analyze_threat_landscape(self, threat_models: Dict[str, ThreatModel]) -> Dict[str, Any]:
        """Analyze the overall threat landscape."""
        if not threat_models:
            return {}
        
        all_threats = []
        for model in threat_models.values():
            all_threats.extend(model.threat_vectors)
        
        # Analyze threat categories
        from collections import Counter
        threat_categories = Counter(threat.category for threat in all_threats)
        
        # Analyze attack vectors
        attack_vectors = Counter(threat.attack_vector for threat in all_threats)
        
        # Find high-likelihood threats
        high_likelihood_threats = [t for t in all_threats if t.likelihood > 0.7]
        
        return {
            "total_threat_vectors": len(all_threats),
            "threat_categories": dict(threat_categories),
            "attack_vectors": dict(attack_vectors),
            "high_likelihood_threats": len(high_likelihood_threats),
            "average_likelihood": sum(t.likelihood for t in all_threats) / len(all_threats) if all_threats else 0.0
        }
    
    def _analyze_risk_trends(self, server_reports: List[ServerRiskReport]) -> Dict[str, Any]:
        """Analyze risk trends across servers."""
        if not server_reports:
            return {}
        
        # Risk distribution by server
        risk_distribution = {
            "by_server": {
                report.server_name or report.server_id: report.total_risks 
                for report in server_reports
            }
        }
        
        # Risk score distribution
        risk_scores = [report.risk_score for report in server_reports if report.risk_score > 0]
        if risk_scores:
            risk_distribution["score_statistics"] = {
                "min": min(risk_scores),
                "max": max(risk_scores),
                "average": sum(risk_scores) / len(risk_scores),
                "median": sorted(risk_scores)[len(risk_scores) // 2]
            }
        
        return risk_distribution
    
    def _generate_global_recommendations(self, server_reports: List[ServerRiskReport], 
                                       summary: RiskSummary) -> List[str]:
        """Generate global recommendations based on overall assessment."""
        recommendations = []
        
        # Critical risk recommendations
        if summary.critical_risks > 0:
            recommendations.append(
                f"URGENT: {summary.critical_risks} critical risks identified across "
                f"{summary.total_servers} servers. Immediate remediation required."
            )
        
        # High risk recommendations
        if summary.high_risks > 0:
            recommendations.append(
                f"HIGH PRIORITY: {summary.high_risks} high-severity risks require "
                "attention within 24-48 hours."
            )
        
        # Common category recommendations
        if summary.most_common_risk_category:
            recommendations.append(
                f"Focus on {summary.most_common_risk_category} risks as they are "
                "the most prevalent across your MCP infrastructure."
            )
        
        # Risk score recommendations
        if summary.average_risk_score > 7.0:
            recommendations.append(
                "Overall risk level is HIGH. Consider implementing comprehensive "
                "security controls and monitoring."
            )
        elif summary.average_risk_score > 4.0:
            recommendations.append(
                "Overall risk level is MEDIUM. Regular security reviews and "
                "improvements are recommended."
            )
        
        # Server-specific recommendations
        high_risk_servers = [
            report for report in server_reports 
            if report.overall_risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]
        
        if high_risk_servers:
            server_names = [r.server_name or r.server_id for r in high_risk_servers[:3]]
            recommendations.append(
                f"Prioritize security improvements for high-risk servers: {', '.join(server_names)}"
            )
        
        return recommendations
    
    def _generate_executive_summary(self, summary: RiskSummary, 
                                  recommendations: List[str]) -> str:
        """Generate executive summary."""
        lines = [
            "# MCP Security Risk Assessment - Executive Summary",
            "",
            f"This assessment analyzed {summary.total_servers} MCP servers and identified "
            f"{summary.total_risks} security risks.",
            "",
            "## Key Findings:",
            f"- Critical Risks: {summary.critical_risks}",
            f"- High Risks: {summary.high_risks}",
            f"- Medium Risks: {summary.medium_risks}",
            f"- Average Risk Score: {summary.average_risk_score:.2f}/10.0",
            ""
        ]
        
        if summary.critical_risks > 0:
            lines.extend([
                "## Immediate Action Required:",
                f"There are {summary.critical_risks} critical security risks that require "
                "immediate attention to prevent potential security incidents.",
                ""
            ])
        
        if recommendations:
            lines.extend([
                "## Top Recommendations:",
                ""
            ])
            for i, rec in enumerate(recommendations[:5], 1):
                lines.append(f"{i}. {rec}")
        
        return "\n".join(lines)
    
    def _generate_technical_details(self, server_reports: List[ServerRiskReport], 
                                  report_level: ReportLevel) -> Dict[str, Any]:
        """Generate technical details section."""
        if report_level == ReportLevel.SUMMARY:
            return {}
        
        details = {
            "methodology": {
                "analysis_components": [
                    "Dynamic tool risk analysis",
                    "Capability-based threat modeling",
                    "Risk categorization and scoring",
                    "Schema-based security analysis"
                ],
                "risk_scoring": "CVSS-like methodology with environmental factors",
                "threat_modeling": "Capability-based analysis with attack vector mapping"
            }
        }
        
        if report_level == ReportLevel.COMPREHENSIVE:
            details["detailed_findings"] = {
                "server_breakdown": [
                    {
                        "server_id": report.server_id,
                        "risk_score": report.risk_score,
                        "total_risks": report.total_risks,
                        "threat_vectors": len(report.threat_vectors),
                        "schema_risks": len(report.schema_risks)
                    }
                    for report in server_reports
                ]
            }
        
        return details
    
    def _generate_server_recommendations(self, server: MCPServerInfo,
                                       risks: List[SecurityRisk],
                                       threat_model: Optional[ThreatModel] = None,
                                       risk_score: Optional[CompositeRiskScore] = None,
                                       schema_analysis: Optional[SchemaAnalysisResult] = None) -> List[str]:
        """Generate recommendations for a specific server."""
        recommendations = []
        
        # Risk-based recommendations
        critical_risks = [r for r in risks if r.severity == RiskLevel.CRITICAL]
        if critical_risks:
            recommendations.append(
                f"CRITICAL: Address {len(critical_risks)} critical risks immediately"
            )
        
        # Category-specific recommendations
        categories = set(risk.category for risk in risks)
        for category in categories:
            if category == RiskCategory.CODE_EXECUTION.value:
                recommendations.append("Implement strict input validation and sandboxing for code execution")
            elif category == RiskCategory.FILE_SYSTEM.value:
                recommendations.append("Apply file access controls and path validation")
            elif category == RiskCategory.NETWORK_ACCESS.value:
                recommendations.append("Implement network segmentation and monitoring")
        
        # Threat model recommendations
        if threat_model:
            high_likelihood_threats = [t for t in threat_model.threat_vectors if t.likelihood > 0.7]
            if high_likelihood_threats:
                recommendations.append(
                    f"Address {len(high_likelihood_threats)} high-likelihood threat vectors"
                )
        
        # Schema analysis recommendations
        if schema_analysis and schema_analysis.schema_risks:
            critical_schema_risks = schema_analysis.get_critical_risks()
            if critical_schema_risks:
                recommendations.append(
                    f"Fix {len(critical_schema_risks)} critical schema vulnerabilities"
                )
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _generate_mitigation_priorities(self, risks: List[SecurityRisk]) -> List[str]:
        """Generate mitigation priorities based on risk analysis."""
        priorities = []
        
        # Prioritize by severity
        critical_risks = [r for r in risks if r.severity == RiskLevel.CRITICAL]
        high_risks = [r for r in risks if r.severity == RiskLevel.HIGH]
        
        if critical_risks:
            priorities.append(f"Priority 1: {len(critical_risks)} critical risks")
        if high_risks:
            priorities.append(f"Priority 2: {len(high_risks)} high risks")
        
        # Prioritize by category
        from collections import Counter
        categories = Counter(risk.category for risk in risks)
        
        for category, count in categories.most_common(3):
            priorities.append(f"Focus area: {category} ({count} risks)")
        
        return priorities
    
    def _export_json(self, report: ComprehensiveRiskReport, output_path: Optional[str] = None) -> str:
        """Export report as JSON."""
        # Convert dataclasses to dict for JSON serialization
        report_dict = self._convert_report_to_dict(report)
        
        json_content = json.dumps(report_dict, indent=2, default=str)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_content)
            return output_path
        
        return json_content
    
    def _export_markdown(self, report: ComprehensiveRiskReport, output_path: Optional[str] = None) -> str:
        """Export report as Markdown."""
        lines = [
            f"# MCP Security Risk Assessment Report",
            f"**Report ID:** {report.report_id}",
            f"**Generated:** {report.generation_timestamp}",
            f"**Assessment Period:** {report.assessment_period}",
            "",
            report.executive_summary,
            "",
            "## Risk Summary",
            f"- Total Servers: {report.summary.total_servers}",
            f"- Total Risks: {report.summary.total_risks}",
            f"- Critical: {report.summary.critical_risks}",
            f"- High: {report.summary.high_risks}",
            f"- Medium: {report.summary.medium_risks}",
            f"- Low: {report.summary.low_risks}",
            f"- Average Risk Score: {report.summary.average_risk_score:.2f}/10.0",
            "",
            "## Server Reports",
            ""
        ]
        
        for server_report in report.server_reports:
            lines.extend([
                f"### {server_report.server_name or server_report.server_id}",
                f"- Risk Level: **{server_report.overall_risk_level.value.upper()}**",
                f"- Risk Score: {server_report.risk_score:.2f}/10.0",
                f"- Total Risks: {server_report.total_risks}",
                ""
            ])
        
        if report.recommendations:
            lines.extend([
                "## Recommendations",
                ""
            ])
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
        
        markdown_content = "\n".join(lines)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(markdown_content)
            return output_path
        
        return markdown_content
    
    def _export_html(self, report: ComprehensiveRiskReport, output_path: Optional[str] = None) -> str:
        """Export report as HTML."""
        # Basic HTML template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MCP Security Risk Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>MCP Security Risk Assessment Report</h1>
            <p><strong>Report ID:</strong> {report.report_id}</p>
            <p><strong>Generated:</strong> {report.generation_timestamp}</p>
            
            <h2>Executive Summary</h2>
            <pre>{report.executive_summary}</pre>
            
            <h2>Risk Summary</h2>
            <ul>
                <li>Total Servers: {report.summary.total_servers}</li>
                <li>Total Risks: {report.summary.total_risks}</li>
                <li class="critical">Critical: {report.summary.critical_risks}</li>
                <li class="high">High: {report.summary.high_risks}</li>
                <li class="medium">Medium: {report.summary.medium_risks}</li>
                <li class="low">Low: {report.summary.low_risks}</li>
                <li>Average Risk Score: {report.summary.average_risk_score:.2f}/10.0</li>
            </ul>
            
            <h2>Server Reports</h2>
            <table>
                <tr>
                    <th>Server</th>
                    <th>Risk Level</th>
                    <th>Risk Score</th>
                    <th>Total Risks</th>
                </tr>
        """
        
        for server_report in report.server_reports:
            risk_class = server_report.overall_risk_level.value.lower()
            html_content += f"""
                <tr>
                    <td>{server_report.server_name or server_report.server_id}</td>
                    <td class="{risk_class}">{server_report.overall_risk_level.value.upper()}</td>
                    <td>{server_report.risk_score:.2f}</td>
                    <td>{server_report.total_risks}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(html_content)
            return output_path
        
        return html_content
    
    def _export_csv(self, report: ComprehensiveRiskReport, output_path: Optional[str] = None) -> str:
        """Export report as CSV."""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Server ID', 'Server Name', 'Risk Level', 'Risk Score', 
            'Total Risks', 'Critical', 'High', 'Medium', 'Low'
        ])
        
        # Write server data
        for server_report in report.server_reports:
            writer.writerow([
                server_report.server_id,
                server_report.server_name or '',
                server_report.overall_risk_level.value,
                f"{server_report.risk_score:.2f}",
                server_report.total_risks,
                server_report.risk_breakdown.get(RiskLevel.CRITICAL, 0),
                server_report.risk_breakdown.get(RiskLevel.HIGH, 0),
                server_report.risk_breakdown.get(RiskLevel.MEDIUM, 0),
                server_report.risk_breakdown.get(RiskLevel.LOW, 0)
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(csv_content)
            return output_path
        
        return csv_content
    
    def _convert_report_to_dict(self, report: ComprehensiveRiskReport) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        # This is a simplified conversion - in practice, you'd want more sophisticated handling
        return {
            "report_id": report.report_id,
            "generation_timestamp": report.generation_timestamp.isoformat(),
            "assessment_period": report.assessment_period,
            "report_level": report.report_level.value,
            "summary": asdict(report.summary),
            "server_reports": [asdict(sr) for sr in report.server_reports],
            "risk_trends": report.risk_trends,
            "threat_landscape": report.threat_landscape,
            "recommendations": report.recommendations,
            "executive_summary": report.executive_summary,
            "technical_details": report.technical_details
        }
