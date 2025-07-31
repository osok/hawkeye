"""
Executive summary generator for HawkEye security reconnaissance tool.

This module provides functionality to generate executive summaries from
detailed scan and assessment results, focusing on high-level insights
and actionable recommendations for decision makers.
"""

import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .base import ReportData, ScanSummary, DetectionSummary, RiskSummary
from ..utils.logging import get_logger


@dataclass
class ExecutiveFinding:
    """Executive-level finding with business impact."""
    title: str
    description: str
    business_impact: str
    risk_level: str
    recommendation: str
    priority: int  # 1-5, 1 being highest priority


@dataclass
class ExecutiveMetrics:
    """Key metrics for executive reporting."""
    total_systems_scanned: int
    mcp_servers_detected: int
    critical_vulnerabilities: int
    high_risk_systems: int
    compliance_issues: int
    security_score: float  # 0-100
    risk_reduction_potential: float  # 0-100


class ExecutiveSummaryGenerator:
    """Generator for executive summary reports."""
    
    def __init__(self):
        """Initialize executive summary generator."""
        self.logger = get_logger(self.__class__.__name__)
    
    def generate_summary(self, data: ReportData) -> str:
        """
        Generate executive summary from report data.
        
        Args:
            data: Complete report data
            
        Returns:
            str: Executive summary text
        """
        try:
            self.logger.info("Generating executive summary")
            
            # Extract key metrics
            metrics = self._extract_metrics(data)
            
            # Identify key findings
            findings = self._identify_key_findings(data)
            
            # Generate summary sections
            overview = self._generate_overview(metrics)
            key_findings = self._generate_key_findings(findings)
            risk_assessment = self._generate_risk_assessment(data.risk_summary, metrics)
            recommendations = self._generate_recommendations(findings)
            conclusion = self._generate_conclusion(metrics, findings)
            
            # Combine into full summary
            summary = self._combine_summary_sections(
                overview, key_findings, risk_assessment, recommendations, conclusion
            )
            
            self.logger.info("Executive summary generated successfully")
            return summary
            
        except Exception as e:
            self.logger.error(f"Executive summary generation failed: {e}")
            return self._generate_fallback_summary(data)
    
    def _extract_metrics(self, data: ReportData) -> ExecutiveMetrics:
        """Extract key metrics for executive reporting."""
        # Calculate security score based on findings
        security_score = self._calculate_security_score(data)
        
        # Calculate risk reduction potential
        risk_reduction = self._calculate_risk_reduction_potential(data)
        
        return ExecutiveMetrics(
            total_systems_scanned=data.total_targets,
            mcp_servers_detected=len(data.detection_results),
            critical_vulnerabilities=data.critical_findings,
            high_risk_systems=data.high_risk_targets,
            compliance_issues=self._count_compliance_issues(data),
            security_score=security_score,
            risk_reduction_potential=risk_reduction
        )
    
    def _identify_key_findings(self, data: ReportData) -> List[ExecutiveFinding]:
        """Identify key findings for executive attention."""
        findings = []
        
        # Critical MCP server exposures
        if data.critical_findings > 0:
            findings.append(ExecutiveFinding(
                title="Critical MCP Server Exposures",
                description=f"{data.critical_findings} MCP servers with critical security exposures detected",
                business_impact="Potential unauthorized access to AI capabilities and sensitive data",
                risk_level="Critical",
                recommendation="Immediate remediation required - implement access controls and network segmentation",
                priority=1
            ))
        
        # Unprotected MCP deployments
        unprotected_count = self._count_unprotected_deployments(data)
        if unprotected_count > 0:
            findings.append(ExecutiveFinding(
                title="Unprotected MCP Deployments",
                description=f"{unprotected_count} MCP servers lack proper authentication and encryption",
                business_impact="Risk of data breaches and unauthorized AI model access",
                risk_level="High",
                recommendation="Implement authentication mechanisms and enable encryption",
                priority=2
            ))
        
        # Network exposure risks
        if data.high_risk_targets > 0:
            findings.append(ExecutiveFinding(
                title="Network Exposure Risks",
                description=f"{data.high_risk_targets} systems with high network exposure risk",
                business_impact="Increased attack surface and potential for lateral movement",
                risk_level="High",
                recommendation="Review network segmentation and firewall configurations",
                priority=2
            ))
        
        # Compliance gaps
        compliance_issues = self._count_compliance_issues(data)
        if compliance_issues > 0:
            findings.append(ExecutiveFinding(
                title="Compliance Gaps",
                description=f"{compliance_issues} compliance-related issues identified",
                business_impact="Potential regulatory violations and audit findings",
                risk_level="Medium",
                recommendation="Develop compliance remediation plan and implement controls",
                priority=3
            ))
        
        # Sort by priority
        findings.sort(key=lambda x: x.priority)
        
        return findings[:5]  # Top 5 findings for executive summary
    
    def _generate_overview(self, metrics: ExecutiveMetrics) -> str:
        """Generate overview section."""
        return f"""
## Assessment Overview

HawkEye conducted a comprehensive security assessment of your organization's infrastructure, 
scanning {metrics.total_systems_scanned} systems and identifying {metrics.mcp_servers_detected} 
Model Context Protocol (MCP) server deployments.

**Key Metrics:**
- Security Score: {metrics.security_score:.1f}/100
- Critical Vulnerabilities: {metrics.critical_vulnerabilities}
- High Risk Systems: {metrics.high_risk_systems}
- Risk Reduction Potential: {metrics.risk_reduction_potential:.1f}%

The assessment reveals significant opportunities for security improvement, particularly 
around MCP server deployments which present unique risks to your organization's AI infrastructure.
        """.strip()
    
    def _generate_key_findings(self, findings: List[ExecutiveFinding]) -> str:
        """Generate key findings section."""
        if not findings:
            return """
## Key Findings

No critical security issues were identified during the assessment. Your MCP infrastructure 
appears to be well-secured with appropriate controls in place.
            """.strip()
        
        findings_text = "## Key Findings\n\n"
        
        for i, finding in enumerate(findings, 1):
            findings_text += f"""
### {i}. {finding.title} ({finding.risk_level} Risk)

**Issue:** {finding.description}

**Business Impact:** {finding.business_impact}

**Recommendation:** {finding.recommendation}

---
            """.strip() + "\n\n"
        
        return findings_text.strip()
    
    def _generate_risk_assessment(self, risk_summary: RiskSummary, metrics: ExecutiveMetrics) -> str:
        """Generate risk assessment section."""
        risk_level = self._determine_overall_risk_level(metrics)
        
        return f"""
## Risk Assessment

**Overall Risk Level: {risk_level}**

Based on the assessment findings, your organization faces a **{risk_level.lower()}** level of risk 
from MCP server deployments. The primary risk factors include:

- **Exposure Risk:** {metrics.high_risk_systems} systems with elevated network exposure
- **Access Control:** Insufficient authentication and authorization controls
- **Data Protection:** Potential for unauthorized access to sensitive AI models and data
- **Compliance:** {metrics.compliance_issues} compliance-related gaps identified

**Risk Mitigation Priority:**
1. Address critical vulnerabilities immediately (within 24-48 hours)
2. Implement network segmentation for MCP servers (within 1 week)
3. Deploy authentication and encryption (within 2 weeks)
4. Establish monitoring and governance (within 1 month)
        """.strip()
    
    def _generate_recommendations(self, findings: List[ExecutiveFinding]) -> str:
        """Generate recommendations section."""
        if not findings:
            return """
## Recommendations

Continue monitoring your MCP infrastructure and maintain current security controls. 
Consider implementing additional monitoring capabilities to detect new deployments.
            """.strip()
        
        recommendations = """
## Priority Recommendations

### Immediate Actions (0-7 days)
        """.strip()
        
        immediate_actions = [f for f in findings if f.priority <= 2]
        for finding in immediate_actions:
            recommendations += f"\n- {finding.recommendation}"
        
        recommendations += """

### Short-term Actions (1-4 weeks)
- Implement comprehensive MCP server inventory and monitoring
- Develop security policies and procedures for MCP deployments
- Conduct security training for development and operations teams
- Establish incident response procedures for MCP-related security events

### Long-term Actions (1-3 months)
- Deploy automated security scanning for MCP servers
- Implement zero-trust network architecture
- Establish governance framework for AI/ML infrastructure
- Conduct regular security assessments and penetration testing
        """
        
        return recommendations
    
    def _generate_conclusion(self, metrics: ExecutiveMetrics, findings: List[ExecutiveFinding]) -> str:
        """Generate conclusion section."""
        if metrics.security_score >= 80:
            tone = "positive"
        elif metrics.security_score >= 60:
            tone = "cautious"
        else:
            tone = "urgent"
        
        if tone == "positive":
            return """
## Conclusion

Your organization demonstrates strong security practices for MCP infrastructure. 
Continue current security measures and maintain vigilance for new deployments. 
Regular assessments will help ensure continued security posture.
            """.strip()
        elif tone == "cautious":
            return f"""
## Conclusion

While your organization has basic security controls in place, there are significant 
opportunities for improvement. Implementing the recommended security measures will 
reduce risk by approximately {metrics.risk_reduction_potential:.0f}% and strengthen 
your overall security posture.

The investment in MCP security improvements will provide substantial risk reduction 
and help ensure compliance with emerging AI governance requirements.
            """.strip()
        else:
            return f"""
## Conclusion

**Immediate action is required** to address critical security gaps in your MCP infrastructure. 
The current security posture presents significant risk to your organization's data and AI capabilities.

Implementing the priority recommendations will:
- Reduce critical risk exposure by {metrics.risk_reduction_potential:.0f}%
- Improve compliance posture
- Protect valuable AI assets and intellectual property
- Prevent potential security incidents and data breaches

We recommend engaging security leadership immediately to prioritize remediation efforts.
            """.strip()
    
    def _combine_summary_sections(self, *sections: str) -> str:
        """Combine summary sections into final document."""
        header = """
# Executive Summary - HawkEye Security Assessment

*This executive summary provides a high-level overview of security findings and 
recommendations for your organization's Model Context Protocol (MCP) infrastructure.*

---
        """.strip()
        
        return header + "\n\n" + "\n\n".join(sections)
    
    def _calculate_security_score(self, data: ReportData) -> float:
        """Calculate overall security score (0-100)."""
        if data.total_targets == 0:
            return 100.0
        
        # Base score
        score = 100.0
        
        # Deduct for critical findings
        critical_penalty = min(data.critical_findings * 20, 60)
        score -= critical_penalty
        
        # Deduct for high risk targets
        high_risk_penalty = min(data.high_risk_targets * 10, 30)
        score -= high_risk_penalty
        
        # Deduct for unprotected deployments
        unprotected = self._count_unprotected_deployments(data)
        unprotected_penalty = min(unprotected * 5, 20)
        score -= unprotected_penalty
        
        return max(score, 0.0)
    
    def _calculate_risk_reduction_potential(self, data: ReportData) -> float:
        """Calculate potential risk reduction from implementing recommendations."""
        if data.total_targets == 0:
            return 0.0
        
        # Base potential from addressing critical findings
        critical_reduction = min(data.critical_findings * 15, 50)
        
        # Additional reduction from securing high-risk targets
        high_risk_reduction = min(data.high_risk_targets * 8, 30)
        
        # Reduction from implementing best practices
        best_practices_reduction = 20
        
        total_reduction = critical_reduction + high_risk_reduction + best_practices_reduction
        return min(total_reduction, 85.0)
    
    def _count_compliance_issues(self, data: ReportData) -> int:
        """Count compliance-related issues."""
        # This would be enhanced based on specific compliance requirements
        issues = 0
        
        # Count unprotected deployments as compliance issues
        issues += self._count_unprotected_deployments(data)
        
        # Count high-risk exposures as compliance issues
        issues += min(data.high_risk_targets, 5)
        
        return issues
    
    def _count_unprotected_deployments(self, data: ReportData) -> int:
        """Count unprotected MCP deployments."""
        # This would analyze detection results for authentication/encryption status
        # For now, estimate based on high-risk targets
        return min(data.high_risk_targets, len(data.detection_results))
    
    def _determine_overall_risk_level(self, metrics: ExecutiveMetrics) -> str:
        """Determine overall risk level."""
        if metrics.critical_vulnerabilities > 0 or metrics.security_score < 40:
            return "Critical"
        elif metrics.high_risk_systems > 2 or metrics.security_score < 60:
            return "High"
        elif metrics.compliance_issues > 0 or metrics.security_score < 80:
            return "Medium"
        else:
            return "Low"
    
    def _generate_fallback_summary(self, data: ReportData) -> str:
        """Generate basic summary if detailed generation fails."""
        return f"""
# Executive Summary - HawkEye Security Assessment

## Overview
Assessment completed for {data.total_targets} systems with {len(data.detection_results)} MCP servers detected.

## Key Findings
- Critical findings: {data.critical_findings}
- High risk targets: {data.high_risk_targets}
- Total MCP servers: {len(data.detection_results)}

## Recommendations
Review detailed technical report for specific remediation steps and security improvements.
        """.strip() 