"""
Compliance Checking Framework for MCP Security Assessments.

This module provides comprehensive compliance checking capabilities for MCP server
security assessments, mapping security findings to various compliance frameworks
including OWASP Top 10, NIST CSF, PCI DSS, GDPR, SOC2, and ISO 27001.
"""

import time
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict

from .base import (
    RiskAssessor,
    AssessmentResult,
    SecurityFinding,
    VulnerabilityInfo,
    VulnerabilityCategory,
    RiskLevel,
    ComplianceFramework,
    CVSSVector,
)
from ..detection.base import DetectionResult
from ..utils.logging import get_logger


class ComplianceStatus(Enum):
    """Compliance status enumeration."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ComplianceRequirement(Enum):
    """Compliance requirement categories."""
    ACCESS_CONTROL = "access_control"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_PROTECTION = "data_protection"
    ENCRYPTION = "encryption"
    LOGGING_MONITORING = "logging_monitoring"
    NETWORK_SECURITY = "network_security"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    INCIDENT_RESPONSE = "incident_response"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    SECURE_DEVELOPMENT = "secure_development"
    RISK_MANAGEMENT = "risk_management"


@dataclass
class ComplianceControl:
    """Represents a specific compliance control."""
    id: str
    framework: ComplianceFramework
    title: str
    description: str
    requirement_category: ComplianceRequirement
    severity: RiskLevel
    applicable_categories: List[VulnerabilityCategory] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    remediation_guidance: str = ""


@dataclass
class ComplianceViolation:
    """Represents a compliance violation."""
    control: ComplianceControl
    finding: SecurityFinding
    violation_description: str
    impact_level: RiskLevel
    remediation_priority: int  # 1-5, 1 being highest priority
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """Comprehensive compliance assessment report."""
    target_host: str
    framework: ComplianceFramework
    overall_status: ComplianceStatus
    compliance_score: float  # 0-100
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    violations: List[ComplianceViolation] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    assessment_duration: float = 0.0
    raw_data: Dict[str, Any] = field(default_factory=dict)


class ComplianceChecker(RiskAssessor):
    """Compliance checking framework for MCP security assessments."""
    
    def __init__(self, settings=None):
        """Initialize the compliance checker."""
        super().__init__(settings)
        self.logger = get_logger(__name__)
        
        # Initialize compliance controls database
        self.compliance_controls = self._initialize_compliance_controls()
        
        # Compliance scoring weights
        self.scoring_weights = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5,
            RiskLevel.INFO: 1
        }
    
    def get_assessment_type(self) -> str:
        """Get the assessment type identifier."""
        return "compliance_checking"
    
    def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
        """
        Perform compliance assessment for an MCP server.
        
        Args:
            detection_result: Detection result containing MCP server information
            **kwargs: Additional assessment parameters including:
                - frameworks: List of frameworks to check (default: all)
                - findings: List of security findings to assess
                
        Returns:
            AssessmentResult: Compliance assessment result
        """
        start_time = time.time()
        
        try:
            if not detection_result.success:
                return self._create_failed_result(
                    detection_result.target_host,
                    "No MCP server detected for compliance assessment",
                    time.time() - start_time
                )
            
            # Get frameworks to check
            frameworks = kwargs.get('frameworks', list(ComplianceFramework))
            if isinstance(frameworks, ComplianceFramework):
                frameworks = [frameworks]
            
            # Get security findings to assess
            findings = kwargs.get('findings', [])
            if not findings:
                self.logger.warning("No security findings provided for compliance assessment")
                return self._create_empty_result(detection_result.target_host, time.time() - start_time)
            
            # Generate compliance reports for each framework
            compliance_reports = []
            overall_findings = []
            overall_vulnerabilities = []
            
            for framework in frameworks:
                report = self._assess_framework_compliance(
                    detection_result.target_host,
                    framework,
                    findings
                )
                compliance_reports.append(report)
                
                # Convert violations to security findings
                framework_findings = self._convert_violations_to_findings(report.violations)
                overall_findings.extend(framework_findings)
                
                # Generate vulnerabilities from violations
                framework_vulnerabilities = self._generate_vulnerabilities_from_violations(report.violations)
                overall_vulnerabilities.extend(framework_vulnerabilities)
            
            # Create assessment result
            result = AssessmentResult(
                target_host=detection_result.target_host,
                findings=overall_findings,
                vulnerabilities=overall_vulnerabilities,
                assessment_duration=time.time() - start_time,
                raw_data={
                    'compliance_reports': [self._serialize_report(report) for report in compliance_reports],
                    'frameworks_assessed': [f.value for f in frameworks],
                    'total_findings_assessed': len(findings),
                    'detection_confidence': detection_result.confidence,
                }
            )
            
            # Calculate overall risk
            result.calculate_overall_risk()
            
            # Generate recommendations
            result.recommendations = self._generate_compliance_recommendations(compliance_reports)
            
            # Set compliance status
            result.compliance_status = self._calculate_overall_compliance_status(compliance_reports)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Compliance assessment failed for {detection_result.target_host}: {e}")
            return self._create_failed_result(
                detection_result.target_host,
                f"Compliance assessment error: {str(e)}",
                time.time() - start_time
            )
    
    def _assess_framework_compliance(
        self, 
        target_host: str, 
        framework: ComplianceFramework, 
        findings: List[SecurityFinding]
    ) -> ComplianceReport:
        """
        Assess compliance against a specific framework.
        
        Args:
            target_host: Target host being assessed
            framework: Compliance framework to assess against
            findings: Security findings to evaluate
            
        Returns:
            ComplianceReport: Framework-specific compliance report
        """
        start_time = time.time()
        
        # Get controls for this framework
        framework_controls = [
            control for control in self.compliance_controls
            if control.framework == framework
        ]
        
        violations = []
        compliant_controls = 0
        
        # Check each control against findings
        for control in framework_controls:
            control_violations = self._check_control_compliance(control, findings)
            
            if control_violations:
                violations.extend(control_violations)
            else:
                compliant_controls += 1
        
        # Calculate compliance metrics
        total_controls = len(framework_controls)
        non_compliant_controls = total_controls - compliant_controls
        compliance_score = (compliant_controls / total_controls * 100) if total_controls > 0 else 100
        
        # Determine overall status
        if compliance_score >= 95:
            overall_status = ComplianceStatus.COMPLIANT
        elif compliance_score >= 70:
            overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            overall_status = ComplianceStatus.NON_COMPLIANT
        
        # Generate recommendations
        recommendations = self._generate_framework_recommendations(framework, violations)
        
        return ComplianceReport(
            target_host=target_host,
            framework=framework,
            overall_status=overall_status,
            compliance_score=compliance_score,
            total_controls=total_controls,
            compliant_controls=compliant_controls,
            non_compliant_controls=non_compliant_controls,
            violations=violations,
            recommendations=recommendations,
            assessment_duration=time.time() - start_time,
            raw_data={
                'framework_name': framework.value,
                'controls_assessed': len(framework_controls),
                'violation_count': len(violations),
            }
        )
    
    def _check_control_compliance(
        self, 
        control: ComplianceControl, 
        findings: List[SecurityFinding]
    ) -> List[ComplianceViolation]:
        """
        Check if a specific control is violated by any findings.
        
        Args:
            control: Compliance control to check
            findings: Security findings to evaluate
            
        Returns:
            List[ComplianceViolation]: List of violations for this control
        """
        violations = []
        
        for finding in findings:
            # Check if finding violates this control
            if self._is_control_violated(control, finding):
                violation = ComplianceViolation(
                    control=control,
                    finding=finding,
                    violation_description=self._generate_violation_description(control, finding),
                    impact_level=self._calculate_violation_impact(control, finding),
                    remediation_priority=self._calculate_remediation_priority(control, finding),
                    evidence={
                        'finding_id': finding.id,
                        'finding_category': finding.category.value,
                        'finding_severity': finding.severity.value,
                        'control_id': control.id,
                        'control_category': control.requirement_category.value,
                    }
                )
                violations.append(violation)
        
        return violations
    
    def _is_control_violated(self, control: ComplianceControl, finding: SecurityFinding) -> bool:
        """
        Determine if a finding violates a specific control.
        
        Args:
            control: Compliance control
            finding: Security finding
            
        Returns:
            bool: True if control is violated
        """
        # Check category match
        if finding.category in control.applicable_categories:
            return True
        
        # Check keyword match in finding title or description
        finding_text = f"{finding.title} {finding.description}".lower()
        for keyword in control.keywords:
            if keyword.lower() in finding_text:
                return True
        
        # Check severity threshold
        if finding.severity.value >= control.severity.value:
            # Additional logic for specific control types
            if control.requirement_category == ComplianceRequirement.ENCRYPTION:
                return self._check_encryption_violation(control, finding)
            elif control.requirement_category == ComplianceRequirement.AUTHENTICATION:
                return self._check_authentication_violation(control, finding)
            elif control.requirement_category == ComplianceRequirement.ACCESS_CONTROL:
                return self._check_access_control_violation(control, finding)
        
        return False
    
    def _check_encryption_violation(self, control: ComplianceControl, finding: SecurityFinding) -> bool:
        """Check if finding violates encryption controls."""
        encryption_keywords = ['unencrypted', 'plaintext', 'weak cipher', 'ssl', 'tls', 'https']
        finding_text = f"{finding.title} {finding.description}".lower()
        return any(keyword in finding_text for keyword in encryption_keywords)
    
    def _check_authentication_violation(self, control: ComplianceControl, finding: SecurityFinding) -> bool:
        """Check if finding violates authentication controls."""
        auth_keywords = ['password', 'authentication', 'credential', 'token', 'session', 'login']
        finding_text = f"{finding.title} {finding.description}".lower()
        return any(keyword in finding_text for keyword in auth_keywords)
    
    def _check_access_control_violation(self, control: ComplianceControl, finding: SecurityFinding) -> bool:
        """Check if finding violates access control controls."""
        access_keywords = ['authorization', 'permission', 'privilege', 'access', 'role', 'admin']
        finding_text = f"{finding.title} {finding.description}".lower()
        return any(keyword in finding_text for keyword in access_keywords)
    
    def _generate_violation_description(self, control: ComplianceControl, finding: SecurityFinding) -> str:
        """Generate a description for a compliance violation."""
        return (
            f"Control {control.id} ({control.title}) is violated by finding: "
            f"{finding.title}. {finding.description}"
        )
    
    def _calculate_violation_impact(self, control: ComplianceControl, finding: SecurityFinding) -> RiskLevel:
        """Calculate the impact level of a compliance violation."""
        # Use the higher of control severity or finding severity
        control_severity_value = control.severity.value
        finding_severity_value = finding.severity.value
        
        max_severity_value = max(control_severity_value, finding_severity_value)
        
        for level in RiskLevel:
            if level.value == max_severity_value:
                return level
        
        return RiskLevel.MEDIUM
    
    def _calculate_remediation_priority(self, control: ComplianceControl, finding: SecurityFinding) -> int:
        """Calculate remediation priority (1-5, 1 being highest)."""
        severity_priority = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 4,
            RiskLevel.INFO: 5
        }
        
        impact_level = self._calculate_violation_impact(control, finding)
        return severity_priority.get(impact_level, 3)
    
    def _convert_violations_to_findings(self, violations: List[ComplianceViolation]) -> List[SecurityFinding]:
        """Convert compliance violations to security findings."""
        findings = []
        
        for violation in violations:
            finding = SecurityFinding(
                id=f"compliance_violation_{violation.control.framework.value}_{violation.control.id}",
                title=f"Compliance Violation: {violation.control.title}",
                description=violation.violation_description,
                category=VulnerabilityCategory.COMPLIANCE,
                severity=violation.impact_level,
                confidence=violation.finding.confidence,
                affected_asset=violation.finding.affected_asset,
                evidence=violation.evidence,
                remediation=violation.control.remediation_guidance or violation.finding.remediation,
                compliance_violations=[violation.control.framework]
            )
            findings.append(finding)
        
        return findings
    
    def _generate_vulnerabilities_from_violations(
        self, 
        violations: List[ComplianceViolation]
    ) -> List[VulnerabilityInfo]:
        """Generate vulnerability information from compliance violations."""
        vulnerabilities = []
        
        for violation in violations:
            # Create CVSS vector for compliance violation
            cvss_vector = self._create_compliance_cvss_vector(violation)
            
            vulnerability = VulnerabilityInfo(
                id=f"COMP-{violation.control.framework.value}-{violation.control.id}",
                title=f"Compliance Violation: {violation.control.title}",
                description=violation.violation_description,
                category=VulnerabilityCategory.COMPLIANCE,
                severity=violation.impact_level,
                cvss_vector=cvss_vector,
                cvss_score=self._calculate_compliance_cvss_score(violation),
                affected_asset=violation.finding.affected_asset,
                evidence=violation.evidence,
                remediation=violation.control.remediation_guidance,
                compliance_frameworks=[violation.control.framework]
            )
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _create_compliance_cvss_vector(self, violation: ComplianceViolation) -> CVSSVector:
        """Create CVSS vector for compliance violation."""
        # Base CVSS vector for compliance violations
        return CVSSVector(
            attack_vector="N",  # Network
            attack_complexity="L",  # Low
            privileges_required="N",  # None
            user_interaction="N",  # None
            scope="U",  # Unchanged
            confidentiality_impact="L",  # Low
            integrity_impact="L",  # Low
            availability_impact="N"  # None
        )
    
    def _calculate_compliance_cvss_score(self, violation: ComplianceViolation) -> float:
        """Calculate CVSS score for compliance violation."""
        # Base score for compliance violations
        base_scores = {
            RiskLevel.CRITICAL: 9.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.LOW: 3.0,
            RiskLevel.INFO: 1.0
        }
        
        return base_scores.get(violation.impact_level, 5.0)
    
    def _generate_framework_recommendations(
        self, 
        framework: ComplianceFramework, 
        violations: List[ComplianceViolation]
    ) -> List[str]:
        """Generate recommendations for framework compliance."""
        recommendations = []
        
        if not violations:
            recommendations.append(f"All {framework.value} controls are compliant")
            return recommendations
        
        # Group violations by category
        category_violations = defaultdict(list)
        for violation in violations:
            category_violations[violation.control.requirement_category].append(violation)
        
        # Generate category-specific recommendations
        for category, cat_violations in category_violations.items():
            high_priority_count = sum(1 for v in cat_violations if v.remediation_priority <= 2)
            
            if high_priority_count > 0:
                recommendations.append(
                    f"Address {high_priority_count} high-priority {category.value} "
                    f"violations to improve {framework.value} compliance"
                )
        
        # Add specific remediation guidance
        for violation in sorted(violations, key=lambda v: v.remediation_priority)[:5]:
            if violation.control.remediation_guidance:
                recommendations.append(violation.control.remediation_guidance)
        
        return recommendations
    
    def _generate_compliance_recommendations(self, reports: List[ComplianceReport]) -> List[str]:
        """Generate overall compliance recommendations."""
        recommendations = []
        
        # Analyze overall compliance status
        non_compliant_frameworks = [r for r in reports if r.overall_status == ComplianceStatus.NON_COMPLIANT]
        partially_compliant_frameworks = [r for r in reports if r.overall_status == ComplianceStatus.PARTIALLY_COMPLIANT]
        
        if non_compliant_frameworks:
            frameworks_list = ", ".join([r.framework.value for r in non_compliant_frameworks])
            recommendations.append(
                f"Critical: Address non-compliance with {frameworks_list} frameworks"
            )
        
        if partially_compliant_frameworks:
            frameworks_list = ", ".join([r.framework.value for r in partially_compliant_frameworks])
            recommendations.append(
                f"Improve partial compliance with {frameworks_list} frameworks"
            )
        
        # Add framework-specific recommendations
        for report in reports:
            recommendations.extend(report.recommendations)
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    def _calculate_overall_compliance_status(self, reports: List[ComplianceReport]) -> Dict[ComplianceFramework, bool]:
        """Calculate overall compliance status across frameworks."""
        compliance_status = {}
        
        for report in reports:
            compliance_status[report.framework] = report.overall_status == ComplianceStatus.COMPLIANT
        
        return compliance_status
    
    def _serialize_report(self, report: ComplianceReport) -> Dict[str, Any]:
        """Serialize compliance report for storage."""
        return {
            'target_host': report.target_host,
            'framework': report.framework.value,
            'overall_status': report.overall_status.value,
            'compliance_score': report.compliance_score,
            'total_controls': report.total_controls,
            'compliant_controls': report.compliant_controls,
            'non_compliant_controls': report.non_compliant_controls,
            'violation_count': len(report.violations),
            'assessment_duration': report.assessment_duration,
            'recommendations': report.recommendations,
        }
    
    def _create_empty_result(self, target_host: str, duration: float) -> AssessmentResult:
        """Create empty assessment result."""
        return AssessmentResult(
            target_host=target_host,
            findings=[],
            vulnerabilities=[],
            assessment_duration=duration,
            raw_data={'error': 'No security findings provided for compliance assessment'}
        )
    
    def _create_failed_result(self, target_host: str, error_message: str, duration: float) -> AssessmentResult:
        """Create failed assessment result."""
        return AssessmentResult(
            target_host=target_host,
            findings=[],
            vulnerabilities=[],
            assessment_duration=duration,
            raw_data={'error': error_message}
        )
    
    def _initialize_compliance_controls(self) -> List[ComplianceControl]:
        """Initialize the compliance controls database."""
        controls = []
        
        # OWASP Top 10 Controls
        controls.extend(self._get_owasp_controls())
        
        # NIST CSF Controls
        controls.extend(self._get_nist_controls())
        
        # PCI DSS Controls
        controls.extend(self._get_pci_controls())
        
        # GDPR Controls
        controls.extend(self._get_gdpr_controls())
        
        # SOC2 Controls
        controls.extend(self._get_soc2_controls())
        
        # ISO 27001 Controls
        controls.extend(self._get_iso27001_controls())
        
        return controls
    
    def _get_owasp_controls(self) -> List[ComplianceControl]:
        """Get OWASP Top 10 compliance controls."""
        return [
            ComplianceControl(
                id="A01",
                framework=ComplianceFramework.OWASP_TOP_10,
                title="Broken Access Control",
                description="Ensure proper access controls are implemented",
                requirement_category=ComplianceRequirement.ACCESS_CONTROL,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ACCESS_CONTROL, VulnerabilityCategory.AUTHENTICATION],
                keywords=["access", "authorization", "privilege", "permission"],
                remediation_guidance="Implement proper access controls and authorization mechanisms"
            ),
            ComplianceControl(
                id="A02",
                framework=ComplianceFramework.OWASP_TOP_10,
                title="Cryptographic Failures",
                description="Ensure proper encryption and cryptographic controls",
                requirement_category=ComplianceRequirement.ENCRYPTION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ENCRYPTION],
                keywords=["encryption", "crypto", "ssl", "tls", "cipher"],
                remediation_guidance="Implement strong encryption and proper cryptographic controls"
            ),
            ComplianceControl(
                id="A03",
                framework=ComplianceFramework.OWASP_TOP_10,
                title="Injection",
                description="Prevent injection vulnerabilities",
                requirement_category=ComplianceRequirement.SECURE_DEVELOPMENT,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.INPUT_VALIDATION],
                keywords=["injection", "sql", "command", "script"],
                remediation_guidance="Implement proper input validation and parameterized queries"
            ),
            ComplianceControl(
                id="A05",
                framework=ComplianceFramework.OWASP_TOP_10,
                title="Security Misconfiguration",
                description="Ensure secure configuration management",
                requirement_category=ComplianceRequirement.CONFIGURATION_MANAGEMENT,
                severity=RiskLevel.MEDIUM,
                applicable_categories=[VulnerabilityCategory.CONFIGURATION],
                keywords=["configuration", "default", "misconfiguration"],
                remediation_guidance="Review and harden security configurations"
            ),
            ComplianceControl(
                id="A07",
                framework=ComplianceFramework.OWASP_TOP_10,
                title="Identification and Authentication Failures",
                description="Ensure robust authentication mechanisms",
                requirement_category=ComplianceRequirement.AUTHENTICATION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.AUTHENTICATION],
                keywords=["authentication", "password", "session", "credential"],
                remediation_guidance="Implement strong authentication and session management"
            ),
        ]
    
    def _get_nist_controls(self) -> List[ComplianceControl]:
        """Get NIST Cybersecurity Framework controls."""
        return [
            ComplianceControl(
                id="PR.AC-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Access Control Policy",
                description="Identities and credentials are issued, managed, verified, revoked, and audited",
                requirement_category=ComplianceRequirement.ACCESS_CONTROL,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ACCESS_CONTROL, VulnerabilityCategory.AUTHENTICATION],
                keywords=["access", "identity", "credential", "authentication"],
                remediation_guidance="Implement comprehensive access control policies and procedures"
            ),
            ComplianceControl(
                id="PR.DS-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Data Protection",
                description="Data-at-rest is protected",
                requirement_category=ComplianceRequirement.DATA_PROTECTION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ENCRYPTION],
                keywords=["encryption", "data", "protection", "storage"],
                remediation_guidance="Implement encryption for data at rest"
            ),
            ComplianceControl(
                id="PR.DS-2",
                framework=ComplianceFramework.NIST_CSF,
                title="Data in Transit Protection",
                description="Data-in-transit is protected",
                requirement_category=ComplianceRequirement.ENCRYPTION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ENCRYPTION],
                keywords=["encryption", "transit", "tls", "ssl", "https"],
                remediation_guidance="Implement encryption for data in transit"
            ),
        ]
    
    def _get_pci_controls(self) -> List[ComplianceControl]:
        """Get PCI DSS compliance controls."""
        return [
            ComplianceControl(
                id="PCI-4",
                framework=ComplianceFramework.PCI_DSS,
                title="Encrypt Transmission",
                description="Encrypt transmission of cardholder data across open, public networks",
                requirement_category=ComplianceRequirement.ENCRYPTION,
                severity=RiskLevel.CRITICAL,
                applicable_categories=[VulnerabilityCategory.ENCRYPTION],
                keywords=["encryption", "transmission", "network", "ssl", "tls"],
                remediation_guidance="Use strong cryptography and security protocols to safeguard sensitive data during transmission"
            ),
            ComplianceControl(
                id="PCI-8",
                framework=ComplianceFramework.PCI_DSS,
                title="Identify and Authenticate Access",
                description="Identify and authenticate access to system components",
                requirement_category=ComplianceRequirement.AUTHENTICATION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.AUTHENTICATION],
                keywords=["authentication", "identity", "access", "user"],
                remediation_guidance="Implement strong authentication mechanisms for all system access"
            ),
        ]
    
    def _get_gdpr_controls(self) -> List[ComplianceControl]:
        """Get GDPR compliance controls."""
        return [
            ComplianceControl(
                id="GDPR-32",
                framework=ComplianceFramework.GDPR,
                title="Security of Processing",
                description="Implement appropriate technical and organizational measures to ensure security",
                requirement_category=ComplianceRequirement.DATA_PROTECTION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ENCRYPTION, VulnerabilityCategory.ACCESS_CONTROL],
                keywords=["security", "processing", "encryption", "access"],
                remediation_guidance="Implement appropriate security measures for personal data processing"
            ),
        ]
    
    def _get_soc2_controls(self) -> List[ComplianceControl]:
        """Get SOC2 compliance controls."""
        return [
            ComplianceControl(
                id="CC6.1",
                framework=ComplianceFramework.SOC2,
                title="Logical and Physical Access Controls",
                description="Implement logical and physical access controls",
                requirement_category=ComplianceRequirement.ACCESS_CONTROL,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ACCESS_CONTROL],
                keywords=["access", "control", "logical", "physical"],
                remediation_guidance="Implement comprehensive access control mechanisms"
            ),
        ]
    
    def _get_iso27001_controls(self) -> List[ComplianceControl]:
        """Get ISO 27001 compliance controls."""
        return [
            ComplianceControl(
                id="A.9.1.1",
                framework=ComplianceFramework.ISO_27001,
                title="Access Control Policy",
                description="An access control policy shall be established, documented and reviewed",
                requirement_category=ComplianceRequirement.ACCESS_CONTROL,
                severity=RiskLevel.MEDIUM,
                applicable_categories=[VulnerabilityCategory.ACCESS_CONTROL],
                keywords=["access", "policy", "control"],
                remediation_guidance="Establish and maintain formal access control policies"
            ),
            ComplianceControl(
                id="A.10.1.1",
                framework=ComplianceFramework.ISO_27001,
                title="Cryptographic Controls",
                description="A policy on the use of cryptographic controls shall be developed and implemented",
                requirement_category=ComplianceRequirement.ENCRYPTION,
                severity=RiskLevel.HIGH,
                applicable_categories=[VulnerabilityCategory.ENCRYPTION],
                keywords=["cryptographic", "encryption", "crypto"],
                remediation_guidance="Develop and implement cryptographic control policies"
            ),
        ]
