"""
Base classes and data models for MCP security risk assessment.

This module provides the foundational classes and data structures for
assessing security risks in MCP server deployments, including CVSS scoring,
vulnerability tracking, and security finding management.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

from ..detection.base import DetectionResult, MCPServerInfo
from ..utils.logging import get_logger


class RiskLevel(Enum):
    """Enumeration of risk severity levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityCategory(Enum):
    """Categories of security vulnerabilities."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    INPUT_VALIDATION = "input_validation"
    SESSION_MANAGEMENT = "session_management"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    COMPLIANCE = "compliance"


class ComplianceFramework(Enum):
    """Security compliance frameworks."""
    OWASP_TOP_10 = "owasp_top_10"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"


@dataclass
class CVSSVector:
    """CVSS (Common Vulnerability Scoring System) vector representation."""
    
    # Base Score Metrics
    attack_vector: str = "N"  # Network, Adjacent, Local, Physical
    attack_complexity: str = "L"  # Low, High
    privileges_required: str = "N"  # None, Low, High
    user_interaction: str = "N"  # None, Required
    scope: str = "U"  # Unchanged, Changed
    confidentiality: str = "N"  # None, Low, High
    integrity: str = "N"  # None, Low, High
    availability: str = "N"  # None, Low, High
    
    # Temporal Score Metrics (optional)
    exploit_code_maturity: Optional[str] = None  # Not Defined, Unproven, Proof-of-Concept, Functional, High
    remediation_level: Optional[str] = None  # Not Defined, Official Fix, Temporary Fix, Workaround, Unavailable
    report_confidence: Optional[str] = None  # Not Defined, Unknown, Reasonable, Confirmed
    
    # Environmental Score Metrics (optional)
    confidentiality_requirement: Optional[str] = None  # Not Defined, Low, Medium, High
    integrity_requirement: Optional[str] = None  # Not Defined, Low, Medium, High
    availability_requirement: Optional[str] = None  # Not Defined, Low, Medium, High
    
    def to_vector_string(self) -> str:
        """Convert CVSS vector to standard string representation."""
        vector_parts = [
            f"AV:{self.attack_vector}",
            f"AC:{self.attack_complexity}",
            f"PR:{self.privileges_required}",
            f"UI:{self.user_interaction}",
            f"S:{self.scope}",
            f"C:{self.confidentiality}",
            f"I:{self.integrity}",
            f"A:{self.availability}"
        ]
        
        # Add temporal metrics if present
        if self.exploit_code_maturity:
            vector_parts.append(f"E:{self.exploit_code_maturity}")
        if self.remediation_level:
            vector_parts.append(f"RL:{self.remediation_level}")
        if self.report_confidence:
            vector_parts.append(f"RC:{self.report_confidence}")
        
        # Add environmental metrics if present
        if self.confidentiality_requirement:
            vector_parts.append(f"CR:{self.confidentiality_requirement}")
        if self.integrity_requirement:
            vector_parts.append(f"IR:{self.integrity_requirement}")
        if self.availability_requirement:
            vector_parts.append(f"AR:{self.availability_requirement}")
        
        return "CVSS:3.1/" + "/".join(vector_parts)


@dataclass
class VulnerabilityInfo:
    """Information about a specific security vulnerability."""
    
    id: str  # Unique identifier (CVE, custom ID, etc.)
    title: str
    description: str
    category: VulnerabilityCategory
    severity: RiskLevel
    cvss_vector: Optional[CVSSVector] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None  # Common Weakness Enumeration ID
    references: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    workaround_available: bool = False
    
    @property
    def is_exploitable(self) -> bool:
        """Check if vulnerability is actively exploitable."""
        return self.exploit_available and self.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    
    @property
    def has_mitigation(self) -> bool:
        """Check if vulnerability has available mitigation."""
        return self.patch_available or self.workaround_available


@dataclass
class SecurityFinding:
    """A specific security finding from assessment."""
    
    id: str  # Unique finding identifier
    title: str
    description: str
    category: VulnerabilityCategory
    severity: RiskLevel
    confidence: float  # 0.0 to 1.0
    affected_asset: str  # Host, service, component affected
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    compliance_violations: List[ComplianceFramework] = field(default_factory=list)
    vulnerability_info: Optional[VulnerabilityInfo] = None
    
    @property
    def risk_score(self) -> float:
        """Calculate risk score based on severity and confidence."""
        severity_weights = {
            RiskLevel.NONE: 0.0,
            RiskLevel.LOW: 2.5,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.HIGH: 7.5,
            RiskLevel.CRITICAL: 10.0
        }
        return severity_weights.get(self.severity, 0.0) * self.confidence


@dataclass
class AssessmentResult:
    """Result of a security risk assessment."""
    
    target_host: str
    assessment_timestamp: float = field(default_factory=time.time)
    overall_risk_level: RiskLevel = RiskLevel.NONE
    overall_risk_score: float = 0.0
    findings: List[SecurityFinding] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    compliance_status: Dict[ComplianceFramework, bool] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    assessment_duration: Optional[float] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def critical_findings(self) -> List[SecurityFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == RiskLevel.CRITICAL]
    
    @property
    def high_findings(self) -> List[SecurityFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == RiskLevel.HIGH]
    
    @property
    def exploitable_vulnerabilities(self) -> List[VulnerabilityInfo]:
        """Get vulnerabilities that are actively exploitable."""
        return [v for v in self.vulnerabilities if v.is_exploitable]
    
    @property
    def unpatched_vulnerabilities(self) -> List[VulnerabilityInfo]:
        """Get vulnerabilities without available patches."""
        return [v for v in self.vulnerabilities if not v.has_mitigation]
    
    def get_findings_by_category(self, category: VulnerabilityCategory) -> List[SecurityFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]
    
    def get_compliance_violations(self) -> Dict[ComplianceFramework, List[SecurityFinding]]:
        """Get compliance violations grouped by framework."""
        violations = {}
        for framework in ComplianceFramework:
            violations[framework] = [
                f for f in self.findings 
                if framework in f.compliance_violations
            ]
        return violations
    
    def calculate_overall_risk(self) -> None:
        """Calculate overall risk level and score from findings."""
        if not self.findings:
            self.overall_risk_level = RiskLevel.NONE
            self.overall_risk_score = 0.0
            return
        
        # Calculate weighted risk score
        total_score = sum(finding.risk_score for finding in self.findings)
        max_possible_score = len(self.findings) * 10.0  # Max score per finding
        self.overall_risk_score = (total_score / max_possible_score) * 10.0 if max_possible_score > 0 else 0.0
        
        # Determine overall risk level
        if any(f.severity == RiskLevel.CRITICAL for f in self.findings):
            self.overall_risk_level = RiskLevel.CRITICAL
        elif any(f.severity == RiskLevel.HIGH for f in self.findings):
            self.overall_risk_level = RiskLevel.HIGH
        elif any(f.severity == RiskLevel.MEDIUM for f in self.findings):
            self.overall_risk_level = RiskLevel.MEDIUM
        elif any(f.severity == RiskLevel.LOW for f in self.findings):
            self.overall_risk_level = RiskLevel.LOW
        else:
            self.overall_risk_level = RiskLevel.NONE
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment result to dictionary."""
        return {
            'target_host': self.target_host,
            'assessment_timestamp': self.assessment_timestamp,
            'overall_risk_level': self.overall_risk_level.value,
            'overall_risk_score': self.overall_risk_score,
            'assessment_duration': self.assessment_duration,
            'summary': {
                'total_findings': len(self.findings),
                'critical_findings': len(self.critical_findings),
                'high_findings': len(self.high_findings),
                'total_vulnerabilities': len(self.vulnerabilities),
                'exploitable_vulnerabilities': len(self.exploitable_vulnerabilities),
                'unpatched_vulnerabilities': len(self.unpatched_vulnerabilities),
            },
            'findings': [
                {
                    'id': f.id,
                    'title': f.title,
                    'description': f.description,
                    'category': f.category.value,
                    'severity': f.severity.value,
                    'confidence': f.confidence,
                    'risk_score': f.risk_score,
                    'affected_asset': f.affected_asset,
                    'remediation': f.remediation,
                    'compliance_violations': [cv.value for cv in f.compliance_violations],
                }
                for f in self.findings
            ],
            'vulnerabilities': [
                {
                    'id': v.id,
                    'title': v.title,
                    'category': v.category.value,
                    'severity': v.severity.value,
                    'cvss_score': v.cvss_score,
                    'cvss_vector': v.cvss_vector.to_vector_string() if v.cvss_vector else None,
                    'cwe_id': v.cwe_id,
                    'is_exploitable': v.is_exploitable,
                    'has_mitigation': v.has_mitigation,
                }
                for v in self.vulnerabilities
            ],
            'compliance_status': {
                framework.value: status 
                for framework, status in self.compliance_status.items()
            },
            'recommendations': self.recommendations,
            'raw_data': self.raw_data,
        }


class RiskAssessment:
    """Container for risk assessment data and operations."""
    
    def __init__(self):
        self.results: List[AssessmentResult] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
    
    def add_result(self, result: AssessmentResult) -> None:
        """Add an assessment result."""
        self.results.append(result)
    
    def get_results_by_risk_level(self, risk_level: RiskLevel) -> List[AssessmentResult]:
        """Get results filtered by risk level."""
        return [r for r in self.results if r.overall_risk_level == risk_level]
    
    def get_high_risk_targets(self) -> List[AssessmentResult]:
        """Get targets with high or critical risk levels."""
        return [
            r for r in self.results 
            if r.overall_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]
    
    def get_overall_statistics(self) -> Dict[str, Any]:
        """Get overall assessment statistics."""
        if not self.results:
            return {}
        
        total_findings = sum(len(r.findings) for r in self.results)
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in self.results)
        
        risk_distribution = {}
        for level in RiskLevel:
            risk_distribution[level.value] = len(self.get_results_by_risk_level(level))
        
        return {
            'total_targets_assessed': len(self.results),
            'total_findings': total_findings,
            'total_vulnerabilities': total_vulnerabilities,
            'high_risk_targets': len(self.get_high_risk_targets()),
            'risk_distribution': risk_distribution,
            'assessment_duration': self.end_time - self.start_time if self.start_time and self.end_time else None,
        }


class RiskAssessor(ABC):
    """Abstract base class for risk assessment operations."""
    
    def __init__(self, settings=None):
        """Initialize the risk assessor with configuration settings."""
        from ..config.settings import get_settings
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        self._assessment_stats = {
            'total_assessments': 0,
            'successful_assessments': 0,
            'failed_assessments': 0,
            'findings_generated': 0,
            'vulnerabilities_identified': 0,
        }
    
    @abstractmethod
    def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
        """
        Perform risk assessment on a detection result.
        
        Args:
            detection_result: Result from MCP detection
            **kwargs: Additional assessment parameters
            
        Returns:
            AssessmentResult: Result of the risk assessment
        """
        pass
    
    @abstractmethod
    def get_assessment_type(self) -> str:
        """
        Get the type of assessment performed by this assessor.
        
        Returns:
            str: Assessment type identifier
        """
        pass
    
    def assess_multiple(self, detection_results: List[DetectionResult], **kwargs) -> RiskAssessment:
        """
        Perform assessment on multiple detection results.
        
        Args:
            detection_results: List of detection results to assess
            **kwargs: Additional assessment parameters
            
        Returns:
            RiskAssessment: Container with all assessment results
        """
        assessment = RiskAssessment()
        assessment.start_time = time.time()
        
        for detection_result in detection_results:
            try:
                result = self.assess(detection_result, **kwargs)
                assessment.add_result(result)
                self._assessment_stats['successful_assessments'] += 1
                self._assessment_stats['findings_generated'] += len(result.findings)
                self._assessment_stats['vulnerabilities_identified'] += len(result.vulnerabilities)
            except Exception as e:
                self.logger.error(f"Assessment failed for {detection_result.target_host}: {e}")
                self._assessment_stats['failed_assessments'] += 1
            
            self._assessment_stats['total_assessments'] += 1
        
        assessment.end_time = time.time()
        return assessment
    
    def get_assessment_statistics(self) -> Dict[str, Any]:
        """Get assessment statistics."""
        return self._assessment_stats.copy()
    
    def clear_statistics(self) -> None:
        """Clear assessment statistics."""
        for key in self._assessment_stats:
            self._assessment_stats[key] = 0


# Exception Classes
class AssessmentError(Exception):
    """Base exception for assessment operations."""
    pass


class CVSSError(AssessmentError):
    """Exception for CVSS scoring errors."""
    pass


class ConfigurationError(AssessmentError):
    """Exception for configuration analysis errors."""
    pass


class ComplianceError(AssessmentError):
    """Exception for compliance checking errors."""
    pass 