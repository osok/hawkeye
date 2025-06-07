"""
Risk Assessment Module for HawkEye Security Reconnaissance Tool.

This module provides comprehensive security risk assessment capabilities for
identified MCP (Model Context Protocol) server deployments, including CVSS-based
vulnerability scoring, security configuration analysis, and remediation recommendations.
"""

from .base import (
    RiskAssessment,
    RiskAssessor,
    VulnerabilityInfo,
    SecurityFinding,
    RiskLevel,
    AssessmentResult,
    AssessmentError,
    CVSSError,
    ConfigurationError,
    ComplianceError,
    CVSSVector,
    VulnerabilityCategory,
    ComplianceFramework,
)

from .exceptions import (
    RemediationError,
    InvalidFindingError,
    RemediationTemplateError,
    PrioritizationError,
    RiskCalculationError,
)

from .cvss_scoring import (
    CVSSScores,
    CVSSCalculator,
    CVSSAssessment,
    calculate_cvss_score,
    get_risk_level_from_score,
)

from .config_analysis import (
    ConfigurationIssue,
    SecurityConfiguration,
    ConfigurationAnalyzer,
    analyze_configuration,
)

from .default_detect import (
    DefaultPattern,
    DefaultDetectionResult,
    DefaultConfigurationDetector,
    detect_default_configurations,
    get_default_patterns,
    check_for_pattern,
)

from .auth_analysis import (
    AuthenticationIssue,
    AuthenticationConfiguration,
    AuthenticationAnalyzer,
    analyze_authentication,
    check_password_strength,
    validate_jwt_token,
)

from .remediation import (
    RemediationPriority,
    RemediationComplexity,
    RemediationCategory,
    RemediationAction,
    RemediationPlan,
    RemediationEngine,
    generate_remediation_plan,
    get_quick_wins,
    estimate_implementation_time,
)

__all__ = [
    # Base classes
    'RiskAssessment',
    'RiskAssessor',
    'VulnerabilityInfo',
    'SecurityFinding',
    'RiskLevel',
    'AssessmentResult',
    'CVSSVector',
    'VulnerabilityCategory',
    'ComplianceFramework',
    
    # CVSS scoring
    'CVSSScores',
    'CVSSCalculator',
    'CVSSAssessment',
    'calculate_cvss_score',
    'get_risk_level_from_score',
    
    # Configuration analysis
    'ConfigurationIssue',
    'SecurityConfiguration',
    'ConfigurationAnalyzer',
    'analyze_configuration',
    
    # Default detection
    'DefaultPattern',
    'DefaultDetectionResult',
    'DefaultConfigurationDetector',
    'detect_default_configurations',
    'get_default_patterns',
    'check_for_pattern',
    
    # Authentication analysis
    'AuthenticationIssue',
    'AuthenticationConfiguration',
    'AuthenticationAnalyzer',
    'analyze_authentication',
    'check_password_strength',
    'validate_jwt_token',
    
    # Remediation
    'RemediationPriority',
    'RemediationComplexity',
    'RemediationCategory',
    'RemediationAction',
    'RemediationPlan',
    'RemediationEngine',
    'generate_remediation_plan',
    'get_quick_wins',
    'estimate_implementation_time',
    
    # Exceptions
    'AssessmentError',
    'CVSSError',
    'ConfigurationError',
    'ComplianceError',
    'RemediationError',
    'InvalidFindingError',
    'RemediationTemplateError',
    'PrioritizationError',
    'RiskCalculationError',
] 