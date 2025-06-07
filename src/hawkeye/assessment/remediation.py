"""
Remediation recommendation engine for MCP security assessments.

This module provides centralized remediation recommendation functionality,
aggregating findings from all assessment modules and providing prioritized
remediation guidance with implementation details and timelines.
"""

import time
from enum import Enum
from typing import Dict, List, Any, Set, Tuple
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from .base import (
    AssessmentResult, SecurityFinding, VulnerabilityInfo, RiskLevel, 
    VulnerabilityCategory, ComplianceFramework, RiskAssessor
)
from .exceptions import RemediationError, InvalidFindingError, PrioritizationError
from ..detection.base import DetectionResult
from ..utils.logging import get_logger


class RemediationPriority(Enum):
    """Priority levels for remediation actions."""
    IMMEDIATE = "immediate"  # Critical issues requiring immediate attention
    HIGH = "high"           # High priority, should be addressed within days
    MEDIUM = "medium"       # Medium priority, should be addressed within weeks
    LOW = "low"            # Low priority, can be addressed in next maintenance cycle
    INFORMATIONAL = "informational"  # Informational, no immediate action required


class RemediationComplexity(Enum):
    """Complexity levels for remediation implementation."""
    TRIVIAL = "trivial"      # Simple configuration change
    LOW = "low"             # Minor code or configuration changes
    MEDIUM = "medium"       # Moderate development effort required
    HIGH = "high"           # Significant development or infrastructure changes
    COMPLEX = "complex"     # Major architectural changes required


class RemediationCategory(Enum):
    """Categories of remediation actions."""
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    NETWORK_SECURITY = "network_security"
    ACCESS_CONTROL = "access_control"
    MONITORING = "monitoring"
    COMPLIANCE = "compliance"
    INFRASTRUCTURE = "infrastructure"
    CODE_CHANGES = "code_changes"
    PROCESS_IMPROVEMENT = "process_improvement"


class RemediationAction(BaseModel):
    """A specific remediation action with implementation details."""
    
    id: str
    title: str
    description: str
    category: RemediationCategory
    priority: RemediationPriority
    complexity: RemediationComplexity
    estimated_effort_hours: int
    implementation_steps: List[str] = Field(default_factory=list)
    prerequisites: List[str] = Field(default_factory=list)
    verification_steps: List[str] = Field(default_factory=list)
    tools_required: List[str] = Field(default_factory=list)
    documentation_links: List[str] = Field(default_factory=list)
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    affected_findings: List[str] = Field(default_factory=list)  # Finding IDs
    risk_reduction: float = Field(default=0.0, ge=0.0, le=10.0)  # Expected risk score reduction (0.0-10.0)
    cost_estimate: str | None = None
    timeline_estimate: str | None = None
    
    @field_validator('estimated_effort_hours')
    @classmethod
    def validate_effort_hours(cls, v):
        """Validate effort hours is positive."""
        if v < 0:
            raise ValueError('Estimated effort hours must be non-negative')
        return v
    
    @property
    def priority_score(self) -> int:
        """Calculate numeric priority score for sorting."""
        priority_weights = {
            RemediationPriority.IMMEDIATE: 100,
            RemediationPriority.HIGH: 75,
            RemediationPriority.MEDIUM: 50,
            RemediationPriority.LOW: 25,
            RemediationPriority.INFORMATIONAL: 10
        }
        return priority_weights.get(self.priority, 0)
    
    @property
    def effort_to_impact_ratio(self) -> float:
        """Calculate effort-to-impact ratio for prioritization."""
        if self.estimated_effort_hours == 0:
            return float('inf') if self.risk_reduction == 0 else 0.0
        return self.risk_reduction / self.estimated_effort_hours


class RemediationPlan(BaseModel):
    """A comprehensive remediation plan with prioritized actions."""
    
    target_host: str
    plan_timestamp: float = Field(default_factory=time.time)
    actions: List[RemediationAction] = Field(default_factory=list)
    total_estimated_effort: int = Field(default=0, ge=0)  # Total hours
    total_risk_reduction: float = Field(default=0.0, ge=0.0)
    implementation_phases: List[List[str]] = Field(default_factory=list)  # Action IDs by phase
    executive_summary: str = Field(default="")
    quick_wins: List[str] = Field(default_factory=list)  # Action IDs for quick wins
    long_term_actions: List[str] = Field(default_factory=list)  # Action IDs for long-term
    
    @property
    def immediate_actions(self) -> List[RemediationAction]:
        """Get actions requiring immediate attention."""
        return [a for a in self.actions if a.priority == RemediationPriority.IMMEDIATE]
    
    @property
    def high_priority_actions(self) -> List[RemediationAction]:
        """Get high priority actions."""
        return [a for a in self.actions if a.priority == RemediationPriority.HIGH]
    
    def get_actions_by_category(self, category: RemediationCategory) -> List[RemediationAction]:
        """Get actions filtered by category."""
        return [a for a in self.actions if a.category == category]
    
    def get_actions_by_complexity(self, complexity: RemediationComplexity) -> List[RemediationAction]:
        """Get actions filtered by complexity."""
        return [a for a in self.actions if a.complexity == complexity]
    
    def calculate_totals(self) -> None:
        """Calculate total effort and risk reduction."""
        self.total_estimated_effort = sum(action.estimated_effort_hours for action in self.actions)
        self.total_risk_reduction = sum(action.risk_reduction for action in self.actions)


class RemediationEngine:
    """Central engine for generating remediation recommendations."""
    
    def __init__(self, settings=None):
        """Initialize remediation engine."""
        self.settings = settings or {}
        self.logger = get_logger(__name__)
        self._remediation_templates = self._load_remediation_templates()
    
    def generate_remediation_plan(self, assessment_results: List[AssessmentResult]) -> RemediationPlan:
        """
        Generate comprehensive remediation plan from assessment results.
        
        Args:
            assessment_results: List of assessment results to analyze
            
        Returns:
            RemediationPlan: Comprehensive remediation plan
        """
        self.logger.info(f"Generating remediation plan for {len(assessment_results)} assessment results")
        
        if not assessment_results:
            self.logger.warning("No assessment results provided, returning empty plan")
            return RemediationPlan(target_host="unknown")
        
        # Use first target host as primary (could be enhanced for multi-host)
        target_host = assessment_results[0].target_host
        self.logger.debug(f"Creating remediation plan for target host: {target_host}")
        plan = RemediationPlan(target_host=target_host)
        
        # Aggregate all findings
        all_findings = []
        for result in assessment_results:
            all_findings.extend(result.findings)
        
        self.logger.info(f"Processing {len(all_findings)} total security findings")
        
        # Generate remediation actions
        actions = self._generate_remediation_actions(all_findings)
        self.logger.info(f"Generated {len(actions)} remediation actions")
        
        # Prioritize and organize actions
        plan.actions = self._prioritize_actions(actions)
        
        # Identify quick wins and long-term actions
        plan.quick_wins = self._identify_quick_wins(plan.actions)
        plan.long_term_actions = self._identify_long_term_actions(plan.actions)
        self.logger.debug(f"Identified {len(plan.quick_wins)} quick wins and {len(plan.long_term_actions)} long-term actions")
        
        # Create implementation phases
        plan.implementation_phases = self._create_implementation_phases(plan.actions)
        self.logger.debug(f"Created {len(plan.implementation_phases)} implementation phases")
        
        # Generate executive summary
        plan.executive_summary = self._generate_executive_summary(plan, all_findings)
        
        # Calculate totals
        plan.calculate_totals()
        
        self.logger.info(f"Remediation plan complete: {plan.total_estimated_effort} hours, {plan.total_risk_reduction:.1f} risk reduction")
        return plan
    
    def _generate_remediation_actions(self, findings: List[SecurityFinding]) -> List[RemediationAction]:
        """Generate remediation actions from security findings."""
        try:
            actions = []
            action_id_counter = 1
            
            # Validate findings
            for finding in findings:
                if not finding.id or not finding.title:
                    raise InvalidFindingError(f"Invalid finding: missing required fields (id: {finding.id}, title: {finding.title})")
            
            # Group findings by category for more efficient remediation
            findings_by_category = {}
            for finding in findings:
                if finding.category not in findings_by_category:
                    findings_by_category[finding.category] = []
                findings_by_category[finding.category].append(finding)
            
            # Generate actions for each category
            for category, category_findings in findings_by_category.items():
                category_actions = self._generate_category_actions(category, category_findings, action_id_counter)
                actions.extend(category_actions)
                action_id_counter += len(category_actions)
            
            # Generate cross-cutting actions
            cross_cutting_actions = self._generate_cross_cutting_actions(findings, action_id_counter)
            actions.extend(cross_cutting_actions)
            
            return actions
            
        except InvalidFindingError as e:
            self.logger.error(f"Invalid finding detected: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to generate remediation actions: {e}")
            raise RemediationError(f"Failed to generate remediation actions: {e}") from e
    
    def _generate_category_actions(self, category: VulnerabilityCategory, 
                                 findings: List[SecurityFinding], 
                                 start_id: int) -> List[RemediationAction]:
        """Generate remediation actions for a specific vulnerability category."""
        actions = []
        
        if category == VulnerabilityCategory.AUTHENTICATION:
            actions.extend(self._generate_auth_actions(findings, start_id))
        elif category == VulnerabilityCategory.ENCRYPTION:
            actions.extend(self._generate_encryption_actions(findings, start_id))
        elif category == VulnerabilityCategory.CONFIGURATION:
            actions.extend(self._generate_config_actions(findings, start_id))
        elif category == VulnerabilityCategory.NETWORK:
            actions.extend(self._generate_network_actions(findings, start_id))
        elif category == VulnerabilityCategory.AUTHORIZATION:
            actions.extend(self._generate_authorization_actions(findings, start_id))
        elif category == VulnerabilityCategory.INPUT_VALIDATION:
            actions.extend(self._generate_input_validation_actions(findings, start_id))
        elif category == VulnerabilityCategory.SESSION_MANAGEMENT:
            actions.extend(self._generate_session_actions(findings, start_id))
        elif category == VulnerabilityCategory.ERROR_HANDLING:
            actions.extend(self._generate_error_handling_actions(findings, start_id))
        elif category == VulnerabilityCategory.LOGGING:
            actions.extend(self._generate_logging_actions(findings, start_id))
        elif category == VulnerabilityCategory.COMPLIANCE:
            actions.extend(self._generate_compliance_actions(findings, start_id))
        
        return actions
    
    def _generate_auth_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate authentication-related remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        # Check for specific authentication issues
        has_weak_auth = any("weak" in f.title.lower() or "default" in f.title.lower() for f in findings)
        has_no_auth = any("disabled" in f.title.lower() or "missing" in f.title.lower() for f in findings)
        has_weak_passwords = any("password" in f.title.lower() for f in findings)
        
        if has_no_auth:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Enable Authentication",
                description="Implement authentication mechanisms to secure access to the MCP server",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.IMMEDIATE,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=8,
                implementation_steps=[
                    "Choose appropriate authentication method (API keys, JWT, OAuth)",
                    "Configure authentication middleware",
                    "Update server configuration to require authentication",
                    "Test authentication with valid and invalid credentials",
                    "Update client applications to use authentication"
                ],
                verification_steps=[
                    "Verify unauthenticated requests are rejected",
                    "Test authentication with valid credentials",
                    "Confirm proper error messages for invalid credentials"
                ],
                tools_required=["Authentication library", "Configuration management"],
                documentation_links=[
                    "https://nodejs.org/api/crypto.html",
                    "https://jwt.io/introduction/"
                ],
                affected_findings=finding_ids,
                risk_reduction=7.0,
                timeline_estimate="1-2 days"
            ))
            start_id += 1
        
        if has_weak_passwords:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Strengthen Password Policy",
                description="Implement strong password requirements and replace default passwords",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4,
                implementation_steps=[
                    "Define password complexity requirements",
                    "Implement password validation",
                    "Force password changes for default accounts",
                    "Consider implementing password hashing with salt"
                ],
                verification_steps=[
                    "Test password validation with weak passwords",
                    "Verify strong passwords are accepted",
                    "Confirm default passwords are changed"
                ],
                affected_findings=finding_ids,
                risk_reduction=5.0,
                timeline_estimate="4-8 hours"
            ))
            start_id += 1
        
        if has_weak_auth:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Upgrade Authentication Methods",
                description="Replace weak authentication methods with stronger alternatives",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=12,
                implementation_steps=[
                    "Evaluate current authentication weaknesses",
                    "Select stronger authentication method (JWT, OAuth 2.0)",
                    "Implement new authentication system",
                    "Migrate existing users to new system",
                    "Deprecate old authentication methods"
                ],
                verification_steps=[
                    "Test new authentication system thoroughly",
                    "Verify old methods are disabled",
                    "Confirm security improvements"
                ],
                affected_findings=finding_ids,
                risk_reduction=6.0,
                timeline_estimate="1-2 weeks"
            ))
        
        return actions
    
    def _generate_encryption_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate encryption-related remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        has_no_tls = any("tls" in f.title.lower() or "ssl" in f.title.lower() for f in findings)
        has_weak_crypto = any("weak" in f.title.lower() and "cipher" in f.title.lower() for f in findings)
        
        if has_no_tls:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Enable TLS Encryption",
                description="Configure TLS encryption for secure communication",
                category=RemediationCategory.ENCRYPTION,
                priority=RemediationPriority.IMMEDIATE,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=6,
                implementation_steps=[
                    "Obtain TLS certificate from trusted CA",
                    "Configure server to use TLS 1.2 or higher",
                    "Update client connections to use HTTPS/WSS",
                    "Redirect HTTP traffic to HTTPS",
                    "Test encrypted connections"
                ],
                verification_steps=[
                    "Verify TLS certificate is valid",
                    "Test encrypted communication",
                    "Confirm HTTP redirects to HTTPS"
                ],
                tools_required=["TLS certificate", "Web server configuration"],
                affected_findings=finding_ids,
                risk_reduction=8.0,
                timeline_estimate="1 day"
            ))
            start_id += 1
        
        if has_weak_crypto:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Strengthen Cryptographic Settings",
                description="Update cryptographic settings to use strong algorithms",
                category=RemediationCategory.ENCRYPTION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=3,
                implementation_steps=[
                    "Disable weak cipher suites (RC4, DES, MD5)",
                    "Enable strong cipher suites (AES-256, ChaCha20)",
                    "Configure perfect forward secrecy",
                    "Update TLS version to 1.2 or higher"
                ],
                verification_steps=[
                    "Test cipher suite configuration",
                    "Verify weak ciphers are disabled",
                    "Confirm strong encryption is used"
                ],
                affected_findings=finding_ids,
                risk_reduction=4.0,
                timeline_estimate="2-4 hours"
            ))
        
        return actions
    
    def _generate_config_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate configuration-related remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        has_default_config = any("default" in f.title.lower() for f in findings)
        has_debug_enabled = any("debug" in f.title.lower() for f in findings)
        
        if has_default_config:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Customize Default Configurations",
                description="Replace default configurations with secure custom settings",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4,
                implementation_steps=[
                    "Identify all default configuration values",
                    "Generate secure custom configuration",
                    "Update configuration files",
                    "Test application with new configuration"
                ],
                verification_steps=[
                    "Verify no default values remain",
                    "Test application functionality",
                    "Confirm security improvements"
                ],
                affected_findings=finding_ids,
                risk_reduction=3.0,
                timeline_estimate="4-6 hours"
            ))
            start_id += 1
        
        if has_debug_enabled:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Disable Debug Mode",
                description="Disable debug mode and verbose error messages in production",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.TRIVIAL,
                estimated_effort_hours=1,
                implementation_steps=[
                    "Set debug mode to false in configuration",
                    "Configure appropriate logging levels",
                    "Remove debug endpoints if present",
                    "Test error handling in production mode"
                ],
                verification_steps=[
                    "Verify debug information is not exposed",
                    "Test error responses are generic",
                    "Confirm logging is appropriate"
                ],
                affected_findings=finding_ids,
                risk_reduction=2.0,
                timeline_estimate="30 minutes"
            ))
        
        return actions
    
    def _generate_network_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate network security remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        has_cors_issues = any("cors" in f.title.lower() for f in findings)
        has_port_issues = any("port" in f.title.lower() for f in findings)
        
        if has_cors_issues:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Configure Secure CORS Policy",
                description="Implement restrictive CORS policy to prevent unauthorized cross-origin requests",
                category=RemediationCategory.NETWORK_SECURITY,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2,
                implementation_steps=[
                    "Define allowed origins for CORS",
                    "Configure CORS middleware with specific origins",
                    "Remove wildcard (*) CORS policies",
                    "Test CORS policy with legitimate and unauthorized requests"
                ],
                verification_steps=[
                    "Verify unauthorized origins are blocked",
                    "Test legitimate cross-origin requests work",
                    "Confirm no wildcard policies remain"
                ],
                affected_findings=finding_ids,
                risk_reduction=4.0,
                timeline_estimate="1-2 hours"
            ))
            start_id += 1
        
        if has_port_issues:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Secure Network Configuration",
                description="Configure secure network settings and port usage",
                category=RemediationCategory.NETWORK_SECURITY,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=3,
                implementation_steps=[
                    "Change default ports to non-standard values",
                    "Bind services to specific interfaces",
                    "Configure firewall rules",
                    "Implement rate limiting"
                ],
                verification_steps=[
                    "Verify services use non-default ports",
                    "Test network access restrictions",
                    "Confirm rate limiting is effective"
                ],
                affected_findings=finding_ids,
                risk_reduction=3.0,
                timeline_estimate="2-4 hours"
            ))
        
        return actions
    
    def _generate_authorization_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate authorization-related remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        actions.append(RemediationAction(
            id=f"REM_{start_id:04d}",
            title="Implement Access Control",
            description="Implement proper authorization and access control mechanisms",
            category=RemediationCategory.ACCESS_CONTROL,
            priority=RemediationPriority.HIGH,
            complexity=RemediationComplexity.MEDIUM,
            estimated_effort_hours=10,
            implementation_steps=[
                "Define user roles and permissions",
                "Implement role-based access control (RBAC)",
                "Add authorization checks to all endpoints",
                "Test access control with different user roles"
            ],
            verification_steps=[
                "Verify unauthorized access is prevented",
                "Test role-based permissions",
                "Confirm principle of least privilege"
            ],
            affected_findings=finding_ids,
            risk_reduction=6.0,
            timeline_estimate="1-2 weeks"
        ))
        
        return actions
    
    def _generate_input_validation_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate input validation remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        actions.append(RemediationAction(
            id=f"REM_{start_id:04d}",
            title="Implement Input Validation",
            description="Add comprehensive input validation and sanitization",
            category=RemediationCategory.CODE_CHANGES,
            priority=RemediationPriority.HIGH,
            complexity=RemediationComplexity.MEDIUM,
            estimated_effort_hours=8,
            implementation_steps=[
                "Identify all input points",
                "Implement input validation schemas",
                "Add input sanitization",
                "Test with malicious input payloads"
            ],
            verification_steps=[
                "Verify malicious input is rejected",
                "Test input sanitization",
                "Confirm proper error handling"
            ],
            affected_findings=finding_ids,
            risk_reduction=5.0,
            timeline_estimate="1 week"
        ))
        
        return actions
    
    def _generate_session_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate session management remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        actions.append(RemediationAction(
            id=f"REM_{start_id:04d}",
            title="Secure Session Management",
            description="Implement secure session management practices",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.MEDIUM,
            complexity=RemediationComplexity.MEDIUM,
            estimated_effort_hours=6,
            implementation_steps=[
                "Implement secure session tokens",
                "Configure session timeouts",
                "Add session invalidation",
                "Implement session fixation protection"
            ],
            verification_steps=[
                "Test session timeout functionality",
                "Verify session invalidation works",
                "Test session fixation protection"
            ],
            affected_findings=finding_ids,
            risk_reduction=4.0,
            timeline_estimate="3-5 days"
        ))
        
        return actions
    
    def _generate_error_handling_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate error handling remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        actions.append(RemediationAction(
            id=f"REM_{start_id:04d}",
            title="Improve Error Handling",
            description="Implement secure error handling and logging",
            category=RemediationCategory.CODE_CHANGES,
            priority=RemediationPriority.LOW,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=4,
            implementation_steps=[
                "Implement generic error messages",
                "Add proper error logging",
                "Remove stack traces from responses",
                "Test error handling scenarios"
            ],
            verification_steps=[
                "Verify no sensitive information in errors",
                "Test error logging functionality",
                "Confirm generic error messages"
            ],
            affected_findings=finding_ids,
            risk_reduction=2.0,
            timeline_estimate="2-4 hours"
        ))
        
        return actions
    
    def _generate_logging_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate logging-related remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        actions.append(RemediationAction(
            id=f"REM_{start_id:04d}",
            title="Implement Security Logging",
            description="Implement comprehensive security logging and monitoring",
            category=RemediationCategory.MONITORING,
            priority=RemediationPriority.MEDIUM,
            complexity=RemediationComplexity.MEDIUM,
            estimated_effort_hours=8,
            implementation_steps=[
                "Define security events to log",
                "Implement structured logging",
                "Configure log rotation and retention",
                "Set up log monitoring and alerting"
            ],
            verification_steps=[
                "Verify security events are logged",
                "Test log rotation functionality",
                "Confirm monitoring alerts work"
            ],
            affected_findings=finding_ids,
            risk_reduction=3.0,
            timeline_estimate="1 week"
        ))
        
        return actions
    
    def _generate_compliance_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate compliance-related remediation actions."""
        actions = []
        finding_ids = [f.id for f in findings]
        
        # Extract compliance frameworks from findings
        frameworks = set()
        for finding in findings:
            frameworks.update(finding.compliance_violations)
        
        if frameworks:
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Address Compliance Violations",
                description=f"Address compliance violations for {', '.join(f.value for f in frameworks)}",
                category=RemediationCategory.COMPLIANCE,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.HIGH,
                estimated_effort_hours=16,
                implementation_steps=[
                    "Review compliance requirements",
                    "Implement required controls",
                    "Document compliance measures",
                    "Conduct compliance audit"
                ],
                verification_steps=[
                    "Verify compliance controls are implemented",
                    "Test compliance measures",
                    "Document compliance status"
                ],
                compliance_frameworks=list(frameworks),
                affected_findings=finding_ids,
                risk_reduction=4.0,
                timeline_estimate="2-4 weeks"
            ))
        
        return actions
    
    def _generate_cross_cutting_actions(self, findings: List[SecurityFinding], start_id: int) -> List[RemediationAction]:
        """Generate cross-cutting remediation actions that address multiple categories."""
        actions = []
        
        # Security monitoring and incident response
        if len(findings) > 5:  # If there are many findings, recommend monitoring
            actions.append(RemediationAction(
                id=f"REM_{start_id:04d}",
                title="Implement Security Monitoring",
                description="Implement comprehensive security monitoring and incident response",
                category=RemediationCategory.MONITORING,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.HIGH,
                estimated_effort_hours=20,
                implementation_steps=[
                    "Deploy security monitoring tools",
                    "Configure security alerts",
                    "Develop incident response procedures",
                    "Train team on security monitoring"
                ],
                verification_steps=[
                    "Test security monitoring alerts",
                    "Verify incident response procedures",
                    "Confirm monitoring coverage"
                ],
                tools_required=["SIEM", "Log aggregation", "Alerting system"],
                affected_findings=[f.id for f in findings],
                risk_reduction=5.0,
                timeline_estimate="3-4 weeks"
            ))
            start_id += 1
        
        # Security training and awareness
        actions.append(RemediationAction(
            id=f"REM_{start_id:04d}",
            title="Security Training and Awareness",
            description="Provide security training to development and operations teams",
            category=RemediationCategory.PROCESS_IMPROVEMENT,
            priority=RemediationPriority.LOW,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=8,
            implementation_steps=[
                "Develop security training materials",
                "Conduct security awareness sessions",
                "Establish security best practices",
                "Regular security updates and training"
            ],
            verification_steps=[
                "Verify team understands security practices",
                "Test knowledge through assessments",
                "Monitor adherence to security practices"
            ],
            affected_findings=[],
            risk_reduction=2.0,
            timeline_estimate="Ongoing"
        ))
        
        return actions
    
    def _prioritize_actions(self, actions: List[RemediationAction]) -> List[RemediationAction]:
        """Prioritize remediation actions based on multiple criteria."""
        
        def priority_key(action: RemediationAction) -> Tuple[int, float, int]:
            # Sort by: priority score (desc), effort-to-impact ratio (asc), effort hours (asc)
            return (-action.priority_score, action.effort_to_impact_ratio, action.estimated_effort_hours)
        
        return sorted(actions, key=priority_key)
    
    def _identify_quick_wins(self, actions: List[RemediationAction]) -> List[str]:
        """Identify quick win actions (low effort, high impact)."""
        quick_wins = []
        
        for action in actions:
            # Quick wins: <= 4 hours effort and >= 3.0 risk reduction
            if action.estimated_effort_hours <= 4 and action.risk_reduction >= 3.0:
                quick_wins.append(action.id)
        
        return quick_wins
    
    def _identify_long_term_actions(self, actions: List[RemediationAction]) -> List[str]:
        """Identify long-term actions (high effort or complexity)."""
        long_term = []
        
        for action in actions:
            # Long-term: > 16 hours effort or high/complex complexity
            if (action.estimated_effort_hours > 16 or 
                action.complexity in [RemediationComplexity.HIGH, RemediationComplexity.COMPLEX]):
                long_term.append(action.id)
        
        return long_term
    
    def _create_implementation_phases(self, actions: List[RemediationAction]) -> List[List[str]]:
        """Create implementation phases for remediation actions."""
        phases = [[], [], [], []]  # 4 phases
        
        for action in actions:
            if action.priority == RemediationPriority.IMMEDIATE:
                phases[0].append(action.id)
            elif action.priority == RemediationPriority.HIGH:
                phases[1].append(action.id)
            elif action.priority == RemediationPriority.MEDIUM:
                phases[2].append(action.id)
            else:
                phases[3].append(action.id)
        
        return [phase for phase in phases if phase]  # Remove empty phases
    
    def _generate_executive_summary(self, plan: RemediationPlan, findings: List[SecurityFinding]) -> str:
        """Generate executive summary for the remediation plan."""
        
        critical_count = len([f for f in findings if f.severity == RiskLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == RiskLevel.HIGH])
        
        summary_parts = [
            f"Security assessment identified {len(findings)} security findings for {plan.target_host}.",
        ]
        
        if critical_count > 0:
            summary_parts.append(f"{critical_count} critical severity issues require immediate attention.")
        
        if high_count > 0:
            summary_parts.append(f"{high_count} high severity issues should be addressed within days.")
        
        summary_parts.extend([
            f"Remediation plan includes {len(plan.actions)} recommended actions.",
            f"Total estimated effort: {plan.total_estimated_effort} hours.",
            f"Expected risk reduction: {plan.total_risk_reduction:.1f} points.",
        ])
        
        if plan.quick_wins:
            summary_parts.append(f"{len(plan.quick_wins)} quick wins identified for immediate implementation.")
        
        return " ".join(summary_parts)
    
    def _load_remediation_templates(self) -> Dict[str, Any]:
        """Load remediation templates and patterns."""
        # This could be loaded from external files in a real implementation
        return {
            "authentication": {
                "enable_auth": {
                    "title": "Enable Authentication",
                    "steps": ["Configure auth middleware", "Update configuration", "Test authentication"],
                    "effort_hours": 8,
                    "complexity": "medium"
                }
            },
            "encryption": {
                "enable_tls": {
                    "title": "Enable TLS Encryption",
                    "steps": ["Obtain certificate", "Configure TLS", "Test encryption"],
                    "effort_hours": 6,
                    "complexity": "medium"
                }
            }
        }


# Convenience functions
def generate_remediation_plan(assessment_results: List[AssessmentResult], settings=None) -> RemediationPlan:
    """
    Generate remediation plan from assessment results.
    
    Args:
        assessment_results: List of assessment results
        settings: Optional settings
        
    Returns:
        RemediationPlan: Generated remediation plan
    """
    engine = RemediationEngine(settings)
    return engine.generate_remediation_plan(assessment_results)


def get_quick_wins(remediation_plan: RemediationPlan) -> List[RemediationAction]:
    """
    Get quick win actions from remediation plan.
    
    Args:
        remediation_plan: Remediation plan to analyze
        
    Returns:
        List[RemediationAction]: Quick win actions
    """
    return [action for action in remediation_plan.actions if action.id in remediation_plan.quick_wins]


def estimate_implementation_time(remediation_plan: RemediationPlan) -> Dict[str, Any]:
    """
    Estimate implementation time for remediation plan.
    
    Args:
        remediation_plan: Remediation plan to analyze
        
    Returns:
        Dict[str, Any]: Time estimates by priority and phase
    """
    estimates = {
        "total_hours": remediation_plan.total_estimated_effort,
        "by_priority": {},
        "by_phase": [],
        "quick_wins_hours": 0,
        "long_term_hours": 0
    }
    
    # Calculate by priority
    for priority in RemediationPriority:
        priority_actions = [a for a in remediation_plan.actions if a.priority == priority]
        estimates["by_priority"][priority.value] = sum(a.estimated_effort_hours for a in priority_actions)
    
    # Calculate by phase
    for i, phase in enumerate(remediation_plan.implementation_phases):
        phase_actions = [a for a in remediation_plan.actions if a.id in phase]
        phase_hours = sum(a.estimated_effort_hours for a in phase_actions)
        estimates["by_phase"].append({
            "phase": i + 1,
            "hours": phase_hours,
            "actions": len(phase_actions)
        })
    
    # Calculate quick wins and long-term
    quick_win_actions = [a for a in remediation_plan.actions if a.id in remediation_plan.quick_wins]
    long_term_actions = [a for a in remediation_plan.actions if a.id in remediation_plan.long_term_actions]
    
    estimates["quick_wins_hours"] = sum(a.estimated_effort_hours for a in quick_win_actions)
    estimates["long_term_hours"] = sum(a.estimated_effort_hours for a in long_term_actions)
    
    return estimates 