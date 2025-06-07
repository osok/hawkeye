"""
Authentication Analysis for MCP servers.

This module provides specialized analysis capabilities for identifying weak
authentication mechanisms and authentication-related vulnerabilities in MCP
(Model Context Protocol) server deployments.
"""

import re
import json
import hashlib
import base64
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from urllib.parse import urlparse
from datetime import datetime, timedelta

from .base import (
    RiskAssessor, AssessmentResult, SecurityFinding, VulnerabilityInfo,
    RiskLevel, VulnerabilityCategory, ComplianceFramework, ConfigurationError
)
from ..detection.base import DetectionResult, MCPServerInfo, TransportType
from ..utils.logging import get_logger


@dataclass
class AuthenticationIssue:
    """Represents an authentication-related security issue."""
    
    issue_id: str
    name: str
    description: str
    severity: RiskLevel
    category: str  # e.g., "weak_password", "no_auth", "insecure_token"
    affected_component: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    compliance_violations: List[ComplianceFramework] = field(default_factory=list)


@dataclass
class AuthenticationConfiguration:
    """Represents the authentication configuration of an MCP server."""
    
    target_host: str
    authentication_enabled: bool = False
    authentication_methods: List[str] = field(default_factory=list)
    password_policies: Dict[str, Any] = field(default_factory=dict)
    token_configurations: Dict[str, Any] = field(default_factory=dict)
    session_configurations: Dict[str, Any] = field(default_factory=dict)
    multi_factor_auth: bool = False
    encryption_in_transit: bool = False
    issues: List[AuthenticationIssue] = field(default_factory=list)
    security_score: float = 0.0  # 0.0 (worst) to 10.0 (best)
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def critical_issues(self) -> List[AuthenticationIssue]:
        """Get critical severity authentication issues."""
        return [issue for issue in self.issues if issue.severity == RiskLevel.CRITICAL]
    
    @property
    def high_issues(self) -> List[AuthenticationIssue]:
        """Get high severity authentication issues."""
        return [issue for issue in self.issues if issue.severity == RiskLevel.HIGH]
    
    def get_issues_by_category(self, category: str) -> List[AuthenticationIssue]:
        """Get authentication issues filtered by category."""
        return [issue for issue in self.issues if issue.category == category]
    
    def calculate_security_score(self) -> None:
        """Calculate overall authentication security score."""
        base_score = 10.0
        
        # Deduct points for issues based on severity
        severity_deductions = {
            RiskLevel.CRITICAL: 3.0,
            RiskLevel.HIGH: 2.0,
            RiskLevel.MEDIUM: 1.0,
            RiskLevel.LOW: 0.5,
            RiskLevel.NONE: 0.0
        }
        
        for issue in self.issues:
            deduction = severity_deductions.get(issue.severity, 0)
            base_score -= deduction
        
        # Bonus points for good practices
        if self.authentication_enabled:
            base_score += 1.0
        if self.multi_factor_auth:
            base_score += 1.0
        if self.encryption_in_transit:
            base_score += 0.5
        if len(self.authentication_methods) > 1:
            base_score += 0.5
        
        # Ensure score is within bounds
        self.security_score = max(0.0, min(10.0, base_score))


class AuthenticationAnalyzer(RiskAssessor):
    """Analyzes authentication mechanisms and identifies weaknesses in MCP servers."""
    
    def __init__(self, settings=None):
        """Initialize the authentication analyzer."""
        super().__init__(settings)
        self.logger = get_logger(self.__class__.__name__)
        
        # Initialize weak password patterns
        self._init_weak_password_patterns()
        
        # Initialize authentication rules
        self._init_authentication_rules()
    
    def _init_weak_password_patterns(self) -> None:
        """Initialize patterns for detecting weak passwords."""
        
        self.weak_password_patterns = [
            # Common weak passwords
            r'^(password|admin|root|user|guest|test|demo)$',
            r'^(123456|password123|admin123|qwerty|letmein)$',
            r'^(welcome|changeme|default|secret|public)$',
            
            # Sequential patterns
            r'^(123456789|abcdefgh|qwertyui)$',
            r'^(111111|222222|333333|aaaaaa|bbbbbb)$',
            
            # Short passwords (less than 8 characters)
            r'^.{1,7}$',
            
            # Dictionary words
            r'^(computer|internet|network|server|system)$',
            r'^(company|business|office|manager|employee)$',
            
            # Keyboard patterns
            r'^(qwerty|asdfgh|zxcvbn|123qwe|abc123)$',
            r'^(qaz|wsx|edc|rfv|tgb|yhn|ujm)$',
            
            # Date patterns
            r'^\d{4}$',  # Year only
            r'^\d{2}/\d{2}/\d{4}$',  # Date format
            r'^\d{8}$',  # YYYYMMDD
        ]
        
        # Compile patterns for performance
        self.compiled_weak_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.weak_password_patterns]
    
    def _init_authentication_rules(self) -> None:
        """Initialize authentication security rules."""
        
        self.auth_rules = {
            # No authentication rules
            'no_authentication': {
                'patterns': [
                    r'"auth"\s*:\s*false',
                    r'"authentication"\s*:\s*false',
                    r'"require[_-]?auth"\s*:\s*false',
                    r'"no[_-]?auth"\s*:\s*true',
                    r'--no-auth',
                    r'--disable-auth'
                ],
                'severity': RiskLevel.CRITICAL,
                'description': 'Authentication is disabled',
                'remediation': 'Enable authentication to secure access'
            },
            
            # Weak password rules
            'weak_password': {
                'patterns': [
                    r'"password"\s*:\s*"(admin|password|123456|root|guest)"',
                    r'"pass"\s*:\s*"[^"]{1,7}"',  # Short passwords
                    r'"pwd"\s*:\s*"(test|demo|changeme)"',
                    r'password\s*=\s*(admin|password|123456)'
                ],
                'severity': RiskLevel.HIGH,
                'description': 'Weak or default password detected',
                'remediation': 'Use strong, unique passwords with complexity requirements'
            },
            
            # Hardcoded credentials
            'hardcoded_credentials': {
                'patterns': [
                    r'"username"\s*:\s*"admin".*"password"\s*:\s*"[^"]+"',
                    r'"user"\s*:\s*"root".*"pass"\s*:\s*"[^"]+"',
                    r'"login"\s*:\s*"[^"]+".*"password"\s*:\s*"[^"]+"',
                    r'Basic\s+[A-Za-z0-9+/=]+',  # Base64 encoded credentials
                    r'Bearer\s+[A-Za-z0-9\-._~+/]+'  # Bearer tokens
                ],
                'severity': RiskLevel.HIGH,
                'description': 'Hardcoded credentials found in configuration',
                'remediation': 'Use environment variables or secure credential storage'
            },
            
            # Weak token/API key rules
            'weak_tokens': {
                'patterns': [
                    r'"api[_-]?key"\s*:\s*"(test|demo|example|sample|key)"',
                    r'"token"\s*:\s*"[^"]{1,16}"',  # Short tokens
                    r'"secret"\s*:\s*"(secret|key|token|password)"',
                    r'"jwt[_-]?secret"\s*:\s*"[^"]{1,32}"',  # Short JWT secrets
                    r'API_KEY\s*=\s*(test|demo|example|sample)'
                ],
                'severity': RiskLevel.HIGH,
                'description': 'Weak API key or token detected',
                'remediation': 'Generate strong, random API keys and tokens'
            },
            
            # Session security rules
            'insecure_sessions': {
                'patterns': [
                    r'"session[_-]?secret"\s*:\s*"[^"]{1,16}"',  # Short session secrets
                    r'"cookie[_-]?secure"\s*:\s*false',
                    r'"http[_-]?only"\s*:\s*false',
                    r'"same[_-]?site"\s*:\s*"none"',
                    r'"session[_-]?timeout"\s*:\s*\d{7,}'  # Very long timeouts
                ],
                'severity': RiskLevel.MEDIUM,
                'description': 'Insecure session configuration detected',
                'remediation': 'Configure secure session settings with proper timeouts'
            },
            
            # OAuth/JWT security rules
            'oauth_jwt_issues': {
                'patterns': [
                    r'"algorithm"\s*:\s*"none"',  # No signature algorithm
                    r'"verify"\s*:\s*false',  # Signature verification disabled
                    r'"iss"\s*:\s*"(test|demo|localhost)"',  # Test issuers
                    r'"aud"\s*:\s*"\*"',  # Wildcard audience
                    r'"exp"\s*:\s*\d{13,}'  # Very long expiration times
                ],
                'severity': RiskLevel.HIGH,
                'description': 'Insecure OAuth/JWT configuration detected',
                'remediation': 'Configure proper JWT validation and security settings'
            },
            
            # Multi-factor authentication rules
            'no_mfa': {
                'patterns': [
                    r'"mfa"\s*:\s*false',
                    r'"two[_-]?factor"\s*:\s*false',
                    r'"2fa"\s*:\s*false',
                    r'"multi[_-]?factor"\s*:\s*false'
                ],
                'severity': RiskLevel.MEDIUM,
                'description': 'Multi-factor authentication is disabled',
                'remediation': 'Enable multi-factor authentication for enhanced security'
            },
            
            # Password policy rules
            'weak_password_policy': {
                'patterns': [
                    r'"min[_-]?length"\s*:\s*[1-7]',  # Short minimum length
                    r'"require[_-]?uppercase"\s*:\s*false',
                    r'"require[_-]?lowercase"\s*:\s*false',
                    r'"require[_-]?numbers"\s*:\s*false',
                    r'"require[_-]?special"\s*:\s*false',
                    r'"password[_-]?expiry"\s*:\s*0'  # No password expiry
                ],
                'severity': RiskLevel.MEDIUM,
                'description': 'Weak password policy configuration',
                'remediation': 'Implement strong password policy requirements'
            },
            
            # Rate limiting rules
            'no_rate_limiting': {
                'patterns': [
                    r'"rate[_-]?limit"\s*:\s*false',
                    r'"login[_-]?attempts"\s*:\s*0',
                    r'"throttle"\s*:\s*false',
                    r'"brute[_-]?force[_-]?protection"\s*:\s*false'
                ],
                'severity': RiskLevel.MEDIUM,
                'description': 'Authentication rate limiting is disabled',
                'remediation': 'Enable rate limiting to prevent brute force attacks'
            }
        }
    
    def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
        """
        Perform authentication analysis on a detection result.
        
        Args:
            detection_result: Result from MCP detection
            **kwargs: Additional assessment parameters
            
        Returns:
            AssessmentResult: Result of the authentication analysis
        """
        try:
            self.logger.info(f"Starting authentication analysis for {detection_result.target_host}")
            
            # Perform authentication analysis
            auth_config = self._analyze_authentication(detection_result)
            
            # Convert authentication issues to security findings
            findings = self._convert_issues_to_findings(auth_config)
            
            # Create assessment result
            result = AssessmentResult(
                target_host=detection_result.target_host,
                findings=findings
            )
            
            # Calculate overall risk
            result.calculate_overall_risk()
            
            # Add authentication-specific recommendations
            result.recommendations.extend(auth_config.recommendations)
            
            # Store raw authentication data
            result.raw_data['authentication_analysis'] = {
                'authentication_enabled': auth_config.authentication_enabled,
                'authentication_methods': auth_config.authentication_methods,
                'multi_factor_auth': auth_config.multi_factor_auth,
                'encryption_in_transit': auth_config.encryption_in_transit,
                'security_score': auth_config.security_score,
                'issues_count': len(auth_config.issues),
                'critical_issues_count': len(auth_config.critical_issues),
                'high_issues_count': len(auth_config.high_issues)
            }
            
            self.logger.info(f"Authentication analysis completed for {detection_result.target_host}")
            return result
            
        except Exception as e:
            self.logger.error(f"Authentication analysis failed for {detection_result.target_host}: {e}")
            raise ConfigurationError(f"Failed to analyze authentication: {e}")
    
    def get_assessment_type(self) -> str:
        """Get the type of assessment performed by this assessor."""
        return "authentication_analysis"
    
    def _analyze_authentication(self, detection_result: DetectionResult) -> AuthenticationConfiguration:
        """Analyze authentication configuration in the detection result."""
        
        config = AuthenticationConfiguration(target_host=detection_result.target_host)
        
        # Analyze MCP server authentication
        if detection_result.mcp_server:
            self._analyze_server_authentication(detection_result.mcp_server, config)
        
        # Analyze raw data for authentication patterns
        if detection_result.raw_data:
            self._analyze_raw_data_authentication(detection_result.raw_data, config)
        
        # Calculate security score
        config.calculate_security_score()
        
        # Generate recommendations
        self._generate_auth_recommendations(config)
        
        return config
    
    def _analyze_server_authentication(self, server_info: MCPServerInfo, config: AuthenticationConfiguration) -> None:
        """Analyze MCP server authentication configuration."""
        
        # Check if authentication is enabled
        if server_info.authentication:
            config.authentication_enabled = server_info.authentication.get('enabled', False)
            
            # Check if authentication is explicitly disabled
            if not config.authentication_enabled:
                issue = AuthenticationIssue(
                    issue_id="AUTH_DISABLED",
                    name="Authentication Disabled",
                    description="Authentication is explicitly disabled in configuration",
                    severity=RiskLevel.CRITICAL,
                    category="no_authentication",
                    affected_component="authentication_configuration",
                    remediation="Enable authentication for the MCP server"
                )
                config.issues.append(issue)
            
            # Extract authentication methods
            auth_methods = server_info.authentication.get('methods', [])
            if isinstance(auth_methods, str):
                auth_methods = [auth_methods]
            config.authentication_methods = auth_methods
            
            # Check for multi-factor authentication
            config.multi_factor_auth = server_info.authentication.get('mfa', False) or \
                                     server_info.authentication.get('two_factor', False)
            
            # Analyze authentication configuration
            self._analyze_auth_config(server_info.authentication, config)
        else:
            # No authentication configuration found
            issue = AuthenticationIssue(
                issue_id="NO_AUTH_CONFIG",
                name="No Authentication Configuration",
                description="No authentication configuration found",
                severity=RiskLevel.HIGH,
                category="no_authentication",
                affected_component="server_configuration",
                remediation="Configure authentication for the MCP server"
            )
            config.issues.append(issue)
        
        # Check transport security
        if server_info.transport_type in [TransportType.HTTP, TransportType.WEBSOCKET]:
            # Check if using HTTPS/WSS
            if server_info.security_config:
                config.encryption_in_transit = server_info.security_config.get('tls_enabled', False) or \
                                             server_info.security_config.get('ssl_enabled', False)
            
            if not config.encryption_in_transit:
                issue = AuthenticationIssue(
                    issue_id="NO_TRANSPORT_ENCRYPTION",
                    name="No Transport Encryption",
                    description="Authentication credentials transmitted without encryption",
                    severity=RiskLevel.HIGH,
                    category="insecure_transport",
                    affected_component="transport_layer",
                    remediation="Enable HTTPS/WSS for secure credential transmission",
                    compliance_violations=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.PCI_DSS]
                )
                config.issues.append(issue)
    
    def _analyze_auth_config(self, auth_config: Dict[str, Any], config: AuthenticationConfiguration) -> None:
        """Analyze detailed authentication configuration."""
        
        auth_str = json.dumps(auth_config, indent=2).lower()
        
        # Apply authentication rules
        for rule_name, rule_config in self.auth_rules.items():
            for pattern in rule_config['patterns']:
                if re.search(pattern, auth_str, re.IGNORECASE):
                    issue = AuthenticationIssue(
                        issue_id=f"AUTH_{rule_name.upper()}_{hash(auth_str) % 10000:04d}",
                        name=rule_config['description'],
                        description=f"{rule_config['description']} detected in authentication configuration",
                        severity=rule_config['severity'],
                        category=rule_name,
                        affected_component="authentication_configuration",
                        evidence={'pattern': pattern, 'config': auth_config},
                        remediation=rule_config['remediation']
                    )
                    config.issues.append(issue)
                    break
        
        # Analyze specific authentication components
        self._analyze_passwords(auth_config, config)
        self._analyze_tokens(auth_config, config)
        self._analyze_sessions(auth_config, config)
    
    def _analyze_passwords(self, auth_config: Dict[str, Any], config: AuthenticationConfiguration) -> None:
        """Analyze password-related configuration."""
        
        # Extract password policies
        password_policy = auth_config.get('password_policy', {})
        config.password_policies = password_policy
        
        # Check for weak password policies
        min_length = password_policy.get('min_length', 0)
        if min_length < 8:
            issue = AuthenticationIssue(
                issue_id="WEAK_PASSWORD_POLICY",
                name="Weak Password Policy",
                description=f"Minimum password length is {min_length}, should be at least 8",
                severity=RiskLevel.MEDIUM,
                category="weak_password_policy",
                affected_component="password_policy",
                evidence={'min_length': min_length},
                remediation="Set minimum password length to at least 8 characters"
            )
            config.issues.append(issue)
        
        # Check for password complexity requirements
        complexity_checks = [
            ('require_uppercase', 'uppercase letters'),
            ('require_lowercase', 'lowercase letters'),
            ('require_numbers', 'numbers'),
            ('require_special', 'special characters')
        ]
        
        for check, description in complexity_checks:
            if not password_policy.get(check, False):
                issue = AuthenticationIssue(
                    issue_id=f"NO_{check.upper()}",
                    name=f"No {description.title()} Requirement",
                    description=f"Password policy does not require {description}",
                    severity=RiskLevel.LOW,
                    category="weak_password_policy",
                    affected_component="password_policy",
                    remediation=f"Require {description} in passwords"
                )
                config.issues.append(issue)
        
        # Check for hardcoded passwords
        for key, value in auth_config.items():
            if 'password' in key.lower() and isinstance(value, str):
                if self._is_weak_password(value):
                    issue = AuthenticationIssue(
                        issue_id="WEAK_HARDCODED_PASSWORD",
                        name="Weak Hardcoded Password",
                        description=f"Weak password found in configuration: {key}",
                        severity=RiskLevel.HIGH,
                        category="weak_password",
                        affected_component="authentication_configuration",
                        evidence={'field': key, 'password_length': len(value)},
                        remediation="Use strong passwords and avoid hardcoding credentials"
                    )
                    config.issues.append(issue)
    
    def _analyze_tokens(self, auth_config: Dict[str, Any], config: AuthenticationConfiguration) -> None:
        """Analyze token-related configuration."""
        
        # Extract token configurations
        token_config = auth_config.get('tokens', {})
        config.token_configurations = token_config
        
        # Check for weak API keys and tokens
        token_fields = ['api_key', 'token', 'secret', 'jwt_secret', 'signing_key']
        
        for field in token_fields:
            value = auth_config.get(field) or token_config.get(field)
            if value and isinstance(value, str):
                if len(value) < 32:  # Tokens should be at least 32 characters
                    issue = AuthenticationIssue(
                        issue_id=f"WEAK_{field.upper()}",
                        name=f"Weak {field.replace('_', ' ').title()}",
                        description=f"{field} is too short ({len(value)} characters)",
                        severity=RiskLevel.HIGH,
                        category="weak_tokens",
                        affected_component="token_configuration",
                        evidence={'field': field, 'length': len(value)},
                        remediation=f"Use a strong {field} with at least 32 characters"
                    )
                    config.issues.append(issue)
                
                # Check for common weak tokens
                if value.lower() in ['test', 'demo', 'example', 'sample', 'key', 'token', 'secret']:
                    issue = AuthenticationIssue(
                        issue_id=f"DEFAULT_{field.upper()}",
                        name=f"Default {field.replace('_', ' ').title()}",
                        description=f"Default or example {field} detected",
                        severity=RiskLevel.CRITICAL,
                        category="weak_tokens",
                        affected_component="token_configuration",
                        evidence={'field': field, 'value': value},
                        remediation=f"Replace default {field} with a secure, randomly generated value"
                    )
                    config.issues.append(issue)
        
        # Check JWT-specific configurations
        jwt_config = auth_config.get('jwt', {})
        if jwt_config:
            # Check for insecure JWT algorithms
            algorithm = jwt_config.get('algorithm', '').lower()
            if algorithm == 'none':
                issue = AuthenticationIssue(
                    issue_id="JWT_NO_SIGNATURE",
                    name="JWT Without Signature",
                    description="JWT configured with 'none' algorithm (no signature)",
                    severity=RiskLevel.CRITICAL,
                    category="oauth_jwt_issues",
                    affected_component="jwt_configuration",
                    remediation="Use a secure JWT signing algorithm (RS256, HS256, etc.)"
                )
                config.issues.append(issue)
            
            # Check for signature verification disabled
            if not jwt_config.get('verify', True):
                issue = AuthenticationIssue(
                    issue_id="JWT_NO_VERIFICATION",
                    name="JWT Signature Verification Disabled",
                    description="JWT signature verification is disabled",
                    severity=RiskLevel.CRITICAL,
                    category="oauth_jwt_issues",
                    affected_component="jwt_configuration",
                    remediation="Enable JWT signature verification"
                )
                config.issues.append(issue)
    
    def _analyze_sessions(self, auth_config: Dict[str, Any], config: AuthenticationConfiguration) -> None:
        """Analyze session-related configuration."""
        
        # Extract session configurations
        session_config = auth_config.get('session', {})
        config.session_configurations = session_config
        
        # Check session security settings
        if session_config:
            # Check for insecure cookie settings
            if not session_config.get('cookie_secure', True):
                issue = AuthenticationIssue(
                    issue_id="INSECURE_COOKIE",
                    name="Insecure Cookie Settings",
                    description="Session cookies not marked as secure",
                    severity=RiskLevel.MEDIUM,
                    category="insecure_sessions",
                    affected_component="session_configuration",
                    remediation="Set secure flag on session cookies"
                )
                config.issues.append(issue)
            
            if not session_config.get('http_only', True):
                issue = AuthenticationIssue(
                    issue_id="COOKIE_NOT_HTTP_ONLY",
                    name="Cookie Not HTTP Only",
                    description="Session cookies accessible via JavaScript",
                    severity=RiskLevel.MEDIUM,
                    category="insecure_sessions",
                    affected_component="session_configuration",
                    remediation="Set HttpOnly flag on session cookies"
                )
                config.issues.append(issue)
            
            # Check session timeout
            timeout = session_config.get('timeout', 0)
            if timeout > 86400:  # More than 24 hours
                issue = AuthenticationIssue(
                    issue_id="LONG_SESSION_TIMEOUT",
                    name="Long Session Timeout",
                    description=f"Session timeout is very long ({timeout} seconds)",
                    severity=RiskLevel.LOW,
                    category="insecure_sessions",
                    affected_component="session_configuration",
                    evidence={'timeout': timeout},
                    remediation="Set reasonable session timeout (e.g., 1-8 hours)"
                )
                config.issues.append(issue)
    
    def _analyze_raw_data_authentication(self, raw_data: Dict[str, Any], config: AuthenticationConfiguration) -> None:
        """Analyze raw detection data for authentication patterns."""
        
        # Analyze configuration files
        config_files = raw_data.get('configuration_files', [])
        for file_path in config_files:
            try:
                self._analyze_config_file_auth(file_path, config)
            except Exception as e:
                self.logger.warning(f"Failed to analyze config file {file_path}: {e}")
        
        # Analyze environment variables
        env_vars = raw_data.get('environment_variables', {})
        if env_vars:
            self._analyze_environment_auth(env_vars, config)
        
        # Analyze command line
        command_line = raw_data.get('command_line', '')
        if command_line:
            self._analyze_command_line_auth(command_line, config)
    
    def _analyze_config_file_auth(self, file_path: str, config: AuthenticationConfiguration) -> None:
        """Analyze a configuration file for authentication patterns."""
        
        try:
            path = Path(file_path)
            if not path.exists():
                return
            
            content = path.read_text(encoding='utf-8')
            
            # Apply authentication rules to file content
            for rule_name, rule_config in self.auth_rules.items():
                for pattern in rule_config['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        issue = AuthenticationIssue(
                            issue_id=f"FILE_{rule_name.upper()}_{hash(file_path) % 10000:04d}",
                            name=f"{rule_config['description']} in {path.name}",
                            description=f"{rule_config['description']} found in configuration file",
                            severity=rule_config['severity'],
                            category=rule_name,
                            affected_component=str(path),
                            evidence={
                                'file': str(path),
                                'pattern': pattern,
                                'match': match.group(),
                                'line_number': content[:match.start()].count('\n') + 1
                            },
                            remediation=rule_config['remediation']
                        )
                        config.issues.append(issue)
                        break  # Only report first match per rule per file
            
            # Look for specific authentication-related content
            self._analyze_file_content_auth(content, path, config)
            
        except Exception as e:
            self.logger.warning(f"Error analyzing config file {file_path}: {e}")
    
    def _analyze_file_content_auth(self, content: str, file_path: Path, config: AuthenticationConfiguration) -> None:
        """Analyze file content for specific authentication patterns."""
        
        # Look for Base64 encoded credentials
        base64_pattern = r'Basic\s+([A-Za-z0-9+/=]+)'
        for match in re.finditer(base64_pattern, content):
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-8')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    if self._is_weak_password(password):
                        issue = AuthenticationIssue(
                            issue_id=f"WEAK_BASIC_AUTH_{hash(str(file_path)) % 10000:04d}",
                            name="Weak Basic Authentication",
                            description=f"Weak password in Basic authentication: {file_path.name}",
                            severity=RiskLevel.HIGH,
                            category="weak_password",
                            affected_component=str(file_path),
                            evidence={'username': username, 'password_length': len(password)},
                            remediation="Use strong passwords for Basic authentication"
                        )
                        config.issues.append(issue)
            except Exception:
                pass  # Invalid Base64 or format
        
        # Look for JWT tokens
        jwt_pattern = r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*'
        for match in re.finditer(jwt_pattern, content):
            # Basic JWT validation - check if it's a test/demo token
            token = match.group()
            if self._is_test_jwt(token):
                issue = AuthenticationIssue(
                    issue_id=f"TEST_JWT_{hash(str(file_path)) % 10000:04d}",
                    name="Test JWT Token",
                    description=f"Test or demo JWT token found: {file_path.name}",
                    severity=RiskLevel.MEDIUM,
                    category="weak_tokens",
                    affected_component=str(file_path),
                    evidence={'token_prefix': token[:50] + '...'},
                    remediation="Replace test JWT tokens with production tokens"
                )
                config.issues.append(issue)
    
    def _analyze_environment_auth(self, env_vars: Dict[str, str], config: AuthenticationConfiguration) -> None:
        """Analyze environment variables for authentication patterns."""
        
        auth_env_vars = [
            'PASSWORD', 'PASS', 'PWD', 'SECRET', 'TOKEN', 'API_KEY', 'AUTH_TOKEN',
            'JWT_SECRET', 'SESSION_SECRET', 'PRIVATE_KEY', 'ACCESS_TOKEN'
        ]
        
        for var_name, var_value in env_vars.items():
            var_upper = var_name.upper()
            
            # Check if it's an authentication-related variable
            if any(auth_var in var_upper for auth_var in auth_env_vars):
                # Check for weak values
                if self._is_weak_credential(var_value):
                    issue = AuthenticationIssue(
                        issue_id=f"WEAK_ENV_{var_upper}",
                        name=f"Weak Environment Variable: {var_name}",
                        description=f"Weak credential in environment variable {var_name}",
                        severity=RiskLevel.HIGH,
                        category="weak_password" if "PASSWORD" in var_upper else "weak_tokens",
                        affected_component="environment_variables",
                        evidence={'variable': var_name, 'value_length': len(var_value)},
                        remediation=f"Use a strong value for {var_name}"
                    )
                    config.issues.append(issue)
    
    def _analyze_command_line_auth(self, command_line: str, config: AuthenticationConfiguration) -> None:
        """Analyze command line for authentication patterns."""
        
        # Check for authentication flags
        auth_flags = [
            '--no-auth', '--disable-auth', '--skip-auth',
            '--password=', '--token=', '--api-key=', '--secret='
        ]
        
        for flag in auth_flags:
            if flag in command_line.lower():
                if flag.startswith('--no-') or flag.startswith('--disable-') or flag.startswith('--skip-'):
                    issue = AuthenticationIssue(
                        issue_id="CMD_NO_AUTH",
                        name="Authentication Disabled via Command Line",
                        description=f"Authentication disabled using {flag}",
                        severity=RiskLevel.HIGH,
                        category="no_authentication",
                        affected_component="command_line",
                        evidence={'flag': flag, 'command': command_line},
                        remediation="Remove authentication bypass flags"
                    )
                    config.issues.append(issue)
                elif '=' in flag:
                    # Extract credential value
                    pattern = re.escape(flag) + r'([^\s]+)'
                    match = re.search(pattern, command_line, re.IGNORECASE)
                    if match:
                        value = match.group(1)
                        if self._is_weak_credential(value):
                            issue = AuthenticationIssue(
                                issue_id="CMD_WEAK_CRED",
                                name="Weak Credential in Command Line",
                                description=f"Weak credential passed via {flag}",
                                severity=RiskLevel.HIGH,
                                category="weak_password" if "password" in flag else "weak_tokens",
                                affected_component="command_line",
                                evidence={'flag': flag, 'value_length': len(value)},
                                remediation="Use strong credentials and avoid command line exposure"
                            )
                            config.issues.append(issue)
    
    def _is_weak_password(self, password: str) -> bool:
        """Check if a password is weak based on common patterns."""
        
        if not password or len(password) < 8:
            return True
        
        # Check against weak password patterns
        for pattern in self.compiled_weak_patterns:
            if pattern.match(password):
                return True
        
        # Check for common patterns
        if password.lower() in ['password', 'admin', 'root', 'user', 'guest', 'test', 'demo']:
            return True
        
        # Check for simple patterns
        if password.isdigit() or password.isalpha():
            return True
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', 'abcd']
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            return True
        
        return False
    
    def _is_weak_credential(self, credential: str) -> bool:
        """Check if a credential (password, token, etc.) is weak."""
        
        if not credential:
            return True
        
        # Check length
        if len(credential) < 16:  # Tokens should be longer than passwords
            return True
        
        # Check for common weak values
        weak_values = [
            'test', 'demo', 'example', 'sample', 'default', 'changeme',
            'secret', 'password', 'token', 'key', 'admin', 'root'
        ]
        
        if credential.lower() in weak_values:
            return True
        
        # Check for simple patterns
        if credential.isdigit() or credential.isalpha():
            return True
        
        return False
    
    def _is_test_jwt(self, token: str) -> bool:
        """Check if a JWT token appears to be a test/demo token."""
        
        try:
            # Split JWT into parts
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            # Decode header and payload (ignore signature)
            header = json.loads(base64.b64decode(parts[0] + '=='))
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            
            # Check for test indicators
            test_indicators = [
                'test', 'demo', 'example', 'sample', 'localhost',
                'dev', 'development', 'staging'
            ]
            
            # Check issuer
            iss = payload.get('iss', '').lower()
            if any(indicator in iss for indicator in test_indicators):
                return True
            
            # Check audience
            aud = payload.get('aud', '').lower()
            if any(indicator in aud for indicator in test_indicators):
                return True
            
            # Check subject
            sub = payload.get('sub', '').lower()
            if any(indicator in sub for indicator in test_indicators):
                return True
            
        except Exception:
            pass  # Invalid JWT format
        
        return False
    
    def _generate_auth_recommendations(self, config: AuthenticationConfiguration) -> None:
        """Generate authentication-specific recommendations."""
        
        recommendations = []
        
        # General recommendations based on issues
        if config.critical_issues:
            recommendations.append("Immediately address critical authentication vulnerabilities")
        
        if config.high_issues:
            recommendations.append("Review and fix high-severity authentication issues")
        
        # Specific recommendations based on configuration
        if not config.authentication_enabled:
            recommendations.append("Enable authentication to secure access to the MCP server")
        
        if not config.multi_factor_auth:
            recommendations.append("Implement multi-factor authentication for enhanced security")
        
        if not config.encryption_in_transit:
            recommendations.append("Enable HTTPS/TLS for secure credential transmission")
        
        if len(config.authentication_methods) == 0:
            recommendations.append("Configure at least one secure authentication method")
        elif len(config.authentication_methods) == 1:
            recommendations.append("Consider implementing multiple authentication methods for redundancy")
        
        # Category-specific recommendations
        weak_password_issues = config.get_issues_by_category("weak_password")
        if weak_password_issues:
            recommendations.append("Implement strong password policies and replace weak passwords")
        
        token_issues = config.get_issues_by_category("weak_tokens")
        if token_issues:
            recommendations.append("Generate strong, random API keys and tokens")
        
        session_issues = config.get_issues_by_category("insecure_sessions")
        if session_issues:
            recommendations.append("Configure secure session management settings")
        
        jwt_issues = config.get_issues_by_category("oauth_jwt_issues")
        if jwt_issues:
            recommendations.append("Review and secure JWT/OAuth configuration")
        
        config.recommendations = recommendations
    
    def _convert_issues_to_findings(self, config: AuthenticationConfiguration) -> List[SecurityFinding]:
        """Convert authentication issues to security findings."""
        
        findings = []
        
        for issue in config.issues:
            finding = SecurityFinding(
                id=issue.issue_id,
                title=issue.name,
                description=issue.description,
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=issue.severity,
                confidence=0.9,  # High confidence for authentication analysis
                affected_asset=config.target_host,
                evidence=issue.evidence,
                remediation=issue.remediation,
                references=issue.references,
                compliance_violations=issue.compliance_violations
            )
            findings.append(finding)
        
        return findings


# Convenience functions
def analyze_authentication(detection_result: DetectionResult, settings=None) -> AuthenticationConfiguration:
    """
    Analyze authentication configuration in a detected MCP server.
    
    Args:
        detection_result: Detection result to analyze
        settings: Optional settings
        
    Returns:
        AuthenticationConfiguration: Analysis results
    """
    analyzer = AuthenticationAnalyzer(settings)
    assessment_result = analyzer.assess(detection_result)
    
    # Extract authentication data from raw_data
    auth_data = assessment_result.raw_data.get('authentication_analysis', {})
    
    config = AuthenticationConfiguration(
        target_host=detection_result.target_host,
        authentication_enabled=auth_data.get('authentication_enabled', False),
        authentication_methods=auth_data.get('authentication_methods', []),
        multi_factor_auth=auth_data.get('multi_factor_auth', False),
        encryption_in_transit=auth_data.get('encryption_in_transit', False),
        security_score=auth_data.get('security_score', 0.0)
    )
    
    # Convert findings back to authentication issues
    for finding in assessment_result.findings:
        issue = AuthenticationIssue(
            issue_id=finding.id,
            name=finding.title,
            description=finding.description,
            severity=finding.severity,
            category=finding.evidence.get('category', 'unknown'),
            affected_component=finding.evidence.get('affected_component', 'unknown'),
            evidence=finding.evidence,
            remediation=finding.remediation,
            references=finding.references,
            compliance_violations=finding.compliance_violations
        )
        config.issues.append(issue)
    
    return config


def check_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Check password strength and return issues.
    
    Args:
        password: Password to check
        
    Returns:
        Tuple of (is_strong, list_of_issues)
    """
    analyzer = AuthenticationAnalyzer()
    issues = []
    
    if len(password) < 8:
        issues.append("Password is too short (minimum 8 characters)")
    
    if password.isdigit():
        issues.append("Password contains only numbers")
    
    if password.isalpha():
        issues.append("Password contains only letters")
    
    if analyzer._is_weak_password(password):
        issues.append("Password matches common weak patterns")
    
    if not re.search(r'[A-Z]', password):
        issues.append("Password should contain uppercase letters")
    
    if not re.search(r'[a-z]', password):
        issues.append("Password should contain lowercase letters")
    
    if not re.search(r'\d', password):
        issues.append("Password should contain numbers")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("Password should contain special characters")
    
    return len(issues) == 0, issues


def validate_jwt_token(token: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Validate JWT token structure and extract claims.
    
    Args:
        token: JWT token to validate
        
    Returns:
        Tuple of (is_valid, claims_dict)
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False, {'error': 'Invalid JWT format'}
        
        # Decode header and payload
        header = json.loads(base64.b64decode(parts[0] + '=='))
        payload = json.loads(base64.b64decode(parts[1] + '=='))
        
        # Basic validation
        claims = {
            'header': header,
            'payload': payload,
            'algorithm': header.get('alg'),
            'issuer': payload.get('iss'),
            'audience': payload.get('aud'),
            'subject': payload.get('sub'),
            'expiration': payload.get('exp'),
            'issued_at': payload.get('iat')
        }
        
        # Check expiration
        if claims['expiration']:
            exp_time = datetime.fromtimestamp(claims['expiration'])
            if exp_time < datetime.now():
                claims['expired'] = True
            else:
                claims['expired'] = False
        
        return True, claims
        
    except Exception as e:
        return False, {'error': str(e)} 