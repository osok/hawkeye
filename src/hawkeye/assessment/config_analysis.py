"""
Security Configuration Analysis for MCP servers.

This module provides comprehensive security configuration analysis capabilities
for MCP (Model Context Protocol) server deployments, identifying misconfigurations,
security weaknesses, and compliance violations.
"""

import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .base import (
    RiskAssessor, AssessmentResult, SecurityFinding, VulnerabilityInfo,
    RiskLevel, VulnerabilityCategory, ComplianceFramework, ConfigurationError
)
from ..detection.base import DetectionResult, MCPServerInfo, TransportType
from ..utils.logging import get_logger


@dataclass
class ConfigurationIssue:
    """Represents a specific configuration security issue."""
    
    issue_id: str
    title: str
    description: str
    severity: RiskLevel
    category: VulnerabilityCategory
    affected_config: str  # Configuration file or setting
    current_value: Any
    recommended_value: Optional[Any] = None
    remediation: Optional[str] = None
    compliance_violations: List[ComplianceFramework] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class SecurityConfiguration:
    """Container for security configuration analysis results."""
    
    target_host: str
    transport_type: TransportType
    configuration_files: List[str] = field(default_factory=list)
    security_settings: Dict[str, Any] = field(default_factory=dict)
    issues: List[ConfigurationIssue] = field(default_factory=list)
    security_score: float = 0.0  # 0.0 (worst) to 10.0 (best)
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def critical_issues(self) -> List[ConfigurationIssue]:
        """Get critical severity configuration issues."""
        return [issue for issue in self.issues if issue.severity == RiskLevel.CRITICAL]
    
    @property
    def high_issues(self) -> List[ConfigurationIssue]:
        """Get high severity configuration issues."""
        return [issue for issue in self.issues if issue.severity == RiskLevel.HIGH]
    
    def get_issues_by_category(self, category: VulnerabilityCategory) -> List[ConfigurationIssue]:
        """Get issues filtered by category."""
        return [issue for issue in self.issues if issue.category == category]
    
    def calculate_security_score(self) -> None:
        """Calculate overall security score based on issues."""
        if not self.issues:
            self.security_score = 10.0
            return
        
        # Weight issues by severity
        severity_weights = {
            RiskLevel.CRITICAL: -4.0,
            RiskLevel.HIGH: -2.0,
            RiskLevel.MEDIUM: -1.0,
            RiskLevel.LOW: -0.5,
            RiskLevel.NONE: 0.0
        }
        
        total_deduction = sum(severity_weights.get(issue.severity, 0) for issue in self.issues)
        self.security_score = max(0.0, min(10.0, 10.0 + total_deduction))


class ConfigurationAnalyzer(RiskAssessor):
    """Analyzes security configurations of MCP servers."""
    
    def __init__(self, settings=None):
        """Initialize the configuration analyzer."""
        super().__init__(settings)
        self.logger = get_logger(self.__class__.__name__)
        
        # Security configuration patterns and rules
        self._init_security_rules()
        self._init_compliance_mappings()
    
    def _init_security_rules(self) -> None:
        """Initialize security configuration rules and patterns."""
        
        # Authentication and authorization rules
        self.auth_rules = {
            'no_authentication': {
                'patterns': [
                    r'auth.*false',
                    r'authentication.*disabled',
                    r'require.*auth.*false',
                    r'no.*auth',
                    r'skip.*auth'
                ],
                'severity': RiskLevel.CRITICAL,
                'category': VulnerabilityCategory.AUTHENTICATION,
                'title': 'Authentication Disabled',
                'description': 'Authentication is disabled, allowing unrestricted access'
            },
            'weak_authentication': {
                'patterns': [
                    r'auth.*basic',
                    r'password.*\b(admin|password|123|test)\b',
                    r'api.*key.*\b(test|demo|example)\b',
                    r'token.*\b(abc|123|test)\b'
                ],
                'severity': RiskLevel.HIGH,
                'category': VulnerabilityCategory.AUTHENTICATION,
                'title': 'Weak Authentication Configuration',
                'description': 'Weak or default authentication credentials detected'
            },
            'missing_authorization': {
                'patterns': [
                    r'authorization.*false',
                    r'rbac.*disabled',
                    r'permissions.*none',
                    r'access.*control.*false'
                ],
                'severity': RiskLevel.HIGH,
                'category': VulnerabilityCategory.AUTHORIZATION,
                'title': 'Authorization Controls Missing',
                'description': 'Authorization controls are disabled or missing'
            }
        }
        
        # Encryption and transport security rules
        self.encryption_rules = {
            'unencrypted_transport': {
                'patterns': [
                    r'ssl.*false',
                    r'tls.*disabled',
                    r'https.*false',
                    r'secure.*false',
                    r'encryption.*none'
                ],
                'severity': RiskLevel.HIGH,
                'category': VulnerabilityCategory.ENCRYPTION,
                'title': 'Unencrypted Transport',
                'description': 'Transport encryption is disabled, data transmitted in plaintext'
            },
            'weak_encryption': {
                'patterns': [
                    r'ssl.*v[12]',
                    r'tls.*v1\.[01]',
                    r'cipher.*rc4',
                    r'cipher.*des',
                    r'cipher.*md5'
                ],
                'severity': RiskLevel.MEDIUM,
                'category': VulnerabilityCategory.ENCRYPTION,
                'title': 'Weak Encryption Configuration',
                'description': 'Weak or deprecated encryption protocols/ciphers in use'
            }
        }
        
        # Network and access control rules
        self.network_rules = {
            'open_access': {
                'patterns': [
                    r'bind.*0\.0\.0\.0',
                    r'host.*\*',
                    r'allow.*\*',
                    r'cors.*\*',
                    r'origin.*\*'
                ],
                'severity': RiskLevel.MEDIUM,
                'category': VulnerabilityCategory.NETWORK,
                'title': 'Overly Permissive Network Access',
                'description': 'Network access controls are too permissive'
            },
            'insecure_cors': {
                'patterns': [
                    r'cors.*origin.*\*',
                    r'access.*control.*allow.*origin.*\*',
                    r'cors.*credentials.*true.*origin.*\*'
                ],
                'severity': RiskLevel.MEDIUM,
                'category': VulnerabilityCategory.NETWORK,
                'title': 'Insecure CORS Configuration',
                'description': 'CORS configuration allows unrestricted cross-origin access'
            }
        }
        
        # Logging and monitoring rules
        self.logging_rules = {
            'logging_disabled': {
                'patterns': [
                    r'log.*false',
                    r'logging.*disabled',
                    r'audit.*false',
                    r'log.*level.*none'
                ],
                'severity': RiskLevel.MEDIUM,
                'category': VulnerabilityCategory.LOGGING,
                'title': 'Logging Disabled',
                'description': 'Security logging and auditing is disabled'
            },
            'verbose_logging': {
                'patterns': [
                    r'log.*level.*debug',
                    r'log.*level.*trace',
                    r'verbose.*true',
                    r'debug.*true'
                ],
                'severity': RiskLevel.LOW,
                'category': VulnerabilityCategory.LOGGING,
                'title': 'Verbose Logging Enabled',
                'description': 'Verbose logging may expose sensitive information'
            }
        }
        
        # Error handling rules
        self.error_rules = {
            'verbose_errors': {
                'patterns': [
                    r'error.*stack.*true',
                    r'debug.*errors.*true',
                    r'show.*errors.*true',
                    r'error.*details.*true'
                ],
                'severity': RiskLevel.LOW,
                'category': VulnerabilityCategory.ERROR_HANDLING,
                'title': 'Verbose Error Messages',
                'description': 'Detailed error messages may expose sensitive information'
            }
        }
        
        # Combine all rules
        self.all_rules = {
            **self.auth_rules,
            **self.encryption_rules,
            **self.network_rules,
            **self.logging_rules,
            **self.error_rules
        }
    
    def _init_compliance_mappings(self) -> None:
        """Initialize compliance framework mappings."""
        self.compliance_mappings = {
            VulnerabilityCategory.AUTHENTICATION: [
                ComplianceFramework.OWASP_TOP_10,
                ComplianceFramework.NIST_CSF,
                ComplianceFramework.ISO_27001
            ],
            VulnerabilityCategory.AUTHORIZATION: [
                ComplianceFramework.OWASP_TOP_10,
                ComplianceFramework.NIST_CSF,
                ComplianceFramework.SOC2
            ],
            VulnerabilityCategory.ENCRYPTION: [
                ComplianceFramework.NIST_CSF,
                ComplianceFramework.ISO_27001,
                ComplianceFramework.PCI_DSS,
                ComplianceFramework.GDPR
            ],
            VulnerabilityCategory.NETWORK: [
                ComplianceFramework.NIST_CSF,
                ComplianceFramework.ISO_27001,
                ComplianceFramework.SOC2
            ],
            VulnerabilityCategory.LOGGING: [
                ComplianceFramework.NIST_CSF,
                ComplianceFramework.SOC2,
                ComplianceFramework.PCI_DSS
            ]
        }
    
    def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
        """
        Perform security configuration assessment on a detection result.
        
        Args:
            detection_result: Result from MCP detection
            **kwargs: Additional assessment parameters
            
        Returns:
            AssessmentResult: Result of the configuration assessment
        """
        try:
            self.logger.info(f"Starting configuration analysis for {detection_result.target_host}")
            
            # Analyze security configuration
            config_analysis = self._analyze_security_configuration(detection_result)
            
            # Convert configuration issues to security findings
            findings = self._convert_issues_to_findings(config_analysis)
            
            # Create assessment result
            result = AssessmentResult(
                target_host=detection_result.target_host,
                findings=findings
            )
            
            # Calculate overall risk
            result.calculate_overall_risk()
            
            # Add configuration-specific recommendations
            result.recommendations.extend(config_analysis.recommendations)
            
            # Store raw configuration data
            result.raw_data['security_configuration'] = {
                'security_score': config_analysis.security_score,
                'configuration_files': config_analysis.configuration_files,
                'security_settings': config_analysis.security_settings,
                'issues_count': len(config_analysis.issues),
                'critical_issues_count': len(config_analysis.critical_issues),
                'high_issues_count': len(config_analysis.high_issues)
            }
            
            self.logger.info(f"Configuration analysis completed for {detection_result.target_host}")
            return result
            
        except Exception as e:
            self.logger.error(f"Configuration analysis failed for {detection_result.target_host}: {e}")
            raise ConfigurationError(f"Failed to analyze configuration: {e}")
    
    def get_assessment_type(self) -> str:
        """Get the type of assessment performed by this assessor."""
        return "security_configuration_analysis"
    
    def _analyze_security_configuration(self, detection_result: DetectionResult) -> SecurityConfiguration:
        """Analyze security configuration of detected MCP server."""
        config = SecurityConfiguration(
            target_host=detection_result.target_host,
            transport_type=detection_result.mcp_server.transport_type if detection_result.mcp_server else TransportType.UNKNOWN
        )
        
        # Analyze different configuration sources
        if detection_result.mcp_server:
            self._analyze_server_configuration(detection_result.mcp_server, config)
        
        if detection_result.raw_data:
            self._analyze_raw_configuration_data(detection_result.raw_data, config)
        
        # Analyze transport-specific security
        self._analyze_transport_security(config)
        
        # Calculate security score
        config.calculate_security_score()
        
        # Generate recommendations
        self._generate_recommendations(config)
        
        return config
    
    def _analyze_server_configuration(self, server_info: MCPServerInfo, config: SecurityConfiguration) -> None:
        """Analyze MCP server configuration for security issues."""
        
        # Check for insecure transport
        if server_info.transport_type in [TransportType.HTTP, TransportType.WEBSOCKET]:
            # Check if using secure variants
            if not server_info.security_config or not server_info.security_config.get('tls_enabled', False):
                issue = ConfigurationIssue(
                    issue_id="INSECURE_TRANSPORT",
                    title="Insecure Transport Protocol",
                    description=f"MCP server using insecure {server_info.transport_type.value} transport without TLS",
                    severity=RiskLevel.HIGH,
                    category=VulnerabilityCategory.ENCRYPTION,
                    affected_config="transport_configuration",
                    current_value=server_info.transport_type.value,
                    recommended_value=f"{server_info.transport_type.value}S (with TLS)",
                    remediation="Enable TLS/SSL encryption for transport security"
                )
                config.issues.append(issue)
        
        # Check for default ports
        if server_info.port:
            default_ports = {3000, 8000, 8080, 3001, 5000}
            if server_info.port in default_ports:
                issue = ConfigurationIssue(
                    issue_id="DEFAULT_PORT",
                    title="Default Port Usage",
                    description=f"MCP server using common default port {server_info.port}",
                    severity=RiskLevel.LOW,
                    category=VulnerabilityCategory.CONFIGURATION,
                    affected_config="port_configuration",
                    current_value=server_info.port,
                    recommended_value="Non-default port",
                    remediation="Use a non-standard port to reduce attack surface"
                )
                config.issues.append(issue)
        
        # Check for open network binding
        if server_info.host in ['0.0.0.0', '*', '']:
            issue = ConfigurationIssue(
                issue_id="OPEN_NETWORK_BINDING",
                title="Open Network Binding",
                description="MCP server bound to all network interfaces",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.NETWORK,
                affected_config="host_binding",
                current_value=server_info.host or "0.0.0.0",
                recommended_value="127.0.0.1 or specific interface",
                remediation="Bind to specific network interface instead of all interfaces"
            )
            config.issues.append(issue)
        
        # Analyze security information if available
        if server_info.security_config:
            self._analyze_security_info(server_info.security_config, config)
    
    def _analyze_security_info(self, security_info: Dict[str, Any], config: SecurityConfiguration) -> None:
        """Analyze security information from server detection."""
        
        # Check authentication status
        auth_enabled = security_info.get('authentication_required', False)
        if not auth_enabled:
            issue = ConfigurationIssue(
                issue_id="NO_AUTHENTICATION",
                title="Authentication Not Required",
                description="MCP server does not require authentication",
                severity=RiskLevel.CRITICAL,
                category=VulnerabilityCategory.AUTHENTICATION,
                affected_config="authentication_settings",
                current_value=False,
                recommended_value=True,
                remediation="Enable authentication to control access to MCP server"
            )
            config.issues.append(issue)
        
        # Check for weak authentication methods
        auth_methods = security_info.get('authentication_methods', [])
        weak_methods = ['basic', 'none', 'anonymous']
        if any(method in weak_methods for method in auth_methods):
            issue = ConfigurationIssue(
                issue_id="WEAK_AUTHENTICATION",
                title="Weak Authentication Methods",
                description=f"Weak authentication methods detected: {auth_methods}",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.AUTHENTICATION,
                affected_config="authentication_methods",
                current_value=auth_methods,
                recommended_value="Strong authentication (OAuth2, JWT, API keys)",
                remediation="Use strong authentication methods instead of basic auth"
            )
            config.issues.append(issue)
        
        # Check TLS configuration
        tls_enabled = security_info.get('tls_enabled', False)
        if not tls_enabled:
            issue = ConfigurationIssue(
                issue_id="TLS_DISABLED",
                title="TLS Encryption Disabled",
                description="TLS encryption is not enabled",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.ENCRYPTION,
                affected_config="tls_settings",
                current_value=False,
                recommended_value=True,
                remediation="Enable TLS encryption for secure communication"
            )
            config.issues.append(issue)
        
        # Check TLS version
        tls_version = security_info.get('tls_version')
        if tls_version and tls_version in ['1.0', '1.1', 'SSLv2', 'SSLv3']:
            issue = ConfigurationIssue(
                issue_id="WEAK_TLS_VERSION",
                title="Weak TLS Version",
                description=f"Weak or deprecated TLS version: {tls_version}",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.ENCRYPTION,
                affected_config="tls_version",
                current_value=tls_version,
                recommended_value="TLS 1.2 or higher",
                remediation="Upgrade to TLS 1.2 or higher for better security"
            )
            config.issues.append(issue)
    
    def _analyze_raw_configuration_data(self, raw_data: Dict[str, Any], config: SecurityConfiguration) -> None:
        """Analyze raw configuration data for security issues."""
        
        # Analyze configuration files if available
        config_files = raw_data.get('configuration_files', [])
        for file_path in config_files:
            try:
                self._analyze_configuration_file(file_path, config)
            except Exception as e:
                self.logger.warning(f"Failed to analyze configuration file {file_path}: {e}")
        
        # Analyze environment variables
        env_vars = raw_data.get('environment_variables', {})
        if env_vars:
            self._analyze_environment_variables(env_vars, config)
        
        # Analyze process command line
        command_line = raw_data.get('command_line', '')
        if command_line:
            self._analyze_command_line(command_line, config)
    
    def _analyze_configuration_file(self, file_path: str, config: SecurityConfiguration) -> None:
        """Analyze a specific configuration file for security issues."""
        try:
            path = Path(file_path)
            if not path.exists():
                return
            
            config.configuration_files.append(str(path))
            
            # Read file content
            content = path.read_text(encoding='utf-8')
            
            # Parse based on file type
            parsed_config = None
            if path.suffix.lower() in ['.json']:
                try:
                    parsed_config = json.loads(content)
                except json.JSONDecodeError:
                    pass
            elif path.suffix.lower() in ['.yml', '.yaml']:
                try:
                    parsed_config = yaml.safe_load(content)
                except yaml.YAMLError:
                    pass
            
            # Analyze parsed configuration
            if parsed_config:
                self._analyze_parsed_configuration(parsed_config, config, str(path))
            
            # Analyze raw content with regex patterns
            self._analyze_configuration_content(content, config, str(path))
            
        except Exception as e:
            self.logger.warning(f"Error analyzing configuration file {file_path}: {e}")
    
    def _analyze_parsed_configuration(self, parsed_config: Dict[str, Any], config: SecurityConfiguration, file_path: str) -> None:
        """Analyze parsed configuration data."""
        
        # Flatten configuration for analysis
        flattened = self._flatten_dict(parsed_config)
        config.security_settings.update(flattened)
        
        # Check for specific security settings
        security_keys = [
            'auth', 'authentication', 'authorization', 'ssl', 'tls', 'https',
            'security', 'cors', 'csrf', 'session', 'cookie', 'token'
        ]
        
        for key, value in flattened.items():
            key_lower = key.lower()
            
            # Check if this is a security-related setting
            if any(sec_key in key_lower for sec_key in security_keys):
                # Analyze the setting
                self._analyze_security_setting(key, value, config, file_path)
    
    def _analyze_security_setting(self, key: str, value: Any, config: SecurityConfiguration, file_path: str) -> None:
        """Analyze a specific security setting."""
        
        key_lower = key.lower()
        value_str = str(value).lower()
        
        # Check against security rules
        for rule_id, rule in self.all_rules.items():
            for pattern in rule['patterns']:
                if re.search(pattern, f"{key_lower}:{value_str}", re.IGNORECASE):
                    issue = ConfigurationIssue(
                        issue_id=f"CONFIG_{rule_id.upper()}",
                        title=rule['title'],
                        description=f"{rule['description']} (found in {key})",
                        severity=rule['severity'],
                        category=rule['category'],
                        affected_config=f"{file_path}:{key}",
                        current_value=value,
                        remediation=f"Review and secure the '{key}' configuration setting"
                    )
                    
                    # Add compliance violations
                    issue.compliance_violations = self.compliance_mappings.get(rule['category'], [])
                    
                    config.issues.append(issue)
                    break
    
    def _analyze_configuration_content(self, content: str, config: SecurityConfiguration, file_path: str) -> None:
        """Analyze configuration file content with regex patterns."""
        
        content_lower = content.lower()
        
        # Check for hardcoded secrets
        secret_patterns = [
            (r'"password"\s*:\s*"([^"]+)"', 'Hardcoded Password'),
            (r'"api[_-]?key"\s*:\s*"([^"]+)"', 'Hardcoded API Key'),
            (r'"secret"\s*:\s*"([^"]+)"', 'Hardcoded Secret'),
            (r'"token"\s*:\s*"([^"]+)"', 'Hardcoded Token'),
            (r'password\s*[=:]\s*["\']?([^"\'\s,}]+)', 'Hardcoded Password'),
            (r'api[_-]?key\s*[=:]\s*["\']?([^"\'\s,}]+)', 'Hardcoded API Key'),
            (r'secret\s*[=:]\s*["\']?([^"\'\s,}]+)', 'Hardcoded Secret'),
            (r'token\s*[=:]\s*["\']?([^"\'\s,}]+)', 'Hardcoded Token'),
        ]
        
        for pattern, title in secret_patterns:
            matches = re.finditer(pattern, content_lower, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(1)
                
                # Skip obvious placeholders
                if secret_value.lower() in ['your_password', 'your_key', 'your_secret', 'your_token', 
                                           'placeholder', 'example', 'changeme', '***', 'xxx', 'false', 'true', 'null']:
                    continue
                
                issue = ConfigurationIssue(
                    issue_id="HARDCODED_SECRET",
                    title=title,
                    description=f"Hardcoded secret found in configuration file",
                    severity=RiskLevel.HIGH,
                    category=VulnerabilityCategory.CONFIGURATION,
                    affected_config=file_path,
                    current_value="[REDACTED]",
                    recommended_value="Environment variable or secure vault",
                    remediation="Move secrets to environment variables or secure credential storage"
                )
                config.issues.append(issue)
    
    def _analyze_environment_variables(self, env_vars: Dict[str, str], config: SecurityConfiguration) -> None:
        """Analyze environment variables for security issues."""
        
        for var_name, var_value in env_vars.items():
            var_name_lower = var_name.lower()
            var_value_lower = var_value.lower()
            
            # Check for debug/development settings
            if 'debug' in var_name_lower and var_value_lower in ['true', '1', 'on']:
                issue = ConfigurationIssue(
                    issue_id="DEBUG_ENABLED",
                    title="Debug Mode Enabled",
                    description=f"Debug mode enabled via environment variable {var_name}",
                    severity=RiskLevel.MEDIUM,
                    category=VulnerabilityCategory.CONFIGURATION,
                    affected_config=f"env:{var_name}",
                    current_value=var_value,
                    recommended_value="false",
                    remediation="Disable debug mode in production environments"
                )
                config.issues.append(issue)
            
            # Check for insecure protocols in URLs
            if any(keyword in var_name_lower for keyword in ['url', 'endpoint', 'host']):
                if var_value.startswith('http://'):
                    issue = ConfigurationIssue(
                        issue_id="INSECURE_URL",
                        title="Insecure URL in Environment",
                        description=f"Insecure HTTP URL in environment variable {var_name}",
                        severity=RiskLevel.MEDIUM,
                        category=VulnerabilityCategory.ENCRYPTION,
                        affected_config=f"env:{var_name}",
                        current_value=var_value,
                        recommended_value=var_value.replace('http://', 'https://'),
                        remediation="Use HTTPS instead of HTTP for secure communication"
                    )
                    config.issues.append(issue)
    
    def _analyze_command_line(self, command_line: str, config: SecurityConfiguration) -> None:
        """Analyze command line arguments for security issues."""
        
        command_lower = command_line.lower()
        
        # Check for insecure flags
        insecure_flags = [
            ('--insecure', 'Insecure Flag'),
            ('--no-ssl', 'SSL Disabled'),
            ('--no-tls', 'TLS Disabled'),
            ('--allow-insecure', 'Insecure Connections Allowed'),
            ('--debug', 'Debug Mode Enabled'),
            ('--verbose', 'Verbose Mode Enabled')
        ]
        
        for flag, title in insecure_flags:
            if flag in command_lower:
                severity = RiskLevel.HIGH if 'ssl' in flag or 'tls' in flag or 'insecure' in flag else RiskLevel.MEDIUM
                
                issue = ConfigurationIssue(
                    issue_id="INSECURE_COMMAND_FLAG",
                    title=title,
                    description=f"Insecure command line flag detected: {flag}",
                    severity=severity,
                    category=VulnerabilityCategory.CONFIGURATION,
                    affected_config="command_line",
                    current_value=flag,
                    remediation=f"Remove the {flag} flag for better security"
                )
                config.issues.append(issue)
    
    def _analyze_transport_security(self, config: SecurityConfiguration) -> None:
        """Analyze transport-specific security configurations."""
        
        if config.transport_type == TransportType.HTTP:
            # HTTP-specific security checks
            if not any(issue.issue_id == "INSECURE_TRANSPORT" for issue in config.issues):
                issue = ConfigurationIssue(
                    issue_id="HTTP_TRANSPORT",
                    title="Unencrypted HTTP Transport",
                    description="MCP server using unencrypted HTTP transport",
                    severity=RiskLevel.HIGH,
                    category=VulnerabilityCategory.ENCRYPTION,
                    affected_config="transport_type",
                    current_value="HTTP",
                    recommended_value="HTTPS",
                    remediation="Upgrade to HTTPS for encrypted communication"
                )
                config.issues.append(issue)
        
        elif config.transport_type == TransportType.WEBSOCKET:
            # WebSocket-specific security checks
            if not any(issue.issue_id == "INSECURE_TRANSPORT" for issue in config.issues):
                issue = ConfigurationIssue(
                    issue_id="WS_TRANSPORT",
                    title="Unencrypted WebSocket Transport",
                    description="MCP server using unencrypted WebSocket transport",
                    severity=RiskLevel.HIGH,
                    category=VulnerabilityCategory.ENCRYPTION,
                    affected_config="transport_type",
                    current_value="WebSocket",
                    recommended_value="WebSocket Secure (WSS)",
                    remediation="Upgrade to WSS for encrypted WebSocket communication"
                )
                config.issues.append(issue)
    
    def _generate_recommendations(self, config: SecurityConfiguration) -> None:
        """Generate security recommendations based on analysis."""
        
        recommendations = []
        
        # General recommendations based on issues
        if config.critical_issues:
            recommendations.append("Address critical security issues immediately")
        
        if config.high_issues:
            recommendations.append("Review and fix high-severity security configurations")
        
        # Transport-specific recommendations
        if config.transport_type in [TransportType.HTTP, TransportType.WEBSOCKET]:
            recommendations.append("Enable TLS/SSL encryption for secure communication")
        
        # Authentication recommendations
        auth_issues = config.get_issues_by_category(VulnerabilityCategory.AUTHENTICATION)
        if auth_issues:
            recommendations.append("Implement strong authentication mechanisms")
            recommendations.append("Use API keys, OAuth2, or JWT for authentication")
        
        # Network security recommendations
        network_issues = config.get_issues_by_category(VulnerabilityCategory.NETWORK)
        if network_issues:
            recommendations.append("Restrict network access to specific interfaces")
            recommendations.append("Implement proper CORS policies")
        
        # Configuration recommendations
        config_issues = config.get_issues_by_category(VulnerabilityCategory.CONFIGURATION)
        if config_issues:
            recommendations.append("Review configuration files for hardcoded secrets")
            recommendations.append("Use environment variables for sensitive configuration")
        
        # Logging recommendations
        logging_issues = config.get_issues_by_category(VulnerabilityCategory.LOGGING)
        if logging_issues:
            recommendations.append("Enable security logging and monitoring")
            recommendations.append("Avoid verbose logging in production")
        
        config.recommendations = recommendations
    
    def _convert_issues_to_findings(self, config: SecurityConfiguration) -> List[SecurityFinding]:
        """Convert configuration issues to security findings."""
        
        findings = []
        
        for issue in config.issues:
            finding = SecurityFinding(
                id=f"CONFIG_{issue.issue_id}_{hash(issue.affected_config) % 10000:04d}",
                title=issue.title,
                description=issue.description,
                category=issue.category,
                severity=issue.severity,
                confidence=0.9,  # High confidence for configuration analysis
                affected_asset=config.target_host,
                evidence={
                    'affected_config': issue.affected_config,
                    'current_value': str(issue.current_value),
                    'recommended_value': str(issue.recommended_value) if issue.recommended_value else None,
                    'configuration_files': config.configuration_files,
                    'security_score': config.security_score
                },
                remediation=issue.remediation,
                references=issue.references,
                compliance_violations=issue.compliance_violations
            )
            findings.append(finding)
        
        return findings
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten a nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)


# Convenience functions
def analyze_configuration(detection_result: DetectionResult, settings=None) -> SecurityConfiguration:
    """
    Analyze security configuration of a detected MCP server.
    
    Args:
        detection_result: Detection result to analyze
        settings: Optional settings
        
    Returns:
        SecurityConfiguration: Analysis results
    """
    analyzer = ConfigurationAnalyzer(settings)
    assessment_result = analyzer.assess(detection_result)
    
    # Extract configuration data from raw_data
    config_data = assessment_result.raw_data.get('security_configuration', {})
    
    config = SecurityConfiguration(
        target_host=detection_result.target_host,
        transport_type=detection_result.mcp_server.transport_type if detection_result.mcp_server else TransportType.UNKNOWN,
        configuration_files=config_data.get('configuration_files', []),
        security_settings=config_data.get('security_settings', {}),
        security_score=config_data.get('security_score', 0.0)
    )
    
    # Convert findings back to issues
    for finding in assessment_result.findings:
        issue = ConfigurationIssue(
            issue_id=finding.id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            category=finding.category,
            affected_config=finding.evidence.get('affected_config', ''),
            current_value=finding.evidence.get('current_value', ''),
            recommended_value=finding.evidence.get('recommended_value'),
            remediation=finding.remediation,
            compliance_violations=finding.compliance_violations
        )
        config.issues.append(issue)
    
    return config 