"""
Default Configuration Detection for MCP servers.

This module provides specialized detection capabilities for identifying default,
insecure, and commonly misconfigured settings in MCP (Model Context Protocol)
server deployments.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .base import (
    RiskAssessor, AssessmentResult, SecurityFinding, VulnerabilityInfo,
    RiskLevel, VulnerabilityCategory, ComplianceFramework, ConfigurationError
)
from .config_analysis import ConfigurationIssue, SecurityConfiguration
from ..detection.base import DetectionResult, MCPServerInfo, TransportType
from ..utils.logging import get_logger


@dataclass
class DefaultPattern:
    """Represents a default configuration pattern to detect."""
    
    pattern_id: str
    name: str
    description: str
    severity: RiskLevel
    category: VulnerabilityCategory
    detection_patterns: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)
    port_patterns: List[int] = field(default_factory=list)
    environment_patterns: Dict[str, str] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    compliance_violations: List[ComplianceFramework] = field(default_factory=list)


@dataclass
class DefaultDetectionResult:
    """Result of default configuration detection."""
    
    target_host: str
    detected_defaults: List[DefaultPattern] = field(default_factory=list)
    configuration_files: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    process_info: Optional[Dict[str, Any]] = None
    risk_score: float = 0.0  # 0.0 (best) to 10.0 (worst)
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def critical_defaults(self) -> List[DefaultPattern]:
        """Get critical severity default patterns."""
        return [pattern for pattern in self.detected_defaults if pattern.severity == RiskLevel.CRITICAL]
    
    @property
    def high_defaults(self) -> List[DefaultPattern]:
        """Get high severity default patterns."""
        return [pattern for pattern in self.detected_defaults if pattern.severity == RiskLevel.HIGH]
    
    def get_defaults_by_category(self, category: VulnerabilityCategory) -> List[DefaultPattern]:
        """Get default patterns filtered by category."""
        return [pattern for pattern in self.detected_defaults if pattern.category == category]
    
    def calculate_risk_score(self) -> None:
        """Calculate overall risk score based on detected defaults."""
        if not self.detected_defaults:
            self.risk_score = 0.0
            return
        
        # Weight defaults by severity
        severity_weights = {
            RiskLevel.CRITICAL: 3.0,
            RiskLevel.HIGH: 2.0,
            RiskLevel.MEDIUM: 1.0,
            RiskLevel.LOW: 0.5,
            RiskLevel.NONE: 0.0
        }
        
        total_score = sum(severity_weights.get(pattern.severity, 0) for pattern in self.detected_defaults)
        self.risk_score = min(10.0, total_score)


class DefaultConfigurationDetector(RiskAssessor):
    """Detects default and insecure configuration patterns in MCP servers."""
    
    def __init__(self, settings=None):
        """Initialize the default configuration detector."""
        super().__init__(settings)
        self.logger = get_logger(self.__class__.__name__)
        
        # Initialize default patterns database
        self._init_default_patterns()
    
    def _init_default_patterns(self) -> None:
        """Initialize the database of default configuration patterns."""
        
        self.default_patterns = [
            # Default ports
            DefaultPattern(
                pattern_id="DEFAULT_PORT_3000",
                name="Default Port 3000",
                description="MCP server running on default development port 3000",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.CONFIGURATION,
                port_patterns=[3000],
                remediation="Change to a non-standard port to reduce attack surface",
                references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"]
            ),
            
            DefaultPattern(
                pattern_id="DEFAULT_PORT_8000",
                name="Default Port 8000",
                description="MCP server running on default development port 8000",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.CONFIGURATION,
                port_patterns=[8000],
                remediation="Change to a non-standard port to reduce attack surface"
            ),
            
            DefaultPattern(
                pattern_id="DEFAULT_PORT_8080",
                name="Default Port 8080",
                description="MCP server running on common default port 8080",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.CONFIGURATION,
                port_patterns=[8080],
                remediation="Change to a non-standard port to reduce attack surface"
            ),
            
            # Default credentials
            DefaultPattern(
                pattern_id="DEFAULT_ADMIN_PASSWORD",
                name="Default Admin Password",
                description="Default administrative password detected",
                severity=RiskLevel.CRITICAL,
                category=VulnerabilityCategory.AUTHENTICATION,
                detection_patterns=[
                    r'"password"\s*:\s*"admin"',
                    r'"password"\s*:\s*"password"',
                    r'"password"\s*:\s*"123456"',
                    r'"password"\s*:\s*"admin123"',
                    r'"password"\s*:\s*"root"',
                    r'password\s*=\s*admin',
                    r'password\s*=\s*password',
                    r'password\s*=\s*123456'
                ],
                remediation="Change default passwords to strong, unique passwords",
                compliance_violations=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.NIST_CSF]
            ),
            
            DefaultPattern(
                pattern_id="DEFAULT_API_KEY",
                name="Default API Key",
                description="Default or example API key detected",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.AUTHENTICATION,
                detection_patterns=[
                    r'"api[_-]?key"\s*:\s*"(test|demo|example|sample|default)"',
                    r'"token"\s*:\s*"(test|demo|example|sample|default)"',
                    r'api[_-]?key\s*=\s*(test|demo|example|sample|default)',
                    r'"api[_-]?key"\s*:\s*"(abc|123|xxx|yyy|zzz)"'
                ],
                remediation="Replace default API keys with secure, randomly generated keys"
            ),
            
            # Default database configurations
            DefaultPattern(
                pattern_id="DEFAULT_DATABASE_CONFIG",
                name="Default Database Configuration",
                description="Default database connection settings detected",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.CONFIGURATION,
                detection_patterns=[
                    r'"host"\s*:\s*"localhost".*"user"\s*:\s*"root".*"password"\s*:\s*""',
                    r'"database"\s*:\s*"test"',
                    r'"user"\s*:\s*"admin".*"password"\s*:\s*"admin"',
                    r'mongodb://localhost:27017/test',
                    r'mysql://root:@localhost',
                    r'postgresql://postgres:@localhost'
                ],
                remediation="Configure secure database credentials and connection strings"
            ),
            
            # Default session secrets
            DefaultPattern(
                pattern_id="DEFAULT_SESSION_SECRET",
                name="Default Session Secret",
                description="Default or weak session secret detected",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.AUTHENTICATION,
                detection_patterns=[
                    r'"secret"\s*:\s*"(secret|keyboard|cat|default|changeme)"',
                    r'"session[_-]?secret"\s*:\s*"[^"]{1,8}"',  # Very short secrets
                    r'session[_-]?secret\s*=\s*(secret|keyboard|cat|default|changeme)'
                ],
                remediation="Use a strong, randomly generated session secret"
            ),
            
            # Default CORS settings
            DefaultPattern(
                pattern_id="DEFAULT_CORS_WILDCARD",
                name="Default CORS Wildcard",
                description="CORS configured to allow all origins (*)",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.NETWORK,
                detection_patterns=[
                    r'"origin"\s*:\s*"\*"',
                    r'"cors"\s*:\s*{\s*"origin"\s*:\s*"\*"',
                    r'Access-Control-Allow-Origin:\s*\*'
                ],
                remediation="Configure CORS to allow only specific trusted origins"
            ),
            
            # Default SSL/TLS settings
            DefaultPattern(
                pattern_id="DEFAULT_SSL_DISABLED",
                name="SSL/TLS Disabled",
                description="SSL/TLS encryption is disabled by default",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.ENCRYPTION,
                detection_patterns=[
                    r'"ssl"\s*:\s*false',
                    r'"tls"\s*:\s*false',
                    r'"https"\s*:\s*false',
                    r'"secure"\s*:\s*false'
                ],
                remediation="Enable SSL/TLS encryption for secure communication"
            ),
            
            # Default logging settings
            DefaultPattern(
                pattern_id="DEFAULT_DEBUG_ENABLED",
                name="Debug Mode Enabled",
                description="Debug mode is enabled by default",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.LOGGING,
                detection_patterns=[
                    r'"debug"\s*:\s*true',
                    r'"log[_-]?level"\s*:\s*"debug"',
                    r'"verbose"\s*:\s*true'
                ],
                environment_patterns={
                    'DEBUG': 'true',
                    'NODE_ENV': 'development',
                    'LOG_LEVEL': 'debug'
                },
                remediation="Disable debug mode in production environments"
            ),
            
            # Default authentication settings
            DefaultPattern(
                pattern_id="DEFAULT_AUTH_DISABLED",
                name="Authentication Disabled",
                description="Authentication is disabled by default",
                severity=RiskLevel.CRITICAL,
                category=VulnerabilityCategory.AUTHENTICATION,
                detection_patterns=[
                    r'"auth"\s*:\s*false',
                    r'"authentication"\s*:\s*false',
                    r'"require[_-]?auth"\s*:\s*false',
                    r'"no[_-]?auth"\s*:\s*true'
                ],
                remediation="Enable authentication to secure access to the MCP server",
                compliance_violations=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.NIST_CSF]
            ),
            
            # Default file paths
            DefaultPattern(
                pattern_id="DEFAULT_CONFIG_PATHS",
                name="Default Configuration Paths",
                description="Using default configuration file paths",
                severity=RiskLevel.LOW,
                category=VulnerabilityCategory.CONFIGURATION,
                file_patterns=[
                    "config.json",
                    "config.js",
                    "settings.json",
                    ".env",
                    "mcp.config.js"
                ],
                remediation="Use custom configuration file paths to reduce predictability"
            ),
            
            # Default JWT secrets
            DefaultPattern(
                pattern_id="DEFAULT_JWT_SECRET",
                name="Default JWT Secret",
                description="Default or weak JWT signing secret detected",
                severity=RiskLevel.HIGH,
                category=VulnerabilityCategory.AUTHENTICATION,
                detection_patterns=[
                    r'"jwt[_-]?secret"\s*:\s*"(secret|jwt|token|default)"',
                    r'"signing[_-]?key"\s*:\s*"[^"]{1,16}"',  # Short signing keys
                    r'JWT_SECRET\s*=\s*(secret|jwt|token|default)'
                ],
                remediation="Use a strong, randomly generated JWT signing secret"
            ),
            
            # Default rate limiting
            DefaultPattern(
                pattern_id="DEFAULT_RATE_LIMITING_DISABLED",
                name="Rate Limiting Disabled",
                description="Rate limiting is disabled by default",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.NETWORK,
                detection_patterns=[
                    r'"rate[_-]?limit"\s*:\s*false',
                    r'"rate[_-]?limiting"\s*:\s*false',
                    r'"throttle"\s*:\s*false'
                ],
                remediation="Enable rate limiting to prevent abuse and DoS attacks"
            ),
            
            # Default error handling
            DefaultPattern(
                pattern_id="DEFAULT_ERROR_DETAILS",
                name="Detailed Error Messages",
                description="Detailed error messages enabled by default",
                severity=RiskLevel.LOW,
                category=VulnerabilityCategory.ERROR_HANDLING,
                detection_patterns=[
                    r'"show[_-]?errors"\s*:\s*true',
                    r'"error[_-]?details"\s*:\s*true',
                    r'"stack[_-]?trace"\s*:\s*true'
                ],
                remediation="Disable detailed error messages in production"
            ),
            
            # Default NPX package configurations
            DefaultPattern(
                pattern_id="DEFAULT_NPX_GLOBAL",
                name="Global NPX Package Installation",
                description="MCP server installed globally via NPX with default settings",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.CONFIGURATION,
                detection_patterns=[
                    r'npx\s+@modelcontextprotocol/.*--port\s+3000',
                    r'npx\s+.*mcp.*--host\s+0\.0\.0\.0',
                    r'npx\s+.*mcp.*--no-auth'
                ],
                remediation="Use local installation with custom configuration"
            ),
            
            # Default Docker configurations
            DefaultPattern(
                pattern_id="DEFAULT_DOCKER_CONFIG",
                name="Default Docker Configuration",
                description="Docker container using default MCP configuration",
                severity=RiskLevel.MEDIUM,
                category=VulnerabilityCategory.CONFIGURATION,
                detection_patterns=[
                    r'EXPOSE\s+3000',
                    r'ENV\s+NODE_ENV\s+development',
                    r'ENV\s+DEBUG\s+true'
                ],
                remediation="Customize Docker configuration for production use"
            )
        ]
    
    def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
        """
        Perform default configuration detection on a detection result.
        
        Args:
            detection_result: Result from MCP detection
            **kwargs: Additional assessment parameters
            
        Returns:
            AssessmentResult: Result of the default configuration detection
        """
        try:
            self.logger.info(f"Starting default configuration detection for {detection_result.target_host}")
            
            # Perform default configuration detection
            default_detection = self._detect_default_configurations(detection_result)
            
            # Convert detected defaults to security findings
            findings = self._convert_defaults_to_findings(default_detection)
            
            # Create assessment result
            result = AssessmentResult(
                target_host=detection_result.target_host,
                findings=findings
            )
            
            # Calculate overall risk
            result.calculate_overall_risk()
            
            # Add default-specific recommendations
            result.recommendations.extend(default_detection.recommendations)
            
            # Store raw default detection data
            result.raw_data['default_detection'] = {
                'risk_score': default_detection.risk_score,
                'detected_defaults_count': len(default_detection.detected_defaults),
                'critical_defaults_count': len(default_detection.critical_defaults),
                'high_defaults_count': len(default_detection.high_defaults),
                'configuration_files': default_detection.configuration_files,
                'environment_variables': default_detection.environment_variables
            }
            
            self.logger.info(f"Default configuration detection completed for {detection_result.target_host}")
            return result
            
        except Exception as e:
            self.logger.error(f"Default configuration detection failed for {detection_result.target_host}: {e}")
            raise ConfigurationError(f"Failed to detect default configurations: {e}")
    
    def get_assessment_type(self) -> str:
        """Get the type of assessment performed by this assessor."""
        return "default_configuration_detection"
    
    def _detect_default_configurations(self, detection_result: DetectionResult) -> DefaultDetectionResult:
        """Detect default configuration patterns in the detection result."""
        
        result = DefaultDetectionResult(target_host=detection_result.target_host)
        
        # Extract data from detection result
        if detection_result.mcp_server:
            self._analyze_server_defaults(detection_result.mcp_server, result)
        
        if detection_result.raw_data:
            self._analyze_raw_data_defaults(detection_result.raw_data, result)
        
        # Calculate risk score
        result.calculate_risk_score()
        
        # Generate recommendations
        self._generate_default_recommendations(result)
        
        return result
    
    def _analyze_server_defaults(self, server_info: MCPServerInfo, result: DefaultDetectionResult) -> None:
        """Analyze MCP server information for default configurations."""
        
        # Check for default ports
        if server_info.port:
            for pattern in self.default_patterns:
                if pattern.port_patterns and server_info.port in pattern.port_patterns:
                    result.detected_defaults.append(pattern)
                    self.logger.debug(f"Detected default port pattern: {pattern.name}")
        
        # Check for default host binding
        if server_info.host in ['0.0.0.0', '*', '']:
            # This is handled by configuration analysis, but we can add specific default patterns
            pass
        
        # Analyze security configuration for defaults
        if server_info.security_config:
            self._analyze_security_config_defaults(server_info.security_config, result)
        
        # Analyze authentication configuration
        if server_info.authentication:
            self._analyze_auth_config_defaults(server_info.authentication, result)
    
    def _analyze_security_config_defaults(self, security_config: Dict[str, Any], result: DefaultDetectionResult) -> None:
        """Analyze security configuration for default patterns."""
        
        config_str = json.dumps(security_config, indent=2).lower()
        
        for pattern in self.default_patterns:
            if pattern.detection_patterns:
                for detection_pattern in pattern.detection_patterns:
                    if re.search(detection_pattern, config_str, re.IGNORECASE):
                        result.detected_defaults.append(pattern)
                        self.logger.debug(f"Detected default security config pattern: {pattern.name}")
                        break
    
    def _analyze_auth_config_defaults(self, auth_config: Dict[str, Any], result: DefaultDetectionResult) -> None:
        """Analyze authentication configuration for default patterns."""
        
        config_str = json.dumps(auth_config, indent=2).lower()
        
        # Check for disabled authentication
        if not auth_config.get('enabled', True) or auth_config.get('disabled', False):
            auth_disabled_pattern = next(
                (p for p in self.default_patterns if p.pattern_id == "DEFAULT_AUTH_DISABLED"), 
                None
            )
            if auth_disabled_pattern:
                result.detected_defaults.append(auth_disabled_pattern)
        
        # Check for default credentials
        for pattern in self.default_patterns:
            if pattern.category == VulnerabilityCategory.AUTHENTICATION and pattern.detection_patterns:
                for detection_pattern in pattern.detection_patterns:
                    if re.search(detection_pattern, config_str, re.IGNORECASE):
                        result.detected_defaults.append(pattern)
                        self.logger.debug(f"Detected default auth pattern: {pattern.name}")
                        break
    
    def _analyze_raw_data_defaults(self, raw_data: Dict[str, Any], result: DefaultDetectionResult) -> None:
        """Analyze raw detection data for default configuration patterns."""
        
        # Analyze configuration files
        config_files = raw_data.get('configuration_files', [])
        for file_path in config_files:
            try:
                self._analyze_configuration_file_defaults(file_path, result)
            except Exception as e:
                self.logger.warning(f"Failed to analyze configuration file {file_path}: {e}")
        
        # Analyze environment variables
        env_vars = raw_data.get('environment_variables', {})
        if env_vars:
            result.environment_variables = env_vars
            self._analyze_environment_defaults(env_vars, result)
        
        # Analyze process command line
        command_line = raw_data.get('command_line', '')
        if command_line:
            self._analyze_command_line_defaults(command_line, result)
        
        # Analyze process information
        process_info = raw_data.get('process_info')
        if process_info:
            result.process_info = process_info
    
    def _analyze_configuration_file_defaults(self, file_path: str, result: DefaultDetectionResult) -> None:
        """Analyze a configuration file for default patterns."""
        
        try:
            path = Path(file_path)
            if not path.exists():
                return
            
            result.configuration_files.append(str(path))
            
            # Check for default file names
            for pattern in self.default_patterns:
                if pattern.file_patterns and path.name in pattern.file_patterns:
                    result.detected_defaults.append(pattern)
                    self.logger.debug(f"Detected default file pattern: {pattern.name}")
            
            # Read and analyze file content
            content = path.read_text(encoding='utf-8')
            self._analyze_content_defaults(content, result)
            
        except Exception as e:
            self.logger.warning(f"Error analyzing configuration file {file_path}: {e}")
    
    def _analyze_content_defaults(self, content: str, result: DefaultDetectionResult) -> None:
        """Analyze file content for default configuration patterns."""
        
        content_lower = content.lower()
        
        for pattern in self.default_patterns:
            if pattern.detection_patterns:
                for detection_pattern in pattern.detection_patterns:
                    if re.search(detection_pattern, content_lower, re.IGNORECASE):
                        # Avoid duplicates
                        if pattern not in result.detected_defaults:
                            result.detected_defaults.append(pattern)
                            self.logger.debug(f"Detected default content pattern: {pattern.name}")
                        break
    
    def _analyze_environment_defaults(self, env_vars: Dict[str, str], result: DefaultDetectionResult) -> None:
        """Analyze environment variables for default patterns."""
        
        for pattern in self.default_patterns:
            if pattern.environment_patterns:
                for env_key, env_value in pattern.environment_patterns.items():
                    if env_key in env_vars and env_vars[env_key].lower() == env_value.lower():
                        if pattern not in result.detected_defaults:
                            result.detected_defaults.append(pattern)
                            self.logger.debug(f"Detected default environment pattern: {pattern.name}")
    
    def _analyze_command_line_defaults(self, command_line: str, result: DefaultDetectionResult) -> None:
        """Analyze command line for default configuration patterns."""
        
        command_lower = command_line.lower()
        
        for pattern in self.default_patterns:
            if pattern.detection_patterns:
                for detection_pattern in pattern.detection_patterns:
                    if re.search(detection_pattern, command_lower, re.IGNORECASE):
                        if pattern not in result.detected_defaults:
                            result.detected_defaults.append(pattern)
                            self.logger.debug(f"Detected default command line pattern: {pattern.name}")
                        break
    
    def _generate_default_recommendations(self, result: DefaultDetectionResult) -> None:
        """Generate recommendations based on detected default configurations."""
        
        recommendations = []
        
        # General recommendations based on detected defaults
        if result.critical_defaults:
            recommendations.append("Immediately address critical default configurations")
        
        if result.high_defaults:
            recommendations.append("Review and change high-risk default settings")
        
        # Category-specific recommendations
        auth_defaults = result.get_defaults_by_category(VulnerabilityCategory.AUTHENTICATION)
        if auth_defaults:
            recommendations.append("Implement strong authentication mechanisms")
            recommendations.append("Change all default passwords and API keys")
        
        config_defaults = result.get_defaults_by_category(VulnerabilityCategory.CONFIGURATION)
        if config_defaults:
            recommendations.append("Customize configuration files and settings")
            recommendations.append("Use non-default ports and file paths")
        
        encryption_defaults = result.get_defaults_by_category(VulnerabilityCategory.ENCRYPTION)
        if encryption_defaults:
            recommendations.append("Enable SSL/TLS encryption")
            recommendations.append("Use strong encryption settings")
        
        network_defaults = result.get_defaults_by_category(VulnerabilityCategory.NETWORK)
        if network_defaults:
            recommendations.append("Configure proper CORS policies")
            recommendations.append("Enable rate limiting and access controls")
        
        logging_defaults = result.get_defaults_by_category(VulnerabilityCategory.LOGGING)
        if logging_defaults:
            recommendations.append("Disable debug mode in production")
            recommendations.append("Configure appropriate logging levels")
        
        result.recommendations = recommendations
    
    def _convert_defaults_to_findings(self, result: DefaultDetectionResult) -> List[SecurityFinding]:
        """Convert detected default patterns to security findings."""
        
        findings = []
        
        for pattern in result.detected_defaults:
            finding = SecurityFinding(
                id=f"DEFAULT_{pattern.pattern_id}_{hash(result.target_host) % 10000:04d}",
                title=pattern.name,
                description=pattern.description,
                category=pattern.category,
                severity=pattern.severity,
                confidence=0.8,  # High confidence for default detection
                affected_asset=result.target_host,
                evidence={
                    'pattern_id': pattern.pattern_id,
                    'detection_patterns': pattern.detection_patterns,
                    'file_patterns': pattern.file_patterns,
                    'port_patterns': pattern.port_patterns,
                    'environment_patterns': pattern.environment_patterns,
                    'configuration_files': result.configuration_files,
                    'environment_variables': result.environment_variables,
                    'risk_score': result.risk_score
                },
                remediation=pattern.remediation,
                references=pattern.references,
                compliance_violations=pattern.compliance_violations
            )
            findings.append(finding)
        
        return findings


# Convenience functions
def detect_default_configurations(detection_result: DetectionResult, settings=None) -> DefaultDetectionResult:
    """
    Detect default configurations in a detected MCP server.
    
    Args:
        detection_result: Detection result to analyze
        settings: Optional settings
        
    Returns:
        DefaultDetectionResult: Detection results
    """
    detector = DefaultConfigurationDetector(settings)
    assessment_result = detector.assess(detection_result)
    
    # Extract default detection data from raw_data
    default_data = assessment_result.raw_data.get('default_detection', {})
    
    result = DefaultDetectionResult(
        target_host=detection_result.target_host,
        configuration_files=default_data.get('configuration_files', []),
        environment_variables=default_data.get('environment_variables', {}),
        risk_score=default_data.get('risk_score', 0.0)
    )
    
    # Convert findings back to default patterns
    for finding in assessment_result.findings:
        pattern = DefaultPattern(
            pattern_id=finding.evidence.get('pattern_id', finding.id),
            name=finding.title,
            description=finding.description,
            severity=finding.severity,
            category=finding.category,
            detection_patterns=finding.evidence.get('detection_patterns', []),
            file_patterns=finding.evidence.get('file_patterns', []),
            port_patterns=finding.evidence.get('port_patterns', []),
            environment_patterns=finding.evidence.get('environment_patterns', {}),
            remediation=finding.remediation,
            references=finding.references,
            compliance_violations=finding.compliance_violations
        )
        result.detected_defaults.append(pattern)
    
    return result


def get_default_patterns() -> List[DefaultPattern]:
    """
    Get the list of all default configuration patterns.
    
    Returns:
        List[DefaultPattern]: List of default patterns
    """
    detector = DefaultConfigurationDetector()
    return detector.default_patterns


def check_for_pattern(content: str, pattern_id: str) -> bool:
    """
    Check if content matches a specific default pattern.
    
    Args:
        content: Content to check
        pattern_id: ID of the pattern to check
        
    Returns:
        bool: True if pattern matches
    """
    detector = DefaultConfigurationDetector()
    pattern = next((p for p in detector.default_patterns if p.pattern_id == pattern_id), None)
    
    if not pattern or not pattern.detection_patterns:
        return False
    
    content_lower = content.lower()
    for detection_pattern in pattern.detection_patterns:
        if re.search(detection_pattern, content_lower, re.IGNORECASE):
            return True
    
    return False 