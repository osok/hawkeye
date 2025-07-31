"""
Transport Configuration Validation

Comprehensive validation for MCP transport configurations including
security checks, format validation, and configuration recommendations.
"""

import re
import logging
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from ..models import TransportType


class ValidationSeverity(str, Enum):
    """Validation issue severity levels."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: ValidationSeverity
    field: str
    message: str
    suggestion: Optional[str] = None


class TransportConfigValidator:
    """
    Validates MCP transport configurations for correctness and security.
    
    Provides comprehensive validation including format checks, security
    analysis, and configuration recommendations.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the validator.
        
        Args:
            logger: Logger instance for validation messages
        """
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Security patterns to check for
        self._dangerous_patterns = [
            r'[;&|`$]',  # Shell injection characters
            r'\.\./.*',  # Path traversal
            r'rm\s+-rf',  # Dangerous commands
            r'eval\s*\(',  # Code evaluation
        ]
        
        # Common secure ports
        self._secure_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
        
        # Required fields for each transport type
        self._required_fields = {
            TransportType.STDIO: {'command'},
            TransportType.SSE: {'url'},
            TransportType.HTTP: {'base_url'},
        }
        
        # Optional but recommended fields
        self._recommended_fields = {
            TransportType.STDIO: {'args', 'timeout'},
            TransportType.SSE: {'headers', 'verify_ssl'},
            TransportType.HTTP: {'auth', 'verify_ssl', 'timeout'},
        }
    
    def validate_config(
        self,
        config: Dict[str, Any],
        transport_type: Optional[TransportType] = None
    ) -> List[ValidationIssue]:
        """
        Validate a transport configuration.
        
        Args:
            config: Configuration dictionary to validate
            transport_type: Specific transport type to validate for
            
        Returns:
            List of validation issues found
        """
        issues = []
        
        # Auto-detect transport type if not provided
        if transport_type is None:
            transport_type = self._detect_transport_type(config)
            if transport_type is None:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="transport",
                    message="Cannot determine transport type from configuration",
                    suggestion="Add explicit 'transport' field or ensure required fields are present"
                ))
                return issues
        
        # Validate required fields
        issues.extend(self._validate_required_fields(config, transport_type))
        
        # Validate transport-specific configuration
        if transport_type == TransportType.STDIO:
            issues.extend(self._validate_stdio_config(config))
        elif transport_type == TransportType.SSE:
            issues.extend(self._validate_sse_config(config))
        elif transport_type == TransportType.HTTP:
            issues.extend(self._validate_http_config(config))
        
        # Validate common fields
        issues.extend(self._validate_common_fields(config))
        
        # Security validation
        issues.extend(self._validate_security(config, transport_type))
        
        # Performance recommendations
        issues.extend(self._validate_performance(config, transport_type))
        
        return issues
    
    def _detect_transport_type(self, config: Dict[str, Any]) -> Optional[TransportType]:
        """Detect transport type from configuration."""
        if 'transport' in config:
            try:
                return TransportType(config['transport'].lower())
            except ValueError:
                return None
        
        if 'command' in config:
            return TransportType.STDIO
        elif 'url' in config:
            url = config['url']
            if any(indicator in url.lower() for indicator in ['sse', 'events', 'stream']):
                return TransportType.SSE
            else:
                return TransportType.HTTP
        elif 'base_url' in config:
            return TransportType.HTTP
        
        return None
    
    def _validate_required_fields(
        self,
        config: Dict[str, Any],
        transport_type: TransportType
    ) -> List[ValidationIssue]:
        """Validate required fields for transport type."""
        issues = []
        required = self._required_fields.get(transport_type, set())
        
        for field in required:
            if field not in config:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field=field,
                    message=f"Required field '{field}' is missing for {transport_type.value} transport",
                    suggestion=f"Add '{field}' field to configuration"
                ))
            elif not config[field]:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field=field,
                    message=f"Required field '{field}' is empty",
                    suggestion=f"Provide a valid value for '{field}'"
                ))
        
        return issues
    
    def _validate_stdio_config(self, config: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate stdio-specific configuration."""
        issues = []
        
        # Validate command
        if 'command' in config:
            command = config['command']
            
            # Check if command is a string
            if not isinstance(command, str):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="command",
                    message="Command must be a string",
                    suggestion="Ensure command is specified as a string value"
                ))
            else:
                # Check for dangerous patterns
                for pattern in self._dangerous_patterns:
                    if re.search(pattern, command):
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            field="command",
                            message=f"Command contains potentially dangerous pattern: {pattern}",
                            suggestion="Review command for security implications"
                        ))
                
                # Check if command exists (basic check)
                if not command.strip():
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        field="command",
                        message="Command is empty",
                        suggestion="Provide a valid command to execute"
                    ))
        
        # Validate arguments
        if 'args' in config:
            args = config['args']
            if not isinstance(args, list):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="args",
                    message="Arguments must be a list",
                    suggestion="Provide arguments as a list of strings"
                ))
            else:
                for i, arg in enumerate(args):
                    if not isinstance(arg, str):
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            field=f"args[{i}]",
                            message="Argument should be a string",
                            suggestion="Convert argument to string"
                        ))
                    
                    # Check for dangerous patterns in arguments
                    for pattern in self._dangerous_patterns:
                        if re.search(pattern, str(arg)):
                            issues.append(ValidationIssue(
                                severity=ValidationSeverity.WARNING,
                                field=f"args[{i}]",
                                message=f"Argument contains potentially dangerous pattern: {pattern}",
                                suggestion="Review argument for security implications"
                            ))
        
        # Validate environment variables
        if 'env' in config:
            env = config['env']
            if not isinstance(env, dict):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="env",
                    message="Environment variables must be a dictionary",
                    suggestion="Provide environment variables as key-value pairs"
                ))
        
        return issues
    
    def _validate_sse_config(self, config: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate SSE-specific configuration."""
        issues = []
        
        # Validate URL
        if 'url' in config:
            url = config['url']
            issues.extend(self._validate_url(url, 'url'))
        
        # Validate headers
        if 'headers' in config:
            headers = config['headers']
            if not isinstance(headers, dict):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="headers",
                    message="Headers must be a dictionary",
                    suggestion="Provide headers as key-value pairs"
                ))
            else:
                # Check for sensitive headers
                sensitive_headers = {'authorization', 'cookie', 'x-api-key'}
                for header_name in headers:
                    if header_name.lower() in sensitive_headers:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.INFO,
                            field=f"headers.{header_name}",
                            message="Header contains sensitive information",
                            suggestion="Ensure sensitive headers are properly secured"
                        ))
        
        return issues
    
    def _validate_http_config(self, config: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate HTTP-specific configuration."""
        issues = []
        
        # Validate base URL
        if 'base_url' in config:
            base_url = config['base_url']
            issues.extend(self._validate_url(base_url, 'base_url'))
        
        # Validate authentication
        if 'auth' in config:
            auth = config['auth']
            if not isinstance(auth, dict):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="auth",
                    message="Authentication must be a dictionary",
                    suggestion="Provide authentication as key-value pairs"
                ))
            else:
                # Check for valid auth methods
                valid_auth_keys = {'bearer_token', 'api_key', 'basic_auth', 'api_key_header'}
                auth_keys = set(auth.keys())
                
                if not auth_keys.intersection(valid_auth_keys):
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        field="auth",
                        message="No recognized authentication method found",
                        suggestion=f"Use one of: {', '.join(valid_auth_keys)}"
                    ))
                
                # Check for empty auth values
                for key, value in auth.items():
                    if not value:
                        issues.append(ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            field=f"auth.{key}",
                            message="Authentication value is empty",
                            suggestion="Provide a valid authentication value"
                        ))
        
        return issues
    
    def _validate_url(self, url: str, field_name: str) -> List[ValidationIssue]:
        """Validate URL format and security."""
        issues = []
        
        if not isinstance(url, str):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field=field_name,
                message="URL must be a string",
                suggestion="Provide URL as a string value"
            ))
            return issues
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ('http', 'https'):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field=field_name,
                    message=f"Invalid URL scheme: {parsed.scheme}",
                    suggestion="Use http:// or https:// scheme"
                ))
            
            # Check hostname
            if not parsed.hostname:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field=field_name,
                    message="URL missing hostname",
                    suggestion="Provide a valid hostname in the URL"
                ))
            
            # Security recommendations
            if parsed.scheme == 'http':
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    field=field_name,
                    message="Using insecure HTTP connection",
                    suggestion="Consider using HTTPS for better security"
                ))
            
            # Check port
            if parsed.port and parsed.port not in self._secure_ports:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    field=field_name,
                    message=f"Using non-standard port: {parsed.port}",
                    suggestion="Verify port is correct and accessible"
                ))
            
        except Exception as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                field=field_name,
                message=f"Invalid URL format: {e}",
                suggestion="Provide a valid URL"
            ))
        
        return issues
    
    def _validate_common_fields(self, config: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate common configuration fields."""
        issues = []
        
        # Validate timeout
        if 'timeout' in config:
            timeout = config['timeout']
            if not isinstance(timeout, (int, float)):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="timeout",
                    message="Timeout must be a number",
                    suggestion="Provide timeout as seconds (integer or float)"
                ))
            elif timeout <= 0:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="timeout",
                    message="Timeout must be positive",
                    suggestion="Use a positive timeout value"
                ))
            elif timeout > 300:  # 5 minutes
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    field="timeout",
                    message="Timeout is very high (>5 minutes)",
                    suggestion="Consider using a shorter timeout"
                ))
        
        # Validate max_retries
        if 'max_retries' in config:
            max_retries = config['max_retries']
            if not isinstance(max_retries, int):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="max_retries",
                    message="Max retries must be an integer",
                    suggestion="Provide max_retries as an integer"
                ))
            elif max_retries < 0:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    field="max_retries",
                    message="Max retries cannot be negative",
                    suggestion="Use 0 or positive value for max_retries"
                ))
            elif max_retries > 10:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    field="max_retries",
                    message="Max retries is very high (>10)",
                    suggestion="Consider using fewer retries"
                ))
        
        return issues
    
    def _validate_security(
        self,
        config: Dict[str, Any],
        transport_type: TransportType
    ) -> List[ValidationIssue]:
        """Validate security aspects of configuration."""
        issues = []
        
        # Check SSL verification
        if 'verify_ssl' in config:
            verify_ssl = config['verify_ssl']
            if verify_ssl is False:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    field="verify_ssl",
                    message="SSL verification is disabled",
                    suggestion="Enable SSL verification for better security"
                ))
        
        # Check for hardcoded credentials
        sensitive_fields = ['password', 'token', 'key', 'secret']
        for field, value in config.items():
            if any(sensitive in field.lower() for sensitive in sensitive_fields):
                if isinstance(value, str) and len(value) > 10:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        field=field,
                        message="Potential hardcoded credential detected",
                        suggestion="Consider using environment variables for credentials"
                    ))
        
        return issues
    
    def _validate_performance(
        self,
        config: Dict[str, Any],
        transport_type: TransportType
    ) -> List[ValidationIssue]:
        """Validate performance-related configuration."""
        issues = []
        
        # Check for recommended fields
        recommended = self._recommended_fields.get(transport_type, set())
        for field in recommended:
            if field not in config:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    field=field,
                    message=f"Recommended field '{field}' is missing",
                    suggestion=f"Consider adding '{field}' for better performance/reliability"
                ))
        
        return issues
    
    def is_valid(self, config: Dict[str, Any], transport_type: Optional[TransportType] = None) -> bool:
        """
        Check if configuration is valid (no errors).
        
        Args:
            config: Configuration to validate
            transport_type: Transport type to validate for
            
        Returns:
            bool: True if configuration has no errors
        """
        issues = self.validate_config(config, transport_type)
        return not any(issue.severity == ValidationSeverity.ERROR for issue in issues)
    
    def get_validation_summary(
        self,
        issues: List[ValidationIssue]
    ) -> Dict[str, Any]:
        """
        Get a summary of validation results.
        
        Args:
            issues: List of validation issues
            
        Returns:
            Dict containing validation summary
        """
        error_count = sum(1 for issue in issues if issue.severity == ValidationSeverity.ERROR)
        warning_count = sum(1 for issue in issues if issue.severity == ValidationSeverity.WARNING)
        info_count = sum(1 for issue in issues if issue.severity == ValidationSeverity.INFO)
        
        return {
            'total_issues': len(issues),
            'errors': error_count,
            'warnings': warning_count,
            'info': info_count,
            'is_valid': error_count == 0,
            'issues_by_severity': {
                'error': [issue for issue in issues if issue.severity == ValidationSeverity.ERROR],
                'warning': [issue for issue in issues if issue.severity == ValidationSeverity.WARNING],
                'info': [issue for issue in issues if issue.severity == ValidationSeverity.INFO],
            }
        } 