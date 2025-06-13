"""
Transport Error Handling and Logging

Comprehensive error handling, classification, and logging for MCP transport
operations with detailed error context and recovery suggestions.
"""

import logging
import traceback
from typing import Any, Dict, List, Optional, Type, Union
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

from .base import TransportError, ConnectionFailedError, ConnectionTimeoutError


class ErrorSeverity(str, Enum):
    """Error severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ErrorCategory(str, Enum):
    """Error category classification."""
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    PROTOCOL = "protocol"
    TIMEOUT = "timeout"
    PERMISSION = "permission"
    RESOURCE = "resource"
    UNKNOWN = "unknown"


@dataclass
class ErrorContext:
    """Context information for an error."""
    timestamp: datetime
    operation: str
    transport_type: str
    error_type: str
    error_message: str
    severity: ErrorSeverity
    category: ErrorCategory
    details: Dict[str, Any]
    stack_trace: Optional[str] = None
    recovery_suggestions: List[str] = None
    
    def __post_init__(self):
        if self.recovery_suggestions is None:
            self.recovery_suggestions = []


class TransportErrorHandler:
    """
    Handles and classifies transport errors with detailed context and logging.
    
    Provides error classification, recovery suggestions, and comprehensive
    logging for MCP transport operations.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the error handler.
        
        Args:
            logger: Logger instance for error reporting
        """
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._error_history: List[ErrorContext] = []
        self._error_patterns: Dict[str, int] = {}
    
    def classify_error(
        self,
        error: Exception,
        operation: str,
        transport_type: str,
        details: Optional[Dict[str, Any]] = None
    ) -> ErrorContext:
        """
        Classify an error and create detailed context.
        
        Args:
            error: Exception that occurred
            operation: Operation that was being performed
            transport_type: Type of transport (stdio, sse, http)
            details: Additional context details
            
        Returns:
            ErrorContext: Classified error with context
        """
        details = details or {}
        error_type = type(error).__name__
        error_message = str(error)
        
        # Classify error category and severity
        category, severity = self._classify_error_type(error, error_message)
        
        # Generate recovery suggestions
        suggestions = self._generate_recovery_suggestions(error, category, transport_type)
        
        # Create error context
        context = ErrorContext(
            timestamp=datetime.now(),
            operation=operation,
            transport_type=transport_type,
            error_type=error_type,
            error_message=error_message,
            severity=severity,
            category=category,
            details=details,
            stack_trace=traceback.format_exc(),
            recovery_suggestions=suggestions
        )
        
        # Track error patterns
        pattern_key = f"{error_type}:{category.value}"
        self._error_patterns[pattern_key] = self._error_patterns.get(pattern_key, 0) + 1
        
        # Store in history
        self._error_history.append(context)
        
        # Keep only recent errors (last 100)
        if len(self._error_history) > 100:
            self._error_history = self._error_history[-100:]
        
        return context
    
    def _classify_error_type(
        self,
        error: Exception,
        message: str
    ) -> tuple[ErrorCategory, ErrorSeverity]:
        """
        Classify error type and determine severity.
        
        Args:
            error: Exception instance
            message: Error message
            
        Returns:
            Tuple of (category, severity)
        """
        message_lower = message.lower()
        
        # Network-related errors
        if isinstance(error, (ConnectionError, OSError)) or any(
            keyword in message_lower for keyword in [
                'connection', 'network', 'socket', 'host', 'unreachable',
                'refused', 'reset', 'broken pipe', 'no route'
            ]
        ):
            severity = ErrorSeverity.HIGH if 'refused' in message_lower else ErrorSeverity.MEDIUM
            return ErrorCategory.NETWORK, severity
        
        # Timeout errors
        if isinstance(error, (ConnectionTimeoutError, TimeoutError)) or 'timeout' in message_lower:
            return ErrorCategory.TIMEOUT, ErrorSeverity.MEDIUM
        
        # Authentication errors
        if any(keyword in message_lower for keyword in [
            'auth', 'unauthorized', 'forbidden', 'token', 'credential',
            'permission denied', '401', '403'
        ]):
            return ErrorCategory.AUTHENTICATION, ErrorSeverity.HIGH
        
        # Configuration errors
        if any(keyword in message_lower for keyword in [
            'config', 'invalid', 'missing', 'required', 'format',
            'parse', 'syntax', 'malformed'
        ]):
            return ErrorCategory.CONFIGURATION, ErrorSeverity.MEDIUM
        
        # Protocol errors
        if any(keyword in message_lower for keyword in [
            'protocol', 'mcp', 'jsonrpc', 'invalid response',
            'unexpected', 'malformed response'
        ]):
            return ErrorCategory.PROTOCOL, ErrorSeverity.HIGH
        
        # Permission errors
        if any(keyword in message_lower for keyword in [
            'permission', 'access denied', 'not allowed', 'privilege'
        ]):
            return ErrorCategory.PERMISSION, ErrorSeverity.HIGH
        
        # Resource errors
        if any(keyword in message_lower for keyword in [
            'memory', 'disk', 'space', 'limit', 'quota', 'resource'
        ]):
            return ErrorCategory.RESOURCE, ErrorSeverity.MEDIUM
        
        # Default classification
        return ErrorCategory.UNKNOWN, ErrorSeverity.MEDIUM
    
    def _generate_recovery_suggestions(
        self,
        error: Exception,
        category: ErrorCategory,
        transport_type: str
    ) -> List[str]:
        """
        Generate recovery suggestions based on error category and transport type.
        
        Args:
            error: Exception instance
            category: Error category
            transport_type: Transport type
            
        Returns:
            List of recovery suggestions
        """
        suggestions = []
        
        if category == ErrorCategory.NETWORK:
            suggestions.extend([
                "Check network connectivity",
                "Verify server is running and accessible",
                "Check firewall settings",
                "Try connecting from a different network"
            ])
            
            if transport_type in ('sse', 'http'):
                suggestions.extend([
                    "Verify URL is correct and accessible",
                    "Check if server supports the transport protocol",
                    "Try using a different port or endpoint"
                ])
        
        elif category == ErrorCategory.TIMEOUT:
            suggestions.extend([
                "Increase connection timeout value",
                "Check server response time",
                "Verify server is not overloaded",
                "Try connecting during off-peak hours"
            ])
        
        elif category == ErrorCategory.AUTHENTICATION:
            suggestions.extend([
                "Verify authentication credentials",
                "Check if token/API key is valid and not expired",
                "Ensure proper authentication headers are set",
                "Contact administrator for access permissions"
            ])
        
        elif category == ErrorCategory.CONFIGURATION:
            suggestions.extend([
                "Review configuration parameters",
                "Check for typos in configuration values",
                "Validate configuration against schema",
                "Refer to documentation for correct format"
            ])
            
            if transport_type == 'stdio':
                suggestions.extend([
                    "Verify command path is correct",
                    "Check if command is executable",
                    "Ensure all required arguments are provided"
                ])
        
        elif category == ErrorCategory.PROTOCOL:
            suggestions.extend([
                "Verify server supports MCP protocol",
                "Check MCP protocol version compatibility",
                "Ensure server is properly configured for MCP",
                "Try using a different transport method"
            ])
        
        elif category == ErrorCategory.PERMISSION:
            suggestions.extend([
                "Check file/directory permissions",
                "Run with appropriate user privileges",
                "Verify access to required resources",
                "Contact system administrator"
            ])
        
        elif category == ErrorCategory.RESOURCE:
            suggestions.extend([
                "Check available system resources",
                "Free up memory or disk space",
                "Reduce concurrent connections",
                "Monitor resource usage"
            ])
        
        # Add transport-specific suggestions
        if transport_type == 'stdio':
            suggestions.extend([
                "Ensure Node.js/Python runtime is available",
                "Check if server script exists and is executable"
            ])
        elif transport_type in ('sse', 'http'):
            suggestions.extend([
                "Verify SSL/TLS configuration",
                "Check proxy settings if applicable"
            ])
        
        return suggestions
    
    def log_error(self, context: ErrorContext) -> None:
        """
        Log an error with appropriate level and formatting.
        
        Args:
            context: Error context to log
        """
        # Determine log level based on severity
        if context.severity == ErrorSeverity.CRITICAL:
            log_level = logging.CRITICAL
        elif context.severity == ErrorSeverity.HIGH:
            log_level = logging.ERROR
        elif context.severity == ErrorSeverity.MEDIUM:
            log_level = logging.WARNING
        elif context.severity == ErrorSeverity.LOW:
            log_level = logging.INFO
        else:
            log_level = logging.DEBUG
        
        # Format error message
        message = (
            f"Transport error in {context.operation} "
            f"({context.transport_type}): {context.error_message}"
        )
        
        # Add details if available
        if context.details:
            details_str = ", ".join(f"{k}={v}" for k, v in context.details.items())
            message += f" | Details: {details_str}"
        
        # Log the error
        self.logger.log(log_level, message)
        
        # Log recovery suggestions at debug level
        if context.recovery_suggestions:
            suggestions_str = "; ".join(context.recovery_suggestions)
            self.logger.debug(f"Recovery suggestions: {suggestions_str}")
        
        # Log stack trace for high severity errors
        if context.severity in (ErrorSeverity.CRITICAL, ErrorSeverity.HIGH) and context.stack_trace:
            self.logger.debug(f"Stack trace:\n{context.stack_trace}")
    
    def handle_error(
        self,
        error: Exception,
        operation: str,
        transport_type: str,
        details: Optional[Dict[str, Any]] = None,
        raise_error: bool = True
    ) -> ErrorContext:
        """
        Handle an error with classification, logging, and optional re-raising.
        
        Args:
            error: Exception that occurred
            operation: Operation that was being performed
            transport_type: Type of transport
            details: Additional context details
            raise_error: Whether to re-raise the error
            
        Returns:
            ErrorContext: Classified error context
            
        Raises:
            Exception: Re-raises the original error if raise_error is True
        """
        context = self.classify_error(error, operation, transport_type, details)
        self.log_error(context)
        
        if raise_error:
            raise error
        
        return context
    
    def get_error_stats(self) -> Dict[str, Any]:
        """
        Get error statistics and patterns.
        
        Returns:
            Dict containing error statistics
        """
        if not self._error_history:
            return {'total_errors': 0}
        
        # Count by category and severity
        category_counts = {}
        severity_counts = {}
        
        for error in self._error_history:
            category_counts[error.category.value] = category_counts.get(error.category.value, 0) + 1
            severity_counts[error.severity.value] = severity_counts.get(error.severity.value, 0) + 1
        
        # Recent errors (last hour)
        recent_errors = [
            e for e in self._error_history
            if (datetime.now() - e.timestamp).total_seconds() < 3600
        ]
        
        return {
            'total_errors': len(self._error_history),
            'recent_errors': len(recent_errors),
            'category_counts': category_counts,
            'severity_counts': severity_counts,
            'error_patterns': dict(self._error_patterns),
            'most_common_category': max(category_counts.items(), key=lambda x: x[1])[0] if category_counts else None,
        }
    
    def get_recent_errors(self, limit: int = 10) -> List[ErrorContext]:
        """
        Get recent error contexts.
        
        Args:
            limit: Maximum number of errors to return
            
        Returns:
            List of recent error contexts
        """
        return self._error_history[-limit:] if self._error_history else []
    
    def clear_history(self) -> None:
        """Clear error history and patterns."""
        self._error_history.clear()
        self._error_patterns.clear()
        self.logger.info("Error history cleared") 