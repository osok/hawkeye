"""
Custom exception classes for HawkEye security reconnaissance tool.

This module defines the exception hierarchy used throughout the application
for proper error handling and user feedback.
"""

from typing import Any, Dict, Optional


class HawkEyeError(Exception):
    """Base exception class for all HawkEye-related errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(HawkEyeError):
    """Raised when there are configuration-related errors."""
    pass


class NetworkError(HawkEyeError):
    """Raised when network operations fail."""
    pass


class ScanError(HawkEyeError):
    """Raised when scanning operations encounter errors."""
    pass


class DetectionError(HawkEyeError):
    """Raised when MCP detection operations fail."""
    pass


class AssessmentError(HawkEyeError):
    """Raised when risk assessment operations fail."""
    pass


class ReportingError(HawkEyeError):
    """Raised when report generation fails."""
    pass


class ValidationError(HawkEyeError):
    """Raised when input validation fails."""
    pass 