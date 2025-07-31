"""
Custom exceptions for the assessment module.

This module defines specific exception types for assessment-related errors,
providing meaningful error messages and proper error handling.
"""


class AssessmentError(Exception):
    """Base exception for assessment-related errors."""
    pass


class RemediationError(AssessmentError):
    """Exception raised when remediation planning fails."""
    pass


class InvalidFindingError(AssessmentError):
    """Exception raised when a security finding is invalid or malformed."""
    pass


class RemediationTemplateError(RemediationError):
    """Exception raised when remediation templates are invalid or missing."""
    pass


class PrioritizationError(RemediationError):
    """Exception raised when action prioritization fails."""
    pass


class RiskCalculationError(AssessmentError):
    """Exception raised when risk calculation fails."""
    pass


class ComplianceError(AssessmentError):
    """Exception raised when compliance assessment fails."""
    pass 