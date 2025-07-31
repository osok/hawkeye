"""
HawkEye - Hidden Application Weaknesses & Key Entry-point Yielding Evaluator

A comprehensive security reconnaissance tool designed to identify and assess 
Model Context Protocol (MCP) server deployments within network infrastructure.
"""

__version__ = "0.1.0"
__author__ = "HawkEye Security Team"
__description__ = "MCP Security Reconnaissance Tool"

from .exceptions import HawkEyeError
from . import detection
from . import scanner

__all__ = ["HawkEyeError", "__version__", "detection", "scanner"] 