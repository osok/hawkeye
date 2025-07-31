"""
Logging infrastructure for HawkEye security reconnaissance tool.

This module provides centralized logging configuration with support for
structured logging, file rotation, colored console output, and audit trails.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

import colorlog
import structlog

from ..config import get_settings
from ..exceptions import ConfigurationError


class HawkEyeLogger:
    """Centralized logger configuration for HawkEye application."""
    
    def __init__(self):
        self.settings = get_settings().logging
        self._configured = False
        self._logger = None
    
    def configure(self) -> logging.Logger:
        """
        Configure and return the main application logger.
        
        Returns:
            logging.Logger: Configured logger instance
            
        Raises:
            ConfigurationError: If logging configuration fails
        """
        if self._configured:
            return self._logger
            
        try:
            # Configure structlog if enabled
            if self.settings.enable_structured_logging:
                self._configure_structlog()
            
            # Create main logger
            self._logger = logging.getLogger("hawkeye")
            self._logger.setLevel(getattr(logging, self.settings.log_level.upper()))
            
            # Clear any existing handlers
            self._logger.handlers.clear()
            
            # Add console handler
            self._add_console_handler()
            
            # Add file handler if specified
            if self.settings.log_file:
                self._add_file_handler()
            
            # Prevent duplicate logs
            self._logger.propagate = False
            
            self._configured = True
            return self._logger
            
        except Exception as e:
            raise ConfigurationError(f"Failed to configure logging: {e}")
    
    def _configure_structlog(self):
        """Configure structured logging with structlog."""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def _add_console_handler(self):
        """Add colored console handler."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, self.settings.console_log_level.upper()))
        
        if self.settings.enable_color_logging:
            # Colored formatter for console
            formatter = colorlog.ColoredFormatter(
                "%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white',
                }
            )
        else:
            # Standard formatter for console
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)
    
    def _add_file_handler(self):
        """Add rotating file handler."""
        log_file = Path(self.settings.log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=self.settings.max_log_size_mb * 1024 * 1024,
            backupCount=self.settings.log_backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, self.settings.file_log_level.upper()))
        
        # Detailed formatter for file logs
        if self.settings.enable_structured_logging:
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "name": "%(name)s", "level": "%(levelname)s", '
                '"module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d, '
                '"message": "%(message)s"}',
                datefmt="%Y-%m-%dT%H:%M:%S"
            )
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """
        Get a logger instance.
        
        Args:
            name: Logger name (defaults to calling module)
            
        Returns:
            logging.Logger: Logger instance
        """
        if not self._configured:
            self.configure()
        
        if name:
            return logging.getLogger(f"hawkeye.{name}")
        return self._logger


class AuditLogger:
    """Specialized logger for audit trail and security events."""
    
    def __init__(self):
        self.settings = get_settings()
        self.logger = logging.getLogger("hawkeye.audit")
        self._configure_audit_logger()
    
    def _configure_audit_logger(self):
        """Configure audit-specific logging."""
        if not self.settings.audit_trail:
            return
        
        # Create audit log file
        audit_file = Path("logs/hawkeye_audit.log")
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Audit file handler (no rotation for security)
        audit_handler = logging.FileHandler(
            filename=audit_file,
            mode='a',
            encoding='utf-8'
        )
        audit_handler.setLevel(logging.INFO)
        
        # Structured audit formatter
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "event_type": "audit", "level": "%(levelname)s", '
            '"message": "%(message)s", "user": "%(user)s", "action": "%(action)s", '
            '"target": "%(target)s", "result": "%(result)s"}',
            datefmt="%Y-%m-%dT%H:%M:%S"
        )
        
        audit_handler.setFormatter(formatter)
        self.logger.addHandler(audit_handler)
        self.logger.propagate = False
    
    def log_scan_start(self, target: str, user: str = "system"):
        """Log scan operation start."""
        self.logger.info(
            "Scan operation started",
            extra={
                "user": user,
                "action": "scan_start",
                "target": target,
                "result": "initiated"
            }
        )
    
    def log_scan_complete(self, target: str, findings_count: int, user: str = "system"):
        """Log scan operation completion."""
        self.logger.info(
            f"Scan operation completed with {findings_count} findings",
            extra={
                "user": user,
                "action": "scan_complete",
                "target": target,
                "result": f"completed_{findings_count}_findings"
            }
        )
    
    def log_detection_event(self, target: str, service_type: str, user: str = "system"):
        """Log MCP service detection."""
        self.logger.info(
            f"MCP service detected: {service_type}",
            extra={
                "user": user,
                "action": "mcp_detection",
                "target": target,
                "result": f"detected_{service_type}"
            }
        )
    
    def log_security_event(self, event_type: str, details: str, user: str = "system"):
        """Log security-related events."""
        self.logger.warning(
            f"Security event: {event_type} - {details}",
            extra={
                "user": user,
                "action": "security_event",
                "target": event_type,
                "result": "flagged"
            }
        )


# Global logger instances
_hawkeye_logger = HawkEyeLogger()
_audit_logger = AuditLogger()


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (defaults to calling module)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    return _hawkeye_logger.get_logger(name)


def get_audit_logger() -> AuditLogger:
    """
    Get the audit logger instance.
    
    Returns:
        AuditLogger: Audit logger instance
    """
    return _audit_logger


def configure_logging() -> logging.Logger:
    """
    Configure the main application logging.
    
    Returns:
        logging.Logger: Main application logger
    """
    return _hawkeye_logger.configure() 