"""
Unit tests for HawkEye logging infrastructure.

Tests for logger configuration, audit logging, and log formatting.
"""

import logging
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hawkeye.config.settings import HawkEyeSettings, LoggingSettings
from hawkeye.exceptions import ConfigurationError
from hawkeye.utils.logging import (
    AuditLogger,
    HawkEyeLogger,
    configure_logging,
    get_audit_logger,
    get_logger,
)


class TestHawkEyeLogger:
    """Test cases for HawkEyeLogger class."""
    
    def test_logger_initialization(self):
        """Test logger initialization."""
        logger_instance = HawkEyeLogger()
        
        assert logger_instance.settings is not None
        assert logger_instance._configured is False
        assert logger_instance._logger is None
    
    def test_configure_basic_setup(self):
        """Test basic logger configuration."""
        logger_instance = HawkEyeLogger()
        main_logger = logger_instance.configure()
        
        assert main_logger is not None
        assert main_logger.name == "hawkeye"
        assert logger_instance._configured is True
        assert logger_instance._logger is main_logger
    
    def test_configure_idempotent(self):
        """Test that configure() is idempotent."""
        logger_instance = HawkEyeLogger()
        
        logger1 = logger_instance.configure()
        logger2 = logger_instance.configure()
        
        assert logger1 is logger2
        assert logger_instance._configured is True
    
    def test_console_handler_configuration(self):
        """Test console handler configuration."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            # Mock settings
            mock_settings = MagicMock()
            mock_settings.logging.log_level = "INFO"
            mock_settings.logging.console_log_level = "INFO"
            mock_settings.logging.enable_color_logging = True
            mock_settings.logging.enable_structured_logging = False
            mock_settings.logging.log_file = None
            mock_get_settings.return_value = mock_settings
            
            logger_instance = HawkEyeLogger()
            main_logger = logger_instance.configure()
            
            # Check that console handler was added
            assert len(main_logger.handlers) >= 1
            console_handler = main_logger.handlers[0]
            assert isinstance(console_handler, logging.StreamHandler)
    
    def test_file_handler_configuration(self):
        """Test file handler configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"
            
            with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
                # Mock settings with file logging
                mock_settings = MagicMock()
                mock_settings.logging.log_level = "INFO"
                mock_settings.logging.console_log_level = "INFO"
                mock_settings.logging.file_log_level = "DEBUG"
                mock_settings.logging.enable_color_logging = False
                mock_settings.logging.enable_structured_logging = False
                mock_settings.logging.log_file = log_file
                mock_settings.logging.max_log_size_mb = 10
                mock_settings.logging.log_backup_count = 3
                mock_get_settings.return_value = mock_settings
                
                logger_instance = HawkEyeLogger()
                main_logger = logger_instance.configure()
                
                # Check that both console and file handlers were added
                assert len(main_logger.handlers) >= 2
                
                # Find file handler
                file_handler = None
                for handler in main_logger.handlers:
                    if isinstance(handler, logging.handlers.RotatingFileHandler):
                        file_handler = handler
                        break
                
                assert file_handler is not None
                assert file_handler.baseFilename == str(log_file)
    
    def test_get_logger_with_name(self):
        """Test getting logger with specific name."""
        logger_instance = HawkEyeLogger()
        named_logger = logger_instance.get_logger("test_module")
        
        assert named_logger.name == "hawkeye.test_module"
        assert logger_instance._configured is True
    
    def test_get_logger_without_name(self):
        """Test getting logger without specific name."""
        logger_instance = HawkEyeLogger()
        main_logger = logger_instance.get_logger()
        
        assert main_logger.name == "hawkeye"
        assert logger_instance._configured is True
    
    def test_configuration_error_handling(self):
        """Test configuration error handling."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            # Mock settings that will cause an error
            mock_get_settings.side_effect = Exception("Configuration error")
            
            logger_instance = HawkEyeLogger()
            
            with pytest.raises(ConfigurationError):
                logger_instance.configure()


class TestAuditLogger:
    """Test cases for AuditLogger class."""
    
    def test_audit_logger_initialization(self):
        """Test audit logger initialization."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = True
            mock_get_settings.return_value = mock_settings
            
            with patch('pathlib.Path.mkdir'):
                audit_logger = AuditLogger()
                
                assert audit_logger.settings is not None
                assert audit_logger.logger.name == "hawkeye.audit"
    
    def test_audit_logger_disabled(self):
        """Test audit logger when audit trail is disabled."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = False
            mock_get_settings.return_value = mock_settings
            
            audit_logger = AuditLogger()
            
            # Should not configure file handler when audit trail is disabled
            assert len(audit_logger.logger.handlers) == 0
    
    def test_log_scan_start(self):
        """Test logging scan start event."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = False  # Disable file handler for test
            mock_get_settings.return_value = mock_settings
            
            audit_logger = AuditLogger()
            
            with patch.object(audit_logger.logger, 'info') as mock_info:
                audit_logger.log_scan_start("192.168.1.0/24", "test_user")
                
                mock_info.assert_called_once()
                call_args = mock_info.call_args
                assert "Scan operation started" in call_args[0][0]
                assert call_args[1]['extra']['action'] == "scan_start"
                assert call_args[1]['extra']['target'] == "192.168.1.0/24"
                assert call_args[1]['extra']['user'] == "test_user"
    
    def test_log_scan_complete(self):
        """Test logging scan completion event."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = False
            mock_get_settings.return_value = mock_settings
            
            audit_logger = AuditLogger()
            
            with patch.object(audit_logger.logger, 'info') as mock_info:
                audit_logger.log_scan_complete("192.168.1.100", 5, "test_user")
                
                mock_info.assert_called_once()
                call_args = mock_info.call_args
                assert "5 findings" in call_args[0][0]
                assert call_args[1]['extra']['action'] == "scan_complete"
                assert call_args[1]['extra']['result'] == "completed_5_findings"
    
    def test_log_detection_event(self):
        """Test logging MCP detection event."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = False
            mock_get_settings.return_value = mock_settings
            
            audit_logger = AuditLogger()
            
            with patch.object(audit_logger.logger, 'info') as mock_info:
                audit_logger.log_detection_event("192.168.1.100", "mcp-server", "test_user")
                
                mock_info.assert_called_once()
                call_args = mock_info.call_args
                assert "MCP service detected: mcp-server" in call_args[0][0]
                assert call_args[1]['extra']['action'] == "mcp_detection"
                assert call_args[1]['extra']['result'] == "detected_mcp-server"
    
    def test_log_security_event(self):
        """Test logging security event."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = False
            mock_get_settings.return_value = mock_settings
            
            audit_logger = AuditLogger()
            
            with patch.object(audit_logger.logger, 'warning') as mock_warning:
                audit_logger.log_security_event("unauthorized_access", "Attempted scan without authorization")
                
                mock_warning.assert_called_once()
                call_args = mock_warning.call_args
                assert "Security event: unauthorized_access" in call_args[0][0]
                assert call_args[1]['extra']['action'] == "security_event"
                assert call_args[1]['extra']['result'] == "flagged"


class TestGlobalFunctions:
    """Test cases for global logging functions."""
    
    def test_get_logger_function(self):
        """Test get_logger global function."""
        logger = get_logger("test_module")
        
        assert logger.name == "hawkeye.test_module"
        assert isinstance(logger, logging.Logger)
    
    def test_get_logger_without_name(self):
        """Test get_logger without name parameter."""
        logger = get_logger()
        
        assert logger.name == "hawkeye"
        assert isinstance(logger, logging.Logger)
    
    def test_get_audit_logger_function(self):
        """Test get_audit_logger global function."""
        with patch('hawkeye.utils.logging.get_settings') as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.audit_trail = False
            mock_get_settings.return_value = mock_settings
            
            audit_logger = get_audit_logger()
            
            assert isinstance(audit_logger, AuditLogger)
            assert audit_logger.logger.name == "hawkeye.audit"
    
    def test_configure_logging_function(self):
        """Test configure_logging global function."""
        logger = configure_logging()
        
        assert logger.name == "hawkeye"
        assert isinstance(logger, logging.Logger)
    
    def test_singleton_behavior(self):
        """Test that global functions return singleton instances."""
        logger1 = get_logger()
        logger2 = get_logger()
        
        # Should be the same logger instance
        assert logger1 is logger2
        
        audit1 = get_audit_logger()
        audit2 = get_audit_logger()
        
        # Should be the same audit logger instance
        assert audit1 is audit2


class TestLoggingIntegration:
    """Integration tests for logging system."""
    
    def test_complete_logging_setup(self):
        """Test complete logging setup with file and console handlers."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "hawkeye.log"
            
            # Create custom settings
            logging_settings = LoggingSettings(
                log_level="DEBUG",
                console_log_level="INFO",
                file_log_level="DEBUG",
                log_file=log_file,
                enable_color_logging=True,
                enable_structured_logging=False
            )
            
            settings = HawkEyeSettings(logging=logging_settings)
            
            with patch('hawkeye.utils.logging.get_settings', return_value=settings):
                logger = configure_logging()
                
                # Test logging at different levels
                logger.debug("Debug message")
                logger.info("Info message")
                logger.warning("Warning message")
                logger.error("Error message")
                
                # Check that log file was created
                assert log_file.exists()
                
                # Read log file content
                log_content = log_file.read_text()
                assert "Debug message" in log_content
                assert "Info message" in log_content
                assert "Warning message" in log_content
                assert "Error message" in log_content
    
    def test_structured_logging_format(self):
        """Test structured logging format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "structured.log"
            
            logging_settings = LoggingSettings(
                log_level="INFO",
                file_log_level="INFO",
                log_file=log_file,
                enable_structured_logging=True
            )
            
            settings = HawkEyeSettings(logging=logging_settings)
            
            with patch('hawkeye.utils.logging.get_settings', return_value=settings):
                logger = configure_logging()
                logger.info("Test structured message")
                
                # Check that log file contains JSON-like structure
                log_content = log_file.read_text()
                assert '"timestamp"' in log_content
                assert '"level"' in log_content
                assert '"message"' in log_content
    
    def test_audit_trail_integration(self):
        """Test audit trail integration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock the audit log path
            with patch('hawkeye.utils.logging.Path') as mock_path:
                mock_audit_file = MagicMock()
                mock_audit_file.parent.mkdir = MagicMock()
                mock_path.return_value = mock_audit_file
                
                settings = HawkEyeSettings(audit_trail=True)
                
                with patch('hawkeye.utils.logging.get_settings', return_value=settings):
                    audit_logger = get_audit_logger()
                    
                    # Test audit logging
                    audit_logger.log_scan_start("192.168.1.0/24")
                    audit_logger.log_detection_event("192.168.1.100", "mcp-server")
                    audit_logger.log_security_event("test_event", "Test details")
                    
                    # Verify audit file setup was attempted
                    mock_audit_file.parent.mkdir.assert_called_once()
    
    def test_logging_with_different_levels(self):
        """Test logging behavior with different log levels."""
        test_cases = [
            ("DEBUG", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
            ("INFO", ["INFO", "WARNING", "ERROR", "CRITICAL"]),
            ("WARNING", ["WARNING", "ERROR", "CRITICAL"]),
            ("ERROR", ["ERROR", "CRITICAL"]),
            ("CRITICAL", ["CRITICAL"])
        ]
        
        for log_level, expected_levels in test_cases:
            with tempfile.TemporaryDirectory() as temp_dir:
                log_file = Path(temp_dir) / f"test_{log_level.lower()}.log"
                
                logging_settings = LoggingSettings(
                    log_level=log_level,
                    file_log_level=log_level,
                    log_file=log_file,
                    enable_structured_logging=False
                )
                
                settings = HawkEyeSettings(logging=logging_settings)
                
                with patch('hawkeye.utils.logging.get_settings', return_value=settings):
                    # Clear any existing handlers
                    logging.getLogger("hawkeye").handlers.clear()
                    
                    logger = configure_logging()
                    
                    # Log messages at all levels
                    logger.debug("Debug message")
                    logger.info("Info message")
                    logger.warning("Warning message")
                    logger.error("Error message")
                    logger.critical("Critical message")
                    
                    # Check log file content
                    if log_file.exists():
                        log_content = log_file.read_text()
                        
                        # Check that only expected levels are logged
                        for level in expected_levels:
                            assert f"{level.title()} message" in log_content
                        
                        # Check that lower levels are not logged
                        all_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
                        for level in all_levels:
                            if level not in expected_levels:
                                assert f"{level.title()} message" not in log_content 