"""
Unit tests for HawkEye configuration settings.

Tests for Pydantic BaseSettings classes, validation, and environment variable handling.
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from hawkeye.config.settings import (
    AssessmentSettings,
    DetectionSettings,
    HawkEyeSettings,
    LoggingSettings,
    ReportingSettings,
    ScanSettings,
    get_settings,
)


class TestScanSettings:
    """Test cases for ScanSettings configuration."""
    
    def test_default_values(self):
        """Test default configuration values."""
        settings = ScanSettings()
        
        assert settings.max_threads == 50
        assert settings.timeout_seconds == 5
        assert settings.retry_attempts == 3
        assert settings.rate_limit_requests == 100
        assert settings.default_ports == [3000, 8000, 8080, 9000]
        assert settings.port_range_start == 1
        assert settings.port_range_end == 65535
        assert settings.enable_tcp_scan is True
        assert settings.enable_udp_scan is False
        assert settings.enable_ipv6 is False
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict(os.environ, {
            'HAWKEYE_SCAN_MAX_THREADS': '100',
            'HAWKEYE_SCAN_TIMEOUT_SECONDS': '10',
            'HAWKEYE_SCAN_ENABLE_UDP_SCAN': 'true'
        }):
            settings = ScanSettings()
            
            assert settings.max_threads == 100
            assert settings.timeout_seconds == 10
            assert settings.enable_udp_scan is True
    
    def test_validation_constraints(self):
        """Test field validation constraints."""
        # Test max_threads constraints
        with pytest.raises(ValidationError):
            ScanSettings(max_threads=0)  # Below minimum
        
        with pytest.raises(ValidationError):
            ScanSettings(max_threads=1001)  # Above maximum
        
        # Test timeout constraints
        with pytest.raises(ValidationError):
            ScanSettings(timeout_seconds=0)  # Below minimum
        
        with pytest.raises(ValidationError):
            ScanSettings(timeout_seconds=301)  # Above maximum
    
    def test_port_range_validation(self):
        """Test port range validation."""
        # Valid port range
        settings = ScanSettings(port_range_start=1000, port_range_end=2000)
        assert settings.port_range_start == 1000
        assert settings.port_range_end == 2000
        
        # Invalid port range (end < start)
        with pytest.raises(ValidationError):
            ScanSettings(port_range_start=2000, port_range_end=1000)


class TestDetectionSettings:
    """Test cases for DetectionSettings configuration."""
    
    def test_default_values(self):
        """Test default configuration values."""
        settings = DetectionSettings()
        
        assert settings.enable_process_enum is True
        assert settings.enable_config_discovery is True
        assert settings.enable_docker_inspect is True
        assert settings.enable_handshake_verify is True
        assert settings.handshake_timeout == 10
        assert settings.max_depth == 3
        assert "package.json" in settings.config_file_patterns
        assert "mcp.json" in settings.config_file_patterns
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict(os.environ, {
            'HAWKEYE_DETECT_ENABLE_PROCESS_ENUM': 'false',
            'HAWKEYE_DETECT_HANDSHAKE_TIMEOUT': '30',
            'HAWKEYE_DETECT_MAX_DEPTH': '5'
        }):
            settings = DetectionSettings()
            
            assert settings.enable_process_enum is False
            assert settings.handshake_timeout == 30
            assert settings.max_depth == 5
    
    def test_validation_constraints(self):
        """Test field validation constraints."""
        # Test handshake_timeout constraints
        with pytest.raises(ValidationError):
            DetectionSettings(handshake_timeout=0)  # Below minimum
        
        with pytest.raises(ValidationError):
            DetectionSettings(handshake_timeout=61)  # Above maximum
        
        # Test max_depth constraints
        with pytest.raises(ValidationError):
            DetectionSettings(max_depth=0)  # Below minimum
        
        with pytest.raises(ValidationError):
            DetectionSettings(max_depth=11)  # Above maximum


class TestAssessmentSettings:
    """Test cases for AssessmentSettings configuration."""
    
    def test_default_values(self):
        """Test default configuration values."""
        settings = AssessmentSettings()
        
        assert settings.enable_cvss_scoring is True
        assert settings.risk_threshold == 5.0
        assert settings.check_default_configs is True
        assert settings.check_weak_auth is True
        assert settings.check_transport_security is True
        assert settings.check_public_access is True
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict(os.environ, {
            'HAWKEYE_ASSESS_ENABLE_CVSS_SCORING': 'false',
            'HAWKEYE_ASSESS_RISK_THRESHOLD': '7.5',
            'HAWKEYE_ASSESS_CHECK_WEAK_AUTH': 'false'
        }):
            settings = AssessmentSettings()
            
            assert settings.enable_cvss_scoring is False
            assert settings.risk_threshold == 7.5
            assert settings.check_weak_auth is False
    
    def test_validation_constraints(self):
        """Test field validation constraints."""
        # Test risk_threshold constraints
        with pytest.raises(ValidationError):
            AssessmentSettings(risk_threshold=-0.1)  # Below minimum
        
        with pytest.raises(ValidationError):
            AssessmentSettings(risk_threshold=10.1)  # Above maximum


class TestReportingSettings:
    """Test cases for ReportingSettings configuration."""
    
    def test_default_values(self):
        """Test default configuration values."""
        settings = ReportingSettings()
        
        assert settings.default_format == "json"
        assert settings.enable_executive_summary is True
        assert settings.output_directory == Path("./reports")
        assert settings.timestamp_files is True
        assert settings.include_raw_data is False
        assert settings.max_findings_per_report == 1000
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict(os.environ, {
            'HAWKEYE_REPORT_DEFAULT_FORMAT': 'csv',
            'HAWKEYE_REPORT_OUTPUT_DIRECTORY': '/tmp/reports',
            'HAWKEYE_REPORT_INCLUDE_RAW_DATA': 'true'
        }):
            settings = ReportingSettings()
            
            assert settings.default_format == "csv"
            assert settings.output_directory == Path("/tmp/reports")
            assert settings.include_raw_data is True
    
    def test_validation_constraints(self):
        """Test field validation constraints."""
        # Test default_format validation
        with pytest.raises(ValidationError):
            ReportingSettings(default_format="invalid")
        
        # Valid formats should work
        for format_type in ["json", "csv", "xml", "html"]:
            settings = ReportingSettings(default_format=format_type)
            assert settings.default_format == format_type
        
        # Test max_findings_per_report constraints
        with pytest.raises(ValidationError):
            ReportingSettings(max_findings_per_report=0)  # Below minimum
        
        with pytest.raises(ValidationError):
            ReportingSettings(max_findings_per_report=10001)  # Above maximum


class TestLoggingSettings:
    """Test cases for LoggingSettings configuration."""
    
    def test_default_values(self):
        """Test default configuration values."""
        settings = LoggingSettings()
        
        assert settings.log_level == "INFO"
        assert settings.console_log_level == "INFO"
        assert settings.file_log_level == "DEBUG"
        assert settings.log_file is None
        assert settings.max_log_size_mb == 100
        assert settings.log_backup_count == 5
        assert settings.enable_structured_logging is True
        assert settings.enable_color_logging is True
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict(os.environ, {
            'HAWKEYE_LOG_LOG_LEVEL': 'DEBUG',
            'HAWKEYE_LOG_LOG_FILE': '/tmp/hawkeye.log',
            'HAWKEYE_LOG_ENABLE_COLOR_LOGGING': 'false'
        }):
            settings = LoggingSettings()
            
            assert settings.log_level == "DEBUG"
            assert settings.log_file == Path("/tmp/hawkeye.log")
            assert settings.enable_color_logging is False
    
    def test_validation_constraints(self):
        """Test field validation constraints."""
        # Test log level validation
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in valid_levels:
            settings = LoggingSettings(log_level=level)
            assert settings.log_level == level
        
        # Invalid log level
        with pytest.raises(ValidationError):
            LoggingSettings(log_level="INVALID")
        
        # Test size constraints
        with pytest.raises(ValidationError):
            LoggingSettings(max_log_size_mb=0)  # Below minimum
        
        with pytest.raises(ValidationError):
            LoggingSettings(max_log_size_mb=1001)  # Above maximum


class TestHawkEyeSettings:
    """Test cases for main HawkEyeSettings configuration."""
    
    def test_default_values(self):
        """Test default configuration values."""
        settings = HawkEyeSettings()
        
        assert settings.app_name == "HawkEye"
        assert settings.app_version == "0.1.0"
        assert settings.debug is False
        assert settings.require_authorization is True
        assert settings.audit_trail is True
        
        # Test nested settings
        assert isinstance(settings.scan, ScanSettings)
        assert isinstance(settings.detection, DetectionSettings)
        assert isinstance(settings.assessment, AssessmentSettings)
        assert isinstance(settings.reporting, ReportingSettings)
        assert isinstance(settings.logging, LoggingSettings)
    
    def test_environment_variable_override(self):
        """Test environment variable configuration override."""
        with patch.dict(os.environ, {
            'HAWKEYE_DEBUG': 'true',
            'HAWKEYE_REQUIRE_AUTHORIZATION': 'false',
            'HAWKEYE_SCAN__MAX_THREADS': '200',  # Nested setting
            'HAWKEYE_LOGGING__LOG_LEVEL': 'ERROR'  # Nested setting
        }):
            settings = HawkEyeSettings()
            
            assert settings.debug is True
            assert settings.require_authorization is False
            assert settings.scan.max_threads == 200
            assert settings.logging.log_level == "ERROR"
    
    def test_nested_settings_independence(self):
        """Test that nested settings can be configured independently."""
        settings = HawkEyeSettings()
        
        # Modify nested settings
        settings.scan.max_threads = 100
        settings.logging.log_level = "DEBUG"
        
        assert settings.scan.max_threads == 100
        assert settings.logging.log_level == "DEBUG"
        
        # Other settings should remain default
        assert settings.detection.enable_process_enum is True
        assert settings.assessment.risk_threshold == 5.0


class TestGetSettings:
    """Test cases for get_settings function."""
    
    def test_singleton_behavior(self):
        """Test that get_settings returns the same instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        
        assert settings1 is settings2
    
    def test_caching_with_environment_changes(self):
        """Test that settings are cached even with environment changes."""
        # Get initial settings
        settings1 = get_settings()
        initial_threads = settings1.scan.max_threads
        
        # Change environment variable
        with patch.dict(os.environ, {'HAWKEYE_SCAN_MAX_THREADS': '999'}):
            settings2 = get_settings()
            
            # Should return cached instance, not new one with env var
            assert settings2 is settings1
            assert settings2.scan.max_threads == initial_threads
    
    def test_settings_type(self):
        """Test that get_settings returns correct type."""
        settings = get_settings()
        assert isinstance(settings, HawkEyeSettings)


class TestConfigurationIntegration:
    """Integration tests for configuration system."""
    
    def test_complete_configuration_from_environment(self):
        """Test complete configuration from environment variables."""
        env_vars = {
            'HAWKEYE_DEBUG': 'true',
            'HAWKEYE_SCAN__MAX_THREADS': '75',
            'HAWKEYE_SCAN__ENABLE_UDP_SCAN': 'true',
            'HAWKEYE_DETECT__HANDSHAKE_TIMEOUT': '20',
            'HAWKEYE_ASSESS__RISK_THRESHOLD': '6.5',
            'HAWKEYE_REPORT__DEFAULT_FORMAT': 'html',
            'HAWKEYE_LOG__LOG_LEVEL': 'WARNING'
        }
        
        with patch.dict(os.environ, env_vars):
            settings = HawkEyeSettings()
            
            assert settings.debug is True
            assert settings.scan.max_threads == 75
            assert settings.scan.enable_udp_scan is True
            assert settings.detection.handshake_timeout == 20
            assert settings.assessment.risk_threshold == 6.5
            assert settings.reporting.default_format == "html"
            assert settings.logging.log_level == "WARNING"
    
    def test_partial_configuration_override(self):
        """Test partial configuration override with defaults."""
        with patch.dict(os.environ, {
            'HAWKEYE_SCAN__MAX_THREADS': '25',
            'HAWKEYE_LOG__LOG_LEVEL': 'ERROR'
        }):
            settings = HawkEyeSettings()
            
            # Overridden values
            assert settings.scan.max_threads == 25
            assert settings.logging.log_level == "ERROR"
            
            # Default values should remain
            assert settings.scan.timeout_seconds == 5
            assert settings.detection.enable_process_enum is True
            assert settings.assessment.risk_threshold == 5.0
    
    def test_configuration_validation_errors(self):
        """Test that invalid configuration raises appropriate errors."""
        with patch.dict(os.environ, {
            'HAWKEYE_SCAN__MAX_THREADS': 'invalid_number'
        }):
            with pytest.raises(ValidationError):
                HawkEyeSettings()
        
        with patch.dict(os.environ, {
            'HAWKEYE_REPORT__DEFAULT_FORMAT': 'invalid_format'
        }):
            with pytest.raises(ValidationError):
                HawkEyeSettings() 