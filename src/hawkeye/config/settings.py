"""
Configuration settings for HawkEye security reconnaissance tool.

This module provides centralized configuration management using Pydantic BaseSettings
for environment-based configuration with validation and type safety.
"""

import logging
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class ScanSettings(BaseSettings):
    """Configuration for network scanning operations."""
    
    # Threading and performance
    max_threads: int = Field(default=50, ge=1, le=1000, description="Maximum number of concurrent threads")
    timeout_seconds: int = Field(default=5, ge=1, le=300, description="Network operation timeout in seconds")
    retry_attempts: int = Field(default=3, ge=0, le=10, description="Number of retry attempts for failed connections")
    rate_limit_requests: int = Field(default=100, ge=1, le=10000, description="Rate limit for requests per second")
    
    # Port scanning configuration
    default_ports: List[int] = Field(default=[3000, 8000, 8080, 9000], description="Default MCP ports to scan")
    port_range_start: int = Field(default=1, ge=1, le=65535, description="Start of port range")
    port_range_end: int = Field(default=65535, ge=1, le=65535, description="End of port range")
    
    # Protocol settings
    enable_tcp_scan: bool = Field(default=True, description="Enable TCP port scanning")
    enable_udp_scan: bool = Field(default=False, description="Enable UDP port scanning")
    enable_ipv6: bool = Field(default=False, description="Enable IPv6 support")
    
    @validator('port_range_end')
    def validate_port_range(cls, v, values):
        if 'port_range_start' in values and v < values['port_range_start']:
            raise ValueError('port_range_end must be greater than or equal to port_range_start')
        return v

    class Config:
        env_prefix = "HAWKEYE_SCAN_"


class DetectionSettings(BaseSettings):
    """Configuration for MCP detection operations."""
    
    # Process detection
    enable_process_enum: bool = Field(default=True, description="Enable Node.js process enumeration")
    enable_config_discovery: bool = Field(default=True, description="Enable configuration file discovery")
    enable_docker_inspect: bool = Field(default=True, description="Enable Docker container inspection")
    
    # Protocol verification
    enable_handshake_verify: bool = Field(default=True, description="Enable MCP handshake verification")
    handshake_timeout: int = Field(default=10, ge=1, le=60, description="MCP handshake timeout in seconds")
    
    # File system scanning
    max_depth: int = Field(default=3, ge=1, le=10, description="Maximum directory depth for file discovery")
    config_file_patterns: List[str] = Field(
        default=["package.json", "mcp.json", "*.mcp.json", ".mcprc"],
        description="Patterns for MCP configuration files"
    )

    class Config:
        env_prefix = "HAWKEYE_DETECT_"


class AssessmentSettings(BaseSettings):
    """Configuration for risk assessment operations."""
    
    # Risk scoring
    enable_cvss_scoring: bool = Field(default=True, description="Enable CVSS-based risk scoring")
    risk_threshold: float = Field(default=5.0, ge=0.0, le=10.0, description="Minimum risk score to report")
    
    # Security checks
    check_default_configs: bool = Field(default=True, description="Check for default configurations")
    check_weak_auth: bool = Field(default=True, description="Check for weak authentication")
    check_transport_security: bool = Field(default=True, description="Check transport layer security")
    check_public_access: bool = Field(default=True, description="Check for public accessibility")

    class Config:
        env_prefix = "HAWKEYE_ASSESS_"


class ReportingSettings(BaseSettings):
    """Configuration for reporting and output operations."""
    
    # Output formats
    default_format: str = Field(default="json", pattern="^(json|csv|xml|html)$", description="Default output format")
    enable_executive_summary: bool = Field(default=True, description="Include executive summary in reports")
    
    # File output
    output_directory: Path = Field(default=Path("./reports"), description="Directory for output files")
    timestamp_files: bool = Field(default=True, description="Add timestamps to output filenames")
    
    # Report content
    include_raw_data: bool = Field(default=False, description="Include raw scan data in reports")
    max_findings_per_report: int = Field(default=1000, ge=1, le=10000, description="Maximum findings per report")

    class Config:
        env_prefix = "HAWKEYE_REPORT_"


class LoggingSettings(BaseSettings):
    """Configuration for logging operations."""
    
    # Log levels
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$", description="Logging level")
    console_log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$", description="Console logging level")
    file_log_level: str = Field(default="DEBUG", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$", description="File logging level")
    
    # Log files
    log_file: Optional[Path] = Field(default=None, description="Log file path")
    max_log_size_mb: int = Field(default=100, ge=1, le=1000, description="Maximum log file size in MB")
    log_backup_count: int = Field(default=5, ge=1, le=50, description="Number of log backup files to keep")
    
    # Log format
    enable_structured_logging: bool = Field(default=True, description="Enable structured JSON logging")
    enable_color_logging: bool = Field(default=True, description="Enable colored console logging")

    class Config:
        env_prefix = "HAWKEYE_LOG_"


class HawkEyeSettings(BaseSettings):
    """Main configuration class for HawkEye application."""
    
    # Application metadata
    app_name: str = Field(default="HawkEye", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # Component settings
    scan: ScanSettings = Field(default_factory=ScanSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    assessment: AssessmentSettings = Field(default_factory=AssessmentSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    
    # Security settings
    require_authorization: bool = Field(default=True, description="Require explicit authorization for scanning")
    audit_trail: bool = Field(default=True, description="Enable comprehensive audit trail")
    
    class Config:
        env_prefix = "HAWKEYE_"
        case_sensitive = False
        env_nested_delimiter = "__"


@lru_cache()
def get_settings() -> HawkEyeSettings:
    """
    Get application settings with caching.
    
    Returns:
        HawkEyeSettings: Cached application settings instance
    """
    return HawkEyeSettings() 