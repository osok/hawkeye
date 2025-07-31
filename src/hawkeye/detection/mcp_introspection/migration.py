"""
Configuration Migration Tools for MCP Introspection System

This module provides tools to migrate from the old Node.js script generation
approach to the new Python-based MCP introspection system.
"""

import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from ...config.settings import HawkEyeSettings
from .models import MCPServerInfo, MCPCapabilities, MCPTool, MCPResource


logger = logging.getLogger(__name__)


class MigrationConfig(BaseModel):
    """Configuration for migration process"""
    
    backup_enabled: bool = Field(default=True, description="Create backup of old configuration")
    backup_directory: str = Field(default="backups", description="Directory for configuration backups")
    validate_migration: bool = Field(default=True, description="Validate migrated configuration")
    preserve_old_config: bool = Field(default=True, description="Keep old configuration files")
    migration_log_level: str = Field(default="INFO", description="Logging level for migration")


class LegacyMCPConfig(BaseModel):
    """Legacy MCP configuration structure"""
    
    servers: List[Dict[str, Any]] = Field(default_factory=list)
    nodejs_script_path: Optional[str] = None
    timeout_seconds: int = 30
    max_retries: int = 3
    enable_introspection: bool = True


class MigrationResult(BaseModel):
    """Result of configuration migration"""
    
    success: bool
    migrated_servers: int
    failed_servers: int
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    backup_path: Optional[str] = None
    migration_timestamp: datetime = Field(default_factory=datetime.now)


class ConfigurationMigrator:
    """Handles migration from legacy Node.js-based configuration to Python-based system"""
    
    def __init__(self, config: Optional[MigrationConfig] = None):
        """Initialize the configuration migrator
        
        Args:
            config: Migration configuration options
        """
        self.config = config or MigrationConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Set migration-specific log level
        if self.config.migration_log_level:
            self.logger.setLevel(getattr(logging, self.config.migration_log_level.upper()))
    
    def migrate_configuration(
        self,
        legacy_config_path: str,
        output_config_path: Optional[str] = None
    ) -> MigrationResult:
        """Migrate legacy configuration to new format
        
        Args:
            legacy_config_path: Path to legacy configuration file
            output_config_path: Path for new configuration (optional)
            
        Returns:
            Migration result with status and details
        """
        result = MigrationResult(success=False, migrated_servers=0, failed_servers=0)
        
        try:
            # Create backup if enabled
            if self.config.backup_enabled:
                result.backup_path = self._create_backup(legacy_config_path)
                self.logger.info(f"Created backup at: {result.backup_path}")
            
            # Load legacy configuration
            legacy_config = self._load_legacy_config(legacy_config_path)
            if not legacy_config:
                result.errors.append("Failed to load legacy configuration")
                return result
            
            # Migrate configuration
            migrated_config = self._migrate_config_structure(legacy_config, result)
            
            # Validate migration if enabled
            if self.config.validate_migration:
                validation_errors = self._validate_migrated_config(migrated_config)
                if validation_errors:
                    result.errors.extend(validation_errors)
                    result.warnings.append("Migration validation failed")
            
            # Save migrated configuration
            if output_config_path:
                self._save_migrated_config(migrated_config, output_config_path)
                self.logger.info(f"Saved migrated configuration to: {output_config_path}")
            
            result.success = len(result.errors) == 0
            
            # Log migration summary
            self._log_migration_summary(result)
            
        except Exception as e:
            self.logger.error(f"Migration failed: {e}")
            result.errors.append(f"Migration exception: {str(e)}")
        
        return result
    
    def _create_backup(self, config_path: str) -> str:
        """Create backup of legacy configuration
        
        Args:
            config_path: Path to configuration file to backup
            
        Returns:
            Path to backup file
        """
        # Create backup directory
        backup_dir = Path(self.config.backup_directory)
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate backup filename with timestamp
        config_file = Path(config_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{config_file.stem}_backup_{timestamp}{config_file.suffix}"
        backup_path = backup_dir / backup_filename
        
        # Copy configuration file
        shutil.copy2(config_path, backup_path)
        
        return str(backup_path)
    
    def _load_legacy_config(self, config_path: str) -> Optional[LegacyMCPConfig]:
        """Load legacy configuration file
        
        Args:
            config_path: Path to legacy configuration
            
        Returns:
            Parsed legacy configuration or None if failed
        """
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.json'):
                    data = json.load(f)
                elif config_path.endswith(('.yml', '.yaml')):
                    import yaml
                    data = yaml.safe_load(f)
                else:
                    # Try JSON first, then YAML
                    content = f.read()
                    try:
                        data = json.loads(content)
                    except json.JSONDecodeError:
                        import yaml
                        data = yaml.safe_load(content)
            
            return LegacyMCPConfig(**data)
            
        except Exception as e:
            self.logger.error(f"Failed to load legacy config from {config_path}: {e}")
            return None
    
    def _migrate_config_structure(
        self,
        legacy_config: LegacyMCPConfig,
        result: MigrationResult
    ) -> Dict[str, Any]:
        """Migrate configuration structure from legacy to new format
        
        Args:
            legacy_config: Legacy configuration object
            result: Migration result to update
            
        Returns:
            Migrated configuration dictionary
        """
        migrated = {
            "mcp_introspection": {
                "enabled": legacy_config.enable_introspection,
                "timeout_seconds": legacy_config.timeout_seconds,
                "max_retries": legacy_config.max_retries,
                "use_python_client": True,  # New Python-based approach
                "servers": []
            }
        }
        
        # Migrate server configurations
        for server_config in legacy_config.servers:
            try:
                migrated_server = self._migrate_server_config(server_config)
                migrated["mcp_introspection"]["servers"].append(migrated_server)
                result.migrated_servers += 1
                
            except Exception as e:
                self.logger.warning(f"Failed to migrate server config: {e}")
                result.failed_servers += 1
                result.warnings.append(f"Failed to migrate server: {str(e)}")
        
        # Add new Python-specific settings
        migrated["mcp_introspection"].update({
            "transport": {
                "stdio": {
                    "timeout": 30,
                    "buffer_size": 8192
                },
                "sse": {
                    "timeout": 60,
                    "max_retries": 3
                },
                "http": {
                    "timeout": 45,
                    "max_connections": 10
                }
            },
            "discovery": {
                "cache_ttl": 300,
                "enable_tool_discovery": True,
                "enable_resource_discovery": True,
                "enable_capability_assessment": True
            },
            "risk_analysis": {
                "enabled": True,
                "scoring_method": "weighted_average",
                "risk_policies": {
                    "file_system_access": "medium",
                    "network_access": "high",
                    "code_execution": "critical"
                }
            }
        })
        
        return migrated
    
    def _migrate_server_config(self, server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate individual server configuration
        
        Args:
            server_config: Legacy server configuration
            
        Returns:
            Migrated server configuration
        """
        migrated_server = {
            "name": server_config.get("name", "unknown"),
            "command": server_config.get("command", ""),
            "args": server_config.get("args", []),
            "transport_type": self._detect_transport_type(server_config),
            "enabled": server_config.get("enabled", True)
        }
        
        # Migrate transport-specific settings
        if "stdio" in server_config:
            migrated_server["stdio_config"] = server_config["stdio"]
        
        if "sse" in server_config:
            migrated_server["sse_config"] = server_config["sse"]
        
        if "http" in server_config:
            migrated_server["http_config"] = server_config["http"]
        
        # Migrate environment variables
        if "env" in server_config:
            migrated_server["env"] = server_config["env"]
        
        # Migrate working directory
        if "cwd" in server_config:
            migrated_server["working_directory"] = server_config["cwd"]
        
        return migrated_server
    
    def _detect_transport_type(self, server_config: Dict[str, Any]) -> str:
        """Detect transport type from legacy configuration
        
        Args:
            server_config: Legacy server configuration
            
        Returns:
            Detected transport type
        """
        # Check for explicit transport type
        if "transport" in server_config:
            return server_config["transport"]
        
        # Infer from configuration structure
        if "stdio" in server_config or server_config.get("command"):
            return "stdio"
        elif "sse" in server_config or "url" in server_config:
            return "sse"
        elif "http" in server_config:
            return "http"
        else:
            return "stdio"  # Default fallback
    
    def _validate_migrated_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate migrated configuration
        
        Args:
            config: Migrated configuration
            
        Returns:
            List of validation errors
        """
        errors = []
        
        try:
            # Validate structure
            if "mcp_introspection" not in config:
                errors.append("Missing mcp_introspection section")
                return errors
            
            mcp_config = config["mcp_introspection"]
            
            # Validate required fields
            required_fields = ["enabled", "timeout_seconds", "servers"]
            for field in required_fields:
                if field not in mcp_config:
                    errors.append(f"Missing required field: {field}")
            
            # Validate servers
            if "servers" in mcp_config:
                for i, server in enumerate(mcp_config["servers"]):
                    server_errors = self._validate_server_config(server, i)
                    errors.extend(server_errors)
            
            # Validate transport configuration
            if "transport" in mcp_config:
                transport_errors = self._validate_transport_config(mcp_config["transport"])
                errors.extend(transport_errors)
            
        except Exception as e:
            errors.append(f"Validation exception: {str(e)}")
        
        return errors
    
    def _validate_server_config(self, server: Dict[str, Any], index: int) -> List[str]:
        """Validate individual server configuration
        
        Args:
            server: Server configuration
            index: Server index for error reporting
            
        Returns:
            List of validation errors for this server
        """
        errors = []
        
        # Required fields
        required_fields = ["name", "transport_type"]
        for field in required_fields:
            if field not in server:
                errors.append(f"Server {index}: Missing required field '{field}'")
        
        # Validate transport type
        valid_transports = ["stdio", "sse", "http"]
        if "transport_type" in server and server["transport_type"] not in valid_transports:
            errors.append(f"Server {index}: Invalid transport type '{server['transport_type']}'")
        
        # Validate command for stdio transport
        if server.get("transport_type") == "stdio" and not server.get("command"):
            errors.append(f"Server {index}: stdio transport requires 'command' field")
        
        return errors
    
    def _validate_transport_config(self, transport: Dict[str, Any]) -> List[str]:
        """Validate transport configuration
        
        Args:
            transport: Transport configuration
            
        Returns:
            List of validation errors
        """
        errors = []
        
        # Validate transport types
        valid_transports = ["stdio", "sse", "http"]
        for transport_type in transport:
            if transport_type not in valid_transports:
                errors.append(f"Invalid transport type: {transport_type}")
        
        return errors
    
    def _save_migrated_config(self, config: Dict[str, Any], output_path: str) -> None:
        """Save migrated configuration to file
        
        Args:
            config: Migrated configuration
            output_path: Path to save configuration
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            if output_path.endswith('.json'):
                json.dump(config, f, indent=2)
            elif output_path.endswith(('.yml', '.yaml')):
                import yaml
                yaml.dump(config, f, default_flow_style=False, indent=2)
            else:
                # Default to JSON
                json.dump(config, f, indent=2)
    
    def _log_migration_summary(self, result: MigrationResult) -> None:
        """Log migration summary
        
        Args:
            result: Migration result to summarize
        """
        self.logger.info("=== Migration Summary ===")
        self.logger.info(f"Success: {result.success}")
        self.logger.info(f"Migrated servers: {result.migrated_servers}")
        self.logger.info(f"Failed servers: {result.failed_servers}")
        self.logger.info(f"Warnings: {len(result.warnings)}")
        self.logger.info(f"Errors: {len(result.errors)}")
        
        if result.backup_path:
            self.logger.info(f"Backup created: {result.backup_path}")
        
        if result.warnings:
            self.logger.warning("Migration warnings:")
            for warning in result.warnings:
                self.logger.warning(f"  - {warning}")
        
        if result.errors:
            self.logger.error("Migration errors:")
            for error in result.errors:
                self.logger.error(f"  - {error}")


class ConfigurationValidator:
    """Validates MCP introspection configurations"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def validate_configuration(self, config_path: str) -> Tuple[bool, List[str]]:
        """Validate MCP introspection configuration
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        try:
            # Load configuration
            with open(config_path, 'r') as f:
                if config_path.endswith('.json'):
                    config = json.load(f)
                elif config_path.endswith(('.yml', '.yaml')):
                    import yaml
                    config = yaml.safe_load(f)
                else:
                    errors.append("Unsupported configuration file format")
                    return False, errors
            
            # Validate structure
            validation_errors = self._validate_config_structure(config)
            errors.extend(validation_errors)
            
            # Validate server configurations
            if "mcp_introspection" in config and "servers" in config["mcp_introspection"]:
                for i, server in enumerate(config["mcp_introspection"]["servers"]):
                    server_errors = self._validate_server_configuration(server, i)
                    errors.extend(server_errors)
            
        except Exception as e:
            errors.append(f"Configuration validation failed: {str(e)}")
        
        return len(errors) == 0, errors
    
    def _validate_config_structure(self, config: Dict[str, Any]) -> List[str]:
        """Validate overall configuration structure
        
        Args:
            config: Configuration dictionary
            
        Returns:
            List of validation errors
        """
        errors = []
        
        if "mcp_introspection" not in config:
            errors.append("Missing 'mcp_introspection' section")
            return errors
        
        mcp_config = config["mcp_introspection"]
        
        # Check required fields
        required_fields = ["enabled", "servers"]
        for field in required_fields:
            if field not in mcp_config:
                errors.append(f"Missing required field: mcp_introspection.{field}")
        
        # Validate field types
        if "enabled" in mcp_config and not isinstance(mcp_config["enabled"], bool):
            errors.append("mcp_introspection.enabled must be boolean")
        
        if "servers" in mcp_config and not isinstance(mcp_config["servers"], list):
            errors.append("mcp_introspection.servers must be a list")
        
        return errors
    
    def _validate_server_configuration(self, server: Dict[str, Any], index: int) -> List[str]:
        """Validate individual server configuration
        
        Args:
            server: Server configuration
            index: Server index for error reporting
            
        Returns:
            List of validation errors
        """
        errors = []
        
        # Required fields
        required_fields = ["name", "transport_type"]
        for field in required_fields:
            if field not in server:
                errors.append(f"Server {index}: Missing required field '{field}'")
        
        # Validate transport type
        valid_transports = ["stdio", "sse", "http"]
        if "transport_type" in server:
            if server["transport_type"] not in valid_transports:
                errors.append(f"Server {index}: Invalid transport type '{server['transport_type']}'")
            
            # Transport-specific validation
            if server["transport_type"] == "stdio":
                if not server.get("command"):
                    errors.append(f"Server {index}: stdio transport requires 'command' field")
            elif server["transport_type"] in ["sse", "http"]:
                if not server.get("url"):
                    errors.append(f"Server {index}: {server['transport_type']} transport requires 'url' field")
        
        return errors


def migrate_legacy_configuration(
    legacy_config_path: str,
    output_config_path: Optional[str] = None,
    migration_config: Optional[MigrationConfig] = None
) -> MigrationResult:
    """Convenience function to migrate legacy configuration
    
    Args:
        legacy_config_path: Path to legacy configuration file
        output_config_path: Path for new configuration (optional)
        migration_config: Migration configuration options
        
    Returns:
        Migration result with status and details
    """
    migrator = ConfigurationMigrator(migration_config)
    return migrator.migrate_configuration(legacy_config_path, output_config_path)


def validate_configuration(config_path: str) -> Tuple[bool, List[str]]:
    """Convenience function to validate configuration
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Tuple of (is_valid, error_messages)
    """
    validator = ConfigurationValidator()
    return validator.validate_configuration(config_path)