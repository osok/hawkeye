"""
Configuration file support for HawkEye CLI.

This module provides configuration file loading, validation, and management
for CLI operations with support for multiple formats and environment overrides.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
import json
import yaml
import toml
from dataclasses import asdict

import click
from pydantic import ValidationError

from ..config import HawkEyeSettings, get_settings
from ..exceptions import ConfigurationError
from ..utils import get_logger

logger = get_logger(__name__)


class ConfigFileManager:
    """Manager for configuration file operations."""
    
    SUPPORTED_FORMATS = {
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.toml': 'toml',
        '.ini': 'ini'
    }
    
    DEFAULT_CONFIG_NAMES = [
        'hawkeye.json',
        'hawkeye.yaml',
        'hawkeye.yml',
        'hawkeye.toml',
        '.hawkeye.json',
        '.hawkeye.yaml',
        '.hawkeye.yml',
        '.hawkeye.toml'
    ]
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
    def find_config_file(self, start_path: Optional[Path] = None) -> Optional[Path]:
        """
        Find configuration file by searching up the directory tree.
        
        Args:
            start_path: Starting directory for search (default: current directory)
            
        Returns:
            Path to configuration file if found, None otherwise
        """
        if start_path is None:
            start_path = Path.cwd()
        
        current_path = start_path.resolve()
        
        # Search up the directory tree
        while current_path != current_path.parent:
            for config_name in self.DEFAULT_CONFIG_NAMES:
                config_path = current_path / config_name
                if config_path.exists() and config_path.is_file():
                    self.logger.debug(f"Found config file: {config_path}")
                    return config_path
            
            current_path = current_path.parent
        
        # Check user home directory
        home_path = Path.home()
        for config_name in self.DEFAULT_CONFIG_NAMES:
            config_path = home_path / config_name
            if config_path.exists() and config_path.is_file():
                self.logger.debug(f"Found config file in home: {config_path}")
                return config_path
        
        return None
    
    def load_config_file(self, config_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
            
        Raises:
            ConfigurationError: If file cannot be loaded or parsed
        """
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        
        if not config_path.is_file():
            raise ConfigurationError(f"Configuration path is not a file: {config_path}")
        
        # Determine file format
        file_format = self.SUPPORTED_FORMATS.get(config_path.suffix.lower())
        if not file_format:
            raise ConfigurationError(f"Unsupported configuration file format: {config_path.suffix}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if file_format == 'json':
                config_data = json.loads(content)
            elif file_format == 'yaml':
                config_data = yaml.safe_load(content)
            elif file_format == 'toml':
                config_data = toml.loads(content)
            elif file_format == 'ini':
                import configparser
                parser = configparser.ConfigParser()
                parser.read_string(content)
                config_data = {section: dict(parser[section]) for section in parser.sections()}
            else:
                raise ConfigurationError(f"Unsupported format: {file_format}")
            
            self.logger.info(f"Loaded configuration from {config_path}")
            return config_data
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in {config_path}: {e}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {config_path}: {e}")
        except toml.TomlDecodeError as e:
            raise ConfigurationError(f"Invalid TOML in {config_path}: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading {config_path}: {e}")
    
    def save_config_file(self, config_data: Dict[str, Any], config_path: Union[str, Path], 
                        format: Optional[str] = None) -> None:
        """
        Save configuration to file.
        
        Args:
            config_data: Configuration dictionary to save
            config_path: Path where to save configuration
            format: File format (auto-detected from extension if not provided)
            
        Raises:
            ConfigurationError: If file cannot be saved
        """
        config_path = Path(config_path)
        
        # Determine file format
        if format is None:
            format = self.SUPPORTED_FORMATS.get(config_path.suffix.lower())
            if not format:
                raise ConfigurationError(f"Cannot determine format for: {config_path}")
        
        # Ensure parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                if format == 'json':
                    json.dump(config_data, f, indent=2, default=str)
                elif format == 'yaml':
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
                elif format == 'toml':
                    toml.dump(config_data, f)
                elif format == 'ini':
                    import configparser
                    parser = configparser.ConfigParser()
                    for section, values in config_data.items():
                        parser[section] = values
                    parser.write(f)
                else:
                    raise ConfigurationError(f"Unsupported format: {format}")
            
            self.logger.info(f"Saved configuration to {config_path}")
            
        except Exception as e:
            raise ConfigurationError(f"Error saving configuration to {config_path}: {e}")
    
    def validate_config(self, config_data: Dict[str, Any]) -> HawkEyeSettings:
        """
        Validate configuration data against settings schema.
        
        Args:
            config_data: Configuration dictionary to validate
            
        Returns:
            Validated HawkEyeSettings instance
            
        Raises:
            ConfigurationError: If validation fails
        """
        try:
            # Create settings instance from config data
            settings = HawkEyeSettings(**config_data)
            return settings
        except ValidationError as e:
            error_details = []
            for error in e.errors():
                field = '.'.join(str(x) for x in error['loc'])
                message = error['msg']
                error_details.append(f"{field}: {message}")
            
            raise ConfigurationError(f"Configuration validation failed:\n" + '\n'.join(error_details))
        except Exception as e:
            raise ConfigurationError(f"Configuration validation error: {e}")
    
    def merge_configs(self, base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two configuration dictionaries with override precedence.
        
        Args:
            base_config: Base configuration dictionary
            override_config: Override configuration dictionary
            
        Returns:
            Merged configuration dictionary
        """
        merged = base_config.copy()
        
        for key, value in override_config.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                merged[key] = self.merge_configs(merged[key], value)
            else:
                # Override value
                merged[key] = value
        
        return merged
    
    def apply_environment_overrides(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply environment variable overrides to configuration.
        
        Environment variables should be prefixed with HAWKEYE_ and use
        double underscores for nested keys (e.g., HAWKEYE_SCAN__MAX_THREADS).
        
        Args:
            config_data: Base configuration dictionary
            
        Returns:
            Configuration with environment overrides applied
        """
        env_overrides = {}
        
        for env_key, env_value in os.environ.items():
            if env_key.startswith('HAWKEYE_'):
                # Remove prefix and convert to lowercase
                config_key = env_key[8:].lower()
                
                # Handle nested keys (double underscore separator)
                key_parts = config_key.split('__')
                
                # Convert environment value to appropriate type
                value = self._convert_env_value(env_value)
                
                # Build nested dictionary structure
                current_dict = env_overrides
                for part in key_parts[:-1]:
                    if part not in current_dict:
                        current_dict[part] = {}
                    current_dict = current_dict[part]
                
                current_dict[key_parts[-1]] = value
        
        if env_overrides:
            self.logger.debug(f"Applying environment overrides: {env_overrides}")
            config_data = self.merge_configs(config_data, env_overrides)
        
        return config_data
    
    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate Python type."""
        # Boolean values
        if value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif value.lower() in ('false', 'no', '0', 'off'):
            return False
        
        # Numeric values
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
        
        # List values (comma-separated)
        if ',' in value:
            return [item.strip() for item in value.split(',')]
        
        # String value
        return value
    
    def create_default_config(self) -> Dict[str, Any]:
        """Create default configuration dictionary."""
        settings = HawkEyeSettings()
        return asdict(settings)
    
    def generate_config_template(self, format: str = 'yaml') -> str:
        """
        Generate configuration file template.
        
        Args:
            format: Output format (json, yaml, toml)
            
        Returns:
            Configuration template as string
        """
        default_config = self.create_default_config()
        
        if format == 'json':
            return json.dumps(default_config, indent=2, default=str)
        elif format == 'yaml':
            return yaml.dump(default_config, default_flow_style=False, indent=2)
        elif format == 'toml':
            return toml.dumps(default_config)
        else:
            raise ValueError(f"Unsupported template format: {format}")


def load_config_from_file(config_path: Optional[str] = None) -> HawkEyeSettings:
    """
    Load and validate configuration from file.
    
    Args:
        config_path: Path to configuration file (auto-discovered if None)
        
    Returns:
        Validated HawkEyeSettings instance
        
    Raises:
        ConfigurationError: If configuration cannot be loaded or is invalid
    """
    manager = ConfigFileManager()
    
    if config_path:
        config_file = Path(config_path)
        if not config_file.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
    else:
        config_file = manager.find_config_file()
        if not config_file:
            # No config file found, use defaults
            logger.debug("No configuration file found, using defaults")
            return get_settings()
    
    # Load configuration
    config_data = manager.load_config_file(config_file)
    
    # Apply environment overrides
    config_data = manager.apply_environment_overrides(config_data)
    
    # Validate and return settings
    return manager.validate_config(config_data)


def save_current_config(config_path: str, format: Optional[str] = None) -> None:
    """
    Save current configuration to file.
    
    Args:
        config_path: Path where to save configuration
        format: File format (auto-detected if None)
    """
    manager = ConfigFileManager()
    settings = get_settings()
    config_data = asdict(settings)
    manager.save_config_file(config_data, config_path, format)


# Click parameter types for configuration
class ConfigFileType(click.ParamType):
    """Click parameter type for configuration files."""
    
    name = "config_file"
    
    def convert(self, value, param, ctx):
        if value is None:
            return None
        
        config_path = Path(value)
        if not config_path.exists():
            self.fail(f"Configuration file '{value}' does not exist.", param, ctx)
        
        if not config_path.is_file():
            self.fail(f"'{value}' is not a file.", param, ctx)
        
        # Validate file format
        manager = ConfigFileManager()
        if config_path.suffix.lower() not in manager.SUPPORTED_FORMATS:
            self.fail(f"Unsupported configuration file format: {config_path.suffix}", param, ctx)
        
        return str(config_path)


# Click commands for configuration management
@click.group()
def config():
    """Configuration file management commands."""
    pass


@config.command()
@click.option(
    '--output', '-o',
    type=click.Path(),
    default='hawkeye.yaml',
    help='Output file path (default: hawkeye.yaml)'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['json', 'yaml', 'toml']),
    default='yaml',
    help='Output format (default: yaml)'
)
@click.option(
    '--overwrite/--no-overwrite',
    default=False,
    help='Overwrite existing file'
)
def init(output: str, format: str, overwrite: bool):
    """Initialize a new configuration file with default values."""
    output_path = Path(output)
    
    if output_path.exists() and not overwrite:
        click.echo(f"Configuration file '{output}' already exists. Use --overwrite to replace it.")
        return
    
    try:
        manager = ConfigFileManager()
        template = manager.generate_config_template(format)
        
        with open(output_path, 'w') as f:
            f.write(template)
        
        click.echo(f"Configuration template created: {output}")
        click.echo(f"Edit the file to customize your HawkEye settings.")
        
    except Exception as e:
        click.echo(f"Error creating configuration file: {e}", err=True)
        sys.exit(1)


@config.command()
@click.option(
    '--config-file', '-c',
    type=ConfigFileType(),
    help='Configuration file to validate'
)
def validate(config_file: Optional[str]):
    """Validate configuration file."""
    try:
        if config_file:
            settings = load_config_from_file(config_file)
            click.echo(f"✅ Configuration file '{config_file}' is valid.")
        else:
            # Try to find and validate auto-discovered config
            manager = ConfigFileManager()
            found_config = manager.find_config_file()
            if found_config:
                settings = load_config_from_file(str(found_config))
                click.echo(f"✅ Configuration file '{found_config}' is valid.")
            else:
                click.echo("ℹ️  No configuration file found. Using default settings.")
        
    except ConfigurationError as e:
        click.echo(f"❌ Configuration validation failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error validating configuration: {e}", err=True)
        sys.exit(1)


@config.command()
@click.option(
    '--config-file', '-c',
    type=ConfigFileType(),
    help='Configuration file to show'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['json', 'yaml', 'table']),
    default='table',
    help='Output format (default: table)'
)
def show(config_file: Optional[str], format: str):
    """Show current configuration."""
    try:
        if config_file:
            settings = load_config_from_file(config_file)
            source = config_file
        else:
            manager = ConfigFileManager()
            found_config = manager.find_config_file()
            if found_config:
                settings = load_config_from_file(str(found_config))
                source = str(found_config)
            else:
                settings = get_settings()
                source = "defaults"
        
        config_data = asdict(settings)
        
        if format == 'json':
            click.echo(json.dumps(config_data, indent=2, default=str))
        elif format == 'yaml':
            click.echo(yaml.dump(config_data, default_flow_style=False, indent=2))
        elif format == 'table':
            click.echo(f"Configuration source: {source}")
            click.echo()
            _print_config_table(config_data)
        
    except Exception as e:
        click.echo(f"Error showing configuration: {e}", err=True)
        sys.exit(1)


def _print_config_table(config_data: Dict[str, Any], prefix: str = ""):
    """Print configuration as a formatted table."""
    for key, value in config_data.items():
        full_key = f"{prefix}.{key}" if prefix else key
        
        if isinstance(value, dict):
            click.echo(f"{full_key}:")
            _print_config_table(value, full_key)
        else:
            click.echo(f"  {full_key}: {value}")


# Global configuration manager instance
config_manager = ConfigFileManager()