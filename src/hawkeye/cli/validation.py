"""
Input validation and error handling for HawkEye CLI.

This module provides comprehensive input validation, error handling, and
user-friendly error messages for CLI operations.
"""

import re
import ipaddress
from pathlib import Path
from typing import Optional, List, Union, Tuple, Any
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..exceptions import HawkEyeError, ValidationError
from ..utils import get_logger

logger = get_logger(__name__)
console = Console()


class InputValidator:
    """Comprehensive input validation for HawkEye CLI."""
    
    # Regular expressions for validation
    HOSTNAME_REGEX = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
    )
    
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    PORT_RANGE_REGEX = re.compile(
        r'^(\d+)(?:-(\d+))?$'
    )
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def validate_ip_address(self, ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """
        Validate IP address string.
        
        Args:
            ip_str: IP address string to validate
            
        Returns:
            IPv4Address or IPv6Address object
            
        Raises:
            ValidationError: If IP address is invalid
        """
        try:
            return ipaddress.ip_address(ip_str.strip())
        except ValueError as e:
            raise ValidationError(f"Invalid IP address '{ip_str}': {e}")
    
    def validate_network(self, network_str: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """
        Validate network CIDR string.
        
        Args:
            network_str: Network CIDR string to validate
            
        Returns:
            IPv4Network or IPv6Network object
            
        Raises:
            ValidationError: If network is invalid
        """
        try:
            return ipaddress.ip_network(network_str.strip(), strict=False)
        except ValueError as e:
            raise ValidationError(f"Invalid network '{network_str}': {e}")
    
    def validate_hostname(self, hostname: str) -> str:
        """
        Validate hostname string.
        
        Args:
            hostname: Hostname string to validate
            
        Returns:
            Validated hostname
            
        Raises:
            ValidationError: If hostname is invalid
        """
        hostname = hostname.strip().lower()
        
        if not hostname:
            raise ValidationError("Hostname cannot be empty")
        
        if len(hostname) > 253:
            raise ValidationError("Hostname too long (max 253 characters)")
        
        # Check if it's an IP address (which is valid)
        try:
            ipaddress.ip_address(hostname)
            return hostname
        except ValueError:
            pass
        
        # Validate as domain name
        if not self.DOMAIN_REGEX.match(hostname):
            raise ValidationError(f"Invalid hostname format: {hostname}")
        
        return hostname
    
    def validate_target(self, target: str) -> Tuple[str, str]:
        """
        Validate target specification (IP, network, or hostname).
        
        Args:
            target: Target string to validate
            
        Returns:
            Tuple of (validated_target, target_type)
            
        Raises:
            ValidationError: If target is invalid
        """
        target = target.strip()
        
        if not target:
            raise ValidationError("Target cannot be empty")
        
        # Try IP address
        try:
            validated_ip = self.validate_ip_address(target)
            return str(validated_ip), "ip"
        except ValidationError:
            pass
        
        # Try network CIDR
        try:
            validated_network = self.validate_network(target)
            return str(validated_network), "network"
        except ValidationError:
            pass
        
        # Try hostname
        try:
            validated_hostname = self.validate_hostname(target)
            return validated_hostname, "hostname"
        except ValidationError:
            pass
        
        raise ValidationError(f"Invalid target specification: {target}")
    
    def validate_port(self, port: Union[str, int]) -> int:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            
        Returns:
            Validated port number
            
        Raises:
            ValidationError: If port is invalid
        """
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid port number: {port}")
        
        if port_num < 1 or port_num > 65535:
            raise ValidationError(f"Port number out of range (1-65535): {port_num}")
        
        return port_num
    
    def validate_port_range(self, port_range: str) -> List[int]:
        """
        Validate and parse port range specification.
        
        Args:
            port_range: Port range string (e.g., "80", "80-443", "80,443,8080")
            
        Returns:
            List of validated port numbers
            
        Raises:
            ValidationError: If port range is invalid
        """
        if not port_range:
            raise ValidationError("Port range cannot be empty")
        
        ports = []
        
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                # Port range (e.g., "80-443")
                match = self.PORT_RANGE_REGEX.match(part)
                if not match:
                    raise ValidationError(f"Invalid port range format: {part}")
                
                start_port = self.validate_port(match.group(1))
                end_port = self.validate_port(match.group(2))
                
                if start_port > end_port:
                    raise ValidationError(f"Invalid port range (start > end): {part}")
                
                if end_port - start_port > 10000:
                    raise ValidationError(f"Port range too large (max 10000 ports): {part}")
                
                ports.extend(range(start_port, end_port + 1))
            else:
                # Single port
                port = self.validate_port(part)
                ports.append(port)
        
        if not ports:
            raise ValidationError("No valid ports specified")
        
        if len(ports) > 10000:
            raise ValidationError("Too many ports specified (max 10000)")
        
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def validate_file_path(self, file_path: str, must_exist: bool = False, 
                          must_be_file: bool = True, must_be_readable: bool = True) -> Path:
        """
        Validate file path.
        
        Args:
            file_path: File path to validate
            must_exist: Whether file must exist
            must_be_file: Whether path must be a file (not directory)
            must_be_readable: Whether file must be readable
            
        Returns:
            Validated Path object
            
        Raises:
            ValidationError: If file path is invalid
        """
        if not file_path:
            raise ValidationError("File path cannot be empty")
        
        path = Path(file_path).expanduser().resolve()
        
        if must_exist and not path.exists():
            raise ValidationError(f"File does not exist: {path}")
        
        if path.exists():
            if must_be_file and not path.is_file():
                raise ValidationError(f"Path is not a file: {path}")
            
            if must_be_readable and not os.access(path, os.R_OK):
                raise ValidationError(f"File is not readable: {path}")
        
        return path
    
    def validate_directory_path(self, dir_path: str, must_exist: bool = False,
                               must_be_writable: bool = False) -> Path:
        """
        Validate directory path.
        
        Args:
            dir_path: Directory path to validate
            must_exist: Whether directory must exist
            must_be_writable: Whether directory must be writable
            
        Returns:
            Validated Path object
            
        Raises:
            ValidationError: If directory path is invalid
        """
        if not dir_path:
            raise ValidationError("Directory path cannot be empty")
        
        path = Path(dir_path).expanduser().resolve()
        
        if must_exist and not path.exists():
            raise ValidationError(f"Directory does not exist: {path}")
        
        if path.exists() and not path.is_dir():
            raise ValidationError(f"Path is not a directory: {path}")
        
        if must_be_writable and path.exists() and not os.access(path, os.W_OK):
            raise ValidationError(f"Directory is not writable: {path}")
        
        return path
    
    def validate_url(self, url: str) -> str:
        """
        Validate URL string.
        
        Args:
            url: URL string to validate
            
        Returns:
            Validated URL
            
        Raises:
            ValidationError: If URL is invalid
        """
        if not url:
            raise ValidationError("URL cannot be empty")
        
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                raise ValidationError("URL must include scheme (http/https)")
            
            if parsed.scheme not in ['http', 'https']:
                raise ValidationError("URL scheme must be http or https")
            
            if not parsed.netloc:
                raise ValidationError("URL must include hostname")
            
            return url
            
        except Exception as e:
            raise ValidationError(f"Invalid URL: {e}")
    
    def validate_timeout(self, timeout: Union[str, int, float]) -> float:
        """
        Validate timeout value.
        
        Args:
            timeout: Timeout value to validate
            
        Returns:
            Validated timeout in seconds
            
        Raises:
            ValidationError: If timeout is invalid
        """
        try:
            timeout_val = float(timeout)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid timeout value: {timeout}")
        
        if timeout_val <= 0:
            raise ValidationError("Timeout must be positive")
        
        if timeout_val > 3600:  # 1 hour max
            raise ValidationError("Timeout too large (max 3600 seconds)")
        
        return timeout_val
    
    def validate_thread_count(self, threads: Union[str, int]) -> int:
        """
        Validate thread count.
        
        Args:
            threads: Thread count to validate
            
        Returns:
            Validated thread count
            
        Raises:
            ValidationError: If thread count is invalid
        """
        try:
            thread_count = int(threads)
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid thread count: {threads}")
        
        if thread_count < 1:
            raise ValidationError("Thread count must be at least 1")
        
        if thread_count > 1000:
            raise ValidationError("Thread count too large (max 1000)")
        
        return thread_count
    
    def validate_output_format(self, format_str: str, supported_formats: List[str]) -> str:
        """
        Validate output format.
        
        Args:
            format_str: Format string to validate
            supported_formats: List of supported formats
            
        Returns:
            Validated format string
            
        Raises:
            ValidationError: If format is invalid
        """
        if not format_str:
            raise ValidationError("Output format cannot be empty")
        
        format_lower = format_str.lower().strip()
        
        if format_lower not in [f.lower() for f in supported_formats]:
            raise ValidationError(
                f"Unsupported output format '{format_str}'. "
                f"Supported formats: {', '.join(supported_formats)}"
            )
        
        return format_lower


class CLIErrorHandler:
    """Enhanced error handling for CLI operations."""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.logger = get_logger(__name__)
    
    def handle_validation_error(self, error: ValidationError, param_name: Optional[str] = None):
        """Handle validation errors with user-friendly messages."""
        if param_name:
            message = f"Invalid {param_name}: {error.message}"
        else:
            message = f"Validation error: {error.message}"
        
        self.console.print(f"[red]❌ {message}[/red]")
        
        # Provide suggestions if available
        if hasattr(error, 'suggestions') and error.suggestions:
            self.console.print("\n[yellow]💡 Suggestions:[/yellow]")
            for suggestion in error.suggestions:
                self.console.print(f"  • {suggestion}")
    
    def handle_configuration_error(self, error: Exception):
        """Handle configuration-related errors."""
        self.console.print(f"[red]❌ Configuration error: {error}[/red]")
        
        self.console.print("\n[yellow]💡 Try:[/yellow]")
        self.console.print("  • Check your configuration file syntax")
        self.console.print("  • Run 'hawkeye config validate' to check configuration")
        self.console.print("  • Run 'hawkeye config init' to create a new configuration")
    
    def handle_network_error(self, error: Exception, target: Optional[str] = None):
        """Handle network-related errors."""
        if target:
            message = f"Network error connecting to {target}: {error}"
        else:
            message = f"Network error: {error}"
        
        self.console.print(f"[red]❌ {message}[/red]")
        
        self.console.print("\n[yellow]💡 Check:[/yellow]")
        self.console.print("  • Network connectivity")
        self.console.print("  • Firewall settings")
        self.console.print("  • Target availability")
        self.console.print("  • DNS resolution")
    
    def handle_permission_error(self, error: Exception, operation: Optional[str] = None):
        """Handle permission-related errors."""
        if operation:
            message = f"Permission denied for {operation}: {error}"
        else:
            message = f"Permission denied: {error}"
        
        self.console.print(f"[red]❌ {message}[/red]")
        
        self.console.print("\n[yellow]💡 Try:[/yellow]")
        self.console.print("  • Running with appropriate privileges")
        self.console.print("  • Checking file/directory permissions")
        self.console.print("  • Using sudo if required (with caution)")
    
    def handle_file_error(self, error: Exception, file_path: Optional[str] = None):
        """Handle file-related errors."""
        if file_path:
            message = f"File error with {file_path}: {error}"
        else:
            message = f"File error: {error}"
        
        self.console.print(f"[red]❌ {message}[/red]")
        
        self.console.print("\n[yellow]💡 Check:[/yellow]")
        self.console.print("  • File exists and is accessible")
        self.console.print("  • File permissions")
        self.console.print("  • Disk space availability")
        self.console.print("  • File format and syntax")
    
    def handle_generic_error(self, error: Exception, operation: Optional[str] = None):
        """Handle generic errors with helpful context."""
        if operation:
            message = f"Error during {operation}: {error}"
        else:
            message = f"Error: {error}"
        
        self.console.print(f"[red]❌ {message}[/red]")
        
        # Show debug information if available
        if hasattr(error, '__cause__') and error.__cause__:
            self.console.print(f"[dim]Caused by: {error.__cause__}[/dim]")
        
        self.console.print("\n[yellow]💡 For more information:[/yellow]")
        self.console.print("  • Run with --verbose for detailed output")
        self.console.print("  • Check log files for additional details")
        self.console.print("  • Verify your configuration and inputs")
    
    def create_error_panel(self, title: str, message: str, suggestions: Optional[List[str]] = None) -> Panel:
        """Create a formatted error panel."""
        content = Text(message, style="red")
        
        if suggestions:
            content.append("\n\n💡 Suggestions:\n", style="yellow")
            for suggestion in suggestions:
                content.append(f"  • {suggestion}\n", style="dim")
        
        return Panel(
            content,
            title=f"❌ {title}",
            border_style="red",
            padding=(1, 2)
        )


# Click parameter types with validation
class ValidatedIPAddress(click.ParamType):
    """Click parameter type for IP addresses."""
    name = "ip_address"
    
    def convert(self, value, param, ctx):
        if value is None:
            return None
        
        validator = InputValidator()
        try:
            return str(validator.validate_ip_address(value))
        except ValidationError as e:
            self.fail(str(e), param, ctx)


class ValidatedTarget(click.ParamType):
    """Click parameter type for target specifications."""
    name = "target"
    
    def convert(self, value, param, ctx):
        if value is None:
            return None
        
        validator = InputValidator()
        try:
            validated_target, target_type = validator.validate_target(value)
            return validated_target
        except ValidationError as e:
            self.fail(str(e), param, ctx)


class ValidatedPortRange(click.ParamType):
    """Click parameter type for port ranges."""
    name = "port_range"
    
    def convert(self, value, param, ctx):
        if value is None:
            return None
        
        validator = InputValidator()
        try:
            return validator.validate_port_range(value)
        except ValidationError as e:
            self.fail(str(e), param, ctx)


class ValidatedTimeout(click.ParamType):
    """Click parameter type for timeout values."""
    name = "timeout"
    
    def convert(self, value, param, ctx):
        if value is None:
            return None
        
        validator = InputValidator()
        try:
            return validator.validate_timeout(value)
        except ValidationError as e:
            self.fail(str(e), param, ctx)


# Global instances
validator = InputValidator()
error_handler = CLIErrorHandler()


def validate_cli_input(func):
    """Decorator for CLI input validation."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValidationError as e:
            error_handler.handle_validation_error(e)
            raise click.Abort()
        except Exception as e:
            error_handler.handle_generic_error(e, func.__name__)
            raise click.Abort()
    
    return wrapper