"""
Output control and verbosity management for HawkEye CLI.

This module provides centralized control over output verbosity levels,
quiet mode handling, and logging configuration for CLI operations.
"""

import sys
import logging
from typing import Optional, Dict, Any
from enum import Enum
from contextlib import contextmanager

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text
from rich.panel import Panel

from ..utils import get_logger


class VerbosityLevel(Enum):
    """Verbosity levels for CLI output."""
    QUIET = 0      # Only errors
    NORMAL = 1     # Normal output
    VERBOSE = 2    # Detailed output
    DEBUG = 3      # Debug information


class OutputController:
    """Centralized output control for HawkEye CLI."""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.verbosity = VerbosityLevel.NORMAL
        self.quiet_mode = False
        self.debug_mode = False
        self.log_file = None
        self.logger = get_logger(__name__)
        
    def set_verbosity(self, level: VerbosityLevel):
        """Set the verbosity level."""
        self.verbosity = level
        self.quiet_mode = (level == VerbosityLevel.QUIET)
        self.debug_mode = (level == VerbosityLevel.DEBUG)
        
        # Update logging configuration
        self._configure_logging()
    
    def set_quiet_mode(self, quiet: bool):
        """Enable or disable quiet mode."""
        self.quiet_mode = quiet
        if quiet:
            self.verbosity = VerbosityLevel.QUIET
        self._configure_logging()
    
    def set_debug_mode(self, debug: bool):
        """Enable or disable debug mode."""
        self.debug_mode = debug
        if debug:
            self.verbosity = VerbosityLevel.DEBUG
        self._configure_logging()
    
    def set_log_file(self, log_file: Optional[str]):
        """Set log file path."""
        self.log_file = log_file
        self._configure_logging()
    
    def _configure_logging(self):
        """Configure logging based on current settings."""
        # Determine log level
        if self.debug_mode:
            log_level = logging.DEBUG
        elif self.verbosity == VerbosityLevel.VERBOSE:
            log_level = logging.INFO
        elif self.quiet_mode:
            log_level = logging.ERROR
        else:
            log_level = logging.WARNING
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Console handler
        if not self.quiet_mode:
            console_handler = RichHandler(
                console=self.console,
                show_time=self.debug_mode,
                show_path=self.debug_mode,
                rich_tracebacks=True
            )
            console_handler.setLevel(log_level)
            root_logger.addHandler(console_handler)
        
        # File handler
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)  # Always debug level for file
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    
    def print(self, *args, **kwargs):
        """Print with verbosity control."""
        if not self.quiet_mode:
            self.console.print(*args, **kwargs)
    
    def print_verbose(self, *args, **kwargs):
        """Print only in verbose mode."""
        if self.verbosity.value >= VerbosityLevel.VERBOSE.value:
            self.console.print(*args, **kwargs)
    
    def print_debug(self, *args, **kwargs):
        """Print only in debug mode."""
        if self.debug_mode:
            self.console.print(*args, **kwargs)
    
    def print_error(self, *args, **kwargs):
        """Print errors (always shown unless completely silent)."""
        self.console.print(*args, **kwargs, style="red")
    
    def print_warning(self, *args, **kwargs):
        """Print warnings (shown in normal and verbose modes)."""
        if not self.quiet_mode:
            self.console.print(*args, **kwargs, style="yellow")
    
    def print_success(self, *args, **kwargs):
        """Print success messages."""
        if not self.quiet_mode:
            self.console.print(*args, **kwargs, style="green")
    
    def print_info(self, *args, **kwargs):
        """Print informational messages."""
        if self.verbosity.value >= VerbosityLevel.NORMAL.value:
            self.console.print(*args, **kwargs, style="blue")
    
    def print_banner(self, title: str, subtitle: Optional[str] = None):
        """Print application banner."""
        if self.quiet_mode:
            return
        
        banner_text = f"🦅 {title}"
        if subtitle:
            banner_text += f"\n{subtitle}"
        
        panel = Panel(
            Text(banner_text, style="bold blue", justify="center"),
            style="blue",
            padding=(1, 2)
        )
        self.console.print(panel)
    
    def print_section_header(self, title: str):
        """Print section header."""
        if self.quiet_mode:
            return
        
        self.console.print(f"\n[bold blue]{title}[/bold blue]")
        self.console.print("─" * len(title), style="blue")
    
    def print_operation_start(self, operation: str, details: Optional[str] = None):
        """Print operation start message."""
        if self.quiet_mode:
            return
        
        message = f"🚀 Starting {operation}"
        if details:
            message += f": {details}"
        
        self.console.print(message, style="bold green")
    
    def print_operation_complete(self, operation: str, duration: Optional[float] = None):
        """Print operation completion message."""
        if self.quiet_mode:
            return
        
        message = f"✅ {operation} completed"
        if duration:
            message += f" in {duration:.2f}s"
        
        self.console.print(message, style="bold green")
    
    def print_operation_failed(self, operation: str, error: str):
        """Print operation failure message."""
        message = f"❌ {operation} failed: {error}"
        self.console.print(message, style="bold red")
    
    def print_progress_update(self, message: str, current: int, total: int):
        """Print progress update in verbose mode."""
        if self.verbosity.value >= VerbosityLevel.VERBOSE.value:
            percentage = (current / total) * 100 if total > 0 else 0
            self.console.print(f"📊 {message} ({current}/{total} - {percentage:.1f}%)", style="dim")
    
    def print_debug_info(self, category: str, data: Dict[str, Any]):
        """Print debug information."""
        if not self.debug_mode:
            return
        
        self.console.print(f"\n[bold yellow]DEBUG - {category}:[/bold yellow]")
        for key, value in data.items():
            self.console.print(f"  {key}: {value}", style="dim")
    
    def print_statistics(self, title: str, stats: Dict[str, Any]):
        """Print statistics summary."""
        if self.quiet_mode:
            return
        
        self.console.print(f"\n[bold magenta]📈 {title}[/bold magenta]")
        for key, value in stats.items():
            self.console.print(f"  • {key}: {value}")
    
    @contextmanager
    def capture_output(self):
        """Context manager to capture output for processing."""
        if self.quiet_mode:
            # In quiet mode, capture everything
            original_console = self.console
            self.console = Console(file=sys.stderr, quiet=True)
            try:
                yield
            finally:
                self.console = original_console
        else:
            yield
    
    @contextmanager
    def temporary_verbosity(self, level: VerbosityLevel):
        """Temporarily change verbosity level."""
        original_level = self.verbosity
        original_quiet = self.quiet_mode
        original_debug = self.debug_mode
        
        self.set_verbosity(level)
        try:
            yield
        finally:
            self.verbosity = original_level
            self.quiet_mode = original_quiet
            self.debug_mode = original_debug
            self._configure_logging()
    
    def format_duration(self, seconds: float) -> str:
        """Format duration for display."""
        if seconds < 60:
            return f"{seconds:.2f}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = seconds % 60
            return f"{minutes}m {secs:.1f}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            secs = seconds % 60
            return f"{hours}h {minutes}m {secs:.0f}s"
    
    def format_size(self, bytes_count: int) -> str:
        """Format byte count for display."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    def format_rate(self, count: int, duration: float, unit: str = "items") -> str:
        """Format rate for display."""
        if duration <= 0:
            return f"0 {unit}/s"
        
        rate = count / duration
        if rate < 1:
            return f"{rate:.2f} {unit}/s"
        elif rate < 100:
            return f"{rate:.1f} {unit}/s"
        else:
            return f"{rate:.0f} {unit}/s"


class QuietMode:
    """Context manager for temporary quiet mode."""
    
    def __init__(self, output_controller: OutputController):
        self.output_controller = output_controller
        self.original_quiet = output_controller.quiet_mode
    
    def __enter__(self):
        self.output_controller.set_quiet_mode(True)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.output_controller.set_quiet_mode(self.original_quiet)


class VerboseMode:
    """Context manager for temporary verbose mode."""
    
    def __init__(self, output_controller: OutputController):
        self.output_controller = output_controller
        self.original_verbosity = output_controller.verbosity
    
    def __enter__(self):
        self.output_controller.set_verbosity(VerbosityLevel.VERBOSE)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.output_controller.set_verbosity(self.original_verbosity)


class DebugMode:
    """Context manager for temporary debug mode."""
    
    def __init__(self, output_controller: OutputController):
        self.output_controller = output_controller
        self.original_debug = output_controller.debug_mode
    
    def __enter__(self):
        self.output_controller.set_debug_mode(True)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.output_controller.set_debug_mode(self.original_debug)


# Global output controller instance
output_controller = OutputController()


def configure_output(verbosity: VerbosityLevel, quiet: bool = False, 
                    debug: bool = False, log_file: Optional[str] = None):
    """Configure global output settings."""
    global output_controller
    
    if quiet:
        output_controller.set_quiet_mode(True)
    elif debug:
        output_controller.set_debug_mode(True)
    else:
        output_controller.set_verbosity(verbosity)
    
    if log_file:
        output_controller.set_log_file(log_file)


def get_output_controller() -> OutputController:
    """Get the global output controller instance."""
    return output_controller


# Convenience functions for common output operations
def print_banner(title: str, subtitle: Optional[str] = None):
    """Print application banner."""
    output_controller.print_banner(title, subtitle)


def print_section_header(title: str):
    """Print section header."""
    output_controller.print_section_header(title)


def print_operation_start(operation: str, details: Optional[str] = None):
    """Print operation start message."""
    output_controller.print_operation_start(operation, details)


def print_operation_complete(operation: str, duration: Optional[float] = None):
    """Print operation completion message."""
    output_controller.print_operation_complete(operation, duration)


def print_operation_failed(operation: str, error: str):
    """Print operation failure message."""
    output_controller.print_operation_failed(operation, error)


def print_statistics(title: str, stats: Dict[str, Any]):
    """Print statistics summary."""
    output_controller.print_statistics(title, stats)


def print_debug_info(category: str, data: Dict[str, Any]):
    """Print debug information."""
    output_controller.print_debug_info(category, data)