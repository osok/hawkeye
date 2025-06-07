"""
Main CLI application for HawkEye security reconnaissance tool.

This module defines the primary command-line interface using Click framework
with support for multiple command groups and configuration options.
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from ..config import get_settings
from ..exceptions import HawkEyeError
from ..utils import configure_logging, get_logger
from .. import __version__


# Global console for rich output
console = Console()


class HawkEyeContext:
    """Context object for sharing state between CLI commands."""
    
    def __init__(self):
        self.settings = get_settings()
        self.logger = None
        self.verbose = False
        self.quiet = False
        self.output_file = None
        
    def setup_logging(self, verbose: bool = False, quiet: bool = False, log_file: Optional[str] = None):
        """Setup logging based on CLI options."""
        self.verbose = verbose
        self.quiet = quiet
        
        # Override log settings based on CLI options
        if verbose:
            self.settings.logging.log_level = "DEBUG"
            self.settings.logging.console_log_level = "DEBUG"
        elif quiet:
            self.settings.logging.console_log_level = "ERROR"
        
        if log_file:
            self.settings.logging.log_file = Path(log_file)
        
        self.logger = configure_logging()


# Custom Click group with better error handling
class HawkEyeGroup(click.Group):
    """Custom Click group with enhanced error handling and help formatting."""
    
    def format_help(self, ctx, formatter):
        """Format help with HawkEye branding."""
        formatter.write_heading("🦅 HawkEye - MCP Security Reconnaissance Tool")
        formatter.write_paragraph()
        formatter.write("Hidden Application Weaknesses & Key Entry-point Yielding Evaluator")
        formatter.write_paragraph()
        super().format_help(ctx, formatter)
    
    def invoke(self, ctx):
        """Invoke command with error handling."""
        try:
            return super().invoke(ctx)
        except HawkEyeError as e:
            console.print(f"[red]Error:[/red] {e.message}")
            if e.details and ctx.obj.verbose:
                console.print(f"[yellow]Details:[/yellow] {e.details}")
            sys.exit(1)
        except Exception as e:
            if ctx.obj.verbose:
                console.print_exception()
            else:
                console.print(f"[red]Unexpected error:[/red] {e}")
            sys.exit(1)


@click.group(cls=HawkEyeGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output and debug logging"
)
@click.option(
    "--quiet", "-q", 
    is_flag=True,
    help="Suppress all output except errors"
)
@click.option(
    "--log-file",
    type=click.Path(),
    help="Write logs to specified file"
)
@click.option(
    "--config-file",
    type=click.Path(exists=True),
    help="Load configuration from file"
)
@click.version_option(version=__version__, prog_name="HawkEye")
@click.pass_context
def cli(ctx, verbose: bool, quiet: bool, log_file: Optional[str], config_file: Optional[str]):
    """
    🦅 HawkEye - MCP Security Reconnaissance Tool
    
    Identify and assess Model Context Protocol (MCP) server deployments
    within network infrastructure for security vulnerabilities.
    
    Use 'hawkeye COMMAND --help' for command-specific help.
    """
    # Ensure context object exists
    ctx.ensure_object(HawkEyeContext)
    
    # Setup logging
    ctx.obj.setup_logging(verbose=verbose, quiet=quiet, log_file=log_file)
    
    # Load config file if specified
    if config_file:
        # TODO: Implement config file loading
        pass
    
    # Show banner if not quiet
    if not quiet:
        show_banner()


def show_banner():
    """Display HawkEye banner."""
    banner = """
    🦅 HawkEye v{version}
    Hidden Application Weaknesses & Key Entry-point Yielding Evaluator
    
    Seeing beyond the visible, securing the invisible.
    """.format(version=__version__)
    
    console.print(banner, style="bold blue")


@cli.group()
@click.pass_context
def scan(ctx):
    """Network scanning operations for MCP server discovery."""
    pass


@cli.group()
@click.pass_context  
def detect(ctx):
    """MCP-specific detection and analysis operations."""
    pass


@cli.group()
@click.pass_context
def assess(ctx):
    """Security assessment and risk analysis operations."""
    pass


@cli.group()
@click.pass_context
def report(ctx):
    """Report generation and output formatting operations."""
    pass


@cli.command()
@click.pass_context
def info(ctx):
    """Display system information and configuration."""
    settings = ctx.obj.settings
    
    # Create info table
    table = Table(title="HawkEye Configuration", show_header=True, header_style="bold magenta")
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    # Application info
    table.add_row("Version", __version__)
    table.add_row("Debug Mode", str(settings.debug))
    table.add_row("Audit Trail", str(settings.audit_trail))
    
    # Scan settings
    table.add_row("Max Threads", str(settings.scan.max_threads))
    table.add_row("Default Ports", str(settings.scan.default_ports))
    table.add_row("TCP Scan", str(settings.scan.enable_tcp_scan))
    table.add_row("UDP Scan", str(settings.scan.enable_udp_scan))
    
    # Detection settings
    table.add_row("Process Enumeration", str(settings.detection.enable_process_enum))
    table.add_row("Config Discovery", str(settings.detection.enable_config_discovery))
    table.add_row("Docker Inspection", str(settings.detection.enable_docker_inspect))
    
    # Logging settings
    table.add_row("Log Level", settings.logging.log_level)
    table.add_row("Log File", str(settings.logging.log_file) if settings.logging.log_file else "None")
    
    console.print(table)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target IP address, CIDR range, or hostname"
)
@click.option(
    "--ports", "-p",
    help="Port range (e.g., 1-1000) or comma-separated ports"
)
@click.option(
    "--threads",
    type=int,
    help="Number of concurrent threads"
)
@click.option(
    "--timeout",
    type=int,
    help="Connection timeout in seconds"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml", "html"]),
    default="json",
    help="Output format"
)
@click.pass_context
def quick_scan(ctx, target: str, ports: Optional[str], threads: Optional[int], 
               timeout: Optional[int], output: Optional[str], format: str):
    """
    Perform a quick scan of the target for MCP services.
    
    This command combines network scanning, MCP detection, and basic
    risk assessment in a single operation.
    """
    logger = ctx.obj.logger
    
    if not ctx.obj.quiet:
        console.print(f"[bold green]Starting quick scan of {target}[/bold green]")
    
    logger.info(f"Quick scan initiated for target: {target}")
    
    # TODO: Implement quick scan logic
    console.print("[yellow]Quick scan functionality not yet implemented[/yellow]")
    
    if output:
        console.print(f"[blue]Results would be saved to: {output}[/blue]")


if __name__ == "__main__":
    cli() 