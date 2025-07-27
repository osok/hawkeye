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

# Import command groups
from .scan_commands import scan
from .detect_commands import detect
from .report_commands import report
from .config_file import config, load_config_from_file
from .output_control import configure_output, VerbosityLevel


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
    
    # Configure output control
    if verbose:
        configure_output(VerbosityLevel.VERBOSE, quiet=quiet, log_file=log_file)
    elif quiet:
        configure_output(VerbosityLevel.QUIET, quiet=quiet, log_file=log_file)
    else:
        configure_output(VerbosityLevel.NORMAL, quiet=quiet, log_file=log_file)
    
    # Load config file if specified
    if config_file:
        try:
            settings = load_config_from_file(config_file)
            ctx.obj.settings = settings
        except Exception as e:
            console.print(f"[red]Error loading config file: {e}[/red]")
            sys.exit(1)
    
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


# Add command groups to main CLI
cli.add_command(scan)
cli.add_command(detect)
cli.add_command(report)
cli.add_command(config)


@cli.group()
@click.pass_context
def assess(ctx):
    """Security assessment and risk analysis operations."""
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
        console.print(f"[bold green]🦅 HawkEye Quick Scan[/bold green]")
        console.print(f"Target: {target}")
    
    logger.info(f"Quick scan initiated for target: {target}")
    
    try:
        # Import required modules
        from ..scanner.tcp_scanner import TCPScanner
        from ..scanner.target_enum import TargetEnumerator
        from ..detection.protocol_verify import ProtocolVerifier
        from ..detection.transport_detect import TransportDetector
        from ..cli.scan_commands import parse_ports
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        from rich.table import Table
        
        # Set defaults
        if ports is None:
            ports = "3000,8000,8080,9000"  # Common MCP ports
        if threads is None:
            threads = 50
        if timeout is None:
            timeout = 5
        
        # Parse ports
        port_list = parse_ports(ports)
        if not port_list:
            port_list = [3000, 8000, 8080, 9000]
        
        console.print(f"Ports: {len(port_list)} ports")
        console.print(f"Threads: {threads}, Timeout: {timeout}s")
        console.print()
        
        # Step 1: Network Scanning
        console.print("[bold blue]Phase 1: Network Scanning[/bold blue]")
        
        # Enumerate targets
        enumerator = TargetEnumerator()
        targets = enumerator.enumerate_targets(target)
        
        # Configure scanner settings
        scan_settings = ctx.obj.settings
        scan_settings.scan.timeout_seconds = timeout
        scan_settings.scan.max_threads = threads
        
        # Perform TCP scan
        tcp_scanner = TCPScanner(settings=scan_settings)
        scan_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Scanning ports...", total=len(targets) * len(port_list))
            
            for target_host in targets:
                from ..scanner.base import ScanTarget
                scan_target = ScanTarget(host=target_host, ports=port_list)
                results = tcp_scanner.scan_target(scan_target)
                scan_results.extend(results)
                progress.advance(task, len(port_list))
        
        # Filter for open ports
        open_ports = [r for r in scan_results if r.state.value == "open"]
        
        if not open_ports:
            console.print("[yellow]No open ports found. Quick scan complete.[/yellow]")
            return
        
        console.print(f"[green]Found {len(open_ports)} open ports[/green]")
        
        # Step 2: MCP Detection
        console.print("\n[bold blue]Phase 2: MCP Detection[/bold blue]")
        
        # Initialize detectors
        protocol_verifier = ProtocolVerifier(settings=scan_settings)
        transport_detector = TransportDetector(settings=scan_settings)
        
        detection_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Detecting MCP services...", total=len(open_ports))
            
            for result in open_ports:
                try:
                    # Try protocol verification
                    protocol_result = protocol_verifier.detect(result.target.host, port=result.port)
                    if protocol_result.success:
                        detection_results.append(protocol_result)
                    
                    # Try transport detection
                    transport_result = transport_detector.detect(result.target.host, port=result.port)
                    if transport_result.success:
                        detection_results.append(transport_result)
                        
                except Exception as e:
                    logger.debug(f"Detection failed for {result.target.host}:{result.port}: {e}")
                
                progress.advance(task, 1)
        
        # Step 3: Results Summary
        console.print("\n[bold blue]Phase 3: Results Summary[/bold blue]")
        
        if detection_results:
            # Display MCP detection results
            table = Table(title="MCP Services Detected", show_header=True, header_style="bold magenta")
            table.add_column("Host", style="cyan", no_wrap=True)
            table.add_column("Port", style="green")
            table.add_column("Transport", style="blue")
            table.add_column("Confidence", style="yellow")
            table.add_column("Risk Level", style="red")
            
            for result in detection_results:
                confidence_color = "green" if result.confidence > 0.8 else "yellow" if result.confidence > 0.5 else "red"
                risk_color = "red" if result.risk_level == "high" else "yellow" if result.risk_level == "medium" else "green"
                
                table.add_row(
                    result.target_host,
                    str(result.mcp_server.port) if result.mcp_server and result.mcp_server.port else "N/A",
                    result.mcp_server.transport_type.value if result.mcp_server else "unknown",
                    f"[{confidence_color}]{result.confidence:.2f}[/{confidence_color}]",
                    f"[{risk_color}]{result.risk_level}[/{risk_color}]"
                )
            
            console.print(table)
            console.print(f"\n[bold green]Quick scan complete: Found {len(detection_results)} potential MCP services[/bold green]")
            
            # Basic risk assessment
            high_risk = sum(1 for r in detection_results if r.risk_level == "high")
            medium_risk = sum(1 for r in detection_results if r.risk_level == "medium")
            
            if high_risk > 0:
                console.print(f"[bold red]⚠️  {high_risk} high-risk services detected![/bold red]")
            if medium_risk > 0:
                console.print(f"[bold yellow]⚠️  {medium_risk} medium-risk services detected[/bold yellow]")
        else:
            console.print("[yellow]No MCP services detected on open ports[/yellow]")
        
        # Save results if output specified
        if output:
            # Combine scan and detection results
            combined_results = {
                'scan_results': [r.to_dict() for r in scan_results],
                'detection_results': [r.to_dict() for r in detection_results],
                'summary': {
                    'total_ports_scanned': len(scan_results),
                    'open_ports': len(open_ports),
                    'mcp_services_detected': len(detection_results),
                    'high_risk_services': sum(1 for r in detection_results if r.risk_level == "high"),
                    'medium_risk_services': sum(1 for r in detection_results if r.risk_level == "medium"),
                }
            }
            
            import json
            from pathlib import Path
            
            output_path = Path(output)
            with open(output_path, 'w') as f:
                json.dump(combined_results, f, indent=2, default=str)
            
            console.print(f"\n[green]Results saved to {output}[/green]")
        
    except Exception as e:
        logger.error(f"Quick scan failed: {e}")
        raise click.ClickException(f"Quick scan failed: {e}")


def main():
    """Main entry point for the HawkEye CLI application."""
    cli()


if __name__ == "__main__":
    main() 