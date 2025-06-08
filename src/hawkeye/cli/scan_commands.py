"""
Scan command for HawkEye CLI.

This module implements network scanning commands for MCP server discovery.
"""

import sys
from pathlib import Path
from typing import Optional, List
import ipaddress

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from ..scanner.base import ScanTarget
from ..scanner.tcp_scanner import TCPScanner
from ..scanner.udp_scanner import UDPScanner
from ..scanner.target_enum import TargetEnumerator
from ..exceptions import HawkEyeError, ScanError
from ..utils import get_logger

console = Console()
logger = get_logger(__name__)


def validate_target(target: str) -> None:
    """Validate target specification."""
    try:
        # Try parsing as IP address
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass
    
    try:
        # Try parsing as CIDR network
        ipaddress.ip_network(target, strict=False)
        return
    except ValueError:
        pass
    
    # Check if it's a valid hostname (basic validation)
    if target and all(c.isalnum() or c in '.-_' for c in target):
        return
    
    raise click.BadParameter(f"Invalid target specification: {target}")


def parse_ports(ports_str: str) -> List[int]:
    """Parse port specification string into list of ports."""
    if not ports_str:
        return []
    
    port_list = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            # Port range
            try:
                start, end = part.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError("Invalid port range")
                port_list.extend(range(start_port, end_port + 1))
            except ValueError:
                raise click.BadParameter(f"Invalid port range: {part}")
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError("Port out of range")
                port_list.append(port)
            except ValueError:
                raise click.BadParameter(f"Invalid port: {part}")
    
    return sorted(list(set(port_list)))  # Remove duplicates and sort


@click.command()
@click.option(
    "--target", "-t",
    required=True,
    callback=lambda ctx, param, value: validate_target(value) or value,
    help="Target IP address, CIDR range, or hostname"
)
@click.option(
    "--ports", "-p",
    default="3000,8000,8080,9000",
    help="Port range (e.g., 1-1000) or comma-separated ports (default: common MCP ports)"
)
@click.option(
    "--tcp/--no-tcp",
    default=True,
    help="Enable/disable TCP scanning"
)
@click.option(
    "--udp/--no-udp", 
    default=False,
    help="Enable/disable UDP scanning"
)
@click.option(
    "--threads",
    type=int,
    default=50,
    help="Number of concurrent threads (default: 50)"
)
@click.option(
    "--timeout",
    type=int,
    default=5,
    help="Connection timeout in seconds (default: 5)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for scan results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml"]),
    default="json",
    help="Output format (default: json)"
)
@click.pass_context
def scan(ctx, target: str, ports: str, tcp: bool, udp: bool, threads: int, 
         timeout: int, output: Optional[str], format: str):
    """
    Network scanning operations for MCP server discovery.
    
    Scan specified target for MCP servers. TARGET can be:
    - Single IP address (e.g., 192.168.1.100)
    - CIDR network (e.g., 192.168.1.0/24)
    - Hostname (e.g., example.com)
    
    Examples:
    \b
        hawkeye scan -t 192.168.1.100
        hawkeye scan -t 192.168.1.0/24 -p 3000-3010
        hawkeye scan -t example.com --tcp --udp
    """
    if not tcp and not udp:
        raise click.UsageError("At least one of --tcp or --udp must be enabled")
    
    try:
        # Parse ports
        port_list = parse_ports(ports)
        if not port_list:
            port_list = [3000, 8000, 8080, 9000]  # Default MCP ports
        
        console.print(f"[bold blue]🦅 HawkEye Network Scan[/bold blue]")
        console.print(f"Target: {target}")
        console.print(f"Ports: {len(port_list)} ports ({min(port_list)}-{max(port_list)})")
        console.print(f"Protocols: {'TCP' if tcp else ''}{' UDP' if udp else ''}")
        console.print(f"Threads: {threads}, Timeout: {timeout}s")
        console.print()
        
        # Enumerate targets
        enumerator = TargetEnumerator()
        targets = enumerator.enumerate_targets(target)
        
        console.print(f"Discovered {len(targets)} target hosts")
        
        # Initialize scanners
        results = []
        
        # Create a temporary settings override for this scan
        scan_settings = ctx.obj.settings
        scan_settings.scan.timeout_seconds = timeout
        scan_settings.scan.max_threads = threads
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            if tcp:
                tcp_scanner = TCPScanner(settings=scan_settings)
                
                task = progress.add_task("TCP Scanning...", total=len(targets) * len(port_list))
                
                for target_host in targets:
                    scan_target = ScanTarget(host=target_host, ports=port_list)
                    tcp_results = tcp_scanner.scan_target(scan_target)
                    results.extend(tcp_results)
                    progress.advance(task, len(port_list))
            
            if udp:
                udp_scanner = UDPScanner(settings=scan_settings)
                
                task = progress.add_task("UDP Scanning...", total=len(targets) * len(port_list))
                
                for target_host in targets:
                    scan_target = ScanTarget(host=target_host, ports=port_list)
                    udp_results = udp_scanner.scan_target(scan_target)
                    results.extend(udp_results)
                    progress.advance(task, len(port_list))
        
        # Display results summary
        display_scan_results(results)
        
        # Save results if output specified
        if output:
            save_scan_results(results, output, format)
            console.print(f"\n[green]Results saved to {output}[/green]")
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise click.ClickException(f"Scan failed: {e}")


def display_scan_results(results):
    """Display scan results in a formatted table."""
    if not results:
        console.print("[yellow]No open ports found[/yellow]")
        return
    
    # Filter for open ports only
    open_results = [r for r in results if r.state.value == "open"]
    
    if not open_results:
        console.print("[yellow]No open ports found[/yellow]")
        return
    
    # Create results table
    table = Table(title="Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Port", style="green")
    table.add_column("Protocol", style="blue")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Response Time", style="dim")
    
    for result in open_results:
        service_name = ""
        if result.service_info:
            service_name = result.service_info.name or "unknown"
        
        table.add_row(
            result.target.host,
            str(result.port),
            result.scan_type.value.upper(),
            result.state.value.upper(),
            service_name,
            f"{result.response_time:.2f}ms" if result.response_time else "N/A"
        )
    
    console.print(table)
    console.print(f"\n[bold green]Found {len(open_results)} open ports on {len(set(r.target.host for r in open_results))} hosts[/bold green]")


def save_scan_results(results, output_path: str, format: str):
    """Save scan results to file in specified format."""
    from ..reporting.json_reporter import JSONReporter
    from ..reporting.csv_reporter import CSVReporter
    from ..reporting.xml_reporter import XMLReporter
    from ..reporting.base import ReportData, ReportMetadata, ReportFormat, ReportType
    
    # Create report metadata
    metadata = ReportMetadata(
        title="HawkEye Network Scan Results",
        report_type=ReportType.RISK_ASSESSMENT,
        format=ReportFormat(format.lower()),
        generated_by="hawkeye-cli",
        version="1.0.0",
        description="Network scan results from HawkEye reconnaissance tool",
        author="HawkEye",
        organization="Security Team",
        classification="Internal"
    )
    
    # Create report data
    report_data = ReportData(
        metadata=metadata,
        scan_results=results,
        detection_results=[],
        assessment_results=[],
        recommendations=[]
    )
    
    # Generate report
    if format == "json":
        reporter = JSONReporter()
    elif format == "csv":
        reporter = CSVReporter()
    elif format == "xml":
        reporter = XMLReporter()
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    reporter.generate_report(report_data, Path(output_path))