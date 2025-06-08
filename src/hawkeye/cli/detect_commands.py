"""
Detect command group for HawkEye CLI.

This module implements MCP-specific detection and analysis commands including
target detection, local process analysis, and configuration discovery.
"""

import sys
from pathlib import Path
from typing import Optional, List
import ipaddress

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.tree import Tree

from ..detection.base import MCPDetector, DetectionResult
from ..detection.process_enum import ProcessEnumerator
from ..detection.config_discovery import ConfigFileDiscovery
from ..detection.protocol_verify import ProtocolVerifier
from ..detection.transport_detect import TransportDetector
from ..detection.npx_detect import NPXDetector
from ..detection.docker_inspect import DockerInspector
from ..detection.env_analysis import EnvironmentAnalyzer
from ..exceptions import HawkEyeError, DetectionError
from ..utils import get_logger

console = Console()
logger = get_logger(__name__)


@click.group()
def detect():
    """MCP-specific detection and analysis operations."""
    pass


@detect.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target IP address or hostname"
)
@click.option(
    "--ports", "-p",
    default="3000,8000,8080,9000",
    help="Port range or comma-separated ports (default: common MCP ports)"
)
@click.option(
    "--timeout",
    type=int,
    default=10,
    help="Connection timeout in seconds (default: 10)"
)
@click.option(
    "--verify-protocol/--no-verify-protocol",
    default=True,
    help="Verify MCP protocol handshake"
)
@click.option(
    "--detect-transport/--no-detect-transport",
    default=True,
    help="Detect transport layer (HTTP, WebSocket, stdio)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for detection results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml"]),
    default="json",
    help="Output format (default: json)"
)
@click.pass_context
def target(ctx, target: str, ports: str, timeout: int, verify_protocol: bool,
           detect_transport: bool, output: Optional[str], format: str):
    """
    Detect MCP servers on specified target.
    
    Performs comprehensive MCP detection including protocol verification
    and transport layer identification.
    
    Examples:
    \b
        hawkeye detect target -t 192.168.1.100
        hawkeye detect target -t example.com -p 3000-3010
        hawkeye detect target -t 10.0.0.1 --verify-protocol --detect-transport
    """
    try:
        # Parse ports
        from .scan_commands import parse_ports
        port_list = parse_ports(ports)
        if not port_list:
            port_list = [3000, 8000, 8080, 9000]  # Default MCP ports
        
        console.print(f"[bold blue]🦅 HawkEye MCP Detection[/bold blue]")
        console.print(f"Target: {target}")
        console.print(f"Ports: {len(port_list)} ports")
        console.print(f"Protocol Verification: {'Enabled' if verify_protocol else 'Disabled'}")
        console.print(f"Transport Detection: {'Enabled' if detect_transport else 'Disabled'}")
        console.print()
        
        # Initialize detectors
        detectors = []
        if verify_protocol:
            detectors.append(ProtocolVerifier(timeout=timeout))
        if detect_transport:
            detectors.append(TransportDetector(timeout=timeout))
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Detecting MCP services...", total=len(port_list))
            
            for port in port_list:
                try:
                    # Run detection on each port
                    for detector in detectors:
                        detection_result = detector.detect(target, port=port)
                        if detection_result.success:
                            results.append(detection_result)
                    
                except Exception as e:
                    logger.debug(f"Detection failed for {target}:{port}: {e}")
                
                progress.advance(task, 1)
        
        # Display results
        display_detection_results(results)
        
        # Save results if output specified
        if output:
            save_detection_results(results, output, format)
            console.print(f"\n[green]Results saved to {output}[/green]")
        
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        raise click.ClickException(f"Detection failed: {e}")


@detect.command()
@click.option(
    "--interface",
    help="Network interface to scan (default: auto-detect)"
)
@click.option(
    "--include-processes/--no-include-processes",
    default=True,
    help="Include local process enumeration"
)
@click.option(
    "--include-configs/--no-include-configs",
    default=True,
    help="Include configuration file discovery"
)
@click.option(
    "--include-docker/--no-include-docker",
    default=True,
    help="Include Docker container inspection"
)
@click.option(
    "--include-env/--no-include-env",
    default=True,
    help="Include environment variable analysis"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for detection results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml"]),
    default="json",
    help="Output format (default: json)"
)
@click.pass_context
def local(ctx, interface: Optional[str], include_processes: bool, include_configs: bool,
          include_docker: bool, include_env: bool, output: Optional[str], format: str):
    """
    Detect MCP servers on local system.
    
    Performs comprehensive local MCP detection including process enumeration,
    configuration discovery, Docker inspection, and environment analysis.
    
    Examples:
    \b
        hawkeye detect local
        hawkeye detect local --include-processes --include-docker
        hawkeye detect local --no-include-env
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Local MCP Detection[/bold blue]")
        console.print(f"Interface: {interface or 'auto-detect'}")
        console.print(f"Process Enumeration: {'Enabled' if include_processes else 'Disabled'}")
        console.print(f"Config Discovery: {'Enabled' if include_configs else 'Disabled'}")
        console.print(f"Docker Inspection: {'Enabled' if include_docker else 'Disabled'}")
        console.print(f"Environment Analysis: {'Enabled' if include_env else 'Disabled'}")
        console.print()
        
        all_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            total_tasks = sum([include_processes, include_configs, include_docker, include_env])
            main_task = progress.add_task("Local Detection...", total=total_tasks)
            
            # Process enumeration
            if include_processes:
                progress.update(main_task, description="Enumerating processes...")
                process_enum = ProcessEnumerator()
                process_results = process_enum.enumerate_mcp_processes()
                all_results.extend(process_results)
                progress.advance(main_task, 1)
            
            # Configuration discovery
            if include_configs:
                progress.update(main_task, description="Discovering configurations...")
                config_discovery = ConfigFileDiscovery()
                config_result = config_discovery.detect("localhost")
                if config_result.success:
                    all_results.append(config_result)
                progress.advance(main_task, 1)
            
            # Docker inspection
            if include_docker:
                progress.update(main_task, description="Inspecting Docker containers...")
                docker_inspector = DockerInspector()
                docker_results = docker_inspector.inspect_mcp_containers()
                all_results.extend(docker_results)
                progress.advance(main_task, 1)
            
            # Environment analysis
            if include_env:
                progress.update(main_task, description="Analyzing environment...")
                env_analyzer = EnvironmentAnalyzer()
                env_results = env_analyzer.analyze_mcp_environment()
                all_results.extend(env_results)
                progress.advance(main_task, 1)
        
        # Display results
        display_detection_results(all_results)
        
        # Save results if output specified
        if output:
            save_detection_results(all_results, output, format)
            console.print(f"\n[green]Results saved to {output}[/green]")
        
    except Exception as e:
        logger.error(f"Local detection failed: {e}")
        raise click.ClickException(f"Local detection failed: {e}")


@detect.command()
@click.option(
    "--pid",
    type=int,
    required=True,
    help="Process ID to analyze"
)
@click.option(
    "--deep-analysis/--no-deep-analysis",
    default=True,
    help="Perform deep process analysis"
)
@click.option(
    "--check-children/--no-check-children",
    default=True,
    help="Check child processes"
)
@click.option(
    "--analyze-env/--no-analyze-env",
    default=True,
    help="Analyze environment variables"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for analysis results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml"]),
    default="json",
    help="Output format (default: json)"
)
@click.pass_context
def process(ctx, pid: int, deep_analysis: bool, check_children: bool,
            analyze_env: bool, output: Optional[str], format: str):
    """
    Analyze specific process for MCP indicators.
    
    Performs detailed analysis of a specific process including command line
    arguments, environment variables, open files, and network connections.
    
    Examples:
    \b
        hawkeye detect process --pid 1234
        hawkeye detect process --pid 5678 --deep-analysis --check-children
        hawkeye detect process --pid 9012 --no-analyze-env
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Process Analysis[/bold blue]")
        console.print(f"Process ID: {pid}")
        console.print(f"Deep Analysis: {'Enabled' if deep_analysis else 'Disabled'}")
        console.print(f"Check Children: {'Enabled' if check_children else 'Disabled'}")
        console.print(f"Environment Analysis: {'Enabled' if analyze_env else 'Disabled'}")
        console.print()
        
        # Initialize process enumerator
        process_enum = ProcessEnumerator()
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Analyzing process...", total=4)
            
            # Basic process analysis
            progress.update(task, description="Basic process analysis...")
            basic_results = process_enum.analyze_process(pid)
            results.extend(basic_results)
            progress.advance(task, 1)
            
            # Deep analysis
            if deep_analysis:
                progress.update(task, description="Deep process analysis...")
                deep_results = process_enum.deep_analyze_process(pid)
                results.extend(deep_results)
            progress.advance(task, 1)
            
            # Child process analysis
            if check_children:
                progress.update(task, description="Analyzing child processes...")
                child_results = process_enum.analyze_child_processes(pid)
                results.extend(child_results)
            progress.advance(task, 1)
            
            # Environment analysis
            if analyze_env:
                progress.update(task, description="Analyzing environment...")
                env_analyzer = EnvironmentAnalyzer()
                env_results = env_analyzer.analyze_process_environment(pid)
                results.extend(env_results)
            progress.advance(task, 1)
        
        # Display results
        display_process_analysis(results, pid)
        
        # Save results if output specified
        if output:
            save_detection_results(results, output, format)
            console.print(f"\n[green]Results saved to {output}[/green]")
        
    except Exception as e:
        logger.error(f"Process analysis failed: {e}")
        raise click.ClickException(f"Process analysis failed: {e}")


@detect.command()
@click.option(
    "--path",
    type=click.Path(exists=True),
    default=".",
    help="Path to search for MCP configurations (default: current directory)"
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    help="Search recursively in subdirectories"
)
@click.option(
    "--include-hidden/--no-include-hidden",
    default=False,
    help="Include hidden files and directories"
)
@click.option(
    "--max-depth",
    type=int,
    default=5,
    help="Maximum directory depth for recursive search (default: 5)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for discovery results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml"]),
    default="json",
    help="Output format (default: json)"
)
@click.pass_context
def config(ctx, path: str, recursive: bool, include_hidden: bool, max_depth: int,
           output: Optional[str], format: str):
    """
    Discover MCP configuration files.
    
    Searches for MCP-related configuration files including package.json,
    MCP server configs, environment files, and Docker configurations.
    
    Examples:
    \b
        hawkeye detect config
        hawkeye detect config --path /opt/mcp --recursive
        hawkeye detect config --path . --include-hidden --max-depth 3
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Configuration Discovery[/bold blue]")
        console.print(f"Search Path: {path}")
        console.print(f"Recursive: {'Enabled' if recursive else 'Disabled'}")
        console.print(f"Include Hidden: {'Enabled' if include_hidden else 'Disabled'}")
        console.print(f"Max Depth: {max_depth}")
        console.print()
        
        # Initialize config discovery
        config_discovery = ConfigFileDiscovery()
        
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Discovering configurations...", total=1)
            
            # Discover configurations
            config_result = config_discovery.detect(
                "localhost",
                search_paths=[path],
                max_depth=max_depth
            )
            if config_result.success:
                results.append(config_result)
            
            progress.advance(task, 1)
        
        # Display results
        display_config_discovery(results, path)
        
        # Save results if output specified
        if output:
            save_detection_results(results, output, format)
            console.print(f"\n[green]Results saved to {output}[/green]")
        
    except Exception as e:
        logger.error(f"Configuration discovery failed: {e}")
        raise click.ClickException(f"Configuration discovery failed: {e}")


def display_detection_results(results):
    """Display detection results in a formatted table."""
    if not results:
        console.print("[yellow]No MCP services detected[/yellow]")
        return
    
    # Create results table
    table = Table(title="MCP Detection Results", show_header=True, header_style="bold magenta")
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Port", style="green")
    table.add_column("Detection Method", style="blue")
    table.add_column("Confidence", style="yellow")
    table.add_column("Transport", style="magenta")
    table.add_column("Details", style="dim")
    
    for result in results:
        confidence_color = "green" if result.confidence > 0.8 else "yellow" if result.confidence > 0.5 else "red"
        
        table.add_row(
            result.target.host if hasattr(result, 'target') else "localhost",
            str(result.port) if hasattr(result, 'port') else "N/A",
            result.detection_method.value,
            f"[{confidence_color}]{result.confidence:.2f}[/{confidence_color}]",
            result.transport_type.value if hasattr(result, 'transport_type') else "unknown",
            result.details[:50] + "..." if len(result.details) > 50 else result.details
        )
    
    console.print(table)
    console.print(f"\n[bold green]Detected {len(results)} MCP services[/bold green]")


def display_process_analysis(results, pid: int):
    """Display process analysis results."""
    if not results:
        console.print(f"[yellow]No MCP indicators found in process {pid}[/yellow]")
        return
    
    console.print(f"[bold green]Process {pid} Analysis Results[/bold green]")
    
    # Group results by type
    process_info = [r for r in results if r.detection_method.value == "process_analysis"]
    env_info = [r for r in results if r.detection_method.value == "environment_analysis"]
    child_info = [r for r in results if r.detection_method.value == "child_process_analysis"]
    
    if process_info:
        console.print("\n[bold blue]Process Information:[/bold blue]")
        for result in process_info:
            console.print(f"  • {result.details}")
    
    if env_info:
        console.print("\n[bold blue]Environment Variables:[/bold blue]")
        for result in env_info:
            console.print(f"  • {result.details}")
    
    if child_info:
        console.print("\n[bold blue]Child Processes:[/bold blue]")
        for result in child_info:
            console.print(f"  • {result.details}")


def display_config_discovery(results, search_path: str):
    """Display configuration discovery results."""
    if not results:
        console.print(f"[yellow]No MCP configurations found in {search_path}[/yellow]")
        return
    
    console.print(f"[bold green]Configuration Discovery Results[/bold green]")
    
    # Create tree structure
    tree = Tree(f"📁 {search_path}")
    
    # Group by file type
    config_types = {}
    for result in results:
        config_type = result.details.split(":")[0] if ":" in result.details else "unknown"
        if config_type not in config_types:
            config_types[config_type] = []
        config_types[config_type].append(result)
    
    for config_type, configs in config_types.items():
        type_branch = tree.add(f"📄 {config_type} ({len(configs)} files)")
        for config in configs:
            file_path = config.details.split(":", 1)[1] if ":" in config.details else config.details
            confidence_color = "green" if config.confidence > 0.8 else "yellow" if config.confidence > 0.5 else "red"
            type_branch.add(f"[{confidence_color}]{file_path}[/{confidence_color}]")
    
    console.print(tree)
    console.print(f"\n[bold green]Found {len(results)} configuration files[/bold green]")


def save_detection_results(results, output_path: str, format: str):
    """Save detection results to file in specified format."""
    from ..reporting.json_reporter import JSONReporter
    from ..reporting.csv_reporter import CSVReporter
    from ..reporting.xml_reporter import XMLReporter
    from ..reporting.base import ReportData, ReportMetadata, ReportFormat, ReportType
    
    # Create report metadata
    metadata = ReportMetadata(
        title="HawkEye MCP Detection Results",
        report_type=ReportType.RISK_ASSESSMENT,
        format=ReportFormat(format.upper()),
        generated_by="hawkeye-cli",
        version="1.0.0",
        description="MCP detection results from HawkEye reconnaissance tool",
        author="HawkEye",
        organization="Security Team",
        classification="Internal"
    )
    
    # Create report data
    report_data = ReportData(
        metadata=metadata,
        scan_results=[],
        detection_results=results,
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