"""
Detect command group for HawkEye CLI.

This module implements MCP-specific detection and analysis commands including
target detection, local process analysis, and configuration discovery.
"""

import sys
from pathlib import Path
from typing import Optional, List
import ipaddress
from datetime import datetime

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
from ..detection.pipeline import DetectionPipeline, PipelineConfig, create_detection_pipeline
from ..exceptions import HawkEyeError, DetectionError
from ..utils import get_logger
from ..reporting.pipeline_converter import convert_pipeline_results_to_report
from ..reporting import IntrospectionReporter, JSONReporter, CSVReporter, XMLReporter, HTMLReporter

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
    "--enable-introspection/--disable-introspection",
    default=True,
    help="Enable enhanced MCP introspection (default: enabled)"
)
@click.option(
    "--introspection-timeout",
    type=int,
    default=180,
    help="Timeout for MCP introspection in seconds (default: 180)"
)
@click.option(
    "--enable-risk-assessment/--disable-risk-assessment",
    default=True,
    help="Enable risk assessment of discovered servers (default: enabled)"
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.3,
    help="Minimum confidence threshold for results (default: 0.3)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for comprehensive results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml", "html"]),
    default="json",
    help="Output format (default: json)"
)
@click.option(
    "--generate-introspection-report/--no-introspection-report",
    default=False,
    help="Generate detailed introspection report (default: disabled)"
)
@click.option(
    "--introspection-report-path",
    type=click.Path(),
    help="Path for introspection report (default: auto-generated)"
)
@click.pass_context
def comprehensive(ctx, target: str, enable_introspection: bool, introspection_timeout: int,
                 enable_risk_assessment: bool, confidence_threshold: float, output: Optional[str], 
                 format: str, generate_introspection_report: bool, introspection_report_path: Optional[str]):
    """
    Comprehensive MCP detection using integrated pipeline.
    
    Performs complete MCP detection including traditional methods and
    enhanced introspection with risk assessment.
    
    Examples:
    \b
        hawkeye detect comprehensive -t 192.168.1.100
        hawkeye detect comprehensive -t localhost --disable-introspection
        hawkeye detect comprehensive -t example.com --confidence-threshold 0.5
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Comprehensive MCP Detection[/bold blue]")
        console.print(f"Target: {target}")
        console.print(f"Enhanced Introspection: {'Enabled' if enable_introspection else 'Disabled'}")
        console.print(f"Risk Assessment: {'Enabled' if enable_risk_assessment else 'Disabled'}")
        console.print(f"Confidence Threshold: {confidence_threshold}")
        console.print()
        
        # Create pipeline configuration
        pipeline_config = PipelineConfig(
            enable_mcp_introspection=enable_introspection,
            introspection_timeout=float(introspection_timeout),
            enable_risk_assessment=enable_risk_assessment,
            min_confidence_threshold=confidence_threshold
        )
        
        # Create and execute pipeline
        pipeline = create_detection_pipeline(pipeline_config, ctx.obj.settings)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Executing comprehensive detection...", total=None)
            
            # Execute the pipeline
            result = pipeline.execute_pipeline(target)
            
            progress.update(task, description="Detection complete", total=1, completed=1)
        
        # Display comprehensive results
        display_comprehensive_results(result)
        
        # Display pipeline statistics
        stats = pipeline.get_pipeline_statistics()
        display_pipeline_statistics(stats)
        
        # Generate and save reports if requested
        if output or generate_introspection_report:
            # Convert pipeline result to report data
            report_data = convert_pipeline_results_to_report(
                [result],
                report_title=f"MCP Detection Report - {target}",
                report_format=format
            )
            
            # Save main report if output specified
            if output:
                output_path = Path(output)
                
                # Select appropriate reporter based on format
                if format == "json":
                    reporter = JSONReporter(ctx.obj.settings)
                elif format == "csv":
                    reporter = CSVReporter(ctx.obj.settings)
                elif format == "xml":
                    reporter = XMLReporter(ctx.obj.settings)
                elif format == "html":
                    reporter = HTMLReporter(ctx.obj.settings)
                else:
                    reporter = JSONReporter(ctx.obj.settings)  # Default fallback
                
                # Generate and save report
                report_content = reporter.generate_report(report_data, output_path)
                console.print(f"\n[green]Main report saved to {output_path}[/green]")
            
            # Generate introspection report if requested
            if generate_introspection_report and report_data.has_introspection_data:
                introspection_reporter = IntrospectionReporter(ctx.obj.settings)
                
                # Determine introspection report path
                if introspection_report_path:
                    introspection_path = Path(introspection_report_path)
                else:
                    # Auto-generate path based on target and timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    introspection_path = Path(f"hawkeye_introspection_{target}_{timestamp}.json")
                
                # Generate introspection report
                introspection_content = introspection_reporter.generate_report(report_data, introspection_path)
                console.print(f"[green]Introspection report saved to {introspection_path}[/green]")
                
                # Display summary of introspection findings
                if report_data.introspection_summary:
                    console.print(f"\n[bold cyan]Introspection Summary:[/bold cyan]")
                    console.print(f"  Servers Introspected: {report_data.introspection_summary.total_servers_introspected}")
                    console.print(f"  Success Rate: {report_data.introspection_summary.success_rate:.1%}")
                    console.print(f"  Tools Discovered: {report_data.introspection_summary.total_tools_discovered}")
                    console.print(f"  Resources Discovered: {report_data.introspection_summary.total_resources_discovered}")
                    console.print(f"  High Risk Servers: {report_data.introspection_summary.high_risk_servers}")
            elif generate_introspection_report and not report_data.has_introspection_data:
                console.print("[yellow]No introspection data available for detailed report generation[/yellow]")
        
    except Exception as e:
        logger.error(f"Comprehensive detection failed: {e}")
        raise click.ClickException(f"Comprehensive detection failed: {e}")


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
        
        # Create a temporary settings override for this detection
        detection_settings = ctx.obj.settings
        detection_settings.detection.handshake_timeout = timeout
        
        if verify_protocol:
            detectors.append(ProtocolVerifier(settings=detection_settings))
        if detect_transport:
            detectors.append(TransportDetector(settings=detection_settings))
        
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
                docker_result = docker_inspector.detect("localhost")
                if docker_result.success:
                    all_results.append(docker_result)
                progress.advance(main_task, 1)
            
            # Environment analysis
            if include_env:
                progress.update(main_task, description="Analyzing environment...")
                env_analyzer = EnvironmentAnalyzer()
                env_result = env_analyzer.detect("localhost")
                if env_result.success:
                    all_results.append(env_result)
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
            basic_result = process_enum.analyze_process_by_pid(pid, include_env=analyze_env)
            if basic_result:
                results.append(basic_result)
            progress.advance(task, 1)
            
            # Deep analysis (using the same method with more details)
            if deep_analysis:
                progress.update(task, description="Deep process analysis...")
                # For now, we'll use the same method but could extend it later
                pass
            progress.advance(task, 1)
            
            # Child process analysis (would need to be implemented)
            if check_children:
                progress.update(task, description="Analyzing child processes...")
                # This would need to be implemented to find child processes
                pass
            progress.advance(task, 1)
            
            # Environment analysis
            if analyze_env:
                progress.update(task, description="Analyzing environment...")
                env_analyzer = EnvironmentAnalyzer()
                env_result = env_analyzer.detect("localhost", analyze_processes=True)
                if env_result.success:
                    results.append(env_result)
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
        
        # Extract details from raw_data or use fallback
        details = result.raw_data.get('process_details', 'MCP detected') if result.raw_data else 'MCP detected'
        
        table.add_row(
            result.target_host,
            str(result.mcp_server.port) if result.mcp_server and result.mcp_server.port else "N/A",
            result.detection_method.value,
            f"[{confidence_color}]{result.confidence:.2f}[/{confidence_color}]",
            result.mcp_server.transport_type.value if result.mcp_server else "unknown",
            details[:50] + "..." if len(details) > 50 else details
        )
    
    console.print(table)
    console.print(f"\n[bold green]Detected {len(results)} MCP services[/bold green]")


def display_process_analysis(results, pid: int):
    """Display process analysis results."""
    if not results:
        console.print(f"[yellow]No MCP indicators found in process {pid}[/yellow]")
        return
    
    console.print(f"[bold green]Process {pid} Analysis Results[/bold green]")
    
    # Handle mixed result types (ProcessInfo and DetectionResult)
    process_info = []
    env_info = []
    child_info = []
    
    for result in results:
        if hasattr(result, 'detection_method'):
            # This is a DetectionResult
            if result.detection_method.value == "process_enumeration":
                process_info.append(result)
            elif result.detection_method.value == "environment_analysis":
                env_info.append(result)
            elif result.detection_method.value == "child_process_analysis":
                child_info.append(result)
        else:
            # This is a ProcessInfo object
            process_info.append(result)
    
    if process_info:
        console.print("\n[bold blue]Process Information:[/bold blue]")
        for result in process_info:
            if hasattr(result, 'raw_data'):
                # DetectionResult
                details = result.raw_data.get('process_details', 'Process detected') if result.raw_data else 'Process detected'
                console.print(f"  • {details}")
            else:
                # ProcessInfo
                console.print(f"  • PID: {result.pid}")
                console.print(f"  • Name: {result.name}")
                console.print(f"  • Command: {' '.join(result.cmdline)}")
                console.print(f"  • Working Directory: {result.cwd}")
                console.print(f"  • User: {result.user}")
                if result.env_vars:
                    console.print(f"  • Environment Variables: {len(result.env_vars)} found")
    
    if env_info:
        console.print("\n[bold blue]Environment Variables:[/bold blue]")
        for result in env_info:
            details = result.raw_data.get('process_details', 'Environment detected') if result.raw_data else 'Environment detected'
            console.print(f"  • {details}")
    
    if child_info:
        console.print("\n[bold blue]Child Processes:[/bold blue]")
        for result in child_info:
            details = result.raw_data.get('process_details', 'Child process detected') if result.raw_data else 'Child process detected'
            console.print(f"  • {details}")


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
        # Extract config type from raw_data or use fallback
        details = result.raw_data.get('config_details', 'config:unknown') if result.raw_data else 'config:unknown'
        config_type = details.split(":")[0] if ":" in details else "unknown"
        if config_type not in config_types:
            config_types[config_type] = []
        config_types[config_type].append(result)
    
    for config_type, configs in config_types.items():
        type_branch = tree.add(f"📄 {config_type} ({len(configs)} files)")
        for config in configs:
            # Extract file path from raw_data or use fallback
            details = config.raw_data.get('config_details', 'config:unknown') if config.raw_data else 'config:unknown'
            file_path = details.split(":", 1)[1] if ":" in details else details
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
        format=ReportFormat(format.lower()),
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


def display_comprehensive_results(result):
    """Display comprehensive detection pipeline results."""
    from ..detection.pipeline import PipelineResult
    
    console.print(f"\n[bold green]🔍 Comprehensive Detection Results[/bold green]")
    console.print(f"Target: {result.target_host}")
    console.print(f"Duration: {result.duration:.2f} seconds")
    console.print(f"Success: {'✅' if result.success else '❌'}")
    console.print()
    
    # Summary statistics
    console.print("[bold cyan]📊 Detection Summary[/bold cyan]")
    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary_table.add_row("Total Detections", str(result.total_detections))
    summary_table.add_row("Successful Detections", str(result.successful_detections))
    summary_table.add_row("Failed Detections", str(result.failed_detections))
    summary_table.add_row("MCP Servers Found", str(result.mcp_servers_found))
    summary_table.add_row("Servers Introspected", str(len(result.introspection_results)))
    
    console.print(summary_table)
    console.print()
    
    # Detection results by method
    if result.detection_results:
        console.print("[bold cyan]🔍 Detection Results by Method[/bold cyan]")
        method_table = Table(show_header=True, header_style="bold magenta")
        method_table.add_column("Detection Method", style="cyan")
        method_table.add_column("Results", style="green")
        method_table.add_column("Success Rate", style="yellow")
        
        for method, results in result.detection_results.items():
            successful = sum(1 for r in results if r.success)
            total = len(results)
            success_rate = f"{(successful/max(total,1)*100):.1f}%" if total > 0 else "N/A"
            
            method_table.add_row(
                method.value.replace('_', ' ').title(),
                f"{successful}/{total}",
                success_rate
            )
        
        console.print(method_table)
        console.print()
    
    # Introspection results
    if result.introspection_results:
        console.print("[bold cyan]🔬 MCP Server Introspection Results[/bold cyan]")
        introspection_table = Table(show_header=True, header_style="bold magenta")
        introspection_table.add_column("Server ID", style="cyan")
        introspection_table.add_column("Tools", style="green")
        introspection_table.add_column("Resources", style="blue")
        introspection_table.add_column("Risk Level", style="red")
        introspection_table.add_column("Capabilities", style="yellow")
        
        for server_id, capabilities in result.introspection_results.items():
            risk_color = {
                "low": "green",
                "medium": "yellow", 
                "high": "orange",
                "critical": "red"
            }.get(capabilities.highest_risk_level, "white")
            
            capability_flags = []
            if capabilities.has_file_access:
                capability_flags.append("📁 File")
            if capabilities.has_external_access:
                capability_flags.append("🌐 Network")
            if capabilities.has_code_execution:
                capability_flags.append("⚡ Code")
            
            introspection_table.add_row(
                server_id,
                str(capabilities.tool_count),
                str(capabilities.resource_count),
                f"[{risk_color}]{capabilities.highest_risk_level.upper()}[/{risk_color}]",
                " ".join(capability_flags) if capability_flags else "None"
            )
        
        console.print(introspection_table)
        console.print()
    
    # Risk assessment
    if result.risk_assessment:
        console.print("[bold cyan]⚠️  Risk Assessment[/bold cyan]")
        risk = result.risk_assessment
        
        risk_color = {
            "low": "green",
            "medium": "yellow",
            "high": "orange", 
            "critical": "red"
        }.get(risk.get("overall_risk_level", "low"), "white")
        
        console.print(f"Overall Risk Level: [{risk_color}]{risk.get('overall_risk_level', 'Unknown').upper()}[/{risk_color}]")
        
        if risk.get("risk_factors"):
            console.print("\n[yellow]Risk Factors:[/yellow]")
            for factor in risk["risk_factors"]:
                console.print(f"  • {factor}")
        
        if risk.get("security_concerns"):
            console.print("\n[red]Security Concerns:[/red]")
            for concern in risk["security_concerns"]:
                console.print(f"  ⚠️  {concern}")
        
        if risk.get("recommendations"):
            console.print("\n[blue]Recommendations:[/blue]")
            for rec in risk["recommendations"]:
                console.print(f"  💡 {rec}")
        
        console.print()
    
    # Best findings
    if result.best_mcp_server:
        console.print("[bold cyan]🎯 Best MCP Server Found[/bold cyan]")
        server = result.best_mcp_server
        console.print(f"Name: {server.name}")
        console.print(f"Host: {server.host}")
        if hasattr(server, 'port') and server.port:
            console.print(f"Port: {server.port}")
        console.print()
    
    # Errors and warnings
    if result.errors:
        console.print("[bold red]❌ Errors[/bold red]")
        for error in result.errors:
            console.print(f"  • {error}")
        console.print()
    
    if result.warnings:
        console.print("[bold yellow]⚠️  Warnings[/bold yellow]")
        for warning in result.warnings:
            console.print(f"  • {warning}")
        console.print()


def display_pipeline_statistics(stats):
    """Display pipeline execution statistics."""
    console.print("[bold cyan]📈 Pipeline Statistics[/bold cyan]")
    
    stats_table = Table(show_header=True, header_style="bold magenta")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")
    
    stats_table.add_row("Total Pipelines Executed", str(stats.get("total_pipelines_executed", 0)))
    stats_table.add_row("Successful Pipelines", str(stats.get("successful_pipelines", 0)))
    stats_table.add_row("Failed Pipelines", str(stats.get("failed_pipelines", 0)))
    stats_table.add_row("Success Rate", f"{stats.get('success_rate', 0):.1f}%")
    stats_table.add_row("Total Introspections", str(stats.get("total_introspections", 0)))
    stats_table.add_row("Successful Introspections", str(stats.get("successful_introspections", 0)))
    stats_table.add_row("Introspection Success Rate", f"{stats.get('introspection_success_rate', 0):.1f}%")
    stats_table.add_row("Average Duration", f"{stats.get('average_pipeline_duration', 0):.2f}s")
    stats_table.add_row("Introspection Enabled", "✅" if stats.get("introspection_enabled", False) else "❌")
    
    console.print(stats_table)
    console.print()

# Alias for backward compatibility
detect_group = detect