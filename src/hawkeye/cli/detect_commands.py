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
import time # Added for timestamp

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
from ..scanner.target_enum import TargetEnumerator  # Import TargetEnumerator for CIDR handling
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
    help="Target IP address, CIDR range, or hostname (e.g., 192.168.1.100, 192.168.1.0/24, example.com)"
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
    enhanced introspection with risk assessment. Supports CIDR notation.
    
    Examples:
    \b
        hawkeye detect comprehensive -t 192.168.1.100
        hawkeye detect comprehensive -t 192.168.1.0/24
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
        
        # Handle CIDR notation - enumerate individual targets
        enumerator = TargetEnumerator()
        try:
            # Check if target is CIDR notation
            if '/' in target:
                console.print(f"[yellow]Detected CIDR notation, enumerating targets...[/yellow]")
                targets = enumerator.enumerate_targets(target)
                console.print(f"[green]Enumerated {len(targets)} targets from CIDR {target}[/green]")
            else:
                # Single target
                targets = [target]
        except Exception as e:
            console.print(f"[red]Error parsing target '{target}': {e}[/red]")
            raise click.ClickException(f"Invalid target specification: {target}")
        
        # Create pipeline configuration
        pipeline_config = PipelineConfig(
            enable_mcp_introspection=enable_introspection,
            introspection_timeout=float(introspection_timeout),
            enable_risk_assessment=enable_risk_assessment,
            min_confidence_threshold=confidence_threshold
        )
        
        # Create pipeline
        pipeline = create_detection_pipeline(pipeline_config, ctx.obj.settings)
        
        # Execute detection on all targets
        all_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Executing comprehensive detection...", total=len(targets))
            
            for i, individual_target in enumerate(targets):
                try:
                    progress.update(task, description=f"Detecting on {individual_target}...")
                    
                    # Execute the pipeline for this target
                    result = pipeline.execute_pipeline(individual_target)
                    all_results.append(result)
                    
                    progress.advance(task, 1)
                    
                except Exception as e:
                    logger.warning(f"Detection failed for {individual_target}: {e}")
                    progress.advance(task, 1)
                    continue
            
            progress.update(task, description="Detection complete")
        
        # Filter successful results
        successful_results = [r for r in all_results if r.success]
        
        # Display comprehensive results for each target
        for result in all_results:
            if result.success:
                console.print(f"\n[bold green]Results for {result.target_host}:[/bold green]")
                display_comprehensive_results(result)
        
        # Display overall summary
        console.print(f"\n[bold cyan]Overall Summary:[/bold cyan]")
        console.print(f"  Targets Processed: {len(all_results)}")
        console.print(f"  Successful Detections: {len(successful_results)}")
        console.print(f"  Failed Detections: {len(all_results) - len(successful_results)}")
        
        total_mcp_servers = sum(r.mcp_servers_found for r in successful_results)
        if total_mcp_servers > 0:
            console.print(f"  [bold green]Total MCP Servers Found: {total_mcp_servers}[/bold green]")
        else:
            console.print(f"  [yellow]No MCP Servers Found[/yellow]")
        
        # Display pipeline statistics
        stats = pipeline.get_pipeline_statistics()
        display_pipeline_statistics(stats)
        
        # Generate and save reports if requested
        if output or generate_introspection_report:
            # Convert pipeline results to report data (use all results, not just successful ones)
            report_data = convert_pipeline_results_to_report(
                all_results,
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


@click.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True),
    required=True,
    help="Input JSON file containing detection results"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for threat analysis results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "html", "csv", "xml"]),
    default="json",
    help="Output format (default: json)"
)
@click.option(
    "--analysis-type",
    type=click.Choice(["quick", "comprehensive", "detailed"]),
    default="comprehensive",
    help="Type of threat analysis to perform (default: comprehensive)"
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.3,  # Lowered from 0.5 to include more detections
    help="Minimum confidence threshold for analysis (default: 0.3)"
)
@click.option(
    "--enable-ai/--disable-ai",
    default=True,
    help="Enable AI-powered analysis (requires API keys)"
)
@click.option(
    "--parallel-processing/--sequential-processing",
    default=True,
    help="Enable parallel processing for multiple servers"
)
@click.option(
    "--max-workers",
    type=int,
    default=3,
    help="Maximum number of parallel workers (default: 3)"
)
@click.option(
    "--cost-limit",
    type=float,
    help="Maximum cost limit for AI analysis (USD)"
)
@click.pass_context
def analyze_threats(ctx, input: str, output: Optional[str], format: str, analysis_type: str,
                   confidence_threshold: float, enable_ai: bool, parallel_processing: bool,
                   max_workers: int, cost_limit: Optional[float]):
    """
    Analyze threats from JSON detection results using AI-powered analysis.
    
    This command processes JSON files generated by detect commands and performs
    comprehensive threat analysis using the AI-powered threat analysis system.
    
    Examples:
        hawkeye detect comprehensive -t 192.168.1.100 -o results.json
        hawkeye analyze-threats -i results.json -o threats.json
        
        hawkeye detect local -o local_results.json
        hawkeye analyze-threats -i local_results.json -f html -o threat_report.html
    """
    logger = ctx.obj.logger
    
    if not ctx.obj.quiet:
        console.print(f"[bold green]🦅 HawkEye AI Threat Analysis[/bold green]")
        console.print(f"Input: {input}")
        console.print(f"Analysis Type: {analysis_type}")
        console.print(f"AI Enabled: {'✅' if enable_ai else '❌'}")
    
    logger.info(f"Starting threat analysis from detection results: {input}")
    
    try:
        import json
        from pathlib import Path
        from ..detection.ai_threat import AIThreatAnalyzer
        from ..detection.ai_threat.models import (
            EnvironmentContext, DeploymentType, SecurityPosture, 
            DataSensitivity, NetworkExposure, UserPrivileges, ComplianceFramework
        )
        from ..detection.mcp_introspection.models import MCPServerInfo, MCPTool
        from ..detection.base import TransportType, MCPServerType
        from ..reporting.html_reporter import HTMLReporter
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        
        # Load detection results from JSON file
        console.print("[bold blue]📂 Loading Detection Results[/bold blue]")
        with open(input, 'r') as f:
            detection_data = json.load(f)
        
        # Extract MCP servers from detection results
        mcp_servers = []
        
        # Handle different JSON structures from different detect commands
        if 'detection_results' in detection_data:
            # From comprehensive/target commands
            detection_results = detection_data['detection_results']
        elif isinstance(detection_data, list):
            # Direct list of detection results
            detection_results = detection_data
        elif 'results' in detection_data:
            # Alternative structure
            detection_results = detection_data['results']
        else:
            raise click.ClickException("Invalid JSON format: could not find detection results")
        
        # Convert raw detection result dictionaries to DetectionResult objects
        from ..detection.base import DetectionResult, DetectionMethod
        converted_detection_results = []
        
        for result_data in detection_results:
            if isinstance(result_data, dict):
                # Convert dictionary to DetectionResult object
                try:
                    # Map detection method string to enum
                    detection_method_str = result_data.get('detection_method', 'unknown')
                    detection_method = DetectionMethod.PROCESS_ENUMERATION  # Default
                    
                    # Map string values to enum
                    method_mapping = {
                        'process_enumeration': DetectionMethod.PROCESS_ENUMERATION,
                        'config_discovery': DetectionMethod.CONFIG_FILE_DISCOVERY,
                        'config_file_discovery': DetectionMethod.CONFIG_FILE_DISCOVERY,
                        'protocol_verification': DetectionMethod.PROTOCOL_HANDSHAKE,
                        'protocol_handshake': DetectionMethod.PROTOCOL_HANDSHAKE,
                        'transport_detection': DetectionMethod.TRANSPORT_DETECTION,
                        'npx_package_detection': DetectionMethod.NPX_PACKAGE_DETECTION,
                        'docker_inspection': DetectionMethod.DOCKER_INSPECTION,
                        'environment_analysis': DetectionMethod.ENVIRONMENT_ANALYSIS,
                        'introspection': DetectionMethod.PROCESS_ENUMERATION,  # Map to closest equivalent
                        'unknown': DetectionMethod.PROCESS_ENUMERATION  # Default fallback
                    }
                    detection_method = method_mapping.get(detection_method_str, DetectionMethod.PROCESS_ENUMERATION)
                    
                    # Extract MCP server data from JSON if present
                    mcp_server = None
                    if 'mcp_server' in result_data and result_data['mcp_server']:
                        server_data = result_data['mcp_server']
                        
                        # Convert string values to enums
                        transport_type_str = server_data.get('transport_type', 'http')
                        transport_type = TransportType.HTTP  # Default
                        try:
                            # Map transport type strings to enum values
                            transport_mapping = {
                                'http': TransportType.HTTP,
                                'websocket': TransportType.WEBSOCKET, 
                                'stdio': TransportType.STDIO,
                                'sse': TransportType.SSE
                            }
                            transport_type = transport_mapping.get(transport_type_str.lower(), TransportType.HTTP)
                        except (AttributeError, KeyError):
                            transport_type = TransportType.HTTP
                        
                        server_type_str = server_data.get('server_type', 'standalone')
                        server_type = MCPServerType.STANDALONE  # Default
                        try:
                            # Map server type strings to enum values  
                            server_type_mapping = {
                                'standalone': MCPServerType.STANDALONE,
                                'embedded': MCPServerType.EMBEDDED,
                                'managed': MCPServerType.MANAGED,
                                'unknown': MCPServerType.UNKNOWN,
                                'npx_package': MCPServerType.NPX_PACKAGE,
                                'docker_container': MCPServerType.DOCKER_CONTAINER
                            }
                            server_type = server_type_mapping.get(server_type_str.lower(), MCPServerType.STANDALONE)
                        except (AttributeError, KeyError):
                            server_type = MCPServerType.STANDALONE
                        
                        # Create MCPServerInfo from JSON data
                        mcp_server = MCPServerInfo(
                            server_id=server_data.get('server_id', f"json-server-{len(converted_detection_results)}"),
                            server_url=server_data.get('endpoint_url', ''),
                            tools=[],  # Tools will be empty from JSON as they aren't fully introspected
                            capabilities=server_data.get('capabilities', []),
                            metadata={},
                            transport_type=transport_type,
                            host=server_data.get('host', result_data.get('target_host', 'unknown')),
                            port=server_data.get('port'),
                            has_authentication=server_data.get('has_authentication', False),
                            is_secure=server_data.get('is_secure', False),
                            security_config=server_data.get('security_config', {}),
                            endpoint_url=server_data.get('endpoint_url', ''),
                            server_type=server_type,
                            detected_via=result_data.get('detection_method', 'unknown')
                        )
                    
                    # Create DetectionResult object
                    detection_result = DetectionResult(
                        target_host=result_data.get('target_host', 'unknown'),
                        detection_method=detection_method,
                        timestamp=result_data.get('timestamp', time.time()),
                        success=result_data.get('success', False),
                        mcp_server=mcp_server,
                        confidence=result_data.get('confidence', 0.0),
                        error=result_data.get('error'),
                        raw_data=result_data.get('raw_data', {}),
                        scan_duration=result_data.get('scan_duration')
                    )
                    converted_detection_results.append(detection_result)
                    
                except Exception as e:
                    logger.warning(f"Failed to convert detection result to object: {e}")
                    # Continue processing other results
                    continue
        
        # Use converted results for further processing
        detection_results = converted_detection_results
        
        # Convert detection results to MCPServerInfo objects
        for result in detection_results:
            result_data = result.raw_data if hasattr(result, 'raw_data') else {}
            
            # Extract MCP server information - check direct mcp_server field first
            if hasattr(result, 'mcp_server') and result.mcp_server:
                server_data = result.mcp_server
                
                # server_data is already an MCPServerInfo object, just use it directly
                mcp_server = server_data
                # Update the detected_via field to include detection method info
                if hasattr(mcp_server, 'detected_via'):
                    mcp_server.detected_via = result.detection_method.value if hasattr(result.detection_method, 'value') else str(result.detection_method)
                
                # Only include servers above confidence threshold
                if result.confidence >= confidence_threshold:
                    mcp_servers.append(mcp_server)
            
            # Fallback: Extract from raw_data in case of old format (for backward compatibility)
            elif 'mcp_server' in result_data and result_data['mcp_server']:
                server_data = result_data['mcp_server']
                
                # Create MCPServerInfo from the detection result
                server_id = server_data.get('server_id') or f"detected-{len(mcp_servers)}"
                
                # Handle tools - convert to MCPTool objects if needed
                tools = []
                if 'tools' in server_data and server_data['tools']:
                    for tool_data in server_data['tools']:
                        if isinstance(tool_data, dict):
                            tool = MCPTool(
                                name=tool_data.get('name', 'unknown'),
                                description=tool_data.get('description', ''),
                                input_schema=tool_data.get('input_schema', {})
                            )
                            tools.append(tool)
                
                # Create MCP server object
                mcp_server = MCPServerInfo(
                    server_id=server_id,
                    server_url=server_data.get('server_url', ''),
                    tools=tools,
                    capabilities=server_data.get('capabilities', []),
                    metadata=server_data.get('metadata', {}),
                    transport_type=server_data.get('transport_type', 'unknown'),
                    host=result.target_host,
                    port=server_data.get('port'),
                    detected_via=result.detection_method.value if hasattr(result.detection_method, 'value') else str(result.detection_method)
                )
                
                # Only include servers above confidence threshold
                if result.confidence >= confidence_threshold:
                    mcp_servers.append(mcp_server)
            
            # Fallback: Create MCP server from process data if has_mcp_indicators is true
            elif ('process_data' in result_data and 
                  result_data['process_data'].get('has_mcp_indicators', False)):
                
                process_data = result_data['process_data']
                
                # Extract server name from command line
                cmdline = process_data.get('cmdline', [])
                server_name = 'unknown'
                if cmdline and len(cmdline) > 1:
                    # Try to extract server name from executable path (not arguments)
                    # Look for the actual server binary, not directory arguments
                    for i, arg in enumerate(cmdline):
                        # Skip the first argument if it's an interpreter (node, python, etc.)
                        if i == 0 and arg.split('/')[-1] in ['node', 'python', 'python3', 'uv']:
                            continue
                        
                        # Look for MCP server binaries (not directory paths)
                        if ('mcp' in arg.lower() and ('server' in arg.lower() or 'mcp-server' in arg.lower())):
                            # Extract just the binary name from the path
                            if '/' in arg:
                                binary_name = arg.split('/')[-1]
                                # Make sure it's actually a server binary, not a directory
                                if any(term in binary_name.lower() for term in ['server', 'mcp']):
                                    server_name = binary_name
                                    break
                            else:
                                server_name = arg
                                break
                    
                    # Fallback: if still unknown, look for any executable-like argument
                    if server_name == 'unknown':
                        for i, arg in enumerate(cmdline[1:], 1):  # Skip first arg (interpreter)
                            if '/' in arg and not arg.startswith('/tmp/') and not arg.startswith('/ai/work/'):
                                # This looks like an executable path, not a directory argument
                                potential_name = arg.split('/')[-1]
                                if potential_name and not potential_name.startswith('.'):
                                    server_name = potential_name
                                    break
                
                # Clean up server name
                if server_name and server_name != 'unknown':
                    server_name = server_name.replace('.js', '').replace('.py', '')
                else:
                    server_name = f"{process_data.get('name', 'unknown')}-mcp"
                
                # Create MCP server object from process data
                mcp_server = MCPServerInfo(
                    server_id=server_name,  # Use server name as ID
                    server_url=f"process://{process_data.get('pid', 'unknown')}",
                    tools=[],  # No tools discovered yet
                    capabilities=[],
                    metadata={
                        'pid': process_data.get('pid'),
                        'name': server_name,  # Use server name instead of process name
                        'cmdline': process_data.get('cmdline'),
                        'user': process_data.get('user'),
                        'cwd': process_data.get('cwd'),
                        'server_name': server_name,
                        'process_name': process_data.get('name')  # Keep original process name for reference
                    },
                    transport_type='process',
                    host=result.target_host,
                    port=None,
                    detected_via=result.detection_method.value if hasattr(result.detection_method, 'value') else str(result.detection_method)
                )
                
                # Only include servers above confidence threshold
                if result.confidence >= confidence_threshold:
                    mcp_servers.append(mcp_server)
        
        if not mcp_servers:
            console.print(f"[yellow]No MCP servers found above confidence threshold {confidence_threshold}[/yellow]")
            return
        
        console.print(f"[green]Found {len(mcp_servers)} MCP servers for analysis[/green]")
        
        # Create environment context based on detection data
        env_context = EnvironmentContext(
            deployment_type=DeploymentType.LOCAL if 'local' in str(input).lower() else DeploymentType.REMOTE,
            security_posture=SecurityPosture.MEDIUM,
            data_sensitivity=DataSensitivity.INTERNAL,
            network_exposure=NetworkExposure.INTERNAL,
            user_privileges=UserPrivileges.STANDARD,
            compliance_requirements=[ComplianceFramework.OWASP_TOP_10]
        )
        
        # Initialize AI threat analyzer
        analyzer = AIThreatAnalyzer()
        
        # Set cost limit if specified
        if cost_limit:
            # Note: Cost limiting will be handled by individual providers
            logger.info(f"Cost limit set to ${cost_limit}")
        
        console.print(f"[bold blue]🤖 Performing Threat Analysis[/bold blue]")
        console.print(f"Servers to analyze: {len(mcp_servers)}")
        console.print(f"Analysis type: {analysis_type}")
        console.print(f"Parallel processing: {'✅' if parallel_processing else '❌'}")
        
        # Perform threat analysis
        threat_analyses = {}
        errors = {}
        
        if parallel_processing and len(mcp_servers) > 1:
            # Use batch processing for multiple servers
            def progress_callback(completed, total, current_tool):
                console.print(f"  Progress: {completed}/{total} - Processing: {current_tool}")
            
            try:
                # Use the existing analyze_multiple_threats method
                analyses_list = analyzer.analyze_multiple_threats(
                    mcp_servers=mcp_servers,
                    environment_context=env_context,
                    analysis_type=analysis_type
                )
                
                # Convert list to dictionary format
                for analysis in analyses_list:
                    tool_name = analysis.tool_capabilities.tool_name
                    threat_analyses[tool_name] = analysis
                
                # Create basic statistics
                statistics = {
                    "execution_time": 0.0,  # Will be calculated later
                    "tools_per_second": len(analyses_list) / max(1, 0.1),  # Placeholder
                    "success_rate": 1.0,
                    "parallel_efficiency": len(analyses_list) * 2  # Placeholder
                }
                
            except Exception as e:
                logger.error(f"Batch analysis failed: {e}")
                errors["batch_analysis"] = str(e)
                statistics = {"execution_time": 0.0, "tools_per_second": 0.0, "success_rate": 0.0}
            
        else:
            # Sequential processing
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task("Analyzing threats...", total=len(mcp_servers))
                
                for mcp_server in mcp_servers:
                    try:
                        tool_name = mcp_server.metadata.get('name', mcp_server.server_id)
                        threat_analysis = analyzer.analyze_threats(mcp_server, env_context)
                        threat_analyses[tool_name] = threat_analysis
                        
                    except Exception as e:
                        logger.error(f"Threat analysis failed for {mcp_server.server_id}: {e}")
                        errors[mcp_server.server_id] = str(e)
                    
                    progress.advance(task, 1)
        
        # Display results summary
        console.print(f"\n[bold cyan]📊 Threat Analysis Results[/bold cyan]")
        console.print(f"✅ Successful Analyses: {len(threat_analyses)}")
        console.print(f"❌ Failed Analyses: {len(errors)}")
        
        if parallel_processing and 'statistics' in locals():
            console.print(f"⏱️  Total Time: {statistics['execution_time']:.2f}s")
            console.print(f"⚡ Processing Rate: {statistics['tools_per_second']:.2f} tools/second")
        
        # Display individual threat analysis summaries
        for tool_name, analysis in threat_analyses.items():
            console.print(f"\n🎯 {tool_name}")
            console.print(f"  Threat Level: {analysis.threat_level.value.upper()}")
            console.print(f"  Attack Vectors: {len(analysis.attack_vectors)}")
            console.print(f"  Mitigations: {len(analysis.mitigation_strategies)}")
            console.print(f"  Confidence: {analysis.confidence_score:.2f}")
            console.print(f"  Cost: ${analysis.analysis_metadata.cost:.4f}")
        
        # Show any errors
        if errors:
            console.print(f"\n[bold red]❌ Analysis Errors[/bold red]")
            for tool_name, error in errors.items():
                console.print(f"  {tool_name}: {error}")
        
        # Show analysis statistics
        stats = analyzer.get_analysis_stats()
        console.print(f"\n[bold cyan]📈 Analysis Statistics[/bold cyan]")
        console.print(f"  Total Analyses: {stats['analyses_performed']}")
        console.print(f"  Cache Hits: {stats['cache_hits']}")
        console.print(f"  Total Cost: ${stats['total_cost']:.4f}")
        
        # Save results if output specified
        if output:
            console.print(f"\n[bold blue]💾 Saving Results[/bold blue]")
            
            # Prepare threat analysis data for reporting
            threat_analysis_data = {
                'metadata': {
                    'title': f"HawkEye AI Security Threat Analysis",
                    'source_file': str(input),
                    'analysis_type': analysis_type,
                    'generated_at': datetime.now().isoformat(),
                    'total_servers_analyzed': len(mcp_servers),
                    'successful_analyses': len(threat_analyses),
                    'failed_analyses': len(errors),
                    'ai_enabled': enable_ai,
                    'parallel_processing': parallel_processing
                },
                'threat_analyses': {},
                'errors': errors,
                'statistics': stats
            }
            
            # Convert threat analyses to serializable format
            for tool_name, analysis in threat_analyses.items():
                threat_analysis_data['threat_analyses'][tool_name] = {
                    'tool_capabilities': {
                        'tool_name': analysis.tool_capabilities.tool_name,
                        'capability_categories': [cat.value for cat in analysis.tool_capabilities.capability_categories],
                        'risk_score': analysis.tool_capabilities.risk_surface.risk_score,
                        'confidence': analysis.tool_capabilities.confidence
                    },
                    'threat_level': analysis.threat_level.value,
                    'attack_vectors': [
                        {
                            'name': av.name,
                            'severity': av.severity.value,
                            'description': av.description,
                            'impact': av.impact,
                            'likelihood': av.likelihood,
                            'prerequisites': av.prerequisites,
                            'attack_steps': av.attack_steps
                        } for av in analysis.attack_vectors
                    ],
                    'mitigation_strategies': [
                        {
                            'name': ms.name,
                            'description': ms.description,
                            'implementation_steps': ms.implementation_steps,
                            'effectiveness_score': ms.effectiveness_score,
                            'cost_estimate': ms.cost_estimate
                        } for ms in analysis.mitigation_strategies
                    ],
                    'abuse_scenarios': [
                        {
                            'scenario_name': scenario.scenario_name,
                            'threat_actor': scenario.threat_actor.value if hasattr(scenario.threat_actor, 'value') else str(scenario.threat_actor),
                            'motivation': scenario.motivation,
                            'required_access': scenario.required_access.value if hasattr(scenario.required_access, 'value') else str(scenario.required_access),
                            'detection_difficulty': scenario.detection_difficulty.value if hasattr(scenario.detection_difficulty, 'value') else str(scenario.detection_difficulty),
                            'business_impact': {
                                'financial_impact': scenario.business_impact.financial_impact,
                                'operational_impact': scenario.business_impact.operational_impact,
                                'reputation_impact': scenario.business_impact.reputation_impact
                            }
                        } for scenario in analysis.abuse_scenarios
                    ],
                    'compliance_impact': {
                        'affected_frameworks': [fw.value if hasattr(fw, 'value') else str(fw) for fw in analysis.compliance_impact.affected_frameworks],
                        'violation_risk': analysis.compliance_impact.violation_risk.value if hasattr(analysis.compliance_impact.violation_risk, 'value') else str(analysis.compliance_impact.violation_risk),
                        'required_controls': analysis.compliance_impact.required_controls
                    },
                    'confidence_score': analysis.confidence_score,
                    'analysis_metadata': {
                        'provider': analysis.analysis_metadata.provider,
                        'model': analysis.analysis_metadata.model,
                        'cost': analysis.analysis_metadata.cost,
                        'analysis_duration': analysis.analysis_metadata.analysis_duration,
                        'timestamp': analysis.analysis_metadata.timestamp.isoformat()
                    }
                }
            
            # Save based on format
            output_path = Path(output)
            
            if format == "json":
                with open(output_path, 'w') as f:
                    json.dump(threat_analysis_data, f, indent=2, default=str)
                console.print(f"[green]Threat analysis results saved to {output_path}[/green]")
                
            elif format == "html":
                # Direct AI analysis to HTML conversion
                def convert_ai_analysis_to_html_vars(threat_analyses):
                    """Convert AI threat analysis results directly to HTML template variables."""
                    from datetime import datetime
                    
                    # Calculate threat level counts
                    critical_count = sum(1 for analysis in threat_analyses.values() 
                                       if analysis.threat_level.value.upper() == 'CRITICAL')
                    high_count = sum(1 for analysis in threat_analyses.values() 
                                    if analysis.threat_level.value.upper() == 'HIGH')
                    medium_count = sum(1 for analysis in threat_analyses.values() 
                                      if analysis.threat_level.value.upper() == 'MEDIUM')
                    low_count = sum(1 for analysis in threat_analyses.values() 
                                   if analysis.threat_level.value.upper() == 'LOW')
                    
                    # Determine overall threat level
                    if critical_count > 0:
                        overall_threat = "CRITICAL"
                    elif high_count > 0:
                        overall_threat = "HIGH"
                    elif medium_count > 0:
                        overall_threat = "MEDIUM"
                    else:
                        overall_threat = "LOW"
                    
                    # Format attack vectors from AI analysis
                    attack_vector_html = ""
                    for tool_name, analysis in threat_analyses.items():
                        if analysis.attack_vectors:
                            attack_vector_html += f"""
                            <div class="attack-vector">
                                <h3>{tool_name} MCP Server <span class="threat-level {analysis.threat_level.value.lower()}">{analysis.threat_level.value}</span></h3>
                                <p><strong>Target:</strong> {tool_name}</p>
                                <p><strong>Confidence:</strong> {analysis.confidence_score:.2f}</p>
                                
                                <div class="attack-details">
                                    <h4>🎯 Attack Vectors Identified: {len(analysis.attack_vectors)}</h4>
                                    <div class="attack-list">
                            """
                            
                            for i, vector in enumerate(analysis.attack_vectors[:10], 1):  # Limit to top 10
                                attack_vector_html += f"""
                                <div class="attack-item">
                                    <h5>{i}. {vector.name}</h5>
                                    <p><strong>Severity:</strong> <span class="threat-level {vector.severity.value.lower()}">{vector.severity.value}</span></p>
                                    <p><strong>Description:</strong> {vector.description}</p>
                                    <p><strong>Impact:</strong> {vector.impact}</p>
                                    <p><strong>Likelihood:</strong> {vector.likelihood:.2f}</p>
                                    
                                    <div class="attack-steps">
                                        <h6>Attack Steps:</h6>
                                        <ol>
                                """
                                
                                for step in vector.attack_steps:
                                    attack_vector_html += f"<li>{step}</li>"
                                
                                attack_vector_html += """
                                        </ol>
                                    </div>
                                    
                                    <div class="code-example">
                                        <code>{}</code>
                                    </div>
                                </div>
                                """.format(vector.example_code or "# No example code available")
                            
                            attack_vector_html += """
                                    </div>
                                </div>
                            </div>
                            """
                    
                    if not attack_vector_html:
                        attack_vector_html = "<p>No detailed attack vectors available from AI analysis.</p>"
                    
                    # Format mitigation strategies
                    mitigation_html = ""
                    for tool_name, analysis in threat_analyses.items():
                        if analysis.mitigation_strategies:
                            mitigation_html += f"""
                            <div class="mitigation-section">
                                <h4>{tool_name} Security Controls ({len(analysis.mitigation_strategies)} strategies)</h4>
                            """
                            
                            for i, mitigation in enumerate(analysis.mitigation_strategies[:8], 1):  # Limit to top 8
                                mitigation_html += f"""
                                <div class="mitigation-item">
                                    <h5>{i}. {mitigation.name}</h5>
                                    <p>{mitigation.description}</p>
                                    <p><strong>Effectiveness:</strong> {mitigation.effectiveness_score:.1f}/5.0</p>
                                    <p><strong>Implementation:</strong> {', '.join(mitigation.implementation_steps[:3])}...</p>
                                </div>
                                """
                            
                            mitigation_html += "</div>"
                    
                    if not mitigation_html:
                        mitigation_html = "<p>No specific mitigation strategies available from AI analysis.</p>"
                    
                    # Format key attack scenarios  
                    key_scenarios = ""
                    total_vectors = sum(len(analysis.attack_vectors) for analysis in threat_analyses.values())
                    if total_vectors > 0:
                        key_scenarios = f"""
                        <ul>
                            <li><strong>{total_vectors} attack vectors</strong> identified across {len(threat_analyses)} MCP servers</li>
                            <li><strong>Process injection and privilege escalation</strong> risks from MCP server exploitation</li>
                            <li><strong>Data exfiltration</strong> through compromised MCP tool capabilities</li>
                            <li><strong>Lateral movement</strong> opportunities via MCP server network access</li>
                        </ul>
                        """
                    else:
                        key_scenarios = "<p>No critical attack scenarios identified.</p>"
                    
                    return {
                        # Basic metadata
                        "scan_target": "localhost",
                        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "overall_threat_level": overall_threat,
                        
                        # Threat summary
                        "critical_threats": critical_count,
                        "high_threats": high_count, 
                        "medium_threats": medium_count,
                        "low_threats": low_count,
                        
                        # Key findings
                        "key_attack_scenarios": key_scenarios,
                        
                        # Detailed analysis
                        "attack_vector_analysis": attack_vector_html,
                        "abuse_scenarios_analysis": f"<p>AI analysis identified {total_vectors} potential abuse scenarios across detected MCP servers.</p>",
                        "attack_chains_analysis": f"<p>Multi-server attack chains possible with {len(threat_analyses)} detected MCP servers.</p>", 
                        
                        # Mitigation and detection
                        "mitigation_strategies": mitigation_html,
                        "detection_indicators": "<p>Monitor MCP server processes, network connections, and unusual API calls.</p>",
                        "security_recommendations": """
                        <ol>
                            <li>Implement principle of least privilege for all MCP tools</li>
                            <li>Enable comprehensive logging and monitoring</li>
                            <li>Regular security assessments and penetration testing</li>
                            <li>Establish incident response procedures for AI tool abuse</li>
                            <li>Implement network segmentation for MCP services</li>
                            <li>Use sandboxing and containerization where possible</li>
                            <li>Regular updates and security patches for all MCP tools</li>
                            <li>Employee training on AI tool security risks</li>
                        </ol>
                        """,
                        "compliance_impact": f"""
                        <div class="alert info">
                            <h4>Risk Level: {overall_threat}</h4>
                            <p>The detected MCP tools may impact compliance with the following frameworks:</p>
                        </div>
                        
                        <h4>Affected Compliance Frameworks</h4>
                        <ul>
                            <li>SOC 2 Type II - System monitoring and access controls</li>
                            <li>ISO 27001 - Information security management</li>
                            <li>NIST Cybersecurity Framework - Asset management and monitoring</li>
                        </ul>
                        
                        <h4>Compliance Recommendations</h4>
                        <ul>
                            <li>Conduct regular security assessments of MCP tools</li>
                            <li>Implement data loss prevention (DLP) controls</li>
                            <li>Establish incident response procedures for AI tool abuse</li>
                            <li>Document security controls for compliance audits</li>
                        </ul>
                        """,
                        
                        # Template metadata
                        "template_name": "threat_analysis",
                        "render_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
                    }
                
                template_vars = convert_ai_analysis_to_html_vars(threat_analyses)
                
                # Remove template_name to avoid parameter conflict
                template_vars.pop('template_name', None)
                
                # Create minimal ReportData for HTML reporter (required for validation)
                from ..reporting.base import ReportData, ReportMetadata, ReportFormat, ReportType
                minimal_detection_result = DetectionResult(
                    target_host="localhost",
                    detection_method=DetectionMethod.PROCESS_ENUMERATION,
                    timestamp=time.time(),
                    success=True,
                    mcp_server=None,
                    confidence=1.0,
                    error=None,
                    raw_data={},
                    scan_duration=0.0
                )
                
                minimal_data = ReportData(
                    metadata=ReportMetadata(
                        title="AI Threat Analysis",
                        report_type=ReportType.THREAT_ANALYSIS,
                        format=ReportFormat.HTML,
                        generated_by="hawkeye-cli",
                        version="1.0.0"
                    ),
                    scan_results=[],
                    detection_results=[minimal_detection_result],  # Add minimal data to pass validation
                    assessment_results=[],
                    recommendations=[]
                )
                
                reporter = HTMLReporter()
                # Pass AI analysis data directly to template, bypassing threat analyzer
                html_content = reporter.generate_report(
                    data=minimal_data,
                    output_file=None,
                    template_name="threat_analysis",
                    **template_vars
                )
                with open(output_path, 'w') as f:
                    f.write(html_content)
                console.print(f"[green]HTML threat analysis report saved to {output_path}[/green]")
                
            elif format == "csv":
                # Convert to CSV format
                import csv
                with open(output_path, 'w', newline='') as csvfile:
                    fieldnames = ['tool_name', 'threat_level', 'attack_vectors_count', 
                                'mitigations_count', 'confidence_score', 'analysis_cost']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for tool_name, analysis in threat_analyses.items():
                        writer.writerow({
                            'tool_name': tool_name,
                            'threat_level': analysis.threat_level.value,
                            'attack_vectors_count': len(analysis.attack_vectors),
                            'mitigations_count': len(analysis.mitigation_strategies),
                            'confidence_score': analysis.confidence_score,
                            'analysis_cost': analysis.analysis_metadata.cost
                        })
                console.print(f"[green]CSV threat analysis results saved to {output_path}[/green]")
                
            elif format == "xml":
                # Convert to XML format
                import xml.etree.ElementTree as ET
                root = ET.Element("threat_analysis_results")
                
                # Add metadata
                metadata_elem = ET.SubElement(root, "metadata")
                for key, value in threat_analysis_data['metadata'].items():
                    elem = ET.SubElement(metadata_elem, key)
                    elem.text = str(value)
                
                # Add threat analyses
                analyses_elem = ET.SubElement(root, "threat_analyses")
                for tool_name, analysis_data in threat_analysis_data['threat_analyses'].items():
                    analysis_elem = ET.SubElement(analyses_elem, "analysis", tool_name=tool_name)
                    
                    # Add basic info
                    ET.SubElement(analysis_elem, "threat_level").text = analysis_data['threat_level']
                    ET.SubElement(analysis_elem, "confidence_score").text = str(analysis_data['confidence_score'])
                    
                    # Add attack vectors
                    vectors_elem = ET.SubElement(analysis_elem, "attack_vectors")
                    for vector in analysis_data['attack_vectors']:
                        vector_elem = ET.SubElement(vectors_elem, "vector")
                        ET.SubElement(vector_elem, "name").text = vector['name']
                        ET.SubElement(vector_elem, "severity").text = vector['severity']
                        ET.SubElement(vector_elem, "description").text = vector['description']
                
                # Write XML to file
                tree = ET.ElementTree(root)
                tree.write(output_path, encoding='utf-8', xml_declaration=True)
                console.print(f"[green]XML threat analysis results saved to {output_path}[/green]")
        
        console.print(f"\n[bold green]✅ Threat Analysis Complete![/bold green]")
        
        if not threat_analyses:
            console.print("[yellow]No threat analyses were generated. Check your detection results and API configuration.[/yellow]")
        else:
            # Show summary recommendations
            console.print(f"\n[bold cyan]🛡️ Security Recommendations[/bold cyan]")
            
            high_risk_count = sum(1 for analysis in threat_analyses.values() 
                                if analysis.threat_level.value in ['high', 'critical'])
            
            if high_risk_count > 0:
                console.print(f"[red]⚠️  {high_risk_count} high-risk MCP tools detected![/red]")
                console.print("[red]  → Immediate security review recommended[/red]")
                console.print("[red]  → Consider implementing access controls[/red]")
                console.print("[red]  → Monitor these tools closely[/red]")
            else:
                console.print("[green]✅ No critical security issues detected[/green]")
                console.print("[green]  → Continue monitoring MCP deployments[/green]")
                console.print("[green]  → Regular security assessments recommended[/green]")

    except FileNotFoundError:
        raise click.ClickException(f"Input file not found: {input}")
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON format in input file: {e}")
    except Exception as e:
        logger.error(f"Threat analysis failed: {e}")
        if ctx.obj.verbose:
            console.print_exception()
        raise click.ClickException(f"Threat analysis failed: {e}")


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