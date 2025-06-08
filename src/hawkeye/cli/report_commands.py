"""
Report command group for HawkEye CLI.

This module implements report generation and output formatting commands including
multi-format report generation, executive summaries, and data aggregation.
"""

import sys
from pathlib import Path
from typing import Optional, List
import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel

from ..reporting.json_reporter import JSONReporter
from ..reporting.csv_reporter import CSVReporter
from ..reporting.xml_reporter import XMLReporter
from ..reporting.html_reporter import HTMLReporter
from ..reporting.executive_summary import ExecutiveSummaryGenerator
from ..reporting.aggregation import DataAggregator
from ..reporting.base import ReportData, ReportMetadata, ReportFormat, ReportType
from ..exceptions import HawkEyeError, ReportingError
from ..utils import get_logger

console = Console()
logger = get_logger(__name__)


@click.group()
def report():
    """Report generation and output formatting operations."""
    pass


@report.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True),
    required=True,
    help="Input file containing scan/detection results"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    required=True,
    help="Output file path for generated report"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml", "html"]),
    required=True,
    help="Output format for the report"
)
@click.option(
    "--title",
    default="HawkEye Security Assessment Report",
    help="Report title (default: HawkEye Security Assessment Report)"
)
@click.option(
    "--author",
    default="HawkEye Security Team",
    help="Report author (default: HawkEye Security Team)"
)
@click.option(
    "--organization",
    default="Security Assessment Team",
    help="Organization name (default: Security Assessment Team)"
)
@click.option(
    "--classification",
    type=click.Choice(["Public", "Internal", "Confidential", "Restricted"]),
    default="Internal",
    help="Report classification level (default: Internal)"
)
@click.option(
    "--template",
    type=click.Path(exists=True),
    help="Custom template file for HTML reports"
)
@click.pass_context
def generate(ctx, input: str, output: str, format: str, title: str, author: str,
             organization: str, classification: str, template: Optional[str]):
    """
    Generate report from scan/detection results.
    
    Converts raw scan and detection data into formatted reports with
    comprehensive analysis and recommendations.
    
    Examples:
    \b
        hawkeye report generate -i results.json -o report.html -f html
        hawkeye report generate -i scan_data.json -o summary.csv -f csv
        hawkeye report generate -i detection.json -o report.xml -f xml --title "Security Assessment"
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Report Generation[/bold blue]")
        console.print(f"Input: {input}")
        console.print(f"Output: {output}")
        console.print(f"Format: {format.upper()}")
        console.print(f"Title: {title}")
        console.print()
        
        # Load input data
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Loading input data...", total=4)
            
            # Load and parse input file
            input_data = load_input_data(input)
            progress.advance(task, 1)
            
            # Convert dictionary data to objects
            converted_data = convert_dict_data_to_objects(input_data)
            
            # Create report metadata
            metadata = ReportMetadata(
                title=title,
                report_type=ReportType.RISK_ASSESSMENT,
                format=ReportFormat(format.lower()),
                generated_by="hawkeye-cli",
                version="1.0.0",
                description=f"Security assessment report generated from {input}",
                author=author,
                organization=organization,
                classification=classification
            )
            progress.advance(task, 1)
            
            # Create report data
            report_data = ReportData(
                metadata=metadata,
                scan_results=converted_data.get('scan_results', []),
                detection_results=converted_data.get('detection_results', []),
                assessment_results=converted_data.get('assessment_results', []),
                recommendations=converted_data.get('recommendations', [])
            )
            progress.advance(task, 1)
            
            # Generate report
            progress.update(task, description=f"Generating {format.upper()} report...")
            
            if format == "json":
                reporter = JSONReporter()
            elif format == "csv":
                reporter = CSVReporter()
            elif format == "xml":
                reporter = XMLReporter()
            elif format == "html":
                reporter = HTMLReporter()
                if template:
                    reporter.set_template(Path(template))
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            reporter.generate_report(report_data, Path(output))
            progress.advance(task, 1)
        
        # Display generation summary
        display_generation_summary(report_data, output, format)
        
        console.print(f"\n[green]Report successfully generated: {output}[/green]")
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise click.ClickException(f"Report generation failed: {e}")


@report.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True),
    required=True,
    help="Input file containing assessment results"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    required=True,
    help="Output file path for executive summary"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["html", "pdf", "docx"]),
    default="html",
    help="Output format for executive summary (default: html)"
)
@click.option(
    "--include-charts/--no-include-charts",
    default=True,
    help="Include charts and visualizations"
)
@click.option(
    "--include-recommendations/--no-include-recommendations",
    default=True,
    help="Include detailed recommendations"
)
@click.option(
    "--risk-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum risk level to include (default: medium)"
)
@click.pass_context
def summary(ctx, input: str, output: str, format: str, include_charts: bool,
            include_recommendations: bool, risk_threshold: str):
    """
    Generate executive summary from assessment results.
    
    Creates a high-level executive summary with key findings,
    risk metrics, and strategic recommendations.
    
    Examples:
    \b
        hawkeye report summary -i assessment.json -o summary.html
        hawkeye report summary -i results.json -o executive.pdf -f pdf
        hawkeye report summary -i data.json -o brief.html --risk-threshold high
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Executive Summary[/bold blue]")
        console.print(f"Input: {input}")
        console.print(f"Output: {output}")
        console.print(f"Format: {format.upper()}")
        console.print(f"Risk Threshold: {risk_threshold.upper()}")
        console.print()
        
        # Load input data
        input_data = load_input_data(input)
        
        # Initialize summary generator
        summary_generator = ExecutiveSummaryGenerator()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Generating executive summary...", total=3)
            
            # Analyze data
            progress.update(task, description="Analyzing assessment data...")
            analysis_results = summary_generator.analyze_assessment_data(input_data)
            progress.advance(task, 1)
            
            # Generate summary
            progress.update(task, description="Creating executive summary...")
            summary_data = summary_generator.generate_summary(
                analysis_results,
                include_charts=include_charts,
                include_recommendations=include_recommendations,
                risk_threshold=risk_threshold
            )
            progress.advance(task, 1)
            
            # Export summary
            progress.update(task, description=f"Exporting {format.upper()} summary...")
            summary_generator.export_summary(summary_data, Path(output), format)
            progress.advance(task, 1)
        
        # Display summary statistics
        display_summary_statistics(analysis_results)
        
        console.print(f"\n[green]Executive summary generated: {output}[/green]")
        
    except Exception as e:
        logger.error(f"Summary generation failed: {e}")
        raise click.ClickException(f"Summary generation failed: {e}")


@report.command()
@click.option(
    "--input", "-i",
    type=click.Path(exists=True),
    required=True,
    help="Input file containing raw results"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path for aggregated data (optional)"
)
@click.option(
    "--group-by",
    type=click.Choice(["host", "port", "service", "risk_level", "detection_method"]),
    default="host",
    help="Grouping criteria for aggregation (default: host)"
)
@click.option(
    "--include-statistics/--no-include-statistics",
    default=True,
    help="Include statistical analysis"
)
@click.option(
    "--include-trends/--no-include-trends",
    default=True,
    help="Include trend analysis"
)
@click.pass_context
def aggregate(ctx, input: str, output: Optional[str], group_by: str,
              include_statistics: bool, include_trends: bool):
    """
    Aggregate and analyze scan/detection data.
    
    Performs data aggregation, statistical analysis, and trend identification
    to provide insights into the security assessment results.
    
    Examples:
    \b
        hawkeye report aggregate -i results.json --group-by host
        hawkeye report aggregate -i data.json -o aggregated.json --group-by risk_level
        hawkeye report aggregate -i scan.json --group-by service --include-trends
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Data Aggregation[/bold blue]")
        console.print(f"Input: {input}")
        console.print(f"Group By: {group_by}")
        console.print(f"Statistics: {'Enabled' if include_statistics else 'Disabled'}")
        console.print(f"Trends: {'Enabled' if include_trends else 'Disabled'}")
        console.print()
        
        # Load input data
        input_data = load_input_data(input)
        
        # Initialize aggregator
        aggregator = DataAggregator()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Aggregating data...", total=4)
            
            # Aggregate data
            progress.update(task, description="Grouping data...")
            aggregated_data = aggregator.aggregate_by_criteria(input_data, group_by)
            progress.advance(task, 1)
            
            # Statistical analysis
            statistics = None
            if include_statistics:
                progress.update(task, description="Computing statistics...")
                statistics = aggregator.compute_statistics(aggregated_data)
                progress.advance(task, 1)
            else:
                progress.advance(task, 1)
            
            # Trend analysis
            trends = None
            if include_trends:
                progress.update(task, description="Analyzing trends...")
                trends = aggregator.analyze_trends(aggregated_data)
                progress.advance(task, 1)
            else:
                progress.advance(task, 1)
            
            # Prepare output
            progress.update(task, description="Preparing output...")
            output_data = {
                'aggregated_data': aggregated_data,
                'statistics': statistics,
                'trends': trends,
                'metadata': {
                    'group_by': group_by,
                    'total_records': len(input_data.get('scan_results', []) + input_data.get('detection_results', [])),
                    'groups': len(aggregated_data)
                }
            }
            progress.advance(task, 1)
        
        # Display aggregation results
        display_aggregation_results(output_data, group_by)
        
        # Save output if specified
        if output:
            with open(output, 'w') as f:
                json.dump(output_data, f, indent=2, default=str)
            console.print(f"\n[green]Aggregated data saved: {output}[/green]")
        
    except Exception as e:
        logger.error(f"Data aggregation failed: {e}")
        raise click.ClickException(f"Data aggregation failed: {e}")


@report.command()
@click.option(
    "--input-dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    required=True,
    help="Directory containing multiple result files"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    required=True,
    help="Output file path for combined report"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "csv", "xml", "html"]),
    default="html",
    help="Output format for combined report (default: html)"
)
@click.option(
    "--merge-strategy",
    type=click.Choice(["append", "merge", "deduplicate"]),
    default="deduplicate",
    help="Strategy for combining multiple files (default: deduplicate)"
)
@click.pass_context
def combine(ctx, input_dir: str, output: str, format: str, merge_strategy: str):
    """
    Combine multiple result files into a single report.
    
    Merges multiple scan and detection result files from different
    assessments into a comprehensive combined report.
    
    Examples:
    \b
        hawkeye report combine --input-dir ./results -o combined.html
        hawkeye report combine --input-dir /data/scans -o merged.json -f json
        hawkeye report combine --input-dir ./assessments -o report.xml --merge-strategy append
    """
    try:
        console.print(f"[bold blue]🦅 HawkEye Report Combination[/bold blue]")
        console.print(f"Input Directory: {input_dir}")
        console.print(f"Output: {output}")
        console.print(f"Format: {format.upper()}")
        console.print(f"Merge Strategy: {merge_strategy}")
        console.print()
        
        # Discover input files
        input_path = Path(input_dir)
        result_files = list(input_path.glob("*.json")) + list(input_path.glob("*.csv")) + list(input_path.glob("*.xml"))
        
        if not result_files:
            raise click.ClickException(f"No result files found in {input_dir}")
        
        console.print(f"Found {len(result_files)} result files")
        
        combined_data = {
            'scan_results': [],
            'detection_results': [],
            'assessment_results': [],
            'recommendations': []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Combining files...", total=len(result_files) + 2)
            
            # Load and combine all files
            for file_path in result_files:
                progress.update(task, description=f"Loading {file_path.name}...")
                try:
                    file_data = load_input_data(str(file_path))
                    
                    # Merge data based on strategy
                    if merge_strategy == "append":
                        for key in combined_data:
                            combined_data[key].extend(file_data.get(key, []))
                    elif merge_strategy == "merge":
                        # Merge with conflict resolution
                        combined_data = merge_data_with_resolution(combined_data, file_data)
                    elif merge_strategy == "deduplicate":
                        # Deduplicate based on key fields
                        combined_data = deduplicate_data(combined_data, file_data)
                    
                except Exception as e:
                    logger.warning(f"Failed to load {file_path}: {e}")
                
                progress.advance(task, 1)
            
            # Create combined report metadata
            progress.update(task, description="Creating combined report...")
            metadata = ReportMetadata(
                title="HawkEye Combined Security Assessment Report",
                report_type=ReportType.RISK_ASSESSMENT,
                format=ReportFormat(format.lower()),
                generated_by="hawkeye-cli",
                version="1.0.0",
                description=f"Combined report from {len(result_files)} assessment files",
                author="HawkEye Security Team",
                organization="Security Assessment Team",
                classification="Internal"
            )
            
            report_data = ReportData(
                metadata=metadata,
                scan_results=combined_data['scan_results'],
                detection_results=combined_data['detection_results'],
                assessment_results=combined_data['assessment_results'],
                recommendations=combined_data['recommendations']
            )
            progress.advance(task, 1)
            
            # Generate combined report
            progress.update(task, description=f"Generating {format.upper()} report...")
            
            if format == "json":
                reporter = JSONReporter()
            elif format == "csv":
                reporter = CSVReporter()
            elif format == "xml":
                reporter = XMLReporter()
            elif format == "html":
                reporter = HTMLReporter()
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            reporter.generate_report(report_data, Path(output))
            progress.advance(task, 1)
        
        # Display combination summary
        display_combination_summary(combined_data, len(result_files))
        
        console.print(f"\n[green]Combined report generated: {output}[/green]")
        
    except Exception as e:
        logger.error(f"Report combination failed: {e}")
        raise click.ClickException(f"Report combination failed: {e}")


def load_input_data(file_path: str) -> dict:
    """Load and parse input data file."""
    path = Path(file_path)
    
    if path.suffix.lower() == '.json':
        with open(path, 'r') as f:
            return json.load(f)
    elif path.suffix.lower() == '.csv':
        # Convert CSV to dict format
        import pandas as pd
        df = pd.read_csv(path)
        return {'scan_results': df.to_dict('records')}
    elif path.suffix.lower() == '.xml':
        # Parse XML to dict format
        import xml.etree.ElementTree as ET
        tree = ET.parse(path)
        root = tree.getroot()
        # Simplified XML parsing - would need more sophisticated parsing in practice
        return {'scan_results': []}
    else:
        raise ValueError(f"Unsupported file format: {path.suffix}")


def convert_dict_data_to_objects(input_data: dict) -> dict:
    """Convert dictionary data back to proper objects for reporting."""
    from ..scanner.base import ScanResult, ScanTarget, PortState, ScanType
    from ..detection.base import DetectionResult, DetectionMethod
    from ..assessment.base import AssessmentResult, RiskLevel, VulnerabilityCategory
    
    converted_data = {
        'scan_results': [],
        'detection_results': [],
        'assessment_results': [],
        'recommendations': input_data.get('recommendations', [])
    }
    
    # Convert scan results
    for scan_dict in input_data.get('scan_results', []):
        try:
            # Create ScanTarget (without port - port is separate in ScanResult)
            target = ScanTarget(
                host=scan_dict['host'],
                ports=[scan_dict['port']]  # ScanTarget expects a list of ports
            )
            
            # Create ScanResult
            scan_result = ScanResult(
                target=target,
                port=scan_dict['port'],  # Port is separate parameter
                state=PortState(scan_dict['state']),
                scan_type=ScanType(scan_dict['scan_type']),
                timestamp=scan_dict['timestamp'],
                response_time=scan_dict.get('response_time'),
                error=scan_dict.get('error'),
                raw_data=scan_dict.get('raw_data', {})
            )
            converted_data['scan_results'].append(scan_result)
        except Exception as e:
            logger.warning(f"Failed to convert scan result: {e}")
    
    # Convert detection results
    for detection_dict in input_data.get('detection_results', []):
        try:
            detection_result = DetectionResult(
                target_host=detection_dict['target_host'],
                detection_method=DetectionMethod(detection_dict['detection_method']),
                timestamp=detection_dict['timestamp'],
                success=detection_dict.get('success', False),
                confidence=detection_dict.get('confidence', 0.0),
                error=detection_dict.get('error'),
                raw_data=detection_dict.get('raw_data', {})
            )
            converted_data['detection_results'].append(detection_result)
        except Exception as e:
            logger.warning(f"Failed to convert detection result: {e}")
    
    # Convert assessment results
    for assessment_dict in input_data.get('assessment_results', []):
        try:
            assessment_result = AssessmentResult(
                target_host=assessment_dict['target_host'],
                overall_risk_level=RiskLevel(assessment_dict['overall_risk_level']),
                risk_score=assessment_dict.get('risk_score', 0.0),
                timestamp=assessment_dict['timestamp'],
                findings=assessment_dict.get('findings', []),
                recommendations=assessment_dict.get('recommendations', []),
                raw_data=assessment_dict.get('raw_data', {})
            )
            converted_data['assessment_results'].append(assessment_result)
        except Exception as e:
            logger.warning(f"Failed to convert assessment result: {e}")
    
    return converted_data


def display_generation_summary(report_data: ReportData, output_path: str, format: str):
    """Display report generation summary."""
    table = Table(title="Report Generation Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Count", style="green")
    
    table.add_row("Scan Results", str(len(report_data.scan_results)))
    table.add_row("Detection Results", str(len(report_data.detection_results)))
    table.add_row("Assessment Results", str(len(report_data.assessment_results)))
    table.add_row("Recommendations", str(len(report_data.recommendations)))
    table.add_row("Output Format", format.upper())
    table.add_row("Output File", output_path)
    
    console.print(table)


def display_summary_statistics(analysis_results: dict):
    """Display executive summary statistics."""
    panel_content = f"""
[bold]Risk Distribution:[/bold]
• Critical: {analysis_results.get('critical_risks', 0)}
• High: {analysis_results.get('high_risks', 0)}
• Medium: {analysis_results.get('medium_risks', 0)}
• Low: {analysis_results.get('low_risks', 0)}

[bold]Key Findings:[/bold]
• Total Hosts Scanned: {analysis_results.get('total_hosts', 0)}
• Services Detected: {analysis_results.get('services_detected', 0)}
• Vulnerabilities Found: {analysis_results.get('vulnerabilities', 0)}
• Recommendations Generated: {analysis_results.get('recommendations', 0)}
    """
    
    console.print(Panel(panel_content, title="Executive Summary Statistics", border_style="blue"))


def display_aggregation_results(output_data: dict, group_by: str):
    """Display data aggregation results."""
    metadata = output_data['metadata']
    
    table = Table(title="Data Aggregation Results", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    
    table.add_row("Grouping Criteria", group_by.title())
    table.add_row("Total Records", str(metadata['total_records']))
    table.add_row("Groups Created", str(metadata['groups']))
    
    if output_data.get('statistics'):
        stats = output_data['statistics']
        table.add_row("Average per Group", f"{stats.get('average_per_group', 0):.2f}")
        table.add_row("Largest Group", str(stats.get('largest_group_size', 0)))
        table.add_row("Smallest Group", str(stats.get('smallest_group_size', 0)))
    
    console.print(table)


def display_combination_summary(combined_data: dict, file_count: int):
    """Display report combination summary."""
    table = Table(title="Report Combination Summary", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Count", style="green")
    
    table.add_row("Files Combined", str(file_count))
    table.add_row("Total Scan Results", str(len(combined_data['scan_results'])))
    table.add_row("Total Detection Results", str(len(combined_data['detection_results'])))
    table.add_row("Total Assessment Results", str(len(combined_data['assessment_results'])))
    table.add_row("Total Recommendations", str(len(combined_data['recommendations'])))
    
    console.print(table)


def merge_data_with_resolution(data1: dict, data2: dict) -> dict:
    """Merge two data dictionaries with conflict resolution."""
    # Simplified merge - in practice would need sophisticated conflict resolution
    merged = data1.copy()
    for key in data2:
        if key in merged:
            merged[key].extend(data2[key])
        else:
            merged[key] = data2[key]
    return merged


def deduplicate_data(data1: dict, data2: dict) -> dict:
    """Deduplicate data when combining."""
    # Simplified deduplication - in practice would need field-based deduplication
    merged = data1.copy()
    for key in data2:
        if key in merged:
            # Simple deduplication by converting to set (would need more sophisticated logic)
            existing_items = {str(item) for item in merged[key]}
            for item in data2[key]:
                if str(item) not in existing_items:
                    merged[key].append(item)
        else:
            merged[key] = data2[key]
    return merged