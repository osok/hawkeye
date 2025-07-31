"""
Progress indicators and status display for HawkEye CLI.

This module provides rich progress indicators, status displays, and real-time
feedback for long-running operations like scanning and detection.
"""

import time
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from threading import Lock

from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn,
    TimeElapsedColumn, TimeRemainingColumn, MofNCompleteColumn
)
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.align import Align

from ..utils import get_logger

logger = get_logger(__name__)


class HawkEyeProgress:
    """Enhanced progress tracking for HawkEye operations."""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.progress = None
        self.live = None
        self.tasks = {}
        self.stats = {}
        self.lock = Lock()
        
    def create_progress(self, show_speed: bool = True, show_eta: bool = True) -> Progress:
        """Create a progress instance with HawkEye styling."""
        columns = [
            SpinnerColumn(spinner_style="blue"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="blue", complete_style="green"),
            TaskProgressColumn(),
        ]
        
        if show_speed:
            columns.append(TextColumn("[progress.percentage]{task.speed} ops/s"))
        
        if show_eta:
            columns.extend([
                TimeElapsedColumn(),
                TimeRemainingColumn()
            ])
        
        return Progress(*columns, console=self.console)
    
    @contextmanager
    def scanning_progress(self, total_targets: int, total_ports: int):
        """Context manager for network scanning progress."""
        with self.create_progress() as progress:
            self.progress = progress
            
            # Main scanning task
            scan_task = progress.add_task(
                f"🔍 Scanning {total_targets} targets on {total_ports} ports...",
                total=total_targets * total_ports
            )
            
            # Statistics tracking
            self.stats = {
                'targets_scanned': 0,
                'ports_scanned': 0,
                'open_ports': 0,
                'closed_ports': 0,
                'filtered_ports': 0,
                'start_time': time.time()
            }
            
            try:
                yield ScanProgressTracker(progress, scan_task, self.stats)
            finally:
                self.progress = None
    
    @contextmanager
    def detection_progress(self, total_targets: int):
        """Context manager for MCP detection progress."""
        with self.create_progress() as progress:
            self.progress = progress
            
            # Main detection task
            detect_task = progress.add_task(
                f"🔎 Detecting MCP services on {total_targets} targets...",
                total=total_targets
            )
            
            # Statistics tracking
            self.stats = {
                'targets_analyzed': 0,
                'mcp_services_found': 0,
                'high_confidence': 0,
                'medium_confidence': 0,
                'low_confidence': 0,
                'start_time': time.time()
            }
            
            try:
                yield DetectionProgressTracker(progress, detect_task, self.stats)
            finally:
                self.progress = None
    
    @contextmanager
    def assessment_progress(self, total_services: int):
        """Context manager for security assessment progress."""
        with self.create_progress() as progress:
            self.progress = progress
            
            # Main assessment task
            assess_task = progress.add_task(
                f"🛡️ Assessing {total_services} services...",
                total=total_services
            )
            
            # Statistics tracking
            self.stats = {
                'services_assessed': 0,
                'critical_risks': 0,
                'high_risks': 0,
                'medium_risks': 0,
                'low_risks': 0,
                'start_time': time.time()
            }
            
            try:
                yield AssessmentProgressTracker(progress, assess_task, self.stats)
            finally:
                self.progress = None
    
    @contextmanager
    def reporting_progress(self, total_reports: int):
        """Context manager for report generation progress."""
        with self.create_progress() as progress:
            self.progress = progress
            
            # Main reporting task
            report_task = progress.add_task(
                f"📊 Generating {total_reports} reports...",
                total=total_reports
            )
            
            # Statistics tracking
            self.stats = {
                'reports_generated': 0,
                'total_findings': 0,
                'total_recommendations': 0,
                'start_time': time.time()
            }
            
            try:
                yield ReportingProgressTracker(progress, report_task, self.stats)
            finally:
                self.progress = None
    
    def display_final_summary(self, operation_type: str, stats: Dict[str, Any]):
        """Display final operation summary."""
        elapsed_time = time.time() - stats.get('start_time', time.time())
        
        # Create summary table
        table = Table(title=f"{operation_type} Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        
        # Add operation-specific metrics
        if operation_type == "Scanning":
            table.add_row("Targets Scanned", str(stats.get('targets_scanned', 0)))
            table.add_row("Ports Scanned", str(stats.get('ports_scanned', 0)))
            table.add_row("Open Ports", str(stats.get('open_ports', 0)))
            table.add_row("Closed Ports", str(stats.get('closed_ports', 0)))
            table.add_row("Filtered Ports", str(stats.get('filtered_ports', 0)))
        
        elif operation_type == "Detection":
            table.add_row("Targets Analyzed", str(stats.get('targets_analyzed', 0)))
            table.add_row("MCP Services Found", str(stats.get('mcp_services_found', 0)))
            table.add_row("High Confidence", str(stats.get('high_confidence', 0)))
            table.add_row("Medium Confidence", str(stats.get('medium_confidence', 0)))
            table.add_row("Low Confidence", str(stats.get('low_confidence', 0)))
        
        elif operation_type == "Assessment":
            table.add_row("Services Assessed", str(stats.get('services_assessed', 0)))
            table.add_row("Critical Risks", str(stats.get('critical_risks', 0)))
            table.add_row("High Risks", str(stats.get('high_risks', 0)))
            table.add_row("Medium Risks", str(stats.get('medium_risks', 0)))
            table.add_row("Low Risks", str(stats.get('low_risks', 0)))
        
        elif operation_type == "Reporting":
            table.add_row("Reports Generated", str(stats.get('reports_generated', 0)))
            table.add_row("Total Findings", str(stats.get('total_findings', 0)))
            table.add_row("Total Recommendations", str(stats.get('total_recommendations', 0)))
        
        # Common metrics
        table.add_row("Elapsed Time", f"{elapsed_time:.2f} seconds")
        
        self.console.print(table)


class ProgressTracker:
    """Base class for progress tracking."""
    
    def __init__(self, progress: Progress, task_id: int, stats: Dict[str, Any]):
        self.progress = progress
        self.task_id = task_id
        self.stats = stats
        self.lock = Lock()
    
    def update(self, advance: int = 1, description: Optional[str] = None):
        """Update progress with optional description change."""
        with self.lock:
            if description:
                self.progress.update(self.task_id, description=description)
            self.progress.advance(self.task_id, advance)
    
    def set_description(self, description: str):
        """Update task description."""
        with self.lock:
            self.progress.update(self.task_id, description=description)


class ScanProgressTracker(ProgressTracker):
    """Progress tracker for network scanning operations."""
    
    def update_scan_result(self, target: str, port: int, state: str):
        """Update progress with scan result."""
        with self.lock:
            self.stats['ports_scanned'] += 1
            
            if state == 'open':
                self.stats['open_ports'] += 1
            elif state == 'closed':
                self.stats['closed_ports'] += 1
            elif state == 'filtered':
                self.stats['filtered_ports'] += 1
            
            # Update description with current stats
            description = (
                f"🔍 Scanning... "
                f"Open: {self.stats['open_ports']} | "
                f"Closed: {self.stats['closed_ports']} | "
                f"Filtered: {self.stats['filtered_ports']}"
            )
            
            self.progress.update(self.task_id, description=description)
            self.progress.advance(self.task_id, 1)
    
    def update_target_complete(self, target: str):
        """Mark target as complete."""
        with self.lock:
            self.stats['targets_scanned'] += 1


class DetectionProgressTracker(ProgressTracker):
    """Progress tracker for MCP detection operations."""
    
    def update_detection_result(self, target: str, confidence: float, found_mcp: bool):
        """Update progress with detection result."""
        with self.lock:
            self.stats['targets_analyzed'] += 1
            
            if found_mcp:
                self.stats['mcp_services_found'] += 1
                
                if confidence >= 0.8:
                    self.stats['high_confidence'] += 1
                elif confidence >= 0.5:
                    self.stats['medium_confidence'] += 1
                else:
                    self.stats['low_confidence'] += 1
            
            # Update description with current stats
            description = (
                f"🔎 Detecting... "
                f"Found: {self.stats['mcp_services_found']} | "
                f"High: {self.stats['high_confidence']} | "
                f"Medium: {self.stats['medium_confidence']} | "
                f"Low: {self.stats['low_confidence']}"
            )
            
            self.progress.update(self.task_id, description=description)
            self.progress.advance(self.task_id, 1)


class AssessmentProgressTracker(ProgressTracker):
    """Progress tracker for security assessment operations."""
    
    def update_assessment_result(self, service: str, risk_level: str):
        """Update progress with assessment result."""
        with self.lock:
            self.stats['services_assessed'] += 1
            
            if risk_level == 'critical':
                self.stats['critical_risks'] += 1
            elif risk_level == 'high':
                self.stats['high_risks'] += 1
            elif risk_level == 'medium':
                self.stats['medium_risks'] += 1
            elif risk_level == 'low':
                self.stats['low_risks'] += 1
            
            # Update description with current stats
            description = (
                f"🛡️ Assessing... "
                f"Critical: {self.stats['critical_risks']} | "
                f"High: {self.stats['high_risks']} | "
                f"Medium: {self.stats['medium_risks']} | "
                f"Low: {self.stats['low_risks']}"
            )
            
            self.progress.update(self.task_id, description=description)
            self.progress.advance(self.task_id, 1)


class ReportingProgressTracker(ProgressTracker):
    """Progress tracker for report generation operations."""
    
    def update_report_result(self, report_type: str, findings: int, recommendations: int):
        """Update progress with report generation result."""
        with self.lock:
            self.stats['reports_generated'] += 1
            self.stats['total_findings'] += findings
            self.stats['total_recommendations'] += recommendations
            
            # Update description with current stats
            description = (
                f"📊 Generating... "
                f"Reports: {self.stats['reports_generated']} | "
                f"Findings: {self.stats['total_findings']} | "
                f"Recommendations: {self.stats['total_recommendations']}"
            )
            
            self.progress.update(self.task_id, description=description)
            self.progress.advance(self.task_id, 1)


class StatusDisplay:
    """Real-time status display for HawkEye operations."""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.layout = None
        self.live = None
        
    @contextmanager
    def live_status(self, title: str):
        """Context manager for live status display."""
        # Create layout
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        # Header
        header = Panel(
            Align.center(Text(f"🦅 HawkEye - {title}", style="bold blue")),
            style="blue"
        )
        layout["header"].update(header)
        
        # Footer
        footer = Panel(
            Align.center(Text("Press Ctrl+C to stop", style="dim")),
            style="dim"
        )
        layout["footer"].update(footer)
        
        # Main content (will be updated by caller)
        layout["main"].update(Panel("Initializing...", title="Status"))
        
        with Live(layout, console=self.console, refresh_per_second=4) as live:
            self.layout = layout
            self.live = live
            try:
                yield StatusUpdater(layout, live)
            finally:
                self.layout = None
                self.live = None


class StatusUpdater:
    """Helper class for updating live status display."""
    
    def __init__(self, layout: Layout, live: Live):
        self.layout = layout
        self.live = live
        
    def update_main(self, content):
        """Update main content area."""
        if isinstance(content, str):
            content = Panel(content, title="Status")
        self.layout["main"].update(content)
        
    def update_header(self, title: str):
        """Update header title."""
        header = Panel(
            Align.center(Text(f"🦅 HawkEye - {title}", style="bold blue")),
            style="blue"
        )
        self.layout["header"].update(header)


def create_status_table(stats: Dict[str, Any], operation_type: str) -> Table:
    """Create a status table for live display."""
    table = Table(title=f"{operation_type} Status", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_column("Rate", style="yellow")
    
    elapsed_time = time.time() - stats.get('start_time', time.time())
    
    if operation_type == "Scanning":
        ports_scanned = stats.get('ports_scanned', 0)
        rate = f"{ports_scanned / max(elapsed_time, 1):.1f} ports/s" if elapsed_time > 0 else "0 ports/s"
        
        table.add_row("Targets Scanned", str(stats.get('targets_scanned', 0)), "")
        table.add_row("Ports Scanned", str(ports_scanned), rate)
        table.add_row("Open Ports", str(stats.get('open_ports', 0)), "")
        table.add_row("Closed Ports", str(stats.get('closed_ports', 0)), "")
        table.add_row("Filtered Ports", str(stats.get('filtered_ports', 0)), "")
    
    elif operation_type == "Detection":
        targets_analyzed = stats.get('targets_analyzed', 0)
        rate = f"{targets_analyzed / max(elapsed_time, 1):.1f} targets/s" if elapsed_time > 0 else "0 targets/s"
        
        table.add_row("Targets Analyzed", str(targets_analyzed), rate)
        table.add_row("MCP Services Found", str(stats.get('mcp_services_found', 0)), "")
        table.add_row("High Confidence", str(stats.get('high_confidence', 0)), "")
        table.add_row("Medium Confidence", str(stats.get('medium_confidence', 0)), "")
        table.add_row("Low Confidence", str(stats.get('low_confidence', 0)), "")
    
    table.add_row("Elapsed Time", f"{elapsed_time:.1f}s", "")
    
    return table


# Global progress instance for CLI commands
progress_manager = HawkEyeProgress()