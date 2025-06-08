"""
End-to-end workflow tests for HawkEye security reconnaissance tool.

This module provides comprehensive end-to-end testing of complete HawkEye workflows,
including scanning, detection, assessment, and reporting operations.
"""

import pytest
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from hawkeye.config.settings import get_settings
from hawkeye.scanner.tcp_scanner import TCPScanner
from hawkeye.detection.process_enum import ProcessEnumerator
from hawkeye.detection.config_discovery import ConfigFileDiscovery
from hawkeye.assessment.config_analysis import ConfigurationAnalyzer
from hawkeye.reporting.json_reporter import JSONReporter
from hawkeye.reporting.base import ReportData, ReportMetadata, ReportType, ReportFormat


class TestCompleteWorkflows:
    """Test complete end-to-end workflows."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_complete_localhost_scan_workflow(self):
        """Test complete workflow for localhost scanning."""
        # Step 1: Network scanning
        from hawkeye.scanner.base import ScanTarget
        scanner = TCPScanner(self.settings)
        target = ScanTarget(host="127.0.0.1", ports=[22, 80, 443, 3000])
        scan_results = scanner.scan_target(target)
        
        assert len(scan_results) > 0
        
        # Step 2: MCP detection
        detector = ProcessEnumerator(self.settings)
        detection_result = detector.detect("127.0.0.1")
        
        assert detection_result is not None
        assert detection_result.target_host == "127.0.0.1"
        
        # Step 3: Configuration discovery
        config_detector = ConfigFileDiscovery(self.settings)
        config_result = config_detector.detect("127.0.0.1")
        
        assert config_result is not None
        
        # Step 4: Risk assessment
        assessor = ConfigurationAnalyzer(self.settings)
        assessment_result = assessor.assess(detection_result)
        
        assert assessment_result is not None
        
        # Step 5: Report generation
        metadata = ReportMetadata(
            title="E2E Test Report",
            report_type=ReportType.TECHNICAL_DETAILED,
            format=ReportFormat.JSON
        )
        
        report_data = ReportData(
            metadata=metadata,
            scan_results=scan_results,
            detection_results=[detection_result],
            assessment_results=[assessment_result]
        )
        
        reporter = JSONReporter()
        output_file = self.temp_dir / "e2e_test_report.json"
        result_path = reporter.generate_report(report_data, output_file)
        
        assert output_file.exists()
        assert result_path == str(output_file)
        
        # Read the actual JSON content
        with open(output_file, 'r') as f:
            report_content = f.read()
        
        assert len(report_content) > 0
        
        # Verify report structure
        import json
        report_json = json.loads(report_content)
        assert "metadata" in report_json
        assert "scan_results" in report_json
        assert "detection_results" in report_json
        assert "assessment_results" in report_json
    
    @patch('hawkeye.scanner.tcp_scanner.socket.socket')
    def test_network_scan_to_report_workflow(self, mock_socket):
        """Test workflow from network scan to final report."""
        # Mock successful connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_socket.return_value.__enter__.return_value = mock_sock
        
                 # Step 1: Scan multiple targets
        from hawkeye.scanner.base import ScanTarget
        scanner = TCPScanner(self.settings)
        target_hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        all_scan_results = []
        
        for host in target_hosts:
            target = ScanTarget(host=host, ports=[3000, 8000])
            results = scanner.scan_target(target)
            all_scan_results.extend(results)
        
        assert len(all_scan_results) > 0
        
        # Step 2: Generate comprehensive report
        metadata = ReportMetadata(
            title="Network Scan Report",
            report_type=ReportType.SCAN_RESULTS,
            format=ReportFormat.JSON
        )
        
        report_data = ReportData(
            metadata=metadata,
            scan_results=all_scan_results
        )
        
        reporter = JSONReporter()
        output_file = self.temp_dir / "network_scan_report.json"
        result_path = reporter.generate_report(report_data, output_file)
        
        assert output_file.exists()
        
        # Read the actual JSON content
        with open(output_file, 'r') as f:
            report_content = f.read()
        
                 # Verify report contains all targets
        import json
        report_json = json.loads(report_content)
        scan_targets = {result["host"] for result in report_json["scan_results"]}
        assert scan_targets == set(target_hosts)
    
    @patch('psutil.process_iter')
    def test_detection_to_assessment_workflow(self, mock_process_iter):
        """Test workflow from MCP detection to risk assessment."""
        # Mock Node.js process with MCP indicators
        mock_process = Mock()
        mock_process.info = {
            'pid': 1234,
            'name': 'node',
            'cmdline': ['node', '/path/to/mcp-server.js', '--port', '3000'],
            'cwd': '/home/user/mcp-project',
            'username': 'user',
            'create_time': time.time()
        }
        mock_process.cpu_percent.return_value = 5.0
        mock_process.memory_percent.return_value = 2.5
        mock_process_iter.return_value = [mock_process]
        
        # Step 1: MCP detection
        detector = ProcessEnumerator(self.settings)
        detection_result = detector.detect("127.0.0.1")
        
        assert detection_result.success
        assert detection_result.mcp_server is not None
        
        # Step 2: Risk assessment
        assessor = ConfigurationAnalyzer(self.settings)
        assessment_result = assessor.assess(detection_result)
        
        assert assessment_result is not None
        assert assessment_result.target_host == "127.0.0.1"
        
        # Step 3: Generate assessment report
        metadata = ReportMetadata(
            title="Risk Assessment Report",
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.JSON
        )
        
        report_data = ReportData(
            metadata=metadata,
            detection_results=[detection_result],
            assessment_results=[assessment_result]
        )
        
        reporter = JSONReporter()
        output_file = self.temp_dir / "risk_assessment_report.json"
        result_path = reporter.generate_report(report_data, output_file)
        
        assert output_file.exists()
        
        # Read the actual JSON content
        with open(output_file, 'r') as f:
            report_content = f.read()
        
        # Verify assessment data
        import json
        report_json = json.loads(report_content)
        assert len(report_json["assessment_results"]) == 1
        assert report_json["assessment_results"][0]["target_host"] == "127.0.0.1"


class TestWorkflowPerformance:
    """Test workflow performance and scalability."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    @patch('hawkeye.scanner.tcp_scanner.socket.socket')
    def test_large_scale_scan_performance(self, mock_socket):
        """Test performance with large number of targets."""
        # Mock fast connections
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        # Generate large target list
        targets = [f"192.168.1.{i}" for i in range(1, 51)]  # 50 targets
        ports = [3000, 8000, 8080, 9000]  # 4 ports each
        
        scanner = TCPScanner(self.settings)
        
        start_time = time.time()
        all_results = []
        
        for host in targets:
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host=host, ports=ports)
            results = scanner.scan_target(target)
            all_results.extend(results)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Performance assertions
        assert len(all_results) == len(targets) * len(ports)
        assert scan_duration < 30.0  # Should complete within 30 seconds
        
        # Verify scan statistics
        stats = scanner.get_scan_statistics()
        assert stats['total_scans'] == len(targets) * len(ports)
    
    def test_memory_usage_during_large_workflow(self):
        """Test memory usage during large workflow execution."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Simulate large workflow
        scanner = TCPScanner(self.settings)
        detector = ProcessEnumerator(self.settings)
        
        # Generate many results
        for i in range(100):
            # Create mock scan results
            from hawkeye.scanner.base import ScanResult, PortState, ScanTarget, ScanType
            target = ScanTarget(host=f"192.168.1.{i % 10}", ports=[3000 + i])
            result = ScanResult(
                target=target,
                port=3000 + i,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT
            )
            scanner._results.append(result)
        
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory
        
        # Memory should not increase excessively (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024


class TestWorkflowErrorHandling:
    """Test error handling in complete workflows."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_workflow_with_network_errors(self):
        """Test workflow resilience to network errors."""
        scanner = TCPScanner(self.settings)
        
                 # Test with unreachable host
        from hawkeye.scanner.base import ScanTarget
        target = ScanTarget(host="192.168.255.255", ports=[3000])
        results = scanner.scan_target(target)
        
        # Should handle gracefully
        assert len(results) > 0
        assert all(result.state.name in ["CLOSED", "FILTERED"] for result in results)
    
    def test_workflow_with_detection_failures(self):
        """Test workflow when detection fails."""
        detector = ProcessEnumerator(self.settings)
        
        # Test with invalid host
        result = detector.detect("invalid.host.example")
        
        # Should return failed result, not raise exception
        assert result is not None
        assert not result.success
        assert result.error is not None
    
    def test_workflow_with_assessment_errors(self):
        """Test workflow when assessment encounters errors."""
        from hawkeye.detection.base import DetectionResult, DetectionMethod
        
        # Create invalid detection result
        invalid_result = DetectionResult(
            target_host="test.host",
            detection_method=DetectionMethod.PROCESS_ENUMERATION,
            success=False,
            error="Mock detection failure"
        )
        
        assessor = ConfigurationAnalyzer(self.settings)
        
        # Should handle gracefully
        assessment_result = assessor.assess(invalid_result)
        
        # Assessment should indicate no findings due to failed detection
        assert assessment_result is not None
        assert len(assessment_result.findings) == 0
    
    def test_workflow_with_reporting_errors(self):
        """Test workflow when reporting encounters errors."""
        metadata = ReportMetadata(
            title="Error Test Report",
            report_type=ReportType.TECHNICAL_DETAILED,
            format=ReportFormat.JSON
        )
        
        # Create report data with invalid path
        report_data = ReportData(metadata=metadata)
        
        reporter = JSONReporter()
        
        # Test with invalid output path
        invalid_path = Path("/invalid/path/report.json")
        
        with pytest.raises(Exception):
            reporter.generate_report(report_data, invalid_path)


class TestWorkflowIntegration:
    """Test integration between different workflow components."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
    
    def test_data_flow_between_components(self):
        """Test data flow and compatibility between components."""
                 # Test that scan results can be used by detection
        from hawkeye.scanner.base import ScanResult, PortState, ScanTarget, ScanType
        
        target = ScanTarget(host="127.0.0.1", ports=[3000])
        scan_result = ScanResult(
            target=target,
            port=3000,
            state=PortState.OPEN,
            scan_type=ScanType.TCP_CONNECT
        )
        
        # Detection should be able to use scan results
        detector = ProcessEnumerator(self.settings)
        detection_result = detector.detect(scan_result.target.host)
        
        assert detection_result.target_host == scan_result.target.host
    
    def test_configuration_consistency(self):
        """Test that all components use consistent configuration."""
        scanner = TCPScanner(self.settings)
        detector = ProcessEnumerator(self.settings)
        assessor = ConfigurationAnalyzer(self.settings)
        reporter = JSONReporter()
        
        # All components should have access to same settings
        assert scanner.settings.scan.timeout_seconds == self.settings.scan.timeout_seconds
        assert detector.settings.detection.handshake_timeout == self.settings.detection.handshake_timeout
        assert assessor.settings.assessment.risk_threshold == self.settings.assessment.risk_threshold
    
    def test_logging_integration(self):
        """Test that logging works consistently across workflow."""
        import logging
        from hawkeye.utils.logging import get_logger
        
        # Capture log messages
        log_messages = []
        
        class TestHandler(logging.Handler):
            def emit(self, record):
                log_messages.append(record.getMessage())
        
        # Add test handler to root logger
        test_handler = TestHandler()
        root_logger = logging.getLogger("hawkeye")
        root_logger.addHandler(test_handler)
        root_logger.setLevel(logging.INFO)
        
        try:
            # Execute workflow components
            scanner = TCPScanner(self.settings)
            detector = ProcessEnumerator(self.settings)
            
                         # Should generate log messages
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host="127.0.0.1", ports=[22])
            scanner.scan_target(target)
            detector.detect("127.0.0.1")
            
            # Verify logging occurred
            assert len(log_messages) > 0
            assert any("scan" in msg.lower() for msg in log_messages)
            
        finally:
            root_logger.removeHandler(test_handler) 