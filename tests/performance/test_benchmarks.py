"""
Performance benchmarking tests for HawkEye security reconnaissance tool.

This module provides performance testing and benchmarking capabilities to ensure
HawkEye maintains acceptable performance characteristics under various load conditions.
"""

import pytest
import time
import threading
import statistics
from pathlib import Path
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor, as_completed

from hawkeye.config.settings import get_settings
from hawkeye.scanner.tcp_scanner import TCPScanner
from hawkeye.detection.process_enum import ProcessEnumerator
from hawkeye.assessment.config_analysis import ConfigurationAnalyzer
from hawkeye.reporting.json_reporter import JSONReporter


class TestScannerPerformance:
    """Performance tests for network scanning operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
        
    @patch('hawkeye.scanner.tcp_scanner.socket.socket')
    def test_tcp_scan_throughput(self, mock_socket):
        """Test TCP scanning throughput."""
        # Mock fast successful connections
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        scanner = TCPScanner(self.settings)
        
        # Test parameters
        target_count = 10
        ports_per_target = 10
        targets = [f"192.168.1.{i}" for i in range(1, target_count + 1)]
        ports = list(range(3000, 3000 + ports_per_target))
        
        start_time = time.time()
        
        for host in targets:
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host=host, ports=ports)
            scanner.scan_target(target)
        
        end_time = time.time()
        total_time = end_time - start_time
        total_scans = target_count * ports_per_target
        throughput = total_scans / total_time
        
        # Performance assertions
        assert throughput > 50  # Should scan at least 50 ports per second
        assert total_time < 10.0  # Should complete within 10 seconds
        
        # Verify all scans completed
        stats = scanner.get_scan_statistics()
        assert stats['total_scans'] == total_scans
    
    @patch('hawkeye.scanner.tcp_scanner.socket.socket')
    def test_concurrent_scan_performance(self, mock_socket):
        """Test performance with concurrent scanning."""
        # Mock connections
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        scanner = TCPScanner(self.settings)
        
        # Test concurrent scanning
        targets = [f"192.168.1.{i}" for i in range(1, 21)]  # 20 targets
        ports = [3000, 8000, 8080]
        
        def scan_target_wrapper(host):
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host=host, ports=ports)
            return scanner.scan_target(target)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_target_wrapper, host) for host in targets]
            results = [future.result() for future in as_completed(futures)]
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Performance assertions
        assert total_time < 15.0  # Should complete within 15 seconds
        assert len(results) == len(targets)
        
        # Verify concurrent execution was faster than sequential
        # (This is a rough estimate, actual improvement depends on system)
        expected_sequential_time = len(targets) * len(ports) * 0.1  # Rough estimate
        assert total_time < expected_sequential_time * 0.7  # At least 30% improvement
    
    def test_memory_usage_during_large_scan(self):
        """Test memory usage during large scanning operations."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        scanner = TCPScanner(self.settings)
        
        # Simulate large number of scan results
        from hawkeye.scanner.base import ScanResult, PortState, ScanTarget, ScanType
        
        for i in range(1000):  # 1000 scan results
            target = ScanTarget(host=f"192.168.{i // 256}.{i % 256}", ports=[3000 + (i % 100)])
            result = ScanResult(
                target=target,
                port=3000 + (i % 100),
                state=PortState.OPEN if i % 3 == 0 else PortState.CLOSED,
                scan_type=ScanType.TCP_CONNECT
            )
            scanner._results.append(result)
        
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory
        
        # Memory increase should be reasonable (less than 50MB for 1000 results)
        assert memory_increase < 50 * 1024 * 1024
        
        # Verify all results are stored
        assert len(scanner.get_results()) == 1000


class TestDetectionPerformance:
    """Performance tests for MCP detection operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
    
    @patch('psutil.process_iter')
    def test_process_enumeration_performance(self, mock_process_iter):
        """Test process enumeration performance."""
        # Mock large number of processes
        mock_processes = []
        for i in range(100):  # 100 processes
            mock_process = Mock()
            mock_process.info = {
                'pid': 1000 + i,
                'name': 'node' if i % 10 == 0 else f'process_{i}',
                'cmdline': ['node', f'/app/server_{i}.js'] if i % 10 == 0 else [f'cmd_{i}'],
                'cwd': f'/home/user/app_{i}',
                'username': 'user'
            }
            mock_processes.append(mock_process)
        
        mock_process_iter.return_value = mock_processes
        
        detector = ProcessEnumerator(self.settings)
        
        start_time = time.time()
        result = detector.detect("127.0.0.1")
        end_time = time.time()
        
        detection_time = end_time - start_time
        
        # Performance assertions
        assert detection_time < 5.0  # Should complete within 5 seconds
        assert result is not None
    
    def test_detection_with_multiple_targets(self):
        """Test detection performance with multiple targets."""
        detector = ProcessEnumerator(self.settings)
        
        targets = [f"192.168.1.{i}" for i in range(1, 11)]  # 10 targets
        
        start_time = time.time()
        results = detector.detect_multiple(targets)
        end_time = time.time()
        
        total_time = end_time - start_time
        
        # Performance assertions
        assert total_time < 30.0  # Should complete within 30 seconds
        assert len(results) == len(targets)
        
        # Verify all targets were processed
        target_hosts = {result.target_host for result in results}
        assert target_hosts == set(targets)


class TestAssessmentPerformance:
    """Performance tests for risk assessment operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
    
    def test_assessment_throughput(self):
        """Test risk assessment throughput."""
        from hawkeye.detection.base import DetectionResult, DetectionMethod, MCPServerInfo, TransportType
        
        assessor = ConfigurationAnalyzer(self.settings)
        
        # Create multiple detection results
        detection_results = []
        for i in range(20):  # 20 detection results
            server_info = MCPServerInfo(
                host=f"192.168.1.{i}",
                port=3000 + i,
                transport_type=TransportType.HTTP,
                capabilities=["tool1", "tool2"],
                tools=["test_tool"],
                resources=["test_resource"]
            )
            
            result = DetectionResult(
                target_host=f"192.168.1.{i}",
                detection_method=DetectionMethod.PROCESS_ENUMERATION,
                success=True,
                mcp_server=server_info,
                confidence=0.8
            )
            detection_results.append(result)
        
        start_time = time.time()
        
        assessment_results = []
        for detection_result in detection_results:
            assessment = assessor.assess(detection_result)
            assessment_results.append(assessment)
        
        end_time = time.time()
        total_time = end_time - start_time
        throughput = len(detection_results) / total_time
        
        # Performance assertions
        assert throughput > 5  # Should assess at least 5 targets per second
        assert total_time < 10.0  # Should complete within 10 seconds
        assert len(assessment_results) == len(detection_results)
    
    def test_concurrent_assessment_performance(self):
        """Test performance with concurrent assessments."""
        from hawkeye.detection.base import DetectionResult, DetectionMethod, MCPServerInfo, TransportType
        
        assessor = ConfigurationAnalyzer(self.settings)
        
        # Create detection results
        detection_results = []
        for i in range(10):
            server_info = MCPServerInfo(
                host=f"192.168.1.{i}",
                port=3000,
                transport_type=TransportType.HTTP
            )
            
            result = DetectionResult(
                target_host=f"192.168.1.{i}",
                detection_method=DetectionMethod.PROCESS_ENUMERATION,
                success=True,
                mcp_server=server_info,
                confidence=0.8
            )
            detection_results.append(result)
        
        def assess_wrapper(detection_result):
            return assessor.assess(detection_result)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(assess_wrapper, result) for result in detection_results]
            assessment_results = [future.result() for future in as_completed(futures)]
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Performance assertions
        assert total_time < 15.0  # Should complete within 15 seconds
        assert len(assessment_results) == len(detection_results)


class TestReportingPerformance:
    """Performance tests for report generation operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
    
    def test_large_report_generation_performance(self):
        """Test performance with large report generation."""
        from hawkeye.reporting.base import ReportData, ReportMetadata, ReportType, ReportFormat
        from hawkeye.scanner.base import ScanResult, PortState, ScanTarget, ScanType
        from hawkeye.detection.base import DetectionResult, DetectionMethod
        
        # Create large dataset
        scan_results = []
        detection_results = []
        
        for i in range(500):  # 500 results each
            # Scan results
            target = ScanTarget(host=f"192.168.{i // 256}.{i % 256}", ports=[3000 + (i % 100)])
            scan_result = ScanResult(
                target=target,
                port=3000 + (i % 100),
                state=PortState.OPEN if i % 3 == 0 else PortState.CLOSED,
                scan_type=ScanType.TCP_CONNECT
            )
            scan_results.append(scan_result)
            
            # Detection results
            detection_result = DetectionResult(
                target_host=f"192.168.{i // 256}.{i % 256}",
                detection_method=DetectionMethod.PROCESS_ENUMERATION,
                success=i % 4 == 0,  # 25% success rate
                confidence=0.7 if i % 4 == 0 else 0.0
            )
            detection_results.append(detection_result)
        
        metadata = ReportMetadata(
            title="Large Performance Test Report",
            report_type=ReportType.TECHNICAL_DETAILED,
            format=ReportFormat.JSON
        )
        
        report_data = ReportData(
            metadata=metadata,
            scan_results=scan_results,
            detection_results=detection_results
        )
        
        reporter = JSONReporter()
        
        start_time = time.time()
        report_content = reporter.generate_report(report_data)
        end_time = time.time()
        
        generation_time = end_time - start_time
        
        # Performance assertions
        assert generation_time < 10.0  # Should complete within 10 seconds
        assert len(report_content) > 0
        
        # Verify report contains all data
        import json
        report_json = json.loads(report_content)
        assert len(report_json["scan_results"]) == 500
        assert len(report_json["detection_results"]) == 500
    
    def test_multiple_format_generation_performance(self):
        """Test performance when generating multiple report formats."""
        from hawkeye.reporting.base import ReportData, ReportMetadata, ReportType, ReportFormat
        from hawkeye.reporting.csv_reporter import CSVReporter
        from hawkeye.reporting.xml_reporter import XMLReporter
        from hawkeye.scanner.base import ScanResult, PortState, ScanTarget, ScanType
        
        # Create moderate dataset
        scan_results = []
        for i in range(100):
            target = ScanTarget(host=f"192.168.1.{i % 10}", ports=[3000 + i])
            result = ScanResult(
                target=target,
                port=3000 + i,
                state=PortState.OPEN if i % 2 == 0 else PortState.CLOSED,
                scan_type=ScanType.TCP_CONNECT
            )
            scan_results.append(result)
        
        metadata_json = ReportMetadata(
            title="Multi-Format Test Report",
            report_type=ReportType.SCAN_RESULTS,
            format=ReportFormat.JSON
        )
        
        metadata_csv = ReportMetadata(
            title="Multi-Format Test Report",
            report_type=ReportType.SCAN_RESULTS,
            format=ReportFormat.CSV
        )
        
        metadata_xml = ReportMetadata(
            title="Multi-Format Test Report",
            report_type=ReportType.SCAN_RESULTS,
            format=ReportFormat.XML
        )
        
        report_data_json = ReportData(metadata=metadata_json, scan_results=scan_results)
        report_data_csv = ReportData(metadata=metadata_csv, scan_results=scan_results)
        report_data_xml = ReportData(metadata=metadata_xml, scan_results=scan_results)
        
        reporters = [
            (JSONReporter(), report_data_json),
            (CSVReporter(), report_data_csv),
            (XMLReporter(), report_data_xml)
        ]
        
        start_time = time.time()
        
        for reporter, data in reporters:
            content = reporter.generate_report(data)
            assert len(content) > 0
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Performance assertions
        assert total_time < 15.0  # Should complete all formats within 15 seconds


class TestSystemResourceUsage:
    """Test system resource usage during operations."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
    
    def test_cpu_usage_during_intensive_operations(self):
        """Test CPU usage during intensive operations."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Measure CPU usage during intensive scanning
        scanner = TCPScanner(self.settings)
        
        # Start CPU monitoring
        cpu_percentages = []
        
        def monitor_cpu():
            for _ in range(10):  # Monitor for 10 intervals
                cpu_percentages.append(process.cpu_percent(interval=0.1))
        
        # Start monitoring in background
        monitor_thread = threading.Thread(target=monitor_cpu)
        monitor_thread.start()
        
        # Perform intensive operations
        target_hosts = [f"127.0.0.{i}" for i in range(1, 11)]
        ports = list(range(3000, 3010))
        
        for host in target_hosts:
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host=host, ports=ports)
            scanner.scan_target(target)
        
        monitor_thread.join()
        
        # Analyze CPU usage
        if cpu_percentages:
            avg_cpu = statistics.mean(cpu_percentages)
            max_cpu = max(cpu_percentages)
            
            # CPU usage should be reasonable (not constantly at 100%)
            assert avg_cpu < 80.0  # Average should be less than 80%
            assert max_cpu < 95.0  # Peak should be less than 95%
    
    def test_file_descriptor_usage(self):
        """Test file descriptor usage during operations."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
        
        scanner = TCPScanner(self.settings)
        
        # Perform operations that might leak file descriptors
        for i in range(50):
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host="127.0.0.1", ports=[22, 80, 443])
            scanner.scan_target(target)
        
        final_fds = process.num_fds() if hasattr(process, 'num_fds') else 0
        
        # File descriptor count should not increase significantly
        if initial_fds > 0:  # Only test if we can measure FDs
            fd_increase = final_fds - initial_fds
            assert fd_increase < 10  # Should not leak more than 10 FDs


class TestScalabilityBenchmarks:
    """Scalability benchmarks for different load levels."""
    
    def setup_method(self):
        """Set up test environment."""
        self.settings = get_settings()
    
    @pytest.mark.parametrize("target_count,port_count", [
        (10, 10),    # Small scale
        (50, 20),    # Medium scale
        (100, 50),   # Large scale
    ])
    @patch('hawkeye.scanner.tcp_scanner.socket.socket')
    def test_scanning_scalability(self, mock_socket, target_count, port_count):
        """Test scanning scalability with different load levels."""
        # Mock connections
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        scanner = TCPScanner(self.settings)
        
        target_hosts = [f"192.168.1.{i % 255}" for i in range(target_count)]
        ports = list(range(3000, 3000 + port_count))
        
        start_time = time.time()
        
        for host in target_hosts:
            from hawkeye.scanner.base import ScanTarget
            target = ScanTarget(host=host, ports=ports)
            scanner.scan_target(target)
        
        end_time = time.time()
        total_time = end_time - start_time
        total_operations = target_count * port_count
        throughput = total_operations / total_time
        
        # Scalability assertions (throughput should remain reasonable)
        if target_count <= 10:
            assert throughput > 20  # Small scale: >20 ops/sec
        elif target_count <= 50:
            assert throughput > 15  # Medium scale: >15 ops/sec
        else:
            assert throughput > 10  # Large scale: >10 ops/sec
        
        # Time should scale reasonably
        expected_max_time = total_operations * 0.1  # 0.1 sec per operation
        assert total_time < expected_max_time 