"""
Integration tests for the complete reporting pipeline.

This module tests the integration of all reporting components including
data aggregation, multi-format generation, and end-to-end workflows.
"""

import pytest
import tempfile
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.hawkeye.reporting.base import (
    ReportData, ReportMetadata, ReportFormat, ReportType, ReportingError
)
from src.hawkeye.reporting.json_reporter import JSONReporter
from src.hawkeye.reporting.csv_reporter import CSVReporter
from src.hawkeye.reporting.xml_reporter import XMLReporter
from src.hawkeye.reporting.html_reporter import HTMLReporter
from src.hawkeye.reporting.executive_summary import ExecutiveSummaryGenerator
from src.hawkeye.reporting.aggregation import DataAggregator
from src.hawkeye.scanner.base import ScanResult, ScanTarget, PortState, ScanType, ServiceInfo
from src.hawkeye.detection.base import (
    DetectionResult, MCPServerInfo, TransportType, MCPServerType, DetectionMethod
)
from src.hawkeye.assessment.base import (
    AssessmentResult, RiskLevel, VulnerabilityCategory, SecurityFinding
)


class TestReportingPipeline:
    """Integration tests for the complete reporting pipeline."""
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata."""
        return ReportMetadata(
            title="Integration Test Security Report",
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.JSON,  # Will be overridden per reporter
            generated_by="integration_test",
            version="1.0.0",
            description="Integration test report",
            author="Test Suite",
            organization="HawkEye Testing",
            classification="Internal"
        )
    
    @pytest.fixture
    def comprehensive_scan_results(self):
        """Create comprehensive scan results for testing."""
        results = []
        hosts = ["192.168.1.100", "192.168.1.101", "10.0.0.50"]
        ports = [80, 443, 3000, 8080, 9000]
        
        for host in hosts:
            target = ScanTarget(host=host, ports=ports)
            for port in ports:
                state = PortState.OPEN if port in [80, 443, 3000] else PortState.CLOSED
                service_info = None
                if state == PortState.OPEN:
                    service_info = ServiceInfo(
                        name="http" if port == 80 else "https" if port == 443 else "mcp" if port == 3000 else None,
                        version="1.1",
                        product="nginx" if port in [80, 443] else "node" if port == 3000 else None,
                        banner=f"Service on {host}:{port}",
                        confidence=0.9
                    )
                
                results.append(ScanResult(
                    target=target,
                    port=port,
                    state=state,
                    scan_type=ScanType.TCP_CONNECT,
                    response_time=50.0 + (port % 100),
                    service_info=service_info
                ))
        
        return results
    
    @pytest.fixture
    def comprehensive_detection_results(self):
        """Create comprehensive detection results for testing."""
        results = []
        hosts = ["192.168.1.100", "192.168.1.101"]
        
        for i, host in enumerate(hosts):
            server_info = MCPServerInfo(
                host=host,
                port=3000,
                transport_type=TransportType.HTTP if i == 0 else TransportType.WEBSOCKET,
                server_type=MCPServerType.STANDALONE,
                version="1.0.0",
                capabilities=["tools", "resources"] if i == 0 else ["tools"]
            )
            
            results.append(DetectionResult(
                target_host=host,
                detection_method=DetectionMethod.PROCESS_ENUMERATION,
                success=True,
                mcp_server=server_info,
                confidence=0.95 - (i * 0.1),
                raw_data={"npm_packages": ["@modelcontextprotocol/server"]}
            ))
        
        return results
    
    @pytest.fixture
    def comprehensive_assessment_results(self):
        """Create comprehensive assessment results for testing."""
        results = []
        hosts = ["192.168.1.100", "192.168.1.101"]
        risk_levels = [RiskLevel.HIGH, RiskLevel.MEDIUM]
        
        for i, (host, risk_level) in enumerate(zip(hosts, risk_levels)):
            findings = []
            
            # Add multiple findings per host
            finding_configs = [
                (VulnerabilityCategory.AUTHENTICATION, "Weak Authentication", "Default credentials detected"),
                (VulnerabilityCategory.ENCRYPTION, "Weak Encryption", "Unencrypted transport detected"),
                (VulnerabilityCategory.CONFIGURATION, "Insecure Configuration", "Debug mode enabled")
            ]
            
            for category, title, description in finding_configs:
                findings.append(SecurityFinding(
                    id=f"FINDING-{len(findings)+1:03d}",
                    category=category,
                    severity=risk_level,
                    title=title,
                    description=description,
                    affected_asset=f"{host}:3000",
                    remediation=f"Fix {title.lower()}",
                    confidence=0.8 + (i * 0.1),
                    references=[f"CWE-{100 + i}"]
                ))
            
            results.append(AssessmentResult(
                target_host=host,
                overall_risk_level=risk_level,
                overall_risk_score=7.5 - (i * 2.0),
                findings=findings,
                assessment_duration=120.5 + (i * 30)
            ))
        
        return results
    
    @pytest.fixture
    def comprehensive_report_data(self, sample_metadata, comprehensive_scan_results,
                                 comprehensive_detection_results, comprehensive_assessment_results):
        """Create comprehensive report data for testing."""
        return ReportData(
            metadata=sample_metadata,
            scan_results=comprehensive_scan_results,
            detection_results=comprehensive_detection_results,
            assessment_results=comprehensive_assessment_results,
            recommendations=[
                "Update all default configurations",
                "Enable strong authentication mechanisms",
                "Implement HTTPS transport for all services",
                "Disable debug mode in production",
                "Regular security assessments"
            ]
        )
    
    def test_all_reporters_generate_valid_output(self, comprehensive_report_data):
        """Test that all reporters can generate valid output from the same data."""
        reporters = [
            JSONReporter(),
            CSVReporter(),
            XMLReporter()
        ]
        
        results = {}
        
        for reporter in reporters:
            # Update metadata format for each reporter
            data = comprehensive_report_data
            data.metadata.format = reporter.get_format()
            
            # Generate report
            result = reporter.generate_report(data)
            results[reporter.get_format().value] = result
            
            # Basic validation
            assert isinstance(result, str)
            assert len(result) > 100  # Should have substantial content
        
        # Verify all formats were generated
        assert ReportFormat.JSON.value in results
        assert ReportFormat.CSV.value in results
        assert ReportFormat.XML.value in results
        
        # Verify JSON is valid
        json_data = json.loads(results[ReportFormat.JSON.value])
        assert "metadata" in json_data
        assert "scan_results" in json_data
        
        # Verify XML is valid
        xml_root = ET.fromstring(results[ReportFormat.XML.value])
        assert xml_root.tag == "hawkeye_report"
        
        # Verify CSV has proper structure
        csv_content = results[ReportFormat.CSV.value]
        assert "# REPORT METADATA" in csv_content
        assert "# SCAN RESULTS" in csv_content
        
        # Note: HTML reporter not implemented yet
    
    def test_multi_format_file_generation(self, comprehensive_report_data):
        """Test generating multiple report formats to files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir)
            
            reporters = [
                (JSONReporter(), "report.json"),
                (CSVReporter(), "report.csv"),
                (XMLReporter(), "report.xml")
            ]
            
            generated_files = []
            
            for reporter, filename in reporters:
                # Update metadata format
                data = comprehensive_report_data
                data.metadata.format = reporter.get_format()
                
                # Generate to file
                output_path = base_path / filename
                result = reporter.generate_report(data, output_path)
                
                # Verify file was created
                assert output_path.exists()
                assert result == str(output_path)
                generated_files.append(output_path)
            
            # Verify all files exist and have content
            for file_path in generated_files:
                assert file_path.exists()
                assert file_path.stat().st_size > 100
                
                # Verify file format specific content
                content = file_path.read_text()
                if file_path.suffix == ".json":
                    json.loads(content)  # Should parse without error
                elif file_path.suffix == ".xml":
                    ET.fromstring(content)  # Should parse without error
                elif file_path.suffix == ".csv":
                    assert "# REPORT METADATA" in content
                # Note: HTML format not implemented yet
    
    def test_data_aggregation_pipeline(self, comprehensive_scan_results,
                                     comprehensive_detection_results,
                                     comprehensive_assessment_results):
        """Test the data aggregation pipeline."""
        aggregator = DataAggregator()
        
        # Test scan data aggregation
        scan_summary = aggregator.aggregate_scan_data(comprehensive_scan_results)
        assert scan_summary.total_ports_scanned > 0
        assert scan_summary.open_ports > 0
        assert scan_summary.services_detected > 0
        assert 0 <= scan_summary.success_rate <= 1
        
        # Test detection data aggregation
        detection_summary = aggregator.aggregate_detection_data(comprehensive_detection_results)
        assert detection_summary.mcp_servers_detected == 2
        assert 0 <= detection_summary.detection_rate <= 1
        assert 0 <= detection_summary.security_rate <= 1
        
        # Test assessment data aggregation
        risk_summary = aggregator.aggregate_assessment_data(comprehensive_assessment_results)
        assert risk_summary.total_assessments == 2
        assert risk_summary.critical_risk_targets >= 0
        assert risk_summary.high_risk_targets >= 0
        assert risk_summary.average_risk_score > 0
    
    def test_executive_summary_generation(self, comprehensive_report_data):
        """Test executive summary generation."""
        generator = ExecutiveSummaryGenerator()
        
        summary = generator.generate_summary(comprehensive_report_data)
        
        assert isinstance(summary, str)
        assert len(summary) > 100
        assert "security assessment" in summary.lower()
        assert "mcp server" in summary.lower()
        
        # Should contain key metrics
        assert any(char.isdigit() for char in summary)  # Should have numbers
    
    def test_end_to_end_reporting_workflow(self, comprehensive_report_data):
        """Test complete end-to-end reporting workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir)
            
            # Step 1: Generate executive summary
            generator = ExecutiveSummaryGenerator()
            executive_summary = generator.generate_summary(comprehensive_report_data)
            comprehensive_report_data.executive_summary = executive_summary
            
            # Step 2: Generate all report formats
            formats_and_reporters = [
                (ReportFormat.JSON, JSONReporter()),
                (ReportFormat.CSV, CSVReporter()),
                (ReportFormat.XML, XMLReporter())
            ]
            
            generated_reports = {}
            
            for format_type, reporter in formats_and_reporters:
                # Update metadata
                data = comprehensive_report_data
                data.metadata.format = format_type
                
                # Generate report
                output_path = base_path / f"report.{format_type.value.lower()}"
                result_path = reporter.generate_report(data, output_path)
                
                generated_reports[format_type] = result_path
                
                # Verify generation
                assert Path(result_path).exists()
            
            # Step 3: Verify all reports contain consistent data
            # Check JSON structure
            json_path = Path(generated_reports[ReportFormat.JSON])
            json_data = json.loads(json_path.read_text())
            
            # Check XML structure
            xml_path = Path(generated_reports[ReportFormat.XML])
            xml_root = ET.fromstring(xml_path.read_text())
            
            # Verify consistent metadata
            assert json_data["metadata"]["title"] == "Integration Test Security Report"
            assert xml_root.find("metadata/title").text == "Integration Test Security Report"
            
            # Verify consistent scan results count
            json_scan_count = len(json_data["scan_results"])
            xml_scan_count = len(xml_root.find("scan_results").findall("scan_result"))
            assert json_scan_count == xml_scan_count
            
            # Verify consistent detection results count
            json_detection_count = len(json_data["detection_results"])
            xml_detection_count = len(xml_root.find("detection_results").findall("detection_result"))
            assert json_detection_count == xml_detection_count
    
    def test_error_handling_across_reporters(self):
        """Test error handling consistency across all reporters."""
        reporters = [
            JSONReporter(),
            CSVReporter(),
            XMLReporter()
        ]
        
        # Test with invalid data
        for reporter in reporters:
            with pytest.raises(ReportingError):
                reporter.generate_report(None)
            
            # Verify error statistics
            stats = reporter.get_generation_statistics()
            assert stats['failed_generations'] >= 1
    
    def test_performance_with_large_dataset(self, sample_metadata):
        """Test reporting performance with large datasets."""
        # Create large dataset
        large_scan_results = []
        for i in range(500):  # Moderate size for integration test
            target = ScanTarget(host=f"192.168.{i//255}.{i%255}", ports=[80])
            large_scan_results.append(ScanResult(
                target=target,
                port=80,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=50.0
            ))
        
        large_data = ReportData(
            metadata=sample_metadata,
            scan_results=large_scan_results,
            detection_results=[],
            assessment_results=[],
            recommendations=[]
        )
        
        # Test all reporters can handle large dataset
        reporters = [JSONReporter(), CSVReporter(), XMLReporter()]
        
        for reporter in reporters:
            large_data.metadata.format = reporter.get_format()
            
            # Should complete without errors
            result = reporter.generate_report(large_data)
            assert isinstance(result, str)
            assert len(result) > 1000  # Should have substantial content
    
    def test_concurrent_report_generation(self, comprehensive_report_data):
        """Test concurrent report generation."""
        import threading
        import time
        
        results = {}
        errors = []
        
        def generate_report(reporter_class, format_name):
            try:
                reporter = reporter_class()
                data = comprehensive_report_data
                data.metadata.format = reporter.get_format()
                
                result = reporter.generate_report(data)
                results[format_name] = result
            except Exception as e:
                errors.append((format_name, str(e)))
        
        # Create threads for concurrent generation
        threads = []
        reporter_configs = [
            (JSONReporter, "json"),
            (CSVReporter, "csv"),
            (XMLReporter, "xml")
        ]
        
        for reporter_class, format_name in reporter_configs:
            thread = threading.Thread(
                target=generate_report,
                args=(reporter_class, format_name)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout
        
        # Verify no errors occurred
        assert len(errors) == 0, f"Errors during concurrent generation: {errors}"
        
        # Verify all reports were generated
        assert len(results) == 3
        for format_name in ["json", "csv", "xml"]:
            assert format_name in results
            assert isinstance(results[format_name], str)
            assert len(results[format_name]) > 100
    
    def test_report_data_consistency(self, comprehensive_report_data):
        """Test that report data remains consistent across different reporters."""
        # Generate reports with all formats
        json_reporter = JSONReporter()
        csv_reporter = CSVReporter()
        xml_reporter = XMLReporter()
        
        # Generate JSON report
        comprehensive_report_data.metadata.format = ReportFormat.JSON
        json_result = json_reporter.generate_report(comprehensive_report_data)
        json_data = json.loads(json_result)
        
        # Generate XML report
        comprehensive_report_data.metadata.format = ReportFormat.XML
        xml_result = xml_reporter.generate_report(comprehensive_report_data)
        xml_root = ET.fromstring(xml_result)
        
        # Verify metadata consistency
        assert json_data["metadata"]["title"] == xml_root.find("metadata/title").text
        assert json_data["metadata"]["author"] == xml_root.find("metadata/author").text
        
        # Verify scan results consistency
        json_scan_hosts = {result["host"] for result in json_data["scan_results"]}
        xml_scan_hosts = {result.find("host").text for result in xml_root.find("scan_results").findall("scan_result")}
        assert json_scan_hosts == xml_scan_hosts
        
        # Verify detection results consistency
        json_detection_hosts = {result["target_host"] for result in json_data["detection_results"]}
        xml_detection_hosts = {result.find("target_host").text for result in xml_root.find("detection_results").findall("detection_result")}
        assert json_detection_hosts == xml_detection_hosts
    
    def test_statistics_aggregation(self, comprehensive_report_data):
        """Test statistics aggregation across multiple report generations."""
        reporter = JSONReporter()
        
        # Generate multiple reports
        for i in range(3):
            comprehensive_report_data.metadata.format = ReportFormat.JSON
            reporter.generate_report(comprehensive_report_data)
        
        # Check aggregated statistics
        stats = reporter.get_generation_statistics()
        assert stats['reports_generated'] == 3
        assert stats['successful_generations'] == 3
        assert stats['failed_generations'] == 0
        assert stats['total_generation_time'] > 0
    
    def test_memory_usage_optimization(self, sample_metadata):
        """Test memory usage with multiple large reports."""
        import gc
        
        # Create moderately large dataset
        large_scan_results = []
        for i in range(200):
            target = ScanTarget(host=f"192.168.{i//255}.{i%255}", ports=[80])
            large_scan_results.append(ScanResult(
                target=target,
                port=80,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=50.0
            ))
        
        large_data = ReportData(
            metadata=sample_metadata,
            scan_results=large_scan_results,
            detection_results=[],
            assessment_results=[],
            recommendations=[]
        )
        
        # Generate multiple reports and ensure memory is managed
        reporter = JSONReporter()
        
        for i in range(5):
            large_data.metadata.format = ReportFormat.JSON
            result = reporter.generate_report(large_data)
            
            # Verify report was generated
            assert isinstance(result, str)
            assert len(result) > 1000
            
            # Force garbage collection
            del result
            gc.collect()
        
        # Should complete without memory issues 