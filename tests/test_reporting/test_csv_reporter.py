"""
Unit tests for CSV report generator.

This module tests the CSV report generation functionality including
data formatting, file output, and error handling.
"""

import csv
import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from io import StringIO
from unittest.mock import Mock, patch, MagicMock

from src.hawkeye.reporting.csv_reporter import CSVReporter
from src.hawkeye.reporting.base import (
    ReportData, ReportMetadata, ReportFormat, ReportType, ReportingError
)
from src.hawkeye.scanner.base import ScanResult, ScanTarget, PortState, ScanType
from src.hawkeye.detection.base import (
    DetectionResult, MCPServerInfo, TransportType, MCPServerType
)
from src.hawkeye.assessment.base import (
    AssessmentResult, RiskLevel, VulnerabilityCategory, SecurityFinding
)


class TestCSVReporter:
    """Test cases for CSV reporter."""
    
    @pytest.fixture
    def reporter(self):
        """Create CSV reporter instance."""
        return CSVReporter()
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata."""
        return ReportMetadata(
            title="Test Security Report",
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.CSV,
            generated_by="test_user",
            version="1.0.0",
            description="Test report description",
            author="Test Author",
            organization="Test Org",
            classification="Internal"
        )
    
    @pytest.fixture
    def sample_scan_results(self):
        """Create sample scan results."""
        from src.hawkeye.scanner.base import ServiceInfo
        target = ScanTarget(host="192.168.1.100", ports=[80, 443])
        
        return [
            ScanResult(
                target=target,
                port=80,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=50.5,
                service_info=ServiceInfo(
                    name="http",
                    version="1.1",
                    product="nginx",
                    banner="nginx/1.18.0",
                    confidence=0.95
                )
            ),
            ScanResult(
                target=target,
                port=443,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=75.2,
                service_info=ServiceInfo(
                    name="https",
                    version="1.1",
                    product="nginx",
                    banner="nginx/1.18.0 (Ubuntu)",
                    confidence=0.90
                )
            )
        ]
    
    @pytest.fixture
    def sample_detection_results(self):
        """Create sample detection results."""
        from src.hawkeye.detection.base import DetectionMethod
        server_info = MCPServerInfo(
            host="192.168.1.100",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            version="1.0.0",
            capabilities=["tools", "resources"]
        )
        
        return [
            DetectionResult(
                target_host="192.168.1.100",
                detection_method=DetectionMethod.PROCESS_ENUMERATION,
                success=True,
                mcp_server=server_info,
                confidence=0.95,
                raw_data={"npm_packages": ["@modelcontextprotocol/server"]}
            )
        ]
    
    @pytest.fixture
    def sample_assessment_results(self):
        """Create sample assessment results."""
        finding = SecurityFinding(
            id="FINDING-001",
            title="Weak Authentication",
            description="Default credentials detected",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            confidence=0.90,
            affected_asset="192.168.1.100:3000",
            remediation="Change default credentials",
            references=["CWE-521"]
        )
        
        return [
            AssessmentResult(
                target_host="192.168.1.100",
                overall_risk_level=RiskLevel.HIGH,
                overall_risk_score=7.5,
                findings=[finding],
                assessment_duration=120.5
            )
        ]
    
    @pytest.fixture
    def sample_report_data(self, sample_metadata, sample_scan_results, 
                          sample_detection_results, sample_assessment_results):
        """Create sample report data."""
        return ReportData(
            metadata=sample_metadata,
            scan_results=sample_scan_results,
            detection_results=sample_detection_results,
            assessment_results=sample_assessment_results,
            recommendations=["Update default configurations", "Enable authentication"]
        )
    
    def test_reporter_init(self, reporter):
        """Test CSV reporter initialization."""
        assert reporter.get_format() == ReportFormat.CSV
        assert reporter.delimiter == ','
        assert reporter.quoting == csv.QUOTE_MINIMAL
        assert hasattr(reporter, 'logger')
    
    def test_reporter_init_custom_params(self):
        """Test CSV reporter initialization with custom parameters."""
        reporter = CSVReporter(delimiter=';', quoting=csv.QUOTE_ALL)
        assert reporter.delimiter == ';'
        assert reporter.quoting == csv.QUOTE_ALL
    
    def test_get_format(self, reporter):
        """Test get_format method."""
        assert reporter.get_format() == ReportFormat.CSV
    
    def test_generate_report_memory(self, reporter, sample_report_data):
        """Test generating CSV report in memory."""
        result = reporter.generate_report(sample_report_data)
        
        assert isinstance(result, str)
        assert "# REPORT METADATA" in result
        assert "# EXECUTIVE SUMMARY" in result
        assert "# SCAN RESULTS" in result
        assert "# MCP DETECTION RESULTS" in result
        assert "# RISK ASSESSMENT RESULTS" in result
        assert "# RECOMMENDATIONS" in result
        
        # Verify CSV structure
        lines = result.split('\n')
        assert any("Test Security Report" in line for line in lines)
        assert any("192.168.1.100" in line for line in lines)
    
    def test_generate_report_file_output(self, reporter, sample_report_data):
        """Test generating CSV report to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.csv"
            
            result = reporter.generate_report(sample_report_data, output_path)
            
            assert result == str(output_path)
            assert output_path.exists()
            
            # Verify file content
            content = output_path.read_text()
            assert "# REPORT METADATA" in content
            assert "Test Security Report" in content
    
    def test_generate_report_invalid_data(self, reporter):
        """Test generating report with invalid data."""
        with pytest.raises(ReportingError):
            reporter.generate_report(None)
    
    @patch('src.hawkeye.reporting.csv_reporter.get_logger')
    def test_generate_report_logging(self, mock_logger, reporter, sample_report_data):
        """Test that report generation logs appropriately."""
        mock_log = Mock()
        mock_logger.return_value = mock_log
        
        reporter.logger = mock_log
        reporter.generate_report(sample_report_data)
        
        mock_log.info.assert_called()
    
    def test_write_metadata_section(self, reporter, sample_metadata):
        """Test writing metadata section."""
        output = StringIO()
        reporter._write_metadata_section(output, sample_metadata)

        content = output.getvalue()
        assert "# REPORT METADATA" in content
        assert "Test Security Report" in content
        assert "risk_assessment" in content
        assert "csv" in content
        assert "Test Author" in content
        assert "Test Org" in content
    
    def test_write_summary_section(self, reporter, sample_report_data):
        """Test writing summary section."""
        output = StringIO()
        reporter._write_summary_section(output, sample_report_data)
        
        content = output.getvalue()
        assert "# EXECUTIVE SUMMARY" in content
        assert "Total Targets" in content
        assert "Critical Findings" in content
        assert "High Risk Targets" in content
    
    def test_write_scan_results_section(self, reporter, sample_scan_results):
        """Test writing scan results section."""
        output = StringIO()
        reporter._write_scan_results_section(output, sample_scan_results)
        
        content = output.getvalue()
        assert "# SCAN RESULTS" in content
        assert "Host,Port,State" in content
        assert "192.168.1.100" in content
        assert "80" in content
        assert "443" in content
        assert "open" in content
        assert "nginx" in content
    
    def test_write_detection_results_section(self, reporter, sample_detection_results):
        """Test writing detection results section."""
        output = StringIO()
        reporter._write_detection_results_section(output, sample_detection_results)
        
        content = output.getvalue()
        assert "# MCP DETECTION RESULTS" in content
        assert "Target Host,Detection Method" in content
        assert "192.168.1.100" in content
        assert "process_enumeration" in content
        assert "http" in content
        assert "standalone" in content
    
    def test_write_assessment_results_section(self, reporter, sample_assessment_results):
        """Test writing assessment results section."""
        output = StringIO()
        reporter._write_assessment_results_section(output, sample_assessment_results)
        
        content = output.getvalue()
        assert "# RISK ASSESSMENT RESULTS" in content
        assert "Target Host,Assessment Timestamp" in content
        assert "192.168.1.100" in content
        assert "high" in content
        assert "7.50" in content
    
    def test_write_recommendations_section(self, reporter):
        """Test writing recommendations section."""
        recommendations = [
            "Update default configurations",
            "Enable authentication",
            "Use HTTPS transport"
        ]
        
        output = StringIO()
        reporter._write_recommendations_section(output, recommendations)
        
        content = output.getvalue()
        assert "# RECOMMENDATIONS" in content
        assert "Priority,Recommendation" in content
        assert "Update default configurations" in content
        assert "Enable authentication" in content
        assert "Use HTTPS transport" in content
    
    def test_save_csv_file(self, reporter):
        """Test saving CSV content to file."""
        content = "test,csv,content\n1,2,3\n"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test.csv"
            
            reporter._save_csv_file(content, output_path)
            
            assert output_path.exists()
            assert output_path.read_text() == content
    
    def test_save_csv_file_error(self, reporter):
        """Test CSV file save error handling."""
        content = "test,csv,content\n"
        invalid_path = Path("/invalid/path/test.csv")
        
        with pytest.raises(ReportingError):
            reporter._save_csv_file(content, invalid_path)
    
    def test_generate_separate_files(self, reporter, sample_report_data):
        """Test generating separate CSV files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "report"
            
            files = reporter.generate_separate_files(sample_report_data, base_path)
            
            assert len(files) == 4  # metadata, scan, detection, assessment
            
            for file_path in files:
                assert Path(file_path).exists()
                assert Path(file_path).suffix == '.csv'
    
    def test_generate_metadata_file(self, reporter, sample_metadata):
        """Test generating metadata CSV file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "metadata.csv"
            
            reporter._generate_metadata_file(sample_metadata, output_path)
            
            assert output_path.exists()
            content = output_path.read_text()
            assert "Field,Value" in content
            assert "Test Security Report" in content
    
    def test_generate_scan_results_file(self, reporter, sample_scan_results):
        """Test generating scan results CSV file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "scan_results.csv"
            
            reporter._generate_scan_results_file(sample_scan_results, output_path)
            
            assert output_path.exists()
            content = output_path.read_text()
            assert "Host,Port,State" in content
            assert "192.168.1.100" in content
    
    def test_generate_detection_results_file(self, reporter, sample_detection_results):
        """Test generating detection results CSV file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "detection_results.csv"
            
            reporter._generate_detection_results_file(sample_detection_results, output_path)
            
            assert output_path.exists()
            content = output_path.read_text()
            assert "Target Host,Detection Method" in content
            assert "192.168.1.100" in content
    
    def test_generate_assessment_results_file(self, reporter, sample_assessment_results):
        """Test generating assessment results CSV file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "assessment_results.csv"

            reporter._generate_assessment_results_file(sample_assessment_results, output_path)

            assert output_path.exists()
            content = output_path.read_text()
            assert "Target Host,Risk Level,Risk Score" in content
            assert "high" in content
    
    def test_csv_parsing_validity(self, reporter, sample_report_data):
        """Test that generated CSV is valid and parseable."""
        result = reporter.generate_report(sample_report_data)
        
        # Extract CSV sections and verify they parse correctly
        lines = result.split('\n')
        csv_sections = []
        current_section = []
        
        for line in lines:
            if line.startswith('#') and current_section:
                csv_sections.append('\n'.join(current_section))
                current_section = []
            elif not line.startswith('#') and line.strip():
                current_section.append(line)
        
        if current_section:
            csv_sections.append('\n'.join(current_section))
        
        # Verify each section parses as valid CSV
        for section in csv_sections:
            if section.strip():
                reader = csv.reader(StringIO(section))
                rows = list(reader)
                assert len(rows) > 0  # Should have at least headers
    
    def test_custom_delimiter(self, sample_report_data):
        """Test CSV generation with custom delimiter."""
        reporter = CSVReporter(delimiter=';')
        result = reporter.generate_report(sample_report_data)
        
        # Verify semicolon delimiter is used
        assert ';' in result
        assert 'Field;Value' in result
    
    def test_custom_quoting(self, sample_report_data):
        """Test CSV generation with custom quoting."""
        reporter = CSVReporter(quoting=csv.QUOTE_ALL)
        result = reporter.generate_report(sample_report_data)
        
        # Should have more quotes due to QUOTE_ALL
        assert result.count('"') > 0
    
    def test_empty_data_sections(self, reporter, sample_metadata):
        """Test handling of empty data sections."""
        # Create report data with only metadata - this should raise an error
        # since the validation requires at least one type of data
        data = ReportData(
            metadata=sample_metadata,
            scan_results=[],
            detection_results=[],
            assessment_results=[],
            recommendations=[]
        )
        
        # Should raise ReportingError for empty data
        with pytest.raises(ReportingError, match="Report must contain at least one type of data"):
            reporter.generate_report(data)
    
    def test_large_data_handling(self, reporter, sample_metadata):
        """Test handling of large datasets."""
        # Create large dataset
        large_scan_results = []
        for i in range(1000):
            target = ScanTarget(host=f"192.168.1.{i % 255}", ports=[80])
            result = ScanResult(
                target=target,
                port=80,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=50.0
            )
            large_scan_results.append(result)
        
        data = ReportData(
            metadata=sample_metadata,
            scan_results=large_scan_results,
            detection_results=[],
            assessment_results=[],
            recommendations=[]
        )
        
        result = reporter.generate_report(data)
        
        # Should handle large dataset without errors
        assert isinstance(result, str)
        assert len(result) > 10000  # Should be substantial content
        assert result.count('\n') > 1000  # Should have many lines
    
    def test_statistics_tracking(self, reporter, sample_report_data):
        """Test that statistics are tracked during report generation."""
        # Clear any existing statistics
        reporter.clear_statistics()
        
        # Generate a report
        reporter.generate_report(sample_report_data)
        
        # Verify statistics were updated
        stats = reporter.get_generation_statistics()
        assert stats['reports_generated'] == 1
        assert stats['successful_generations'] == 1
        assert stats['failed_generations'] == 0
        assert stats['total_generation_time'] > 0  # Should have some generation time
    
    def test_error_handling_and_statistics(self, reporter):
        """Test error handling and statistics tracking for failures."""
        with pytest.raises(ReportingError):
            reporter.generate_report(None)
        
        # Verify failure statistics
        stats = reporter.get_generation_statistics()
        assert stats['failed_generations'] == 1 