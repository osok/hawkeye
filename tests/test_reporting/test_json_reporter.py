"""
Unit tests for JSON reporter functionality.

This module tests the JSON report generation capabilities including
data serialization, formatting, validation, and file operations.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from src.hawkeye.reporting.json_reporter import JSONReporter
from src.hawkeye.reporting.base import (
    ReportData, ReportMetadata, ReportFormat, ReportType,
    ScanSummary, DetectionSummary, RiskSummary,
    ReportingError
)
from src.hawkeye.assessment.base import AssessmentResult, RiskLevel, SecurityFinding, VulnerabilityCategory
from src.hawkeye.detection.base import DetectionResult, DetectionMethod, MCPServerInfo, TransportType, MCPServerType
from src.hawkeye.scanner.base import ScanResult, ScanTarget, PortState, ScanType, ServiceInfo


class TestJSONReporter:
    """Test cases for JSONReporter class."""
    
    @pytest.fixture
    def json_reporter(self):
        """Create a JSONReporter instance for testing."""
        return JSONReporter()
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata."""
        return ReportMetadata(
            title="Test Security Report",
            report_type=ReportType.COMBINED_REPORT,
            format=ReportFormat.JSON,
            description="Test report for unit testing",
            author="Test Author",
            organization="Test Organization"
        )
    
    @pytest.fixture
    def sample_scan_results(self):
        """Create sample scan results."""
        target = ScanTarget(host="192.168.1.100", ports=[80, 443])
        service_info = ServiceInfo(
            name="http",
            version="1.1",
            product="nginx",
            banner="nginx/1.18.0",
            confidence=0.95
        )
        
        return [
            ScanResult(
                target=target,
                port=80,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=0.05,
                service_info=service_info
            ),
            ScanResult(
                target=target,
                port=443,
                state=PortState.OPEN,
                scan_type=ScanType.TCP_CONNECT,
                response_time=0.03
            )
        ]
    
    @pytest.fixture
    def sample_detection_results(self):
        """Create sample detection results."""
        mcp_server = MCPServerInfo(
            host="192.168.1.100",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            capabilities=["tools", "resources"],
            tools=["file_reader", "web_search"],
            version="1.0.0"
        )
        
        return [
            DetectionResult(
                target_host="192.168.1.100",
                detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
                success=True,
                mcp_server=mcp_server,
                confidence=0.9
            )
        ]
    
    @pytest.fixture
    def sample_assessment_results(self):
        """Create sample assessment results."""
        finding = SecurityFinding(
            id="FIND-001",
            title="Insecure MCP Server",
            description="MCP server running without authentication",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            confidence=0.8,
            affected_asset="192.168.1.100:3000"
        )
        
        return [
            AssessmentResult(
                target_host="192.168.1.100",
                overall_risk_level=RiskLevel.HIGH,
                overall_risk_score=7.5,
                findings=[finding]
            )
        ]
    
    @pytest.fixture
    def sample_report_data(self, sample_metadata, sample_scan_results, 
                          sample_detection_results, sample_assessment_results):
        """Create complete sample report data."""
        return ReportData(
            metadata=sample_metadata,
            scan_results=sample_scan_results,
            detection_results=sample_detection_results,
            assessment_results=sample_assessment_results,
            recommendations=["Implement authentication", "Use HTTPS transport"]
        )
    
    def test_get_format(self, json_reporter):
        """Test that reporter returns correct format."""
        assert json_reporter.get_format() == ReportFormat.JSON
    
    def test_generate_report_in_memory(self, json_reporter, sample_report_data):
        """Test generating JSON report in memory."""
        result = json_reporter.generate_report(sample_report_data)
        
        # Should return JSON string
        assert isinstance(result, str)
        
        # Should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        
        # Should contain expected sections
        assert 'metadata' in parsed
        assert 'summary' in parsed
        assert 'scan_results' in parsed
        assert 'detection_results' in parsed
        assert 'assessment_results' in parsed
        assert 'recommendations' in parsed
    
    def test_generate_report_to_file(self, json_reporter, sample_report_data):
        """Test generating JSON report to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.json"
            
            result = json_reporter.generate_report(sample_report_data, output_path)
            
            # Should return file path
            assert result == str(output_path)
            
            # File should exist and contain valid JSON
            assert output_path.exists()
            
            with open(output_path, 'r') as f:
                content = f.read()
                parsed = json.loads(content)
                assert isinstance(parsed, dict)
    
    def test_json_content_structure(self, json_reporter, sample_report_data):
        """Test the structure of generated JSON content."""
        result = json_reporter.generate_report(sample_report_data)
        parsed = json.loads(result)
        
        # Check metadata structure
        metadata = parsed['metadata']
        assert metadata['title'] == "Test Security Report"
        assert metadata['report_type'] == "combined_report"
        assert metadata['format'] == "json"
        assert 'generated_timestamp' in metadata
        
        # Check summary structure
        summary = parsed['summary']
        assert 'total_targets' in summary
        assert 'has_scan_data' in summary
        assert 'has_detection_data' in summary
        assert 'has_assessment_data' in summary
        
        # Check scan results structure
        scan_results = parsed['scan_results']
        assert len(scan_results) == 2
        assert scan_results[0]['host'] == "192.168.1.100"
        assert scan_results[0]['port'] == 80
        assert scan_results[0]['state'] == "open"
        
        # Check detection results structure
        detection_results = parsed['detection_results']
        assert len(detection_results) == 1
        assert detection_results[0]['target_host'] == "192.168.1.100"
        assert detection_results[0]['is_mcp_detected'] is True
        
        # Check assessment results structure
        assessment_results = parsed['assessment_results']
        assert len(assessment_results) == 1
        assert assessment_results[0]['target_host'] == "192.168.1.100"
        assert assessment_results[0]['overall_risk_level'] == "high"
    
    def test_enhanced_scan_results(self, json_reporter, sample_report_data):
        """Test enhanced scan results with computed fields."""
        result = json_reporter.generate_report(sample_report_data)
        parsed = json.loads(result)
        
        scan_result = parsed['scan_results'][0]
        
        # Should have computed fields
        assert 'is_open' in scan_result
        assert 'has_service_info' in scan_result
        assert 'formatted_timestamp' in scan_result
        
        # Values should be correct
        assert scan_result['is_open'] is True
        assert scan_result['has_service_info'] is True
    
    def test_enhanced_detection_results(self, json_reporter, sample_report_data):
        """Test enhanced detection results with computed fields."""
        result = json_reporter.generate_report(sample_report_data)
        parsed = json.loads(result)
        
        detection_result = parsed['detection_results'][0]
        
        # Should have computed fields
        assert 'is_mcp_detected' in detection_result
        assert 'formatted_timestamp' in detection_result
        
        # Values should be correct
        assert detection_result['is_mcp_detected'] is True
    
    def test_enhanced_assessment_results(self, json_reporter, sample_report_data):
        """Test enhanced assessment results with statistics."""
        result = json_reporter.generate_report(sample_report_data)
        parsed = json.loads(result)
        
        assessment_result = parsed['assessment_results'][0]
        
        # Should have computed statistics
        assert 'statistics' in assessment_result
        assert 'formatted_timestamp' in assessment_result
        
        stats = assessment_result['statistics']
        assert 'critical_findings_count' in stats
        assert 'high_findings_count' in stats
        assert 'exploitable_vulnerabilities_count' in stats
        assert 'unpatched_vulnerabilities_count' in stats
    
    def test_aggregated_statistics(self, json_reporter, sample_report_data):
        """Test aggregated statistics generation."""
        result = json_reporter.generate_report(sample_report_data)
        parsed = json.loads(result)
        
        # Should have aggregated statistics
        assert 'aggregated_statistics' in parsed
        
        stats = parsed['aggregated_statistics']
        assert 'overview' in stats
        assert 'scan_statistics' in stats
        assert 'detection_statistics' in stats
        assert 'risk_statistics' in stats
        
        # Check overview
        overview = stats['overview']
        assert overview['total_targets'] == 1
        assert 'scan_results' in overview['data_types_present']
        assert 'detection_results' in overview['data_types_present']
        assert 'assessment_results' in overview['data_types_present']
    
    def test_json_serializer_custom_types(self, json_reporter):
        """Test custom JSON serializer for non-standard types."""
        # Test Path object
        path_obj = Path("/test/path")
        result = json_reporter._json_serializer(path_obj)
        assert result == "/test/path"
        
        # Test enum object
        enum_obj = ReportFormat.JSON
        result = json_reporter._json_serializer(enum_obj)
        assert result == "json"
        
        # Test fallback to string
        class CustomObject:
            def __str__(self):
                return "custom_string"
        
        custom_obj = CustomObject()
        result = json_reporter._json_serializer(custom_obj)
        assert result == "custom_string"
    
    def test_validate_json_output(self, json_reporter):
        """Test JSON validation functionality."""
        # Valid JSON
        valid_json = '{"key": "value", "number": 123}'
        assert json_reporter.validate_json_output(valid_json) is True
        
        # Invalid JSON
        invalid_json = '{"key": "value", "number": 123'  # Missing closing brace
        assert json_reporter.validate_json_output(invalid_json) is False
        
        # Non-string input
        assert json_reporter.validate_json_output(None) is False
    
    def test_data_validation(self, json_reporter):
        """Test report data validation."""
        # Valid data should pass
        metadata = ReportMetadata(
            title="Test",
            report_type=ReportType.SCAN_RESULTS,
            format=ReportFormat.JSON
        )
        valid_data = ReportData(metadata=metadata, scan_results=[])
        json_reporter.validate_data(valid_data)  # Should not raise
        
        # Invalid data type should fail
        with pytest.raises(ReportingError, match="Invalid data type"):
            json_reporter.validate_data("not_report_data")
        
        # Missing metadata should fail
        invalid_data = ReportData(metadata=None)
        with pytest.raises(ReportingError, match="metadata is required"):
            json_reporter.validate_data(invalid_data)
        
        # No data should fail
        empty_data = ReportData(metadata=metadata)
        with pytest.raises(ReportingError, match="must contain at least one type"):
            json_reporter.validate_data(empty_data)
    
    def test_generation_statistics(self, json_reporter, sample_report_data):
        """Test generation statistics tracking."""
        # Initial statistics should be zero
        stats = json_reporter.get_generation_statistics()
        assert stats['reports_generated'] == 0
        assert stats['successful_generations'] == 0
        assert stats['failed_generations'] == 0
        
        # Generate a report
        json_reporter.generate_report(sample_report_data)
        
        # Statistics should be updated
        stats = json_reporter.get_generation_statistics()
        assert stats['reports_generated'] == 1
        assert stats['successful_generations'] == 1
        assert stats['failed_generations'] == 0
        assert stats['success_rate'] == 1.0
        assert stats['average_generation_time'] > 0
    
    def test_error_handling(self, json_reporter):
        """Test error handling during report generation."""
        # Test with invalid data
        with pytest.raises(ReportingError):
            json_reporter.generate_report("invalid_data")
        
        # Statistics should track the failure
        stats = json_reporter.get_generation_statistics()
        assert stats['failed_generations'] > 0
    
    def test_file_save_error_handling(self, json_reporter, sample_report_data):
        """Test error handling during file save operations."""
        # Try to save to invalid path
        invalid_path = Path("/invalid/path/that/does/not/exist/report.json")
        
        with pytest.raises(ReportingError, match="JSON report generation failed"):
            json_reporter.generate_report(sample_report_data, invalid_path)
    
    def test_custom_formatting_options(self):
        """Test custom JSON formatting options."""
        # Test with custom indentation
        reporter = JSONReporter(indent=4, sort_keys=False)
        assert reporter.indent == 4
        assert reporter.sort_keys is False
        
        # Test format is still JSON
        assert reporter.get_format() == ReportFormat.JSON
    
    def test_clear_statistics(self, json_reporter, sample_report_data):
        """Test clearing generation statistics."""
        # Generate a report to create statistics
        json_reporter.generate_report(sample_report_data)
        
        # Verify statistics exist
        stats = json_reporter.get_generation_statistics()
        assert stats['reports_generated'] > 0
        
        # Clear statistics
        json_reporter.clear_statistics()
        
        # Verify statistics are reset
        stats = json_reporter.get_generation_statistics()
        assert stats['reports_generated'] == 0
        assert stats['successful_generations'] == 0
        assert stats['failed_generations'] == 0
        assert stats['total_generation_time'] == 0.0
    
    @patch('src.hawkeye.reporting.json_reporter.time.time')
    def test_generation_timing(self, mock_time, json_reporter, sample_report_data):
        """Test generation timing measurement."""
        # Mock time to control timing
        mock_time.side_effect = [1000.0, 1001.5]  # 1.5 second generation
        
        json_reporter.generate_report(sample_report_data)
        
        stats = json_reporter.get_generation_statistics()
        assert stats['average_generation_time'] == 1.5 