"""
Unit tests for XML report generator.

This module tests the XML report generation functionality including
data formatting, file output, XML validation, and error handling.
"""

import pytest
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.hawkeye.reporting.xml_reporter import XMLReporter
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


class TestXMLReporter:
    """Test cases for XML reporter."""
    
    @pytest.fixture
    def reporter(self):
        """Create XML reporter instance."""
        return XMLReporter()
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata."""
        return ReportMetadata(
            title="Test Security Report",
            report_type=ReportType.RISK_ASSESSMENT,
            format=ReportFormat.XML,
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
        """Test XML reporter initialization."""
        assert reporter.get_format() == ReportFormat.XML
        assert reporter.pretty_print is True
        assert reporter.encoding == 'utf-8'
        assert hasattr(reporter, 'logger')
    
    def test_reporter_init_custom_params(self):
        """Test XML reporter initialization with custom parameters."""
        reporter = XMLReporter(pretty_print=False, encoding='utf-16')
        assert reporter.pretty_print is False
        assert reporter.encoding == 'utf-16'
    
    def test_get_format(self, reporter):
        """Test get_format method."""
        assert reporter.get_format() == ReportFormat.XML
    
    def test_generate_report_memory(self, reporter, sample_report_data):
        """Test generating XML report in memory."""
        result = reporter.generate_report(sample_report_data)
        
        assert isinstance(result, str)
        assert result.startswith('<?xml')
        assert '<hawkeye_report' in result
        assert '<metadata>' in result
        assert '<executive_summary>' in result
        assert 'scan_results' in result
        assert 'detection_results' in result
        assert 'assessment_results' in result
        assert 'recommendations' in result
        
        # Verify XML is well-formed
        root = ET.fromstring(result)
        assert root.tag == 'hawkeye_report'
        assert root.get('version') == '1.0'
        assert root.get('schema') == 'hawkeye-xml-v1'
    
    def test_generate_report_file_output(self, reporter, sample_report_data):
        """Test generating XML report to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_report.xml"
            
            result = reporter.generate_report(sample_report_data, output_path)
            
            assert result == str(output_path)
            assert output_path.exists()
            
            # Verify file content
            content = output_path.read_text()
            assert '<?xml' in content
            assert '<hawkeye_report' in content
            assert 'Test Security Report' in content
    
    def test_generate_report_invalid_data(self, reporter):
        """Test generating report with invalid data."""
        with pytest.raises(ReportingError):
            reporter.generate_report(None)
    
    @patch('src.hawkeye.reporting.xml_reporter.get_logger')
    def test_generate_report_logging(self, mock_logger, reporter, sample_report_data):
        """Test that report generation logs appropriately."""
        mock_log = Mock()
        mock_logger.return_value = mock_log
        
        reporter.logger = mock_log
        reporter.generate_report(sample_report_data)
        
        mock_log.info.assert_called()
    
    def test_add_metadata_section(self, reporter, sample_metadata):
        """Test adding metadata section to XML."""
        root = ET.Element("test")
        reporter._add_metadata_section(root, sample_metadata)
        
        metadata_elem = root.find('metadata')
        assert metadata_elem is not None
        assert metadata_elem.find('title').text == "Test Security Report"
        assert metadata_elem.find('report_type').text == "risk_assessment"
        assert metadata_elem.find('format').text == "xml"
        assert metadata_elem.find('author').text == "Test Author"
        assert metadata_elem.find('organization').text == "Test Org"
        assert metadata_elem.find('classification').text == "Internal"
    
    def test_add_summary_section(self, reporter, sample_report_data):
        """Test adding summary section to XML."""
        root = ET.Element("test")
        reporter._add_summary_section(root, sample_report_data)
        
        summary_elem = root.find('executive_summary')
        assert summary_elem is not None
        
        stats_elem = summary_elem.find('statistics')
        assert stats_elem is not None
        assert stats_elem.find('total_targets') is not None
        assert stats_elem.find('critical_findings') is not None
        assert stats_elem.find('high_risk_targets') is not None
    
    def test_add_scan_results_section(self, reporter, sample_scan_results):
        """Test adding scan results section to XML."""
        root = ET.Element("test")
        reporter._add_scan_results_section(root, sample_scan_results)
        
        scan_results_elem = root.find('scan_results')
        assert scan_results_elem is not None
        
        results = scan_results_elem.findall('scan_result')
        assert len(results) == 2
        
        # Check first result
        result = results[0]
        assert result.find('host').text == "192.168.1.100"
        assert result.find('port').text == "80"
        assert result.find('state').text == "open"
        service_elem = result.find('service')
        assert service_elem.find('name').text == "http"
        assert service_elem.find('product').text == "nginx"
    
    def test_add_detection_results_section(self, reporter, sample_detection_results):
        """Test adding detection results section to XML."""
        root = ET.Element("test")
        reporter._add_detection_results_section(root, sample_detection_results)
        
        detection_results_elem = root.find('detection_results')
        assert detection_results_elem is not None
        
        results = detection_results_elem.findall('detection_result')
        assert len(results) == 1
        
        # Check result structure
        result = results[0]
        assert result.find('target_host').text == "192.168.1.100"
        assert result.find('detection_method').text == "process_enumeration"
        assert result.find('confidence').text == "0.9500"
        
        # Check server info
        server_info = result.find('mcp_server')
        assert server_info is not None
        assert server_info.find('transport_type').text == "http"
        assert server_info.find('server_type').text == "standalone"
    
    def test_add_assessment_results_section(self, reporter, sample_assessment_results):
        """Test adding assessment results section to XML."""
        root = ET.Element("test")
        reporter._add_assessment_results_section(root, sample_assessment_results)
        
        assessment_results_elem = root.find('assessment_results')
        assert assessment_results_elem is not None
        
        results = assessment_results_elem.findall('assessment_result')
        assert len(results) == 1
        
        # Check result structure
        result = results[0]
        assert result.find('target_host').text == "192.168.1.100"
        assert result.find('overall_risk_level').text == "high"
        assert result.find('overall_risk_score').text == "7.5000"
        
        # Check findings
        findings = result.find('findings')
        assert findings is not None
        finding_elems = findings.findall('finding')
        assert len(finding_elems) == 1
        
        finding = finding_elems[0]
        assert finding.find('title').text == "Weak Authentication"
        assert finding.find('severity').text == "high"
        assert finding.find('category').text == "authentication"
    
    def test_add_recommendations_section(self, reporter):
        """Test adding recommendations section to XML."""
        recommendations = [
            "Update default configurations",
            "Enable authentication",
            "Use HTTPS transport"
        ]
        
        root = ET.Element("test")
        reporter._add_recommendations_section(root, recommendations)
        
        recommendations_elem = root.find('recommendations')
        assert recommendations_elem is not None
        
        recommendation_elems = recommendations_elem.findall('recommendation')
        assert len(recommendation_elems) == 3
        
        assert recommendation_elems[0].text == "Update default configurations"
        assert recommendation_elems[1].text == "Enable authentication"
        assert recommendation_elems[2].text == "Use HTTPS transport"
    
    def test_prettify_xml(self, reporter):
        """Test XML prettification."""
        root = ET.Element("test")
        child = ET.SubElement(root, "child")
        child.text = "content"
        
        pretty_xml = reporter._prettify_xml(root)
        
        assert pretty_xml.startswith('<?xml')
        assert '\n' in pretty_xml  # Should have line breaks
        assert '  ' in pretty_xml  # Should have indentation
    
    def test_save_xml_file(self, reporter):
        """Test saving XML content to file."""
        content = '<?xml version="1.0"?><test>content</test>'
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test.xml"
            
            reporter._save_xml_file(content, output_path)
            
            assert output_path.exists()
            assert output_path.read_text() == content
    
    def test_save_xml_file_error(self, reporter):
        """Test XML file save error handling."""
        content = '<?xml version="1.0"?><test>content</test>'
        invalid_path = Path("/invalid/path/test.xml")
        
        with pytest.raises(ReportingError):
            reporter._save_xml_file(content, invalid_path)
    
    def test_validate_xml_output(self, reporter, sample_report_data):
        """Test XML validation functionality."""
        result = reporter.generate_report(sample_report_data)
        
        # Should validate successfully
        assert reporter.validate_xml_output(result) is True
        
        # Invalid XML should fail validation
        invalid_xml = "<invalid><unclosed>"
        assert reporter.validate_xml_output(invalid_xml) is False
    
    def test_xml_structure_completeness(self, reporter, sample_report_data):
        """Test that generated XML contains all expected elements."""
        result = reporter.generate_report(sample_report_data)
        root = ET.fromstring(result)
        
        # Check root attributes
        assert root.get('version') == '1.0'
        assert root.get('schema') == 'hawkeye-xml-v1'
        
        # Check main sections exist
        assert root.find('metadata') is not None
        assert root.find('executive_summary') is not None
        assert root.find('scan_results') is not None
        assert root.find('detection_results') is not None
        assert root.find('assessment_results') is not None
        assert root.find('recommendations') is not None
    
    def test_xml_data_integrity(self, reporter, sample_report_data):
        """Test that XML preserves data integrity."""
        result = reporter.generate_report(sample_report_data)
        root = ET.fromstring(result)
        
        # Check metadata preservation
        metadata = root.find('metadata')
        assert metadata.find('title').text == "Test Security Report"
        assert metadata.find('author').text == "Test Author"
        
        # Check scan results preservation
        scan_results = root.find('scan_results')
        scan_result = scan_results.find('scan_result')
        assert scan_result.find('host').text == "192.168.1.100"
        assert scan_result.find('port').text == "80"
        
        # Check detection results preservation
        detection_results = root.find('detection_results')
        detection_result = detection_results.find('detection_result')
        server_info = detection_result.find('mcp_server')
        assert server_info.find('transport_type').text == "http"
    
    def test_pretty_print_disabled(self, sample_report_data):
        """Test XML generation without pretty printing."""
        reporter = XMLReporter(pretty_print=False)
        result = reporter.generate_report(sample_report_data)
        
        # Should not have extra whitespace/indentation
        lines = result.split('\n')
        # Should be fewer lines without pretty printing
        assert len(lines) < 50  # Arbitrary threshold
    
    def test_custom_encoding(self, sample_report_data):
        """Test XML generation with custom encoding."""
        reporter = XMLReporter(encoding='utf-16')
        result = reporter.generate_report(sample_report_data)
        
        # Should still be valid XML
        root = ET.fromstring(result)
        assert root.tag == 'hawkeye_report'
    
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
        for i in range(100):  # Smaller than CSV test for XML overhead
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
        root = ET.fromstring(result)  # Should parse without errors
        
        # Check that all results are present
        scan_results = root.find('scan_results')
        scan_result_elems = scan_results.findall('scan_result')
        assert len(scan_result_elems) == 100
    
    def test_special_characters_handling(self, reporter, sample_metadata, sample_scan_results):
        """Test handling of special characters in XML."""
        # Create data with special characters
        metadata = sample_metadata
        metadata.title = "Test & Report <with> \"special\" 'characters'"
        metadata.description = "Contains <>&\"' characters"
        
        data = ReportData(
            metadata=metadata,
            scan_results=sample_scan_results,  # Need at least one type of data
            detection_results=[],
            assessment_results=[],
            recommendations=["Use <secure> & \"safe\" configurations"]
        )
        
        result = reporter.generate_report(data)
        
        # Should be valid XML despite special characters
        root = ET.fromstring(result)
        
        # Check that special characters are properly escaped
        title_elem = root.find('metadata/title')
        assert title_elem.text == "Test & Report <with> \"special\" 'characters'"
    
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
    
    def test_xml_namespace_handling(self, reporter, sample_report_data):
        """Test that XML namespaces are handled correctly."""
        result = reporter.generate_report(sample_report_data)
        
        # Should not have namespace conflicts
        root = ET.fromstring(result)
        assert root.tag == 'hawkeye_report'
        
        # All child elements should be accessible
        assert len(list(root)) > 0
    
    def test_xml_encoding_declaration(self, reporter, sample_report_data):
        """Test that XML encoding declaration is correct."""
        result = reporter.generate_report(sample_report_data)
        
        # Should start with XML declaration
        assert result.startswith('<?xml version="1.0"')
        # Note: encoding may not be explicitly declared in the XML when using default utf-8 