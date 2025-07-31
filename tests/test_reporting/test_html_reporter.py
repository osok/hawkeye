"""
Unit tests for HTML reporter and template system.

This module tests the HTML report generation functionality including
template rendering, data binding, and output formatting.
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from src.hawkeye.reporting.html_reporter import HTMLReporter
from src.hawkeye.reporting.templates.base import BaseTemplate, TemplateEngine, TemplateError
from src.hawkeye.reporting.templates.html_templates import (
    ExecutiveSummaryTemplate,
    TechnicalReportTemplate,
    VulnerabilityReportTemplate,
    ComplianceReportTemplate
)
from src.hawkeye.reporting.base import (
    ReportData,
    ReportMetadata,
    ScanSummary,
    DetectionSummary,
    RiskSummary,
    ReportFormat,
    ReportingError
)


class TestHTMLReporter:
    """Test cases for HTML reporter."""
    
    @pytest.fixture
    def html_reporter(self):
        """Create HTML reporter instance."""
        return HTMLReporter()
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata."""
        return ReportMetadata(
            scan_id="test-scan-001",
            timestamp=datetime.now(),
            version="1.0.0",
            target_specification="192.168.1.0/24",
            scan_type="comprehensive"
        )
    
    @pytest.fixture
    def sample_scan_summary(self):
        """Create sample scan summary."""
        return ScanSummary(
            total_targets=10,
            successful_scans=8,
            failed_scans=2,
            scan_duration=120.5,
            ports_scanned=1000
        )
    
    @pytest.fixture
    def sample_detection_summary(self):
        """Create sample detection summary."""
        return DetectionSummary(
            total_detections=5,
            confirmed_mcp_servers=3,
            potential_mcp_servers=2,
            false_positives=0
        )
    
    @pytest.fixture
    def sample_risk_summary(self):
        """Create sample risk summary."""
        return RiskSummary(
            critical_risk_count=1,
            high_risk_count=2,
            medium_risk_count=3,
            low_risk_count=4,
            overall_risk_score=7.5
        )
    
    @pytest.fixture
    def sample_report_data(self, sample_metadata, sample_scan_summary, 
                          sample_detection_summary, sample_risk_summary):
        """Create sample report data."""
        return ReportData(
            metadata=sample_metadata,
            scan_results=[
                {"target": "192.168.1.10", "status": "success", "ports": [8080, 8443]},
                {"target": "192.168.1.20", "status": "success", "ports": [3000]}
            ],
            detection_results=[
                {"target": "192.168.1.10", "mcp_detected": True, "confidence": 0.95},
                {"target": "192.168.1.20", "mcp_detected": True, "confidence": 0.87}
            ],
            assessment_results=[
                {"target": "192.168.1.10", "risk_level": "high", "score": 8.5},
                {"target": "192.168.1.20", "risk_level": "medium", "score": 6.0}
            ],
            recommendations=[
                "Implement network segmentation",
                "Enable authentication on MCP servers",
                "Deploy monitoring solutions"
            ],
            scan_summary=sample_scan_summary,
            detection_summary=sample_detection_summary,
            risk_summary=sample_risk_summary,
            executive_summary="Test executive summary content"
        )
    
    def test_html_reporter_initialization(self, html_reporter):
        """Test HTML reporter initialization."""
        assert html_reporter is not None
        assert isinstance(html_reporter.template_engine, TemplateEngine)
        
        # Check that default templates are registered
        templates = html_reporter.list_available_templates()
        expected_templates = [
            "executive_summary",
            "technical_report", 
            "vulnerability_report",
            "compliance_report"
        ]
        for template in expected_templates:
            assert template in templates
    
    def test_generate_technical_report(self, html_reporter, sample_report_data):
        """Test technical report generation."""
        html_content = html_reporter.generate_technical_report(sample_report_data)
        
        assert html_content is not None
        assert isinstance(html_content, str)
        assert len(html_content) > 0
        
        # Check for HTML structure
        assert "<!DOCTYPE html>" in html_content
        assert "<html" in html_content
        assert "</html>" in html_content
        assert "<head>" in html_content
        assert "<body>" in html_content
        
        # Check for report content
        assert "HawkEye Security Assessment" in html_content
        assert "Technical Analysis Report" in html_content
        assert sample_report_data.metadata.scan_id in html_content
    
    def test_generate_executive_summary_report(self, html_reporter, sample_report_data):
        """Test executive summary report generation."""
        html_content = html_reporter.generate_executive_summary(sample_report_data)
        
        assert html_content is not None
        assert "Executive Summary Report" in html_content
        assert "Assessment Overview" in html_content
        assert str(sample_report_data.total_targets) in html_content
        assert str(sample_report_data.critical_findings) in html_content
    
    def test_generate_vulnerability_report(self, html_reporter, sample_report_data):
        """Test vulnerability report generation."""
        html_content = html_reporter.generate_vulnerability_report(sample_report_data)
        
        assert html_content is not None
        assert "Vulnerability Analysis Report" in html_content
        assert "Critical Vulnerabilities" in html_content
        assert "Security Recommendations" in html_content
    
    def test_generate_compliance_report(self, html_reporter, sample_report_data):
        """Test compliance report generation."""
        html_content = html_reporter.generate_compliance_report(sample_report_data)
        
        assert html_content is not None
        assert "Compliance Analysis Report" in html_content
        assert "Compliance Overview" in html_content
        assert "Compliance Analysis" in html_content
    
    def test_save_to_file(self, html_reporter, sample_report_data):
        """Test saving HTML report to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "test_report.html"
            
            html_content = html_reporter.generate_technical_report(
                sample_report_data, output_file
            )
            
            # Check file was created
            assert output_file.exists()
            
            # Check file content
            with open(output_file, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            assert file_content == html_content
            assert len(file_content) > 0
    
    def test_custom_template_variables(self, html_reporter, sample_report_data):
        """Test custom template variables."""
        custom_vars = {
            "custom_title": "Custom Security Report",
            "organization": "Test Organization"
        }
        
        html_content = html_reporter.generate_technical_report(
            sample_report_data, **custom_vars
        )
        
        assert html_content is not None
        # Note: Custom variables would need to be used in templates to appear in output
    
    def test_invalid_template_name(self, html_reporter, sample_report_data):
        """Test error handling for invalid template name."""
        with pytest.raises(ReportingError):
            html_reporter.generate_report(
                sample_report_data, template_name="nonexistent_template"
            )
    
    def test_register_custom_template(self, html_reporter):
        """Test registering custom template."""
        class CustomTemplate(BaseTemplate):
            def __init__(self):
                super().__init__("custom_test")
            
            def get_template_content(self):
                return "<html><body>Custom Template: $metadata</body></html>"
        
        custom_template = CustomTemplate()
        html_reporter.register_custom_template(custom_template)
        
        templates = html_reporter.list_available_templates()
        assert "custom_test" in templates
    
    def test_get_supported_formats(self, html_reporter):
        """Test getting supported formats."""
        formats = html_reporter.get_supported_formats()
        assert ReportFormat.HTML in formats
        assert len(formats) == 1


class TestTemplateEngine:
    """Test cases for template engine."""
    
    @pytest.fixture
    def template_engine(self):
        """Create template engine instance."""
        return TemplateEngine()
    
    @pytest.fixture
    def sample_template(self):
        """Create sample template."""
        class SampleTemplate(BaseTemplate):
            def __init__(self):
                super().__init__("sample")
            
            def get_template_content(self):
                return "<html><body>Hello $name, you have $count items.</body></html>"
        
        return SampleTemplate()
    
    @pytest.fixture
    def sample_data(self):
        """Create sample template data."""
        return ReportData(
            metadata=ReportMetadata(
                scan_id="test",
                timestamp=datetime.now(),
                version="1.0.0",
                target_specification="test",
                scan_type="test"
            ),
            scan_results=[],
            detection_results=[],
            assessment_results=[],
            recommendations=[],
            scan_summary=ScanSummary(0, 0, 0, 0, 0),
            detection_summary=DetectionSummary(0, 0, 0, 0),
            risk_summary=RiskSummary(0, 0, 0, 0, 0.0),
            executive_summary=""
        )
    
    def test_template_engine_initialization(self, template_engine):
        """Test template engine initialization."""
        assert template_engine is not None
        assert len(template_engine.list_templates()) == 0
    
    def test_register_template(self, template_engine, sample_template):
        """Test template registration."""
        template_engine.register_template(sample_template)
        
        templates = template_engine.list_templates()
        assert "sample" in templates
        assert len(templates) == 1
    
    def test_get_template(self, template_engine, sample_template):
        """Test getting registered template."""
        template_engine.register_template(sample_template)
        
        retrieved = template_engine.get_template("sample")
        assert retrieved is not None
        assert retrieved.template_name == "sample"
        
        # Test non-existent template
        assert template_engine.get_template("nonexistent") is None
    
    def test_render_template(self, template_engine, sample_template, sample_data):
        """Test template rendering."""
        template_engine.register_template(sample_template)
        
        rendered = template_engine.render_template("sample", sample_data, name="Test", count=5)
        
        assert rendered is not None
        assert "Hello Test" in rendered
        assert "5 items" in rendered
    
    def test_render_nonexistent_template(self, template_engine, sample_data):
        """Test error handling for non-existent template."""
        with pytest.raises(TemplateError):
            template_engine.render_template("nonexistent", sample_data)
    
    def test_clear_templates(self, template_engine, sample_template):
        """Test clearing all templates."""
        template_engine.register_template(sample_template)
        assert len(template_engine.list_templates()) == 1
        
        template_engine.clear_templates()
        assert len(template_engine.list_templates()) == 0


class TestHTMLTemplates:
    """Test cases for HTML template classes."""
    
    @pytest.fixture
    def sample_data(self):
        """Create sample report data."""
        return ReportData(
            metadata=ReportMetadata(
                scan_id="test-001",
                timestamp=datetime.now(),
                version="1.0.0",
                target_specification="192.168.1.0/24",
                scan_type="comprehensive"
            ),
            scan_results=[{"target": "192.168.1.10", "status": "success"}],
            detection_results=[{"target": "192.168.1.10", "mcp_detected": True}],
            assessment_results=[{"target": "192.168.1.10", "risk_level": "high"}],
            recommendations=["Implement security controls"],
            scan_summary=ScanSummary(1, 1, 0, 60.0, 1000),
            detection_summary=DetectionSummary(1, 1, 0, 0),
            risk_summary=RiskSummary(1, 0, 0, 0, 9.0),
            executive_summary="Test summary"
        )
    
    def test_executive_summary_template(self, sample_data):
        """Test executive summary template."""
        template = ExecutiveSummaryTemplate()
        
        assert template.template_name == "executive_summary"
        
        rendered = template.render(sample_data)
        assert rendered is not None
        assert "Executive Summary Report" in rendered
        assert "Assessment Overview" in rendered
    
    def test_technical_report_template(self, sample_data):
        """Test technical report template."""
        template = TechnicalReportTemplate()
        
        assert template.template_name == "technical_report"
        
        rendered = template.render(sample_data)
        assert rendered is not None
        assert "Technical Analysis Report" in rendered
        assert "Network Scan Results" in rendered
    
    def test_vulnerability_report_template(self, sample_data):
        """Test vulnerability report template."""
        template = VulnerabilityReportTemplate()
        
        assert template.template_name == "vulnerability_report"
        
        rendered = template.render(sample_data)
        assert rendered is not None
        assert "Vulnerability Analysis Report" in rendered
        assert "Critical Vulnerabilities" in rendered
    
    def test_compliance_report_template(self, sample_data):
        """Test compliance report template."""
        template = ComplianceReportTemplate()
        
        assert template.template_name == "compliance_report"
        
        rendered = template.render(sample_data)
        assert rendered is not None
        assert "Compliance Analysis Report" in rendered
        assert "Compliance Overview" in rendered
    
    def test_template_css_content(self):
        """Test template CSS content."""
        template = ExecutiveSummaryTemplate()
        css = template.get_css_content()
        
        assert css is not None
        assert "body {" in css
        assert "font-family:" in css
    
    def test_template_js_content(self):
        """Test template JavaScript content."""
        template = ExecutiveSummaryTemplate()
        js = template.get_js_content()
        
        assert js is not None
        assert "document.addEventListener" in js
    
    def test_compliance_template_enhanced_css(self):
        """Test compliance template enhanced CSS."""
        template = ComplianceReportTemplate()
        css = template.get_css_content()
        
        assert css is not None
        assert "compliance-section" in css
        assert "compliance-status" in css


class TestBaseTemplate:
    """Test cases for base template functionality."""
    
    def test_html_escaping(self):
        """Test HTML escaping functionality."""
        class TestTemplate(BaseTemplate):
            def __init__(self):
                super().__init__("test")
            
            def get_template_content(self):
                return "<p>$escaped_content</p>"
        
        template = TestTemplate()
        
        # Test escaping
        escaped = template._escape_html("<script>alert('xss')</script>")
        assert "&lt;script&gt;" in escaped
        assert "&lt;/script&gt;" in escaped
        assert "<script>" not in escaped
    
    def test_list_rendering(self):
        """Test list rendering to HTML."""
        class TestTemplate(BaseTemplate):
            def __init__(self):
                super().__init__("test")
            
            def get_template_content(self):
                return "$list_content"
        
        template = TestTemplate()
        
        # Test list rendering
        test_list = ["item1", "item2", "item3"]
        rendered = template._render_list(test_list)
        
        assert "<ul>" in rendered
        assert "</ul>" in rendered
        assert "<li>item1</li>" in rendered
        assert "<li>item2</li>" in rendered
        assert "<li>item3</li>" in rendered
    
    def test_dict_rendering(self):
        """Test dictionary rendering to HTML table."""
        class TestTemplate(BaseTemplate):
            def __init__(self):
                super().__init__("test")
            
            def get_template_content(self):
                return "$dict_content"
        
        template = TestTemplate()
        
        # Test dict rendering
        test_dict = {"key1": "value1", "key2": "value2"}
        rendered = template._render_dict(test_dict)
        
        assert "<table" in rendered
        assert "</table>" in rendered
        assert "<tr>" in rendered
        assert "</tr>" in rendered
        assert "key1" in rendered
        assert "value1" in rendered 