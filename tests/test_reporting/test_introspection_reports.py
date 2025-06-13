"""
Unit tests for introspection data reporting.

Tests that all reporters correctly handle and format introspection data
from the enhanced MCP introspection system.
"""

import pytest
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

from src.hawkeye.reporting.base import (
    ReportData, ReportMetadata, ReportType, ReportFormat, IntrospectionSummary
)
from src.hawkeye.reporting.json_reporter import JSONReporter
from src.hawkeye.reporting.csv_reporter import CSVReporter
from src.hawkeye.reporting.xml_reporter import XMLReporter
from src.hawkeye.reporting.html_reporter import HTMLReporter
from src.hawkeye.reporting.introspection_reporter import IntrospectionReporter
from src.hawkeye.detection.mcp_introspection.models import (
    MCPServerInfo, MCPTool, MCPResource, MCPCapabilities, RiskLevel
)
from src.hawkeye.detection.pipeline import PipelineResult


class TestIntrospectionReporting:
    """Test introspection data reporting across all formats."""
    
    @pytest.fixture
    def sample_mcp_server(self):
        """Create a sample MCP server with introspection data."""
        tools = [
            MCPTool(
                name="file_read",
                description="Read files from filesystem",
                parameters={
                    "path": {"type": "string", "required": True},
                    "encoding": {"type": "string", "default": "utf-8"}
                }
            ),
            MCPTool(
                name="web_search",
                description="Search the web",
                parameters={
                    "query": {"type": "string", "required": True},
                    "limit": {"type": "integer", "default": 10}
                }
            )
        ]
        
        resources = [
            MCPResource(
                uri="file:///etc/passwd",
                name="system_passwd",
                description="System password file",
                mime_type="text/plain"
            ),
            MCPResource(
                uri="https://api.example.com/data",
                name="api_data",
                description="External API data",
                mime_type="application/json"
            )
        ]
        
        server = MCPServerInfo("test-server", "localhost")
        server.port = 8080
        server.tools = tools
        server.resources = resources
        server.overall_risk_level = RiskLevel.HIGH
        server.risk_score = 7.5
        server.security_risks = ["file_access", "network_access"]
        server.discovery_timestamp = datetime.now().isoformat()
        
        return server
    
    @pytest.fixture
    def sample_capabilities(self):
        """Create sample MCP capabilities."""
        return MCPCapabilities(
            server_name="test-server",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            tools=[],
            resources=[],
            capabilities={
                "notifications": {},
                "tools": {"listChanged": True},
                "resources": {"listChanged": True}
            }
        )
    
    @pytest.fixture
    def sample_introspection_summary(self):
        """Create sample introspection summary."""
        return IntrospectionSummary(
            total_servers_introspected=5,
            successful_introspections=4,
            failed_introspections=1,
            total_tools_discovered=12,
            total_resources_discovered=8,
            total_capabilities_discovered=15,
            critical_risk_servers=1,
            high_risk_servers=2,
            medium_risk_servers=1,
            low_risk_servers=0,
            minimal_risk_servers=0,
            file_access_tools=3,
            network_tools=4,
            code_execution_tools=2,
            data_access_tools=2,
            system_tools=1,
            stdio_servers=2,
            http_servers=2,
            sse_servers=1,
            websocket_servers=0,
            introspection_duration=45.5
        )
    
    @pytest.fixture
    def sample_pipeline_result(self, sample_mcp_server):
        """Create sample pipeline result with introspection data."""
        start_time = datetime.now()
        end_time = datetime.now()
        
        return PipelineResult(
            target_host="localhost",
            start_time=start_time,
            end_time=end_time,
            duration=30.5,
            success=True,
            detection_results={},
            introspection_results={"test-server": sample_mcp_server},
            total_detections=3,
            successful_detections=2,
            failed_detections=1,
            mcp_servers_found=1,
            best_mcp_server=sample_mcp_server,
            highest_confidence_result=None,
            risk_assessment={
                "risk_factors": ["file_access", "high_privilege"],
                "security_concerns": ["Unrestricted file access"],
                "recommendations": ["Implement access controls"]
            },
            errors=[],
            warnings=["High risk server detected"],
            raw_data={}
        )
    
    @pytest.fixture
    def sample_report_data(self, sample_mcp_server, sample_capabilities, 
                          sample_introspection_summary, sample_pipeline_result):
        """Create comprehensive report data with introspection information."""
        metadata = ReportMetadata(
            title="MCP Introspection Test Report",
            report_type=ReportType.INTROSPECTION_REPORT,
            format=ReportFormat.JSON
        )
        
        data = ReportData(metadata)
        data.mcp_servers = [sample_mcp_server]
        data.introspection_data = {"test-server": sample_capabilities}
        data.introspection_summary = sample_introspection_summary
        data.pipeline_results = [sample_pipeline_result]
        data.executive_summary = "Test executive summary with introspection findings"
        data.recommendations = [
            "Implement strict access controls for file operations",
            "Monitor network access patterns",
            "Regular security audits of MCP servers"
        ]
        
        return data
    
    def test_json_reporter_introspection(self, sample_mcp_server, sample_capabilities, sample_introspection_summary):
        """Test JSON reporter with introspection data."""
        metadata = ReportMetadata(
            title="MCP Introspection Test Report",
            report_type=ReportType.INTROSPECTION_REPORT,
            format=ReportFormat.JSON
        )
        
        data = ReportData(metadata)
        data.mcp_servers = [sample_mcp_server]
        data.introspection_data = {"test-server": sample_capabilities}
        data.introspection_summary = sample_introspection_summary
        
        reporter = JSONReporter()
        result = reporter.generate_report(data)
        
        # Parse and validate JSON
        report_dict = json.loads(result)
        
        # Check basic structure
        assert "metadata" in report_dict
        assert "mcp_servers" in report_dict
        assert "introspection_data" in report_dict
        assert "aggregated_statistics" in report_dict
        
        # Check MCP servers
        assert len(report_dict["mcp_servers"]) == 1
        server = report_dict["mcp_servers"][0]
        assert server["name"] == "test-server"
        assert server["host"] == "localhost"
        assert server["tool_count"] == 2
        assert server["resource_count"] == 2
    
    def test_csv_reporter_introspection(self, sample_mcp_server, sample_capabilities, sample_introspection_summary):
        """Test CSV reporter with introspection data."""
        metadata = ReportMetadata(
            title="MCP Introspection Test Report",
            report_type=ReportType.INTROSPECTION_REPORT,
            format=ReportFormat.CSV
        )
        
        data = ReportData(metadata)
        data.mcp_servers = [sample_mcp_server]
        data.introspection_data = {"test-server": sample_capabilities}
        data.introspection_summary = sample_introspection_summary
        
        reporter = CSVReporter()
        result = reporter.generate_report(data)
        
        # Check that introspection sections are present
        assert "# INTROSPECTION SUMMARY" in result
        assert "# MCP SERVERS DISCOVERED" in result
        assert "# INTROSPECTION CAPABILITIES" in result
        
        # Check introspection summary data
        lines = result.split('\n')
        summary_section = False
        for line in lines:
            if "# INTROSPECTION SUMMARY" in line:
                summary_section = True
            elif summary_section and "Total Servers Introspected" in line:
                assert "5" in line  # From sample data
                break
    
    def test_xml_reporter_introspection(self, sample_mcp_server, sample_capabilities, sample_introspection_summary):
        """Test XML reporter with introspection data."""
        metadata = ReportMetadata(
            title="MCP Introspection Test Report",
            report_type=ReportType.INTROSPECTION_REPORT,
            format=ReportFormat.XML
        )
        
        data = ReportData(metadata)
        data.mcp_servers = [sample_mcp_server]
        data.introspection_data = {"test-server": sample_capabilities}
        data.introspection_summary = sample_introspection_summary
        
        reporter = XMLReporter()
        result = reporter.generate_report(data)
        
        # Parse XML
        root = ET.fromstring(result)
        
        # Check basic structure
        assert root.tag == "hawkeye_report"
        assert root.find("metadata") is not None
        assert root.find("executive_summary") is not None
        assert root.find("introspection_data") is not None
        
        # Check introspection summary in executive summary
        exec_summary = root.find("executive_summary")
        introspection_summary = exec_summary.find("introspection_summary")
        assert introspection_summary is not None
        assert introspection_summary.find("total_servers_introspected").text == "5"
        assert introspection_summary.find("successful_introspections").text == "4"
        
        # Check introspection data section
        introspection_data = root.find("introspection_data")
        assert introspection_data is not None
        
        # Check MCP servers
        mcp_servers = introspection_data.find("mcp_servers")
        assert mcp_servers is not None
        assert mcp_servers.get("count") == "1"
        
        server = mcp_servers.find("mcp_server")
        assert server is not None
        assert server.find("name").text == "test-server"
        assert server.find("host").text == "localhost"
        assert server.find("tool_count").text == "2"
        assert server.find("resource_count").text == "2"
    
    def test_html_reporter_introspection(self, sample_report_data):
        """Test HTML reporter with introspection data."""
        reporter = HTMLReporter()
        result = reporter.generate_report(sample_report_data, template_name="technical_report")
        
        # Check that HTML is generated
        assert "<html" in result or "<!DOCTYPE" in result
        assert "test-server" in result
        assert "localhost" in result
        
        # Check for introspection-related content
        assert "introspection" in result.lower() or "mcp" in result.lower()
    
    def test_introspection_reporter_specialized(self, sample_mcp_server, sample_capabilities, sample_introspection_summary):
        """Test specialized introspection reporter."""
        metadata = ReportMetadata(
            title="MCP Introspection Test Report",
            report_type=ReportType.INTROSPECTION_REPORT,
            format=ReportFormat.JSON
        )
        
        data = ReportData(metadata)
        data.mcp_servers = [sample_mcp_server]
        data.introspection_data = {"test-server": sample_capabilities}
        data.introspection_summary = sample_introspection_summary
        
        reporter = IntrospectionReporter()
        result = reporter.generate_report(data)
        
        # Parse JSON result
        report_dict = json.loads(result)
        
        # Check specialized introspection analysis
        assert "introspection_analysis" in report_dict
        analysis = report_dict["introspection_analysis"]
        
        # Check analysis sections
        assert "executive_summary" in analysis
        assert "server_analysis" in analysis
        assert "tool_analysis" in analysis
        assert "resource_analysis" in analysis
        assert "capability_analysis" in analysis
        assert "security_analysis" in analysis
        assert "risk_assessment" in analysis
        assert "recommendations" in analysis
        assert "detailed_findings" in analysis
    
    def test_all_reporters_handle_empty_introspection(self):
        """Test that all reporters handle empty introspection data gracefully."""
        metadata = ReportMetadata(
            title="Empty Introspection Test",
            report_type=ReportType.INTROSPECTION_REPORT,
            format=ReportFormat.JSON
        )
        
        data = ReportData(metadata)
        # No introspection data added
        
        reporters = [
            JSONReporter(),
            CSVReporter(),
            XMLReporter(),
            IntrospectionReporter()
        ]
        
        for reporter in reporters:
            try:
                result = reporter.generate_report(data)
                assert result is not None
                assert len(result) > 0
            except Exception as e:
                pytest.fail(f"{reporter.__class__.__name__} failed with empty data: {e}")
    
    def test_pipeline_result_introspection_integration(self, sample_pipeline_result):
        """Test that pipeline results with introspection data are properly handled."""
        metadata = ReportMetadata(
            title="Pipeline Integration Test",
            report_type=ReportType.COMBINED_REPORT,
            format=ReportFormat.JSON
        )
        
        data = ReportData(metadata)
        data.pipeline_results = [sample_pipeline_result]
        
        # Test JSON reporter
        json_reporter = JSONReporter()
        json_result = json_reporter.generate_report(data)
        json_data = json.loads(json_result)
        
        assert "pipeline_results" in json_data
        pipeline_results = json_data["pipeline_results"]
        assert len(pipeline_results) == 1
        
        pipeline_result = pipeline_results[0]
        assert pipeline_result["target_host"] == "localhost"
        assert pipeline_result["success"] == True
        assert pipeline_result["mcp_servers_found"] == 1
        assert pipeline_result["introspection_results_count"] == 1
        assert "best_mcp_server" in pipeline_result
        assert "risk_assessment" in pipeline_result
        
        # Test XML reporter
        xml_reporter = XMLReporter()
        xml_result = xml_reporter.generate_report(data)
        xml_root = ET.fromstring(xml_result)
        
        pipeline_section = xml_root.find("pipeline_results")
        assert pipeline_section is not None
        assert pipeline_section.get("count") == "1"
        
        pipeline_elem = pipeline_section.find("pipeline_result")
        assert pipeline_elem is not None
        assert pipeline_elem.find("target_host").text == "localhost"
        assert pipeline_elem.find("success").text == "true"
        
        stats = pipeline_elem.find("statistics")
        assert stats.find("mcp_servers_found").text == "1"
        assert stats.find("introspection_results_count").text == "1"
    
    def test_report_data_introspection_properties(self, sample_report_data):
        """Test ReportData introspection-related properties."""
        # Test has_introspection_data
        assert sample_report_data.has_introspection_data == True
        
        # Test introspected_servers property
        servers = sample_report_data.introspected_servers
        assert len(servers) >= 1  # At least one from mcp_servers
        
        # Test total_tools_discovered property
        assert sample_report_data.total_tools_discovered >= 2
        
        # Test total_resources_discovered property
        assert sample_report_data.total_resources_discovered >= 2
        
        # Test get_servers_by_risk_level
        high_risk_servers = sample_report_data.get_servers_by_risk_level("high")
        assert len(high_risk_servers) >= 1
        
        # Test get_tools_by_category
        file_tools = sample_report_data.get_tools_by_category("file")
        assert len(file_tools) >= 1  # Should find file_read tool


if __name__ == "__main__":
    pytest.main([__file__]) 