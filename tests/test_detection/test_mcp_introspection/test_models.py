"""
Unit tests for MCP introspection data models.

Tests the enhanced data models for MCP capabilities, tools, resources,
server information, and risk assessment functionality.
"""

import pytest
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from unittest.mock import Mock

from src.hawkeye.detection.mcp_introspection.models import (
    MCPCapabilities,
    MCPTool,
    MCPResource,
    MCPServerInfo,
    MCPIntrospectionResult,
    RiskAssessment,
    SecurityFinding,
    ComplianceCheck,
    PerformanceMetrics,
    TransportConfig,
    ValidationError,
    RiskLevel,
    SecurityCategory,
    ComplianceStatus
)


class TestMCPCapabilities:
    """Test MCPCapabilities data class."""
    
    def test_default_capabilities(self):
        """Test default capability values."""
        capabilities = MCPCapabilities()
        
        assert capabilities.supports_tools is False
        assert capabilities.supports_resources is False
        assert capabilities.supports_prompts is False
        assert capabilities.supports_logging is False
        assert capabilities.supports_completion is False
        assert capabilities.supports_sampling is False
        assert capabilities.experimental_capabilities == {}
        assert capabilities.server_version is None
        assert capabilities.protocol_version is None
    
    def test_custom_capabilities(self):
        """Test custom capability values."""
        experimental = {"custom_feature": True, "beta_api": "v2"}
        capabilities = MCPCapabilities(
            supports_tools=True,
            supports_resources=True,
            supports_prompts=True,
            supports_logging=True,
            supports_completion=True,
            supports_sampling=True,
            experimental_capabilities=experimental,
            server_version="1.2.3",
            protocol_version="2024-11-05"
        )
        
        assert capabilities.supports_tools is True
        assert capabilities.supports_resources is True
        assert capabilities.supports_prompts is True
        assert capabilities.supports_logging is True
        assert capabilities.supports_completion is True
        assert capabilities.supports_sampling is True
        assert capabilities.experimental_capabilities == experimental
        assert capabilities.server_version == "1.2.3"
        assert capabilities.protocol_version == "2024-11-05"
    
    def test_has_capability(self):
        """Test capability checking method."""
        capabilities = MCPCapabilities(
            supports_tools=True,
            supports_resources=False,
            experimental_capabilities={"custom": True}
        )
        
        assert capabilities.has_capability("tools") is True
        assert capabilities.has_capability("resources") is False
        assert capabilities.has_capability("custom") is True
        assert capabilities.has_capability("nonexistent") is False
    
    def test_get_capability_count(self):
        """Test capability counting method."""
        capabilities = MCPCapabilities(
            supports_tools=True,
            supports_resources=True,
            supports_prompts=False,
            experimental_capabilities={"custom1": True, "custom2": False}
        )
        
        count = capabilities.get_capability_count()
        assert count == 3  # tools + resources + custom1


class TestMCPTool:
    """Test MCPTool data class."""
    
    def test_basic_tool(self):
        """Test basic tool creation."""
        schema = {
            "type": "object",
            "properties": {
                "filename": {"type": "string"},
                "content": {"type": "string"}
            },
            "required": ["filename"]
        }
        
        tool = MCPTool(
            name="write_file",
            description="Write content to a file",
            input_schema=schema
        )
        
        assert tool.name == "write_file"
        assert tool.description == "Write content to a file"
        assert tool.input_schema == schema
        assert tool.risk_categories == []
        assert tool.risk_level == RiskLevel.UNKNOWN
        assert tool.security_notes == []
    
    def test_tool_with_risk_assessment(self):
        """Test tool with risk assessment."""
        schema = {"type": "object", "properties": {"command": {"type": "string"}}}
        risk_categories = [SecurityCategory.CODE_EXECUTION, SecurityCategory.SYSTEM_ACCESS]
        security_notes = ["Executes arbitrary commands", "Requires system privileges"]
        
        tool = MCPTool(
            name="execute_command",
            description="Execute system command",
            input_schema=schema,
            risk_categories=risk_categories,
            risk_level=RiskLevel.HIGH,
            security_notes=security_notes
        )
        
        assert tool.risk_categories == risk_categories
        assert tool.risk_level == RiskLevel.HIGH
        assert tool.security_notes == security_notes
    
    def test_has_risk_category(self):
        """Test risk category checking."""
        tool = MCPTool(
            name="test_tool",
            description="Test tool",
            input_schema={},
            risk_categories=[SecurityCategory.FILE_SYSTEM, SecurityCategory.NETWORK_ACCESS]
        )
        
        assert tool.has_risk_category(SecurityCategory.FILE_SYSTEM) is True
        assert tool.has_risk_category(SecurityCategory.NETWORK_ACCESS) is True
        assert tool.has_risk_category(SecurityCategory.CODE_EXECUTION) is False
    
    def test_get_required_parameters(self):
        """Test getting required parameters from schema."""
        schema = {
            "type": "object",
            "properties": {
                "required_param": {"type": "string"},
                "optional_param": {"type": "string"}
            },
            "required": ["required_param"]
        }
        
        tool = MCPTool(
            name="test_tool",
            description="Test tool",
            input_schema=schema
        )
        
        required = tool.get_required_parameters()
        assert required == ["required_param"]
    
    def test_get_optional_parameters(self):
        """Test getting optional parameters from schema."""
        schema = {
            "type": "object",
            "properties": {
                "required_param": {"type": "string"},
                "optional_param": {"type": "string"}
            },
            "required": ["required_param"]
        }
        
        tool = MCPTool(
            name="test_tool",
            description="Test tool",
            input_schema=schema
        )
        
        optional = tool.get_optional_parameters()
        assert optional == ["optional_param"]


class TestMCPResource:
    """Test MCPResource data class."""
    
    def test_basic_resource(self):
        """Test basic resource creation."""
        resource = MCPResource(
            uri="file:///path/to/file.txt",
            name="config_file",
            description="Configuration file"
        )
        
        assert resource.uri == "file:///path/to/file.txt"
        assert resource.name == "config_file"
        assert resource.description == "Configuration file"
        assert resource.mime_type is None
        assert resource.risk_categories == []
        assert resource.risk_level == RiskLevel.UNKNOWN
        assert resource.security_notes == []
    
    def test_resource_with_risk_assessment(self):
        """Test resource with risk assessment."""
        risk_categories = [SecurityCategory.DATA_ACCESS, SecurityCategory.PRIVACY]
        security_notes = ["Contains sensitive data", "PII exposure risk"]
        
        resource = MCPResource(
            uri="database://localhost/users",
            name="user_database",
            description="User database",
            mime_type="application/sql",
            risk_categories=risk_categories,
            risk_level=RiskLevel.MEDIUM,
            security_notes=security_notes
        )
        
        assert resource.mime_type == "application/sql"
        assert resource.risk_categories == risk_categories
        assert resource.risk_level == RiskLevel.MEDIUM
        assert resource.security_notes == security_notes
    
    def test_get_uri_scheme(self):
        """Test URI scheme extraction."""
        resource = MCPResource(
            uri="https://api.example.com/data",
            name="api_data",
            description="API data"
        )
        
        scheme = resource.get_uri_scheme()
        assert scheme == "https"
    
    def test_is_local_resource(self):
        """Test local resource detection."""
        local_resource = MCPResource(
            uri="file:///local/path",
            name="local_file",
            description="Local file"
        )
        
        remote_resource = MCPResource(
            uri="https://remote.com/data",
            name="remote_data",
            description="Remote data"
        )
        
        assert local_resource.is_local_resource() is True
        assert remote_resource.is_local_resource() is False


class TestMCPServerInfo:
    """Test MCPServerInfo data class."""
    
    def test_basic_server_info(self):
        """Test basic server info creation."""
        capabilities = MCPCapabilities(supports_tools=True)
        tools = [MCPTool(name="test_tool", description="Test", input_schema={})]
        resources = [MCPResource(uri="file://test", name="test", description="Test")]
        
        server_info = MCPServerInfo(
            name="test_server",
            command="node",
            args=["server.js"],
            transport_type="stdio",
            capabilities=capabilities,
            tools=tools,
            resources=resources
        )
        
        assert server_info.name == "test_server"
        assert server_info.command == "node"
        assert server_info.args == ["server.js"]
        assert server_info.transport_type == "stdio"
        assert server_info.capabilities == capabilities
        assert server_info.tools == tools
        assert server_info.resources == resources
        assert server_info.risk_level == RiskLevel.UNKNOWN
        assert server_info.error_message is None
        assert server_info.introspection_timestamp is not None
    
    def test_server_info_with_error(self):
        """Test server info with error."""
        server_info = MCPServerInfo(
            name="failed_server",
            command="node",
            args=["server.js"],
            transport_type="stdio",
            capabilities=MCPCapabilities(),
            tools=[],
            resources=[],
            error_message="Connection failed"
        )
        
        assert server_info.error_message == "Connection failed"
        assert server_info.has_error() is True
    
    def test_get_tool_count(self):
        """Test tool count method."""
        tools = [
            MCPTool(name="tool1", description="Test", input_schema={}),
            MCPTool(name="tool2", description="Test", input_schema={})
        ]
        
        server_info = MCPServerInfo(
            name="test_server",
            command="node",
            args=[],
            transport_type="stdio",
            capabilities=MCPCapabilities(),
            tools=tools,
            resources=[]
        )
        
        assert server_info.get_tool_count() == 2
    
    def test_get_resource_count(self):
        """Test resource count method."""
        resources = [
            MCPResource(uri="file://1", name="res1", description="Test"),
            MCPResource(uri="file://2", name="res2", description="Test"),
            MCPResource(uri="file://3", name="res3", description="Test")
        ]
        
        server_info = MCPServerInfo(
            name="test_server",
            command="node",
            args=[],
            transport_type="stdio",
            capabilities=MCPCapabilities(),
            tools=[],
            resources=resources
        )
        
        assert server_info.get_resource_count() == 3
    
    def test_get_high_risk_tools(self):
        """Test getting high risk tools."""
        tools = [
            MCPTool(name="safe_tool", description="Safe", input_schema={}, risk_level=RiskLevel.LOW),
            MCPTool(name="risky_tool", description="Risky", input_schema={}, risk_level=RiskLevel.HIGH),
            MCPTool(name="critical_tool", description="Critical", input_schema={}, risk_level=RiskLevel.CRITICAL)
        ]
        
        server_info = MCPServerInfo(
            name="test_server",
            command="node",
            args=[],
            transport_type="stdio",
            capabilities=MCPCapabilities(),
            tools=tools,
            resources=[]
        )
        
        high_risk = server_info.get_high_risk_tools()
        assert len(high_risk) == 2
        assert high_risk[0].name == "risky_tool"
        assert high_risk[1].name == "critical_tool"


class TestRiskAssessment:
    """Test RiskAssessment data class."""
    
    def test_basic_risk_assessment(self):
        """Test basic risk assessment creation."""
        findings = [
            SecurityFinding(
                category=SecurityCategory.CODE_EXECUTION,
                severity=RiskLevel.HIGH,
                description="Allows code execution",
                recommendation="Restrict execution permissions"
            )
        ]
        
        assessment = RiskAssessment(
            overall_risk_level=RiskLevel.HIGH,
            security_findings=findings,
            risk_score=8.5
        )
        
        assert assessment.overall_risk_level == RiskLevel.HIGH
        assert assessment.security_findings == findings
        assert assessment.risk_score == 8.5
        assert assessment.compliance_checks == []
        assert assessment.assessment_timestamp is not None
    
    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        findings = [
            SecurityFinding(SecurityCategory.FILE_SYSTEM, RiskLevel.LOW, "Low risk", "Monitor"),
            SecurityFinding(SecurityCategory.NETWORK_ACCESS, RiskLevel.HIGH, "High risk", "Restrict"),
            SecurityFinding(SecurityCategory.CODE_EXECUTION, RiskLevel.CRITICAL, "Critical risk", "Block")
        ]
        
        assessment = RiskAssessment(
            overall_risk_level=RiskLevel.HIGH,
            security_findings=findings,
            risk_score=7.0
        )
        
        high_findings = assessment.get_findings_by_severity(RiskLevel.HIGH)
        assert len(high_findings) == 2  # HIGH and CRITICAL
        
        critical_findings = assessment.get_findings_by_severity(RiskLevel.CRITICAL)
        assert len(critical_findings) == 1
    
    def test_get_findings_by_category(self):
        """Test filtering findings by category."""
        findings = [
            SecurityFinding(SecurityCategory.FILE_SYSTEM, RiskLevel.LOW, "File access", "Monitor"),
            SecurityFinding(SecurityCategory.FILE_SYSTEM, RiskLevel.HIGH, "File write", "Restrict"),
            SecurityFinding(SecurityCategory.NETWORK_ACCESS, RiskLevel.MEDIUM, "Network call", "Review")
        ]
        
        assessment = RiskAssessment(
            overall_risk_level=RiskLevel.MEDIUM,
            security_findings=findings,
            risk_score=5.0
        )
        
        file_findings = assessment.get_findings_by_category(SecurityCategory.FILE_SYSTEM)
        assert len(file_findings) == 2
        
        network_findings = assessment.get_findings_by_category(SecurityCategory.NETWORK_ACCESS)
        assert len(network_findings) == 1


class TestSecurityFinding:
    """Test SecurityFinding data class."""
    
    def test_security_finding_creation(self):
        """Test security finding creation."""
        finding = SecurityFinding(
            category=SecurityCategory.DATA_ACCESS,
            severity=RiskLevel.MEDIUM,
            description="Accesses sensitive data",
            recommendation="Implement access controls",
            affected_components=["user_tool", "data_resource"],
            cve_references=["CVE-2023-1234"],
            mitigation_steps=["Step 1", "Step 2"]
        )
        
        assert finding.category == SecurityCategory.DATA_ACCESS
        assert finding.severity == RiskLevel.MEDIUM
        assert finding.description == "Accesses sensitive data"
        assert finding.recommendation == "Implement access controls"
        assert finding.affected_components == ["user_tool", "data_resource"]
        assert finding.cve_references == ["CVE-2023-1234"]
        assert finding.mitigation_steps == ["Step 1", "Step 2"]
    
    def test_is_high_severity(self):
        """Test high severity checking."""
        high_finding = SecurityFinding(
            SecurityCategory.CODE_EXECUTION,
            RiskLevel.HIGH,
            "High risk",
            "Fix it"
        )
        
        critical_finding = SecurityFinding(
            SecurityCategory.SYSTEM_ACCESS,
            RiskLevel.CRITICAL,
            "Critical risk",
            "Fix immediately"
        )
        
        low_finding = SecurityFinding(
            SecurityCategory.DATA_ACCESS,
            RiskLevel.LOW,
            "Low risk",
            "Monitor"
        )
        
        assert high_finding.is_high_severity() is True
        assert critical_finding.is_high_severity() is True
        assert low_finding.is_high_severity() is False


class TestComplianceCheck:
    """Test ComplianceCheck data class."""
    
    def test_compliance_check_creation(self):
        """Test compliance check creation."""
        check = ComplianceCheck(
            framework="SOC2",
            control_id="CC6.1",
            description="Logical access security",
            status=ComplianceStatus.COMPLIANT,
            evidence=["Access controls implemented", "Audit logs enabled"],
            recommendations=["Regular review", "Update policies"]
        )
        
        assert check.framework == "SOC2"
        assert check.control_id == "CC6.1"
        assert check.description == "Logical access security"
        assert check.status == ComplianceStatus.COMPLIANT
        assert check.evidence == ["Access controls implemented", "Audit logs enabled"]
        assert check.recommendations == ["Regular review", "Update policies"]
    
    def test_is_compliant(self):
        """Test compliance status checking."""
        compliant_check = ComplianceCheck(
            "GDPR", "Art.32", "Security", ComplianceStatus.COMPLIANT
        )
        
        non_compliant_check = ComplianceCheck(
            "HIPAA", "164.312", "Access control", ComplianceStatus.NON_COMPLIANT
        )
        
        assert compliant_check.is_compliant() is True
        assert non_compliant_check.is_compliant() is False


class TestPerformanceMetrics:
    """Test PerformanceMetrics data class."""
    
    def test_performance_metrics_creation(self):
        """Test performance metrics creation."""
        metrics = PerformanceMetrics(
            connection_time=1.5,
            discovery_time=3.2,
            total_introspection_time=4.7,
            memory_usage_mb=128.5,
            cpu_usage_percent=15.3,
            network_requests=25,
            cache_hit_rate=0.85
        )
        
        assert metrics.connection_time == 1.5
        assert metrics.discovery_time == 3.2
        assert metrics.total_introspection_time == 4.7
        assert metrics.memory_usage_mb == 128.5
        assert metrics.cpu_usage_percent == 15.3
        assert metrics.network_requests == 25
        assert metrics.cache_hit_rate == 0.85
    
    def test_is_performant(self):
        """Test performance checking."""
        fast_metrics = PerformanceMetrics(
            connection_time=0.5,
            discovery_time=1.0,
            total_introspection_time=1.5
        )
        
        slow_metrics = PerformanceMetrics(
            connection_time=5.0,
            discovery_time=10.0,
            total_introspection_time=15.0
        )
        
        assert fast_metrics.is_performant() is True
        assert slow_metrics.is_performant() is False


class TestTransportConfig:
    """Test TransportConfig data class."""
    
    def test_stdio_transport_config(self):
        """Test stdio transport configuration."""
        config = TransportConfig(
            transport_type="stdio",
            command="node",
            args=["server.js"],
            env={"NODE_ENV": "production"},
            working_directory="/app",
            timeout=30.0
        )
        
        assert config.transport_type == "stdio"
        assert config.command == "node"
        assert config.args == ["server.js"]
        assert config.env == {"NODE_ENV": "production"}
        assert config.working_directory == "/app"
        assert config.timeout == 30.0
    
    def test_sse_transport_config(self):
        """Test SSE transport configuration."""
        config = TransportConfig(
            transport_type="sse",
            url="http://localhost:3000/sse",
            headers={"Authorization": "Bearer token"},
            timeout=60.0
        )
        
        assert config.transport_type == "sse"
        assert config.url == "http://localhost:3000/sse"
        assert config.headers == {"Authorization": "Bearer token"}
        assert config.timeout == 60.0
    
    def test_validate_stdio_config(self):
        """Test stdio configuration validation."""
        # Valid config
        valid_config = TransportConfig(
            transport_type="stdio",
            command="node",
            args=["server.js"]
        )
        valid_config.validate()  # Should not raise
        
        # Invalid config - missing command
        invalid_config = TransportConfig(
            transport_type="stdio",
            args=["server.js"]
        )
        
        with pytest.raises(ValidationError):
            invalid_config.validate()
    
    def test_validate_sse_config(self):
        """Test SSE configuration validation."""
        # Valid config
        valid_config = TransportConfig(
            transport_type="sse",
            url="http://localhost:3000/sse"
        )
        valid_config.validate()  # Should not raise
        
        # Invalid config - missing URL
        invalid_config = TransportConfig(
            transport_type="sse"
        )
        
        with pytest.raises(ValidationError):
            invalid_config.validate()


class TestMCPIntrospectionResult:
    """Test MCPIntrospectionResult data class."""
    
    def test_introspection_result_creation(self):
        """Test introspection result creation."""
        server_info = MCPServerInfo(
            name="test_server",
            command="node",
            args=["server.js"],
            transport_type="stdio",
            capabilities=MCPCapabilities(),
            tools=[],
            resources=[]
        )
        
        risk_assessment = RiskAssessment(
            overall_risk_level=RiskLevel.LOW,
            security_findings=[],
            risk_score=2.0
        )
        
        performance_metrics = PerformanceMetrics(
            connection_time=1.0,
            discovery_time=2.0,
            total_introspection_time=3.0
        )
        
        result = MCPIntrospectionResult(
            server_info=server_info,
            risk_assessment=risk_assessment,
            performance_metrics=performance_metrics,
            success=True
        )
        
        assert result.server_info == server_info
        assert result.risk_assessment == risk_assessment
        assert result.performance_metrics == performance_metrics
        assert result.success is True
        assert result.error_message is None
        assert result.timestamp is not None
    
    def test_failed_introspection_result(self):
        """Test failed introspection result."""
        result = MCPIntrospectionResult(
            server_info=None,
            risk_assessment=None,
            performance_metrics=None,
            success=False,
            error_message="Connection failed"
        )
        
        assert result.success is False
        assert result.error_message == "Connection failed"
        assert result.server_info is None
    
    def test_to_dict(self):
        """Test converting result to dictionary."""
        server_info = MCPServerInfo(
            name="test_server",
            command="node",
            args=[],
            transport_type="stdio",
            capabilities=MCPCapabilities(),
            tools=[],
            resources=[]
        )
        
        result = MCPIntrospectionResult(
            server_info=server_info,
            risk_assessment=None,
            performance_metrics=None,
            success=True
        )
        
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict["success"] is True
        assert "server_info" in result_dict
        assert "timestamp" in result_dict


class TestEnums:
    """Test enum classes."""
    
    def test_risk_level_enum(self):
        """Test RiskLevel enum."""
        assert RiskLevel.UNKNOWN.value == "unknown"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"
    
    def test_security_category_enum(self):
        """Test SecurityCategory enum."""
        assert SecurityCategory.FILE_SYSTEM.value == "file_system"
        assert SecurityCategory.NETWORK_ACCESS.value == "network_access"
        assert SecurityCategory.CODE_EXECUTION.value == "code_execution"
        assert SecurityCategory.DATA_ACCESS.value == "data_access"
        assert SecurityCategory.SYSTEM_ACCESS.value == "system_access"
        assert SecurityCategory.PRIVACY.value == "privacy"
        assert SecurityCategory.AUTHENTICATION.value == "authentication"
        assert SecurityCategory.AUTHORIZATION.value == "authorization"
    
    def test_compliance_status_enum(self):
        """Test ComplianceStatus enum."""
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.PARTIALLY_COMPLIANT.value == "partially_compliant"
        assert ComplianceStatus.NOT_APPLICABLE.value == "not_applicable"
        assert ComplianceStatus.UNKNOWN.value == "unknown"


class TestValidationError:
    """Test ValidationError exception."""
    
    def test_validation_error(self):
        """Test ValidationError exception."""
        error = ValidationError("Invalid configuration")
        assert str(error) == "Invalid configuration"
        assert isinstance(error, ValueError)


if __name__ == "__main__":
    pytest.main([__file__]) 