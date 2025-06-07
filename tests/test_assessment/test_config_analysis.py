"""
Unit tests for security configuration analysis functionality.
"""

import pytest
import json
import yaml
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from src.hawkeye.assessment.config_analysis import (
    ConfigurationIssue, SecurityConfiguration, ConfigurationAnalyzer,
    analyze_configuration
)
from src.hawkeye.assessment.base import (
    RiskLevel, VulnerabilityCategory, ComplianceFramework, ConfigurationError
)
from src.hawkeye.detection.base import (
    DetectionResult, DetectionMethod, MCPServerInfo, TransportType, MCPServerType
)


class TestConfigurationIssue:
    """Test cases for ConfigurationIssue class."""
    
    def test_configuration_issue_init(self):
        """Test configuration issue initialization."""
        issue = ConfigurationIssue(
            issue_id="TEST_001",
            title="Test Issue",
            description="A test configuration issue",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test.json",
            current_value="false",
            recommended_value="true",
            remediation="Enable authentication"
        )
        
        assert issue.issue_id == "TEST_001"
        assert issue.title == "Test Issue"
        assert issue.description == "A test configuration issue"
        assert issue.severity == RiskLevel.HIGH
        assert issue.category == VulnerabilityCategory.AUTHENTICATION
        assert issue.affected_config == "test.json"
        assert issue.current_value == "false"
        assert issue.recommended_value == "true"
        assert issue.remediation == "Enable authentication"
        assert issue.compliance_violations == []
        assert issue.references == []


class TestSecurityConfiguration:
    """Test cases for SecurityConfiguration class."""
    
    def test_security_configuration_init(self):
        """Test security configuration initialization."""
        config = SecurityConfiguration(
            target_host="localhost",
            transport_type=TransportType.HTTP
        )
        
        assert config.target_host == "localhost"
        assert config.transport_type == TransportType.HTTP
        assert config.configuration_files == []
        assert config.security_settings == {}
        assert config.issues == []
        assert config.security_score == 0.0
        assert config.recommendations == []
    
    def test_critical_issues_property(self):
        """Test critical_issues property."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        critical_issue = ConfigurationIssue(
            issue_id="CRIT_001",
            title="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        high_issue = ConfigurationIssue(
            issue_id="HIGH_001",
            title="High Issue",
            description="High",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        config.issues = [critical_issue, high_issue]
        
        critical_issues = config.critical_issues
        assert len(critical_issues) == 1
        assert critical_issues[0].severity == RiskLevel.CRITICAL
    
    def test_high_issues_property(self):
        """Test high_issues property."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        critical_issue = ConfigurationIssue(
            issue_id="CRIT_001",
            title="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        high_issue = ConfigurationIssue(
            issue_id="HIGH_001",
            title="High Issue",
            description="High",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        config.issues = [critical_issue, high_issue]
        
        high_issues = config.high_issues
        assert len(high_issues) == 1
        assert high_issues[0].severity == RiskLevel.HIGH
    
    def test_get_issues_by_category(self):
        """Test get_issues_by_category method."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        auth_issue = ConfigurationIssue(
            issue_id="AUTH_001",
            title="Auth Issue",
            description="Auth",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        network_issue = ConfigurationIssue(
            issue_id="NET_001",
            title="Network Issue",
            description="Network",
            severity=RiskLevel.MEDIUM,
            category=VulnerabilityCategory.NETWORK,
            affected_config="test",
            current_value="*"
        )
        
        config.issues = [auth_issue, network_issue]
        
        auth_issues = config.get_issues_by_category(VulnerabilityCategory.AUTHENTICATION)
        assert len(auth_issues) == 1
        assert auth_issues[0].category == VulnerabilityCategory.AUTHENTICATION
        
        network_issues = config.get_issues_by_category(VulnerabilityCategory.NETWORK)
        assert len(network_issues) == 1
        assert network_issues[0].category == VulnerabilityCategory.NETWORK
        
        encryption_issues = config.get_issues_by_category(VulnerabilityCategory.ENCRYPTION)
        assert len(encryption_issues) == 0
    
    def test_calculate_security_score_no_issues(self):
        """Test security score calculation with no issues."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        config.calculate_security_score()
        
        assert config.security_score == 10.0
    
    def test_calculate_security_score_with_issues(self):
        """Test security score calculation with various issues."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        # Add issues of different severities
        critical_issue = ConfigurationIssue(
            issue_id="CRIT_001",
            title="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        high_issue = ConfigurationIssue(
            issue_id="HIGH_001",
            title="High Issue",
            description="High",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.ENCRYPTION,
            affected_config="test",
            current_value="false"
        )
        
        medium_issue = ConfigurationIssue(
            issue_id="MED_001",
            title="Medium Issue",
            description="Medium",
            severity=RiskLevel.MEDIUM,
            category=VulnerabilityCategory.NETWORK,
            affected_config="test",
            current_value="*"
        )
        
        config.issues = [critical_issue, high_issue, medium_issue]
        config.calculate_security_score()
        
        # Score should be 10.0 - 4.0 (critical) - 2.0 (high) - 1.0 (medium) = 3.0
        assert config.security_score == 3.0
    
    def test_calculate_security_score_minimum(self):
        """Test security score calculation doesn't go below 0."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        # Add many critical issues
        for i in range(5):
            critical_issue = ConfigurationIssue(
                issue_id=f"CRIT_{i:03d}",
                title=f"Critical Issue {i}",
                description="Critical",
                severity=RiskLevel.CRITICAL,
                category=VulnerabilityCategory.AUTHENTICATION,
                affected_config="test",
                current_value="false"
            )
            config.issues.append(critical_issue)
        
        config.calculate_security_score()
        
        # Score should not go below 0
        assert config.security_score == 0.0


class TestConfigurationAnalyzer:
    """Test cases for ConfigurationAnalyzer class."""
    
    @pytest.fixture
    def analyzer(self):
        """Create configuration analyzer for testing."""
        return ConfigurationAnalyzer()
    
    @pytest.fixture
    def sample_detection_result(self):
        """Create sample detection result for testing."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={
                'authentication_required': False,
                'tls_enabled': False,
                'authentication_methods': ['basic']
            }
        )
        
        return DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            mcp_server=server_info,
            confidence=0.9,
            raw_data={
                'configuration_files': [],
                'environment_variables': {
                    'DEBUG': 'true',
                    'MCP_URL': 'http://localhost:3000'
                },
                'command_line': 'node server.js --debug --insecure'
            }
        )
    
    def test_analyzer_init(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer.logger is not None
        assert hasattr(analyzer, 'all_rules')
        assert hasattr(analyzer, 'compliance_mappings')
        assert len(analyzer.all_rules) > 0
        assert len(analyzer.compliance_mappings) > 0
    
    def test_get_assessment_type(self, analyzer):
        """Test get_assessment_type method."""
        assert analyzer.get_assessment_type() == "security_configuration_analysis"
    
    def test_assess_basic_functionality(self, analyzer, sample_detection_result):
        """Test basic assess functionality."""
        result = analyzer.assess(sample_detection_result)
        
        assert result.target_host == "localhost"
        assert len(result.findings) > 0
        assert result.overall_risk_level != RiskLevel.NONE
        assert 'security_configuration' in result.raw_data
    
    def test_analyze_server_configuration_insecure_transport(self, analyzer):
        """Test analysis of insecure transport configuration."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={'tls_enabled': False}
        )
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_server_configuration(server_info, config)
        
        # Should detect insecure transport
        insecure_issues = [issue for issue in config.issues if issue.issue_id == "INSECURE_TRANSPORT"]
        assert len(insecure_issues) == 1
        assert insecure_issues[0].severity == RiskLevel.HIGH
    
    def test_analyze_server_configuration_default_port(self, analyzer):
        """Test analysis of default port usage."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,  # Default port
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE
        )
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_server_configuration(server_info, config)
        
        # Should detect default port usage
        port_issues = [issue for issue in config.issues if issue.issue_id == "DEFAULT_PORT"]
        assert len(port_issues) == 1
        assert port_issues[0].severity == RiskLevel.LOW
    
    def test_analyze_server_configuration_open_binding(self, analyzer):
        """Test analysis of open network binding."""
        server_info = MCPServerInfo(
            host="0.0.0.0",  # Open binding
            port=8080,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE
        )
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_server_configuration(server_info, config)
        
        # Should detect open network binding
        binding_issues = [issue for issue in config.issues if issue.issue_id == "OPEN_NETWORK_BINDING"]
        assert len(binding_issues) == 1
        assert binding_issues[0].severity == RiskLevel.MEDIUM
    
    def test_analyze_security_info_no_authentication(self, analyzer):
        """Test analysis of missing authentication."""
        security_info = {
            'authentication_required': False,
            'tls_enabled': True
        }
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_security_info(security_info, config)
        
        # Should detect missing authentication
        auth_issues = [issue for issue in config.issues if issue.issue_id == "NO_AUTHENTICATION"]
        assert len(auth_issues) == 1
        assert auth_issues[0].severity == RiskLevel.CRITICAL
    
    def test_analyze_security_info_weak_authentication(self, analyzer):
        """Test analysis of weak authentication methods."""
        security_info = {
            'authentication_required': True,
            'authentication_methods': ['basic', 'none'],
            'tls_enabled': True
        }
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_security_info(security_info, config)
        
        # Should detect weak authentication
        weak_auth_issues = [issue for issue in config.issues if issue.issue_id == "WEAK_AUTHENTICATION"]
        assert len(weak_auth_issues) == 1
        assert weak_auth_issues[0].severity == RiskLevel.HIGH
    
    def test_analyze_security_info_tls_disabled(self, analyzer):
        """Test analysis of disabled TLS."""
        security_info = {
            'authentication_required': True,
            'tls_enabled': False
        }
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_security_info(security_info, config)
        
        # Should detect disabled TLS
        tls_issues = [issue for issue in config.issues if issue.issue_id == "TLS_DISABLED"]
        assert len(tls_issues) == 1
        assert tls_issues[0].severity == RiskLevel.HIGH
    
    def test_analyze_security_info_weak_tls_version(self, analyzer):
        """Test analysis of weak TLS version."""
        security_info = {
            'authentication_required': True,
            'tls_enabled': True,
            'tls_version': '1.0'  # Weak version
        }
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_security_info(security_info, config)
        
        # Should detect weak TLS version
        weak_tls_issues = [issue for issue in config.issues if issue.issue_id == "WEAK_TLS_VERSION"]
        assert len(weak_tls_issues) == 1
        assert weak_tls_issues[0].severity == RiskLevel.MEDIUM
    
    def test_analyze_environment_variables_debug_enabled(self, analyzer):
        """Test analysis of debug mode in environment variables."""
        env_vars = {
            'DEBUG': 'true',
            'NODE_ENV': 'production'
        }
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_environment_variables(env_vars, config)
        
        # Should detect debug mode
        debug_issues = [issue for issue in config.issues if issue.issue_id == "DEBUG_ENABLED"]
        assert len(debug_issues) == 1
        assert debug_issues[0].severity == RiskLevel.MEDIUM
    
    def test_analyze_environment_variables_insecure_url(self, analyzer):
        """Test analysis of insecure URLs in environment variables."""
        env_vars = {
            'API_URL': 'http://api.example.com',
            'DATABASE_URL': 'https://db.example.com'
        }
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_environment_variables(env_vars, config)
        
        # Should detect insecure URL
        url_issues = [issue for issue in config.issues if issue.issue_id == "INSECURE_URL"]
        assert len(url_issues) == 1
        assert url_issues[0].severity == RiskLevel.MEDIUM
        assert url_issues[0].affected_config == "env:API_URL"
    
    def test_analyze_command_line_insecure_flags(self, analyzer):
        """Test analysis of insecure command line flags."""
        command_line = "node server.js --insecure --no-ssl --debug"
        
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_command_line(command_line, config)
        
        # Should detect multiple insecure flags
        flag_issues = [issue for issue in config.issues if issue.issue_id == "INSECURE_COMMAND_FLAG"]
        assert len(flag_issues) == 3  # --insecure, --no-ssl, --debug
        
        # Check severities
        high_severity_issues = [issue for issue in flag_issues if issue.severity == RiskLevel.HIGH]
        medium_severity_issues = [issue for issue in flag_issues if issue.severity == RiskLevel.MEDIUM]
        
        assert len(high_severity_issues) == 2  # --insecure, --no-ssl
        assert len(medium_severity_issues) == 1  # --debug
    
    def test_analyze_configuration_file_json(self, analyzer):
        """Test analysis of JSON configuration file."""
        config_data = {
            "server": {
                "auth": False,
                "ssl": False,
                "host": "0.0.0.0",
                "password": "admin123"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            config = SecurityConfiguration("localhost", TransportType.HTTP)
            analyzer._analyze_configuration_file(temp_path, config)
            
            # Should detect multiple issues
            assert len(config.issues) > 0
            assert temp_path in config.configuration_files
            
            # Check for hardcoded secret
            secret_issues = [issue for issue in config.issues if issue.issue_id == "HARDCODED_SECRET"]
            assert len(secret_issues) >= 1
            
        finally:
            Path(temp_path).unlink()
    
    def test_analyze_configuration_file_yaml(self, analyzer):
        """Test analysis of YAML configuration file."""
        config_data = {
            "mcp": {
                "authentication": False,
                "tls": {
                    "enabled": False
                },
                "cors": {
                    "origin": "*"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name
        
        try:
            config = SecurityConfiguration("localhost", TransportType.HTTP)
            analyzer._analyze_configuration_file(temp_path, config)
            
            # Should detect configuration issues
            assert len(config.issues) > 0
            assert temp_path in config.configuration_files
            
        finally:
            Path(temp_path).unlink()
    
    def test_analyze_transport_security_http(self, analyzer):
        """Test transport security analysis for HTTP."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        analyzer._analyze_transport_security(config)
        
        # Should detect unencrypted HTTP transport
        http_issues = [issue for issue in config.issues if issue.issue_id == "HTTP_TRANSPORT"]
        assert len(http_issues) == 1
        assert http_issues[0].severity == RiskLevel.HIGH
    
    def test_analyze_transport_security_websocket(self, analyzer):
        """Test transport security analysis for WebSocket."""
        config = SecurityConfiguration("localhost", TransportType.WEBSOCKET)
        analyzer._analyze_transport_security(config)
        
        # Should detect unencrypted WebSocket transport
        ws_issues = [issue for issue in config.issues if issue.issue_id == "WS_TRANSPORT"]
        assert len(ws_issues) == 1
        assert ws_issues[0].severity == RiskLevel.HIGH
    
    def test_analyze_transport_security_stdio(self, analyzer):
        """Test transport security analysis for STDIO."""
        config = SecurityConfiguration("localhost", TransportType.STDIO)
        analyzer._analyze_transport_security(config)
        
        # Should not detect transport issues for STDIO
        transport_issues = [issue for issue in config.issues 
                          if issue.issue_id in ["HTTP_TRANSPORT", "WS_TRANSPORT"]]
        assert len(transport_issues) == 0
    
    def test_generate_recommendations(self, analyzer):
        """Test recommendation generation."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        # Add various issues
        critical_issue = ConfigurationIssue(
            issue_id="CRIT_001",
            title="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        auth_issue = ConfigurationIssue(
            issue_id="AUTH_001",
            title="Auth Issue",
            description="Auth",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test",
            current_value="false"
        )
        
        network_issue = ConfigurationIssue(
            issue_id="NET_001",
            title="Network Issue",
            description="Network",
            severity=RiskLevel.MEDIUM,
            category=VulnerabilityCategory.NETWORK,
            affected_config="test",
            current_value="*"
        )
        
        config.issues = [critical_issue, auth_issue, network_issue]
        analyzer._generate_recommendations(config)
        
        # Should generate relevant recommendations
        assert len(config.recommendations) > 0
        
        # Check for specific recommendations
        recommendations_text = ' '.join(config.recommendations).lower()
        assert 'critical' in recommendations_text
        assert 'authentication' in recommendations_text
        assert 'network' in recommendations_text
        assert 'tls' in recommendations_text or 'ssl' in recommendations_text
    
    def test_convert_issues_to_findings(self, analyzer):
        """Test conversion of configuration issues to security findings."""
        config = SecurityConfiguration("localhost", TransportType.HTTP)
        
        issue = ConfigurationIssue(
            issue_id="TEST_001",
            title="Test Issue",
            description="Test description",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            affected_config="test.json",
            current_value="false",
            recommended_value="true",
            remediation="Enable authentication",
            compliance_violations=[ComplianceFramework.OWASP_TOP_10]
        )
        
        config.issues = [issue]
        config.security_score = 7.5
        
        findings = analyzer._convert_issues_to_findings(config)
        
        assert len(findings) == 1
        finding = findings[0]
        
        assert finding.title == "Test Issue"
        assert finding.description == "Test description"
        assert finding.severity == RiskLevel.HIGH
        assert finding.category == VulnerabilityCategory.AUTHENTICATION
        assert finding.confidence == 0.9
        assert finding.affected_asset == "localhost"
        assert finding.remediation == "Enable authentication"
        assert ComplianceFramework.OWASP_TOP_10 in finding.compliance_violations
        
        # Check evidence
        assert finding.evidence['affected_config'] == "test.json"
        assert finding.evidence['current_value'] == "false"
        assert finding.evidence['recommended_value'] == "true"
        assert finding.evidence['security_score'] == 7.5
    
    def test_flatten_dict(self, analyzer):
        """Test dictionary flattening utility."""
        nested_dict = {
            'server': {
                'auth': {
                    'enabled': False,
                    'method': 'basic'
                },
                'port': 3000
            },
            'debug': True
        }
        
        flattened = analyzer._flatten_dict(nested_dict)
        
        expected = {
            'server.auth.enabled': False,
            'server.auth.method': 'basic',
            'server.port': 3000,
            'debug': True
        }
        
        assert flattened == expected
    
    def test_assess_with_exception(self, analyzer):
        """Test assess method with exception handling."""
        # Create invalid detection result
        invalid_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True
        )
        
        # Mock an exception in analysis
        with patch.object(analyzer, '_analyze_security_configuration', side_effect=Exception("Test error")):
            with pytest.raises(ConfigurationError):
                analyzer.assess(invalid_result)


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    def test_analyze_configuration_function(self):
        """Test analyze_configuration convenience function."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={'authentication_required': False}
        )
        
        detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            mcp_server=server_info,
            confidence=0.9
        )
        
        config = analyze_configuration(detection_result)
        
        assert isinstance(config, SecurityConfiguration)
        assert config.target_host == "localhost"
        assert config.transport_type == TransportType.HTTP
        assert len(config.issues) > 0  # Should detect authentication issue


class TestSecurityRules:
    """Test cases for security rule patterns."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer for testing."""
        return ConfigurationAnalyzer()
    
    def test_authentication_rules(self, analyzer):
        """Test authentication security rules."""
        # Test no authentication pattern
        test_configs = [
            ("auth", "false"),
            ("authentication", "disabled"),
            ("require_auth", "false")
        ]
        
        for key, value in test_configs:
            config = SecurityConfiguration("localhost", TransportType.HTTP)
            analyzer._analyze_security_setting(key, value, config, "test.json")
            
            # Should detect authentication issues
            auth_issues = [issue for issue in config.issues 
                          if issue.category == VulnerabilityCategory.AUTHENTICATION]
            assert len(auth_issues) > 0
    
    def test_encryption_rules(self, analyzer):
        """Test encryption security rules."""
        # Test encryption disabled patterns
        test_configs = [
            ("ssl", "false"),
            ("tls", "disabled"),
            ("https", "false")
        ]
        
        for key, value in test_configs:
            config = SecurityConfiguration("localhost", TransportType.HTTP)
            analyzer._analyze_security_setting(key, value, config, "test.json")
            
            # Should detect encryption issues
            encryption_issues = [issue for issue in config.issues 
                               if issue.category == VulnerabilityCategory.ENCRYPTION]
            assert len(encryption_issues) > 0
    
    def test_network_rules(self, analyzer):
        """Test network security rules."""
        # Test open access patterns
        test_configs = [
            ("bind", "0.0.0.0"),
            ("host", "*"),
            ("cors_origin", "*")
        ]
        
        for key, value in test_configs:
            config = SecurityConfiguration("localhost", TransportType.HTTP)
            analyzer._analyze_security_setting(key, value, config, "test.json")
            
            # Should detect network issues
            network_issues = [issue for issue in config.issues 
                            if issue.category == VulnerabilityCategory.NETWORK]
            assert len(network_issues) > 0
    
    def test_logging_rules(self, analyzer):
        """Test logging security rules."""
        # Test logging disabled patterns
        test_configs = [
            ("log", "false"),
            ("logging", "disabled"),
            ("audit", "false")
        ]
        
        for key, value in test_configs:
            config = SecurityConfiguration("localhost", TransportType.HTTP)
            analyzer._analyze_security_setting(key, value, config, "test.json")
            
            # Should detect logging issues
            logging_issues = [issue for issue in config.issues 
                            if issue.category == VulnerabilityCategory.LOGGING]
            assert len(logging_issues) > 0


if __name__ == '__main__':
    pytest.main([__file__]) 