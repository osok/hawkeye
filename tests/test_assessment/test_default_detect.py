"""
Unit tests for default configuration detection functionality.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from src.hawkeye.assessment.default_detect import (
    DefaultPattern, DefaultDetectionResult, DefaultConfigurationDetector,
    detect_default_configurations, get_default_patterns, check_for_pattern
)
from src.hawkeye.assessment.base import (
    RiskLevel, VulnerabilityCategory, ComplianceFramework, ConfigurationError
)
from src.hawkeye.detection.base import (
    DetectionResult, DetectionMethod, MCPServerInfo, TransportType, MCPServerType
)


class TestDefaultPattern:
    """Test cases for DefaultPattern class."""
    
    def test_default_pattern_init(self):
        """Test default pattern initialization."""
        pattern = DefaultPattern(
            pattern_id="TEST_001",
            name="Test Pattern",
            description="A test default pattern",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            detection_patterns=[r'"password"\s*:\s*"admin"'],
            port_patterns=[3000],
            remediation="Change default password"
        )
        
        assert pattern.pattern_id == "TEST_001"
        assert pattern.name == "Test Pattern"
        assert pattern.description == "A test default pattern"
        assert pattern.severity == RiskLevel.HIGH
        assert pattern.category == VulnerabilityCategory.AUTHENTICATION
        assert pattern.detection_patterns == [r'"password"\s*:\s*"admin"']
        assert pattern.port_patterns == [3000]
        assert pattern.remediation == "Change default password"
        assert pattern.file_patterns == []
        assert pattern.environment_patterns == {}
        assert pattern.references == []
        assert pattern.compliance_violations == []


class TestDefaultDetectionResult:
    """Test cases for DefaultDetectionResult class."""
    
    def test_default_detection_result_init(self):
        """Test default detection result initialization."""
        result = DefaultDetectionResult(target_host="localhost")
        
        assert result.target_host == "localhost"
        assert result.detected_defaults == []
        assert result.configuration_files == []
        assert result.environment_variables == {}
        assert result.process_info is None
        assert result.risk_score == 0.0
        assert result.recommendations == []
    
    def test_critical_defaults_property(self):
        """Test critical_defaults property."""
        result = DefaultDetectionResult(target_host="localhost")
        
        critical_pattern = DefaultPattern(
            pattern_id="CRIT_001",
            name="Critical Pattern",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        high_pattern = DefaultPattern(
            pattern_id="HIGH_001",
            name="High Pattern",
            description="High",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        result.detected_defaults = [critical_pattern, high_pattern]
        
        critical_defaults = result.critical_defaults
        assert len(critical_defaults) == 1
        assert critical_defaults[0].severity == RiskLevel.CRITICAL
    
    def test_high_defaults_property(self):
        """Test high_defaults property."""
        result = DefaultDetectionResult(target_host="localhost")
        
        critical_pattern = DefaultPattern(
            pattern_id="CRIT_001",
            name="Critical Pattern",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        high_pattern = DefaultPattern(
            pattern_id="HIGH_001",
            name="High Pattern",
            description="High",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        result.detected_defaults = [critical_pattern, high_pattern]
        
        high_defaults = result.high_defaults
        assert len(high_defaults) == 1
        assert high_defaults[0].severity == RiskLevel.HIGH
    
    def test_get_defaults_by_category(self):
        """Test get_defaults_by_category method."""
        result = DefaultDetectionResult(target_host="localhost")
        
        auth_pattern = DefaultPattern(
            pattern_id="AUTH_001",
            name="Auth Pattern",
            description="Auth",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        config_pattern = DefaultPattern(
            pattern_id="CONFIG_001",
            name="Config Pattern",
            description="Config",
            severity=RiskLevel.MEDIUM,
            category=VulnerabilityCategory.CONFIGURATION
        )
        
        result.detected_defaults = [auth_pattern, config_pattern]
        
        auth_defaults = result.get_defaults_by_category(VulnerabilityCategory.AUTHENTICATION)
        assert len(auth_defaults) == 1
        assert auth_defaults[0].category == VulnerabilityCategory.AUTHENTICATION
        
        config_defaults = result.get_defaults_by_category(VulnerabilityCategory.CONFIGURATION)
        assert len(config_defaults) == 1
        assert config_defaults[0].category == VulnerabilityCategory.CONFIGURATION
        
        encryption_defaults = result.get_defaults_by_category(VulnerabilityCategory.ENCRYPTION)
        assert len(encryption_defaults) == 0
    
    def test_calculate_risk_score_no_defaults(self):
        """Test risk score calculation with no defaults."""
        result = DefaultDetectionResult(target_host="localhost")
        result.calculate_risk_score()
        
        assert result.risk_score == 0.0
    
    def test_calculate_risk_score_with_defaults(self):
        """Test risk score calculation with various defaults."""
        result = DefaultDetectionResult(target_host="localhost")
        
        # Add defaults of different severities
        critical_pattern = DefaultPattern(
            pattern_id="CRIT_001",
            name="Critical Pattern",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        high_pattern = DefaultPattern(
            pattern_id="HIGH_001",
            name="High Pattern",
            description="High",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.ENCRYPTION
        )
        
        medium_pattern = DefaultPattern(
            pattern_id="MED_001",
            name="Medium Pattern",
            description="Medium",
            severity=RiskLevel.MEDIUM,
            category=VulnerabilityCategory.NETWORK
        )
        
        result.detected_defaults = [critical_pattern, high_pattern, medium_pattern]
        result.calculate_risk_score()
        
        # Score should be 3.0 (critical) + 2.0 (high) + 1.0 (medium) = 6.0
        assert result.risk_score == 6.0
    
    def test_calculate_risk_score_maximum(self):
        """Test risk score calculation doesn't exceed 10.0."""
        result = DefaultDetectionResult(target_host="localhost")
        
        # Add many critical defaults
        for i in range(5):
            critical_pattern = DefaultPattern(
                pattern_id=f"CRIT_{i:03d}",
                name=f"Critical Pattern {i}",
                description="Critical",
                severity=RiskLevel.CRITICAL,
                category=VulnerabilityCategory.AUTHENTICATION
            )
            result.detected_defaults.append(critical_pattern)
        
        result.calculate_risk_score()
        
        # Score should not exceed 10.0
        assert result.risk_score == 10.0


class TestDefaultConfigurationDetector:
    """Test cases for DefaultConfigurationDetector class."""
    
    @pytest.fixture
    def detector(self):
        """Create default configuration detector for testing."""
        return DefaultConfigurationDetector()
    
    @pytest.fixture
    def sample_detection_result(self):
        """Create sample detection result for testing."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,  # Default port
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={
                'auth': False,
                'ssl': False,
                'debug': True
            },
            authentication={
                'enabled': False,
                'password': 'admin'
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
                    'NODE_ENV': 'development'
                },
                'command_line': 'npx @modelcontextprotocol/server --port 3000 --no-auth'
            }
        )
    
    def test_detector_init(self, detector):
        """Test detector initialization."""
        assert detector.logger is not None
        assert hasattr(detector, 'default_patterns')
        assert len(detector.default_patterns) > 0
        
        # Check that we have patterns for different categories
        pattern_categories = {pattern.category for pattern in detector.default_patterns}
        assert VulnerabilityCategory.AUTHENTICATION in pattern_categories
        assert VulnerabilityCategory.CONFIGURATION in pattern_categories
        assert VulnerabilityCategory.ENCRYPTION in pattern_categories
    
    def test_get_assessment_type(self, detector):
        """Test get_assessment_type method."""
        assert detector.get_assessment_type() == "default_configuration_detection"
    
    def test_assess_basic_functionality(self, detector, sample_detection_result):
        """Test basic assess functionality."""
        result = detector.assess(sample_detection_result)
        
        assert result.target_host == "localhost"
        assert len(result.findings) > 0
        assert result.overall_risk_level != RiskLevel.NONE
        assert 'default_detection' in result.raw_data
    
    def test_analyze_server_defaults_default_port(self, detector):
        """Test analysis of default port configuration."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,  # Default port
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE
        )
        
        result = DefaultDetectionResult("localhost")
        detector._analyze_server_defaults(server_info, result)
        
        # Should detect default port
        port_defaults = [d for d in result.detected_defaults if d.pattern_id == "DEFAULT_PORT_3000"]
        assert len(port_defaults) == 1
    
    def test_analyze_server_defaults_multiple_ports(self, detector):
        """Test analysis with multiple default ports."""
        ports_to_test = [3000, 8000, 8080]
        
        for port in ports_to_test:
            server_info = MCPServerInfo(
                host="localhost",
                port=port,
                transport_type=TransportType.HTTP,
                server_type=MCPServerType.STANDALONE
            )
            
            result = DefaultDetectionResult("localhost")
            detector._analyze_server_defaults(server_info, result)
            
            # Should detect the corresponding default port pattern
            port_defaults = [d for d in result.detected_defaults if port in d.port_patterns]
            assert len(port_defaults) >= 1
    
    def test_analyze_security_config_defaults(self, detector):
        """Test analysis of security configuration defaults."""
        security_config = {
            'auth': False,
            'ssl': False,
            'debug': True,
            'password': 'admin'
        }
        
        result = DefaultDetectionResult("localhost")
        detector._analyze_security_config_defaults(security_config, result)
        
        # Should detect multiple default patterns
        assert len(result.detected_defaults) > 0
        
        # Check for specific patterns
        pattern_ids = [d.pattern_id for d in result.detected_defaults]
        assert any('AUTH' in pid for pid in pattern_ids)
        assert any('SSL' in pid for pid in pattern_ids)
    
    def test_analyze_auth_config_defaults_disabled(self, detector):
        """Test analysis of disabled authentication."""
        auth_config = {'enabled': False}
        
        result = DefaultDetectionResult("localhost")
        detector._analyze_auth_config_defaults(auth_config, result)
        
        # Should detect disabled authentication
        auth_disabled = [d for d in result.detected_defaults if d.pattern_id == "DEFAULT_AUTH_DISABLED"]
        assert len(auth_disabled) == 1
    
    def test_analyze_auth_config_defaults_weak_password(self, detector):
        """Test analysis of weak authentication credentials."""
        auth_config = {
            'enabled': True,
            'password': 'admin',
            'api_key': 'test'
        }
        
        result = DefaultDetectionResult("localhost")
        detector._analyze_auth_config_defaults(auth_config, result)
        
        # Should detect weak credentials
        assert len(result.detected_defaults) > 0
        
        # Check for authentication-related patterns
        auth_patterns = [d for d in result.detected_defaults 
                        if d.category == VulnerabilityCategory.AUTHENTICATION]
        assert len(auth_patterns) > 0
    
    def test_analyze_configuration_file_defaults_json(self, detector):
        """Test analysis of JSON configuration file defaults."""
        config_data = {
            "server": {
                "auth": False,
                "ssl": False,
                "password": "admin123",
                "api_key": "test",
                "debug": True
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            result = DefaultDetectionResult("localhost")
            detector._analyze_configuration_file_defaults(temp_path, result)
            
            # Should detect multiple default patterns
            assert len(result.detected_defaults) > 0
            assert temp_path in result.configuration_files
            
            # Check for specific patterns
            pattern_ids = [d.pattern_id for d in result.detected_defaults]
            assert any('PASSWORD' in pid for pid in pattern_ids)
            
        finally:
            Path(temp_path).unlink()
    
    def test_analyze_configuration_file_defaults_filename(self, detector):
        """Test analysis of default configuration file names."""
        default_filenames = ['config.json', 'settings.json', '.env']
        
        for filename in default_filenames:
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'_{filename}', delete=False) as f:
                f.write('{}')
                temp_path = f.name
            
            try:
                # Rename to match default pattern
                new_path = Path(temp_path).parent / filename
                Path(temp_path).rename(new_path)
                
                result = DefaultDetectionResult("localhost")
                detector._analyze_configuration_file_defaults(str(new_path), result)
                
                # Should detect default file pattern
                file_defaults = [d for d in result.detected_defaults 
                               if filename in d.file_patterns]
                assert len(file_defaults) >= 1
                
            finally:
                if new_path.exists():
                    new_path.unlink()
    
    def test_analyze_environment_defaults(self, detector):
        """Test analysis of environment variable defaults."""
        env_vars = {
            'DEBUG': 'true',
            'NODE_ENV': 'development',
            'LOG_LEVEL': 'debug'
        }
        
        result = DefaultDetectionResult("localhost")
        detector._analyze_environment_defaults(env_vars, result)
        
        # Should detect debug-related defaults
        debug_defaults = [d for d in result.detected_defaults 
                         if d.pattern_id == "DEFAULT_DEBUG_ENABLED"]
        assert len(debug_defaults) >= 1
    
    def test_analyze_command_line_defaults(self, detector):
        """Test analysis of command line defaults."""
        # Test command lines that match the actual regex patterns
        command_lines = [
            'npx @modelcontextprotocol/server --port 3000',  # Should match first pattern
            'npx some-mcp-server --host 0.0.0.0',           # Should match second pattern  
            'npx mcp-tool --no-auth'                         # Should match third pattern
        ]
        
        for command_line in command_lines:
            result = DefaultDetectionResult("localhost")
            detector._analyze_command_line_defaults(command_line, result)
            
            # Should detect NPX-related defaults
            npx_defaults = [d for d in result.detected_defaults 
                           if d.pattern_id == "DEFAULT_NPX_GLOBAL"]
            assert len(npx_defaults) >= 1
    
    def test_generate_default_recommendations(self, detector):
        """Test recommendation generation."""
        result = DefaultDetectionResult("localhost")
        
        # Add various default patterns
        critical_pattern = DefaultPattern(
            pattern_id="CRIT_001",
            name="Critical Pattern",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        auth_pattern = DefaultPattern(
            pattern_id="AUTH_001",
            name="Auth Pattern",
            description="Auth",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION
        )
        
        config_pattern = DefaultPattern(
            pattern_id="CONFIG_001",
            name="Config Pattern",
            description="Config",
            severity=RiskLevel.MEDIUM,
            category=VulnerabilityCategory.CONFIGURATION
        )
        
        result.detected_defaults = [critical_pattern, auth_pattern, config_pattern]
        detector._generate_default_recommendations(result)
        
        # Should generate relevant recommendations
        assert len(result.recommendations) > 0
        
        # Check for specific recommendations
        recommendations_text = ' '.join(result.recommendations).lower()
        assert 'critical' in recommendations_text
        assert 'authentication' in recommendations_text
        assert 'configuration' in recommendations_text
    
    def test_convert_defaults_to_findings(self, detector):
        """Test conversion of default patterns to security findings."""
        result = DefaultDetectionResult("localhost")
        
        pattern = DefaultPattern(
            pattern_id="TEST_001",
            name="Test Pattern",
            description="Test description",
            severity=RiskLevel.HIGH,
            category=VulnerabilityCategory.AUTHENTICATION,
            detection_patterns=[r'"password"\s*:\s*"admin"'],
            remediation="Change default password",
            compliance_violations=[ComplianceFramework.OWASP_TOP_10]
        )
        
        result.detected_defaults = [pattern]
        result.risk_score = 5.0
        
        findings = detector._convert_defaults_to_findings(result)
        
        assert len(findings) == 1
        finding = findings[0]
        
        assert finding.title == "Test Pattern"
        assert finding.description == "Test description"
        assert finding.severity == RiskLevel.HIGH
        assert finding.category == VulnerabilityCategory.AUTHENTICATION
        assert finding.confidence == 0.8
        assert finding.affected_asset == "localhost"
        assert finding.remediation == "Change default password"
        assert ComplianceFramework.OWASP_TOP_10 in finding.compliance_violations
        
        # Check evidence
        assert finding.evidence['pattern_id'] == "TEST_001"
        assert finding.evidence['detection_patterns'] == [r'"password"\s*:\s*"admin"']
        assert finding.evidence['risk_score'] == 5.0
    
    def test_assess_with_exception(self, detector):
        """Test assess method with exception handling."""
        # Create invalid detection result
        invalid_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True
        )
        
        # Mock an exception in detection
        with patch.object(detector, '_detect_default_configurations', side_effect=Exception("Test error")):
            with pytest.raises(ConfigurationError):
                detector.assess(invalid_result)


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    def test_detect_default_configurations_function(self):
        """Test detect_default_configurations convenience function."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,  # Default port
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={'auth': False}
        )
        
        detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            mcp_server=server_info,
            confidence=0.9
        )
        
        result = detect_default_configurations(detection_result)
        
        assert isinstance(result, DefaultDetectionResult)
        assert result.target_host == "localhost"
        assert len(result.detected_defaults) > 0
    
    def test_get_default_patterns_function(self):
        """Test get_default_patterns convenience function."""
        patterns = get_default_patterns()
        
        assert isinstance(patterns, list)
        assert len(patterns) > 0
        assert all(isinstance(p, DefaultPattern) for p in patterns)
        
        # Check that we have patterns for different categories
        pattern_categories = {pattern.category for pattern in patterns}
        assert VulnerabilityCategory.AUTHENTICATION in pattern_categories
        assert VulnerabilityCategory.CONFIGURATION in pattern_categories
    
    def test_check_for_pattern_function(self):
        """Test check_for_pattern convenience function."""
        # Test with content that should match
        content_with_default = '{"password": "admin", "debug": true}'
        
        # This should match the default admin password pattern
        result = check_for_pattern(content_with_default, "DEFAULT_ADMIN_PASSWORD")
        assert result is True
        
        # Test with content that shouldn't match
        content_without_default = '{"password": "secure_random_password", "debug": false}'
        result = check_for_pattern(content_without_default, "DEFAULT_ADMIN_PASSWORD")
        assert result is False
        
        # Test with non-existent pattern
        result = check_for_pattern(content_with_default, "NON_EXISTENT_PATTERN")
        assert result is False


class TestDefaultPatterns:
    """Test cases for specific default patterns."""
    
    @pytest.fixture
    def detector(self):
        """Create detector for testing."""
        return DefaultConfigurationDetector()
    
    def test_default_port_patterns(self, detector):
        """Test default port detection patterns."""
        default_ports = [3000, 8000, 8080]
        
        for port in default_ports:
            server_info = MCPServerInfo(
                host="localhost",
                port=port,
                transport_type=TransportType.HTTP,
                server_type=MCPServerType.STANDALONE
            )
            
            result = DefaultDetectionResult("localhost")
            detector._analyze_server_defaults(server_info, result)
            
            # Should detect the default port
            port_patterns = [d for d in result.detected_defaults if port in d.port_patterns]
            assert len(port_patterns) >= 1
    
    def test_default_password_patterns(self, detector):
        """Test default password detection patterns."""
        test_configs = [
            '{"password": "admin"}',
            '{"password": "password"}',
            '{"password": "123456"}',
            '{"password": "admin123"}',
            'password=admin'
        ]
        
        for config in test_configs:
            result = DefaultDetectionResult("localhost")
            detector._analyze_content_defaults(config, result)
            
            # Should detect default password
            password_patterns = [d for d in result.detected_defaults 
                               if d.pattern_id == "DEFAULT_ADMIN_PASSWORD"]
            assert len(password_patterns) >= 1
    
    def test_default_api_key_patterns(self, detector):
        """Test default API key detection patterns."""
        test_configs = [
            '{"api_key": "test"}',
            '{"api-key": "demo"}',
            '{"token": "example"}',
            'api_key=test'
        ]
        
        for config in test_configs:
            result = DefaultDetectionResult("localhost")
            detector._analyze_content_defaults(config, result)
            
            # Should detect default API key
            api_key_patterns = [d for d in result.detected_defaults 
                              if d.pattern_id == "DEFAULT_API_KEY"]
            assert len(api_key_patterns) >= 1
    
    def test_default_ssl_disabled_patterns(self, detector):
        """Test SSL disabled detection patterns."""
        test_configs = [
            '{"ssl": false}',
            '{"tls": false}',
            '{"https": false}',
            '{"secure": false}'
        ]
        
        for config in test_configs:
            result = DefaultDetectionResult("localhost")
            detector._analyze_content_defaults(config, result)
            
            # Should detect SSL disabled
            ssl_patterns = [d for d in result.detected_defaults 
                          if d.pattern_id == "DEFAULT_SSL_DISABLED"]
            assert len(ssl_patterns) >= 1
    
    def test_default_debug_enabled_patterns(self, detector):
        """Test debug mode enabled detection patterns."""
        test_configs = [
            '{"debug": true}',
            '{"log_level": "debug"}',
            '{"verbose": true}'
        ]
        
        for config in test_configs:
            result = DefaultDetectionResult("localhost")
            detector._analyze_content_defaults(config, result)
            
            # Should detect debug enabled
            debug_patterns = [d for d in result.detected_defaults 
                            if d.pattern_id == "DEFAULT_DEBUG_ENABLED"]
            assert len(debug_patterns) >= 1
    
    def test_default_cors_wildcard_patterns(self, detector):
        """Test CORS wildcard detection patterns."""
        test_configs = [
            '{"origin": "*"}',
            '{"cors": {"origin": "*"}}',
            'Access-Control-Allow-Origin: *'
        ]
        
        for config in test_configs:
            result = DefaultDetectionResult("localhost")
            detector._analyze_content_defaults(config, result)
            
            # Should detect CORS wildcard
            cors_patterns = [d for d in result.detected_defaults 
                           if d.pattern_id == "DEFAULT_CORS_WILDCARD"]
            assert len(cors_patterns) >= 1


if __name__ == '__main__':
    pytest.main([__file__]) 