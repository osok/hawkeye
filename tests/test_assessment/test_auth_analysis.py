"""
Unit tests for authentication analysis functionality.
"""

import pytest
import json
import tempfile
import base64
from pathlib import Path
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.hawkeye.assessment.auth_analysis import (
    AuthenticationIssue, AuthenticationConfiguration, AuthenticationAnalyzer,
    analyze_authentication, check_password_strength, validate_jwt_token
)
from src.hawkeye.assessment.base import (
    RiskLevel, VulnerabilityCategory, ComplianceFramework, ConfigurationError
)
from src.hawkeye.detection.base import (
    DetectionResult, DetectionMethod, MCPServerInfo, TransportType, MCPServerType
)


class TestAuthenticationIssue:
    """Test cases for AuthenticationIssue class."""
    
    def test_authentication_issue_init(self):
        """Test authentication issue initialization."""
        issue = AuthenticationIssue(
            issue_id="AUTH_001",
            name="Test Issue",
            description="A test authentication issue",
            severity=RiskLevel.HIGH,
            category="weak_password",
            affected_component="authentication_config",
            evidence={"test": "data"},
            remediation="Fix the issue"
        )
        
        assert issue.issue_id == "AUTH_001"
        assert issue.name == "Test Issue"
        assert issue.description == "A test authentication issue"
        assert issue.severity == RiskLevel.HIGH
        assert issue.category == "weak_password"
        assert issue.affected_component == "authentication_config"
        assert issue.evidence == {"test": "data"}
        assert issue.remediation == "Fix the issue"
        assert issue.references == []
        assert issue.compliance_violations == []


class TestAuthenticationConfiguration:
    """Test cases for AuthenticationConfiguration class."""
    
    def test_authentication_configuration_init(self):
        """Test authentication configuration initialization."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        assert config.target_host == "localhost"
        assert config.authentication_enabled is False
        assert config.authentication_methods == []
        assert config.password_policies == {}
        assert config.token_configurations == {}
        assert config.session_configurations == {}
        assert config.multi_factor_auth is False
        assert config.encryption_in_transit is False
        assert config.issues == []
        assert config.security_score == 0.0
        assert config.recommendations == []
    
    def test_critical_issues_property(self):
        """Test critical_issues property."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        critical_issue = AuthenticationIssue(
            issue_id="CRIT_001",
            name="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category="no_authentication",
            affected_component="server"
        )
        
        high_issue = AuthenticationIssue(
            issue_id="HIGH_001",
            name="High Issue",
            description="High",
            severity=RiskLevel.HIGH,
            category="weak_password",
            affected_component="config"
        )
        
        config.issues = [critical_issue, high_issue]
        
        critical_issues = config.critical_issues
        assert len(critical_issues) == 1
        assert critical_issues[0].severity == RiskLevel.CRITICAL
    
    def test_high_issues_property(self):
        """Test high_issues property."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        critical_issue = AuthenticationIssue(
            issue_id="CRIT_001",
            name="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category="no_authentication",
            affected_component="server"
        )
        
        high_issue = AuthenticationIssue(
            issue_id="HIGH_001",
            name="High Issue",
            description="High",
            severity=RiskLevel.HIGH,
            category="weak_password",
            affected_component="config"
        )
        
        config.issues = [critical_issue, high_issue]
        
        high_issues = config.high_issues
        assert len(high_issues) == 1
        assert high_issues[0].severity == RiskLevel.HIGH
    
    def test_get_issues_by_category(self):
        """Test get_issues_by_category method."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        auth_issue = AuthenticationIssue(
            issue_id="AUTH_001",
            name="Auth Issue",
            description="Auth",
            severity=RiskLevel.HIGH,
            category="no_authentication",
            affected_component="server"
        )
        
        password_issue = AuthenticationIssue(
            issue_id="PASS_001",
            name="Password Issue",
            description="Password",
            severity=RiskLevel.MEDIUM,
            category="weak_password",
            affected_component="config"
        )
        
        config.issues = [auth_issue, password_issue]
        
        auth_issues = config.get_issues_by_category("no_authentication")
        assert len(auth_issues) == 1
        assert auth_issues[0].category == "no_authentication"
        
        password_issues = config.get_issues_by_category("weak_password")
        assert len(password_issues) == 1
        assert password_issues[0].category == "weak_password"
        
        token_issues = config.get_issues_by_category("weak_tokens")
        assert len(token_issues) == 0
    
    def test_calculate_security_score_no_issues(self):
        """Test security score calculation with no issues."""
        config = AuthenticationConfiguration(target_host="localhost")
        config.calculate_security_score()
        
        assert config.security_score == 10.0
    
    def test_calculate_security_score_with_issues(self):
        """Test security score calculation with various issues."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        # Add issues of different severities
        critical_issue = AuthenticationIssue(
            issue_id="CRIT_001",
            name="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category="no_authentication",
            affected_component="server"
        )
        
        high_issue = AuthenticationIssue(
            issue_id="HIGH_001",
            name="High Issue",
            description="High",
            severity=RiskLevel.HIGH,
            category="weak_password",
            affected_component="config"
        )
        
        medium_issue = AuthenticationIssue(
            issue_id="MED_001",
            name="Medium Issue",
            description="Medium",
            severity=RiskLevel.MEDIUM,
            category="insecure_sessions",
            affected_component="session"
        )
        
        config.issues = [critical_issue, high_issue, medium_issue]
        config.calculate_security_score()
        
        # Score should be 10.0 - 3.0 (critical) - 2.0 (high) - 1.0 (medium) = 4.0
        assert config.security_score == 4.0
    
    def test_calculate_security_score_with_bonuses(self):
        """Test security score calculation with bonus points."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        # Enable good practices
        config.authentication_enabled = True
        config.multi_factor_auth = True
        config.encryption_in_transit = True
        config.authentication_methods = ["password", "token"]
        
        config.calculate_security_score()
        
        # Score should be 10.0 + 1.0 (auth) + 1.0 (mfa) + 0.5 (tls) + 0.5 (multiple methods) = 13.0, capped at 10.0
        assert config.security_score == 10.0
    
    def test_calculate_security_score_minimum(self):
        """Test security score calculation doesn't go below 0.0."""
        config = AuthenticationConfiguration(target_host="localhost")
        
        # Add many critical issues
        for i in range(5):
            critical_issue = AuthenticationIssue(
                issue_id=f"CRIT_{i:03d}",
                name=f"Critical Issue {i}",
                description="Critical",
                severity=RiskLevel.CRITICAL,
                category="no_authentication",
                affected_component="server"
            )
            config.issues.append(critical_issue)
        
        config.calculate_security_score()
        
        # Score should not go below 0.0
        assert config.security_score == 0.0


class TestAuthenticationAnalyzer:
    """Test cases for AuthenticationAnalyzer class."""
    
    @pytest.fixture
    def analyzer(self):
        """Create authentication analyzer for testing."""
        return AuthenticationAnalyzer()
    
    @pytest.fixture
    def sample_detection_result(self):
        """Create sample detection result for testing."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={
                'tls_enabled': False,
                'ssl_enabled': False
            },
            authentication={
                'enabled': True,
                'methods': ['password'],
                'password_policy': {
                    'min_length': 6,
                    'require_uppercase': False
                },
                'jwt': {
                    'algorithm': 'HS256',
                    'verify': True
                }
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
                    'PASSWORD': 'admin',
                    'API_KEY': 'test'
                },
                'command_line': 'node server.js --password=weak'
            }
        )
    
    def test_analyzer_init(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer.logger is not None
        assert hasattr(analyzer, 'weak_password_patterns')
        assert hasattr(analyzer, 'compiled_weak_patterns')
        assert hasattr(analyzer, 'auth_rules')
        assert len(analyzer.auth_rules) > 0
        
        # Check that we have rules for different categories
        rule_categories = set(analyzer.auth_rules.keys())
        assert 'no_authentication' in rule_categories
        assert 'weak_password' in rule_categories
        assert 'weak_tokens' in rule_categories
    
    def test_get_assessment_type(self, analyzer):
        """Test get_assessment_type method."""
        assert analyzer.get_assessment_type() == "authentication_analysis"
    
    def test_assess_basic_functionality(self, analyzer, sample_detection_result):
        """Test basic assess functionality."""
        result = analyzer.assess(sample_detection_result)
        
        assert result.target_host == "localhost"
        assert len(result.findings) > 0
        assert result.overall_risk_level != RiskLevel.NONE
        assert 'authentication_analysis' in result.raw_data
    
    def test_is_weak_password(self, analyzer):
        """Test weak password detection."""
        # Weak passwords
        weak_passwords = [
            'admin',
            'password',
            '123456',
            'qwerty',
            'short',
            '',
            '12345678',  # Only digits
            'abcdefgh',  # Only letters
            'qwerty123'  # Common pattern
        ]
        
        for password in weak_passwords:
            assert analyzer._is_weak_password(password), f"Should detect '{password}' as weak"
        
        # Strong passwords
        strong_passwords = [
            'MyStr0ng!P@ssw0rd',
            'C0mpl3x#P@ssw0rd!',
            'Rand0m$ecur3P@ss',
            'L0ng&C0mpl3xP@ssw0rd!'
        ]
        
        for password in strong_passwords:
            assert not analyzer._is_weak_password(password), f"Should not detect '{password}' as weak"
    
    def test_is_weak_credential(self, analyzer):
        """Test weak credential detection."""
        # Weak credentials
        weak_credentials = [
            'test',
            'demo',
            'example',
            'short',
            '',
            '123456789012345',  # Only digits
            'abcdefghijklmnop',  # Only letters
            'secret'
        ]
        
        for credential in weak_credentials:
            assert analyzer._is_weak_credential(credential), f"Should detect '{credential}' as weak"
        
        # Strong credentials
        strong_credentials = [
            'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
            'MyStr0ng!T0k3n#W1th$p3c1@lCh@rs',
            'Rand0m$ecur3T0k3n!W1th#C0mpl3x1ty'
        ]
        
        for credential in strong_credentials:
            assert not analyzer._is_weak_credential(credential), f"Should not detect '{credential}' as weak"
    
    def test_analyze_server_authentication_no_auth(self, analyzer):
        """Test analysis when authentication is disabled."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            authentication={'enabled': False}
        )
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_server_authentication(server_info, config)
        
        assert not config.authentication_enabled
        # Should have issues related to disabled authentication
        auth_issues = [issue for issue in config.issues if 'auth' in issue.category.lower()]
        assert len(auth_issues) > 0
    
    def test_analyze_server_authentication_no_transport_encryption(self, analyzer):
        """Test analysis when transport encryption is disabled."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            security_config={'tls_enabled': False},
            authentication={'enabled': True}
        )
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_server_authentication(server_info, config)
        
        assert not config.encryption_in_transit
        # Should have issues related to insecure transport
        transport_issues = [issue for issue in config.issues if 'transport' in issue.category.lower()]
        assert len(transport_issues) > 0
    
    def test_analyze_passwords(self, analyzer):
        """Test password analysis."""
        auth_config = {
            'password_policy': {
                'min_length': 6,  # Too short
                'require_uppercase': False,
                'require_lowercase': False,
                'require_numbers': False,
                'require_special': False
            },
            'admin_password': 'admin123'  # Weak password
        }
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_passwords(auth_config, config)
        
        # Should detect weak password policy and weak password
        assert len(config.issues) > 0
        
        # Check for specific issues
        policy_issues = [issue for issue in config.issues if 'policy' in issue.category.lower()]
        assert len(policy_issues) > 0
        
        weak_password_issues = [issue for issue in config.issues if 'password' in issue.category.lower()]
        assert len(weak_password_issues) > 0
    
    def test_analyze_tokens(self, analyzer):
        """Test token analysis."""
        auth_config = {
            'api_key': 'test',  # Weak token
            'jwt_secret': 'short',  # Too short
            'tokens': {
                'access_token': 'demo123'  # Weak token
            },
            'jwt': {
                'algorithm': 'none',  # Insecure
                'verify': False  # Insecure
            }
        }
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_tokens(auth_config, config)
        
        # Should detect multiple token issues
        assert len(config.issues) > 0
        
        # Check for specific issues
        token_issues = [issue for issue in config.issues if 'token' in issue.category.lower()]
        assert len(token_issues) > 0
        
        jwt_issues = [issue for issue in config.issues if 'jwt' in issue.category.lower()]
        assert len(jwt_issues) > 0
    
    def test_analyze_sessions(self, analyzer):
        """Test session analysis."""
        auth_config = {
            'session': {
                'cookie_secure': False,  # Insecure
                'http_only': False,  # Insecure
                'timeout': 172800  # Very long (48 hours)
            }
        }
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_sessions(auth_config, config)
        
        # Should detect session security issues
        assert len(config.issues) > 0
        
        # Check for specific issues
        session_issues = [issue for issue in config.issues if 'session' in issue.category.lower()]
        assert len(session_issues) > 0
    
    def test_analyze_config_file_auth(self, analyzer):
        """Test configuration file authentication analysis."""
        config_data = {
            "authentication": {
                "enabled": False,
                "password": "admin123",
                "api_key": "test",
                "jwt_secret": "weak"
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name
        
        try:
            config = AuthenticationConfiguration("localhost")
            analyzer._analyze_config_file_auth(temp_path, config)
            
            # Should detect multiple authentication issues
            assert len(config.issues) > 0
            
            # Check for file-specific issues
            file_issues = [issue for issue in config.issues if temp_path in str(issue.affected_component)]
            assert len(file_issues) > 0
            
        finally:
            Path(temp_path).unlink()
    
    def test_analyze_environment_auth(self, analyzer):
        """Test environment variable authentication analysis."""
        env_vars = {
            'PASSWORD': 'admin',
            'API_KEY': 'test',
            'JWT_SECRET': 'weak',
            'TOKEN': 'demo123',
            'OTHER_VAR': 'not_auth_related'
        }
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_environment_auth(env_vars, config)
        
        # Should detect weak credentials in environment variables
        assert len(config.issues) > 0
        
        # Check that only auth-related variables are flagged
        env_issues = [issue for issue in config.issues if 'environment' in str(issue.affected_component)]
        assert len(env_issues) > 0
        
        # Should not flag non-auth variables
        other_var_issues = [issue for issue in config.issues if 'OTHER_VAR' in str(issue.evidence)]
        assert len(other_var_issues) == 0
    
    def test_analyze_command_line_auth(self, analyzer):
        """Test command line authentication analysis."""
        command_lines = [
            'node server.js --no-auth',
            'npm start --disable-auth',
            'server --password=weak123',
            'app --token=test --api-key=demo'
        ]
        
        for command_line in command_lines:
            config = AuthenticationConfiguration("localhost")
            analyzer._analyze_command_line_auth(command_line, config)
            
            # Should detect authentication issues in command line
            assert len(config.issues) > 0
            
            cmd_issues = [issue for issue in config.issues if 'command' in str(issue.affected_component)]
            assert len(cmd_issues) > 0
    
    def test_analyze_file_content_auth_basic_auth(self, analyzer):
        """Test analysis of Basic authentication in file content."""
        # Create Base64 encoded credentials (admin:weak)
        credentials = base64.b64encode(b'admin:weak').decode('utf-8')
        content = f'Authorization: Basic {credentials}'
        
        config = AuthenticationConfiguration("localhost")
        analyzer._analyze_file_content_auth(content, Path('test.conf'), config)
        
        # Should detect weak Basic authentication
        basic_auth_issues = [issue for issue in config.issues if 'basic' in issue.name.lower()]
        assert len(basic_auth_issues) > 0
    
    def test_is_test_jwt(self, analyzer):
        """Test JWT test token detection."""
        # Create a test JWT token
        header = base64.b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
        payload = base64.b64encode(json.dumps({
            'iss': 'test-issuer',
            'aud': 'demo-audience',
            'sub': 'test-user',
            'exp': 9999999999
        }).encode()).decode().rstrip('=')
        signature = 'fake_signature'
        
        test_jwt = f'{header}.{payload}.{signature}'
        
        assert analyzer._is_test_jwt(test_jwt)
        
        # Create a production-like JWT token
        prod_payload = base64.b64encode(json.dumps({
            'iss': 'production-issuer',
            'aud': 'production-audience',
            'sub': 'user123',
            'exp': 9999999999
        }).encode()).decode().rstrip('=')
        
        prod_jwt = f'{header}.{prod_payload}.{signature}'
        
        assert not analyzer._is_test_jwt(prod_jwt)
    
    def test_generate_auth_recommendations(self, analyzer):
        """Test authentication recommendation generation."""
        config = AuthenticationConfiguration("localhost")
        
        # Add various issues
        critical_issue = AuthenticationIssue(
            issue_id="CRIT_001",
            name="Critical Issue",
            description="Critical",
            severity=RiskLevel.CRITICAL,
            category="no_authentication",
            affected_component="server"
        )
        
        weak_password_issue = AuthenticationIssue(
            issue_id="PASS_001",
            name="Weak Password",
            description="Weak password",
            severity=RiskLevel.HIGH,
            category="weak_password",
            affected_component="config"
        )
        
        token_issue = AuthenticationIssue(
            issue_id="TOKEN_001",
            name="Weak Token",
            description="Weak token",
            severity=RiskLevel.HIGH,
            category="weak_tokens",
            affected_component="config"
        )
        
        config.issues = [critical_issue, weak_password_issue, token_issue]
        config.authentication_enabled = False
        config.multi_factor_auth = False
        config.encryption_in_transit = False
        
        analyzer._generate_auth_recommendations(config)
        
        # Should generate relevant recommendations
        assert len(config.recommendations) > 0
        
        # Check for specific recommendations
        recommendations_text = ' '.join(config.recommendations).lower()
        assert 'critical' in recommendations_text
        assert 'authentication' in recommendations_text
        assert 'password' in recommendations_text
        assert 'token' in recommendations_text
    
    def test_convert_issues_to_findings(self, analyzer):
        """Test conversion of authentication issues to security findings."""
        config = AuthenticationConfiguration("localhost")
        
        issue = AuthenticationIssue(
            issue_id="AUTH_001",
            name="Test Authentication Issue",
            description="Test description",
            severity=RiskLevel.HIGH,
            category="weak_password",
            affected_component="authentication_config",
            evidence={'test': 'data'},
            remediation="Fix the issue",
            compliance_violations=[ComplianceFramework.OWASP_TOP_10]
        )
        
        config.issues = [issue]
        
        findings = analyzer._convert_issues_to_findings(config)
        
        assert len(findings) == 1
        finding = findings[0]
        
        assert finding.id == "AUTH_001"
        assert finding.title == "Test Authentication Issue"
        assert finding.description == "Test description"
        assert finding.severity == RiskLevel.HIGH
        assert finding.category == VulnerabilityCategory.AUTHENTICATION
        assert finding.confidence == 0.9
        assert finding.affected_asset == "localhost"
        assert finding.remediation == "Fix the issue"
        assert ComplianceFramework.OWASP_TOP_10 in finding.compliance_violations
    
    def test_assess_with_exception(self, analyzer):
        """Test assess method with exception handling."""
        # Create invalid detection result
        invalid_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True
        )
        
        # Mock an exception in analysis
        with patch.object(analyzer, '_analyze_authentication', side_effect=Exception("Test error")):
            with pytest.raises(ConfigurationError):
                analyzer.assess(invalid_result)


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    def test_analyze_authentication_function(self):
        """Test analyze_authentication convenience function."""
        server_info = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            authentication={'enabled': True, 'methods': ['password']}
        )
        
        detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
            success=True,
            mcp_server=server_info,
            confidence=0.9
        )
        
        config = analyze_authentication(detection_result)
        
        assert isinstance(config, AuthenticationConfiguration)
        assert config.target_host == "localhost"
        assert config.authentication_enabled is True
    
    def test_check_password_strength_weak(self):
        """Test password strength checking for weak passwords."""
        weak_passwords = [
            'admin',
            'password',
            '123456',
            'short',
            'onlylowercase',
            'ONLYUPPERCASE',
            '12345678'
        ]
        
        for password in weak_passwords:
            is_strong, issues = check_password_strength(password)
            assert not is_strong, f"Should detect '{password}' as weak"
            assert len(issues) > 0, f"Should have issues for '{password}'"
    
    def test_check_password_strength_strong(self):
        """Test password strength checking for strong passwords."""
        strong_passwords = [
            'MyStr0ng!P@ssw0rd',
            'C0mpl3x#P@ssw0rd!',
            'Rand0m$ecur3P@ss'
        ]
        
        for password in strong_passwords:
            is_strong, issues = check_password_strength(password)
            assert is_strong, f"Should detect '{password}' as strong"
            assert len(issues) == 0, f"Should have no issues for '{password}'"
    
    def test_validate_jwt_token_valid(self):
        """Test JWT token validation for valid tokens."""
        # Create a valid JWT token
        header = base64.b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
        
        # Create payload with future expiration
        future_exp = int((datetime.now() + timedelta(hours=1)).timestamp())
        payload = base64.b64encode(json.dumps({
            'iss': 'test-issuer',
            'aud': 'test-audience',
            'sub': 'user123',
            'exp': future_exp,
            'iat': int(datetime.now().timestamp())
        }).encode()).decode().rstrip('=')
        
        signature = 'fake_signature'
        jwt_token = f'{header}.{payload}.{signature}'
        
        is_valid, claims = validate_jwt_token(jwt_token)
        
        assert is_valid
        assert 'header' in claims
        assert 'payload' in claims
        assert claims['algorithm'] == 'HS256'
        assert claims['issuer'] == 'test-issuer'
        assert claims['audience'] == 'test-audience'
        assert claims['subject'] == 'user123'
        assert claims['expired'] is False
    
    def test_validate_jwt_token_expired(self):
        """Test JWT token validation for expired tokens."""
        # Create an expired JWT token
        header = base64.b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
        
        # Create payload with past expiration
        past_exp = int((datetime.now() - timedelta(hours=1)).timestamp())
        payload = base64.b64encode(json.dumps({
            'iss': 'test-issuer',
            'exp': past_exp
        }).encode()).decode().rstrip('=')
        
        signature = 'fake_signature'
        jwt_token = f'{header}.{payload}.{signature}'
        
        is_valid, claims = validate_jwt_token(jwt_token)
        
        assert is_valid  # Structure is valid
        assert claims['expired'] is True
    
    def test_validate_jwt_token_invalid(self):
        """Test JWT token validation for invalid tokens."""
        invalid_tokens = [
            'invalid.jwt.token',
            'not_a_jwt',
            'too.few.parts',
            'too.many.parts.here.invalid'
        ]
        
        for token in invalid_tokens:
            is_valid, claims = validate_jwt_token(token)
            assert not is_valid
            assert 'error' in claims


class TestAuthenticationRules:
    """Test cases for specific authentication rules."""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer for testing."""
        return AuthenticationAnalyzer()
    
    def test_no_authentication_rules(self, analyzer):
        """Test no authentication detection rules."""
        test_configs = [
            '{"auth": false}',
            '{"authentication": false}',
            '{"require_auth": false}',
            '{"no_auth": true}'
        ]
        
        for config_str in test_configs:
            config = AuthenticationConfiguration("localhost")
            analyzer._analyze_auth_config(json.loads(config_str), config)
            
            # Should detect disabled authentication
            no_auth_issues = [issue for issue in config.issues if 'no_authentication' in issue.category]
            assert len(no_auth_issues) >= 1
    
    def test_weak_password_rules(self, analyzer):
        """Test weak password detection rules."""
        test_configs = [
            '{"password": "admin"}',
            '{"password": "password"}',
            '{"password": "123456"}',
            '{"pass": "weak"}'
        ]
        
        for config_str in test_configs:
            config = AuthenticationConfiguration("localhost")
            analyzer._analyze_auth_config(json.loads(config_str), config)
            
            # Should detect weak passwords
            weak_password_issues = [issue for issue in config.issues if 'weak_password' in issue.category]
            assert len(weak_password_issues) >= 1
    
    def test_weak_token_rules(self, analyzer):
        """Test weak token detection rules."""
        test_configs = [
            '{"api_key": "test"}',
            '{"token": "demo"}',
            '{"secret": "secret"}',
            '{"jwt_secret": "weak"}'
        ]
        
        for config_str in test_configs:
            config = AuthenticationConfiguration("localhost")
            analyzer._analyze_auth_config(json.loads(config_str), config)
            
            # Should detect weak tokens
            weak_token_issues = [issue for issue in config.issues if 'weak_tokens' in issue.category]
            assert len(weak_token_issues) >= 1
    
    def test_oauth_jwt_issues_rules(self, analyzer):
        """Test OAuth/JWT security rules."""
        test_configs = [
            '{"algorithm": "none"}',
            '{"verify": false}',
            '{"iss": "test"}',
            '{"aud": "*"}'
        ]
        
        for config_str in test_configs:
            config = AuthenticationConfiguration("localhost")
            analyzer._analyze_auth_config(json.loads(config_str), config)
            
            # Should detect OAuth/JWT issues
            jwt_issues = [issue for issue in config.issues if 'oauth_jwt_issues' in issue.category]
            assert len(jwt_issues) >= 1


if __name__ == '__main__':
    pytest.main([__file__]) 