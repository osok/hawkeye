"""
Unit tests for transport security assessment module.

This module tests the TransportSecurityAssessor class and its ability to
assess security risks in MCP server transport layers including HTTP,
WebSocket, and STDIO transports.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import ssl
import socket
from pathlib import Path
from requests.exceptions import RequestException, Timeout, ConnectionError

from src.hawkeye.assessment.transport_security import TransportSecurityAssessor
from src.hawkeye.assessment.base import (
    AssessmentResult,
    SecurityFinding,
    VulnerabilityInfo,
    VulnerabilityCategory,
    RiskLevel,
    ComplianceFramework,
)
from src.hawkeye.detection.base import (
    DetectionResult,
    DetectionMethod,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ProcessInfo,
    ConfigFileInfo,
)


class TestTransportSecurityAssessor(unittest.TestCase):
    """Test cases for TransportSecurityAssessor."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.assessor = TransportSecurityAssessor()
        
        # Mock process info
        self.mock_process_info = ProcessInfo(
            pid=1234,
            name="node",
            cmdline=["node", "server.js", "--port", "3000"],
            cwd="/app",
            create_time=1234567890.0
        )
        
        # Mock config info
        self.mock_config_info = ConfigFileInfo(
            path=Path("/app/config.json"),
            file_type="json",
            content={"port": 3000, "host": "localhost"},
            dependencies=["@modelcontextprotocol/sdk"]
        )
        
        # Mock MCP server info for HTTP
        self.mock_http_server = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={"ssl": False, "auth": "none"}
        )
        
        # Mock MCP server info for WebSocket
        self.mock_ws_server = MCPServerInfo(
            host="localhost",
            port=8080,
            transport_type=TransportType.WEBSOCKET,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={"ssl": False, "cors": False}
        )
        
        # Mock MCP server info for STDIO
        self.mock_stdio_server = MCPServerInfo(
            host="localhost",
            port=None,
            transport_type=TransportType.STDIO,
            server_type=MCPServerType.NPX_PACKAGE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={}
        )
        
        # Mock successful detection result
        self.mock_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=self.mock_http_server,
            confidence=0.9,
            scan_duration=1.5
        )
    
    def test_get_assessment_type(self):
        """Test assessment type identifier."""
        self.assertEqual(self.assessor.get_assessment_type(), "transport_security")
    
    def test_assess_failed_detection(self):
        """Test assessment with failed detection result."""
        failed_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=False,
            error="No MCP server found",
            scan_duration=1.0
        )
        
        result = self.assessor.assess(failed_result)
        
        self.assertIsInstance(result, AssessmentResult)
        self.assertEqual(result.target_host, "localhost")
        self.assertEqual(len(result.findings), 0)
        self.assertIn("error", result.raw_data)
    
    def test_assess_no_mcp_server(self):
        """Test assessment with detection result but no MCP server."""
        no_server_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=None,
            confidence=0.0,
            scan_duration=1.0
        )
        
        result = self.assessor.assess(no_server_result)
        
        self.assertIsInstance(result, AssessmentResult)
        self.assertEqual(len(result.findings), 0)
        self.assertIn("error", result.raw_data)
    
    @patch('src.hawkeye.assessment.transport_security.requests.Session')
    def test_assess_http_unencrypted(self, mock_session_class):
        """Test assessment of unencrypted HTTP transport."""
        # Mock HTTP session
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.get.side_effect = [ConnectionError(), ConnectionError()]
        mock_session.head.return_value.headers = {}
        mock_session.options.return_value.headers = {}
        
        result = self.assessor.assess(self.mock_detection_result)
        
        self.assertIsInstance(result, AssessmentResult)
        self.assertGreater(len(result.findings), 0)
        
        # Check for unencrypted HTTP finding
        unencrypted_findings = [
            f for f in result.findings 
            if f.category == VulnerabilityCategory.ENCRYPTION and "unencrypted" in f.title.lower()
        ]
        self.assertGreater(len(unencrypted_findings), 0)
        
        finding = unencrypted_findings[0]
        self.assertEqual(finding.severity, RiskLevel.HIGH)
        self.assertIn(ComplianceFramework.OWASP_TOP_10, finding.compliance_violations)
    
    @patch('src.hawkeye.assessment.transport_security.requests.Session')
    def test_assess_http_security_headers(self, mock_session_class):
        """Test assessment of HTTP security headers."""
        # Mock HTTP session
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.get.side_effect = [ConnectionError(), ConnectionError()]
        
        # Mock missing security headers
        mock_response = Mock()
        mock_response.headers = {}  # No security headers
        mock_session.head.return_value = mock_response
        mock_session.options.return_value.headers = {}
        
        result = self.assessor.assess(self.mock_detection_result)
        
        # Check for missing header findings
        header_findings = [
            f for f in result.findings 
            if "header" in f.title.lower()
        ]
        self.assertGreater(len(header_findings), 0)
        
        # Should find multiple missing headers
        expected_headers = ['Strict-Transport-Security', 'X-Content-Type-Options', 
                          'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']
        found_headers = [f.evidence.get('missing_header') for f in header_findings]
        
        for header in expected_headers:
            self.assertIn(header, found_headers)
    
    @patch('src.hawkeye.assessment.transport_security.requests.Session')
    def test_assess_http_dangerous_methods(self, mock_session_class):
        """Test assessment of dangerous HTTP methods."""
        # Mock HTTP session
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.get.side_effect = [ConnectionError(), ConnectionError()]
        mock_session.head.return_value.headers = {}
        
        # Mock dangerous HTTP methods
        mock_response = Mock()
        mock_response.headers = {'Allow': 'GET, POST, PUT, DELETE, TRACE'}
        mock_session.options.return_value = mock_response
        
        result = self.assessor.assess(self.mock_detection_result)
        
        # Check for dangerous methods finding
        method_findings = [
            f for f in result.findings 
            if "dangerous" in f.title.lower() and "methods" in f.title.lower()
        ]
        self.assertGreater(len(method_findings), 0)
        
        finding = method_findings[0]
        self.assertEqual(finding.severity, RiskLevel.MEDIUM)
        self.assertIn('DELETE', finding.evidence['dangerous_methods'])
        self.assertIn('TRACE', finding.evidence['dangerous_methods'])
    
    def test_assess_websocket_unencrypted(self):
        """Test assessment of unencrypted WebSocket transport."""
        ws_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=self.mock_ws_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        with patch.object(self.assessor, '_test_wss_availability', return_value=False):
            result = self.assessor.assess(ws_detection_result)
        
        # Check for unencrypted WebSocket finding
        unencrypted_findings = [
            f for f in result.findings 
            if f.category == VulnerabilityCategory.ENCRYPTION and "websocket" in f.title.lower()
        ]
        self.assertGreater(len(unencrypted_findings), 0)
        
        finding = unencrypted_findings[0]
        self.assertEqual(finding.severity, RiskLevel.HIGH)
        self.assertIn("WSS", finding.remediation)
    
    def test_assess_websocket_no_origin_validation(self):
        """Test assessment of WebSocket origin validation."""
        # Create WebSocket server without origin validation config
        ws_server_no_origin = MCPServerInfo(
            host="localhost",
            port=8080,
            transport_type=TransportType.WEBSOCKET,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={"ssl": False}  # No origin/cors config
        )
        
        ws_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=ws_server_no_origin,
            confidence=0.9,
            scan_duration=1.5
        )
        
        with patch.object(self.assessor, '_test_wss_availability', return_value=False):
            result = self.assessor.assess(ws_detection_result)
        
        # Check for origin validation finding
        origin_findings = [
            f for f in result.findings 
            if "origin" in f.title.lower()
        ]
        self.assertGreater(len(origin_findings), 0)
        
        finding = origin_findings[0]
        self.assertEqual(finding.severity, RiskLevel.MEDIUM)
        self.assertEqual(finding.category, VulnerabilityCategory.AUTHENTICATION)
    
    def test_assess_stdio_elevated_privileges(self):
        """Test assessment of STDIO process with elevated privileges."""
        # Mock elevated process
        elevated_process = ProcessInfo(
            pid=1234,
            name="node",
            cmdline=["node", "server.js"],
            cwd="/app",
            create_time=1234567890.0
        )
        elevated_process.username = "root"  # Elevated user
        
        stdio_server = MCPServerInfo(
            host="localhost",
            port=None,
            transport_type=TransportType.STDIO,
            server_type=MCPServerType.NPX_PACKAGE,
            process_info=elevated_process,
            config_info=self.mock_config_info,
            security_config={}
        )
        
        stdio_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=stdio_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        result = self.assessor.assess(stdio_detection_result)
        
        # Check for elevated privileges finding
        privilege_findings = [
            f for f in result.findings 
            if "elevated" in f.title.lower() and "privileges" in f.title.lower()
        ]
        self.assertGreater(len(privilege_findings), 0)
        
        finding = privilege_findings[0]
        self.assertEqual(finding.severity, RiskLevel.MEDIUM)
        self.assertEqual(finding.category, VulnerabilityCategory.AUTHORIZATION)
    
    def test_assess_stdio_cmdline_credentials(self):
        """Test assessment of STDIO command line with credentials."""
        # Mock process with credentials in command line
        credential_process = ProcessInfo(
            pid=1234,
            name="node",
            cmdline=["node", "server.js", "--password", "secret123", "--api-key", "abc123"],
            cwd="/app",
            create_time=1234567890.0
        )
        
        stdio_server = MCPServerInfo(
            host="localhost",
            port=None,
            transport_type=TransportType.STDIO,
            server_type=MCPServerType.NPX_PACKAGE,
            process_info=credential_process,
            config_info=self.mock_config_info,
            security_config={}
        )
        
        stdio_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=stdio_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        result = self.assessor.assess(stdio_detection_result)
        
        # Check for command line credentials finding
        cmdline_findings = [
            f for f in result.findings 
            if "credentials" in f.title.lower() and "command" in f.title.lower()
        ]
        self.assertGreater(len(cmdline_findings), 0)
        
        finding = cmdline_findings[0]
        self.assertEqual(finding.severity, RiskLevel.HIGH)
        self.assertEqual(finding.category, VulnerabilityCategory.AUTHENTICATION)
    
    @patch('src.hawkeye.assessment.transport_security.socket.create_connection')
    @patch('src.hawkeye.assessment.transport_security.ssl.create_default_context')
    def test_assess_tls_weak_protocols(self, mock_ssl_context, mock_socket):
        """Test assessment of weak TLS protocols."""
        # Mock HTTPS server with weak TLS
        https_server = MCPServerInfo(
            host="localhost",
            port=443,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={"ssl": True}
        )
        
        https_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=https_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        # Mock TLS connection with weak protocol
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        mock_sock = Mock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        mock_ssock = Mock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = {'subject': []}
        mock_ssock.cipher.return_value = ('AES256-SHA', 'TLSv1', 256)
        mock_ssock.version.return_value = 'TLSv1'  # Weak protocol
        
        result = self.assessor.assess(https_detection_result)
        
        # Check for weak TLS protocol finding
        tls_findings = [
            f for f in result.findings 
            if "weak" in f.title.lower() and "tls" in f.title.lower() and "protocols" in f.title.lower()
        ]
        self.assertGreater(len(tls_findings), 0)
        
        finding = tls_findings[0]
        self.assertEqual(finding.severity, RiskLevel.HIGH)
        self.assertEqual(finding.category, VulnerabilityCategory.ENCRYPTION)
    
    @patch('src.hawkeye.assessment.transport_security.socket.create_connection')
    @patch('src.hawkeye.assessment.transport_security.ssl.create_default_context')
    def test_assess_tls_weak_ciphers(self, mock_ssl_context, mock_socket):
        """Test assessment of weak TLS ciphers."""
        # Mock HTTPS server
        https_server = MCPServerInfo(
            host="localhost",
            port=443,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={"ssl": True}
        )
        
        https_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=https_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        # Mock TLS connection with weak cipher
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        mock_sock = Mock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        mock_ssock = Mock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = {'subject': []}
        mock_ssock.cipher.return_value = ('RC4-MD5', 'TLSv1.2', 128)  # Weak cipher
        mock_ssock.version.return_value = 'TLSv1.2'
        
        result = self.assessor.assess(https_detection_result)
        
        # Check for weak cipher finding
        cipher_findings = [
            f for f in result.findings 
            if "weak" in f.title.lower() and "cipher" in f.title.lower()
        ]
        self.assertGreater(len(cipher_findings), 0)
        
        finding = cipher_findings[0]
        self.assertEqual(finding.severity, RiskLevel.MEDIUM)
        self.assertEqual(finding.category, VulnerabilityCategory.ENCRYPTION)
    
    def test_assess_network_bind_all_interfaces(self):
        """Test assessment of server bound to all interfaces."""
        # Mock server bound to all interfaces
        all_interfaces_server = MCPServerInfo(
            host="0.0.0.0",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={}
        )
        
        all_interfaces_detection_result = DetectionResult(
            target_host="0.0.0.0",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=all_interfaces_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        with patch.object(self.assessor, '_test_https_availability', return_value=False):
            result = self.assessor.assess(all_interfaces_detection_result)
        
        # Check for bind all interfaces finding
        bind_findings = [
            f for f in result.findings 
            if "bound" in f.title.lower() and "interfaces" in f.title.lower()
        ]
        self.assertGreater(len(bind_findings), 0)
        
        finding = bind_findings[0]
        self.assertEqual(finding.severity, RiskLevel.MEDIUM)
        self.assertEqual(finding.category, VulnerabilityCategory.NETWORK)
    
    def test_assess_insecure_port(self):
        """Test assessment of service on commonly targeted port."""
        # Mock server on insecure port
        insecure_port_server = MCPServerInfo(
            host="localhost",
            port=80,  # Commonly targeted port
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={}
        )
        
        insecure_port_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=insecure_port_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        with patch.object(self.assessor, '_test_https_availability', return_value=False):
            result = self.assessor.assess(insecure_port_detection_result)
        
        # Check for insecure port finding
        port_findings = [
            f for f in result.findings 
            if "commonly targeted" in f.title.lower() and "port" in f.title.lower()
        ]
        self.assertGreater(len(port_findings), 0)
        
        finding = port_findings[0]
        self.assertEqual(finding.severity, RiskLevel.LOW)
        self.assertEqual(finding.category, VulnerabilityCategory.NETWORK)
    
    def test_assess_insecure_protocol_config(self):
        """Test assessment of insecure protocol in configuration."""
        # Mock server with insecure protocol config
        insecure_config_server = MCPServerInfo(
            host="localhost",
            port=3000,
            transport_type=TransportType.HTTP,
            server_type=MCPServerType.STANDALONE,
            process_info=self.mock_process_info,
            config_info=self.mock_config_info,
            security_config={
                "upstream_url": "http://insecure-service.com",
                "backup_url": "ftp://backup.example.com"
            }
        )
        
        insecure_config_detection_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=insecure_config_server,
            confidence=0.9,
            scan_duration=1.5
        )
        
        with patch.object(self.assessor, '_test_https_availability', return_value=False):
            result = self.assessor.assess(insecure_config_detection_result)
        
        # Check for insecure protocol findings
        protocol_findings = [
            f for f in result.findings 
            if "insecure" in f.title.lower() and "protocol" in f.title.lower()
        ]
        self.assertGreater(len(protocol_findings), 0)
        
        # Should find both HTTP and FTP insecure protocols
        found_protocols = [f.evidence.get('insecure_pattern') for f in protocol_findings]
        self.assertIn('http://', found_protocols)
        self.assertIn('ftp://', found_protocols)
    
    def test_generate_vulnerabilities(self):
        """Test vulnerability generation from findings."""
        # Create test findings
        findings = [
            SecurityFinding(
                id="test_critical",
                title="Critical Finding",
                description="Critical security issue",
                category=VulnerabilityCategory.ENCRYPTION,
                severity=RiskLevel.CRITICAL,
                confidence=0.9,
                affected_asset="localhost:3000"
            ),
            SecurityFinding(
                id="test_high",
                title="High Finding",
                description="High security issue",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.HIGH,
                confidence=0.8,
                affected_asset="localhost:3000"
            ),
            SecurityFinding(
                id="test_medium",
                title="Medium Finding",
                description="Medium security issue",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.MEDIUM,
                confidence=0.7,
                affected_asset="localhost:3000"
            )
        ]
        
        vulnerabilities = self.assessor._generate_vulnerabilities(findings)
        
        # Should generate vulnerabilities for critical and high findings only
        self.assertEqual(len(vulnerabilities), 2)
        
        # Check vulnerability properties
        critical_vuln = next(v for v in vulnerabilities if v.severity == RiskLevel.CRITICAL)
        self.assertTrue(critical_vuln.exploit_available)
        self.assertTrue(critical_vuln.patch_available)
        
        high_vuln = next(v for v in vulnerabilities if v.severity == RiskLevel.HIGH)
        self.assertFalse(high_vuln.exploit_available)
        self.assertTrue(high_vuln.patch_available)
    
    def test_create_cvss_vector(self):
        """Test CVSS vector creation for findings."""
        # Test encryption finding
        encryption_finding = SecurityFinding(
            id="test_encryption",
            title="Encryption Issue",
            description="Encryption vulnerability",
            category=VulnerabilityCategory.ENCRYPTION,
            severity=RiskLevel.HIGH,
            confidence=0.9,
            affected_asset="localhost:3000"
        )
        
        vector = self.assessor._create_cvss_vector(encryption_finding)
        
        self.assertEqual(vector.attack_vector, "N")  # Network
        self.assertEqual(vector.attack_complexity, "L")  # Low (high severity)
        self.assertEqual(vector.confidentiality, "H")  # High impact
        self.assertEqual(vector.integrity, "H")  # High impact
        
        # Test authentication finding
        auth_finding = SecurityFinding(
            id="test_auth",
            title="Authentication Issue",
            description="Authentication vulnerability",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.MEDIUM,
            confidence=0.8,
            affected_asset="localhost:3000"
        )
        
        vector = self.assessor._create_cvss_vector(auth_finding)
        
        self.assertEqual(vector.attack_complexity, "H")  # High (medium severity)
        self.assertEqual(vector.confidentiality, "H")  # High impact
        self.assertEqual(vector.availability, "L")  # Low impact
    
    def test_calculate_cvss_score(self):
        """Test CVSS score calculation."""
        # Test critical finding
        critical_finding = SecurityFinding(
            id="test_critical",
            title="Critical Finding",
            description="Critical issue",
            category=VulnerabilityCategory.ENCRYPTION,
            severity=RiskLevel.CRITICAL,
            confidence=0.9,
            affected_asset="localhost:3000"
        )
        
        score = self.assessor._calculate_cvss_score(critical_finding)
        self.assertEqual(score, 9.0 * 0.9)  # 8.1
        
        # Test low finding
        low_finding = SecurityFinding(
            id="test_low",
            title="Low Finding",
            description="Low issue",
            category=VulnerabilityCategory.CONFIGURATION,
            severity=RiskLevel.LOW,
            confidence=0.5,
            affected_asset="localhost:3000"
        )
        
        score = self.assessor._calculate_cvss_score(low_finding)
        self.assertEqual(score, 2.5 * 0.5)  # 1.25
    
    def test_generate_recommendations(self):
        """Test recommendation generation."""
        # Create findings for different categories
        findings = [
            SecurityFinding(
                id="http_encryption",
                title="Unencrypted HTTP",
                description="HTTP not encrypted",
                category=VulnerabilityCategory.ENCRYPTION,
                severity=RiskLevel.HIGH,
                confidence=0.9,
                affected_asset="localhost:3000"
            ),
            SecurityFinding(
                id="missing_header",
                title="Missing Security Header",
                description="Security header missing",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.LOW,
                confidence=0.8,
                affected_asset="localhost:3000",
                compliance_violations=[ComplianceFramework.OWASP_TOP_10]
            )
        ]
        
        recommendations = self.assessor._generate_recommendations(findings, self.mock_http_server)
        
        # Should include transport-specific recommendations
        self.assertTrue(any("HTTPS" in rec for rec in recommendations))
        self.assertTrue(any("security headers" in rec for rec in recommendations))
        self.assertTrue(any("high and critical" in rec for rec in recommendations))
        self.assertTrue(any("OWASP Top 10" in rec for rec in recommendations))
    
    def test_assess_compliance(self):
        """Test compliance assessment."""
        # Create findings with compliance violations
        findings = [
            SecurityFinding(
                id="test_finding_1",
                title="Finding 1",
                description="Test finding",
                category=VulnerabilityCategory.ENCRYPTION,
                severity=RiskLevel.HIGH,
                confidence=0.9,
                affected_asset="localhost:3000",
                compliance_violations=[ComplianceFramework.PCI_DSS, ComplianceFramework.GDPR]
            ),
            SecurityFinding(
                id="test_finding_2",
                title="Finding 2",
                description="Test finding",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.MEDIUM,
                confidence=0.8,
                affected_asset="localhost:3000",
                compliance_violations=[ComplianceFramework.OWASP_TOP_10]
            )
        ]
        
        compliance_status = self.assessor._assess_compliance(findings)
        
        # Frameworks with violations should be non-compliant
        self.assertFalse(compliance_status[ComplianceFramework.PCI_DSS])
        self.assertFalse(compliance_status[ComplianceFramework.GDPR])
        self.assertFalse(compliance_status[ComplianceFramework.OWASP_TOP_10])
        
        # Frameworks without violations should be compliant
        self.assertTrue(compliance_status[ComplianceFramework.NIST_CSF])
        self.assertTrue(compliance_status[ComplianceFramework.ISO_27001])
        self.assertTrue(compliance_status[ComplianceFramework.SOC2])
    
    def test_test_https_availability(self):
        """Test HTTPS availability testing."""
        with patch.object(self.assessor.session, 'get') as mock_get:
            # Test HTTPS available on same port
            mock_get.return_value = Mock()
            result = self.assessor._test_https_availability("localhost", 3000)
            self.assertTrue(result)
            
            # Test HTTPS not available
            mock_get.side_effect = [ConnectionError(), ConnectionError()]
            result = self.assessor._test_https_availability("localhost", 3000)
            self.assertFalse(result)
    
    @patch('src.hawkeye.assessment.transport_security.socket.create_connection')
    @patch('src.hawkeye.assessment.transport_security.ssl.create_default_context')
    def test_test_wss_availability(self, mock_ssl_context, mock_socket):
        """Test WSS availability testing."""
        # Test WSS available
        mock_context = Mock()
        mock_ssl_context.return_value = mock_context
        
        mock_sock = Mock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        mock_ssock = Mock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        result = self.assessor._test_wss_availability("localhost", 8080)
        self.assertTrue(result)
        
        # Test WSS not available
        mock_socket.side_effect = ConnectionError()
        result = self.assessor._test_wss_availability("localhost", 8080)
        self.assertFalse(result)
    
    def test_is_elevated_process(self):
        """Test elevated process detection."""
        # Test root user
        root_process = Mock()
        root_process.username = "root"
        self.assertTrue(self.assessor._is_elevated_process(root_process))
        
        # Test administrator user
        admin_process = Mock()
        admin_process.username = "Administrator"
        self.assertTrue(self.assessor._is_elevated_process(admin_process))
        
        # Test regular user
        user_process = Mock()
        user_process.username = "user"
        self.assertFalse(self.assessor._is_elevated_process(user_process))
        
        # Test no username
        no_user_process = Mock()
        del no_user_process.username
        self.assertFalse(self.assessor._is_elevated_process(no_user_process))
    
    def test_security_rules_initialization(self):
        """Test security rules initialization."""
        self.assertIn('http', self.assessor.security_rules)
        self.assertIn('websocket', self.assessor.security_rules)
        self.assertIn('stdio', self.assessor.security_rules)
        self.assertIn('general', self.assessor.security_rules)
        
        # Check HTTP rules
        http_rules = self.assessor.security_rules['http']
        self.assertIsInstance(http_rules, list)
        self.assertGreater(len(http_rules), 0)
        
        # Check rule structure
        rule = http_rules[0]
        self.assertIn('id', rule)
        self.assertIn('name', rule)
        self.assertIn('description', rule)
        self.assertIn('category', rule)
        self.assertIn('severity', rule)
    
    def test_weak_tls_patterns(self):
        """Test weak TLS pattern detection."""
        patterns = self.assessor.weak_tls_patterns
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)
        
        # Test pattern matching
        import re
        test_configs = [
            "ssl_version: sslv3",
            "tls_version: tlsv1.0",
            "cipher: rc4-md5",
            "cipher_suite: des-cbc"
        ]
        
        for config in test_configs:
            matched = any(re.search(pattern, config, re.IGNORECASE) for pattern in patterns)
            self.assertTrue(matched, f"Pattern should match: {config}")
    
    def test_insecure_protocols(self):
        """Test insecure protocol patterns."""
        protocols = self.assessor.insecure_protocols
        self.assertIn('http', protocols)
        self.assertIn('websocket', protocols)
        self.assertIn('ftp', protocols)
        
        # Check patterns
        self.assertIn('http://', protocols['http'])
        self.assertIn('ws://', protocols['websocket'])
        self.assertIn('ftp://', protocols['ftp'])


if __name__ == '__main__':
    unittest.main()