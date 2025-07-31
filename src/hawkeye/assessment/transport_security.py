"""
Transport Security Assessment for MCP Servers.

This module provides comprehensive security assessment capabilities for MCP server
transport layers, including HTTP, WebSocket, and STDIO transports. It evaluates
encryption, authentication, and protocol-specific security configurations.
"""

import ssl
import socket
import time
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from .base import (
    RiskAssessor,
    AssessmentResult,
    SecurityFinding,
    VulnerabilityInfo,
    VulnerabilityCategory,
    RiskLevel,
    ComplianceFramework,
    CVSSVector,
)
from ..detection.base import DetectionResult, TransportType, MCPServerInfo
from ..utils.logging import get_logger


class TransportSecurityAssessor(RiskAssessor):
    """Assessor for transport layer security of MCP servers."""
    
    def __init__(self, settings=None):
        """Initialize the transport security assessor."""
        super().__init__(settings)
        self.logger = get_logger(__name__)
        
        # Security assessment rules for different transport types
        self.security_rules = {
            'http': self._get_http_security_rules(),
            'websocket': self._get_websocket_security_rules(),
            'stdio': self._get_stdio_security_rules(),
            'general': self._get_general_transport_rules()
        }
        
        # TLS/SSL configuration patterns
        self.weak_tls_patterns = [
            r'ssl_?version.*["\']?ssl[v]?[23]["\']?',  # SSLv2, SSLv3
            r'tls_?version.*["\']?tls[v]?1[\.0]?["\']?',  # TLSv1.0
            r'tls_?version.*["\']?tls[v]?1\.1["\']?',  # TLSv1.1
            r'cipher.*rc4',  # RC4 cipher
            r'cipher.*des',  # DES cipher
            r'cipher.*md5',  # MD5 hash
        ]
        
        # Insecure protocol patterns
        self.insecure_protocols = {
            'http': ['http://', 'unencrypted', 'plain'],
            'websocket': ['ws://', 'unencrypted', 'plain'],
            'ftp': ['ftp://', 'telnet://'],
        }
        
        # Setup HTTP session for testing
        self.session = requests.Session()
        self.session.timeout = 10
    
    def get_assessment_type(self) -> str:
        """Get the assessment type identifier."""
        return "transport_security"
    
    def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
        """
        Assess transport security for an MCP server.
        
        Args:
            detection_result: Detection result containing MCP server information
            **kwargs: Additional assessment parameters
            
        Returns:
            AssessmentResult: Transport security assessment result
        """
        start_time = time.time()
        
        try:
            if not detection_result.success or not detection_result.mcp_server:
                return self._create_failed_result(
                    detection_result.target_host,
                    "No MCP server detected for transport security assessment",
                    time.time() - start_time
                )
            
            mcp_server = detection_result.mcp_server
            findings = []
            vulnerabilities = []
            
            # Assess transport-specific security
            transport_findings = self._assess_transport_security(mcp_server)
            findings.extend(transport_findings)
            
            # Assess TLS/SSL configuration
            tls_findings = self._assess_tls_security(mcp_server)
            findings.extend(tls_findings)
            
            # Assess protocol security
            protocol_findings = self._assess_protocol_security(mcp_server)
            findings.extend(protocol_findings)
            
            # Assess network security
            network_findings = self._assess_network_security(mcp_server)
            findings.extend(network_findings)
            
            # Generate vulnerabilities from findings
            vulnerabilities = self._generate_vulnerabilities(findings)
            
            # Create assessment result
            result = AssessmentResult(
                target_host=detection_result.target_host,
                findings=findings,
                vulnerabilities=vulnerabilities,
                assessment_duration=time.time() - start_time,
                raw_data={
                    'transport_type': mcp_server.transport_type.value,
                    'server_info': {
                        'host': mcp_server.host,
                        'port': mcp_server.port,
                        'server_type': mcp_server.server_type.value if mcp_server.server_type else None,
                    },
                    'security_config': mcp_server.security_config,
                    'detection_confidence': detection_result.confidence,
                }
            )
            
            # Calculate overall risk
            result.calculate_overall_risk()
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(findings, mcp_server)
            
            # Set compliance status
            result.compliance_status = self._assess_compliance(findings)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Transport security assessment failed for {detection_result.target_host}: {e}")
            return self._create_failed_result(
                detection_result.target_host,
                f"Transport security assessment error: {str(e)}",
                time.time() - start_time
            )
    
    def _assess_transport_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """
        Assess security specific to the transport type.
        
        Args:
            mcp_server: MCP server information
            
        Returns:
            List[SecurityFinding]: Transport-specific security findings
        """
        findings = []
        transport_type = mcp_server.transport_type
        
        if transport_type == TransportType.HTTP:
            findings.extend(self._assess_http_security(mcp_server))
        elif transport_type == TransportType.WEBSOCKET:
            findings.extend(self._assess_websocket_security(mcp_server))
        elif transport_type == TransportType.STDIO:
            findings.extend(self._assess_stdio_security(mcp_server))
        
        return findings
    
    def _assess_http_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Assess HTTP transport security."""
        findings = []
        
        # Check if HTTP is used instead of HTTPS
        if mcp_server.port and mcp_server.port not in [443, 8443, 9443]:
            # Test if HTTPS is available
            https_available = self._test_https_availability(mcp_server.host, mcp_server.port)
            
            if not https_available:
                findings.append(SecurityFinding(
                    id=f"http_unencrypted_{mcp_server.host}_{mcp_server.port}",
                    title="Unencrypted HTTP Transport",
                    description=f"MCP server on {mcp_server.host}:{mcp_server.port} uses unencrypted HTTP transport",
                    category=VulnerabilityCategory.ENCRYPTION,
                    severity=RiskLevel.HIGH,
                    confidence=0.9,
                    affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                    evidence={
                        'transport_type': 'HTTP',
                        'port': mcp_server.port,
                        'https_available': False
                    },
                    remediation="Configure HTTPS with proper TLS encryption",
                    compliance_violations=[
                        ComplianceFramework.OWASP_TOP_10,
                        ComplianceFramework.PCI_DSS,
                        ComplianceFramework.GDPR
                    ]
                ))
        
        # Check HTTP security headers
        headers_findings = self._check_http_security_headers(mcp_server)
        findings.extend(headers_findings)
        
        # Check for HTTP methods exposure
        methods_findings = self._check_http_methods(mcp_server)
        findings.extend(methods_findings)
        
        return findings
    
    def _assess_websocket_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Assess WebSocket transport security."""
        findings = []
        
        # Check if WS is used instead of WSS
        if mcp_server.port and mcp_server.port not in [443, 8443, 9443]:
            # Test if WSS is available
            wss_available = self._test_wss_availability(mcp_server.host, mcp_server.port)
            
            if not wss_available:
                findings.append(SecurityFinding(
                    id=f"ws_unencrypted_{mcp_server.host}_{mcp_server.port}",
                    title="Unencrypted WebSocket Transport",
                    description=f"MCP server on {mcp_server.host}:{mcp_server.port} uses unencrypted WebSocket transport",
                    category=VulnerabilityCategory.ENCRYPTION,
                    severity=RiskLevel.HIGH,
                    confidence=0.9,
                    affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                    evidence={
                        'transport_type': 'WebSocket',
                        'port': mcp_server.port,
                        'wss_available': False
                    },
                    remediation="Configure WSS (WebSocket Secure) with proper TLS encryption",
                    compliance_violations=[
                        ComplianceFramework.OWASP_TOP_10,
                        ComplianceFramework.PCI_DSS,
                        ComplianceFramework.GDPR
                    ]
                ))
        
        # Check WebSocket-specific security
        ws_findings = self._check_websocket_security(mcp_server)
        findings.extend(ws_findings)
        
        return findings
    
    def _assess_stdio_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Assess STDIO transport security."""
        findings = []
        
        # STDIO is inherently local, but check for security issues
        if mcp_server.process_info:
            # Check if process is running with elevated privileges
            if self._is_elevated_process(mcp_server.process_info):
                findings.append(SecurityFinding(
                    id=f"stdio_elevated_privileges_{mcp_server.host}",
                    title="STDIO MCP Server Running with Elevated Privileges",
                    description="MCP server process is running with elevated privileges, increasing attack surface",
                    category=VulnerabilityCategory.AUTHORIZATION,
                    severity=RiskLevel.MEDIUM,
                    confidence=0.8,
                    affected_asset=f"{mcp_server.host} (PID: {mcp_server.process_info.pid})",
                    evidence={
                        'transport_type': 'STDIO',
                        'process_user': getattr(mcp_server.process_info, 'username', 'unknown'),
                        'process_pid': mcp_server.process_info.pid
                    },
                    remediation="Run MCP server with minimal required privileges",
                    compliance_violations=[ComplianceFramework.NIST_CSF]
                ))
            
            # Check for insecure command line arguments
            cmdline_findings = self._check_stdio_cmdline_security(mcp_server)
            findings.extend(cmdline_findings)
        
        return findings
    
    def _assess_tls_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Assess TLS/SSL security configuration."""
        findings = []
        
        if mcp_server.transport_type in [TransportType.HTTP, TransportType.WEBSOCKET]:
            if mcp_server.port in [443, 8443, 9443]:
                # Analyze TLS configuration
                tls_config = self._analyze_tls_configuration(mcp_server.host, mcp_server.port)
                
                if tls_config.get('weak_protocols'):
                    findings.append(SecurityFinding(
                        id=f"weak_tls_protocols_{mcp_server.host}_{mcp_server.port}",
                        title="Weak TLS Protocols Enabled",
                        description=f"Server supports weak TLS protocols: {', '.join(tls_config['weak_protocols'])}",
                        category=VulnerabilityCategory.ENCRYPTION,
                        severity=RiskLevel.HIGH,
                        confidence=0.9,
                        affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                        evidence=tls_config,
                        remediation="Disable weak TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) and use TLSv1.2+",
                        compliance_violations=[
                            ComplianceFramework.PCI_DSS,
                            ComplianceFramework.NIST_CSF
                        ]
                    ))
                
                if tls_config.get('weak_ciphers'):
                    findings.append(SecurityFinding(
                        id=f"weak_tls_ciphers_{mcp_server.host}_{mcp_server.port}",
                        title="Weak TLS Cipher Suites",
                        description=f"Server supports weak cipher suites: {', '.join(tls_config['weak_ciphers'])}",
                        category=VulnerabilityCategory.ENCRYPTION,
                        severity=RiskLevel.MEDIUM,
                        confidence=0.8,
                        affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                        evidence=tls_config,
                        remediation="Configure strong cipher suites and disable weak ciphers (RC4, DES, MD5)",
                        compliance_violations=[ComplianceFramework.PCI_DSS]
                    ))
                
                if not tls_config.get('certificate_valid'):
                    findings.append(SecurityFinding(
                        id=f"invalid_tls_certificate_{mcp_server.host}_{mcp_server.port}",
                        title="Invalid TLS Certificate",
                        description="Server has an invalid or self-signed TLS certificate",
                        category=VulnerabilityCategory.ENCRYPTION,
                        severity=RiskLevel.MEDIUM,
                        confidence=0.9,
                        affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                        evidence=tls_config,
                        remediation="Install a valid TLS certificate from a trusted Certificate Authority",
                        compliance_violations=[ComplianceFramework.PCI_DSS]
                    ))
        
        return findings
    
    def _assess_protocol_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Assess protocol-level security."""
        findings = []
        
        # Check for insecure protocol configurations in server config
        if mcp_server.security_config:
            for key, value in mcp_server.security_config.items():
                if isinstance(value, str):
                    # Check for insecure protocol patterns
                    for protocol, patterns in self.insecure_protocols.items():
                        for pattern in patterns:
                            if pattern.lower() in value.lower():
                                findings.append(SecurityFinding(
                                    id=f"insecure_protocol_{protocol}_{mcp_server.host}",
                                    title=f"Insecure {protocol.upper()} Protocol Configuration",
                                    description=f"Configuration contains insecure {protocol} protocol reference: {pattern}",
                                    category=VulnerabilityCategory.CONFIGURATION,
                                    severity=RiskLevel.MEDIUM,
                                    confidence=0.7,
                                    affected_asset=f"{mcp_server.host}",
                                    evidence={
                                        'config_key': key,
                                        'config_value': value,
                                        'insecure_pattern': pattern
                                    },
                                    remediation=f"Replace insecure {protocol} with secure alternatives",
                                    compliance_violations=[ComplianceFramework.OWASP_TOP_10]
                                ))
        
        return findings
    
    def _assess_network_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Assess network-level security."""
        findings = []
        
        # Check if server is bound to all interfaces (0.0.0.0)
        if mcp_server.host in ['0.0.0.0', '::']:
            findings.append(SecurityFinding(
                id=f"bind_all_interfaces_{mcp_server.host}_{mcp_server.port}",
                title="Server Bound to All Network Interfaces",
                description="MCP server is bound to all network interfaces, potentially exposing it to external networks",
                category=VulnerabilityCategory.NETWORK,
                severity=RiskLevel.MEDIUM,
                confidence=0.8,
                affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                evidence={
                    'bind_address': mcp_server.host,
                    'port': mcp_server.port
                },
                remediation="Bind server to specific interfaces (localhost/127.0.0.1) if external access is not required",
                compliance_violations=[ComplianceFramework.NIST_CSF]
            ))
        
        # Check for common insecure ports
        if mcp_server.port:
            insecure_ports = [21, 23, 25, 53, 80, 110, 143, 993, 995]
            if mcp_server.port in insecure_ports:
                findings.append(SecurityFinding(
                    id=f"insecure_port_{mcp_server.port}_{mcp_server.host}",
                    title="Service Running on Commonly Targeted Port",
                    description=f"MCP server is running on port {mcp_server.port}, which is commonly targeted by attackers",
                    category=VulnerabilityCategory.NETWORK,
                    severity=RiskLevel.LOW,
                    confidence=0.6,
                    affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                    evidence={'port': mcp_server.port},
                    remediation="Consider using non-standard ports and implement proper firewall rules",
                    compliance_violations=[ComplianceFramework.NIST_CSF]
                ))
        
        return findings
    
    def _test_https_availability(self, host: str, port: int) -> bool:
        """Test if HTTPS is available on the given host and port."""
        try:
            # Try HTTPS on the same port
            response = self.session.get(f"https://{host}:{port}", timeout=5, verify=False)
            return True
        except:
            try:
                # Try HTTPS on standard HTTPS port
                response = self.session.get(f"https://{host}:443", timeout=5, verify=False)
                return True
            except:
                return False
    
    def _test_wss_availability(self, host: str, port: int) -> bool:
        """Test if WSS (WebSocket Secure) is available."""
        try:
            # Simple socket test for TLS on WebSocket port
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except:
            return False
    
    def _check_http_security_headers(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Check for missing HTTP security headers."""
        findings = []
        
        try:
            url = f"http://{mcp_server.host}:{mcp_server.port}"
            response = self.session.head(url, timeout=5)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS header missing',
                'X-Content-Type-Options': 'Content type options header missing',
                'X-Frame-Options': 'Frame options header missing',
                'X-XSS-Protection': 'XSS protection header missing',
                'Content-Security-Policy': 'Content Security Policy header missing'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    findings.append(SecurityFinding(
                        id=f"missing_header_{header.lower().replace('-', '_')}_{mcp_server.host}_{mcp_server.port}",
                        title=f"Missing {header} Header",
                        description=description,
                        category=VulnerabilityCategory.CONFIGURATION,
                        severity=RiskLevel.LOW,
                        confidence=0.8,
                        affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                        evidence={'missing_header': header},
                        remediation=f"Add {header} header to HTTP responses",
                        compliance_violations=[ComplianceFramework.OWASP_TOP_10]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Could not check HTTP headers for {mcp_server.host}:{mcp_server.port}: {e}")
        
        return findings
    
    def _check_http_methods(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Check for dangerous HTTP methods exposure."""
        findings = []
        
        try:
            url = f"http://{mcp_server.host}:{mcp_server.port}"
            response = self.session.options(url, timeout=5)
            
            if 'Allow' in response.headers:
                allowed_methods = response.headers['Allow'].split(', ')
                dangerous_methods = ['TRACE', 'TRACK', 'DELETE', 'PUT', 'PATCH']
                
                found_dangerous = [method for method in dangerous_methods if method in allowed_methods]
                
                if found_dangerous:
                    findings.append(SecurityFinding(
                        id=f"dangerous_http_methods_{mcp_server.host}_{mcp_server.port}",
                        title="Dangerous HTTP Methods Enabled",
                        description=f"Server allows potentially dangerous HTTP methods: {', '.join(found_dangerous)}",
                        category=VulnerabilityCategory.CONFIGURATION,
                        severity=RiskLevel.MEDIUM,
                        confidence=0.8,
                        affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                        evidence={
                            'allowed_methods': allowed_methods,
                            'dangerous_methods': found_dangerous
                        },
                        remediation="Disable unnecessary HTTP methods and restrict to required methods only",
                        compliance_violations=[ComplianceFramework.OWASP_TOP_10]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Could not check HTTP methods for {mcp_server.host}:{mcp_server.port}: {e}")
        
        return findings
    
    def _check_websocket_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Check WebSocket-specific security issues."""
        findings = []
        
        # Check for WebSocket origin validation
        try:
            # This would require a more sophisticated WebSocket client
            # For now, we'll check configuration-based indicators
            if mcp_server.security_config:
                origin_check = any(
                    'origin' in str(key).lower() or 'cors' in str(key).lower()
                    for key in mcp_server.security_config.keys()
                )
                
                if not origin_check:
                    findings.append(SecurityFinding(
                        id=f"websocket_no_origin_validation_{mcp_server.host}_{mcp_server.port}",
                        title="WebSocket Origin Validation Missing",
                        description="No origin validation configuration found for WebSocket connections",
                        category=VulnerabilityCategory.AUTHENTICATION,
                        severity=RiskLevel.MEDIUM,
                        confidence=0.6,
                        affected_asset=f"{mcp_server.host}:{mcp_server.port}",
                        evidence={'config_checked': True},
                        remediation="Implement proper origin validation for WebSocket connections",
                        compliance_violations=[ComplianceFramework.OWASP_TOP_10]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Could not check WebSocket security for {mcp_server.host}:{mcp_server.port}: {e}")
        
        return findings
    
    def _is_elevated_process(self, process_info) -> bool:
        """Check if process is running with elevated privileges."""
        try:
            # Check if process user is root/administrator
            username = getattr(process_info, 'username', '').lower()
            return username in ['root', 'administrator', 'system']
        except:
            return False
    
    def _check_stdio_cmdline_security(self, mcp_server: MCPServerInfo) -> List[SecurityFinding]:
        """Check STDIO command line for security issues."""
        findings = []
        
        if not mcp_server.process_info or not mcp_server.process_info.cmdline:
            return findings
        
        cmdline_str = ' '.join(mcp_server.process_info.cmdline)
        
        # Check for hardcoded credentials in command line
        credential_patterns = [
            r'--password[=\s]+[^\s]+',
            r'--token[=\s]+[^\s]+',
            r'--api[_-]?key[=\s]+[^\s]+',
            r'--secret[=\s]+[^\s]+',
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, cmdline_str, re.IGNORECASE):
                findings.append(SecurityFinding(
                    id=f"stdio_cmdline_credentials_{mcp_server.host}",
                    title="Credentials in Command Line",
                    description="Potential credentials found in process command line arguments",
                    category=VulnerabilityCategory.AUTHENTICATION,
                    severity=RiskLevel.HIGH,
                    confidence=0.8,
                    affected_asset=f"{mcp_server.host} (PID: {mcp_server.process_info.pid})",
                    evidence={'cmdline_pattern': pattern},
                    remediation="Use environment variables or configuration files for credentials",
                    compliance_violations=[
                        ComplianceFramework.OWASP_TOP_10,
                        ComplianceFramework.PCI_DSS
                    ]
                ))
        
        return findings
    
    def _analyze_tls_configuration(self, host: str, port: int) -> Dict[str, Any]:
        """Analyze TLS configuration of the server."""
        config = {
            'weak_protocols': [],
            'weak_ciphers': [],
            'certificate_valid': True,
            'certificate_info': {}
        }
        
        try:
            # Get SSL certificate and supported protocols
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    config['certificate_info'] = {
                        'subject': cert.get('subject', []),
                        'issuer': cert.get('issuer', []),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                    }
                    
                    # Check TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        config['weak_protocols'].append(version)
                    
                    # Check cipher suite
                    if cipher:
                        cipher_name = cipher[0].lower()
                        if any(weak in cipher_name for weak in ['rc4', 'des', 'md5', 'null']):
                            config['weak_ciphers'].append(cipher[0])
                    
                    # Basic certificate validation
                    if not cert:
                        config['certificate_valid'] = False
        
        except Exception as e:
            self.logger.debug(f"Could not analyze TLS configuration for {host}:{port}: {e}")
            config['certificate_valid'] = False
        
        return config
    
    def _generate_vulnerabilities(self, findings: List[SecurityFinding]) -> List[VulnerabilityInfo]:
        """Generate vulnerability information from security findings."""
        vulnerabilities = []
        
        # Group findings by category and create vulnerabilities
        critical_findings = [f for f in findings if f.severity == RiskLevel.CRITICAL]
        high_findings = [f for f in findings if f.severity == RiskLevel.HIGH]
        
        # Create vulnerabilities for critical and high severity findings
        for finding in critical_findings + high_findings:
            vuln = VulnerabilityInfo(
                id=finding.id,
                title=finding.title,
                description=finding.description,
                category=finding.category,
                severity=finding.severity,
                cvss_vector=self._create_cvss_vector(finding),
                cvss_score=self._calculate_cvss_score(finding),
                references=[],
                affected_components=[finding.affected_asset],
                exploit_available=finding.severity == RiskLevel.CRITICAL,
                patch_available=True,  # Assume patches/mitigations are available
                workaround_available=True
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_cvss_vector(self, finding: SecurityFinding) -> CVSSVector:
        """Create CVSS vector for a security finding."""
        # Create basic CVSS vector based on finding characteristics
        vector = CVSSVector()
        
        # Set attack vector based on category
        if finding.category in [VulnerabilityCategory.NETWORK, VulnerabilityCategory.ENCRYPTION]:
            vector.attack_vector = "N"  # Network
        else:
            vector.attack_vector = "L"  # Local
        
        # Set complexity based on severity
        vector.attack_complexity = "L" if finding.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL] else "H"
        
        # Set impact based on category
        if finding.category == VulnerabilityCategory.ENCRYPTION:
            vector.confidentiality = "H"
            vector.integrity = "H"
            vector.availability = "N"
        elif finding.category == VulnerabilityCategory.AUTHENTICATION:
            vector.confidentiality = "H"
            vector.integrity = "H"
            vector.availability = "L"
        elif finding.category == VulnerabilityCategory.CONFIGURATION:
            vector.confidentiality = "L"
            vector.integrity = "L"
            vector.availability = "L"
        else:
            vector.confidentiality = "L"
            vector.integrity = "L"
            vector.availability = "L"
        
        return vector
    
    def _calculate_cvss_score(self, finding: SecurityFinding) -> float:
        """Calculate CVSS score for a security finding."""
        # Simplified CVSS scoring based on severity
        severity_scores = {
            RiskLevel.CRITICAL: 9.0,
            RiskLevel.HIGH: 7.5,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.LOW: 2.5,
            RiskLevel.NONE: 0.0
        }
        
        base_score = severity_scores.get(finding.severity, 0.0)
        return base_score * finding.confidence
    
    def _generate_recommendations(self, findings: List[SecurityFinding], 
                                mcp_server: MCPServerInfo) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Transport-specific recommendations
        if mcp_server.transport_type == TransportType.HTTP:
            if any(f.category == VulnerabilityCategory.ENCRYPTION for f in findings):
                recommendations.append("Implement HTTPS with TLS 1.2 or higher for all HTTP communications")
            
            if any('header' in f.id for f in findings):
                recommendations.append("Configure security headers (HSTS, CSP, X-Frame-Options, etc.)")
        
        elif mcp_server.transport_type == TransportType.WEBSOCKET:
            if any(f.category == VulnerabilityCategory.ENCRYPTION for f in findings):
                recommendations.append("Use WSS (WebSocket Secure) instead of unencrypted WebSocket connections")
            
            if any('origin' in f.id for f in findings):
                recommendations.append("Implement proper origin validation for WebSocket connections")
        
        elif mcp_server.transport_type == TransportType.STDIO:
            if any(f.category == VulnerabilityCategory.AUTHORIZATION for f in findings):
                recommendations.append("Run MCP server processes with minimal required privileges")
            
            if any('cmdline' in f.id for f in findings):
                recommendations.append("Avoid passing sensitive information through command line arguments")
        
        # General recommendations
        if any(f.category == VulnerabilityCategory.NETWORK for f in findings):
            recommendations.append("Implement network segmentation and firewall rules to restrict access")
        
        if any(f.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL] for f in findings):
            recommendations.append("Prioritize remediation of high and critical severity findings")
        
        # Add compliance-specific recommendations
        compliance_violations = set()
        for finding in findings:
            compliance_violations.update(finding.compliance_violations)
        
        if ComplianceFramework.PCI_DSS in compliance_violations:
            recommendations.append("Ensure PCI DSS compliance by addressing encryption and authentication issues")
        
        if ComplianceFramework.OWASP_TOP_10 in compliance_violations:
            recommendations.append("Follow OWASP Top 10 guidelines to address common web application vulnerabilities")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _assess_compliance(self, findings: List[SecurityFinding]) -> Dict[ComplianceFramework, bool]:
        """Assess compliance status based on findings."""
        compliance_status = {}
        
        for framework in ComplianceFramework:
            # Check if any findings violate this framework
            violations = [f for f in findings if framework in f.compliance_violations]
            compliance_status[framework] = len(violations) == 0
        
        return compliance_status
    
    def _create_failed_result(self, target_host: str, error_message: str, 
                            duration: float) -> AssessmentResult:
        """Create a failed assessment result."""
        return AssessmentResult(
            target_host=target_host,
            assessment_duration=duration,
            raw_data={'error': error_message}
        )
    
    def _get_http_security_rules(self) -> List[Dict[str, Any]]:
        """Get HTTP-specific security rules."""
        return [
            {
                'id': 'http_encryption',
                'name': 'HTTP Encryption',
                'description': 'Check for HTTPS usage',
                'category': VulnerabilityCategory.ENCRYPTION,
                'severity': RiskLevel.HIGH
            },
            {
                'id': 'http_headers',
                'name': 'HTTP Security Headers',
                'description': 'Check for security headers',
                'category': VulnerabilityCategory.CONFIGURATION,
                'severity': RiskLevel.LOW
            }
        ]
    
    def _get_websocket_security_rules(self) -> List[Dict[str, Any]]:
        """Get WebSocket-specific security rules."""
        return [
            {
                'id': 'websocket_encryption',
                'name': 'WebSocket Encryption',
                'description': 'Check for WSS usage',
                'category': VulnerabilityCategory.ENCRYPTION,
                'severity': RiskLevel.HIGH
            },
            {
                'id': 'websocket_origin',
                'name': 'WebSocket Origin Validation',
                'description': 'Check for origin validation',
                'category': VulnerabilityCategory.AUTHENTICATION,
                'severity': RiskLevel.MEDIUM
            }
        ]
    
    def _get_stdio_security_rules(self) -> List[Dict[str, Any]]:
        """Get STDIO-specific security rules."""
        return [
            {
                'id': 'stdio_privileges',
                'name': 'STDIO Process Privileges',
                'description': 'Check for elevated privileges',
                'category': VulnerabilityCategory.AUTHORIZATION,
                'severity': RiskLevel.MEDIUM
            },
            {
                'id': 'stdio_cmdline',
                'name': 'STDIO Command Line Security',
                'description': 'Check for credentials in command line',
                'category': VulnerabilityCategory.AUTHENTICATION,
                'severity': RiskLevel.HIGH
            }
        ]
    
    def _get_general_transport_rules(self) -> List[Dict[str, Any]]:
        """Get general transport security rules."""
        return [
            {
                'id': 'transport_encryption',
                'name': 'Transport Encryption',
                'description': 'Check for encrypted transport',
                'category': VulnerabilityCategory.ENCRYPTION,
                'severity': RiskLevel.HIGH
            },
            {
                'id': 'network_binding',
                'name': 'Network Binding',
                'description': 'Check for secure network binding',
                'category': VulnerabilityCategory.NETWORK,
                'severity': RiskLevel.MEDIUM
            }
        ]