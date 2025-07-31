"""
Unit tests for UDP scanner functionality.

Tests cover UDP port scanning, timeout handling, ICMP responses,
service-specific probes, and error scenarios.
"""

import socket
import time
import pytest
from unittest.mock import Mock, patch, MagicMock

from src.hawkeye.scanner.udp_scanner import UDPScanner
from src.hawkeye.scanner.base import ScanTarget, ScanResult, PortState, ScanType
from src.hawkeye.config.settings import get_settings


class TestUDPScanner:
    """Test cases for UDP scanner."""
    
    @pytest.fixture
    def scanner(self):
        """Create UDP scanner instance."""
        settings = get_settings()
        return UDPScanner(settings)
    
    @pytest.fixture 
    def target(self):
        """Create test scan target."""
        return ScanTarget(
            host="127.0.0.1",
            ports=[53, 161, 123],
            scan_types={ScanType.UDP}
        )
    
    @pytest.fixture
    def ipv6_target(self):
        """Create IPv6 test scan target."""
        return ScanTarget(
            host="::1",
            ports=[53, 161],
            scan_types={ScanType.UDP}
        )
    
    def test_scanner_initialization(self, scanner):
        """Test UDP scanner initialization."""
        assert isinstance(scanner, UDPScanner)
        assert scanner.get_scan_type() == ScanType.UDP
        assert scanner.logger is not None
    
    @patch('socket.socket')
    def test_scan_port_open_response(self, mock_socket_class, scanner, target):
        """Test UDP scan with response indicating open port."""
        # Mock socket instance
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock successful response
        test_response = b"DNS response data"
        mock_socket.recvfrom.return_value = (test_response, ('127.0.0.1', 53))
        
        result = scanner.scan_port(target, 53)
        
        assert isinstance(result, ScanResult)
        assert result.port == 53
        assert result.state == PortState.OPEN
        assert result.scan_type == ScanType.UDP
        assert result.response_time > 0
        assert 'response' in result.raw_data
        
        # Verify socket operations
        mock_socket.sendto.assert_called_once()
        mock_socket.recvfrom.assert_called_once_with(1024)
        mock_socket.close.assert_called_once()
    
    @patch('socket.socket')
    def test_scan_port_timeout_filtered(self, mock_socket_class, scanner, target):
        """Test UDP scan with timeout indicating filtered/open port."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock timeout exception
        mock_socket.recvfrom.side_effect = socket.timeout()
        
        result = scanner.scan_port(target, 161)
        
        assert result.port == 161
        assert result.state == PortState.FILTERED
        assert result.scan_type == ScanType.UDP
        assert result.response_time > 0
        assert result.raw_data['status'] == 'no_response'
    
    @patch('socket.socket')
    def test_scan_port_icmp_unreachable(self, mock_socket_class, scanner, target):
        """Test UDP scan with ICMP port unreachable indicating closed port."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock ICMP port unreachable error
        icmp_error = socket.error("port unreachable")
        icmp_error.errno = 111
        mock_socket.sendto.side_effect = icmp_error
        
        result = scanner.scan_port(target, 9999)
        
        assert result.port == 9999
        assert result.state == PortState.CLOSED
        assert result.scan_type == ScanType.UDP
        assert 'icmp_error' in result.raw_data
    
    @patch('socket.socket')
    def test_scan_port_socket_error(self, mock_socket_class, scanner, target):
        """Test UDP scan with generic socket error."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock generic socket error
        mock_socket.sendto.side_effect = socket.error("Network unreachable")
        
        result = scanner.scan_port(target, 123)
        
        assert result.port == 123
        assert result.state == PortState.UNKNOWN
        assert result.scan_type == ScanType.UDP
        assert result.error is not None
    
    @patch('socket.socket')
    def test_scan_port_unexpected_error(self, mock_socket_class, scanner, target):
        """Test UDP scan with unexpected error."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock unexpected exception
        mock_socket.sendto.side_effect = Exception("Unexpected error")
        
        result = scanner.scan_port(target, 161)
        
        assert result.port == 161
        assert result.state == PortState.UNKNOWN
        assert result.scan_type == ScanType.UDP
        assert "Scan error" in result.error
    
    def test_create_udp_socket_ipv4(self, scanner, target):
        """Test UDP socket creation for IPv4."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            result_socket = scanner._create_udp_socket(target)
            
            mock_socket_class.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
            mock_socket.settimeout.assert_called_once()
            assert result_socket == mock_socket
    
    def test_create_udp_socket_ipv6(self, scanner, ipv6_target):
        """Test UDP socket creation for IPv6."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            result_socket = scanner._create_udp_socket(ipv6_target)
            
            mock_socket_class.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
            mock_socket.settimeout.assert_called_once()
    
    @patch('socket.socket')
    def test_scan_with_service_probe_dns(self, mock_socket_class, scanner, target):
        """Test UDP scan with DNS service probe."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock DNS response
        dns_response = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        mock_socket.recvfrom.return_value = (dns_response, ('127.0.0.1', 53))
        
        result = scanner.scan_with_service_probe(target, 53)
        
        assert result.port == 53
        assert result.state == PortState.OPEN
        assert result.service_info is not None
        assert 'response' in result.raw_data
    
    @patch('socket.socket')
    def test_scan_with_service_probe_snmp(self, mock_socket_class, scanner, target):
        """Test UDP scan with SNMP service probe."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock SNMP response
        snmp_response = b'\x30\x82\x00\x1a\x02\x01\x00\x04\x06public'
        mock_socket.recvfrom.return_value = (snmp_response, ('127.0.0.1', 161))
        
        result = scanner.scan_with_service_probe(target, 161)
        
        assert result.port == 161
        assert result.state == PortState.OPEN
        assert result.service_info is not None
    
    @patch('socket.socket')
    def test_scan_with_service_probe_timeout_fallback(self, mock_socket_class, scanner, target):
        """Test service probe falling back to basic scan on timeout."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock timeout on service probe, then success on fallback
        mock_socket.recvfrom.side_effect = [socket.timeout(), socket.timeout()]
        
        result = scanner.scan_with_service_probe(target, 123)
        
        assert result.port == 123
        assert result.state == PortState.FILTERED  # From fallback basic scan
    
    def test_get_service_probe_dns(self, scanner):
        """Test DNS service probe generation."""
        probe_data = scanner._get_service_probe(53)
        
        assert isinstance(probe_data, bytes)
        assert len(probe_data) > 0
        # DNS query should start with transaction ID and flags
    
    def test_get_service_probe_snmp(self, scanner):
        """Test SNMP service probe generation."""
        probe_data = scanner._get_service_probe(161)
        
        assert isinstance(probe_data, bytes)
        assert len(probe_data) > 0
        # SNMP GetRequest should start with sequence tag
        assert probe_data.startswith(b'\x30')
    
    def test_get_service_probe_ntp(self, scanner):
        """Test NTP service probe generation."""
        probe_data = scanner._get_service_probe(123)
        
        assert isinstance(probe_data, bytes)
        assert len(probe_data) == 48  # NTP packet size
        # NTP packet should have proper version and mode
        assert probe_data[0] & 0x3f == 0x1b  # Version 3, Mode 3 (client)
    
    def test_get_service_probe_default(self, scanner):
        """Test default service probe for unknown ports."""
        probe_data = scanner._get_service_probe(9999)
        
        assert isinstance(probe_data, bytes)
        assert b"HawkEye UDP Probe" in probe_data
    
    def test_analyze_udp_response_dns(self, scanner):
        """Test DNS response analysis."""
        # Mock DNS response packet
        dns_response = b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        
        service_info = scanner._analyze_udp_response(dns_response, 53)
        
        assert service_info is not None
        assert service_info.service == "DNS"
        assert service_info.confidence > 0.8
    
    def test_analyze_udp_response_snmp(self, scanner):
        """Test SNMP response analysis."""
        # Mock SNMP response packet
        snmp_response = b'\x30\x82\x00\x1a\x02\x01\x00\x04\x06public'
        
        service_info = scanner._analyze_udp_response(snmp_response, 161)
        
        assert service_info is not None
        assert service_info.service == "SNMP"
        assert service_info.confidence > 0.8
    
    def test_analyze_udp_response_unknown(self, scanner):
        """Test analysis of unknown response."""
        unknown_response = b'unknown service response'
        
        service_info = scanner._analyze_udp_response(unknown_response, 9999)
        
        # Should return None or basic service info for unknown responses
        if service_info:
            assert service_info.confidence < 0.5
    
    @patch('socket.socket')
    def test_multiple_port_scan(self, mock_socket_class, scanner, target):
        """Test scanning multiple UDP ports."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock different responses for different ports
        responses = [
            (b'DNS response', ('127.0.0.1', 53)),
            socket.timeout(),  # Port 161 timeout
            (b'NTP response', ('127.0.0.1', 123))
        ]
        mock_socket.recvfrom.side_effect = responses
        
        results = []
        for port in target.ports:
            result = scanner.scan_port(target, port)
            results.append(result)
        
        assert len(results) == 3
        assert results[0].state == PortState.OPEN  # DNS
        assert results[1].state == PortState.FILTERED  # SNMP timeout
        assert results[2].state == PortState.OPEN  # NTP
    
    def test_response_time_measurement(self, scanner, target):
        """Test that response times are properly measured."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock delayed response
            def delayed_response(*args):
                time.sleep(0.1)  # 100ms delay
                return (b'response', ('127.0.0.1', 53))
            
            mock_socket.recvfrom.side_effect = delayed_response
            
            result = scanner.scan_port(target, 53)
            
            assert result.response_time >= 0.1
            assert result.response_time < 1.0  # Should be reasonable
    
    @patch('socket.socket')
    def test_socket_cleanup_on_error(self, mock_socket_class, scanner, target):
        """Test that sockets are properly cleaned up on errors."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock error after socket creation
        mock_socket.sendto.side_effect = Exception("Test error")
        
        result = scanner.scan_port(target, 53)
        
        # Socket should still be closed despite error
        mock_socket.close.assert_called_once()
        assert result.error is not None 