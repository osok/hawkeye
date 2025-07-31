"""
Unit tests for TCP scanner functionality.

This module contains tests for the TCPScanner class and related functionality.
"""

import pytest
import socket
import threading
import time
from unittest.mock import Mock, patch, MagicMock

from src.hawkeye.scanner.tcp_scanner import TCPScanner
from src.hawkeye.scanner.base import ScanTarget, ScanResult, PortState, ScanType
from src.hawkeye.config.settings import get_settings


class TestTCPScanner:
    """Test cases for TCPScanner class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.settings = get_settings()
        self.scanner = TCPScanner(self.settings)
        self.target = ScanTarget(host="127.0.0.1", ports=[80, 443, 22])
    
    def test_scanner_initialization(self):
        """Test TCP scanner initialization."""
        assert self.scanner is not None
        assert self.scanner.settings == self.settings
        assert self.scanner.get_scan_type() == ScanType.TCP_CONNECT
    
    def test_scan_open_port(self):
        """Test scanning an open port."""
        # Create a mock socket that succeeds
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0  # Success
            mock_socket_class.return_value = mock_socket
            
            result = self.scanner.scan_port(self.target, 80)
            
            assert isinstance(result, ScanResult)
            assert result.target == self.target
            assert result.port == 80
            assert result.state == PortState.OPEN
            assert result.scan_type == ScanType.TCP_CONNECT
            assert result.response_time is not None
            assert result.response_time > 0
            
            # Verify socket operations
            mock_socket.connect_ex.assert_called_once_with(("127.0.0.1", 80))
            mock_socket.close.assert_called_once()
    
    def test_scan_closed_port(self):
        """Test scanning a closed port."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 111  # Connection refused
            mock_socket_class.return_value = mock_socket
            
            result = self.scanner.scan_port(self.target, 9999)
            
            assert result.state == PortState.CLOSED
            assert result.port == 9999
            assert result.error is None
            assert 'errno' in result.raw_data
            assert result.raw_data['errno'] == '111'
    
    def test_scan_timeout(self):
        """Test scanning with timeout."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.side_effect = socket.timeout()
            mock_socket_class.return_value = mock_socket
            
            result = self.scanner.scan_port(self.target, 80)
            
            assert result.state == PortState.FILTERED
            assert result.error == "Connection timeout"
            assert result.response_time is not None
    
    def test_scan_dns_error(self):
        """Test scanning with DNS resolution error."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.side_effect = socket.gaierror("Name resolution failed")
            mock_socket_class.return_value = mock_socket
            
            target = ScanTarget(host="nonexistent.example.com", ports=[80])
            result = self.scanner.scan_port(target, 80)
            
            assert result.state == PortState.UNKNOWN
            assert "DNS resolution failed" in result.error
    
    def test_scan_target_multiple_ports(self):
        """Test scanning multiple ports on a target."""
        with patch.object(self.scanner, 'scan_port') as mock_scan_port:
            # Mock successful scans
            mock_results = [
                ScanResult(self.target, 80, PortState.OPEN, ScanType.TCP_CONNECT),
                ScanResult(self.target, 443, PortState.CLOSED, ScanType.TCP_CONNECT),
                ScanResult(self.target, 22, PortState.OPEN, ScanType.TCP_CONNECT),
            ]
            mock_scan_port.side_effect = mock_results
            
            results = self.scanner.scan_target(self.target)
            
            assert len(results) == 3
            assert mock_scan_port.call_count == 3
            
            # Check that all ports were scanned
            scanned_ports = [call[0][1] for call in mock_scan_port.call_args_list]
            assert set(scanned_ports) == {80, 443, 22}
    
    def test_banner_grabbing(self):
        """Test banner grabbing functionality."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0
            mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
            mock_socket_class.return_value = mock_socket
            
            banner = self.scanner.grab_banner(self.target, 80)
            
            assert banner is not None
            assert "HTTP/1.1 200 OK" in banner
            assert "nginx/1.18.0" in banner
            
            mock_socket.connect_ex.assert_called_once()
            mock_socket.recv.assert_called_once()
            mock_socket.close.assert_called_once()
    
    def test_banner_grabbing_no_response(self):
        """Test banner grabbing with no response."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0
            mock_socket.recv.return_value = b""  # No data
            mock_socket_class.return_value = mock_socket
            
            banner = self.scanner.grab_banner(self.target, 80)
            
            assert banner is None
    
    def test_banner_grabbing_connection_failed(self):
        """Test banner grabbing with connection failure."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 111  # Connection refused
            mock_socket_class.return_value = mock_socket
            
            banner = self.scanner.grab_banner(self.target, 80)
            
            assert banner is None
    
    def test_http_service_detection(self):
        """Test HTTP service detection."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0
            mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html>..."
            mock_socket_class.return_value = mock_socket
            
            response = self.scanner.test_http_service(self.target, 80)
            
            assert response is not None
            assert response.startswith("HTTP/1.1 200 OK")
            assert "Apache/2.4.41" in response
            
            # Verify HTTP request was sent
            mock_socket.send.assert_called_once()
            sent_data = mock_socket.send.call_args[0][0].decode()
            assert "GET / HTTP/1.1" in sent_data
            assert "Host: 127.0.0.1" in sent_data
    
    def test_scan_with_banner_grab(self):
        """Test scanning with banner grabbing enabled."""
        with patch.object(self.scanner, 'scan_port') as mock_scan_port, \
             patch.object(self.scanner, 'grab_banner') as mock_grab_banner, \
             patch.object(self.scanner, 'test_http_service') as mock_http_test:
            
            # Mock an open port
            open_result = ScanResult(self.target, 80, PortState.OPEN, ScanType.TCP_CONNECT)
            mock_scan_port.return_value = open_result
            
            # Mock banner and HTTP response
            mock_grab_banner.return_value = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"
            mock_http_test.return_value = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
            
            result = self.scanner.scan_with_banner_grab(self.target, 80)
            
            assert result.state == PortState.OPEN
            assert result.service_info is not None
            assert 'banner' in result.raw_data
            assert 'http_response' in result.raw_data
            
            mock_grab_banner.assert_called_once_with(self.target, 80)
            mock_http_test.assert_called_once_with(self.target, 80)
    
    def test_scan_statistics(self):
        """Test scan statistics tracking."""
        with patch.object(self.scanner, 'scan_port') as mock_scan_port:
            # Mock some successful and failed scans
            mock_scan_port.side_effect = [
                ScanResult(self.target, 80, PortState.OPEN, ScanType.TCP_CONNECT),
                ScanResult(self.target, 443, PortState.CLOSED, ScanType.TCP_CONNECT),
                Exception("Network error"),
            ]
            
            # Scan target with 3 ports, one will fail
            target_with_3_ports = ScanTarget(host="127.0.0.1", ports=[80, 443, 22])
            results = self.scanner.scan_target(target_with_3_ports)
            
            stats = self.scanner.get_scan_statistics()
            
            assert stats['total_scans'] == 3
            assert stats['successful_scans'] == 2
            assert stats['failed_scans'] == 1
            assert stats['start_time'] is not None
            assert stats['end_time'] is not None
            assert stats['duration'] > 0
    
    def test_ipv6_support(self):
        """Test IPv6 address scanning."""
        ipv6_target = ScanTarget(host="::1", ports=[80])
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket.connect_ex.return_value = 0
            mock_socket_class.return_value = mock_socket
            
            result = self.scanner.scan_port(ipv6_target, 80)
            
            # Verify IPv6 socket was created
            mock_socket_class.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM)
            assert result.state == PortState.OPEN
    
    def test_socket_timeout_configuration(self):
        """Test that socket timeout is properly configured."""
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            self.scanner._create_socket(self.target)
            
            # Verify timeout was set
            mock_socket.settimeout.assert_called_with(self.settings.scan.timeout_seconds)
    
    def test_clear_results(self):
        """Test clearing scan results and statistics."""
        # Add some mock results
        self.scanner._results = [
            ScanResult(self.target, 80, PortState.OPEN, ScanType.TCP_CONNECT),
            ScanResult(self.target, 443, PortState.CLOSED, ScanType.TCP_CONNECT),
        ]
        self.scanner._scan_stats['total_scans'] = 2
        
        self.scanner.clear_results()
        
        assert len(self.scanner._results) == 0
        assert self.scanner._scan_stats['total_scans'] == 0
        assert self.scanner._scan_stats['successful_scans'] == 0
        assert self.scanner._scan_stats['failed_scans'] == 0
    
    def test_get_open_ports(self):
        """Test filtering for open ports only."""
        # Add mixed results
        self.scanner._results = [
            ScanResult(self.target, 80, PortState.OPEN, ScanType.TCP_CONNECT),
            ScanResult(self.target, 443, PortState.CLOSED, ScanType.TCP_CONNECT),
            ScanResult(self.target, 22, PortState.OPEN, ScanType.TCP_CONNECT),
            ScanResult(self.target, 23, PortState.FILTERED, ScanType.TCP_CONNECT),
        ]
        
        open_ports = self.scanner.get_open_ports()
        
        assert len(open_ports) == 2
        assert all(result.state == PortState.OPEN for result in open_ports)
        assert {result.port for result in open_ports} == {80, 22} 