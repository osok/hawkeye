"""
Integration tests for complete scanning workflow.

Tests cover end-to-end scanning operations including TCP/UDP scanning,
service fingerprinting, rate limiting, and complete scan pipeline.
"""

import time
import threading
import pytest
from unittest.mock import Mock, patch, MagicMock
import socket

from src.hawkeye.scanner.tcp_scanner import TCPScanner
from src.hawkeye.scanner.udp_scanner import UDPScanner
from src.hawkeye.scanner.target_enum import TargetEnumerator
from src.hawkeye.scanner.fingerprint import ServiceFingerprinter
from src.hawkeye.scanner.connection_pool import ConnectionPool
from src.hawkeye.scanner.rate_limiter import RateLimiter
from src.hawkeye.scanner.base import ScanTarget, ScanResult, PortState, ScanType
from src.hawkeye.config.settings import get_settings


class TestScanningIntegration:
    """Integration tests for complete scanning workflow."""
    
    @pytest.fixture
    def settings(self):
        """Get test settings."""
        return get_settings()
    
    @pytest.fixture
    def tcp_scanner(self, settings):
        """Create TCP scanner instance."""
        return TCPScanner(settings)
    
    @pytest.fixture
    def udp_scanner(self, settings):
        """Create UDP scanner instance."""
        return UDPScanner(settings)
    
    @pytest.fixture
    def target_enumerator(self, settings):
        """Create target enumerator instance."""
        return TargetEnumerator(settings)
    
    @pytest.fixture
    def fingerprinter(self, settings):
        """Create service fingerprinter instance."""
        return ServiceFingerprinter(settings)
    
    @pytest.fixture
    def connection_pool(self, settings):
        """Create connection pool instance."""
        return ConnectionPool(settings)
    
    @pytest.fixture
    def rate_limiter(self, settings):
        """Create rate limiter instance."""
        return RateLimiter(settings)
    
    @pytest.fixture
    def test_targets(self):
        """Create test scan targets."""
        return [
            ScanTarget(
                host="127.0.0.1",
                ports=[22, 80, 443, 3000],
                scan_types={ScanType.TCP, ScanType.UDP}
            ),
            ScanTarget(
                host="127.0.0.1",
                ports=[53, 161, 123],
                scan_types={ScanType.UDP}
            )
        ]
    
    def test_complete_tcp_scan_workflow(self, tcp_scanner, fingerprinter, test_targets):
        """Test complete TCP scanning workflow."""
        target = test_targets[0]
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock successful connection
            mock_socket.connect_ex.return_value = 0
            mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
            
            results = []
            for port in target.ports:
                # Scan port
                scan_result = tcp_scanner.scan_port(target, port)
                
                # Fingerprint if open
                if scan_result.state == PortState.OPEN:
                    scan_result = fingerprinter.fingerprint_service(scan_result)
                
                results.append(scan_result)
            
            # Verify results
            assert len(results) == len(target.ports)
            
            # At least some ports should be detected as open (mocked)
            open_ports = [r for r in results if r.state == PortState.OPEN]
            assert len(open_ports) > 0
            
            # Verify service fingerprinting occurred
            for result in open_ports:
                assert result.service_info is not None
    
    def test_complete_udp_scan_workflow(self, udp_scanner, fingerprinter, test_targets):
        """Test complete UDP scanning workflow."""
        target = test_targets[1]  # UDP-only target
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock DNS response for port 53
            def mock_recvfrom(size):
                if hasattr(mock_recvfrom, 'call_count'):
                    mock_recvfrom.call_count += 1
                else:
                    mock_recvfrom.call_count = 1
                
                if mock_recvfrom.call_count == 1:
                    # DNS response
                    return (b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00', ('127.0.0.1', 53))
                else:
                    # Timeout for other ports
                    raise socket.timeout()
            
            mock_socket.recvfrom.side_effect = mock_recvfrom
            
            results = []
            for port in target.ports:
                scan_result = udp_scanner.scan_port(target, port)
                
                # Fingerprint if open
                if scan_result.state == PortState.OPEN:
                    scan_result = fingerprinter.fingerprint_service(scan_result)
                
                results.append(scan_result)
            
            # Verify results
            assert len(results) == len(target.ports)
            
            # DNS port should be open, others filtered
            dns_result = next((r for r in results if r.port == 53), None)
            assert dns_result is not None
            assert dns_result.state == PortState.OPEN
    
    def test_target_enumeration_to_scanning(self, target_enumerator, tcp_scanner):
        """Test target enumeration integration with scanning."""
        cidr = "127.0.0.0/31"  # Just 2 addresses
        ports = [80, 443]
        
        # Enumerate targets
        targets = list(target_enumerator.enumerate_from_cidr(cidr, ports))
        
        assert len(targets) == 2
        assert all(isinstance(t, ScanTarget) for t in targets)
        
        # Mock scanning
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 0  # Success
            
            all_results = []
            for target in targets:
                for port in target.ports:
                    result = tcp_scanner.scan_port(target, port)
                    all_results.append(result)
            
            # Should have scanned all ports on all targets
            expected_scans = len(targets) * len(ports)
            assert len(all_results) == expected_scans
    
    def test_rate_limiting_integration(self, tcp_scanner, rate_limiter):
        """Test rate limiting integration with scanning."""
        target = ScanTarget(
            host="127.0.0.1",
            ports=[80, 443, 22, 21],
            scan_types={ScanType.TCP}
        )
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 0
            
            start_time = time.time()
            results = []
            
            for port in target.ports:
                # Apply rate limiting
                rate_limiter.acquire()
                
                # Perform scan
                result = tcp_scanner.scan_port(target, port)
                results.append(result)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # With rate limiting, should take measurable time
            assert total_time > 0.1  # At least some delay
            assert len(results) == len(target.ports)
    
    def test_connection_pool_integration(self, connection_pool, tcp_scanner):
        """Test connection pool integration with scanning."""
        targets = [
            ScanTarget(host="127.0.0.1", ports=[80, 443], scan_types={ScanType.TCP}),
            ScanTarget(host="127.0.0.1", ports=[22, 21], scan_types={ScanType.TCP}),
        ]
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 0
            
            # Submit tasks to connection pool
            future_results = []
            for target in targets:
                for port in target.ports:
                    future = connection_pool.submit(tcp_scanner.scan_port, target, port)
                    future_results.append(future)
            
            # Wait for completion
            results = []
            for future in future_results:
                result = future.result(timeout=10)
                results.append(result)
            
            # Verify all scans completed
            assert len(results) == 4  # 2 targets × 2 ports each
            assert all(isinstance(r, ScanResult) for r in results)
    
    def test_mixed_tcp_udp_scanning(self, tcp_scanner, udp_scanner):
        """Test mixed TCP and UDP scanning workflow."""
        target = ScanTarget(
            host="127.0.0.1",
            ports=[80, 53, 443, 161],  # Mix of TCP and UDP common ports
            scan_types={ScanType.TCP, ScanType.UDP}
        )
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock TCP success
            mock_socket.connect_ex.return_value = 0
            # Mock UDP timeout
            mock_socket.recvfrom.side_effect = socket.timeout()
            
            tcp_results = []
            udp_results = []
            
            for port in target.ports:
                # TCP scan
                if ScanType.TCP in target.scan_types:
                    tcp_result = tcp_scanner.scan_port(target, port)
                    tcp_results.append(tcp_result)
                
                # UDP scan
                if ScanType.UDP in target.scan_types:
                    udp_result = udp_scanner.scan_port(target, port)
                    udp_results.append(udp_result)
            
            # Verify both types of scans
            assert len(tcp_results) == len(target.ports)
            assert len(udp_results) == len(target.ports)
            
            # Verify scan types
            assert all(r.scan_type == ScanType.TCP for r in tcp_results)
            assert all(r.scan_type == ScanType.UDP for r in udp_results)
    
    def test_service_fingerprinting_integration(self, tcp_scanner, fingerprinter):
        """Test service fingerprinting integration with scanning."""
        target = ScanTarget(
            host="127.0.0.1",
            ports=[80, 443, 22],
            scan_types={ScanType.TCP}
        )
        
        service_banners = {
            80: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
            443: b"HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.41\r\n\r\n",
            22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"
        }
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 0
            
            def mock_recv(size):
                # Get port from last connect call
                if hasattr(mock_socket, '_last_port'):
                    port = mock_socket._last_port
                    return service_banners.get(port, b"")
                return b""
            
            mock_socket.recv.side_effect = mock_recv
            
            results = []
            for port in target.ports:
                mock_socket._last_port = port  # Track which port we're testing
                
                # Scan port
                scan_result = tcp_scanner.scan_port(target, port)
                
                # Fingerprint service
                if scan_result.state == PortState.OPEN:
                    scan_result = fingerprinter.fingerprint_service(scan_result)
                
                results.append(scan_result)
            
            # Verify service identification
            http_results = [r for r in results if r.port in [80, 443]]
            ssh_results = [r for r in results if r.port == 22]
            
            for result in http_results:
                assert result.service_info is not None
                assert "HTTP" in result.service_info.service.upper()
            
            for result in ssh_results:
                assert result.service_info is not None
                assert "SSH" in result.service_info.service.upper()
    
    def test_error_handling_integration(self, tcp_scanner, udp_scanner):
        """Test error handling in complete scanning workflow."""
        target = ScanTarget(
            host="127.0.0.1",
            ports=[80, 53],
            scan_types={ScanType.TCP, ScanType.UDP}
        )
        
        with patch('socket.socket') as mock_socket_class:
            # Mock socket creation failure
            mock_socket_class.side_effect = socket.error("Socket creation failed")
            
            tcp_result = tcp_scanner.scan_port(target, 80)
            udp_result = udp_scanner.scan_port(target, 53)
            
            # Both should handle errors gracefully
            assert tcp_result.state == PortState.UNKNOWN
            assert udp_result.state == PortState.UNKNOWN
            assert tcp_result.error is not None
            assert udp_result.error is not None
    
    def test_threaded_scanning_workflow(self, tcp_scanner, connection_pool):
        """Test threaded scanning workflow with multiple targets."""
        targets = []
        for i in range(3):
            target = ScanTarget(
                host="127.0.0.1",
                ports=[80 + i, 443 + i],
                scan_types={ScanType.TCP}
            )
            targets.append(target)
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 0
            
            # Submit all scan tasks
            futures = []
            for target in targets:
                for port in target.ports:
                    future = connection_pool.submit(tcp_scanner.scan_port, target, port)
                    futures.append(future)
            
            # Collect results
            results = []
            for future in futures:
                result = future.result(timeout=10)
                results.append(result)
            
            # Verify all scans completed
            expected_count = sum(len(t.ports) for t in targets)
            assert len(results) == expected_count
            
            # Verify no errors in threaded execution
            error_results = [r for r in results if r.error is not None]
            assert len(error_results) == 0
    
    def test_scan_statistics_collection(self, tcp_scanner, udp_scanner):
        """Test collection of scan statistics during workflow."""
        target = ScanTarget(
            host="127.0.0.1",
            ports=[80, 443, 53, 161],
            scan_types={ScanType.TCP, ScanType.UDP}
        )
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock mixed results
            mock_socket.connect_ex.side_effect = [0, 1, 0, 1]  # TCP: open, closed, open, closed
            mock_socket.recvfrom.side_effect = [
                (b"response", ("127.0.0.1", 53)),  # UDP: open
                socket.timeout(),  # UDP: filtered
                (b"response", ("127.0.0.1", 161)),  # UDP: open
                socket.timeout()  # UDP: filtered
            ]
            
            tcp_results = []
            udp_results = []
            
            # Perform scans
            for port in target.ports:
                tcp_result = tcp_scanner.scan_port(target, port)
                udp_result = udp_scanner.scan_port(target, port)
                
                tcp_results.append(tcp_result)
                udp_results.append(udp_result)
            
            # Analyze statistics
            tcp_open = sum(1 for r in tcp_results if r.state == PortState.OPEN)
            tcp_closed = sum(1 for r in tcp_results if r.state == PortState.CLOSED)
            udp_open = sum(1 for r in udp_results if r.state == PortState.OPEN)
            udp_filtered = sum(1 for r in udp_results if r.state == PortState.FILTERED)
            
            # Verify statistics match expectations
            assert tcp_open == 2
            assert tcp_closed == 2
            assert udp_open == 2
            assert udp_filtered == 2
    
    def test_timeout_handling_integration(self, tcp_scanner, udp_scanner):
        """Test timeout handling across different scanners."""
        target = ScanTarget(
            host="127.0.0.1",
            ports=[80, 53],
            scan_types={ScanType.TCP, ScanType.UDP}
        )
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            
            # Mock timeouts
            mock_socket.connect_ex.side_effect = socket.timeout()
            mock_socket.recvfrom.side_effect = socket.timeout()
            
            start_time = time.time()
            
            tcp_result = tcp_scanner.scan_port(target, 80)
            udp_result = udp_scanner.scan_port(target, 53)
            
            end_time = time.time()
            
            # Should handle timeouts gracefully
            assert tcp_result.state == PortState.UNKNOWN
            assert udp_result.state == PortState.FILTERED
            
            # Should respect timeout settings
            total_time = end_time - start_time
            assert total_time < 30  # Should not hang indefinitely
    
    def test_ipv6_scanning_integration(self, tcp_scanner, target_enumerator):
        """Test IPv6 scanning integration."""
        # Test IPv6 localhost
        targets = list(target_enumerator.enumerate_from_cidr("::1/128", [80, 443]))
        
        assert len(targets) == 1
        ipv6_target = targets[0]
        assert ipv6_target.is_ipv6
        
        with patch('socket.socket') as mock_socket_class:
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket
            mock_socket.connect_ex.return_value = 0
            
            results = []
            for port in ipv6_target.ports:
                result = tcp_scanner.scan_port(ipv6_target, port)
                results.append(result)
            
            # Verify IPv6 socket was created
            mock_socket_class.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM)
            
            # Verify scan results
            assert len(results) == len(ipv6_target.ports)
            for result in results:
                assert result.target.is_ipv6 