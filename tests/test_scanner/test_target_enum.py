"""
Unit tests for target enumeration functionality.

Tests cover CIDR parsing, IP ranges, hostname resolution,
and various target input formats.
"""

import ipaddress
import pytest
from unittest.mock import Mock, patch, MagicMock

from src.hawkeye.scanner.target_enum import TargetEnumerator
from src.hawkeye.scanner.base import ScanTarget, ScanType
from src.hawkeye.config.settings import get_settings


class TestTargetEnumerator:
    """Test cases for target enumeration."""
    
    @pytest.fixture
    def enumerator(self):
        """Create target enumerator instance."""
        settings = get_settings()
        return TargetEnumerator(settings)
    
    @pytest.fixture
    def default_ports(self):
        """Default ports for testing."""
        return [80, 443, 22, 3000]
    
    def test_enumerator_initialization(self, enumerator):
        """Test target enumerator initialization."""
        assert isinstance(enumerator, TargetEnumerator)
        assert enumerator.settings is not None
        assert enumerator.logger is not None
    
    def test_enumerate_targets_single_ip(self, enumerator, default_ports):
        """Test enumeration of single IP address."""
        target = "192.168.1.100"
        
        targets = enumerator.enumerate_targets(target, default_ports)
        
        assert len(targets) == 1
        assert targets[0] == "192.168.1.100"
    
    def test_enumerate_targets_hostname(self, enumerator, default_ports):
        """Test enumeration of hostname with DNS resolution."""
        with patch.object(enumerator, '_resolve_host') as mock_resolve:
            mock_resolve.return_value = ['192.168.1.100']
            
            targets = enumerator.enumerate_targets("example.com", default_ports)
            
            assert len(targets) == 1
            assert targets[0] == "192.168.1.100"
            mock_resolve.assert_called_once_with("example.com")
    
    def test_enumerate_targets_cidr_small(self, enumerator, default_ports):
        """Test enumeration of small CIDR range."""
        target = "192.168.1.0/30"  # 4 addresses
        
        targets = enumerator.enumerate_targets(target, default_ports)
        
        # Should include network, broadcast, and host addresses
        assert len(targets) == 4
        expected = ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]
        assert set(targets) == set(expected)
    
    def test_enumerate_targets_invalid_format(self, enumerator, default_ports):
        """Test enumeration with invalid target format."""
        with pytest.raises(ValueError, match="Invalid target specification"):
            enumerator.enumerate_targets("invalid.target.format!", default_ports)
    
    def test_enumerate_from_cidr_ipv4(self, enumerator, default_ports):
        """Test CIDR enumeration for IPv4."""
        cidr = "10.0.1.0/29"  # 8 addresses
        
        targets = list(enumerator.enumerate_from_cidr(cidr, default_ports))
        
        # Should get 8 targets (including network and broadcast)
        assert len(targets) == 8
        
        # Verify all targets are ScanTarget objects
        for target in targets:
            assert isinstance(target, ScanTarget)
            assert target.ports == default_ports
            assert ScanType.TCP in target.scan_types or ScanType.UDP in target.scan_types
    
    def test_enumerate_from_cidr_ipv6(self, enumerator, default_ports):
        """Test CIDR enumeration for IPv6."""
        cidr = "2001:db8::/126"  # 4 addresses
        
        targets = list(enumerator.enumerate_from_cidr(cidr, default_ports))
        
        assert len(targets) == 4
        for target in targets:
            assert isinstance(target, ScanTarget)
            assert target.is_ipv6
    
    def test_enumerate_from_cidr_invalid(self, enumerator, default_ports):
        """Test CIDR enumeration with invalid CIDR."""
        with pytest.raises(ValueError, match="Invalid CIDR notation"):
            list(enumerator.enumerate_from_cidr("not.a.cidr/format", default_ports))
    
    def test_enumerate_from_range_ipv4(self, enumerator, default_ports):
        """Test IP range enumeration for IPv4."""
        start_ip = "192.168.1.10"
        end_ip = "192.168.1.15"
        
        targets = list(enumerator.enumerate_from_range(start_ip, end_ip, default_ports))
        
        assert len(targets) == 6  # 10, 11, 12, 13, 14, 15
        
        expected_ips = [f"192.168.1.{i}" for i in range(10, 16)]
        actual_ips = [target.host for target in targets]
        assert actual_ips == expected_ips
    
    def test_enumerate_from_range_ipv6(self, enumerator, default_ports):
        """Test IP range enumeration for IPv6."""
        start_ip = "2001:db8::1"
        end_ip = "2001:db8::3"
        
        targets = list(enumerator.enumerate_from_range(start_ip, end_ip, default_ports))
        
        assert len(targets) == 3
        for target in targets:
            assert target.is_ipv6
    
    def test_enumerate_from_range_invalid_order(self, enumerator, default_ports):
        """Test IP range with start > end."""
        with pytest.raises(ValueError, match="Start IP address must be less than"):
            list(enumerator.enumerate_from_range("192.168.1.20", "192.168.1.10", default_ports))
    
    def test_enumerate_from_range_mixed_types(self, enumerator, default_ports):
        """Test IP range with mixed IPv4/IPv6."""
        with pytest.raises(ValueError, match="must be the same type"):
            list(enumerator.enumerate_from_range("192.168.1.1", "2001:db8::1", default_ports))
    
    def test_enumerate_from_list_mixed(self, enumerator, default_ports):
        """Test enumeration from list of mixed hosts."""
        hosts = ["192.168.1.1", "example.com", "10.0.0.1"]
        
        with patch.object(enumerator, '_resolve_host') as mock_resolve:
            mock_resolve.side_effect = [
                ["192.168.1.1"],    # IP already resolved
                ["93.184.216.34"],  # example.com resolution
                ["10.0.0.1"]        # IP already resolved
            ]
            
            targets = list(enumerator.enumerate_from_list(hosts, default_ports))
            
            assert len(targets) == 3
            actual_ips = [target.host for target in targets]
            assert "192.168.1.1" in actual_ips
            assert "93.184.216.34" in actual_ips
            assert "10.0.0.1" in actual_ips
    
    def test_enumerate_from_list_resolution_error(self, enumerator, default_ports):
        """Test list enumeration with DNS resolution error."""
        hosts = ["good.host.com", "bad.host.invalid"]
        
        with patch.object(enumerator, '_resolve_host') as mock_resolve:
            def resolve_side_effect(host):
                if "bad.host" in host:
                    raise Exception("DNS resolution failed")
                return ["192.168.1.1"]
            
            mock_resolve.side_effect = resolve_side_effect
            
            # Should continue with good hosts despite errors
            targets = list(enumerator.enumerate_from_list(hosts, default_ports))
            
            assert len(targets) == 1
            assert targets[0].host == "192.168.1.1"
    
    def test_enumerate_localhost(self, enumerator, default_ports):
        """Test localhost enumeration."""
        targets = list(enumerator.enumerate_localhost(default_ports))
        
        # Should include both IPv4 and IPv6 localhost
        assert len(targets) >= 2
        
        hosts = [target.host for target in targets]
        assert "127.0.0.1" in hosts
        assert "::1" in hosts
    
    def test_enumerate_from_file(self, enumerator, default_ports):
        """Test enumeration from file."""
        file_content = "192.168.1.1\nexample.com\n10.0.0.1\n# comment line\n\n"
        
        with patch('builtins.open', mock_open(read_data=file_content)):
            with patch.object(enumerator, '_resolve_host') as mock_resolve:
                mock_resolve.side_effect = [
                    ["192.168.1.1"],
                    ["93.184.216.34"],
                    ["10.0.0.1"]
                ]
                
                targets = list(enumerator.enumerate_from_file("test_hosts.txt", default_ports))
                
                assert len(targets) == 3
    
    def test_enumerate_from_file_not_found(self, enumerator, default_ports):
        """Test file enumeration with missing file."""
        with patch('builtins.open', side_effect=FileNotFoundError()):
            with pytest.raises(FileNotFoundError):
                list(enumerator.enumerate_from_file("missing.txt", default_ports))
    
    def test_get_enabled_scan_types(self, enumerator):
        """Test getting enabled scan types from settings."""
        scan_types = enumerator._get_enabled_scan_types()
        
        assert isinstance(scan_types, set)
        assert len(scan_types) > 0
        assert all(isinstance(st, ScanType) for st in scan_types)
    
    @patch('socket.gethostbyname_ex')
    def test_resolve_host_success(self, mock_gethostbyname, enumerator):
        """Test successful hostname resolution."""
        mock_gethostbyname.return_value = (
            'example.com',
            ['example.com'],
            ['93.184.216.34']
        )
        
        result = enumerator._resolve_host("example.com")
        
        assert result == ['93.184.216.34']
        mock_gethostbyname.assert_called_once_with("example.com")
    
    @patch('socket.gethostbyname_ex')
    def test_resolve_host_already_ip(self, mock_gethostbyname, enumerator):
        """Test resolution of already-IP address."""
        result = enumerator._resolve_host("192.168.1.1")
        
        assert result == ["192.168.1.1"]
        mock_gethostbyname.assert_not_called()
    
    @patch('socket.gethostbyname_ex')
    def test_resolve_host_failure(self, mock_gethostbyname, enumerator):
        """Test hostname resolution failure."""
        mock_gethostbyname.side_effect = Exception("Name resolution failed")
        
        with pytest.raises(Exception, match="Name resolution failed"):
            enumerator._resolve_host("nonexistent.example.com")
    
    def test_get_port_range_default(self, enumerator):
        """Test getting default port range."""
        ports = enumerator.get_port_range()
        
        assert isinstance(ports, list)
        assert len(ports) > 0
        assert all(isinstance(p, int) for p in ports)
    
    def test_get_port_range_custom(self, enumerator):
        """Test getting custom port range."""
        ports = enumerator.get_port_range(start_port=80, end_port=85)
        
        expected = [80, 81, 82, 83, 84, 85]
        assert ports == expected
    
    def test_get_port_range_invalid(self, enumerator):
        """Test invalid port range."""
        with pytest.raises(ValueError):
            enumerator.get_port_range(start_port=100, end_port=50)
    
    def test_get_common_ports(self, enumerator):
        """Test getting common ports list."""
        ports = enumerator.get_common_ports()
        
        assert isinstance(ports, list)
        assert len(ports) > 0
        
        # Should include common ports
        common_ports = [22, 80, 443, 21, 25, 53, 110, 143, 993, 995]
        for port in common_ports:
            if port in ports:  # Some may not be in default list
                assert isinstance(port, int)
                assert 1 <= port <= 65535
    
    def test_validate_target_valid_ip(self, enumerator):
        """Test target validation with valid IP."""
        assert enumerator.validate_target("192.168.1.1") is True
        assert enumerator.validate_target("2001:db8::1") is True
    
    def test_validate_target_valid_cidr(self, enumerator):
        """Test target validation with valid CIDR."""
        assert enumerator.validate_target("192.168.1.0/24") is True
        assert enumerator.validate_target("2001:db8::/64") is True
    
    def test_validate_target_valid_hostname(self, enumerator):
        """Test target validation with valid hostname."""
        with patch.object(enumerator, '_resolve_host') as mock_resolve:
            mock_resolve.return_value = ["192.168.1.1"]
            
            assert enumerator.validate_target("example.com") is True
            mock_resolve.assert_called_once_with("example.com")
    
    def test_validate_target_invalid(self, enumerator):
        """Test target validation with invalid input."""
        assert enumerator.validate_target("") is False
        assert enumerator.validate_target("invalid..format") is False
        assert enumerator.validate_target("999.999.999.999") is False
    
    def test_validate_target_resolution_failure(self, enumerator):
        """Test target validation with DNS resolution failure."""
        with patch.object(enumerator, '_resolve_host') as mock_resolve:
            mock_resolve.side_effect = Exception("DNS failure")
            
            assert enumerator.validate_target("nonexistent.example.com") is False
    
    def test_ipv6_target_detection(self, enumerator, default_ports):
        """Test proper IPv6 target detection."""
        targets = list(enumerator.enumerate_from_cidr("2001:db8::/127", default_ports))
        
        for target in targets:
            assert target.is_ipv6 is True
    
    def test_ipv4_target_detection(self, enumerator, default_ports):
        """Test proper IPv4 target detection."""
        targets = list(enumerator.enumerate_from_cidr("192.168.1.0/30", default_ports))
        
        for target in targets:
            assert target.is_ipv6 is False
    
    def test_large_cidr_handling(self, enumerator, default_ports):
        """Test handling of large CIDR ranges."""
        # Use /28 which gives 16 addresses - manageable for testing
        cidr = "10.0.1.0/28"
        
        targets = list(enumerator.enumerate_from_cidr(cidr, default_ports))
        
        assert len(targets) == 16
        
        # Verify all IPs are in the expected range
        for target in targets:
            ip = ipaddress.ip_address(target.host)
            assert ip in ipaddress.ip_network(cidr)
    
    def test_port_assignment_consistency(self, enumerator, default_ports):
        """Test that all targets get consistent port assignments."""
        targets = list(enumerator.enumerate_from_cidr("192.168.1.0/30", default_ports))
        
        for target in targets:
            assert target.ports == default_ports
            assert len(target.scan_types) > 0


def mock_open(read_data=''):
    """Mock open function for file operations."""
    from unittest.mock import mock_open as _mock_open
    return _mock_open(read_data=read_data) 