"""
Target enumeration for network scanning operations.

This module provides functionality to enumerate scan targets from various
input formats including CIDR ranges, IP ranges, and individual hosts.
"""

import ipaddress
import socket
from typing import Iterator, List, Set, Union
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address, AddressValueError

from .base import ScanTarget, ScanType
from ..config.settings import get_settings
from ..utils.logging import get_logger


class TargetEnumerator:
    """Enumerates scan targets from various input formats."""
    
    def __init__(self, settings=None):
        """Initialize target enumerator."""
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
    
    def enumerate_from_cidr(self, cidr: str, ports: List[int] = None) -> Iterator[ScanTarget]:
        """
        Enumerate targets from CIDR notation.
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            ports: List of ports to scan (uses default if None)
            
        Yields:
            ScanTarget: Individual scan targets
        """
        if ports is None:
            ports = self.settings.scan.default_ports
        
        try:
            # Parse CIDR network
            network = ipaddress.ip_network(cidr, strict=False)
            self.logger.info(f"Enumerating targets from CIDR: {cidr} ({network.num_addresses} addresses)")
            
            # Determine scan types based on settings
            scan_types = self._get_enabled_scan_types()
            
            # Enumerate all hosts in the network
            for ip in network.hosts():
                yield ScanTarget(
                    host=str(ip),
                    ports=ports.copy(),
                    scan_types=scan_types
                )
            
            # Also include network and broadcast addresses for completeness
            if network.num_addresses > 2:  # Skip for /31 and /32 networks
                yield ScanTarget(
                    host=str(network.network_address),
                    ports=ports.copy(),
                    scan_types=scan_types
                )
                yield ScanTarget(
                    host=str(network.broadcast_address),
                    ports=ports.copy(),
                    scan_types=scan_types
                )
                
        except ValueError as e:
            self.logger.error(f"Invalid CIDR notation '{cidr}': {e}")
            raise ValueError(f"Invalid CIDR notation: {cidr}")
    
    def enumerate_from_range(self, start_ip: str, end_ip: str, ports: List[int] = None) -> Iterator[ScanTarget]:
        """
        Enumerate targets from IP address range.
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
            ports: List of ports to scan (uses default if None)
            
        Yields:
            ScanTarget: Individual scan targets
        """
        if ports is None:
            ports = self.settings.scan.default_ports
        
        try:
            start_addr = ipaddress.ip_address(start_ip)
            end_addr = ipaddress.ip_address(end_ip)
            
            # Ensure both addresses are the same type (IPv4 or IPv6)
            if type(start_addr) != type(end_addr):
                raise ValueError("Start and end IP addresses must be the same type (IPv4 or IPv6)")
            
            if start_addr > end_addr:
                raise ValueError("Start IP address must be less than or equal to end IP address")
            
            self.logger.info(f"Enumerating targets from range: {start_ip} to {end_ip}")
            
            scan_types = self._get_enabled_scan_types()
            
            # Enumerate IP addresses in range
            current = start_addr
            while current <= end_addr:
                yield ScanTarget(
                    host=str(current),
                    ports=ports.copy(),
                    scan_types=scan_types
                )
                current += 1
                
        except ValueError as e:
            self.logger.error(f"Invalid IP range '{start_ip}' to '{end_ip}': {e}")
            raise ValueError(f"Invalid IP range: {start_ip} to {end_ip}")
    
    def enumerate_from_list(self, hosts: List[str], ports: List[int] = None) -> Iterator[ScanTarget]:
        """
        Enumerate targets from a list of hosts.
        
        Args:
            hosts: List of hostnames or IP addresses
            ports: List of ports to scan (uses default if None)
            
        Yields:
            ScanTarget: Individual scan targets
        """
        if ports is None:
            ports = self.settings.scan.default_ports
        
        scan_types = self._get_enabled_scan_types()
        
        for host in hosts:
            try:
                # Validate and resolve if necessary
                resolved_ips = self._resolve_host(host)
                
                for ip in resolved_ips:
                    yield ScanTarget(
                        host=ip,
                        ports=ports.copy(),
                        scan_types=scan_types
                    )
                    
            except Exception as e:
                self.logger.error(f"Failed to process host '{host}': {e}")
                continue
    
    def enumerate_localhost(self, ports: List[int] = None) -> Iterator[ScanTarget]:
        """
        Enumerate localhost targets.
        
        Args:
            ports: List of ports to scan (uses default if None)
            
        Yields:
            ScanTarget: Localhost scan targets
        """
        if ports is None:
            ports = self.settings.scan.default_ports
        
        scan_types = self._get_enabled_scan_types()
        
        # IPv4 localhost
        yield ScanTarget(
            host="127.0.0.1",
            ports=ports.copy(),
            scan_types=scan_types
        )
        
        # IPv6 localhost if enabled
        if self.settings.scan.enable_ipv6:
            yield ScanTarget(
                host="::1",
                ports=ports.copy(),
                scan_types=scan_types
            )
    
    def enumerate_from_file(self, filename: str, ports: List[int] = None) -> Iterator[ScanTarget]:
        """
        Enumerate targets from a file.
        
        The file should contain one host per line. Supports:
        - IP addresses
        - Hostnames
        - CIDR notation
        - IP ranges (start-end format)
        
        Args:
            filename: Path to the file containing targets
            ports: List of ports to scan (uses default if None)
            
        Yields:
            ScanTarget: Individual scan targets
        """
        try:
            with open(filename, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Determine the format and enumerate accordingly
                        if '/' in line:
                            # CIDR notation
                            yield from self.enumerate_from_cidr(line, ports)
                        elif '-' in line and not line.replace('.', '').replace(':', '').replace('-', '').isdigit():
                            # IP range format (e.g., 192.168.1.1-192.168.1.10)
                            start_ip, end_ip = line.split('-', 1)
                            yield from self.enumerate_from_range(start_ip.strip(), end_ip.strip(), ports)
                        else:
                            # Single host
                            yield from self.enumerate_from_list([line], ports)
                            
                    except Exception as e:
                        self.logger.error(f"Error processing line {line_num} in {filename}: {e}")
                        continue
                        
        except FileNotFoundError:
            self.logger.error(f"Target file not found: {filename}")
            raise FileNotFoundError(f"Target file not found: {filename}")
        except Exception as e:
            self.logger.error(f"Error reading target file {filename}: {e}")
            raise
    
    def _get_enabled_scan_types(self) -> Set[ScanType]:
        """Get enabled scan types based on settings."""
        scan_types = set()
        
        if self.settings.scan.enable_tcp_scan:
            scan_types.add(ScanType.TCP_CONNECT)
        
        if self.settings.scan.enable_udp_scan:
            scan_types.add(ScanType.UDP)
        
        # Default to TCP if nothing is enabled
        if not scan_types:
            scan_types.add(ScanType.TCP_CONNECT)
        
        return scan_types
    
    def _resolve_host(self, host: str) -> List[str]:
        """
        Resolve a hostname to IP addresses.
        
        Args:
            host: Hostname or IP address
            
        Returns:
            List[str]: List of resolved IP addresses
        """
        try:
            # Check if it's already an IP address
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        
        # Resolve hostname
        try:
            addr_info = socket.getaddrinfo(
                host, None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM
            )
            
            # Extract unique IP addresses
            ips = list(set(info[4][0] for info in addr_info))
            
            # Filter by IPv6 setting
            if not self.settings.scan.enable_ipv6:
                ips = [ip for ip in ips if ':' not in ip]
            
            self.logger.debug(f"Resolved {host} to {ips}")
            return ips
            
        except socket.gaierror as e:
            self.logger.error(f"Failed to resolve hostname {host}: {e}")
            raise ValueError(f"Cannot resolve hostname: {host}")
    
    def get_port_range(self, start_port: int = None, end_port: int = None) -> List[int]:
        """
        Get a range of ports to scan.
        
        Args:
            start_port: Starting port (uses setting default if None)
            end_port: Ending port (uses setting default if None)
            
        Returns:
            List[int]: List of port numbers
        """
        if start_port is None:
            start_port = self.settings.scan.port_range_start
        if end_port is None:
            end_port = self.settings.scan.port_range_end
        
        if start_port > end_port:
            raise ValueError("Start port must be less than or equal to end port")
        
        if start_port < 1 or end_port > 65535:
            raise ValueError("Port numbers must be between 1 and 65535")
        
        return list(range(start_port, end_port + 1))
    
    def get_common_ports(self) -> List[int]:
        """
        Get list of commonly scanned ports.
        
        Returns:
            List[int]: List of common port numbers
        """
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000, 9001, 9002,
            # MCP common ports
            3000, 8000, 8080, 9000
        ]
        
        # Add configured default ports
        common_ports.extend(self.settings.scan.default_ports)
        
        # Remove duplicates and sort
        return sorted(list(set(common_ports)))
    
    def validate_target(self, target: str) -> bool:
        """
        Validate if a target string is valid.
        
        Args:
            target: Target string to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            if '/' in target:
                # CIDR notation
                ipaddress.ip_network(target, strict=False)
                return True
            elif '-' in target:
                # IP range
                start_ip, end_ip = target.split('-', 1)
                ipaddress.ip_address(start_ip.strip())
                ipaddress.ip_address(end_ip.strip())
                return True
            else:
                # Single host - try to resolve
                self._resolve_host(target)
                return True
                
        except Exception:
            return False 