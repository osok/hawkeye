"""
NPX package detection for MCP servers.

This module implements detection of MCP servers that are running through
NPX (Node Package eXecute) packages, which is a common deployment method
for MCP servers.
"""

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from .base import (
    MCPDetector, DetectionResult, DetectionMethod, MCPServerInfo,
    MCPServerType, TransportType, ProcessInfo, ConfigFileInfo,
    MCPDetectionError
)
from ..utils.logging import get_logger


class NPXDetector(MCPDetector):
    """Detector for MCP servers running through NPX packages."""
    
    def __init__(self, settings=None):
        super().__init__(settings)
        self.logger = get_logger(__name__)
        
        # Common NPX MCP package patterns
        self.mcp_package_patterns = [
            r'@modelcontextprotocol/.*',
            r'mcp-server-.*',
            r'.*-mcp-server',
            r'mcp-.*',
            r'.*-mcp',
        ]
        
        # Known MCP NPX packages
        self.known_mcp_packages = {
            '@modelcontextprotocol/server-filesystem',
            '@modelcontextprotocol/server-git',
            '@modelcontextprotocol/server-github',
            '@modelcontextprotocol/server-postgres',
            '@modelcontextprotocol/server-sqlite',
            '@modelcontextprotocol/server-brave-search',
            '@modelcontextprotocol/server-memory',
            'mcp-server-anthropic',
            'mcp-server-openai',
            'mcp-server-claude',
        }
        
        # NPX command patterns that indicate MCP usage
        self.npx_mcp_patterns = [
            r'npx\s+@modelcontextprotocol/',
            r'npx\s+mcp-server-',
            r'npx\s+.*-mcp-server',
            r'npx\s+.*mcp.*',
        ]
    
    def get_detection_method(self) -> DetectionMethod:
        """Return the detection method identifier."""
        return DetectionMethod.NPX_PACKAGE_DETECTION
    
    def detect(self, target_host: str, **kwargs) -> DetectionResult:
        """
        Detect MCP servers running through NPX packages.
        
        Args:
            target_host: Target host to scan
            **kwargs: Additional detection parameters
                - check_global: Check globally installed NPX packages
                - check_local: Check local node_modules
                - check_processes: Check running NPX processes
        
        Returns:
            DetectionResult with NPX package detection results
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting NPX package detection for {target_host}")
            
            # Detection options
            check_global = kwargs.get('check_global', True)
            check_local = kwargs.get('check_local', True)
            check_processes = kwargs.get('check_processes', True)
            
            # Collect all detection results
            detection_data = {
                'global_packages': [],
                'local_packages': [],
                'running_processes': [],
                'package_configs': [],
            }
            
            mcp_servers = []
            
            # Check globally installed NPX packages
            if check_global:
                global_packages = self._detect_global_npx_packages()
                detection_data['global_packages'] = global_packages
                mcp_servers.extend(self._analyze_npx_packages(global_packages, 'global'))
            
            # Check local node_modules for MCP packages
            if check_local:
                local_packages = self._detect_local_mcp_packages()
                detection_data['local_packages'] = local_packages
                mcp_servers.extend(self._analyze_npx_packages(local_packages, 'local'))
            
            # Check running NPX processes
            if check_processes:
                running_processes = self._detect_running_npx_processes()
                detection_data['running_processes'] = running_processes
                mcp_servers.extend(self._analyze_running_processes(running_processes))
            
            # Determine the best MCP server candidate
            best_server = self._select_best_mcp_server(mcp_servers)
            
            scan_duration = time.time() - start_time
            
            if best_server:
                self.logger.info(f"NPX MCP server detected: {best_server.server_type.value}")
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    mcp_server=best_server,
                    confidence=self._calculate_confidence(best_server, detection_data),
                    raw_data=detection_data,
                    scan_duration=scan_duration
                )
            else:
                self.logger.debug(f"No NPX MCP servers detected for {target_host}")
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=False,
                    confidence=0.0,
                    raw_data=detection_data,
                    scan_duration=scan_duration
                )
        
        except Exception as e:
            self.logger.error(f"NPX detection failed for {target_host}: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=str(e),
                scan_duration=time.time() - start_time
            )
    
    def _detect_global_npx_packages(self) -> List[Dict[str, Any]]:
        """Detect globally installed NPX packages that might be MCP servers."""
        packages = []
        
        try:
            # Get list of globally installed packages
            result = subprocess.run(
                ['npm', 'list', '-g', '--depth=0', '--json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                npm_data = json.loads(result.stdout)
                dependencies = npm_data.get('dependencies', {})
                
                for package_name, package_info in dependencies.items():
                    if self._is_mcp_package(package_name):
                        packages.append({
                            'name': package_name,
                            'version': package_info.get('version'),
                            'location': 'global',
                            'path': package_info.get('path'),
                            'confidence': self._get_package_confidence(package_name)
                        })
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.warning(f"Failed to detect global NPX packages: {e}")
        
        return packages
    
    def _detect_local_mcp_packages(self) -> List[Dict[str, Any]]:
        """Detect local node_modules packages that might be MCP servers."""
        packages = []
        
        # Search for package.json files in common locations
        search_paths = [
            Path.cwd(),
            Path.home(),
            Path('/opt'),
            Path('/usr/local'),
            Path('/var/www'),
        ]
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            
            try:
                # Find package.json files
                for package_json in search_path.rglob('package.json'):
                    if 'node_modules' in str(package_json):
                        continue  # Skip node_modules subdirectories
                    
                    try:
                        with open(package_json, 'r') as f:
                            package_data = json.load(f)
                        
                        # Check dependencies for MCP packages
                        all_deps = {}
                        all_deps.update(package_data.get('dependencies', {}))
                        all_deps.update(package_data.get('devDependencies', {}))
                        all_deps.update(package_data.get('peerDependencies', {}))
                        
                        for dep_name, dep_version in all_deps.items():
                            if self._is_mcp_package(dep_name):
                                packages.append({
                                    'name': dep_name,
                                    'version': dep_version,
                                    'location': 'local',
                                    'path': str(package_json.parent),
                                    'package_json': str(package_json),
                                    'confidence': self._get_package_confidence(dep_name)
                                })
                    
                    except (json.JSONDecodeError, IOError) as e:
                        self.logger.debug(f"Failed to read {package_json}: {e}")
            
            except PermissionError:
                self.logger.debug(f"Permission denied accessing {search_path}")
        
        return packages
    
    def _detect_running_npx_processes(self) -> List[Dict[str, Any]]:
        """Detect currently running NPX processes that might be MCP servers."""
        processes = []
        
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd', 'create_time']):
                try:
                    proc_info = proc.info
                    cmdline = proc_info.get('cmdline', [])
                    
                    if not cmdline:
                        continue
                    
                    cmdline_str = ' '.join(cmdline)
                    
                    # Check if this is an NPX process with MCP indicators
                    if self._is_npx_mcp_process(cmdline_str):
                        processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': cmdline,
                            'cwd': proc_info.get('cwd'),
                            'create_time': proc_info.get('create_time'),
                            'package_name': self._extract_package_name(cmdline_str),
                            'confidence': self._get_process_confidence(cmdline_str)
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except ImportError:
            self.logger.warning("psutil not available, cannot detect running NPX processes")
        
        return processes
    
    def _is_mcp_package(self, package_name: str) -> bool:
        """Check if a package name indicates an MCP server."""
        # Check known MCP packages
        if package_name in self.known_mcp_packages:
            return True
        
        # Check against patterns
        for pattern in self.mcp_package_patterns:
            if re.match(pattern, package_name, re.IGNORECASE):
                return True
        
        return False
    
    def _is_npx_mcp_process(self, cmdline: str) -> bool:
        """Check if a command line indicates an NPX MCP process."""
        for pattern in self.npx_mcp_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True
        return False
    
    def _extract_package_name(self, cmdline: str) -> Optional[str]:
        """Extract package name from NPX command line."""
        # Look for npx package-name pattern
        match = re.search(r'npx\s+([^\s]+)', cmdline, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    def _get_package_confidence(self, package_name: str) -> float:
        """Calculate confidence score for a package being an MCP server."""
        if package_name in self.known_mcp_packages:
            return 0.95
        
        # Check pattern matches
        for pattern in self.mcp_package_patterns:
            if re.match(pattern, package_name, re.IGNORECASE):
                if '@modelcontextprotocol' in package_name:
                    return 0.9
                elif 'mcp-server' in package_name:
                    return 0.8
                elif 'mcp' in package_name:
                    return 0.6
        
        return 0.3
    
    def _get_process_confidence(self, cmdline: str) -> float:
        """Calculate confidence score for a process being an MCP server."""
        confidence = 0.0
        
        if '@modelcontextprotocol' in cmdline.lower():
            confidence += 0.4
        if 'mcp-server' in cmdline.lower():
            confidence += 0.3
        if 'mcp' in cmdline.lower():
            confidence += 0.2
        if '--stdio' in cmdline or '--http' in cmdline or '--websocket' in cmdline:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _analyze_npx_packages(self, packages: List[Dict[str, Any]], location: str) -> List[MCPServerInfo]:
        """Analyze detected NPX packages and create MCP server info."""
        servers = []
        
        for package in packages:
            try:
                # Create basic server info
                server = MCPServerInfo(
                    host="localhost",  # NPX packages typically run locally
                    server_type=MCPServerType.NPX_PACKAGE,
                    transport_type=self._infer_transport_type(package),
                    version=package.get('version'),
                )
                
                # Add package-specific configuration
                if package.get('package_json'):
                    config_info = self._analyze_package_config(package['package_json'])
                    if config_info:
                        server.config_info = config_info
                
                servers.append(server)
            
            except Exception as e:
                self.logger.warning(f"Failed to analyze package {package.get('name')}: {e}")
        
        return servers
    
    def _analyze_running_processes(self, processes: List[Dict[str, Any]]) -> List[MCPServerInfo]:
        """Analyze running NPX processes and create MCP server info."""
        servers = []
        
        for process in processes:
            try:
                # Create process info
                process_info = ProcessInfo(
                    pid=process['pid'],
                    name=process['name'],
                    cmdline=process['cmdline'],
                    cwd=process.get('cwd'),
                    create_time=process.get('create_time')
                )
                
                # Create server info
                server = MCPServerInfo(
                    host="localhost",
                    server_type=MCPServerType.NPX_PACKAGE,
                    process_info=process_info,
                    transport_type=self._infer_transport_from_cmdline(process['cmdline']),
                )
                
                # Try to extract port from command line
                port = self._extract_port_from_cmdline(process['cmdline'])
                if port:
                    server.port = port
                
                servers.append(server)
            
            except Exception as e:
                self.logger.warning(f"Failed to analyze process {process.get('pid')}: {e}")
        
        return servers
    
    def _analyze_package_config(self, package_json_path: str) -> Optional[ConfigFileInfo]:
        """Analyze package.json for MCP configuration."""
        try:
            with open(package_json_path, 'r') as f:
                config_data = json.load(f)
            
            # Extract dependencies
            dependencies = []
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                dependencies.extend(config_data.get(dep_type, {}).keys())
            
            # Extract scripts
            scripts = config_data.get('scripts', {})
            
            return ConfigFileInfo(
                path=Path(package_json_path),
                file_type='package.json',
                content=config_data,
                dependencies=dependencies,
                scripts=scripts
            )
        
        except Exception as e:
            self.logger.debug(f"Failed to analyze package config {package_json_path}: {e}")
            return None
    
    def _infer_transport_type(self, package: Dict[str, Any]) -> TransportType:
        """Infer transport type from package information."""
        package_name = package.get('name', '').lower()
        
        if 'websocket' in package_name or 'ws' in package_name:
            return TransportType.WEBSOCKET
        elif 'http' in package_name or 'web' in package_name:
            return TransportType.HTTP
        else:
            return TransportType.STDIO  # Default for NPX packages
    
    def _infer_transport_from_cmdline(self, cmdline: List[str]) -> TransportType:
        """Infer transport type from command line arguments."""
        cmdline_str = ' '.join(cmdline).lower()
        
        if '--websocket' in cmdline_str or '--ws' in cmdline_str:
            return TransportType.WEBSOCKET
        elif '--http' in cmdline_str:
            return TransportType.HTTP
        elif '--stdio' in cmdline_str:
            return TransportType.STDIO
        elif '--port' in cmdline_str:
            return TransportType.HTTP  # Port usually indicates HTTP
        else:
            return TransportType.STDIO  # Default
    
    def _extract_port_from_cmdline(self, cmdline: List[str]) -> Optional[int]:
        """Extract port number from command line arguments."""
        cmdline_str = ' '.join(cmdline)
        
        # Look for --port argument
        port_match = re.search(r'--port[=\s]+(\d+)', cmdline_str)
        if port_match:
            return int(port_match.group(1))
        
        # Look for -p argument
        p_match = re.search(r'-p[=\s]+(\d+)', cmdline_str)
        if p_match:
            return int(p_match.group(1))
        
        return None
    
    def _select_best_mcp_server(self, servers: List[MCPServerInfo]) -> Optional[MCPServerInfo]:
        """Select the best MCP server from detected candidates."""
        if not servers:
            return None
        
        # Prefer running processes over installed packages
        running_servers = [s for s in servers if s.process_info is not None]
        if running_servers:
            return running_servers[0]
        
        # Otherwise return the first detected server
        return servers[0]
    
    def _calculate_confidence(self, server: MCPServerInfo, detection_data: Dict[str, Any]) -> float:
        """Calculate overall confidence score for the detection."""
        confidence = 0.0
        
        # Base confidence from having a server
        confidence += 0.3
        
        # Bonus for running process
        if server.process_info:
            confidence += 0.4
        
        # Bonus for configuration file
        if server.config_info:
            confidence += 0.2
        
        # Bonus for known transport type (STDIO is default, so it gets bonus)
        if server.transport_type != TransportType.UNKNOWN:
            confidence += 0.1
        
        return min(confidence, 1.0)


def create_npx_detector(settings=None) -> NPXDetector:
    """Factory function to create an NPX detector instance."""
    return NPXDetector(settings)