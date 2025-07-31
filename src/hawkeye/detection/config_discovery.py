"""
Configuration File Discovery for MCP Detection.

This module provides functionality to discover and analyze configuration files
that may indicate the presence of MCP servers, including package.json files,
MCP-specific configuration files, and other relevant configuration sources.
"""

import json
import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
import re

from .base import (
    MCPDetector,
    DetectionResult,
    DetectionMethod,
    ConfigFileInfo,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ConfigDetectionError,
)


class ConfigFileDiscovery(MCPDetector):
    """Detector for identifying MCP servers through configuration file analysis."""
    
    def __init__(self, settings=None):
        """Initialize the config file discovery detector."""
        super().__init__(settings)
        
        # Configuration file patterns to search for
        self.config_patterns = [
            'package.json',
            'mcp.config.js',
            'mcp.config.json',
            'mcp-server.json',
            '.mcprc',
            '.mcprc.json',
            'mcp.yaml',
            'mcp.yml',
            'docker-compose.yml',
            'docker-compose.yaml',
            'Dockerfile',
        ]
        
        # MCP-related package names and patterns
        self.mcp_packages = [
            '@modelcontextprotocol/sdk',
            '@modelcontextprotocol/server',
            '@modelcontextprotocol/client',
            'mcp-server',
            'mcp-client',
            '@mcp/',  # Scoped packages
        ]
        
        # MCP-related script patterns
        self.mcp_script_patterns = [
            r'mcp[_-]?server',
            r'mcp[_-]?client',
            r'model[_-]?context[_-]?protocol',
            r'@modelcontextprotocol',
        ]
        
        # Common directories to search
        self.search_directories = [
            '.',
            './src',
            './lib',
            './server',
            './servers',
            './mcp',
            './config',
            './configs',
            '~/.config/mcp',
            '~/.mcp',
            '/etc/mcp',
            '/opt/mcp',
        ]
        
        # Maximum search depth
        self.max_depth = 3
        
        # Maximum files to analyze (performance limit)
        self.max_files = 1000
    
    def get_detection_method(self) -> DetectionMethod:
        """Get the detection method."""
        return DetectionMethod.CONFIG_FILE_DISCOVERY
    
    def detect(self, target_host: str = "localhost", **kwargs) -> DetectionResult:
        """
        Detect MCP servers through configuration file discovery.
        
        Args:
            target_host: Target host (only localhost supported for file discovery)
            **kwargs: Additional parameters (search_paths, max_depth, include_docker)
            
        Returns:
            DetectionResult: Result of the detection operation
        """
        start_time = time.time()
        
        # Config file discovery only works on localhost
        if target_host not in ['localhost', '127.0.0.1', '::1']:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="Config file discovery only supported on localhost",
                scan_duration=time.time() - start_time
            )
        
        try:
            # Get configuration options
            search_paths = kwargs.get('search_paths', self.search_directories)
            max_depth = kwargs.get('max_depth', self.max_depth)
            include_docker = kwargs.get('include_docker', True)
            
            # Discover configuration files
            config_files = self._discover_config_files(search_paths, max_depth)
            
            # Analyze configuration files for MCP indicators
            mcp_configs = self._analyze_config_files(config_files, include_docker)
            
            if mcp_configs:
                # Create MCP server info from the most promising config
                best_config = max(mcp_configs, key=lambda c: self._calculate_config_confidence(c))
                mcp_server = self._create_mcp_server_from_config(best_config, target_host)
                confidence = self._calculate_config_confidence(best_config)
                
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    mcp_server=mcp_server,
                    confidence=confidence,
                    raw_data={
                        'total_config_files': len(config_files),
                        'mcp_config_files': len(mcp_configs),
                        'all_mcp_configs': [self._config_to_dict(c) for c in mcp_configs]
                    },
                    scan_duration=time.time() - start_time
                )
            else:
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    confidence=0.0,
                    raw_data={
                        'total_config_files': len(config_files),
                        'mcp_config_files': 0,
                    },
                    scan_duration=time.time() - start_time
                )
                
        except Exception as e:
            self.logger.error(f"Config file discovery failed: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=str(e),
                scan_duration=time.time() - start_time
            )
    
    def _discover_config_files(self, search_paths: List[str], max_depth: int) -> List[Path]:
        """
        Discover configuration files in the specified paths.
        
        Args:
            search_paths: List of paths to search
            max_depth: Maximum directory depth to search
            
        Returns:
            List[Path]: List of discovered configuration files
        """
        config_files = []
        files_processed = 0
        
        for search_path in search_paths:
            try:
                # Expand user home directory
                expanded_path = Path(search_path).expanduser()
                
                if not expanded_path.exists():
                    continue
                
                # Search for config files
                for pattern in self.config_patterns:
                    try:
                        if expanded_path.is_file() and expanded_path.name == pattern:
                            config_files.append(expanded_path)
                            files_processed += 1
                        elif expanded_path.is_dir():
                            # Use glob to find files matching pattern
                            found_files = list(expanded_path.rglob(pattern))
                            
                            # Filter by depth
                            for file_path in found_files:
                                if files_processed >= self.max_files:
                                    break
                                
                                # Calculate depth relative to search path
                                try:
                                    relative_path = file_path.relative_to(expanded_path)
                                    depth = len(relative_path.parts) - 1
                                    
                                    if depth <= max_depth:
                                        config_files.append(file_path)
                                        files_processed += 1
                                except ValueError:
                                    # File is not relative to search path
                                    continue
                        
                        if files_processed >= self.max_files:
                            break
                            
                    except (PermissionError, OSError) as e:
                        self.logger.debug(f"Cannot access {expanded_path}/{pattern}: {e}")
                        continue
                
                if files_processed >= self.max_files:
                    break
                    
            except Exception as e:
                self.logger.debug(f"Error searching path {search_path}: {e}")
                continue
        
        # Remove duplicates and sort
        unique_files = list(set(config_files))
        unique_files.sort()
        
        self.logger.info(f"Discovered {len(unique_files)} configuration files")
        return unique_files
    
    def _analyze_config_files(self, config_files: List[Path], include_docker: bool = True) -> List[ConfigFileInfo]:
        """
        Analyze configuration files for MCP indicators.
        
        Args:
            config_files: List of configuration files to analyze
            include_docker: Whether to include Docker configuration analysis
            
        Returns:
            List[ConfigFileInfo]: List of configuration files with MCP indicators
        """
        mcp_configs = []
        
        for config_file in config_files:
            try:
                config_info = self._analyze_single_config_file(config_file, include_docker)
                if config_info and self._has_mcp_indicators(config_info):
                    mcp_configs.append(config_info)
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing config file {config_file}: {e}")
                continue
        
        self.logger.info(f"Found {len(mcp_configs)} configuration files with MCP indicators")
        return mcp_configs
    
    def _analyze_single_config_file(self, config_file: Path, include_docker: bool) -> Optional[ConfigFileInfo]:
        """
        Analyze a single configuration file.
        
        Args:
            config_file: Path to the configuration file
            include_docker: Whether to include Docker configuration analysis
            
        Returns:
            Optional[ConfigFileInfo]: Configuration file information if valid
        """
        try:
            file_type = config_file.name.lower()
            content = {}
            mcp_config = {}
            dependencies = []
            scripts = {}
            
            # Read and parse file based on type
            if file_type == 'package.json':
                content = self._parse_package_json(config_file)
                dependencies = self._extract_dependencies(content)
                scripts = content.get('scripts', {})
                mcp_config = content.get('mcp', {})
                
            elif file_type.endswith(('.json', '.mcprc')):
                content = self._parse_json_file(config_file)
                mcp_config = content
                
            elif file_type.endswith(('.yml', '.yaml')):
                content = self._parse_yaml_file(config_file)
                mcp_config = content.get('mcp', content)
                
            elif file_type.startswith('dockerfile') and include_docker:
                content = self._parse_dockerfile(config_file)
                
            elif file_type.startswith('docker-compose') and include_docker:
                content = self._parse_docker_compose(config_file)
                
            else:
                # Try to parse as text for other file types
                content = self._parse_text_file(config_file)
            
            return ConfigFileInfo(
                path=config_file,
                file_type=file_type,
                content=content,
                mcp_config=mcp_config,
                dependencies=dependencies,
                scripts=scripts,
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse config file {config_file}: {e}")
            return None
    
    def _parse_package_json(self, file_path: Path) -> Dict[str, Any]:
        """Parse a package.json file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _parse_json_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse a JSON configuration file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _parse_yaml_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse a YAML configuration file."""
        try:
            import yaml
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            self.logger.debug("PyYAML not available, skipping YAML file")
            return {}
    
    def _parse_dockerfile(self, file_path: Path) -> Dict[str, Any]:
        """Parse a Dockerfile for MCP-related content."""
        content = {'type': 'dockerfile', 'instructions': []}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    content['instructions'].append({
                        'line': line_num,
                        'instruction': line
                    })
        
        return content
    
    def _parse_docker_compose(self, file_path: Path) -> Dict[str, Any]:
        """Parse a docker-compose file."""
        return self._parse_yaml_file(file_path)
    
    def _parse_text_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse a text file for MCP-related content."""
        content = {'type': 'text', 'lines': []}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if any(keyword in line.lower() for keyword in ['mcp', 'model-context-protocol']):
                        content['lines'].append({
                            'line': line_num,
                            'content': line.strip()
                        })
        except UnicodeDecodeError:
            # Skip binary files
            return {}
        
        return content
    
    def _extract_dependencies(self, package_json: Dict[str, Any]) -> List[str]:
        """Extract all dependencies from package.json."""
        dependencies = []
        
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            deps = package_json.get(dep_type, {})
            dependencies.extend(deps.keys())
        
        return dependencies
    
    def _has_mcp_indicators(self, config_info: ConfigFileInfo) -> bool:
        """
        Check if configuration file has MCP-related indicators.
        
        Args:
            config_info: Configuration file information
            
        Returns:
            bool: True if MCP indicators are found
        """
        # Check dependencies
        if config_info.has_mcp_dependencies:
            return True
        
        # Check scripts
        if config_info.has_mcp_scripts:
            return True
        
        # Check MCP configuration section
        if config_info.mcp_config:
            return True
        
        # Check file content for MCP keywords
        content_str = json.dumps(config_info.content).lower()
        mcp_keywords = ['mcp', 'model-context-protocol', '@modelcontextprotocol']
        
        if any(keyword in content_str for keyword in mcp_keywords):
            return True
        
        # Check for MCP-related patterns in scripts
        for script in config_info.scripts.values():
            for pattern in self.mcp_script_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    return True
        
        return False
    
    def _calculate_config_confidence(self, config_info: ConfigFileInfo) -> float:
        """
        Calculate confidence score for MCP detection based on configuration.
        
        Args:
            config_info: Configuration file information
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        confidence = 0.0
        
        # Base confidence for having MCP indicators
        confidence += 0.3
        
        # Boost for MCP dependencies
        if config_info.has_mcp_dependencies:
            confidence += 0.4
            
            # Additional boost for official MCP packages
            official_packages = [pkg for pkg in config_info.dependencies 
                               if pkg.startswith('@modelcontextprotocol/')]
            confidence += min(len(official_packages) * 0.1, 0.2)
        
        # Boost for MCP scripts
        if config_info.has_mcp_scripts:
            confidence += 0.2
        
        # Boost for dedicated MCP configuration
        if config_info.mcp_config:
            confidence += 0.3
            
            # Additional boost for detailed MCP config
            if isinstance(config_info.mcp_config, dict) and len(config_info.mcp_config) > 1:
                confidence += 0.1
        
        # Boost for specific file types
        if config_info.file_type in ['mcp.config.js', 'mcp.config.json', 'mcp-server.json']:
            confidence += 0.4
        elif config_info.file_type == 'package.json':
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _create_mcp_server_from_config(self, config_info: ConfigFileInfo, host: str) -> MCPServerInfo:
        """
        Create MCP server information from configuration file.
        
        Args:
            config_info: Configuration file information
            host: Target host
            
        Returns:
            MCPServerInfo: MCP server information
        """
        # Extract server information from configuration
        port = self._extract_port_from_config(config_info)
        transport_type = self._determine_transport_type(config_info)
        server_type = self._determine_server_type(config_info)
        capabilities = self._extract_capabilities(config_info)
        tools = self._extract_tools(config_info)
        resources = self._extract_resources(config_info)
        version = self._extract_version(config_info)
        security_config = self._extract_security_config(config_info)
        
        return MCPServerInfo(
            host=host,
            port=port,
            transport_type=transport_type,
            server_type=server_type,
            config_info=config_info,
            capabilities=capabilities,
            tools=tools,
            resources=resources,
            version=version,
            security_config=security_config,
        )
    
    def _extract_port_from_config(self, config_info: ConfigFileInfo) -> Optional[int]:
        """Extract port number from configuration."""
        # Check MCP configuration
        if config_info.mcp_config:
            port = config_info.mcp_config.get('port')
            if port:
                return int(port)
        
        # Check scripts for port arguments
        for script in config_info.scripts.values():
            port_match = re.search(r'--port[=\s]+(\d+)', script)
            if port_match:
                return int(port_match.group(1))
            
            port_match = re.search(r'-p[=\s]+(\d+)', script)
            if port_match:
                return int(port_match.group(1))
        
        # Check general content
        content_str = json.dumps(config_info.content)
        port_match = re.search(r'"port":\s*(\d+)', content_str)
        if port_match:
            return int(port_match.group(1))
        
        return None
    
    def _determine_transport_type(self, config_info: ConfigFileInfo) -> TransportType:
        """Determine transport type from configuration."""
        content_str = json.dumps(config_info.content).lower()
        
        if 'websocket' in content_str or 'ws://' in content_str or 'wss://' in content_str:
            return TransportType.WEBSOCKET
        elif 'http' in content_str or self._extract_port_from_config(config_info):
            return TransportType.HTTP
        elif 'stdio' in content_str:
            return TransportType.STDIO
        
        return TransportType.UNKNOWN
    
    def _determine_server_type(self, config_info: ConfigFileInfo) -> MCPServerType:
        """Determine server type from configuration."""
        if config_info.file_type == 'package.json':
            # Check if it's an NPX package
            if any('npx' in script for script in config_info.scripts.values()):
                return MCPServerType.NPX_PACKAGE
            return MCPServerType.STANDALONE
        elif 'docker' in config_info.file_type:
            return MCPServerType.DOCKER_CONTAINER
        
        return MCPServerType.UNKNOWN
    
    def _extract_capabilities(self, config_info: ConfigFileInfo) -> List[str]:
        """Extract capabilities from configuration."""
        capabilities = []
        
        if config_info.mcp_config:
            caps = config_info.mcp_config.get('capabilities', [])
            if isinstance(caps, list):
                capabilities.extend(caps)
            elif isinstance(caps, dict):
                capabilities.extend(caps.keys())
        
        return capabilities
    
    def _extract_tools(self, config_info: ConfigFileInfo) -> List[str]:
        """Extract tools from configuration."""
        tools = []
        
        if config_info.mcp_config:
            tool_list = config_info.mcp_config.get('tools', [])
            if isinstance(tool_list, list):
                tools.extend(tool_list)
            elif isinstance(tool_list, dict):
                tools.extend(tool_list.keys())
        
        return tools
    
    def _extract_resources(self, config_info: ConfigFileInfo) -> List[str]:
        """Extract resources from configuration."""
        resources = []
        
        if config_info.mcp_config:
            resource_list = config_info.mcp_config.get('resources', [])
            if isinstance(resource_list, list):
                resources.extend(resource_list)
            elif isinstance(resource_list, dict):
                resources.extend(resource_list.keys())
        
        return resources
    
    def _extract_version(self, config_info: ConfigFileInfo) -> Optional[str]:
        """Extract version from configuration."""
        if config_info.file_type == 'package.json':
            return config_info.content.get('version')
        
        if config_info.mcp_config:
            return config_info.mcp_config.get('version')
        
        return None
    
    def _extract_security_config(self, config_info: ConfigFileInfo) -> Dict[str, Any]:
        """Extract security configuration."""
        security_config = {}
        
        if config_info.mcp_config:
            security = config_info.mcp_config.get('security', {})
            if isinstance(security, dict):
                security_config.update(security)
        
        # Check for TLS/SSL configuration
        content_str = json.dumps(config_info.content).lower()
        if 'tls' in content_str or 'ssl' in content_str or 'https' in content_str:
            security_config['tls'] = True
        
        return security_config
    
    def _config_to_dict(self, config_info: ConfigFileInfo) -> Dict[str, Any]:
        """Convert configuration info to dictionary."""
        return {
            'path': str(config_info.path),
            'file_type': config_info.file_type,
            'has_mcp_dependencies': config_info.has_mcp_dependencies,
            'has_mcp_scripts': config_info.has_mcp_scripts,
            'dependencies_count': len(config_info.dependencies),
            'scripts_count': len(config_info.scripts),
            'mcp_config_present': bool(config_info.mcp_config),
            'confidence': self._calculate_config_confidence(config_info),
        }
    
    def discover_config_files_in_path(self, search_path: str, max_depth: int = None) -> List[ConfigFileInfo]:
        """
        Discover and analyze configuration files in a specific path.
        
        Args:
            search_path: Path to search for configuration files
            max_depth: Maximum directory depth to search
            
        Returns:
            List[ConfigFileInfo]: List of discovered configuration files with MCP indicators
        """
        if max_depth is None:
            max_depth = self.max_depth
        
        config_files = self._discover_config_files([search_path], max_depth)
        return self._analyze_config_files(config_files)
    
    def analyze_specific_config_file(self, file_path: str) -> Optional[ConfigFileInfo]:
        """
        Analyze a specific configuration file.
        
        Args:
            file_path: Path to the configuration file
            
        Returns:
            Optional[ConfigFileInfo]: Configuration file information if it has MCP indicators
        """
        config_file = Path(file_path)
        if not config_file.exists():
            raise ConfigDetectionError(f"Configuration file not found: {file_path}")
        
        config_info = self._analyze_single_config_file(config_file, include_docker=True)
        
        if config_info and self._has_mcp_indicators(config_info):
            return config_info
        
        return None 