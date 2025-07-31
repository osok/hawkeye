"""
Environment variable analysis for MCP servers.

This module implements detection of MCP servers through analysis of
environment variables in running processes and system configuration,
which often contain MCP-related configuration and deployment information.
"""

import os
import re
import time
from typing import Dict, List, Optional, Any, Set, Tuple

from .base import (
    MCPDetector, DetectionResult, DetectionMethod, MCPServerInfo,
    MCPServerType, TransportType, ProcessInfo, ConfigFileInfo,
    MCPDetectionError
)
from ..utils.logging import get_logger


class EnvironmentAnalyzer(MCPDetector):
    """Detector for MCP servers through environment variable analysis."""
    
    def __init__(self, settings=None):
        super().__init__(settings)
        self.logger = get_logger(__name__)
        
        # Environment variable patterns that indicate MCP usage
        self.mcp_env_patterns = [
            # Direct MCP patterns
            r'MCP_.*',
            r'.*_MCP_.*',
            r'MODEL_CONTEXT_PROTOCOL_.*',
            r'.*MCP.*SERVER.*',
            r'.*MCP.*PORT.*',
            r'.*MCP.*HOST.*',
            r'.*MCP.*CONFIG.*',
            
            # Transport-specific patterns
            r'.*MCP.*HTTP.*',
            r'.*MCP.*WEBSOCKET.*',
            r'.*MCP.*WS.*',
            r'.*MCP.*STDIO.*',
            
            # Tool and capability patterns
            r'.*MCP.*TOOL.*',
            r'.*MCP.*CAPABILITY.*',
            r'.*MCP.*RESOURCE.*',
            r'.*MCP.*PROMPT.*',
            
            # Authentication patterns
            r'.*MCP.*AUTH.*',
            r'.*MCP.*TOKEN.*',
            r'.*MCP.*KEY.*',
            r'.*MCP.*SECRET.*',
        ]
        
        # Known MCP environment variable names
        self.known_mcp_env_vars = {
            'MCP_SERVER_PORT',
            'MCP_SERVER_HOST',
            'MCP_SERVER_CONFIG',
            'MCP_TRANSPORT_TYPE',
            'MCP_WEBSOCKET_PORT',
            'MCP_HTTP_PORT',
            'MCP_STDIO_MODE',
            'MCP_AUTH_TOKEN',
            'MCP_API_KEY',
            'MCP_SERVER_NAME',
            'MCP_CAPABILITIES',
            'MCP_TOOLS_CONFIG',
            'MCP_RESOURCES_PATH',
            'MCP_PROMPTS_PATH',
            'MCP_LOG_LEVEL',
            'MCP_DEBUG',
            'MODEL_CONTEXT_PROTOCOL_PORT',
            'MODEL_CONTEXT_PROTOCOL_HOST',
        }
        
        # Environment variables that might contain MCP-related values
        self.mcp_value_patterns = [
            r'.*@modelcontextprotocol.*',
            r'.*mcp-server.*',
            r'.*model-context-protocol.*',
            r'.*mcp\..*',
            r'.*://.*mcp.*',
            r'.*mcp://.*',
        ]
        
        # Port patterns in environment variables
        self.port_patterns = [
            r'PORT[=:](\d+)',
            r'.*_PORT[=:](\d+)',
            r'.*PORT.*[=:](\d+)',
            r'://[^:]+:(\d+)',  # URL format like http://host:port
            r':(\d+)/',  # Port in URL path
            r':(\d+)$',  # Port at end of string
            r'(\d+)',  # Fallback for numeric values
        ]
        
        # Common MCP server ports
        self.common_mcp_ports = [3000, 8000, 8080, 9000, 3001, 8001]
        
        # Transport type indicators in environment variables
        self.transport_indicators = {
            TransportType.HTTP: [
                'http', 'https', 'rest', 'api', 'web'
            ],
            TransportType.WEBSOCKET: [
                'websocket', 'ws', 'wss', 'socket'
            ],
            TransportType.STDIO: [
                'stdio', 'stdin', 'stdout', 'pipe', 'cli'
            ]
        }
    
    def get_detection_method(self) -> DetectionMethod:
        """Return the detection method identifier."""
        return DetectionMethod.ENVIRONMENT_ANALYSIS
    
    def detect(self, target_host: str, **kwargs) -> DetectionResult:
        """
        Detect MCP servers through environment variable analysis.
        
        Args:
            target_host: Target host to scan
            **kwargs: Additional detection parameters
                - analyze_system: Analyze system environment variables
                - analyze_processes: Analyze process environment variables
                - include_inherited: Include inherited environment variables
        
        Returns:
            DetectionResult with environment variable analysis results
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting environment variable analysis for {target_host}")
            
            # Detection options
            analyze_system = kwargs.get('analyze_system', True)
            analyze_processes = kwargs.get('analyze_processes', True)
            include_inherited = kwargs.get('include_inherited', False)
            
            # Collect all detection results
            detection_data = {
                'system_env_vars': {},
                'process_env_vars': [],
                'mcp_indicators': [],
                'transport_indicators': [],
                'port_indicators': [],
                'security_indicators': [],
            }
            
            mcp_servers = []
            
            # Analyze system environment variables
            if analyze_system:
                system_env = self._analyze_system_environment()
                detection_data['system_env_vars'] = system_env
                mcp_servers.extend(self._extract_servers_from_env(system_env, 'system'))
            
            # Analyze process environment variables
            if analyze_processes:
                process_envs = self._analyze_process_environments(include_inherited)
                detection_data['process_env_vars'] = process_envs
                for proc_env in process_envs:
                    mcp_servers.extend(self._extract_servers_from_env(
                        proc_env['env_vars'], 
                        f"process_{proc_env['pid']}"
                    ))
            
            # Extract MCP indicators
            detection_data['mcp_indicators'] = self._extract_mcp_indicators(detection_data)
            detection_data['transport_indicators'] = self._extract_transport_indicators(detection_data)
            detection_data['port_indicators'] = self._extract_port_indicators(detection_data)
            detection_data['security_indicators'] = self._extract_security_indicators(detection_data)
            
            # Determine the best MCP server candidate
            best_server = self._select_best_mcp_server(mcp_servers)
            
            scan_duration = time.time() - start_time
            
            if best_server:
                self.logger.info(f"Environment MCP server detected: {best_server.server_type.value}")
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
                self.logger.debug(f"No environment MCP servers detected for {target_host}")
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=False,
                    confidence=0.0,
                    raw_data=detection_data,
                    scan_duration=scan_duration
                )
        
        except Exception as e:
            self.logger.error(f"Environment analysis failed for {target_host}: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=str(e),
                scan_duration=time.time() - start_time
            )
    
    def _analyze_system_environment(self) -> Dict[str, str]:
        """Analyze system environment variables for MCP indicators."""
        try:
            env_vars = {}
            
            # Get all environment variables
            for key, value in os.environ.items():
                if self._is_mcp_related_env_var(key, value):
                    env_vars[key] = value
            
            self.logger.debug(f"Found {len(env_vars)} MCP-related system environment variables")
            return env_vars
        
        except Exception as e:
            self.logger.warning(f"Failed to analyze system environment: {e}")
            return {}
    
    def _analyze_process_environments(self, include_inherited: bool = False) -> List[Dict[str, Any]]:
        """Analyze process environment variables for MCP indicators."""
        process_envs = []
        
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info['name']
                    cmdline = proc_info['cmdline'] or []
                    
                    # Skip system processes
                    if pid < 100:
                        continue
                    
                    # Get process environment
                    try:
                        env_dict = proc.environ()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        continue
                    
                    # Filter for MCP-related environment variables
                    mcp_env_vars = {}
                    for key, value in env_dict.items():
                        if self._is_mcp_related_env_var(key, value):
                            mcp_env_vars[key] = value
                    
                    # Only include processes with MCP-related environment variables
                    if mcp_env_vars:
                        process_envs.append({
                            'pid': pid,
                            'name': name,
                            'cmdline': cmdline,
                            'env_vars': mcp_env_vars,
                            'confidence': self._calculate_process_env_confidence(mcp_env_vars, cmdline)
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except ImportError:
            self.logger.warning("psutil not available for process environment analysis")
        except Exception as e:
            self.logger.warning(f"Failed to analyze process environments: {e}")
        
        self.logger.debug(f"Found {len(process_envs)} processes with MCP-related environment variables")
        return process_envs
    
    def _is_mcp_related_env_var(self, key: str, value: str) -> bool:
        """Check if an environment variable is MCP-related."""
        # Check key patterns
        if key.upper() in self.known_mcp_env_vars:
            return True
        
        for pattern in self.mcp_env_patterns:
            if re.search(pattern, key, re.IGNORECASE):
                return True
        
        # Check value patterns
        for pattern in self.mcp_value_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_servers_from_env(self, env_vars: Dict[str, str], source: str) -> List[MCPServerInfo]:
        """Extract MCP server information from environment variables."""
        servers = []
        
        if not env_vars:
            return servers
        
        try:
            # Extract basic server information
            host = self._extract_host_from_env(env_vars)
            port = self._extract_port_from_env(env_vars)
            transport_type = self._extract_transport_from_env(env_vars)
            server_type = self._determine_server_type_from_env(env_vars, source)
            
            # Create server info
            server = MCPServerInfo(
                host=host or "localhost",
                port=port,
                server_type=server_type,
                transport_type=transport_type,
                environment_info={
                    'source': source,
                    'env_vars': env_vars,
                    'indicators': self._extract_env_indicators(env_vars)
                }
            )
            
            servers.append(server)
        
        except Exception as e:
            self.logger.warning(f"Failed to extract server from environment {source}: {e}")
        
        return servers
    
    def _extract_host_from_env(self, env_vars: Dict[str, str]) -> Optional[str]:
        """Extract host information from environment variables."""
        # Check for explicit host variables
        host_vars = ['MCP_SERVER_HOST', 'MCP_HOST', 'HOST', 'SERVER_HOST']
        
        for var in host_vars:
            if var in env_vars:
                return env_vars[var]
        
        # Check for host in other variables
        for key, value in env_vars.items():
            if 'host' in key.lower() and value:
                return value
        
        return None
    
    def _extract_port_from_env(self, env_vars: Dict[str, str]) -> Optional[int]:
        """Extract port information from environment variables."""
        # Check for explicit port variables
        port_vars = ['MCP_SERVER_PORT', 'MCP_PORT', 'PORT', 'SERVER_PORT']
        
        for var in port_vars:
            if var in env_vars:
                try:
                    return int(env_vars[var])
                except ValueError:
                    continue
        
        # Check for port in other variables
        for key, value in env_vars.items():
            # Check all patterns, not just when key contains 'port'
            for pattern in self.port_patterns:
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    try:
                        port = int(match.group(1))
                        if 1 <= port <= 65535:
                            return port
                    except (ValueError, IndexError):
                        continue
        
        return None
    
    def _extract_transport_from_env(self, env_vars: Dict[str, str]) -> TransportType:
        """Extract transport type from environment variables."""
        # Check for explicit transport variables
        transport_vars = ['MCP_TRANSPORT_TYPE', 'MCP_TRANSPORT', 'TRANSPORT_TYPE']
        
        for var in transport_vars:
            if var in env_vars:
                transport_value = env_vars[var].lower()
                if 'websocket' in transport_value or 'ws' in transport_value:
                    return TransportType.WEBSOCKET
                elif 'http' in transport_value:
                    return TransportType.HTTP
                elif 'stdio' in transport_value:
                    return TransportType.STDIO
        
        # Infer from other environment variables
        all_values = ' '.join(env_vars.values()).lower()
        
        for transport_type, indicators in self.transport_indicators.items():
            for indicator in indicators:
                if indicator in all_values:
                    return transport_type
        
        # Default based on port presence
        if self._extract_port_from_env(env_vars):
            return TransportType.HTTP
        else:
            return TransportType.STDIO
    
    def _determine_server_type_from_env(self, env_vars: Dict[str, str], source: str) -> MCPServerType:
        """Determine server type from environment variables."""
        all_values = ' '.join(env_vars.values()).lower()
        
        if 'docker' in source or 'container' in all_values:
            return MCPServerType.DOCKER_CONTAINER
        elif 'npx' in all_values or '@modelcontextprotocol' in all_values:
            return MCPServerType.NPX_PACKAGE
        elif 'node' in all_values or 'npm' in all_values:
            return MCPServerType.STANDALONE  # Node.js apps are typically standalone
        else:
            return MCPServerType.STANDALONE
    
    def _extract_env_indicators(self, env_vars: Dict[str, str]) -> Dict[str, Any]:
        """Extract various indicators from environment variables."""
        indicators = {
            'mcp_vars': [],
            'transport_vars': [],
            'port_vars': [],
            'auth_vars': [],
            'config_vars': [],
            'tool_vars': [],
        }
        
        for key, value in env_vars.items():
            key_lower = key.lower()
            value_lower = value.lower()
            
            # Categorize variables
            if any(pattern in key_lower for pattern in ['mcp', 'model_context_protocol']):
                indicators['mcp_vars'].append({'key': key, 'value': value})
            
            if any(pattern in key_lower for pattern in ['transport', 'http', 'websocket', 'stdio']):
                indicators['transport_vars'].append({'key': key, 'value': value})
            
            if 'port' in key_lower:
                indicators['port_vars'].append({'key': key, 'value': value})
            
            if any(pattern in key_lower for pattern in ['auth', 'token', 'key', 'secret']):
                indicators['auth_vars'].append({'key': key, 'value': value})
            
            if any(pattern in key_lower for pattern in ['config', 'settings', 'options']):
                indicators['config_vars'].append({'key': key, 'value': value})
            
            if any(pattern in key_lower for pattern in ['tool', 'capability', 'resource', 'prompt']):
                indicators['tool_vars'].append({'key': key, 'value': value})
        
        return indicators
    
    def _calculate_process_env_confidence(self, env_vars: Dict[str, str], cmdline: List[str]) -> float:
        """Calculate confidence score for process environment variables."""
        confidence = 0.0
        
        # Base confidence for having MCP environment variables
        confidence += 0.3
        
        # Bonus for known MCP environment variables
        known_vars = sum(1 for key in env_vars.keys() if key.upper() in self.known_mcp_env_vars)
        confidence += min(known_vars * 0.1, 0.3)
        
        # Bonus for MCP-related command line
        cmdline_str = ' '.join(cmdline).lower()
        if any(pattern in cmdline_str for pattern in ['mcp', 'model-context-protocol', '@modelcontextprotocol']):
            confidence += 0.2
        
        # Bonus for transport configuration
        if any('transport' in key.lower() for key in env_vars.keys()):
            confidence += 0.1
        
        # Bonus for port configuration
        if any('port' in key.lower() for key in env_vars.keys()):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _extract_mcp_indicators(self, detection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract MCP-specific indicators from detection data."""
        indicators = []
        
        # System environment indicators
        for key, value in detection_data.get('system_env_vars', {}).items():
            indicators.append({
                'source': 'system',
                'type': 'environment_variable',
                'key': key,
                'value': value,
                'confidence': self._get_env_var_confidence(key, value)
            })
        
        # Process environment indicators
        for proc_env in detection_data.get('process_env_vars', []):
            for key, value in proc_env.get('env_vars', {}).items():
                indicators.append({
                    'source': f"process_{proc_env['pid']}",
                    'type': 'environment_variable',
                    'key': key,
                    'value': value,
                    'process_name': proc_env['name'],
                    'confidence': self._get_env_var_confidence(key, value)
                })
        
        return indicators
    
    def _extract_transport_indicators(self, detection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract transport-related indicators from detection data."""
        indicators = []
        
        all_env_vars = {}
        all_env_vars.update(detection_data.get('system_env_vars', {}))
        
        for proc_env in detection_data.get('process_env_vars', []):
            all_env_vars.update(proc_env.get('env_vars', {}))
        
        for key, value in all_env_vars.items():
            for transport_type, transport_indicators in self.transport_indicators.items():
                for indicator in transport_indicators:
                    if indicator in key.lower() or indicator in value.lower():
                        indicators.append({
                            'transport_type': transport_type.value,
                            'indicator': indicator,
                            'env_var': key,
                            'value': value
                        })
        
        return indicators
    
    def _extract_port_indicators(self, detection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract port-related indicators from detection data."""
        indicators = []
        
        all_env_vars = {}
        all_env_vars.update(detection_data.get('system_env_vars', {}))
        
        for proc_env in detection_data.get('process_env_vars', []):
            all_env_vars.update(proc_env.get('env_vars', {}))
        
        for key, value in all_env_vars.items():
            if 'port' in key.lower():
                for pattern in self.port_patterns:
                    match = re.search(pattern, value, re.IGNORECASE)
                    if match:
                        try:
                            port = int(match.group(1))
                            if 1 <= port <= 65535:
                                indicators.append({
                                    'port': port,
                                    'env_var': key,
                                    'value': value,
                                    'is_common_mcp_port': port in self.common_mcp_ports
                                })
                        except (ValueError, IndexError):
                            continue
        
        return indicators
    
    def _extract_security_indicators(self, detection_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract security-related indicators from detection data."""
        indicators = []
        
        all_env_vars = {}
        all_env_vars.update(detection_data.get('system_env_vars', {}))
        
        for proc_env in detection_data.get('process_env_vars', []):
            all_env_vars.update(proc_env.get('env_vars', {}))
        
        security_patterns = [
            ('auth', 'authentication'),
            ('token', 'token_authentication'),
            ('key', 'api_key'),
            ('secret', 'secret_key'),
            ('password', 'password'),
            ('ssl', 'ssl_tls'),
            ('tls', 'ssl_tls'),
            ('https', 'https_transport'),
            ('wss', 'websocket_secure'),
        ]
        
        for key, value in all_env_vars.items():
            key_lower = key.lower()
            value_lower = value.lower()
            
            for pattern, security_type in security_patterns:
                if pattern in key_lower or pattern in value_lower:
                    indicators.append({
                        'security_type': security_type,
                        'env_var': key,
                        'value': value,
                        'has_value': bool(value.strip())
                    })
        
        return indicators
    
    def _get_env_var_confidence(self, key: str, value: str) -> float:
        """Calculate confidence score for an environment variable."""
        confidence = 0.0
        
        # High confidence for known MCP variables
        if key.upper() in self.known_mcp_env_vars:
            confidence += 0.6
        
        # Medium confidence for MCP patterns in key
        for pattern in self.mcp_env_patterns:
            if re.search(pattern, key, re.IGNORECASE):
                confidence += 0.4
                break
        
        # Low confidence for MCP patterns in value
        for pattern in self.mcp_value_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                confidence += 0.2
                break
        
        # Bonus for having a meaningful value (only if already MCP-related)
        if confidence > 0 and value and value.strip():
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _select_best_mcp_server(self, servers: List[MCPServerInfo]) -> Optional[MCPServerInfo]:
        """Select the best MCP server from detected candidates."""
        if not servers:
            return None
        
        # Sort by confidence (highest first)
        servers_with_confidence = []
        for server in servers:
            env_info = server.environment_info or {}
            env_vars = env_info.get('env_vars', {})
            confidence = sum(
                self._get_env_var_confidence(k, v) 
                for k, v in env_vars.items()
            ) / max(len(env_vars), 1)
            servers_with_confidence.append((server, confidence))
        
        servers_with_confidence.sort(key=lambda x: x[1], reverse=True)
        return servers_with_confidence[0][0]
    
    def _calculate_confidence(self, server: MCPServerInfo, detection_data: Dict[str, Any]) -> float:
        """Calculate overall confidence score for the detection."""
        confidence = 0.0
        
        # Base confidence from having a server
        confidence += 0.2
        
        # Confidence from MCP indicators
        mcp_indicators = detection_data.get('mcp_indicators', [])
        if mcp_indicators:
            avg_indicator_confidence = sum(
                indicator.get('confidence', 0) 
                for indicator in mcp_indicators
            ) / len(mcp_indicators)
            confidence += avg_indicator_confidence * 0.4
        
        # Bonus for transport indicators
        transport_indicators = detection_data.get('transport_indicators', [])
        if transport_indicators:
            confidence += 0.1
        
        # Bonus for port indicators
        port_indicators = detection_data.get('port_indicators', [])
        if port_indicators:
            confidence += 0.1
            # Extra bonus for common MCP ports
            if any(indicator.get('is_common_mcp_port') for indicator in port_indicators):
                confidence += 0.1
        
        # Bonus for security indicators
        security_indicators = detection_data.get('security_indicators', [])
        if security_indicators:
            confidence += 0.1
        
        return min(confidence, 1.0)


def create_environment_analyzer(settings=None) -> EnvironmentAnalyzer:
    """Factory function to create an environment analyzer instance."""
    return EnvironmentAnalyzer(settings) 