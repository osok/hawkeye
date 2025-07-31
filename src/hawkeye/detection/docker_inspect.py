"""
Docker container inspection for MCP servers.

This module implements detection of MCP servers that are running inside
Docker containers, which is a common deployment method for containerized
MCP server applications.
"""

import json
import re
import subprocess
import time
from typing import Dict, List, Optional, Any

from .base import (
    MCPDetector, DetectionResult, DetectionMethod, MCPServerInfo,
    MCPServerType, TransportType, ProcessInfo, ConfigFileInfo,
    MCPDetectionError
)
from ..utils.logging import get_logger


class DockerInspector(MCPDetector):
    """Detector for MCP servers running in Docker containers."""
    
    def __init__(self, settings=None):
        super().__init__(settings)
        self.logger = get_logger(__name__)
        
        # Docker image patterns that might contain MCP servers
        self.mcp_image_patterns = [
            r'.*mcp.*',
            r'.*model-context-protocol.*',
            r'.*@modelcontextprotocol.*',
            r'node.*mcp.*',
            r'.*mcp-server.*',
        ]
        
        # Known MCP Docker images
        self.known_mcp_images = {
            'modelcontextprotocol/server',
            'mcp/server',
            'mcp-server',
            'node:mcp-server',
        }
        
        # Environment variable patterns that indicate MCP usage
        self.mcp_env_patterns = [
            r'MCP_.*',
            r'.*_MCP_.*',
            r'MODEL_CONTEXT_PROTOCOL_.*',
            r'.*MCP.*SERVER.*',
        ]
        
        # Command patterns in containers that indicate MCP
        self.mcp_command_patterns = [
            r'.*npx.*@modelcontextprotocol.*',
            r'.*node.*mcp.*',
            r'.*mcp-server.*',
            r'.*model-context-protocol.*',
        ]
        
        # Common MCP server ports
        self.common_mcp_ports = [
            # Node.js development range
            3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010,
            # Common HTTP server ports
            4000, 5000, 8000, 8001, 8080, 8888, 9000, 9001, 9002
        ]
    
    def get_detection_method(self) -> DetectionMethod:
        """Return the detection method identifier."""
        return DetectionMethod.DOCKER_INSPECTION
    
    def detect(self, target_host: str, **kwargs) -> DetectionResult:
        """
        Detect MCP servers running in Docker containers.
        
        Args:
            target_host: Target host to scan
            **kwargs: Additional detection parameters
                - check_running: Check running containers
                - check_images: Check available images
                - check_compose: Check docker-compose files
        
        Returns:
            DetectionResult with Docker container detection results
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting Docker container inspection for {target_host}")
            
            # Detection options
            check_running = kwargs.get('check_running', True)
            check_images = kwargs.get('check_images', True)
            check_compose = kwargs.get('check_compose', True)
            
            # Collect all detection results
            detection_data = {
                'running_containers': [],
                'available_images': [],
                'compose_files': [],
                'docker_info': {},
            }
            
            mcp_servers = []
            
            # Check if Docker is available
            if not self._is_docker_available():
                self.logger.warning("Docker is not available or accessible")
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=False,
                    error="Docker not available",
                    scan_duration=time.time() - start_time
                )
            
            # Get Docker system information
            detection_data['docker_info'] = self._get_docker_info()
            
            # Check running containers
            if check_running:
                running_containers = self._inspect_running_containers()
                detection_data['running_containers'] = running_containers
                mcp_servers.extend(self._analyze_containers(running_containers))
            
            # Check available images
            if check_images:
                available_images = self._inspect_available_images()
                detection_data['available_images'] = available_images
                mcp_servers.extend(self._analyze_images(available_images))
            
            # Check docker-compose files
            if check_compose:
                compose_files = self._find_compose_files()
                detection_data['compose_files'] = compose_files
                mcp_servers.extend(self._analyze_compose_files(compose_files))
            
            # Determine the best MCP server candidate
            best_server = self._select_best_mcp_server(mcp_servers)
            
            scan_duration = time.time() - start_time
            
            if best_server:
                self.logger.info(f"Docker MCP server detected: {best_server.server_type.value}")
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
                self.logger.debug(f"No Docker MCP servers detected for {target_host}")
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=False,
                    confidence=0.0,
                    raw_data=detection_data,
                    scan_duration=scan_duration
                )
        
        except Exception as e:
            self.logger.error(f"Docker inspection failed for {target_host}: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=str(e),
                scan_duration=time.time() - start_time
            )
    
    def _is_docker_available(self) -> bool:
        """Check if Docker is available and accessible."""
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _get_docker_info(self) -> Dict[str, Any]:
        """Get Docker system information."""
        try:
            result = subprocess.run(
                ['docker', 'info', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.debug(f"Failed to get Docker info: {e}")
        
        return {}
    
    def _inspect_running_containers(self) -> List[Dict[str, Any]]:
        """Inspect running Docker containers for MCP indicators."""
        containers = []
        
        try:
            # Get list of running containers
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            container_info = json.loads(line)
                            container_id = container_info.get('ID')
                            
                            if container_id and self._is_mcp_container(container_info):
                                # Get detailed container information
                                detailed_info = self._get_container_details(container_id)
                                if detailed_info:
                                    containers.append(detailed_info)
                        
                        except json.JSONDecodeError:
                            continue
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            self.logger.warning(f"Failed to inspect running containers: {e}")
        
        return containers
    
    def _inspect_available_images(self) -> List[Dict[str, Any]]:
        """Inspect available Docker images for MCP indicators."""
        images = []
        
        try:
            # Get list of available images
            result = subprocess.run(
                ['docker', 'images', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            image_info = json.loads(line)
                            
                            if self._is_mcp_image(image_info):
                                # Get detailed image information
                                image_name = f"{image_info.get('Repository')}:{image_info.get('Tag')}"
                                detailed_info = self._get_image_details(image_name)
                                if detailed_info:
                                    images.append(detailed_info)
                        
                        except json.JSONDecodeError:
                            continue
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            self.logger.warning(f"Failed to inspect available images: {e}")
        
        return images
    
    def _find_compose_files(self) -> List[Dict[str, Any]]:
        """Find and analyze docker-compose files for MCP services."""
        compose_files = []
        
        # Common docker-compose file names
        compose_filenames = [
            'docker-compose.yml',
            'docker-compose.yaml',
            'compose.yml',
            'compose.yaml',
            'docker-compose.override.yml',
        ]
        
        # Search in common locations
        search_paths = [
            '.',
            './docker',
            './compose',
            '../',
        ]
        
        for search_path in search_paths:
            for filename in compose_filenames:
                try:
                    import os
                    filepath = os.path.join(search_path, filename)
                    
                    if os.path.exists(filepath):
                        compose_data = self._analyze_compose_file(filepath)
                        if compose_data and self._has_mcp_services(compose_data):
                            compose_files.append({
                                'path': filepath,
                                'content': compose_data,
                                'mcp_services': self._extract_mcp_services(compose_data)
                            })
                
                except Exception as e:
                    self.logger.debug(f"Failed to analyze compose file {filepath}: {e}")
        
        return compose_files
    
    def _is_mcp_container(self, container_info: Dict[str, Any]) -> bool:
        """Check if a container appears to be running an MCP server."""
        # Check image name
        image = container_info.get('Image', '').lower()
        if self._is_mcp_image_name(image):
            return True
        
        # Check command
        command = container_info.get('Command', '').lower()
        for pattern in self.mcp_command_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        
        # Check ports
        ports = container_info.get('Ports', '')
        for port in self.common_mcp_ports:
            if str(port) in ports:
                return True
        
        return False
    
    def _is_mcp_image(self, image_info: Dict[str, Any]) -> bool:
        """Check if an image appears to be an MCP server image."""
        repository = image_info.get('Repository', '').lower()
        tag = image_info.get('Tag', '').lower()
        
        return self._is_mcp_image_name(f"{repository}:{tag}")
    
    def _is_mcp_image_name(self, image_name: str) -> bool:
        """Check if an image name indicates an MCP server."""
        image_name = image_name.lower()
        
        # Check known images
        if image_name in self.known_mcp_images:
            return True
        
        # Check patterns
        for pattern in self.mcp_image_patterns:
            if re.search(pattern, image_name, re.IGNORECASE):
                return True
        
        return False
    
    def _get_container_details(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a container."""
        try:
            result = subprocess.run(
                ['docker', 'inspect', container_id],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                container_data = json.loads(result.stdout)[0]
                
                return {
                    'id': container_id,
                    'name': container_data.get('Name', '').lstrip('/'),
                    'image': container_data.get('Config', {}).get('Image', ''),
                    'command': container_data.get('Config', {}).get('Cmd', []),
                    'env_vars': container_data.get('Config', {}).get('Env', []),
                    'ports': container_data.get('NetworkSettings', {}).get('Ports', {}),
                    'labels': container_data.get('Config', {}).get('Labels', {}),
                    'state': container_data.get('State', {}),
                    'mounts': container_data.get('Mounts', []),
                    'confidence': self._get_container_confidence(container_data)
                }
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.debug(f"Failed to get container details for {container_id}: {e}")
        
        return None
    
    def _get_image_details(self, image_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about an image."""
        try:
            result = subprocess.run(
                ['docker', 'inspect', image_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                image_data = json.loads(result.stdout)[0]
                
                return {
                    'name': image_name,
                    'id': image_data.get('Id', ''),
                    'tags': image_data.get('RepoTags', []),
                    'command': image_data.get('Config', {}).get('Cmd', []),
                    'env_vars': image_data.get('Config', {}).get('Env', []),
                    'exposed_ports': image_data.get('Config', {}).get('ExposedPorts', {}),
                    'labels': image_data.get('Config', {}).get('Labels', {}),
                    'created': image_data.get('Created', ''),
                    'confidence': self._get_image_confidence(image_data)
                }
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            self.logger.debug(f"Failed to get image details for {image_name}: {e}")
        
        return None
    
    def _analyze_compose_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Analyze a docker-compose file."""
        try:
            import yaml
            
            with open(filepath, 'r') as f:
                return yaml.safe_load(f)
        
        except Exception as e:
            self.logger.debug(f"Failed to parse compose file {filepath}: {e}")
            return None
    
    def _has_mcp_services(self, compose_data: Dict[str, Any]) -> bool:
        """Check if compose file contains MCP services."""
        services = compose_data.get('services', {})
        
        for service_name, service_config in services.items():
            if self._is_mcp_service(service_name, service_config):
                return True
        
        return False
    
    def _is_mcp_service(self, service_name: str, service_config: Dict[str, Any]) -> bool:
        """Check if a service appears to be an MCP server."""
        # Check service name
        if 'mcp' in service_name.lower():
            return True
        
        # Check image
        image = service_config.get('image', '').lower()
        if self._is_mcp_image_name(image):
            return True
        
        # Check command
        command = service_config.get('command', '')
        if isinstance(command, list):
            command = ' '.join(command)
        
        for pattern in self.mcp_command_patterns:
            if re.search(pattern, str(command), re.IGNORECASE):
                return True
        
        # Check environment variables
        environment = service_config.get('environment', [])
        if isinstance(environment, dict):
            environment = [f"{k}={v}" for k, v in environment.items()]
        
        for env_var in environment:
            for pattern in self.mcp_env_patterns:
                if re.search(pattern, str(env_var), re.IGNORECASE):
                    return True
        
        # Check ports
        ports = service_config.get('ports', [])
        for port_mapping in ports:
            port_str = str(port_mapping)
            for port in self.common_mcp_ports:
                if str(port) in port_str:
                    return True
        
        return False
    
    def _extract_mcp_services(self, compose_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract MCP services from compose data."""
        mcp_services = []
        services = compose_data.get('services', {})
        
        for service_name, service_config in services.items():
            if self._is_mcp_service(service_name, service_config):
                mcp_services.append({
                    'name': service_name,
                    'config': service_config,
                    'confidence': self._get_service_confidence(service_name, service_config)
                })
        
        return mcp_services
    
    def _get_container_confidence(self, container_data: Dict[str, Any]) -> float:
        """Calculate confidence score for a container being an MCP server."""
        confidence = 0.0
        
        # Check image name
        image = container_data.get('Config', {}).get('Image', '').lower()
        if image in self.known_mcp_images:
            confidence += 0.4
        elif any(re.search(pattern, image, re.IGNORECASE) for pattern in self.mcp_image_patterns):
            confidence += 0.3
        
        # Check command
        command = ' '.join(container_data.get('Config', {}).get('Cmd', [])).lower()
        for pattern in self.mcp_command_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                confidence += 0.2
                break
        
        # Check environment variables
        env_vars = container_data.get('Config', {}).get('Env', [])
        for env_var in env_vars:
            for pattern in self.mcp_env_patterns:
                if re.search(pattern, env_var, re.IGNORECASE):
                    confidence += 0.1
                    break
        
        # Check ports
        ports = container_data.get('NetworkSettings', {}).get('Ports', {})
        for port_key in ports.keys():
            port_num = int(port_key.split('/')[0]) if '/' in port_key else 0
            if port_num in self.common_mcp_ports:
                confidence += 0.1
                break
        
        return min(confidence, 1.0)
    
    def _get_image_confidence(self, image_data: Dict[str, Any]) -> float:
        """Calculate confidence score for an image being an MCP server."""
        confidence = 0.0
        
        # Check image tags
        tags = image_data.get('RepoTags', [])
        for tag in tags:
            if tag.lower() in self.known_mcp_images:
                confidence += 0.4
                break
            elif any(re.search(pattern, tag, re.IGNORECASE) for pattern in self.mcp_image_patterns):
                confidence += 0.3
                break
        
        # Check command
        command = ' '.join(image_data.get('Config', {}).get('Cmd', [])).lower()
        for pattern in self.mcp_command_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                confidence += 0.2
                break
        
        # Check environment variables
        env_vars = image_data.get('Config', {}).get('Env', [])
        for env_var in env_vars:
            for pattern in self.mcp_env_patterns:
                if re.search(pattern, env_var, re.IGNORECASE):
                    confidence += 0.1
                    break
        
        return min(confidence, 1.0)
    
    def _get_service_confidence(self, service_name: str, service_config: Dict[str, Any]) -> float:
        """Calculate confidence score for a compose service being an MCP server."""
        confidence = 0.0
        
        # Check service name
        if 'mcp' in service_name.lower():
            confidence += 0.3
        
        # Check image
        image = service_config.get('image', '').lower()
        if self._is_mcp_image_name(image):
            confidence += 0.3
        
        # Check command
        command = service_config.get('command', '')
        if isinstance(command, list):
            command = ' '.join(command)
        
        for pattern in self.mcp_command_patterns:
            if re.search(pattern, str(command), re.IGNORECASE):
                confidence += 0.2
                break
        
        # Check environment variables
        environment = service_config.get('environment', [])
        if isinstance(environment, dict):
            environment = [f"{k}={v}" for k, v in environment.items()]
        
        for env_var in environment:
            for pattern in self.mcp_env_patterns:
                if re.search(pattern, str(env_var), re.IGNORECASE):
                    confidence += 0.1
                    break
        
        return min(confidence, 1.0)
    
    def _analyze_containers(self, containers: List[Dict[str, Any]]) -> List[MCPServerInfo]:
        """Analyze detected containers and create MCP server info."""
        servers = []
        
        for container in containers:
            try:
                # Extract port information
                port = self._extract_container_port(container)
                
                # Create server info
                server = MCPServerInfo(
                    host="localhost",  # Containers typically run locally
                    port=port,
                    server_type=MCPServerType.DOCKER_CONTAINER,
                    transport_type=self._infer_transport_from_container(container),
                    docker_info=container,
                )
                
                servers.append(server)
            
            except Exception as e:
                self.logger.warning(f"Failed to analyze container {container.get('id')}: {e}")
        
        return servers
    
    def _analyze_images(self, images: List[Dict[str, Any]]) -> List[MCPServerInfo]:
        """Analyze detected images and create MCP server info."""
        servers = []
        
        for image in images:
            try:
                # Extract port information
                port = self._extract_image_port(image)
                
                # Create server info
                server = MCPServerInfo(
                    host="localhost",
                    port=port,
                    server_type=MCPServerType.DOCKER_CONTAINER,
                    transport_type=self._infer_transport_from_image(image),
                    docker_info=image,
                )
                
                servers.append(server)
            
            except Exception as e:
                self.logger.warning(f"Failed to analyze image {image.get('name')}: {e}")
        
        return servers
    
    def _analyze_compose_files(self, compose_files: List[Dict[str, Any]]) -> List[MCPServerInfo]:
        """Analyze compose files and create MCP server info."""
        servers = []
        
        for compose_file in compose_files:
            try:
                for service in compose_file.get('mcp_services', []):
                    # Extract port information
                    port = self._extract_service_port(service)
                    
                    # Create server info
                    server = MCPServerInfo(
                        host="localhost",
                        port=port,
                        server_type=MCPServerType.DOCKER_CONTAINER,
                        transport_type=self._infer_transport_from_service(service),
                        docker_info={
                            'compose_file': compose_file['path'],
                            'service': service
                        },
                    )
                    
                    servers.append(server)
            
            except Exception as e:
                self.logger.warning(f"Failed to analyze compose file {compose_file.get('path')}: {e}")
        
        return servers
    
    def _extract_container_port(self, container: Dict[str, Any]) -> Optional[int]:
        """Extract port number from container information."""
        ports = container.get('ports', {})
        
        for port_key, port_bindings in ports.items():
            if port_bindings:
                port_num = int(port_key.split('/')[0]) if '/' in port_key else 0
                if port_num in self.common_mcp_ports:
                    return port_num
        
        # Return first exposed port if no MCP port found
        for port_key in ports.keys():
            if ports[port_key]:
                return int(port_key.split('/')[0]) if '/' in port_key else None
        
        return None
    
    def _extract_image_port(self, image: Dict[str, Any]) -> Optional[int]:
        """Extract port number from image information."""
        exposed_ports = image.get('exposed_ports', {})
        
        for port_key in exposed_ports.keys():
            port_num = int(port_key.split('/')[0]) if '/' in port_key else 0
            if port_num in self.common_mcp_ports:
                return port_num
        
        # Return first exposed port if no MCP port found
        for port_key in exposed_ports.keys():
            return int(port_key.split('/')[0]) if '/' in port_key else None
        
        return None
    
    def _extract_service_port(self, service: Dict[str, Any]) -> Optional[int]:
        """Extract port number from compose service information."""
        service_config = service.get('config', {})
        ports = service_config.get('ports', [])
        
        for port_mapping in ports:
            port_str = str(port_mapping)
            # Handle different port mapping formats
            if ':' in port_str:
                external_port = port_str.split(':')[0]
                try:
                    port_num = int(external_port)
                    if port_num in self.common_mcp_ports:
                        return port_num
                except ValueError:
                    continue
        
        return None
    
    def _infer_transport_from_container(self, container: Dict[str, Any]) -> TransportType:
        """Infer transport type from container information."""
        # Check command for transport indicators
        command = ' '.join(container.get('command', [])).lower()
        
        if '--websocket' in command or '--ws' in command:
            return TransportType.WEBSOCKET
        elif '--http' in command or container.get('ports'):
            return TransportType.HTTP
        elif '--stdio' in command:
            return TransportType.STDIO
        else:
            return TransportType.HTTP  # Default for containers
    
    def _infer_transport_from_image(self, image: Dict[str, Any]) -> TransportType:
        """Infer transport type from image information."""
        # Check command for transport indicators
        command = ' '.join(image.get('command', [])).lower()
        
        if '--websocket' in command or '--ws' in command:
            return TransportType.WEBSOCKET
        elif '--http' in command or image.get('exposed_ports'):
            return TransportType.HTTP
        elif '--stdio' in command:
            return TransportType.STDIO
        else:
            return TransportType.HTTP  # Default for images
    
    def _infer_transport_from_service(self, service: Dict[str, Any]) -> TransportType:
        """Infer transport type from compose service information."""
        service_config = service.get('config', {})
        
        # Check command
        command = service_config.get('command', '')
        if isinstance(command, list):
            command = ' '.join(command)
        command = str(command).lower()
        
        if '--websocket' in command or '--ws' in command:
            return TransportType.WEBSOCKET
        elif '--http' in command or service_config.get('ports'):
            return TransportType.HTTP
        elif '--stdio' in command:
            return TransportType.STDIO
        else:
            return TransportType.HTTP  # Default for services
    
    def _select_best_mcp_server(self, servers: List[MCPServerInfo]) -> Optional[MCPServerInfo]:
        """Select the best MCP server from detected candidates."""
        if not servers:
            return None
        
        # Prefer running containers over images or compose files
        running_servers = [s for s in servers if s.docker_info and 'state' in s.docker_info]
        if running_servers:
            return running_servers[0]
        
        # Otherwise return the first detected server
        return servers[0]
    
    def _calculate_confidence(self, server: MCPServerInfo, detection_data: Dict[str, Any]) -> float:
        """Calculate overall confidence score for the detection."""
        confidence = 0.0
        
        # Base confidence from having a server
        confidence += 0.3
        
        # Bonus for running container
        if server.docker_info and 'state' in server.docker_info:
            confidence += 0.4
        
        # Bonus for known port
        if server.port and server.port in self.common_mcp_ports:
            confidence += 0.2
        
        # Bonus for known transport type
        if server.transport_type != TransportType.UNKNOWN:
            confidence += 0.1
        
        return min(confidence, 1.0)


def create_docker_inspector(settings=None) -> DockerInspector:
    """Factory function to create a Docker inspector instance."""
    return DockerInspector(settings)