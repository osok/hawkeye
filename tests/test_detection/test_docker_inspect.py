"""
Unit tests for Docker container inspection functionality.
"""

import json
import subprocess
import pytest
from unittest.mock import Mock, patch, mock_open, MagicMock
from pathlib import Path

from src.hawkeye.detection.docker_inspect import DockerInspector, create_docker_inspector
from src.hawkeye.detection.base import (
    DetectionMethod, MCPServerType, TransportType
)


class TestDockerInspector:
    """Test cases for DockerInspector class."""
    
    @pytest.fixture
    def inspector(self):
        """Create DockerInspector instance for testing."""
        return DockerInspector()
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        settings = Mock()
        settings.detection = Mock()
        settings.detection.timeout = 30
        return settings
    
    def test_init(self, mock_settings):
        """Test DockerInspector initialization."""
        inspector = DockerInspector(mock_settings)
        
        assert inspector.settings == mock_settings
        assert len(inspector.mcp_image_patterns) > 0
        assert len(inspector.known_mcp_images) > 0
        assert len(inspector.mcp_env_patterns) > 0
        assert len(inspector.mcp_command_patterns) > 0
        assert len(inspector.common_mcp_ports) > 0
    
    def test_get_detection_method(self, inspector):
        """Test detection method identifier."""
        assert inspector.get_detection_method() == DetectionMethod.DOCKER_INSPECTION
    
    @patch('subprocess.run')
    def test_is_docker_available_success(self, mock_run, inspector):
        """Test Docker availability check when Docker is available."""
        mock_run.return_value = Mock(returncode=0)
        
        assert inspector._is_docker_available() is True
        mock_run.assert_called_once_with(
            ['docker', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
    
    @patch('subprocess.run')
    def test_is_docker_available_failure(self, mock_run, inspector):
        """Test Docker availability check when Docker is not available."""
        mock_run.side_effect = FileNotFoundError()
        
        assert inspector._is_docker_available() is False
    
    @patch('subprocess.run')
    def test_get_docker_info_success(self, mock_run, inspector):
        """Test Docker info retrieval success."""
        docker_info = {'ServerVersion': '20.10.0', 'Containers': 5}
        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps(docker_info)
        )
        
        result = inspector._get_docker_info()
        
        assert result == docker_info
        mock_run.assert_called_once_with(
            ['docker', 'info', '--format', '{{json .}}'],
            capture_output=True,
            text=True,
            timeout=30
        )
    
    @patch('subprocess.run')
    def test_get_docker_info_failure(self, mock_run, inspector):
        """Test Docker info retrieval failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'docker')
        
        result = inspector._get_docker_info()
        
        assert result == {}
    
    def test_is_mcp_image_name_known_images(self, inspector):
        """Test MCP image name detection for known images."""
        assert inspector._is_mcp_image_name('modelcontextprotocol/server')
        assert inspector._is_mcp_image_name('mcp/server')
        assert inspector._is_mcp_image_name('mcp-server')
        
        assert not inspector._is_mcp_image_name('nginx')
        assert not inspector._is_mcp_image_name('redis')
    
    def test_is_mcp_image_name_patterns(self, inspector):
        """Test MCP image name detection using patterns."""
        assert inspector._is_mcp_image_name('custom-mcp-server')
        assert inspector._is_mcp_image_name('node-mcp-app')
        assert inspector._is_mcp_image_name('my-model-context-protocol-server')
        
        assert not inspector._is_mcp_image_name('web-server')
        assert not inspector._is_mcp_image_name('database')
    
    def test_is_mcp_container(self, inspector):
        """Test MCP container detection."""
        # Container with MCP image
        mcp_container = {
            'Image': 'mcp-server:latest',
            'Command': 'node server.js',
            'Ports': '3000/tcp'
        }
        assert inspector._is_mcp_container(mcp_container)
        
        # Container with MCP command
        mcp_command_container = {
            'Image': 'node:16',
            'Command': 'npx @modelcontextprotocol/server-filesystem',
            'Ports': ''
        }
        assert inspector._is_mcp_container(mcp_command_container)
        
        # Container with MCP port
        mcp_port_container = {
            'Image': 'node:16',
            'Command': 'node app.js',
            'Ports': '3000:3000/tcp'
        }
        assert inspector._is_mcp_container(mcp_port_container)
        
        # Non-MCP container
        regular_container = {
            'Image': 'nginx:latest',
            'Command': 'nginx -g daemon off;',
            'Ports': '80/tcp'
        }
        assert not inspector._is_mcp_container(regular_container)
    
    def test_is_mcp_image(self, inspector):
        """Test MCP image detection."""
        mcp_image = {
            'Repository': 'mcp-server',
            'Tag': 'latest'
        }
        assert inspector._is_mcp_image(mcp_image)
        
        regular_image = {
            'Repository': 'nginx',
            'Tag': 'latest'
        }
        assert not inspector._is_mcp_image(regular_image)
    
    def test_is_mcp_service(self, inspector):
        """Test MCP service detection in compose files."""
        # Service with MCP name
        mcp_service = {
            'image': 'node:16',
            'command': 'node server.js',
            'ports': ['3000:3000']
        }
        assert inspector._is_mcp_service('mcp-server', mcp_service)
        
        # Service with MCP image
        mcp_image_service = {
            'image': 'mcp-server:latest',
            'ports': ['8000:8000']
        }
        assert inspector._is_mcp_service('api', mcp_image_service)
        
        # Service with MCP command
        mcp_command_service = {
            'image': 'node:16',
            'command': 'npx @modelcontextprotocol/server-filesystem',
        }
        assert inspector._is_mcp_service('filesystem', mcp_command_service)
        
        # Service with MCP environment
        mcp_env_service = {
            'image': 'node:16',
            'environment': ['MCP_SERVER_PORT=3000']
        }
        assert inspector._is_mcp_service('server', mcp_env_service)
        
        # Service with MCP port
        mcp_port_service = {
            'image': 'node:16',
            'ports': ['3000:3000']
        }
        assert inspector._is_mcp_service('api', mcp_port_service)
        
        # Regular service
        regular_service = {
            'image': 'nginx:latest',
            'ports': ['80:80']
        }
        assert not inspector._is_mcp_service('web', regular_service)
    
    @patch('subprocess.run')
    def test_get_container_details_success(self, mock_run, inspector):
        """Test container details retrieval success."""
        container_data = {
            'Name': '/mcp-server',
            'Config': {
                'Image': 'mcp-server:latest',
                'Cmd': ['node', 'server.js'],
                'Env': ['MCP_PORT=3000'],
                'Labels': {'app': 'mcp-server'}
            },
            'NetworkSettings': {
                'Ports': {'3000/tcp': [{'HostPort': '3000'}]}
            },
            'State': {'Running': True},
            'Mounts': []
        }
        
        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps([container_data])
        )
        
        result = inspector._get_container_details('container123')
        
        assert result is not None
        assert result['name'] == 'mcp-server'
        assert result['image'] == 'mcp-server:latest'
        assert result['command'] == ['node', 'server.js']
        assert 'confidence' in result
    
    @patch('subprocess.run')
    def test_get_container_details_failure(self, mock_run, inspector):
        """Test container details retrieval failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'docker')
        
        result = inspector._get_container_details('container123')
        
        assert result is None
    
    @patch('subprocess.run')
    def test_get_image_details_success(self, mock_run, inspector):
        """Test image details retrieval success."""
        image_data = {
            'Id': 'sha256:abc123',
            'RepoTags': ['mcp-server:latest'],
            'Config': {
                'Cmd': ['node', 'server.js'],
                'Env': ['NODE_ENV=production'],
                'ExposedPorts': {'3000/tcp': {}},
                'Labels': {'version': '1.0'}
            },
            'Created': '2024-01-01T00:00:00Z'
        }
        
        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps([image_data])
        )
        
        result = inspector._get_image_details('mcp-server:latest')
        
        assert result is not None
        assert result['name'] == 'mcp-server:latest'
        assert result['id'] == 'sha256:abc123'
        assert result['tags'] == ['mcp-server:latest']
        assert 'confidence' in result
    
    @patch('subprocess.run')
    def test_get_image_details_failure(self, mock_run, inspector):
        """Test image details retrieval failure."""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'docker')
        
        result = inspector._get_image_details('mcp-server:latest')
        
        assert result is None
    
    @patch('builtins.open', new_callable=mock_open)
    def test_analyze_compose_file_success(self, mock_file, inspector):
        """Test compose file analysis success."""
        compose_content = """
        version: '3.8'
        services:
          mcp-server:
            image: mcp-server:latest
            ports:
              - "3000:3000"
        """
        
        mock_file.return_value.read.return_value = compose_content
        
        with patch('yaml.safe_load') as mock_yaml:
            mock_yaml.return_value = {
                'version': '3.8',
                'services': {
                    'mcp-server': {
                        'image': 'mcp-server:latest',
                        'ports': ['3000:3000']
                    }
                }
            }
            
            result = inspector._analyze_compose_file('/test/docker-compose.yml')
            
            assert result is not None
            assert 'services' in result
            assert 'mcp-server' in result['services']
    
    def test_analyze_compose_file_failure(self, inspector):
        """Test compose file analysis failure."""
        with patch('builtins.open', side_effect=FileNotFoundError()):
            result = inspector._analyze_compose_file('/nonexistent/docker-compose.yml')
            
            assert result is None
    
    def test_has_mcp_services(self, inspector):
        """Test MCP services detection in compose data."""
        compose_with_mcp = {
            'services': {
                'mcp-server': {
                    'image': 'mcp-server:latest',
                    'ports': ['3000:3000']
                },
                'database': {
                    'image': 'postgres:13',
                    'ports': ['5432:5432']
                }
            }
        }
        assert inspector._has_mcp_services(compose_with_mcp)
        
        compose_without_mcp = {
            'services': {
                'web': {
                    'image': 'nginx:latest',
                    'ports': ['80:80']
                },
                'database': {
                    'image': 'postgres:13',
                    'ports': ['5432:5432']
                }
            }
        }
        assert not inspector._has_mcp_services(compose_without_mcp)
    
    def test_extract_mcp_services(self, inspector):
        """Test MCP services extraction from compose data."""
        compose_data = {
            'services': {
                'mcp-server': {
                    'image': 'mcp-server:latest',
                    'ports': ['3000:3000']
                },
                'web': {
                    'image': 'nginx:latest',
                    'ports': ['80:80']
                }
            }
        }
        
        mcp_services = inspector._extract_mcp_services(compose_data)
        
        assert len(mcp_services) == 1
        assert mcp_services[0]['name'] == 'mcp-server'
        assert 'confidence' in mcp_services[0]
    
    def test_get_container_confidence(self, inspector):
        """Test container confidence calculation."""
        # High confidence container
        high_confidence_container = {
            'Config': {
                'Image': 'modelcontextprotocol/server',
                'Cmd': ['npx', '@modelcontextprotocol/server-filesystem'],
                'Env': ['MCP_SERVER_PORT=3000']
            },
            'NetworkSettings': {
                'Ports': {'3000/tcp': [{'HostPort': '3000'}]}
            }
        }
        confidence = inspector._get_container_confidence(high_confidence_container)
        assert confidence >= 0.7
        
        # Low confidence container
        low_confidence_container = {
            'Config': {
                'Image': 'nginx:latest',
                'Cmd': ['nginx', '-g', 'daemon off;'],
                'Env': ['NGINX_PORT=80']
            },
            'NetworkSettings': {
                'Ports': {'80/tcp': [{'HostPort': '80'}]}
            }
        }
        confidence = inspector._get_container_confidence(low_confidence_container)
        assert confidence < 0.3
    
    def test_get_image_confidence(self, inspector):
        """Test image confidence calculation."""
        # High confidence image
        high_confidence_image = {
            'RepoTags': ['mcp-server:latest'],
            'Config': {
                'Cmd': ['npx', '@modelcontextprotocol/server-filesystem'],
                'Env': ['MCP_SERVER_PORT=3000']
            }
        }
        confidence = inspector._get_image_confidence(high_confidence_image)
        assert confidence >= 0.6
        
        # Low confidence image
        low_confidence_image = {
            'RepoTags': ['nginx:latest'],
            'Config': {
                'Cmd': ['nginx', '-g', 'daemon off;'],
                'Env': ['NGINX_PORT=80']
            }
        }
        confidence = inspector._get_image_confidence(low_confidence_image)
        assert confidence < 0.3
    
    def test_get_service_confidence(self, inspector):
        """Test service confidence calculation."""
        # High confidence service
        high_confidence_service = {
            'image': 'mcp-server:latest',
            'command': 'npx @modelcontextprotocol/server-filesystem',
            'environment': ['MCP_SERVER_PORT=3000']
        }
        confidence = inspector._get_service_confidence('mcp-server', high_confidence_service)
        assert confidence >= 0.8
        
        # Low confidence service
        low_confidence_service = {
            'image': 'nginx:latest',
            'command': 'nginx -g daemon off;',
            'environment': ['NGINX_PORT=80']
        }
        confidence = inspector._get_service_confidence('web', low_confidence_service)
        assert confidence < 0.3
    
    def test_extract_container_port(self, inspector):
        """Test port extraction from container information."""
        # Container with MCP port
        container_with_mcp_port = {
            'ports': {
                '3000/tcp': [{'HostPort': '3000'}],
                '8080/tcp': [{'HostPort': '8080'}]
            }
        }
        port = inspector._extract_container_port(container_with_mcp_port)
        assert port == 3000
        
        # Container with non-MCP port
        container_with_other_port = {
            'ports': {
                '5432/tcp': [{'HostPort': '5432'}]
            }
        }
        port = inspector._extract_container_port(container_with_other_port)
        assert port == 5432
        
        # Container with no ports
        container_no_ports = {'ports': {}}
        port = inspector._extract_container_port(container_no_ports)
        assert port is None
    
    def test_extract_image_port(self, inspector):
        """Test port extraction from image information."""
        # Image with MCP port
        image_with_mcp_port = {
            'exposed_ports': {
                '3000/tcp': {},
                '8080/tcp': {}
            }
        }
        port = inspector._extract_image_port(image_with_mcp_port)
        assert port == 3000
        
        # Image with no exposed ports
        image_no_ports = {'exposed_ports': {}}
        port = inspector._extract_image_port(image_no_ports)
        assert port is None
    
    def test_extract_service_port(self, inspector):
        """Test port extraction from service information."""
        # Service with MCP port
        service_with_mcp_port = {
            'config': {
                'ports': ['3000:3000', '8080:8080']
            }
        }
        port = inspector._extract_service_port(service_with_mcp_port)
        assert port == 3000
        
        # Service with no ports
        service_no_ports = {'config': {}}
        port = inspector._extract_service_port(service_no_ports)
        assert port is None
    
    def test_infer_transport_from_container(self, inspector):
        """Test transport type inference from container."""
        # WebSocket transport
        ws_container = {'command': ['node', 'server.js', '--websocket']}
        assert inspector._infer_transport_from_container(ws_container) == TransportType.WEBSOCKET
        
        # HTTP transport
        http_container = {'command': ['node', 'server.js', '--http'], 'ports': {'3000/tcp': []}}
        assert inspector._infer_transport_from_container(http_container) == TransportType.HTTP
        
        # STDIO transport
        stdio_container = {'command': ['node', 'server.js', '--stdio']}
        assert inspector._infer_transport_from_container(stdio_container) == TransportType.STDIO
        
        # Default transport
        default_container = {'command': ['node', 'server.js']}
        assert inspector._infer_transport_from_container(default_container) == TransportType.HTTP
    
    def test_infer_transport_from_image(self, inspector):
        """Test transport type inference from image."""
        # WebSocket transport
        ws_image = {'command': ['node', 'server.js', '--websocket']}
        assert inspector._infer_transport_from_image(ws_image) == TransportType.WEBSOCKET
        
        # HTTP transport
        http_image = {'command': ['node', 'server.js', '--http'], 'exposed_ports': {'3000/tcp': {}}}
        assert inspector._infer_transport_from_image(http_image) == TransportType.HTTP
        
        # Default transport
        default_image = {'command': ['node', 'server.js']}
        assert inspector._infer_transport_from_image(default_image) == TransportType.HTTP
    
    def test_infer_transport_from_service(self, inspector):
        """Test transport type inference from service."""
        # WebSocket transport
        ws_service = {'config': {'command': 'node server.js --websocket'}}
        assert inspector._infer_transport_from_service(ws_service) == TransportType.WEBSOCKET
        
        # HTTP transport
        http_service = {'config': {'command': 'node server.js --http', 'ports': ['3000:3000']}}
        assert inspector._infer_transport_from_service(http_service) == TransportType.HTTP
        
        # Default transport
        default_service = {'config': {'command': 'node server.js'}}
        assert inspector._infer_transport_from_service(default_service) == TransportType.HTTP
    
    def test_analyze_containers(self, inspector):
        """Test container analysis."""
        containers = [
            {
                'id': 'container123',
                'name': 'mcp-server',
                'image': 'mcp-server:latest',
                'command': ['node', 'server.js', '--http'],
                'ports': {'3000/tcp': [{'HostPort': '3000'}]}
            }
        ]
        
        servers = inspector._analyze_containers(containers)
        
        assert len(servers) == 1
        server = servers[0]
        assert server.host == 'localhost'
        assert server.server_type == MCPServerType.DOCKER_CONTAINER
        assert server.transport_type == TransportType.HTTP
        assert server.port == 3000
        assert server.docker_info == containers[0]
    
    def test_analyze_images(self, inspector):
        """Test image analysis."""
        images = [
            {
                'name': 'mcp-server:latest',
                'command': ['node', 'server.js'],
                'exposed_ports': {'3000/tcp': {}}
            }
        ]
        
        servers = inspector._analyze_images(images)
        
        assert len(servers) == 1
        server = servers[0]
        assert server.host == 'localhost'
        assert server.server_type == MCPServerType.DOCKER_CONTAINER
        assert server.transport_type == TransportType.HTTP
        assert server.port == 3000
        assert server.docker_info == images[0]
    
    def test_analyze_compose_files(self, inspector):
        """Test compose file analysis."""
        compose_files = [
            {
                'path': '/test/docker-compose.yml',
                'mcp_services': [
                    {
                        'name': 'mcp-server',
                        'config': {
                            'image': 'mcp-server:latest',
                            'ports': ['3000:3000']
                        }
                    }
                ]
            }
        ]
        
        servers = inspector._analyze_compose_files(compose_files)
        
        assert len(servers) == 1
        server = servers[0]
        assert server.host == 'localhost'
        assert server.server_type == MCPServerType.DOCKER_CONTAINER
        assert server.transport_type == TransportType.HTTP
        assert server.port == 3000
        assert 'compose_file' in server.docker_info
    
    def test_select_best_mcp_server(self, inspector):
        """Test MCP server selection logic."""
        from src.hawkeye.detection.base import MCPServerInfo
        
        # Test empty list
        assert inspector._select_best_mcp_server([]) is None
        
        # Create test servers
        running_server = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.DOCKER_CONTAINER,
            docker_info={'state': {'Running': True}}
        )
        
        image_server = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.DOCKER_CONTAINER,
            docker_info={'name': 'mcp-server:latest'}
        )
        
        # Should prefer running container
        best = inspector._select_best_mcp_server([image_server, running_server])
        assert best == running_server
        
        # Should return first if no running containers
        best = inspector._select_best_mcp_server([image_server])
        assert best == image_server
    
    def test_calculate_confidence(self, inspector):
        """Test confidence calculation."""
        from src.hawkeye.detection.base import MCPServerInfo
        
        # Base server (transport_type defaults to UNKNOWN, so no transport bonus)
        server = MCPServerInfo(
            host='localhost',
            server_type=MCPServerType.DOCKER_CONTAINER,
            docker_info={}
        )
        detection_data = {}
        
        confidence = inspector._calculate_confidence(server, detection_data)
        assert confidence == 0.3  # Base only (no transport bonus for UNKNOWN)
        
        # Add transport type
        server.transport_type = TransportType.HTTP
        confidence = inspector._calculate_confidence(server, detection_data)
        assert confidence == 0.4  # Base + transport type
        
        # Add running state
        server.docker_info = {'state': {'Running': True}}
        confidence = inspector._calculate_confidence(server, detection_data)
        assert abs(confidence - 0.8) < 0.001  # Base + running + transport type
        
        # Add MCP port
        server.port = 3000
        confidence = inspector._calculate_confidence(server, detection_data)
        assert abs(confidence - 1.0) < 0.001  # Base + running + port + transport type
    
    @patch.object(DockerInspector, '_is_docker_available')
    def test_detect_docker_not_available(self, mock_docker_available, inspector):
        """Test detection when Docker is not available."""
        mock_docker_available.return_value = False
        
        result = inspector.detect('localhost')
        
        assert not result.success
        assert result.error == "Docker not available"
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.DOCKER_INSPECTION
    
    @patch.object(DockerInspector, '_is_docker_available')
    @patch.object(DockerInspector, '_get_docker_info')
    @patch.object(DockerInspector, '_inspect_running_containers')
    @patch.object(DockerInspector, '_inspect_available_images')
    @patch.object(DockerInspector, '_find_compose_files')
    def test_detect_success(self, mock_compose, mock_images, mock_containers, 
                           mock_docker_info, mock_docker_available, inspector):
        """Test successful Docker detection."""
        # Mock Docker availability
        mock_docker_available.return_value = True
        mock_docker_info.return_value = {'ServerVersion': '20.10.0'}
        
        # Mock detection methods
        mock_containers.return_value = [
            {
                'id': 'container123',
                'name': 'mcp-server',
                'image': 'mcp-server:latest',
                'command': ['node', 'server.js'],
                'ports': {'3000/tcp': [{'HostPort': '3000'}]},
                'state': {'Running': True}
            }
        ]
        mock_images.return_value = []
        mock_compose.return_value = []
        
        result = inspector.detect('localhost')
        
        assert result.success
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.DOCKER_INSPECTION
        assert result.mcp_server is not None
        assert result.confidence > 0
    
    @patch.object(DockerInspector, '_is_docker_available')
    @patch.object(DockerInspector, '_get_docker_info')
    @patch.object(DockerInspector, '_inspect_running_containers')
    @patch.object(DockerInspector, '_inspect_available_images')
    @patch.object(DockerInspector, '_find_compose_files')
    def test_detect_no_servers(self, mock_compose, mock_images, mock_containers,
                              mock_docker_info, mock_docker_available, inspector):
        """Test Docker detection with no servers found."""
        # Mock Docker availability
        mock_docker_available.return_value = True
        mock_docker_info.return_value = {'ServerVersion': '20.10.0'}
        
        # Mock empty results
        mock_containers.return_value = []
        mock_images.return_value = []
        mock_compose.return_value = []
        
        result = inspector.detect('localhost')
        
        assert not result.success
        assert result.target_host == 'localhost'
        assert result.detection_method == DetectionMethod.DOCKER_INSPECTION
        assert result.mcp_server is None
        assert result.confidence == 0.0
    
    @patch.object(DockerInspector, '_is_docker_available')
    def test_detect_exception(self, mock_docker_available, inspector):
        """Test Docker detection with exception."""
        mock_docker_available.side_effect = Exception("Test error")
        
        result = inspector.detect('localhost')
        
        assert not result.success
        assert result.error == "Test error"
    
    def test_create_docker_inspector(self):
        """Test Docker inspector factory function."""
        inspector = create_docker_inspector()
        assert isinstance(inspector, DockerInspector)
        
        mock_settings = Mock()
        inspector = create_docker_inspector(mock_settings)
        assert isinstance(inspector, DockerInspector)
        assert inspector.settings == mock_settings


if __name__ == '__main__':
    pytest.main([__file__]) 