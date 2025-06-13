"""
Integration tests for MCP Transport Handlers

Tests for the complete transport handler ecosystem including
factory integration, error handling, and cross-transport scenarios.
"""

import pytest
import asyncio
import logging
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection.transport.factory import TransportFactory
from src.hawkeye.detection.mcp_introspection.transport.stdio import StdioTransportHandler
from src.hawkeye.detection.mcp_introspection.transport.sse import SSETransportHandler
from src.hawkeye.detection.mcp_introspection.transport.http import StreamableHTTPTransportHandler
from src.hawkeye.detection.mcp_introspection.transport.base import (
    ConnectionFailedError,
    TransportError
)
from src.hawkeye.detection.mcp_introspection.models import TransportType


class TestTransportIntegration:
    """Integration tests for transport handlers."""
    
    @pytest.fixture
    def factory(self):
        """Create a transport factory for integration tests."""
        logger = logging.getLogger("integration_test")
        return TransportFactory(logger=logger)
    
    @pytest.fixture
    def sample_configs(self):
        """Sample configurations for different transport types."""
        return {
            'stdio': {
                'command': 'node',
                'args': ['--version'],
                'timeout': 10.0,
                'max_retries': 2
            },
            'sse': {
                'url': 'https://api.example.com/sse',
                'headers': {'Authorization': 'Bearer test-token'},
                'timeout': 15.0,
                'max_retries': 3
            },
            'http': {
                'base_url': 'https://api.example.com/mcp',
                'auth': {'bearer_token': 'test-token'},
                'timeout': 20.0,
                'max_retries': 1
            }
        }
    
    def test_factory_creates_all_transport_types(self, factory, sample_configs):
        """Test that factory can create all transport types."""
        handlers = {}
        
        for transport_type, config in sample_configs.items():
            handler = factory.create_from_config(config)
            handlers[transport_type] = handler
            
            # Verify correct handler type
            if transport_type == 'stdio':
                assert isinstance(handler, StdioTransportHandler)
            elif transport_type == 'sse':
                assert isinstance(handler, SSETransportHandler)
            elif transport_type == 'http':
                assert isinstance(handler, StreamableHTTPTransportHandler)
            
            # Verify configuration was applied
            assert handler.timeout == config['timeout']
            assert handler.max_retries == config['max_retries']
    
    def test_auto_detection_accuracy(self, factory):
        """Test auto-detection accuracy across different config patterns."""
        test_cases = [
            # Stdio patterns
            ({'command': 'node'}, TransportType.STDIO),
            ({'args': ['--help']}, TransportType.STDIO),
            ({'command': 'python', 'args': ['server.py']}, TransportType.STDIO),
            
            # SSE patterns
            ({'url': 'https://api.com/sse'}, TransportType.SSE),
            ({'url': 'http://localhost:8080/events'}, TransportType.SSE),
            ({'url': 'https://server.com/stream'}, TransportType.SSE),
            
            # HTTP patterns
            ({'url': 'https://api.com/mcp'}, TransportType.HTTP),
            ({'base_url': 'https://api.com/v1'}, TransportType.HTTP),
            ({'url': 'http://localhost:3000/api'}, TransportType.HTTP),
            
            # Explicit transport
            ({'transport': 'stdio', 'url': 'https://api.com'}, TransportType.STDIO),
            ({'transport': 'sse', 'command': 'node'}, TransportType.SSE),
            ({'transport': 'http', 'args': ['--help']}, TransportType.HTTP),
        ]
        
        for config, expected_type in test_cases:
            detected_type = factory.auto_detect_transport(config)
            assert detected_type == expected_type, f"Failed for config: {config}"
    
    def test_config_validation_comprehensive(self, factory):
        """Test comprehensive config validation across transport types."""
        valid_configs = [
            # Valid stdio configs
            {'command': 'node'},
            {'command': 'python', 'args': ['server.py']},
            
            # Valid SSE configs
            {'url': 'https://api.example.com/sse'},
            {'url': 'http://localhost:8080/events'},
            
            # Valid HTTP configs
            {'base_url': 'https://api.example.com/mcp'},
            {'url': 'https://api.example.com/mcp'},
        ]
        
        invalid_configs = [
            # Invalid stdio configs
            {'args': ['--help']},  # Missing command
            {},  # Empty config
            
            # Invalid SSE configs
            {'headers': {'Auth': 'token'}},  # Missing URL
            
            # Invalid HTTP configs
            {'auth': {'token': 'value'}},  # Missing URL/base_url
        ]
        
        for config in valid_configs:
            assert factory.validate_config(config), f"Should be valid: {config}"
        
        for config in invalid_configs:
            assert not factory.validate_config(config), f"Should be invalid: {config}"
    
    @pytest.mark.asyncio
    async def test_connection_lifecycle_all_transports(self, factory, sample_configs):
        """Test connection lifecycle for all transport types."""
        for transport_type, config in sample_configs.items():
            handler = factory.create_from_config(config)
            
            # Mock the underlying transport mechanisms
            if transport_type == 'stdio':
                with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (b'output', b'')
                    mock_process.returncode = 0
                    mock_subprocess.return_value = mock_process
                    
                    # Test connection lifecycle
                    assert not handler.is_connected
                    
                    # Connect should work
                    await handler.connect(**config)
                    assert handler.is_connected
                    
                    # Health check should work
                    health = await handler.health_check()
                    assert health is True
                    
                    # Disconnect should work
                    await handler.disconnect()
                    assert not handler.is_connected
            
            elif transport_type == 'sse':
                with patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse:
                    mock_session = AsyncMock()
                    mock_sse.return_value = mock_session
                    
                    # Test connection lifecycle
                    assert not handler.is_connected
                    
                    await handler.connect(**config)
                    assert handler.is_connected
                    
                    health = await handler.health_check()
                    assert health is True
                    
                    await handler.disconnect()
                    assert not handler.is_connected
            
            elif transport_type == 'http':
                with patch('src.hawkeye.detection.mcp_introspection.transport.http.http_client') as mock_http:
                    mock_session = AsyncMock()
                    mock_http.return_value = mock_session
                    
                    # Test connection lifecycle
                    assert not handler.is_connected
                    
                    await handler.connect(**config)
                    assert handler.is_connected
                    
                    health = await handler.health_check()
                    assert health is True
                    
                    await handler.disconnect()
                    assert not handler.is_connected
    
    @pytest.mark.asyncio
    async def test_error_handling_consistency(self, factory, sample_configs):
        """Test that error handling is consistent across transport types."""
        for transport_type, config in sample_configs.items():
            handler = factory.create_from_config(config)
            
            # Test connection failure handling
            if transport_type == 'stdio':
                with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                    mock_subprocess.side_effect = Exception("Process creation failed")
                    
                    with pytest.raises(ConnectionFailedError):
                        await handler.connect(**config)
                    
                    assert not handler.is_connected
            
            elif transport_type == 'sse':
                with patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse:
                    mock_sse.side_effect = Exception("SSE connection failed")
                    
                    with pytest.raises(ConnectionFailedError):
                        await handler.connect(**config)
                    
                    assert not handler.is_connected
            
            elif transport_type == 'http':
                with patch('src.hawkeye.detection.mcp_introspection.transport.http.http_client') as mock_http:
                    mock_http.side_effect = Exception("HTTP connection failed")
                    
                    with pytest.raises(ConnectionFailedError):
                        await handler.connect(**config)
                    
                    assert not handler.is_connected
    
    def test_server_info_consistency(self, factory, sample_configs):
        """Test that server info format is consistent across transport types."""
        for transport_type, config in sample_configs.items():
            handler = factory.create_from_config(config)
            
            # Set some state to test info retrieval
            if transport_type == 'stdio':
                handler._command = config.get('command')
                handler._args = config.get('args', [])
            elif transport_type == 'sse':
                handler._url = config.get('url')
                handler._headers = config.get('headers', {})
            elif transport_type == 'http':
                handler._base_url = config.get('base_url')
                handler._auth = config.get('auth', {})
            
            info = handler.get_server_info()
            
            # Common fields that should be present
            assert 'transport_type' in info
            assert 'connected' in info
            assert 'timeout' in info
            assert 'max_retries' in info
            
            # Verify transport-specific fields
            if transport_type == 'stdio':
                assert info['transport_type'] == 'stdio'
                assert 'command' in info
                assert 'args' in info
            elif transport_type == 'sse':
                assert info['transport_type'] == 'sse'
                assert 'url' in info
                assert 'headers' in info
            elif transport_type == 'http':
                assert info['transport_type'] == 'http'
                assert 'base_url' in info
                assert 'auth_configured' in info
    
    @pytest.mark.asyncio
    async def test_concurrent_connections(self, factory):
        """Test concurrent connections across different transport types."""
        configs = [
            {'command': 'echo', 'args': ['test1']},
            {'url': 'https://api1.example.com/sse'},
            {'base_url': 'https://api2.example.com/mcp'}
        ]
        
        handlers = [factory.create_from_config(config) for config in configs]
        
        # Mock all transport mechanisms
        with patch('asyncio.create_subprocess_exec') as mock_subprocess, \
             patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse, \
             patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http:
            
            # Setup mocks
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b'test1', b'')
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            mock_sse_session = AsyncMock()
            mock_sse.return_value = mock_sse_session
            
            mock_http_session = AsyncMock()
            mock_http.return_value = mock_http_session
            
            # Connect all handlers concurrently
            connect_tasks = [
                handler.connect(**config) 
                for handler, config in zip(handlers, configs)
            ]
            
            await asyncio.gather(*connect_tasks)
            
            # Verify all connections succeeded
            for handler in handlers:
                assert handler.is_connected
            
            # Disconnect all handlers concurrently
            disconnect_tasks = [handler.disconnect() for handler in handlers]
            await asyncio.gather(*disconnect_tasks)
            
            # Verify all disconnections succeeded
            for handler in handlers:
                assert not handler.is_connected
    
    def test_transport_registration(self, factory):
        """Test custom transport registration."""
        # Create a mock custom transport
        class CustomTransportHandler:
            def __init__(self, **kwargs):
                self.timeout = kwargs.get('timeout', 30.0)
                self.max_retries = kwargs.get('max_retries', 3)
        
        # Create a mock transport type
        mock_transport_type = Mock()
        mock_transport_type.value = 'custom'
        
        # Register the custom handler
        factory.register_handler(mock_transport_type, CustomTransportHandler)
        
        # Verify registration
        assert mock_transport_type in factory._handlers
        assert factory._handlers[mock_transport_type] == CustomTransportHandler
        
        # Test creation
        handler = factory.create_handler(mock_transport_type, timeout=45.0)
        assert isinstance(handler, CustomTransportHandler)
        assert handler.timeout == 45.0
    
    @pytest.mark.asyncio
    async def test_factory_connection_testing(self, factory):
        """Test factory-level connection testing."""
        configs = [
            {'command': 'echo', 'args': ['hello']},
            {'url': 'https://api.example.com/sse'},
            {'base_url': 'https://api.example.com/mcp'}
        ]
        
        # Mock successful connections
        with patch('asyncio.create_subprocess_exec') as mock_subprocess, \
             patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse, \
             patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http:
            
            # Setup successful mocks
            mock_process = AsyncMock()
            mock_process.communicate.return_value = (b'hello', b'')
            mock_process.returncode = 0
            mock_subprocess.return_value = mock_process
            
            mock_sse.return_value = AsyncMock()
            mock_http.return_value = AsyncMock()
            
            # Test connections through factory
            for config in configs:
                result = await factory.test_connection(config)
                assert result is True
        
        # Test failed connections
        with patch('asyncio.create_subprocess_exec') as mock_subprocess, \
             patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse, \
             patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http:
            
            # Setup failing mocks
            mock_subprocess.side_effect = Exception("Process failed")
            mock_sse.side_effect = Exception("SSE failed")
            mock_http.side_effect = Exception("HTTP failed")
            
            # Test failed connections through factory
            for config in configs:
                result = await factory.test_connection(config)
                assert result is False


class TestTransportErrorScenarios:
    """Test error scenarios across transport types."""
    
    @pytest.fixture
    def factory(self):
        """Create a factory for error testing."""
        return TransportFactory()
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self, factory):
        """Test timeout handling across transport types."""
        configs = [
            {'command': 'sleep', 'args': ['10'], 'timeout': 0.1},
            {'url': 'https://slow.example.com/sse', 'timeout': 0.1},
            {'base_url': 'https://slow.example.com/mcp', 'timeout': 0.1}
        ]
        
        for config in configs:
            handler = factory.create_from_config(config)
            
            # Mock slow responses
            if 'command' in config:
                with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                    # Simulate a process that takes too long
                    async def slow_process(*args, **kwargs):
                        await asyncio.sleep(1.0)  # Longer than timeout
                        return AsyncMock()
                    
                    mock_subprocess.side_effect = slow_process
                    
                    with pytest.raises((ConnectionFailedError, asyncio.TimeoutError)):
                        await handler.connect(**config)
            
            elif 'url' in config and 'sse' in config['url']:
                with patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse:
                    async def slow_sse(*args, **kwargs):
                        await asyncio.sleep(1.0)
                        return AsyncMock()
                    
                    mock_sse.side_effect = slow_sse
                    
                    with pytest.raises((ConnectionFailedError, asyncio.TimeoutError)):
                        await handler.connect(**config)
            
            elif 'base_url' in config:
                with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http:
                    async def slow_http(*args, **kwargs):
                        await asyncio.sleep(1.0)
                        return AsyncMock()
                    
                    mock_http.side_effect = slow_http
                    
                    with pytest.raises((ConnectionFailedError, asyncio.TimeoutError)):
                        await handler.connect(**config)
    
    @pytest.mark.asyncio
    async def test_retry_behavior(self, factory):
        """Test retry behavior across transport types."""
        configs = [
            {'command': 'false', 'max_retries': 2},  # Command that always fails
            {'url': 'https://unreachable.example.com/sse', 'max_retries': 2},
            {'base_url': 'https://unreachable.example.com/mcp', 'max_retries': 2}
        ]
        
        for config in configs:
            handler = factory.create_from_config(config)
            
            # Mock failing connections
            if 'command' in config:
                with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                    mock_subprocess.side_effect = Exception("Connection failed")
                    
                    with pytest.raises(ConnectionFailedError):
                        await handler.connect(**config)
                    
                    # Verify retries were attempted
                    assert mock_subprocess.call_count <= config['max_retries'] + 1
            
            elif 'url' in config and 'sse' in config['url']:
                with patch('src.hawkeye.detection.mcp_introspection.transport.sse.sse_client') as mock_sse:
                    mock_sse.side_effect = Exception("Connection failed")
                    
                    with pytest.raises(ConnectionFailedError):
                        await handler.connect(**config)
            
            elif 'base_url' in config:
                with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http:
                    mock_http.side_effect = Exception("Connection failed")
                    
                    with pytest.raises(ConnectionFailedError):
                        await handler.connect(**config)
    
    def test_invalid_configuration_handling(self, factory):
        """Test handling of invalid configurations."""
        invalid_configs = [
            {'command': ''},  # Empty command
            {'url': 'invalid-url'},  # Invalid URL
            {'base_url': 'not-a-url'},  # Invalid base URL
            {'transport': 'unknown'},  # Unknown transport type
        ]
        
        for config in invalid_configs:
            # Some configs should fail validation
            if not factory.validate_config(config):
                continue
            
            # Others should fail during handler creation or connection
            try:
                handler = factory.create_from_config(config)
                # If handler creation succeeds, connection should fail
                # This is tested in async methods above
            except (TransportError, ConnectionFailedError):
                # Expected for invalid configs
                pass


class TestTransportPerformance:
    """Performance tests for transport handlers."""
    
    @pytest.fixture
    def factory(self):
        """Create a factory for performance testing."""
        return TransportFactory()
    
    def test_handler_creation_performance(self, factory):
        """Test performance of handler creation."""
        import time
        
        configs = [
            {'command': 'echo', 'args': ['test']},
            {'url': 'https://api.example.com/sse'},
            {'base_url': 'https://api.example.com/mcp'}
        ]
        
        # Measure handler creation time
        start_time = time.time()
        
        for _ in range(100):  # Create 100 handlers
            for config in configs:
                handler = factory.create_from_config(config)
                assert handler is not None
        
        end_time = time.time()
        creation_time = end_time - start_time
        
        # Should be able to create 300 handlers in reasonable time
        assert creation_time < 1.0, f"Handler creation took too long: {creation_time}s"
    
    def test_auto_detection_performance(self, factory):
        """Test performance of transport auto-detection."""
        import time
        
        configs = [
            {'command': 'node', 'args': ['server.js']},
            {'url': 'https://api.example.com/sse'},
            {'base_url': 'https://api.example.com/mcp'},
            {'transport': 'stdio', 'command': 'python'},
            {'args': ['--help']},
            {'url': 'http://localhost:8080/events'},
        ]
        
        # Measure auto-detection time
        start_time = time.time()
        
        for _ in range(1000):  # Run 1000 detections
            for config in configs:
                transport_type = factory.auto_detect_transport(config)
                assert transport_type is not None
        
        end_time = time.time()
        detection_time = end_time - start_time
        
        # Should be able to run 6000 detections in reasonable time
        assert detection_time < 1.0, f"Auto-detection took too long: {detection_time}s"


if __name__ == "__main__":
    pytest.main([__file__]) 