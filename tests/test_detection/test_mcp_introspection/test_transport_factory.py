"""
Unit tests for Transport Factory

Tests for the TransportFactory class that creates and auto-detects
appropriate MCP transport handlers based on server configuration.
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from src.hawkeye.detection.mcp_introspection.transport.factory import (
    TransportFactory,
    create_transport_handler,
    create_from_config
)
from src.hawkeye.detection.mcp_introspection.transport.base import (
    BaseTransportHandler,
    TransportError
)
from src.hawkeye.detection.mcp_introspection.transport.stdio import StdioTransportHandler
from src.hawkeye.detection.mcp_introspection.transport.sse import SSETransportHandler
from src.hawkeye.detection.mcp_introspection.transport.http import StreamableHTTPTransportHandler
from src.hawkeye.detection.mcp_introspection.models import TransportType


class TestTransportFactory:
    """Test cases for TransportFactory."""
    
    @pytest.fixture
    def factory(self):
        """Create a test transport factory."""
        logger = logging.getLogger("test_factory")
        return TransportFactory(logger=logger)
    
    def test_init(self, factory):
        """Test factory initialization."""
        assert factory.logger is not None
        assert TransportType.STDIO in factory._handlers
        assert TransportType.SSE in factory._handlers
        assert TransportType.HTTP in factory._handlers
    
    def test_init_default_logger(self):
        """Test factory initialization with default logger."""
        factory = TransportFactory()
        assert factory.logger is not None
        assert factory.logger.name == "TransportFactory"
    
    def test_create_handler_stdio_enum(self, factory):
        """Test creating stdio handler with enum."""
        handler = factory.create_handler(TransportType.STDIO)
        
        assert isinstance(handler, StdioTransportHandler)
        assert handler.timeout == 30.0
        assert handler.max_retries == 3
        assert handler.retry_delay == 1.0
    
    def test_create_handler_sse_string(self, factory):
        """Test creating SSE handler with string."""
        handler = factory.create_handler("sse")
        
        assert isinstance(handler, SSETransportHandler)
        assert handler.timeout == 30.0
        assert handler.max_retries == 3
        assert handler.retry_delay == 1.0
    
    def test_create_handler_http_with_kwargs(self, factory):
        """Test creating HTTP handler with custom kwargs."""
        handler = factory.create_handler(
            TransportType.HTTP,
            timeout=60.0,
            max_retries=5,
            retry_delay=2.0
        )
        
        assert isinstance(handler, StreamableHTTPTransportHandler)
        assert handler.timeout == 60.0
        assert handler.max_retries == 5
        assert handler.retry_delay == 2.0
    
    def test_create_handler_invalid_string(self, factory):
        """Test creating handler with invalid string type."""
        with pytest.raises(TransportError, match="Unsupported transport type"):
            factory.create_handler("invalid_type")
    
    def test_create_handler_unsupported_enum(self, factory):
        """Test creating handler with unsupported enum."""
        # Create a mock enum value that's not in the registry
        mock_transport = Mock()
        mock_transport.value = "unsupported"
        
        with pytest.raises(TransportError, match="No handler available"):
            factory.create_handler(mock_transport)
    
    def test_auto_detect_transport_explicit(self, factory):
        """Test auto-detection with explicit transport type."""
        config = {"transport": "stdio"}
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO
        
        config = {"transport": "SSE"}  # Test case insensitive
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.SSE
        
        config = {"transport": "HTTP"}
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.HTTP
    
    def test_auto_detect_transport_invalid_explicit(self, factory):
        """Test auto-detection with invalid explicit transport type."""
        config = {"transport": "invalid"}
        # Should continue with auto-detection instead of failing
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO  # Default fallback
    
    def test_auto_detect_transport_stdio_command(self, factory):
        """Test auto-detection for stdio transport with command."""
        config = {"command": "node", "args": ["server.js"]}
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO
    
    def test_auto_detect_transport_stdio_args_only(self, factory):
        """Test auto-detection for stdio transport with args only."""
        config = {"args": ["--port", "3000"]}
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO
    
    def test_auto_detect_transport_sse_url(self, factory):
        """Test auto-detection for SSE transport."""
        sse_urls = [
            "https://api.example.com/sse",
            "http://localhost:8080/events",
            "https://server.com/stream",
            "http://api.test.com/mcp/sse"
        ]
        
        for url in sse_urls:
            config = {"url": url}
            transport_type = factory.auto_detect_transport(config)
            assert transport_type == TransportType.SSE, f"Should detect SSE for URL: {url}"
    
    def test_auto_detect_transport_http_url(self, factory):
        """Test auto-detection for HTTP transport."""
        http_urls = [
            "https://api.example.com/mcp",
            "http://localhost:8080/api",
            "https://server.com/v1",
            "http://api.test.com/mcp/v2"
        ]
        
        for url in http_urls:
            config = {"url": url}
            transport_type = factory.auto_detect_transport(config)
            assert transport_type == TransportType.HTTP, f"Should detect HTTP for URL: {url}"
    
    def test_auto_detect_transport_base_url(self, factory):
        """Test auto-detection for HTTP transport with base_url."""
        config = {"base_url": "https://api.example.com/mcp"}
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.HTTP
    
    def test_auto_detect_transport_fallback(self, factory):
        """Test auto-detection fallback to stdio."""
        config = {"some_other_key": "value"}
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO
    
    def test_create_from_config_stdio(self, factory):
        """Test creating handler from stdio config."""
        config = {
            "command": "node",
            "args": ["server.js"],
            "timeout": 45.0,
            "max_retries": 4
        }
        
        handler = factory.create_from_config(config)
        
        assert isinstance(handler, StdioTransportHandler)
        assert handler.timeout == 45.0
        assert handler.max_retries == 4
    
    def test_create_from_config_sse(self, factory):
        """Test creating handler from SSE config."""
        config = {
            "url": "https://api.example.com/sse",
            "timeout": 20.0,
            "retry_delay": 0.5
        }
        
        handler = factory.create_from_config(config)
        
        assert isinstance(handler, SSETransportHandler)
        assert handler.timeout == 20.0
        assert handler.retry_delay == 0.5
    
    def test_create_from_config_http(self, factory):
        """Test creating handler from HTTP config."""
        config = {
            "base_url": "https://api.example.com/mcp",
            "timeout": 60.0,
            "max_retries": 2
        }
        
        handler = factory.create_from_config(config)
        
        assert isinstance(handler, StreamableHTTPTransportHandler)
        assert handler.timeout == 60.0
        assert handler.max_retries == 2
    
    def test_validate_config_stdio_valid(self, factory):
        """Test config validation for valid stdio config."""
        config = {"command": "node", "args": ["server.js"]}
        assert factory.validate_config(config) is True
    
    def test_validate_config_stdio_missing_command(self, factory):
        """Test config validation for stdio config missing command."""
        config = {"args": ["server.js"]}
        assert factory.validate_config(config) is False
    
    def test_validate_config_sse_valid(self, factory):
        """Test config validation for valid SSE config."""
        config = {"url": "https://api.example.com/sse"}
        assert factory.validate_config(config) is True
    
    def test_validate_config_sse_missing_url(self, factory):
        """Test config validation for SSE config missing URL."""
        config = {"headers": {"Authorization": "Bearer token"}}
        assert factory.validate_config(config) is False
    
    def test_validate_config_http_valid_base_url(self, factory):
        """Test config validation for valid HTTP config with base_url."""
        config = {"base_url": "https://api.example.com/mcp"}
        assert factory.validate_config(config) is True
    
    def test_validate_config_http_valid_url(self, factory):
        """Test config validation for valid HTTP config with url."""
        config = {"url": "https://api.example.com/mcp"}
        assert factory.validate_config(config) is True
    
    def test_validate_config_http_missing_url(self, factory):
        """Test config validation for HTTP config missing URL."""
        config = {"auth": {"bearer_token": "token"}}
        assert factory.validate_config(config) is False
    
    def test_get_supported_transports(self, factory):
        """Test getting supported transport types."""
        transports = factory.get_supported_transports()
        
        assert TransportType.STDIO in transports
        assert TransportType.SSE in transports
        assert TransportType.HTTP in transports
        assert len(transports) == 3
    
    def test_register_handler(self, factory):
        """Test registering a new handler."""
        # Create a mock transport type and handler
        mock_transport = Mock()
        mock_transport.value = "custom"
        mock_handler_class = Mock(spec=BaseTransportHandler)
        
        factory.register_handler(mock_transport, mock_handler_class)
        
        assert mock_transport in factory._handlers
        assert factory._handlers[mock_transport] == mock_handler_class
    
    @pytest.mark.asyncio
    async def test_test_connection_success(self, factory):
        """Test successful connection test."""
        config = {"command": "node", "args": ["server.js"]}
        
        with patch.object(factory, 'create_from_config') as mock_create:
            mock_handler = Mock()
            mock_handler.test_connection = Mock(return_value=True)
            mock_create.return_value = mock_handler
            
            result = await factory.test_connection(config)
            
            assert result is True
            mock_create.assert_called_once_with(config)
            mock_handler.test_connection.assert_called_once_with(**config)
    
    @pytest.mark.asyncio
    async def test_test_connection_failure(self, factory):
        """Test connection test failure."""
        config = {"url": "https://api.example.com/sse"}
        
        with patch.object(factory, 'create_from_config') as mock_create:
            mock_handler = Mock()
            mock_handler.test_connection = Mock(side_effect=Exception("Connection failed"))
            mock_create.return_value = mock_handler
            
            result = await factory.test_connection(config)
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_test_connection_invalid_config(self, factory):
        """Test connection test with invalid config."""
        config = {"invalid": "config"}
        
        result = await factory.test_connection(config)
        assert result is False
    
    def test_repr(self, factory):
        """Test string representation."""
        repr_str = repr(factory)
        assert "TransportFactory" in repr_str
        assert "handlers=3" in repr_str


class TestTransportFactoryFunctions:
    """Test cases for module-level factory functions."""
    
    def test_create_transport_handler_stdio(self):
        """Test creating stdio handler via module function."""
        handler = create_transport_handler("stdio", timeout=25.0)
        
        assert isinstance(handler, StdioTransportHandler)
        assert handler.timeout == 25.0
    
    def test_create_transport_handler_sse_enum(self):
        """Test creating SSE handler via module function with enum."""
        handler = create_transport_handler(TransportType.SSE, max_retries=5)
        
        assert isinstance(handler, SSETransportHandler)
        assert handler.max_retries == 5
    
    def test_create_transport_handler_invalid(self):
        """Test creating handler with invalid type via module function."""
        with pytest.raises(TransportError):
            create_transport_handler("invalid")
    
    def test_create_from_config_stdio(self):
        """Test creating handler from config via module function."""
        config = {"command": "python", "args": ["server.py"]}
        handler = create_from_config(config)
        
        assert isinstance(handler, StdioTransportHandler)
    
    def test_create_from_config_http(self):
        """Test creating HTTP handler from config via module function."""
        config = {"base_url": "https://api.example.com/mcp"}
        handler = create_from_config(config)
        
        assert isinstance(handler, StreamableHTTPTransportHandler)


class TestTransportFactoryIntegration:
    """Integration tests for transport factory."""
    
    @pytest.fixture
    def factory(self):
        """Create a factory for integration tests."""
        return TransportFactory()
    
    def test_full_stdio_workflow(self, factory):
        """Test complete stdio workflow."""
        config = {
            "command": "node",
            "args": ["--version"],
            "timeout": 10.0,
            "max_retries": 2
        }
        
        # Validate config
        assert factory.validate_config(config) is True
        
        # Auto-detect transport
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO
        
        # Create handler
        handler = factory.create_from_config(config)
        assert isinstance(handler, StdioTransportHandler)
        assert handler.timeout == 10.0
        assert handler.max_retries == 2
    
    def test_full_sse_workflow(self, factory):
        """Test complete SSE workflow."""
        config = {
            "url": "https://api.example.com/events",
            "timeout": 15.0,
            "retry_delay": 0.5
        }
        
        # Validate config
        assert factory.validate_config(config) is True
        
        # Auto-detect transport
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.SSE
        
        # Create handler
        handler = factory.create_from_config(config)
        assert isinstance(handler, SSETransportHandler)
        assert handler.timeout == 15.0
        assert handler.retry_delay == 0.5
    
    def test_full_http_workflow(self, factory):
        """Test complete HTTP workflow."""
        config = {
            "base_url": "https://api.example.com/mcp",
            "timeout": 30.0,
            "max_retries": 1
        }
        
        # Validate config
        assert factory.validate_config(config) is True
        
        # Auto-detect transport
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.HTTP
        
        # Create handler
        handler = factory.create_from_config(config)
        assert isinstance(handler, StreamableHTTPTransportHandler)
        assert handler.timeout == 30.0
        assert handler.max_retries == 1
    
    def test_config_priority_explicit_transport(self, factory):
        """Test that explicit transport type takes priority."""
        config = {
            "transport": "http",  # Explicit HTTP
            "command": "node",    # Would normally indicate stdio
            "base_url": "https://api.example.com/mcp"
        }
        
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.HTTP
        
        handler = factory.create_from_config(config)
        assert isinstance(handler, StreamableHTTPTransportHandler)
    
    def test_fallback_behavior(self, factory):
        """Test fallback behavior with minimal config."""
        config = {"some_random_key": "value"}
        
        # Should fallback to stdio
        transport_type = factory.auto_detect_transport(config)
        assert transport_type == TransportType.STDIO
        
        # Should create stdio handler
        handler = factory.create_from_config(config)
        assert isinstance(handler, StdioTransportHandler)
        
        # Config validation should fail for stdio without command
        assert factory.validate_config(config) is False


if __name__ == "__main__":
    pytest.main([__file__]) 