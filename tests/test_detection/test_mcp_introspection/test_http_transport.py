"""
Unit tests for HTTP Transport Handler

Tests for the StreamableHTTPTransportHandler class that manages connections to
production MCP servers using HTTP with streaming support.
"""

import pytest
import asyncio
import logging
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.hawkeye.detection.mcp_introspection.transport.http import StreamableHTTPTransportHandler
from src.hawkeye.detection.mcp_introspection.transport.base import (
    ConnectionFailedError, 
    TransportError
)


class TestStreamableHTTPTransportHandler:
    """Test cases for StreamableHTTPTransportHandler."""
    
    @pytest.fixture
    def handler(self):
        """Create a test HTTP transport handler."""
        logger = logging.getLogger("test_http_handler")
        return StreamableHTTPTransportHandler(
            timeout=15.0,
            max_retries=3,
            retry_delay=0.2,
            logger=logger
        )
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock MCP client session."""
        session = AsyncMock()
        session.initialize = AsyncMock()
        session.close = AsyncMock()
        return session
    
    def test_init(self, handler):
        """Test handler initialization."""
        assert handler.timeout == 15.0
        assert handler.max_retries == 3
        assert handler.retry_delay == 0.2
        assert handler._base_url is None
        assert handler._headers == {}
        assert handler._auth == {}
        assert handler._session_connector is None
        assert handler._streaming_enabled is False
    
    def test_validate_url_valid_http(self, handler):
        """Test URL validation with valid HTTP URLs."""
        valid_urls = [
            "http://localhost:8080/api",
            "https://api.example.com/mcp",
            "http://192.168.1.100:3000/v1",
            "https://10.0.0.1:8443/mcp/v2"
        ]
        
        for url in valid_urls:
            assert handler._validate_url(url), f"Should accept valid URL: {url}"
    
    def test_validate_url_invalid_scheme(self, handler):
        """Test URL validation with invalid schemes."""
        invalid_urls = [
            "ftp://example.com/api",
            "ws://example.com/api",
            "file:///path/to/file",
            "mailto:test@example.com"
        ]
        
        for url in invalid_urls:
            assert not handler._validate_url(url), f"Should reject invalid URL: {url}"
    
    def test_validate_url_missing_hostname(self, handler):
        """Test URL validation with missing hostname."""
        invalid_urls = [
            "http:///path",
            "https://",
            "http://:8080/path"
        ]
        
        for url in invalid_urls:
            assert not handler._validate_url(url), f"Should reject URL without hostname: {url}"
    
    def test_prepare_auth_headers_bearer_token(self, handler):
        """Test authentication header preparation with bearer token."""
        auth = {"bearer_token": "test-token-123"}
        headers = handler._prepare_auth_headers(auth)
        
        assert headers == {"Authorization": "Bearer test-token-123"}
    
    def test_prepare_auth_headers_api_key(self, handler):
        """Test authentication header preparation with API key."""
        auth = {"api_key": "api-key-456", "api_key_header": "X-API-Key"}
        headers = handler._prepare_auth_headers(auth)
        
        assert headers == {"X-API-Key": "api-key-456"}
    
    def test_prepare_auth_headers_api_key_default_header(self, handler):
        """Test authentication header preparation with API key using default header."""
        auth = {"api_key": "api-key-789"}
        headers = handler._prepare_auth_headers(auth)
        
        assert headers == {"X-API-Key": "api-key-789"}
    
    def test_prepare_auth_headers_custom_headers(self, handler):
        """Test authentication header preparation with custom headers."""
        auth = {"custom_headers": {"X-Custom-Auth": "custom-value", "X-Client-ID": "client-123"}}
        headers = handler._prepare_auth_headers(auth)
        
        expected = {"X-Custom-Auth": "custom-value", "X-Client-ID": "client-123"}
        assert headers == expected
    
    def test_prepare_auth_headers_empty(self, handler):
        """Test authentication header preparation with empty auth."""
        headers = handler._prepare_auth_headers({})
        assert headers == {}
    
    @pytest.mark.asyncio
    async def test_create_session_success(self, handler):
        """Test successful session creation."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client, \
             patch('aiohttp.TCPConnector') as mock_connector:
            
            mock_session = AsyncMock()
            mock_http_client.return_value = mock_session
            mock_connector_instance = Mock()
            mock_connector.return_value = mock_connector_instance
            
            session = await handler._create_session(
                base_url="https://api.example.com/mcp",
                headers={"Content-Type": "application/json"},
                auth={"bearer_token": "test-token"},
                verify_ssl=True,
                streaming=True
            )
            
            assert session == mock_session
            assert handler._base_url == "https://api.example.com/mcp"
            assert handler._headers == {"Content-Type": "application/json"}
            assert handler._auth == {"bearer_token": "test-token"}
            assert handler._streaming_enabled is True
            assert handler._session_connector == mock_connector_instance
            
            mock_http_client.assert_called_once()
            mock_connector.assert_called_once_with(
                verify_ssl=True,
                limit=20,
                limit_per_host=10,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=60,
                enable_cleanup_closed=True
            )
    
    @pytest.mark.asyncio
    async def test_create_session_no_base_url(self, handler):
        """Test session creation without base URL."""
        with pytest.raises(ConnectionFailedError, match="Base URL is required"):
            await handler._create_session()
    
    @pytest.mark.asyncio
    async def test_create_session_invalid_url(self, handler):
        """Test session creation with invalid URL."""
        with pytest.raises(ConnectionFailedError, match="Invalid base URL format"):
            await handler._create_session(base_url="invalid-url")
    
    @pytest.mark.asyncio
    async def test_create_session_connection_error(self, handler):
        """Test session creation with connection error."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client:
            mock_http_client.side_effect = Exception("Connection failed")
            
            with pytest.raises(ConnectionFailedError, match="Failed to create HTTP session"):
                await handler._create_session(base_url="https://api.example.com/mcp")
    
    @pytest.mark.asyncio
    async def test_cleanup_session(self, handler, mock_session):
        """Test session cleanup."""
        mock_connector = AsyncMock()
        handler._session = mock_session
        handler._session_connector = mock_connector
        
        await handler._cleanup_session()
        
        mock_session.close.assert_called_once()
        mock_connector.close.assert_called_once()
        assert handler._session_connector is None
    
    @pytest.mark.asyncio
    async def test_cleanup_session_error(self, handler, mock_session):
        """Test session cleanup with error."""
        mock_session.close.side_effect = Exception("Cleanup error")
        handler._session = mock_session
        
        # Should not raise exception
        await handler._cleanup_session()
        mock_session.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_not_connected(self, handler):
        """Test health check when not connected."""
        assert not await handler.health_check()
    
    @pytest.mark.asyncio
    async def test_health_check_connected_success(self, handler, mock_session):
        """Test successful health check when connected."""
        handler._session = mock_session
        handler._connected = True
        
        result = await handler.health_check()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_health_check_connected_with_initialize(self, handler, mock_session):
        """Test health check with initialize method."""
        handler._session = mock_session
        handler._connected = True
        mock_session.initialize = AsyncMock()
        
        result = await handler.health_check()
        assert result is True
        mock_session.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_error(self, handler, mock_session):
        """Test health check with error."""
        handler._session = mock_session
        handler._connected = True
        mock_session.initialize = AsyncMock(side_effect=Exception("Health check failed"))
        
        result = await handler.health_check()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_test_connection_success(self, handler):
        """Test successful connection test."""
        with patch.object(handler, '_create_session') as mock_create, \
             patch.object(handler, '_cleanup_session') as mock_cleanup:
            
            mock_session = AsyncMock()
            mock_create.return_value = mock_session
            
            result = await handler.test_connection(
                base_url="https://api.example.com/mcp",
                headers={"Content-Type": "application/json"},
                auth={"bearer_token": "test-token"}
            )
            
            assert result is True
            mock_create.assert_called_once_with(
                base_url="https://api.example.com/mcp",
                headers={"Content-Type": "application/json"},
                auth={"bearer_token": "test-token"}
            )
            mock_cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_test_connection_failure(self, handler):
        """Test connection test failure."""
        with patch.object(handler, '_create_session') as mock_create, \
             patch.object(handler, '_cleanup_session') as mock_cleanup:
            
            mock_create.side_effect = ConnectionFailedError("Connection failed")
            
            result = await handler.test_connection(base_url="https://api.example.com/mcp")
            
            assert result is False
            mock_cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_discover_endpoints(self, handler):
        """Test endpoint discovery."""
        with patch('aiohttp.ClientSession') as mock_client_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "endpoints": ["/mcp/v1", "/mcp/v2", "/health"]
            }
            
            mock_session = AsyncMock()
            mock_session.get.return_value.__aenter__.return_value = mock_response
            mock_client_session.return_value.__aenter__.return_value = mock_session
            
            endpoints = await handler.discover_endpoints("https://api.example.com")
            
            expected = [
                "https://api.example.com/mcp/v1",
                "https://api.example.com/mcp/v2",
                "https://api.example.com/health"
            ]
            assert endpoints == expected
    
    @pytest.mark.asyncio
    async def test_discover_endpoints_error(self, handler):
        """Test endpoint discovery with error."""
        with patch('aiohttp.ClientSession') as mock_client_session:
            mock_session = AsyncMock()
            mock_session.get.side_effect = Exception("Discovery failed")
            mock_client_session.return_value.__aenter__.return_value = mock_session
            
            endpoints = await handler.discover_endpoints("https://api.example.com")
            assert endpoints == []
    
    def test_get_server_info(self, handler):
        """Test getting server information."""
        handler._base_url = "https://api.example.com/mcp"
        handler._headers = {"Content-Type": "application/json"}
        handler._auth = {"bearer_token": "test-token"}
        handler._streaming_enabled = True
        
        info = handler.get_server_info()
        
        expected = {
            'transport_type': 'http',
            'base_url': 'https://api.example.com/mcp',
            'headers': {"Content-Type": "application/json"},
            'auth_configured': True,
            'streaming_enabled': True,
            'connected': False,
            'timeout': 15.0,
            'max_retries': 3
        }
        
        assert info == expected
    
    def test_get_server_info_no_auth(self, handler):
        """Test getting server information without auth."""
        handler._base_url = "https://api.example.com/mcp"
        
        info = handler.get_server_info()
        assert info['auth_configured'] is False
    
    @pytest.mark.asyncio
    async def test_connect_success(self, handler):
        """Test successful connection."""
        with patch.object(handler, '_create_session') as mock_create:
            mock_session = AsyncMock()
            mock_create.return_value = mock_session
            
            await handler.connect(
                base_url="https://api.example.com/mcp",
                headers={"Content-Type": "application/json"},
                auth={"bearer_token": "test-token"}
            )
            
            assert handler.is_connected
            assert handler._session == mock_session
            mock_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_failure(self, handler):
        """Test connection failure."""
        with patch.object(handler, '_create_session') as mock_create:
            mock_create.side_effect = ConnectionFailedError("Connection failed")
            
            with pytest.raises(ConnectionFailedError):
                await handler.connect(base_url="https://api.example.com/mcp")
            
            assert not handler.is_connected
    
    def test_repr(self, handler):
        """Test string representation."""
        handler._base_url = "https://api.example.com/mcp"
        handler._streaming_enabled = True
        
        repr_str = repr(handler)
        assert "StreamableHTTPTransportHandler" in repr_str
        assert "https://api.example.com/mcp" in repr_str
        assert "streaming=True" in repr_str
        assert "connected=False" in repr_str


class TestStreamableHTTPTransportHandlerIntegration:
    """Integration tests for HTTP transport handler."""
    
    @pytest.fixture
    def handler(self):
        """Create a test handler for integration tests."""
        return StreamableHTTPTransportHandler(timeout=5.0, max_retries=1, retry_delay=0.1)
    
    @pytest.mark.asyncio
    async def test_full_connection_lifecycle(self, handler):
        """Test complete connection lifecycle."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client, \
             patch('aiohttp.TCPConnector') as mock_connector:
            
            mock_session = AsyncMock()
            mock_http_client.return_value = mock_session
            mock_connector_instance = AsyncMock()
            mock_connector.return_value = mock_connector_instance
            
            # Test connection
            await handler.connect(
                base_url="https://api.example.com/mcp",
                auth={"bearer_token": "test-token"}
            )
            assert handler.is_connected
            
            # Test health check
            health = await handler.health_check()
            assert health is True
            
            # Test disconnect
            await handler.disconnect()
            assert not handler.is_connected
            
            # Verify cleanup was called
            mock_session.close.assert_called_once()
            mock_connector_instance.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connection_with_streaming(self, handler):
        """Test connection with streaming enabled."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client:
            mock_session = AsyncMock()
            mock_http_client.return_value = mock_session
            
            await handler.connect(
                base_url="https://api.example.com/mcp",
                streaming=True
            )
            
            # Verify streaming was enabled
            call_args = mock_http_client.call_args
            assert call_args[1]['streaming'] is True
            assert handler._streaming_enabled is True
    
    @pytest.mark.asyncio
    async def test_connection_with_proxy(self, handler):
        """Test connection with proxy configuration."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client:
            mock_session = AsyncMock()
            mock_http_client.return_value = mock_session
            
            await handler.connect(
                base_url="https://api.example.com/mcp",
                proxy="http://proxy.example.com:8080"
            )
            
            # Verify proxy was passed to http_client
            call_args = mock_http_client.call_args
            assert call_args[1]['proxy'] == "http://proxy.example.com:8080"
    
    @pytest.mark.asyncio
    async def test_connection_with_ssl_disabled(self, handler):
        """Test connection with SSL verification disabled."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client, \
             patch('aiohttp.TCPConnector') as mock_connector:
            
            mock_session = AsyncMock()
            mock_http_client.return_value = mock_session
            
            await handler.connect(
                base_url="http://api.example.com/mcp",
                verify_ssl=False
            )
            
            # Verify SSL verification was disabled
            mock_connector.assert_called_once()
            call_args = mock_connector.call_args
            assert call_args[1]['verify_ssl'] is False
    
    @pytest.mark.asyncio
    async def test_authentication_integration(self, handler):
        """Test authentication integration."""
        with patch('src.hawkeye.detection.mcp_introspection.transport.http.streamablehttp_client') as mock_http_client:
            mock_session = AsyncMock()
            mock_http_client.return_value = mock_session
            
            await handler.connect(
                base_url="https://api.example.com/mcp",
                headers={"Content-Type": "application/json"},
                auth={
                    "bearer_token": "test-token",
                    "custom_headers": {"X-Client-ID": "client-123"}
                }
            )
            
            # Verify auth headers were merged correctly
            call_args = mock_http_client.call_args
            headers = call_args[1]['headers']
            
            assert headers["Content-Type"] == "application/json"
            assert headers["Authorization"] == "Bearer test-token"
            assert headers["X-Client-ID"] == "client-123"


if __name__ == "__main__":
    pytest.main([__file__]) 