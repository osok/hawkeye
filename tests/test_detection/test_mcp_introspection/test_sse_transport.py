"""
Unit tests for SSE Transport Handler

Tests for the SSETransportHandler class that manages connections to
HTTP-based MCP servers using Server-Sent Events.
"""

import pytest
import asyncio
import logging
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.hawkeye.detection.mcp_introspection.transport.sse import SSETransportHandler
from src.hawkeye.detection.mcp_introspection.transport.base import (
    ConnectionFailedError, 
    TransportError
)


class TestSSETransportHandler:
    """Test cases for SSETransportHandler."""
    
    @pytest.fixture
    def handler(self):
        """Create a test SSE transport handler."""
        logger = logging.getLogger("test_sse_handler")
        return SSETransportHandler(
            timeout=10.0,
            max_retries=2,
            retry_delay=0.1,
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
        assert handler.timeout == 10.0
        assert handler.max_retries == 2
        assert handler.retry_delay == 0.1
        assert handler._url is None
        assert handler._headers == {}
        assert handler._session_connector is None
    
    def test_validate_url_valid_http(self, handler):
        """Test URL validation with valid HTTP URLs."""
        valid_urls = [
            "http://localhost:8080/sse",
            "https://api.example.com/mcp/events",
            "http://192.168.1.100:3000/stream",
            "https://10.0.0.1:8443/sse"
        ]
        
        for url in valid_urls:
            assert handler._validate_url(url), f"Should accept valid URL: {url}"
    
    def test_validate_url_invalid_scheme(self, handler):
        """Test URL validation with invalid schemes."""
        invalid_urls = [
            "ftp://example.com/sse",
            "ws://example.com/sse",
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
    
    def test_validate_url_malformed(self, handler):
        """Test URL validation with malformed URLs."""
        invalid_urls = [
            "not-a-url",
            "http://",
            "://missing-scheme",
            ""
        ]
        
        for url in invalid_urls:
            assert not handler._validate_url(url), f"Should reject malformed URL: {url}"
    
    @pytest.mark.asyncio
    async def test_create_session_success(self, handler):
        """Test successful session creation."""
        with patch('aiohttp.TCPConnector') as mock_connector:
            mock_connector_instance = Mock()
            mock_connector.return_value = mock_connector_instance
            
            session = await handler._create_session(
                url="https://api.example.com/sse",
                headers={"Authorization": "Bearer token"},
                verify_ssl=True
            )
            
            assert session is not None
            assert handler._url == "https://api.example.com/sse"
            assert handler._headers == {"Authorization": "Bearer token"}
            assert handler._session_connector == mock_connector_instance
            
            mock_connector.assert_called_once_with(
                verify_ssl=True,
                limit=10,
                limit_per_host=5,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
    
    @pytest.mark.asyncio
    async def test_create_session_no_url(self, handler):
        """Test session creation without URL."""
        with pytest.raises(ConnectionFailedError, match="URL is required"):
            await handler._create_session()
    
    @pytest.mark.asyncio
    async def test_create_session_invalid_url(self, handler):
        """Test session creation with invalid URL."""
        with pytest.raises(ConnectionFailedError, match="Invalid URL format"):
            await handler._create_session(url="invalid-url")
    
    @pytest.mark.asyncio
    async def test_create_session_connection_error(self, handler):
        """Test session creation with connection error."""
        with patch('aiohttp.TCPConnector') as mock_connector:
            mock_connector.side_effect = Exception("Connection failed")
            
            with pytest.raises(ConnectionFailedError, match="Failed to create SSE session"):
                await handler._create_session(url="https://api.example.com/sse")
    
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
                url="https://api.example.com/sse",
                headers={"Authorization": "Bearer token"}
            )
            
            assert result is True
            mock_create.assert_called_once_with(
                url="https://api.example.com/sse",
                headers={"Authorization": "Bearer token"}
            )
            mock_cleanup.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_test_connection_failure(self, handler):
        """Test connection test failure."""
        with patch.object(handler, '_create_session') as mock_create, \
             patch.object(handler, '_cleanup_session') as mock_cleanup:
            
            mock_create.side_effect = ConnectionFailedError("Connection failed")
            
            result = await handler.test_connection(url="https://api.example.com/sse")
            
            assert result is False
            mock_cleanup.assert_called_once()
    
    def test_get_server_info(self, handler):
        """Test getting server information."""
        handler._url = "https://api.example.com/sse"
        handler._headers = {"Authorization": "Bearer token"}
        
        info = handler.get_server_info()
        
        expected = {
            'transport_type': 'sse',
            'url': 'https://api.example.com/sse',
            'headers': {"Authorization": "Bearer token"},
            'connected': False,
            'timeout': 10.0,
            'max_retries': 2
        }
        
        assert info == expected
    
    @pytest.mark.asyncio
    async def test_connect_success(self, handler):
        """Test successful connection."""
        with patch.object(handler, '_create_session') as mock_create:
            mock_session = AsyncMock()
            mock_create.return_value = mock_session
            
            await handler.connect(
                url="https://api.example.com/sse",
                headers={"Authorization": "Bearer token"}
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
                await handler.connect(url="https://api.example.com/sse")
            
            assert not handler.is_connected
    
    def test_repr(self, handler):
        """Test string representation."""
        handler._url = "https://api.example.com/sse"
        
        repr_str = repr(handler)
        assert "SSETransportHandler" in repr_str
        assert "https://api.example.com/sse" in repr_str
        assert "connected=False" in repr_str


class TestSSETransportHandlerIntegration:
    """Integration tests for SSE transport handler."""
    
    @pytest.fixture
    def handler(self):
        """Create a test handler for integration tests."""
        return SSETransportHandler(timeout=5.0, max_retries=1, retry_delay=0.1)
    
    @pytest.mark.asyncio
    async def test_full_connection_lifecycle(self, handler):
        """Test complete connection lifecycle."""
        with patch('aiohttp.TCPConnector') as mock_connector:
            mock_connector_instance = AsyncMock()
            mock_connector.return_value = mock_connector_instance
            
            # Test connection
            await handler.connect(url="https://api.example.com/sse")
            assert handler.is_connected
            
            # Test health check
            health = await handler.health_check()
            assert health is True
            
            # Test disconnect
            await handler.disconnect()
            assert not handler.is_connected
            
            # Verify cleanup was called
            mock_connector_instance.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connection_with_proxy(self, handler):
        """Test connection with proxy configuration."""
        await handler.connect(
            url="https://api.example.com/sse",
            proxy="http://proxy.example.com:8080"
        )
        
        # Verify connection was successful
        assert handler.is_connected
        assert handler._url == "https://api.example.com/sse"
    
    @pytest.mark.asyncio
    async def test_connection_with_ssl_disabled(self, handler):
        """Test connection with SSL verification disabled."""
        with patch('aiohttp.TCPConnector') as mock_connector:
            mock_connector.return_value = Mock()
            
            await handler.connect(
                url="http://api.example.com/sse",
                verify_ssl=False
            )
            
            # Verify SSL verification was disabled
            mock_connector.assert_called_once()
            call_args = mock_connector.call_args
            assert call_args[1]['verify_ssl'] is False


if __name__ == "__main__":
    pytest.main([__file__]) 