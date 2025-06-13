"""
Unit tests for StdioTransportHandler

Tests the stdio transport handler functionality including connection management,
command validation, and error handling.
"""

import pytest
import asyncio
import logging
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from src.hawkeye.detection.mcp_introspection.transport.stdio import StdioTransportHandler
from src.hawkeye.detection.mcp_introspection.transport.base import (
    ConnectionFailedError,
    ConnectionTimeoutError,
)


class TestStdioTransportHandler:
    """Test cases for StdioTransportHandler."""
    
    @pytest.fixture
    def handler(self):
        """Create a stdio transport handler for testing."""
        return StdioTransportHandler(
            timeout=5.0,
            max_retries=2,
            retry_delay=0.1,
            logger=logging.getLogger("test")
        )
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock MCP client session."""
        session = AsyncMock()
        session.close = AsyncMock()
        session.initialize = AsyncMock()
        return session
    
    def test_init(self, handler):
        """Test handler initialization."""
        assert handler.timeout == 5.0
        assert handler.max_retries == 2
        assert handler.retry_delay == 0.1
        assert not handler.is_connected
        assert handler._process is None
        assert handler._server_params is None
    
    def test_validate_command_valid(self, handler):
        """Test command validation with valid commands."""
        # Valid commands
        assert handler._validate_command("node", ["server.js"])
        assert handler._validate_command("python", ["-m", "server"])
        assert handler._validate_command("/usr/bin/node", ["app.js"])
    
    def test_validate_command_invalid(self, handler):
        """Test command validation with invalid commands."""
        # Empty command
        assert not handler._validate_command("", [])
        assert not handler._validate_command("   ", [])
        
        # Dangerous patterns in command
        assert not handler._validate_command("rm -rf /", [])
        assert not handler._validate_command("node; rm file", [])
        
        # Dangerous patterns in arguments
        assert not handler._validate_command("node", ["server.js", "; rm file"])
        assert not handler._validate_command("python", ["-c", "eval('malicious')"])
    
    @patch('shutil.which')
    def test_validate_command_not_found(self, mock_which, handler):
        """Test command validation when command not found in PATH."""
        mock_which.return_value = None
        assert not handler._validate_command("nonexistent", [])
        mock_which.assert_called_once_with("nonexistent")
    
    @patch('os.access')
    @patch('pathlib.Path.exists')
    def test_validate_command_absolute_path(self, mock_exists, mock_access, handler):
        """Test command validation with absolute paths."""
        # Existing executable file
        mock_exists.return_value = True
        mock_access.return_value = True
        assert handler._validate_command("/usr/bin/node", [])
        
        # Non-existing file
        mock_exists.return_value = False
        assert not handler._validate_command("/nonexistent/command", [])
        
        # Existing but not executable
        mock_exists.return_value = True
        mock_access.return_value = False
        assert not handler._validate_command("/usr/bin/node", [])
    
    @pytest.mark.asyncio
    @patch('src.hawkeye.detection.mcp_introspection.transport.stdio.stdio_client')
    async def test_create_session_success(self, mock_stdio_client, handler, mock_session):
        """Test successful session creation."""
        mock_stdio_client.return_value = mock_session
        
        session = await handler._create_session(
            command="node",
            args=["server.js"],
            env={"NODE_ENV": "test"}
        )
        
        assert session == mock_session
        assert handler._server_params is not None
        assert handler._server_params.command == "node"
        assert handler._server_params.args == ["server.js"]
        mock_stdio_client.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_session_no_command(self, handler):
        """Test session creation without command."""
        with pytest.raises(ConnectionFailedError, match="Command is required"):
            await handler._create_session()
    
    @pytest.mark.asyncio
    @patch('src.hawkeye.detection.mcp_introspection.transport.stdio.stdio_client')
    async def test_create_session_failure(self, mock_stdio_client, handler):
        """Test session creation failure."""
        mock_stdio_client.side_effect = Exception("Connection failed")
        
        with pytest.raises(ConnectionFailedError, match="Failed to create stdio session"):
            await handler._create_session(command="node", args=["server.js"])
    
    @pytest.mark.asyncio
    async def test_cleanup_session(self, handler, mock_session):
        """Test session cleanup."""
        handler._session = mock_session
        
        await handler._cleanup_session()
        
        mock_session.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_session_error(self, handler, mock_session):
        """Test session cleanup with error."""
        handler._session = mock_session
        mock_session.close.side_effect = Exception("Cleanup error")
        
        # Should not raise exception
        await handler._cleanup_session()
        mock_session.close.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('src.hawkeye.detection.mcp_introspection.transport.stdio.stdio_client')
    async def test_connect_success(self, mock_stdio_client, handler, mock_session):
        """Test successful connection."""
        mock_stdio_client.return_value = mock_session
        
        await handler.connect(command="node", args=["server.js"])
        
        assert handler.is_connected
        assert handler._session == mock_session
    
    @pytest.mark.asyncio
    async def test_connect_validation_failure(self, handler):
        """Test connection with command validation failure."""
        with pytest.raises(ConnectionFailedError, match="Command validation failed"):
            await handler.connect(command="rm -rf /", args=[])
    
    @pytest.mark.asyncio
    async def test_connect_skip_validation(self, handler):
        """Test connection with validation skipped."""
        with patch.object(handler, '_create_session') as mock_create:
            mock_create.side_effect = ConnectionFailedError("Test error")
            
            with pytest.raises(ConnectionFailedError):
                await handler.connect(
                    command="rm -rf /",
                    args=[],
                    validate_command=False
                )
            
            mock_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_already_connected(self, handler, mock_session):
        """Test connection when already connected."""
        handler._session = mock_session
        handler._connected = True
        
        with patch.object(handler, '_create_session') as mock_create:
            await handler.connect(command="node", args=["server.js"])
            mock_create.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_disconnect(self, handler, mock_session):
        """Test disconnection."""
        handler._session = mock_session
        handler._connected = True
        
        await handler.disconnect()
        
        assert not handler.is_connected
        assert handler._session is None
        mock_session.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self, handler):
        """Test disconnection when not connected."""
        with patch.object(handler, '_cleanup_session') as mock_cleanup:
            await handler.disconnect()
            mock_cleanup.assert_not_called()
    
    @pytest.mark.asyncio
    @patch('src.hawkeye.detection.mcp_introspection.transport.stdio.stdio_client')
    async def test_session_context(self, mock_stdio_client, handler, mock_session):
        """Test session context manager."""
        mock_stdio_client.return_value = mock_session
        
        async with handler.session_context(command="node", args=["server.js"]) as session:
            assert session == mock_session
            assert handler.is_connected
        
        # Should be disconnected after context
        assert not handler.is_connected
        mock_session.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_not_connected(self, handler):
        """Test health check when not connected."""
        result = await handler.health_check()
        assert result is False
    
    @pytest.mark.asyncio
    async def test_health_check_connected(self, handler, mock_session):
        """Test health check when connected."""
        handler._session = mock_session
        handler._connected = True
        
        result = await handler.health_check()
        assert result is True
    
    @pytest.mark.asyncio
    async def test_health_check_with_initialize(self, handler, mock_session):
        """Test health check with initialize method."""
        handler._session = mock_session
        handler._connected = True
        mock_session.initialize = AsyncMock()
        
        result = await handler.health_check()
        assert result is True
        mock_session.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_initialize_failure(self, handler, mock_session):
        """Test health check when initialize fails."""
        handler._session = mock_session
        handler._connected = True
        mock_session.initialize = AsyncMock(side_effect=Exception("Initialize failed"))
        
        result = await handler.health_check()
        assert result is False
    
    def test_get_server_info_not_configured(self, handler):
        """Test get_server_info when not configured."""
        info = handler.get_server_info()
        assert info == {}
    
    def test_get_server_info_configured(self, handler):
        """Test get_server_info when configured."""
        from mcp import StdioServerParameters
        
        handler._server_params = StdioServerParameters(
            command="node",
            args=["server.js"],
            env={"NODE_ENV": "test"}
        )
        handler._connected = True
        
        info = handler.get_server_info()
        
        assert info['transport_type'] == 'stdio'
        assert info['command'] == 'node'
        assert info['args'] == ['server.js']
        assert info['env'] == {'NODE_ENV': 'test'}
        assert info['connected'] is True
    
    def test_repr_not_configured(self, handler):
        """Test string representation when not configured."""
        repr_str = repr(handler)
        assert repr_str == "StdioTransportHandler(not configured)"
    
    def test_repr_configured(self, handler):
        """Test string representation when configured."""
        from mcp import StdioServerParameters
        
        handler._server_params = StdioServerParameters(
            command="node",
            args=["server.js"]
        )
        
        repr_str = repr(handler)
        assert repr_str == "StdioTransportHandler(command='node')"
    
    @pytest.mark.asyncio
    async def test_connection_timeout(self, handler):
        """Test connection timeout handling."""
        with patch.object(handler, '_create_session') as mock_create:
            mock_create.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(ConnectionFailedError):
                await handler.connect(command="node", args=["server.js"])
    
    @pytest.mark.asyncio
    async def test_connection_retry(self, handler):
        """Test connection retry logic."""
        with patch.object(handler, '_create_session') as mock_create:
            # First call fails, second succeeds
            mock_session = AsyncMock()
            mock_create.side_effect = [Exception("First failure"), mock_session]
            
            await handler.connect(command="node", args=["server.js"])
            
            assert handler.is_connected
            assert mock_create.call_count == 2
    
    @pytest.mark.asyncio
    async def test_send_message_not_connected(self, handler):
        """Test sending message when not connected."""
        from mcp.types import JSONRPCMessage
        
        message = JSONRPCMessage(method="test", params={})
        
        with pytest.raises(ConnectionFailedError, match="Not connected"):
            await handler.send_message(message)
    
    def test_connection_info(self, handler):
        """Test get_connection_info method."""
        info = handler.get_connection_info()
        
        assert 'transport_type' in info
        assert 'timeout' in info
        assert 'max_retries' in info
        assert 'connected' in info
        assert info['transport_type'] == 'stdio'
        assert info['timeout'] == 5.0
        assert info['max_retries'] == 2
        assert info['connected'] is False 