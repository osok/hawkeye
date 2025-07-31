"""
Unit tests for base transport handler.

Tests the abstract base class functionality, error handling, and connection management.
"""

import asyncio
import logging
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any, Dict

from mcp import ClientSession

from src.hawkeye.detection.mcp_introspection.transport.base import (
    BaseTransportHandler,
    TransportError,
    ConnectionTimeoutError,
    ConnectionFailedError,
)


class MockTransportHandler(BaseTransportHandler):
    """Mock implementation of BaseTransportHandler for testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.create_session_called = False
        self.cleanup_session_called = False
        self.should_fail_connection = False
        self.should_timeout = False
        self.mock_session = AsyncMock(spec=ClientSession)
    
    async def _create_session(self, **kwargs) -> ClientSession:
        """Mock implementation of session creation."""
        self.create_session_called = True
        
        if self.should_timeout:
            await asyncio.sleep(100)  # Simulate timeout
        
        if self.should_fail_connection:
            raise ConnectionError("Mock connection failed")
        
        return self.mock_session
    
    async def _cleanup_session(self) -> None:
        """Mock implementation of session cleanup."""
        self.cleanup_session_called = True


class TestBaseTransportHandler:
    """Test cases for BaseTransportHandler."""
    
    @pytest.fixture
    def handler(self):
        """Create a mock transport handler for testing."""
        return MockTransportHandler(
            timeout=5.0,
            max_retries=2,
            retry_delay=0.1,
            logger=logging.getLogger("test")
        )
    
    @pytest.fixture
    def failing_handler(self):
        """Create a handler that fails connections."""
        handler = MockTransportHandler(timeout=5.0, max_retries=2, retry_delay=0.1)
        handler.should_fail_connection = True
        return handler
    
    @pytest.fixture
    def timeout_handler(self):
        """Create a handler that times out."""
        handler = MockTransportHandler(timeout=0.1, max_retries=1, retry_delay=0.1)
        handler.should_timeout = True
        return handler
    
    def test_initialization(self, handler):
        """Test handler initialization."""
        assert handler.timeout == 5.0
        assert handler.max_retries == 2
        assert handler.retry_delay == 0.1
        assert not handler.is_connected
        assert handler._session is None
        assert not handler._connected
    
    def test_is_connected_property(self, handler):
        """Test the is_connected property."""
        # Initially not connected
        assert not handler.is_connected
        
        # Set session but not connected flag
        handler._session = MagicMock()
        assert not handler.is_connected
        
        # Set both session and connected flag
        handler._connected = True
        assert handler.is_connected
        
        # Remove session
        handler._session = None
        assert not handler.is_connected
    
    @pytest.mark.asyncio
    async def test_successful_connection(self, handler):
        """Test successful connection establishment."""
        await handler.connect(test_param="value")
        
        assert handler.is_connected
        assert handler.create_session_called
        assert handler._session is not None
        assert handler._connected
    
    @pytest.mark.asyncio
    async def test_connection_already_connected(self, handler):
        """Test connection when already connected."""
        # First connection
        await handler.connect()
        assert handler.is_connected
        
        # Reset the flag to check if create_session is called again
        handler.create_session_called = False
        
        # Second connection attempt
        await handler.connect()
        assert handler.is_connected
        # Should not create session again
        assert not handler.create_session_called
    
    @pytest.mark.asyncio
    async def test_connection_failure_with_retries(self, failing_handler):
        """Test connection failure with retry logic."""
        with pytest.raises(ConnectionFailedError) as exc_info:
            await failing_handler.connect()
        
        assert "Connection failed" in str(exc_info.value)
        assert not failing_handler.is_connected
    
    @pytest.mark.asyncio
    async def test_connection_timeout(self, timeout_handler):
        """Test connection timeout."""
        with pytest.raises(ConnectionTimeoutError) as exc_info:
            await timeout_handler.connect()
        
        assert "timed out" in str(exc_info.value)
        assert not timeout_handler.is_connected
    
    @pytest.mark.asyncio
    async def test_disconnect_when_connected(self, handler):
        """Test disconnection when connected."""
        # First connect
        await handler.connect()
        assert handler.is_connected
        
        # Then disconnect
        await handler.disconnect()
        assert not handler.is_connected
        assert handler.cleanup_session_called
        assert handler._session is None
        assert not handler._connected
    
    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, handler):
        """Test disconnection when not connected."""
        # Should not raise error
        await handler.disconnect()
        assert not handler.is_connected
        assert not handler.cleanup_session_called
    
    @pytest.mark.asyncio
    async def test_disconnect_with_cleanup_error(self, handler):
        """Test disconnection when cleanup raises error."""
        await handler.connect()
        
        # Make cleanup raise an error
        async def failing_cleanup():
            raise Exception("Cleanup failed")
        
        handler._cleanup_session = failing_cleanup
        
        # Should not raise error, but should still clean up state
        await handler.disconnect()
        assert not handler.is_connected
        assert handler._session is None
        assert not handler._connected
    
    @pytest.mark.asyncio
    async def test_session_context_manager(self, handler):
        """Test session context manager."""
        async with handler.session_context(test_param="value") as session:
            assert handler.is_connected
            assert session is handler._session
            assert handler.create_session_called
        
        # After context, should be disconnected
        assert not handler.is_connected
        assert handler.cleanup_session_called
    
    @pytest.mark.asyncio
    async def test_session_context_manager_with_exception(self, handler):
        """Test session context manager when exception occurs."""
        with pytest.raises(ValueError):
            async with handler.session_context() as session:
                assert handler.is_connected
                raise ValueError("Test exception")
        
        # Should still clean up after exception
        assert not handler.is_connected
        assert handler.cleanup_session_called
    
    @pytest.mark.asyncio
    async def test_send_message_when_connected(self, handler):
        """Test sending message when connected."""
        await handler.connect()
        
        # send_message is not implemented in base class
        with pytest.raises(NotImplementedError):
            await handler.send_message({"test": "message"})
    
    @pytest.mark.asyncio
    async def test_send_message_when_not_connected(self, handler):
        """Test sending message when not connected."""
        with pytest.raises(ConnectionFailedError) as exc_info:
            await handler.send_message({"test": "message"})
        
        assert "Not connected" in str(exc_info.value)
    
    def test_get_connection_info(self, handler):
        """Test getting connection information."""
        info = handler.get_connection_info()
        
        expected_keys = {
            "connected", "timeout", "max_retries", 
            "retry_delay", "transport_type"
        }
        assert set(info.keys()) == expected_keys
        assert info["connected"] == handler.is_connected
        assert info["timeout"] == handler.timeout
        assert info["max_retries"] == handler.max_retries
        assert info["retry_delay"] == handler.retry_delay
        assert info["transport_type"] == "MockTransportHandler"
    
    @pytest.mark.asyncio
    async def test_connection_retry_with_exponential_backoff(self):
        """Test connection retry with exponential backoff."""
        handler = MockTransportHandler(timeout=5.0, max_retries=3, retry_delay=0.1)
        
        call_times = []
        original_create_session = handler._create_session
        
        async def timed_create_session(**kwargs):
            call_times.append(asyncio.get_event_loop().time())
            if len(call_times) < 3:  # Fail first 2 attempts
                raise ConnectionError("Mock failure")
            return await original_create_session(**kwargs)
        
        handler._create_session = timed_create_session
        
        await handler.connect()
        
        # Should have made 3 attempts
        assert len(call_times) == 3
        assert handler.is_connected
        
        # Check exponential backoff timing (approximately)
        if len(call_times) >= 3:
            delay1 = call_times[1] - call_times[0]
            delay2 = call_times[2] - call_times[1]
            
            # Second delay should be roughly double the first
            # Allow some tolerance for timing variations
            assert delay2 > delay1 * 1.5
    
    @pytest.mark.asyncio
    async def test_multiple_concurrent_connections(self, handler):
        """Test handling multiple concurrent connection attempts."""
        # Start multiple connection attempts concurrently
        tasks = [handler.connect() for _ in range(5)]
        
        # All should complete successfully
        await asyncio.gather(*tasks)
        
        assert handler.is_connected
        # Should only create session once
        assert handler.create_session_called
    
    def test_custom_logger(self):
        """Test using custom logger."""
        custom_logger = logging.getLogger("custom_test_logger")
        handler = MockTransportHandler(logger=custom_logger)
        
        assert handler.logger is custom_logger
    
    def test_default_logger(self):
        """Test default logger creation."""
        handler = MockTransportHandler()
        
        assert handler.logger is not None
        assert handler.logger.name == "MockTransportHandler"


class TestTransportErrors:
    """Test cases for transport error classes."""
    
    def test_transport_error_base(self):
        """Test base TransportError."""
        error = TransportError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)
    
    def test_connection_timeout_error(self):
        """Test ConnectionTimeoutError."""
        error = ConnectionTimeoutError("Timeout occurred")
        assert str(error) == "Timeout occurred"
        assert isinstance(error, TransportError)
    
    def test_connection_failed_error(self):
        """Test ConnectionFailedError."""
        error = ConnectionFailedError("Connection failed")
        assert str(error) == "Connection failed"
        assert isinstance(error, TransportError)


@pytest.mark.asyncio
async def test_abstract_methods_not_implemented():
    """Test that abstract methods raise NotImplementedError."""
    # Cannot instantiate abstract class directly
    with pytest.raises(TypeError):
        BaseTransportHandler()


class TestTransportHandlerEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.mark.asyncio
    async def test_connection_with_zero_retries(self):
        """Test connection with zero retries."""
        handler = MockTransportHandler(max_retries=0, retry_delay=0.1)
        handler.should_fail_connection = True
        
        with pytest.raises(ConnectionFailedError):
            await handler.connect()
    
    @pytest.mark.asyncio
    async def test_very_short_timeout(self):
        """Test with very short timeout."""
        handler = MockTransportHandler(timeout=0.001, max_retries=1)
        handler.should_timeout = True
        
        with pytest.raises(ConnectionTimeoutError):
            await handler.connect()
    
    def test_invalid_initialization_parameters(self):
        """Test initialization with invalid parameters."""
        # These should work due to Pydantic validation in settings
        # but we test the handler directly
        handler = MockTransportHandler(
            timeout=-1,  # Invalid but not validated in handler
            max_retries=-1,
            retry_delay=-1
        )
        
        # Handler should still be created
        assert handler.timeout == -1
        assert handler.max_retries == -1
        assert handler.retry_delay == -1 