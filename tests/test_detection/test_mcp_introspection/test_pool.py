"""
Unit tests for MCP introspection connection pooling.

Tests the ConnectionPool class and related functionality for managing
MCP client connections with proper lifecycle management, cleanup, and monitoring.
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection.transport.pool import (
    ConnectionPool,
    ConnectionInfo,
    PoolStats
)
from src.hawkeye.detection.mcp_introspection.transport.base import (
    BaseTransportHandler,
    ConnectionTimeoutError,
    ConnectionFailedError,
    TransportError
)


class TestPoolStats:
    """Test PoolStats data class."""
    
    def test_pool_stats_creation(self):
        """Test creating pool statistics."""
        stats = PoolStats(
            total_connections=10,
            active_connections=5,
            idle_connections=3,
            failed_connections=2,
            total_requests=100,
            successful_requests=95,
            failed_requests=5,
            average_response_time=0.5
        )
        
        assert stats.total_connections == 10
        assert stats.active_connections == 5
        assert stats.idle_connections == 3
        assert stats.failed_connections == 2
        assert stats.total_requests == 100
        assert stats.successful_requests == 95
        assert stats.failed_requests == 5
        assert stats.average_response_time == 0.5
        assert stats.created_at > 0
    
    def test_default_stats(self):
        """Test default statistics values."""
        stats = PoolStats()
        
        assert stats.total_connections == 0
        assert stats.active_connections == 0
        assert stats.idle_connections == 0
        assert stats.failed_connections == 0
        assert stats.total_requests == 0
        assert stats.successful_requests == 0
        assert stats.failed_requests == 0
        assert stats.average_response_time == 0.0
        assert stats.created_at > 0


class TestConnectionInfo:
    """Test ConnectionInfo data class."""
    
    def test_connection_info_creation(self):
        """Test creating connection info."""
        mock_handler = Mock(spec=BaseTransportHandler)
        created_time = time.time()
        
        conn_info = ConnectionInfo(
            handler=mock_handler,
            created_at=created_time,
            last_used=created_time
        )
        
        assert conn_info.handler == mock_handler
        assert conn_info.created_at == created_time
        assert conn_info.last_used == created_time
        assert conn_info.use_count == 0
        assert conn_info.is_active is False
        assert conn_info.connection_id != ""
    
    def test_connection_info_with_custom_id(self):
        """Test connection info with custom ID."""
        mock_handler = Mock(spec=BaseTransportHandler)
        created_time = time.time()
        custom_id = "custom_connection_123"
        
        conn_info = ConnectionInfo(
            handler=mock_handler,
            created_at=created_time,
            last_used=created_time,
            connection_id=custom_id
        )
        
        assert conn_info.connection_id == custom_id
    
    def test_connection_info_auto_id_generation(self):
        """Test automatic connection ID generation."""
        mock_handler = Mock(spec=BaseTransportHandler)
        created_time = time.time()
        
        conn_info = ConnectionInfo(
            handler=mock_handler,
            created_at=created_time,
            last_used=created_time
        )
        
        # Should generate ID based on handler id and created time
        expected_id = f"{id(mock_handler)}_{created_time}"
        assert conn_info.connection_id == expected_id


class TestConnectionPool:
    """Test ConnectionPool class."""
    
    @pytest.fixture
    def mock_handler_factory(self):
        """Create mock handler factory."""
        def factory():
            handler = Mock(spec=BaseTransportHandler)
            handler.is_connected = True
            handler.connect = AsyncMock()
            handler.disconnect = AsyncMock()
            return handler
        return factory
    
    @pytest.fixture
    def connection_pool(self):
        """Create test connection pool."""
        return ConnectionPool(
            max_connections=3,
            max_idle_time=2.0,
            cleanup_interval=1.0,
            connection_timeout=1.0
        )
    
    def test_pool_initialization(self, connection_pool):
        """Test pool initialization."""
        assert connection_pool.max_connections == 3
        assert connection_pool.max_idle_time == 2.0
        assert connection_pool.cleanup_interval == 1.0
        assert connection_pool.connection_timeout == 1.0
        assert len(connection_pool._connections) == 0
        assert len(connection_pool._active_connections) == 0
        assert len(connection_pool._idle_connections) == 0
        assert connection_pool._shutdown is False
    
    @pytest.mark.asyncio
    async def test_pool_start_stop(self, connection_pool):
        """Test pool start and stop."""
        # Start pool
        await connection_pool.start()
        assert connection_pool._cleanup_task is not None
        assert not connection_pool._shutdown
        
        # Stop pool
        await connection_pool.stop()
        assert connection_pool._cleanup_task is None
        assert connection_pool._shutdown is True
    
    @pytest.mark.asyncio
    async def test_get_connection_new(self, connection_pool, mock_handler_factory):
        """Test getting a new connection."""
        await connection_pool.start()
        
        try:
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server"
            ) as handler:
                assert handler is not None
                assert handler.is_connected is True
                assert len(connection_pool._active_connections) == 1
                assert len(connection_pool._idle_connections) == 0
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_get_connection_reuse(self, connection_pool, mock_handler_factory):
        """Test reusing an existing connection."""
        await connection_pool.start()
        
        try:
            # First connection
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server"
            ) as handler1:
                handler1_id = id(handler1)
            
            # Should have one idle connection now
            assert len(connection_pool._idle_connections) == 1
            assert len(connection_pool._active_connections) == 0
            
            # Second connection - should reuse
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server"
            ) as handler2:
                handler2_id = id(handler2)
                # Should be the same handler instance
                assert handler1_id == handler2_id
                
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_connection_pool_capacity(self, connection_pool, mock_handler_factory):
        """Test connection pool capacity limits."""
        await connection_pool.start()
        
        try:
            # Create connections up to capacity
            connections = []
            for i in range(connection_pool.max_connections):
                conn_ctx = connection_pool.get_connection(
                    mock_handler_factory, 
                    f"test_server_{i}"
                )
                handler = await conn_ctx.__aenter__()
                connections.append((conn_ctx, handler))
            
            # Pool should be at capacity
            assert len(connection_pool._active_connections) == connection_pool.max_connections
            
            # Try to get one more - should raise error
            with pytest.raises(TransportError):
                async with connection_pool.get_connection(
                    mock_handler_factory, 
                    "overflow_server"
                ) as handler:
                    pass
            
            # Clean up connections
            for conn_ctx, handler in connections:
                await conn_ctx.__aexit__(None, None, None)
                
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_connection_timeout(self, mock_handler_factory):
        """Test connection timeout handling."""
        # Create factory that times out
        def timeout_factory():
            handler = Mock(spec=BaseTransportHandler)
            handler.is_connected = True
            
            async def slow_connect(*args, **kwargs):
                await asyncio.sleep(2.0)  # Longer than timeout
            
            handler.connect = slow_connect
            handler.disconnect = AsyncMock()
            return handler
        
        pool = ConnectionPool(connection_timeout=0.5)
        await pool.start()
        
        try:
            with pytest.raises((ConnectionTimeoutError, asyncio.TimeoutError)):
                async with pool.get_connection(timeout_factory, "slow_server") as handler:
                    pass
        finally:
            await pool.stop()
    
    @pytest.mark.asyncio
    async def test_cleanup_idle_connections(self, connection_pool, mock_handler_factory):
        """Test cleanup of idle connections."""
        await connection_pool.start()
        
        try:
            # Create and release a connection
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server"
            ) as handler:
                pass
            
            # Should have one idle connection
            assert len(connection_pool._idle_connections) == 1
            
            # Manually trigger cleanup (simulate time passing)
            for conn_id, conn_info in connection_pool._connections.items():
                conn_info.last_used = time.time() - connection_pool.max_idle_time - 1
            
            await connection_pool._cleanup_idle_connections()
            
            # Idle connection should be removed
            assert len(connection_pool._idle_connections) == 0
            assert len(connection_pool._connections) == 0
            
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_get_stats(self, connection_pool, mock_handler_factory):
        """Test getting pool statistics."""
        await connection_pool.start()
        
        try:
            # Create some connections
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server_1"
            ) as handler1:
                async with connection_pool.get_connection(
                    mock_handler_factory, 
                    "test_server_2"
                ) as handler2:
                    stats = connection_pool.get_stats()
                    
                    assert stats.total_connections == 2
                    assert stats.active_connections == 2
                    assert stats.idle_connections == 0
                    assert stats.total_requests == 2
            
            # After context exit, connections should be idle
            stats = connection_pool.get_stats()
            assert stats.active_connections == 0
            assert stats.idle_connections == 2
            
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_health_check(self, connection_pool, mock_handler_factory):
        """Test pool health check."""
        await connection_pool.start()
        
        try:
            # Create a connection
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server"
            ) as handler:
                health = await connection_pool.health_check()
                
                assert isinstance(health, dict)
                assert "total_connections" in health
                assert "active_connections" in health
                assert "idle_connections" in health
                assert "pool_status" in health
                
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_connection_callbacks(self, connection_pool, mock_handler_factory):
        """Test connection event callbacks."""
        created_connections = []
        destroyed_connections = []
        
        async def on_created(conn_id: str):
            created_connections.append(conn_id)
        
        async def on_destroyed(conn_id: str):
            destroyed_connections.append(conn_id)
        
        connection_pool.add_connection_callback(
            on_created=on_created,
            on_destroyed=on_destroyed
        )
        
        await connection_pool.start()
        
        try:
            # Create and destroy a connection
            async with connection_pool.get_connection(
                mock_handler_factory, 
                "test_server"
            ) as handler:
                pass
            
            # Force cleanup to trigger destroy callback
            await connection_pool.stop()
            
            # Callbacks should have been called
            assert len(created_connections) >= 1
            assert len(destroyed_connections) >= 1
            
        finally:
            if not connection_pool._shutdown:
                await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_error_handling_in_factory(self, connection_pool):
        """Test error handling when handler factory fails."""
        def failing_factory():
            raise Exception("Factory failed")
        
        await connection_pool.start()
        
        try:
            with pytest.raises(Exception):
                async with connection_pool.get_connection(
                    failing_factory, 
                    "test_server"
                ) as handler:
                    pass
        finally:
            await connection_pool.stop()
    
    @pytest.mark.asyncio
    async def test_concurrent_access(self, connection_pool, mock_handler_factory):
        """Test concurrent access to the pool."""
        await connection_pool.start()
        
        try:
            async def get_and_use_connection(server_id: str):
                async with connection_pool.get_connection(
                    mock_handler_factory, 
                    f"test_server_{server_id}"
                ) as handler:
                    await asyncio.sleep(0.01)  # Simulate work
                    return id(handler)
            
            # Run multiple concurrent operations
            tasks = [get_and_use_connection(str(i)) for i in range(5)]
            results = await asyncio.gather(*tasks)
            
            # Should have created connections (may reuse some)
            assert len(results) == 5
            assert all(result is not None for result in results)
            
        finally:
            await connection_pool.stop()


class TestTransportExceptions:
    """Test transport-specific exceptions."""
    
    def test_transport_error(self):
        """Test TransportError exception."""
        error = TransportError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)
    
    def test_connection_failed_error(self):
        """Test ConnectionFailedError exception."""
        error = ConnectionFailedError("Connection failed")
        assert str(error) == "Connection failed"
        assert isinstance(error, TransportError)
    
    def test_connection_timeout_error(self):
        """Test ConnectionTimeoutError exception."""
        error = ConnectionTimeoutError("Connection timeout")
        assert str(error) == "Connection timeout"
        assert isinstance(error, TransportError)


if __name__ == "__main__":
    pytest.main([__file__]) 