"""
Connection Pool and Timeout Management

Provides connection pooling and timeout management for MCP transport handlers
to efficiently manage multiple concurrent connections to MCP servers.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set, Any, Callable, Awaitable
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from weakref import WeakSet

from .base import BaseTransportHandler, ConnectionFailedError, TransportError


@dataclass
class PoolStats:
    """Statistics for connection pool monitoring."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    created_at: float = field(default_factory=time.time)


@dataclass
class ConnectionInfo:
    """Information about a pooled connection."""
    handler: BaseTransportHandler
    created_at: float
    last_used: float
    use_count: int = 0
    is_active: bool = False
    connection_id: str = ""
    
    def __post_init__(self):
        if not self.connection_id:
            self.connection_id = f"{id(self.handler)}_{self.created_at}"


class ConnectionPool:
    """
    Connection pool for managing multiple MCP transport handlers.
    
    Provides efficient connection reuse, timeout management, and resource cleanup
    for concurrent MCP server connections.
    """
    
    def __init__(
        self,
        max_connections: int = 10,
        max_idle_time: float = 300.0,  # 5 minutes
        cleanup_interval: float = 60.0,  # 1 minute
        connection_timeout: float = 30.0,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the connection pool.
        
        Args:
            max_connections: Maximum number of concurrent connections
            max_idle_time: Maximum time a connection can remain idle (seconds)
            cleanup_interval: Interval between cleanup cycles (seconds)
            connection_timeout: Default timeout for new connections (seconds)
            logger: Logger instance for this pool
        """
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.cleanup_interval = cleanup_interval
        self.connection_timeout = connection_timeout
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        # Connection tracking
        self._connections: Dict[str, ConnectionInfo] = {}
        self._active_connections: Set[str] = set()
        self._idle_connections: Set[str] = set()
        self._connection_lock = asyncio.Lock()
        
        # Pool management
        self._stats = PoolStats()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown = False
        
        # Callbacks for connection events
        self._on_connection_created: List[Callable[[str], Awaitable[None]]] = []
        self._on_connection_destroyed: List[Callable[[str], Awaitable[None]]] = []
    
    async def start(self) -> None:
        """Start the connection pool and background cleanup task."""
        if self._cleanup_task is not None:
            self.logger.warning("Pool already started")
            return
        
        self._shutdown = False
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.logger.info(f"Connection pool started (max_connections={self.max_connections})")
    
    async def stop(self) -> None:
        """Stop the connection pool and clean up all connections."""
        self._shutdown = True
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        
        # Close all connections
        async with self._connection_lock:
            for conn_id in list(self._connections.keys()):
                await self._remove_connection(conn_id)
        
        self.logger.info("Connection pool stopped")
    
    @asynccontextmanager
    async def get_connection(
        self,
        handler_factory: Callable[[], BaseTransportHandler],
        connection_key: str,
        **connect_kwargs
    ):
        """
        Get a connection from the pool or create a new one.
        
        Args:
            handler_factory: Factory function to create new transport handlers
            connection_key: Unique key to identify this connection type
            **connect_kwargs: Arguments to pass to the connection
            
        Yields:
            BaseTransportHandler: Connected transport handler
            
        Raises:
            ConnectionFailedError: If unable to get or create connection
            TransportError: If pool is at capacity
        """
        if self._shutdown:
            raise TransportError("Connection pool is shut down")
        
        conn_id = None
        start_time = time.time()
        
        try:
            # Get or create connection
            conn_id = await self._get_or_create_connection(
                handler_factory, connection_key, **connect_kwargs
            )
            
            connection = self._connections[conn_id]
            connection.last_used = time.time()
            connection.use_count += 1
            
            self._stats.total_requests += 1
            
            yield connection.handler
            
            # Mark as successful
            self._stats.successful_requests += 1
            response_time = time.time() - start_time
            self._update_average_response_time(response_time)
            
        except Exception as e:
            self._stats.failed_requests += 1
            self.logger.error(f"Error using connection {conn_id}: {e}")
            raise
        finally:
            # Return connection to idle state
            if conn_id and conn_id in self._connections:
                await self._return_connection(conn_id)
    
    async def _get_or_create_connection(
        self,
        handler_factory: Callable[[], BaseTransportHandler],
        connection_key: str,
        **connect_kwargs
    ) -> str:
        """Get an existing idle connection or create a new one."""
        async with self._connection_lock:
            # Look for existing idle connection with matching key
            for conn_id, conn_info in self._connections.items():
                if (conn_id.startswith(connection_key) and 
                    conn_id in self._idle_connections and
                    conn_info.handler.is_connected):
                    
                    # Move from idle to active
                    self._idle_connections.discard(conn_id)
                    self._active_connections.add(conn_id)
                    conn_info.is_active = True
                    
                    self.logger.debug(f"Reusing connection {conn_id}")
                    return conn_id
            
            # Check if we can create a new connection
            if len(self._connections) >= self.max_connections:
                # Try to clean up idle connections first
                await self._cleanup_idle_connections()
                
                if len(self._connections) >= self.max_connections:
                    raise TransportError(f"Connection pool at capacity ({self.max_connections})")
            
            # Create new connection
            return await self._create_new_connection(
                handler_factory, connection_key, **connect_kwargs
            )
    
    async def _create_new_connection(
        self,
        handler_factory: Callable[[], BaseTransportHandler],
        connection_key: str,
        **connect_kwargs
    ) -> str:
        """Create a new connection and add it to the pool."""
        handler = handler_factory()
        current_time = time.time()
        
        # Generate unique connection ID
        conn_id = f"{connection_key}_{current_time}_{id(handler)}"
        
        try:
            # Connect the handler
            await asyncio.wait_for(
                handler.connect(**connect_kwargs),
                timeout=self.connection_timeout
            )
            
            # Add to pool
            conn_info = ConnectionInfo(
                handler=handler,
                created_at=current_time,
                last_used=current_time,
                is_active=True,
                connection_id=conn_id
            )
            
            self._connections[conn_id] = conn_info
            self._active_connections.add(conn_id)
            self._stats.total_connections += 1
            
            # Notify callbacks
            for callback in self._on_connection_created:
                try:
                    await callback(conn_id)
                except Exception as e:
                    self.logger.warning(f"Connection created callback failed: {e}")
            
            self.logger.info(f"Created new connection {conn_id}")
            return conn_id
            
        except Exception as e:
            self._stats.failed_connections += 1
            self.logger.error(f"Failed to create connection {conn_id}: {e}")
            raise ConnectionFailedError(f"Failed to create connection: {e}")
    
    async def _return_connection(self, conn_id: str) -> None:
        """Return a connection to the idle state."""
        async with self._connection_lock:
            if conn_id not in self._connections:
                return
            
            conn_info = self._connections[conn_id]
            
            # Move from active to idle
            self._active_connections.discard(conn_id)
            
            if conn_info.handler.is_connected:
                self._idle_connections.add(conn_id)
                conn_info.is_active = False
                self.logger.debug(f"Returned connection {conn_id} to idle state")
            else:
                # Connection is broken, remove it
                await self._remove_connection(conn_id)
    
    async def _remove_connection(self, conn_id: str) -> None:
        """Remove a connection from the pool and clean up resources."""
        if conn_id not in self._connections:
            return
        
        conn_info = self._connections[conn_id]
        
        try:
            if conn_info.handler.is_connected:
                await conn_info.handler.disconnect()
        except Exception as e:
            self.logger.warning(f"Error disconnecting {conn_id}: {e}")
        
        # Remove from tracking sets
        self._active_connections.discard(conn_id)
        self._idle_connections.discard(conn_id)
        del self._connections[conn_id]
        
        # Notify callbacks
        for callback in self._on_connection_destroyed:
            try:
                await callback(conn_id)
            except Exception as e:
                self.logger.warning(f"Connection destroyed callback failed: {e}")
        
        self.logger.debug(f"Removed connection {conn_id}")
    
    async def _cleanup_loop(self) -> None:
        """Background task to clean up idle connections."""
        while not self._shutdown:
            try:
                await asyncio.sleep(self.cleanup_interval)
                if not self._shutdown:
                    await self._cleanup_idle_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
    
    async def _cleanup_idle_connections(self) -> None:
        """Clean up connections that have been idle too long."""
        current_time = time.time()
        to_remove = []
        
        async with self._connection_lock:
            for conn_id in list(self._idle_connections):
                conn_info = self._connections[conn_id]
                idle_time = current_time - conn_info.last_used
                
                if idle_time > self.max_idle_time:
                    to_remove.append(conn_id)
            
            # Remove idle connections
            for conn_id in to_remove:
                await self._remove_connection(conn_id)
        
        if to_remove:
            self.logger.info(f"Cleaned up {len(to_remove)} idle connections")
    
    def _update_average_response_time(self, response_time: float) -> None:
        """Update the average response time statistic."""
        if self._stats.successful_requests == 1:
            self._stats.average_response_time = response_time
        else:
            # Exponential moving average
            alpha = 0.1
            self._stats.average_response_time = (
                alpha * response_time + 
                (1 - alpha) * self._stats.average_response_time
            )
    
    def get_stats(self) -> PoolStats:
        """Get current pool statistics."""
        self._stats.active_connections = len(self._active_connections)
        self._stats.idle_connections = len(self._idle_connections)
        return self._stats
    
    def add_connection_callback(
        self,
        on_created: Optional[Callable[[str], Awaitable[None]]] = None,
        on_destroyed: Optional[Callable[[str], Awaitable[None]]] = None
    ) -> None:
        """Add callbacks for connection lifecycle events."""
        if on_created:
            self._on_connection_created.append(on_created)
        if on_destroyed:
            self._on_connection_destroyed.append(on_destroyed)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a health check on the connection pool."""
        stats = self.get_stats()
        
        # Check for unhealthy connections
        unhealthy_connections = []
        async with self._connection_lock:
            for conn_id, conn_info in self._connections.items():
                if not conn_info.handler.is_connected:
                    unhealthy_connections.append(conn_id)
        
        # Clean up unhealthy connections
        for conn_id in unhealthy_connections:
            await self._remove_connection(conn_id)
        
        return {
            "healthy": len(unhealthy_connections) == 0,
            "stats": stats,
            "unhealthy_connections": len(unhealthy_connections),
            "pool_utilization": len(self._connections) / self.max_connections,
        } 