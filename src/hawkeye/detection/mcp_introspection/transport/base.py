"""
Base Transport Handler

Abstract base class for MCP transport handlers providing a common interface
for different transport types (stdio, SSE, HTTP).
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Union
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.types import JSONRPCMessage


class TransportError(Exception):
    """Base exception for transport-related errors."""
    pass


class ConnectionTimeoutError(TransportError):
    """Raised when connection times out."""
    pass


class ConnectionFailedError(TransportError):
    """Raised when connection fails to establish."""
    pass


class BaseTransportHandler(ABC):
    """
    Abstract base class for MCP transport handlers.
    
    Provides a common interface for connecting to MCP servers using different
    transport protocols (stdio, SSE, HTTP).
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the transport handler.
        
        Args:
            timeout: Connection timeout in seconds
            max_retries: Maximum number of connection retries
            retry_delay: Delay between retries in seconds
            logger: Logger instance for this handler
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._session: Optional[ClientSession] = None
        self._connected = False
    
    @property
    def is_connected(self) -> bool:
        """Check if the transport is currently connected."""
        return self._connected and self._session is not None
    
    @abstractmethod
    async def _create_session(self, **kwargs) -> ClientSession:
        """
        Create and return a new MCP client session.
        
        This method must be implemented by concrete transport handlers
        to create the appropriate session type for their transport protocol.
        
        Args:
            **kwargs: Transport-specific connection parameters
            
        Returns:
            ClientSession: Configured MCP client session
            
        Raises:
            ConnectionFailedError: If session creation fails
        """
        pass
    
    @abstractmethod
    async def _cleanup_session(self) -> None:
        """
        Clean up the current session and any associated resources.
        
        This method must be implemented by concrete transport handlers
        to properly clean up transport-specific resources.
        """
        pass
    
    async def connect(self, **kwargs) -> None:
        """
        Establish connection to the MCP server.
        
        Args:
            **kwargs: Transport-specific connection parameters
            
        Raises:
            ConnectionFailedError: If connection fails after all retries
            ConnectionTimeoutError: If connection times out
        """
        if self.is_connected:
            self.logger.warning("Already connected, skipping connection attempt")
            return
        
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                self.logger.debug(f"Connection attempt {attempt + 1}/{self.max_retries + 1}")
                
                # Create session with timeout
                self._session = await asyncio.wait_for(
                    self._create_session(**kwargs),
                    timeout=self.timeout
                )
                
                self._connected = True
                self.logger.info("Successfully connected to MCP server")
                return
                
            except asyncio.TimeoutError as e:
                last_error = ConnectionTimeoutError(f"Connection timed out after {self.timeout}s")
                self.logger.warning(f"Connection attempt {attempt + 1} timed out")
                
            except Exception as e:
                last_error = ConnectionFailedError(f"Connection failed: {e}")
                self.logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < self.max_retries:
                await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
        
        # All attempts failed
        self.logger.error(f"Failed to connect after {self.max_retries + 1} attempts")
        raise last_error or ConnectionFailedError("Connection failed for unknown reason")
    
    async def disconnect(self) -> None:
        """
        Disconnect from the MCP server and clean up resources.
        """
        if not self.is_connected:
            self.logger.debug("Not connected, skipping disconnect")
            return
        
        try:
            await self._cleanup_session()
            self.logger.info("Successfully disconnected from MCP server")
        except Exception as e:
            self.logger.error(f"Error during disconnect: {e}")
        finally:
            self._session = None
            self._connected = False
    
    @asynccontextmanager
    async def session_context(self, **kwargs):
        """
        Context manager for automatic connection and cleanup.
        
        Args:
            **kwargs: Transport-specific connection parameters
            
        Yields:
            ClientSession: The connected MCP client session
            
        Example:
            async with handler.session_context(command="my-server") as session:
                tools = await session.list_tools()
        """
        await self.connect(**kwargs)
        try:
            yield self._session
        finally:
            await self.disconnect()
    
    async def send_message(self, message: JSONRPCMessage) -> Any:
        """
        Send a message to the MCP server.
        
        Args:
            message: JSON-RPC message to send
            
        Returns:
            Response from the server
            
        Raises:
            ConnectionFailedError: If not connected to server
        """
        if not self.is_connected:
            raise ConnectionFailedError("Not connected to MCP server")
        
        try:
            # This would be implemented based on the specific MCP client API
            # For now, this is a placeholder for the interface
            self.logger.debug(f"Sending message: {message}")
            # return await self._session.send(message)
            raise NotImplementedError("Message sending not yet implemented")
        except Exception as e:
            self.logger.error(f"Failed to send message: {e}")
            raise TransportError(f"Message send failed: {e}")
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get information about the current connection.
        
        Returns:
            Dictionary containing connection status and metadata
        """
        return {
            "connected": self.is_connected,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "transport_type": self.__class__.__name__,
        } 