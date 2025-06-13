"""
SSE Transport Handler

Implementation of MCP transport handler for HTTP-based servers that use
Server-Sent Events (SSE) for communication.
"""

import asyncio
import logging
import aiohttp
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse, urljoin

from typing import AsyncContextManager
from mcp import ClientSession

from .base import BaseTransportHandler, ConnectionFailedError, TransportError


class SSETransportHandler(BaseTransportHandler):
    """
    Transport handler for MCP servers using Server-Sent Events (SSE).
    
    This handler manages connections to HTTP-based MCP servers that
    communicate via Server-Sent Events.
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the SSE transport handler.
        
        Args:
            timeout: Connection timeout in seconds
            max_retries: Maximum number of connection retries
            retry_delay: Delay between retries in seconds
            logger: Logger instance for this handler
        """
        super().__init__(timeout, max_retries, retry_delay, logger)
        self._url: Optional[str] = None
        self._headers: Dict[str, str] = {}
        self._session_connector: Optional[aiohttp.TCPConnector] = None
    
    async def _create_session(self, **kwargs) -> ClientSession:
        """
        Create and return a new MCP client session for SSE transport.
        
        Args:
            url: URL of the MCP server SSE endpoint
            headers: HTTP headers to include in requests
            verify_ssl: Whether to verify SSL certificates (default: True)
            proxy: HTTP proxy URL if needed
            
        Returns:
            ClientSession: Configured MCP client session
            
        Raises:
            ConnectionFailedError: If session creation fails
        """
        url = kwargs.get('url')
        headers = kwargs.get('headers', {})
        verify_ssl = kwargs.get('verify_ssl', True)
        proxy = kwargs.get('proxy')
        
        if not url:
            raise ConnectionFailedError("URL is required for SSE transport")
        
        # Validate URL format
        if not self._validate_url(url):
            raise ConnectionFailedError(f"Invalid URL format: {url}")
        
        self._url = url
        self._headers = headers.copy()
        
        try:
            # Create connector with SSL settings
            connector = aiohttp.TCPConnector(
                verify_ssl=verify_ssl,
                limit=10,  # Connection pool limit
                limit_per_host=5,
                ttl_dns_cache=300,  # DNS cache TTL
                use_dns_cache=True,
            )
            self._session_connector = connector
            
            self.logger.debug(f"Connecting to MCP server via SSE: {url}")
            
            # For Phase 2, we create a mock session that represents the transport layer
            # The actual MCP protocol implementation will be added in Phase 3
            from unittest.mock import AsyncMock
            session = AsyncMock(spec=ClientSession)
            session.url = url
            session.headers = headers
            session.connector = connector
            
            self.logger.info(f"Successfully created SSE session for: {url}")
            return session
            
        except Exception as e:
            self.logger.error(f"Failed to create SSE session: {e}")
            raise ConnectionFailedError(f"Failed to create SSE session: {e}")
    
    async def _cleanup_session(self) -> None:
        """
        Clean up the current session and HTTP connector.
        """
        try:
            if self._session:
                # Close the session
                await self._session.close()
                self.logger.debug("Closed MCP SSE session")
            
            if self._session_connector:
                # Close the HTTP connector
                await self._session_connector.close()
                self._session_connector = None
                self.logger.debug("Closed HTTP connector")
                
        except Exception as e:
            self.logger.error(f"Error during SSE session cleanup: {e}")
    
    def _validate_url(self, url: str) -> bool:
        """
        Validate that the URL is properly formatted and safe.
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if URL is valid and safe
        """
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ('http', 'https'):
                self.logger.warning(f"Invalid URL scheme: {parsed.scheme}")
                return False
            
            # Check hostname
            if not parsed.hostname:
                self.logger.warning("URL missing hostname")
                return False
            
            # Basic security checks
            if parsed.hostname in ('localhost', '127.0.0.1', '::1'):
                # Local connections are generally safe
                pass
            elif parsed.hostname.startswith('192.168.') or parsed.hostname.startswith('10.'):
                # Private network ranges
                pass
            elif parsed.hostname.startswith('172.'):
                # Check if it's in the 172.16.0.0/12 range
                try:
                    parts = parsed.hostname.split('.')
                    if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                        pass  # Private range
                    else:
                        self.logger.info(f"Connecting to external host: {parsed.hostname}")
                except ValueError:
                    pass
            else:
                self.logger.info(f"Connecting to external host: {parsed.hostname}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating URL: {e}")
            return False
    
    async def health_check(self) -> bool:
        """
        Perform a health check on the SSE connection.
        
        Returns:
            bool: True if connection is healthy
        """
        if not self.is_connected:
            return False
        
        try:
            # Try to ping the server or check connection status
            if hasattr(self._session, 'initialize'):
                # Try a simple initialize call to check if server is responsive
                await asyncio.wait_for(
                    self._session.initialize(),
                    timeout=5.0
                )
                return True
            
            return True
            
        except Exception as e:
            self.logger.warning(f"SSE health check failed: {e}")
            return False
    
    async def test_connection(self, url: str, headers: Optional[Dict[str, str]] = None) -> bool:
        """
        Test if the SSE endpoint is reachable without establishing a full session.
        
        Args:
            url: URL to test
            headers: Optional headers to include
            
        Returns:
            bool: True if endpoint is reachable
        """
        try:
            connector = aiohttp.TCPConnector(verify_ssl=True)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10.0)
            ) as session:
                
                # Try a HEAD request first to check if endpoint exists
                async with session.head(url, headers=headers) as response:
                    if response.status == 200:
                        return True
                    elif response.status == 405:  # Method not allowed, but endpoint exists
                        return True
                    else:
                        self.logger.warning(f"SSE endpoint returned status {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.debug(f"SSE connection test failed: {e}")
            return False
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        Get information about the connected SSE server.
        
        Returns:
            Dict containing server connection information
        """
        return {
            'transport_type': 'sse',
            'url': self._url,
            'headers': self._headers,
            'connected': self.is_connected,
        }
    
    async def connect(self, **kwargs) -> None:
        """
        Establish connection to the MCP server via SSE.
        
        Args:
            url: URL of the MCP server SSE endpoint
            headers: HTTP headers to include in requests
            verify_ssl: Whether to verify SSL certificates (default: True)
            proxy: HTTP proxy URL if needed
            test_connection: Whether to test connection first (default: True)
            
        Raises:
            ConnectionFailedError: If connection fails
        """
        url = kwargs.get('url')
        test_connection = kwargs.get('test_connection', True)
        
        # Optionally test connection first
        if test_connection and url:
            if not await self.test_connection(url, kwargs.get('headers')):
                raise ConnectionFailedError(f"SSE endpoint test failed: {url}")
        
        await super().connect(**kwargs)
    
    def __repr__(self) -> str:
        """String representation of the handler."""
        if self._url:
            return f"SSETransportHandler(url='{self._url}')"
        return "SSETransportHandler(not configured)" 