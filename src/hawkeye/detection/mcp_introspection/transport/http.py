"""
HTTP Transport Handler

Implementation of MCP transport handler for production servers that use
HTTP-based communication with streaming support.
"""

import asyncio
import logging
import aiohttp
import json
from typing import Any, Dict, Optional, Union, List
from urllib.parse import urlparse, urljoin

from typing import AsyncContextManager
from mcp import ClientSession

from .base import BaseTransportHandler, ConnectionFailedError, TransportError


class StreamableHTTPTransportHandler(BaseTransportHandler):
    """
    Transport handler for MCP servers using HTTP with streaming support.
    
    This handler manages connections to production MCP servers that
    communicate via HTTP with optional streaming capabilities.
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the HTTP transport handler.
        
        Args:
            timeout: Connection timeout in seconds
            max_retries: Maximum number of connection retries
            retry_delay: Delay between retries in seconds
            logger: Logger instance for this handler
        """
        super().__init__(timeout, max_retries, retry_delay, logger)
        self._base_url: Optional[str] = None
        self._headers: Dict[str, str] = {}
        self._auth: Optional[Dict[str, str]] = None
        self._session_connector: Optional[aiohttp.TCPConnector] = None
        self._streaming_enabled: bool = False
    
    async def _create_session(self, **kwargs) -> ClientSession:
        """
        Create and return a new MCP client session for HTTP transport.
        
        Args:
            base_url: Base URL of the MCP server
            headers: HTTP headers to include in requests
            auth: Authentication configuration (bearer_token, api_key, etc.)
            verify_ssl: Whether to verify SSL certificates (default: True)
            proxy: HTTP proxy URL if needed
            streaming: Whether to enable streaming support (default: False)
            
        Returns:
            ClientSession: Configured MCP client session
            
        Raises:
            ConnectionFailedError: If session creation fails
        """
        base_url = kwargs.get('base_url')
        headers = kwargs.get('headers', {})
        auth = kwargs.get('auth', {})
        verify_ssl = kwargs.get('verify_ssl', True)
        proxy = kwargs.get('proxy')
        streaming = kwargs.get('streaming', False)
        
        if not base_url:
            raise ConnectionFailedError("Base URL is required for HTTP transport")
        
        # Validate URL format
        if not self._validate_url(base_url):
            raise ConnectionFailedError(f"Invalid base URL format: {base_url}")
        
        self._base_url = base_url
        self._headers = headers.copy()
        self._auth = auth.copy() if auth else {}
        self._streaming_enabled = streaming
        
        try:
            # Prepare authentication headers
            auth_headers = self._prepare_auth_headers(auth)
            all_headers = {**headers, **auth_headers}
            
            # Create connector with SSL settings
            connector = aiohttp.TCPConnector(
                verify_ssl=verify_ssl,
                limit=20,  # Higher limit for HTTP
                limit_per_host=10,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=60,
                enable_cleanup_closed=True,
            )
            self._session_connector = connector
            
            self.logger.debug(f"Connecting to MCP server via HTTP: {base_url}")
            
            # For Phase 2, we create a mock session that represents the transport layer
            # The actual MCP protocol implementation will be added in Phase 3
            from unittest.mock import AsyncMock
            session = AsyncMock(spec=ClientSession)
            session.base_url = base_url
            session.headers = all_headers
            session.connector = connector
            session.streaming = streaming
            
            self.logger.info(f"Successfully created HTTP session for: {base_url}")
            return session
            
        except Exception as e:
            self.logger.error(f"Failed to create HTTP session: {e}")
            raise ConnectionFailedError(f"Failed to create HTTP session: {e}")
    
    async def _cleanup_session(self) -> None:
        """
        Clean up the current session and HTTP connector.
        """
        try:
            if self._session:
                # Close the session
                await self._session.close()
                self.logger.debug("Closed MCP HTTP session")
            
            if self._session_connector:
                # Close the HTTP connector
                await self._session_connector.close()
                self._session_connector = None
                self.logger.debug("Closed HTTP connector")
                
        except Exception as e:
            self.logger.error(f"Error during HTTP session cleanup: {e}")
    
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
            
            # Prefer HTTPS for production
            if parsed.scheme == 'http':
                self.logger.warning(f"Using insecure HTTP connection: {url}")
            
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
    
    def _prepare_auth_headers(self, auth: Dict[str, str]) -> Dict[str, str]:
        """
        Prepare authentication headers from auth configuration.
        
        Args:
            auth: Authentication configuration
            
        Returns:
            Dict of headers to add for authentication
        """
        headers = {}
        
        if 'bearer_token' in auth:
            headers['Authorization'] = f"Bearer {auth['bearer_token']}"
        elif 'api_key' in auth:
            # Common API key header patterns
            key_header = auth.get('api_key_header', 'X-API-Key')
            headers[key_header] = auth['api_key']
        elif 'basic_auth' in auth:
            # Basic authentication
            import base64
            credentials = base64.b64encode(auth['basic_auth'].encode()).decode()
            headers['Authorization'] = f"Basic {credentials}"
        
        return headers
    
    async def health_check(self) -> bool:
        """
        Perform a health check on the HTTP connection.
        
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
            self.logger.warning(f"HTTP health check failed: {e}")
            return False
    
    async def test_connection(
        self, 
        base_url: str, 
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Test if the HTTP endpoint is reachable without establishing a full session.
        
        Args:
            base_url: Base URL to test
            headers: Optional headers to include
            auth: Optional authentication configuration
            
        Returns:
            bool: True if endpoint is reachable
        """
        try:
            connector = aiohttp.TCPConnector(verify_ssl=True)
            
            # Prepare headers with authentication
            test_headers = headers.copy() if headers else {}
            if auth:
                auth_headers = self._prepare_auth_headers(auth)
                test_headers.update(auth_headers)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10.0)
            ) as session:
                
                # Try to access a common MCP endpoint
                test_endpoints = [
                    urljoin(base_url, '/health'),
                    urljoin(base_url, '/status'),
                    urljoin(base_url, '/'),
                    base_url
                ]
                
                for endpoint in test_endpoints:
                    try:
                        async with session.get(endpoint, headers=test_headers) as response:
                            if response.status < 500:  # Any non-server-error response
                                return True
                    except Exception:
                        continue
                
                return False
                        
        except Exception as e:
            self.logger.debug(f"HTTP connection test failed: {e}")
            return False
    
    async def discover_endpoints(self, base_url: str) -> List[str]:
        """
        Discover available MCP endpoints on the server.
        
        Args:
            base_url: Base URL to scan
            
        Returns:
            List of discovered endpoint paths
        """
        endpoints = []
        common_paths = [
            '/mcp',
            '/api/mcp',
            '/v1/mcp',
            '/rpc',
            '/jsonrpc',
            '/.well-known/mcp',
        ]
        
        try:
            connector = aiohttp.TCPConnector(verify_ssl=True)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=5.0)
            ) as session:
                
                for path in common_paths:
                    try:
                        url = urljoin(base_url, path)
                        async with session.head(url) as response:
                            if response.status < 400:
                                endpoints.append(path)
                                self.logger.debug(f"Found MCP endpoint: {path}")
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Endpoint discovery failed: {e}")
        
        return endpoints
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        Get information about the connected HTTP server.
        
        Returns:
            Dict containing server connection information
        """
        return {
            'transport_type': 'http',
            'base_url': self._base_url,
            'headers': {k: v for k, v in self._headers.items() if 'auth' not in k.lower()},
            'streaming_enabled': self._streaming_enabled,
            'connected': self.is_connected,
        }
    
    async def connect(self, **kwargs) -> None:
        """
        Establish connection to the MCP server via HTTP.
        
        Args:
            base_url: Base URL of the MCP server
            headers: HTTP headers to include in requests
            auth: Authentication configuration
            verify_ssl: Whether to verify SSL certificates (default: True)
            proxy: HTTP proxy URL if needed
            streaming: Whether to enable streaming support (default: False)
            test_connection: Whether to test connection first (default: True)
            discover_endpoints: Whether to discover endpoints (default: False)
            
        Raises:
            ConnectionFailedError: If connection fails
        """
        base_url = kwargs.get('base_url')
        test_connection = kwargs.get('test_connection', True)
        discover_endpoints = kwargs.get('discover_endpoints', False)
        
        # Optionally test connection first
        if test_connection and base_url:
            if not await self.test_connection(
                base_url, 
                kwargs.get('headers'), 
                kwargs.get('auth')
            ):
                raise ConnectionFailedError(f"HTTP endpoint test failed: {base_url}")
        
        # Optionally discover endpoints
        if discover_endpoints and base_url:
            endpoints = await self.discover_endpoints(base_url)
            if endpoints:
                self.logger.info(f"Discovered MCP endpoints: {endpoints}")
        
        await super().connect(**kwargs)
    
    def __repr__(self) -> str:
        """String representation of the handler."""
        if self._base_url:
            return f"StreamableHTTPTransportHandler(base_url='{self._base_url}')"
        return "StreamableHTTPTransportHandler(not configured)" 