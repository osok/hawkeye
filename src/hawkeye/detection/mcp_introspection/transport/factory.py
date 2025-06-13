"""
Transport Factory

Factory for creating and auto-detecting appropriate MCP transport handlers
based on server configuration and connection parameters.
"""

import logging
from typing import Any, Dict, Optional, Type, Union
from urllib.parse import urlparse

from .base import BaseTransportHandler, TransportError
from .stdio import StdioTransportHandler
from .sse import SSETransportHandler
from .http import StreamableHTTPTransportHandler
from ..models import TransportType


class TransportFactory:
    """
    Factory for creating MCP transport handlers.
    
    Automatically detects the appropriate transport type based on
    configuration and creates the corresponding handler.
    """
    
    # Registry of available transport handlers
    _handlers: Dict[TransportType, Type[BaseTransportHandler]] = {
        TransportType.STDIO: StdioTransportHandler,
        TransportType.SSE: SSETransportHandler,
        TransportType.HTTP: StreamableHTTPTransportHandler,
    }
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the transport factory.
        
        Args:
            logger: Logger instance for the factory
        """
        self.logger = logger or logging.getLogger(self.__class__.__name__)
    
    def create_handler(
        self,
        transport_type: Union[str, TransportType],
        **kwargs
    ) -> BaseTransportHandler:
        """
        Create a transport handler of the specified type.
        
        Args:
            transport_type: Type of transport handler to create
            **kwargs: Additional arguments for handler initialization
            
        Returns:
            BaseTransportHandler: Configured transport handler
            
        Raises:
            TransportError: If transport type is not supported
        """
        # Convert string to enum if needed
        if isinstance(transport_type, str):
            try:
                transport_type = TransportType(transport_type.lower())
            except ValueError:
                raise TransportError(f"Unsupported transport type: {transport_type}")
        
        if transport_type not in self._handlers:
            raise TransportError(f"No handler available for transport type: {transport_type}")
        
        handler_class = self._handlers[transport_type]
        
        # Extract handler-specific kwargs
        handler_kwargs = {
            'timeout': kwargs.get('timeout', 30.0),
            'max_retries': kwargs.get('max_retries', 3),
            'retry_delay': kwargs.get('retry_delay', 1.0),
            'logger': kwargs.get('logger', self.logger),
        }
        
        self.logger.debug(f"Creating {transport_type.value} transport handler")
        return handler_class(**handler_kwargs)
    
    def auto_detect_transport(self, config: Dict[str, Any]) -> TransportType:
        """
        Automatically detect the appropriate transport type from configuration.
        
        Args:
            config: Server configuration dictionary
            
        Returns:
            TransportType: Detected transport type
            
        Raises:
            TransportError: If transport type cannot be determined
        """
        # Check for explicit transport type
        if 'transport' in config:
            transport_str = config['transport'].lower()
            try:
                return TransportType(transport_str)
            except ValueError:
                self.logger.warning(f"Invalid transport type specified: {transport_str}")
        
        # Auto-detect based on configuration keys
        if 'command' in config or 'args' in config:
            self.logger.debug("Detected stdio transport (command/args present)")
            return TransportType.STDIO
        
        if 'url' in config:
            url = config['url']
            parsed = urlparse(url)
            
            if parsed.scheme in ('http', 'https'):
                # Check for SSE-specific indicators
                if any(indicator in url.lower() for indicator in ['sse', 'events', 'stream']):
                    self.logger.debug("Detected SSE transport (SSE indicators in URL)")
                    return TransportType.SSE
                else:
                    self.logger.debug("Detected HTTP transport (HTTP URL)")
                    return TransportType.HTTP
        
        if 'base_url' in config:
            self.logger.debug("Detected HTTP transport (base_url present)")
            return TransportType.HTTP
        
        # Default fallback
        self.logger.warning("Could not auto-detect transport type, defaulting to stdio")
        return TransportType.STDIO
    
    def create_from_config(self, config: Dict[str, Any]) -> BaseTransportHandler:
        """
        Create a transport handler from configuration.
        
        Args:
            config: Server configuration dictionary
            
        Returns:
            BaseTransportHandler: Configured transport handler
            
        Example config formats:
            # Stdio
            {
                "command": "node",
                "args": ["server.js"],
                "env": {"NODE_ENV": "production"}
            }
            
            # SSE
            {
                "url": "https://api.example.com/mcp/sse",
                "headers": {"Authorization": "Bearer token"}
            }
            
            # HTTP
            {
                "base_url": "https://api.example.com/mcp",
                "auth": {"bearer_token": "token"}
            }
        """
        # Auto-detect transport type
        transport_type = self.auto_detect_transport(config)
        
        # Create handler
        handler = self.create_handler(
            transport_type,
            timeout=config.get('timeout', 30.0),
            max_retries=config.get('max_retries', 3),
            retry_delay=config.get('retry_delay', 1.0),
            logger=self.logger
        )
        
        self.logger.info(f"Created {transport_type.value} transport handler from config")
        return handler
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate that the configuration contains required fields for transport.
        
        Args:
            config: Configuration to validate
            
        Returns:
            bool: True if configuration is valid
        """
        try:
            transport_type = self.auto_detect_transport(config)
            
            # Validate required fields for each transport type
            if transport_type == TransportType.STDIO:
                return 'command' in config
            
            elif transport_type == TransportType.SSE:
                return 'url' in config
            
            elif transport_type == TransportType.HTTP:
                return 'base_url' in config or 'url' in config
            
            return False
            
        except Exception as e:
            self.logger.error(f"Config validation failed: {e}")
            return False
    
    def get_supported_transports(self) -> list[TransportType]:
        """
        Get list of supported transport types.
        
        Returns:
            List of supported TransportType values
        """
        return list(self._handlers.keys())
    
    def register_handler(
        self, 
        transport_type: TransportType, 
        handler_class: Type[BaseTransportHandler]
    ) -> None:
        """
        Register a custom transport handler.
        
        Args:
            transport_type: Transport type to register
            handler_class: Handler class to register
        """
        if not issubclass(handler_class, BaseTransportHandler):
            raise TransportError("Handler must inherit from BaseTransportHandler")
        
        self._handlers[transport_type] = handler_class
        self.logger.info(f"Registered custom handler for {transport_type.value}")
    
    async def test_connection(self, config: Dict[str, Any]) -> bool:
        """
        Test if a connection can be established with the given configuration.
        
        Args:
            config: Server configuration to test
            
        Returns:
            bool: True if connection test succeeds
        """
        try:
            handler = self.create_from_config(config)
            
            # Prepare connection parameters based on transport type
            transport_type = self.auto_detect_transport(config)
            
            if transport_type == TransportType.STDIO:
                connect_params = {
                    'command': config.get('command'),
                    'args': config.get('args', []),
                    'env': config.get('env', {}),
                    'validate_command': config.get('validate_command', True)
                }
            elif transport_type == TransportType.SSE:
                connect_params = {
                    'url': config.get('url'),
                    'headers': config.get('headers', {}),
                    'verify_ssl': config.get('verify_ssl', True),
                    'test_connection': True
                }
            elif transport_type == TransportType.HTTP:
                connect_params = {
                    'base_url': config.get('base_url') or config.get('url'),
                    'headers': config.get('headers', {}),
                    'auth': config.get('auth', {}),
                    'verify_ssl': config.get('verify_ssl', True),
                    'test_connection': True
                }
            else:
                return False
            
            # Test connection
            await handler.connect(**connect_params)
            await handler.disconnect()
            
            self.logger.debug(f"Connection test successful for {transport_type.value}")
            return True
            
        except Exception as e:
            self.logger.debug(f"Connection test failed: {e}")
            return False
    
    def __repr__(self) -> str:
        """String representation of the factory."""
        supported = [t.value for t in self.get_supported_transports()]
        return f"TransportFactory(supported={supported})"


# Global factory instance
default_factory = TransportFactory()


def create_transport_handler(
    transport_type: Union[str, TransportType],
    **kwargs
) -> BaseTransportHandler:
    """
    Convenience function to create a transport handler.
    
    Args:
        transport_type: Type of transport handler to create
        **kwargs: Additional arguments for handler initialization
        
    Returns:
        BaseTransportHandler: Configured transport handler
    """
    return default_factory.create_handler(transport_type, **kwargs)


def create_from_config(config: Dict[str, Any]) -> BaseTransportHandler:
    """
    Convenience function to create a transport handler from configuration.
    
    Args:
        config: Server configuration dictionary
        
    Returns:
        BaseTransportHandler: Configured transport handler
    """
    return default_factory.create_from_config(config) 