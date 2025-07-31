"""
MCP Transport Package

Provides transport handlers for different MCP communication protocols
including stdio, SSE, and HTTP with comprehensive error handling and validation.
"""

from .base import (
    BaseTransportHandler,
    TransportError,
    ConnectionFailedError,
    ConnectionTimeoutError,
)

from .stdio import StdioTransportHandler
from .sse import SSETransportHandler
from .http import StreamableHTTPTransportHandler

from .factory import (
    TransportFactory,
    default_factory,
    create_transport_handler,
    create_from_config,
)

from .retry import (
    RetryManager,
    RetryConfig,
    RetryStrategy,
    CircuitState,
)

from .errors import (
    TransportErrorHandler,
    ErrorContext,
    ErrorSeverity,
    ErrorCategory,
)

from .validation import (
    TransportConfigValidator,
    ValidationIssue,
    ValidationSeverity,
)

from .pool import (
    ConnectionPool,
    PoolStats,
    ConnectionInfo,
)

__all__ = [
    # Base classes and exceptions
    'BaseTransportHandler',
    'TransportError',
    'ConnectionFailedError',
    'ConnectionTimeoutError',
    
    # Transport handlers
    'StdioTransportHandler',
    'SSETransportHandler',
    'StreamableHTTPTransportHandler',
    
    # Factory and convenience functions
    'TransportFactory',
    'default_factory',
    'create_transport_handler',
    'create_from_config',
    
    # Retry management
    'RetryManager',
    'RetryConfig',
    'RetryStrategy',
    'CircuitState',
    
    # Error handling
    'TransportErrorHandler',
    'ErrorContext',
    'ErrorSeverity',
    'ErrorCategory',
    
    # Validation
    'TransportConfigValidator',
    'ValidationIssue',
    'ValidationSeverity',
    
    # Connection pooling
    'ConnectionPool',
    'PoolStats',
    'ConnectionInfo',
] 