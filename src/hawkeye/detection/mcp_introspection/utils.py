"""
Utilities and Error Handling Framework

Provides utility functions and error handling mechanisms for MCP introspection
operations, including error recovery and logging.
"""

import asyncio
import functools
import logging
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, TypeVar, Union
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum

import async_timeout
from pydantic import BaseModel


class ErrorHandler:
    """Simple synchronous error handler for MCP introspection."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize error handler."""
        self.logger = logger or logging.getLogger(__name__)
    
    def handle_error(self, error: Exception, context: str = "operation") -> None:
        """Handle an error by logging it."""
        self.logger.error(f"Error in {context}: {error}")
    
    def log_warning(self, message: str, context: str = "operation") -> None:
        """Log a warning message."""
        self.logger.warning(f"Warning in {context}: {message}")
    
    def log_info(self, message: str, context: str = "operation") -> None:
        """Log an info message."""
        self.logger.info(f"Info in {context}: {message}")


T = TypeVar('T')


class ErrorSeverity(str, Enum):
    """Error severity levels for categorization."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ErrorCategory(str, Enum):
    """Error category enumeration for classification."""
    CONNECTION = "connection"
    TIMEOUT = "timeout"
    AUTHENTICATION = "authentication"
    PROTOCOL = "protocol"
    VALIDATION = "validation"
    RESOURCE = "resource"
    PERMISSION = "permission"
    UNKNOWN = "unknown"


@dataclass
class ErrorContext:
    """Context information for error handling."""
    operation: str
    server_name: Optional[str] = None
    transport_type: Optional[str] = None
    attempt_number: int = 1
    start_time: float = 0.0
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}
        if self.start_time == 0.0:
            self.start_time = time.time()


class MCPIntrospectionError(Exception):
    """Base exception for MCP introspection errors."""
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.UNKNOWN,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        context: Optional[ErrorContext] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.context = context
        self.original_error = original_error
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging/reporting."""
        return {
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "context": {
                "operation": self.context.operation if self.context else None,
                "server_name": self.context.server_name if self.context else None,
                "transport_type": self.context.transport_type if self.context else None,
                "attempt_number": self.context.attempt_number if self.context else None,
                "duration": time.time() - self.context.start_time if self.context else None,
                "additional_info": self.context.additional_info if self.context else {},
            },
            "original_error": str(self.original_error) if self.original_error else None,
        }


class ConnectionError(MCPIntrospectionError):
    """Error during connection establishment."""
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None, original_error: Optional[Exception] = None):
        super().__init__(
            message,
            category=ErrorCategory.CONNECTION,
            severity=ErrorSeverity.HIGH,
            context=context,
            original_error=original_error
        )


class TimeoutError(MCPIntrospectionError):
    """Error due to operation timeout."""
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None, original_error: Optional[Exception] = None):
        super().__init__(
            message,
            category=ErrorCategory.TIMEOUT,
            severity=ErrorSeverity.MEDIUM,
            context=context,
            original_error=original_error
        )


class ProtocolError(MCPIntrospectionError):
    """Error in MCP protocol communication."""
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None, original_error: Optional[Exception] = None):
        super().__init__(
            message,
            category=ErrorCategory.PROTOCOL,
            severity=ErrorSeverity.HIGH,
            context=context,
            original_error=original_error
        )


class ValidationError(MCPIntrospectionError):
    """Error in data validation."""
    
    def __init__(self, message: str, context: Optional[ErrorContext] = None, original_error: Optional[Exception] = None):
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            context=context,
            original_error=original_error
        )


def with_timeout(timeout_seconds: float):
    """
    Decorator to add timeout to async functions.
    
    Args:
        timeout_seconds: Timeout in seconds
        
    Returns:
        Decorated function with timeout
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            try:
                async with async_timeout.timeout(timeout_seconds):
                    return await func(*args, **kwargs)
            except asyncio.TimeoutError as e:
                context = ErrorContext(operation=func.__name__)
                raise TimeoutError(
                    f"Operation {func.__name__} timed out after {timeout_seconds}s",
                    context=context,
                    original_error=e
                )
        return wrapper
    return decorator


def with_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """
    Decorator to add retry logic to async functions.
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts
        backoff_factor: Exponential backoff factor
        exceptions: Tuple of exceptions to retry on
        
    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        # Last attempt, re-raise
                        break
                    
                    # Wait before retry
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff_factor
            
            # All attempts failed
            context = ErrorContext(
                operation=func.__name__,
                attempt_number=max_attempts
            )
            raise MCPIntrospectionError(
                f"Operation {func.__name__} failed after {max_attempts} attempts",
                context=context,
                original_error=last_exception
            )
        return wrapper
    return decorator


def with_error_handling(
    operation_name: str,
    server_name: Optional[str] = None,
    transport_type: Optional[str] = None
):
    """
    Decorator to add comprehensive error handling to async functions.
    
    Args:
        operation_name: Name of the operation for context
        server_name: Name of the server being operated on
        transport_type: Type of transport being used
        
    Returns:
        Decorated function with error handling
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            context = ErrorContext(
                operation=operation_name,
                server_name=server_name,
                transport_type=transport_type
            )
            
            try:
                return await func(*args, **kwargs)
            except MCPIntrospectionError:
                # Re-raise our custom errors
                raise
            except asyncio.TimeoutError as e:
                raise TimeoutError(
                    f"Timeout during {operation_name}",
                    context=context,
                    original_error=e
                )
            except ConnectionRefusedError as e:
                raise ConnectionError(
                    f"Connection refused during {operation_name}",
                    context=context,
                    original_error=e
                )
            except Exception as e:
                raise MCPIntrospectionError(
                    f"Unexpected error during {operation_name}: {e}",
                    context=context,
                    original_error=e
                )
        return wrapper
    return decorator


async def gather_with_concurrency(
    tasks: List[Awaitable[T]],
    max_concurrency: int = 10,
    return_exceptions: bool = True
) -> List[Union[T, Exception]]:
    """
    Execute multiple async tasks with limited concurrency.
    
    Args:
        tasks: List of awaitable tasks
        max_concurrency: Maximum number of concurrent tasks
        return_exceptions: Whether to return exceptions instead of raising
        
    Returns:
        List of results or exceptions
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def limited_task(task: Awaitable[T]) -> Union[T, Exception]:
        async with semaphore:
            try:
                return await task
            except Exception as e:
                if return_exceptions:
                    return e
                raise
    
    limited_tasks = [limited_task(task) for task in tasks]
    return await asyncio.gather(*limited_tasks, return_exceptions=return_exceptions)


@asynccontextmanager
async def timeout_context(timeout_seconds: float, operation_name: str = "operation"):
    """
    Async context manager for timeout handling.
    
    Args:
        timeout_seconds: Timeout in seconds
        operation_name: Name of operation for error messages
        
    Yields:
        None
        
    Raises:
        TimeoutError: If operation times out
    """
    try:
        async with async_timeout.timeout(timeout_seconds):
            yield
    except asyncio.TimeoutError as e:
        context = ErrorContext(operation=operation_name)
        raise TimeoutError(
            f"Operation {operation_name} timed out after {timeout_seconds}s",
            context=context,
            original_error=e
        )


class AsyncBatch:
    """
    Utility for batching async operations with concurrency control.
    """
    
    def __init__(
        self,
        max_concurrency: int = 10,
        batch_size: int = 100,
        logger: Optional[logging.Logger] = None
    ):
        self.max_concurrency = max_concurrency
        self.batch_size = batch_size
        self.logger = logger or logging.getLogger(self.__class__.__name__)
    
    async def process_batch(
        self,
        items: List[Any],
        processor: Callable[[Any], Awaitable[T]],
        error_handler: Optional[Callable[[Any, Exception], Awaitable[None]]] = None
    ) -> List[Union[T, Exception]]:
        """
        Process a batch of items with concurrency control.
        
        Args:
            items: Items to process
            processor: Async function to process each item
            error_handler: Optional error handler for failed items
            
        Returns:
            List of results or exceptions
        """
        results = []
        
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            self.logger.debug(f"Processing batch {i//self.batch_size + 1} with {len(batch)} items")
            
            # Create tasks for this batch
            tasks = []
            for item in batch:
                task = self._process_item_with_error_handling(item, processor, error_handler)
                tasks.append(task)
            
            # Execute batch with concurrency limit
            batch_results = await gather_with_concurrency(
                tasks,
                max_concurrency=self.max_concurrency,
                return_exceptions=True
            )
            
            results.extend(batch_results)
        
        return results
    
    async def _process_item_with_error_handling(
        self,
        item: Any,
        processor: Callable[[Any], Awaitable[T]],
        error_handler: Optional[Callable[[Any, Exception], Awaitable[None]]]
    ) -> Union[T, Exception]:
        """Process a single item with error handling."""
        try:
            return await processor(item)
        except Exception as e:
            if error_handler:
                try:
                    await error_handler(item, e)
                except Exception as handler_error:
                    self.logger.error(f"Error handler failed: {handler_error}")
            return e


class PerformanceMonitor:
    """
    Monitor performance of async operations.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.metrics: Dict[str, List[float]] = {}
    
    @asynccontextmanager
    async def measure(self, operation_name: str):
        """
        Context manager to measure operation duration.
        
        Args:
            operation_name: Name of the operation
            
        Yields:
            None
        """
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.record_metric(operation_name, duration)
    
    def record_metric(self, operation_name: str, duration: float) -> None:
        """Record a performance metric."""
        if operation_name not in self.metrics:
            self.metrics[operation_name] = []
        
        self.metrics[operation_name].append(duration)
        
        # Log slow operations
        if duration > 10.0:  # More than 10 seconds
            self.logger.warning(f"Slow operation detected: {operation_name} took {duration:.2f}s")
    
    def get_stats(self, operation_name: str) -> Dict[str, float]:
        """Get statistics for an operation."""
        if operation_name not in self.metrics:
            return {}
        
        durations = self.metrics[operation_name]
        return {
            "count": len(durations),
            "total": sum(durations),
            "average": sum(durations) / len(durations),
            "min": min(durations),
            "max": max(durations),
        }
    
    def get_all_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all operations."""
        return {op: self.get_stats(op) for op in self.metrics.keys()}


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


def safe_json_serialize(obj: Any) -> Any:
    """
    Safely serialize objects to JSON-compatible format.
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON-serializable representation
    """
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, (list, tuple)):
        return [safe_json_serialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(k): safe_json_serialize(v) for k, v in obj.items()}
    elif isinstance(obj, BaseModel):
        return obj.dict()
    elif hasattr(obj, '__dict__'):
        return safe_json_serialize(obj.__dict__)
    else:
        return str(obj)


async def run_with_fallback(
    primary_func: Callable[..., Awaitable[T]],
    fallback_func: Callable[..., Awaitable[T]],
    *args,
    **kwargs
) -> T:
    """
    Run a primary function with fallback on failure.
    
    Args:
        primary_func: Primary function to try
        fallback_func: Fallback function if primary fails
        *args: Arguments to pass to functions
        **kwargs: Keyword arguments to pass to functions
        
    Returns:
        Result from primary or fallback function
    """
    try:
        return await primary_func(*args, **kwargs)
    except Exception as e:
        logging.getLogger(__name__).warning(f"Primary function failed, using fallback: {e}")
        return await fallback_func(*args, **kwargs) 