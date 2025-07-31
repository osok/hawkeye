"""
Connection Retry Logic

Implements robust retry mechanisms with exponential backoff for MCP transport
connections, including circuit breaker patterns and failure tracking.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Dict, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

from .base import TransportError, ConnectionFailedError, ConnectionTimeoutError


class RetryStrategy(str, Enum):
    """Retry strategy enumeration."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIXED = "fixed"
    FIBONACCI = "fibonacci"


class CircuitState(str, Enum):
    """Circuit breaker state enumeration."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    backoff_multiplier: float = 2.0
    jitter: bool = True
    jitter_range: float = 0.1
    
    # Circuit breaker settings
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3


@dataclass
class RetryState:
    """State tracking for retry operations."""
    attempt_count: int = 0
    total_delay: float = 0.0
    last_attempt: Optional[datetime] = None
    last_error: Optional[Exception] = None
    consecutive_failures: int = 0
    circuit_state: CircuitState = CircuitState.CLOSED
    circuit_opened_at: Optional[datetime] = None
    half_open_calls: int = 0


class RetryManager:
    """
    Manages retry logic with exponential backoff and circuit breaker patterns.
    
    Provides robust retry mechanisms for MCP transport connections with
    configurable strategies and failure tracking.
    """
    
    def __init__(
        self,
        config: Optional[RetryConfig] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the retry manager.
        
        Args:
            config: Retry configuration
            logger: Logger instance
        """
        self.config = config or RetryConfig()
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.state = RetryState()
        self._failure_history: list[datetime] = []
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for the given attempt number.
        
        Args:
            attempt: Current attempt number (0-based)
            
        Returns:
            float: Delay in seconds
        """
        if self.config.strategy == RetryStrategy.FIXED:
            delay = self.config.base_delay
        
        elif self.config.strategy == RetryStrategy.LINEAR:
            delay = self.config.base_delay * (attempt + 1)
        
        elif self.config.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.config.base_delay * (self.config.backoff_multiplier ** attempt)
        
        elif self.config.strategy == RetryStrategy.FIBONACCI:
            delay = self.config.base_delay * self._fibonacci(attempt + 1)
        
        else:
            delay = self.config.base_delay
        
        # Apply maximum delay limit
        delay = min(delay, self.config.max_delay)
        
        # Add jitter if enabled
        if self.config.jitter:
            import random
            jitter_amount = delay * self.config.jitter_range
            jitter = random.uniform(-jitter_amount, jitter_amount)
            delay = max(0.1, delay + jitter)  # Ensure minimum delay
        
        return delay
    
    def _fibonacci(self, n: int) -> int:
        """Calculate nth Fibonacci number."""
        if n <= 1:
            return n
        a, b = 0, 1
        for _ in range(2, n + 1):
            a, b = b, a + b
        return b
    
    def should_retry(self, error: Exception) -> bool:
        """
        Determine if an error should trigger a retry.
        
        Args:
            error: Exception that occurred
            
        Returns:
            bool: True if retry should be attempted
        """
        # Check circuit breaker state
        if self.state.circuit_state == CircuitState.OPEN:
            if self._should_attempt_recovery():
                self.state.circuit_state = CircuitState.HALF_OPEN
                self.state.half_open_calls = 0
                self.logger.info("Circuit breaker transitioning to half-open")
            else:
                self.logger.debug("Circuit breaker is open, rejecting retry")
                return False
        
        # Check attempt limit
        if self.state.attempt_count >= self.config.max_attempts:
            self.logger.debug(f"Max attempts ({self.config.max_attempts}) reached")
            return False
        
        # Check if error is retryable
        retryable_errors = (
            ConnectionFailedError,
            ConnectionTimeoutError,
            asyncio.TimeoutError,
            OSError,  # Network errors
        )
        
        if not isinstance(error, retryable_errors):
            self.logger.debug(f"Error type {type(error).__name__} is not retryable")
            return False
        
        return True
    
    def _should_attempt_recovery(self) -> bool:
        """Check if circuit breaker should attempt recovery."""
        if self.state.circuit_opened_at is None:
            return False
        
        time_since_open = datetime.now() - self.state.circuit_opened_at
        return time_since_open.total_seconds() >= self.config.recovery_timeout
    
    def record_attempt(self, error: Optional[Exception] = None) -> None:
        """
        Record an attempt and its result.
        
        Args:
            error: Exception if attempt failed, None if successful
        """
        self.state.attempt_count += 1
        self.state.last_attempt = datetime.now()
        
        if error:
            self.state.last_error = error
            self.state.consecutive_failures += 1
            self._failure_history.append(datetime.now())
            
            # Update circuit breaker state
            if self.state.circuit_state == CircuitState.HALF_OPEN:
                # Failed during half-open, go back to open
                self.state.circuit_state = CircuitState.OPEN
                self.state.circuit_opened_at = datetime.now()
                self.logger.warning("Circuit breaker reopened due to failure during half-open")
            
            elif (self.state.circuit_state == CircuitState.CLOSED and 
                  self.state.consecutive_failures >= self.config.failure_threshold):
                # Too many failures, open circuit
                self.state.circuit_state = CircuitState.OPEN
                self.state.circuit_opened_at = datetime.now()
                self.logger.warning(f"Circuit breaker opened after {self.state.consecutive_failures} failures")
        
        else:
            # Success
            self.state.consecutive_failures = 0
            self.state.last_error = None
            
            if self.state.circuit_state == CircuitState.HALF_OPEN:
                self.state.half_open_calls += 1
                if self.state.half_open_calls >= self.config.half_open_max_calls:
                    # Enough successful calls, close circuit
                    self.state.circuit_state = CircuitState.CLOSED
                    self.logger.info("Circuit breaker closed after successful recovery")
    
    async def execute_with_retry(
        self,
        operation: Callable[[], Any],
        operation_name: str = "operation"
    ) -> Any:
        """
        Execute an operation with retry logic.
        
        Args:
            operation: Async function to execute
            operation_name: Name for logging purposes
            
        Returns:
            Result of the operation
            
        Raises:
            Exception: Last exception if all retries failed
        """
        self.reset()
        
        while True:
            try:
                self.logger.debug(f"Attempting {operation_name} (attempt {self.state.attempt_count + 1})")
                
                result = await operation()
                self.record_attempt()  # Success
                
                if self.state.attempt_count > 1:
                    self.logger.info(f"{operation_name} succeeded after {self.state.attempt_count} attempts")
                
                return result
                
            except Exception as e:
                self.record_attempt(e)
                
                if not self.should_retry(e):
                    self.logger.error(f"{operation_name} failed permanently: {e}")
                    raise e
                
                # Calculate delay for next attempt
                delay = self.calculate_delay(self.state.attempt_count - 1)
                self.state.total_delay += delay
                
                self.logger.warning(
                    f"{operation_name} failed (attempt {self.state.attempt_count}), "
                    f"retrying in {delay:.2f}s: {e}"
                )
                
                await asyncio.sleep(delay)
    
    def reset(self) -> None:
        """Reset retry state for a new operation."""
        self.state.attempt_count = 0
        self.state.total_delay = 0.0
        self.state.last_attempt = None
        self.state.last_error = None
        # Don't reset circuit breaker state or failure history
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get retry statistics.
        
        Returns:
            Dict containing retry statistics
        """
        now = datetime.now()
        recent_failures = [
            f for f in self._failure_history
            if (now - f).total_seconds() < 300  # Last 5 minutes
        ]
        
        return {
            'attempt_count': self.state.attempt_count,
            'total_delay': self.state.total_delay,
            'consecutive_failures': self.state.consecutive_failures,
            'circuit_state': self.state.circuit_state.value,
            'recent_failure_count': len(recent_failures),
            'last_error': str(self.state.last_error) if self.state.last_error else None,
            'config': {
                'max_attempts': self.config.max_attempts,
                'strategy': self.config.strategy.value,
                'base_delay': self.config.base_delay,
                'max_delay': self.config.max_delay,
            }
        }
    
    def __repr__(self) -> str:
        """String representation of the retry manager."""
        return (
            f"RetryManager(attempts={self.state.attempt_count}, "
            f"circuit={self.state.circuit_state.value}, "
            f"failures={self.state.consecutive_failures})"
        ) 