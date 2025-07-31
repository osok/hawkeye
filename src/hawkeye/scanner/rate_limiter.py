"""
Rate limiting for network scanning operations.

This module provides rate limiting functionality to control the speed
of network scanning operations and prevent overwhelming target networks.
"""

import time
import threading
from collections import deque
from typing import Optional, Dict, Any
from dataclasses import dataclass

from ..config.settings import get_settings
from ..utils.logging import get_logger


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    
    requests_per_second: float
    burst_size: int = 10
    window_size: float = 1.0  # seconds
    
    def __post_init__(self):
        """Validate configuration."""
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        if self.burst_size <= 0:
            raise ValueError("burst_size must be positive")
        if self.window_size <= 0:
            raise ValueError("window_size must be positive")


class TokenBucket:
    """Token bucket algorithm implementation for rate limiting."""
    
    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket.
        
        Args:
            rate: Token generation rate (tokens per second)
            capacity: Maximum bucket capacity
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            bool: True if tokens were consumed, False otherwise
        """
        with self._lock:
            now = time.time()
            
            # Add tokens based on elapsed time
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def wait_for_tokens(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """
        Wait until tokens are available.
        
        Args:
            tokens: Number of tokens needed
            timeout: Maximum time to wait
            
        Returns:
            bool: True if tokens were acquired, False if timeout
        """
        start_time = time.time()
        
        while True:
            if self.consume(tokens):
                return True
            
            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    return False
            
            # Calculate sleep time
            with self._lock:
                tokens_needed = tokens - self.tokens
                sleep_time = tokens_needed / self.rate
                sleep_time = min(sleep_time, 0.1)  # Cap at 100ms
            
            time.sleep(sleep_time)
    
    def get_available_tokens(self) -> float:
        """Get the current number of available tokens."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            return min(self.capacity, self.tokens + elapsed * self.rate)


class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""
    
    def __init__(self, rate: float, window_size: float = 1.0):
        """
        Initialize sliding window rate limiter.
        
        Args:
            rate: Maximum requests per window
            window_size: Window size in seconds
        """
        self.rate = rate
        self.window_size = window_size
        self.requests = deque()
        self._lock = threading.Lock()
    
    def is_allowed(self) -> bool:
        """
        Check if a request is allowed.
        
        Returns:
            bool: True if request is allowed, False otherwise
        """
        now = time.time()
        
        with self._lock:
            # Remove old requests outside the window
            cutoff_time = now - self.window_size
            while self.requests and self.requests[0] <= cutoff_time:
                self.requests.popleft()
            
            # Check if we're under the rate limit
            if len(self.requests) < self.rate:
                self.requests.append(now)
                return True
            
            return False
    
    def wait_until_allowed(self, timeout: Optional[float] = None) -> bool:
        """
        Wait until a request is allowed.
        
        Args:
            timeout: Maximum time to wait
            
        Returns:
            bool: True if request was allowed, False if timeout
        """
        start_time = time.time()
        
        while True:
            if self.is_allowed():
                return True
            
            # Check timeout
            if timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    return False
            
            # Calculate sleep time
            with self._lock:
                if self.requests:
                    oldest_request = self.requests[0]
                    sleep_time = (oldest_request + self.window_size) - time.time()
                    sleep_time = max(0.01, min(sleep_time, 0.1))  # Between 10ms and 100ms
                else:
                    sleep_time = 0.01
            
            time.sleep(sleep_time)
    
    def get_current_rate(self) -> float:
        """Get the current request rate."""
        now = time.time()
        
        with self._lock:
            # Remove old requests
            cutoff_time = now - self.window_size
            while self.requests and self.requests[0] <= cutoff_time:
                self.requests.popleft()
            
            return len(self.requests) / self.window_size


class RateLimiter:
    """Main rate limiter class combining multiple algorithms."""
    
    def __init__(self, settings=None):
        """Initialize rate limiter."""
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        
        # Rate limiting configuration
        self.requests_per_second = self.settings.scan.rate_limit_requests
        
        # Initialize rate limiting algorithms
        self.token_bucket = TokenBucket(
            rate=self.requests_per_second,
            capacity=min(self.requests_per_second * 2, 100)  # Allow some burst
        )
        
        self.sliding_window = SlidingWindowRateLimiter(
            rate=self.requests_per_second,
            window_size=1.0
        )
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'allowed_requests': 0,
            'blocked_requests': 0,
            'total_wait_time': 0.0,
            'start_time': time.time(),
        }
        
        self._lock = threading.Lock()
        
        self.logger.info(f"Rate limiter initialized: {self.requests_per_second} requests/second")
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire permission to make a request.
        
        Args:
            timeout: Maximum time to wait for permission
            
        Returns:
            bool: True if permission granted, False if timeout
        """
        start_time = time.time()
        
        with self._lock:
            self.stats['total_requests'] += 1
        
        # Use token bucket as primary rate limiter
        success = self.token_bucket.wait_for_tokens(1, timeout)
        
        if success:
            # Double-check with sliding window
            if not self.sliding_window.is_allowed():
                # Wait a bit and try again
                remaining_timeout = None
                if timeout is not None:
                    elapsed = time.time() - start_time
                    remaining_timeout = max(0, timeout - elapsed)
                
                success = self.sliding_window.wait_until_allowed(remaining_timeout)
        
        # Update statistics
        wait_time = time.time() - start_time
        
        with self._lock:
            if success:
                self.stats['allowed_requests'] += 1
            else:
                self.stats['blocked_requests'] += 1
            
            self.stats['total_wait_time'] += wait_time
        
        if success:
            self.logger.debug(f"Request allowed (waited {wait_time:.3f}s)")
        else:
            self.logger.debug(f"Request blocked after {wait_time:.3f}s timeout")
        
        return success
    
    def try_acquire(self) -> bool:
        """
        Try to acquire permission without waiting.
        
        Returns:
            bool: True if permission granted immediately, False otherwise
        """
        with self._lock:
            self.stats['total_requests'] += 1
        
        # Check both rate limiters
        token_allowed = self.token_bucket.consume(1)
        window_allowed = self.sliding_window.is_allowed() if token_allowed else False
        
        success = token_allowed and window_allowed
        
        with self._lock:
            if success:
                self.stats['allowed_requests'] += 1
            else:
                self.stats['blocked_requests'] += 1
        
        return success
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self._lock:
            stats = self.stats.copy()
        
        # Calculate derived statistics
        if stats['total_requests'] > 0:
            stats['success_rate'] = stats['allowed_requests'] / stats['total_requests']
            stats['average_wait_time'] = stats['total_wait_time'] / stats['total_requests']
        else:
            stats['success_rate'] = 0.0
            stats['average_wait_time'] = 0.0
        
        # Current rates
        stats['current_token_bucket_tokens'] = self.token_bucket.get_available_tokens()
        stats['current_sliding_window_rate'] = self.sliding_window.get_current_rate()
        
        # Runtime
        stats['runtime'] = time.time() - stats['start_time']
        if stats['runtime'] > 0:
            stats['actual_request_rate'] = stats['allowed_requests'] / stats['runtime']
        else:
            stats['actual_request_rate'] = 0.0
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset rate limiter statistics."""
        with self._lock:
            self.stats = {
                'total_requests': 0,
                'allowed_requests': 0,
                'blocked_requests': 0,
                'total_wait_time': 0.0,
                'start_time': time.time(),
            }
        
        self.logger.info("Rate limiter statistics reset")
    
    def update_rate(self, new_rate: float) -> None:
        """
        Update the rate limit.
        
        Args:
            new_rate: New requests per second rate
        """
        if new_rate <= 0:
            raise ValueError("Rate must be positive")
        
        old_rate = self.requests_per_second
        self.requests_per_second = new_rate
        
        # Update rate limiters
        self.token_bucket = TokenBucket(
            rate=new_rate,
            capacity=min(new_rate * 2, 100)
        )
        
        self.sliding_window = SlidingWindowRateLimiter(
            rate=new_rate,
            window_size=1.0
        )
        
        self.logger.info(f"Rate limit updated: {old_rate} -> {new_rate} requests/second")
    
    def get_estimated_wait_time(self) -> float:
        """
        Get estimated wait time for next request.
        
        Returns:
            float: Estimated wait time in seconds
        """
        # Check token bucket wait time
        available_tokens = self.token_bucket.get_available_tokens()
        if available_tokens >= 1:
            token_wait = 0.0
        else:
            tokens_needed = 1 - available_tokens
            token_wait = tokens_needed / self.token_bucket.rate
        
        # Check sliding window wait time
        current_rate = self.sliding_window.get_current_rate()
        if current_rate < self.requests_per_second:
            window_wait = 0.0
        else:
            # Estimate based on oldest request in window
            with self.sliding_window._lock:
                if self.sliding_window.requests:
                    oldest_request = self.sliding_window.requests[0]
                    window_wait = (oldest_request + self.sliding_window.window_size) - time.time()
                    window_wait = max(0, window_wait)
                else:
                    window_wait = 0.0
        
        return max(token_wait, window_wait) 