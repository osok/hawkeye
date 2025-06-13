"""
Advanced Connection Pooling Optimization

Provides enhanced connection pooling optimizations including adaptive pool sizing,
load balancing, connection health monitoring, and performance tuning for MCP servers.
"""

import asyncio
import logging
import time
import statistics
from typing import Dict, List, Optional, Set, Any, Callable, Awaitable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import weakref

from ..transport.pool import ConnectionPool, ConnectionInfo, PoolStats
from ..transport.base import BaseTransportHandler, TransportError


@dataclass
class PoolOptimizationConfig:
    """Configuration for connection pool optimizations."""
    # Adaptive sizing
    enable_adaptive_sizing: bool = True
    min_pool_size: int = 2
    max_pool_size: int = 50
    target_utilization: float = 0.7  # 70% utilization target
    scaling_factor: float = 1.5
    
    # Load balancing
    enable_load_balancing: bool = True
    load_balance_strategy: str = "least_connections"  # least_connections, round_robin, weighted
    health_check_interval: float = 30.0
    
    # Performance optimization
    enable_connection_warming: bool = True
    warm_connections_count: int = 3
    enable_predictive_scaling: bool = True
    request_pattern_window: int = 100
    
    # Advanced features
    enable_circuit_breaker: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 60.0
    enable_connection_affinity: bool = True


@dataclass
class ConnectionMetrics:
    """Detailed metrics for a connection."""
    connection_id: str
    response_times: deque = field(default_factory=lambda: deque(maxlen=50))
    error_count: int = 0
    success_count: int = 0
    last_error_time: Optional[float] = None
    health_score: float = 1.0
    load_factor: float = 0.0
    
    def add_response_time(self, response_time: float) -> None:
        """Add a response time measurement."""
        self.response_times.append(response_time)
    
    def add_success(self) -> None:
        """Record a successful operation."""
        self.success_count += 1
        self.health_score = min(1.0, self.health_score + 0.01)
    
    def add_error(self) -> None:
        """Record an error."""
        self.error_count += 1
        self.last_error_time = time.time()
        self.health_score = max(0.0, self.health_score - 0.1)
    
    @property
    def average_response_time(self) -> float:
        """Get average response time."""
        return statistics.mean(self.response_times) if self.response_times else 0.0
    
    @property
    def error_rate(self) -> float:
        """Get error rate."""
        total = self.success_count + self.error_count
        return self.error_count / total if total > 0 else 0.0


class CircuitBreaker:
    """Circuit breaker for connection failure protection."""
    
    def __init__(self, threshold: int = 5, timeout: float = 60.0):
        self.threshold = threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"  # closed, open, half_open
    
    def record_success(self) -> None:
        """Record a successful operation."""
        self.failure_count = 0
        if self.state == "half_open":
            self.state = "closed"
    
    def record_failure(self) -> None:
        """Record a failed operation."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.threshold:
            self.state = "open"
    
    def can_execute(self) -> bool:
        """Check if operation can be executed."""
        if self.state == "closed":
            return True
        elif self.state == "open":
            if time.time() - self.last_failure_time >= self.timeout:
                self.state = "half_open"
                return True
            return False
        else:  # half_open
            return True


class OptimizedConnectionPool(ConnectionPool):
    """
    Enhanced connection pool with advanced optimizations.
    
    Provides adaptive sizing, load balancing, health monitoring,
    and performance optimizations for MCP server connections.
    """
    
    def __init__(
        self,
        config: Optional[PoolOptimizationConfig] = None,
        **kwargs
    ):
        """Initialize the optimized connection pool."""
        self.config = config or PoolOptimizationConfig()
        
        # Override base pool settings with optimization config
        kwargs.setdefault('max_connections', self.config.max_pool_size)
        super().__init__(**kwargs)
        
        # Optimization state
        self._connection_metrics: Dict[str, ConnectionMetrics] = {}
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._request_history: deque = deque(maxlen=self.config.request_pattern_window)
        self._load_balancer_state: Dict[str, Any] = {}
        self._warm_connections: Set[str] = set()
        
        # Adaptive sizing
        self._current_pool_size = self.config.min_pool_size
        self._last_resize_time = time.time()
        self._resize_cooldown = 30.0  # 30 seconds between resizes
        
        # Background tasks
        self._optimization_task: Optional[asyncio.Task] = None
        self._health_check_task: Optional[asyncio.Task] = None
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get detailed optimization statistics."""
        base_stats = self.get_stats()
        
        # Calculate additional metrics
        avg_health_score = 0.0
        avg_response_time = 0.0
        total_errors = 0
        
        if self._connection_metrics:
            health_scores = [m.health_score for m in self._connection_metrics.values()]
            avg_health_score = statistics.mean(health_scores)
            
            response_times = []
            for metrics in self._connection_metrics.values():
                if metrics.response_times:
                    response_times.extend(metrics.response_times)
                total_errors += metrics.error_count
            
            if response_times:
                avg_response_time = statistics.mean(response_times)
        
        return {
            "base_stats": base_stats,
            "optimization_config": {
                "adaptive_sizing": self.config.enable_adaptive_sizing,
                "load_balancing": self.config.enable_load_balancing,
                "circuit_breaker": self.config.enable_circuit_breaker,
                "current_pool_size": self._current_pool_size,
                "target_utilization": self.config.target_utilization,
            },
            "performance_metrics": {
                "average_health_score": avg_health_score,
                "average_response_time": avg_response_time,
                "total_errors": total_errors,
                "circuit_breaker_states": {
                    key: cb.state for key, cb in self._circuit_breakers.items()
                },
            },
            "request_patterns": {
                "recent_requests": len(self._request_history),
                "request_rate": len([r for r in self._request_history 
                                   if time.time() - r['timestamp'] < 60]) / 60.0,
            }
        }
