"""
Performance Monitoring and Metrics Module

This module provides comprehensive performance monitoring and metrics collection
for the MCP introspection system, including timing, resource usage, and
operational statistics.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque


logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Individual performance metric data point."""
    name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimingMetric:
    """Timing-specific metric with duration tracking."""
    operation: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    
    def finish(self, success: bool = True, error_message: Optional[str] = None):
        """Mark the timing metric as finished."""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.success = success
        self.error_message = error_message


class MetricsCollector:
    """
    Centralized metrics collection and aggregation system.
    
    Provides thread-safe collection of performance metrics with
    automatic aggregation and reporting capabilities.
    """
    
    def __init__(self, max_metrics: int = 10000):
        """
        Initialize metrics collector.
        
        Args:
            max_metrics: Maximum number of metrics to retain in memory
        """
        self.max_metrics = max_metrics
        self._metrics: deque = deque(maxlen=max_metrics)
        self._timing_metrics: deque = deque(maxlen=max_metrics)
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Performance tracking
        self._start_time = time.time()
        self._operation_counts = defaultdict(int)
        self._error_counts = defaultdict(int)
        
        logger.debug("MetricsCollector initialized")
    
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None, 
                     metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Record a general performance metric.
        
        Args:
            name: Metric name
            value: Metric value
            tags: Optional tags for categorization
            metadata: Optional additional metadata
        """
        with self._lock:
            metric = PerformanceMetric(
                name=name,
                value=value,
                timestamp=datetime.now(),
                tags=tags or {},
                metadata=metadata or {}
            )
            self._metrics.append(metric)
            
            # Update histogram
            self._histograms[name].append(value)
            
            logger.debug(f"Recorded metric: {name}={value}")
    
    def start_timing(self, operation: str, tags: Optional[Dict[str, str]] = None) -> TimingMetric:
        """
        Start timing an operation.
        
        Args:
            operation: Operation name
            tags: Optional tags for categorization
            
        Returns:
            TimingMetric object to be finished when operation completes
        """
        timing_metric = TimingMetric(
            operation=operation,
            start_time=time.time(),
            tags=tags or {}
        )
        
        with self._lock:
            self._operation_counts[operation] += 1
        
        logger.debug(f"Started timing operation: {operation}")
        return timing_metric
    
    def finish_timing(self, timing_metric: TimingMetric, success: bool = True, 
                     error_message: Optional[str] = None) -> None:
        """
        Finish timing an operation and record the metric.
        
        Args:
            timing_metric: TimingMetric to finish
            success: Whether the operation was successful
            error_message: Optional error message if operation failed
        """
        timing_metric.finish(success, error_message)
        
        with self._lock:
            self._timing_metrics.append(timing_metric)
            
            # Update counters
            if success:
                self.increment_counter(f"{timing_metric.operation}_success")
            else:
                self.increment_counter(f"{timing_metric.operation}_error")
                self._error_counts[timing_metric.operation] += 1
            
            # Record duration as metric
            if timing_metric.duration is not None:
                self.record_metric(
                    f"{timing_metric.operation}_duration",
                    timing_metric.duration,
                    timing_metric.tags,
                    {"success": success, "error_message": error_message}
                )
        
        logger.debug(
            f"Finished timing operation: {timing_metric.operation}, "
            f"duration: {timing_metric.duration:.3f}s, success: {success}"
        )
    
    def increment_counter(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Increment a counter metric.
        
        Args:
            name: Counter name
            value: Value to increment by (default: 1)
            tags: Optional tags for categorization
        """
        with self._lock:
            self._counters[name] += value
            
            # Also record as a general metric
            self.record_metric(f"counter_{name}", self._counters[name], tags)
        
        logger.debug(f"Incremented counter: {name} by {value}")
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """
        Set a gauge metric value.
        
        Args:
            name: Gauge name
            value: Gauge value
            tags: Optional tags for categorization
        """
        with self._lock:
            self._gauges[name] = value
            
            # Also record as a general metric
            self.record_metric(f"gauge_{name}", value, tags)
        
        logger.debug(f"Set gauge: {name}={value}")
    
    def get_counter(self, name: str) -> int:
        """Get current counter value."""
        with self._lock:
            return self._counters.get(name, 0)
    
    def get_gauge(self, name: str) -> Optional[float]:
        """Get current gauge value."""
        with self._lock:
            return self._gauges.get(name)
    
    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """
        Get statistical summary of histogram data.
        
        Args:
            name: Histogram name
            
        Returns:
            Dictionary with statistical metrics
        """
        with self._lock:
            values = self._histograms.get(name, [])
            
            if not values:
                return {}
            
            sorted_values = sorted(values)
            count = len(values)
            
            return {
                "count": count,
                "min": min(values),
                "max": max(values),
                "mean": sum(values) / count,
                "median": sorted_values[count // 2],
                "p95": sorted_values[int(count * 0.95)] if count > 0 else 0,
                "p99": sorted_values[int(count * 0.99)] if count > 0 else 0
            }
    
    def get_operation_summary(self) -> Dict[str, Any]:
        """
        Get summary of all operations.
        
        Returns:
            Dictionary with operation statistics
        """
        with self._lock:
            total_operations = sum(self._operation_counts.values())
            total_errors = sum(self._error_counts.values())
            uptime = time.time() - self._start_time
            
            return {
                "uptime_seconds": uptime,
                "total_operations": total_operations,
                "total_errors": total_errors,
                "error_rate": (total_errors / max(total_operations, 1)) * 100,
                "operations_per_second": total_operations / max(uptime, 1),
                "operation_breakdown": dict(self._operation_counts),
                "error_breakdown": dict(self._error_counts),
                "metrics_collected": len(self._metrics),
                "timing_metrics_collected": len(self._timing_metrics)
            }
    
    def get_recent_metrics(self, minutes: int = 5) -> List[PerformanceMetric]:
        """
        Get metrics from the last N minutes.
        
        Args:
            minutes: Number of minutes to look back
            
        Returns:
            List of recent metrics
        """
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        with self._lock:
            return [
                metric for metric in self._metrics
                if metric.timestamp >= cutoff_time
            ]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance report.
        
        Returns:
            Dictionary containing performance analysis
        """
        with self._lock:
            operation_summary = self.get_operation_summary()
            
            # Get timing statistics for key operations
            timing_stats = {}
            for operation in self._operation_counts.keys():
                duration_key = f"{operation}_duration"
                timing_stats[operation] = self.get_histogram_stats(duration_key)
            
            # Get recent performance trends
            recent_metrics = self.get_recent_metrics(5)
            recent_operations = len([m for m in recent_metrics if "duration" in m.name])
            
            return {
                "timestamp": datetime.now().isoformat(),
                "operation_summary": operation_summary,
                "timing_statistics": timing_stats,
                "recent_activity": {
                    "last_5_minutes_operations": recent_operations,
                    "recent_metrics_count": len(recent_metrics)
                },
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "memory_usage": {
                    "metrics_in_memory": len(self._metrics),
                    "timing_metrics_in_memory": len(self._timing_metrics),
                    "max_metrics": self.max_metrics
                }
            }
    
    def clear_metrics(self) -> None:
        """Clear all collected metrics."""
        with self._lock:
            self._metrics.clear()
            self._timing_metrics.clear()
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._operation_counts.clear()
            self._error_counts.clear()
            self._start_time = time.time()
        
        logger.info("All metrics cleared")


class PerformanceMonitor:
    """
    High-level performance monitoring interface.
    
    Provides decorators and context managers for easy performance monitoring
    integration with existing code.
    """
    
    def __init__(self, metrics_collector: Optional[MetricsCollector] = None):
        """
        Initialize performance monitor.
        
        Args:
            metrics_collector: Optional custom metrics collector
        """
        self.metrics = metrics_collector or MetricsCollector()
        self.logger = logger
    
    def time_operation(self, operation_name: str, tags: Optional[Dict[str, str]] = None):
        """
        Context manager for timing operations.
        
        Args:
            operation_name: Name of the operation being timed
            tags: Optional tags for categorization
            
        Example:
            with monitor.time_operation("server_introspection"):
                # perform introspection
                pass
        """
        return TimingContext(self.metrics, operation_name, tags)
    
    def monitor_function(self, operation_name: Optional[str] = None, 
                        tags: Optional[Dict[str, str]] = None):
        """
        Decorator for monitoring function performance.
        
        Args:
            operation_name: Optional custom operation name (defaults to function name)
            tags: Optional tags for categorization
            
        Example:
            @monitor.monitor_function("introspect_server")
            def introspect_server(self, server_info):
                # function implementation
                pass
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                op_name = operation_name or func.__name__
                timing_metric = self.metrics.start_timing(op_name, tags)
                
                try:
                    result = func(*args, **kwargs)
                    self.metrics.finish_timing(timing_metric, success=True)
                    return result
                except Exception as e:
                    self.metrics.finish_timing(
                        timing_metric, 
                        success=False, 
                        error_message=str(e)
                    )
                    raise
            
            return wrapper
        return decorator
    
    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a custom metric."""
        self.metrics.record_metric(name, value, tags)
    
    def increment_counter(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter."""
        self.metrics.increment_counter(name, value, tags)
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge value."""
        self.metrics.set_gauge(name, value, tags)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report."""
        return self.metrics.get_performance_report()


class TimingContext:
    """Context manager for timing operations."""
    
    def __init__(self, metrics_collector: MetricsCollector, operation_name: str, 
                 tags: Optional[Dict[str, str]] = None):
        self.metrics = metrics_collector
        self.operation_name = operation_name
        self.tags = tags or {}
        self.timing_metric = None
    
    def __enter__(self):
        self.timing_metric = self.metrics.start_timing(self.operation_name, self.tags)
        return self.timing_metric
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.timing_metric:
            success = exc_type is None
            error_message = str(exc_val) if exc_val else None
            self.metrics.finish_timing(self.timing_metric, success, error_message)


# Global performance monitor instance
global_monitor = PerformanceMonitor()


def get_global_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance."""
    return global_monitor


def time_operation(operation_name: str, tags: Optional[Dict[str, str]] = None):
    """Convenience function for timing operations using global monitor."""
    return global_monitor.time_operation(operation_name, tags)


def monitor_function(operation_name: Optional[str] = None, tags: Optional[Dict[str, str]] = None):
    """Convenience decorator for monitoring functions using global monitor."""
    return global_monitor.monitor_function(operation_name, tags) 