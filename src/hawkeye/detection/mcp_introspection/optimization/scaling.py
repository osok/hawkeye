"""
Large-Scale Scanning Optimization

Provides advanced optimization features for large-scale MCP server scanning including
batch processing, parallel execution, resource management, and adaptive scaling.
"""

import time
import threading
import queue
import logging
import statistics
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Iterator
from dataclasses import dataclass, field
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from contextlib import contextmanager
import weakref
import gc
import psutil
import os

from ..models import MCPServerConfig, MCPServerInfo, IntrospectionResult
from ..introspection import MCPIntrospection, IntrospectionConfig
from .pooling import OptimizedConnectionPool, PoolOptimizationConfig
from .caching import ResultCache, CacheConfig


@dataclass
class ScalingConfig:
    """Configuration for large-scale scanning optimizations."""
    # Batch processing
    enable_batch_processing: bool = True
    batch_size: int = 50
    max_batch_size: int = 200
    adaptive_batch_sizing: bool = True
    batch_timeout: float = 300.0  # 5 minutes per batch
    
    # Parallel execution
    max_workers: int = 10
    worker_scaling_factor: float = 1.5
    adaptive_worker_scaling: bool = True
    worker_timeout: float = 180.0  # 3 minutes per worker
    
    # Resource management
    enable_resource_monitoring: bool = True
    max_memory_usage_mb: int = 1024  # 1GB
    max_cpu_usage_percent: float = 80.0
    resource_check_interval: float = 10.0
    
    # Performance optimization
    enable_result_streaming: bool = True
    enable_early_termination: bool = True
    failure_threshold_percent: float = 50.0
    enable_priority_queuing: bool = True
    
    # Advanced features
    enable_load_balancing: bool = True
    enable_circuit_breaker: bool = True
    enable_backpressure: bool = True
    backpressure_threshold: int = 100


@dataclass
class BatchMetrics:
    """Metrics for a batch of servers."""
    batch_id: str
    server_count: int
    start_time: float
    end_time: Optional[float] = None
    successful_scans: int = 0
    failed_scans: int = 0
    timeout_scans: int = 0
    total_duration: float = 0.0
    average_scan_time: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate batch success rate."""
        total = self.successful_scans + self.failed_scans + self.timeout_scans
        return (self.successful_scans / total * 100) if total > 0 else 0.0
    
    @property
    def is_complete(self) -> bool:
        """Check if batch is complete."""
        return self.end_time is not None
    
    def complete_batch(self) -> None:
        """Mark batch as complete and calculate final metrics."""
        self.end_time = time.time()
        self.total_duration = self.end_time - self.start_time
        total_scans = self.successful_scans + self.failed_scans + self.timeout_scans
        if total_scans > 0:
            self.average_scan_time = self.total_duration / total_scans


@dataclass
class ScalingStatistics:
    """Comprehensive scaling statistics."""
    total_servers_processed: int = 0
    total_batches_processed: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    timeout_scans: int = 0
    average_batch_size: float = 0.0
    average_batch_duration: float = 0.0
    peak_memory_usage_mb: float = 0.0
    peak_cpu_usage_percent: float = 0.0
    total_processing_time: float = 0.0
    throughput_servers_per_second: float = 0.0
    
    @property
    def overall_success_rate(self) -> float:
        """Calculate overall success rate."""
        total = self.successful_scans + self.failed_scans + self.timeout_scans
        return (self.successful_scans / total * 100) if total > 0 else 0.0


class ResourceMonitor:
    """Monitors system resources during large-scale scanning."""
    
    def __init__(self, config: ScalingConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._resource_history: deque = deque(maxlen=100)
        self._alerts: List[str] = []
        
    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        if self._monitoring:
            return
            
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self.logger.info("Resource monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        self.logger.info("Resource monitoring stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring:
            try:
                # Get current resource usage
                memory_usage = psutil.virtual_memory().percent
                cpu_usage = psutil.cpu_percent(interval=1.0)
                
                # Record metrics
                timestamp = time.time()
                self._resource_history.append({
                    'timestamp': timestamp,
                    'memory_percent': memory_usage,
                    'cpu_percent': cpu_usage,
                    'memory_mb': psutil.Process().memory_info().rss / 1024 / 1024
                })
                
                # Check thresholds
                if memory_usage > 90.0:
                    alert = f"High memory usage: {memory_usage:.1f}%"
                    self._alerts.append(alert)
                    self.logger.warning(alert)
                
                if cpu_usage > self.config.max_cpu_usage_percent:
                    alert = f"High CPU usage: {cpu_usage:.1f}%"
                    self._alerts.append(alert)
                    self.logger.warning(alert)
                
                time.sleep(self.config.resource_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in resource monitoring: {e}")
                time.sleep(5.0)
    
    def get_current_usage(self) -> Dict[str, float]:
        """Get current resource usage."""
        return {
            'memory_percent': psutil.virtual_memory().percent,
            'cpu_percent': psutil.cpu_percent(),
            'memory_mb': psutil.Process().memory_info().rss / 1024 / 1024
        }
    
    def should_throttle(self) -> bool:
        """Check if processing should be throttled due to resource constraints."""
        current = self.get_current_usage()
        return (
            current['memory_mb'] > self.config.max_memory_usage_mb or
            current['cpu_percent'] > self.config.max_cpu_usage_percent
        )
    
    def get_resource_history(self) -> List[Dict[str, Any]]:
        """Get resource usage history."""
        return list(self._resource_history)


class BatchProcessor:
    """Processes batches of MCP servers efficiently."""
    
    def __init__(self, config: ScalingConfig, introspection: MCPIntrospection):
        self.config = config
        self.introspection = introspection
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Batch tracking
        self._batch_metrics: Dict[str, BatchMetrics] = {}
        self._batch_counter = 0
        
        # Worker management
        self._executor: Optional[ThreadPoolExecutor] = None
        self._active_futures: Set[Future] = set()
        
        # Resource monitoring
        self._resource_monitor = ResourceMonitor(config)
        
    def process_servers_in_batches(
        self,
        servers: List[MCPServerConfig],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Iterator[Tuple[str, List[IntrospectionResult]]]:
        """
        Process servers in optimized batches.
        
        Args:
            servers: List of server configurations to process
            progress_callback: Optional callback for progress updates
            
        Yields:
            Tuple of (batch_id, results) for each completed batch
        """
        if not servers:
            return
        
        self.logger.info(f"Starting batch processing of {len(servers)} servers")
        
        # Start resource monitoring
        if self.config.enable_resource_monitoring:
            self._resource_monitor.start_monitoring()
        
        try:
            # Create batches
            batches = self._create_batches(servers)
            self.logger.info(f"Created {len(batches)} batches")
            
            # Initialize thread pool
            max_workers = min(self.config.max_workers, len(batches))
            self._executor = ThreadPoolExecutor(max_workers=max_workers)
            
            # Process batches
            batch_futures = {}
            completed_batches = 0
            
            for batch_id, batch_servers in batches:
                # Check resource constraints
                if self.config.enable_resource_monitoring and self._resource_monitor.should_throttle():
                    self.logger.warning("Resource constraints detected, throttling batch submission")
                    time.sleep(5.0)
                
                # Submit batch for processing
                future = self._executor.submit(self._process_batch, batch_id, batch_servers)
                batch_futures[future] = batch_id
                self._active_futures.add(future)
                
                self.logger.debug(f"Submitted batch {batch_id} with {len(batch_servers)} servers")
            
            # Collect results as batches complete
            for future in as_completed(batch_futures, timeout=self.config.batch_timeout * len(batches)):
                batch_id = batch_futures[future]
                
                try:
                    results = future.result()
                    completed_batches += 1
                    
                    # Update progress
                    if progress_callback:
                        progress_callback(completed_batches, len(batches))
                    
                    # Yield results
                    yield batch_id, results
                    
                    self.logger.info(f"Completed batch {batch_id} ({completed_batches}/{len(batches)})")
                    
                except Exception as e:
                    self.logger.error(f"Batch {batch_id} failed: {e}")
                    yield batch_id, []
                
                finally:
                    self._active_futures.discard(future)
                    
                    # Force garbage collection after each batch
                    gc.collect()
        
        finally:
            # Cleanup
            if self._executor:
                self._executor.shutdown(wait=True)
            
            if self.config.enable_resource_monitoring:
                self._resource_monitor.stop_monitoring()
            
            self.logger.info("Batch processing completed")
    
    def _create_batches(self, servers: List[MCPServerConfig]) -> List[Tuple[str, List[MCPServerConfig]]]:
        """Create optimized batches from server list."""
        batches = []
        
        # Determine optimal batch size
        batch_size = self._calculate_optimal_batch_size(len(servers))
        
        # Create batches
        for i in range(0, len(servers), batch_size):
            batch_servers = servers[i:i + batch_size]
            batch_id = f"batch_{self._batch_counter:04d}"
            self._batch_counter += 1
            
            batches.append((batch_id, batch_servers))
            
            # Initialize batch metrics
            self._batch_metrics[batch_id] = BatchMetrics(
                batch_id=batch_id,
                server_count=len(batch_servers),
                start_time=time.time()
            )
        
        return batches
    
    def _calculate_optimal_batch_size(self, total_servers: int) -> int:
        """Calculate optimal batch size based on configuration and system resources."""
        if not self.config.adaptive_batch_sizing:
            return self.config.batch_size
        
        # Base batch size
        batch_size = self.config.batch_size
        
        # Adjust based on total servers
        if total_servers > 1000:
            batch_size = min(self.config.max_batch_size, batch_size * 2)
        elif total_servers < 100:
            batch_size = max(10, batch_size // 2)
        
        # Adjust based on available resources
        if self.config.enable_resource_monitoring:
            current_usage = self._resource_monitor.get_current_usage()
            if current_usage['memory_percent'] > 70:
                batch_size = max(10, batch_size // 2)
            elif current_usage['cpu_percent'] > 70:
                batch_size = max(10, batch_size // 2)
        
        return min(batch_size, self.config.max_batch_size)
    
    def _process_batch(self, batch_id: str, servers: List[MCPServerConfig]) -> List[IntrospectionResult]:
        """Process a single batch of servers."""
        batch_metrics = self._batch_metrics[batch_id]
        results = []
        
        self.logger.debug(f"Processing batch {batch_id} with {len(servers)} servers")
        
        try:
            for server in servers:
                try:
                    # Check for early termination
                    if self.config.enable_early_termination:
                        failure_rate = (batch_metrics.failed_scans + batch_metrics.timeout_scans) / max(1, len(results))
                        if failure_rate > (self.config.failure_threshold_percent / 100):
                            self.logger.warning(f"Early termination triggered for batch {batch_id} due to high failure rate")
                            break
                    
                    # Perform introspection
                    start_time = time.time()
                    result = self.introspection.introspect_server(server)
                    duration = time.time() - start_time
                    
                    # Update metrics
                    if result.success:
                        batch_metrics.successful_scans += 1
                    else:
                        batch_metrics.failed_scans += 1
                    
                    results.append(result)
                    
                    self.logger.debug(f"Processed server {server.name} in {duration:.2f}s")
                    
                except TimeoutError:
                    batch_metrics.timeout_scans += 1
                    self.logger.warning(f"Timeout processing server {server.name}")
                    
                except Exception as e:
                    batch_metrics.failed_scans += 1
                    self.logger.error(f"Error processing server {server.name}: {e}")
            
            # Update resource usage
            if self.config.enable_resource_monitoring:
                current_usage = self._resource_monitor.get_current_usage()
                batch_metrics.memory_usage_mb = current_usage['memory_mb']
                batch_metrics.cpu_usage_percent = current_usage['cpu_percent']
            
            batch_metrics.complete_batch()
            
            self.logger.info(
                f"Batch {batch_id} completed: {batch_metrics.successful_scans} successful, "
                f"{batch_metrics.failed_scans} failed, {batch_metrics.timeout_scans} timeout "
                f"(success rate: {batch_metrics.success_rate:.1f}%)"
            )
            
        except Exception as e:
            self.logger.error(f"Unexpected error in batch {batch_id}: {e}")
            batch_metrics.complete_batch()
        
        return results
    
    def get_batch_statistics(self) -> Dict[str, Any]:
        """Get comprehensive batch processing statistics."""
        completed_batches = [m for m in self._batch_metrics.values() if m.is_complete]
        
        if not completed_batches:
            return {"message": "No completed batches"}
        
        # Calculate aggregate statistics
        total_servers = sum(b.server_count for b in completed_batches)
        total_successful = sum(b.successful_scans for b in completed_batches)
        total_failed = sum(b.failed_scans for b in completed_batches)
        total_timeout = sum(b.timeout_scans for b in completed_batches)
        
        avg_batch_size = statistics.mean(b.server_count for b in completed_batches)
        avg_batch_duration = statistics.mean(b.total_duration for b in completed_batches)
        avg_success_rate = statistics.mean(b.success_rate for b in completed_batches)
        
        return {
            "batch_summary": {
                "total_batches": len(completed_batches),
                "total_servers_processed": total_servers,
                "average_batch_size": avg_batch_size,
                "average_batch_duration": avg_batch_duration,
            },
            "scan_results": {
                "successful_scans": total_successful,
                "failed_scans": total_failed,
                "timeout_scans": total_timeout,
                "overall_success_rate": (total_successful / max(1, total_servers)) * 100,
                "average_success_rate": avg_success_rate,
            },
            "performance_metrics": {
                "peak_memory_usage_mb": max((b.memory_usage_mb for b in completed_batches), default=0),
                "peak_cpu_usage_percent": max((b.cpu_usage_percent for b in completed_batches), default=0),
                "throughput_servers_per_second": total_servers / sum(b.total_duration for b in completed_batches) if completed_batches else 0,
            },
            "resource_monitoring": self._resource_monitor.get_resource_history() if self.config.enable_resource_monitoring else []
        }


class LargeScaleOptimizer:
    """
    Main optimizer for large-scale MCP server scanning.
    
    Coordinates batch processing, resource management, and performance optimization
    for scanning hundreds or thousands of MCP servers efficiently.
    """
    
    def __init__(
        self,
        scaling_config: Optional[ScalingConfig] = None,
        introspection_config: Optional[IntrospectionConfig] = None,
        pool_config: Optional[PoolOptimizationConfig] = None,
        cache_config: Optional[CacheConfig] = None
    ):
        """Initialize the large-scale optimizer."""
        self.scaling_config = scaling_config or ScalingConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize introspection system with optimizations
        self.introspection_config = introspection_config or IntrospectionConfig(
            timeout=120.0,  # Shorter timeout for large-scale scans
            enable_detailed_analysis=False,  # Disable for performance
            enable_risk_assessment=True
        )
        
        self.introspection = MCPIntrospection(self.introspection_config)
        
        # Initialize optimized components
        self.connection_pool = OptimizedConnectionPool(pool_config)
        self.result_cache = ResultCache(cache_config)
        self.batch_processor = BatchProcessor(self.scaling_config, self.introspection)
        
        # Statistics tracking
        self.statistics = ScalingStatistics()
        self._start_time: Optional[float] = None
        
        self.logger.info(
            f"LargeScaleOptimizer initialized with batch_size={self.scaling_config.batch_size}, "
            f"max_workers={self.scaling_config.max_workers}, "
            f"resource_monitoring={self.scaling_config.enable_resource_monitoring}"
        )
    
    def optimize_large_scan(
        self,
        servers: List[MCPServerConfig],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[IntrospectionResult]:
        """
        Perform optimized large-scale scanning of MCP servers.
        
        Args:
            servers: List of server configurations to scan
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of introspection results
        """
        if not servers:
            return []
        
        self._start_time = time.time()
        all_results = []
        
        self.logger.info(f"Starting large-scale optimization for {len(servers)} servers")
        
        try:
            # Process servers in optimized batches
            total_batches = 0
            completed_batches = 0
            
            for batch_id, batch_results in self.batch_processor.process_servers_in_batches(
                servers, progress_callback
            ):
                all_results.extend(batch_results)
                completed_batches += 1
                
                # Update statistics
                self._update_statistics(batch_results)
                
                self.logger.debug(f"Processed batch {batch_id}: {len(batch_results)} results")
            
            # Finalize statistics
            self._finalize_statistics()
            
            self.logger.info(
                f"Large-scale optimization completed: {len(all_results)} results, "
                f"success rate: {self.statistics.overall_success_rate:.1f}%, "
                f"duration: {self.statistics.total_processing_time:.2f}s"
            )
            
        except Exception as e:
            self.logger.error(f"Error in large-scale optimization: {e}", exc_info=True)
        
        return all_results
    
    def _update_statistics(self, batch_results: List[IntrospectionResult]) -> None:
        """Update running statistics with batch results."""
        for result in batch_results:
            self.statistics.total_servers_processed += 1
            
            if result.success:
                self.statistics.successful_scans += 1
            else:
                error_type = result.metadata.get('error_type', 'unknown')
                if 'timeout' in error_type.lower():
                    self.statistics.timeout_scans += 1
                else:
                    self.statistics.failed_scans += 1
    
    def _finalize_statistics(self) -> None:
        """Finalize statistics after all processing is complete."""
        if self._start_time:
            self.statistics.total_processing_time = time.time() - self._start_time
            
            if self.statistics.total_processing_time > 0:
                self.statistics.throughput_servers_per_second = (
                    self.statistics.total_servers_processed / self.statistics.total_processing_time
                )
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics."""
        base_stats = {
            "scaling_statistics": {
                "total_servers_processed": self.statistics.total_servers_processed,
                "successful_scans": self.statistics.successful_scans,
                "failed_scans": self.statistics.failed_scans,
                "timeout_scans": self.statistics.timeout_scans,
                "overall_success_rate": self.statistics.overall_success_rate,
                "total_processing_time": self.statistics.total_processing_time,
                "throughput_servers_per_second": self.statistics.throughput_servers_per_second,
            },
            "batch_statistics": self.batch_processor.get_batch_statistics(),
            "connection_pool_statistics": self.connection_pool.get_optimization_stats(),
            "cache_statistics": self.result_cache.get_statistics().__dict__,
        }
        
        return base_stats
    
    @contextmanager
    def optimization_context(self):
        """Context manager for optimization lifecycle."""
        try:
            self.logger.info("Starting optimization context")
            yield self
        finally:
            self.logger.info("Cleaning up optimization context")
            # Cleanup resources
            gc.collect()