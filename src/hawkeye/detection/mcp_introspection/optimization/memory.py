"""
Memory Usage Optimization for MCP Introspection

Provides comprehensive memory management features including garbage collection
optimization, memory-efficient data structures, memory monitoring, and
automatic memory cleanup for large-scale MCP server introspection.
"""

import gc
import sys
import time
import threading
import psutil
import weakref
import logging
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union, Generator
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import contextmanager
from enum import Enum
import tracemalloc
import linecache
import os

from ..models import MCPServerConfig, MCPServerInfo, IntrospectionResult


class MemoryOptimizationLevel(Enum):
    """Memory optimization levels."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    MAXIMUM = "maximum"


@dataclass
class MemoryConfig:
    """Configuration for memory optimization."""
    # Optimization level
    optimization_level: MemoryOptimizationLevel = MemoryOptimizationLevel.STANDARD
    
    # Memory limits
    max_memory_mb: int = 512
    warning_threshold_mb: int = 400
    cleanup_threshold_mb: int = 450
    
    # Garbage collection
    enable_gc_optimization: bool = True
    gc_threshold_0: int = 700
    gc_threshold_1: int = 10
    gc_threshold_2: int = 10
    force_gc_interval: float = 30.0
    
    # Memory monitoring
    enable_memory_monitoring: bool = True
    monitoring_interval: float = 5.0
    track_memory_allocations: bool = False
    max_allocation_traces: int = 100
    
    # Cache management
    enable_cache_management: bool = True
    max_cache_entries: int = 1000
    cache_cleanup_interval: float = 60.0
    
    # Data structure optimization
    enable_data_compression: bool = True
    enable_weak_references: bool = True
    enable_object_pooling: bool = True
    
    # Memory leak detection
    enable_leak_detection: bool = True
    leak_detection_interval: float = 120.0
    leak_threshold_mb: int = 50


@dataclass
class MemorySnapshot:
    """Memory usage snapshot."""
    timestamp: float
    total_memory_mb: float
    available_memory_mb: float
    process_memory_mb: float
    memory_percent: float
    gc_stats: Dict[str, int]
    object_counts: Dict[str, int]
    top_allocations: List[Tuple[str, int, str]]
    
    @property
    def memory_pressure(self) -> str:
        """Calculate memory pressure level."""
        if self.memory_percent > 90:
            return "critical"
        elif self.memory_percent > 80:
            return "high"
        elif self.memory_percent > 60:
            return "medium"
        else:
            return "low"


@dataclass
class MemoryStatistics:
    """Comprehensive memory statistics."""
    peak_memory_mb: float = 0.0
    average_memory_mb: float = 0.0
    total_gc_collections: int = 0
    objects_collected: int = 0
    cleanup_operations: int = 0
    memory_warnings: int = 0
    memory_errors: int = 0
    leak_detections: int = 0
    cache_evictions: int = 0
    
    def update_peak_memory(self, current_mb: float) -> None:
        """Update peak memory usage."""
        if current_mb > self.peak_memory_mb:
            self.peak_memory_mb = current_mb


class MemoryEfficientCache:
    """Memory-efficient cache using weak references and size limits."""
    
    def __init__(self, max_size: int = 1000, ttl: float = 3600.0):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._access_order: deque = deque()
        self._lock = threading.RLock()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl:
                    # Move to end (most recently used)
                    self._access_order.remove(key)
                    self._access_order.append(key)
                    return value
                else:
                    # Expired entry
                    del self._cache[key]
                    self._access_order.remove(key)
            return None
    
    def put(self, key: str, value: Any) -> None:
        """Put value in cache."""
        with self._lock:
            current_time = time.time()
            
            # Remove existing entry if present
            if key in self._cache:
                self._access_order.remove(key)
            
            # Add new entry
            self._cache[key] = (value, current_time)
            self._access_order.append(key)
            
            # Evict if over size limit
            while len(self._cache) > self.max_size:
                oldest_key = self._access_order.popleft()
                if oldest_key in self._cache:
                    del self._cache[oldest_key]
    
    def clear(self) -> int:
        """Clear cache and return number of entries removed."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._access_order.clear()
            return count
    
    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        with self._lock:
            current_time = time.time()
            expired_keys = []
            
            for key, (_, timestamp) in self._cache.items():
                if current_time - timestamp >= self.ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
                self._access_order.remove(key)
            
            return len(expired_keys)
    
    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)


class ObjectPool:
    """Object pool for reusing expensive objects."""
    
    def __init__(self, factory: Callable, max_size: int = 50):
        self.factory = factory
        self.max_size = max_size
        self._pool: List[Any] = []
        self._lock = threading.Lock()
        self.created_count = 0
        self.reused_count = 0
    
    def acquire(self) -> Any:
        """Acquire object from pool."""
        with self._lock:
            if self._pool:
                self.reused_count += 1
                return self._pool.pop()
            else:
                self.created_count += 1
                return self.factory()
    
    def release(self, obj: Any) -> None:
        """Release object back to pool."""
        with self._lock:
            if len(self._pool) < self.max_size:
                # Reset object state if it has a reset method
                if hasattr(obj, 'reset'):
                    obj.reset()
                self._pool.append(obj)
    
    def clear(self) -> None:
        """Clear the pool."""
        with self._lock:
            self._pool.clear()
    
    def stats(self) -> Dict[str, int]:
        """Get pool statistics."""
        return {
            'pool_size': len(self._pool),
            'created_count': self.created_count,
            'reused_count': self.reused_count,
            'reuse_ratio': self.reused_count / max(self.created_count, 1)
        }


class MemoryProfiler:
    """Memory profiler for tracking allocations and usage."""
    
    def __init__(self, config: MemoryConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self._tracking = False
        self._snapshots: deque = deque(maxlen=100)
        
    def start_tracking(self) -> None:
        """Start memory tracking."""
        if self.config.track_memory_allocations:
            tracemalloc.start()
        self._tracking = True
        self.logger.info("Memory tracking started")
    
    def stop_tracking(self) -> None:
        """Stop memory tracking."""
        self._tracking = False
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        self.logger.info("Memory tracking stopped")
    
    def take_snapshot(self) -> MemorySnapshot:
        """Take a memory usage snapshot."""
        current_time = time.time()
        
        # System memory info
        memory = psutil.virtual_memory()
        process = psutil.Process()
        process_memory = process.memory_info()
        
        # Garbage collection stats
        gc_stats = {
            f'generation_{i}': len(gc.get_objects(i))
            for i in range(3)
        }
        gc_stats['total_collections'] = sum(gc.get_stats()[i]['collections'] for i in range(3))
        
        # Object counts
        object_counts = defaultdict(int)
        for obj in gc.get_objects():
            object_counts[type(obj).__name__] += 1
        
        # Top allocations
        top_allocations = []
        if tracemalloc.is_tracing():
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')[:10]
            
            for stat in top_stats:
                filename = stat.traceback.format()[0]
                top_allocations.append((
                    filename,
                    stat.size,
                    f"{stat.size / 1024 / 1024:.2f} MB"
                ))
        
        snapshot = MemorySnapshot(
            timestamp=current_time,
            total_memory_mb=memory.total / 1024 / 1024,
            available_memory_mb=memory.available / 1024 / 1024,
            process_memory_mb=process_memory.rss / 1024 / 1024,
            memory_percent=memory.percent,
            gc_stats=dict(gc_stats),
            object_counts=dict(object_counts),
            top_allocations=top_allocations
        )
        
        self._snapshots.append(snapshot)
        return snapshot
    
    def get_memory_trend(self, minutes: int = 10) -> Dict[str, Any]:
        """Get memory usage trend over time."""
        cutoff_time = time.time() - (minutes * 60)
        recent_snapshots = [
            s for s in self._snapshots
            if s.timestamp >= cutoff_time
        ]
        
        if not recent_snapshots:
            return {}
        
        memory_values = [s.process_memory_mb for s in recent_snapshots]
        return {
            'trend_direction': 'increasing' if memory_values[-1] > memory_values[0] else 'decreasing',
            'average_memory_mb': sum(memory_values) / len(memory_values),
            'peak_memory_mb': max(memory_values),
            'memory_variance': max(memory_values) - min(memory_values),
            'snapshot_count': len(recent_snapshots)
        }


class GarbageCollectionOptimizer:
    """Optimizes garbage collection for better memory management."""
    
    def __init__(self, config: MemoryConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self._original_thresholds = gc.get_threshold()
        self._collections_performed = 0
        self._objects_collected = 0
        
    def optimize_gc_settings(self) -> None:
        """Optimize garbage collection settings."""
        if not self.config.enable_gc_optimization:
            return
        
        # Set custom thresholds
        gc.set_threshold(
            self.config.gc_threshold_0,
            self.config.gc_threshold_1,
            self.config.gc_threshold_2
        )
        
        self.logger.info(
            f"GC thresholds set to: {self.config.gc_threshold_0}, "
            f"{self.config.gc_threshold_1}, {self.config.gc_threshold_2}"
        )
    
    def force_garbage_collection(self) -> Dict[str, int]:
        """Force garbage collection and return statistics."""
        initial_objects = len(gc.get_objects())
        
        # Collect each generation
        collected = {}
        for generation in range(3):
            collected[f'generation_{generation}'] = gc.collect(generation)
        
        final_objects = len(gc.get_objects())
        objects_freed = initial_objects - final_objects
        
        self._collections_performed += 1
        self._objects_collected += objects_freed
        
        stats = {
            'objects_before': initial_objects,
            'objects_after': final_objects,
            'objects_freed': objects_freed,
            'collections_by_generation': collected
        }
        
        self.logger.debug(f"Forced GC: {objects_freed} objects freed")
        return stats
    
    def restore_original_settings(self) -> None:
        """Restore original GC settings."""
        gc.set_threshold(*self._original_thresholds)
        self.logger.info("GC thresholds restored to original values")
    
    def get_gc_statistics(self) -> Dict[str, Any]:
        """Get garbage collection statistics."""
        stats = gc.get_stats()
        return {
            'current_thresholds': gc.get_threshold(),
            'generation_stats': stats,
            'total_collections_performed': self._collections_performed,
            'total_objects_collected': self._objects_collected,
            'gc_enabled': gc.isenabled()
        }


class MemoryLeakDetector:
    """Detects potential memory leaks."""
    
    def __init__(self, config: MemoryConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self._baseline_objects: Dict[str, int] = {}
        self._leak_alerts: List[Dict[str, Any]] = []
        
    def set_baseline(self) -> None:
        """Set baseline object counts."""
        self._baseline_objects = defaultdict(int)
        for obj in gc.get_objects():
            self._baseline_objects[type(obj).__name__] += 1
        
        self.logger.info(f"Memory leak baseline set with {len(self._baseline_objects)} object types")
    
    def check_for_leaks(self) -> List[Dict[str, Any]]:
        """Check for potential memory leaks."""
        if not self._baseline_objects:
            self.set_baseline()
            return []
        
        current_objects = defaultdict(int)
        for obj in gc.get_objects():
            current_objects[type(obj).__name__] += 1
        
        leaks = []
        for obj_type, baseline_count in self._baseline_objects.items():
            current_count = current_objects.get(obj_type, 0)
            growth = current_count - baseline_count
            
            # Check for significant growth
            if growth > 100 and growth > baseline_count * 0.5:  # 50% growth threshold
                leak_info = {
                    'object_type': obj_type,
                    'baseline_count': baseline_count,
                    'current_count': current_count,
                    'growth': growth,
                    'growth_percent': (growth / baseline_count) * 100,
                    'timestamp': time.time()
                }
                leaks.append(leak_info)
                self._leak_alerts.append(leak_info)
        
        if leaks:
            self.logger.warning(f"Detected {len(leaks)} potential memory leaks")
            for leak in leaks:
                self.logger.warning(
                    f"Leak detected: {leak['object_type']} "
                    f"({leak['baseline_count']} -> {leak['current_count']}, "
                    f"+{leak['growth_percent']:.1f}%)"
                )
        
        return leaks
    
    def reset_baseline(self) -> None:
        """Reset the memory baseline."""
        self.set_baseline()
        self._leak_alerts.clear()
        self.logger.info("Memory leak baseline reset")
    
    def get_leak_history(self) -> List[Dict[str, Any]]:
        """Get history of detected leaks."""
        return self._leak_alerts.copy()


class MemoryOptimizer:
    """Main memory optimization coordinator."""
    
    def __init__(self, config: Optional[MemoryConfig] = None):
        self.config = config or MemoryConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Components
        self.profiler = MemoryProfiler(self.config)
        self.gc_optimizer = GarbageCollectionOptimizer(self.config)
        self.leak_detector = MemoryLeakDetector(self.config)
        self.cache = MemoryEfficientCache(
            max_size=self.config.max_cache_entries,
            ttl=self.config.cache_cleanup_interval
        )
        
        # Object pools
        self.object_pools: Dict[str, ObjectPool] = {}
        
        # Monitoring
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None
        self.statistics = MemoryStatistics()
        
        # Weak reference tracking
        self._weak_refs: Set[weakref.ref] = set()
        
    def start_optimization(self) -> None:
        """Start memory optimization."""
        self.logger.info(f"Starting memory optimization (level: {self.config.optimization_level.value})")
        
        # Optimize GC settings
        self.gc_optimizer.optimize_gc_settings()
        
        # Start profiling
        self.profiler.start_tracking()
        
        # Set leak detection baseline
        self.leak_detector.set_baseline()
        
        # Start monitoring
        if self.config.enable_memory_monitoring:
            self._start_monitoring()
        
        self.logger.info("Memory optimization started")
    
    def stop_optimization(self) -> None:
        """Stop memory optimization."""
        self.logger.info("Stopping memory optimization")
        
        # Stop monitoring
        self._stop_monitoring()
        
        # Stop profiling
        self.profiler.stop_tracking()
        
        # Restore GC settings
        self.gc_optimizer.restore_original_settings()
        
        # Clear caches and pools
        self.cache.clear()
        for pool in self.object_pools.values():
            pool.clear()
        
        self.logger.info("Memory optimization stopped")
    
    def _start_monitoring(self) -> None:
        """Start background monitoring threads."""
        self._monitoring = True
        
        # Memory monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        # Cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        
        self.logger.info("Memory monitoring threads started")
    
    def _stop_monitoring(self) -> None:
        """Stop background monitoring threads."""
        self._monitoring = False
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5.0)
        
        self.logger.info("Memory monitoring threads stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring:
            try:
                # Take memory snapshot
                snapshot = self.profiler.take_snapshot()
                
                # Update statistics
                self.statistics.update_peak_memory(snapshot.process_memory_mb)
                
                # Check for memory pressure
                if snapshot.process_memory_mb > self.config.warning_threshold_mb:
                    self.statistics.memory_warnings += 1
                    self.logger.warning(
                        f"High memory usage: {snapshot.process_memory_mb:.1f} MB "
                        f"(threshold: {self.config.warning_threshold_mb} MB)"
                    )
                
                # Force cleanup if needed
                if snapshot.process_memory_mb > self.config.cleanup_threshold_mb:
                    self.force_cleanup()
                
                time.sleep(self.config.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in memory monitoring: {e}")
                time.sleep(5.0)
    
    def _cleanup_loop(self) -> None:
        """Cleanup loop for periodic maintenance."""
        while self._monitoring:
            try:
                # Cache cleanup
                if self.config.enable_cache_management:
                    expired = self.cache.cleanup_expired()
                    if expired > 0:
                        self.statistics.cache_evictions += expired
                
                # Garbage collection
                if self.config.enable_gc_optimization:
                    gc_stats = self.gc_optimizer.force_garbage_collection()
                    self.statistics.total_gc_collections += 1
                    self.statistics.objects_collected += gc_stats['objects_freed']
                
                # Leak detection
                if self.config.enable_leak_detection:
                    leaks = self.leak_detector.check_for_leaks()
                    if leaks:
                        self.statistics.leak_detections += len(leaks)
                
                # Clean up weak references
                self._cleanup_weak_references()
                
                time.sleep(self.config.cache_cleanup_interval)
                
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                time.sleep(10.0)
    
    def _cleanup_weak_references(self) -> None:
        """Clean up dead weak references."""
        dead_refs = {ref for ref in self._weak_refs if ref() is None}
        self._weak_refs -= dead_refs
    
    def force_cleanup(self) -> Dict[str, Any]:
        """Force comprehensive memory cleanup."""
        self.logger.info("Forcing comprehensive memory cleanup")
        
        cleanup_stats = {
            'cache_cleared': 0,
            'objects_collected': 0,
            'weak_refs_cleaned': 0,
            'pools_cleared': 0
        }
        
        # Clear cache
        cleanup_stats['cache_cleared'] = self.cache.clear()
        
        # Force garbage collection
        gc_stats = self.gc_optimizer.force_garbage_collection()
        cleanup_stats['objects_collected'] = gc_stats['objects_freed']
        
        # Clean weak references
        initial_weak_refs = len(self._weak_refs)
        self._cleanup_weak_references()
        cleanup_stats['weak_refs_cleaned'] = initial_weak_refs - len(self._weak_refs)
        
        # Clear object pools
        for pool in self.object_pools.values():
            pool.clear()
            cleanup_stats['pools_cleared'] += 1
        
        self.statistics.cleanup_operations += 1
        
        self.logger.info(f"Memory cleanup completed: {cleanup_stats}")
        return cleanup_stats
    
    def get_object_pool(self, name: str, factory: Callable, max_size: int = 50) -> ObjectPool:
        """Get or create an object pool."""
        if name not in self.object_pools:
            self.object_pools[name] = ObjectPool(factory, max_size)
        return self.object_pools[name]
    
    def add_weak_reference(self, obj: Any, callback: Optional[Callable] = None) -> weakref.ref:
        """Add a weak reference for tracking."""
        ref = weakref.ref(obj, callback)
        self._weak_refs.add(ref)
        return ref
    
    def get_current_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage information."""
        snapshot = self.profiler.take_snapshot()
        return {
            'process_memory_mb': snapshot.process_memory_mb,
            'memory_percent': snapshot.memory_percent,
            'available_memory_mb': snapshot.available_memory_mb,
            'memory_pressure': snapshot.memory_pressure
        }
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics."""
        current_usage = self.get_current_memory_usage()
        
        return {
            'current_memory': current_usage,
            'peak_memory_mb': self.statistics.peak_memory_mb,
            'total_gc_collections': self.statistics.total_gc_collections,
            'objects_collected': self.statistics.objects_collected,
            'cleanup_operations': self.statistics.cleanup_operations,
            'memory_warnings': self.statistics.memory_warnings,
            'leak_detections': self.statistics.leak_detections,
            'cache_stats': {
                'size': self.cache.size(),
                'evictions': self.statistics.cache_evictions
            },
            'gc_stats': self.gc_optimizer.get_gc_statistics(),
            'object_pool_stats': {
                name: pool.stats() for name, pool in self.object_pools.items()
            },
            'weak_refs_count': len(self._weak_refs),
            'config': {
                'optimization_level': self.config.optimization_level.value,
                'max_memory_mb': self.config.max_memory_mb,
                'monitoring_enabled': self.config.enable_memory_monitoring
            }
        }
    
    @contextmanager
    def memory_context(self, operation_name: str = "operation"):
        """Context manager for monitoring memory usage during operations."""
        initial_snapshot = self.profiler.take_snapshot()
        start_time = time.time()
        
        self.logger.debug(f"Starting {operation_name} with {initial_snapshot.process_memory_mb:.1f} MB")
        
        try:
            yield self
        finally:
            final_snapshot = self.profiler.take_snapshot()
            duration = time.time() - start_time
            memory_delta = final_snapshot.process_memory_mb - initial_snapshot.process_memory_mb
            
            self.logger.debug(
                f"Completed {operation_name} in {duration:.2f}s, "
                f"memory delta: {memory_delta:+.1f} MB "
                f"(final: {final_snapshot.process_memory_mb:.1f} MB)"
            )
            
            # Force cleanup if significant memory increase
            if memory_delta > 50:  # 50MB threshold
                self.logger.info(f"Large memory increase detected (+{memory_delta:.1f} MB), forcing cleanup")
                self.force_cleanup()


def create_memory_optimizer(optimization_level: str = "standard") -> MemoryOptimizer:
    """Create a memory optimizer with the specified optimization level."""
    config = MemoryConfig(
        optimization_level=MemoryOptimizationLevel(optimization_level)
    )
    
    # Adjust settings based on optimization level
    if config.optimization_level == MemoryOptimizationLevel.MINIMAL:
        config.enable_gc_optimization = False
        config.enable_memory_monitoring = False
        config.track_memory_allocations = False
    elif config.optimization_level == MemoryOptimizationLevel.AGGRESSIVE:
        config.max_memory_mb = 256
        config.warning_threshold_mb = 200
        config.cleanup_threshold_mb = 230
        config.force_gc_interval = 15.0
        config.monitoring_interval = 2.0
    elif config.optimization_level == MemoryOptimizationLevel.MAXIMUM:
        config.max_memory_mb = 128
        config.warning_threshold_mb = 100
        config.cleanup_threshold_mb = 115
        config.force_gc_interval = 5.0
        config.monitoring_interval = 1.0
        config.track_memory_allocations = True
    
    return MemoryOptimizer(config) 