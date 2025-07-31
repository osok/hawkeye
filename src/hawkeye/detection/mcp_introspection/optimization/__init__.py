"""
MCP Introspection Optimization Module

Provides advanced optimization features for MCP introspection including
connection pooling, caching, scaling, memory optimization, and performance enhancements.
"""

from .pooling import (
    OptimizedConnectionPool,
    PoolOptimizationConfig,
    ConnectionMetrics,
    CircuitBreaker
)

from .caching import (
    CacheStrategy,
    CacheConfig,
    CacheEntry,
    CacheStatistics,
    CacheKeyGenerator,
    ResultCache
)

from .scaling import (
    ScalingConfig,
    BatchMetrics,
    ScalingStatistics,
    ResourceMonitor,
    BatchProcessor,
    LargeScaleOptimizer
)

from .memory import (
    MemoryOptimizationLevel,
    MemoryConfig,
    MemorySnapshot,
    MemoryStatistics,
    MemoryEfficientCache,
    ObjectPool,
    MemoryProfiler,
    GarbageCollectionOptimizer,
    MemoryLeakDetector,
    MemoryOptimizer,
    create_memory_optimizer
)

__all__ = [
    # Connection pooling
    'OptimizedConnectionPool',
    'PoolOptimizationConfig', 
    'ConnectionMetrics',
    'CircuitBreaker',
    
    # Caching
    'CacheStrategy',
    'CacheConfig',
    'CacheEntry',
    'CacheStatistics',
    'CacheKeyGenerator',
    'ResultCache',
    
    # Scaling
    'ScalingConfig',
    'BatchMetrics',
    'ScalingStatistics',
    'ResourceMonitor',
    'BatchProcessor',
    'LargeScaleOptimizer',
    
    # Memory optimization
    'MemoryOptimizationLevel',
    'MemoryConfig',
    'MemorySnapshot',
    'MemoryStatistics',
    'MemoryEfficientCache',
    'ObjectPool',
    'MemoryProfiler',
    'GarbageCollectionOptimizer',
    'MemoryLeakDetector',
    'MemoryOptimizer',
    'create_memory_optimizer'
] 