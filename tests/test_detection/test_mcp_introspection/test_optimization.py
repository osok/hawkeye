"""
Unit tests for MCP Introspection Performance Optimizations

Tests for connection pooling, result caching, large-scale processing, 
and memory optimization components.
"""

import pytest
import time
import threading
import gc
import weakref
from unittest.mock import Mock, patch, MagicMock, call
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from src.hawkeye.detection.mcp_introspection.optimization import (
    # Connection pooling
    OptimizedConnectionPool,
    PoolOptimizationConfig,
    ConnectionMetrics,
    CircuitBreaker,
    # Caching
    CacheStrategy,
    CacheConfig,
    CacheEntry,
    CacheStatistics,
    CacheKeyGenerator,
    ResultCache,
    # Scaling
    ScalingConfig,
    BatchMetrics,
    ScalingStatistics,
    ResourceMonitor,
    BatchProcessor,
    LargeScaleOptimizer,
    # Memory optimization
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

from src.hawkeye.detection.mcp_introspection.models import (
    MCPServerConfig,
    MCPServerInfo,
    IntrospectionResult
)


class TestOptimizedConnectionPool:
    """Test cases for OptimizedConnectionPool."""
    
    @pytest.fixture
    def pool_config(self):
        """Create test pool configuration."""
        return PoolOptimizationConfig(
            max_connections=5,
            connection_timeout=1.0,
            idle_timeout=2.0,
            health_check_interval=0.5,
            enable_circuit_breaker=True,
            circuit_breaker_threshold=3,
            circuit_breaker_timeout=1.0
        )
    
    @pytest.fixture
    def connection_pool(self, pool_config):
        """Create test connection pool."""
        pool = OptimizedConnectionPool(pool_config)
        yield pool
        pool.shutdown()
    
    def test_pool_initialization(self, pool_config):
        """Test connection pool initialization."""
        pool = OptimizedConnectionPool(pool_config)
        
        assert pool.config == pool_config
        assert pool._max_connections == 5
        assert pool._connection_timeout == 1.0
        assert len(pool._connections) == 0
        assert pool._is_shutdown == False
        
        pool.shutdown()
    
    def test_connection_acquisition_and_release(self, connection_pool):
        """Test connection acquisition and release."""
        mock_factory = Mock(return_value="mock_connection")
        
        # Acquire connection
        with connection_pool.get_connection("test_server", mock_factory) as conn:
            assert conn == "mock_connection"
            assert connection_pool.get_active_connections() == 1
        
        # Connection should be released
        assert connection_pool.get_active_connections() == 0
    
    def test_connection_pool_limit(self, connection_pool):
        """Test connection pool size limits."""
        mock_factory = Mock(return_value="mock_connection")
        connections = []
        
        # Acquire maximum connections
        for i in range(5):
            conn_ctx = connection_pool.get_connection(f"server_{i}", mock_factory)
            connections.append(conn_ctx)
            connections[i].__enter__()
        
        assert connection_pool.get_active_connections() == 5
        
        # Clean up
        for conn_ctx in connections:
            conn_ctx.__exit__(None, None, None)
    
    def test_connection_reuse(self, connection_pool):
        """Test connection reuse for same server."""
        mock_factory = Mock(return_value="mock_connection")
        
        # First connection
        with connection_pool.get_connection("test_server", mock_factory):
            pass
        
        # Second connection to same server should reuse
        with connection_pool.get_connection("test_server", mock_factory):
            pass
        
        # Factory should only be called once
        assert mock_factory.call_count == 1
    
    def test_circuit_breaker(self, connection_pool):
        """Test circuit breaker functionality."""
        def failing_factory():
            raise Exception("Connection failed")
        
        # Trigger circuit breaker
        for _ in range(3):
            with pytest.raises(Exception):
                with connection_pool.get_connection("failing_server", failing_factory):
                    pass
        
        # Circuit should be open now
        assert connection_pool._circuit_breakers["failing_server"].is_open()
    
    def test_health_checks(self, connection_pool):
        """Test connection health checking."""
        mock_connection = Mock()
        mock_connection.is_healthy.return_value = False
        mock_factory = Mock(return_value=mock_connection)
        
        with connection_pool.get_connection("test_server", mock_factory):
            pass
        
        # Simulate health check
        time.sleep(0.6)  # Wait for health check interval
        
        # Connection should be marked unhealthy and removed
        assert "test_server" not in connection_pool._connections
    
    def test_metrics_collection(self, connection_pool):
        """Test metrics collection."""
        mock_factory = Mock(return_value="mock_connection")
        
        with connection_pool.get_connection("test_server", mock_factory):
            pass
        
        metrics = connection_pool.get_metrics()
        assert isinstance(metrics, ConnectionMetrics)
        assert metrics.total_connections_created >= 1
        assert metrics.total_connections_released >= 1


class TestResultCache:
    """Test cases for ResultCache."""
    
    @pytest.fixture
    def cache_config(self):
        """Create test cache configuration."""
        return CacheConfig(
            strategy=CacheStrategy.LRU,
            max_size=100,
            ttl=60.0,
            enable_compression=False,
            enable_persistence=False
        )
    
    @pytest.fixture
    def result_cache(self, cache_config):
        """Create test result cache."""
        cache = ResultCache(cache_config)
        yield cache
        cache.clear()
    
    def test_cache_initialization(self, cache_config):
        """Test cache initialization."""
        cache = ResultCache(cache_config)
        
        assert cache.config == cache_config
        assert cache._max_size == 100
        assert cache._ttl == 60.0
        assert len(cache._cache) == 0
    
    def test_cache_put_and_get(self, result_cache):
        """Test basic cache operations."""
        test_result = IntrospectionResult(
            server_config=MCPServerConfig(name="test", command="node", args=[]),
            success=True,
            timestamp=time.time(),
            duration=1.0
        )
        
        # Put value
        result_cache.put("test_key", test_result)
        
        # Get value
        cached_result = result_cache.get("test_key")
        assert cached_result is not None
        assert cached_result.server_config.name == "test"
    
    def test_cache_expiration(self, cache_config):
        """Test cache entry expiration."""
        cache_config.ttl = 0.1  # 100ms TTL
        cache = ResultCache(cache_config)
        
        test_result = IntrospectionResult(
            server_config=MCPServerConfig(name="test", command="node", args=[]),
            success=True,
            timestamp=time.time(),
            duration=1.0
        )
        
        cache.put("test_key", test_result)
        assert cache.get("test_key") is not None
        
        # Wait for expiration
        time.sleep(0.2)
        assert cache.get("test_key") is None
    
    def test_cache_lru_eviction(self, result_cache):
        """Test LRU eviction policy."""
        result_cache._max_size = 3
        
        # Fill cache beyond capacity
        for i in range(5):
            test_result = IntrospectionResult(
                server_config=MCPServerConfig(name=f"test_{i}", command="node", args=[]),
                success=True,
                timestamp=time.time(),
                duration=1.0
            )
            result_cache.put(f"key_{i}", test_result)
        
        # Only last 3 entries should remain
        assert result_cache.size() == 3
        assert result_cache.get("key_0") is None  # Should be evicted
        assert result_cache.get("key_1") is None  # Should be evicted
        assert result_cache.get("key_2") is not None
        assert result_cache.get("key_3") is not None
        assert result_cache.get("key_4") is not None
    
    def test_cache_statistics(self, result_cache):
        """Test cache statistics collection."""
        test_result = IntrospectionResult(
            server_config=MCPServerConfig(name="test", command="node", args=[]),
            success=True,
            timestamp=time.time(),
            duration=1.0
        )
        
        # Generate some cache activity
        result_cache.put("key1", test_result)
        result_cache.get("key1")  # Hit
        result_cache.get("key2")  # Miss
        
        stats = result_cache.get_statistics()
        assert isinstance(stats, CacheStatistics)
        assert stats.hits >= 1
        assert stats.misses >= 1
        assert stats.hit_ratio > 0


class TestLargeScaleOptimizer:
    """Test cases for LargeScaleOptimizer."""
    
    @pytest.fixture
    def scaling_config(self):
        """Create test scaling configuration."""
        return ScalingConfig(
            enable_batch_processing=True,
            batch_size=5,
            max_workers=3,
            enable_resource_monitoring=False,  # Disable for tests
            adaptive_batch_sizing=False
        )
    
    @pytest.fixture
    def mock_introspection(self):
        """Create mock introspection service."""
        mock = Mock()
        mock.introspect_server.return_value = IntrospectionResult(
            server_config=MCPServerConfig(name="test", command="node", args=[]),
            success=True,
            timestamp=time.time(),
            duration=1.0
        )
        return mock
    
    @pytest.fixture
    def large_scale_optimizer(self, scaling_config, mock_introspection):
        """Create test large scale optimizer."""
        optimizer = LargeScaleOptimizer(
            scaling_config=scaling_config,
            introspection=mock_introspection
        )
        yield optimizer
        optimizer.cleanup()
    
    def test_optimizer_initialization(self, scaling_config, mock_introspection):
        """Test optimizer initialization."""
        optimizer = LargeScaleOptimizer(
            scaling_config=scaling_config,
            introspection=mock_introspection
        )
        
        assert optimizer.scaling_config == scaling_config
        assert optimizer.introspection == mock_introspection
        assert optimizer.statistics.total_servers_processed == 0
    
    def test_batch_processing(self, large_scale_optimizer):
        """Test batch processing functionality."""
        # Create test servers
        servers = [
            MCPServerConfig(name=f"server_{i}", command="node", args=[])
            for i in range(12)
        ]
        
        # Process servers
        results = large_scale_optimizer.optimize_large_scan(servers)
        
        assert len(results) == 12
        assert all(result.success for result in results)
        assert large_scale_optimizer.statistics.total_servers_processed == 12
    
    def test_batch_size_calculation(self, large_scale_optimizer):
        """Test batch size calculation."""
        processor = large_scale_optimizer.batch_processor
        
        # Test various server counts
        assert processor._calculate_optimal_batch_size(10) == 5  # Default batch size
        assert processor._calculate_optimal_batch_size(50) == 5
        assert processor._calculate_optimal_batch_size(3) == 3   # Smaller than batch size
    
    def test_statistics_tracking(self, large_scale_optimizer):
        """Test statistics tracking."""
        servers = [
            MCPServerConfig(name=f"server_{i}", command="node", args=[])
            for i in range(7)
        ]
        
        large_scale_optimizer.optimize_large_scan(servers)
        
        stats = large_scale_optimizer.get_optimization_statistics()
        assert stats['total_servers_processed'] == 7
        assert stats['total_batches_processed'] >= 1
        assert stats['overall_success_rate'] == 100.0


class TestResourceMonitor:
    """Test cases for ResourceMonitor."""
    
    @pytest.fixture
    def scaling_config(self):
        """Create test scaling configuration."""
        return ScalingConfig(
            enable_resource_monitoring=True,
            max_memory_usage_mb=512,
            max_cpu_usage_percent=80.0,
            resource_check_interval=0.1
        )
    
    @pytest.fixture
    def resource_monitor(self, scaling_config):
        """Create test resource monitor."""
        monitor = ResourceMonitor(scaling_config)
        yield monitor
        monitor.stop_monitoring()
    
    def test_monitor_initialization(self, scaling_config):
        """Test resource monitor initialization."""
        monitor = ResourceMonitor(scaling_config)
        
        assert monitor.config == scaling_config
        assert monitor._monitoring == False
        assert len(monitor._resource_history) == 0
    
    def test_resource_monitoring(self, resource_monitor):
        """Test resource monitoring functionality."""
        resource_monitor.start_monitoring()
        assert resource_monitor._monitoring == True
        
        # Wait for some monitoring data
        time.sleep(0.2)
        
        usage = resource_monitor.get_current_usage()
        assert 'memory_percent' in usage
        assert 'cpu_percent' in usage
        assert 'memory_mb' in usage
        
        resource_monitor.stop_monitoring()
        assert resource_monitor._monitoring == False
    
    def test_throttling_check(self, resource_monitor):
        """Test throttling decision logic."""
        # Mock high resource usage
        with patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.cpu_percent') as mock_cpu, \
             patch('psutil.Process') as mock_process:
            
            mock_memory.return_value.percent = 95.0
            mock_cpu.return_value = 85.0
            mock_process.return_value.memory_info.return_value.rss = 600 * 1024 * 1024
            
            assert resource_monitor.should_throttle() == True
    
    def test_resource_history(self, resource_monitor):
        """Test resource usage history tracking."""
        resource_monitor.start_monitoring()
        time.sleep(0.2)
        resource_monitor.stop_monitoring()
        
        history = resource_monitor.get_resource_history()
        assert len(history) > 0
        assert all('timestamp' in entry for entry in history)
        assert all('memory_percent' in entry for entry in history)


class TestMemoryOptimizer:
    """Test cases for MemoryOptimizer."""
    
    @pytest.fixture
    def memory_config(self):
        """Create test memory configuration."""
        return MemoryConfig(
            optimization_level=MemoryOptimizationLevel.STANDARD,
            max_memory_mb=256,
            enable_memory_monitoring=False,  # Disable for tests
            enable_gc_optimization=True,
            enable_leak_detection=True
        )
    
    @pytest.fixture
    def memory_optimizer(self, memory_config):
        """Create test memory optimizer."""
        optimizer = MemoryOptimizer(memory_config)
        yield optimizer
        optimizer.stop_optimization()
    
    def test_optimizer_initialization(self, memory_config):
        """Test memory optimizer initialization."""
        optimizer = MemoryOptimizer(memory_config)
        
        assert optimizer.config == memory_config
        assert isinstance(optimizer.profiler, MemoryProfiler)
        assert isinstance(optimizer.gc_optimizer, GarbageCollectionOptimizer)
        assert isinstance(optimizer.leak_detector, MemoryLeakDetector)
        assert isinstance(optimizer.cache, MemoryEfficientCache)
    
    def test_optimization_lifecycle(self, memory_optimizer):
        """Test optimization start/stop lifecycle."""
        memory_optimizer.start_optimization()
        assert memory_optimizer.profiler._tracking == True
        
        memory_optimizer.stop_optimization()
        assert memory_optimizer.profiler._tracking == False
    
    def test_memory_context_manager(self, memory_optimizer):
        """Test memory context manager."""
        memory_optimizer.start_optimization()
        
        with memory_optimizer.memory_context("test_operation") as ctx:
            assert ctx == memory_optimizer
            # Simulate some work
            dummy_data = list(range(1000))
        
        # Context should complete without errors
        assert True
    
    def test_force_cleanup(self, memory_optimizer):
        """Test forced memory cleanup."""
        memory_optimizer.start_optimization()
        
        # Add some cache entries
        memory_optimizer.cache.put("key1", "value1")
        memory_optimizer.cache.put("key2", "value2")
        
        cleanup_stats = memory_optimizer.force_cleanup()
        
        assert isinstance(cleanup_stats, dict)
        assert 'cache_cleared' in cleanup_stats
        assert 'objects_collected' in cleanup_stats
        assert cleanup_stats['cache_cleared'] >= 0
    
    def test_object_pool_management(self, memory_optimizer):
        """Test object pool management."""
        def factory():
            return {"data": "test"}
        
        pool = memory_optimizer.get_object_pool("test_pool", factory, max_size=5)
        assert isinstance(pool, ObjectPool)
        
        # Test object acquisition and release
        obj = pool.acquire()
        assert obj == {"data": "test"}
        pool.release(obj)
        
        stats = pool.stats()
        assert stats['created_count'] == 1
        assert stats['reused_count'] == 0
    
    def test_weak_reference_tracking(self, memory_optimizer):
        """Test weak reference tracking."""
        test_obj = {"test": "data"}
        ref = memory_optimizer.add_weak_reference(test_obj)
        
        assert isinstance(ref, weakref.ref)
        assert ref() == test_obj
        
        # Delete object and cleanup
        del test_obj
        memory_optimizer._cleanup_weak_references()
        
        assert ref() is None


class TestMemoryEfficientCache:
    """Test cases for MemoryEfficientCache."""
    
    @pytest.fixture
    def memory_cache(self):
        """Create test memory efficient cache."""
        return MemoryEfficientCache(max_size=5, ttl=60.0)
    
    def test_cache_basic_operations(self, memory_cache):
        """Test basic cache operations."""
        # Put and get
        memory_cache.put("key1", "value1")
        assert memory_cache.get("key1") == "value1"
        
        # Non-existent key
        assert memory_cache.get("nonexistent") is None
        
        # Size tracking
        assert memory_cache.size() == 1
    
    def test_cache_ttl_expiration(self):
        """Test TTL-based expiration."""
        cache = MemoryEfficientCache(max_size=5, ttl=0.1)  # 100ms TTL
        
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Wait for expiration
        time.sleep(0.2)
        assert cache.get("key1") is None
    
    def test_cache_size_limit(self, memory_cache):
        """Test cache size limits and LRU eviction."""
        # Fill cache to capacity
        for i in range(5):
            memory_cache.put(f"key{i}", f"value{i}")
        
        assert memory_cache.size() == 5
        
        # Add one more item (should evict oldest)
        memory_cache.put("key5", "value5")
        assert memory_cache.size() == 5
        assert memory_cache.get("key0") is None  # Should be evicted
        assert memory_cache.get("key5") == "value5"
    
    def test_cache_access_order(self, memory_cache):
        """Test LRU access order."""
        # Fill cache
        for i in range(5):
            memory_cache.put(f"key{i}", f"value{i}")
        
        # Access key0 to make it recently used
        memory_cache.get("key0")
        
        # Add new item (should evict key1, not key0)
        memory_cache.put("key5", "value5")
        assert memory_cache.get("key0") == "value0"  # Should still exist
        assert memory_cache.get("key1") is None      # Should be evicted
    
    def test_cache_cleanup(self, memory_cache):
        """Test cache cleanup operations."""
        # Add entries
        for i in range(3):
            memory_cache.put(f"key{i}", f"value{i}")
        
        # Clear cache
        cleared_count = memory_cache.clear()
        assert cleared_count == 3
        assert memory_cache.size() == 0
    
    def test_expired_cleanup(self):
        """Test cleanup of expired entries."""
        cache = MemoryEfficientCache(max_size=5, ttl=0.1)
        
        # Add entries
        cache.put("key1", "value1")
        cache.put("key2", "value2")
        
        # Wait for expiration
        time.sleep(0.2)
        
        # Cleanup expired entries
        expired_count = cache.cleanup_expired()
        assert expired_count == 2
        assert cache.size() == 0


class TestGarbageCollectionOptimizer:
    """Test cases for GarbageCollectionOptimizer."""
    
    @pytest.fixture
    def memory_config(self):
        """Create test memory configuration."""
        return MemoryConfig(
            enable_gc_optimization=True,
            gc_threshold_0=500,
            gc_threshold_1=8,
            gc_threshold_2=8
        )
    
    @pytest.fixture 
    def gc_optimizer(self, memory_config):
        """Create test GC optimizer."""
        optimizer = GarbageCollectionOptimizer(memory_config)
        yield optimizer
        optimizer.restore_original_settings()
    
    def test_gc_optimization_settings(self, gc_optimizer):
        """Test GC settings optimization."""
        original_thresholds = gc.get_threshold()
        
        gc_optimizer.optimize_gc_settings()
        
        new_thresholds = gc.get_threshold()
        assert new_thresholds == (500, 8, 8)
        
        gc_optimizer.restore_original_settings()
        assert gc.get_threshold() == original_thresholds
    
    def test_force_garbage_collection(self, gc_optimizer):
        """Test forced garbage collection."""
        # Create some objects to collect
        dummy_objects = [{"data": i} for i in range(100)]
        
        stats = gc_optimizer.force_garbage_collection()
        
        assert isinstance(stats, dict)
        assert 'objects_before' in stats
        assert 'objects_after' in stats
        assert 'objects_freed' in stats
        assert 'collections_by_generation' in stats
        
        # Objects should be freed
        assert stats['objects_freed'] >= 0
    
    def test_gc_statistics(self, gc_optimizer):
        """Test GC statistics collection."""
        gc_optimizer.optimize_gc_settings()
        gc_optimizer.force_garbage_collection()
        
        stats = gc_optimizer.get_gc_statistics()
        
        assert isinstance(stats, dict)
        assert 'current_thresholds' in stats
        assert 'generation_stats' in stats
        assert 'total_collections_performed' in stats
        assert 'total_objects_collected' in stats
        assert 'gc_enabled' in stats
        
        assert stats['total_collections_performed'] >= 1


class TestMemoryLeakDetector:
    """Test cases for MemoryLeakDetector."""
    
    @pytest.fixture
    def memory_config(self):
        """Create test memory configuration."""
        return MemoryConfig(
            enable_leak_detection=True,
            leak_threshold_mb=50
        )
    
    @pytest.fixture
    def leak_detector(self, memory_config):
        """Create test leak detector."""
        return MemoryLeakDetector(memory_config)
    
    def test_baseline_setting(self, leak_detector):
        """Test baseline object count setting."""
        leak_detector.set_baseline()
        
        assert len(leak_detector._baseline_objects) > 0
        assert 'dict' in leak_detector._baseline_objects
        assert 'list' in leak_detector._baseline_objects
    
    def test_leak_detection(self, leak_detector):
        """Test memory leak detection."""
        leak_detector.set_baseline()
        
        # Create many objects of same type to simulate leak
        leak_objects = [{"leak": i} for i in range(500)]
        
        leaks = leak_detector.check_for_leaks()
        
        # Should detect increased dict count
        if leaks:
            assert any(leak['object_type'] == 'dict' for leak in leaks)
            assert all('growth' in leak for leak in leaks)
            assert all('growth_percent' in leak for leak in leaks)
    
    def test_baseline_reset(self, leak_detector):
        """Test baseline reset functionality."""
        leak_detector.set_baseline()
        original_count = len(leak_detector._baseline_objects)
        
        # Create objects
        dummy_objects = [{"test": i} for i in range(50)]
        
        # Reset baseline
        leak_detector.reset_baseline()
        new_count = len(leak_detector._baseline_objects)
        
        # New baseline should account for new objects
        assert new_count >= original_count
        assert len(leak_detector._leak_alerts) == 0
    
    def test_leak_history(self, leak_detector):
        """Test leak detection history."""
        leak_detector.set_baseline()
        
        # Simulate leak detection
        leak_objects = [{"leak": i} for i in range(200)]
        leak_detector.check_for_leaks()
        
        history = leak_detector.get_leak_history()
        assert isinstance(history, list)


class TestFactoryFunctions:
    """Test cases for factory functions."""
    
    def test_create_memory_optimizer(self):
        """Test memory optimizer factory function."""
        # Test standard level
        optimizer = create_memory_optimizer("standard")
        assert isinstance(optimizer, MemoryOptimizer)
        assert optimizer.config.optimization_level == MemoryOptimizationLevel.STANDARD
        
        # Test aggressive level
        optimizer = create_memory_optimizer("aggressive")
        assert optimizer.config.optimization_level == MemoryOptimizationLevel.AGGRESSIVE
        assert optimizer.config.max_memory_mb == 256
        
        # Test maximum level
        optimizer = create_memory_optimizer("maximum")
        assert optimizer.config.optimization_level == MemoryOptimizationLevel.MAXIMUM
        assert optimizer.config.max_memory_mb == 128
        assert optimizer.config.track_memory_allocations == True
    
    def test_create_memory_optimizer_minimal(self):
        """Test minimal optimization level."""
        optimizer = create_memory_optimizer("minimal")
        assert optimizer.config.optimization_level == MemoryOptimizationLevel.MINIMAL
        assert optimizer.config.enable_gc_optimization == False
        assert optimizer.config.enable_memory_monitoring == False


class TestIntegrationScenarios:
    """Integration test scenarios for optimization components."""
    
    def test_cache_and_pool_integration(self):
        """Test integration between cache and connection pool."""
        pool_config = PoolOptimizationConfig(max_connections=3)
        cache_config = CacheConfig(max_size=10, ttl=60.0)
        
        pool = OptimizedConnectionPool(pool_config)
        cache = ResultCache(cache_config)
        
        try:
            # Simulate workflow with caching and pooling
            mock_factory = Mock(return_value="connection")
            
            with pool.get_connection("server1", mock_factory) as conn:
                result = IntrospectionResult(
                    server_config=MCPServerConfig(name="server1", command="node", args=[]),
                    success=True,
                    timestamp=time.time(),
                    duration=1.0
                )
                cache.put("server1", result)
            
            # Verify integration
            cached_result = cache.get("server1")
            assert cached_result is not None
            assert cached_result.server_config.name == "server1"
            
        finally:
            pool.shutdown()
            cache.clear()
    
    def test_memory_and_scaling_integration(self):
        """Test integration between memory optimization and scaling."""
        memory_config = MemoryConfig(
            optimization_level=MemoryOptimizationLevel.STANDARD,
            enable_memory_monitoring=False
        )
        scaling_config = ScalingConfig(
            batch_size=3,
            max_workers=2,
            enable_resource_monitoring=False
        )
        
        memory_optimizer = MemoryOptimizer(memory_config)
        
        try:
            memory_optimizer.start_optimization()
            
            # Simulate large-scale operation with memory monitoring
            with memory_optimizer.memory_context("scaling_test"):
                # Create test data
                test_data = [{"batch": i} for i in range(10)]
                
                # Process in batches
                batch_size = scaling_config.batch_size
                for i in range(0, len(test_data), batch_size):
                    batch = test_data[i:i + batch_size]
                    # Simulate processing
                    processed = [item for item in batch]
            
            # Check memory statistics
            stats = memory_optimizer.get_optimization_statistics()
            assert 'current_memory' in stats
            assert 'peak_memory_mb' in stats
            
        finally:
            memory_optimizer.stop_optimization()
    
    def test_comprehensive_optimization_pipeline(self):
        """Test comprehensive optimization pipeline."""
        # Configuration
        pool_config = PoolOptimizationConfig(max_connections=2)
        cache_config = CacheConfig(max_size=5, ttl=30.0)
        memory_config = MemoryConfig(
            optimization_level=MemoryOptimizationLevel.STANDARD,
            enable_memory_monitoring=False
        )
        
        # Components
        pool = OptimizedConnectionPool(pool_config)
        cache = ResultCache(cache_config)
        memory_optimizer = MemoryOptimizer(memory_config)
        
        try:
            memory_optimizer.start_optimization()
            
            # Simulate complete workflow
            mock_factory = Mock(return_value="connection")
            
            servers = [
                MCPServerConfig(name=f"server_{i}", command="node", args=[])
                for i in range(5)
            ]
            
            results = []
            for server in servers:
                # Check cache first
                cache_key = f"{server.name}_{server.command}"
                cached_result = cache.get(cache_key)
                
                if cached_result:
                    results.append(cached_result)
                else:
                    # Use connection pool
                    with pool.get_connection(server.name, mock_factory):
                        # Simulate introspection
                        result = IntrospectionResult(
                            server_config=server,
                            success=True,
                            timestamp=time.time(),
                            duration=0.5
                        )
                        cache.put(cache_key, result)
                        results.append(result)
            
            # Verify results
            assert len(results) == 5
            assert all(result.success for result in results)
            
            # Check component statistics
            pool_metrics = pool.get_metrics()
            cache_stats = cache.get_statistics()
            memory_stats = memory_optimizer.get_optimization_statistics()
            
            assert pool_metrics.total_connections_created > 0
            assert cache_stats.entries_added > 0
            assert memory_stats['peak_memory_mb'] > 0
            
        finally:
            pool.shutdown()
            cache.clear()
            memory_optimizer.stop_optimization()


if __name__ == "__main__":
    pytest.main([__file__]) 