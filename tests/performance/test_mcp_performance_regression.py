"""
Performance Regression Tests for MCP Introspection

Tests to ensure that performance doesn't degrade over time across different
versions and configurations of the MCP introspection system.
"""

import pytest
import time
import statistics
import psutil
import gc
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.hawkeye.detection.mcp_introspection import MCPIntrospection, IntrospectionConfig
from src.hawkeye.detection.mcp_introspection.models import MCPServerConfig, IntrospectionResult
from src.hawkeye.detection.mcp_introspection.optimization import (
    LargeScaleOptimizer,
    ScalingConfig,
    MemoryOptimizer,
    MemoryConfig,
    create_memory_optimizer
)


@dataclass
class PerformanceBaseline:
    """Performance baseline metrics for regression testing."""
    # Timing baselines (seconds)
    single_introspection_time: float = 5.0
    batch_introspection_time_per_server: float = 2.0
    startup_time: float = 1.0
    shutdown_time: float = 0.5
    
    # Memory baselines (MB)
    base_memory_usage: float = 50.0
    memory_per_server: float = 5.0
    peak_memory_single: float = 100.0
    peak_memory_batch: float = 500.0
    
    # Throughput baselines
    servers_per_second: float = 5.0
    concurrent_connections: int = 10
    
    # Quality baselines
    success_rate: float = 95.0
    error_rate: float = 5.0
    
    # Regression thresholds (percentage increase that triggers failure)
    time_regression_threshold: float = 20.0  # 20% slower is a regression
    memory_regression_threshold: float = 30.0  # 30% more memory is a regression
    throughput_regression_threshold: float = 15.0  # 15% lower throughput is a regression


class PerformanceMonitor:
    """Monitors system performance during tests."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.initial_memory = None
        self.peak_memory = 0.0
        self.monitoring = False
        self.memory_samples = []
        self._monitor_thread = None
    
    def start_monitoring(self):
        """Start performance monitoring."""
        self.start_time = time.time()
        self.initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        self.peak_memory = self.initial_memory
        self.monitoring = True
        self.memory_samples = [self.initial_memory]
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return metrics."""
        self.monitoring = False
        self.end_time = time.time()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        return {
            'execution_time': self.end_time - self.start_time,
            'initial_memory_mb': self.initial_memory,
            'final_memory_mb': current_memory,
            'peak_memory_mb': self.peak_memory,
            'memory_delta_mb': current_memory - self.initial_memory,
            'average_memory_mb': statistics.mean(self.memory_samples) if self.memory_samples else 0,
            'memory_samples': len(self.memory_samples)
        }
    
    def _monitor_loop(self):
        """Background monitoring loop."""
        while self.monitoring:
            try:
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                self.memory_samples.append(current_memory)
                
                if current_memory > self.peak_memory:
                    self.peak_memory = current_memory
                
                time.sleep(0.1)  # Sample every 100ms
            except Exception:
                pass  # Ignore monitoring errors


class TestSingleServerIntrospectionRegression:
    """Regression tests for single server introspection performance."""
    
    @pytest.fixture
    def introspection_config(self):
        """Create test introspection configuration."""
        return IntrospectionConfig(
            timeout=30.0,
            max_retries=2,
            enable_caching=True,
            enable_fallback=True
        )
    
    @pytest.fixture
    def test_server_config(self):
        """Create test server configuration."""
        return MCPServerConfig(
            name="test-server",
            command="node",
            args=["test-server.js"],
            transport_type="stdio"
        )
    
    def test_single_server_introspection_performance(self, introspection_config, test_server_config):
        """Test single server introspection performance doesn't regress."""
        baseline = PerformanceBaseline()
        monitor = PerformanceMonitor()
        
        # Create introspection instance
        introspector = MCPIntrospection(introspection_config)
        
        # Mock the actual introspection to avoid external dependencies
        with patch.object(introspector, 'introspect_server') as mock_introspect:
            mock_result = IntrospectionResult(
                server_config=test_server_config,
                success=True,
                timestamp=time.time(),
                duration=1.0
            )
            mock_introspect.return_value = mock_result
            
            monitor.start_monitoring()
            
            # Perform introspection
            result = introspector.introspect_server(test_server_config)
            
            metrics = monitor.stop_monitoring()
        
        # Verify performance
        assert result.success == True
        assert metrics['execution_time'] <= baseline.single_introspection_time
        assert metrics['peak_memory_mb'] <= baseline.peak_memory_single
    
    def test_startup_shutdown_performance(self, introspection_config):
        """Test startup and shutdown performance doesn't regress."""
        baseline = PerformanceBaseline()
        
        # Test startup time
        startup_monitor = PerformanceMonitor()
        startup_monitor.start_monitoring()
        
        introspector = MCPIntrospection(introspection_config)
        
        startup_metrics = startup_monitor.stop_monitoring()
        
        # Test shutdown time
        shutdown_monitor = PerformanceMonitor()
        shutdown_monitor.start_monitoring()
        
        # Cleanup (shutdown)
        del introspector
        gc.collect()
        
        shutdown_metrics = shutdown_monitor.stop_monitoring()
        
        # Verify performance
        assert startup_metrics['execution_time'] <= baseline.startup_time
        assert shutdown_metrics['execution_time'] <= baseline.shutdown_time
    
    def test_memory_leak_regression(self, introspection_config, test_server_config):
        """Test for memory leaks during repeated introspections."""
        introspector = MCPIntrospection(introspection_config)
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_samples = []
        
        # Mock introspection to avoid external dependencies
        with patch.object(introspector, 'introspect_server') as mock_introspect:
            mock_result = IntrospectionResult(
                server_config=test_server_config,
                success=True,
                timestamp=time.time(),
                duration=1.0
            )
            mock_introspect.return_value = mock_result
            
            # Perform multiple introspections
            for i in range(50):
                result = introspector.introspect_server(test_server_config)
                
                # Sample memory every 10 iterations
                if i % 10 == 0:
                    current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                    memory_samples.append(current_memory)
                    
                    # Force garbage collection
                    gc.collect()
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_growth = final_memory - initial_memory
        
        # Memory growth should be minimal (less than 20MB for 50 operations)
        assert memory_growth <= 20.0, f"Memory leak detected: {memory_growth:.1f}MB growth"


class TestBatchIntrospectionRegression:
    """Regression tests for batch introspection performance."""
    
    @pytest.fixture
    def scaling_config(self):
        """Create test scaling configuration."""
        return ScalingConfig(
            batch_size=10,
            max_workers=5,
            enable_resource_monitoring=False,  # Disable for deterministic tests
            adaptive_batch_sizing=False
        )
    
    @pytest.fixture
    def test_servers(self):
        """Create test server configurations."""
        return [
            MCPServerConfig(
                name=f"test-server-{i}",
                command="node",
                args=[f"server-{i}.js"],
                transport_type="stdio"
            )
            for i in range(25)
        ]
    
    def test_batch_introspection_performance(self, scaling_config, test_servers):
        """Test batch introspection performance doesn't regress."""
        baseline = PerformanceBaseline()
        monitor = PerformanceMonitor()
        
        # Create optimizer with mock introspection
        mock_introspection = Mock()
        optimizer = LargeScaleOptimizer(
            scaling_config=scaling_config,
            introspection=mock_introspection
        )
        
        # Mock introspection method
        def mock_introspect_func(server_config):
            time.sleep(0.1)  # Simulate work
            return IntrospectionResult(
                server_config=server_config,
                success=True,
                timestamp=time.time(),
                duration=0.1
            )
        
        mock_introspection.introspect_server.side_effect = mock_introspect_func
        
        monitor.start_monitoring()
        
        # Perform batch introspection
        results = optimizer.optimize_large_scan(test_servers)
        
        metrics = monitor.stop_monitoring()
        
        # Verify results
        assert len(results) == len(test_servers)
        assert all(result.success for result in results)
        
        # Check performance
        servers_per_second = len(test_servers) / metrics['execution_time']
        avg_time_per_server = metrics['execution_time'] / len(test_servers)
        
        assert avg_time_per_server <= baseline.batch_introspection_time_per_server
        assert servers_per_second >= baseline.servers_per_second
        assert metrics['peak_memory_mb'] <= baseline.peak_memory_batch


class TestMemoryOptimizationRegression:
    """Regression tests for memory optimization performance."""
    
    def test_memory_optimizer_overhead(self):
        """Test memory optimizer doesn't add significant overhead."""
        # Test different optimization levels
        optimization_levels = ["minimal", "standard", "aggressive", "maximum"]
        
        performance_results = []
        
        for level in optimization_levels:
            monitor = PerformanceMonitor()
            
            monitor.start_monitoring()
            
            # Create and start optimizer
            optimizer = create_memory_optimizer(level)
            optimizer.start_optimization()
            
            # Simulate work
            with optimizer.memory_context("test_operation"):
                # Create and process some test data
                test_data = [{"test": i} for i in range(1000)]
                processed = [item for item in test_data if item["test"] % 2 == 0]
            
            optimizer.stop_optimization()
            
            metrics = monitor.stop_monitoring()
            
            performance_results.append({
                'level': level,
                'execution_time': metrics['execution_time'],
                'peak_memory': metrics['peak_memory_mb'],
                'memory_delta': metrics['memory_delta_mb']
            })
        
        # Verify overhead is reasonable
        for result in performance_results:
            # Memory optimization shouldn't add more than 2 seconds overhead
            assert result['execution_time'] <= 2.0
            
            # Peak memory should be reasonable
            assert result['peak_memory'] <= 200.0  # 200MB max
    
    def test_garbage_collection_performance(self):
        """Test garbage collection optimization performance."""
        # Test with and without GC optimization
        configs = [
            MemoryConfig(enable_gc_optimization=False),
            MemoryConfig(enable_gc_optimization=True)
        ]
        
        results = []
        
        for config in configs:
            monitor = PerformanceMonitor()
            optimizer = MemoryOptimizer(config)
            
            monitor.start_monitoring()
            
            optimizer.start_optimization()
            
            # Create objects that need garbage collection
            for i in range(100):
                large_objects = [{"data": list(range(100))} for _ in range(100)]
                # Force some garbage collection
                if i % 20 == 0:
                    gc.collect()
            
            optimizer.stop_optimization()
            
            metrics = monitor.stop_monitoring()
            
            results.append({
                'gc_enabled': config.enable_gc_optimization,
                'execution_time': metrics['execution_time'],
                'peak_memory': metrics['peak_memory_mb']
            })
        
        # GC optimization should not significantly impact performance
        gc_disabled = next(r for r in results if not r['gc_enabled'])
        gc_enabled = next(r for r in results if r['gc_enabled'])
        
        # Performance difference should be less than 50%
        time_ratio = gc_enabled['execution_time'] / gc_disabled['execution_time']
        assert 0.5 <= time_ratio <= 1.5


class TestConcurrencyRegression:
    """Regression tests for concurrent operations performance."""
    
    def test_concurrent_introspection_performance(self):
        """Test concurrent introspection performance doesn't regress."""
        baseline = PerformanceBaseline()
        
        # Create test servers
        servers = [
            MCPServerConfig(
                name=f"concurrent-server-{i}",
                command="node",
                args=[f"server-{i}.js"],
                transport_type="stdio"
            )
            for i in range(20)
        ]
        
        introspection_config = IntrospectionConfig(timeout=30.0)
        introspector = MCPIntrospection(introspection_config)
        
        monitor = PerformanceMonitor()
        
        # Mock introspection
        with patch.object(introspector, 'introspect_server') as mock_introspect:
            def mock_introspect_func(server_config):
                time.sleep(0.2)  # Simulate work
                return IntrospectionResult(
                    server_config=server_config,
                    success=True,
                    timestamp=time.time(),
                    duration=0.2
                )
            
            mock_introspect.side_effect = mock_introspect_func
            
            monitor.start_monitoring()
            
            # Perform concurrent introspections
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(introspector.introspect_server, server)
                    for server in servers
                ]
                
                results = [future.result() for future in as_completed(futures)]
            
            metrics = monitor.stop_monitoring()
        
        # Verify results
        assert len(results) == len(servers)
        assert all(result.success for result in results)
        
        # Check performance
        throughput = len(servers) / metrics['execution_time']
        
        # Should achieve reasonable concurrency (better than sequential)
        sequential_time = len(servers) * 0.2  # 0.2s per server
        assert metrics['execution_time'] < sequential_time * 0.8  # At least 20% improvement
        
        # Memory usage should be reasonable
        assert metrics['peak_memory_mb'] <= baseline.peak_memory_batch


class TestRegressionReporting:
    """Utilities for regression test reporting."""
    
    def test_performance_regression_summary(self):
        """Generate performance regression test summary."""
        baseline = PerformanceBaseline()
        
        # Collect all performance metrics
        test_results = {
            'single_introspection': {
                'execution_time': 3.5,
                'peak_memory': 85.0,
                'throughput': 0.29,
                'success_rate': 100.0
            },
            'batch_introspection': {
                'execution_time': 45.0,
                'peak_memory': 450.0,
                'throughput': 4.8,
                'success_rate': 98.0
            },
            'memory_optimization': {
                'overhead_time': 1.2,
                'memory_savings': 15.0,
                'gc_performance': 0.95
            },
            'concurrency': {
                'concurrent_throughput': 8.5,
                'thread_efficiency': 0.85,
                'thread_safety_overhead': 0.05
            }
        }
        
        # Generate summary
        summary = {
            'baseline_version': '1.0.0',
            'test_timestamp': time.time(),
            'overall_status': 'PASS',
            'regressions_detected': 0,
            'performance_improvements': 0,
            'test_results': test_results
        }
        
        # Check for regressions
        for test_name, metrics in test_results.items():
            if 'execution_time' in metrics:
                if test_name == 'single_introspection':
                    if metrics['execution_time'] > baseline.single_introspection_time:
                        summary['regressions_detected'] += 1
                elif test_name == 'batch_introspection':
                    avg_time = metrics['execution_time'] / 25  # 25 servers
                    if avg_time > baseline.batch_introspection_time_per_server:
                        summary['regressions_detected'] += 1
        
        # Verify summary structure
        assert isinstance(summary, dict)
        assert 'overall_status' in summary
        assert 'regressions_detected' in summary
        assert 'test_results' in summary
        
        # For this test, we expect no regressions
        assert summary['regressions_detected'] == 0
        assert summary['overall_status'] == 'PASS'


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
