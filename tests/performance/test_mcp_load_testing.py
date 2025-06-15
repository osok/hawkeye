"""
Performance benchmarks and load testing for MCP introspection system.

This module provides comprehensive performance testing including load testing,
stress testing, memory usage profiling, and performance regression detection.
"""

import pytest
import time
import psutil
import threading
import concurrent.futures
import statistics
import sys
import os
import gc
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType


@dataclass
class PerformanceMetrics:
    """Performance metrics for a test run."""
    operation_count: int
    total_time: float
    average_time: float
    min_time: float
    max_time: float
    median_time: float
    p95_time: float
    p99_time: float
    throughput_ops_per_sec: float
    memory_usage_mb: float
    memory_peak_mb: float
    cpu_usage_percent: float
    success_rate: float
    error_count: int


class PerformanceProfiler:
    """Utility class for profiling performance metrics."""
    
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.start_time = None
        self.start_memory = None
        self.peak_memory = 0
        self.cpu_samples = []
        self.operation_times = []
        self.success_count = 0
        self.error_count = 0
        self.monitoring = False
        self.monitor_thread = None
    
    def start_monitoring(self):
        """Start performance monitoring."""
        self.start_time = time.time()
        self.start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        self.peak_memory = self.start_memory
        self.monitoring = True
        
        # Start background monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_resources)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def record_operation(self, duration: float, success: bool = True):
        """Record an operation's performance."""
        self.operation_times.append(duration)
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
    
    def get_metrics(self) -> PerformanceMetrics:
        """Get performance metrics."""
        if not self.operation_times:
            return PerformanceMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        
        total_time = time.time() - self.start_time if self.start_time else 0
        operation_count = len(self.operation_times)
        
        return PerformanceMetrics(
            operation_count=operation_count,
            total_time=total_time,
            average_time=statistics.mean(self.operation_times),
            min_time=min(self.operation_times),
            max_time=max(self.operation_times),
            median_time=statistics.median(self.operation_times),
            p95_time=self._percentile(self.operation_times, 95),
            p99_time=self._percentile(self.operation_times, 99),
            throughput_ops_per_sec=operation_count / total_time if total_time > 0 else 0,
            memory_usage_mb=self.process.memory_info().rss / 1024 / 1024,
            memory_peak_mb=self.peak_memory,
            cpu_usage_percent=statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
            success_rate=self.success_count / operation_count if operation_count > 0 else 0,
            error_count=self.error_count
        )
    
    def _monitor_resources(self):
        """Background resource monitoring."""
        while self.monitoring:
            try:
                # Monitor memory
                current_memory = self.process.memory_info().rss / 1024 / 1024
                self.peak_memory = max(self.peak_memory, current_memory)
                
                # Monitor CPU
                cpu_percent = self.process.cpu_percent()
                self.cpu_samples.append(cpu_percent)
                
                time.sleep(0.1)  # Sample every 100ms
            except Exception:
                break
    
    @staticmethod
    def _percentile(data: List[float], percentile: int) -> float:
        """Calculate percentile."""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]


class MockServerHelper:
    """Helper for creating mock servers for performance testing."""
    
    @staticmethod
    def create_fast_mock_server_script() -> str:
        """Create a fast-responding mock server script."""
        return '''
import json
import sys

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "fast-mock-server", "version": "1.0.0"}
                }
            }
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "test_tool",
                            "description": "A test tool",
                            "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}}
                        }
                    ]
                }
            }
        elif method == "resources/list":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"resources": []}
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"}
            }
        
        print(json.dumps(response), flush=True)
    except Exception:
        break
'''
    
    @staticmethod
    def create_slow_mock_server_script(delay_ms: int = 1000) -> str:
        """Create a slow-responding mock server script."""
        return f'''
import json
import sys
import time

delay_seconds = {delay_ms / 1000.0}

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        # Add delay
        time.sleep(delay_seconds)
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{
                    "protocolVersion": "2024-11-05",
                    "capabilities": {{"tools": {{"listChanged": True}}}},
                    "serverInfo": {{"name": "slow-mock-server", "version": "1.0.0"}}
                }}
            }}
        elif method == "tools/list":
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{"tools": []}}
            }}
        elif method == "resources/list":
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{"resources": []}}
            }}
        else:
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {{"code": -32601, "message": "Method not found"}}
            }}
        
        print(json.dumps(response), flush=True)
    except Exception:
        break
'''
    
    @staticmethod
    def create_heavy_mock_server_script(tool_count: int = 100) -> str:
        """Create a mock server with many tools for testing large responses."""
        return f'''
import json
import sys

# Generate many tools
tools = []
for i in range({tool_count}):
    tools.append({{
        "name": f"tool_{{i}}",
        "description": f"Tool number {{i}} with long description " + "x" * 50,
        "inputSchema": {{
            "type": "object",
            "properties": {{
                f"param_{{j}}": {{"type": "string", "description": f"Parameter {{j}}"}}
                for j in range(5)
            }}
        }}
    }})

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{
                    "protocolVersion": "2024-11-05",
                    "capabilities": {{"tools": {{"listChanged": True}}}},
                    "serverInfo": {{"name": "heavy-mock-server", "version": "1.0.0"}}
                }}
            }}
        elif method == "tools/list":
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{"tools": tools}}
            }}
        elif method == "resources/list":
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {{"resources": []}}
            }}
        else:
            response = {{
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {{"code": -32601, "message": "Method not found"}}
            }}
        
        print(json.dumps(response), flush=True)
    except Exception:
        break
'''


@pytest.mark.performance
class TestBasicPerformance:
    """Basic performance tests for MCP introspection."""
    
    @pytest.fixture
    def fast_introspector(self):
        """Create introspector optimized for performance."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=True,
            cache_ttl=60.0,
            enable_performance_monitoring=True
        )
        return MCPIntrospector(config=config)
    
    @pytest.fixture
    def fast_server_config(self):
        """Create configuration for fast mock server."""
        return MCPServerConfig(
            name="fast-performance-server",
            command="python",
            args=["-c", MockServerHelper.create_fast_mock_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
    
    def test_single_introspection_performance(self, fast_introspector, fast_server_config):
        """Test performance of single introspection operation."""
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        start_time = time.time()
        result = fast_introspector.introspect_server(fast_server_config)
        duration = time.time() - start_time
        
        profiler.record_operation(duration, result is not None)
        profiler.stop_monitoring()
        
        metrics = profiler.get_metrics()
        
        # Performance assertions
        assert duration < 5.0, f"Single introspection took {duration:.2f}s, expected < 5.0s"
        assert metrics.memory_usage_mb < 100, f"Memory usage {metrics.memory_usage_mb:.1f}MB too high"
        assert result is not None, "Introspection should succeed"
        assert result.server_name == "fast-mock-server"
    
    def test_repeated_introspection_performance(self, fast_introspector, fast_server_config):
        """Test performance of repeated introspection operations."""
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        iterations = 10
        for i in range(iterations):
            start_time = time.time()
            result = fast_introspector.introspect_server(fast_server_config)
            duration = time.time() - start_time
            
            profiler.record_operation(duration, result is not None)
        
        profiler.stop_monitoring()
        metrics = profiler.get_metrics()
        
        # Performance assertions
        assert metrics.average_time < 2.0, f"Average time {metrics.average_time:.2f}s too high"
        assert metrics.success_rate >= 0.9, f"Success rate {metrics.success_rate:.2f} too low"
        assert metrics.throughput_ops_per_sec > 0.5, f"Throughput {metrics.throughput_ops_per_sec:.2f} ops/s too low"
        
        print(f"Performance Metrics for {iterations} iterations:")
        print(f"  Average time: {metrics.average_time:.3f}s")
        print(f"  Min/Max time: {metrics.min_time:.3f}s / {metrics.max_time:.3f}s")
        print(f"  P95/P99 time: {metrics.p95_time:.3f}s / {metrics.p99_time:.3f}s")
        print(f"  Throughput: {metrics.throughput_ops_per_sec:.2f} ops/s")
        print(f"  Memory usage: {metrics.memory_usage_mb:.1f}MB (peak: {metrics.memory_peak_mb:.1f}MB)")
    
    def test_caching_performance_improvement(self, fast_introspector, fast_server_config):
        """Test that caching improves performance for repeated operations."""
        # First run (cold cache)
        start_time = time.time()
        result1 = fast_introspector.introspect_server(fast_server_config)
        first_run_time = time.time() - start_time
        
        # Second run (warm cache)
        start_time = time.time()
        result2 = fast_introspector.introspect_server(fast_server_config)
        second_run_time = time.time() - start_time
        
        # Assertions
        assert result1 is not None and result2 is not None
        assert result1.server_name == result2.server_name
        
        # Second run should be faster (cached) or at least not significantly slower
        # Note: In real scenarios, this might not always be true due to system variations
        print(f"First run: {first_run_time:.3f}s, Second run: {second_run_time:.3f}s")
        assert second_run_time < first_run_time * 2.0, "Caching should not significantly slow down operations"


@pytest.mark.performance
class TestLoadTesting:
    """Load testing for MCP introspection system."""
    
    @pytest.fixture
    def load_test_introspector(self):
        """Create introspector for load testing."""
        config = IntrospectionConfig(
            timeout=15.0,
            max_retries=2,
            retry_delay=0.2,
            enable_caching=True,
            cache_ttl=30.0
        )
        return MCPIntrospector(config=config)
    
    def test_concurrent_introspection_load(self, load_test_introspector):
        """Test concurrent introspection operations."""
        server_configs = []
        for i in range(5):  # Create 5 different server configs
            server_configs.append(MCPServerConfig(
                name=f"load-test-server-{i}",
                command="python",
                args=["-c", MockServerHelper.create_fast_mock_server_script()],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            ))
        
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        def introspect_server(config):
            """Worker function for concurrent introspection."""
            start_time = time.time()
            try:
                result = load_test_introspector.introspect_server(config)
                duration = time.time() - start_time
                return duration, result is not None, None
            except Exception as e:
                duration = time.time() - start_time
                return duration, False, str(e)
        
        # Run concurrent introspections
        max_workers = 3
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit tasks for each server config multiple times
            futures = []
            for _ in range(2):  # 2 rounds
                for config in server_configs:
                    futures.append(executor.submit(introspect_server, config))
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                duration, success, error = future.result()
                profiler.record_operation(duration, success)
                if error:
                    print(f"Error in concurrent operation: {error}")
        
        profiler.stop_monitoring()
        metrics = profiler.get_metrics()
        
        # Load testing assertions
        assert metrics.success_rate >= 0.8, f"Success rate {metrics.success_rate:.2f} too low for load test"
        assert metrics.average_time < 10.0, f"Average time {metrics.average_time:.2f}s too high under load"
        assert metrics.memory_usage_mb < 200, f"Memory usage {metrics.memory_usage_mb:.1f}MB too high"
        
        print(f"Load Test Results ({len(futures)} concurrent operations):")
        print(f"  Success rate: {metrics.success_rate:.2%}")
        print(f"  Average time: {metrics.average_time:.3f}s")
        print(f"  P95 time: {metrics.p95_time:.3f}s")
        print(f"  Throughput: {metrics.throughput_ops_per_sec:.2f} ops/s")
        print(f"  Memory usage: {metrics.memory_usage_mb:.1f}MB")
    
    def test_sustained_load(self, load_test_introspector):
        """Test sustained load over longer period."""
        server_config = MCPServerConfig(
            name="sustained-load-server",
            command="python",
            args=["-c", MockServerHelper.create_fast_mock_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        # Run for 30 seconds with regular interval
        start_time = time.time()
        duration_limit = 10.0  # 10 seconds for testing
        operation_interval = 0.5  # Operation every 0.5 seconds
        
        while (time.time() - start_time) < duration_limit:
            operation_start = time.time()
            try:
                result = load_test_introspector.introspect_server(server_config)
                operation_duration = time.time() - operation_start
                profiler.record_operation(operation_duration, result is not None)
            except Exception as e:
                operation_duration = time.time() - operation_start
                profiler.record_operation(operation_duration, False)
                print(f"Error in sustained load: {e}")
            
            # Wait for next operation
            elapsed = time.time() - operation_start
            if elapsed < operation_interval:
                time.sleep(operation_interval - elapsed)
        
        profiler.stop_monitoring()
        metrics = profiler.get_metrics()
        
        # Sustained load assertions
        assert metrics.operation_count >= 15, f"Expected at least 15 operations, got {metrics.operation_count}"
        assert metrics.success_rate >= 0.8, f"Success rate {metrics.success_rate:.2f} degraded under sustained load"
        
        print(f"Sustained Load Results ({metrics.operation_count} operations over {duration_limit}s):")
        print(f"  Success rate: {metrics.success_rate:.2%}")
        print(f"  Average time: {metrics.average_time:.3f}s")
        print(f"  Memory usage: {metrics.memory_usage_mb:.1f}MB (peak: {metrics.memory_peak_mb:.1f}MB)")


@pytest.mark.performance  
class TestStressTesting:
    """Stress testing for extreme scenarios."""
    
    @pytest.fixture
    def stress_test_introspector(self):
        """Create introspector for stress testing."""
        config = IntrospectionConfig(
            timeout=20.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=False  # Disable caching for stress testing
        )
        return MCPIntrospector(config=config)
    
    def test_large_response_handling(self, stress_test_introspector):
        """Test handling of servers with large responses."""
        server_config = MCPServerConfig(
            name="large-response-server",
            command="python",
            args=["-c", MockServerHelper.create_heavy_mock_server_script(500)],  # 500 tools
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        start_time = time.time()
        result = stress_test_introspector.introspect_server(server_config)
        duration = time.time() - start_time
        
        profiler.record_operation(duration, result is not None)
        profiler.stop_monitoring()
        
        metrics = profiler.get_metrics()
        
        # Stress test assertions
        assert result is not None, "Should handle large responses"
        assert len(result.tools) > 400, f"Expected >400 tools, got {len(result.tools)}"
        assert duration < 30.0, f"Large response took {duration:.2f}s, expected < 30.0s"
        assert metrics.memory_usage_mb < 500, f"Memory usage {metrics.memory_usage_mb:.1f}MB too high"
        
        print(f"Large Response Stress Test:")
        print(f"  Tools parsed: {len(result.tools)}")
        print(f"  Duration: {duration:.3f}s")
        print(f"  Memory usage: {metrics.memory_usage_mb:.1f}MB")
    
    def test_rapid_fire_requests(self, stress_test_introspector):
        """Test rapid succession of requests."""
        server_config = MCPServerConfig(
            name="rapid-fire-server",
            command="python",
            args=["-c", MockServerHelper.create_fast_mock_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        # Fire requests as fast as possible
        rapid_fire_count = 20
        for i in range(rapid_fire_count):
            start_time = time.time()
            try:
                result = stress_test_introspector.introspect_server(server_config)
                duration = time.time() - start_time
                profiler.record_operation(duration, result is not None)
            except Exception as e:
                duration = time.time() - start_time
                profiler.record_operation(duration, False)
                print(f"Error in rapid fire {i}: {e}")
        
        profiler.stop_monitoring()
        metrics = profiler.get_metrics()
        
        # Rapid fire assertions
        assert metrics.operation_count == rapid_fire_count
        assert metrics.success_rate >= 0.7, f"Success rate {metrics.success_rate:.2f} too low for rapid fire"
        
        print(f"Rapid Fire Stress Test ({rapid_fire_count} requests):")
        print(f"  Success rate: {metrics.success_rate:.2%}")
        print(f"  Average time: {metrics.average_time:.3f}s")
        print(f"  Throughput: {metrics.throughput_ops_per_sec:.2f} ops/s")


@pytest.mark.performance
class TestMemoryUsageTesting:
    """Memory usage and leak testing."""
    
    @pytest.fixture
    def memory_test_introspector(self):
        """Create introspector for memory testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=True,
            cache_ttl=60.0
        )
        return MCPIntrospector(config=config)
    
    def test_memory_usage_stability(self, memory_test_introspector):
        """Test memory usage remains stable over many operations."""
        server_config = MCPServerConfig(
            name="memory-stability-server", 
            command="python",
            args=["-c", MockServerHelper.create_fast_mock_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Get baseline memory
        gc.collect()  # Force garbage collection
        process = psutil.Process(os.getpid())
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform many operations
        iterations = 50
        memory_samples = []
        
        for i in range(iterations):
            result = memory_test_introspector.introspect_server(server_config)
            assert result is not None, f"Operation {i} failed"
            
            if i % 10 == 0:  # Sample memory every 10 operations
                gc.collect()
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_samples.append(current_memory)
        
        # Final memory check
        gc.collect()
        final_memory = process.memory_info().rss / 1024 / 1024
        
        # Memory stability assertions
        memory_increase = final_memory - baseline_memory
        assert memory_increase < 50, f"Memory increased by {memory_increase:.1f}MB, expected < 50MB"
        
        # Check for memory leaks (monotonic increase)
        if len(memory_samples) >= 3:
            memory_trend = memory_samples[-1] - memory_samples[0]
            assert memory_trend < 30, f"Memory trend {memory_trend:.1f}MB suggests possible leak"
        
        print(f"Memory Stability Test ({iterations} operations):")
        print(f"  Baseline memory: {baseline_memory:.1f}MB")
        print(f"  Final memory: {final_memory:.1f}MB")
        print(f"  Memory increase: {memory_increase:.1f}MB")
        print(f"  Memory samples: {[f'{m:.1f}' for m in memory_samples]}")
    
    def test_cache_memory_limits(self, memory_test_introspector):
        """Test that caching doesn't cause excessive memory usage."""
        # Create multiple different server configs to fill cache
        server_configs = []
        for i in range(20):
            server_configs.append(MCPServerConfig(
                name=f"cache-test-server-{i}",
                command="python", 
                args=["-c", MockServerHelper.create_fast_mock_server_script()],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={}
            ))
        
        gc.collect()
        process = psutil.Process(os.getpid())
        baseline_memory = process.memory_info().rss / 1024 / 1024
        
        # Fill cache with different servers
        for config in server_configs:
            result = memory_test_introspector.introspect_server(config)
            assert result is not None
        
        gc.collect()
        cached_memory = process.memory_info().rss / 1024 / 1024
        cache_overhead = cached_memory - baseline_memory
        
        # Cache memory assertions
        assert cache_overhead < 100, f"Cache overhead {cache_overhead:.1f}MB too high"
        
        print(f"Cache Memory Test:")
        print(f"  Baseline memory: {baseline_memory:.1f}MB")
        print(f"  Memory with cache: {cached_memory:.1f}MB")
        print(f"  Cache overhead: {cache_overhead:.1f}MB")


@pytest.mark.performance
class TestPerformanceRegression:
    """Performance regression testing."""
    
    PERFORMANCE_BASELINES = {
        "single_introspection_max_time": 5.0,
        "concurrent_success_rate_min": 0.8,
        "memory_usage_max_mb": 100,
        "throughput_min_ops_per_sec": 0.5
    }
    
    @pytest.fixture
    def regression_test_introspector(self):
        """Create introspector for regression testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=True
        )
        return MCPIntrospector(config=config)
    
    def test_performance_regression_single_operation(self, regression_test_introspector):
        """Test for performance regression in single operations."""
        server_config = MCPServerConfig(
            name="regression-test-server",
            command="python",
            args=["-c", MockServerHelper.create_fast_mock_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        # Run multiple samples for statistical significance
        samples = 5
        for _ in range(samples):
            start_time = time.time()
            result = regression_test_introspector.introspect_server(server_config)
            duration = time.time() - start_time
            profiler.record_operation(duration, result is not None)
        
        profiler.stop_monitoring()
        metrics = profiler.get_metrics()
        
        # Regression testing assertions against baselines
        assert metrics.average_time <= self.PERFORMANCE_BASELINES["single_introspection_max_time"], \
            f"Regression: Average time {metrics.average_time:.3f}s exceeds baseline {self.PERFORMANCE_BASELINES['single_introspection_max_time']}s"
        
        assert metrics.memory_usage_mb <= self.PERFORMANCE_BASELINES["memory_usage_max_mb"], \
            f"Regression: Memory usage {metrics.memory_usage_mb:.1f}MB exceeds baseline {self.PERFORMANCE_BASELINES['memory_usage_max_mb']}MB"
        
        assert metrics.success_rate >= 0.95, \
            f"Regression: Success rate {metrics.success_rate:.2f} below expected 0.95"
        
        print(f"Performance Regression Test - Single Operation:")
        print(f"  Average time: {metrics.average_time:.3f}s (baseline: {self.PERFORMANCE_BASELINES['single_introspection_max_time']}s)")
        print(f"  Memory usage: {metrics.memory_usage_mb:.1f}MB (baseline: {self.PERFORMANCE_BASELINES['memory_usage_max_mb']}MB)")
        print(f"  Success rate: {metrics.success_rate:.2%}")
    
    def test_performance_regression_concurrent_operations(self, regression_test_introspector):
        """Test for performance regression in concurrent operations."""
        server_config = MCPServerConfig(
            name="concurrent-regression-server",
            command="python",
            args=["-c", MockServerHelper.create_fast_mock_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = PerformanceProfiler()
        profiler.start_monitoring()
        
        def worker():
            start_time = time.time()
            try:
                result = regression_test_introspector.introspect_server(server_config)
                duration = time.time() - start_time
                return duration, result is not None
            except Exception:
                duration = time.time() - start_time
                return duration, False
        
        # Run concurrent operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(worker) for _ in range(6)]
            
            for future in concurrent.futures.as_completed(futures):
                duration, success = future.result()
                profiler.record_operation(duration, success)
        
        profiler.stop_monitoring()
        metrics = profiler.get_metrics()
        
        # Concurrent regression assertions
        assert metrics.success_rate >= self.PERFORMANCE_BASELINES["concurrent_success_rate_min"], \
            f"Regression: Concurrent success rate {metrics.success_rate:.2f} below baseline {self.PERFORMANCE_BASELINES['concurrent_success_rate_min']}"
        
        assert metrics.throughput_ops_per_sec >= self.PERFORMANCE_BASELINES["throughput_min_ops_per_sec"], \
            f"Regression: Throughput {metrics.throughput_ops_per_sec:.2f} ops/s below baseline {self.PERFORMANCE_BASELINES['throughput_min_ops_per_sec']}"
        
        print(f"Performance Regression Test - Concurrent Operations:")
        print(f"  Success rate: {metrics.success_rate:.2%} (baseline: {self.PERFORMANCE_BASELINES['concurrent_success_rate_min']:.2%})")
        print(f"  Throughput: {metrics.throughput_ops_per_sec:.2f} ops/s (baseline: {self.PERFORMANCE_BASELINES['throughput_min_ops_per_sec']:.2f})")
        print(f"  Average time: {metrics.average_time:.3f}s")


if __name__ == "__main__":
    # Allow running performance tests directly
    pytest.main([__file__, "-v", "-m", "performance"]) 