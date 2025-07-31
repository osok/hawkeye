"""
Memory Leak and Resource Cleanup Testing for MCP Introspection.

This module provides comprehensive testing for memory leaks, resource cleanup,
and proper resource management in the MCP introspection system.
"""

import pytest
import gc
import os
import sys
import time
import threading
import psutil
import tempfile
import weakref
import tracemalloc
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import patch, MagicMock
from contextlib import contextmanager
from dataclasses import dataclass

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType


@dataclass
class MemorySnapshot:
    """Snapshot of memory usage at a point in time."""
    rss_mb: float
    vms_mb: float
    percent: float
    timestamp: float
    gc_objects: int
    
    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = time.time()


class MemoryProfiler:
    """Memory profiling utility for detecting leaks."""
    
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.snapshots: List[MemorySnapshot] = []
        self.monitoring = False
        self.monitor_thread = None
        self.baseline_snapshot: Optional[MemorySnapshot] = None
        
    def start_monitoring(self, interval: float = 0.1):
        """Start memory monitoring."""
        self.monitoring = True
        self.baseline_snapshot = self.take_snapshot()
        
        def monitor():
            while self.monitoring:
                self.snapshots.append(self.take_snapshot())
                time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop memory monitoring."""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def take_snapshot(self) -> MemorySnapshot:
        """Take a memory snapshot."""
        memory_info = self.process.memory_info()
        return MemorySnapshot(
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            percent=self.process.memory_percent(),
            timestamp=time.time(),
            gc_objects=len(gc.get_objects())
        )
    
    def detect_leak(self, threshold_mb: float = 10.0) -> Tuple[bool, Dict[str, Any]]:
        """Detect if there's a memory leak."""
        if len(self.snapshots) < 2:
            return False, {"error": "Insufficient snapshots"}
        
        # Calculate memory growth
        baseline = self.baseline_snapshot or self.snapshots[0]
        latest = self.snapshots[-1]
        
        rss_growth = latest.rss_mb - baseline.rss_mb
        vms_growth = latest.vms_mb - baseline.vms_mb
        gc_growth = latest.gc_objects - baseline.gc_objects
        
        # Check for consistent growth pattern
        if len(self.snapshots) >= 5:
            recent_snapshots = self.snapshots[-5:]
            rss_trend = [s.rss_mb for s in recent_snapshots]
            is_growing = all(rss_trend[i] <= rss_trend[i+1] for i in range(len(rss_trend)-1))
        else:
            is_growing = rss_growth > 0
        
        is_leak = (rss_growth > threshold_mb and is_growing) or gc_growth > 1000
        
        return is_leak, {
            "rss_growth_mb": rss_growth,
            "vms_growth_mb": vms_growth,
            "gc_object_growth": gc_growth,
            "is_consistent_growth": is_growing,
            "snapshot_count": len(self.snapshots),
            "duration_seconds": latest.timestamp - baseline.timestamp
        }
    
    def get_memory_summary(self) -> Dict[str, Any]:
        """Get memory usage summary."""
        if not self.snapshots:
            return {"error": "No snapshots available"}
        
        baseline = self.baseline_snapshot or self.snapshots[0]
        latest = self.snapshots[-1]
        peak_rss = max(s.rss_mb for s in self.snapshots)
        
        return {
            "baseline_rss_mb": baseline.rss_mb,
            "current_rss_mb": latest.rss_mb,
            "peak_rss_mb": peak_rss,
            "growth_mb": latest.rss_mb - baseline.rss_mb,
            "gc_objects_baseline": baseline.gc_objects,
            "gc_objects_current": latest.gc_objects,
            "duration_seconds": latest.timestamp - baseline.timestamp,
            "snapshot_count": len(self.snapshots)
        }


class MockServerForLeakTesting:
    """Mock servers designed to test memory leak scenarios."""
    
    @staticmethod
    def create_normal_server_script() -> str:
        """Create a normal server that shouldn't leak memory."""
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
                    "serverInfo": {"name": "normal-server", "version": "1.0.0"}
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
    def create_memory_leaking_server_script() -> str:
        """Create a server that intentionally leaks memory."""
        return '''
import json
import sys

# Global list to simulate memory leak
leaked_data = []

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        # Intentionally leak memory by storing data
        leaked_data.append("x" * 1000)  # Add 1KB each request
        
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
                    "serverInfo": {
                        "name": "leaky-server", 
                        "version": "1.0.0",
                        "leak_size": len(leaked_data)
                    }
                }
            }
        elif method == "tools/list":
            # Add more leaked data
            leaked_data.extend(["leak"] * 100)
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": []}
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
    def create_resource_holding_server_script() -> str:
        """Create a server that holds onto resources without cleanup."""
        return '''
import json
import sys
import tempfile
import os

# Global storage for file handles (simulating resource leak)
open_files = []

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        
        # Open temporary files without closing them (resource leak)
        try:
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(b"resource leak test data")
            open_files.append(temp_file)  # Keep reference to prevent closing
        except:
            pass
        
        message = json.loads(line.strip())
        method = message.get("method")
        msg_id = message.get("id", 1)
        
        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": {
                        "name": "resource-holding-server",
                        "version": "1.0.0",
                        "open_files": len(open_files)
                    }
                }
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


@pytest.mark.memory_leak
class TestMemoryLeakDetection:
    """Test memory leak detection in MCP introspection."""
    
    @pytest.fixture
    def leak_test_introspector(self):
        """Create introspector for leak testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=False,  # Disable caching to isolate memory leaks
            enable_memory_monitoring=True
        )
        return MCPIntrospector(config=config)
    
    def test_no_memory_leak_with_normal_server(self, leak_test_introspector):
        """Test that normal operations don't cause memory leaks."""
        server_config = MCPServerConfig(
            name="normal-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = MemoryProfiler()
        profiler.start_monitoring(interval=0.05)  # Fast monitoring
        
        # Perform multiple introsctions
        iterations = 20
        for i in range(iterations):
            result = leak_test_introspector.introspect_server(server_config)
            assert result is not None, f"Introspection {i} failed"
            
            # Force garbage collection periodically
            if i % 5 == 0:
                gc.collect()
        
        # Allow some time for cleanup
        time.sleep(0.5)
        gc.collect()
        
        profiler.stop_monitoring()
        
        # Check for memory leaks
        is_leak, leak_info = profiler.detect_leak(threshold_mb=20.0)
        summary = profiler.get_memory_summary()
        
        print(f"Memory Summary after {iterations} operations:")
        print(f"  Growth: {summary['growth_mb']:.2f}MB")
        print(f"  Peak: {summary['peak_rss_mb']:.2f}MB")
        print(f"  GC Objects: {summary['gc_objects_baseline']} -> {summary['gc_objects_current']}")
        
        # Should not have significant memory leak
        assert not is_leak, f"Memory leak detected: {leak_info}"
        assert summary['growth_mb'] < 30.0, f"Memory growth {summary['growth_mb']:.2f}MB too high"
    
    def test_memory_leak_detection_with_leaky_server(self, leak_test_introspector):
        """Test that we can detect memory leaks when they occur."""
        # Note: This test is about detecting leaks in our introspection system,
        # not the server itself. A leaky server shouldn't affect our memory.
        
        server_config = MCPServerConfig(
            name="leaky-server",
            command="python", 
            args=["-c", MockServerForLeakTesting.create_memory_leaking_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        profiler = MemoryProfiler()
        profiler.start_monitoring(interval=0.05)
        
        # Perform introsctions with leaky server
        iterations = 15
        for i in range(iterations):
            result = leak_test_introspector.introspect_server(server_config)
            # Server might fail due to internal leaks, that's OK
            
        profiler.stop_monitoring()
        
        summary = profiler.get_memory_summary()
        
        print(f"Memory Summary with leaky server ({iterations} operations):")
        print(f"  Growth: {summary['growth_mb']:.2f}MB")
        print(f"  Peak: {summary['peak_rss_mb']:.2f}MB")
        
        # Our introspection system should still be leak-free
        # The server's leaks shouldn't affect our process
        assert summary['growth_mb'] < 50.0, f"Introspection system leaked {summary['growth_mb']:.2f}MB"
    
    def test_object_reference_cleanup(self, leak_test_introspector):
        """Test that object references are properly cleaned up."""
        server_config = MCPServerConfig(
            name="reference-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Track objects with weak references
        tracked_objects = []
        
        def track_result(result):
            if result is not None:
                # Create weak references to track object cleanup
                tracked_objects.append(weakref.ref(result))
                if result.tools:
                    for tool in result.tools:
                        tracked_objects.append(weakref.ref(tool))
                if result.resources:
                    for resource in result.resources:
                        tracked_objects.append(weakref.ref(resource))
        
        # Perform introsctions and track objects
        for i in range(10):
            result = leak_test_introspector.introspect_server(server_config)
            track_result(result)
            
            # Delete reference and force garbage collection
            del result
            gc.collect()
        
        # Force final garbage collection
        gc.collect()
        time.sleep(0.1)
        gc.collect()
        
        # Check that objects were cleaned up
        alive_objects = [ref for ref in tracked_objects if ref() is not None]
        cleanup_rate = (len(tracked_objects) - len(alive_objects)) / len(tracked_objects)
        
        print(f"Object cleanup: {len(tracked_objects) - len(alive_objects)}/{len(tracked_objects)} ({cleanup_rate:.2%})")
        
        # Most objects should be cleaned up
        assert cleanup_rate >= 0.8, f"Only {cleanup_rate:.2%} of objects were cleaned up"
    
    def test_repeated_introspections_memory_stability(self, leak_test_introspector):
        """Test memory stability over many repeated introsctions."""
        server_config = MCPServerConfig(
            name="stability-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Take memory snapshots at intervals
        memory_snapshots = []
        process = psutil.Process(os.getpid())
        
        def take_memory_snapshot():
            return process.memory_info().rss / 1024 / 1024  # MB
        
        # Baseline measurement
        gc.collect()
        baseline_memory = take_memory_snapshot()
        memory_snapshots.append(baseline_memory)
        
        # Perform many introsctions with periodic memory sampling
        total_iterations = 50
        sample_interval = 10
        
        for i in range(total_iterations):
            result = leak_test_introspector.introspect_server(server_config)
            assert result is not None, f"Introspection {i} failed"
            
            if (i + 1) % sample_interval == 0:
                gc.collect()
                memory_snapshots.append(take_memory_snapshot())
        
        # Final measurement
        gc.collect()
        final_memory = take_memory_snapshot()
        memory_snapshots.append(final_memory)
        
        # Analyze memory stability
        memory_growth = final_memory - baseline_memory
        max_memory = max(memory_snapshots)
        memory_variance = max(memory_snapshots) - min(memory_snapshots)
        
        print(f"Memory Stability Test ({total_iterations} iterations):")
        print(f"  Baseline: {baseline_memory:.2f}MB")
        print(f"  Final: {final_memory:.2f}MB")
        print(f"  Growth: {memory_growth:.2f}MB")
        print(f"  Peak: {max_memory:.2f}MB")
        print(f"  Variance: {memory_variance:.2f}MB")
        print(f"  Snapshots: {[f'{m:.1f}' for m in memory_snapshots]}")
        
        # Memory should be stable
        assert memory_growth < 25.0, f"Memory grew by {memory_growth:.2f}MB over {total_iterations} iterations"
        assert memory_variance < 40.0, f"Memory variance {memory_variance:.2f}MB too high"


@pytest.mark.memory_leak
class TestResourceCleanup:
    """Test proper cleanup of system resources."""
    
    @pytest.fixture
    def resource_test_introspector(self):
        """Create introspector for resource testing."""
        config = IntrospectionConfig(
            timeout=8.0,
            max_retries=1,
            retry_delay=0.1,
            enable_resource_tracking=True
        )
        return MCPIntrospector(config=config)
    
    def test_subprocess_cleanup(self, resource_test_introspector):
        """Test that subprocesses are properly cleaned up."""
        server_config = MCPServerConfig(
            name="subprocess-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Get initial process count
        initial_process_count = len(psutil.Process().children(recursive=True))
        
        # Perform multiple introsctions
        for i in range(10):
            result = resource_test_introspector.introspect_server(server_config)
            assert result is not None, f"Introspection {i} failed"
        
        # Allow time for cleanup
        time.sleep(1.0)
        
        # Check final process count
        final_process_count = len(psutil.Process().children(recursive=True))
        
        print(f"Process count: {initial_process_count} -> {final_process_count}")
        
        # Should not accumulate subprocess
        assert final_process_count <= initial_process_count + 1, "Subprocesses not properly cleaned up"
    
    def test_file_handle_cleanup(self, resource_test_introspector):
        """Test that file handles are properly cleaned up."""
        server_config = MCPServerConfig(
            name="file-handle-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Get initial file handle count
        process = psutil.Process()
        try:
            initial_fds = process.num_fds()
        except AttributeError:
            # Windows doesn't have num_fds, use open_files
            initial_fds = len(process.open_files())
        
        # Perform introsctions
        for i in range(15):
            result = resource_test_introspector.introspect_server(server_config)
            assert result is not None, f"Introspection {i} failed"
        
        # Allow time for cleanup
        time.sleep(0.5)
        
        # Check final file handle count
        try:
            final_fds = process.num_fds()
        except AttributeError:
            final_fds = len(process.open_files())
        
        fd_growth = final_fds - initial_fds
        
        print(f"File descriptors: {initial_fds} -> {final_fds} (growth: {fd_growth})")
        
        # Should not accumulate file handles
        assert fd_growth <= 5, f"File handle leak detected: grew by {fd_growth}"
    
    def test_thread_cleanup(self, resource_test_introspector):
        """Test that threads are properly cleaned up."""
        # Get initial thread count
        initial_thread_count = threading.active_count()
        
        server_config = MCPServerConfig(
            name="thread-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Perform introsctions
        for i in range(8):
            result = resource_test_introspector.introspect_server(server_config)
            assert result is not None, f"Introspection {i} failed"
        
        # Allow time for thread cleanup
        time.sleep(1.0)
        
        # Check final thread count
        final_thread_count = threading.active_count()
        thread_growth = final_thread_count - initial_thread_count
        
        print(f"Thread count: {initial_thread_count} -> {final_thread_count} (growth: {thread_growth})")
        
        # Should not accumulate threads
        assert thread_growth <= 2, f"Thread leak detected: grew by {thread_growth}"
    
    def test_error_scenario_cleanup(self, resource_test_introspector):
        """Test resource cleanup when errors occur."""
        # Create server that will cause errors
        error_server_config = MCPServerConfig(
            name="error-server",
            command="non-existent-command",
            args=["--invalid"],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Get initial resource counts
        process = psutil.Process()
        initial_children = len(process.children())
        try:
            initial_fds = process.num_fds()
        except AttributeError:
            initial_fds = len(process.open_files())
        
        # Attempt introsctions that will fail
        for i in range(5):
            result = resource_test_introspector.introspect_server(error_server_config)
            # These should fail, but resources should still be cleaned up
        
        # Allow time for cleanup
        time.sleep(1.0)
        
        # Check resource cleanup after errors
        final_children = len(process.children())
        try:
            final_fds = process.num_fds()
        except AttributeError:
            final_fds = len(process.open_files())
        
        child_growth = final_children - initial_children
        fd_growth = final_fds - initial_fds
        
        print(f"After error scenarios - Children: {child_growth}, FDs: {fd_growth}")
        
        # Resources should be cleaned up even after errors
        assert child_growth <= 1, f"Child processes not cleaned up after errors: {child_growth}"
        assert fd_growth <= 3, f"File descriptors not cleaned up after errors: {fd_growth}"


@pytest.mark.memory_leak
class TestCacheMemoryManagement:
    """Test memory management in caching scenarios."""
    
    @pytest.fixture
    def cache_test_introspector(self):
        """Create introspector with caching enabled."""
        config = IntrospectionConfig(
            timeout=10.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=True,
            cache_ttl=60.0,
            max_cache_size=50  # Limit cache size
        )
        return MCPIntrospector(config=config)
    
    def test_cache_memory_bounds(self, cache_test_introspector):
        """Test that cache doesn't grow unbounded."""
        # Create many different servers to fill cache
        server_configs = []
        for i in range(20):
            server_configs.append(MCPServerConfig(
                name=f"cache-test-server-{i}",
                command="python",
                args=["-c", MockServerForLeakTesting.create_normal_server_script()],
                transport_type=TransportType.STDIO,
                working_directory=None,
                environment_variables={"SERVER_ID": str(i)}
            ))
        
        # Monitor memory while filling cache
        profiler = MemoryProfiler()
        profiler.start_monitoring()
        
        # Fill cache beyond configured limit
        for config in server_configs:
            result = cache_test_introspector.introspect_server(config)
            assert result is not None
        
        # Perform additional operations to trigger cache eviction
        for i in range(5):
            for config in server_configs[:5]:  # Repeat some operations
                result = cache_test_introspector.introspect_server(config)
        
        profiler.stop_monitoring()
        
        summary = profiler.get_memory_summary()
        
        print(f"Cache Memory Test:")
        print(f"  Growth: {summary['growth_mb']:.2f}MB")
        print(f"  Peak: {summary['peak_rss_mb']:.2f}MB")
        
        # Cache should have bounded memory usage
        assert summary['growth_mb'] < 40.0, f"Cache memory growth {summary['growth_mb']:.2f}MB too high"
    
    def test_cache_cleanup_on_ttl_expiry(self, cache_test_introspector):
        """Test that cache entries are cleaned up when TTL expires."""
        # Override cache TTL for testing
        cache_test_introspector.config.cache_ttl = 1.0  # 1 second
        
        server_config = MCPServerConfig(
            name="ttl-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Fill cache
        gc.collect()
        baseline_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        for i in range(10):
            result = cache_test_introspector.introspect_server(server_config)
            assert result is not None
        
        cached_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Wait for TTL expiry
        time.sleep(2.0)
        
        # Trigger cache cleanup by performing new operations
        for i in range(3):
            result = cache_test_introspector.introspect_server(server_config)
        
        gc.collect()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        cache_growth = cached_memory - baseline_memory
        final_growth = final_memory - baseline_memory
        
        print(f"TTL Test: Baseline: {baseline_memory:.2f}MB, Cached: {cached_memory:.2f}MB, Final: {final_memory:.2f}MB")
        print(f"Cache growth: {cache_growth:.2f}MB, Final growth: {final_growth:.2f}MB")
        
        # Memory should be reclaimed after TTL expiry
        # Allow some tolerance for timing variations
        assert final_growth < cache_growth * 1.5, "Cache memory not properly reclaimed after TTL expiry"


@pytest.mark.memory_leak
class TestLongRunningMemoryBehavior:
    """Test memory behavior in long-running scenarios."""
    
    @pytest.fixture
    def long_running_introspector(self):
        """Create introspector for long-running tests."""
        config = IntrospectionConfig(
            timeout=5.0,
            max_retries=1,
            retry_delay=0.1,
            enable_caching=True,
            cache_ttl=10.0,
            enable_memory_monitoring=True
        )
        return MCPIntrospector(config=config)
    
    def test_long_running_memory_stability(self, long_running_introspector):
        """Test memory stability over extended operation."""
        server_config = MCPServerConfig(
            name="long-running-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Run for extended period with memory monitoring
        profiler = MemoryProfiler()
        profiler.start_monitoring(interval=0.2)
        
        start_time = time.time()
        duration = 15.0  # 15 seconds
        operation_count = 0
        
        while (time.time() - start_time) < duration:
            result = long_running_introspector.introspect_server(server_config)
            if result is not None:
                operation_count += 1
            
            # Periodic garbage collection
            if operation_count % 10 == 0:
                gc.collect()
            
            # Small delay between operations
            time.sleep(0.1)
        
        profiler.stop_monitoring()
        
        # Analyze long-running behavior
        summary = profiler.get_memory_summary()
        is_leak, leak_info = profiler.detect_leak(threshold_mb=15.0)
        
        print(f"Long-running test ({operation_count} operations over {duration}s):")
        print(f"  Memory growth: {summary['growth_mb']:.2f}MB")
        print(f"  Peak memory: {summary['peak_rss_mb']:.2f}MB")
        print(f"  Operations per second: {operation_count / duration:.2f}")
        
        # Should maintain stable memory usage
        assert not is_leak, f"Memory leak detected in long-running test: {leak_info}"
        assert summary['growth_mb'] < 25.0, f"Memory growth {summary['growth_mb']:.2f}MB too high"
    
    @pytest.mark.slow
    def test_extended_operation_memory_ceiling(self, long_running_introspector):
        """Test that memory usage has a reasonable ceiling."""
        server_config = MCPServerConfig(
            name="ceiling-test-server",
            command="python",
            args=["-c", MockServerForLeakTesting.create_normal_server_script()],
            transport_type=TransportType.STDIO,
            working_directory=None,
            environment_variables={}
        )
        
        # Perform many operations to test memory ceiling
        max_memory = 0
        operation_count = 100
        
        for i in range(operation_count):
            result = long_running_introspector.introspect_server(server_config)
            
            if i % 20 == 0:  # Sample memory periodically
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                max_memory = max(max_memory, current_memory)
                
                if i % 40 == 0:  # Periodic cleanup
                    gc.collect()
        
        # Final memory check
        gc.collect()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        max_memory = max(max_memory, final_memory)
        
        print(f"Extended operation test ({operation_count} operations):")
        print(f"  Peak memory: {max_memory:.2f}MB")
        print(f"  Final memory: {final_memory:.2f}MB")
        
        # Memory should have reasonable ceiling
        assert max_memory < 200.0, f"Memory usage {max_memory:.2f}MB exceeds reasonable ceiling"


if __name__ == "__main__":
    # Allow running memory leak tests directly
    pytest.main([__file__, "-v", "-m", "memory_leak"]) 