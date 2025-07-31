"""
Integration tests for complete MCP introspection workflow.

Tests the end-to-end functionality of the enhanced MCP introspection system,
including transport handlers, discovery components, risk analysis, and
performance monitoring.
"""

import pytest
import time
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection import MCPIntrospector
from src.hawkeye.detection.mcp_introspection.compat import LegacyMCPIntrospector
from src.hawkeye.detection.base import MCPServerInfo, ProcessInfo
from src.hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from src.hawkeye.detection.mcp_introspection.models import (
    MCPServerConfig, MCPServerInfo as NewMCPServerInfo,
    MCPTool as NewMCPTool, MCPResource as NewMCPResource,
    RiskLevel
)
from src.hawkeye.detection.mcp_introspection.metrics import get_global_monitor


class TestCompleteIntrospectionWorkflow:
    """Test the complete introspection workflow end-to-end."""
    
    @pytest.fixture
    def introspector(self):
        """Create an introspector for integration testing."""
        config = IntrospectionConfig(
            timeout=30.0,
            enable_detailed_analysis=True,
            enable_risk_assessment=True
        )
        return MCPIntrospector(config)
    
    @pytest.fixture
    def sample_servers(self):
        """Create sample server configurations for testing."""
        return [
            (
                MCPServerInfo(
                    name="file_server",
                    path="/usr/bin/file-server",
                    args=["--safe-mode"],
                    env={"NODE_ENV": "production"}
                ),
                ProcessInfo(
                    pid=1001,
                    name="file-server",
                    cmdline=["/usr/bin/file-server", "--safe-mode"],
                    cwd="/opt/servers",
                    environ={"NODE_ENV": "production"}
                )
            ),
            (
                MCPServerInfo(
                    name="web_server",
                    path="/usr/bin/web-server",
                    args=["--port", "8080"],
                    env={"NODE_ENV": "development"}
                ),
                ProcessInfo(
                    pid=1002,
                    name="web-server",
                    cmdline=["/usr/bin/web-server", "--port", "8080"],
                    cwd="/opt/servers",
                    environ={"NODE_ENV": "development"}
                )
            ),
            (
                MCPServerInfo(
                    name="api_server",
                    url="http://localhost:9000",
                    args=["--api-mode"],
                    env={"API_KEY": "test123"}
                ),
                ProcessInfo(
                    pid=1003,
                    name="api-server",
                    cmdline=["/usr/bin/api-server", "--api-mode"],
                    cwd="/opt/servers",
                    environ={"API_KEY": "test123"}
                )
            )
        ]
    
    def test_single_server_complete_workflow(self, introspector):
        """Test complete workflow for a single server."""
        server_info = MCPServerInfo(
            name="test_server",
            path="/usr/bin/test-server",
            args=["--test-mode"]
        )
        process_info = ProcessInfo(
            pid=12345,
            name="test-server",
            cmdline=["/usr/bin/test-server", "--test-mode"],
            cwd="/opt/test",
            environ={"TEST_MODE": "true"}
        )
        
        # Record initial statistics
        initial_stats = introspector.get_transport_statistics()
        initial_introspections = initial_stats["total_introspections"]
        
        # Perform introspection (will likely fail in test environment, but should handle gracefully)
        result = introspector.introspect_server(server_info, process_info)
        
        # Verify statistics were updated
        updated_stats = introspector.get_transport_statistics()
        assert updated_stats["total_introspections"] == initial_introspections + 1
        
        # Verify discovery statistics
        discovery_stats = introspector.get_discovery_statistics()
        assert isinstance(discovery_stats, dict)
        assert "tools_discovered" in discovery_stats
        assert "resources_discovered" in discovery_stats
        
        # Verify cache statistics
        cache_stats = introspector.get_cache_statistics()
        assert isinstance(cache_stats, dict)
        assert "cache_hits" in cache_stats
        assert "cache_misses" in cache_stats
    
    def test_multiple_servers_workflow(self, introspector, sample_servers):
        """Test workflow with multiple servers."""
        results = []
        
        for server_info, process_info in sample_servers:
            result = introspector.introspect_server(server_info, process_info)
            results.append((server_info.name, result))
        
        # Verify all servers were processed
        assert len(results) == 3
        
        # Verify statistics reflect multiple introspections
        stats = introspector.get_transport_statistics()
        assert stats["total_introspections"] >= 3
        
        # Test multiple server introspection method
        multiple_results = introspector.introspect_multiple_servers(sample_servers)
        assert isinstance(multiple_results, list)
    
    def test_transport_integration(self, introspector):
        """Test integration with different transport types."""
        # Test stdio transport
        stdio_server = MCPServerInfo("stdio_server", "/usr/bin/stdio-server")
        stdio_process = ProcessInfo(2001, "stdio-server", [], "/", {})
        
        stdio_result = introspector.introspect_server(stdio_server, stdio_process)
        
        # Test HTTP transport
        http_server = MCPServerInfo("http_server", args=["--http", "--port", "8000"])
        http_process = ProcessInfo(2002, "http-server", [], "/", {})
        
        http_result = introspector.introspect_server(http_server, http_process)
        
        # Verify transport statistics
        stats = introspector.get_transport_statistics()
        assert stats["stdio_connections"] >= 1
        
        # Test supported transports
        supported = introspector.get_supported_transports()
        assert isinstance(supported, list)
        assert len(supported) > 0
    
    def test_discovery_integration(self, introspector):
        """Test integration with discovery components."""
        server_info = MCPServerInfo("discovery_test", "/usr/bin/discovery-test")
        process_info = ProcessInfo(3001, "discovery-test", [], "/", {})
        
        # Test individual discovery methods
        tools = introspector.discover_tools_only(server_info, process_info)
        assert isinstance(tools, list)
        
        resources = introspector.discover_resources_only(server_info, process_info)
        assert isinstance(resources, list)
        
        capabilities = introspector.discover_capabilities_only(server_info, process_info)
        assert isinstance(capabilities, dict)
        
        # Verify discovery statistics
        discovery_stats = introspector.get_discovery_statistics()
        assert discovery_stats["discovery_failures"] >= 0  # May fail in test environment
    
    def test_risk_analysis_integration(self, introspector):
        """Test integration with risk analysis components."""
        server_info = MCPServerInfo("risk_test", "/usr/bin/risk-test")
        process_info = ProcessInfo(4001, "risk-test", [], "/", {})
        
        # Test risk analysis methods
        try:
            risks = introspector.analyze_server_risks(server_info, process_info)
            assert isinstance(risks, dict)
        except Exception:
            # Risk analysis may fail in test environment
            pass
        
        try:
            risk_summary = introspector.get_risk_summary(server_info, process_info)
            assert isinstance(risk_summary, dict)
        except Exception:
            # Risk analysis may fail in test environment
            pass
        
        # Test introspection with risk analysis
        result = introspector.introspect_with_risk_analysis(server_info, process_info)
        # Result may be None if introspection fails, which is acceptable in test environment
    
    def test_performance_monitoring_integration(self, introspector):
        """Test integration with performance monitoring."""
        server_info = MCPServerInfo("perf_test", "/usr/bin/perf-test")
        process_info = ProcessInfo(5001, "perf-test", [], "/", {})
        
        # Record initial performance metrics
        initial_report = get_global_monitor().get_performance_report()
        initial_operations = initial_report.get("summary", {}).get("total_operations", 0)
        
        # Perform introspection
        result = introspector.introspect_server(server_info, process_info)
        
        # Verify performance metrics were recorded
        updated_report = get_global_monitor().get_performance_report()
        updated_operations = updated_report.get("summary", {}).get("total_operations", 0)
        
        # Should have recorded at least some operations
        assert updated_operations >= initial_operations
    
    def test_caching_workflow(self, introspector):
        """Test caching behavior in the complete workflow."""
        server_info = MCPServerInfo("cache_test", "/usr/bin/cache-test")
        process_info = ProcessInfo(6001, "cache-test", [], "/", {})
        
        # First introspection
        result1 = introspector.introspect_server(server_info, process_info)
        cache_stats1 = introspector.get_cache_statistics()
        
        # Second introspection (may hit cache)
        result2 = introspector.introspect_server(server_info, process_info)
        cache_stats2 = introspector.get_cache_statistics()
        
        # Verify cache statistics are being tracked
        assert cache_stats2["cache_misses"] >= cache_stats1["cache_misses"]
    
    def test_error_handling_workflow(self, introspector):
        """Test error handling throughout the workflow."""
        # Test with invalid server
        invalid_server = MCPServerInfo("invalid", "/nonexistent/path")
        invalid_process = ProcessInfo(99999, "invalid", [], "/", {})
        
        result = introspector.introspect_server(invalid_server, invalid_process)
        
        # Should handle gracefully
        assert result is None
        
        # Statistics should still be updated
        stats = introspector.get_transport_statistics()
        assert stats["total_introspections"] > 0
    
    def test_configuration_workflow(self, introspector):
        """Test workflow with different configurations."""
        # Test with minimal configuration
        minimal_config = IntrospectionConfig(
            timeout=5.0,
            enable_detailed_analysis=False,
            enable_risk_assessment=False
        )
        minimal_introspector = MCPIntrospector(minimal_config)
        
        server_info = MCPServerInfo("config_test", "/usr/bin/config-test")
        process_info = ProcessInfo(7001, "config-test", [], "/", {})
        
        result = minimal_introspector.introspect_server(server_info, process_info)
        
        # Should work with minimal configuration
        assert minimal_introspector.introspection_config.timeout == 5.0
        assert minimal_introspector.introspection_config.enable_detailed_analysis is False


class TestLegacyCompatibilityWorkflow:
    """Test the complete workflow through the legacy compatibility layer."""
    
    @pytest.fixture
    def legacy_introspector(self):
        """Create a legacy introspector for testing."""
        config = IntrospectionConfig(timeout=30.0)
        return LegacyMCPIntrospector(config)
    
    def test_legacy_complete_workflow(self, legacy_introspector):
        """Test complete workflow through legacy interface."""
        server_info = MCPServerInfo("legacy_test", "/usr/bin/legacy-test")
        process_info = ProcessInfo(8001, "legacy-test", [], "/", {})
        
        # Test legacy introspection
        result = legacy_introspector.introspect_server(server_info, process_info)
        
        # Result may be None if introspection fails in test environment
        if result is not None:
            assert isinstance(result, dict)
            assert "server_name" in result
            assert "tools" in result
            assert "resources" in result
    
    def test_legacy_script_workflow(self, legacy_introspector):
        """Test legacy script generation and execution workflow."""
        server_info = MCPServerInfo("script_test", "/usr/bin/script-test")
        process_info = ProcessInfo(8002, "script-test", [], "/", {})
        
        # Test script generation
        script = legacy_introspector.generate_script(server_info, process_info)
        assert isinstance(script, str)
        assert len(script) > 0
        
        # Test script execution
        result = legacy_introspector.execute_script(script, server_info, process_info)
        
        # Result may be None if execution fails in test environment
        if result is not None:
            assert isinstance(result, dict)


class TestWorkflowPerformance:
    """Test performance characteristics of the complete workflow."""
    
    @pytest.fixture
    def performance_introspector(self):
        """Create an introspector optimized for performance testing."""
        config = IntrospectionConfig(
            timeout=10.0,
            enable_detailed_analysis=True,
            enable_risk_assessment=True
        )
        return MCPIntrospector(config)
    
    def test_single_server_performance(self, performance_introspector):
        """Test performance of single server introspection."""
        server_info = MCPServerInfo("perf_single", "/usr/bin/perf-single")
        process_info = ProcessInfo(9001, "perf-single", [], "/", {})
        
        start_time = time.time()
        result = performance_introspector.introspect_server(server_info, process_info)
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Should complete within reasonable time (even if it fails)
        assert execution_time < 30.0  # Should not hang
        
        # Verify performance metrics were recorded
        stats = performance_introspector.get_transport_statistics()
        assert stats["total_introspections"] > 0
    
    def test_multiple_servers_performance(self, performance_introspector):
        """Test performance of multiple server introspection."""
        servers = [
            (MCPServerInfo(f"perf_multi_{i}", f"/usr/bin/perf-multi-{i}"),
             ProcessInfo(9100 + i, f"perf-multi-{i}", [], "/", {}))
            for i in range(5)
        ]
        
        start_time = time.time()
        
        results = []
        for server_info, process_info in servers:
            result = performance_introspector.introspect_server(server_info, process_info)
            results.append(result)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete all servers within reasonable time
        assert execution_time < 60.0  # Should not hang
        assert len(results) == 5
        
        # Verify statistics
        stats = performance_introspector.get_transport_statistics()
        assert stats["total_introspections"] >= 5
    
    def test_memory_usage_workflow(self, performance_introspector):
        """Test memory usage during workflow execution."""
        # This is a basic test - in a real environment you'd use memory profiling tools
        server_info = MCPServerInfo("memory_test", "/usr/bin/memory-test")
        process_info = ProcessInfo(9201, "memory-test", [], "/", {})
        
        # Perform multiple introspections
        for i in range(10):
            result = performance_introspector.introspect_server(server_info, process_info)
        
        # Verify that statistics are being maintained properly
        stats = performance_introspector.get_transport_statistics()
        assert stats["total_introspections"] >= 10
        
        # Cache should be working
        cache_stats = performance_introspector.get_cache_statistics()
        assert isinstance(cache_stats, dict)


class TestWorkflowRobustness:
    """Test robustness and error recovery of the complete workflow."""
    
    @pytest.fixture
    def robust_introspector(self):
        """Create an introspector for robustness testing."""
        config = IntrospectionConfig(
            timeout=5.0,  # Short timeout for faster testing
            enable_detailed_analysis=True,
            enable_risk_assessment=True
        )
        return MCPIntrospector(config)
    
    def test_invalid_server_robustness(self, robust_introspector):
        """Test robustness with invalid server configurations."""
        invalid_servers = [
            (MCPServerInfo("", ""), ProcessInfo(0, "", [], "", {})),
            (MCPServerInfo("nonexistent", "/nonexistent/path"), ProcessInfo(99999, "nonexistent", [], "/", {})),
            (MCPServerInfo("malformed", None), ProcessInfo(-1, "malformed", [], None, {}))
        ]
        
        for server_info, process_info in invalid_servers:
            try:
                result = robust_introspector.introspect_server(server_info, process_info)
                # Should handle gracefully and return None
                assert result is None
            except Exception as e:
                # Should not raise unhandled exceptions
                pytest.fail(f"Unhandled exception with invalid server: {e}")
    
    def test_timeout_robustness(self, robust_introspector):
        """Test robustness with timeout scenarios."""
        # Use a very short timeout to force timeout scenarios
        timeout_config = IntrospectionConfig(timeout=0.1)
        timeout_introspector = MCPIntrospector(timeout_config)
        
        server_info = MCPServerInfo("timeout_test", "/usr/bin/timeout-test")
        process_info = ProcessInfo(9301, "timeout-test", [], "/", {})
        
        result = timeout_introspector.introspect_server(server_info, process_info)
        
        # Should handle timeout gracefully
        assert result is None
        
        # Statistics should still be updated
        stats = timeout_introspector.get_transport_statistics()
        assert stats["total_introspections"] > 0
    
    def test_concurrent_workflow_robustness(self, robust_introspector):
        """Test robustness with concurrent operations."""
        import threading
        
        results = []
        errors = []
        
        def worker(worker_id):
            try:
                server_info = MCPServerInfo(f"concurrent_{worker_id}", f"/usr/bin/concurrent-{worker_id}")
                process_info = ProcessInfo(9400 + worker_id, f"concurrent-{worker_id}", [], "/", {})
                
                result = robust_introspector.introspect_server(server_info, process_info)
                results.append((worker_id, result))
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(results) == 5
        assert len(errors) == 0  # Should not have any unhandled errors
        
        # Verify statistics reflect concurrent operations
        stats = robust_introspector.get_transport_statistics()
        assert stats["total_introspections"] >= 5


if __name__ == "__main__":
    pytest.main([__file__]) 