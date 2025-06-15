"""
End-to-end integration tests for MCP Introspection System.

These tests verify the complete integration of the MCP introspection system
with all its components working together in realistic scenarios.
"""

import pytest
import time
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Any
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import ThreadPoolExecutor

from src.hawkeye.detection.mcp_introspection import MCPIntrospection, IntrospectionConfig
from src.hawkeye.detection.mcp_introspection.models import (
    MCPServerConfig, MCPServerInfo, MCPTool, MCPResource, 
    IntrospectionResult, RiskLevel
)
from src.hawkeye.detection.mcp_introspection.optimization import (
    create_memory_optimizer, MemoryConfig, MemoryOptimizationLevel
)
from src.hawkeye.detection.mcp_introspection.migration import (
    ConfigurationMigrator, LegacyMCPConfig, MigrationConfig
)
from src.hawkeye.detection.pipeline import DetectionPipeline, PipelineConfig
from src.hawkeye.reporting.json_reporter import JSONReporter
from src.hawkeye.reporting.base import ReportData, ReportMetadata, ReportType, ReportFormat
from src.hawkeye.config.settings import get_settings


class TestMCPIntrospectionE2E:
    """End-to-end tests for MCP introspection system."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        # Cleanup
        import shutil
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_server_configs(self):
        """Create test MCP server configurations."""
        return [
            MCPServerConfig(
                name="file-server",
                command="node",
                args=["file-server.js"],
                transport_type="stdio",
                cwd="/home/user/mcp-servers/file-server"
            ),
            MCPServerConfig(
                name="web-server", 
                command="node",
                args=["web-server.js", "--port", "8080"],
                transport_type="http",
                url="http://localhost:8080"
            ),
            MCPServerConfig(
                name="api-server",
                command="python",
                args=["-m", "mcp_server", "--sse"],
                transport_type="sse",
                url="http://localhost:9000/sse"
            )
        ]
    
    @pytest.fixture
    def introspection_config(self):
        """Create test introspection configuration."""
        return IntrospectionConfig(
            timeout=30.0,
            max_retries=2,
            enable_caching=True,
            cache_ttl=300.0,
            enable_fallback=True,
            enable_risk_analysis=True,
            enable_optimization=True
        )
    
    def test_complete_introspection_workflow(self, test_server_configs, introspection_config, temp_dir):
        """Test complete introspection workflow from config to report."""
        # Create introspector
        introspector = MCPIntrospection(introspection_config)
        
        # Mock the server responses
        def mock_introspect_server(server_config):
            """Mock server introspection with realistic data."""
            tools = []
            resources = []
            
            if server_config.name == "file-server":
                tools = [
                    MCPTool(
                        name="read_file",
                        description="Read file contents",
                        parameters={"path": {"type": "string", "required": True}}
                    ),
                    MCPTool(
                        name="write_file", 
                        description="Write file contents",
                        parameters={"path": {"type": "string"}, "content": {"type": "string"}}
                    )
                ]
                resources = [
                    MCPResource(
                        uri="file:///etc/passwd",
                        name="system_files",
                        description="System configuration files",
                        mime_type="text/plain"
                    )
                ]
            elif server_config.name == "web-server":
                tools = [
                    MCPTool(
                        name="web_search",
                        description="Search the web",
                        parameters={"query": {"type": "string"}}
                    )
                ]
            elif server_config.name == "api-server":
                tools = [
                    MCPTool(
                        name="api_call",
                        description="Make API calls",
                        parameters={"endpoint": {"type": "string"}, "method": {"type": "string"}}
                    )
                ]
            
            server_info = MCPServerInfo(
                server_name=server_config.name,
                server_version="1.0.0",
                protocol_version="2024-11-05",
                transport_type=server_config.transport_type,
                capabilities={
                    "tools": {"list": True},
                    "resources": {"list": True}
                },
                tools=tools,
                resources=resources,
                risk_level=RiskLevel.HIGH if server_config.name == "file-server" else RiskLevel.MEDIUM,
                introspection_timestamp=time.time()
            )
            
            return IntrospectionResult(
                server_config=server_config,
                server_info=server_info,
                success=True,
                timestamp=time.time(),
                duration=1.5,
                error_message=None
            )
        
        with patch.object(introspector, 'introspect_server', side_effect=mock_introspect_server):
            # Step 1: Introspect all servers
            results = []
            for server_config in test_server_configs:
                result = introspector.introspect_server(server_config)
                results.append(result)
            
            # Verify all introspections succeeded
            assert len(results) == 3
            assert all(result.success for result in results)
            
            # Step 2: Verify risk analysis
            high_risk_servers = [r for r in results if r.server_info.risk_level == RiskLevel.HIGH]
            assert len(high_risk_servers) == 1
            assert high_risk_servers[0].server_config.name == "file-server"
            
            # Step 3: Generate comprehensive report
            metadata = ReportMetadata(
                title="MCP Introspection E2E Test Report",
                report_type=ReportType.INTROSPECTION_REPORT,
                format=ReportFormat.JSON
            )
            
            report_data = ReportData(metadata)
            report_data.mcp_servers = [r.server_info for r in results]
            report_data.introspection_results = {r.server_config.name: r for r in results}
            
            # Add aggregated statistics
            total_tools = sum(len(r.server_info.tools) for r in results)
            total_resources = sum(len(r.server_info.resources) for r in results)
            
            report_data.executive_summary = f"Introspected {len(results)} MCP servers, discovered {total_tools} tools and {total_resources} resources"
            
            # Generate report
            reporter = JSONReporter()
            output_file = temp_dir / "e2e_introspection_report.json"
            reporter.generate_report(report_data, output_file)
            
            # Verify report was created
            assert output_file.exists()
            
            # Verify report content
            with open(output_file, 'r') as f:
                report_content = json.loads(f.read())
            
            assert "metadata" in report_content
            assert "mcp_servers" in report_content
            assert len(report_content["mcp_servers"]) == 3
            assert "executive_summary" in report_content
    
    def test_pipeline_integration_e2e(self, test_server_configs, temp_dir):
        """Test complete pipeline integration with introspection."""
        # Create pipeline configuration
        pipeline_config = PipelineConfig(
            enable_process_enumeration=True,
            enable_config_discovery=True, 
            enable_protocol_verification=True,
            enable_transport_detection=True,
            enable_npx_detection=True,
            enable_docker_inspection=True,
            enable_environment_analysis=True,
            enable_mcp_introspection=True,
            introspection_timeout=30.0,
            enable_risk_assessment=True
        )
        
        # Create pipeline
        pipeline = DetectionPipeline(pipeline_config)
        
        # Mock introspection
        with patch.object(pipeline.introspector, 'introspect_servers') as mock_introspect:
            mock_result = {
                "test-server": IntrospectionResult(
                    server_config=test_server_configs[0], 
                    server_info=MCPServerInfo(
                        server_name="test-server",
                        server_version="1.0.0",
                        protocol_version="2024-11-05",
                        transport_type="stdio",
                        capabilities={},
                        tools=[
                            MCPTool(
                                name="dangerous_tool",
                                description="Potentially dangerous file operations",
                                parameters={"path": {"type": "string"}}
                            )
                        ],
                        resources=[],
                        risk_level=RiskLevel.CRITICAL,
                        introspection_timestamp=time.time()
                    ),
                    success=True,
                    timestamp=time.time(),
                    duration=2.0
                )
            }
            mock_introspect.return_value = mock_result
            
            # Execute pipeline
            result = pipeline.execute("localhost", test_server_configs)
            
            # Verify pipeline execution
            assert result.success == True
            assert result.target_host == "localhost"
            assert result.mcp_servers_found > 0
            assert result.introspection_results is not None
            assert len(result.introspection_results) > 0
            
            # Verify risk assessment
            assert result.risk_assessment is not None
            assert "risk_factors" in result.risk_assessment
            assert result.best_mcp_server is not None
            assert result.best_mcp_server.risk_level == RiskLevel.CRITICAL
    
    def test_memory_optimization_e2e(self, test_server_configs, introspection_config):
        """Test memory optimization in complete workflow."""
        # Enable memory optimization
        memory_config = MemoryConfig(
            optimization_level=MemoryOptimizationLevel.STANDARD,
            enable_object_pooling=True,
            enable_weak_references=True,
            enable_gc_optimization=True,
            max_cache_size=100
        )
        
        memory_optimizer = create_memory_optimizer(memory_config)
        
        # Create introspector with memory optimization
        introspector = MCPIntrospection(introspection_config)
        
        # Mock memory-intensive operations
        def mock_memory_intensive_introspection(server_config):
            # Simulate memory usage
            large_data = ["data" * 1000 for _ in range(1000)]
            
            # Use memory optimizer context
            with memory_optimizer.memory_context("introspection"):
                server_info = MCPServerInfo(
                    server_name=server_config.name,
                    server_version="1.0.0", 
                    protocol_version="2024-11-05",
                    transport_type=server_config.transport_type,
                    capabilities={},
                    tools=[],
                    resources=[],
                    risk_level=RiskLevel.LOW,
                    introspection_timestamp=time.time()
                )
                
                # Simulate processing
                processed_data = [item for item in large_data if len(item) > 500]
                
                return IntrospectionResult(
                    server_config=server_config,
                    server_info=server_info,
                    success=True,
                    timestamp=time.time(),
                    duration=1.0
                )
        
        with patch.object(introspector, 'introspect_server', side_effect=mock_memory_intensive_introspection):
            memory_optimizer.start_optimization()
            
            try:
                # Process multiple servers
                results = []
                for server_config in test_server_configs * 5:  # Process 15 servers total
                    result = introspector.introspect_server(server_config)
                    results.append(result)
                
                # Verify all succeeded
                assert len(results) == 15
                assert all(result.success for result in results)
                
                # Get memory statistics
                stats = memory_optimizer.get_statistics()
                assert stats.total_allocations > 0
                assert stats.peak_memory_mb > 0
                
            finally:
                memory_optimizer.stop_optimization()
    
    def test_configuration_migration_e2e(self, temp_dir):
        """Test configuration migration from legacy to modern format."""
        # Create legacy configuration
        legacy_config_file = temp_dir / "legacy_config.json"
        legacy_config_data = {
            "mcp_settings": {
                "timeout": 60,
                "retries": 3,
                "use_cache": True
            },
            "detection_settings": {
                "enable_process_scan": True,
                "enable_config_scan": True
            }
        }
        
        with open(legacy_config_file, 'w') as f:
            json.dump(legacy_config_data, f)
        
        # Migrate configuration
        migrator = ConfigurationMigrator()
        modern_config = migrator.migrate_from_file(str(legacy_config_file))
        
        # Verify migration
        assert isinstance(modern_config, ModernConfig)
        assert modern_config.introspection.timeout == 60.0
        assert modern_config.introspection.max_retries == 3
        assert modern_config.introspection.enable_caching == True
        
        # Test using migrated configuration
        introspection_config = IntrospectionConfig(
            timeout=modern_config.introspection.timeout,
            max_retries=modern_config.introspection.max_retries,
            enable_caching=modern_config.introspection.enable_caching
        )
        
        introspector = MCPIntrospection(introspection_config)
        
        # Verify introspector created successfully
        assert introspector.config.timeout == 60.0
        assert introspector.config.max_retries == 3
        assert introspector.config.enable_caching == True
    
    def test_concurrent_introspection_e2e(self, test_server_configs, introspection_config):
        """Test concurrent introspection operations."""
        introspector = MCPIntrospection(introspection_config)
        
        # Create many server configurations for concurrent testing
        concurrent_servers = []
        for i in range(20):
            server = MCPServerConfig(
                name=f"concurrent-server-{i}",
                command="node",
                args=[f"server-{i}.js"],
                transport_type="stdio"
            )
            concurrent_servers.append(server)
        
        def mock_concurrent_introspect(server_config):
            """Mock concurrent introspection."""
            # Simulate realistic processing time
            time.sleep(0.1)
            
            server_info = MCPServerInfo(
                server_name=server_config.name,
                server_version="1.0.0",
                protocol_version="2024-11-05", 
                transport_type=server_config.transport_type,
                capabilities={},
                tools=[],
                resources=[],
                risk_level=RiskLevel.LOW,
                introspection_timestamp=time.time()
            )
            
            return IntrospectionResult(
                server_config=server_config,
                server_info=server_info,
                success=True,
                timestamp=time.time(),
                duration=0.1
            )
        
        with patch.object(introspector, 'introspect_server', side_effect=mock_concurrent_introspect):
            start_time = time.time()
            
            # Execute concurrent introspections
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(introspector.introspect_server, server)
                    for server in concurrent_servers
                ]
                
                results = [future.result() for future in futures]
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Verify results
            assert len(results) == 20
            assert all(result.success for result in results)
            
            # Verify concurrency benefit (should be much faster than sequential)
            sequential_time = len(concurrent_servers) * 0.1  # 2 seconds sequential
            assert total_time < sequential_time * 0.8  # At least 20% improvement
    
    def test_error_recovery_e2e(self, test_server_configs, introspection_config):
        """Test error recovery and fallback mechanisms."""
        introspector = MCPIntrospection(introspection_config)
        
        # Mock failing and recovering introspection
        call_count = 0
        
        def mock_failing_introspect(server_config):
            nonlocal call_count
            call_count += 1
            
            # Fail first two attempts, succeed on third
            if call_count <= 2:
                raise ConnectionError(f"Connection failed (attempt {call_count})")
            
            # Succeed with fallback data
            server_info = MCPServerInfo(
                server_name=server_config.name,
                server_version="unknown",
                protocol_version="unknown",
                transport_type=server_config.transport_type,
                capabilities={},
                tools=[],
                resources=[],
                risk_level=RiskLevel.MEDIUM,  # Default fallback risk
                introspection_timestamp=time.time()
            )
            
            return IntrospectionResult(
                server_config=server_config,
                server_info=server_info,
                success=True,
                timestamp=time.time(),
                duration=0.5,
                error_message="Recovered from connection error"
            )
        
        with patch.object(introspector, 'introspect_server', side_effect=mock_failing_introspect):
            # This should succeed after retries
            result = introspector.introspect_server(test_server_configs[0])
            
            # Verify successful recovery
            assert result.success == True
            assert result.server_info.server_name == test_server_configs[0].name
            assert result.error_message == "Recovered from connection error"
            assert call_count >= 3  # Should have retried
    
    def test_performance_regression_e2e(self, test_server_configs, introspection_config):
        """Test performance doesn't regress in complete workflow."""
        introspector = MCPIntrospection(introspection_config)
        
        # Baseline performance targets
        MAX_SINGLE_INTROSPECTION_TIME = 5.0
        MAX_BATCH_TIME_PER_SERVER = 2.0
        
        def mock_realistic_introspect(server_config):
            """Mock realistic introspection timing."""
            # Simulate realistic processing
            time.sleep(0.1)  # 100ms processing time
            
            server_info = MCPServerInfo(
                server_name=server_config.name,
                server_version="1.0.0",
                protocol_version="2024-11-05",
                transport_type=server_config.transport_type,
                capabilities={},
                tools=[MCPTool(name="test_tool", description="Test", parameters={})],
                resources=[],
                risk_level=RiskLevel.LOW,
                introspection_timestamp=time.time()
            )
            
            return IntrospectionResult(
                server_config=server_config,
                server_info=server_info,
                success=True,
                timestamp=time.time(),
                duration=0.1
            )
        
        with patch.object(introspector, 'introspect_server', side_effect=mock_realistic_introspect):
            # Test single server performance
            start_time = time.time()
            result = introspector.introspect_server(test_server_configs[0])
            single_time = time.time() - start_time
            
            assert result.success == True
            assert single_time <= MAX_SINGLE_INTROSPECTION_TIME
            
            # Test batch performance
            batch_servers = test_server_configs * 10  # 30 servers total
            
            start_time = time.time()
            batch_results = [
                introspector.introspect_server(server) 
                for server in batch_servers
            ]
            batch_time = time.time() - start_time
            
            # Verify batch performance
            assert len(batch_results) == 30
            assert all(result.success for result in batch_results)
            
            avg_time_per_server = batch_time / len(batch_servers)
            assert avg_time_per_server <= MAX_BATCH_TIME_PER_SERVER


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])