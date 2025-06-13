"""
Unit tests for detection pipeline integration.

Tests the integration of the enhanced MCP introspection system with
the detection pipeline and CLI commands.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.hawkeye.detection.pipeline import (
    DetectionPipeline, PipelineConfig, PipelineResult, create_detection_pipeline
)
from src.hawkeye.detection.base import DetectionResult, DetectionMethod, MCPServerInfo, ProcessInfo
from src.hawkeye.detection.mcp_introspection import MCPCapabilities, MCPTool, MCPResource


class TestDetectionPipelineIntegration:
    """Test detection pipeline integration with MCP introspection."""
    
    @pytest.fixture
    def pipeline_config(self):
        """Create a test pipeline configuration."""
        return PipelineConfig(
            enable_mcp_introspection=True,
            introspection_timeout=30.0,
            enable_risk_assessment=True,
            min_confidence_threshold=0.3
        )
    
    @pytest.fixture
    def mock_detection_result(self):
        """Create a mock detection result with MCP server info."""
        process_info = ProcessInfo(
            pid=12345,
            name="node",
            cmdline=["node", "mcp-server.js"],
            cwd="/test",
            env_vars={}
        )
        
        server_info = MCPServerInfo(
            host="localhost",
            process_info=process_info
        )
        
        return DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROCESS_ENUMERATION,
            success=True,
            confidence=0.85,
            mcp_server=server_info
        )
    
    @pytest.fixture
    def mock_capabilities(self):
        """Create mock MCP capabilities."""
        tools = [
            MCPTool(
                name="file_read",
                description="Read files",
                input_schema={"path": {"type": "string"}}
            ),
            MCPTool(
                name="web_search",
                description="Search web",
                input_schema={"query": {"type": "string"}}
            )
        ]
        resources = [
            MCPResource(
                uri="file:///test.txt",
                name="test",
                description="Test file"
            )
        ]
        
        return MCPCapabilities(
            supports_tools=True,
            supports_resources=True,
            protocol_version="2024-11-05"
        )
    
    def test_pipeline_initialization(self, pipeline_config):
        """Test pipeline initialization with configuration."""
        pipeline = DetectionPipeline(pipeline_config)
        
        assert pipeline.config == pipeline_config
        assert pipeline.introspector is not None
        assert len(pipeline.detectors) > 0
        assert pipeline.stats["total_pipelines_executed"] == 0
    
    def test_pipeline_factory_function(self, pipeline_config):
        """Test pipeline factory function."""
        pipeline = create_detection_pipeline(pipeline_config)
        
        assert isinstance(pipeline, DetectionPipeline)
        assert pipeline.config == pipeline_config
    
    def test_execute_pipeline_success(self, pipeline_config, mock_detection_result, mock_capabilities):
        """Test successful pipeline execution."""
        # Create pipeline
        pipeline = DetectionPipeline(pipeline_config)
        
        # Mock all detectors to return our mock result
        for detector in pipeline.detectors.values():
            detector.detect = Mock(return_value=mock_detection_result)
        
        # Mock introspection
        mock_introspection = Mock()
        mock_introspection.introspect_server.return_value = mock_capabilities
        pipeline.introspector = mock_introspection
        
        result = pipeline.execute_pipeline("localhost")
        
        # Verify result
        assert isinstance(result, PipelineResult)
        assert result.success
        assert result.target_host == "localhost"
        assert result.mcp_servers_found > 0
        assert len(result.introspection_results) > 0
        assert result.duration > 0
    
    def test_execute_pipeline_no_mcp_servers(self, pipeline_config):
        """Test pipeline execution when no MCP servers are found."""
        # Create pipeline
        pipeline = DetectionPipeline(pipeline_config)
        
        # Mock all detectors to return unsuccessful results
        failed_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROCESS_ENUMERATION,
            success=False,
            confidence=0.0
        )
        
        for detector in pipeline.detectors.values():
            detector.detect = Mock(return_value=failed_result)
        
        result = pipeline.execute_pipeline("localhost")
        
        # Verify result
        assert isinstance(result, PipelineResult)
        assert result.target_host == "localhost"
        assert result.mcp_servers_found == 0
        assert len(result.introspection_results) == 0
    
    def test_execute_pipeline_introspection_disabled(self, mock_detection_result):
        """Test pipeline execution with introspection disabled."""
        # Configure pipeline without introspection
        config = PipelineConfig(enable_mcp_introspection=False)
        
        # Create pipeline
        pipeline = DetectionPipeline(config)
        
        # Mock all detectors to return our mock result
        for detector in pipeline.detectors.values():
            detector.detect = Mock(return_value=mock_detection_result)
        
        result = pipeline.execute_pipeline("localhost")
        
        # Verify result
        assert isinstance(result, PipelineResult)
        assert result.success
        assert result.mcp_servers_found > 0  # From detection, not introspection
        assert len(result.introspection_results) == 0  # No introspection
        assert pipeline.introspector is None
    
    def test_execute_pipeline_with_risk_assessment(self, pipeline_config, mock_detection_result, mock_capabilities):
        """Test pipeline execution with risk assessment."""
        # Create pipeline
        pipeline = DetectionPipeline(pipeline_config)
        
        # Mock all detectors to return our mock result
        for detector in pipeline.detectors.values():
            detector.detect = Mock(return_value=mock_detection_result)
        
        # Mock introspection with high-risk capabilities
        high_risk_capabilities = mock_capabilities
        high_risk_capabilities.supports_tools = True  # This indicates potential risk
        
        mock_introspection = Mock()
        mock_introspection.introspect_server.return_value = high_risk_capabilities
        pipeline.introspector = mock_introspection
        
        result = pipeline.execute_pipeline("localhost")
        
        # Verify risk assessment
        assert result.risk_assessment is not None
        assert "risk_factors" in result.risk_assessment
        assert "security_concerns" in result.risk_assessment
        assert "recommendations" in result.risk_assessment
        assert len(result.risk_assessment["risk_factors"]) > 0
    
    def test_extract_mcp_servers(self, pipeline_config, mock_detection_result):
        """Test MCP server extraction from detection results."""
        pipeline = DetectionPipeline(pipeline_config)
        
        detection_results = {
            DetectionMethod.PROCESS_ENUMERATION: [mock_detection_result]
        }
        
        mcp_servers = pipeline._extract_mcp_servers(detection_results)
        
        assert len(mcp_servers) == 1
        server_info, process_info = mcp_servers[0]
        assert server_info.host == "localhost"
        assert process_info.pid == 12345
    
    def test_analyze_results(self, pipeline_config, mock_detection_result):
        """Test result analysis and aggregation."""
        pipeline = DetectionPipeline(pipeline_config)
        
        # Create test result
        result = PipelineResult(
            target_host="localhost",
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration=1.0,
            success=False,  # Will be updated by analysis
            detection_results={DetectionMethod.PROCESS_ENUMERATION: [mock_detection_result]},
            introspection_results={},
            total_detections=0,
            successful_detections=0,
            failed_detections=0,
            mcp_servers_found=0,
            best_mcp_server=None,
            highest_confidence_result=None,
            risk_assessment=None,
            errors=[],
            warnings=[],
            raw_data={}
        )
        
        # Analyze results
        pipeline._analyze_results(result)
        
        # Verify analysis
        assert result.total_detections == 1
        assert result.successful_detections == 1
        assert result.failed_detections == 0
        assert result.mcp_servers_found == 1
        assert result.highest_confidence_result == mock_detection_result
        assert result.best_mcp_server == mock_detection_result.mcp_server
    
    def test_batch_pipeline_execution(self, pipeline_config):
        """Test batch pipeline execution."""
        with patch.object(DetectionPipeline, 'execute_pipeline') as mock_execute:
            # Mock individual pipeline executions
            mock_result = Mock(spec=PipelineResult)
            mock_result.success = True
            mock_execute.return_value = mock_result
            
            pipeline = DetectionPipeline(pipeline_config)
            targets = ["localhost", "127.0.0.1", "example.com"]
            
            results = pipeline.execute_batch_pipeline(targets)
            
            # Verify batch execution
            assert len(results) == 3
            assert mock_execute.call_count == 3
            assert all(r.success for r in results)
    
    def test_pipeline_statistics(self, pipeline_config):
        """Test pipeline statistics tracking."""
        pipeline = DetectionPipeline(pipeline_config)
        
        # Initial statistics
        stats = pipeline.get_pipeline_statistics()
        assert stats["total_pipelines_executed"] == 0
        assert stats["successful_pipelines"] == 0
        assert stats["failed_pipelines"] == 0
        assert stats["introspection_enabled"] == True
        
        # Simulate pipeline execution
        pipeline.stats["total_pipelines_executed"] = 5
        pipeline.stats["successful_pipelines"] = 4
        pipeline.stats["failed_pipelines"] = 1
        pipeline.stats["average_pipeline_duration"] = 2.5
        
        updated_stats = pipeline.get_pipeline_statistics()
        assert updated_stats["total_pipelines_executed"] == 5
        assert updated_stats["success_rate"] == 80.0
        assert updated_stats["average_pipeline_duration"] == 2.5
    
    def test_pipeline_error_handling(self, pipeline_config):
        """Test pipeline error handling."""
        with patch.object(DetectionPipeline, '_execute_traditional_detection') as mock_detect:
            # Mock detection failure
            mock_detect.side_effect = Exception("Detection failed")
            
            pipeline = DetectionPipeline(pipeline_config)
            result = pipeline.execute_pipeline("localhost")
            
            # Verify error handling
            assert isinstance(result, PipelineResult)
            assert not result.success
            assert len(result.errors) > 0
            assert "Detection failed" in str(result.errors[0])
    
    def test_confidence_threshold_filtering(self, pipeline_config):
        """Test confidence threshold filtering."""
        # Set high confidence threshold
        pipeline_config.min_confidence_threshold = 0.9
        pipeline = DetectionPipeline(pipeline_config)
        
        # Create low confidence detection result
        server_info = MCPServerInfo(host="localhost")
        low_confidence_result = DetectionResult(
            target_host="localhost",
            detection_method=DetectionMethod.PROCESS_ENUMERATION,
            success=True,
            confidence=0.5,  # Below threshold
            mcp_server=server_info
        )
        
        # Create test pipeline result
        result = PipelineResult(
            target_host="localhost",
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration=1.0,
            success=False,
            detection_results={DetectionMethod.PROCESS_ENUMERATION: [low_confidence_result]},
            introspection_results={},
            total_detections=0,
            successful_detections=0,
            failed_detections=0,
            mcp_servers_found=0,
            best_mcp_server=None,
            highest_confidence_result=None,
            risk_assessment=None,
            errors=[],
            warnings=[],
            raw_data={}
        )
        
        # Analyze results with confidence filtering
        pipeline._analyze_results(result)
        
        # Verify filtering (low confidence result should not be selected as best)
        assert result.highest_confidence_result is None
        assert result.best_mcp_server is None


class TestPipelineConfigurationOptions:
    """Test different pipeline configuration options."""
    
    def test_minimal_configuration(self):
        """Test pipeline with minimal configuration."""
        config = PipelineConfig(
            enable_process_enumeration=True,
            enable_config_discovery=False,
            enable_protocol_verification=False,
            enable_transport_detection=False,
            enable_npx_detection=False,
            enable_docker_inspection=False,
            enable_environment_analysis=False,
            enable_mcp_introspection=False
        )
        
        pipeline = DetectionPipeline(config)
        
        assert len(pipeline.detectors) == 1  # Only process enumeration
        assert pipeline.introspector is None
    
    def test_full_configuration(self):
        """Test pipeline with all features enabled."""
        config = PipelineConfig(
            enable_process_enumeration=True,
            enable_config_discovery=True,
            enable_protocol_verification=True,
            enable_transport_detection=True,
            enable_npx_detection=True,
            enable_docker_inspection=True,
            enable_environment_analysis=True,
            enable_mcp_introspection=True,
            enable_risk_assessment=True
        )
        
        pipeline = DetectionPipeline(config)
        
        assert len(pipeline.detectors) == 7  # All detection methods
        assert pipeline.introspector is not None
    
    def test_custom_thresholds(self):
        """Test pipeline with custom thresholds."""
        config = PipelineConfig(
            introspection_timeout=60.0,
            min_confidence_threshold=0.7
        )
        
        pipeline = DetectionPipeline(config)
        
        assert pipeline.config.introspection_timeout == 60.0
        assert pipeline.config.min_confidence_threshold == 0.7 