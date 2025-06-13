"""
Unit tests for MCP Introspection Graceful Degradation

Tests for fallback mechanisms when MCP server introspection fails,
ensuring the system continues to operate with reduced functionality.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional

from src.hawkeye.detection.mcp_introspection.fallback import (
    FallbackStrategy,
    FailureReason,
    FallbackConfig,
    FallbackResult,
    FallbackStatistics,
    HeuristicAnalyzer,
    FallbackManager
)

from src.hawkeye.detection.mcp_introspection.models import (
    MCPServerConfig,
    MCPServerInfo,
    RiskLevel
)


class TestFallbackConfig:
    """Test cases for FallbackConfig."""
    
    def test_default_configuration(self):
        """Test default fallback configuration."""
        config = FallbackConfig()
        
        assert config.primary_strategy == FallbackStrategy.HEURISTIC_ANALYSIS
        assert config.secondary_strategy == FallbackStrategy.BASIC_INFO
        assert config.final_strategy == FallbackStrategy.MINIMAL_SAFE
        assert config.enable_retry == True
        assert config.max_retries == 2
        assert config.default_risk_level == RiskLevel.MEDIUM
    
    def test_custom_configuration(self):
        """Test custom fallback configuration."""
        config = FallbackConfig(
            primary_strategy=FallbackStrategy.CACHED_RESULT,
            max_retries=5,
            fallback_timeout=60.0,
            default_risk_level=RiskLevel.HIGH
        )
        
        assert config.primary_strategy == FallbackStrategy.CACHED_RESULT
        assert config.max_retries == 5
        assert config.fallback_timeout == 60.0
        assert config.default_risk_level == RiskLevel.HIGH


class TestFallbackResult:
    """Test cases for FallbackResult."""
    
    def test_fallback_result_creation(self):
        """Test fallback result creation."""
        server_info = MCPServerInfo(
            server_name="test-server",
            server_version="1.0.0",
            protocol_version="1.0",
            transport_type="stdio",
            capabilities={},
            tools=[],
            resources=[],
            risk_level=RiskLevel.LOW,
            introspection_timestamp=time.time()
        )
        
        result = FallbackResult(
            success=True,
            strategy_used=FallbackStrategy.HEURISTIC_ANALYSIS,
            server_info=server_info,
            confidence_score=0.8,
            fallback_reason="Connection timeout",
            original_error="TimeoutError: Connection timed out",
            processing_time=2.5
        )
        
        assert result.success == True
        assert result.strategy_used == FallbackStrategy.HEURISTIC_ANALYSIS
        assert result.server_info == server_info
        assert result.confidence_score == 0.8
        assert result.is_degraded == True  # confidence < 1.0
    
    def test_degraded_result_detection(self):
        """Test degraded result detection."""
        # Non-degraded result (perfect confidence)
        result1 = FallbackResult(
            success=True,
            strategy_used=FallbackStrategy.HEURISTIC_ANALYSIS,
            server_info=None,
            confidence_score=1.0,
            fallback_reason="test",
            original_error=None,
            processing_time=1.0
        )
        assert result1.is_degraded == False
        
        # Degraded result (low confidence)
        result2 = FallbackResult(
            success=True,
            strategy_used=FallbackStrategy.BASIC_INFO,
            server_info=None,
            confidence_score=0.5,
            fallback_reason="test",
            original_error=None,
            processing_time=1.0
        )
        assert result2.is_degraded == True


class TestFallbackStatistics:
    """Test cases for FallbackStatistics."""
    
    def test_statistics_initialization(self):
        """Test statistics initialization."""
        stats = FallbackStatistics()
        
        assert stats.total_fallbacks == 0
        assert stats.successful_fallbacks == 0
        assert stats.failed_fallbacks == 0
        assert stats.success_rate == 0.0
        assert len(stats.strategy_usage) == 0
        assert len(stats.failure_reasons) == 0
    
    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        stats = FallbackStatistics()
        
        # Test with no fallbacks
        assert stats.success_rate == 0.0
        
        # Test with some successful fallbacks
        stats.total_fallbacks = 10
        stats.successful_fallbacks = 7
        assert stats.success_rate == 70.0
        
        # Test with all successful fallbacks
        stats.successful_fallbacks = 10
        assert stats.success_rate == 100.0


class TestHeuristicAnalyzer:
    """Test cases for HeuristicAnalyzer."""
    
    @pytest.fixture
    def analyzer_config(self):
        """Create test analyzer configuration."""
        return FallbackConfig(
            enable_heuristic_analysis=True,
            heuristic_confidence_threshold=0.6,
            enable_pattern_matching=True
        )
    
    @pytest.fixture
    def heuristic_analyzer(self, analyzer_config):
        """Create test heuristic analyzer."""
        return HeuristicAnalyzer(analyzer_config)
    
    def test_analyzer_initialization(self, analyzer_config):
        """Test heuristic analyzer initialization."""
        analyzer = HeuristicAnalyzer(analyzer_config)
        
        assert analyzer.config == analyzer_config
        assert isinstance(analyzer._tool_patterns, dict)
        assert isinstance(analyzer._risk_patterns, dict)
        assert isinstance(analyzer._capability_patterns, dict)
    
    def test_command_analysis(self, heuristic_analyzer):
        """Test command analysis functionality."""
        # Test Node.js command
        result = heuristic_analyzer._analyze_command("node", ["server.js", "--port", "3000"])
        
        assert isinstance(result, dict)
        assert 'tools' in result
        assert 'capabilities' in result
        assert 'confidence' in result
        assert 'risk_level' in result
        assert result['confidence'] > 0
    
    def test_transport_analysis(self, heuristic_analyzer):
        """Test transport type analysis."""
        # Test stdio transport
        result = heuristic_analyzer._analyze_transport("stdio")
        
        assert isinstance(result, dict)
        assert 'capabilities' in result
        assert 'confidence' in result
        assert result['confidence'] > 0
    
    def test_server_analysis(self, heuristic_analyzer):
        """Test complete server analysis."""
        server_config = MCPServerConfig(
            name="test-filesystem-server",
            command="node",
            args=["fs-server.js"],
            transport_type="stdio"
        )
        
        error_context = {
            'error_type': 'timeout',
            'attempt_count': 1
        }
        
        server_info, confidence = heuristic_analyzer.analyze_server(server_config, error_context)
        
        assert isinstance(server_info, MCPServerInfo)
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
        assert server_info.server_name == "test-filesystem-server"
        assert server_info.transport_type == "stdio"
    
    def test_minimal_server_info_creation(self, heuristic_analyzer):
        """Test minimal server info creation."""
        server_config = MCPServerConfig(
            name="minimal-server",
            command="unknown-command",
            args=[]
        )
        
        server_info = heuristic_analyzer._create_minimal_server_info(server_config)
        
        assert isinstance(server_info, MCPServerInfo)
        assert server_info.server_name == "minimal-server"
        assert server_info.risk_level == RiskLevel.MEDIUM  # Default
        assert len(server_info.tools) == 0
        assert len(server_info.resources) == 0


class TestFallbackManager:
    """Test cases for FallbackManager."""
    
    @pytest.fixture
    def fallback_config(self):
        """Create test fallback configuration."""
        return FallbackConfig(
            primary_strategy=FallbackStrategy.HEURISTIC_ANALYSIS,
            secondary_strategy=FallbackStrategy.BASIC_INFO,
            final_strategy=FallbackStrategy.MINIMAL_SAFE,
            enable_retry=True,
            max_retries=2,
            use_cached_results=True,
            fallback_timeout=30.0
        )
    
    @pytest.fixture
    def fallback_manager(self, fallback_config):
        """Create test fallback manager."""
        return FallbackManager(fallback_config)
    
    def test_manager_initialization(self, fallback_config):
        """Test fallback manager initialization."""
        manager = FallbackManager(fallback_config)
        
        assert manager.config == fallback_config
        assert isinstance(manager.heuristic_analyzer, HeuristicAnalyzer)
        assert isinstance(manager.statistics, FallbackStatistics)
        assert manager._result_cache == {}
    
    def test_failure_categorization(self, fallback_manager):
        """Test failure reason categorization."""
        # Test timeout error
        timeout_error = TimeoutError("Connection timed out")
        reason = fallback_manager._categorize_failure(timeout_error, {})
        assert reason == FailureReason.TIMEOUT
        
        # Test connection error
        conn_error = ConnectionError("Connection refused")
        reason = fallback_manager._categorize_failure(conn_error, {})
        assert reason == FailureReason.CONNECTION_ERROR
        
        # Test permission error
        perm_error = PermissionError("Access denied")
        reason = fallback_manager._categorize_failure(perm_error, {})
        assert reason == FailureReason.PERMISSION_ERROR
        
        # Test unknown error
        unknown_error = ValueError("Unknown error")
        reason = fallback_manager._categorize_failure(unknown_error, {})
        assert reason == FailureReason.UNKNOWN_ERROR
    
    def test_skip_strategy(self, fallback_manager):
        """Test skip fallback strategy."""
        server_config = MCPServerConfig(
            name="test-server",
            command="node",
            args=["server.js"]
        )
        
        error = Exception("Test error")
        result = fallback_manager._skip_strategy(server_config, error)
        
        assert isinstance(result, FallbackResult)
        assert result.success == False
        assert result.strategy_used == FallbackStrategy.SKIP
        assert result.server_info is None
        assert result.confidence_score == 0.0
    
    def test_basic_info_strategy(self, fallback_manager):
        """Test basic info fallback strategy."""
        server_config = MCPServerConfig(
            name="test-server",
            command="node",
            args=["server.js"],
            transport_type="stdio"
        )
        
        error = Exception("Test error")
        result = fallback_manager._basic_info_strategy(server_config, error)
        
        assert isinstance(result, FallbackResult)
        assert result.success == True
        assert result.strategy_used == FallbackStrategy.BASIC_INFO
        assert result.server_info is not None
        assert result.server_info.server_name == "test-server"
        assert result.confidence_score > 0.0
    
    def test_cached_result_strategy(self, fallback_manager):
        """Test cached result fallback strategy."""
        server_config = MCPServerConfig(
            name="test-server",
            command="node",
            args=["server.js"]
        )
        
        # First test with no cache
        error = Exception("Test error")
        result = fallback_manager._cached_result_strategy(server_config, error)
        assert result.success == False
        
        # Add to cache
        cached_info = MCPServerInfo(
            server_name="test-server",
            server_version="1.0.0",
            protocol_version="1.0",
            transport_type="stdio",
            capabilities={},
            tools=[],
            resources=[],
            risk_level=RiskLevel.LOW,
            introspection_timestamp=time.time()
        )
        
        cache_key = f"{server_config.name}_{server_config.command}"
        fallback_manager._result_cache[cache_key] = {
            'result': cached_info,
            'timestamp': time.time(),
            'confidence': 0.9
        }
        
        # Test with cache hit
        result = fallback_manager._cached_result_strategy(server_config, error)
        assert result.success == True
        assert result.strategy_used == FallbackStrategy.CACHED_RESULT
        assert result.server_info == cached_info
        assert result.confidence_score == 0.9
    
    def test_heuristic_analysis_strategy(self, fallback_manager):
        """Test heuristic analysis fallback strategy."""
        server_config = MCPServerConfig(
            name="filesystem-server",
            command="node",
            args=["fs-server.js"],
            transport_type="stdio"
        )
        
        error = Exception("Test error")
        error_context = {'error_type': 'timeout'}
        
        result = fallback_manager._heuristic_analysis_strategy(
            server_config, error, error_context
        )
        
        assert isinstance(result, FallbackResult)
        assert result.success == True
        assert result.strategy_used == FallbackStrategy.HEURISTIC_ANALYSIS
        assert result.server_info is not None
        assert result.confidence_score > 0.0
    
    def test_minimal_safe_strategy(self, fallback_manager):
        """Test minimal safe fallback strategy."""
        server_config = MCPServerConfig(
            name="test-server",
            command="unknown",
            args=[]
        )
        
        error = Exception("Test error")
        result = fallback_manager._minimal_safe_strategy(server_config, error)
        
        assert isinstance(result, FallbackResult)
        assert result.success == True
        assert result.strategy_used == FallbackStrategy.MINIMAL_SAFE
        assert result.server_info is not None
        assert result.server_info.risk_level == RiskLevel.MEDIUM  # Conservative default
        assert result.confidence_score == 0.3  # Low confidence for minimal info
    
    def test_fallback_cascade(self, fallback_manager):
        """Test fallback strategy cascade."""
        server_config = MCPServerConfig(
            name="test-server",
            command="node",
            args=["server.js"],
            transport_type="stdio"
        )
        
        error = TimeoutError("Connection timed out")
        error_context = {'attempt_count': 1}
        
        result = fallback_manager.handle_failed_introspection(
            server_config, error, error_context
        )
        
        assert isinstance(result, FallbackResult)
        assert result.success == True  # Should succeed with some strategy
        assert result.strategy_used in [
            FallbackStrategy.HEURISTIC_ANALYSIS,
            FallbackStrategy.BASIC_INFO,
            FallbackStrategy.MINIMAL_SAFE
        ]
        assert result.original_error is not None
    
    def test_statistics_tracking(self, fallback_manager):
        """Test statistics tracking."""
        server_config = MCPServerConfig(
            name="test-server",
            command="node",
            args=["server.js"]
        )
        
        error = Exception("Test error")
        
        # Perform several fallback operations
        for i in range(5):
            result = fallback_manager.handle_failed_introspection(server_config, error)
            
        stats = fallback_manager.get_statistics()
        
        assert stats.total_fallbacks == 5
        assert stats.successful_fallbacks > 0
        assert stats.success_rate > 0
        assert len(stats.strategy_usage) > 0
        assert len(stats.failure_reasons) > 0
    
    def test_cache_management(self, fallback_manager):
        """Test result cache management."""
        # Test cache info
        cache_info = fallback_manager.get_cache_info()
        assert isinstance(cache_info, dict)
        assert 'total_entries' in cache_info
        assert 'cache_size_mb' in cache_info
        
        # Add some cache entries
        server_info = MCPServerInfo(
            server_name="test",
            server_version="1.0.0",
            protocol_version="1.0",
            transport_type="stdio",
            capabilities={},
            tools=[],
            resources=[],
            risk_level=RiskLevel.LOW,
            introspection_timestamp=time.time()
        )
        
        fallback_manager._result_cache['test_key'] = {
            'result': server_info,
            'timestamp': time.time(),
            'confidence': 0.8
        }
        
        # Test cache clearing
        fallback_manager.clear_cache()
        assert len(fallback_manager._result_cache) == 0


class TestErrorHandling:
    """Test cases for error handling in fallback scenarios."""
    
    def test_network_error_handling(self):
        """Test handling of network-related errors."""
        config = FallbackConfig()
        manager = FallbackManager(config)
        
        server_config = MCPServerConfig(
            name="network-server",
            command="node",
            args=["server.js"]
        )
        
        # Test various network errors
        network_errors = [
            ConnectionError("Connection refused"),
            TimeoutError("Request timed out"),
            OSError("Network unreachable")
        ]
        
        for error in network_errors:
            result = manager.handle_failed_introspection(server_config, error)
            assert isinstance(result, FallbackResult)
            assert result.original_error is not None
    
    def test_permission_error_handling(self):
        """Test handling of permission-related errors."""
        config = FallbackConfig()
        manager = FallbackManager(config)
        
        server_config = MCPServerConfig(
            name="restricted-server",
            command="restricted-cmd",
            args=[]
        )
        
        error = PermissionError("Access denied")
        result = manager.handle_failed_introspection(server_config, error)
        
        assert isinstance(result, FallbackResult)
        assert result.original_error is not None
        failure_reason = manager._categorize_failure(error, {})
        assert failure_reason == FailureReason.PERMISSION_ERROR


class TestIntegrationScenarios:
    """Integration test scenarios for fallback functionality."""
    
    def test_complete_fallback_workflow(self):
        """Test complete fallback workflow with multiple strategies."""
        config = FallbackConfig(
            primary_strategy=FallbackStrategy.CACHED_RESULT,
            secondary_strategy=FallbackStrategy.HEURISTIC_ANALYSIS,
            final_strategy=FallbackStrategy.MINIMAL_SAFE,
            enable_retry=True,
            max_retries=1
        )
        
        manager = FallbackManager(config)
        
        server_config = MCPServerConfig(
            name="complex-server",
            command="node",
            args=["complex-server.js", "--features", "filesystem,network"],
            transport_type="stdio"
        )
        
        error = TimeoutError("Connection timed out")
        error_context = {
            'attempt_count': 3,
            'original_timeout': 30.0,
            'error_details': 'Server unresponsive'
        }
        
        result = manager.handle_failed_introspection(server_config, error, error_context)
        
        # Should succeed with some fallback strategy
        assert result.success == True
        assert result.server_info is not None
        assert result.confidence_score > 0.0
        assert result.original_error is not None
        assert result.processing_time > 0.0
        
        # Check statistics
        stats = manager.get_statistics()
        assert stats.total_fallbacks == 1
        assert stats.successful_fallbacks == 1


if __name__ == "__main__":
    pytest.main([__file__])
