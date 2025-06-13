"""
Graceful Degradation for Failed Introspections

Provides fallback mechanisms and graceful degradation strategies when MCP server
introspection fails, ensuring the system continues to operate with reduced functionality
rather than complete failure.
"""

import time
import logging
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import json

from .models import (
    MCPServerConfig, 
    MCPServerInfo, 
    MCPTool, 
    MCPResource, 
    MCPCapabilities,
    IntrospectionResult,
    RiskLevel
)
from .introspection import IntrospectionConfig


class FallbackStrategy(Enum):
    """Available fallback strategies for failed introspections."""
    SKIP = "skip"  # Skip the failed server entirely
    BASIC_INFO = "basic_info"  # Return basic server info only
    CACHED_RESULT = "cached_result"  # Use cached result if available
    HEURISTIC_ANALYSIS = "heuristic_analysis"  # Use heuristic-based analysis
    MINIMAL_SAFE = "minimal_safe"  # Return minimal safe configuration
    RETRY_WITH_TIMEOUT = "retry_with_timeout"  # Retry with reduced timeout
    DEGRADED_SCAN = "degraded_scan"  # Perform limited scan with reduced features


class FailureReason(Enum):
    """Categorization of introspection failure reasons."""
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    PROTOCOL_ERROR = "protocol_error"
    PERMISSION_ERROR = "permission_error"
    RESOURCE_ERROR = "resource_error"
    CONFIGURATION_ERROR = "configuration_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class FallbackConfig:
    """Configuration for fallback behavior."""
    # Strategy selection
    primary_strategy: FallbackStrategy = FallbackStrategy.HEURISTIC_ANALYSIS
    secondary_strategy: FallbackStrategy = FallbackStrategy.BASIC_INFO
    final_strategy: FallbackStrategy = FallbackStrategy.MINIMAL_SAFE
    
    # Retry configuration
    enable_retry: bool = True
    max_retries: int = 2
    retry_delay: float = 5.0
    retry_timeout_reduction: float = 0.5  # Reduce timeout by 50% on retry
    
    # Cache configuration
    use_cached_results: bool = True
    cache_expiry_hours: int = 24
    allow_stale_cache: bool = True
    stale_cache_max_age_hours: int = 168  # 1 week
    
    # Heuristic analysis
    enable_heuristic_analysis: bool = True
    heuristic_confidence_threshold: float = 0.6
    enable_pattern_matching: bool = True
    
    # Safety settings
    default_risk_level: RiskLevel = RiskLevel.MEDIUM
    enable_conservative_defaults: bool = True
    log_fallback_usage: bool = True
    
    # Performance settings
    fallback_timeout: float = 30.0
    max_concurrent_fallbacks: int = 5


@dataclass
class FallbackResult:
    """Result of a fallback operation."""
    success: bool
    strategy_used: FallbackStrategy
    server_info: Optional[MCPServerInfo]
    confidence_score: float
    fallback_reason: str
    original_error: Optional[str]
    processing_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_degraded(self) -> bool:
        """Check if this is a degraded result."""
        return self.strategy_used != FallbackStrategy.SKIP and self.confidence_score < 1.0


@dataclass
class FallbackStatistics:
    """Statistics for fallback operations."""
    total_fallbacks: int = 0
    successful_fallbacks: int = 0
    failed_fallbacks: int = 0
    strategy_usage: Dict[FallbackStrategy, int] = field(default_factory=lambda: defaultdict(int))
    failure_reasons: Dict[FailureReason, int] = field(default_factory=lambda: defaultdict(int))
    average_confidence: float = 0.0
    average_processing_time: float = 0.0
    cache_hit_rate: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate fallback success rate."""
        return (self.successful_fallbacks / max(1, self.total_fallbacks)) * 100


class HeuristicAnalyzer:
    """Performs heuristic analysis of MCP servers when introspection fails."""
    
    def __init__(self, config: FallbackConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Pattern databases
        self._tool_patterns = self._load_tool_patterns()
        self._risk_patterns = self._load_risk_patterns()
        self._capability_patterns = self._load_capability_patterns()
    
    def analyze_server(self, server_config: MCPServerConfig, error_context: Dict[str, Any]) -> Tuple[MCPServerInfo, float]:
        """
        Perform heuristic analysis of a server configuration.
        
        Args:
            server_config: Server configuration to analyze
            error_context: Context about the introspection failure
            
        Returns:
            Tuple of (server_info, confidence_score)
        """
        self.logger.debug(f"Starting heuristic analysis for server {server_config.name}")
        
        # Initialize analysis
        confidence_factors = []
        tools = []
        resources = []
        capabilities = {}
        risk_level = self.config.default_risk_level
        
        try:
            # Analyze command and arguments
            if server_config.command:
                command_analysis = self._analyze_command(server_config.command, server_config.args)
                tools.extend(command_analysis['tools'])
                capabilities.update(command_analysis['capabilities'])
                confidence_factors.append(command_analysis['confidence'])
                
                # Determine risk level from command analysis
                command_risk = command_analysis.get('risk_level', RiskLevel.MEDIUM)
                if command_risk.value > risk_level.value:
                    risk_level = command_risk
            
            # Analyze transport type
            if server_config.transport_type:
                transport_analysis = self._analyze_transport(server_config.transport_type)
                capabilities.update(transport_analysis['capabilities'])
                confidence_factors.append(transport_analysis['confidence'])
            
            # Analyze server name and description
            if server_config.name:
                name_analysis = self._analyze_name(server_config.name)
                tools.extend(name_analysis['tools'])
                confidence_factors.append(name_analysis['confidence'])
            
            # Analyze environment and configuration
            env_analysis = self._analyze_environment(server_config, error_context)
            capabilities.update(env_analysis['capabilities'])
            confidence_factors.append(env_analysis['confidence'])
            
            # Calculate overall confidence
            overall_confidence = sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.3
            
            # Create server info
            server_info = MCPServerInfo(
                server_name=server_config.name or "Unknown Server",
                server_version="unknown",
                protocol_version="unknown",
                transport_type=server_config.transport_type or "unknown",
                capabilities=capabilities,
                tools=tools,
                resources=resources,
                risk_level=risk_level,
                introspection_timestamp=time.time(),
                metadata={
                    'heuristic_analysis': True,
                    'confidence_score': overall_confidence,
                    'analysis_method': 'pattern_matching',
                    'fallback_reason': 'introspection_failed'
                }
            )
            
            self.logger.info(
                f"Heuristic analysis completed for {server_config.name}: "
                f"confidence={overall_confidence:.2f}, tools={len(tools)}, risk={risk_level.name}"
            )
            
            return server_info, overall_confidence
            
        except Exception as e:
            self.logger.error(f"Error in heuristic analysis for {server_config.name}: {e}")
            
            # Return minimal safe configuration
            minimal_info = self._create_minimal_server_info(server_config)
            return minimal_info, 0.1
    
    def _analyze_command(self, command: str, args: List[str]) -> Dict[str, Any]:
        """Analyze server command and arguments for capabilities."""
        analysis = {
            'tools': [],
            'capabilities': {},
            'confidence': 0.5,
            'risk_level': RiskLevel.LOW
        }
        
        command_lower = command.lower()
        args_str = ' '.join(args).lower() if args else ''
        
        # Check for known MCP server patterns
        if 'mcp' in command_lower or 'model-context-protocol' in command_lower:
            analysis['confidence'] += 0.3
            analysis['capabilities']['mcp_server'] = True
        
        # Check for file system tools
        if any(keyword in command_lower for keyword in ['file', 'fs', 'directory', 'path']):
            analysis['tools'].append(MCPTool(
                name="file_operations",
                description="File system operations (heuristic)",
                input_schema={"type": "object"},
                risk_categories=["file_system"]
            ))
            analysis['risk_level'] = RiskLevel.HIGH
            analysis['confidence'] += 0.2
        
        # Check for network tools
        if any(keyword in command_lower for keyword in ['web', 'http', 'api', 'fetch', 'curl']):
            analysis['tools'].append(MCPTool(
                name="network_operations",
                description="Network operations (heuristic)",
                input_schema={"type": "object"},
                risk_categories=["network_access"]
            ))
            analysis['risk_level'] = RiskLevel.HIGH
            analysis['confidence'] += 0.2
        
        # Check for database tools
        if any(keyword in command_lower for keyword in ['db', 'database', 'sql', 'mongo', 'redis']):
            analysis['tools'].append(MCPTool(
                name="database_operations",
                description="Database operations (heuristic)",
                input_schema={"type": "object"},
                risk_categories=["external_integration"]
            ))
            analysis['risk_level'] = RiskLevel.MEDIUM
            analysis['confidence'] += 0.2
        
        # Check for code execution
        if any(keyword in command_lower for keyword in ['exec', 'run', 'shell', 'bash', 'python']):
            analysis['tools'].append(MCPTool(
                name="code_execution",
                description="Code execution (heuristic)",
                input_schema={"type": "object"},
                risk_categories=["code_execution"]
            ))
            analysis['risk_level'] = RiskLevel.CRITICAL
            analysis['confidence'] += 0.3
        
        return analysis
    
    def _analyze_transport(self, transport_type: str) -> Dict[str, Any]:
        """Analyze transport type for capabilities."""
        analysis = {
            'capabilities': {},
            'confidence': 0.8
        }
        
        if transport_type == "stdio":
            analysis['capabilities']['local_execution'] = True
            analysis['capabilities']['process_communication'] = True
        elif transport_type in ["http", "sse"]:
            analysis['capabilities']['network_communication'] = True
            analysis['capabilities']['remote_access'] = True
        
        return analysis
    
    def _analyze_name(self, name: str) -> Dict[str, Any]:
        """Analyze server name for tool hints."""
        analysis = {
            'tools': [],
            'confidence': 0.4
        }
        
        name_lower = name.lower()
        
        # Common tool patterns
        tool_patterns = {
            'filesystem': ['file', 'fs', 'directory', 'folder'],
            'web': ['web', 'http', 'browser', 'fetch'],
            'database': ['db', 'database', 'sql', 'mongo'],
            'search': ['search', 'find', 'query'],
            'ai': ['ai', 'llm', 'gpt', 'claude', 'openai'],
            'git': ['git', 'github', 'repo', 'version'],
            'docs': ['docs', 'documentation', 'wiki', 'knowledge']
        }
        
        for category, keywords in tool_patterns.items():
            if any(keyword in name_lower for keyword in keywords):
                analysis['tools'].append(MCPTool(
                    name=f"{category}_tool",
                    description=f"{category.title()} tool (heuristic from name)",
                    input_schema={"type": "object"},
                    risk_categories=[category]
                ))
                analysis['confidence'] += 0.1
        
        return analysis
    
    def _analyze_environment(self, server_config: MCPServerConfig, error_context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze environment and error context."""
        analysis = {
            'capabilities': {},
            'confidence': 0.3
        }
        
        # Analyze error context for hints
        if error_context:
            error_type = error_context.get('error_type', '')
            if 'permission' in error_type.lower():
                analysis['capabilities']['requires_permissions'] = True
                analysis['confidence'] += 0.2
            elif 'network' in error_type.lower():
                analysis['capabilities']['network_dependent'] = True
                analysis['confidence'] += 0.2
        
        return analysis
    
    def _create_minimal_server_info(self, server_config: MCPServerConfig) -> MCPServerInfo:
        """Create minimal safe server info."""
        return MCPServerInfo(
            server_name=server_config.name or "Unknown Server",
            server_version="unknown",
            protocol_version="unknown",
            transport_type=server_config.transport_type or "unknown",
            capabilities={'minimal_fallback': True},
            tools=[],
            resources=[],
            risk_level=self.config.default_risk_level,
            introspection_timestamp=time.time(),
            metadata={
                'fallback_mode': True,
                'minimal_safe': True,
                'confidence_score': 0.1
            }
        )
    
    def _load_tool_patterns(self) -> Dict[str, Any]:
        """Load tool pattern database."""
        # In a real implementation, this would load from a file or database
        return {
            'file_operations': ['read_file', 'write_file', 'list_directory'],
            'web_operations': ['fetch_url', 'web_search', 'http_request'],
            'database_operations': ['query_db', 'insert_data', 'update_record']
        }
    
    def _load_risk_patterns(self) -> Dict[str, RiskLevel]:
        """Load risk pattern database."""
        return {
            'file_system': RiskLevel.HIGH,
            'network_access': RiskLevel.HIGH,
            'code_execution': RiskLevel.CRITICAL,
            'database_access': RiskLevel.MEDIUM,
            'system_info': RiskLevel.LOW
        }
    
    def _load_capability_patterns(self) -> Dict[str, Any]:
        """Load capability pattern database."""
        return {
            'mcp_standard': ['tools/list', 'resources/list', 'initialize'],
            'extended': ['prompts/list', 'completion/complete']
        }


class FallbackManager:
    """
    Manages graceful degradation strategies for failed MCP introspections.
    
    Provides multiple fallback strategies to ensure the system continues operating
    even when direct introspection fails, with configurable degradation levels.
    """
    
    def __init__(self, config: Optional[FallbackConfig] = None):
        """Initialize the fallback manager."""
        self.config = config or FallbackConfig()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize components
        self.heuristic_analyzer = HeuristicAnalyzer(self.config)
        
        # Statistics tracking
        self.statistics = FallbackStatistics()
        
        # Cache for fallback results
        self._result_cache: Dict[str, Tuple[FallbackResult, float]] = {}
        
        self.logger.info(
            f"FallbackManager initialized with primary_strategy={self.config.primary_strategy.value}, "
            f"retry_enabled={self.config.enable_retry}, "
            f"heuristic_analysis={self.config.enable_heuristic_analysis}"
        )
    
    def handle_failed_introspection(
        self,
        server_config: MCPServerConfig,
        original_error: Exception,
        error_context: Optional[Dict[str, Any]] = None
    ) -> FallbackResult:
        """
        Handle a failed introspection with graceful degradation.
        
        Args:
            server_config: Configuration of the server that failed
            original_error: The original introspection error
            error_context: Additional context about the failure
            
        Returns:
            FallbackResult with degraded server information
        """
        start_time = time.time()
        self.statistics.total_fallbacks += 1
        
        # Categorize the failure
        failure_reason = self._categorize_failure(original_error, error_context)
        self.statistics.failure_reasons[failure_reason] += 1
        
        self.logger.info(
            f"Handling failed introspection for {server_config.name}: "
            f"reason={failure_reason.value}, error={str(original_error)[:100]}"
        )
        
        try:
            # Try primary strategy
            result = self._try_strategy(
                self.config.primary_strategy,
                server_config,
                original_error,
                error_context or {}
            )
            
            if result.success and result.confidence_score >= self.config.heuristic_confidence_threshold:
                return self._finalize_result(result, start_time)
            
            # Try secondary strategy
            self.logger.debug(f"Primary strategy failed, trying secondary for {server_config.name}")
            result = self._try_strategy(
                self.config.secondary_strategy,
                server_config,
                original_error,
                error_context or {}
            )
            
            if result.success:
                return self._finalize_result(result, start_time)
            
            # Try final strategy
            self.logger.debug(f"Secondary strategy failed, trying final for {server_config.name}")
            result = self._try_strategy(
                self.config.final_strategy,
                server_config,
                original_error,
                error_context or {}
            )
            
            return self._finalize_result(result, start_time)
            
        except Exception as e:
            self.logger.error(f"Error in fallback handling for {server_config.name}: {e}")
            
            # Create minimal failure result
            result = FallbackResult(
                success=False,
                strategy_used=FallbackStrategy.SKIP,
                server_info=None,
                confidence_score=0.0,
                fallback_reason=f"Fallback failed: {str(e)}",
                original_error=str(original_error),
                processing_time=time.time() - start_time
            )
            
            self.statistics.failed_fallbacks += 1
            return result
    
    def _try_strategy(
        self,
        strategy: FallbackStrategy,
        server_config: MCPServerConfig,
        original_error: Exception,
        error_context: Dict[str, Any]
    ) -> FallbackResult:
        """Try a specific fallback strategy."""
        self.statistics.strategy_usage[strategy] += 1
        
        try:
            if strategy == FallbackStrategy.SKIP:
                return self._skip_strategy(server_config, original_error)
            
            elif strategy == FallbackStrategy.BASIC_INFO:
                return self._basic_info_strategy(server_config, original_error)
            
            elif strategy == FallbackStrategy.CACHED_RESULT:
                return self._cached_result_strategy(server_config, original_error)
            
            elif strategy == FallbackStrategy.HEURISTIC_ANALYSIS:
                return self._heuristic_analysis_strategy(server_config, original_error, error_context)
            
            elif strategy == FallbackStrategy.MINIMAL_SAFE:
                return self._minimal_safe_strategy(server_config, original_error)
            
            elif strategy == FallbackStrategy.RETRY_WITH_TIMEOUT:
                return self._retry_strategy(server_config, original_error, error_context)
            
            elif strategy == FallbackStrategy.DEGRADED_SCAN:
                return self._degraded_scan_strategy(server_config, original_error, error_context)
            
            else:
                raise ValueError(f"Unknown fallback strategy: {strategy}")
                
        except Exception as e:
            self.logger.error(f"Strategy {strategy.value} failed for {server_config.name}: {e}")
            return FallbackResult(
                success=False,
                strategy_used=strategy,
                server_info=None,
                confidence_score=0.0,
                fallback_reason=f"Strategy failed: {str(e)}",
                original_error=str(original_error),
                processing_time=0.0
            )
    
    def _skip_strategy(self, server_config: MCPServerConfig, original_error: Exception) -> FallbackResult:
        """Skip the failed server entirely."""
        return FallbackResult(
            success=True,
            strategy_used=FallbackStrategy.SKIP,
            server_info=None,
            confidence_score=1.0,
            fallback_reason="Server skipped due to introspection failure",
            original_error=str(original_error),
            processing_time=0.0
        )
    
    def _basic_info_strategy(self, server_config: MCPServerConfig, original_error: Exception) -> FallbackResult:
        """Return basic server information only."""
        server_info = MCPServerInfo(
            server_name=server_config.name or "Unknown Server",
            server_version="unknown",
            protocol_version="unknown",
            transport_type=server_config.transport_type or "unknown",
            capabilities={'basic_info_only': True},
            tools=[],
            resources=[],
            risk_level=self.config.default_risk_level,
            introspection_timestamp=time.time(),
            metadata={
                'fallback_mode': True,
                'basic_info_only': True,
                'original_error': str(original_error)
            }
        )
        
        return FallbackResult(
            success=True,
            strategy_used=FallbackStrategy.BASIC_INFO,
            server_info=server_info,
            confidence_score=0.5,
            fallback_reason="Basic information extracted from configuration",
            original_error=str(original_error),
            processing_time=0.0
        )
    
    def _cached_result_strategy(self, server_config: MCPServerConfig, original_error: Exception) -> FallbackResult:
        """Use cached result if available."""
        cache_key = f"{server_config.name}_{server_config.transport_type}"
        
        if cache_key in self._result_cache:
            cached_result, cache_time = self._result_cache[cache_key]
            age_hours = (time.time() - cache_time) / 3600
            
            # Check if cache is still valid
            if age_hours <= self.config.cache_expiry_hours:
                cached_result.fallback_reason = "Using valid cached result"
                return cached_result
            elif self.config.allow_stale_cache and age_hours <= self.config.stale_cache_max_age_hours:
                cached_result.fallback_reason = f"Using stale cached result (age: {age_hours:.1f}h)"
                cached_result.confidence_score *= 0.8  # Reduce confidence for stale cache
                return cached_result
        
        # No valid cache available
        return FallbackResult(
            success=False,
            strategy_used=FallbackStrategy.CACHED_RESULT,
            server_info=None,
            confidence_score=0.0,
            fallback_reason="No valid cached result available",
            original_error=str(original_error),
            processing_time=0.0
        )
    
    def _heuristic_analysis_strategy(
        self,
        server_config: MCPServerConfig,
        original_error: Exception,
        error_context: Dict[str, Any]
    ) -> FallbackResult:
        """Perform heuristic analysis of the server."""
        if not self.config.enable_heuristic_analysis:
            return FallbackResult(
                success=False,
                strategy_used=FallbackStrategy.HEURISTIC_ANALYSIS,
                server_info=None,
                confidence_score=0.0,
                fallback_reason="Heuristic analysis disabled",
                original_error=str(original_error),
                processing_time=0.0
            )
        
        try:
            server_info, confidence = self.heuristic_analyzer.analyze_server(server_config, error_context)
            
            return FallbackResult(
                success=True,
                strategy_used=FallbackStrategy.HEURISTIC_ANALYSIS,
                server_info=server_info,
                confidence_score=confidence,
                fallback_reason="Heuristic analysis based on configuration patterns",
                original_error=str(original_error),
                processing_time=0.0
            )
            
        except Exception as e:
            self.logger.error(f"Heuristic analysis failed for {server_config.name}: {e}")
            return FallbackResult(
                success=False,
                strategy_used=FallbackStrategy.HEURISTIC_ANALYSIS,
                server_info=None,
                confidence_score=0.0,
                fallback_reason=f"Heuristic analysis failed: {str(e)}",
                original_error=str(original_error),
                processing_time=0.0
            )
    
    def _minimal_safe_strategy(self, server_config: MCPServerConfig, original_error: Exception) -> FallbackResult:
        """Return minimal safe configuration."""
        server_info = MCPServerInfo(
            server_name=server_config.name or "Unknown Server",
            server_version="unknown",
            protocol_version="unknown",
            transport_type=server_config.transport_type or "unknown",
            capabilities={'minimal_safe_mode': True},
            tools=[],
            resources=[],
            risk_level=RiskLevel.HIGH if self.config.enable_conservative_defaults else self.config.default_risk_level,
            introspection_timestamp=time.time(),
            metadata={
                'fallback_mode': True,
                'minimal_safe': True,
                'conservative_defaults': self.config.enable_conservative_defaults,
                'original_error': str(original_error)
            }
        )
        
        return FallbackResult(
            success=True,
            strategy_used=FallbackStrategy.MINIMAL_SAFE,
            server_info=server_info,
            confidence_score=0.3,
            fallback_reason="Minimal safe configuration with conservative defaults",
            original_error=str(original_error),
            processing_time=0.0
        )
    
    def _retry_strategy(
        self,
        server_config: MCPServerConfig,
        original_error: Exception,
        error_context: Dict[str, Any]
    ) -> FallbackResult:
        """Retry with reduced timeout (placeholder - would need introspection system integration)."""
        # This would require integration with the introspection system
        # For now, return a failure indicating retry is not implemented
        return FallbackResult(
            success=False,
            strategy_used=FallbackStrategy.RETRY_WITH_TIMEOUT,
            server_info=None,
            confidence_score=0.0,
            fallback_reason="Retry strategy requires introspection system integration",
            original_error=str(original_error),
            processing_time=0.0
        )
    
    def _degraded_scan_strategy(
        self,
        server_config: MCPServerConfig,
        original_error: Exception,
        error_context: Dict[str, Any]
    ) -> FallbackResult:
        """Perform degraded scan with limited features (placeholder)."""
        # This would require integration with a simplified scanning mechanism
        # For now, return a failure indicating degraded scan is not implemented
        return FallbackResult(
            success=False,
            strategy_used=FallbackStrategy.DEGRADED_SCAN,
            server_info=None,
            confidence_score=0.0,
            fallback_reason="Degraded scan strategy requires simplified scanner implementation",
            original_error=str(original_error),
            processing_time=0.0
        )
    
    def _categorize_failure(self, error: Exception, context: Optional[Dict[str, Any]]) -> FailureReason:
        """Categorize the type of failure."""
        error_str = str(error).lower()
        
        if 'timeout' in error_str:
            return FailureReason.TIMEOUT
        elif 'connection' in error_str or 'connect' in error_str:
            return FailureReason.CONNECTION_ERROR
        elif 'auth' in error_str or 'permission' in error_str:
            return FailureReason.AUTHENTICATION_ERROR
        elif 'protocol' in error_str:
            return FailureReason.PROTOCOL_ERROR
        elif 'resource' in error_str or 'memory' in error_str:
            return FailureReason.RESOURCE_ERROR
        elif 'config' in error_str:
            return FailureReason.CONFIGURATION_ERROR
        else:
            return FailureReason.UNKNOWN_ERROR
    
    def _finalize_result(self, result: FallbackResult, start_time: float) -> FallbackResult:
        """Finalize the fallback result with timing and statistics."""
        result.processing_time = time.time() - start_time
        
        if result.success:
            self.statistics.successful_fallbacks += 1
            
            # Cache successful results
            if result.server_info and self.config.use_cached_results:
                cache_key = f"{result.server_info.server_name}_{result.server_info.transport_type}"
                self._result_cache[cache_key] = (result, time.time())
        else:
            self.statistics.failed_fallbacks += 1
        
        # Update statistics
        self._update_statistics(result)
        
        if self.config.log_fallback_usage:
            self.logger.info(
                f"Fallback completed for server: strategy={result.strategy_used.value}, "
                f"success={result.success}, confidence={result.confidence_score:.2f}, "
                f"time={result.processing_time:.2f}s"
            )
        
        return result
    
    def _update_statistics(self, result: FallbackResult) -> None:
        """Update running statistics."""
        # Update average confidence
        total_successful = self.statistics.successful_fallbacks
        if total_successful > 0:
            self.statistics.average_confidence = (
                (self.statistics.average_confidence * (total_successful - 1) + result.confidence_score) / total_successful
            )
        
        # Update average processing time
        total_fallbacks = self.statistics.total_fallbacks
        if total_fallbacks > 0:
            self.statistics.average_processing_time = (
                (self.statistics.average_processing_time * (total_fallbacks - 1) + result.processing_time) / total_fallbacks
            )
    
    def get_statistics(self) -> FallbackStatistics:
        """Get current fallback statistics."""
        # Calculate cache hit rate
        if self._result_cache:
            cache_hits = sum(1 for strategy_count in self.statistics.strategy_usage.values() 
                           if strategy_count > 0 and FallbackStrategy.CACHED_RESULT in self.statistics.strategy_usage)
            self.statistics.cache_hit_rate = (cache_hits / max(1, self.statistics.total_fallbacks)) * 100
        
        return self.statistics
    
    def clear_cache(self) -> None:
        """Clear the result cache."""
        self._result_cache.clear()
        self.logger.info("Fallback result cache cleared")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get information about the current cache state."""
        current_time = time.time()
        valid_entries = 0
        stale_entries = 0
        
        for _, (result, cache_time) in self._result_cache.items():
            age_hours = (current_time - cache_time) / 3600
            if age_hours <= self.config.cache_expiry_hours:
                valid_entries += 1
            elif age_hours <= self.config.stale_cache_max_age_hours:
                stale_entries += 1
        
        return {
            'total_entries': len(self._result_cache),
            'valid_entries': valid_entries,
            'stale_entries': stale_entries,
            'expired_entries': len(self._result_cache) - valid_entries - stale_entries,
            'cache_expiry_hours': self.config.cache_expiry_hours,
            'stale_cache_max_age_hours': self.config.stale_cache_max_age_hours
        }