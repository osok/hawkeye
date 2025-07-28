"""
AI-Powered Threat Analyzer

This module provides the main orchestration class for AI-powered threat analysis,
coordinating capability analysis, AI providers, and result processing.
"""

import logging
import time
import threading
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AnalysisMetadata,
    ThreatLevel, AttackVector, AbuseScenario, MitigationStrategy, SeverityLevel,
    DetectionIndicator, ComplianceImpact, ThreatActorType, AttackStep, 
    BusinessImpact, AccessLevel, DifficultyLevel
)
from .capability_analyzer import MCPCapabilityAnalyzer
from .ai_providers import (
    AIProvider, OpenAIProvider, AnthropicProvider, LocalLLMProvider,
    AnalysisRequest, AnalysisResponse
)
from .prompts import ThreatAnalysisPrompts
from ..mcp_introspection.models import MCPServerInfo
from ..mcp_introspection.optimization.memory import (
    MemoryOptimizer, MemoryConfig, MemoryOptimizationLevel, create_memory_optimizer
)
from ...config import get_settings


logger = logging.getLogger(__name__)


class ThreatIntelligenceCache:
    """Simple in-memory cache for threat intelligence."""
    
    def __init__(self, ttl: int = 3600):
        """Initialize cache with TTL in seconds."""
        self.cache = {}
        self.ttl = ttl
    
    def get(self, key: str) -> Optional[ThreatAnalysis]:
        """Get cached analysis if still valid."""
        if key in self.cache:
            analysis, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return analysis
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, analysis: ThreatAnalysis) -> None:
        """Cache analysis with current timestamp."""
        self.cache[key] = (analysis, time.time())
    
    def clear(self) -> None:
        """Clear all cached analyses."""
        self.cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "cache_size": len(self.cache),
            "cache_hits": getattr(self, "hits", 0),
            "cache_misses": getattr(self, "misses", 0)
        }


class ResponseTimeMonitor:
    """Monitors and tracks response times for AI threat analysis operations."""
    
    def __init__(self, window_size: int = 100):
        """
        Initialize response time monitor.
        
        Args:
            window_size: Number of recent operations to track
        """
        self.window_size = window_size
        self.response_times: List[float] = []
        self.operation_counts: Dict[str, int] = {}
        self.operation_times: Dict[str, List[float]] = {}
        self.slow_operations: List[Dict[str, Any]] = []
        self.alert_threshold = 30.0  # 30 seconds
        self.warning_threshold = 15.0  # 15 seconds
        self._lock = threading.RLock()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def record_operation(self, operation_name: str, duration: float, 
                        metadata: Optional[Dict[str, Any]] = None) -> None:
        """Record an operation's response time."""
        with self._lock:
            # Update global response times
            self.response_times.append(duration)
            if len(self.response_times) > self.window_size:
                self.response_times.pop(0)
            
            # Update operation-specific times
            if operation_name not in self.operation_times:
                self.operation_times[operation_name] = []
                self.operation_counts[operation_name] = 0
            
            self.operation_times[operation_name].append(duration)
            if len(self.operation_times[operation_name]) > self.window_size:
                self.operation_times[operation_name].pop(0)
            
            self.operation_counts[operation_name] += 1
            
            # Check for slow operations
            if duration > self.alert_threshold:
                slow_op = {
                    'operation': operation_name,
                    'duration': duration,
                    'timestamp': time.time(),
                    'metadata': metadata or {},
                    'severity': 'critical' if duration > self.alert_threshold * 2 else 'high'
                }
                self.slow_operations.append(slow_op)
                if len(self.slow_operations) > 50:  # Keep only recent slow operations
                    self.slow_operations.pop(0)
                
                self.logger.warning(
                    f"Slow operation detected: {operation_name} took {duration:.2f}s "
                    f"(threshold: {self.alert_threshold}s)"
                )
            elif duration > self.warning_threshold:
                self.logger.info(
                    f"Operation above warning threshold: {operation_name} took {duration:.2f}s "
                    f"(threshold: {self.warning_threshold}s)"
                )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive response time statistics."""
        with self._lock:
            if not self.response_times:
                return {
                    'overall': {'count': 0, 'avg': 0, 'min': 0, 'max': 0},
                    'by_operation': {},
                    'slow_operations_count': 0,
                    'performance_health': 'unknown'
                }
            
            # Overall statistics
            overall_stats = {
                'count': len(self.response_times),
                'avg': sum(self.response_times) / len(self.response_times),
                'min': min(self.response_times),
                'max': max(self.response_times),
                'p50': self._percentile(self.response_times, 50),
                'p90': self._percentile(self.response_times, 90),
                'p95': self._percentile(self.response_times, 95),
                'p99': self._percentile(self.response_times, 99)
            }
            
            # Operation-specific statistics
            by_operation = {}
            for op_name, times in self.operation_times.items():
                if times:
                    by_operation[op_name] = {
                        'count': self.operation_counts[op_name],
                        'recent_count': len(times),
                        'avg': sum(times) / len(times),
                        'min': min(times),
                        'max': max(times),
                        'p90': self._percentile(times, 90),
                        'p95': self._percentile(times, 95)
                    }
            
            # Performance health assessment
            avg_time = overall_stats['avg']
            p95_time = overall_stats['p95']
            slow_ops_ratio = len([t for t in self.response_times if t > self.warning_threshold]) / len(self.response_times)
            
            if avg_time < 5.0 and p95_time < 10.0 and slow_ops_ratio < 0.05:
                health = 'excellent'
            elif avg_time < 10.0 and p95_time < 20.0 and slow_ops_ratio < 0.10:
                health = 'good'
            elif avg_time < 20.0 and p95_time < 30.0 and slow_ops_ratio < 0.20:
                health = 'fair'
            else:
                health = 'poor'
            
            return {
                'overall': overall_stats,
                'by_operation': by_operation,
                'slow_operations_count': len(self.slow_operations),
                'slow_operations_recent': self.slow_operations[-10:],  # Last 10 slow operations
                'performance_health': health,
                'slow_operations_ratio': slow_ops_ratio,
                'thresholds': {
                    'warning': self.warning_threshold,
                    'alert': self.alert_threshold
                }
            }
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int((percentile / 100.0) * len(sorted_data))
        if index >= len(sorted_data):
            index = len(sorted_data) - 1
        return sorted_data[index]
    
    def get_slow_operations(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent slow operations."""
        with self._lock:
            return self.slow_operations[-limit:]
    
    def clear_statistics(self) -> None:
        """Clear all statistics."""
        with self._lock:
            self.response_times.clear()
            self.operation_counts.clear()
            self.operation_times.clear()
            self.slow_operations.clear()
        self.logger.info("Response time statistics cleared")
    
    def adjust_thresholds(self, warning_threshold: float, alert_threshold: float) -> None:
        """Adjust warning and alert thresholds."""
        self.warning_threshold = warning_threshold
        self.alert_threshold = alert_threshold
        self.logger.info(f"Response time thresholds updated: warning={warning_threshold}s, alert={alert_threshold}s")


class AIThreatAnalyzer:
    """AI-powered threat analysis for MCP tools with enhanced prompt engineering and memory optimization."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI threat analyzer with enhanced prompt system and memory optimization.
        
        Args:
            config: Optional configuration override
        """
        self.settings = get_settings()
        self.config = config or {}
        
        # Initialize components
        self.capability_analyzer = MCPCapabilityAnalyzer()
        self.prompt_engine = ThreatAnalysisPrompts()
        self.ai_provider = self._initialize_ai_provider()
        self.fallback_provider = self._initialize_fallback_provider()
        self.cache = ThreatIntelligenceCache(
            ttl=self.settings.ai.cache_ttl if self.settings.ai.cache_enabled else 0
        )
        
        # Memory optimization
        optimization_level = self.config.get('memory_optimization_level', 'standard')
        self.memory_optimizer = create_memory_optimizer(optimization_level)
        self.memory_optimizer.start_optimization()
        
        # Response time monitoring
        self.response_monitor = ResponseTimeMonitor(
            window_size=self.config.get('response_time_window', 100)
        )
        
        # Statistics tracking
        self.stats = {
            "analyses_performed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "ai_failures": 0,
            "total_cost": 0.0,
            "prompt_types_used": {},
            "analysis_times": [],
            "memory_cleanups": 0,
            "memory_warnings": 0
        }
        
        logger.info(f"AI Threat Analyzer initialized with provider: {self.settings.ai.provider}")
        logger.info("Enhanced prompt engineering framework enabled")
        logger.info(f"Memory optimization enabled (level: {optimization_level})")
        logger.info("Response time monitoring enabled")
    
    def analyze_threats(self, 
                       mcp_server: MCPServerInfo,
                       environment_context: Optional[EnvironmentContext] = None,
                       analysis_type: str = "comprehensive",
                       force_refresh: bool = False) -> ThreatAnalysis:
        """
        Generate comprehensive threat analysis for an MCP tool using structured prompts with memory optimization.
        
        Args:
            mcp_server: MCP server information
            environment_context: Optional environment context
            analysis_type: Type of analysis (comprehensive, quick_assessment, context_aware)
            force_refresh: Force new analysis (skip cache)
            
        Returns:
            Complete threat analysis
        """
        # Get tool name from metadata or server_id
        tool_name = mcp_server.metadata.get('name', mcp_server.server_id)
        logger.info(f"Starting {analysis_type} threat analysis for: {tool_name}")
        analysis_start = time.time()
        
        # Memory optimization context
        with self.memory_optimizer.memory_context(f"threat_analysis_{tool_name}"):
            try:
                # Check initial memory state
                memory_info = self.memory_optimizer.get_current_memory_usage()
                if memory_info['memory_pressure'] == 'critical':
                    logger.warning(f"High memory pressure before analysis: {memory_info['process_memory_mb']:.1f}MB")
                    self.stats["memory_warnings"] += 1
                    # Force cleanup if memory is critical
                    cleanup_stats = self.memory_optimizer.force_cleanup()
                    self.stats["memory_cleanups"] += 1
                    logger.info(f"Memory cleanup performed: {cleanup_stats}")
                
                # Step 1: Analyze tool capabilities
                tool_capabilities = self.capability_analyzer.analyze_tool(mcp_server)
                
                # Step 2: Build environment context if not provided
                if environment_context is None:
                    environment_context = self.capability_analyzer.build_environment_context([mcp_server])
                
                # Step 3: Check cache if enabled
                cache_key = self._generate_cache_key(tool_capabilities, environment_context, analysis_type)
                
                if not force_refresh and self.settings.ai.cache_enabled:
                    cached_analysis = self.cache.get(cache_key)
                    if cached_analysis:
                        logger.info(f"Using cached analysis for {tool_name}")
                        self.stats["cache_hits"] += 1
                        analysis_duration = time.time() - analysis_start
                        self.response_monitor.record_operation(
                            f"analyze_threats_cached_{analysis_type}",
                            analysis_duration,
                            {'tool_name': tool_name, 'cache_hit': True}
                        )
                        return cached_analysis
                    else:
                        self.stats["cache_misses"] += 1
                
                # Step 4: Perform AI analysis with structured prompts
                analysis = self._perform_enhanced_ai_analysis(
                    tool_capabilities, 
                    environment_context, 
                    analysis_type
                )
                
                # Step 5: Post-process results
                analysis = self._post_process_analysis(analysis, tool_capabilities)
                
                # Step 6: Cache results if enabled
                if self.settings.ai.cache_enabled:
                    self.cache.set(cache_key, analysis)
                
                # Update statistics
                self.stats["analyses_performed"] += 1
                self.stats["total_cost"] += analysis.analysis_metadata.cost
                
                # Track prompt usage
                if analysis_type not in self.stats["prompt_types_used"]:
                    self.stats["prompt_types_used"][analysis_type] = 0
                self.stats["prompt_types_used"][analysis_type] += 1
                
                # Track analysis time and record response time
                analysis_duration = time.time() - analysis_start
                self.stats["analysis_times"].append(analysis_duration)
                
                self.response_monitor.record_operation(
                    f"analyze_threats_{analysis_type}",
                    analysis_duration,
                    {
                        'tool_name': tool_name,
                        'cache_hit': False,
                        'ai_provider': self.settings.ai.provider,
                        'memory_pressure': memory_info['memory_pressure'],
                        'cost': analysis.analysis_metadata.cost
                    }
                )
                
                logger.info(f"Enhanced threat analysis completed for {tool_name} in {analysis_duration:.2f}s")
                
                return analysis
                
            except Exception as e:
                # Handle any errors during analysis
                analysis_duration = time.time() - analysis_start
                logger.error(f"Error during threat analysis for {tool_name}: {e}")
                
                # Record the failed operation
                self.response_monitor.record_operation(
                    f"analyze_threats_{analysis_type}_failed",
                    analysis_duration,
                    {'tool_name': tool_name, 'error': str(e)}
                )
                
                # Try fallback analysis if main provider fails
                return self._create_fallback_analysis(mcp_server, tool_capabilities, environment_context, "comprehensive")
                
            except Exception as e:
                logger.error(f"Enhanced threat analysis failed for {tool_name}: {e}")
                
                # Return minimal analysis on error
                return self._create_fallback_analysis(
                    mcp_server, 
                    tool_capabilities if 'tool_capabilities' in locals() else None, 
                    environment_context,
                    analysis_type
                )
    
    def analyze_context_aware_threats(self,
                                    mcp_server: MCPServerInfo,
                                    environment_context: EnvironmentContext,
                                    similar_tools: Optional[List[str]] = None) -> ThreatAnalysis:
        """
        Perform context-aware threat analysis using specialized prompts.
        
        Args:
            mcp_server: MCP server to analyze
            environment_context: Environment context for analysis
            similar_tools: List of similar tools in the environment
            
        Returns:
            Context-aware threat analysis
        """
        tool_capabilities = self.capability_analyzer.analyze_tool(mcp_server)
        
        # Build context-aware prompt
        prompt_data = self.prompt_engine.build_context_aware_prompt(
            tool_capabilities,
            environment_context,
            similar_tools
        )
        
        # Create enhanced analysis request
        request = AnalysisRequest(
            tool_capabilities=tool_capabilities,
            environment_context=environment_context,
            analysis_type="context_aware",
            max_tokens=prompt_data["max_tokens"],
            temperature=prompt_data["temperature"]
        )
        
        # Add prompt data to request
        request.prompt_data = prompt_data
        
        return self._execute_ai_analysis_request(request)
    
    def analyze_attack_chains(self,
                            mcp_servers: List[MCPServerInfo],
                            environment_context: EnvironmentContext) -> ThreatAnalysis:
        """
        Analyze potential attack chains across multiple MCP tools.
        
        Args:
            mcp_servers: List of MCP servers to analyze for attack chains
            environment_context: Environment context for analysis
            
        Returns:
            Attack chain analysis
        """
        # Analyze capabilities for all tools
        tools_capabilities = []
        for server in mcp_servers:
            capabilities = self.capability_analyzer.analyze_tool(server)
            tools_capabilities.append(capabilities)
        
        # Build attack chain prompt
        prompt_data = self.prompt_engine.build_attack_chain_prompt(
            tools_capabilities,
            environment_context
        )
        
        # Use first tool as primary for analysis structure
        primary_capabilities = tools_capabilities[0] if tools_capabilities else None
        if not primary_capabilities:
            raise ValueError("No tools provided for attack chain analysis")
        
        # Create enhanced analysis request
        request = AnalysisRequest(
            tool_capabilities=primary_capabilities,
            environment_context=environment_context,
            analysis_type="attack_chain",
            max_tokens=prompt_data["max_tokens"],
            temperature=prompt_data["temperature"]
        )
        
        # Add prompt data and additional tools
        request.prompt_data = prompt_data
        request.additional_tools = tools_capabilities[1:]
        
        return self._execute_ai_analysis_request(request)
    
    def analyze_multiple_threats(self, 
                                mcp_servers: List[MCPServerInfo],
                                environment_context: Optional[EnvironmentContext] = None,
                                analysis_type: str = "comprehensive") -> List[ThreatAnalysis]:
        """
        Analyze threats for multiple MCP servers with enhanced prompts.
        
        Args:
            mcp_servers: List of MCP servers to analyze
            environment_context: Optional shared environment context
            analysis_type: Type of analysis to perform
            
        Returns:
            List of threat analyses
        """
        logger.info(f"Starting batch {analysis_type} analysis for {len(mcp_servers)} servers")
        
        analyses = []
        
        # Build shared environment context if not provided
        if environment_context is None:
            environment_context = self.capability_analyzer.build_environment_context(mcp_servers)
        
        for server in mcp_servers:
            try:
                analysis = self.analyze_threats(server, environment_context, analysis_type)
                analyses.append(analysis)
            except Exception as e:
                server_name = server.metadata.get('name', server.server_id)
                logger.error(f"Failed to analyze {server_name}: {e}")
                # Continue with other servers
                continue
        
        logger.info(f"Batch {analysis_type} analysis completed: {len(analyses)}/{len(mcp_servers)} successful")
        return analyses
    
    def assess_risk_level(self, mcp_server: MCPServerInfo) -> Tuple[ThreatLevel, float]:
        """
        Quick risk assessment using enhanced prompt system.
        
        Args:
            mcp_server: MCP server to assess
            
        Returns:
            Tuple of (threat_level, confidence_score)
        """
        try:
            # Use quick assessment analysis type
            analysis = self.analyze_threats(mcp_server, analysis_type="quick_assessment")
            return analysis.threat_level, analysis.confidence_score
            
        except Exception as e:
            tool_name = mcp_server.metadata.get('name', mcp_server.server_id)
            logger.error(f"Risk assessment failed for {tool_name}: {e}")
            return ThreatLevel.MEDIUM, 0.5
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get enhanced analysis statistics."""
        stats = self.stats.copy()
        stats.update(self.cache.get_stats())
        
        # Add timing statistics
        if self.stats["analysis_times"]:
            times = self.stats["analysis_times"]
            stats["avg_analysis_time"] = sum(times) / len(times)
            stats["min_analysis_time"] = min(times)
            stats["max_analysis_time"] = max(times)
        
        # Add AI provider stats if available
        if hasattr(self.ai_provider, 'get_usage_stats'):
            stats.update(self.ai_provider.get_usage_stats())
        
        return stats
    
    # === F4.3: ADVANCED BATCH PROCESSING OPTIMIZATION ===
    
    def analyze_threats_batch_optimized(self,
                                      mcp_servers: List[MCPServerInfo],
                                      adaptive_sizing: bool = True,
                                      target_batch_time: float = 30.0,
                                      min_batch_size: int = 2,
                                      max_batch_size: int = 10,
                                      enable_load_balancing: bool = True,
                                      memory_limit_mb: int = 512,
                                      priority_strategy: str = "complexity",
                                      environment_context: Optional[EnvironmentContext] = None,
                                      analysis_type: str = "comprehensive",
                                      progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        F4.3: Advanced optimized batch processing with adaptive sizing, load balancing, and memory optimization.
        
        This method implements the complete F4.3 batch processing optimization including:
        - Adaptive batch sizing based on performance history and memory usage
        - Intelligent load balancing across AI providers
        - Smart prioritization strategies for optimal processing order
        - Advanced performance tracking and analytics
        - Memory usage optimization and monitoring
        
        Args:
            mcp_servers: List of MCP servers to analyze
            adaptive_sizing: Enable adaptive batch size adjustment based on performance
            target_batch_time: Target processing time per batch in seconds
            min_batch_size: Minimum batch size
            max_batch_size: Maximum batch size
            enable_load_balancing: Enable provider load balancing
            memory_limit_mb: Memory limit per batch in MB
            priority_strategy: Batch prioritization strategy ('complexity', 'cost', 'risk', 'fifo')
            environment_context: Optional shared environment context
            analysis_type: Type of analysis to perform
            progress_callback: Optional callback for progress updates
            
        Returns:
            Enhanced batch analysis results with optimization metrics
        """
        if not mcp_servers:
            return self._create_empty_optimized_batch_stats()
        
        logger.info(f"Starting F4.3 optimized batch analysis for {len(mcp_servers)} MCP servers")
        start_time = time.time()
        
        # Initialize optimization engine
        optimizer = BatchOptimizationEngine(
            target_batch_time=target_batch_time,
            min_batch_size=min_batch_size,
            max_batch_size=max_batch_size,
            memory_limit_mb=memory_limit_mb,
            providers=self._get_provider_names()
        )
        
        # Build shared environment context if not provided
        if environment_context is None:
            environment_context = self.capability_analyzer.build_environment_context(mcp_servers)
        
        # Prioritize and organize servers for optimal processing
        prioritized_servers = self._prioritize_servers_for_optimization(mcp_servers, priority_strategy)
        
        # Initialize tracking
        all_analyses = []
        optimization_metrics = []
        total_processed = 0
        current_batch_size = min_batch_size
        
        # Process with adaptive batching
        batch_num = 0
        i = 0
        
        while i < len(prioritized_servers):
            batch_num += 1
            
            # Determine optimal batch size
            if adaptive_sizing:
                current_batch_size = optimizer.calculate_optimal_batch_size(
                    remaining_servers=len(prioritized_servers) - i,
                    historical_metrics=optimization_metrics,
                    current_memory_usage=self._get_memory_usage_mb()
                )
            
            # Extract batch
            batch_end = min(i + current_batch_size, len(prioritized_servers))
            batch_servers = prioritized_servers[i:batch_end]
            
            logger.info(f"Processing optimized batch {batch_num} ({len(batch_servers)} servers, "
                       f"size: {current_batch_size})")
            
            # Select optimal provider for this batch
            selected_provider = None
            if enable_load_balancing:
                selected_provider = optimizer.select_optimal_provider(batch_servers)
            
            # Process batch with optimization
            batch_result = self._process_optimized_batch(
                batch_servers=batch_servers,
                environment_context=environment_context,
                analysis_type=analysis_type,
                selected_provider=selected_provider,
                batch_size=current_batch_size,
                memory_limit_mb=memory_limit_mb
            )
            
            # Merge results
            all_analyses.extend(batch_result["analyses"])
            
            # Track optimization metrics
            optimization_metrics.append(batch_result["optimization_metrics"])
            
            total_processed += len(batch_servers)
            
            # Progress callback
            if progress_callback:
                progress_callback(
                    total_processed, 
                    len(prioritized_servers), 
                    f"Completed optimized batch {batch_num} (size: {len(batch_servers)})"
                )
            
            # Update batch size for next iteration if adaptive
            if adaptive_sizing:
                optimizer.update_performance_history(batch_result["optimization_metrics"])
            
            i = batch_end
        
        # Calculate comprehensive statistics
        total_time = time.time() - start_time
        statistics = self._calculate_optimized_batch_stats(
            all_analyses, optimization_metrics, total_time
        )
        
        logger.info(f"F4.3 optimized batch analysis completed: {len(all_analyses)} successful "
                   f"in {total_time:.2f}s")
        
        return {
            "analyses": all_analyses,
            "statistics": statistics,
            "optimization_metrics": optimization_metrics
        }

    def _prioritize_servers_for_optimization(self, 
                                           mcp_servers: List[MCPServerInfo], 
                                           strategy: str) -> List[MCPServerInfo]:
        """
        Prioritize servers for optimal batch processing based on strategy.
        
        Args:
            mcp_servers: List of servers to prioritize
            strategy: Prioritization strategy
            
        Returns:
            Prioritized list of servers
        """
        if strategy == "fifo":
            return mcp_servers.copy()
        
        # Implement prioritization based on strategy
        def get_priority_score(server: MCPServerInfo) -> float:
            if strategy == "complexity":
                # Estimate complexity based on server metadata
                metadata_size = len(str(server.metadata))
                return metadata_size
            elif strategy == "cost":
                # Estimate cost based on server characteristics
                return hash(server.server_id) % 100 / 100.0
            elif strategy == "risk":
                # Basic risk estimation
                if server.transport_type in ['http', 'ws']:
                    return 1.0  # Higher priority for less secure
                return 0.5  # Default risk
            else:
                return 0.0
        
        return sorted(mcp_servers, key=get_priority_score, reverse=True)

    def _process_optimized_batch(self,
                               batch_servers: List[MCPServerInfo],
                               environment_context: EnvironmentContext,
                               analysis_type: str,
                               selected_provider: Optional[str],
                               batch_size: int,
                               memory_limit_mb: int) -> Dict[str, Any]:
        """
        Process a batch with F4.3 optimization features.
        
        Args:
            batch_servers: Servers in this batch
            environment_context: Environment context
            analysis_type: Type of analysis
            selected_provider: Optional specific provider to use
            batch_size: Current batch size
            memory_limit_mb: Memory limit
            
        Returns:
            Batch processing results with optimization metrics
        """
        batch_start = time.time()
        memory_start = self._get_memory_usage_mb()
        
        # Analyze all servers in the batch
        analyses = []
        successful_count = 0
        
        for server in batch_servers:
            try:
                analysis = self.analyze_threats(server, environment_context, analysis_type)
                analyses.append(analysis)
                successful_count += 1
            except Exception as e:
                logger.error(f"Analysis failed for {server.server_id}: {e}")
                continue
        
        # Calculate optimization metrics
        batch_time = time.time() - batch_start
        memory_end = self._get_memory_usage_mb()
        memory_used = memory_end - memory_start
        
        optimization_metrics = {
            "batch_size": batch_size,
            "batch_time": batch_time,
            "memory_used_mb": memory_used,
            "memory_efficiency": memory_used / len(batch_servers) if batch_servers else 0,
            "time_per_tool": batch_time / len(batch_servers) if batch_servers else 0,
            "selected_provider": selected_provider or "auto",
            "success_rate": successful_count / len(batch_servers) if batch_servers else 0,
            "tools_per_second": len(batch_servers) / batch_time if batch_time > 0 else 0
        }
        
        return {
            "analyses": analyses,
            "optimization_metrics": optimization_metrics
        }

    def _get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            import os
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            # Fallback if psutil not available
            return 0.0

    def _get_provider_names(self) -> List[str]:
        """Get list of available provider names."""
        providers = []
        if hasattr(self, 'ai_provider') and self.ai_provider:
            providers.append(self.settings.ai.provider)
        if hasattr(self, 'fallback_provider') and self.fallback_provider:
            providers.append(self.settings.ai.fallback_provider)
        return providers

    def _create_empty_optimized_batch_stats(self) -> Dict[str, Any]:
        """Create empty optimized batch statistics."""
        return {
            "total_tools": 0,
            "successful_count": 0,
            "error_count": 0,
            "total_execution_time": 0.0,
            "batch_count": 0,
            "avg_batch_time": 0.0,
            "avg_time_per_tool": 0.0,
            "tools_per_second": 0.0,
            "success_rate": 0.0,
            "optimization_metrics": {
                "adaptive_sizing_enabled": False,
                "load_balancing_enabled": False,
                "avg_batch_size": 0.0,
                "memory_efficiency": 0.0,
                "provider_distribution": {}
            },
            "batch_details": []
        }

    def _calculate_optimized_batch_stats(self,
                                       all_analyses: List[ThreatAnalysis],
                                       optimization_metrics: List[Dict[str, Any]],
                                       total_time: float) -> Dict[str, Any]:
        """Calculate optimized batch processing statistics."""
        total_tools = len(all_analyses)
        successful_count = len(all_analyses)
        error_count = 0  # Errors are not included in analyses list
        
        # Calculate optimization statistics
        if optimization_metrics:
            import statistics as stats_module
            avg_batch_size = stats_module.mean([m["batch_size"] for m in optimization_metrics])
            avg_memory_efficiency = stats_module.mean([m["memory_efficiency"] for m in optimization_metrics])
            provider_usage = {}
            for m in optimization_metrics:
                provider = m.get("selected_provider", "auto")
                provider_usage[provider] = provider_usage.get(provider, 0) + 1
        else:
            avg_batch_size = 0.0
            avg_memory_efficiency = 0.0
            provider_usage = {}
        
        # Base statistics
        base_stats = {
            "total_tools": total_tools,
            "successful_count": successful_count,
            "error_count": error_count,
            "total_execution_time": total_time,
            "batch_count": len(optimization_metrics),
            "avg_batch_time": total_time / len(optimization_metrics) if optimization_metrics else 0.0,
            "avg_time_per_tool": total_time / total_tools if total_tools > 0 else 0.0,
            "tools_per_second": total_tools / total_time if total_time > 0 else 0.0,
            "success_rate": successful_count / total_tools if total_tools > 0 else 0.0,
            "batch_details": optimization_metrics
        }
        
        # Add optimization metrics
        base_stats["optimization_metrics"] = {
            "adaptive_sizing_enabled": True,
            "load_balancing_enabled": True,
            "avg_batch_size": avg_batch_size,
            "memory_efficiency": avg_memory_efficiency,
            "provider_distribution": provider_usage,
            "total_memory_used_mb": sum([m["memory_used_mb"] for m in optimization_metrics]),
            "avg_memory_per_tool": avg_memory_efficiency * avg_batch_size if avg_batch_size > 0 else 0.0
        }
        
        return base_stats
    
    def clear_cache(self) -> None:
        """Clear the threat intelligence cache."""
        self.cache.clear()
        logger.info("Threat intelligence cache cleared")
    
    def _initialize_ai_provider(self) -> AIProvider:
        """Initialize the primary AI provider."""
        provider_name = self.settings.ai.provider
        config = self._build_provider_config()
        
        try:
            if provider_name == "openai":
                return OpenAIProvider(config)
            elif provider_name == "anthropic":
                return AnthropicProvider(config)
            elif provider_name == "local":
                return LocalLLMProvider(config)
            else:
                logger.warning(f"Unknown AI provider: {provider_name}, defaulting to anthropic")
                return AnthropicProvider(config)
                
        except Exception as e:
            logger.error(f"Failed to initialize {provider_name} provider: {e}")
            
            # Try fallback provider
            fallback_name = self.settings.ai.fallback_provider
            if fallback_name != provider_name:
                logger.info(f"Attempting to use fallback provider: {fallback_name}")
                try:
                    if fallback_name == "openai":
                        return OpenAIProvider(config)
                    elif fallback_name == "anthropic":
                        return AnthropicProvider(config)
                    elif fallback_name == "local":
                        return LocalLLMProvider(config)
                except Exception as fallback_error:
                    logger.error(f"Fallback provider also failed: {fallback_error}")
            
            # Final fallback to local LLM
            logger.warning("Using local LLM provider as last resort")
            return LocalLLMProvider(config)
    
    def _initialize_fallback_provider(self) -> Optional[AIProvider]:
        """Initialize fallback AI provider."""
        fallback_name = self.settings.ai.fallback_provider
        
        if fallback_name == self.settings.ai.provider:
            return None  # Same as primary
        
        try:
            config = self._build_provider_config()
            
            if fallback_name == "openai":
                return OpenAIProvider(config)
            elif fallback_name == "anthropic":
                return AnthropicProvider(config)
            elif fallback_name == "local":
                return LocalLLMProvider(config)
                
        except Exception as e:
            logger.warning(f"Failed to initialize fallback provider {fallback_name}: {e}")
            
        return None
    
    def _build_provider_config(self) -> Dict[str, Any]:
        """Build configuration dictionary for AI providers."""
        ai_settings = self.settings.ai
        
        config = {
            # OpenAI settings
            "openai_api_key": ai_settings.openai_api_key,
            "openai_model": ai_settings.openai_model,
            "openai_max_tokens": ai_settings.openai_max_tokens,
            "openai_temperature": ai_settings.openai_temperature,
            "openai_timeout": ai_settings.openai_timeout,
            
            # Anthropic settings
            "anthropic_api_key": ai_settings.anthropic_api_key,
            "anthropic_model": ai_settings.anthropic_model,
            "anthropic_max_tokens": ai_settings.anthropic_max_tokens,
            "anthropic_temperature": ai_settings.anthropic_temperature,
            "anthropic_timeout": ai_settings.anthropic_timeout,
            
            # Local LLM settings
            "local_llm_endpoint": ai_settings.local_llm_endpoint,
            "local_llm_model": ai_settings.local_llm_model,
            "local_llm_timeout": ai_settings.local_llm_timeout,
        }
        
        # Merge with any provided config overrides
        config.update(self.config)
        
        return config
    
    def _perform_enhanced_ai_analysis(self, 
                                    tool_capabilities: ToolCapabilities,
                                    environment_context: EnvironmentContext,
                                    analysis_type: str) -> ThreatAnalysis:
        """Perform AI-powered threat analysis using enhanced prompt system."""
        # Check cost limits
        request = AnalysisRequest(
            tool_capabilities=tool_capabilities,
            environment_context=environment_context,
            analysis_type=analysis_type
        )
        
        estimated_cost = self.ai_provider.estimate_cost(request)
        
        if estimated_cost > self.settings.ai.max_cost_per_analysis:
            logger.warning(f"Analysis cost ${estimated_cost:.4f} exceeds limit ${self.settings.ai.max_cost_per_analysis:.4f}")
            raise ValueError(f"Analysis cost exceeds limit: ${estimated_cost:.4f}")
        
        # Build appropriate prompt based on analysis type
        prompt_data = self._build_analysis_prompt(tool_capabilities, environment_context, analysis_type)
        
        # Add prompt data to request
        request.prompt_data = prompt_data
        request.max_tokens = prompt_data["max_tokens"]
        request.temperature = prompt_data["temperature"]
        
        return self._execute_ai_analysis_request(request)
        
    def _build_analysis_prompt(self,
                              tool_capabilities: ToolCapabilities,
                              environment_context: EnvironmentContext,
                              analysis_type: str) -> Dict[str, Any]:
        """Build appropriate prompt based on analysis type."""
        if analysis_type == "comprehensive":
            return self.prompt_engine.build_comprehensive_prompt(tool_capabilities, environment_context)
        elif analysis_type == "quick_assessment":
            return self.prompt_engine.build_capability_analysis_prompt(tool_capabilities, environment_context)
        elif analysis_type == "context_aware":
            return self.prompt_engine.build_context_aware_prompt(tool_capabilities, environment_context)
        else:
            logger.warning(f"Unknown analysis type: {analysis_type}, using comprehensive")
            return self.prompt_engine.build_comprehensive_prompt(tool_capabilities, environment_context)
    
    def _execute_ai_analysis_request(self, request: AnalysisRequest) -> ThreatAnalysis:
        """Execute AI analysis request with fallback handling."""
        # Attempt primary AI provider
        try:
            response = self.ai_provider.generate_threat_analysis(request)
            
            if response.error:
                raise Exception(response.error)
            
            if response.parsed_analysis:
                return response.parsed_analysis
            else:
                logger.warning("AI provider returned response but parsing failed")
                
        except Exception as e:
            logger.error(f"Primary AI provider failed: {e}")
            self.stats["ai_failures"] += 1
            
            # Try fallback provider if available
            if self.fallback_provider:
                logger.info("Attempting fallback AI provider")
                try:
                    response = self.fallback_provider.generate_threat_analysis(request)
                    if response.parsed_analysis:
                        return response.parsed_analysis
                except Exception as fallback_error:
                    logger.error(f"Fallback AI provider also failed: {fallback_error}")
        
        # If all AI providers fail, create rule-based analysis
        logger.warning("All AI providers failed, falling back to rule-based analysis")
        return self._create_rule_based_analysis(
            request.tool_capabilities, 
            request.environment_context
        )
    
    def _create_rule_based_analysis(self, 
                                  tool_capabilities: ToolCapabilities,
                                  environment_context: EnvironmentContext) -> ThreatAnalysis:
        """Create enhanced rule-based threat analysis with detailed attack scenarios for known MCP tools."""
        tool_name = tool_capabilities.tool_name.lower()
        
        # Enhanced attack scenarios for specific MCP tools
        attack_vectors = self._generate_enhanced_attack_vectors(tool_name, tool_capabilities)
        abuse_scenarios = self._generate_enhanced_abuse_scenarios(tool_name, tool_capabilities)
        mitigation_strategies = self._generate_enhanced_mitigations(tool_name, tool_capabilities)
        detection_indicators = self._generate_enhanced_detection_indicators(tool_name, tool_capabilities)
        
        # Determine threat level based on tool type and capabilities
        threat_level = self._calculate_enhanced_threat_level(tool_name, tool_capabilities)
        
        return ThreatAnalysis(
            tool_signature=tool_capabilities.tool_id,
            tool_capabilities=tool_capabilities,
            environment_context=environment_context,
            threat_level=threat_level,
            attack_vectors=attack_vectors,
            abuse_scenarios=abuse_scenarios,
            mitigation_strategies=mitigation_strategies,
            detection_indicators=detection_indicators,
            compliance_impact=ComplianceImpact(
                affected_frameworks=[ComplianceFramework.SOC2_TYPE_II, ComplianceFramework.ISO_27001],
                violation_risk=threat_level,
                required_controls=["Access controls", "Monitoring", "Incident response"]
            ),
            confidence_score=0.7,  # Higher confidence for enhanced rule-based analysis
            analysis_metadata=AnalysisMetadata(
                provider="enhanced_rule_based",
                model="hawkeye_internal",
                timestamp=datetime.now(),
                analysis_duration=0.1,
                cost=0.0,
                confidence_score=0.7
            )
        )
    
    def _generate_enhanced_attack_vectors(self, tool_name: str, tool_capabilities: ToolCapabilities) -> List[AttackVector]:
        """Generate detailed attack vectors based on detected MCP tool capabilities."""
        attack_vectors = []
        
        # Analyze capabilities to determine potential attack vectors
        capability_categories = [cat.value.lower() for cat in tool_capabilities.capability_categories]
        tools_available = [func.name.lower() for func in tool_capabilities.tool_functions] if tool_capabilities.tool_functions else []
        
        # Generate attack vectors based on detected capabilities, not hard-coded tool names
        if any('network' in cat or 'web' in cat or 'http' in cat for cat in capability_categories) or \
           any('search' in tool or 'web' in tool for tool in tools_available):
            attack_vectors.append(AttackVector(
                name="Information Reconnaissance",
                severity=SeverityLevel.HIGH,
                description="Attacker uses web/network capabilities to gather intelligence about targets",
                attack_steps=[
                    "Gain access to AI assistant with network-enabled MCP server",
                    "Use available tools to research target organization",
                    "Search for employee information, technologies, vulnerabilities", 
                    "Gather intelligence for social engineering attacks",
                    "Map attack surface using available information sources"
                ],
                example_code="""# Example reconnaissance using detected capabilities
# Note: Actual implementation depends on specific MCP tools detected
results = await mcp_tool.execute("research", {"target": "organization.com"})
# Process results for intelligence gathering""",
                prerequisites=["Access to AI assistant", "Network-enabled MCP server"],
                impact="Organizational intelligence gathering",
                likelihood=0.7
            ))
        
        if any('file' in cat or 'filesystem' in cat for cat in capability_categories) or \
           any('file' in tool or 'read' in tool or 'write' in tool for tool in tools_available):
            attack_vectors.extend([
                AttackVector(
                    name="Data Exfiltration",
                    severity=SeverityLevel.CRITICAL,
                    description="Steal sensitive files and data through filesystem access",
                    attack_steps=[
                        "Gain access to AI assistant with file system capabilities",
                        "Map accessible directories and file structure",
                        "Identify sensitive files (configs, credentials, source code)",
                        "Extract valuable data and intellectual property",
                        "Exfiltrate data through available channels"
                    ],
                    example_code="""# Example file system exploitation
# Note: Actual commands depend on detected MCP tool capabilities  
file_list = await mcp_tool.execute("list_files", {"path": "/sensitive"})
for file_path in file_list:
    content = await mcp_tool.execute("read_file", {"path": file_path})
    # Process and exfiltrate sensitive content""",
                    prerequisites=["AI assistant access", "File system MCP server"],
                    impact="Data breach and intellectual property theft",
                    likelihood=0.8
                ),
                AttackVector(
                    name="Malicious File Modification",
                    severity=SeverityLevel.HIGH,
                    description="Modify files to inject malicious content or create backdoors",
                    attack_steps=[
                        "Identify writable files and directories",
                        "Locate critical system or application files",
                        "Inject malicious code or backdoors",
                        "Modify configuration files to weaken security",
                        "Ensure persistence and avoid detection"
                    ],
                    example_code="""# Example malicious file modification
# Note: Educational example - actual implementation varies by MCP tool
original_content = await mcp_tool.execute("read_file", {"path": "app.py"})
malicious_content = original_content + "\\n# Hidden backdoor code"
await mcp_tool.execute("write_file", {"path": "app.py", "content": malicious_content})""",
                    prerequisites=["Write access to file system", "Knowledge of file structure"],
                    impact="System compromise and persistent access",
                    likelihood=0.6
                )
            ])
        
        if any('code' in cat or 'execution' in cat for cat in capability_categories) or \
           any('exec' in tool or 'run' in tool or 'command' in tool for tool in tools_available):
            attack_vectors.append(AttackVector(
                name="Command Injection",
                severity=SeverityLevel.CRITICAL,
                description="Execute arbitrary commands through code execution capabilities",
                attack_steps=[
                    "Identify command execution interfaces in MCP tools",
                    "Craft malicious payloads to inject commands",
                    "Execute commands to gain system access",
                    "Escalate privileges where possible", 
                    "Establish persistent access to the system"
                ],
                example_code="""# Example command injection
# Note: Educational example showing potential attack pattern
payload = "legitimate_command; malicious_command"
result = await mcp_tool.execute("run_command", {"command": payload})
# Attacker gains command execution on host system""",
                prerequisites=["Access to command execution interface"],
                impact="Full system compromise",
                likelihood=0.9
            ))
        
        # Add generic security analysis if no specific capabilities detected
        if not attack_vectors:
            attack_vectors.append(AttackVector(
                name="MCP Tool Security Analysis",
                severity=SeverityLevel.MEDIUM,
                description="General security concerns with detected MCP tool",
                attack_steps=[
                    "Analyze MCP tool interfaces and capabilities",
                    "Identify potential input validation issues",
                    "Test for authorization bypass vulnerabilities",
                    "Attempt privilege escalation through tool misuse",
                    "Evaluate data exposure risks"
                ],
                example_code="""# Generic MCP tool security testing
# Note: Approach varies based on specific tool capabilities
tool_info = await mcp_tool.get_capabilities()
for capability in tool_info:
    # Test each capability for security issues
    test_result = await security_test(capability)""",
                prerequisites=["Access to MCP tool interface"],
                impact="Varies based on tool capabilities and vulnerabilities",
                likelihood=0.5
            ))
        
        return attack_vectors
        
    def _generate_enhanced_abuse_scenarios(self, tool_name: str, tool_capabilities: ToolCapabilities) -> List[AbuseScenario]:
        """Generate detailed abuse scenarios based on detected MCP tool capabilities."""
        scenarios = []
        
        # Analyze capabilities to determine potential abuse scenarios
        capability_categories = [cat.value.lower() for cat in tool_capabilities.capability_categories]
        tools_available = [func.name.lower() for func in tool_capabilities.tool_functions] if tool_capabilities.tool_functions else []
        
        # Generate scenarios based on detected capabilities
        has_network_access = any('network' in cat or 'web' in cat or 'http' in cat for cat in capability_categories) or \
                           any('search' in tool or 'web' in tool for tool in tools_available)
        
        has_file_access = any('file' in cat or 'filesystem' in cat for cat in capability_categories) or \
                         any('file' in tool or 'read' in tool or 'write' in tool for tool in tools_available)
        
        has_execution_capability = any('code' in cat or 'execution' in cat for cat in capability_categories) or \
                                 any('exec' in tool or 'run' in tool or 'command' in tool for tool in tools_available)
        
        if has_network_access or has_file_access or has_execution_capability:
            scenarios.append(AbuseScenario(
                scenario_name="Data Reconnaissance and Exfiltration",
                threat_actor=ThreatActorType.EXTERNAL_ATTACKER,
                motivation="Gather sensitive information and extract valuable data",
                attack_flow=[
                    AttackStep(1, "Gain access to AI assistant with MCP tool capabilities", [], []),
                    AttackStep(2, "Enumerate available tools and their capabilities", [], []),
                    AttackStep(3, "Identify sensitive data sources and access points", [], []),
                    AttackStep(4, "Extract and exfiltrate valuable information", [], [])
                ],
                required_access=AccessLevel.USER,
                detection_difficulty=DifficultyLevel.MEDIUM,
                business_impact=BusinessImpact(
                    financial_impact="High - potential data breach costs",
                    operational_impact="Medium - incident response required",
                    reputation_impact="High - customer trust impact"
                )
            ))
        
        if has_file_access or has_execution_capability:
            scenarios.append(AbuseScenario(
                scenario_name="System Compromise via MCP Tool Abuse",
                threat_actor=ThreatActorType.INSIDER_THREAT,
                motivation="Gain unauthorized system access and establish persistence",
                attack_flow=[
                    AttackStep(1, "Abuse legitimate MCP tool access", [], []),
                    AttackStep(2, "Explore system directories and files", [], []),
                    AttackStep(3, "Modify critical files or execute malicious code", [], []),
                    AttackStep(4, "Establish backdoors for persistent access", [], [])
                ],
                required_access=AccessLevel.ADMIN,
                detection_difficulty=DifficultyLevel.LOW,
                business_impact=BusinessImpact(
                    financial_impact="Critical - system compromise costs",
                    operational_impact="Critical - business disruption",
                    reputation_impact="Critical - security breach disclosure"
                )
            ))
        
        return scenarios
    
    def _generate_enhanced_mitigations(self, tool_name: str, tool_capabilities: ToolCapabilities) -> List[MitigationStrategy]:
        """Generate detailed mitigation strategies based on detected MCP tool capabilities."""
        strategies = []
        
        # Analyze capabilities to determine appropriate mitigations
        capability_categories = [cat.value.lower() for cat in tool_capabilities.capability_categories]
        tools_available = [func.name.lower() for func in tool_capabilities.tool_functions] if tool_capabilities.tool_functions else []
        
        # Network/Web access mitigations
        if any('network' in cat or 'web' in cat or 'http' in cat for cat in capability_categories) or \
           any('search' in tool or 'web' in tool for tool in tools_available):
            strategies.extend([
                MitigationStrategy(
                    name="Network Access Controls",
                    description="Implement strict controls on network-enabled MCP tool capabilities",
                    implementation_steps=[
                        "Configure allowlist of permitted domains and endpoints",
                        "Implement comprehensive request logging and monitoring",
                        "Set rate limits and quotas on network requests",
                        "Review and audit all external network communications"
                    ],
                    effectiveness_score=0.8
                ),
                MitigationStrategy(
                    name="Data Sanitization and Filtering",
                    description="Filter and sanitize data retrieved through network access",
                    implementation_steps=[
                        "Implement content filtering for sensitive information",
                        "Block access to unauthorized data sources",
                        "Sanitize retrieved data before processing",
                        "Log all data retrieval for compliance audit"
                    ],
                    effectiveness_score=0.7
                )
            ])
        
        # File system access mitigations
        if any('file' in cat or 'filesystem' in cat for cat in capability_categories) or \
           any('file' in tool or 'read' in tool or 'write' in tool for tool in tools_available):
            strategies.extend([
                MitigationStrategy(
                    name="File System Access Controls",
                    description="Implement strict filesystem access controls for MCP tools",
                    implementation_steps=[
                        "Use principle of least privilege - read-only where possible",
                        "Implement comprehensive file access logging",
                        "Restrict access to sensitive directories and files",
                        "Use sandboxing, containerization, and chroot jails"
                    ],
                    effectiveness_score=0.9
                ),
                MitigationStrategy(
                    name="File Integrity Monitoring",
                    description="Monitor for unauthorized file system changes",
                    implementation_steps=[
                        "Implement real-time file integrity monitoring",
                        "Use version control systems for all file changes",
                        "Require approval workflows for file modifications",
                        "Set up automated alerts for unexpected file changes"
                    ],
                    effectiveness_score=0.8
                )
            ])
        
        # Code execution mitigations
        if any('code' in cat or 'execution' in cat for cat in capability_categories) or \
           any('exec' in tool or 'run' in tool or 'command' in tool for tool in tools_available):
            strategies.append(MitigationStrategy(
                name="Command Execution Controls",
                description="Control and monitor command execution capabilities",
                implementation_steps=[
                    "Implement command allowlisting and validation",
                    "Use secure execution environments (containers/VMs)",
                    "Monitor all command executions and their outputs",
                    "Implement resource limits and execution timeouts"
                ],
                effectiveness_score=0.9
            ))
        
        # Generic security controls for all MCP tools
        strategies.extend([
            MitigationStrategy(
                name="MCP Tool Security Baseline",
                description="Implement baseline security controls for MCP tool deployment",
                implementation_steps=[
                    "Regular security assessments and penetration testing",
                    "Implement comprehensive logging and monitoring",
                    "Apply principle of least privilege for all access",
                    "Establish incident response procedures for MCP tool abuse",
                    "Regular security updates and patch management"
                ],
                effectiveness_score=0.7
            ),
            MitigationStrategy(
                name="Access Management and Authentication",
                description="Strong authentication and authorization for MCP tool access",
                implementation_steps=[
                    "Implement multi-factor authentication",
                    "Use role-based access control (RBAC)",
                    "Regular access reviews and privilege auditing",
                    "Session management and timeout controls"
                ],
                effectiveness_score=0.8
            )
        ])
        
        return strategies
    
    def _generate_enhanced_detection_indicators(self, tool_name: str, tool_capabilities: ToolCapabilities) -> List[DetectionIndicator]:
        """Generate detailed detection indicators based on detected MCP tool capabilities."""
        indicators = []
        
        # Analyze capabilities to determine appropriate detection indicators
        capability_categories = [cat.value.lower() for cat in tool_capabilities.capability_categories]
        tools_available = [func.name.lower() for func in tool_capabilities.tool_functions] if tool_capabilities.tool_functions else []
        
        # Network/Web access indicators
        if any('network' in cat or 'web' in cat or 'http' in cat for cat in capability_categories) or \
           any('search' in tool or 'web' in tool for tool in tools_available):
            indicators.extend([
                DetectionIndicator(
                    indicator_name="Unusual Network Request Patterns",
                    indicator_type="network_monitoring",
                    pattern="High volume or suspicious patterns in network requests",
                    confidence=0.8
                ),
                DetectionIndicator(
                    indicator_name="Unauthorized Data Retrieval",
                    indicator_type="data_access_monitoring", 
                    pattern="Access to external data sources outside normal usage patterns",
                    confidence=0.7
                )
            ])
        
        # File system access indicators
        if any('file' in cat or 'filesystem' in cat for cat in capability_categories) or \
           any('file' in tool or 'read' in tool or 'write' in tool for tool in tools_available):
            indicators.extend([
                DetectionIndicator(
                    indicator_name="Abnormal File System Activity",
                    indicator_type="filesystem_monitoring",
                    pattern="Access to sensitive files or directories outside normal patterns",
                    confidence=0.9
                ),
                DetectionIndicator(
                    indicator_name="File Modification Attempts",
                    indicator_type="file_integrity_monitoring",
                    pattern="Unauthorized modifications to critical system or application files",
                    confidence=0.8
                )
            ])
        
        # Code execution indicators
        if any('code' in cat or 'execution' in cat for cat in capability_categories) or \
           any('exec' in tool or 'run' in tool or 'command' in tool for tool in tools_available):
            indicators.extend([
                DetectionIndicator(
                    indicator_name="Suspicious Command Execution",
                    indicator_type="command_monitoring",
                    pattern="Execution of unusual or potentially malicious commands",
                    confidence=0.9
                ),
                DetectionIndicator(
                    indicator_name="Privilege Escalation Attempts",
                    indicator_type="privilege_monitoring",
                    pattern="Attempts to escalate privileges through command execution",
                    confidence=0.8
                )
            ])
        
        # Generic MCP tool indicators
        indicators.extend([
            DetectionIndicator(
                indicator_name="MCP Tool Abuse Patterns",
                indicator_type="usage_monitoring",
                pattern="Unusual usage patterns or frequency of MCP tool interactions",
                confidence=0.6
            ),
            DetectionIndicator(
                indicator_name="Authentication and Session Anomalies", 
                indicator_type="authentication_monitoring",
                pattern="Unusual authentication patterns or session management issues",
                confidence=0.7
            )
        ])
        
        return indicators
    
    def _calculate_enhanced_threat_level(self, tool_name: str, tool_capabilities: ToolCapabilities) -> ThreatLevel:
        """Calculate threat level based on detected MCP tool capabilities."""
        # Analyze capabilities to determine threat level
        capability_categories = [cat.value.lower() for cat in tool_capabilities.capability_categories]
        tools_available = [tool.name.lower() for tool in tool_capabilities.server_info.tools] if tool_capabilities.server_info.tools else []
        
        threat_score = 0
        
        # High-risk capabilities that significantly increase threat score
        high_risk_capabilities = [
            ('file', 'filesystem', 'write', 'modify'), # File system access
            ('code', 'execution', 'exec', 'command', 'run'), # Code execution
            ('admin', 'root', 'system', 'privilege') # Administrative access
        ]
        
        # Medium-risk capabilities
        medium_risk_capabilities = [
            ('network', 'web', 'http', 'search'), # Network access
            ('read', 'access', 'data'), # Data access
            ('database', 'db', 'sql') # Database access
        ]
        
        # Check capabilities against risk categories
        for risk_group in high_risk_capabilities:
            if any(risk_term in cat for cat in capability_categories for risk_term in risk_group) or \
               any(risk_term in tool for tool in tools_available for risk_term in risk_group):
                threat_score += 3
                
        for risk_group in medium_risk_capabilities:
            if any(risk_term in cat for cat in capability_categories for risk_term in risk_group) or \
               any(risk_term in tool for tool in tools_available for risk_term in risk_group):
                threat_score += 1
        
        # Factor in overall risk score from tool capabilities
        if hasattr(tool_capabilities, 'risk_surface') and tool_capabilities.risk_surface:
            base_risk = tool_capabilities.risk_surface.risk_score
            if base_risk >= 0.8:
                threat_score += 2
            elif base_risk >= 0.6:
                threat_score += 1
        
        # Determine threat level based on calculated score
        if threat_score >= 5:
            return ThreatLevel.CRITICAL
        elif threat_score >= 3:
            return ThreatLevel.HIGH
        elif threat_score >= 1:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _post_process_analysis(self, 
                             analysis: ThreatAnalysis,
                             tool_capabilities: ToolCapabilities) -> ThreatAnalysis:
        """Post-process analysis results for consistency and completeness."""
        # Ensure tool_signature matches
        analysis.tool_signature = tool_capabilities.tool_id
        
        # Validate threat level consistency
        if len(analysis.attack_vectors) == 0 and analysis.threat_level == ThreatLevel.CRITICAL:
            logger.warning("Downgrading threat level due to lack of attack vectors")
            analysis.threat_level = ThreatLevel.MEDIUM
        
        # Ensure minimum mitigation strategies
        if len(analysis.mitigation_strategies) == 0:
            analysis.mitigation_strategies.append(
                MitigationStrategy(
                    name="General Security Hardening",
                    description="Apply general security best practices",
                    implementation_steps=[
                        "Enable logging and monitoring",
                        "Apply principle of least privilege",
                        "Regular security updates"
                    ],
                    effectiveness_score=0.7
                )
            )
        
        return analysis
    
    def _create_fallback_analysis(self, 
                                mcp_server: MCPServerInfo,
                                tool_capabilities: Optional[ToolCapabilities],
                                environment_context: Optional[EnvironmentContext],
                                analysis_type: str) -> ThreatAnalysis:
        """Create minimal fallback analysis when everything fails."""
        tool_name = mcp_server.metadata.get('name', mcp_server.server_id)
        if tool_capabilities is None:
            tool_capabilities = ToolCapabilities(
                tool_name=tool_name,
                tool_id=f"{tool_name}:fallback",
                server_info=mcp_server,
                confidence_score=0.1
            )
        
        if environment_context is None:
            environment_context = EnvironmentContext()
        
        return ThreatAnalysis(
            tool_signature=tool_capabilities.tool_id,
            tool_capabilities=tool_capabilities,
            environment_context=environment_context,
            threat_level=ThreatLevel.MEDIUM,
            attack_vectors=[],  # No attack vectors in fallback analysis
            abuse_scenarios=[],  # No abuse scenarios in fallback analysis
            mitigation_strategies=[],  # No mitigation strategies in fallback analysis
            detection_indicators=[],  # No detection indicators in fallback analysis
            compliance_impact=ComplianceImpact(
                affected_frameworks=[],
                violation_risk=ThreatLevel.LOW,
                required_controls=[]
            ),
            confidence_score=0.1,
            analysis_metadata=AnalysisMetadata(
                                                        provider="fallback",
                    model="minimal",
                    timestamp=datetime.now(),
                    analysis_duration=0.05,
                    cost=0.0,
                confidence_score=0.1
            )
        )
    
    def _generate_cache_key(self, 
                          tool_capabilities: ToolCapabilities,
                          environment_context: EnvironmentContext,
                          analysis_type: str) -> str:
        """Generate cache key for analysis results."""
        # Create hash of relevant analysis inputs
        import hashlib
        
        key_components = [
            tool_capabilities.tool_name,
            str(sorted([c.value for c in tool_capabilities.capability_categories])),
            str(tool_capabilities.risk_surface.risk_score),
            environment_context.deployment_type.value,
            environment_context.security_posture.value,
            environment_context.network_exposure.value,
            analysis_type
        ]
        
        key_string = "|".join(key_components)
        return hashlib.md5(key_string.encode()).hexdigest() 

    def analyze_threats_streaming(self, 
                                mcp_servers: List[MCPServerInfo],
                                environment_context: Optional[EnvironmentContext] = None,
                                analysis_type: str = "comprehensive",
                                progress_callback: Optional[Callable] = None,
                                **kwargs):
        """
        Stream threat analysis results as they complete (Phase 4 compatibility method).
        
        This is a minimal implementation for Phase 3 completion that yields
        results from the existing analyze_threats method.
        """
        try:
            for i, server in enumerate(mcp_servers):
                # Call existing analyze_threats method
                analysis = self.analyze_threats(server, environment_context)
                
                # Yield streaming event
                event = {
                    "type": "result",
                    "server_id": server.server_id,
                    "analysis": analysis,
                    "progress": (i + 1) / len(mcp_servers),
                    "timestamp": datetime.now()
                }
                yield event
                
                if progress_callback:
                    progress_callback(i + 1, len(mcp_servers), server.server_id)
                    
        except Exception as e:
            yield {
                "type": "error",
                "error": str(e),
                "timestamp": datetime.now()
            }

    def analyze_single_tool_streaming(self,
                                    mcp_server: MCPServerInfo,
                                    environment_context: Optional[EnvironmentContext] = None,
                                    analysis_type: str = "comprehensive",
                                    progress_callback: Optional[Callable] = None,
                                    **kwargs):
        """
        Stream detailed analysis stages for a single tool (Phase 4 compatibility method).
        
        This is a minimal implementation that yields stage-by-stage progress.
        """
        try:
            # Yield initialization event
            yield {
                "type": "initialization",
                "server_id": mcp_server.server_id,
                "message": f"Starting analysis of {mcp_server.server_id}",
                "timestamp": datetime.now()
            }
            
            # Yield progress event
            yield {
                "type": "progress", 
                "server_id": mcp_server.server_id,
                "stage": "capability_analysis",
                "progress": 0.5,
                "timestamp": datetime.now()
            }
            
            # Call existing analyze_threats method
            analysis = self.analyze_threats(mcp_server, environment_context)
            
            # Yield final result
            yield {
                "type": "result",
                "server_id": mcp_server.server_id,
                "analysis": analysis,
                "progress": 1.0,
                "timestamp": datetime.now()
            }
            
            if progress_callback:
                progress_callback(1, 1, mcp_server.server_id)
                
        except Exception as e:
            yield {
                "type": "error",
                "server_id": mcp_server.server_id,
                "error": str(e),
                "timestamp": datetime.now()
            }

    def analyze_threats_batch_streaming(self,
                                      mcp_servers: List[MCPServerInfo],
                                      batch_size: int = 5,
                                      environment_context: Optional[EnvironmentContext] = None,
                                      delay_between_batches: float = 0.1,
                                      progress_callback: Optional[Callable] = None,
                                      **kwargs):
        """
        Stream batch analysis results with resource management (Phase 4 compatibility method).
        
        This is a minimal implementation that uses existing batch_optimized method.
        """
        try:
            # Call existing batch optimized method
            results = self.analyze_threats_batch_optimized(
                mcp_servers=mcp_servers,
                adaptive_sizing=True,
                target_batch_time=30.0,
                min_batch_size=min(batch_size, len(mcp_servers)),
                max_batch_size=batch_size,
                enable_load_balancing=True,
                progress_callback=progress_callback
            )
            
            # Stream the results
            for i, (server_id, analysis) in enumerate(results.items()):
                yield {
                    "type": "result",
                    "server_id": server_id,
                    "analysis": analysis,
                    "batch_progress": (i + 1) / len(results),
                    "timestamp": datetime.now()
                }
                
        except Exception as e:
            yield {
                "type": "error", 
                "error": str(e),
                "timestamp": datetime.now()
            }
    
    # Memory Optimization and Performance Monitoring Methods (F4.4 & F4.5)
    
    def get_memory_status(self) -> Dict[str, Any]:
        """Get comprehensive memory status and optimization statistics."""
        try:
            return {
                "current_usage": self.memory_optimizer.get_current_memory_usage(),
                "optimization_stats": self.memory_optimizer.get_optimization_statistics(),
                "cache_stats": self.cache.get_stats(),
                "memory_warnings": self.stats["memory_warnings"],
                "memory_cleanups": self.stats["memory_cleanups"]
            }
        except Exception as e:
            logger.error(f"Error getting memory status: {e}")
            return {"error": str(e)}
    
    def get_response_time_statistics(self) -> Dict[str, Any]:
        """Get comprehensive response time statistics."""
        try:
            return self.response_monitor.get_statistics()
        except Exception as e:
            logger.error(f"Error getting response time statistics: {e}")
            return {"error": str(e)}
    
    def force_memory_cleanup(self) -> Dict[str, Any]:
        """Force comprehensive memory cleanup and return statistics."""
        try:
            logger.info("Forcing memory cleanup for threat analyzer")
            
            # Clear cache
            cache_cleared = len(self.cache.cache)
            self.cache.clear()
            
            # Force memory optimizer cleanup
            cleanup_stats = self.memory_optimizer.force_cleanup()
            
            # Update statistics
            self.stats["memory_cleanups"] += 1
            
            total_stats = {
                "cache_entries_cleared": cache_cleared,
                "memory_cleanup": cleanup_stats,
                "cleanup_timestamp": time.time()
            }
            
            logger.info(f"Memory cleanup completed: {total_stats}")
            return total_stats
            
        except Exception as e:
            logger.error(f"Error during memory cleanup: {e}")
            return {"error": str(e)}
    
    def adjust_memory_thresholds(self, warning_mb: int, cleanup_mb: int, max_memory_mb: int) -> None:
        """Adjust memory optimization thresholds."""
        try:
            self.memory_optimizer.config.warning_threshold_mb = warning_mb
            self.memory_optimizer.config.cleanup_threshold_mb = cleanup_mb
            self.memory_optimizer.config.max_memory_mb = max_memory_mb
            
            logger.info(f"Memory thresholds updated: warning={warning_mb}MB, cleanup={cleanup_mb}MB, max={max_memory_mb}MB")
        except Exception as e:
            logger.error(f"Error adjusting memory thresholds: {e}")
    
    def adjust_response_time_thresholds(self, warning_seconds: float, alert_seconds: float) -> None:
        """Adjust response time monitoring thresholds."""
        try:
            self.response_monitor.adjust_thresholds(warning_seconds, alert_seconds)
        except Exception as e:
            logger.error(f"Error adjusting response time thresholds: {e}")
    
    def get_performance_health_report(self) -> Dict[str, Any]:
        """Get comprehensive performance and health report."""
        try:
            memory_status = self.get_memory_status()
            response_stats = self.get_response_time_statistics()
            
            # Calculate overall health score
            memory_health = self._assess_memory_health(memory_status)
            response_health = response_stats.get('performance_health', 'unknown')
            
            # Combine health assessments
            if memory_health == 'excellent' and response_health == 'excellent':
                overall_health = 'excellent'
            elif memory_health in ['excellent', 'good'] and response_health in ['excellent', 'good']:
                overall_health = 'good'
            elif memory_health in ['good', 'fair'] and response_health in ['good', 'fair']:
                overall_health = 'fair'
            else:
                overall_health = 'poor'
            
            return {
                "overall_health": overall_health,
                "memory_health": memory_health,
                "response_time_health": response_health,
                "memory_status": memory_status,
                "response_statistics": response_stats,
                "recommendations": self._generate_performance_recommendations(memory_status, response_stats),
                "report_timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Error generating performance health report: {e}")
            return {"error": str(e)}
    
    def _assess_memory_health(self, memory_status: Dict[str, Any]) -> str:
        """Assess memory health based on current status."""
        try:
            current_usage = memory_status.get('current_usage', {})
            memory_pressure = current_usage.get('memory_pressure', 'unknown')
            memory_warnings = self.stats.get('memory_warnings', 0)
            memory_cleanups = self.stats.get('memory_cleanups', 0)
            
            if memory_pressure == 'low' and memory_warnings == 0 and memory_cleanups <= 1:
                return 'excellent'
            elif memory_pressure in ['low', 'medium'] and memory_warnings <= 2 and memory_cleanups <= 3:
                return 'good'
            elif memory_pressure in ['medium', 'high'] and memory_warnings <= 5 and memory_cleanups <= 5:
                return 'fair'
            else:
                return 'poor'
                
        except Exception:
            return 'unknown'
    
    def _generate_performance_recommendations(self, memory_status: Dict[str, Any], 
                                           response_stats: Dict[str, Any]) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []
        
        try:
            # Memory recommendations
            current_usage = memory_status.get('current_usage', {})
            memory_pressure = current_usage.get('memory_pressure', 'unknown')
            
            if memory_pressure == 'critical':
                recommendations.append("Critical: Reduce memory usage immediately - consider increasing cleanup frequency")
            elif memory_pressure == 'high':
                recommendations.append("High memory usage detected - consider enabling aggressive memory optimization")
            
            if self.stats.get('memory_warnings', 0) > 5:
                recommendations.append("Frequent memory warnings - consider reducing batch sizes or cache limits")
            
            # Response time recommendations
            response_health = response_stats.get('performance_health', 'unknown')
            overall_stats = response_stats.get('overall', {})
            
            if response_health == 'poor':
                recommendations.append("Poor response times - consider using faster AI provider or reducing analysis complexity")
            elif overall_stats.get('avg', 0) > 20:
                recommendations.append("High average response times - consider enabling caching or using parallel processing")
            
            slow_ops_ratio = response_stats.get('slow_operations_ratio', 0)
            if slow_ops_ratio > 0.2:
                recommendations.append("High ratio of slow operations - investigate specific bottlenecks")
            
            # Cache recommendations
            cache_stats = memory_status.get('cache_stats', {})
            cache_size = cache_stats.get('cache_size', 0)
            
            if cache_size == 0 and self.settings.ai.cache_enabled:
                recommendations.append("Cache is empty - check if caching is working correctly")
            elif not self.settings.ai.cache_enabled and self.stats.get('analyses_performed', 0) > 10:
                recommendations.append("Consider enabling caching to improve performance for repeated analyses")
            
            if not recommendations:
                recommendations.append("System performance is optimal - no immediate recommendations")
                
        except Exception as e:
            recommendations.append(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def shutdown_optimization(self) -> None:
        """Properly shutdown memory optimization and monitoring."""
        try:
            logger.info("Shutting down AI threat analyzer optimization")
            
            # Stop memory optimization
            self.memory_optimizer.stop_optimization()
            
            # Clear response time monitoring
            self.response_monitor.clear_statistics()
            
            # Clear cache
            self.cache.clear()
            
            logger.info("AI threat analyzer optimization shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during optimization shutdown: {e}")


class AdvancedThreatAnalysisPipeline:
    """
    Advanced threat analysis pipeline for coordinating multi-stage AI analysis workflows.
    
    This pipeline orchestrates complex threat analysis scenarios including:
    - Multi-stage analysis workflows
    - Context-aware threat modeling
    - Attack chain analysis across multiple tools
    - Comprehensive result aggregation and enhancement
    """
    
    def __init__(self, threat_analyzer: AIThreatAnalyzer, config: Optional[Dict[str, Any]] = None):
        """
        Initialize advanced threat analysis pipeline.
        
        Args:
            threat_analyzer: AI threat analyzer instance
            config: Optional pipeline configuration
        """
        self.threat_analyzer = threat_analyzer
        self.config = config or {}
        self.settings = get_settings()
        
        # Pipeline configuration
        self.max_concurrent_analyses = self.config.get("max_concurrent_analyses", 3)
        self.enable_context_enhancement = self.config.get("enable_context_enhancement", True)
        self.enable_attack_chain_analysis = self.config.get("enable_attack_chain_analysis", True)
        self.enable_comprehensive_analysis = self.config.get("enable_comprehensive_analysis", True)
        
        # Pipeline statistics
        self.pipeline_stats = {
            "pipelines_executed": 0,
            "successful_pipelines": 0,
            "failed_pipelines": 0,
            "total_analysis_time": 0.0,
            "avg_pipeline_time": 0.0,
            "stage_performance": {
                "context_building": [],
                "individual_analysis": [],
                "attack_chain_analysis": [],
                "result_aggregation": []
            }
        }
        
        logger.info("Advanced Threat Analysis Pipeline initialized")
    
    def execute_comprehensive_analysis(self,
                                     mcp_servers: List[MCPServerInfo],
                                     environment_context: Optional[EnvironmentContext] = None,
                                     analysis_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute comprehensive multi-stage threat analysis pipeline.
        
        Args:
            mcp_servers: List of MCP servers to analyze
            environment_context: Optional pre-built environment context
            analysis_options: Optional analysis configuration
            
        Returns:
            Comprehensive analysis results
        """
        pipeline_start = time.time()
        self.pipeline_stats["pipelines_executed"] += 1
        options = analysis_options or {}
        
        try:
            logger.info(f"Starting comprehensive analysis pipeline for {len(mcp_servers)} servers")
            
            # Initialize pipeline result
            pipeline_result = {
                "pipeline_id": f"pipeline_{int(time.time())}",
                "start_time": datetime.now(),
                "servers_analyzed": len(mcp_servers),
                "stages_completed": [],
                "individual_analyses": {},
                "attack_chain_analyses": [],
                "enhanced_context": None,
                "aggregated_results": {},
                "pipeline_metrics": {},
                "errors": [],
                "warnings": []
            }
            
            # Stage 1: Context Enhancement and Building
            stage_start = time.time()
            if self.enable_context_enhancement:
                logger.debug("Stage 1: Building enhanced environment context")
                enhanced_context = self._build_enhanced_context(mcp_servers, environment_context, options)
                pipeline_result["enhanced_context"] = enhanced_context
                pipeline_result["stages_completed"].append("context_enhancement")
                
                stage_duration = time.time() - stage_start
                self.pipeline_stats["stage_performance"]["context_building"].append(stage_duration)
                logger.debug(f"Context enhancement completed in {stage_duration:.2f}s")
            else:
                enhanced_context = environment_context or self.threat_analyzer.capability_analyzer.build_environment_context(mcp_servers)
                pipeline_result["enhanced_context"] = enhanced_context
            
            # Stage 2: Individual Server Analysis
            stage_start = time.time()
            if self.enable_comprehensive_analysis:
                logger.debug("Stage 2: Performing individual server analyses")
                individual_results = self._execute_individual_analyses(
                    mcp_servers, 
                    enhanced_context, 
                    options
                )
                pipeline_result["individual_analyses"] = individual_results
                pipeline_result["stages_completed"].append("individual_analysis")
                
                stage_duration = time.time() - stage_start
                self.pipeline_stats["stage_performance"]["individual_analysis"].append(stage_duration)
                logger.debug(f"Individual analyses completed in {stage_duration:.2f}s")
            
            # Stage 3: Attack Chain Analysis
            stage_start = time.time()
            if self.enable_attack_chain_analysis and len(mcp_servers) > 1:
                logger.debug("Stage 3: Performing attack chain analysis")
                attack_chain_results = self._execute_attack_chain_analysis(
                    mcp_servers,
                    enhanced_context,
                    pipeline_result.get("individual_analyses", {}),
                    options
                )
                pipeline_result["attack_chain_analyses"] = attack_chain_results
                pipeline_result["stages_completed"].append("attack_chain_analysis")
                
                stage_duration = time.time() - stage_start
                self.pipeline_stats["stage_performance"]["attack_chain_analysis"].append(stage_duration)
                logger.debug(f"Attack chain analysis completed in {stage_duration:.2f}s")
            
            # Stage 4: Result Aggregation and Enhancement
            stage_start = time.time()
            logger.debug("Stage 4: Aggregating and enhancing results")
            aggregated_results = self._aggregate_and_enhance_results(pipeline_result, options)
            pipeline_result["aggregated_results"] = aggregated_results
            pipeline_result["stages_completed"].append("result_aggregation")
            
            stage_duration = time.time() - stage_start
            self.pipeline_stats["stage_performance"]["result_aggregation"].append(stage_duration)
            logger.debug(f"Result aggregation completed in {stage_duration:.2f}s")
            
            # Finalize pipeline result
            pipeline_duration = time.time() - pipeline_start
            pipeline_result["end_time"] = datetime.now()
            pipeline_result["duration"] = pipeline_duration
            pipeline_result["success"] = True
            
            # Update statistics
            self.pipeline_stats["successful_pipelines"] += 1
            self.pipeline_stats["total_analysis_time"] += pipeline_duration
            self._update_average_pipeline_time()
            
            logger.info(f"Comprehensive analysis pipeline completed successfully in {pipeline_duration:.2f}s")
            return pipeline_result
            
        except Exception as e:
            logger.error(f"Comprehensive analysis pipeline failed: {e}")
            pipeline_duration = time.time() - pipeline_start
            
            # Update error statistics
            self.pipeline_stats["failed_pipelines"] += 1
            self.pipeline_stats["total_analysis_time"] += pipeline_duration
            
            # Return error result
            pipeline_result["end_time"] = datetime.now()
            pipeline_result["duration"] = pipeline_duration
            pipeline_result["success"] = False
            pipeline_result["errors"].append(str(e))
            
            return pipeline_result
    
    def execute_workflow_analysis(self,
                                 mcp_servers: List[MCPServerInfo],
                                 workflow_type: str,
                                 workflow_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute specific analysis workflow type.
        
        Args:
            mcp_servers: List of MCP servers to analyze
            workflow_type: Type of workflow (e.g., 'security_audit', 'compliance_check', 'penetration_test')
            workflow_config: Workflow-specific configuration
            
        Returns:
            Workflow-specific analysis results
        """
        logger.info(f"Starting {workflow_type} workflow for {len(mcp_servers)} servers")
        
        try:
            if workflow_type == "security_audit":
                return self._execute_security_audit_workflow(mcp_servers, workflow_config)
            elif workflow_type == "compliance_check":
                return self._execute_compliance_workflow(mcp_servers, workflow_config)
            elif workflow_type == "penetration_test":
                return self._execute_penetration_test_workflow(mcp_servers, workflow_config)
            elif workflow_type == "risk_assessment":
                return self._execute_risk_assessment_workflow(mcp_servers, workflow_config)
            else:
                raise ValueError(f"Unknown workflow type: {workflow_type}")
                
        except Exception as e:
            logger.error(f"Workflow {workflow_type} failed: {e}")
            return {
                "workflow_type": workflow_type,
                "success": False,
                "error": str(e),
                "results": {}
            }
    
    def _build_enhanced_context(self,
                              mcp_servers: List[MCPServerInfo],
                              base_context: Optional[EnvironmentContext],
                              options: Dict[str, Any]) -> EnvironmentContext:
        """Build enhanced environment context with additional intelligence."""
        logger.debug("Building enhanced environment context")
        
        # Start with base context if provided
        if base_context:
            enhanced_context = base_context
        else:
            enhanced_context = self.threat_analyzer.capability_analyzer.build_environment_context(mcp_servers)
        
        # Enhance with additional intelligence
        try:
            # Analyze deployment patterns
            deployment_info = self._analyze_deployment_patterns(mcp_servers)
            
            # Enhance security posture assessment
            security_assessment = self._assess_security_posture(mcp_servers)
            
            # Update context with enhanced information
            if deployment_info.get("cloud_deployment_detected"):
                enhanced_context.deployment_type = DeploymentType.CLOUD
            elif deployment_info.get("hybrid_deployment_detected"):
                enhanced_context.deployment_type = DeploymentType.HYBRID
            
            # Adjust security posture based on analysis
            if security_assessment.get("high_security_indicators", 0) > 2:
                enhanced_context.security_posture = SecurityPosture.HIGH
            elif security_assessment.get("low_security_indicators", 0) > 2:
                enhanced_context.security_posture = SecurityPosture.LOW
            
            logger.debug("Enhanced context building completed successfully")
            
        except Exception as e:
            logger.warning(f"Context enhancement failed, using base context: {e}")
        
        return enhanced_context
    
    def _execute_individual_analyses(self,
                                   mcp_servers: List[MCPServerInfo],
                                   environment_context: EnvironmentContext,
                                   options: Dict[str, Any]) -> Dict[str, ThreatAnalysis]:
        """Execute individual threat analyses for each server."""
        results = {}
        
        for i, server in enumerate(mcp_servers):
            server_id = server.metadata.get('name', f'server_{i}')
            
            try:
                logger.debug(f"Analyzing individual server: {server_id}")
                
                # Determine analysis type based on options
                analysis_type = options.get("analysis_type", "comprehensive")
                
                # Perform analysis
                analysis = self.threat_analyzer.analyze_threats(
                    server,
                    environment_context,
                    analysis_type
                )
                
                results[server_id] = analysis
                logger.debug(f"Individual analysis completed for {server_id}")
                
            except Exception as e:
                logger.error(f"Individual analysis failed for {server_id}: {e}")
                # Continue with other servers
                continue
        
        return results
    
    def _execute_attack_chain_analysis(self,
                                     mcp_servers: List[MCPServerInfo],
                                     environment_context: EnvironmentContext,
                                     individual_results: Dict[str, ThreatAnalysis],
                                     options: Dict[str, Any]) -> List[ThreatAnalysis]:
        """Execute attack chain analysis across multiple servers."""
        attack_chain_results = []
        
        try:
            # Group servers for attack chain analysis
            server_groups = self._group_servers_for_attack_chains(mcp_servers, individual_results)
            
            for group_id, server_group in server_groups.items():
                try:
                    logger.debug(f"Analyzing attack chain for group: {group_id}")
                    
                    # Perform attack chain analysis
                    chain_analysis = self.threat_analyzer.analyze_attack_chains(
                        server_group,
                        environment_context
                    )
                    
                    attack_chain_results.append(chain_analysis)
                    logger.debug(f"Attack chain analysis completed for group: {group_id}")
                    
                except Exception as e:
                    logger.error(f"Attack chain analysis failed for group {group_id}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Attack chain analysis setup failed: {e}")
        
        return attack_chain_results
    
    def _aggregate_and_enhance_results(self,
                                     pipeline_result: Dict[str, Any],
                                     options: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate and enhance all analysis results."""
        aggregated = {
            "overall_threat_level": ThreatLevel.LOW,
            "total_servers_analyzed": pipeline_result["servers_analyzed"],
            "total_attack_vectors": 0,
            "total_abuse_scenarios": 0,
            "total_mitigation_strategies": 0,
            "critical_findings": [],
            "high_priority_recommendations": [],
            "compliance_impacts": [],
            "attack_chain_risks": [],
            "summary_statistics": {},
            "trend_analysis": {}
        }
        
        try:
            # Aggregate individual analysis results
            individual_analyses = pipeline_result.get("individual_analyses", {})
            
            threat_levels = []
            all_attack_vectors = []
            all_abuse_scenarios = []
            all_mitigations = []
            
            for server_id, analysis in individual_analyses.items():
                threat_levels.append(analysis.threat_level)
                all_attack_vectors.extend(analysis.attack_vectors)
                all_abuse_scenarios.extend(analysis.abuse_scenarios)
                all_mitigations.extend(analysis.mitigation_strategies)
                
                # Collect critical findings
                if analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    aggregated["critical_findings"].append({
                        "server": server_id,
                        "threat_level": analysis.threat_level.value,
                        "confidence": analysis.confidence_score,
                        "key_risks": [av.name for av in analysis.attack_vectors[:3]]
                    })
            
            # Determine overall threat level
            if ThreatLevel.CRITICAL in threat_levels:
                aggregated["overall_threat_level"] = ThreatLevel.CRITICAL
            elif ThreatLevel.HIGH in threat_levels:
                aggregated["overall_threat_level"] = ThreatLevel.HIGH
            elif ThreatLevel.MEDIUM in threat_levels:
                aggregated["overall_threat_level"] = ThreatLevel.MEDIUM
            
            # Update counts
            aggregated["total_attack_vectors"] = len(all_attack_vectors)
            aggregated["total_abuse_scenarios"] = len(all_abuse_scenarios)
            aggregated["total_mitigation_strategies"] = len(all_mitigations)
            
            # Generate high-priority recommendations
            aggregated["high_priority_recommendations"] = self._generate_priority_recommendations(
                individual_analyses,
                pipeline_result.get("attack_chain_analyses", [])
            )
            
            # Analyze attack chain risks
            attack_chain_analyses = pipeline_result.get("attack_chain_analyses", [])
            for chain_analysis in attack_chain_analyses:
                if chain_analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    aggregated["attack_chain_risks"].append({
                        "threat_level": chain_analysis.threat_level.value,
                        "confidence": chain_analysis.confidence_score,
                        "chain_description": chain_analysis.attack_vectors[0].description if chain_analysis.attack_vectors else "Unknown"
                    })
            
            # Generate summary statistics
            aggregated["summary_statistics"] = {
                "servers_with_critical_risk": sum(1 for level in threat_levels if level == ThreatLevel.CRITICAL),
                "servers_with_high_risk": sum(1 for level in threat_levels if level == ThreatLevel.HIGH),
                "servers_with_medium_risk": sum(1 for level in threat_levels if level == ThreatLevel.MEDIUM),
                "servers_with_low_risk": sum(1 for level in threat_levels if level == ThreatLevel.LOW),
                "attack_chains_identified": len(attack_chain_analyses),
                "high_severity_attack_vectors": sum(1 for av in all_attack_vectors if av.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]),
                "average_confidence_score": sum(analysis.confidence_score for analysis in individual_analyses.values()) / max(len(individual_analyses), 1)
            }
            
        except Exception as e:
            logger.error(f"Result aggregation failed: {e}")
            aggregated["error"] = str(e)
        
        return aggregated
    
    def _analyze_deployment_patterns(self, mcp_servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Analyze deployment patterns from server information."""
        patterns = {
            "cloud_deployment_detected": False,
            "hybrid_deployment_detected": False,
            "containerized_deployment": False,
            "distributed_deployment": False
        }
        
        # Analyze server metadata and configuration
        hosts = set()
        docker_indicators = 0
        cloud_indicators = 0
        
        for server in mcp_servers:
            # Collect unique hosts
            hosts.add(server.host)
            
            # Check for Docker indicators
            if server.metadata.get('docker', False) or 'docker' in str(server.metadata).lower():
                docker_indicators += 1
            
            # Check for cloud indicators
            metadata_str = str(server.metadata).lower()
            if any(cloud in metadata_str for cloud in ['aws', 'gcp', 'azure', 'cloud']):
                cloud_indicators += 1
        
        patterns["containerized_deployment"] = docker_indicators > 0
        patterns["distributed_deployment"] = len(hosts) > 1
        patterns["cloud_deployment_detected"] = cloud_indicators > 0
        patterns["hybrid_deployment_detected"] = patterns["distributed_deployment"] and patterns["cloud_deployment_detected"]
        
        return patterns
    
    def _assess_security_posture(self, mcp_servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Assess overall security posture from server information."""
        assessment = {
            "high_security_indicators": 0,
            "low_security_indicators": 0,
            "security_features_detected": [],
            "security_concerns": []
        }
        
        for server in mcp_servers:
            # Check for security features
            if server.transport_type in ['https', 'wss']:
                assessment["high_security_indicators"] += 1
                assessment["security_features_detected"].append("encrypted_transport")
            
            if server.transport_type in ['http', 'ws']:
                assessment["low_security_indicators"] += 1
                assessment["security_concerns"].append("unencrypted_transport")
            
            # Check for authentication indicators in metadata
            metadata_str = str(server.metadata).lower()
            if any(auth in metadata_str for auth in ['auth', 'token', 'key', 'credential']):
                assessment["high_security_indicators"] += 1
                assessment["security_features_detected"].append("authentication_present")
        
        return assessment
    
    def _group_servers_for_attack_chains(self,
                                       mcp_servers: List[MCPServerInfo],
                                       individual_results: Dict[str, ThreatAnalysis]) -> Dict[str, List[MCPServerInfo]]:
        """Group servers for attack chain analysis based on capabilities and risk levels."""
        groups = {}
        
        # Group by host for potential lateral movement
        host_groups = {}
        for server in mcp_servers:
            host = server.host
            if host not in host_groups:
                host_groups[host] = []
            host_groups[host].append(server)
        
        # Create groups only if multiple servers per host
        group_id = 0
        for host, servers in host_groups.items():
            if len(servers) > 1:
                groups[f"host_group_{group_id}"] = servers
                group_id += 1
        
        # Also create capability-based groups
        high_risk_servers = []
        file_access_servers = []
        network_access_servers = []
        
        for server in mcp_servers:
            server_id = server.metadata.get('name', server.server_id)
            if server_id in individual_results:
                analysis = individual_results[server_id]
                if analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    high_risk_servers.append(server)
                
                # Check capabilities for grouping
                for capability in analysis.tool_capabilities.capability_categories:
                    if capability.value == "file_system":
                        file_access_servers.append(server)
                    elif capability.value == "network_access":
                        network_access_servers.append(server)
        
        if len(high_risk_servers) > 1:
            groups["high_risk_group"] = high_risk_servers
        
        if len(file_access_servers) > 0 and len(network_access_servers) > 0:
            # Potential data exfiltration chain
            groups["data_exfiltration_chain"] = list(set(file_access_servers + network_access_servers))
        
        return groups
    
    def _generate_priority_recommendations(self,
                                         individual_analyses: Dict[str, ThreatAnalysis],
                                         attack_chain_analyses: List[ThreatAnalysis]) -> List[str]:
        """Generate high-priority recommendations based on all analyses."""
        recommendations = []
        
        # Analyze individual results for critical issues
        critical_servers = []
        common_issues = {}
        
        for server_id, analysis in individual_analyses.items():
            if analysis.threat_level == ThreatLevel.CRITICAL:
                critical_servers.append(server_id)
            
            # Count common issues
            for vector in analysis.attack_vectors:
                issue_type = vector.name
                if issue_type not in common_issues:
                    common_issues[issue_type] = 0
                common_issues[issue_type] += 1
        
        # Generate recommendations for critical servers
        if critical_servers:
            recommendations.append(
                f"CRITICAL: Immediately review and restrict capabilities for servers: {', '.join(critical_servers)}"
            )
        
        # Generate recommendations for common issues
        for issue, count in sorted(common_issues.items(), key=lambda x: x[1], reverse=True):
            if count >= len(individual_analyses) * 0.5:  # Affects 50% or more servers
                recommendations.append(
                    f"HIGH: Address {issue} vulnerability affecting {count} servers"
                )
        
        # Generate recommendations for attack chains
        if attack_chain_analyses:
            high_risk_chains = [
                chain for chain in attack_chain_analyses 
                if chain.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            ]
            if high_risk_chains:
                recommendations.append(
                    f"HIGH: {len(high_risk_chains)} high-risk attack chains identified - implement network segmentation"
                )
        
        return recommendations[:10]  # Return top 10 recommendations
    
    def _execute_security_audit_workflow(self,
                                       mcp_servers: List[MCPServerInfo],
                                       config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute security audit workflow."""
        return self.execute_comprehensive_analysis(
            mcp_servers,
            analysis_options={
                "analysis_type": "comprehensive",
                "focus_areas": ["security", "vulnerabilities", "compliance"]
            }
        )
    
    def _execute_compliance_workflow(self,
                                   mcp_servers: List[MCPServerInfo], 
                                   config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance check workflow."""
        # Build compliance-focused environment context
        compliance_context = self.threat_analyzer.capability_analyzer.build_environment_context(mcp_servers)
        
        # Add specific compliance requirements from config
        if "compliance_frameworks" in config:
            from .models import ComplianceFramework
            frameworks = []
            for framework_name in config["compliance_frameworks"]:
                try:
                    framework = ComplianceFramework[framework_name.upper()]
                    frameworks.append(framework)
                except KeyError:
                    logger.warning(f"Unknown compliance framework: {framework_name}")
            compliance_context.compliance_requirements = frameworks
        
        return self.execute_comprehensive_analysis(
            mcp_servers,
            compliance_context,
            analysis_options={
                "analysis_type": "context_aware",
                "focus_areas": ["compliance", "governance", "data_protection"]
            }
        )
    
    def _execute_penetration_test_workflow(self,
                                         mcp_servers: List[MCPServerInfo],
                                         config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute penetration test workflow."""
        return self.execute_comprehensive_analysis(
            mcp_servers,
            analysis_options={
                "analysis_type": "comprehensive",
                "focus_areas": ["attack_vectors", "exploitation", "lateral_movement"]
            }
        )
    
    def _execute_risk_assessment_workflow(self,
                                        mcp_servers: List[MCPServerInfo],
                                        config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute risk assessment workflow."""
        return self.execute_comprehensive_analysis(
            mcp_servers,
            analysis_options={
                "analysis_type": "context_aware",
                "focus_areas": ["risk_analysis", "business_impact", "likelihood"]
            }
        )
    
    def _update_average_pipeline_time(self):
        """Update average pipeline execution time."""
        total_pipelines = self.pipeline_stats["pipelines_executed"]
        if total_pipelines > 0:
            self.pipeline_stats["avg_pipeline_time"] = (
                self.pipeline_stats["total_analysis_time"] / total_pipelines
            )
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """Get pipeline execution statistics."""
        stats = self.pipeline_stats.copy()
        
        # Calculate stage averages
        for stage, times in stats["stage_performance"].items():
            if times:
                stats["stage_performance"][f"{stage}_avg"] = sum(times) / len(times)
                stats["stage_performance"][f"{stage}_min"] = min(times)
                stats["stage_performance"][f"{stage}_max"] = max(times)
        
        return stats


class BatchOptimizationEngine:
    """
    F4.3: Advanced batch optimization engine for intelligent batch processing.
    
    This engine implements sophisticated optimization algorithms including:
    - Adaptive batch sizing based on performance history
    - Intelligent provider selection and load balancing
    - Memory usage monitoring and optimization
    - Performance tracking and historical learning
    """
    
    def __init__(self, 
                 target_batch_time: float = 30.0,
                 min_batch_size: int = 2,
                 max_batch_size: int = 10,
                 memory_limit_mb: int = 512,
                 providers: List[str] = None):
        """Initialize batch optimization engine."""
        self.target_batch_time = target_batch_time
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        self.memory_limit_mb = memory_limit_mb
        self.providers = providers or []
        
        # Performance history for adaptive sizing
        self.performance_history = []
        self.max_history_size = 10
        
        # Provider performance tracking
        self.provider_performance = {}
        
        logger.info(f"BatchOptimizationEngine initialized: target_time={target_batch_time}s, "
                   f"batch_size_range=[{min_batch_size}, {max_batch_size}], "
                   f"memory_limit={memory_limit_mb}MB")

    def calculate_optimal_batch_size(self, 
                                   remaining_servers: int, 
                                   historical_metrics: List[Dict[str, Any]],
                                   current_memory_usage: float) -> int:
        """
        Calculate optimal batch size based on performance history and current conditions.
        
        Args:
            remaining_servers: Number of servers remaining to process
            historical_metrics: Previous batch performance metrics
            current_memory_usage: Current memory usage in MB
            
        Returns:
            Optimal batch size
        """
        # Start with default size
        optimal_size = self.min_batch_size
        
        # Adjust based on performance history
        if historical_metrics:
            recent_metrics = historical_metrics[-3:]  # Use last 3 batches
            
            # Calculate average time per tool from recent batches
            time_per_tool_values = [m["time_per_tool"] for m in recent_metrics if m["time_per_tool"] > 0]
            if time_per_tool_values:
                import statistics
                avg_time_per_tool = statistics.mean(time_per_tool_values)
                
                # Estimate optimal size based on target time
                if avg_time_per_tool > 0:
                    estimated_optimal = int(self.target_batch_time / avg_time_per_tool)
                    optimal_size = max(self.min_batch_size, 
                                     min(self.max_batch_size, estimated_optimal))
        
        # Adjust for memory constraints
        memory_available = self.memory_limit_mb - current_memory_usage
        if memory_available < 100:  # Less than 100MB available
            optimal_size = max(1, optimal_size // 2)
        
        # Don't exceed remaining servers
        optimal_size = min(optimal_size, remaining_servers)
        
        logger.debug(f"Calculated optimal batch size: {optimal_size} "
                    f"(remaining: {remaining_servers}, memory: {current_memory_usage:.1f}MB)")
        
        return optimal_size

    def select_optimal_provider(self, batch_servers: List[MCPServerInfo]) -> Optional[str]:
        """
        Select optimal AI provider for the given batch based on provider performance.
        
        Args:
            batch_servers: Servers in the current batch
            
        Returns:
            Name of optimal provider or None for auto-selection
        """
        if not self.providers or len(self.providers) <= 1:
            return None
        
        # If no performance history, return None for auto-selection
        if not self.provider_performance:
            return None
        
        # Select provider with best recent performance
        best_provider = None
        best_score = float('-inf')
        
        for provider_name in self.providers:
            if provider_name in self.provider_performance:
                perf = self.provider_performance[provider_name]
                # Score based on success rate and response time
                score = perf.get("success_rate", 0.0) * 100 - perf.get("avg_response_time", 30.0)
                if score > best_score:
                    best_score = score
                    best_provider = provider_name
        
        logger.debug(f"Selected optimal provider: {best_provider} (score: {best_score:.2f})")
        return best_provider

    def update_performance_history(self, optimization_metrics: Dict[str, Any]):
        """
        Update performance history with new batch metrics.
        
        Args:
            optimization_metrics: Metrics from completed batch
        """
        # Add to general performance history
        self.performance_history.append(optimization_metrics)
        if len(self.performance_history) > self.max_history_size:
            self.performance_history.pop(0)
        
        # Update provider-specific performance
        provider = optimization_metrics.get("selected_provider")
        if provider and provider != "auto":
            if provider not in self.provider_performance:
                self.provider_performance[provider] = {
                    "success_rate": 0.0,
                    "avg_response_time": 0.0,
                    "total_batches": 0
                }
            
            perf = self.provider_performance[provider]
            perf["total_batches"] += 1
            
            # Update running averages
            alpha = 0.3  # Smoothing factor
            perf["success_rate"] = (alpha * optimization_metrics["success_rate"] + 
                                  (1 - alpha) * perf["success_rate"])
            perf["avg_response_time"] = (alpha * optimization_metrics["batch_time"] + 
                                       (1 - alpha) * perf["avg_response_time"])
        
        logger.debug(f"Updated performance history: {len(self.performance_history)} entries")


def create_advanced_pipeline(threat_analyzer: AIThreatAnalyzer, 
                           config: Optional[Dict[str, Any]] = None) -> AdvancedThreatAnalysisPipeline:
    """
    Factory function to create advanced threat analysis pipeline.
    
    Args:
        threat_analyzer: AI threat analyzer instance
        config: Optional pipeline configuration
        
    Returns:
        AdvancedThreatAnalysisPipeline instance
    """
    return AdvancedThreatAnalysisPipeline(threat_analyzer, config) 