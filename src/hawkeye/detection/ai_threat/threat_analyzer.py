"""
AI-Powered Threat Analyzer

This module provides the main orchestration class for AI-powered threat analysis,
coordinating capability analysis, AI providers, and result processing.
"""

import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AnalysisMetadata,
    ThreatLevel, AttackVector, AbuseScenario, MitigationStrategy
)
from .capability_analyzer import MCPCapabilityAnalyzer
from .ai_providers import (
    AIProvider, OpenAIProvider, AnthropicProvider, LocalLLMProvider,
    AnalysisRequest, AnalysisResponse
)
from .prompts import ThreatAnalysisPrompts
from ..mcp_introspection.models import MCPServerInfo
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


class AIThreatAnalyzer:
    """AI-powered threat analysis for MCP tools with enhanced prompt engineering."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI threat analyzer with enhanced prompt system.
        
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
        
        # Statistics tracking
        self.stats = {
            "analyses_performed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "ai_failures": 0,
            "total_cost": 0.0,
            "prompt_types_used": {},
            "analysis_times": []
        }
        
        logger.info(f"AI Threat Analyzer initialized with provider: {self.settings.ai.provider}")
        logger.info("Enhanced prompt engineering framework enabled")
    
    def analyze_threats(self, 
                       mcp_server: MCPServerInfo,
                       environment_context: Optional[EnvironmentContext] = None,
                       analysis_type: str = "comprehensive",
                       force_refresh: bool = False) -> ThreatAnalysis:
        """
        Generate comprehensive threat analysis for an MCP tool using structured prompts.
        
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
        
        try:
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
            self.stats["total_cost"] += analysis.analysis_metadata.cost_estimate
            
            # Track prompt usage
            if analysis_type not in self.stats["prompt_types_used"]:
                self.stats["prompt_types_used"][analysis_type] = 0
            self.stats["prompt_types_used"][analysis_type] += 1
            
            # Track analysis time
            analysis_duration = time.time() - analysis_start
            self.stats["analysis_times"].append(analysis_duration)
            
            logger.info(f"Enhanced threat analysis completed for {tool_name} in {analysis_duration:.2f}s")
            
            return analysis
            
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
        """Create rule-based threat analysis when AI fails."""
        # Determine threat level based on capabilities
        threat_level = ThreatLevel.LOW
        
        high_risk_categories = [
            "CODE_EXECUTION", "FILE_SYSTEM", "NETWORK_ACCESS", "SYSTEM_INFORMATION"
        ]
        
        risk_score = 0
        for category in tool_capabilities.capability_categories:
            if category.value.upper() in high_risk_categories:
                risk_score += 1
        
        if risk_score >= 3:
            threat_level = ThreatLevel.HIGH
        elif risk_score >= 2:
            threat_level = ThreatLevel.MEDIUM
        
        # Create basic attack vectors
        attack_vectors = []
        if any(c.value == "code_execution" for c in tool_capabilities.capability_categories):
            attack_vectors.append(AttackVector(
                name="Command Injection",
                severity=ThreatLevel.HIGH,
                description="Tool may be vulnerable to command injection attacks",
                prerequisites=["Access to tool interface"],
                impact="Arbitrary code execution on host system",
                likelihood=0.7
            ))
        
        # Create basic mitigation strategies
        mitigation_strategies = [
            MitigationStrategy(
                name="Input Validation",
                description="Implement strict input validation and sanitization",
                implementation_steps=[
                    "Validate all user inputs",
                    "Sanitize command parameters",
                    "Use allowlists for acceptable inputs"
                ],
                effectiveness_score=0.8
            )
        ]
        
        return ThreatAnalysis(
            tool_signature=tool_capabilities.tool_id,
            tool_capabilities=tool_capabilities,
            environment_context=environment_context,
            threat_level=threat_level,
            attack_vectors=attack_vectors,
            mitigation_strategies=mitigation_strategies,
            confidence_score=0.6,  # Lower confidence for rule-based
            analysis_metadata=AnalysisMetadata(
                ai_provider="rule_based",
                model_used="internal_rules",
                cost_estimate=0.0,
                confidence_score=0.6
            )
        )
    
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
            confidence_score=0.1,
            analysis_metadata=AnalysisMetadata(
                ai_provider="fallback",
                model_used="minimal",
                cost_estimate=0.0,
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