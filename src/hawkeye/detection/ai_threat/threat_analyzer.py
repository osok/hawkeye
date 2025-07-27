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