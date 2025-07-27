"""
Enhanced AI Provider Selection System

This module provides intelligent AI provider selection with load balancing,
cost optimization, performance monitoring, and dynamic failover capabilities.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import statistics

from .models import ToolCapabilities, EnvironmentContext, ThreatLevel
from .ai_providers import AIProvider


logger = logging.getLogger(__name__)


class SelectionCriteria(Enum):
    """Criteria for provider selection."""
    COST_OPTIMIZED = "cost_optimized"
    PERFORMANCE_OPTIMIZED = "performance_optimized"
    QUALITY_OPTIMIZED = "quality_optimized"
    RELIABILITY_OPTIMIZED = "reliability_optimized"
    BALANCED = "balanced"


class ProviderCapability(Enum):
    """Provider capability levels."""
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"
    EXPERT = "expert"


@dataclass
class ProviderMetrics:
    """Comprehensive metrics for a provider."""
    provider_name: str
    
    # Performance metrics
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    uptime_percentage: float = 0.0
    
    # Quality metrics
    avg_accuracy_score: float = 0.0
    avg_confidence_score: float = 0.0
    complexity_handling: float = 0.0
    
    # Cost metrics
    cost_per_analysis: float = 0.0
    cost_efficiency_score: float = 0.0
    
    # Load metrics
    current_load: int = 0
    max_concurrent: int = 10
    queue_length: int = 0
    
    # Capability metrics
    threat_analysis_capability: ProviderCapability = ProviderCapability.STANDARD
    attack_chain_capability: ProviderCapability = ProviderCapability.STANDARD
    context_understanding: ProviderCapability = ProviderCapability.STANDARD
    
    # Historical data
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    
    # Real-time status
    is_healthy: bool = True
    is_available: bool = True
    maintenance_window: Optional[Tuple[datetime, datetime]] = None


@dataclass
class SelectionContext:
    """Context for provider selection decisions."""
    tool_capabilities: ToolCapabilities
    environment_context: EnvironmentContext
    analysis_type: str
    
    # Requirements
    max_cost_limit: Optional[float] = None
    max_time_limit: Optional[float] = None
    min_accuracy_required: float = 0.8
    min_confidence_required: float = 0.7
    
    # Preferences
    selection_criteria: SelectionCriteria = SelectionCriteria.BALANCED
    allow_experimental_providers: bool = False
    require_fallback_provider: bool = True
    
    # Context factors
    is_urgent_analysis: bool = False
    is_sensitive_data: bool = False
    requires_compliance: bool = False
    priority_level: int = 3  # 1-5, higher is more important


@dataclass
class ProviderSelection:
    """Result of provider selection process."""
    primary_provider: str
    fallback_providers: List[str]
    selection_score: float
    selection_reasoning: str
    estimated_cost: float
    estimated_time: float
    expected_quality: float
    confidence_level: float
    
    # Alternative options
    alternative_selections: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    selection_timestamp: datetime = field(default_factory=datetime.now)
    selection_criteria_used: SelectionCriteria = SelectionCriteria.BALANCED


class EnhancedProviderSelector:
    """
    Enhanced AI provider selection system with intelligent load balancing,
    cost optimization, and performance-based selection.
    """
    
    def __init__(self, providers: Dict[str, AIProvider]):
        """
        Initialize the enhanced provider selector.
        
        Args:
            providers: Dictionary of available AI providers
        """
        self.providers = providers
        self.provider_metrics = {}
        
        # Selection weights for different criteria
        self.selection_weights = {
            SelectionCriteria.COST_OPTIMIZED: {
                "cost": 0.4, "performance": 0.2, "quality": 0.2, "reliability": 0.2
            },
            SelectionCriteria.PERFORMANCE_OPTIMIZED: {
                "cost": 0.1, "performance": 0.4, "quality": 0.3, "reliability": 0.2
            },
            SelectionCriteria.QUALITY_OPTIMIZED: {
                "cost": 0.1, "performance": 0.2, "quality": 0.5, "reliability": 0.2
            },
            SelectionCriteria.RELIABILITY_OPTIMIZED: {
                "cost": 0.1, "performance": 0.2, "quality": 0.2, "reliability": 0.5
            },
            SelectionCriteria.BALANCED: {
                "cost": 0.25, "performance": 0.25, "quality": 0.25, "reliability": 0.25
            }
        }
        
        # Provider capabilities configuration
        self.provider_capabilities = {
            "openai": {
                "threat_analysis": ProviderCapability.EXPERT,
                "attack_chain": ProviderCapability.ADVANCED,
                "context_understanding": ProviderCapability.ADVANCED,
                "cost_tier": "premium",
                "max_concurrent": 50
            },
            "anthropic": {
                "threat_analysis": ProviderCapability.EXPERT,
                "attack_chain": ProviderCapability.ADVANCED,
                "context_understanding": ProviderCapability.EXPERT,
                "cost_tier": "premium",
                "max_concurrent": 30
            },
            "local_llm": {
                "threat_analysis": ProviderCapability.STANDARD,
                "attack_chain": ProviderCapability.BASIC,
                "context_understanding": ProviderCapability.STANDARD,
                "cost_tier": "free",
                "max_concurrent": 5
            }
        }
        
        # Initialize metrics for each provider
        for provider_name in providers.keys():
            self.provider_metrics[provider_name] = ProviderMetrics(
                provider_name=provider_name,
                **self._get_initial_provider_metrics(provider_name)
            )
        
        # Selection history for learning
        self.selection_history = []
        self.performance_history = {}
        
        logger.info(f"Enhanced Provider Selector initialized with {len(providers)} providers")
    
    def select_optimal_provider(self, 
                              selection_context: SelectionContext) -> ProviderSelection:
        """
        Select optimal provider based on comprehensive analysis.
        
        Args:
            selection_context: Context for selection decision
            
        Returns:
            Provider selection with detailed reasoning
        """
        try:
            logger.debug(f"Selecting optimal provider with criteria: {selection_context.selection_criteria}")
            
            # Update current metrics
            self._update_real_time_metrics()
            
            # Filter available providers
            available_providers = self._filter_available_providers(selection_context)
            
            if not available_providers:
                raise ValueError("No providers meet the selection criteria")
            
            # Score each provider
            provider_scores = {}
            for provider_name in available_providers:
                score = self._calculate_provider_score(provider_name, selection_context)
                provider_scores[provider_name] = score
            
            # Select primary provider
            primary_provider = max(provider_scores.keys(), key=lambda p: provider_scores[p])
            
            # Select fallback providers
            fallback_providers = self._select_fallback_providers(
                primary_provider, 
                provider_scores, 
                selection_context
            )
            
            # Create selection result
            selection = self._create_selection_result(
                primary_provider,
                fallback_providers,
                provider_scores,
                selection_context
            )
            
            # Record selection for learning
            self._record_selection(selection, selection_context)
            
            logger.info(f"Selected provider: {primary_provider} (score: {provider_scores[primary_provider]:.3f})")
            return selection
            
        except Exception as e:
            logger.error(f"Provider selection failed: {e}")
            return self._create_fallback_selection(selection_context)
    
    def select_load_balanced_provider(self,
                                    selection_context: SelectionContext,
                                    load_balancing_strategy: str = "weighted_round_robin") -> ProviderSelection:
        """
        Select provider using load balancing strategies.
        
        Args:
            selection_context: Context for selection
            load_balancing_strategy: Strategy for load balancing
            
        Returns:
            Load-balanced provider selection
        """
        try:
            available_providers = self._filter_available_providers(selection_context)
            
            if load_balancing_strategy == "round_robin":
                selected_provider = self._select_round_robin(available_providers)
            elif load_balancing_strategy == "weighted_round_robin":
                selected_provider = self._select_weighted_round_robin(available_providers, selection_context)
            elif load_balancing_strategy == "least_connections":
                selected_provider = self._select_least_connections(available_providers)
            elif load_balancing_strategy == "least_response_time":
                selected_provider = self._select_least_response_time(available_providers)
            else:
                # Default to optimal selection
                return self.select_optimal_provider(selection_context)
            
            # Create simplified selection for load balancing
            fallback_providers = [p for p in available_providers if p != selected_provider][:2]
            
            selection = ProviderSelection(
                primary_provider=selected_provider,
                fallback_providers=fallback_providers,
                selection_score=0.8,  # Standard score for load balancing
                selection_reasoning=f"Load balanced selection using {load_balancing_strategy}",
                estimated_cost=self.provider_metrics[selected_provider].cost_per_analysis,
                estimated_time=self.provider_metrics[selected_provider].avg_response_time,
                expected_quality=0.8,
                confidence_level=0.7,
                selection_criteria_used=selection_context.selection_criteria
            )
            
            logger.debug(f"Load balanced provider selected: {selected_provider}")
            return selection
            
        except Exception as e:
            logger.error(f"Load balanced selection failed: {e}")
            return self._create_fallback_selection(selection_context)
    
    def update_provider_performance(self,
                                  provider_name: str,
                                  response_time: float,
                                  success: bool,
                                  quality_score: Optional[float] = None,
                                  cost: Optional[float] = None) -> None:
        """
        Update provider performance metrics.
        
        Args:
            provider_name: Name of provider
            response_time: Response time in seconds
            success: Whether the request was successful
            quality_score: Optional quality score
            cost: Optional cost of request
        """
        try:
            if provider_name not in self.provider_metrics:
                return
            
            metrics = self.provider_metrics[provider_name]
            
            # Update request counts
            metrics.total_requests += 1
            if success:
                metrics.total_successes += 1
                metrics.last_success = datetime.now()
            else:
                metrics.total_failures += 1
                metrics.last_failure = datetime.now()
            
            # Update success rate
            metrics.success_rate = metrics.total_successes / metrics.total_requests
            
            # Update response time (exponential moving average)
            alpha = 0.1  # Smoothing factor
            if metrics.avg_response_time == 0:
                metrics.avg_response_time = response_time
            else:
                metrics.avg_response_time = (alpha * response_time + 
                                           (1 - alpha) * metrics.avg_response_time)
            
            # Update quality metrics
            if quality_score is not None:
                if metrics.avg_accuracy_score == 0:
                    metrics.avg_accuracy_score = quality_score
                else:
                    metrics.avg_accuracy_score = (alpha * quality_score + 
                                                (1 - alpha) * metrics.avg_accuracy_score)
            
            # Update cost metrics
            if cost is not None:
                if metrics.cost_per_analysis == 0:
                    metrics.cost_per_analysis = cost
                else:
                    metrics.cost_per_analysis = (alpha * cost + 
                                               (1 - alpha) * metrics.cost_per_analysis)
                
                # Calculate cost efficiency (quality per dollar)
                if metrics.cost_per_analysis > 0:
                    metrics.cost_efficiency_score = metrics.avg_accuracy_score / metrics.cost_per_analysis
            
            # Update health status
            recent_failure_rate = self._calculate_recent_failure_rate(provider_name)
            metrics.is_healthy = recent_failure_rate < 0.3 and metrics.success_rate > 0.5
            
            logger.debug(f"Updated metrics for {provider_name}: success_rate={metrics.success_rate:.3f}")
            
        except Exception as e:
            logger.error(f"Failed to update provider performance: {e}")
    
    def get_provider_recommendations(self,
                                   selection_context: SelectionContext) -> List[Dict[str, Any]]:
        """
        Get detailed provider recommendations with analysis.
        
        Args:
            selection_context: Context for recommendations
            
        Returns:
            List of provider recommendations with detailed analysis
        """
        try:
            recommendations = []
            available_providers = self._filter_available_providers(selection_context)
            
            for provider_name in available_providers:
                score = self._calculate_provider_score(provider_name, selection_context)
                metrics = self.provider_metrics[provider_name]
                
                recommendation = {
                    "provider_name": provider_name,
                    "overall_score": score,
                    "suitability": self._assess_provider_suitability(provider_name, selection_context),
                    "estimated_cost": metrics.cost_per_analysis,
                    "estimated_time": metrics.avg_response_time,
                    "expected_quality": metrics.avg_accuracy_score,
                    "reliability": metrics.success_rate,
                    "current_load": f"{metrics.current_load}/{metrics.max_concurrent}",
                    "strengths": self._identify_provider_strengths(provider_name),
                    "weaknesses": self._identify_provider_weaknesses(provider_name),
                    "best_use_cases": self._get_provider_use_cases(provider_name)
                }
                
                recommendations.append(recommendation)
            
            # Sort by overall score
            recommendations.sort(key=lambda x: x["overall_score"], reverse=True)
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to get provider recommendations: {e}")
            return []
    
    def optimize_provider_allocation(self,
                                   workload_prediction: Dict[str, int],
                                   time_horizon_hours: int = 24) -> Dict[str, Any]:
        """
        Optimize provider allocation based on predicted workload.
        
        Args:
            workload_prediction: Predicted workload by analysis type
            time_horizon_hours: Time horizon for optimization
            
        Returns:
            Optimization recommendations
        """
        try:
            optimization_plan = {
                "time_horizon_hours": time_horizon_hours,
                "predicted_workload": workload_prediction,
                "provider_allocations": {},
                "cost_estimates": {},
                "performance_estimates": {},
                "recommendations": []
            }
            
            total_requests = sum(workload_prediction.values())
            
            for provider_name, metrics in self.provider_metrics.items():
                if not metrics.is_healthy or not metrics.is_available:
                    continue
                
                # Calculate optimal allocation
                provider_capacity = metrics.max_concurrent * time_horizon_hours
                capacity_utilization = min(1.0, total_requests / provider_capacity)
                
                # Estimate costs and performance
                estimated_requests = int(total_requests * self._get_provider_weight(provider_name))
                estimated_cost = estimated_requests * metrics.cost_per_analysis
                estimated_time = estimated_requests * metrics.avg_response_time
                
                optimization_plan["provider_allocations"][provider_name] = {
                    "estimated_requests": estimated_requests,
                    "capacity_utilization": capacity_utilization,
                    "recommended_allocation": min(estimated_requests, provider_capacity)
                }
                
                optimization_plan["cost_estimates"][provider_name] = estimated_cost
                optimization_plan["performance_estimates"][provider_name] = estimated_time
            
            # Generate recommendations
            optimization_plan["recommendations"] = self._generate_allocation_recommendations(
                optimization_plan, workload_prediction
            )
            
            return optimization_plan
            
        except Exception as e:
            logger.error(f"Provider allocation optimization failed: {e}")
            return {"error": str(e)}
    
    def get_selection_analytics(self) -> Dict[str, Any]:
        """Get analytics on provider selection patterns and performance."""
        try:
            total_selections = len(self.selection_history)
            
            if total_selections == 0:
                return {"total_selections": 0, "message": "No selection history available"}
            
            # Provider usage analytics
            provider_usage = {}
            criteria_usage = {}
            success_rates = {}
            
            for selection in self.selection_history:
                provider = selection["primary_provider"]
                criteria = selection["selection_criteria"].value
                
                provider_usage[provider] = provider_usage.get(provider, 0) + 1
                criteria_usage[criteria] = criteria_usage.get(criteria, 0) + 1
            
            # Calculate success rates by provider
            for provider_name, metrics in self.provider_metrics.items():
                if metrics.total_requests > 0:
                    success_rates[provider_name] = metrics.success_rate
            
            return {
                "total_selections": total_selections,
                "provider_usage_distribution": provider_usage,
                "selection_criteria_usage": criteria_usage,
                "provider_success_rates": success_rates,
                "average_selection_score": statistics.mean([s["selection_score"] for s in self.selection_history]),
                "most_used_provider": max(provider_usage.items(), key=lambda x: x[1])[0] if provider_usage else None,
                "most_reliable_provider": max(success_rates.items(), key=lambda x: x[1])[0] if success_rates else None,
                "provider_performance_summary": {
                    name: {
                        "avg_response_time": metrics.avg_response_time,
                        "success_rate": metrics.success_rate,
                        "avg_cost": metrics.cost_per_analysis,
                        "current_load": metrics.current_load
                    }
                    for name, metrics in self.provider_metrics.items()
                }
            }
            
        except Exception as e:
            logger.error(f"Selection analytics failed: {e}")
            return {"error": str(e)}
    
    # Private helper methods
    
    def _get_initial_provider_metrics(self, provider_name: str) -> Dict[str, Any]:
        """Get initial metrics for a provider."""
        capabilities = self.provider_capabilities.get(provider_name, {})
        
        return {
            "avg_response_time": 30.0,  # Default 30 seconds
            "success_rate": 0.95,  # Optimistic initial rate
            "uptime_percentage": 0.99,
            "avg_accuracy_score": 0.8,
            "avg_confidence_score": 0.8,
            "cost_per_analysis": 0.50 if capabilities.get("cost_tier") == "premium" else 0.10,
            "max_concurrent": capabilities.get("max_concurrent", 10),
            "threat_analysis_capability": capabilities.get("threat_analysis", ProviderCapability.STANDARD),
            "attack_chain_capability": capabilities.get("attack_chain", ProviderCapability.STANDARD),
            "context_understanding": capabilities.get("context_understanding", ProviderCapability.STANDARD)
        }
    
    def _update_real_time_metrics(self):
        """Update real-time metrics for all providers."""
        try:
            for provider_name, metrics in self.provider_metrics.items():
                # Check if provider is in maintenance
                if metrics.maintenance_window:
                    start_time, end_time = metrics.maintenance_window
                    now = datetime.now()
                    if start_time <= now <= end_time:
                        metrics.is_available = False
                        continue
                    else:
                        metrics.is_available = True
                        metrics.maintenance_window = None
                
                # Update uptime percentage
                recent_failures = self._get_recent_failures(provider_name, hours=24)
                metrics.uptime_percentage = max(0.0, 1.0 - (recent_failures / 24.0))
                
                # Update health status
                metrics.is_healthy = (metrics.success_rate > 0.7 and 
                                    metrics.uptime_percentage > 0.9 and
                                    metrics.current_load < metrics.max_concurrent * 0.9)
        
        except Exception as e:
            logger.error(f"Real-time metrics update failed: {e}")
    
    def _filter_available_providers(self, context: SelectionContext) -> List[str]:
        """Filter providers based on availability and requirements."""
        available = []
        
        for provider_name, metrics in self.provider_metrics.items():
            if not metrics.is_available or not metrics.is_healthy:
                continue
            
            # Check cost limit
            if context.max_cost_limit and metrics.cost_per_analysis > context.max_cost_limit:
                continue
            
            # Check time limit
            if context.max_time_limit and metrics.avg_response_time > context.max_time_limit:
                continue
            
            # Check accuracy requirement
            if metrics.avg_accuracy_score < context.min_accuracy_required:
                continue
            
            # Check load capacity
            if metrics.current_load >= metrics.max_concurrent:
                continue
            
            available.append(provider_name)
        
        return available
    
    def _calculate_provider_score(self, provider_name: str, context: SelectionContext) -> float:
        """Calculate comprehensive score for a provider."""
        metrics = self.provider_metrics[provider_name]
        weights = self.selection_weights[context.selection_criteria]
        
        # Cost score (inverse - lower cost is better)
        max_cost = max(m.cost_per_analysis for m in self.provider_metrics.values())
        cost_score = 1.0 - (metrics.cost_per_analysis / max_cost) if max_cost > 0 else 1.0
        
        # Performance score (inverse - lower time is better)
        max_time = max(m.avg_response_time for m in self.provider_metrics.values())
        performance_score = 1.0 - (metrics.avg_response_time / max_time) if max_time > 0 else 1.0
        
        # Quality score
        quality_score = (metrics.avg_accuracy_score + metrics.avg_confidence_score) / 2.0
        
        # Reliability score
        reliability_score = (metrics.success_rate + metrics.uptime_percentage) / 2.0
        
        # Load adjustment
        load_factor = 1.0 - (metrics.current_load / metrics.max_concurrent)
        
        # Capability match
        capability_bonus = self._calculate_capability_bonus(provider_name, context)
        
        # Calculate weighted score
        total_score = (
            cost_score * weights["cost"] +
            performance_score * weights["performance"] +
            quality_score * weights["quality"] +
            reliability_score * weights["reliability"]
        )
        
        # Apply adjustments
        total_score *= load_factor
        total_score += capability_bonus
        
        return min(1.0, max(0.0, total_score))
    
    def _calculate_capability_bonus(self, provider_name: str, context: SelectionContext) -> float:
        """Calculate bonus score based on provider capabilities."""
        capabilities = self.provider_capabilities.get(provider_name, {})
        bonus = 0.0
        
        # Analysis type bonus
        if context.analysis_type == "comprehensive":
            threat_cap = capabilities.get("threat_analysis", ProviderCapability.STANDARD)
            if threat_cap == ProviderCapability.EXPERT:
                bonus += 0.1
            elif threat_cap == ProviderCapability.ADVANCED:
                bonus += 0.05
        
        elif context.analysis_type == "attack_chain":
            chain_cap = capabilities.get("attack_chain", ProviderCapability.STANDARD)
            if chain_cap == ProviderCapability.EXPERT:
                bonus += 0.1
            elif chain_cap == ProviderCapability.ADVANCED:
                bonus += 0.05
        
        # Context understanding bonus
        if context.environment_context and context.environment_context.data_sensitivity:
            context_cap = capabilities.get("context_understanding", ProviderCapability.STANDARD)
            if context_cap == ProviderCapability.EXPERT:
                bonus += 0.05
        
        return bonus
    
    def _select_fallback_providers(self, 
                                 primary_provider: str,
                                 provider_scores: Dict[str, float],
                                 context: SelectionContext) -> List[str]:
        """Select fallback providers."""
        if not context.require_fallback_provider:
            return []
        
        # Sort providers by score, excluding primary
        candidates = [(name, score) for name, score in provider_scores.items() 
                     if name != primary_provider]
        candidates.sort(key=lambda x: x[1], reverse=True)
        
        # Select top 2 as fallbacks
        return [name for name, _ in candidates[:2]]
    
    def _create_selection_result(self,
                               primary_provider: str,
                               fallback_providers: List[str],
                               provider_scores: Dict[str, float],
                               context: SelectionContext) -> ProviderSelection:
        """Create comprehensive selection result."""
        primary_metrics = self.provider_metrics[primary_provider]
        
        # Generate reasoning
        reasoning = self._generate_selection_reasoning(primary_provider, provider_scores, context)
        
        # Create alternative selections
        alternatives = []
        for provider_name, score in sorted(provider_scores.items(), key=lambda x: x[1], reverse=True)[1:4]:
            if provider_name != primary_provider:
                alt_metrics = self.provider_metrics[provider_name]
                alternatives.append({
                    "provider_name": provider_name,
                    "score": score,
                    "estimated_cost": alt_metrics.cost_per_analysis,
                    "estimated_time": alt_metrics.avg_response_time,
                    "reason_not_selected": self._get_alternative_reason(provider_name, primary_provider, context)
                })
        
        return ProviderSelection(
            primary_provider=primary_provider,
            fallback_providers=fallback_providers,
            selection_score=provider_scores[primary_provider],
            selection_reasoning=reasoning,
            estimated_cost=primary_metrics.cost_per_analysis,
            estimated_time=primary_metrics.avg_response_time,
            expected_quality=primary_metrics.avg_accuracy_score,
            confidence_level=min(0.95, provider_scores[primary_provider] * 1.1),
            alternative_selections=alternatives,
            selection_criteria_used=context.selection_criteria
        )
    
    def _generate_selection_reasoning(self,
                                    provider_name: str,
                                    provider_scores: Dict[str, float],
                                    context: SelectionContext) -> str:
        """Generate human-readable reasoning for selection."""
        metrics = self.provider_metrics[provider_name]
        score = provider_scores[provider_name]
        
        reasoning_parts = [f"Selected {provider_name} with score {score:.3f}"]
        
        # Add criteria-specific reasoning
        if context.selection_criteria == SelectionCriteria.COST_OPTIMIZED:
            reasoning_parts.append(f"due to competitive cost (${metrics.cost_per_analysis:.3f} per analysis)")
        elif context.selection_criteria == SelectionCriteria.PERFORMANCE_OPTIMIZED:
            reasoning_parts.append(f"due to fast response time ({metrics.avg_response_time:.1f}s avg)")
        elif context.selection_criteria == SelectionCriteria.QUALITY_OPTIMIZED:
            reasoning_parts.append(f"due to high accuracy ({metrics.avg_accuracy_score:.2f})")
        elif context.selection_criteria == SelectionCriteria.RELIABILITY_OPTIMIZED:
            reasoning_parts.append(f"due to excellent reliability ({metrics.success_rate:.2f} success rate)")
        else:
            reasoning_parts.append("due to balanced performance across all criteria")
        
        # Add load information if relevant
        if metrics.current_load > 0:
            reasoning_parts.append(f"Current load: {metrics.current_load}/{metrics.max_concurrent}")
        
        return ". ".join(reasoning_parts)
    
    def _get_alternative_reason(self, alternative: str, selected: str, context: SelectionContext) -> str:
        """Get reason why alternative wasn't selected."""
        alt_metrics = self.provider_metrics[alternative]
        sel_metrics = self.provider_metrics[selected]
        
        if context.selection_criteria == SelectionCriteria.COST_OPTIMIZED:
            if alt_metrics.cost_per_analysis > sel_metrics.cost_per_analysis:
                return "Higher cost"
        elif context.selection_criteria == SelectionCriteria.PERFORMANCE_OPTIMIZED:
            if alt_metrics.avg_response_time > sel_metrics.avg_response_time:
                return "Slower response time"
        elif context.selection_criteria == SelectionCriteria.QUALITY_OPTIMIZED:
            if alt_metrics.avg_accuracy_score < sel_metrics.avg_accuracy_score:
                return "Lower accuracy score"
        
        return "Lower overall score"
    
    def _create_fallback_selection(self, context: SelectionContext) -> ProviderSelection:
        """Create fallback selection when optimal selection fails."""
        # Try to find any available provider
        available_providers = [name for name, metrics in self.provider_metrics.items() 
                             if metrics.is_available and metrics.is_healthy]
        
        if available_providers:
            provider_name = available_providers[0]
            metrics = self.provider_metrics[provider_name]
            
            return ProviderSelection(
                primary_provider=provider_name,
                fallback_providers=[],
                selection_score=0.5,
                selection_reasoning="Fallback selection due to optimal selection failure",
                estimated_cost=metrics.cost_per_analysis,
                estimated_time=metrics.avg_response_time,
                expected_quality=metrics.avg_accuracy_score,
                confidence_level=0.3,
                selection_criteria_used=context.selection_criteria
            )
        
        # Last resort - use first available provider regardless of health
        if self.providers:
            provider_name = list(self.providers.keys())[0]
            return ProviderSelection(
                primary_provider=provider_name,
                fallback_providers=[],
                selection_score=0.1,
                selection_reasoning="Emergency fallback - using first available provider",
                estimated_cost=0.50,
                estimated_time=60.0,
                expected_quality=0.5,
                confidence_level=0.1,
                selection_criteria_used=context.selection_criteria
            )
        
        raise ValueError("No providers available for fallback selection")
    
    def _record_selection(self, selection: ProviderSelection, context: SelectionContext):
        """Record selection for learning and analytics."""
        self.selection_history.append({
            "timestamp": selection.selection_timestamp,
            "primary_provider": selection.primary_provider,
            "selection_score": selection.selection_score,
            "selection_criteria": context.selection_criteria,
            "analysis_type": context.analysis_type,
            "estimated_cost": selection.estimated_cost,
            "estimated_time": selection.estimated_time
        })
        
        # Keep only last 1000 selections
        if len(self.selection_history) > 1000:
            self.selection_history = self.selection_history[-1000:]
    
    # Load balancing helper methods
    
    def _select_round_robin(self, providers: List[str]) -> str:
        """Simple round-robin selection."""
        if not hasattr(self, '_round_robin_index'):
            self._round_robin_index = 0
        
        provider = providers[self._round_robin_index % len(providers)]
        self._round_robin_index += 1
        return provider
    
    def _select_weighted_round_robin(self, providers: List[str], context: SelectionContext) -> str:
        """Weighted round-robin based on provider capabilities."""
        weights = []
        for provider in providers:
            score = self._calculate_provider_score(provider, context)
            weights.append(score)
        
        # Select based on weights (simplified)
        total_weight = sum(weights)
        if total_weight == 0:
            return providers[0]
        
        import random
        random_value = random.random() * total_weight
        cumulative_weight = 0
        
        for i, weight in enumerate(weights):
            cumulative_weight += weight
            if random_value <= cumulative_weight:
                return providers[i]
        
        return providers[-1]
    
    def _select_least_connections(self, providers: List[str]) -> str:
        """Select provider with least current connections."""
        return min(providers, key=lambda p: self.provider_metrics[p].current_load)
    
    def _select_least_response_time(self, providers: List[str]) -> str:
        """Select provider with least average response time."""
        return min(providers, key=lambda p: self.provider_metrics[p].avg_response_time)
    
    # Analytics helper methods
    
    def _calculate_recent_failure_rate(self, provider_name: str, hours: int = 24) -> float:
        """Calculate failure rate in recent hours."""
        # Simplified implementation - would need more detailed tracking
        metrics = self.provider_metrics[provider_name]
        if metrics.total_requests == 0:
            return 0.0
        return 1.0 - metrics.success_rate
    
    def _get_recent_failures(self, provider_name: str, hours: int) -> int:
        """Get number of recent failures."""
        # Simplified implementation
        metrics = self.provider_metrics[provider_name]
        recent_failure_rate = self._calculate_recent_failure_rate(provider_name, hours)
        return int(recent_failure_rate * hours)
    
    def _get_provider_weight(self, provider_name: str) -> float:
        """Get weight for provider in allocation calculations."""
        metrics = self.provider_metrics[provider_name]
        return metrics.success_rate * (metrics.max_concurrent / 100.0)
    
    def _assess_provider_suitability(self, provider_name: str, context: SelectionContext) -> str:
        """Assess provider suitability for context."""
        score = self._calculate_provider_score(provider_name, context)
        
        if score >= 0.8:
            return "Excellent"
        elif score >= 0.6:
            return "Good"
        elif score >= 0.4:
            return "Fair"
        else:
            return "Poor"
    
    def _identify_provider_strengths(self, provider_name: str) -> List[str]:
        """Identify provider strengths."""
        metrics = self.provider_metrics[provider_name]
        strengths = []
        
        if metrics.success_rate >= 0.95:
            strengths.append("High reliability")
        if metrics.avg_response_time <= 20.0:
            strengths.append("Fast response")
        if metrics.cost_per_analysis <= 0.25:
            strengths.append("Cost effective")
        if metrics.avg_accuracy_score >= 0.9:
            strengths.append("High accuracy")
        
        return strengths if strengths else ["Standard performance"]
    
    def _identify_provider_weaknesses(self, provider_name: str) -> List[str]:
        """Identify provider weaknesses."""
        metrics = self.provider_metrics[provider_name]
        weaknesses = []
        
        if metrics.success_rate < 0.8:
            weaknesses.append("Lower reliability")
        if metrics.avg_response_time > 60.0:
            weaknesses.append("Slow response")
        if metrics.cost_per_analysis > 0.75:
            weaknesses.append("Higher cost")
        if metrics.avg_accuracy_score < 0.7:
            weaknesses.append("Lower accuracy")
        
        return weaknesses if weaknesses else ["No significant weaknesses"]
    
    def _get_provider_use_cases(self, provider_name: str) -> List[str]:
        """Get best use cases for provider."""
        capabilities = self.provider_capabilities.get(provider_name, {})
        use_cases = []
        
        if capabilities.get("threat_analysis") == ProviderCapability.EXPERT:
            use_cases.append("Complex threat analysis")
        if capabilities.get("attack_chain") == ProviderCapability.EXPERT:
            use_cases.append("Attack chain analysis")
        if capabilities.get("cost_tier") == "free":
            use_cases.append("Cost-sensitive analysis")
        if capabilities.get("context_understanding") == ProviderCapability.EXPERT:
            use_cases.append("Context-aware analysis")
        
        return use_cases if use_cases else ["General purpose analysis"]
    
    def _generate_allocation_recommendations(self, 
                                           optimization_plan: Dict[str, Any],
                                           workload_prediction: Dict[str, int]) -> List[str]:
        """Generate allocation recommendations."""
        recommendations = []
        
        total_predicted = sum(workload_prediction.values())
        total_capacity = sum(
            metrics.max_concurrent * optimization_plan["time_horizon_hours"]
            for metrics in self.provider_metrics.values()
            if metrics.is_healthy
        )
        
        if total_predicted > total_capacity * 0.8:
            recommendations.append("Consider scaling up provider capacity")
        
        # Find underutilized providers
        for provider_name, allocation in optimization_plan["provider_allocations"].items():
            if allocation["capacity_utilization"] < 0.3:
                recommendations.append(f"Provider {provider_name} is underutilized")
        
        # Find overutilized providers
        for provider_name, allocation in optimization_plan["provider_allocations"].items():
            if allocation["capacity_utilization"] > 0.9:
                recommendations.append(f"Provider {provider_name} may be overloaded")
        
        return recommendations 