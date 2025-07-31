"""
Threat Analysis Optimizer

This module provides intelligent optimization for threat analysis, including
AI usage optimization, cost management, and analysis quality improvement
through learning and pattern recognition.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext,
    ThreatLevel, CapabilityCategory
)
from .threat_intelligence_db import ThreatIntelligenceDB, ThreatPattern, SimilarityMatch


logger = logging.getLogger(__name__)


class OptimizationStrategy(Enum):
    """Optimization strategy options."""
    COST_OPTIMIZED = "cost_optimized"
    QUALITY_OPTIMIZED = "quality_optimized"
    BALANCED = "balanced"
    SPEED_OPTIMIZED = "speed_optimized"


@dataclass
class OptimizationRecommendation:
    """Represents an optimization recommendation."""
    strategy: OptimizationStrategy
    use_cached_analysis: bool
    use_pattern_based: bool
    require_full_analysis: bool
    estimated_cost: float
    estimated_accuracy: float
    estimated_time_seconds: float
    confidence_level: float
    reasoning: str


@dataclass
class AnalysisFeedback:
    """Feedback for analysis optimization."""
    tool_signature: str
    accuracy_rating: float  # 0.0-1.0
    usefulness_rating: float  # 0.0-1.0
    completeness_rating: float  # 0.0-1.0
    cost_effectiveness: float  # 0.0-1.0
    timestamp: datetime
    user_comments: Optional[str] = None


class ThreatAnalysisOptimizer:
    """
    Optimizes threat analysis through intelligent use of cached analyses,
    pattern recognition, and cost-benefit analysis.
    """
    
    def __init__(self, threat_intelligence_db: ThreatIntelligenceDB):
        """
        Initialize the threat analysis optimizer.
        
        Args:
            threat_intelligence_db: Threat intelligence database with learning capabilities
        """
        self.threat_db = threat_intelligence_db
        
        # Optimization thresholds
        self.similarity_threshold = 0.8
        self.pattern_confidence_threshold = 0.7
        self.cost_threshold = 0.30  # Maximum cost before recommending alternatives
        self.accuracy_threshold = 0.8  # Minimum accuracy for recommendations
        
        # Strategy configurations
        self.strategy_configs = {
            OptimizationStrategy.COST_OPTIMIZED: {
                "similarity_threshold": 0.6,
                "pattern_confidence_threshold": 0.5,
                "max_cost": 0.20,
                "min_accuracy": 0.7
            },
            OptimizationStrategy.QUALITY_OPTIMIZED: {
                "similarity_threshold": 0.9,
                "pattern_confidence_threshold": 0.8,
                "max_cost": 1.00,
                "min_accuracy": 0.95
            },
            OptimizationStrategy.BALANCED: {
                "similarity_threshold": 0.8,
                "pattern_confidence_threshold": 0.7,
                "max_cost": 0.50,
                "min_accuracy": 0.85
            },
            OptimizationStrategy.SPEED_OPTIMIZED: {
                "similarity_threshold": 0.6,
                "pattern_confidence_threshold": 0.6,
                "max_cost": 0.40,
                "min_accuracy": 0.75
            }
        }
        
        # Statistics
        self.optimization_stats = {
            "recommendations_made": 0,
            "cached_analyses_used": 0,
            "pattern_based_analyses": 0,
            "full_analyses_required": 0,
            "total_cost_saved": 0.0,
            "average_accuracy": 0.0
        }
        
        logger.info("Threat Analysis Optimizer initialized")
    
    def should_use_cached_analysis(self, 
                                 tool_capabilities: ToolCapabilities,
                                 strategy: OptimizationStrategy = OptimizationStrategy.BALANCED) -> bool:
        """
        Determine if cached analysis should be used for optimization.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            strategy: Optimization strategy to use
            
        Returns:
            True if cached analysis should be used
        """
        try:
            config = self.strategy_configs[strategy]
            
            # Check for direct or similar analysis
            similar_result = self.threat_db.retrieve_similar_analysis(
                tool_capabilities, 
                config["similarity_threshold"]
            )
            
            if similar_result:
                similar_analysis, similarity_score = similar_result
                
                # Check if similarity meets strategy requirements
                if similarity_score >= config["similarity_threshold"]:
                    logger.debug(f"Cached analysis recommended with similarity: {similarity_score:.3f}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Cache recommendation failed: {e}")
            return False
    
    def get_optimization_recommendation(self,
                                      tool_capabilities: ToolCapabilities,
                                      environment_context: EnvironmentContext,
                                      strategy: OptimizationStrategy = OptimizationStrategy.BALANCED,
                                      budget_limit: Optional[float] = None) -> OptimizationRecommendation:
        """
        Get comprehensive optimization recommendation for threat analysis.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            environment_context: Environment context
            strategy: Optimization strategy
            budget_limit: Optional budget limit
            
        Returns:
            Optimization recommendation
        """
        try:
            config = self.strategy_configs[strategy]
            
            # Check for cached analysis
            similar_result = self.threat_db.retrieve_similar_analysis(
                tool_capabilities, 
                config["similarity_threshold"]
            )
            
            if similar_result:
                similar_analysis, similarity_score = similar_result
                
                if similarity_score >= config["similarity_threshold"]:
                    return self._create_cached_recommendation(
                        similar_analysis, similarity_score, strategy, config
                    )
            
            # Check for pattern-based analysis
            patterns = self.threat_db.get_pattern_recommendations(tool_capabilities)
            
            if patterns and patterns[0].confidence_score >= config["pattern_confidence_threshold"]:
                return self._create_pattern_recommendation(
                    patterns, strategy, config, tool_capabilities
                )
            
            # Check budget constraints
            cost_estimate = self.threat_db.estimate_analysis_cost(tool_capabilities)
            estimated_cost = cost_estimate.get("estimated_cost", 0.50)
            
            if budget_limit and estimated_cost > budget_limit:
                return self._create_budget_constrained_recommendation(
                    tool_capabilities, budget_limit, strategy, config
                )
            
            # Full analysis recommendation
            return self._create_full_analysis_recommendation(
                estimated_cost, strategy, config
            )
            
        except Exception as e:
            logger.error(f"Optimization recommendation failed: {e}")
            return self._create_fallback_recommendation()
        finally:
            self.optimization_stats["recommendations_made"] += 1
    
    def optimize_ai_prompts(self, feedback: AnalysisFeedback) -> Dict[str, Any]:
        """
        Optimize AI prompts based on user feedback.
        
        Args:
            feedback: Analysis feedback data
            
        Returns:
            Optimization results
        """
        try:
            # Store feedback in database
            feedback_data = {
                "accuracy_rating": feedback.accuracy_rating,
                "usefulness_rating": feedback.usefulness_rating,
                "completeness_rating": feedback.completeness_rating,
                "cost_effectiveness": feedback.cost_effectiveness,
                "timestamp": feedback.timestamp.isoformat(),
                "user_comments": feedback.user_comments
            }
            
            self.threat_db.update_analysis_feedback(feedback.tool_signature, feedback_data)
            
            # Analyze feedback patterns
            optimization_results = self._analyze_feedback_patterns(feedback)
            
            # Update optimization strategies if needed
            self._update_optimization_strategies(feedback)
            
            logger.debug(f"Prompt optimization completed for {feedback.tool_signature}")
            return optimization_results
            
        except Exception as e:
            logger.error(f"Prompt optimization failed: {e}")
            return {"error": str(e)}
    
    def estimate_analysis_cost(self, 
                             tool_capabilities: ToolCapabilities,
                             strategy: OptimizationStrategy = OptimizationStrategy.BALANCED) -> Dict[str, Any]:
        """
        Estimate cost of threat analysis with optimization.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            strategy: Optimization strategy
            
        Returns:
            Cost estimation with optimization details
        """
        try:
            config = self.strategy_configs[strategy]
            
            # Get base cost estimate
            base_estimate = self.threat_db.estimate_analysis_cost(tool_capabilities)
            
            # Check for optimization opportunities
            optimization_savings = 0.0
            optimization_method = "none"
            
            # Similar analysis check
            similar_result = self.threat_db.retrieve_similar_analysis(
                tool_capabilities, 
                config["similarity_threshold"]
            )
            
            if similar_result:
                _, similarity_score = similar_result
                if similarity_score >= config["similarity_threshold"]:
                    optimization_savings = base_estimate.get("estimated_cost", 0.50) * 0.8
                    optimization_method = "similar_analysis"
            
            # Pattern-based check
            elif strategy in [OptimizationStrategy.COST_OPTIMIZED, OptimizationStrategy.SPEED_OPTIMIZED]:
                patterns = self.threat_db.get_pattern_recommendations(tool_capabilities)
                if patterns and patterns[0].confidence_score >= config["pattern_confidence_threshold"]:
                    optimization_savings = base_estimate.get("estimated_cost", 0.50) * 0.5
                    optimization_method = "pattern_based"
            
            optimized_cost = max(0.05, base_estimate.get("estimated_cost", 0.50) - optimization_savings)
            
            return {
                "base_cost": base_estimate.get("estimated_cost", 0.50),
                "optimized_cost": optimized_cost,
                "cost_savings": optimization_savings,
                "optimization_method": optimization_method,
                "strategy": strategy.value,
                "confidence": 0.8 if optimization_method != "none" else 0.6
            }
            
        except Exception as e:
            logger.error(f"Cost estimation failed: {e}")
            return {"error": str(e)}
    
    def get_quality_improvement_suggestions(self,
                                          tool_capabilities: ToolCapabilities,
                                          current_analysis: Optional[ThreatAnalysis] = None) -> List[Dict[str, Any]]:
        """
        Get suggestions for improving analysis quality.
        
        Args:
            tool_capabilities: Tool capabilities being analyzed
            current_analysis: Current analysis if available
            
        Returns:
            List of improvement suggestions
        """
        try:
            suggestions = []
            
            # Check patterns for enhancement opportunities
            patterns = self.threat_db.get_pattern_recommendations(tool_capabilities)
            
            for pattern in patterns:
                if pattern.confidence_score > 0.8:
                    suggestions.append({
                        "type": "pattern_enhancement",
                        "description": f"Consider additional attack vectors based on pattern: {pattern.pattern_name}",
                        "confidence": pattern.confidence_score,
                        "suggested_vectors": pattern.common_attack_vectors[:3]
                    })
            
            # Check for similar tools with higher quality analyses
            similar_tools = self.threat_db.find_similar_tools(tool_capabilities, 0.7)
            
            for match in similar_tools:
                if match.similarity_score > 0.8:
                    suggestions.append({
                        "type": "similar_analysis_enhancement",
                        "description": f"Review similar tool analysis for additional insights",
                        "similarity_score": match.similarity_score,
                        "reusability": match.analysis_reusability
                    })
            
            # Environment-specific suggestions
            suggestions.append({
                "type": "environment_context",
                "description": "Consider environment-specific threats and mitigations",
                "confidence": 0.7
            })
            
            return suggestions[:5]  # Top 5 suggestions
            
        except Exception as e:
            logger.error(f"Quality improvement suggestions failed: {e}")
            return []
    
    def update_optimization_metrics(self, 
                                  analysis_result: ThreatAnalysis,
                                  optimization_used: str,
                                  cost_saved: float,
                                  accuracy_achieved: float) -> None:
        """
        Update optimization metrics based on results.
        
        Args:
            analysis_result: Completed threat analysis
            optimization_used: Type of optimization used
            cost_saved: Amount of cost saved
            accuracy_achieved: Accuracy achieved
        """
        try:
            # Update statistics
            if optimization_used == "cached":
                self.optimization_stats["cached_analyses_used"] += 1
            elif optimization_used == "pattern_based":
                self.optimization_stats["pattern_based_analyses"] += 1
            else:
                self.optimization_stats["full_analyses_required"] += 1
            
            self.optimization_stats["total_cost_saved"] += cost_saved
            
            # Update average accuracy
            current_avg = self.optimization_stats["average_accuracy"]
            total_analyses = (self.optimization_stats["cached_analyses_used"] + 
                            self.optimization_stats["pattern_based_analyses"] + 
                            self.optimization_stats["full_analyses_required"])
            
            if total_analyses > 0:
                self.optimization_stats["average_accuracy"] = (
                    (current_avg * (total_analyses - 1) + accuracy_achieved) / total_analyses
                )
            
            logger.debug(f"Optimization metrics updated: {optimization_used}, cost_saved: ${cost_saved:.3f}")
            
        except Exception as e:
            logger.error(f"Metrics update failed: {e}")
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get current optimization statistics."""
        try:
            stats = self.optimization_stats.copy()
            
            # Add calculated metrics
            total_recommendations = stats["recommendations_made"]
            if total_recommendations > 0:
                stats["optimization_rate"] = (
                    (stats["cached_analyses_used"] + stats["pattern_based_analyses"]) / 
                    total_recommendations
                )
            else:
                stats["optimization_rate"] = 0.0
            
            # Add learning database metrics
            db_metrics = self.threat_db.get_learning_metrics()
            stats["database_metrics"] = {
                "total_analyses_stored": db_metrics.total_analyses_stored,
                "patterns_discovered": db_metrics.patterns_discovered,
                "cache_hit_rate": db_metrics.cache_hit_rate,
                "database_size_mb": db_metrics.database_size_mb
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Stats retrieval failed: {e}")
            return self.optimization_stats
    
    # Private helper methods
    
    def _create_cached_recommendation(self,
                                    similar_analysis: ThreatAnalysis,
                                    similarity_score: float,
                                    strategy: OptimizationStrategy,
                                    config: Dict[str, Any]) -> OptimizationRecommendation:
        """Create recommendation for cached analysis."""
        return OptimizationRecommendation(
            strategy=strategy,
            use_cached_analysis=True,
            use_pattern_based=False,
            require_full_analysis=False,
            estimated_cost=0.05,  # Minimal cost for cached analysis
            estimated_accuracy=min(0.95, similarity_score * 1.1),
            estimated_time_seconds=5.0,
            confidence_level=similarity_score,
            reasoning=f"High similarity ({similarity_score:.3f}) found with existing analysis"
        )
    
    def _create_pattern_recommendation(self,
                                     patterns: List[ThreatPattern],
                                     strategy: OptimizationStrategy,
                                     config: Dict[str, Any],
                                     tool_capabilities: ToolCapabilities) -> OptimizationRecommendation:
        """Create recommendation for pattern-based analysis."""
        best_pattern = patterns[0]
        
        return OptimizationRecommendation(
            strategy=strategy,
            use_cached_analysis=False,
            use_pattern_based=True,
            require_full_analysis=False,
            estimated_cost=0.20,  # Reduced cost for pattern-based
            estimated_accuracy=min(0.90, best_pattern.confidence_score * 1.2),
            estimated_time_seconds=30.0,
            confidence_level=best_pattern.confidence_score,
            reasoning=f"Strong pattern match found ({best_pattern.confidence_score:.3f}) with {best_pattern.occurrence_count} occurrences"
        )
    
    def _create_budget_constrained_recommendation(self,
                                                tool_capabilities: ToolCapabilities,
                                                budget_limit: float,
                                                strategy: OptimizationStrategy,
                                                config: Dict[str, Any]) -> OptimizationRecommendation:
        """Create recommendation when budget is constrained."""
        return OptimizationRecommendation(
            strategy=strategy,
            use_cached_analysis=False,
            use_pattern_based=True,
            require_full_analysis=False,
            estimated_cost=min(budget_limit, 0.25),
            estimated_accuracy=0.75,
            estimated_time_seconds=45.0,
            confidence_level=0.6,
            reasoning=f"Budget constraint (${budget_limit:.2f}) requires pattern-based analysis"
        )
    
    def _create_full_analysis_recommendation(self,
                                           estimated_cost: float,
                                           strategy: OptimizationStrategy,
                                           config: Dict[str, Any]) -> OptimizationRecommendation:
        """Create recommendation for full analysis."""
        return OptimizationRecommendation(
            strategy=strategy,
            use_cached_analysis=False,
            use_pattern_based=False,
            require_full_analysis=True,
            estimated_cost=estimated_cost,
            estimated_accuracy=0.95,
            estimated_time_seconds=120.0,
            confidence_level=0.9,
            reasoning="No optimization opportunities found - full AI analysis required"
        )
    
    def _create_fallback_recommendation(self) -> OptimizationRecommendation:
        """Create fallback recommendation when optimization fails."""
        return OptimizationRecommendation(
            strategy=OptimizationStrategy.BALANCED,
            use_cached_analysis=False,
            use_pattern_based=False,
            require_full_analysis=True,
            estimated_cost=0.50,
            estimated_accuracy=0.80,
            estimated_time_seconds=120.0,
            confidence_level=0.5,
            reasoning="Optimization analysis failed - using conservative approach"
        )
    
    def _analyze_feedback_patterns(self, feedback: AnalysisFeedback) -> Dict[str, Any]:
        """Analyze feedback patterns for optimization insights."""
        try:
            # Basic feedback analysis
            overall_quality = (
                feedback.accuracy_rating + 
                feedback.usefulness_rating + 
                feedback.completeness_rating + 
                feedback.cost_effectiveness
            ) / 4.0
            
            optimization_insights = {
                "overall_quality": overall_quality,
                "strengths": [],
                "weaknesses": [],
                "recommendations": []
            }
            
            # Identify strengths and weaknesses
            if feedback.accuracy_rating >= 0.8:
                optimization_insights["strengths"].append("High accuracy")
            else:
                optimization_insights["weaknesses"].append("Low accuracy")
                optimization_insights["recommendations"].append("Review threat detection patterns")
            
            if feedback.cost_effectiveness >= 0.8:
                optimization_insights["strengths"].append("Cost effective")
            else:
                optimization_insights["weaknesses"].append("Poor cost effectiveness")
                optimization_insights["recommendations"].append("Increase use of cached/pattern analysis")
            
            return optimization_insights
            
        except Exception as e:
            logger.error(f"Feedback pattern analysis failed: {e}")
            return {"error": str(e)}
    
    def _update_optimization_strategies(self, feedback: AnalysisFeedback) -> None:
        """Update optimization strategies based on feedback."""
        try:
            # Adjust thresholds based on feedback
            if feedback.accuracy_rating < 0.7:
                # Increase quality requirements
                self.similarity_threshold = min(0.95, self.similarity_threshold + 0.05)
                self.pattern_confidence_threshold = min(0.9, self.pattern_confidence_threshold + 0.05)
            elif feedback.cost_effectiveness < 0.7:
                # Decrease cost thresholds
                self.cost_threshold = max(0.10, self.cost_threshold - 0.05)
            
            logger.debug("Optimization strategies updated based on feedback")
            
        except Exception as e:
            logger.error(f"Strategy update failed: {e}") 