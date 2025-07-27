"""
AI-Powered Threat Analysis Module

This module provides comprehensive AI-powered threat analysis capabilities
for MCP tools, including capability analysis, threat modeling, attack
chain detection, learning-based threat intelligence, and advanced
multi-provider AI support.
"""

from .capability_analyzer import MCPCapabilityAnalyzer, ThreatContextBuilder
from .ai_providers import AIProvider, OpenAIProvider, AnthropicProvider, LocalLLMProvider
from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AttackVector, 
    AbuseScenario, MitigationStrategy, ThreatLevel, CapabilityCategory,
    AttackChain, ChainLink, ChainFeasibilityScore
)
from .prompts import ThreatAnalysisPrompts
from .threat_analyzer import AIThreatAnalyzer
from .attack_chain_analyzer import AttackChainAnalyzer
from .threat_intelligence_db import ThreatIntelligenceDB, ThreatPattern, SimilarityMatch, LearningMetrics
from .threat_analysis_optimizer import ThreatAnalysisOptimizer, OptimizationStrategy, OptimizationRecommendation, AnalysisFeedback
from .provider_selection import EnhancedProviderSelector, SelectionCriteria, ProviderSelection, SelectionContext

__all__ = [
    'MCPCapabilityAnalyzer',
    'ThreatContextBuilder', 
    'AIProvider',
    'OpenAIProvider',
    'AnthropicProvider',
    'LocalLLMProvider',
    'ThreatAnalysis',
    'ToolCapabilities',
    'EnvironmentContext',
    'AttackVector',
    'AbuseScenario',
    'MitigationStrategy',
    'ThreatLevel',
    'CapabilityCategory',
    'AttackChain',
    'ChainLink',
    'ChainFeasibilityScore',
    'ThreatAnalysisPrompts',
    'AIThreatAnalyzer',
    'AttackChainAnalyzer',
    'ThreatIntelligenceDB',
    'ThreatPattern',
    'SimilarityMatch',
    'LearningMetrics',
    'ThreatAnalysisOptimizer',
    'OptimizationStrategy',
    'OptimizationRecommendation',
    'AnalysisFeedback',
    'EnhancedProviderSelector',
    'SelectionCriteria',
    'ProviderSelection',
    'SelectionContext'
] 