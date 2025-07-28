"""
AI-Powered Threat Analysis Module

This module provides comprehensive AI-powered threat analysis capabilities
for MCP tools, including capability analysis, threat modeling, attack
chain detection, learning-based threat intelligence, advanced multi-provider 
AI support, dynamic example generation, risk prioritization, and dynamic
content generation for threat analysis reports.
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
from .example_generator import (
    DynamicExampleGenerator, GeneratedExample, ExampleType, ExampleGenerationContext
)
from .risk_prioritizer import (
    RiskPrioritizationAlgorithm, PrioritizedThreat, PriorityLevel, 
    TechnicalImpactScore, BusinessImpactScore, LikelihoodScore, EnvironmentalModifiers
)

# Phase 6: Dynamic Content Generation Framework
from .narrative_builder import (
    NarrativeBuilder, AttackNarrative, NarrativeStyle, NarrativeLength
)
from .code_snippet_generator import (
    CodeSnippetGenerator, CodeSnippet, PayloadType, PayloadComplexity, ProgrammingLanguage
)
from .diagram_generator import (
    DiagramGenerator, VisualDiagram, DiagramType, DiagramFormat, DiagramStyle
)

__all__ = [
    # Core Analysis Components
    'MCPCapabilityAnalyzer',
    'ThreatContextBuilder',
    'AIProvider',
    'OpenAIProvider', 
    'AnthropicProvider',
    'LocalLLMProvider',
    'ThreatAnalysisPrompts',
    'AIThreatAnalyzer',
    
    # Data Models
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
    
    # Advanced Analysis Components
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
    'SelectionContext',
    
    # Example Generation Components
    'DynamicExampleGenerator',
    'GeneratedExample',
    'ExampleType', 
    'ExampleGenerationContext',
    
    # Risk Prioritization Components
    'RiskPrioritizationAlgorithm',
    'PrioritizedThreat',
    'PriorityLevel',
    'TechnicalImpactScore',
    'BusinessImpactScore',
    'LikelihoodScore',
    'EnvironmentalModifiers',
    
    # Phase 6: Dynamic Content Generation Framework
    'NarrativeBuilder',
    'AttackNarrative',
    'NarrativeStyle',
    'NarrativeLength',
    'CodeSnippetGenerator',
    'CodeSnippet',
    'PayloadType',
    'PayloadComplexity', 
    'ProgrammingLanguage',
    'DiagramGenerator',
    'VisualDiagram',
    'DiagramType',
    'DiagramFormat',
    'DiagramStyle',
] 