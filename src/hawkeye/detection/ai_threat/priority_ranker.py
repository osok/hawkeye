"""
Priority Ranking Component

This module implements comprehensive priority ranking capabilities using multi-factor scoring
to prioritize security threats, vulnerabilities, and risks for MCP servers based on severity,
likelihood, business impact, and other relevant factors.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import math

from .models import (
    ToolCapabilities, EnvironmentContext, ThreatLevel, SeverityLevel,
    DifficultyLevel, CapabilityCategory, BusinessImpact
)


class PriorityLevel(Enum):
    """Priority levels for threats and vulnerabilities."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class RiskFactor(Enum):
    """Risk factors for priority calculation."""
    SEVERITY = "severity"
    LIKELIHOOD = "likelihood"
    BUSINESS_IMPACT = "business_impact"
    EXPLOITABILITY = "exploitability"
    DETECTABILITY = "detectability"
    REMEDIATION_DIFFICULTY = "remediation_difficulty"
    ATTACK_SURFACE = "attack_surface"
    REGULATORY_IMPACT = "regulatory_impact"


class TimeHorizon(Enum):
    """Time horizons for threat materialization."""
    IMMEDIATE = "immediate"  # 0-24 hours
    SHORT_TERM = "short_term"  # 1-7 days
    MEDIUM_TERM = "medium_term"  # 1-4 weeks
    LONG_TERM = "long_term"  # 1+ months


class RemediationUrgency(Enum):
    """Urgency levels for remediation."""
    EMERGENCY = "emergency"  # Fix immediately
    URGENT = "urgent"  # Fix within 24 hours
    HIGH = "high"  # Fix within 1 week
    MEDIUM = "medium"  # Fix within 1 month
    LOW = "low"  # Fix during next maintenance cycle


@dataclass
class ScoreFactor:
    """Individual scoring factor for priority calculation."""
    factor_name: str
    factor_type: RiskFactor
    raw_score: float  # 0.0-1.0
    weighted_score: float  # Raw score * weight
    weight: float  # Factor weight in overall calculation
    confidence: float = 0.8
    description: str = ""
    data_sources: List[str] = field(default_factory=list)


@dataclass
class PriorityScore:
    """Complete priority scoring result."""
    overall_score: float  # 0.0-1.0
    priority_level: PriorityLevel
    score_factors: List[ScoreFactor] = field(default_factory=list)
    confidence: float = 0.0
    score_rationale: str = ""
    key_drivers: List[str] = field(default_factory=list)
    calculation_timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ThreatPriorityItem:
    """Individual threat/vulnerability item with priority ranking."""
    item_id: str
    item_name: str
    item_type: str  # threat, vulnerability, risk, etc.
    description: str
    priority_score: PriorityScore
    time_horizon: TimeHorizon
    remediation_urgency: RemediationUrgency
    affected_assets: List[str] = field(default_factory=list)
    potential_impact: str = ""
    required_actions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    estimated_effort: str = "Medium"
    success_probability: float = 0.8


@dataclass
class PriorityMatrix:
    """Complete priority ranking matrix."""
    tool_name: str
    assessment_timestamp: datetime
    ranked_items: List[ThreatPriorityItem] = field(default_factory=list)
    critical_items: List[ThreatPriorityItem] = field(default_factory=list)
    immediate_actions: List[str] = field(default_factory=list)
    short_term_actions: List[str] = field(default_factory=list)
    long_term_actions: List[str] = field(default_factory=list)
    resource_allocation_guidance: Dict[str, Any] = field(default_factory=dict)
    executive_summary: str = ""
    risk_appetite_alignment: str = ""


@dataclass
class ScoringWeights:
    """Configurable weights for different scoring factors."""
    severity_weight: float = 0.25
    likelihood_weight: float = 0.20
    business_impact_weight: float = 0.20
    exploitability_weight: float = 0.15
    detectability_weight: float = 0.10
    remediation_difficulty_weight: float = 0.05
    attack_surface_weight: float = 0.03
    regulatory_impact_weight: float = 0.02
    
    def normalize(self) -> None:
        """Normalize weights to sum to 1.0."""
        total = (self.severity_weight + self.likelihood_weight + self.business_impact_weight +
                self.exploitability_weight + self.detectability_weight + 
                self.remediation_difficulty_weight + self.attack_surface_weight + 
                self.regulatory_impact_weight)
        
        if total > 0:
            self.severity_weight /= total
            self.likelihood_weight /= total
            self.business_impact_weight /= total
            self.exploitability_weight /= total
            self.detectability_weight /= total
            self.remediation_difficulty_weight /= total
            self.attack_surface_weight /= total
            self.regulatory_impact_weight /= total


class PriorityRanker:
    """
    Enhanced priority ranking engine with multi-factor scoring for comprehensive
    threat and vulnerability prioritization.
    """
    
    def __init__(self, scoring_weights: Optional[ScoringWeights] = None):
        """Initialize the priority ranker."""
        self.logger = logging.getLogger(__name__)
        self.scoring_weights = scoring_weights or ScoringWeights()
        self.scoring_weights.normalize()
        
        self._priority_thresholds = self._initialize_priority_thresholds()
        self._scoring_models = self._initialize_scoring_models()
        self._urgency_matrix = self._initialize_urgency_matrix()
        self._time_horizon_factors = self._initialize_time_horizon_factors()
    
    def rank_threats(
        self,
        threats: List[Dict[str, Any]],
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> PriorityMatrix:
        """
        Rank threats and vulnerabilities by priority using multi-factor scoring.
        
        Args:
            threats: List of threat/vulnerability objects to rank
            tool_capabilities: Tool capability information
            environment_context: Environment context
            
        Returns:
            Complete priority ranking matrix
        """
        self.logger.info(f"Ranking {len(threats)} threats for {tool_capabilities.tool_name}")
        
        # Score and rank each threat
        ranked_items = []
        for threat in threats:
            priority_item = self._score_and_rank_threat(
                threat, tool_capabilities, environment_context
            )
            ranked_items.append(priority_item)
        
        # Sort by priority score (highest first)
        ranked_items.sort(key=lambda item: item.priority_score.overall_score, reverse=True)
        
        # Identify critical items
        critical_items = [
            item for item in ranked_items 
            if item.priority_score.priority_level == PriorityLevel.CRITICAL
        ]
        
        # Generate action plans
        immediate_actions = self._generate_immediate_actions(ranked_items)
        short_term_actions = self._generate_short_term_actions(ranked_items)
        long_term_actions = self._generate_long_term_actions(ranked_items)
        
        # Generate resource allocation guidance
        resource_guidance = self._generate_resource_allocation_guidance(ranked_items)
        
        # Create executive summary
        executive_summary = self._create_executive_summary(ranked_items, critical_items)
        
        # Assess risk appetite alignment
        risk_appetite = self._assess_risk_appetite_alignment(ranked_items)
        
        matrix = PriorityMatrix(
            tool_name=tool_capabilities.tool_name,
            assessment_timestamp=datetime.now(),
            ranked_items=ranked_items,
            critical_items=critical_items,
            immediate_actions=immediate_actions,
            short_term_actions=short_term_actions,
            long_term_actions=long_term_actions,
            resource_allocation_guidance=resource_guidance,
            executive_summary=executive_summary,
            risk_appetite_alignment=risk_appetite
        )
        
        self.logger.info(f"Completed priority ranking with {len(critical_items)} critical items")
        return matrix
    
    def calculate_priority_score(
        self,
        threat_data: Dict[str, Any],
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> PriorityScore:
        """
        Calculate comprehensive priority score for a single threat.
        
        Args:
            threat_data: Threat/vulnerability data
            tool_capabilities: Tool capabilities
            environment_context: Environment context
            
        Returns:
            Complete priority score
        """
        score_factors = []
        
        # Calculate each scoring factor
        severity_factor = self._calculate_severity_factor(threat_data)
        score_factors.append(severity_factor)
        
        likelihood_factor = self._calculate_likelihood_factor(threat_data)
        score_factors.append(likelihood_factor)
        
        business_impact_factor = self._calculate_business_impact_factor(
            threat_data, environment_context
        )
        score_factors.append(business_impact_factor)
        
        exploitability_factor = self._calculate_exploitability_factor(
            threat_data, tool_capabilities
        )
        score_factors.append(exploitability_factor)
        
        detectability_factor = self._calculate_detectability_factor(threat_data)
        score_factors.append(detectability_factor)
        
        remediation_factor = self._calculate_remediation_difficulty_factor(threat_data)
        score_factors.append(remediation_factor)
        
        attack_surface_factor = self._calculate_attack_surface_factor(
            threat_data, tool_capabilities
        )
        score_factors.append(attack_surface_factor)
        
        regulatory_factor = self._calculate_regulatory_impact_factor(
            threat_data, environment_context
        )
        score_factors.append(regulatory_factor)
        
        # Calculate overall score
        overall_score = sum(factor.weighted_score for factor in score_factors)
        
        # Determine priority level
        priority_level = self._determine_priority_level(overall_score)
        
        # Calculate confidence
        confidence = self._calculate_score_confidence(score_factors)
        
        # Generate rationale
        rationale = self._generate_score_rationale(score_factors, overall_score)
        
        # Identify key drivers
        key_drivers = self._identify_key_drivers(score_factors)
        
        return PriorityScore(
            overall_score=overall_score,
            priority_level=priority_level,
            score_factors=score_factors,
            confidence=confidence,
            score_rationale=rationale,
            key_drivers=key_drivers
        )
    
    def adjust_priorities_for_context(
        self,
        priority_matrix: PriorityMatrix,
        business_context: Dict[str, Any]
    ) -> PriorityMatrix:
        """
        Adjust priorities based on specific business context.
        
        Args:
            priority_matrix: Original priority matrix
            business_context: Business-specific context and constraints
            
        Returns:
            Adjusted priority matrix
        """
        adjusted_items = []
        
        for item in priority_matrix.ranked_items:
            adjusted_item = self._adjust_item_priority(item, business_context)
            adjusted_items.append(adjusted_item)
        
        # Re-sort after adjustments
        adjusted_items.sort(key=lambda item: item.priority_score.overall_score, reverse=True)
        
        # Update matrix
        priority_matrix.ranked_items = adjusted_items
        priority_matrix.critical_items = [
            item for item in adjusted_items 
            if item.priority_score.priority_level == PriorityLevel.CRITICAL
        ]
        
        return priority_matrix
    
    def _initialize_priority_thresholds(self) -> Dict[str, float]:
        """Initialize priority level thresholds."""
        return {
            PriorityLevel.CRITICAL.value: 0.8,
            PriorityLevel.HIGH.value: 0.6,
            PriorityLevel.MEDIUM.value: 0.4,
            PriorityLevel.LOW.value: 0.2,
            PriorityLevel.MINIMAL.value: 0.0
        }
    
    def _initialize_scoring_models(self) -> Dict[str, Dict[str, Any]]:
        """Initialize scoring models for different factors."""
        return {
            "severity": {
                "critical": 1.0,
                "high": 0.8,
                "medium": 0.5,
                "low": 0.2,
                "minimal": 0.1
            },
            "likelihood": {
                "very_high": 1.0,
                "high": 0.8,
                "medium": 0.5,
                "low": 0.2,
                "very_low": 0.1
            },
            "exploitability": {
                "low": 1.0,  # Low complexity = high exploitability
                "medium": 0.6,
                "high": 0.3
            },
            "detectability": {
                "easy": 0.2,  # Easy to detect = lower priority
                "medium": 0.5,
                "hard": 0.8,
                "very_hard": 1.0  # Hard to detect = higher priority
            }
        }
    
    def _initialize_urgency_matrix(self) -> Dict[Tuple[str, str], RemediationUrgency]:
        """Initialize urgency matrix based on priority and time horizon."""
        return {
            (PriorityLevel.CRITICAL.value, TimeHorizon.IMMEDIATE.value): RemediationUrgency.EMERGENCY,
            (PriorityLevel.CRITICAL.value, TimeHorizon.SHORT_TERM.value): RemediationUrgency.URGENT,
            (PriorityLevel.CRITICAL.value, TimeHorizon.MEDIUM_TERM.value): RemediationUrgency.HIGH,
            (PriorityLevel.HIGH.value, TimeHorizon.IMMEDIATE.value): RemediationUrgency.URGENT,
            (PriorityLevel.HIGH.value, TimeHorizon.SHORT_TERM.value): RemediationUrgency.HIGH,
            (PriorityLevel.HIGH.value, TimeHorizon.MEDIUM_TERM.value): RemediationUrgency.MEDIUM,
            (PriorityLevel.MEDIUM.value, TimeHorizon.IMMEDIATE.value): RemediationUrgency.HIGH,
            (PriorityLevel.MEDIUM.value, TimeHorizon.SHORT_TERM.value): RemediationUrgency.MEDIUM,
            (PriorityLevel.MEDIUM.value, TimeHorizon.MEDIUM_TERM.value): RemediationUrgency.LOW,
            (PriorityLevel.LOW.value, TimeHorizon.IMMEDIATE.value): RemediationUrgency.MEDIUM,
            (PriorityLevel.LOW.value, TimeHorizon.SHORT_TERM.value): RemediationUrgency.LOW,
            (PriorityLevel.LOW.value, TimeHorizon.MEDIUM_TERM.value): RemediationUrgency.LOW
        }
    
    def _initialize_time_horizon_factors(self) -> Dict[str, float]:
        """Initialize time horizon adjustment factors."""
        return {
            TimeHorizon.IMMEDIATE.value: 1.2,  # Boost immediate threats
            TimeHorizon.SHORT_TERM.value: 1.0,
            TimeHorizon.MEDIUM_TERM.value: 0.8,
            TimeHorizon.LONG_TERM.value: 0.6
        }
    
    def _score_and_rank_threat(
        self,
        threat: Dict[str, Any],
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> ThreatPriorityItem:
        """Score and rank a single threat."""
        
        # Calculate priority score
        priority_score = self.calculate_priority_score(
            threat, tool_capabilities, environment_context
        )
        
        # Determine time horizon
        time_horizon = self._determine_time_horizon(threat)
        
        # Determine remediation urgency
        urgency = self._determine_remediation_urgency(priority_score.priority_level, time_horizon)
        
        # Extract or generate other fields
        item_id = threat.get("id", f"threat_{hash(str(threat))}")
        item_name = threat.get("name", "Unknown Threat")
        item_type = threat.get("type", "threat")
        description = threat.get("description", "No description available")
        
        # Identify affected assets
        affected_assets = self._identify_affected_assets(threat, tool_capabilities)
        
        # Generate potential impact description
        potential_impact = self._generate_impact_description(threat, priority_score)
        
        # Generate required actions
        required_actions = self._generate_required_actions(threat, priority_score)
        
        # Identify dependencies
        dependencies = threat.get("dependencies", [])
        
        # Estimate effort
        estimated_effort = self._estimate_remediation_effort(threat, priority_score)
        
        # Calculate success probability
        success_probability = self._calculate_success_probability(threat, tool_capabilities)
        
        return ThreatPriorityItem(
            item_id=item_id,
            item_name=item_name,
            item_type=item_type,
            description=description,
            priority_score=priority_score,
            time_horizon=time_horizon,
            remediation_urgency=urgency,
            affected_assets=affected_assets,
            potential_impact=potential_impact,
            required_actions=required_actions,
            dependencies=dependencies,
            estimated_effort=estimated_effort,
            success_probability=success_probability
        )
    
    def _calculate_severity_factor(self, threat_data: Dict[str, Any]) -> ScoreFactor:
        """Calculate severity scoring factor."""
        severity_str = threat_data.get("severity", "medium").lower()
        raw_score = self._scoring_models["severity"].get(severity_str, 0.5)
        weighted_score = raw_score * self.scoring_weights.severity_weight
        
        return ScoreFactor(
            factor_name="Severity",
            factor_type=RiskFactor.SEVERITY,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.severity_weight,
            description=f"Threat severity level: {severity_str}",
            data_sources=["threat_analysis"]
        )
    
    def _calculate_likelihood_factor(self, threat_data: Dict[str, Any]) -> ScoreFactor:
        """Calculate likelihood scoring factor."""
        likelihood_str = threat_data.get("likelihood", "medium").lower()
        raw_score = self._scoring_models["likelihood"].get(likelihood_str, 0.5)
        weighted_score = raw_score * self.scoring_weights.likelihood_weight
        
        return ScoreFactor(
            factor_name="Likelihood",
            factor_type=RiskFactor.LIKELIHOOD,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.likelihood_weight,
            description=f"Attack likelihood: {likelihood_str}",
            data_sources=["likelihood_assessment"]
        )
    
    def _calculate_business_impact_factor(
        self, threat_data: Dict[str, Any], environment_context: EnvironmentContext
    ) -> ScoreFactor:
        """Calculate business impact scoring factor."""
        # Base impact from threat data
        base_impact = threat_data.get("business_impact", 0.5)
        if isinstance(base_impact, str):
            impact_mapping = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
            base_impact = impact_mapping.get(base_impact.lower(), 0.5)
        
        # Adjust for environment factors
        if hasattr(environment_context, 'data_sensitivity'):
            sensitivity_multiplier = {
                "public": 0.5,
                "internal": 0.7,
                "confidential": 0.9,
                "restricted": 1.0,
                "top_secret": 1.2
            }.get(environment_context.data_sensitivity.value, 0.7)
            base_impact *= sensitivity_multiplier
        
        raw_score = min(base_impact, 1.0)
        weighted_score = raw_score * self.scoring_weights.business_impact_weight
        
        return ScoreFactor(
            factor_name="Business Impact",
            factor_type=RiskFactor.BUSINESS_IMPACT,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.business_impact_weight,
            description="Potential business impact of successful attack",
            data_sources=["impact_analysis", "environment_context"]
        )
    
    def _calculate_exploitability_factor(
        self, threat_data: Dict[str, Any], tool_capabilities: ToolCapabilities
    ) -> ScoreFactor:
        """Calculate exploitability scoring factor."""
        # Get complexity from threat data
        complexity = threat_data.get("complexity", "medium").lower()
        base_score = self._scoring_models["exploitability"].get(complexity, 0.6)
        
        # Adjust for tool-specific factors
        if tool_capabilities.external_access:
            base_score *= 1.2  # Easier to exploit if externally accessible
        
        if tool_capabilities.requires_privileges:
            base_score *= 0.8  # Harder to exploit if privileges required
        
        raw_score = min(base_score, 1.0)
        weighted_score = raw_score * self.scoring_weights.exploitability_weight
        
        return ScoreFactor(
            factor_name="Exploitability",
            factor_type=RiskFactor.EXPLOITABILITY,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.exploitability_weight,
            description=f"Ease of exploitation (complexity: {complexity})",
            data_sources=["vulnerability_analysis", "tool_capabilities"]
        )
    
    def _calculate_detectability_factor(self, threat_data: Dict[str, Any]) -> ScoreFactor:
        """Calculate detectability scoring factor."""
        detectability = threat_data.get("detectability", "medium").lower()
        raw_score = self._scoring_models["detectability"].get(detectability, 0.5)
        weighted_score = raw_score * self.scoring_weights.detectability_weight
        
        return ScoreFactor(
            factor_name="Detectability",
            factor_type=RiskFactor.DETECTABILITY,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.detectability_weight,
            description=f"Difficulty of attack detection: {detectability}",
            data_sources=["detection_analysis"]
        )
    
    def _calculate_remediation_difficulty_factor(self, threat_data: Dict[str, Any]) -> ScoreFactor:
        """Calculate remediation difficulty scoring factor."""
        difficulty = threat_data.get("remediation_difficulty", "medium").lower()
        
        # Higher difficulty = higher priority (harder to fix = more concerning)
        difficulty_scores = {"easy": 0.2, "medium": 0.5, "hard": 0.8, "very_hard": 1.0}
        raw_score = difficulty_scores.get(difficulty, 0.5)
        weighted_score = raw_score * self.scoring_weights.remediation_difficulty_weight
        
        return ScoreFactor(
            factor_name="Remediation Difficulty",
            factor_type=RiskFactor.REMEDIATION_DIFFICULTY,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.remediation_difficulty_weight,
            description=f"Difficulty of remediation: {difficulty}",
            data_sources=["remediation_analysis"]
        )
    
    def _calculate_attack_surface_factor(
        self, threat_data: Dict[str, Any], tool_capabilities: ToolCapabilities
    ) -> ScoreFactor:
        """Calculate attack surface scoring factor."""
        # Base attack surface from threat data
        base_surface = threat_data.get("attack_surface", 0.5)
        
        # Adjust based on tool capabilities
        surface_contributors = 0
        if tool_capabilities.external_access:
            surface_contributors += 1
        if len(tool_capabilities.capability_categories) > 3:
            surface_contributors += 1
        if tool_capabilities.requires_privileges:
            surface_contributors -= 0.5  # Reduces surface due to access barriers
        
        raw_score = min(base_surface + (surface_contributors * 0.2), 1.0)
        weighted_score = raw_score * self.scoring_weights.attack_surface_weight
        
        return ScoreFactor(
            factor_name="Attack Surface",
            factor_type=RiskFactor.ATTACK_SURFACE,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.attack_surface_weight,
            description="Size and exposure of attack surface",
            data_sources=["surface_analysis", "tool_capabilities"]
        )
    
    def _calculate_regulatory_impact_factor(
        self, threat_data: Dict[str, Any], environment_context: EnvironmentContext
    ) -> ScoreFactor:
        """Calculate regulatory impact scoring factor."""
        base_impact = 0.0
        
        # Check for compliance requirements
        if hasattr(environment_context, 'compliance_requirements'):
            compliance_count = len(environment_context.compliance_requirements)
            base_impact = min(compliance_count * 0.2, 1.0)
        
        # Adjust for specific regulatory violations mentioned in threat
        regulatory_keywords = ["gdpr", "hipaa", "pci", "sox", "compliance", "regulation"]
        threat_text = str(threat_data).lower()
        regulatory_mentions = sum(1 for keyword in regulatory_keywords if keyword in threat_text)
        
        if regulatory_mentions > 0:
            base_impact = max(base_impact, 0.6)
        
        raw_score = base_impact
        weighted_score = raw_score * self.scoring_weights.regulatory_impact_weight
        
        return ScoreFactor(
            factor_name="Regulatory Impact",
            factor_type=RiskFactor.REGULATORY_IMPACT,
            raw_score=raw_score,
            weighted_score=weighted_score,
            weight=self.scoring_weights.regulatory_impact_weight,
            description="Potential regulatory compliance impact",
            data_sources=["compliance_analysis", "environment_context"]
        )
    
    def _determine_priority_level(self, overall_score: float) -> PriorityLevel:
        """Determine priority level from overall score."""
        if overall_score >= self._priority_thresholds[PriorityLevel.CRITICAL.value]:
            return PriorityLevel.CRITICAL
        elif overall_score >= self._priority_thresholds[PriorityLevel.HIGH.value]:
            return PriorityLevel.HIGH
        elif overall_score >= self._priority_thresholds[PriorityLevel.MEDIUM.value]:
            return PriorityLevel.MEDIUM
        elif overall_score >= self._priority_thresholds[PriorityLevel.LOW.value]:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.MINIMAL
    
    def _calculate_score_confidence(self, score_factors: List[ScoreFactor]) -> float:
        """Calculate confidence in the priority score."""
        if not score_factors:
            return 0.0
        
        # Average confidence across all factors
        avg_confidence = sum(factor.confidence for factor in score_factors) / len(score_factors)
        
        # Adjust for data source diversity
        unique_sources = set()
        for factor in score_factors:
            unique_sources.update(factor.data_sources)
        
        source_diversity_bonus = min(len(unique_sources) * 0.05, 0.2)
        
        return min(avg_confidence + source_diversity_bonus, 1.0)
    
    def _generate_score_rationale(
        self, score_factors: List[ScoreFactor], overall_score: float
    ) -> str:
        """Generate textual rationale for the priority score."""
        # Identify top contributing factors
        top_factors = sorted(score_factors, key=lambda f: f.weighted_score, reverse=True)[:3]
        
        rationale_parts = [
            f"Overall priority score: {overall_score:.2f}"
        ]
        
        for factor in top_factors:
            contribution_pct = (factor.weighted_score / overall_score) * 100 if overall_score > 0 else 0
            rationale_parts.append(
                f"{factor.factor_name} contributes {contribution_pct:.1f}% "
                f"(score: {factor.raw_score:.2f})"
            )
        
        return ". ".join(rationale_parts) + "."
    
    def _identify_key_drivers(self, score_factors: List[ScoreFactor]) -> List[str]:
        """Identify key drivers of the priority score."""
        # Sort by weighted contribution
        sorted_factors = sorted(score_factors, key=lambda f: f.weighted_score, reverse=True)
        
        # Take top factors that contribute significantly
        key_drivers = []
        total_score = sum(f.weighted_score for f in score_factors)
        
        for factor in sorted_factors:
            if factor.weighted_score / total_score > 0.15:  # >15% contribution
                driver_desc = f"{factor.factor_name} ({factor.raw_score:.2f})"
                key_drivers.append(driver_desc)
        
        return key_drivers[:5]  # Limit to top 5 drivers
    
    def _determine_time_horizon(self, threat_data: Dict[str, Any]) -> TimeHorizon:
        """Determine time horizon for threat materialization."""
        # Check if explicitly specified
        if "time_horizon" in threat_data:
            horizon_str = threat_data["time_horizon"].lower()
            for horizon in TimeHorizon:
                if horizon.value == horizon_str:
                    return horizon
        
        # Infer from threat characteristics
        severity = threat_data.get("severity", "medium").lower()
        likelihood = threat_data.get("likelihood", "medium").lower()
        
        if severity == "critical" and likelihood in ["high", "very_high"]:
            return TimeHorizon.IMMEDIATE
        elif severity in ["critical", "high"] or likelihood in ["high", "very_high"]:
            return TimeHorizon.SHORT_TERM
        elif severity == "medium" or likelihood == "medium":
            return TimeHorizon.MEDIUM_TERM
        else:
            return TimeHorizon.LONG_TERM
    
    def _determine_remediation_urgency(
        self, priority_level: PriorityLevel, time_horizon: TimeHorizon
    ) -> RemediationUrgency:
        """Determine remediation urgency from priority and time horizon."""
        key = (priority_level.value, time_horizon.value)
        return self._urgency_matrix.get(key, RemediationUrgency.MEDIUM)
    
    def _identify_affected_assets(
        self, threat_data: Dict[str, Any], tool_capabilities: ToolCapabilities
    ) -> List[str]:
        """Identify assets affected by the threat."""
        # Start with explicitly mentioned assets
        assets = threat_data.get("affected_assets", [])
        
        # Add assets based on tool capabilities
        capability_assets = {
            "file_system": ["file_systems", "data_stores"],
            "network_access": ["network_infrastructure", "connected_systems"],
            "database_access": ["databases", "data_repositories"],
            "code_execution": ["application_servers", "compute_resources"],
            "authentication": ["identity_systems", "user_accounts"]
        }
        
        for capability in tool_capabilities.capability_categories:
            cap_name = capability.value.lower()
            if cap_name in capability_assets:
                assets.extend(capability_assets[cap_name])
        
        # Remove duplicates
        return list(set(assets))
    
    def _generate_impact_description(
        self, threat_data: Dict[str, Any], priority_score: PriorityScore
    ) -> str:
        """Generate potential impact description."""
        severity = threat_data.get("severity", "medium")
        threat_type = threat_data.get("type", "security threat")
        
        impact_templates = {
            "critical": f"Critical {threat_type} with potential for severe business disruption, "
                      "data compromise, and significant financial impact.",
            "high": f"High-impact {threat_type} that could result in data breach, "
                   "service interruption, or compliance violations.",
            "medium": f"Moderate {threat_type} with potential for limited data exposure "
                     "or operational disruption.",
            "low": f"Low-impact {threat_type} with minimal potential for business disruption."
        }
        
        base_description = impact_templates.get(severity.lower(), 
                                               f"{threat_type.title()} with uncertain impact level.")
        
        # Add priority-specific details
        if priority_score.priority_level == PriorityLevel.CRITICAL:
            base_description += " Immediate attention required."
        elif priority_score.priority_level == PriorityLevel.HIGH:
            base_description += " Prompt remediation recommended."
        
        return base_description
    
    def _generate_required_actions(
        self, threat_data: Dict[str, Any], priority_score: PriorityScore
    ) -> List[str]:
        """Generate required actions for threat remediation."""
        actions = []
        
        # Priority-based actions
        if priority_score.priority_level == PriorityLevel.CRITICAL:
            actions.extend([
                "Implement immediate containment measures",
                "Activate incident response team",
                "Notify senior management and stakeholders"
            ])
        elif priority_score.priority_level == PriorityLevel.HIGH:
            actions.extend([
                "Schedule urgent remediation activities",
                "Implement temporary mitigations",
                "Monitor for exploitation attempts"
            ])
        else:
            actions.extend([
                "Plan remediation in next maintenance window",
                "Monitor threat landscape for changes"
            ])
        
        # Threat-specific actions
        threat_type = threat_data.get("type", "").lower()
        if "vulnerability" in threat_type:
            actions.append("Apply security patches or updates")
        if "configuration" in threat_type:
            actions.append("Review and harden configuration settings")
        if "access" in threat_type:
            actions.append("Review and restrict access permissions")
        
        return actions[:6]  # Limit to 6 actions
    
    def _estimate_remediation_effort(
        self, threat_data: Dict[str, Any], priority_score: PriorityScore
    ) -> str:
        """Estimate effort required for remediation."""
        # Base effort from threat data
        base_effort = threat_data.get("remediation_difficulty", "medium").lower()
        
        # Adjust based on priority and complexity
        if priority_score.priority_level == PriorityLevel.CRITICAL:
            if base_effort == "easy":
                return "Low"
            elif base_effort == "medium":
                return "Medium"
            else:
                return "High"
        else:
            effort_mapping = {"easy": "Low", "medium": "Medium", "hard": "High", "very_hard": "Very High"}
            return effort_mapping.get(base_effort, "Medium")
    
    def _calculate_success_probability(
        self, threat_data: Dict[str, Any], tool_capabilities: ToolCapabilities
    ) -> float:
        """Calculate probability of successful remediation."""
        base_probability = 0.8
        
        # Adjust for remediation difficulty
        difficulty = threat_data.get("remediation_difficulty", "medium").lower()
        difficulty_adjustments = {"easy": 0.1, "medium": 0.0, "hard": -0.1, "very_hard": -0.2}
        base_probability += difficulty_adjustments.get(difficulty, 0.0)
        
        # Adjust for tool complexity
        if len(tool_capabilities.tool_functions) > 10:
            base_probability -= 0.1  # More complex tools are harder to remediate
        
        # Adjust for external dependencies
        if tool_capabilities.external_access:
            base_probability -= 0.05  # External dependencies complicate remediation
        
        return max(0.3, min(base_probability, 0.95))  # Keep within reasonable bounds
    
    def _generate_immediate_actions(self, ranked_items: List[ThreatPriorityItem]) -> List[str]:
        """Generate immediate action items."""
        immediate_actions = []
        
        # Focus on critical and emergency items
        critical_items = [
            item for item in ranked_items[:10]  # Top 10 items
            if item.priority_score.priority_level == PriorityLevel.CRITICAL or
               item.remediation_urgency == RemediationUrgency.EMERGENCY
        ]
        
        for item in critical_items:
            actions = [action for action in item.required_actions 
                      if any(keyword in action.lower() for keyword in 
                            ["immediate", "urgent", "activate", "notify"])]
            immediate_actions.extend(actions)
        
        # Add general immediate actions
        if critical_items:
            immediate_actions.extend([
                "Review and validate security monitoring alerts",
                "Ensure incident response procedures are ready",
                "Verify backup and recovery capabilities"
            ])
        
        return list(set(immediate_actions))[:8]  # Remove duplicates, limit to 8
    
    def _generate_short_term_actions(self, ranked_items: List[ThreatPriorityItem]) -> List[str]:
        """Generate short-term action items (1-7 days)."""
        short_term_actions = []
        
        # Focus on high-priority items with appropriate time horizons
        relevant_items = [
            item for item in ranked_items
            if item.time_horizon in [TimeHorizon.IMMEDIATE, TimeHorizon.SHORT_TERM] and
               item.priority_score.priority_level in [PriorityLevel.CRITICAL, PriorityLevel.HIGH]
        ]
        
        for item in relevant_items[:15]:  # Top 15 relevant items
            actions = [action for action in item.required_actions
                      if not any(keyword in action.lower() for keyword in 
                                ["immediate", "urgent", "activate", "notify"])]
            short_term_actions.extend(actions[:2])  # Max 2 actions per item
        
        return list(set(short_term_actions))[:10]  # Remove duplicates, limit to 10
    
    def _generate_long_term_actions(self, ranked_items: List[ThreatPriorityItem]) -> List[str]:
        """Generate long-term action items (weeks to months)."""
        long_term_actions = [
            "Conduct comprehensive security assessment",
            "Review and update security policies and procedures",
            "Implement security awareness training programs",
            "Establish regular vulnerability assessment schedule",
            "Review and enhance incident response capabilities",
            "Evaluate and upgrade security monitoring tools",
            "Conduct penetration testing and red team exercises",
            "Review third-party security vendor arrangements"
        ]
        
        # Add specific actions for medium/low priority items
        medium_low_items = [
            item for item in ranked_items
            if item.priority_score.priority_level in [PriorityLevel.MEDIUM, PriorityLevel.LOW] and
               item.time_horizon in [TimeHorizon.MEDIUM_TERM, TimeHorizon.LONG_TERM]
        ]
        
        for item in medium_low_items[:10]:
            long_term_actions.extend(item.required_actions[:1])  # 1 action per item
        
        return list(set(long_term_actions))[:12]  # Remove duplicates, limit to 12
    
    def _generate_resource_allocation_guidance(
        self, ranked_items: List[ThreatPriorityItem]
    ) -> Dict[str, Any]:
        """Generate resource allocation guidance."""
        critical_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.CRITICAL])
        high_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.HIGH])
        
        # Calculate effort distribution
        total_items = len(ranked_items)
        high_priority_items = critical_count + high_count
        
        guidance = {
            "immediate_focus": f"{critical_count} critical items requiring immediate attention",
            "resource_distribution": {
                "critical_items": f"{(critical_count/total_items)*100:.1f}% of immediate resources",
                "high_priority": f"{(high_count/total_items)*100:.1f}% of short-term resources",
                "other_items": f"{((total_items-high_priority_items)/total_items)*100:.1f}% of long-term resources"
            },
            "staffing_recommendations": self._generate_staffing_recommendations(ranked_items),
            "budget_considerations": self._generate_budget_considerations(ranked_items),
            "timeline_recommendations": self._generate_timeline_recommendations(ranked_items)
        }
        
        return guidance
    
    def _generate_staffing_recommendations(self, ranked_items: List[ThreatPriorityItem]) -> List[str]:
        """Generate staffing recommendations."""
        recommendations = []
        
        critical_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.CRITICAL])
        
        if critical_count > 5:
            recommendations.append("Consider establishing dedicated incident response team")
        if critical_count > 2:
            recommendations.append("Ensure 24/7 security operations coverage")
        
        recommendations.extend([
            "Assign senior security professionals to critical items",
            "Ensure adequate technical expertise for remediation activities",
            "Consider engaging external security consultants for complex issues"
        ])
        
        return recommendations
    
    def _generate_budget_considerations(self, ranked_items: List[ThreatPriorityItem]) -> List[str]:
        """Generate budget considerations."""
        considerations = []
        
        critical_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.CRITICAL])
        high_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.HIGH])
        
        if critical_count > 0:
            considerations.append("Allocate emergency budget for critical item remediation")
        
        if high_count > 3:
            considerations.append("Plan additional security budget for high-priority items")
        
        considerations.extend([
            "Consider cost-benefit analysis for complex remediation projects",
            "Evaluate security tooling investments based on priority items",
            "Budget for external consultant support if needed"
        ])
        
        return considerations
    
    def _generate_timeline_recommendations(self, ranked_items: List[ThreatPriorityItem]) -> Dict[str, str]:
        """Generate timeline recommendations."""
        emergency_items = len([i for i in ranked_items if i.remediation_urgency == RemediationUrgency.EMERGENCY])
        urgent_items = len([i for i in ranked_items if i.remediation_urgency == RemediationUrgency.URGENT])
        
        return {
            "immediate": f"Address {emergency_items} emergency items within hours",
            "24_hours": f"Begin work on {urgent_items} urgent items within 24 hours",
            "1_week": "Complete high-priority remediation activities within 1 week",
            "1_month": "Address all medium-priority items within 1 month",
            "quarterly": "Review and address low-priority items quarterly"
        }
    
    def _create_executive_summary(
        self, ranked_items: List[ThreatPriorityItem], critical_items: List[ThreatPriorityItem]
    ) -> str:
        """Create executive summary of priority assessment."""
        total_items = len(ranked_items)
        critical_count = len(critical_items)
        high_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.HIGH])
        
        summary_parts = [
            f"Priority assessment identified {total_items} security items requiring attention.",
            f"{critical_count} items classified as CRITICAL priority requiring immediate action.",
            f"{high_count} items classified as HIGH priority requiring prompt attention."
        ]
        
        if critical_count > 0:
            summary_parts.append("Immediate mobilization of security resources recommended for critical items.")
        
        if critical_count + high_count > total_items * 0.3:
            summary_parts.append("Significant security attention required - consider additional resources.")
        
        return " ".join(summary_parts)
    
    def _assess_risk_appetite_alignment(self, ranked_items: List[ThreatPriorityItem]) -> str:
        """Assess alignment with organizational risk appetite."""
        critical_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.CRITICAL])
        high_count = len([i for i in ranked_items if i.priority_score.priority_level == PriorityLevel.HIGH])
        total_items = len(ranked_items)
        
        high_risk_percentage = ((critical_count + high_count) / total_items) * 100 if total_items > 0 else 0
        
        if high_risk_percentage > 40:
            return "Risk levels exceed typical organizational appetite - aggressive remediation recommended"
        elif high_risk_percentage > 20:
            return "Risk levels within elevated range - active management required"
        else:
            return "Risk levels within acceptable range - standard monitoring and remediation processes appropriate"
    
    def _adjust_item_priority(
        self, item: ThreatPriorityItem, business_context: Dict[str, Any]
    ) -> ThreatPriorityItem:
        """Adjust individual item priority based on business context."""
        # This is a placeholder for business context adjustments
        # In practice, this would adjust scores based on factors like:
        # - Business critical periods (e.g., holiday shopping season)
        # - Resource constraints
        # - Strategic business initiatives
        # - Regulatory deadlines
        
        adjustment_factor = business_context.get("priority_adjustment", 1.0)
        
        # Adjust the overall score
        adjusted_score = min(item.priority_score.overall_score * adjustment_factor, 1.0)
        
        # Update priority level if needed
        adjusted_priority_level = self._determine_priority_level(adjusted_score)
        
        # Create adjusted priority score
        item.priority_score.overall_score = adjusted_score
        item.priority_score.priority_level = adjusted_priority_level
        
        return item 