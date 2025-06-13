"""
Composite Risk Score Calculation for MCP Introspection

Provides comprehensive risk scoring algorithms that combine multiple risk factors
to generate composite risk scores for better prioritization and decision making.
"""

import logging
import math
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..models import (
    MCPServerInfo, MCPTool, MCPResource, SecurityRisk,
    RiskLevel, RiskCategory
)
from .threat_model import ThreatVector, ThreatModel
from .categorizer import RiskProfile, RiskClassification, RiskDomain


class ScoreComponent(str, Enum):
    """Components that contribute to risk scoring."""
    SEVERITY = "severity"
    LIKELIHOOD = "likelihood"
    IMPACT = "impact"
    EXPOSURE = "exposure"
    EXPLOITABILITY = "exploitability"
    BUSINESS_IMPACT = "business_impact"
    TECHNICAL_IMPACT = "technical_impact"
    COMPLIANCE_IMPACT = "compliance_impact"


class ScoreMethod(str, Enum):
    """Risk scoring methodologies."""
    CVSS_LIKE = "cvss_like"
    WEIGHTED_AVERAGE = "weighted_average"
    MULTIPLICATIVE = "multiplicative"
    MAXIMUM = "maximum"
    CUSTOM = "custom"


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of risk score components."""
    total_score: float
    severity_score: float
    likelihood_score: float
    impact_score: float
    exposure_score: float
    exploitability_score: float
    business_impact_score: float
    technical_impact_score: float
    compliance_impact_score: float
    method: ScoreMethod
    confidence: float  # 0.0 to 1.0
    
    def get_component_scores(self) -> Dict[ScoreComponent, float]:
        """Get all component scores as a dictionary."""
        return {
            ScoreComponent.SEVERITY: self.severity_score,
            ScoreComponent.LIKELIHOOD: self.likelihood_score,
            ScoreComponent.IMPACT: self.impact_score,
            ScoreComponent.EXPOSURE: self.exposure_score,
            ScoreComponent.EXPLOITABILITY: self.exploitability_score,
            ScoreComponent.BUSINESS_IMPACT: self.business_impact_score,
            ScoreComponent.TECHNICAL_IMPACT: self.technical_impact_score,
            ScoreComponent.COMPLIANCE_IMPACT: self.compliance_impact_score,
        }


@dataclass
class CompositeRiskScore:
    """Composite risk score with detailed analysis."""
    server_id: str
    overall_score: float  # 0.0 to 10.0
    risk_level: RiskLevel
    score_breakdown: ScoreBreakdown
    contributing_risks: List[SecurityRisk] = field(default_factory=list)
    threat_vectors: List[ThreatVector] = field(default_factory=list)
    risk_profiles: Dict[RiskCategory, RiskProfile] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def get_risk_level_from_score(self) -> RiskLevel:
        """Determine risk level from numeric score."""
        if self.overall_score >= 9.0:
            return RiskLevel.CRITICAL
        elif self.overall_score >= 7.0:
            return RiskLevel.HIGH
        elif self.overall_score >= 4.0:
            return RiskLevel.MEDIUM
        elif self.overall_score >= 1.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def get_priority_rank(self) -> int:
        """Get priority rank (1-5, where 1 is highest priority)."""
        if self.overall_score >= 9.0:
            return 1
        elif self.overall_score >= 7.0:
            return 2
        elif self.overall_score >= 4.0:
            return 3
        elif self.overall_score >= 1.0:
            return 4
        else:
            return 5


class RiskScorer:
    """
    Calculates composite risk scores using multiple methodologies.
    
    Combines various risk factors including severity, likelihood, impact,
    and business context to generate comprehensive risk scores.
    """
    
    def __init__(self, method: ScoreMethod = ScoreMethod.CVSS_LIKE):
        """Initialize the risk scorer with specified method."""
        self.logger = logging.getLogger(__name__)
        self.method = method
        self._component_weights = self._initialize_component_weights()
        self._severity_mappings = self._initialize_severity_mappings()
        self._category_weights = self._initialize_category_weights()
    
    def calculate_server_score(self, server_info: MCPServerInfo, 
                             threat_model: Optional[ThreatModel] = None,
                             risk_profiles: Optional[Dict[RiskCategory, RiskProfile]] = None) -> CompositeRiskScore:
        """
        Calculate composite risk score for an MCP server.
        
        Args:
            server_info: Server information with risks and capabilities
            threat_model: Optional threat model for the server
            risk_profiles: Optional risk profiles for categorized risks
            
        Returns:
            Composite risk score with detailed breakdown
        """
        # Collect all risks
        all_risks = server_info.security_risks.copy()
        
        # Calculate component scores
        severity_score = self._calculate_severity_score(all_risks)
        likelihood_score = self._calculate_likelihood_score(all_risks, threat_model)
        impact_score = self._calculate_impact_score(all_risks, server_info)
        exposure_score = self._calculate_exposure_score(server_info)
        exploitability_score = self._calculate_exploitability_score(all_risks, threat_model)
        business_impact_score = self._calculate_business_impact_score(all_risks, risk_profiles)
        technical_impact_score = self._calculate_technical_impact_score(all_risks, server_info)
        compliance_impact_score = self._calculate_compliance_impact_score(all_risks, risk_profiles)
        
        # Calculate overall score using selected method
        overall_score = self._calculate_composite_score(
            severity_score, likelihood_score, impact_score, exposure_score,
            exploitability_score, business_impact_score, technical_impact_score,
            compliance_impact_score
        )
        
        # Create score breakdown
        breakdown = ScoreBreakdown(
            total_score=overall_score,
            severity_score=severity_score,
            likelihood_score=likelihood_score,
            impact_score=impact_score,
            exposure_score=exposure_score,
            exploitability_score=exploitability_score,
            business_impact_score=business_impact_score,
            technical_impact_score=technical_impact_score,
            compliance_impact_score=compliance_impact_score,
            method=self.method,
            confidence=self._calculate_confidence(all_risks, threat_model)
        )
        
        # Create composite score
        composite_score = CompositeRiskScore(
            server_id=server_info.server_id,
            overall_score=overall_score,
            risk_level=self._score_to_risk_level(overall_score),
            score_breakdown=breakdown,
            contributing_risks=all_risks,
            threat_vectors=threat_model.threat_vectors if threat_model else [],
            risk_profiles=risk_profiles or {},
            recommendations=self._generate_score_recommendations(overall_score, breakdown)
        )
        
        self.logger.info(f"Calculated risk score for server '{server_info.server_id}': "
                        f"{overall_score:.2f} ({composite_score.risk_level.value})")
        
        return composite_score
    
    def calculate_multiple_scores(self, servers: List[MCPServerInfo],
                                threat_models: Optional[Dict[str, ThreatModel]] = None,
                                risk_profiles: Optional[Dict[str, Dict[RiskCategory, RiskProfile]]] = None) -> Dict[str, CompositeRiskScore]:
        """
        Calculate risk scores for multiple servers.
        
        Args:
            servers: List of server information
            threat_models: Optional threat models by server ID
            risk_profiles: Optional risk profiles by server ID
            
        Returns:
            Dictionary mapping server IDs to their composite risk scores
        """
        scores = {}
        
        for server in servers:
            try:
                threat_model = threat_models.get(server.server_id) if threat_models else None
                server_profiles = risk_profiles.get(server.server_id) if risk_profiles else None
                
                score = self.calculate_server_score(server, threat_model, server_profiles)
                scores[server.server_id] = score
            except Exception as e:
                self.logger.error(f"Error calculating score for server '{server.server_id}': {e}")
                # Create minimal score with error
                scores[server.server_id] = CompositeRiskScore(
                    server_id=server.server_id,
                    overall_score=0.0,
                    risk_level=RiskLevel.UNKNOWN,
                    score_breakdown=ScoreBreakdown(
                        total_score=0.0,
                        severity_score=0.0,
                        likelihood_score=0.0,
                        impact_score=0.0,
                        exposure_score=0.0,
                        exploitability_score=0.0,
                        business_impact_score=0.0,
                        technical_impact_score=0.0,
                        compliance_impact_score=0.0,
                        method=self.method,
                        confidence=0.0
                    ),
                    recommendations=[f"Error calculating score: {str(e)}"]
                )
        
        return scores
    
    def rank_servers_by_risk(self, scores: Dict[str, CompositeRiskScore]) -> List[Tuple[str, CompositeRiskScore]]:
        """
        Rank servers by their risk scores.
        
        Args:
            scores: Dictionary of server scores
            
        Returns:
            List of (server_id, score) tuples sorted by risk (highest first)
        """
        return sorted(
            scores.items(),
            key=lambda x: x[1].overall_score,
            reverse=True
        )
    
    def _calculate_severity_score(self, risks: List[SecurityRisk]) -> float:
        """Calculate severity component score."""
        if not risks:
            return 0.0
        
        severity_weights = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 8.0,
            RiskLevel.MEDIUM: 6.0,
            RiskLevel.LOW: 3.0,
            RiskLevel.MINIMAL: 1.0,
            RiskLevel.UNKNOWN: 0.0
        }
        
        total_weight = sum(severity_weights.get(risk.severity, 0.0) for risk in risks)
        return min(total_weight / len(risks), 10.0)
    
    def _calculate_likelihood_score(self, risks: List[SecurityRisk], 
                                  threat_model: Optional[ThreatModel]) -> float:
        """Calculate likelihood component score."""
        if not threat_model or not threat_model.threat_vectors:
            # Base likelihood on risk count and types
            if not risks:
                return 0.0
            
            # More risks = higher likelihood
            risk_count_factor = min(len(risks) / 10.0, 1.0)  # Normalize to 0-1
            
            # High-severity risks increase likelihood
            high_severity_count = sum(1 for r in risks if r.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH])
            severity_factor = min(high_severity_count / 5.0, 1.0)  # Normalize to 0-1
            
            return (risk_count_factor * 0.6 + severity_factor * 0.4) * 10.0
        
        # Use threat model likelihood data
        avg_likelihood = sum(t.likelihood for t in threat_model.threat_vectors) / len(threat_model.threat_vectors)
        return avg_likelihood * 10.0
    
    def _calculate_impact_score(self, risks: List[SecurityRisk], server_info: MCPServerInfo) -> float:
        """Calculate impact component score."""
        if not risks:
            return 0.0
        
        # Base impact on risk categories and server capabilities
        category_impacts = {
            RiskCategory.CODE_EXECUTION: 10.0,
            RiskCategory.SYSTEM_MODIFICATION: 9.0,
            RiskCategory.DATA_ACCESS: 8.0,
            RiskCategory.AUTHENTICATION: 8.0,
            RiskCategory.NETWORK_ACCESS: 7.0,
            RiskCategory.FILE_SYSTEM: 7.0,
            RiskCategory.DATABASE: 8.0,
            RiskCategory.ENCRYPTION: 6.0,
            RiskCategory.EXTERNAL_API: 5.0,
            RiskCategory.CLOUD_SERVICES: 6.0,
            RiskCategory.UNKNOWN: 3.0
        }
        
        max_impact = 0.0
        for risk in risks:
            try:
                category = RiskCategory(risk.category)
                impact = category_impacts.get(category, 3.0)
                max_impact = max(max_impact, impact)
            except ValueError:
                max_impact = max(max_impact, 3.0)
        
        # Adjust based on server capabilities
        capability_multiplier = 1.0
        if server_info.tools:
            capability_multiplier += len(server_info.tools) * 0.1
        if server_info.resources:
            capability_multiplier += len(server_info.resources) * 0.05
        
        return min(max_impact * capability_multiplier, 10.0)
    
    def _calculate_exposure_score(self, server_info: MCPServerInfo) -> float:
        """Calculate exposure component score."""
        exposure = 0.0
        
        # Network exposure
        if server_info.server_url:
            exposure += 3.0  # Network accessible
        
        # Tool exposure
        tool_count = len(server_info.tools)
        exposure += min(tool_count * 0.5, 4.0)
        
        # Resource exposure
        resource_count = len(server_info.resources)
        exposure += min(resource_count * 0.3, 3.0)
        
        return min(exposure, 10.0)
    
    def _calculate_exploitability_score(self, risks: List[SecurityRisk], 
                                      threat_model: Optional[ThreatModel]) -> float:
        """Calculate exploitability component score."""
        if not risks:
            return 0.0
        
        # Base exploitability on risk types
        exploitable_categories = {
            RiskCategory.CODE_EXECUTION: 9.0,
            RiskCategory.AUTHENTICATION: 8.0,
            RiskCategory.NETWORK_ACCESS: 7.0,
            RiskCategory.FILE_SYSTEM: 6.0,
            RiskCategory.DATA_ACCESS: 5.0,
        }
        
        max_exploitability = 0.0
        for risk in risks:
            try:
                category = RiskCategory(risk.category)
                exploitability = exploitable_categories.get(category, 3.0)
                max_exploitability = max(max_exploitability, exploitability)
            except ValueError:
                max_exploitability = max(max_exploitability, 3.0)
        
        # Adjust based on threat vectors
        if threat_model and threat_model.threat_vectors:
            high_likelihood_threats = [t for t in threat_model.threat_vectors if t.likelihood > 0.7]
            if high_likelihood_threats:
                max_exploitability = min(max_exploitability * 1.5, 10.0)
        
        return max_exploitability
    
    def _calculate_business_impact_score(self, risks: List[SecurityRisk], 
                                       risk_profiles: Optional[Dict[RiskCategory, RiskProfile]]) -> float:
        """Calculate business impact component score."""
        if not risks:
            return 0.0
        
        business_categories = {
            RiskCategory.DATA_ACCESS: 8.0,
            RiskCategory.DATABASE: 8.0,
            RiskCategory.AUTHENTICATION: 7.0,
            RiskCategory.EXTERNAL_API: 6.0,
            RiskCategory.CLOUD_SERVICES: 6.0,
        }
        
        max_business_impact = 0.0
        for risk in risks:
            try:
                category = RiskCategory(risk.category)
                impact = business_categories.get(category, 2.0)
                max_business_impact = max(max_business_impact, impact)
            except ValueError:
                max_business_impact = max(max_business_impact, 2.0)
        
        return max_business_impact
    
    def _calculate_technical_impact_score(self, risks: List[SecurityRisk], 
                                        server_info: MCPServerInfo) -> float:
        """Calculate technical impact component score."""
        if not risks:
            return 0.0
        
        technical_categories = {
            RiskCategory.CODE_EXECUTION: 10.0,
            RiskCategory.SYSTEM_MODIFICATION: 9.0,
            RiskCategory.FILE_SYSTEM: 7.0,
            RiskCategory.NETWORK_ACCESS: 6.0,
        }
        
        max_technical_impact = 0.0
        for risk in risks:
            try:
                category = RiskCategory(risk.category)
                impact = technical_categories.get(category, 3.0)
                max_technical_impact = max(max_technical_impact, impact)
            except ValueError:
                max_technical_impact = max(max_technical_impact, 3.0)
        
        return max_technical_impact
    
    def _calculate_compliance_impact_score(self, risks: List[SecurityRisk], 
                                         risk_profiles: Optional[Dict[RiskCategory, RiskProfile]]) -> float:
        """Calculate compliance impact component score."""
        if not risks:
            return 0.0
        
        compliance_categories = {
            RiskCategory.DATA_ACCESS: 8.0,
            RiskCategory.AUTHENTICATION: 7.0,
            RiskCategory.ENCRYPTION: 6.0,
            RiskCategory.DATABASE: 7.0,
        }
        
        max_compliance_impact = 0.0
        for risk in risks:
            try:
                category = RiskCategory(risk.category)
                impact = compliance_categories.get(category, 2.0)
                max_compliance_impact = max(max_compliance_impact, impact)
            except ValueError:
                max_compliance_impact = max(max_compliance_impact, 2.0)
        
        return max_compliance_impact
    
    def _calculate_composite_score(self, severity: float, likelihood: float, impact: float,
                                 exposure: float, exploitability: float, business_impact: float,
                                 technical_impact: float, compliance_impact: float) -> float:
        """Calculate composite score using selected method."""
        if self.method == ScoreMethod.CVSS_LIKE:
            # CVSS-like calculation: Base Score = Impact * Exploitability
            base_score = (impact * exploitability) / 10.0
            
            # Temporal factors
            temporal_score = base_score * (likelihood / 10.0)
            
            # Environmental factors
            environmental_score = temporal_score * ((exposure + business_impact + compliance_impact) / 30.0)
            
            return min(environmental_score, 10.0)
        
        elif self.method == ScoreMethod.WEIGHTED_AVERAGE:
            weights = self._component_weights
            weighted_sum = (
                severity * weights[ScoreComponent.SEVERITY] +
                likelihood * weights[ScoreComponent.LIKELIHOOD] +
                impact * weights[ScoreComponent.IMPACT] +
                exposure * weights[ScoreComponent.EXPOSURE] +
                exploitability * weights[ScoreComponent.EXPLOITABILITY] +
                business_impact * weights[ScoreComponent.BUSINESS_IMPACT] +
                technical_impact * weights[ScoreComponent.TECHNICAL_IMPACT] +
                compliance_impact * weights[ScoreComponent.COMPLIANCE_IMPACT]
            )
            return min(weighted_sum, 10.0)
        
        elif self.method == ScoreMethod.MULTIPLICATIVE:
            # Multiplicative approach (normalized)
            factors = [severity, likelihood, impact, exposure, exploitability, 
                      business_impact, technical_impact, compliance_impact]
            normalized_factors = [f / 10.0 for f in factors]
            product = 1.0
            for factor in normalized_factors:
                product *= (1.0 + factor)
            return min((product - 1.0) * 10.0, 10.0)
        
        elif self.method == ScoreMethod.MAXIMUM:
            # Take maximum of all components
            return max(severity, likelihood, impact, exposure, exploitability,
                      business_impact, technical_impact, compliance_impact)
        
        else:  # Default to weighted average
            return self._calculate_composite_score(
                severity, likelihood, impact, exposure, exploitability,
                business_impact, technical_impact, compliance_impact
            )
    
    def _calculate_confidence(self, risks: List[SecurityRisk], 
                            threat_model: Optional[ThreatModel]) -> float:
        """Calculate confidence in the risk score."""
        confidence = 0.5  # Base confidence
        
        # More risks = higher confidence
        if risks:
            confidence += min(len(risks) / 20.0, 0.3)
        
        # Threat model increases confidence
        if threat_model and threat_model.threat_vectors:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 9.0:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        elif score >= 1.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _generate_score_recommendations(self, score: float, breakdown: ScoreBreakdown) -> List[str]:
        """Generate recommendations based on score and breakdown."""
        recommendations = []
        
        if score >= 9.0:
            recommendations.append("CRITICAL: Immediate remediation required")
        elif score >= 7.0:
            recommendations.append("HIGH: Prioritize remediation within 24-48 hours")
        elif score >= 4.0:
            recommendations.append("MEDIUM: Address within 1-2 weeks")
        elif score >= 1.0:
            recommendations.append("LOW: Monitor and address during regular maintenance")
        
        # Component-specific recommendations
        if breakdown.exploitability_score >= 8.0:
            recommendations.append("High exploitability detected - implement additional access controls")
        
        if breakdown.exposure_score >= 7.0:
            recommendations.append("High exposure detected - consider network segmentation")
        
        if breakdown.business_impact_score >= 7.0:
            recommendations.append("High business impact - involve business stakeholders in remediation")
        
        return recommendations
    
    def _initialize_component_weights(self) -> Dict[ScoreComponent, float]:
        """Initialize component weights for weighted average method."""
        return {
            ScoreComponent.SEVERITY: 0.25,
            ScoreComponent.LIKELIHOOD: 0.20,
            ScoreComponent.IMPACT: 0.20,
            ScoreComponent.EXPOSURE: 0.10,
            ScoreComponent.EXPLOITABILITY: 0.15,
            ScoreComponent.BUSINESS_IMPACT: 0.05,
            ScoreComponent.TECHNICAL_IMPACT: 0.03,
            ScoreComponent.COMPLIANCE_IMPACT: 0.02,
        }
    
    def _initialize_severity_mappings(self) -> Dict[RiskLevel, float]:
        """Initialize severity to score mappings."""
        return {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 8.0,
            RiskLevel.MEDIUM: 6.0,
            RiskLevel.LOW: 3.0,
            RiskLevel.MINIMAL: 1.0,
            RiskLevel.UNKNOWN: 0.0
        }
    
    def _initialize_category_weights(self) -> Dict[RiskCategory, float]:
        """Initialize category weights for scoring."""
        return {
            RiskCategory.CODE_EXECUTION: 1.0,
            RiskCategory.SYSTEM_MODIFICATION: 0.9,
            RiskCategory.AUTHENTICATION: 0.8,
            RiskCategory.DATA_ACCESS: 0.8,
            RiskCategory.NETWORK_ACCESS: 0.7,
            RiskCategory.FILE_SYSTEM: 0.7,
            RiskCategory.DATABASE: 0.8,
            RiskCategory.ENCRYPTION: 0.6,
            RiskCategory.EXTERNAL_API: 0.5,
            RiskCategory.CLOUD_SERVICES: 0.6,
            RiskCategory.UNKNOWN: 0.3
        } 