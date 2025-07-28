"""
Risk Prioritization Algorithm

This module implements the Risk Prioritization Algorithm from the design
document, which prioritizes threats based on technical impact, business impact,
likelihood, and environmental factors.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AttackVector,
    CapabilityCategory, ThreatLevel
)


logger = logging.getLogger(__name__)


class PriorityLevel(Enum):
    """Priority levels for threat remediation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ImpactCategory(Enum):
    """Categories of business impact."""
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    REPUTATIONAL = "reputational"
    COMPLIANCE = "compliance"
    STRATEGIC = "strategic"


@dataclass
class TechnicalImpactScore:
    """Technical impact assessment results."""
    overall_score: float
    confidentiality_impact: float
    integrity_impact: float
    availability_impact: float
    scope_impact: float
    complexity_factor: float
    scoring_rationale: str


@dataclass
class BusinessImpactScore:
    """Business impact assessment results."""
    overall_score: float
    financial_impact: float
    operational_impact: float
    reputational_impact: float
    compliance_impact: float
    strategic_impact: float
    business_context: str
    cost_estimate: Optional[float]


@dataclass
class LikelihoodScore:
    """Likelihood assessment results."""
    overall_score: float
    threat_actor_capability: float
    attack_complexity: float
    attack_surface_accessibility: float
    existing_controls_effectiveness: float
    historical_frequency: float
    likelihood_rationale: str


@dataclass
class EnvironmentalModifiers:
    """Environmental factors that modify risk scores."""
    deployment_factor: float
    security_posture_factor: float
    network_exposure_factor: float
    data_sensitivity_factor: float
    monitoring_capability_factor: float
    incident_response_factor: float
    overall_modifier: float
    modifier_explanation: str


@dataclass
class PrioritizedThreat:
    """A threat with comprehensive prioritization analysis."""
    threat_id: str
    tool_name: str
    threat_title: str
    threat_description: str
    priority_level: PriorityLevel
    priority_score: float
    technical_impact: TechnicalImpactScore
    business_impact: BusinessImpactScore
    likelihood: LikelihoodScore
    environmental_modifiers: EnvironmentalModifiers
    risk_score: float
    confidence_level: float
    recommended_actions: List[str]
    timeline_recommendation: str
    resource_requirements: List[str]
    success_metrics: List[str]
    dependencies: List[str]
    prioritization_timestamp: str


class RiskPrioritizationAlgorithm:
    """
    Implements the Risk Prioritization Algorithm from the design document.
    
    This algorithm prioritizes threats based on:
    1. Technical impact score calculation
    2. Business impact assessment based on context
    3. Likelihood evaluation based on threat actor capabilities
    4. Environmental modifiers application
    5. Final priority ranking generation
    """
    
    def __init__(self):
        """Initialize the risk prioritization algorithm."""
        self.logger = logging.getLogger(__name__)
        
        # Scoring weights for different components
        self.scoring_weights = {
            'technical_impact': 0.25,
            'business_impact': 0.35,
            'likelihood': 0.25,
            'environmental_factors': 0.15
        }
        
        # Priority thresholds
        self.priority_thresholds = {
            PriorityLevel.CRITICAL: 0.85,
            PriorityLevel.HIGH: 0.70,
            PriorityLevel.MEDIUM: 0.50,
            PriorityLevel.LOW: 0.30
        }
        
        # Business impact cost multipliers
        self.cost_multipliers = {
            'data_breach': 150.0,  # Cost per record
            'downtime': 5000.0,    # Cost per hour
            'regulatory_fine': 100000.0,  # Base fine amount
            'reputation_damage': 50000.0   # Estimated reputation cost
        }
        
        # Threat actor capability assessments
        self.threat_actor_capabilities = {
            'script_kiddie': 0.3,
            'cybercriminal': 0.6,
            'insider_threat': 0.7,
            'nation_state': 0.9,
            'advanced_persistent_threat': 0.95
        }
        
        # Statistics
        self.prioritization_stats = {
            'threats_prioritized': 0,
            'critical_priorities': 0,
            'high_priorities': 0,
            'medium_priorities': 0,
            'low_priorities': 0,
            'total_prioritization_time': 0.0
        }
        
        self.logger.info("Risk Prioritization Algorithm initialized")
    
    def prioritize_threats(self,
                         threat_analyses: List[ThreatAnalysis],
                         tool_capabilities: List[ToolCapabilities],
                         environment_context: EnvironmentContext,
                         business_context: Optional[Dict[str, Any]] = None) -> List[PrioritizedThreat]:
        """
        Prioritize threats using the Risk Prioritization Algorithm.
        
        This implements the Risk Prioritization Algorithm from the design:
        1. Calculate technical impact score
        2. Assess business impact based on context
        3. Evaluate likelihood based on threat actor capabilities
        4. Apply environmental modifiers
        5. Generate final priority ranking
        
        Args:
            threat_analyses: List of threat analysis results
            tool_capabilities: List of tool capabilities
            environment_context: Environment context for risk assessment
            business_context: Optional business context information
            
        Returns:
            List of prioritized threats sorted by priority
        """
        try:
            start_time = datetime.now()
            self.logger.info(f"Starting threat prioritization for {len(threat_analyses)} threats")
            
            prioritized_threats = []
            
            for i, threat_analysis in enumerate(threat_analyses):
                # Find corresponding tool capabilities
                tool_caps = None
                if i < len(tool_capabilities):
                    tool_caps = tool_capabilities[i]
                
                # Step 1: Calculate technical impact score
                technical_impact = self._calculate_technical_impact_score(
                    threat_analysis,
                    tool_caps,
                    environment_context
                )
                
                # Step 2: Assess business impact based on context
                business_impact = self._assess_business_impact(
                    threat_analysis,
                    tool_caps,
                    environment_context,
                    business_context
                )
                
                # Step 3: Evaluate likelihood based on threat actor capabilities
                likelihood = self._evaluate_likelihood(
                    threat_analysis,
                    tool_caps,
                    environment_context
                )
                
                # Step 4: Apply environmental modifiers
                environmental_modifiers = self._apply_environmental_modifiers(
                    threat_analysis,
                    environment_context
                )
                
                # Step 5: Generate final priority ranking
                priority_assessment = self._generate_priority_ranking(
                    threat_analysis,
                    technical_impact,
                    business_impact,
                    likelihood,
                    environmental_modifiers,
                    tool_caps
                )
                
                prioritized_threats.append(priority_assessment)
            
            # Sort by priority score (highest first)
            prioritized_threats.sort(key=lambda x: x.priority_score, reverse=True)
            
            # Update statistics
            prioritization_time = (datetime.now() - start_time).total_seconds()
            self._update_prioritization_statistics(prioritized_threats, prioritization_time)
            
            self.logger.info(f"Threat prioritization completed in {prioritization_time:.2f}s")
            return prioritized_threats
            
        except Exception as e:
            self.logger.error(f"Threat prioritization failed: {e}")
            return []
    
    def _calculate_technical_impact_score(self,
                                        threat_analysis: ThreatAnalysis,
                                        tool_capabilities: Optional[ToolCapabilities],
                                        environment_context: EnvironmentContext) -> TechnicalImpactScore:
        """Calculate technical impact score for a threat."""
        # Confidentiality impact
        confidentiality_impact = self._assess_confidentiality_impact(
            threat_analysis, 
            tool_capabilities
        )
        
        # Integrity impact
        integrity_impact = self._assess_integrity_impact(
            threat_analysis, 
            tool_capabilities
        )
        
        # Availability impact
        availability_impact = self._assess_availability_impact(
            threat_analysis, 
            tool_capabilities
        )
        
        # Scope impact (how widespread the impact could be)
        scope_impact = self._assess_scope_impact(
            threat_analysis, 
            environment_context
        )
        
        # Complexity factor (easier attacks have higher impact)
        complexity_factor = self._calculate_complexity_factor(
            threat_analysis
        )
        
        # Calculate overall technical impact
        overall_score = (
            confidentiality_impact * 0.3 +
            integrity_impact * 0.25 +
            availability_impact * 0.2 +
            scope_impact * 0.15 +
            complexity_factor * 0.1
        )
        
        scoring_rationale = self._generate_technical_impact_rationale(
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            scope_impact,
            complexity_factor
        )
        
        return TechnicalImpactScore(
            overall_score=round(overall_score, 3),
            confidentiality_impact=round(confidentiality_impact, 3),
            integrity_impact=round(integrity_impact, 3),
            availability_impact=round(availability_impact, 3),
            scope_impact=round(scope_impact, 3),
            complexity_factor=round(complexity_factor, 3),
            scoring_rationale=scoring_rationale
        )
    
    def _assess_business_impact(self,
                              threat_analysis: ThreatAnalysis,
                              tool_capabilities: Optional[ToolCapabilities],
                              environment_context: EnvironmentContext,
                              business_context: Optional[Dict[str, Any]]) -> BusinessImpactScore:
        """Assess business impact of a threat."""
        # Financial impact
        financial_impact = self._calculate_financial_impact(
            threat_analysis,
            tool_capabilities,
            environment_context,
            business_context
        )
        
        # Operational impact
        operational_impact = self._calculate_operational_impact(
            threat_analysis,
            tool_capabilities,
            environment_context
        )
        
        # Reputational impact
        reputational_impact = self._calculate_reputational_impact(
            threat_analysis,
            environment_context,
            business_context
        )
        
        # Compliance impact
        compliance_impact = self._calculate_compliance_impact(
            threat_analysis,
            environment_context,
            business_context
        )
        
        # Strategic impact
        strategic_impact = self._calculate_strategic_impact(
            threat_analysis,
            business_context
        )
        
        # Calculate overall business impact
        overall_score = (
            financial_impact * 0.3 +
            operational_impact * 0.25 +
            reputational_impact * 0.2 +
            compliance_impact * 0.15 +
            strategic_impact * 0.1
        )
        
        # Estimate cost
        cost_estimate = self._estimate_business_cost(
            financial_impact,
            operational_impact,
            compliance_impact,
            business_context
        )
        
        business_context_desc = self._generate_business_context_description(
            financial_impact,
            operational_impact,
            reputational_impact,
            compliance_impact,
            strategic_impact
        )
        
        return BusinessImpactScore(
            overall_score=round(overall_score, 3),
            financial_impact=round(financial_impact, 3),
            operational_impact=round(operational_impact, 3),
            reputational_impact=round(reputational_impact, 3),
            compliance_impact=round(compliance_impact, 3),
            strategic_impact=round(strategic_impact, 3),
            business_context=business_context_desc,
            cost_estimate=cost_estimate
        )
    
    def _evaluate_likelihood(self,
                           threat_analysis: ThreatAnalysis,
                           tool_capabilities: Optional[ToolCapabilities],
                           environment_context: EnvironmentContext) -> LikelihoodScore:
        """Evaluate likelihood of threat exploitation."""
        # Threat actor capability assessment
        threat_actor_capability = self._assess_threat_actor_capability(
            threat_analysis
        )
        
        # Attack complexity assessment
        attack_complexity = self._assess_attack_complexity(
            threat_analysis,
            tool_capabilities
        )
        
        # Attack surface accessibility
        attack_surface_accessibility = self._assess_attack_surface_accessibility(
            tool_capabilities,
            environment_context
        )
        
        # Existing controls effectiveness
        existing_controls_effectiveness = self._assess_existing_controls(
            environment_context
        )
        
        # Historical frequency (simplified)
        historical_frequency = self._assess_historical_frequency(
            threat_analysis
        )
        
        # Calculate overall likelihood
        overall_score = (
            threat_actor_capability * 0.25 +
            (1.0 - attack_complexity) * 0.25 +  # Inverse complexity
            attack_surface_accessibility * 0.2 +
            (1.0 - existing_controls_effectiveness) * 0.2 +  # Inverse control effectiveness
            historical_frequency * 0.1
        )
        
        likelihood_rationale = self._generate_likelihood_rationale(
            threat_actor_capability,
            attack_complexity,
            attack_surface_accessibility,
            existing_controls_effectiveness,
            historical_frequency
        )
        
        return LikelihoodScore(
            overall_score=round(overall_score, 3),
            threat_actor_capability=round(threat_actor_capability, 3),
            attack_complexity=round(attack_complexity, 3),
            attack_surface_accessibility=round(attack_surface_accessibility, 3),
            existing_controls_effectiveness=round(existing_controls_effectiveness, 3),
            historical_frequency=round(historical_frequency, 3),
            likelihood_rationale=likelihood_rationale
        )
    
    def _apply_environmental_modifiers(self,
                                     threat_analysis: ThreatAnalysis,
                                     environment_context: EnvironmentContext) -> EnvironmentalModifiers:
        """Apply environmental factors that modify risk scores."""
        # Deployment factor
        deployment_factor = self._calculate_deployment_factor(
            environment_context.deployment_type
        )
        
        # Security posture factor
        security_posture_factor = self._calculate_security_posture_factor(
            environment_context.security_posture
        )
        
        # Network exposure factor
        network_exposure_factor = self._calculate_network_exposure_factor(
            environment_context
        )
        
        # Data sensitivity factor
        data_sensitivity_factor = self._calculate_data_sensitivity_factor(
            environment_context.data_sensitivity
        )
        
        # Monitoring capability factor
        monitoring_capability_factor = self._calculate_monitoring_capability_factor(
            environment_context
        )
        
        # Incident response factor
        incident_response_factor = self._calculate_incident_response_factor(
            environment_context
        )
        
        # Calculate overall modifier
        overall_modifier = (
            deployment_factor * 0.2 +
            security_posture_factor * 0.25 +
            network_exposure_factor * 0.2 +
            data_sensitivity_factor * 0.15 +
            monitoring_capability_factor * 0.1 +
            incident_response_factor * 0.1
        )
        
        modifier_explanation = self._generate_modifier_explanation(
            deployment_factor,
            security_posture_factor,
            network_exposure_factor,
            data_sensitivity_factor,
            monitoring_capability_factor,
            incident_response_factor
        )
        
        return EnvironmentalModifiers(
            deployment_factor=round(deployment_factor, 3),
            security_posture_factor=round(security_posture_factor, 3),
            network_exposure_factor=round(network_exposure_factor, 3),
            data_sensitivity_factor=round(data_sensitivity_factor, 3),
            monitoring_capability_factor=round(monitoring_capability_factor, 3),
            incident_response_factor=round(incident_response_factor, 3),
            overall_modifier=round(overall_modifier, 3),
            modifier_explanation=modifier_explanation
        )
    
    def _generate_priority_ranking(self,
                                 threat_analysis: ThreatAnalysis,
                                 technical_impact: TechnicalImpactScore,
                                 business_impact: BusinessImpactScore,
                                 likelihood: LikelihoodScore,
                                 environmental_modifiers: EnvironmentalModifiers,
                                 tool_capabilities: Optional[ToolCapabilities]) -> PrioritizedThreat:
        """Generate final priority ranking for a threat."""
        # Calculate overall risk score using weighted components
        risk_score = (
            technical_impact.overall_score * self.scoring_weights['technical_impact'] +
            business_impact.overall_score * self.scoring_weights['business_impact'] +
            likelihood.overall_score * self.scoring_weights['likelihood'] +
            environmental_modifiers.overall_modifier * self.scoring_weights['environmental_factors']
        )
        
        # Apply environmental modifier
        final_score = risk_score * environmental_modifiers.overall_modifier
        final_score = max(0.0, min(1.0, final_score))  # Clamp between 0 and 1
        
        # Determine priority level
        priority_level = self._determine_priority_level(final_score)
        
        # Calculate confidence level
        confidence_level = self._calculate_confidence_level(
            technical_impact,
            business_impact,
            likelihood,
            tool_capabilities
        )
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(
            priority_level,
            technical_impact,
            business_impact,
            threat_analysis
        )
        
        # Generate timeline recommendation
        timeline_recommendation = self._generate_timeline_recommendation(
            priority_level,
            business_impact
        )
        
        # Determine resource requirements
        resource_requirements = self._determine_resource_requirements(
            priority_level,
            technical_impact,
            business_impact
        )
        
        # Define success metrics
        success_metrics = self._define_success_metrics(
            priority_level,
            technical_impact,
            business_impact
        )
        
        # Identify dependencies
        dependencies = self._identify_dependencies(
            threat_analysis,
            priority_level
        )
        
        return PrioritizedThreat(
            threat_id=f"threat_{threat_analysis.tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            tool_name=threat_analysis.tool_name,
            threat_title=f"Security Risk: {threat_analysis.tool_name}",
            threat_description=threat_analysis.summary[:200] if threat_analysis.summary else "Security threat identified",
            priority_level=priority_level,
            priority_score=round(final_score, 3),
            technical_impact=technical_impact,
            business_impact=business_impact,
            likelihood=likelihood,
            environmental_modifiers=environmental_modifiers,
            risk_score=round(risk_score, 3),
            confidence_level=round(confidence_level, 3),
            recommended_actions=recommended_actions,
            timeline_recommendation=timeline_recommendation,
            resource_requirements=resource_requirements,
            success_metrics=success_metrics,
            dependencies=dependencies,
            prioritization_timestamp=datetime.now().isoformat()
        )
    
    # Helper methods for impact assessments
    
    def _assess_confidentiality_impact(self,
                                     threat_analysis: ThreatAnalysis,
                                     tool_capabilities: Optional[ToolCapabilities]) -> float:
        """Assess confidentiality impact of a threat."""
        impact = 0.5  # Base impact
        
        if tool_capabilities:
            # Check for data access capabilities
            if CapabilityCategory.FILE_SYSTEM in tool_capabilities.capability_categories:
                impact += 0.2
            if CapabilityCategory.DATABASE_ACCESS in tool_capabilities.capability_categories:
                impact += 0.3
            if CapabilityCategory.NETWORK_ACCESS in tool_capabilities.capability_categories:
                impact += 0.1
        
        # Check for data exposure indicators in attack vectors
        if threat_analysis.attack_vectors:
            for vector in threat_analysis.attack_vectors:
                if any(keyword in vector.description.lower() for keyword in ['data', 'file', 'credential', 'secret']):
                    impact += 0.1
        
        return min(1.0, impact)
    
    def _assess_integrity_impact(self,
                               threat_analysis: ThreatAnalysis,
                               tool_capabilities: Optional[ToolCapabilities]) -> float:
        """Assess integrity impact of a threat."""
        impact = 0.3  # Base impact
        
        if tool_capabilities:
            # Check for modification capabilities
            if CapabilityCategory.CODE_EXECUTION in tool_capabilities.capability_categories:
                impact += 0.4
            if CapabilityCategory.FILE_SYSTEM in tool_capabilities.capability_categories:
                impact += 0.2
            if CapabilityCategory.DATABASE_ACCESS in tool_capabilities.capability_categories:
                impact += 0.2
        
        # Check for modification indicators
        if threat_analysis.attack_vectors:
            for vector in threat_analysis.attack_vectors:
                if any(keyword in vector.description.lower() for keyword in ['modify', 'alter', 'change', 'inject']):
                    impact += 0.1
        
        return min(1.0, impact)
    
    def _assess_availability_impact(self,
                                  threat_analysis: ThreatAnalysis,
                                  tool_capabilities: Optional[ToolCapabilities]) -> float:
        """Assess availability impact of a threat."""
        impact = 0.2  # Base impact
        
        if tool_capabilities:
            # Check for disruptive capabilities
            if CapabilityCategory.CODE_EXECUTION in tool_capabilities.capability_categories:
                impact += 0.3
            if CapabilityCategory.SYSTEM_INFORMATION in tool_capabilities.capability_categories:
                impact += 0.1
        
        # Check for DoS indicators
        if threat_analysis.attack_vectors:
            for vector in threat_analysis.attack_vectors:
                if any(keyword in vector.description.lower() for keyword in ['dos', 'crash', 'overload', 'exhaust']):
                    impact += 0.2
        
        return min(1.0, impact)
    
    def _assess_scope_impact(self,
                           threat_analysis: ThreatAnalysis,
                           environment_context: EnvironmentContext) -> float:
        """Assess how widespread the impact could be."""
        scope = 0.4  # Base scope
        
        # Environment factors
        from .models import DeploymentType
        if environment_context.deployment_type == DeploymentType.CLOUD:
            scope += 0.3
        elif environment_context.deployment_type == DeploymentType.HYBRID:
            scope += 0.2
        
        # Network exposure
        if environment_context.has_network_access:
            scope += 0.2
        
        return min(1.0, scope)
    
    def _calculate_complexity_factor(self, threat_analysis: ThreatAnalysis) -> float:
        """Calculate complexity factor (easier attacks have higher impact)."""
        complexity = 0.5  # Base complexity
        
        # Threat level affects complexity
        if threat_analysis.threat_level == ThreatLevel.CRITICAL:
            complexity = 0.2  # Very easy to exploit
        elif threat_analysis.threat_level == ThreatLevel.HIGH:
            complexity = 0.4
        elif threat_analysis.threat_level == ThreatLevel.MEDIUM:
            complexity = 0.6
        else:
            complexity = 0.8  # Harder to exploit
        
        return 1.0 - complexity  # Invert so easier attacks have higher impact
    
    def _calculate_financial_impact(self,
                                  threat_analysis: ThreatAnalysis,
                                  tool_capabilities: Optional[ToolCapabilities],
                                  environment_context: EnvironmentContext,
                                  business_context: Optional[Dict[str, Any]]) -> float:
        """Calculate financial impact of a threat."""
        impact = 0.3  # Base financial impact
        
        # Data sensitivity affects financial impact
        from .models import DataSensitivity
        if environment_context.data_sensitivity == DataSensitivity.RESTRICTED:
            impact += 0.4
        elif environment_context.data_sensitivity == DataSensitivity.CONFIDENTIAL:
            impact += 0.2
        
        # Business context affects impact
        if business_context:
            revenue = business_context.get('annual_revenue', 0)
            if revenue > 100000000:  # $100M+
                impact += 0.2
            elif revenue > 10000000:  # $10M+
                impact += 0.1
        
        return min(1.0, impact)
    
    def _calculate_operational_impact(self,
                                    threat_analysis: ThreatAnalysis,
                                    tool_capabilities: Optional[ToolCapabilities],
                                    environment_context: EnvironmentContext) -> float:
        """Calculate operational impact of a threat."""
        impact = 0.4  # Base operational impact
        
        # System criticality affects operational impact
        if tool_capabilities:
            if CapabilityCategory.CODE_EXECUTION in tool_capabilities.capability_categories:
                impact += 0.3  # Can disrupt operations
            if CapabilityCategory.DATABASE_ACCESS in tool_capabilities.capability_categories:
                impact += 0.2  # Can affect data operations
        
        return min(1.0, impact)
    
    def _calculate_reputational_impact(self,
                                     threat_analysis: ThreatAnalysis,
                                     environment_context: EnvironmentContext,
                                     business_context: Optional[Dict[str, Any]]) -> float:
        """Calculate reputational impact of a threat."""
        impact = 0.3  # Base reputational impact
        
        # Data sensitivity affects reputation
        from .models import DataSensitivity
        if environment_context.data_sensitivity == DataSensitivity.RESTRICTED:
            impact += 0.4  # High reputational risk
        elif environment_context.data_sensitivity == DataSensitivity.CONFIDENTIAL:
            impact += 0.2
        
        # Public-facing systems have higher reputational risk
        if environment_context.has_network_access:
            impact += 0.1
        
        return min(1.0, impact)
    
    def _calculate_compliance_impact(self,
                                   threat_analysis: ThreatAnalysis,
                                   environment_context: EnvironmentContext,
                                   business_context: Optional[Dict[str, Any]]) -> float:
        """Calculate compliance impact of a threat."""
        impact = 0.2  # Base compliance impact
        
        # Data sensitivity strongly affects compliance
        from .models import DataSensitivity
        if environment_context.data_sensitivity == DataSensitivity.RESTRICTED:
            impact += 0.5  # High compliance requirements
        elif environment_context.data_sensitivity == DataSensitivity.CONFIDENTIAL:
            impact += 0.3
        
        # Industry context affects compliance
        if business_context:
            industry = business_context.get('industry', '')
            if industry.lower() in ['finance', 'healthcare', 'government']:
                impact += 0.2
        
        return min(1.0, impact)
    
    def _calculate_strategic_impact(self,
                                  threat_analysis: ThreatAnalysis,
                                  business_context: Optional[Dict[str, Any]]) -> float:
        """Calculate strategic impact of a threat."""
        impact = 0.2  # Base strategic impact
        
        # Strategic systems have higher impact
        if business_context:
            is_strategic = business_context.get('strategic_system', False)
            if is_strategic:
                impact += 0.4
        
        return min(1.0, impact)
    
    # Additional helper methods would continue here...
    # (Due to length constraints, I'll include key methods but not all helper methods)
    
    def _determine_priority_level(self, final_score: float) -> PriorityLevel:
        """Determine priority level based on final score."""
        if final_score >= self.priority_thresholds[PriorityLevel.CRITICAL]:
            return PriorityLevel.CRITICAL
        elif final_score >= self.priority_thresholds[PriorityLevel.HIGH]:
            return PriorityLevel.HIGH
        elif final_score >= self.priority_thresholds[PriorityLevel.MEDIUM]:
            return PriorityLevel.MEDIUM
        elif final_score >= self.priority_thresholds[PriorityLevel.LOW]:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.INFORMATIONAL
    
    def _calculate_confidence_level(self,
                                  technical_impact: TechnicalImpactScore,
                                  business_impact: BusinessImpactScore,
                                  likelihood: LikelihoodScore,
                                  tool_capabilities: Optional[ToolCapabilities]) -> float:
        """Calculate confidence level in the prioritization."""
        confidence_factors = []
        
        # Technical impact confidence
        if technical_impact.overall_score > 0:
            confidence_factors.append(0.8)
        
        # Business impact confidence
        if business_impact.cost_estimate is not None:
            confidence_factors.append(0.9)
        else:
            confidence_factors.append(0.6)
        
        # Likelihood confidence
        if likelihood.overall_score > 0:
            confidence_factors.append(0.7)
        
        # Tool analysis confidence
        if tool_capabilities and tool_capabilities.tool_functions:
            confidence_factors.append(0.8)
        else:
            confidence_factors.append(0.5)
        
        return sum(confidence_factors) / len(confidence_factors) if confidence_factors else 0.5
    
    def _generate_recommended_actions(self,
                                    priority_level: PriorityLevel,
                                    technical_impact: TechnicalImpactScore,
                                    business_impact: BusinessImpactScore,
                                    threat_analysis: ThreatAnalysis) -> List[str]:
        """Generate recommended actions based on priority level."""
        actions = []
        
        if priority_level == PriorityLevel.CRITICAL:
            actions.extend([
                "Immediate threat response activation",
                "Emergency security controls implementation",
                "Stakeholder notification and communication",
                "Continuous monitoring and assessment"
            ])
        elif priority_level == PriorityLevel.HIGH:
            actions.extend([
                "Prioritize remediation efforts",
                "Implement compensating controls",
                "Enhanced monitoring deployment",
                "Regular progress reviews"
            ])
        elif priority_level == PriorityLevel.MEDIUM:
            actions.extend([
                "Schedule remediation within next cycle",
                "Risk acceptance evaluation",
                "Standard monitoring implementation",
                "Periodic review scheduling"
            ])
        else:
            actions.extend([
                "Document for future consideration",
                "Standard security measures",
                "Periodic risk reassessment"
            ])
        
        return actions
    
    def _generate_timeline_recommendation(self,
                                        priority_level: PriorityLevel,
                                        business_impact: BusinessImpactScore) -> str:
        """Generate timeline recommendation based on priority."""
        if priority_level == PriorityLevel.CRITICAL:
            return "Immediate action required - within 24 hours"
        elif priority_level == PriorityLevel.HIGH:
            return "Urgent action required - within 1 week"
        elif priority_level == PriorityLevel.MEDIUM:
            return "Schedule within next 30 days"
        elif priority_level == PriorityLevel.LOW:
            return "Address within next quarter"
        else:
            return "Review annually or as needed"
    
    def _update_prioritization_statistics(self,
                                        prioritized_threats: List[PrioritizedThreat],
                                        prioritization_time: float) -> None:
        """Update prioritization statistics."""
        self.prioritization_stats["threats_prioritized"] += len(prioritized_threats)
        self.prioritization_stats["total_prioritization_time"] += prioritization_time
        
        for threat in prioritized_threats:
            if threat.priority_level == PriorityLevel.CRITICAL:
                self.prioritization_stats["critical_priorities"] += 1
            elif threat.priority_level == PriorityLevel.HIGH:
                self.prioritization_stats["high_priorities"] += 1
            elif threat.priority_level == PriorityLevel.MEDIUM:
                self.prioritization_stats["medium_priorities"] += 1
            else:
                self.prioritization_stats["low_priorities"] += 1
    
    def get_prioritization_statistics(self) -> Dict[str, Any]:
        """Get current prioritization statistics."""
        stats = self.prioritization_stats.copy()
        
        # Add calculated metrics
        if stats["threats_prioritized"] > 0:
            stats["average_prioritization_time"] = stats["total_prioritization_time"] / stats["threats_prioritized"]
            stats["critical_percentage"] = (stats["critical_priorities"] / stats["threats_prioritized"]) * 100
            stats["high_percentage"] = (stats["high_priorities"] / stats["threats_prioritized"]) * 100
        else:
            stats["average_prioritization_time"] = 0.0
            stats["critical_percentage"] = 0.0
            stats["high_percentage"] = 0.0
        
        return stats
    
    # Placeholder methods for remaining helper functions
    # (These would be fully implemented in a complete system)
    
    def _generate_technical_impact_rationale(self, conf: float, integ: float, avail: float, scope: float, complex: float) -> str:
        return f"Technical impact assessment based on confidentiality ({conf:.2f}), integrity ({integ:.2f}), availability ({avail:.2f}), scope ({scope:.2f}), and complexity ({complex:.2f})"
    
    def _estimate_business_cost(self, financial: float, operational: float, compliance: float, context: Optional[Dict[str, Any]]) -> Optional[float]:
        if context and 'cost_basis' in context:
            return financial * context['cost_basis'] * 1000
        return None
    
    def _generate_business_context_description(self, financial: float, operational: float, reputational: float, compliance: float, strategic: float) -> str:
        return f"Business impact across financial ({financial:.2f}), operational ({operational:.2f}), reputational ({reputational:.2f}), compliance ({compliance:.2f}), and strategic ({strategic:.2f}) dimensions"
    
    def _assess_threat_actor_capability(self, threat_analysis: ThreatAnalysis) -> float:
        # Simplified - would use more sophisticated threat intel
        if threat_analysis.threat_level == ThreatLevel.CRITICAL:
            return 0.9
        elif threat_analysis.threat_level == ThreatLevel.HIGH:
            return 0.7
        else:
            return 0.5
    
    def _assess_attack_complexity(self, threat_analysis: ThreatAnalysis, tool_capabilities: Optional[ToolCapabilities]) -> float:
        # Simplified complexity assessment
        if tool_capabilities and len(tool_capabilities.tool_functions) > 5:
            return 0.7  # More complex
        else:
            return 0.4  # Less complex
    
    def _assess_attack_surface_accessibility(self, tool_capabilities: Optional[ToolCapabilities], environment_context: EnvironmentContext) -> float:
        accessibility = 0.3
        if environment_context.has_network_access:
            accessibility += 0.4
        if tool_capabilities and tool_capabilities.external_access:
            accessibility += 0.3
        return min(1.0, accessibility)
    
    def _assess_existing_controls(self, environment_context: EnvironmentContext) -> float:
        from .models import SecurityPosture
        control_effectiveness = {
            SecurityPosture.HIGH: 0.8,
            SecurityPosture.MEDIUM: 0.6,
            SecurityPosture.LOW: 0.3
        }
        return control_effectiveness.get(environment_context.security_posture, 0.5)
    
    def _assess_historical_frequency(self, threat_analysis: ThreatAnalysis) -> float:
        # Simplified - would use historical threat data
        return 0.5
    
    def _generate_likelihood_rationale(self, actor: float, complexity: float, access: float, controls: float, history: float) -> str:
        return f"Likelihood based on threat actor capability ({actor:.2f}), attack complexity ({complexity:.2f}), accessibility ({access:.2f}), control effectiveness ({controls:.2f}), and historical patterns ({history:.2f})"
    
    def _calculate_deployment_factor(self, deployment_type) -> float:
        from .models import DeploymentType
        factors = {
            DeploymentType.CLOUD: 1.2,
            DeploymentType.HYBRID: 1.1,
            DeploymentType.REMOTE: 1.0,
            DeploymentType.LOCAL: 0.8
        }
        return factors.get(deployment_type, 1.0)
    
    def _calculate_security_posture_factor(self, security_posture) -> float:
        from .models import SecurityPosture
        factors = {
            SecurityPosture.HIGH: 0.7,
            SecurityPosture.MEDIUM: 1.0,
            SecurityPosture.LOW: 1.3
        }
        return factors.get(security_posture, 1.0)
    
    def _calculate_network_exposure_factor(self, environment_context: EnvironmentContext) -> float:
        return 1.2 if environment_context.has_network_access else 0.8
    
    def _calculate_data_sensitivity_factor(self, data_sensitivity) -> float:
        from .models import DataSensitivity
        factors = {
            DataSensitivity.RESTRICTED: 1.3,
            DataSensitivity.CONFIDENTIAL: 1.1,
            DataSensitivity.INTERNAL: 1.0,
            DataSensitivity.PUBLIC: 0.7
        }
        return factors.get(data_sensitivity, 1.0)
    
    def _calculate_monitoring_capability_factor(self, environment_context: EnvironmentContext) -> float:
        return 0.8 if environment_context.security_controls_enabled else 1.2
    
    def _calculate_incident_response_factor(self, environment_context: EnvironmentContext) -> float:
        # Simplified - would assess actual IR capabilities
        return 0.9
    
    def _generate_modifier_explanation(self, deploy: float, security: float, network: float, data: float, monitor: float, incident: float) -> str:
        return f"Environmental modifiers: deployment ({deploy:.2f}), security posture ({security:.2f}), network exposure ({network:.2f}), data sensitivity ({data:.2f}), monitoring ({monitor:.2f}), incident response ({incident:.2f})"
    
    def _determine_resource_requirements(self, priority_level: PriorityLevel, technical_impact: TechnicalImpactScore, business_impact: BusinessImpactScore) -> List[str]:
        if priority_level == PriorityLevel.CRITICAL:
            return ["Security team lead", "System administrator", "Business stakeholder", "External consultant (if needed)"]
        elif priority_level == PriorityLevel.HIGH:
            return ["Security analyst", "System administrator", "Development team"]
        else:
            return ["Security analyst", "System administrator"]
    
    def _define_success_metrics(self, priority_level: PriorityLevel, technical_impact: TechnicalImpactScore, business_impact: BusinessImpactScore) -> List[str]:
        return [
            "Threat eliminated or mitigated",
            "No security incidents related to this threat",
            "Compliance requirements met",
            "Stakeholder approval of remediation"
        ]
    
    def _identify_dependencies(self, threat_analysis: ThreatAnalysis, priority_level: PriorityLevel) -> List[str]:
        dependencies = ["Security team availability", "System access permissions"]
        if priority_level in [PriorityLevel.CRITICAL, PriorityLevel.HIGH]:
            dependencies.append("Management approval for urgent changes")
        return dependencies 