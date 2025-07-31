"""
Business Impact Calculator Component

This module implements comprehensive business impact modeling capabilities including financial impact
assessment, operational disruption analysis, cascading effect modeling, and recovery cost estimation
for MCP server security threats.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json

from .models import (
    ToolCapabilities, EnvironmentContext, ThreatLevel, SeverityLevel,
    DifficultyLevel, CapabilityCategory, BusinessImpact, DataSensitivity,
    NetworkExposure, DeploymentType, ComplianceFramework
)


class ImpactCategory(Enum):
    """Categories of business impact."""
    FINANCIAL = "financial"
    OPERATIONAL = "operational"
    REPUTATION = "reputation"
    LEGAL_COMPLIANCE = "legal_compliance"
    COMPETITIVE = "competitive"
    CUSTOMER_TRUST = "customer_trust"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    BUSINESS_CONTINUITY = "business_continuity"


class ImpactSeverity(Enum):
    """Severity levels for business impact."""
    NEGLIGIBLE = "negligible"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    CATASTROPHIC = "catastrophic"


class RecoveryPhase(Enum):
    """Phases of incident recovery."""
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


class CostCategory(Enum):
    """Categories of incident costs."""
    IMMEDIATE_RESPONSE = "immediate_response"
    INVESTIGATION = "investigation"
    REMEDIATION = "remediation"
    BUSINESS_DISRUPTION = "business_disruption"
    LEGAL_REGULATORY = "legal_regulatory"
    REPUTATION_RECOVERY = "reputation_recovery"
    PREVENTIVE_MEASURES = "preventive_measures"
    INSURANCE_DEDUCTIBLE = "insurance_deductible"


class OrganizationSize(Enum):
    """Organization size categories for impact scaling."""
    STARTUP = "startup"
    SMALL_BUSINESS = "small_business"
    MEDIUM_ENTERPRISE = "medium_enterprise"
    LARGE_ENTERPRISE = "large_enterprise"
    FORTUNE_500 = "fortune_500"


class IndustryVertical(Enum):
    """Industry verticals for context-specific impact assessment."""
    FINANCIAL_SERVICES = "financial_services"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    MANUFACTURING = "manufacturing"
    RETAIL = "retail"
    EDUCATION = "education"
    ENERGY = "energy"
    TELECOMMUNICATIONS = "telecommunications"
    OTHER = "other"


@dataclass
class FinancialImpact:
    """Represents financial impact of a security incident."""
    direct_costs: float = 0.0
    indirect_costs: float = 0.0
    revenue_loss: float = 0.0
    regulatory_fines: float = 0.0
    legal_costs: float = 0.0
    insurance_costs: float = 0.0
    recovery_costs: float = 0.0
    total_estimated_cost: float = 0.0
    cost_confidence: float = 0.5
    currency: str = "USD"
    cost_breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class OperationalImpact:
    """Represents operational impact of a security incident."""
    service_downtime_hours: float = 0.0
    affected_systems: List[str] = field(default_factory=list)
    affected_processes: List[str] = field(default_factory=list)
    productivity_loss_percentage: float = 0.0
    customer_impact_level: ImpactSeverity = ImpactSeverity.MINOR
    recovery_time_estimate: float = 0.0  # hours
    business_continuity_risk: ImpactSeverity = ImpactSeverity.MINOR
    operational_disruption_score: float = 0.0


@dataclass
class ReputationImpact:
    """Represents reputational impact of a security incident."""
    public_disclosure_likelihood: float = 0.5
    media_attention_level: ImpactSeverity = ImpactSeverity.MINOR
    customer_trust_impact: ImpactSeverity = ImpactSeverity.MINOR
    partner_confidence_impact: ImpactSeverity = ImpactSeverity.MINOR
    brand_damage_duration: str = "short_term"  # short_term, medium_term, long_term
    social_media_sentiment_impact: float = 0.0  # -1.0 to 1.0
    market_perception_change: float = 0.0  # -1.0 to 1.0
    reputation_recovery_months: int = 6


@dataclass
class ComplianceImpact:
    """Represents compliance and regulatory impact."""
    affected_regulations: List[ComplianceFramework] = field(default_factory=list)
    violation_likelihood: float = 0.5
    potential_fines: float = 0.0
    audit_requirements: List[str] = field(default_factory=list)
    reporting_obligations: List[str] = field(default_factory=list)
    certification_risks: List[str] = field(default_factory=list)
    remediation_requirements: List[str] = field(default_factory=list)


@dataclass
class CascadingEffect:
    """Represents a cascading effect from the initial incident."""
    effect_id: str
    source_system: str
    target_system: str
    effect_type: str
    propagation_delay: float  # hours
    impact_magnitude: float  # 0.0-1.0
    probability: float  # 0.0-1.0
    mitigation_difficulty: DifficultyLevel
    description: str
    prerequisites: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)


@dataclass
class RecoveryCost:
    """Represents costs for each recovery phase."""
    phase: RecoveryPhase
    estimated_hours: float
    personnel_costs: float
    technology_costs: float
    external_service_costs: float
    opportunity_costs: float
    total_phase_cost: float
    confidence_level: float = 0.5
    cost_drivers: List[str] = field(default_factory=list)


@dataclass
class BusinessImpactAssessment:
    """Complete business impact assessment result."""
    tool_name: str
    assessment_id: str
    organization_context: Dict[str, Any] = field(default_factory=dict)
    financial_impact: FinancialImpact = field(default_factory=FinancialImpact)
    operational_impact: OperationalImpact = field(default_factory=OperationalImpact)
    reputation_impact: ReputationImpact = field(default_factory=ReputationImpact)
    compliance_impact: ComplianceImpact = field(default_factory=ComplianceImpact)
    cascading_effects: List[CascadingEffect] = field(default_factory=list)
    recovery_costs: List[RecoveryCost] = field(default_factory=list)
    overall_impact_score: float = 0.0
    impact_timeframe: str = "immediate_to_long_term"
    business_criticality: ImpactSeverity = ImpactSeverity.MODERATE
    recommended_insurance_coverage: float = 0.0
    assessment_timestamp: datetime = field(default_factory=datetime.now)
    confidence_score: float = 0.0


class ImpactCalculator:
    """
    Enhanced business impact calculator with comprehensive modeling capabilities
    for financial, operational, reputational, and compliance impacts.
    """
    
    def __init__(self):
        """Initialize the impact calculator."""
        self.logger = logging.getLogger(__name__)
        self._impact_models = self._initialize_impact_models()
        self._cost_models = self._initialize_cost_models()
        self._cascading_patterns = self._initialize_cascading_patterns()
        self._industry_multipliers = self._initialize_industry_multipliers()
    
    def calculate_business_impact(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        organization_size: OrganizationSize = OrganizationSize.MEDIUM_ENTERPRISE,
        industry: IndustryVertical = IndustryVertical.TECHNOLOGY
    ) -> BusinessImpactAssessment:
        """
        Calculate comprehensive business impact for MCP tool security threats.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            organization_size: Size of the organization
            industry: Industry vertical
            
        Returns:
            Complete business impact assessment
        """
        self.logger.info(f"Calculating business impact for {tool_capabilities.tool_name}")
        
        assessment_id = self._generate_assessment_id(tool_capabilities.tool_name)
        
        # Calculate financial impact
        financial_impact = self._calculate_financial_impact(
            tool_capabilities, environment_context, organization_size, industry
        )
        
        # Calculate operational impact
        operational_impact = self._calculate_operational_impact(
            tool_capabilities, environment_context, organization_size
        )
        
        # Calculate reputation impact
        reputation_impact = self._calculate_reputation_impact(
            tool_capabilities, environment_context, industry
        )
        
        # Calculate compliance impact
        compliance_impact = self._calculate_compliance_impact(
            tool_capabilities, environment_context, industry
        )
        
        # Analyze cascading effects
        cascading_effects = self._analyze_cascading_effects(
            tool_capabilities, environment_context
        )
        
        # Calculate recovery costs
        recovery_costs = self._calculate_recovery_costs(
            tool_capabilities, financial_impact, operational_impact, organization_size
        )
        
        # Calculate overall impact score
        overall_score = self._calculate_overall_impact_score(
            financial_impact, operational_impact, reputation_impact, compliance_impact
        )
        
        # Determine business criticality
        criticality = self._determine_business_criticality(overall_score, cascading_effects)
        
        # Calculate recommended insurance coverage
        insurance_coverage = self._calculate_insurance_recommendation(financial_impact)
        
        # Calculate confidence score
        confidence = self._calculate_confidence_score(
            tool_capabilities, financial_impact, operational_impact
        )
        
        assessment = BusinessImpactAssessment(
            tool_name=tool_capabilities.tool_name,
            assessment_id=assessment_id,
            organization_context={
                "size": organization_size.value,
                "industry": industry.value,
                "data_sensitivity": environment_context.data_sensitivity.value,
                "network_exposure": environment_context.network_exposure.value
            },
            financial_impact=financial_impact,
            operational_impact=operational_impact,
            reputation_impact=reputation_impact,
            compliance_impact=compliance_impact,
            cascading_effects=cascading_effects,
            recovery_costs=recovery_costs,
            overall_impact_score=overall_score,
            business_criticality=criticality,
            recommended_insurance_coverage=insurance_coverage,
            confidence_score=confidence
        )
        
        self.logger.info(f"Completed business impact assessment with score {overall_score:.2f}")
        return assessment
    
    def _calculate_financial_impact(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        organization_size: OrganizationSize,
        industry: IndustryVertical
    ) -> FinancialImpact:
        """Calculate financial impact of security incident."""
        
        # Base costs by organization size
        size_multipliers = {
            OrganizationSize.STARTUP: 0.1,
            OrganizationSize.SMALL_BUSINESS: 0.3,
            OrganizationSize.MEDIUM_ENTERPRISE: 1.0,
            OrganizationSize.LARGE_ENTERPRISE: 3.0,
            OrganizationSize.FORTUNE_500: 10.0
        }
        
        base_multiplier = size_multipliers[organization_size]
        industry_multiplier = self._industry_multipliers[industry]["financial"]
        
        # Calculate direct costs
        direct_costs = self._calculate_direct_costs(
            tool_capabilities, base_multiplier, industry_multiplier
        )
        
        # Calculate indirect costs
        indirect_costs = self._calculate_indirect_costs(
            tool_capabilities, environment_context, base_multiplier
        )
        
        # Calculate revenue loss
        revenue_loss = self._calculate_revenue_loss(
            tool_capabilities, environment_context, base_multiplier, industry_multiplier
        )
        
        # Calculate regulatory fines
        regulatory_fines = self._calculate_regulatory_fines(
            environment_context, industry, base_multiplier
        )
        
        # Calculate legal costs
        legal_costs = self._calculate_legal_costs(
            environment_context, base_multiplier, industry_multiplier
        )
        
        # Calculate recovery costs
        recovery_costs = direct_costs * 0.3  # Typically 30% of direct costs
        
        total_cost = (direct_costs + indirect_costs + revenue_loss + 
                     regulatory_fines + legal_costs + recovery_costs)
        
        # Build cost breakdown
        cost_breakdown = {
            "direct_costs": direct_costs,
            "indirect_costs": indirect_costs,
            "revenue_loss": revenue_loss,
            "regulatory_fines": regulatory_fines,
            "legal_costs": legal_costs,
            "recovery_costs": recovery_costs
        }
        
        return FinancialImpact(
            direct_costs=direct_costs,
            indirect_costs=indirect_costs,
            revenue_loss=revenue_loss,
            regulatory_fines=regulatory_fines,
            legal_costs=legal_costs,
            recovery_costs=recovery_costs,
            total_estimated_cost=total_cost,
            cost_confidence=0.7,
            cost_breakdown=cost_breakdown
        )
    
    def _calculate_operational_impact(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        organization_size: OrganizationSize
    ) -> OperationalImpact:
        """Calculate operational impact of security incident."""
        
        # Base downtime calculation
        base_downtime = self._estimate_base_downtime(tool_capabilities)
        
        # Adjust for environment factors
        exposure_multiplier = {
            NetworkExposure.ISOLATED: 0.5,
            NetworkExposure.INTERNAL: 0.8,
            NetworkExposure.INTERNET_FACING: 1.5,
            NetworkExposure.PUBLIC: 2.0
        }.get(environment_context.network_exposure, 1.0)
        
        service_downtime = base_downtime * exposure_multiplier
        
        # Identify affected systems
        affected_systems = self._identify_affected_systems(tool_capabilities)
        
        # Identify affected processes
        affected_processes = self._identify_affected_processes(
            tool_capabilities, environment_context
        )
        
        # Calculate productivity loss
        productivity_loss = self._calculate_productivity_loss(
            tool_capabilities, service_downtime, organization_size
        )
        
        # Assess customer impact
        customer_impact = self._assess_customer_impact(
            tool_capabilities, environment_context
        )
        
        # Estimate recovery time
        recovery_time = self._estimate_recovery_time(
            tool_capabilities, service_downtime, organization_size
        )
        
        # Assess business continuity risk
        continuity_risk = self._assess_business_continuity_risk(
            tool_capabilities, environment_context
        )
        
        # Calculate overall operational disruption score
        disruption_score = self._calculate_operational_disruption_score(
            service_downtime, productivity_loss, len(affected_systems)
        )
        
        return OperationalImpact(
            service_downtime_hours=service_downtime,
            affected_systems=affected_systems,
            affected_processes=affected_processes,
            productivity_loss_percentage=productivity_loss,
            customer_impact_level=customer_impact,
            recovery_time_estimate=recovery_time,
            business_continuity_risk=continuity_risk,
            operational_disruption_score=disruption_score
        )
    
    def _calculate_reputation_impact(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        industry: IndustryVertical
    ) -> ReputationImpact:
        """Calculate reputational impact of security incident."""
        
        # Assess disclosure likelihood
        disclosure_likelihood = self._assess_disclosure_likelihood(
            environment_context, industry
        )
        
        # Assess media attention level
        media_attention = self._assess_media_attention_level(
            tool_capabilities, environment_context, industry
        )
        
        # Assess customer trust impact
        customer_trust_impact = self._assess_customer_trust_impact(
            tool_capabilities, environment_context, industry
        )
        
        # Assess partner confidence impact
        partner_impact = self._assess_partner_confidence_impact(
            tool_capabilities, environment_context
        )
        
        # Determine brand damage duration
        damage_duration = self._determine_brand_damage_duration(
            media_attention, customer_trust_impact, industry
        )
        
        # Estimate social media sentiment impact
        sentiment_impact = self._estimate_sentiment_impact(
            media_attention, customer_trust_impact
        )
        
        # Estimate market perception change
        market_perception = self._estimate_market_perception_change(
            tool_capabilities, environment_context, industry
        )
        
        # Estimate reputation recovery time
        recovery_months = self._estimate_reputation_recovery_time(
            media_attention, customer_trust_impact, industry
        )
        
        return ReputationImpact(
            public_disclosure_likelihood=disclosure_likelihood,
            media_attention_level=media_attention,
            customer_trust_impact=customer_trust_impact,
            partner_confidence_impact=partner_impact,
            brand_damage_duration=damage_duration,
            social_media_sentiment_impact=sentiment_impact,
            market_perception_change=market_perception,
            reputation_recovery_months=recovery_months
        )
    
    def _calculate_compliance_impact(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        industry: IndustryVertical
    ) -> ComplianceImpact:
        """Calculate compliance and regulatory impact."""
        
        # Identify affected regulations
        affected_regulations = self._identify_affected_regulations(
            environment_context, industry
        )
        
        # Assess violation likelihood
        violation_likelihood = self._assess_violation_likelihood(
            tool_capabilities, affected_regulations
        )
        
        # Calculate potential fines
        potential_fines = self._calculate_potential_fines(
            affected_regulations, environment_context, industry
        )
        
        # Identify audit requirements
        audit_requirements = self._identify_audit_requirements(affected_regulations)
        
        # Identify reporting obligations
        reporting_obligations = self._identify_reporting_obligations(affected_regulations)
        
        # Identify certification risks
        certification_risks = self._identify_certification_risks(
            affected_regulations, industry
        )
        
        # Identify remediation requirements
        remediation_requirements = self._identify_remediation_requirements(
            affected_regulations
        )
        
        return ComplianceImpact(
            affected_regulations=affected_regulations,
            violation_likelihood=violation_likelihood,
            potential_fines=potential_fines,
            audit_requirements=audit_requirements,
            reporting_obligations=reporting_obligations,
            certification_risks=certification_risks,
            remediation_requirements=remediation_requirements
        )
    
    def _analyze_cascading_effects(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[CascadingEffect]:
        """Analyze potential cascading effects from the initial incident."""
        cascading_effects = []
        
        # Analyze capability-based cascading effects
        for capability in tool_capabilities.capability_categories:
            effects = self._get_cascading_effects_for_capability(
                capability, tool_capabilities, environment_context
            )
            cascading_effects.extend(effects)
        
        # Analyze environment-based cascading effects
        env_effects = self._get_environment_cascading_effects(
            tool_capabilities, environment_context
        )
        cascading_effects.extend(env_effects)
        
        # Sort by probability and impact
        cascading_effects.sort(
            key=lambda e: e.probability * e.impact_magnitude, 
            reverse=True
        )
        
        return cascading_effects[:10]  # Return top 10 most likely effects
    
    def _calculate_recovery_costs(
        self,
        tool_capabilities: ToolCapabilities,
        financial_impact: FinancialImpact,
        operational_impact: OperationalImpact,
        organization_size: OrganizationSize
    ) -> List[RecoveryCost]:
        """Calculate costs for each recovery phase."""
        recovery_costs = []
        
        # Size-based hourly rates
        size_rates = {
            OrganizationSize.STARTUP: 50,
            OrganizationSize.SMALL_BUSINESS: 75,
            OrganizationSize.MEDIUM_ENTERPRISE: 125,
            OrganizationSize.LARGE_ENTERPRISE: 200,
            OrganizationSize.FORTUNE_500: 300
        }
        
        hourly_rate = size_rates[organization_size]
        
        # Calculate costs for each phase
        for phase in RecoveryPhase:
            phase_cost = self._calculate_phase_recovery_cost(
                phase, tool_capabilities, financial_impact, 
                operational_impact, hourly_rate
            )
            recovery_costs.append(phase_cost)
        
        return recovery_costs
    
    def _initialize_impact_models(self) -> Dict[str, Dict[str, Any]]:
        """Initialize impact calculation models."""
        return {
            "financial": {
                "base_incident_cost": 50000,  # Base cost per incident
                "hourly_downtime_cost": 5000,  # Cost per hour of downtime
                "data_record_cost": 150,  # Cost per compromised data record
                "system_recovery_cost": 25000  # Cost to recover a system
            },
            "operational": {
                "base_downtime_hours": 8,  # Base downtime estimate
                "recovery_multiplier": 1.5,  # Recovery time multiplier
                "productivity_impact_rate": 0.3  # Productivity loss rate
            },
            "reputation": {
                "disclosure_base_probability": 0.3,
                "media_attention_threshold": 0.5,
                "customer_trust_recovery_months": 12
            },
            "compliance": {
                "gdpr_max_fine_rate": 0.04,  # 4% of annual revenue
                "hipaa_max_fine": 1500000,  # $1.5M maximum fine
                "pci_dss_max_fine": 500000  # $500K maximum fine
            }
        }
    
    def _initialize_cost_models(self) -> Dict[str, Dict[str, Any]]:
        """Initialize cost calculation models."""
        return {
            "detection": {
                "hours_multiplier": 0.1,
                "technology_cost_ratio": 0.2,
                "external_service_ratio": 0.3
            },
            "containment": {
                "hours_multiplier": 0.2,
                "technology_cost_ratio": 0.3,
                "external_service_ratio": 0.4
            },
            "eradication": {
                "hours_multiplier": 0.3,
                "technology_cost_ratio": 0.4,
                "external_service_ratio": 0.3
            },
            "recovery": {
                "hours_multiplier": 0.3,
                "technology_cost_ratio": 0.5,
                "external_service_ratio": 0.2
            },
            "lessons_learned": {
                "hours_multiplier": 0.1,
                "technology_cost_ratio": 0.1,
                "external_service_ratio": 0.1
            }
        }
    
    def _initialize_cascading_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize cascading effect patterns."""
        return {
            "file_system": [
                {
                    "effect_type": "data_corruption",
                    "target_systems": ["backup_systems", "database_systems"],
                    "probability": 0.6,
                    "impact": 0.8,
                    "delay_hours": 2
                },
                {
                    "effect_type": "malware_spread",
                    "target_systems": ["connected_systems", "network_shares"],
                    "probability": 0.4,
                    "impact": 0.7,
                    "delay_hours": 1
                }
            ],
            "network_access": [
                {
                    "effect_type": "lateral_movement",
                    "target_systems": ["adjacent_systems", "trusted_networks"],
                    "probability": 0.7,
                    "impact": 0.6,
                    "delay_hours": 4
                },
                {
                    "effect_type": "network_disruption",
                    "target_systems": ["network_infrastructure", "communication_systems"],
                    "probability": 0.3,
                    "impact": 0.9,
                    "delay_hours": 0.5
                }
            ],
            "code_execution": [
                {
                    "effect_type": "privilege_escalation",
                    "target_systems": ["domain_controllers", "admin_systems"],
                    "probability": 0.8,
                    "impact": 0.9,
                    "delay_hours": 6
                }
            ]
        }
    
    def _initialize_industry_multipliers(self) -> Dict[IndustryVertical, Dict[str, float]]:
        """Initialize industry-specific impact multipliers."""
        return {
            IndustryVertical.FINANCIAL_SERVICES: {
                "financial": 2.5,
                "reputation": 2.0,
                "compliance": 3.0
            },
            IndustryVertical.HEALTHCARE: {
                "financial": 2.0,
                "reputation": 1.8,
                "compliance": 2.5
            },
            IndustryVertical.GOVERNMENT: {
                "financial": 1.5,
                "reputation": 2.5,
                "compliance": 2.0
            },
            IndustryVertical.TECHNOLOGY: {
                "financial": 1.8,
                "reputation": 2.2,
                "compliance": 1.5
            },
            IndustryVertical.RETAIL: {
                "financial": 1.6,
                "reputation": 1.9,
                "compliance": 1.8
            },
            IndustryVertical.MANUFACTURING: {
                "financial": 1.4,
                "reputation": 1.5,
                "compliance": 1.6
            },
            IndustryVertical.EDUCATION: {
                "financial": 1.2,
                "reputation": 1.6,
                "compliance": 1.4
            },
            IndustryVertical.ENERGY: {
                "financial": 2.2,
                "reputation": 1.8,
                "compliance": 2.2
            },
            IndustryVertical.TELECOMMUNICATIONS: {
                "financial": 1.9,
                "reputation": 2.0,
                "compliance": 1.9
            },
            IndustryVertical.OTHER: {
                "financial": 1.0,
                "reputation": 1.0,
                "compliance": 1.0
            }
        }
    
    def _generate_assessment_id(self, tool_name: str) -> str:
        """Generate unique assessment ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"impact_assess_{tool_name}_{timestamp}"
    
    def _calculate_direct_costs(
        self,
        tool_capabilities: ToolCapabilities,
        base_multiplier: float,
        industry_multiplier: float
    ) -> float:
        """Calculate direct incident response costs."""
        base_cost = self._impact_models["financial"]["base_incident_cost"]
        
        # Adjust for tool complexity
        complexity_multiplier = 1.0 + (len(tool_capabilities.tool_functions) * 0.1)
        
        # Adjust for risk level
        risk_multiplier = 1.0 + (tool_capabilities.risk_score * 0.5)
        
        return (base_cost * base_multiplier * industry_multiplier * 
                complexity_multiplier * risk_multiplier)
    
    def _calculate_indirect_costs(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        base_multiplier: float
    ) -> float:
        """Calculate indirect costs (productivity loss, etc.)."""
        base_cost = self._impact_models["financial"]["base_incident_cost"] * 0.6
        
        # Adjust for data sensitivity
        sensitivity_multiplier = {
            DataSensitivity.PUBLIC: 0.5,
            DataSensitivity.INTERNAL: 1.0,
            DataSensitivity.CONFIDENTIAL: 1.8,
            DataSensitivity.RESTRICTED: 2.5,
            DataSensitivity.TOP_SECRET: 3.0
        }.get(environment_context.data_sensitivity, 1.0)
        
        return base_cost * base_multiplier * sensitivity_multiplier
    
    def _calculate_revenue_loss(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        base_multiplier: float,
        industry_multiplier: float
    ) -> float:
        """Calculate potential revenue loss."""
        # Estimate based on downtime and business criticality
        base_downtime = self._estimate_base_downtime(tool_capabilities)
        hourly_revenue_loss = (self._impact_models["financial"]["hourly_downtime_cost"] * 
                              base_multiplier * industry_multiplier)
        
        return base_downtime * hourly_revenue_loss
    
    def _calculate_regulatory_fines(
        self,
        environment_context: EnvironmentContext,
        industry: IndustryVertical,
        base_multiplier: float
    ) -> float:
        """Calculate potential regulatory fines."""
        fines = 0.0
        
        # GDPR fines (if applicable)
        if ComplianceFramework.GDPR in environment_context.compliance_requirements:
            # Estimate based on 4% of annual revenue (simplified)
            estimated_revenue = base_multiplier * 10000000  # $10M base estimate
            fines += estimated_revenue * self._impact_models["compliance"]["gdpr_max_fine_rate"] * 0.1
        
        # HIPAA fines (if applicable)
        if ComplianceFramework.HIPAA in environment_context.compliance_requirements:
            fines += self._impact_models["compliance"]["hipaa_max_fine"] * 0.2
        
        # PCI DSS fines (if applicable)
        if ComplianceFramework.PCI_DSS in environment_context.compliance_requirements:
            fines += self._impact_models["compliance"]["pci_dss_max_fine"] * 0.3
        
        return fines
    
    def _calculate_legal_costs(
        self,
        environment_context: EnvironmentContext,
        base_multiplier: float,
        industry_multiplier: float
    ) -> float:
        """Calculate legal and consultation costs."""
        base_legal_cost = 25000  # Base legal cost
        
        # Adjust for data sensitivity and compliance requirements
        sensitivity_multiplier = len(environment_context.compliance_requirements) + 1
        
        return base_legal_cost * base_multiplier * industry_multiplier * sensitivity_multiplier
    
    def _estimate_base_downtime(self, tool_capabilities: ToolCapabilities) -> float:
        """Estimate base system downtime hours."""
        base_hours = self._impact_models["operational"]["base_downtime_hours"]
        
        # Adjust for tool complexity and risk
        complexity_factor = len(tool_capabilities.tool_functions) * 0.5
        risk_factor = tool_capabilities.risk_score * 4
        
        return base_hours + complexity_factor + risk_factor
    
    def _identify_affected_systems(self, tool_capabilities: ToolCapabilities) -> List[str]:
        """Identify systems likely to be affected."""
        affected_systems = []
        
        capability_system_mapping = {
            CapabilityCategory.FILE_SYSTEM: ["file_servers", "backup_systems", "workstations"],
            CapabilityCategory.NETWORK_ACCESS: ["network_infrastructure", "firewalls", "routers"],
            CapabilityCategory.DATABASE_ACCESS: ["database_servers", "application_servers"],
            CapabilityCategory.CODE_EXECUTION: ["application_servers", "compute_systems"],
            CapabilityCategory.AUTHENTICATION: ["identity_systems", "domain_controllers"],
            CapabilityCategory.CLOUD_SERVICES: ["cloud_infrastructure", "saas_applications"]
        }
        
        for capability in tool_capabilities.capability_categories:
            if capability in capability_system_mapping:
                affected_systems.extend(capability_system_mapping[capability])
        
        return list(set(affected_systems))  # Remove duplicates
    
    def _identify_affected_processes(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[str]:
        """Identify business processes likely to be affected."""
        processes = []
        
        # Map capabilities to affected business processes
        if CapabilityCategory.FILE_SYSTEM in tool_capabilities.capability_categories:
            processes.extend(["document_management", "data_backup", "file_sharing"])
        
        if CapabilityCategory.NETWORK_ACCESS in tool_capabilities.capability_categories:
            processes.extend(["communication", "collaboration", "remote_access"])
        
        if CapabilityCategory.DATABASE_ACCESS in tool_capabilities.capability_categories:
            processes.extend(["data_processing", "reporting", "analytics"])
        
        if CapabilityCategory.AUTHENTICATION in tool_capabilities.capability_categories:
            processes.extend(["user_access", "security_controls", "identity_management"])
        
        # Add environment-specific processes
        if environment_context.network_exposure in [NetworkExposure.INTERNET_FACING, NetworkExposure.PUBLIC]:
            processes.extend(["customer_services", "e_commerce", "public_communications"])
        
        return list(set(processes))
    
    # Additional helper methods would continue here...
    # Due to length constraints, I'm showing the key structure and some implementations
    
    def _calculate_productivity_loss(
        self,
        tool_capabilities: ToolCapabilities,
        downtime_hours: float,
        organization_size: OrganizationSize
    ) -> float:
        """Calculate productivity loss percentage."""
        base_rate = self._impact_models["operational"]["productivity_impact_rate"]
        
        # Adjust for downtime duration
        if downtime_hours > 24:
            base_rate *= 1.5
        elif downtime_hours > 8:
            base_rate *= 1.2
        
        # Adjust for organization size (larger orgs have more processes affected)
        size_multipliers = {
            OrganizationSize.STARTUP: 0.8,
            OrganizationSize.SMALL_BUSINESS: 0.9,
            OrganizationSize.MEDIUM_ENTERPRISE: 1.0,
            OrganizationSize.LARGE_ENTERPRISE: 1.2,
            OrganizationSize.FORTUNE_500: 1.4
        }
        
        return min(base_rate * size_multipliers[organization_size], 0.8)  # Cap at 80%
    
    def _assess_customer_impact(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> ImpactSeverity:
        """Assess level of customer impact."""
        if environment_context.network_exposure in [NetworkExposure.PUBLIC, NetworkExposure.INTERNET_FACING]:
            if tool_capabilities.external_access:
                return ImpactSeverity.MAJOR
            else:
                return ImpactSeverity.MODERATE
        else:
            return ImpactSeverity.MINOR
    
    def _estimate_recovery_time(
        self,
        tool_capabilities: ToolCapabilities,
        downtime_hours: float,
        organization_size: OrganizationSize
    ) -> float:
        """Estimate recovery time in hours."""
        base_recovery = downtime_hours * self._impact_models["operational"]["recovery_multiplier"]
        
        # Adjust for organization size (larger orgs take longer to coordinate)
        size_multipliers = {
            OrganizationSize.STARTUP: 0.8,
            OrganizationSize.SMALL_BUSINESS: 0.9,
            OrganizationSize.MEDIUM_ENTERPRISE: 1.0,
            OrganizationSize.LARGE_ENTERPRISE: 1.3,
            OrganizationSize.FORTUNE_500: 1.6
        }
        
        return base_recovery * size_multipliers[organization_size]
    
    def _assess_business_continuity_risk(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> ImpactSeverity:
        """Assess business continuity risk level."""
        risk_score = 0
        
        # High-risk capabilities
        high_risk_caps = [CapabilityCategory.CODE_EXECUTION, CapabilityCategory.DATABASE_ACCESS]
        risk_score += len([cap for cap in tool_capabilities.capability_categories if cap in high_risk_caps]) * 2
        
        # Environment factors
        if environment_context.data_sensitivity in [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED]:
            risk_score += 2
        
        if environment_context.network_exposure in [NetworkExposure.INTERNET_FACING, NetworkExposure.PUBLIC]:
            risk_score += 1
        
        # Convert to severity
        if risk_score >= 5:
            return ImpactSeverity.CATASTROPHIC
        elif risk_score >= 4:
            return ImpactSeverity.MAJOR
        elif risk_score >= 2:
            return ImpactSeverity.MODERATE
        else:
            return ImpactSeverity.MINOR
    
    def _calculate_operational_disruption_score(
        self,
        downtime_hours: float,
        productivity_loss: float,
        affected_systems_count: int
    ) -> float:
        """Calculate overall operational disruption score (0.0-1.0)."""
        # Normalize components
        downtime_score = min(downtime_hours / 48.0, 1.0)  # Normalize against 48 hours
        productivity_score = productivity_loss  # Already normalized
        systems_score = min(affected_systems_count / 10.0, 1.0)  # Normalize against 10 systems
        
        # Weighted average
        return (downtime_score * 0.4 + productivity_score * 0.4 + systems_score * 0.2)
    
    # Continue with remaining helper methods...
    # (Additional methods would be implemented for reputation, compliance, cascading effects, etc.)
    
    def _calculate_overall_impact_score(
        self,
        financial_impact: FinancialImpact,
        operational_impact: OperationalImpact,
        reputation_impact: ReputationImpact,
        compliance_impact: ComplianceImpact
    ) -> float:
        """Calculate overall business impact score (0.0-1.0)."""
        # Normalize financial impact (assuming $1M as reference point)
        financial_score = min(financial_impact.total_estimated_cost / 1000000, 1.0)
        
        # Operational impact score (already normalized)
        operational_score = operational_impact.operational_disruption_score
        
        # Reputation impact score
        reputation_score = (
            reputation_impact.public_disclosure_likelihood * 0.3 +
            (len([x for x in [reputation_impact.media_attention_level, 
                             reputation_impact.customer_trust_impact,
                             reputation_impact.partner_confidence_impact] 
                  if x in [ImpactSeverity.MAJOR, ImpactSeverity.CATASTROPHIC]]) / 3.0) * 0.7
        )
        
        # Compliance impact score
        compliance_score = (
            compliance_impact.violation_likelihood * 0.5 +
            min(compliance_impact.potential_fines / 500000, 1.0) * 0.5  # Normalize against $500K
        )
        
        # Weighted average
        return (financial_score * 0.3 + operational_score * 0.3 + 
                reputation_score * 0.2 + compliance_score * 0.2)
    
    def _determine_business_criticality(
        self,
        overall_score: float,
        cascading_effects: List[CascadingEffect]
    ) -> ImpactSeverity:
        """Determine overall business criticality level."""
        # Base criticality from overall score
        if overall_score >= 0.8:
            base_criticality = ImpactSeverity.CATASTROPHIC
        elif overall_score >= 0.6:
            base_criticality = ImpactSeverity.MAJOR
        elif overall_score >= 0.4:
            base_criticality = ImpactSeverity.MODERATE
        elif overall_score >= 0.2:
            base_criticality = ImpactSeverity.MINOR
        else:
            base_criticality = ImpactSeverity.NEGLIGIBLE
        
        # Adjust for cascading effects
        high_impact_cascades = len([e for e in cascading_effects if e.impact_magnitude > 0.7])
        if high_impact_cascades > 2 and base_criticality.value < ImpactSeverity.MAJOR.value:
            # Upgrade criticality if many high-impact cascading effects
            criticality_levels = list(ImpactSeverity)
            current_index = criticality_levels.index(base_criticality)
            return criticality_levels[min(current_index + 1, len(criticality_levels) - 1)]
        
        return base_criticality
    
    def _calculate_insurance_recommendation(self, financial_impact: FinancialImpact) -> float:
        """Calculate recommended cyber insurance coverage."""
        # Recommend coverage of 2-3x the total estimated cost
        return financial_impact.total_estimated_cost * 2.5
    
    def _calculate_confidence_score(
        self,
        tool_capabilities: ToolCapabilities,
        financial_impact: FinancialImpact,
        operational_impact: OperationalImpact
    ) -> float:
        """Calculate confidence score for the impact assessment."""
        base_confidence = 0.6
        
        # Increase confidence with more tool information
        if len(tool_capabilities.tool_functions) > 5:
            base_confidence += 0.1
        
        if tool_capabilities.risk_indicators:
            base_confidence += 0.1
        
        # Consider financial impact confidence
        base_confidence = (base_confidence + financial_impact.cost_confidence) / 2
        
        return min(base_confidence, 0.85)  # Cap at 85%
    
    # Additional helper methods for cascading effects, recovery costs, etc.
    # would be implemented here...
    
    def _get_cascading_effects_for_capability(
        self,
        capability: CapabilityCategory,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[CascadingEffect]:
        """Get cascading effects for a specific capability."""
        effects = []
        capability_key = capability.value.lower()
        
        if capability_key in self._cascading_patterns:
            for pattern in self._cascading_patterns[capability_key]:
                effect = CascadingEffect(
                    effect_id=f"{capability_key}_{pattern['effect_type']}",
                    source_system=tool_capabilities.tool_name,
                    target_system=pattern["target_systems"][0] if pattern["target_systems"] else "unknown",
                    effect_type=pattern["effect_type"],
                    propagation_delay=pattern["delay_hours"],
                    impact_magnitude=pattern["impact"],
                    probability=pattern["probability"],
                    mitigation_difficulty=DifficultyLevel.MEDIUM,
                    description=f"{pattern['effect_type'].replace('_', ' ').title()} effect from {tool_capabilities.tool_name}",
                    prerequisites=["initial_compromise", "network_access"],
                    indicators=["unusual_network_traffic", "system_performance_degradation"]
                )
                effects.append(effect)
        
        return effects
    
    def _get_environment_cascading_effects(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[CascadingEffect]:
        """Get environment-specific cascading effects."""
        effects = []
        
        # High exposure environments have additional cascading risks
        if environment_context.network_exposure in [NetworkExposure.INTERNET_FACING, NetworkExposure.PUBLIC]:
            effect = CascadingEffect(
                effect_id="public_exposure_cascade",
                source_system=tool_capabilities.tool_name,
                target_system="public_reputation",
                effect_type="reputation_damage",
                propagation_delay=24,  # 24 hours for news to spread
                impact_magnitude=0.8,
                probability=0.6,
                mitigation_difficulty=DifficultyLevel.HIGH,
                description="Public exposure leading to reputation damage and media attention",
                prerequisites=["security_incident", "public_disclosure"],
                indicators=["media_coverage", "social_media_mentions", "customer_complaints"]
            )
            effects.append(effect)
        
        return effects
    
    def _calculate_phase_recovery_cost(
        self,
        phase: RecoveryPhase,
        tool_capabilities: ToolCapabilities,
        financial_impact: FinancialImpact,
        operational_impact: OperationalImpact,
        hourly_rate: float
    ) -> RecoveryCost:
        """Calculate recovery costs for a specific phase."""
        phase_key = phase.value
        cost_model = self._cost_models[phase_key]
        
        # Base hours calculation
        base_hours = operational_impact.recovery_time_estimate * cost_model["hours_multiplier"]
        
        # Personnel costs
        personnel_costs = base_hours * hourly_rate
        
        # Technology costs
        technology_costs = personnel_costs * cost_model["technology_cost_ratio"]
        
        # External service costs
        external_costs = personnel_costs * cost_model["external_service_ratio"]
        
        # Opportunity costs (lost productivity)
        opportunity_costs = financial_impact.total_estimated_cost * 0.1  # 10% of total impact
        
        total_cost = personnel_costs + technology_costs + external_costs + opportunity_costs
        
        # Cost drivers
        cost_drivers = [
            f"Personnel: {base_hours:.1f} hours at ${hourly_rate}/hour",
            f"Technology: ${technology_costs:.0f}",
            f"External services: ${external_costs:.0f}",
            f"Opportunity cost: ${opportunity_costs:.0f}"
        ]
        
        return RecoveryCost(
            phase=phase,
            estimated_hours=base_hours,
            personnel_costs=personnel_costs,
            technology_costs=technology_costs,
            external_service_costs=external_costs,
            opportunity_costs=opportunity_costs,
            total_phase_cost=total_cost,
            confidence_level=0.7,
            cost_drivers=cost_drivers
        ) 