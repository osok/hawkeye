"""
Likelihood Assessment Component

This module implements comprehensive likelihood assessment capabilities including threat actor profiling,
attack probability modeling, and environmental risk factor analysis for MCP server security threats.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import math

from .models import (
    ToolCapabilities, EnvironmentContext, ThreatActorType, ThreatLevel,
    SeverityLevel, DifficultyLevel, AccessLevel, CapabilityCategory,
    DataSensitivity, NetworkExposure, SecurityPosture, UserPrivileges
)


class LikelihoodLevel(Enum):
    """Likelihood levels for threat occurrence."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class AttackComplexity(Enum):
    """Attack complexity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionDifficulty(Enum):
    """Difficulty levels for attack detection."""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    VERY_HARD = "very_hard"


class TargetAttractiveness(Enum):
    """Target attractiveness levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ThreatActorSophistication(Enum):
    """Threat actor sophistication levels."""
    SCRIPT_KIDDIE = "script_kiddie"
    OPPORTUNISTIC = "opportunistic"
    SKILLED = "skilled"
    EXPERT = "expert"
    NATION_STATE = "nation_state"


class AttackWindow(Enum):
    """Time windows for attacks."""
    IMMEDIATE = "immediate"  # Minutes to hours
    SHORT_TERM = "short_term"  # Days to weeks
    MEDIUM_TERM = "medium_term"  # Weeks to months
    LONG_TERM = "long_term"  # Months to years


@dataclass
class ThreatActorProfile:
    """Comprehensive threat actor profile for likelihood assessment."""
    actor_type: ThreatActorType
    sophistication: ThreatActorSophistication
    primary_motivations: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    typical_targets: List[str] = field(default_factory=list)
    attack_methods: List[str] = field(default_factory=list)
    operational_security: float = 0.5  # 0.0-1.0, how careful they are
    persistence_level: float = 0.5  # 0.0-1.0, how persistent
    risk_tolerance: float = 0.5  # 0.0-1.0, willingness to take risks
    stealth_preference: float = 0.5  # 0.0-1.0, preference for staying hidden
    activity_patterns: Dict[str, Any] = field(default_factory=dict)
    geographical_focus: List[str] = field(default_factory=list)
    success_rate: float = 0.5  # Historical success rate
    detection_rate: float = 0.3  # How often they get detected


@dataclass
class AttackVector:
    """Detailed attack vector with likelihood assessment."""
    vector_id: str
    name: str
    description: str
    required_capabilities: List[CapabilityCategory] = field(default_factory=list)
    complexity: AttackComplexity = AttackComplexity.MEDIUM
    required_access: AccessLevel = AccessLevel.USER
    detection_difficulty: DetectionDifficulty = DetectionDifficulty.MEDIUM
    time_to_execute: float = 1.0  # Hours
    success_probability: float = 0.5
    stealth_level: float = 0.5
    prerequisites: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)


@dataclass
class EnvironmentalFactor:
    """Environmental factor affecting attack likelihood."""
    factor_name: str
    factor_type: str
    impact_on_likelihood: float  # -1.0 to 1.0, negative reduces likelihood
    confidence: float = 0.7
    description: str = ""
    mitigation_available: bool = False


@dataclass
class LikelihoodAssessment:
    """Complete likelihood assessment for a threat."""
    threat_id: str
    tool_name: str
    base_likelihood: float
    adjusted_likelihood: float
    likelihood_level: LikelihoodLevel
    primary_threat_actors: List[ThreatActorType] = field(default_factory=list)
    attack_vectors: List[AttackVector] = field(default_factory=list)
    environmental_factors: List[EnvironmentalFactor] = field(default_factory=list)
    target_attractiveness: TargetAttractiveness = TargetAttractiveness.MEDIUM
    attack_window: AttackWindow = AttackWindow.SHORT_TERM
    confidence_score: float = 0.0
    assessment_rationale: str = ""
    key_risk_factors: List[str] = field(default_factory=list)
    mitigation_impact: float = 0.0  # How much mitigations reduce likelihood
    assessment_timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ThreatLikelihoodMatrix:
    """Matrix of threat likelihood assessments."""
    tool_name: str
    assessments: List[LikelihoodAssessment] = field(default_factory=list)
    overall_risk_level: ThreatLevel = ThreatLevel.MEDIUM
    highest_likelihood_threats: List[str] = field(default_factory=list)
    recommended_monitoring: List[str] = field(default_factory=list)
    early_warning_indicators: List[str] = field(default_factory=list)
    assessment_summary: str = ""


class LikelihoodAssessor:
    """
    Enhanced likelihood assessor with threat actor profiling and comprehensive
    probability modeling for security threats.
    """
    
    def __init__(self):
        """Initialize the likelihood assessor."""
        self.logger = logging.getLogger(__name__)
        self._threat_actor_profiles = self._initialize_threat_actor_profiles()
        self._attack_patterns = self._initialize_attack_patterns()
        self._environmental_factors = self._initialize_environmental_factors()
        self._complexity_models = self._initialize_complexity_models()
    
    def assess_threat_likelihood(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        threat_scenarios: Optional[List[str]] = None
    ) -> ThreatLikelihoodMatrix:
        """
        Assess the likelihood of various threats against the MCP tool.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            threat_scenarios: Specific threat scenarios to assess (optional)
            
        Returns:
            Complete threat likelihood matrix
        """
        self.logger.info(f"Assessing threat likelihood for {tool_capabilities.tool_name}")
        
        # Generate threat scenarios if not provided
        if not threat_scenarios:
            threat_scenarios = self._generate_threat_scenarios(tool_capabilities)
        
        assessments = []
        
        # Assess likelihood for each threat scenario
        for scenario in threat_scenarios:
            assessment = self._assess_scenario_likelihood(
                scenario, tool_capabilities, environment_context
            )
            assessments.append(assessment)
        
        # Determine overall risk level
        overall_risk = self._calculate_overall_risk_level(assessments)
        
        # Identify highest likelihood threats
        high_likelihood = self._identify_high_likelihood_threats(assessments)
        
        # Generate monitoring recommendations
        monitoring_recs = self._generate_monitoring_recommendations(assessments)
        
        # Generate early warning indicators
        early_warnings = self._generate_early_warning_indicators(assessments)
        
        # Create assessment summary
        summary = self._create_assessment_summary(assessments, overall_risk)
        
        matrix = ThreatLikelihoodMatrix(
            tool_name=tool_capabilities.tool_name,
            assessments=assessments,
            overall_risk_level=overall_risk,
            highest_likelihood_threats=high_likelihood,
            recommended_monitoring=monitoring_recs,
            early_warning_indicators=early_warnings,
            assessment_summary=summary
        )
        
        self.logger.info(f"Completed likelihood assessment with {len(assessments)} scenarios")
        return matrix
    
    def profile_threat_actors(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[ThreatActorProfile]:
        """
        Profile threat actors most likely to target the MCP tool.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            
        Returns:
            List of relevant threat actor profiles
        """
        self.logger.info(f"Profiling threat actors for {tool_capabilities.tool_name}")
        
        # Determine relevant threat actors
        relevant_actors = self._identify_relevant_threat_actors(
            tool_capabilities, environment_context
        )
        
        profiles = []
        for actor_type in relevant_actors:
            profile = self._create_detailed_threat_actor_profile(
                actor_type, tool_capabilities, environment_context
            )
            profiles.append(profile)
        
        # Sort by relevance/threat level
        profiles.sort(key=lambda p: self._calculate_actor_threat_score(p), reverse=True)
        
        self.logger.info(f"Created {len(profiles)} threat actor profiles")
        return profiles
    
    def calculate_attack_probability(
        self,
        attack_vector: AttackVector,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        threat_actor: ThreatActorType
    ) -> float:
        """
        Calculate the probability of a specific attack vector succeeding.
        
        Args:
            attack_vector: Attack vector to assess
            tool_capabilities: Tool capabilities
            environment_context: Environment context
            threat_actor: Threat actor type
            
        Returns:
            Probability score (0.0-1.0)
        """
        # Base probability from attack vector
        base_prob = attack_vector.success_probability
        
        # Adjust for threat actor capabilities
        actor_adjustment = self._calculate_actor_capability_adjustment(
            threat_actor, attack_vector
        )
        
        # Adjust for environmental factors
        env_adjustment = self._calculate_environmental_adjustment(
            attack_vector, environment_context
        )
        
        # Adjust for tool-specific factors
        tool_adjustment = self._calculate_tool_specific_adjustment(
            attack_vector, tool_capabilities
        )
        
        # Combine adjustments
        adjusted_prob = base_prob * actor_adjustment * env_adjustment * tool_adjustment
        
        # Ensure probability stays within bounds
        return max(0.0, min(1.0, adjusted_prob))
    
    def _initialize_threat_actor_profiles(self) -> Dict[ThreatActorType, Dict[str, Any]]:
        """Initialize threat actor profile templates."""
        return {
            ThreatActorType.INSIDER_THREAT: {
                "sophistication": ThreatActorSophistication.SKILLED,
                "motivations": ["financial_gain", "revenge", "ideology", "coercion"],
                "capabilities": ["privileged_access", "system_knowledge", "social_engineering"],
                "resources": ["legitimate_credentials", "internal_network_access", "trust_relationships"],
                "targets": ["sensitive_data", "financial_systems", "intellectual_property"],
                "methods": ["data_exfiltration", "privilege_abuse", "system_sabotage"],
                "operational_security": 0.7,
                "persistence": 0.8,
                "risk_tolerance": 0.4,
                "stealth_preference": 0.9,
                "success_rate": 0.7,
                "detection_rate": 0.2
            },
            ThreatActorType.EXTERNAL_ATTACKER: {
                "sophistication": ThreatActorSophistication.OPPORTUNISTIC,
                "motivations": ["financial_gain", "data_theft", "curiosity", "challenge"],
                "capabilities": ["vulnerability_exploitation", "social_engineering", "reconnaissance"],
                "resources": ["public_exploits", "automated_tools", "online_tutorials"],
                "targets": ["exposed_services", "weak_credentials", "unpatched_systems"],
                "methods": ["brute_force", "phishing", "malware_deployment"],
                "operational_security": 0.4,
                "persistence": 0.5,
                "risk_tolerance": 0.7,
                "stealth_preference": 0.5,
                "success_rate": 0.3,
                "detection_rate": 0.6
            },
            ThreatActorType.NATION_STATE: {
                "sophistication": ThreatActorSophistication.NATION_STATE,
                "motivations": ["espionage", "intelligence_gathering", "strategic_advantage"],
                "capabilities": ["zero_day_exploits", "advanced_malware", "supply_chain_compromise"],
                "resources": ["unlimited_budget", "expert_teams", "custom_tooling"],
                "targets": ["government_systems", "critical_infrastructure", "high_value_data"],
                "methods": ["advanced_persistent_threat", "supply_chain_attack", "insider_recruitment"],
                "operational_security": 0.95,
                "persistence": 0.9,
                "risk_tolerance": 0.2,
                "stealth_preference": 0.95,
                "success_rate": 0.8,
                "detection_rate": 0.1
            },
            ThreatActorType.CYBERCRIMINAL: {
                "sophistication": ThreatActorSophistication.SKILLED,
                "motivations": ["financial_gain", "cryptocurrency", "fraud"],
                "capabilities": ["ransomware", "banking_trojans", "cryptocurrency_mining"],
                "resources": ["criminal_networks", "dark_web_markets", "money_laundering"],
                "targets": ["financial_data", "personal_information", "business_systems"],
                "methods": ["ransomware_deployment", "credential_theft", "fraud_schemes"],
                "operational_security": 0.6,
                "persistence": 0.7,
                "risk_tolerance": 0.6,
                "stealth_preference": 0.7,
                "success_rate": 0.6,
                "detection_rate": 0.4
            },
            ThreatActorType.HACKTIVIST: {
                "sophistication": ThreatActorSophistication.OPPORTUNISTIC,
                "motivations": ["political_activism", "social_causes", "publicity"],
                "capabilities": ["ddos_attacks", "website_defacement", "data_leaks"],
                "resources": ["volunteer_networks", "public_tools", "social_media"],
                "targets": ["government_sites", "corporate_websites", "controversial_organizations"],
                "methods": ["ddos_campaigns", "website_defacement", "data_dumps"],
                "operational_security": 0.3,
                "persistence": 0.4,
                "risk_tolerance": 0.8,
                "stealth_preference": 0.2,
                "success_rate": 0.4,
                "detection_rate": 0.8
            }
        }
    
    def _initialize_attack_patterns(self) -> Dict[str, AttackVector]:
        """Initialize common attack patterns."""
        return {
            "credential_brute_force": AttackVector(
                vector_id="cred_brute_force",
                name="Credential Brute Force Attack",
                description="Systematic attempts to guess authentication credentials",
                required_capabilities=[CapabilityCategory.AUTHENTICATION],
                complexity=AttackComplexity.LOW,
                required_access=AccessLevel.NONE,
                detection_difficulty=DetectionDifficulty.EASY,
                time_to_execute=4.0,
                success_probability=0.3,
                stealth_level=0.2,
                prerequisites=["network_access", "target_identification"],
                indicators=["multiple_failed_logins", "unusual_login_patterns"]
            ),
            "privilege_escalation": AttackVector(
                vector_id="priv_escalation",
                name="Privilege Escalation",
                description="Gaining higher-level system permissions",
                required_capabilities=[CapabilityCategory.CODE_EXECUTION],
                complexity=AttackComplexity.HIGH,
                required_access=AccessLevel.USER,
                detection_difficulty=DetectionDifficulty.HARD,
                time_to_execute=8.0,
                success_probability=0.6,
                stealth_level=0.7,
                prerequisites=["initial_access", "vulnerability_research"],
                indicators=["unexpected_privilege_changes", "unusual_system_calls"]
            ),
            "data_exfiltration": AttackVector(
                vector_id="data_exfil",
                name="Data Exfiltration",
                description="Unauthorized extraction of sensitive data",
                required_capabilities=[CapabilityCategory.FILE_SYSTEM, CapabilityCategory.NETWORK_ACCESS],
                complexity=AttackComplexity.MEDIUM,
                required_access=AccessLevel.USER,
                detection_difficulty=DetectionDifficulty.MEDIUM,
                time_to_execute=2.0,
                success_probability=0.7,
                stealth_level=0.6,
                prerequisites=["data_access", "exfiltration_channel"],
                indicators=["unusual_data_transfers", "large_file_operations"]
            ),
            "lateral_movement": AttackVector(
                vector_id="lateral_movement",
                name="Lateral Movement",
                description="Moving through network to access additional systems",
                required_capabilities=[CapabilityCategory.NETWORK_ACCESS],
                complexity=AttackComplexity.MEDIUM,
                required_access=AccessLevel.USER,
                detection_difficulty=DetectionDifficulty.HARD,
                time_to_execute=6.0,
                success_probability=0.5,
                stealth_level=0.8,
                prerequisites=["network_reconnaissance", "credential_access"],
                indicators=["unusual_network_connections", "cross_system_access"]
            ),
            "command_injection": AttackVector(
                vector_id="cmd_injection",
                name="Command Injection",
                description="Injecting malicious commands into application inputs",
                required_capabilities=[CapabilityCategory.CODE_EXECUTION],
                complexity=AttackComplexity.MEDIUM,
                required_access=AccessLevel.NONE,
                detection_difficulty=DetectionDifficulty.MEDIUM,
                time_to_execute=1.0,
                success_probability=0.8,
                stealth_level=0.4,
                prerequisites=["input_validation_weakness", "command_execution_context"],
                indicators=["unusual_command_execution", "unexpected_process_creation"]
            )
        }
    
    def _initialize_environmental_factors(self) -> Dict[str, List[EnvironmentalFactor]]:
        """Initialize environmental factors that affect likelihood."""
        return {
            "network_exposure": [
                EnvironmentalFactor(
                    factor_name="Internet Facing",
                    factor_type="exposure",
                    impact_on_likelihood=0.5,
                    description="System exposed to internet increases attack likelihood"
                ),
                EnvironmentalFactor(
                    factor_name="Internal Network Only",
                    factor_type="exposure",
                    impact_on_likelihood=-0.3,
                    description="Internal-only systems reduce external attack likelihood"
                )
            ],
            "security_posture": [
                EnvironmentalFactor(
                    factor_name="Strong Security Controls",
                    factor_type="defense",
                    impact_on_likelihood=-0.4,
                    description="Strong security controls reduce attack success probability"
                ),
                EnvironmentalFactor(
                    factor_name="Weak Security Controls",
                    factor_type="defense",
                    impact_on_likelihood=0.3,
                    description="Weak security controls increase vulnerability"
                )
            ],
            "data_sensitivity": [
                EnvironmentalFactor(
                    factor_name="High Value Data",
                    factor_type="motivation",
                    impact_on_likelihood=0.4,
                    description="High-value data increases attacker motivation"
                ),
                EnvironmentalFactor(
                    factor_name="Low Value Data",
                    factor_type="motivation",
                    impact_on_likelihood=-0.2,
                    description="Low-value data reduces attacker interest"
                )
            ],
            "user_privileges": [
                EnvironmentalFactor(
                    factor_name="Administrative Access",
                    factor_type="access",
                    impact_on_likelihood=0.3,
                    description="Administrative access increases attack impact potential"
                ),
                EnvironmentalFactor(
                    factor_name="Restricted Access",
                    factor_type="access",
                    impact_on_likelihood=-0.2,
                    description="Restricted access reduces attack surface"
                )
            ]
        }
    
    def _initialize_complexity_models(self) -> Dict[str, Dict[str, float]]:
        """Initialize attack complexity models."""
        return {
            "base_complexity": {
                AttackComplexity.LOW.value: 0.8,
                AttackComplexity.MEDIUM.value: 0.5,
                AttackComplexity.HIGH.value: 0.2
            },
            "detection_difficulty": {
                DetectionDifficulty.EASY.value: 0.9,
                DetectionDifficulty.MEDIUM.value: 0.6,
                DetectionDifficulty.HARD.value: 0.3,
                DetectionDifficulty.VERY_HARD.value: 0.1
            },
            "actor_sophistication": {
                ThreatActorSophistication.SCRIPT_KIDDIE.value: 0.2,
                ThreatActorSophistication.OPPORTUNISTIC.value: 0.4,
                ThreatActorSophistication.SKILLED.value: 0.7,
                ThreatActorSophistication.EXPERT.value: 0.9,
                ThreatActorSophistication.NATION_STATE.value: 0.95
            }
        }
    
    def _generate_threat_scenarios(self, tool_capabilities: ToolCapabilities) -> List[str]:
        """Generate threat scenarios based on tool capabilities."""
        scenarios = []
        
        # Map capabilities to threat scenarios
        capability_scenarios = {
            CapabilityCategory.FILE_SYSTEM: [
                "unauthorized_file_access",
                "data_theft",
                "file_system_corruption",
                "malware_installation"
            ],
            CapabilityCategory.NETWORK_ACCESS: [
                "network_reconnaissance",
                "lateral_movement",
                "data_exfiltration",
                "command_and_control"
            ],
            CapabilityCategory.CODE_EXECUTION: [
                "remote_code_execution",
                "privilege_escalation",
                "system_compromise",
                "backdoor_installation"
            ],
            CapabilityCategory.DATABASE_ACCESS: [
                "database_compromise",
                "sensitive_data_access",
                "data_manipulation",
                "database_corruption"
            ],
            CapabilityCategory.AUTHENTICATION: [
                "credential_theft",
                "authentication_bypass",
                "session_hijacking",
                "identity_spoofing"
            ],
            CapabilityCategory.CLOUD_SERVICES: [
                "cloud_resource_abuse",
                "service_hijacking",
                "cloud_data_breach",
                "infrastructure_compromise"
            ]
        }
        
        # Generate scenarios based on tool capabilities
        for capability in tool_capabilities.capability_categories:
            if capability in capability_scenarios:
                scenarios.extend(capability_scenarios[capability])
        
        # Remove duplicates while preserving order
        unique_scenarios = []
        for scenario in scenarios:
            if scenario not in unique_scenarios:
                unique_scenarios.append(scenario)
        
        return unique_scenarios[:10]  # Limit to top 10 scenarios
    
    def _assess_scenario_likelihood(
        self,
        scenario: str,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> LikelihoodAssessment:
        """Assess likelihood for a specific threat scenario."""
        
        # Calculate base likelihood
        base_likelihood = self._calculate_base_likelihood(scenario, tool_capabilities)
        
        # Identify relevant threat actors
        threat_actors = self._identify_scenario_threat_actors(scenario)
        
        # Generate attack vectors for scenario
        attack_vectors = self._generate_scenario_attack_vectors(scenario, tool_capabilities)
        
        # Analyze environmental factors
        env_factors = self._analyze_environmental_factors(scenario, environment_context)
        
        # Calculate environmental adjustments
        env_adjustment = sum(factor.impact_on_likelihood for factor in env_factors)
        
        # Calculate adjusted likelihood
        adjusted_likelihood = max(0.0, min(1.0, base_likelihood + env_adjustment))
        
        # Determine likelihood level
        likelihood_level = self._determine_likelihood_level(adjusted_likelihood)
        
        # Assess target attractiveness
        attractiveness = self._assess_target_attractiveness(
            scenario, tool_capabilities, environment_context
        )
        
        # Determine attack window
        attack_window = self._determine_attack_window(scenario, threat_actors)
        
        # Calculate confidence score
        confidence = self._calculate_likelihood_confidence(
            tool_capabilities, env_factors, len(attack_vectors)
        )
        
        # Generate assessment rationale
        rationale = self._generate_assessment_rationale(
            scenario, base_likelihood, env_factors, threat_actors
        )
        
        # Identify key risk factors
        risk_factors = self._identify_key_risk_factors(
            scenario, tool_capabilities, environment_context
        )
        
        # Calculate mitigation impact
        mitigation_impact = self._calculate_mitigation_impact(scenario, environment_context)
        
        return LikelihoodAssessment(
            threat_id=f"{scenario}_{tool_capabilities.tool_name}",
            tool_name=tool_capabilities.tool_name,
            base_likelihood=base_likelihood,
            adjusted_likelihood=adjusted_likelihood,
            likelihood_level=likelihood_level,
            primary_threat_actors=threat_actors,
            attack_vectors=attack_vectors,
            environmental_factors=env_factors,
            target_attractiveness=attractiveness,
            attack_window=attack_window,
            confidence_score=confidence,
            assessment_rationale=rationale,
            key_risk_factors=risk_factors,
            mitigation_impact=mitigation_impact
        )
    
    def _calculate_base_likelihood(self, scenario: str, tool_capabilities: ToolCapabilities) -> float:
        """Calculate base likelihood for a threat scenario."""
        # Base likelihood mapping
        scenario_base_likelihood = {
            "unauthorized_file_access": 0.6,
            "data_theft": 0.7,
            "file_system_corruption": 0.3,
            "malware_installation": 0.4,
            "network_reconnaissance": 0.8,
            "lateral_movement": 0.5,
            "data_exfiltration": 0.6,
            "command_and_control": 0.4,
            "remote_code_execution": 0.5,
            "privilege_escalation": 0.4,
            "system_compromise": 0.5,
            "backdoor_installation": 0.3,
            "database_compromise": 0.6,
            "sensitive_data_access": 0.7,
            "data_manipulation": 0.4,
            "database_corruption": 0.2,
            "credential_theft": 0.8,
            "authentication_bypass": 0.5,
            "session_hijacking": 0.6,
            "identity_spoofing": 0.4,
            "cloud_resource_abuse": 0.5,
            "service_hijacking": 0.4,
            "cloud_data_breach": 0.6,
            "infrastructure_compromise": 0.3
        }
        
        base = scenario_base_likelihood.get(scenario, 0.5)
        
        # Adjust for tool risk score
        risk_adjustment = tool_capabilities.risk_score * 0.3
        
        # Adjust for external access
        if tool_capabilities.external_access:
            base += 0.2
        
        # Adjust for privilege requirements
        if tool_capabilities.requires_privileges:
            base -= 0.1  # Reduces likelihood due to access barriers
        
        return max(0.1, min(0.9, base + risk_adjustment))
    
    def _identify_scenario_threat_actors(self, scenario: str) -> List[ThreatActorType]:
        """Identify threat actors most likely to execute a scenario."""
        scenario_actor_mapping = {
            "unauthorized_file_access": [ThreatActorType.INSIDER_THREAT, ThreatActorType.EXTERNAL_ATTACKER],
            "data_theft": [ThreatActorType.CYBERCRIMINAL, ThreatActorType.NATION_STATE, ThreatActorType.INSIDER_THREAT],
            "network_reconnaissance": [ThreatActorType.EXTERNAL_ATTACKER, ThreatActorType.NATION_STATE],
            "remote_code_execution": [ThreatActorType.CYBERCRIMINAL, ThreatActorType.NATION_STATE],
            "privilege_escalation": [ThreatActorType.EXTERNAL_ATTACKER, ThreatActorType.CYBERCRIMINAL],
            "credential_theft": [ThreatActorType.CYBERCRIMINAL, ThreatActorType.EXTERNAL_ATTACKER],
            "database_compromise": [ThreatActorType.CYBERCRIMINAL, ThreatActorType.NATION_STATE],
            "cloud_resource_abuse": [ThreatActorType.CYBERCRIMINAL, ThreatActorType.EXTERNAL_ATTACKER]
        }
        
        return scenario_actor_mapping.get(scenario, [ThreatActorType.EXTERNAL_ATTACKER])
    
    def _generate_scenario_attack_vectors(
        self, scenario: str, tool_capabilities: ToolCapabilities
    ) -> List[AttackVector]:
        """Generate attack vectors for a specific scenario."""
        vectors = []
        
        # Map scenarios to relevant attack patterns
        scenario_vector_mapping = {
            "unauthorized_file_access": ["data_exfiltration"],
            "data_theft": ["data_exfiltration", "credential_brute_force"],
            "network_reconnaissance": ["lateral_movement"],
            "remote_code_execution": ["command_injection", "privilege_escalation"],
            "privilege_escalation": ["privilege_escalation"],
            "credential_theft": ["credential_brute_force"],
            "database_compromise": ["command_injection", "data_exfiltration"]
        }
        
        vector_names = scenario_vector_mapping.get(scenario, ["credential_brute_force"])
        
        for vector_name in vector_names:
            if vector_name in self._attack_patterns:
                vectors.append(self._attack_patterns[vector_name])
        
        return vectors
    
    def _analyze_environmental_factors(
        self, scenario: str, environment_context: EnvironmentContext
    ) -> List[EnvironmentalFactor]:
        """Analyze environmental factors affecting scenario likelihood."""
        factors = []
        
        # Network exposure factors
        if environment_context.network_exposure == NetworkExposure.INTERNET_FACING:
            factors.append(self._environmental_factors["network_exposure"][0])
        elif environment_context.network_exposure == NetworkExposure.INTERNAL:
            factors.append(self._environmental_factors["network_exposure"][1])
        
        # Security posture factors
        if environment_context.security_posture == SecurityPosture.HIGH:
            factors.append(self._environmental_factors["security_posture"][0])
        elif environment_context.security_posture == SecurityPosture.LOW:
            factors.append(self._environmental_factors["security_posture"][1])
        
        # Data sensitivity factors
        if environment_context.data_sensitivity in [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED]:
            factors.append(self._environmental_factors["data_sensitivity"][0])
        elif environment_context.data_sensitivity == DataSensitivity.PUBLIC:
            factors.append(self._environmental_factors["data_sensitivity"][1])
        
        # User privilege factors
        if environment_context.user_privileges == UserPrivileges.ADMIN:
            factors.append(self._environmental_factors["user_privileges"][0])
        elif environment_context.user_privileges == UserPrivileges.STANDARD:
            factors.append(self._environmental_factors["user_privileges"][1])
        
        return factors
    
    def _determine_likelihood_level(self, likelihood_score: float) -> LikelihoodLevel:
        """Determine likelihood level from numeric score."""
        if likelihood_score >= 0.8:
            return LikelihoodLevel.VERY_HIGH
        elif likelihood_score >= 0.6:
            return LikelihoodLevel.HIGH
        elif likelihood_score >= 0.4:
            return LikelihoodLevel.MEDIUM
        elif likelihood_score >= 0.2:
            return LikelihoodLevel.LOW
        else:
            return LikelihoodLevel.VERY_LOW
    
    def _assess_target_attractiveness(
        self,
        scenario: str,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> TargetAttractiveness:
        """Assess how attractive the target is to attackers."""
        attractiveness_score = 0
        
        # Data sensitivity contribution
        sensitivity_scores = {
            DataSensitivity.PUBLIC: 0,
            DataSensitivity.INTERNAL: 1,
            DataSensitivity.CONFIDENTIAL: 2,
            DataSensitivity.RESTRICTED: 3,
            DataSensitivity.TOP_SECRET: 4
        }
        attractiveness_score += sensitivity_scores.get(environment_context.data_sensitivity, 1)
        
        # Network exposure contribution
        if environment_context.network_exposure in [NetworkExposure.INTERNET_FACING, NetworkExposure.PUBLIC]:
            attractiveness_score += 2
        
        # External access contribution
        if tool_capabilities.external_access:
            attractiveness_score += 1
        
        # Privilege requirements (lower = more attractive)
        if not tool_capabilities.requires_privileges:
            attractiveness_score += 1
        
        # Convert to attractiveness level
        if attractiveness_score >= 6:
            return TargetAttractiveness.VERY_HIGH
        elif attractiveness_score >= 4:
            return TargetAttractiveness.HIGH
        elif attractiveness_score >= 2:
            return TargetAttractiveness.MEDIUM
        else:
            return TargetAttractiveness.LOW
    
    def _determine_attack_window(self, scenario: str, threat_actors: List[ThreatActorType]) -> AttackWindow:
        """Determine typical attack window for scenario and actors."""
        # Nation-state actors typically have longer attack windows
        if ThreatActorType.NATION_STATE in threat_actors:
            return AttackWindow.LONG_TERM
        
        # Cybercriminals typically work in medium-term windows
        if ThreatActorType.CYBERCRIMINAL in threat_actors:
            return AttackWindow.MEDIUM_TERM
        
        # Opportunistic scenarios are typically short-term
        if scenario in ["network_reconnaissance", "credential_theft"]:
            return AttackWindow.SHORT_TERM
        
        # Complex scenarios require more time
        if scenario in ["privilege_escalation", "system_compromise"]:
            return AttackWindow.MEDIUM_TERM
        
        return AttackWindow.SHORT_TERM
    
    def _calculate_likelihood_confidence(
        self, tool_capabilities: ToolCapabilities, env_factors: List[EnvironmentalFactor], vector_count: int
    ) -> float:
        """Calculate confidence score for likelihood assessment."""
        base_confidence = 0.6
        
        # Increase confidence with more tool information
        if len(tool_capabilities.tool_functions) > 3:
            base_confidence += 0.1
        
        if tool_capabilities.risk_indicators:
            base_confidence += 0.1
        
        # Increase confidence with more environmental factors
        if len(env_factors) > 2:
            base_confidence += 0.1
        
        # Increase confidence with more attack vectors
        if vector_count > 1:
            base_confidence += 0.1
        
        return min(base_confidence, 0.9)  # Cap at 90%
    
    def _generate_assessment_rationale(
        self,
        scenario: str,
        base_likelihood: float,
        env_factors: List[EnvironmentalFactor],
        threat_actors: List[ThreatActorType]
    ) -> str:
        """Generate textual rationale for likelihood assessment."""
        rationale_parts = []
        
        # Base likelihood explanation
        if base_likelihood > 0.7:
            rationale_parts.append(f"High base likelihood for {scenario.replace('_', ' ')} scenario")
        elif base_likelihood > 0.4:
            rationale_parts.append(f"Moderate base likelihood for {scenario.replace('_', ' ')} scenario")
        else:
            rationale_parts.append(f"Low base likelihood for {scenario.replace('_', ' ')} scenario")
        
        # Environmental factor contributions
        positive_factors = [f for f in env_factors if f.impact_on_likelihood > 0]
        negative_factors = [f for f in env_factors if f.impact_on_likelihood < 0]
        
        if positive_factors:
            rationale_parts.append(f"Increased by {len(positive_factors)} risk-enhancing factors")
        
        if negative_factors:
            rationale_parts.append(f"Reduced by {len(negative_factors)} risk-mitigating factors")
        
        # Threat actor considerations
        if ThreatActorType.NATION_STATE in threat_actors:
            rationale_parts.append("Nation-state actors increase sophistication and persistence")
        elif ThreatActorType.CYBERCRIMINAL in threat_actors:
            rationale_parts.append("Criminal actors increase financial motivation")
        
        return ". ".join(rationale_parts) + "."
    
    def _identify_key_risk_factors(
        self,
        scenario: str,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[str]:
        """Identify key risk factors for the scenario."""
        risk_factors = []
        
        # Tool-based risk factors
        if tool_capabilities.external_access:
            risk_factors.append("External network access capability")
        
        if tool_capabilities.requires_privileges:
            risk_factors.append("Elevated privilege requirements")
        
        if len(tool_capabilities.risk_indicators) > 3:
            risk_factors.append("Multiple security risk indicators present")
        
        # Environment-based risk factors
        if environment_context.network_exposure in [NetworkExposure.INTERNET_FACING, NetworkExposure.PUBLIC]:
            risk_factors.append("Public network exposure")
        
        if environment_context.data_sensitivity in [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED]:
            risk_factors.append("High-value data present")
        
        if environment_context.security_posture == SecurityPosture.LOW:
            risk_factors.append("Weak security posture")
        
        # Scenario-specific risk factors
        scenario_risks = {
            "data_theft": ["Valuable data accessible", "Exfiltration channels available"],
            "remote_code_execution": ["Code execution capabilities", "Potential for system control"],
            "privilege_escalation": ["Access to privileged functions", "Potential for admin access"],
            "credential_theft": ["Authentication mechanisms present", "Credential storage accessible"]
        }
        
        if scenario in scenario_risks:
            risk_factors.extend(scenario_risks[scenario])
        
        return risk_factors[:8]  # Limit to top 8 risk factors
    
    def _calculate_mitigation_impact(self, scenario: str, environment_context: EnvironmentContext) -> float:
        """Calculate how much existing mitigations reduce likelihood."""
        mitigation_impact = 0.0
        
        # Strong security posture provides significant mitigation
        if environment_context.security_posture == SecurityPosture.HIGH:
            mitigation_impact += 0.3
        elif environment_context.security_posture == SecurityPosture.MEDIUM:
            mitigation_impact += 0.1
        
        # Internal network exposure reduces external attack likelihood
        if environment_context.network_exposure == NetworkExposure.INTERNAL:
            mitigation_impact += 0.2
        elif environment_context.network_exposure == NetworkExposure.ISOLATED:
            mitigation_impact += 0.4
        
        # Compliance requirements often include mitigating controls
        if len(environment_context.compliance_requirements) > 0:
            mitigation_impact += 0.1
        
        return min(mitigation_impact, 0.6)  # Cap at 60% mitigation
    
    def _identify_relevant_threat_actors(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[ThreatActorType]:
        """Identify threat actors relevant to the tool and environment."""
        relevant_actors = []
        
        # Always consider external attackers and insiders
        relevant_actors.extend([ThreatActorType.EXTERNAL_ATTACKER, ThreatActorType.INSIDER_THREAT])
        
        # High-value targets attract nation-state actors
        if (environment_context.data_sensitivity in [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED] or
            CapabilityCategory.CLOUD_SERVICES in tool_capabilities.capability_categories):
            relevant_actors.append(ThreatActorType.NATION_STATE)
        
        # Financial or database capabilities attract cybercriminals
        if (CapabilityCategory.DATABASE_ACCESS in tool_capabilities.capability_categories or
            CapabilityCategory.AUTHENTICATION in tool_capabilities.capability_categories):
            relevant_actors.append(ThreatActorType.CYBERCRIMINAL)
        
        # Public-facing systems attract hacktivists
        if environment_context.network_exposure in [NetworkExposure.INTERNET_FACING, NetworkExposure.PUBLIC]:
            relevant_actors.append(ThreatActorType.HACKTIVIST)
        
        return list(set(relevant_actors))  # Remove duplicates
    
    def _create_detailed_threat_actor_profile(
        self,
        actor_type: ThreatActorType,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> ThreatActorProfile:
        """Create a detailed threat actor profile."""
        template = self._threat_actor_profiles[actor_type]
        
        # Create activity patterns based on actor type
        activity_patterns = {
            "active_hours": "business_hours" if actor_type == ThreatActorType.INSIDER_THREAT else "24/7",
            "attack_duration": template.get("attack_duration", "days_to_weeks"),
            "preferred_methods": template["methods"][:3]  # Top 3 methods
        }
        
        # Determine geographical focus
        geo_focus = ["global"] if actor_type == ThreatActorType.NATION_STATE else ["regional"]
        
        profile = ThreatActorProfile(
            actor_type=actor_type,
            sophistication=template["sophistication"],
            primary_motivations=template["motivations"][:2],  # Top 2 motivations
            capabilities=template["capabilities"],
            resources=template["resources"],
            typical_targets=template["targets"],
            attack_methods=template["methods"],
            operational_security=template["operational_security"],
            persistence_level=template["persistence"],
            risk_tolerance=template["risk_tolerance"],
            stealth_preference=template["stealth_preference"],
            activity_patterns=activity_patterns,
            geographical_focus=geo_focus,
            success_rate=template["success_rate"],
            detection_rate=template["detection_rate"]
        )
        
        return profile
    
    def _calculate_actor_threat_score(self, profile: ThreatActorProfile) -> float:
        """Calculate a threat score for an actor profile."""
        # Combine various factors into a single threat score
        sophistication_weight = {
            ThreatActorSophistication.SCRIPT_KIDDIE: 0.2,
            ThreatActorSophistication.OPPORTUNISTIC: 0.4,
            ThreatActorSophistication.SKILLED: 0.7,
            ThreatActorSophistication.EXPERT: 0.9,
            ThreatActorSophistication.NATION_STATE: 1.0
        }
        
        base_score = sophistication_weight[profile.sophistication]
        
        # Adjust for other factors
        score = (base_score * 0.4 + 
                profile.success_rate * 0.3 +
                profile.persistence_level * 0.2 +
                (1.0 - profile.detection_rate) * 0.1)  # Lower detection rate = higher threat
        
        return score
    
    def _calculate_actor_capability_adjustment(
        self, threat_actor: ThreatActorType, attack_vector: AttackVector
    ) -> float:
        """Calculate adjustment factor based on threat actor capabilities."""
        if threat_actor not in self._threat_actor_profiles:
            return 1.0
        
        profile = self._threat_actor_profiles[threat_actor]
        sophistication = profile["sophistication"]
        
        # Get sophistication multiplier
        base_multiplier = self._complexity_models["actor_sophistication"][sophistication.value]
        
        # Adjust based on attack complexity
        complexity_adjustment = {
            AttackComplexity.LOW: 1.2,
            AttackComplexity.MEDIUM: 1.0,
            AttackComplexity.HIGH: 0.8
        }
        
        return base_multiplier * complexity_adjustment[attack_vector.complexity]
    
    def _calculate_environmental_adjustment(
        self, attack_vector: AttackVector, environment_context: EnvironmentContext
    ) -> float:
        """Calculate environmental adjustment factor."""
        adjustment = 1.0
        
        # Network exposure adjustments
        if environment_context.network_exposure == NetworkExposure.INTERNET_FACING:
            adjustment *= 1.3
        elif environment_context.network_exposure == NetworkExposure.INTERNAL:
            adjustment *= 0.8
        elif environment_context.network_exposure == NetworkExposure.ISOLATED:
            adjustment *= 0.5
        
        # Security posture adjustments
        if environment_context.security_posture == SecurityPosture.HIGH:
            adjustment *= 0.6
        elif environment_context.security_posture == SecurityPosture.LOW:
            adjustment *= 1.4
        
        return adjustment
    
    def _calculate_tool_specific_adjustment(
        self, attack_vector: AttackVector, tool_capabilities: ToolCapabilities
    ) -> float:
        """Calculate tool-specific adjustment factor."""
        adjustment = 1.0
        
        # Risk score adjustment
        adjustment *= (0.5 + tool_capabilities.risk_score)
        
        # External access adjustment
        if tool_capabilities.external_access and CapabilityCategory.NETWORK_ACCESS in attack_vector.required_capabilities:
            adjustment *= 1.2
        
        # Privilege requirement adjustment
        if tool_capabilities.requires_privileges and attack_vector.required_access in [AccessLevel.ADMIN, AccessLevel.ROOT]:
            adjustment *= 0.7  # Harder to achieve with privilege requirements
        
        return adjustment
    
    def _calculate_overall_risk_level(self, assessments: List[LikelihoodAssessment]) -> ThreatLevel:
        """Calculate overall risk level from all assessments."""
        if not assessments:
            return ThreatLevel.LOW
        
        # Count high-likelihood assessments
        very_high_count = sum(1 for a in assessments if a.likelihood_level == LikelihoodLevel.VERY_HIGH)
        high_count = sum(1 for a in assessments if a.likelihood_level == LikelihoodLevel.HIGH)
        
        # Calculate average likelihood
        avg_likelihood = sum(a.adjusted_likelihood for a in assessments) / len(assessments)
        
        if very_high_count > 2 or avg_likelihood > 0.8:
            return ThreatLevel.CRITICAL
        elif very_high_count > 0 or high_count > 2 or avg_likelihood > 0.6:
            return ThreatLevel.HIGH
        elif high_count > 0 or avg_likelihood > 0.4:
            return ThreatLevel.MEDIUM
        elif avg_likelihood > 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MINIMAL
    
    def _identify_high_likelihood_threats(self, assessments: List[LikelihoodAssessment]) -> List[str]:
        """Identify threats with high likelihood."""
        high_likelihood = []
        
        for assessment in assessments:
            if assessment.likelihood_level in [LikelihoodLevel.HIGH, LikelihoodLevel.VERY_HIGH]:
                threat_name = assessment.threat_id.split('_')[0].replace('_', ' ').title()
                high_likelihood.append(threat_name)
        
        return high_likelihood[:5]  # Return top 5
    
    def _generate_monitoring_recommendations(self, assessments: List[LikelihoodAssessment]) -> List[str]:
        """Generate monitoring recommendations based on assessments."""
        recommendations = set()
        
        for assessment in assessments:
            if assessment.likelihood_level in [LikelihoodLevel.HIGH, LikelihoodLevel.VERY_HIGH]:
                # Add monitoring for attack vectors
                for vector in assessment.attack_vectors:
                    for indicator in vector.indicators:
                        recommendations.add(f"Monitor for {indicator}")
                
                # Add scenario-specific monitoring
                scenario = assessment.threat_id.split('_')[0]
                if scenario == "credential":
                    recommendations.add("Implement failed login monitoring")
                elif scenario == "data":
                    recommendations.add("Monitor large data transfers")
                elif scenario == "network":
                    recommendations.add("Enable network traffic analysis")
        
        return sorted(list(recommendations))[:10]  # Return top 10
    
    def _generate_early_warning_indicators(self, assessments: List[LikelihoodAssessment]) -> List[str]:
        """Generate early warning indicators."""
        indicators = set()
        
        # Collect indicators from high-likelihood assessments
        for assessment in assessments:
            if assessment.likelihood_level in [LikelihoodLevel.HIGH, LikelihoodLevel.VERY_HIGH]:
                for vector in assessment.attack_vectors:
                    indicators.update(vector.indicators)
        
        # Add general early warning indicators
        general_indicators = [
            "Unusual authentication patterns",
            "Unexpected network connections",
            "Abnormal system resource usage",
            "Suspicious file system activity",
            "Unusual process execution"
        ]
        
        indicators.update(general_indicators)
        
        return sorted(list(indicators))[:15]  # Return top 15
    
    def _create_assessment_summary(
        self, assessments: List[LikelihoodAssessment], overall_risk: ThreatLevel
    ) -> str:
        """Create a summary of the likelihood assessment."""
        high_likelihood_count = sum(
            1 for a in assessments 
            if a.likelihood_level in [LikelihoodLevel.HIGH, LikelihoodLevel.VERY_HIGH]
        )
        
        medium_likelihood_count = sum(
            1 for a in assessments 
            if a.likelihood_level == LikelihoodLevel.MEDIUM
        )
        
        summary_parts = [
            f"Assessed {len(assessments)} threat scenarios",
            f"Overall risk level: {overall_risk.value.upper()}",
            f"{high_likelihood_count} high-likelihood threats identified",
            f"{medium_likelihood_count} medium-likelihood threats identified"
        ]
        
        if high_likelihood_count > 0:
            summary_parts.append("Immediate attention recommended for high-likelihood threats")
        
        return ". ".join(summary_parts) + "." 