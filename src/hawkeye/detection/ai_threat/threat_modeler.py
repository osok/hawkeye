"""
Enhanced Threat Modeling Component

This module implements comprehensive threat modeling capabilities including STRIDE-based analysis,
attack tree generation, and threat actor profiling for MCP servers and their tools.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import json

from .models import (
    ToolCapabilities, EnvironmentContext, ThreatActorType, ThreatLevel,
    SeverityLevel, DifficultyLevel, AccessLevel, CapabilityCategory,
    AttackVector, BusinessImpact, AttackChain, ChainLink, AbuseScenario
)


class STRIDECategory(Enum):
    """STRIDE threat categories."""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class AttackTreeNodeType(Enum):
    """Types of nodes in attack trees."""
    GOAL = "goal"
    AND_GATE = "and_gate"
    OR_GATE = "or_gate"
    LEAF = "leaf"


class ThreatActorCapability(Enum):
    """Threat actor capability levels."""
    SCRIPT_KIDDIE = "script_kiddie"
    AMATEUR = "amateur"
    PROFESSIONAL = "professional"
    EXPERT = "expert"
    NATION_STATE = "nation_state"


class ThreatActorMotivation(Enum):
    """Threat actor motivations."""
    FINANCIAL_GAIN = "financial_gain"
    ESPIONAGE = "espionage"
    SABOTAGE = "sabotage"
    ACTIVISM = "activism"
    CURIOSITY = "curiosity"
    REVENGE = "revenge"
    CHAOS = "chaos"


@dataclass
class STRIDEThreat:
    """Represents a threat categorized by STRIDE."""
    category: STRIDECategory
    threat_name: str
    description: str
    affected_assets: List[str]
    attack_vectors: List[str]
    impact: str
    likelihood: float
    severity: SeverityLevel
    mitigations: List[str] = field(default_factory=list)


@dataclass
class AttackTreeNode:
    """Represents a node in an attack tree."""
    node_id: str
    node_type: AttackTreeNodeType
    description: str
    parent_id: Optional[str] = None
    children: List['AttackTreeNode'] = field(default_factory=list)
    probability: float = 0.0
    cost: float = 0.0
    difficulty: DifficultyLevel = DifficultyLevel.MEDIUM
    required_skills: List[str] = field(default_factory=list)
    required_resources: List[str] = field(default_factory=list)
    detection_likelihood: float = 0.5
    mitigation_options: List[str] = field(default_factory=list)


@dataclass
class AttackTree:
    """Represents a complete attack tree."""
    tree_id: str
    root_goal: str
    target_asset: str
    threat_actor: ThreatActorType
    root_node: AttackTreeNode
    all_nodes: List[AttackTreeNode] = field(default_factory=list)
    critical_paths: List[List[str]] = field(default_factory=list)
    overall_probability: float = 0.0
    estimated_cost: float = 0.0
    time_to_compromise: int = 0  # Hours


@dataclass
class ThreatActorProfile:
    """Comprehensive threat actor profile."""
    actor_type: ThreatActorType
    capability_level: ThreatActorCapability
    primary_motivation: ThreatActorMotivation
    secondary_motivations: List[ThreatActorMotivation] = field(default_factory=list)
    preferred_attack_methods: List[str] = field(default_factory=list)
    typical_resources: List[str] = field(default_factory=list)
    skill_areas: List[str] = field(default_factory=list)
    risk_tolerance: float = 0.5  # 0.0 (risk-averse) to 1.0 (high-risk)
    persistence_level: float = 0.5  # How likely to continue after setbacks
    stealth_preference: float = 0.5  # Preference for staying undetected
    target_preferences: List[str] = field(default_factory=list)
    geographical_focus: List[str] = field(default_factory=list)
    active_hours: str = "24/7"
    typical_attack_duration: str = "weeks"


@dataclass
class ThreatModelingResult:
    """Complete threat modeling analysis result."""
    tool_name: str
    stride_analysis: List[STRIDEThreat]
    attack_trees: List[AttackTree]
    threat_actor_profiles: List[ThreatActorProfile]
    high_priority_threats: List[STRIDEThreat]
    recommended_countermeasures: List[str]
    overall_risk_rating: ThreatLevel
    confidence_score: float
    analysis_timestamp: str


class ThreatModeler:
    """
    Enhanced threat modeling engine with STRIDE analysis, attack tree generation,
    and threat actor profiling capabilities.
    """
    
    def __init__(self):
        """Initialize the threat modeler."""
        self.logger = logging.getLogger(__name__)
        self._stride_patterns = self._initialize_stride_patterns()
        self._threat_actor_templates = self._initialize_threat_actor_templates()
        self._attack_patterns = self._initialize_attack_patterns()
    
    def perform_stride_analysis(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[STRIDEThreat]:
        """
        Perform comprehensive STRIDE analysis on MCP tool capabilities.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            
        Returns:
            List of identified STRIDE threats
        """
        self.logger.info(f"Performing STRIDE analysis for {tool_capabilities.tool_name}")
        
        stride_threats = []
        
        # Analyze each STRIDE category
        for category in STRIDECategory:
            threats = self._analyze_stride_category(
                category, tool_capabilities, environment_context
            )
            stride_threats.extend(threats)
        
        # Prioritize threats by severity and likelihood
        stride_threats.sort(key=lambda t: (t.severity.value, t.likelihood), reverse=True)
        
        self.logger.info(f"Identified {len(stride_threats)} STRIDE threats")
        return stride_threats
    
    def generate_attack_trees(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext,
        target_goals: Optional[List[str]] = None
    ) -> List[AttackTree]:
        """
        Generate attack trees for potential compromise scenarios.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            target_goals: Specific attack goals to model (optional)
            
        Returns:
            List of generated attack trees
        """
        self.logger.info(f"Generating attack trees for {tool_capabilities.tool_name}")
        
        if not target_goals:
            target_goals = self._identify_attack_goals(tool_capabilities)
        
        attack_trees = []
        
        for goal in target_goals:
            tree = self._build_attack_tree(
                goal, tool_capabilities, environment_context
            )
            if tree:
                attack_trees.append(tree)
        
        self.logger.info(f"Generated {len(attack_trees)} attack trees")
        return attack_trees
    
    def profile_threat_actors(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[ThreatActorProfile]:
        """
        Generate threat actor profiles relevant to the MCP tool.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            
        Returns:
            List of relevant threat actor profiles
        """
        self.logger.info(f"Profiling threat actors for {tool_capabilities.tool_name}")
        
        relevant_actors = self._identify_relevant_threat_actors(
            tool_capabilities, environment_context
        )
        
        profiles = []
        for actor_type in relevant_actors:
            profile = self._create_threat_actor_profile(
                actor_type, tool_capabilities, environment_context
            )
            profiles.append(profile)
        
        self.logger.info(f"Created {len(profiles)} threat actor profiles")
        return profiles
    
    def conduct_comprehensive_analysis(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> ThreatModelingResult:
        """
        Conduct comprehensive threat modeling analysis.
        
        Args:
            tool_capabilities: Analyzed tool capabilities
            environment_context: Deployment environment context
            
        Returns:
            Complete threat modeling result
        """
        self.logger.info(f"Starting comprehensive threat modeling for {tool_capabilities.tool_name}")
        
        # Perform STRIDE analysis
        stride_threats = self.perform_stride_analysis(tool_capabilities, environment_context)
        
        # Generate attack trees
        attack_trees = self.generate_attack_trees(tool_capabilities, environment_context)
        
        # Profile threat actors
        threat_actors = self.profile_threat_actors(tool_capabilities, environment_context)
        
        # Identify high-priority threats
        high_priority = [t for t in stride_threats if t.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]]
        
        # Generate countermeasures
        countermeasures = self._generate_countermeasures(stride_threats, attack_trees)
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(stride_threats, attack_trees)
        
        # Calculate confidence score
        confidence = self._calculate_confidence_score(tool_capabilities, stride_threats)
        
        result = ThreatModelingResult(
            tool_name=tool_capabilities.tool_name,
            stride_analysis=stride_threats,
            attack_trees=attack_trees,
            threat_actor_profiles=threat_actors,
            high_priority_threats=high_priority,
            recommended_countermeasures=countermeasures,
            overall_risk_rating=overall_risk,
            confidence_score=confidence,
            analysis_timestamp=str(datetime.now())
        )
        
        self.logger.info(f"Completed threat modeling analysis with {len(stride_threats)} threats")
        return result
    
    def _initialize_stride_patterns(self) -> Dict[STRIDECategory, Dict[str, Any]]:
        """Initialize STRIDE analysis patterns."""
        return {
            STRIDECategory.SPOOFING: {
                "indicators": ["authentication", "identity", "credentials", "impersonation"],
                "capabilities": [CapabilityCategory.AUTHENTICATION, CapabilityCategory.EXTERNAL_INTEGRATION],
                "descriptions": {
                    "default": "Potential for identity spoofing through tool capabilities",
                    "auth": "Authentication bypass or credential theft capabilities",
                    "api": "API impersonation or service spoofing potential"
                }
            },
            STRIDECategory.TAMPERING: {
                "indicators": ["modify", "write", "update", "delete", "alter"],
                "capabilities": [CapabilityCategory.FILE_SYSTEM, CapabilityCategory.DATABASE_ACCESS],
                "descriptions": {
                    "default": "Data or system tampering through tool capabilities",
                    "file": "File system modification and data tampering",
                    "data": "Database or data structure tampering capabilities"
                }
            },
            STRIDECategory.REPUDIATION: {
                "indicators": ["logging", "audit", "tracking", "non-repudiation"],
                "capabilities": [CapabilityCategory.SYSTEM_INFORMATION, CapabilityCategory.FILE_SYSTEM],
                "descriptions": {
                    "default": "Actions that could deny or obscure accountability",
                    "log": "Log tampering or audit trail manipulation",
                    "trace": "Activity tracing evasion capabilities"
                }
            },
            STRIDECategory.INFORMATION_DISCLOSURE: {
                "indicators": ["read", "access", "retrieve", "export", "disclosure"],
                "capabilities": [CapabilityCategory.FILE_SYSTEM, CapabilityCategory.DATABASE_ACCESS, 
                              CapabilityCategory.SYSTEM_INFORMATION],
                "descriptions": {
                    "default": "Unauthorized information access or disclosure",
                    "file": "File system data access and exfiltration",
                    "system": "System information gathering and reconnaissance"
                }
            },
            STRIDECategory.DENIAL_OF_SERVICE: {
                "indicators": ["resource", "performance", "availability", "flooding"],
                "capabilities": [CapabilityCategory.NETWORK_ACCESS, CapabilityCategory.CODE_EXECUTION],
                "descriptions": {
                    "default": "Service disruption or resource exhaustion attacks",
                    "network": "Network-based denial of service capabilities",
                    "resource": "Resource exhaustion and performance degradation"
                }
            },
            STRIDECategory.ELEVATION_OF_PRIVILEGE: {
                "indicators": ["privilege", "admin", "root", "escalation", "sudo"],
                "capabilities": [CapabilityCategory.CODE_EXECUTION, CapabilityCategory.SYSTEM_INFORMATION],
                "descriptions": {
                    "default": "Privilege escalation through tool abuse",
                    "exec": "Code execution leading to privilege escalation",
                    "system": "System-level access and privilege abuse"
                }
            }
        }
    
    def _initialize_threat_actor_templates(self) -> Dict[ThreatActorType, Dict[str, Any]]:
        """Initialize threat actor profile templates."""
        return {
            ThreatActorType.INSIDER_THREAT: {
                "capability_level": ThreatActorCapability.PROFESSIONAL,
                "motivations": [ThreatActorMotivation.REVENGE, ThreatActorMotivation.FINANCIAL_GAIN],
                "methods": ["privilege_abuse", "data_exfiltration", "system_sabotage"],
                "resources": ["legitimate_access", "internal_knowledge", "trust_relationships"],
                "skills": ["domain_expertise", "system_knowledge", "social_engineering"],
                "risk_tolerance": 0.3,
                "persistence": 0.7,
                "stealth": 0.8
            },
            ThreatActorType.EXTERNAL_ATTACKER: {
                "capability_level": ThreatActorCapability.AMATEUR,
                "motivations": [ThreatActorMotivation.FINANCIAL_GAIN, ThreatActorMotivation.CURIOSITY],
                "methods": ["exploitation", "social_engineering", "brute_force"],
                "resources": ["public_exploits", "automated_tools", "botnets"],
                "skills": ["exploitation", "reconnaissance", "persistence"],
                "risk_tolerance": 0.6,
                "persistence": 0.5,
                "stealth": 0.6
            },
            ThreatActorType.NATION_STATE: {
                "capability_level": ThreatActorCapability.EXPERT,
                "motivations": [ThreatActorMotivation.ESPIONAGE, ThreatActorMotivation.SABOTAGE],
                "methods": ["advanced_persistent_threat", "zero_day_exploits", "supply_chain"],
                "resources": ["unlimited_budget", "custom_malware", "insider_recruitment"],
                "skills": ["zero_day_research", "advanced_tradecraft", "long_term_operations"],
                "risk_tolerance": 0.2,
                "persistence": 0.9,
                "stealth": 0.9
            },
            ThreatActorType.CYBERCRIMINAL: {
                "capability_level": ThreatActorCapability.PROFESSIONAL,
                "motivations": [ThreatActorMotivation.FINANCIAL_GAIN],
                "methods": ["ransomware", "fraud", "cryptocurrency_theft"],
                "resources": ["criminal_networks", "as_a_service_tools", "money_laundering"],
                "skills": ["monetization", "evasion", "scalable_attacks"],
                "risk_tolerance": 0.7,
                "persistence": 0.6,
                "stealth": 0.7
            },
            ThreatActorType.HACKTIVIST: {
                "capability_level": ThreatActorCapability.AMATEUR,
                "motivations": [ThreatActorMotivation.ACTIVISM, ThreatActorMotivation.CHAOS],
                "methods": ["defacement", "ddos", "information_disclosure"],
                "resources": ["volunteer_networks", "leaked_tools", "public_platforms"],
                "skills": ["publicity", "coordination", "simple_attacks"],
                "risk_tolerance": 0.8,
                "persistence": 0.4,
                "stealth": 0.3
            }
        }
    
    def _initialize_attack_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize common attack patterns."""
        return {
            "reconnaissance": {
                "description": "Information gathering and target analysis",
                "techniques": ["passive_reconnaissance", "active_scanning", "social_engineering"],
                "required_capabilities": [CapabilityCategory.SYSTEM_INFORMATION, CapabilityCategory.NETWORK_ACCESS],
                "difficulty": DifficultyLevel.LOW,
                "detection_likelihood": 0.3
            },
            "initial_access": {
                "description": "Gaining initial foothold in target environment",
                "techniques": ["exploitation", "credential_theft", "social_engineering"],
                "required_capabilities": [CapabilityCategory.CODE_EXECUTION, CapabilityCategory.AUTHENTICATION],
                "difficulty": DifficultyLevel.MEDIUM,
                "detection_likelihood": 0.5
            },
            "persistence": {
                "description": "Maintaining access to compromised systems",
                "techniques": ["backdoors", "scheduled_tasks", "service_installation"],
                "required_capabilities": [CapabilityCategory.CODE_EXECUTION, CapabilityCategory.FILE_SYSTEM],
                "difficulty": DifficultyLevel.MEDIUM,
                "detection_likelihood": 0.4
            },
            "privilege_escalation": {
                "description": "Gaining higher-level permissions",
                "techniques": ["exploit_vulnerabilities", "credential_theft", "abuse_misconfigurations"],
                "required_capabilities": [CapabilityCategory.CODE_EXECUTION, CapabilityCategory.SYSTEM_INFORMATION],
                "difficulty": DifficultyLevel.HIGH,
                "detection_likelihood": 0.6
            },
            "lateral_movement": {
                "description": "Moving through the network to other systems",
                "techniques": ["credential_reuse", "remote_services", "shared_resources"],
                "required_capabilities": [CapabilityCategory.NETWORK_ACCESS, CapabilityCategory.AUTHENTICATION],
                "difficulty": DifficultyLevel.MEDIUM,
                "detection_likelihood": 0.5
            },
            "exfiltration": {
                "description": "Stealing and removing sensitive data",
                "techniques": ["data_compression", "encrypted_channels", "steganography"],
                "required_capabilities": [CapabilityCategory.FILE_SYSTEM, CapabilityCategory.NETWORK_ACCESS],
                "difficulty": DifficultyLevel.MEDIUM,
                "detection_likelihood": 0.4
            }
        }
    
    def _analyze_stride_category(
        self,
        category: STRIDECategory,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[STRIDEThreat]:
        """Analyze a specific STRIDE category for threats."""
        threats = []
        pattern = self._stride_patterns[category]
        
        # Check if tool capabilities match STRIDE category indicators
        matching_capabilities = []
        for cap_category in tool_capabilities.capability_categories:
            if cap_category in pattern["capabilities"]:
                matching_capabilities.append(cap_category)
        
        if not matching_capabilities:
            return threats
        
        # Generate threats based on matching capabilities
        for cap_category in matching_capabilities:
            threat = self._create_stride_threat(
                category, cap_category, tool_capabilities, environment_context
            )
            if threat:
                threats.append(threat)
        
        return threats
    
    def _create_stride_threat(
        self,
        stride_category: STRIDECategory,
        capability_category: CapabilityCategory,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> Optional[STRIDEThreat]:
        """Create a specific STRIDE threat."""
        pattern = self._stride_patterns[stride_category]
        
        # Determine threat name and description
        threat_name = f"{stride_category.value.replace('_', ' ').title()} via {tool_capabilities.tool_name}"
        
        description_key = "default"
        if capability_category == CapabilityCategory.AUTHENTICATION:
            description_key = "auth"
        elif capability_category == CapabilityCategory.FILE_SYSTEM:
            description_key = "file"
        elif capability_category == CapabilityCategory.DATABASE_ACCESS:
            description_key = "data"
        elif capability_category == CapabilityCategory.NETWORK_ACCESS:
            description_key = "network"
        elif capability_category == CapabilityCategory.CODE_EXECUTION:
            description_key = "exec"
        elif capability_category == CapabilityCategory.SYSTEM_INFORMATION:
            description_key = "system"
        
        description = pattern["descriptions"].get(description_key, pattern["descriptions"]["default"])
        description += f" through {tool_capabilities.tool_name} {capability_category.value} capabilities."
        
        # Determine affected assets
        affected_assets = self._identify_affected_assets(capability_category, environment_context)
        
        # Generate attack vectors
        attack_vectors = self._generate_attack_vectors_for_stride(
            stride_category, capability_category, tool_capabilities
        )
        
        # Calculate impact and likelihood
        impact = self._calculate_stride_impact(stride_category, environment_context)
        likelihood = self._calculate_stride_likelihood(
            tool_capabilities, capability_category, environment_context
        )
        
        # Determine severity
        severity = self._calculate_stride_severity(stride_category, likelihood, environment_context)
        
        # Generate mitigations
        mitigations = self._generate_stride_mitigations(stride_category, capability_category)
        
        return STRIDEThreat(
            category=stride_category,
            threat_name=threat_name,
            description=description,
            affected_assets=affected_assets,
            attack_vectors=attack_vectors,
            impact=impact,
            likelihood=likelihood,
            severity=severity,
            mitigations=mitigations
        )
    
    def _identify_attack_goals(self, tool_capabilities: ToolCapabilities) -> List[str]:
        """Identify potential attack goals based on tool capabilities."""
        goals = []
        
        capability_goal_mapping = {
            CapabilityCategory.FILE_SYSTEM: [
                "Data Exfiltration",
                "System Configuration Tampering",
                "Malware Installation"
            ],
            CapabilityCategory.NETWORK_ACCESS: [
                "Network Reconnaissance",
                "Lateral Movement",
                "Command and Control Communication"
            ],
            CapabilityCategory.CODE_EXECUTION: [
                "Remote Code Execution",
                "Privilege Escalation",
                "System Compromise"
            ],
            CapabilityCategory.DATABASE_ACCESS: [
                "Database Compromise",
                "Sensitive Data Access",
                "Data Manipulation"
            ],
            CapabilityCategory.AUTHENTICATION: [
                "Credential Theft",
                "Authentication Bypass",
                "Identity Spoofing"
            ],
            CapabilityCategory.CLOUD_SERVICES: [
                "Cloud Resource Abuse",
                "Service Hijacking",
                "Data Breach"
            ]
        }
        
        for capability in tool_capabilities.capability_categories:
            if capability in capability_goal_mapping:
                goals.extend(capability_goal_mapping[capability])
        
        # Remove duplicates while preserving order
        unique_goals = []
        for goal in goals:
            if goal not in unique_goals:
                unique_goals.append(goal)
        
        return unique_goals[:5]  # Limit to top 5 goals
    
    def _build_attack_tree(
        self,
        goal: str,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> Optional[AttackTree]:
        """Build an attack tree for a specific goal."""
        tree_id = f"tree_{goal.replace(' ', '_').lower()}_{tool_capabilities.tool_name}"
        
        # Create root node
        root_node = AttackTreeNode(
            node_id=f"{tree_id}_root",
            node_type=AttackTreeNodeType.GOAL,
            description=f"Achieve {goal} using {tool_capabilities.tool_name}",
            probability=0.0,
            cost=0.0,
            difficulty=DifficultyLevel.MEDIUM
        )
        
        # Build tree structure based on goal and capabilities
        self._populate_attack_tree_nodes(root_node, goal, tool_capabilities, environment_context)
        
        # Calculate probabilities and costs
        self._calculate_attack_tree_metrics(root_node)
        
        # Identify critical paths
        critical_paths = self._find_critical_paths(root_node)
        
        # Create attack tree
        attack_tree = AttackTree(
            tree_id=tree_id,
            root_goal=goal,
            target_asset=tool_capabilities.tool_name,
            threat_actor=ThreatActorType.EXTERNAL_ATTACKER,  # Default, can be refined
            root_node=root_node,
            all_nodes=[root_node],
            critical_paths=critical_paths,
            overall_probability=root_node.probability,
            estimated_cost=root_node.cost,
            time_to_compromise=self._estimate_time_to_compromise(root_node)
        )
        
        # Collect all nodes
        self._collect_all_nodes(root_node, attack_tree.all_nodes)
        
        return attack_tree
    
    def _populate_attack_tree_nodes(
        self,
        parent_node: AttackTreeNode,
        goal: str,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> None:
        """Populate attack tree with child nodes."""
        # This is a simplified implementation - a full version would have more sophisticated logic
        
        if "Data Exfiltration" in goal:
            # Create OR gate for different exfiltration methods
            or_node = AttackTreeNode(
                node_id=f"{parent_node.node_id}_exfil_methods",
                node_type=AttackTreeNodeType.OR_GATE,
                description="Choose exfiltration method",
                parent_id=parent_node.node_id,
                probability=0.8,
                difficulty=DifficultyLevel.MEDIUM
            )
            parent_node.children.append(or_node)
            
            # Add specific methods
            if CapabilityCategory.FILE_SYSTEM in tool_capabilities.capability_categories:
                file_node = AttackTreeNode(
                    node_id=f"{parent_node.node_id}_file_access",
                    node_type=AttackTreeNodeType.LEAF,
                    description="Access sensitive files directly",
                    parent_id=or_node.node_id,
                    probability=0.7,
                    cost=100.0,
                    difficulty=DifficultyLevel.LOW,
                    required_skills=["file_system_knowledge"],
                    detection_likelihood=0.4
                )
                or_node.children.append(file_node)
            
            if CapabilityCategory.NETWORK_ACCESS in tool_capabilities.capability_categories:
                network_node = AttackTreeNode(
                    node_id=f"{parent_node.node_id}_network_exfil",
                    node_type=AttackTreeNodeType.LEAF,
                    description="Exfiltrate via network channels",
                    parent_id=or_node.node_id,
                    probability=0.6,
                    cost=200.0,
                    difficulty=DifficultyLevel.MEDIUM,
                    required_skills=["network_protocols", "steganography"],
                    detection_likelihood=0.6
                )
                or_node.children.append(network_node)
        
        elif "Remote Code Execution" in goal:
            # Create AND gate for RCE prerequisites
            and_node = AttackTreeNode(
                node_id=f"{parent_node.node_id}_rce_prereq",
                node_type=AttackTreeNodeType.AND_GATE,
                description="Fulfill RCE prerequisites",
                parent_id=parent_node.node_id,
                probability=0.5,
                difficulty=DifficultyLevel.HIGH
            )
            parent_node.children.append(and_node)
            
            # Add prerequisites
            access_node = AttackTreeNode(
                node_id=f"{parent_node.node_id}_gain_access",
                node_type=AttackTreeNodeType.LEAF,
                description="Gain initial access to system",
                parent_id=and_node.node_id,
                probability=0.6,
                cost=500.0,
                difficulty=DifficultyLevel.MEDIUM,
                required_skills=["exploitation", "social_engineering"],
                detection_likelihood=0.7
            )
            and_node.children.append(access_node)
            
            if CapabilityCategory.CODE_EXECUTION in tool_capabilities.capability_categories:
                exploit_node = AttackTreeNode(
                    node_id=f"{parent_node.node_id}_exploit_tool",
                    node_type=AttackTreeNodeType.LEAF,
                    description="Exploit tool for code execution",
                    parent_id=and_node.node_id,
                    probability=0.8,
                    cost=300.0,
                    difficulty=DifficultyLevel.MEDIUM,
                    required_skills=["reverse_engineering", "exploit_development"],
                    detection_likelihood=0.5
                )
                and_node.children.append(exploit_node)
        
        # Add more goal-specific logic as needed
    
    def _calculate_attack_tree_metrics(self, node: AttackTreeNode) -> None:
        """Calculate probability and cost metrics for attack tree nodes."""
        if not node.children:
            # Leaf node - metrics already set
            return
        
        # Calculate metrics for children first
        for child in node.children:
            self._calculate_attack_tree_metrics(child)
        
        # Calculate this node's metrics based on type
        if node.node_type == AttackTreeNodeType.AND_GATE:
            # All children must succeed
            node.probability = 1.0
            node.cost = 0.0
            for child in node.children:
                node.probability *= child.probability
                node.cost += child.cost
        
        elif node.node_type == AttackTreeNodeType.OR_GATE:
            # At least one child must succeed (take the best option)
            if node.children:
                best_child = max(node.children, key=lambda c: c.probability)
                node.probability = best_child.probability
                node.cost = best_child.cost
        
        elif node.node_type == AttackTreeNodeType.GOAL:
            # Goal node takes the probability of its primary path
            if node.children:
                node.probability = node.children[0].probability
                node.cost = node.children[0].cost
    
    def _find_critical_paths(self, root_node: AttackTreeNode) -> List[List[str]]:
        """Find critical attack paths through the tree."""
        critical_paths = []
        
        def traverse_path(node: AttackTreeNode, current_path: List[str]) -> None:
            current_path.append(node.node_id)
            
            if not node.children:
                # Leaf node - complete path
                critical_paths.append(current_path.copy())
            else:
                # Continue traversal
                for child in node.children:
                    traverse_path(child, current_path)
            
            current_path.pop()
        
        traverse_path(root_node, [])
        
        # Sort by probability (descending) and return top paths
        return critical_paths[:3]  # Return top 3 critical paths
    
    def _identify_relevant_threat_actors(
        self,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[ThreatActorType]:
        """Identify threat actors relevant to the tool and environment."""
        relevant_actors = []
        
        # Always consider external attackers and insiders
        relevant_actors.extend([ThreatActorType.EXTERNAL_ATTACKER, ThreatActorType.INSIDER_THREAT])
        
        # Add actors based on capabilities and environment
        if (CapabilityCategory.CLOUD_SERVICES in tool_capabilities.capability_categories or
            environment_context.data_sensitivity.value in ["confidential", "restricted"]):
            relevant_actors.append(ThreatActorType.NATION_STATE)
        
        if (CapabilityCategory.AUTHENTICATION in tool_capabilities.capability_categories or
            CapabilityCategory.DATABASE_ACCESS in tool_capabilities.capability_categories):
            relevant_actors.append(ThreatActorType.CYBERCRIMINAL)
        
        if (environment_context.network_exposure.value in ["internet_facing", "public"] and
            tool_capabilities.external_access):
            relevant_actors.append(ThreatActorType.HACKTIVIST)
        
        return list(set(relevant_actors))  # Remove duplicates
    
    def _create_threat_actor_profile(
        self,
        actor_type: ThreatActorType,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> ThreatActorProfile:
        """Create a detailed threat actor profile."""
        template = self._threat_actor_templates[actor_type]
        
        # Customize profile based on tool and environment
        target_preferences = self._determine_target_preferences(
            actor_type, tool_capabilities, environment_context
        )
        
        preferred_methods = template["methods"].copy()
        if CapabilityCategory.CODE_EXECUTION in tool_capabilities.capability_categories:
            preferred_methods.append("exploit_development")
        if CapabilityCategory.NETWORK_ACCESS in tool_capabilities.capability_categories:
            preferred_methods.append("network_exploitation")
        
        profile = ThreatActorProfile(
            actor_type=actor_type,
            capability_level=template["capability_level"],
            primary_motivation=template["motivations"][0],
            secondary_motivations=template["motivations"][1:],
            preferred_attack_methods=preferred_methods,
            typical_resources=template["resources"],
            skill_areas=template["skills"],
            risk_tolerance=template["risk_tolerance"],
            persistence_level=template["persistence"],
            stealth_preference=template["stealth"],
            target_preferences=target_preferences,
            geographical_focus=self._determine_geographical_focus(actor_type),
            active_hours=self._determine_active_hours(actor_type),
            typical_attack_duration=self._determine_attack_duration(actor_type)
        )
        
        return profile
    
    def _generate_countermeasures(
        self,
        stride_threats: List[STRIDEThreat],
        attack_trees: List[AttackTree]
    ) -> List[str]:
        """Generate comprehensive countermeasures."""
        countermeasures = set()
        
        # Add STRIDE-based countermeasures
        for threat in stride_threats:
            countermeasures.update(threat.mitigations)
        
        # Add attack tree-based countermeasures
        for tree in attack_trees:
            for node in tree.all_nodes:
                countermeasures.update(node.mitigation_options)
        
        # Add general security controls
        general_controls = [
            "Implement principle of least privilege",
            "Enable comprehensive logging and monitoring",
            "Regular security assessments and penetration testing",
            "Incident response plan development and testing",
            "Employee security awareness training",
            "Multi-factor authentication implementation",
            "Network segmentation and access controls",
            "Regular software updates and patch management"
        ]
        
        countermeasures.update(general_controls)
        
        return sorted(list(countermeasures))
    
    def _calculate_overall_risk(
        self,
        stride_threats: List[STRIDEThreat],
        attack_trees: List[AttackTree]
    ) -> ThreatLevel:
        """Calculate overall risk rating."""
        if not stride_threats and not attack_trees:
            return ThreatLevel.MINIMAL
        
        # Count threats by severity
        critical_count = sum(1 for t in stride_threats if t.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for t in stride_threats if t.severity == SeverityLevel.HIGH)
        medium_count = sum(1 for t in stride_threats if t.severity == SeverityLevel.MEDIUM)
        
        # Consider attack tree probabilities
        high_prob_trees = sum(1 for t in attack_trees if t.overall_probability > 0.7)
        
        if critical_count > 0 or high_prob_trees > 2:
            return ThreatLevel.CRITICAL
        elif high_count > 2 or (high_count > 0 and high_prob_trees > 0):
            return ThreatLevel.HIGH
        elif high_count > 0 or medium_count > 3:
            return ThreatLevel.MEDIUM
        elif medium_count > 0:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MINIMAL
    
    def _calculate_confidence_score(
        self,
        tool_capabilities: ToolCapabilities,
        stride_threats: List[STRIDEThreat]
    ) -> float:
        """Calculate confidence score for the analysis."""
        base_confidence = 0.7
        
        # Increase confidence with more tool information
        if tool_capabilities.tool_functions:
            base_confidence += 0.1
        
        if tool_capabilities.risk_indicators:
            base_confidence += 0.1
        
        # Consider threat count and severity
        if len(stride_threats) > 3:
            base_confidence += 0.05
        
        return min(base_confidence, 0.95)  # Cap at 95%
    
    # Helper methods for various calculations and determinations
    def _identify_affected_assets(
        self, capability_category: CapabilityCategory, environment_context: EnvironmentContext
    ) -> List[str]:
        """Identify assets affected by a capability category."""
        asset_mapping = {
            CapabilityCategory.FILE_SYSTEM: ["local_files", "configuration_files", "user_data"],
            CapabilityCategory.NETWORK_ACCESS: ["network_resources", "remote_services", "network_traffic"],
            CapabilityCategory.DATABASE_ACCESS: ["databases", "data_stores", "user_records"],
            CapabilityCategory.CODE_EXECUTION: ["system_integrity", "process_space", "memory"],
            CapabilityCategory.AUTHENTICATION: ["user_credentials", "access_tokens", "identity_systems"],
            CapabilityCategory.CLOUD_SERVICES: ["cloud_resources", "cloud_data", "service_configurations"]
        }
        return asset_mapping.get(capability_category, ["unknown_assets"])
    
    def _generate_attack_vectors_for_stride(
        self,
        stride_category: STRIDECategory,
        capability_category: CapabilityCategory,
        tool_capabilities: ToolCapabilities
    ) -> List[str]:
        """Generate attack vectors for a STRIDE category."""
        vectors = []
        
        if stride_category == STRIDECategory.SPOOFING:
            vectors = ["Identity impersonation", "Service spoofing", "Credential theft"]
        elif stride_category == STRIDECategory.TAMPERING:
            vectors = ["Data modification", "Configuration tampering", "File corruption"]
        elif stride_category == STRIDECategory.REPUDIATION:
            vectors = ["Log deletion", "Audit trail manipulation", "Action denial"]
        elif stride_category == STRIDECategory.INFORMATION_DISCLOSURE:
            vectors = ["Data exfiltration", "Unauthorized access", "Information leakage"]
        elif stride_category == STRIDECategory.DENIAL_OF_SERVICE:
            vectors = ["Resource exhaustion", "Service flooding", "System crash"]
        elif stride_category == STRIDECategory.ELEVATION_OF_PRIVILEGE:
            vectors = ["Privilege escalation", "Access control bypass", "Administrative access"]
        
        return vectors
    
    def _calculate_stride_impact(
        self, stride_category: STRIDECategory, environment_context: EnvironmentContext
    ) -> str:
        """Calculate impact description for STRIDE category."""
        base_impacts = {
            STRIDECategory.SPOOFING: "Identity compromise and unauthorized access",
            STRIDECategory.TAMPERING: "Data integrity loss and system corruption",
            STRIDECategory.REPUDIATION: "Loss of accountability and audit trail",
            STRIDECategory.INFORMATION_DISCLOSURE: "Confidentiality breach and data exposure",
            STRIDECategory.DENIAL_OF_SERVICE: "Service unavailability and business disruption",
            STRIDECategory.ELEVATION_OF_PRIVILEGE: "Unauthorized administrative access and control"
        }
        
        base_impact = base_impacts.get(stride_category, "Unknown impact")
        
        # Adjust based on environment sensitivity
        if environment_context.data_sensitivity.value in ["confidential", "restricted"]:
            base_impact += " with high-value data at risk"
        
        return base_impact
    
    def _calculate_stride_likelihood(
        self,
        tool_capabilities: ToolCapabilities,
        capability_category: CapabilityCategory,
        environment_context: EnvironmentContext
    ) -> float:
        """Calculate likelihood score for STRIDE threat."""
        base_likelihood = 0.3
        
        # Increase likelihood based on risk indicators
        if tool_capabilities.risk_indicators:
            base_likelihood += len(tool_capabilities.risk_indicators) * 0.1
        
        # Adjust for external access
        if tool_capabilities.external_access:
            base_likelihood += 0.2
        
        # Adjust for privilege requirements
        if tool_capabilities.requires_privileges:
            base_likelihood -= 0.1
        
        # Adjust for environment exposure
        if environment_context.network_exposure.value in ["internet_facing", "public"]:
            base_likelihood += 0.2
        
        return min(base_likelihood, 0.9)  # Cap at 90%
    
    def _calculate_stride_severity(
        self,
        stride_category: STRIDECategory,
        likelihood: float,
        environment_context: EnvironmentContext
    ) -> SeverityLevel:
        """Calculate severity level for STRIDE threat."""
        # Base severity by category
        category_severity = {
            STRIDECategory.SPOOFING: SeverityLevel.MEDIUM,
            STRIDECategory.TAMPERING: SeverityLevel.HIGH,
            STRIDECategory.REPUDIATION: SeverityLevel.LOW,
            STRIDECategory.INFORMATION_DISCLOSURE: SeverityLevel.HIGH,
            STRIDECategory.DENIAL_OF_SERVICE: SeverityLevel.MEDIUM,
            STRIDECategory.ELEVATION_OF_PRIVILEGE: SeverityLevel.CRITICAL
        }
        
        base_severity = category_severity.get(stride_category, SeverityLevel.MEDIUM)
        
        # Adjust based on likelihood and environment
        if likelihood > 0.7 and environment_context.data_sensitivity.value in ["confidential", "restricted"]:
            if base_severity == SeverityLevel.HIGH:
                return SeverityLevel.CRITICAL
            elif base_severity == SeverityLevel.MEDIUM:
                return SeverityLevel.HIGH
        
        return base_severity
    
    def _generate_stride_mitigations(
        self, stride_category: STRIDECategory, capability_category: CapabilityCategory
    ) -> List[str]:
        """Generate mitigations for STRIDE threats."""
        mitigation_mapping = {
            STRIDECategory.SPOOFING: [
                "Implement strong authentication mechanisms",
                "Use digital certificates and PKI",
                "Enable multi-factor authentication",
                "Implement identity verification procedures"
            ],
            STRIDECategory.TAMPERING: [
                "Implement data integrity checks",
                "Use digital signatures and checksums",
                "Enable file system monitoring",
                "Implement access controls and permissions"
            ],
            STRIDECategory.REPUDIATION: [
                "Enable comprehensive audit logging",
                "Implement non-repudiation mechanisms",
                "Use digital signatures for critical actions",
                "Maintain secure log storage and backup"
            ],
            STRIDECategory.INFORMATION_DISCLOSURE: [
                "Implement data encryption at rest and in transit",
                "Apply principle of least privilege",
                "Use data loss prevention (DLP) solutions",
                "Implement access controls and monitoring"
            ],
            STRIDECategory.DENIAL_OF_SERVICE: [
                "Implement rate limiting and throttling",
                "Use load balancing and redundancy",
                "Monitor resource usage and performance",
                "Implement DDoS protection measures"
            ],
            STRIDECategory.ELEVATION_OF_PRIVILEGE: [
                "Apply principle of least privilege",
                "Implement privilege escalation monitoring",
                "Use privilege access management (PAM)",
                "Regular privilege reviews and audits"
            ]
        }
        
        return mitigation_mapping.get(stride_category, ["Implement general security controls"])
    
    def _determine_target_preferences(
        self,
        actor_type: ThreatActorType,
        tool_capabilities: ToolCapabilities,
        environment_context: EnvironmentContext
    ) -> List[str]:
        """Determine target preferences for threat actor."""
        preferences = []
        
        if actor_type == ThreatActorType.NATION_STATE:
            preferences = ["government_systems", "critical_infrastructure", "intellectual_property"]
        elif actor_type == ThreatActorType.CYBERCRIMINAL:
            preferences = ["financial_systems", "payment_data", "personal_information"]
        elif actor_type == ThreatActorType.HACKTIVIST:
            preferences = ["public_facing_systems", "controversial_organizations", "media_attention"]
        elif actor_type == ThreatActorType.INSIDER_THREAT:
            preferences = ["accessible_systems", "valuable_data", "revenge_targets"]
        else:
            preferences = ["vulnerable_systems", "easy_targets", "learning_opportunities"]
        
        return preferences
    
    def _determine_geographical_focus(self, actor_type: ThreatActorType) -> List[str]:
        """Determine geographical focus for threat actor."""
        if actor_type == ThreatActorType.NATION_STATE:
            return ["adversary_nations", "geopolitical_targets"]
        elif actor_type == ThreatActorType.CYBERCRIMINAL:
            return ["global", "high_value_regions"]
        else:
            return ["regional", "opportunistic"]
    
    def _determine_active_hours(self, actor_type: ThreatActorType) -> str:
        """Determine active hours for threat actor."""
        if actor_type == ThreatActorType.NATION_STATE:
            return "business_hours_timezone"
        elif actor_type == ThreatActorType.INSIDER_THREAT:
            return "work_hours"
        else:
            return "24/7"
    
    def _determine_attack_duration(self, actor_type: ThreatActorType) -> str:
        """Determine typical attack duration for threat actor."""
        duration_mapping = {
            ThreatActorType.NATION_STATE: "months_to_years",
            ThreatActorType.CYBERCRIMINAL: "days_to_weeks",
            ThreatActorType.HACKTIVIST: "hours_to_days",
            ThreatActorType.INSIDER_THREAT: "weeks_to_months",
            ThreatActorType.EXTERNAL_ATTACKER: "hours_to_days"
        }
        return duration_mapping.get(actor_type, "days")
    
    def _estimate_time_to_compromise(self, root_node: AttackTreeNode) -> int:
        """Estimate time to compromise in hours."""
        # This is a simplified estimation based on node difficulty
        base_time = 8  # 8 hours base
        
        def calculate_node_time(node: AttackTreeNode) -> int:
            if node.difficulty == DifficultyLevel.LOW:
                time = 2
            elif node.difficulty == DifficultyLevel.MEDIUM:
                time = 8
            else:  # HIGH
                time = 24
            
            if node.children:
                if node.node_type == AttackTreeNodeType.AND_GATE:
                    # Sum all children times
                    child_time = sum(calculate_node_time(child) for child in node.children)
                else:  # OR_GATE or GOAL
                    # Take minimum child time (best path)
                    child_time = min(calculate_node_time(child) for child in node.children) if node.children else 0
                return time + child_time
            return time
        
        return calculate_node_time(root_node)
    
    def _collect_all_nodes(self, node: AttackTreeNode, all_nodes: List[AttackTreeNode]) -> None:
        """Collect all nodes in the attack tree."""
        for child in node.children:
            all_nodes.append(child)
            self._collect_all_nodes(child, all_nodes)


# Import datetime at module level
from datetime import datetime 