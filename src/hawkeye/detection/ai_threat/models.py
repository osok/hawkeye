"""
AI Threat Analysis Data Models

This module defines the data structures used for AI-powered threat analysis,
including threat levels, attack vectors, and comprehensive threat assessments.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from ..mcp_introspection.models import MCPTool


class ThreatLevel(Enum):
    """Threat level enumeration."""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_string(cls, value: str) -> 'ThreatLevel':
        """Create ThreatLevel from string value."""
        value = value.lower().strip()
        for level in cls:
            if level.value == value:
                return level
        # Default to MEDIUM for unknown values
        return cls.MEDIUM


class SeverityLevel(Enum):
    """Severity level for attack vectors."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DifficultyLevel(Enum):
    """Difficulty level for attacks or detection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ThreatActorType(Enum):
    """Types of threat actors."""
    INSIDER_THREAT = "insider_threat"
    EXTERNAL_ATTACKER = "external_attacker"
    NATION_STATE = "nation_state"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"


class AccessLevel(Enum):
    """Access levels required for attacks."""
    NONE = "none"
    USER = "user"
    ELEVATED = "elevated"
    ADMIN = "admin"
    ROOT = "root"


class CapabilityCategory(Enum):
    """Categories of MCP tool capabilities."""
    FILE_SYSTEM = "file_system"
    NETWORK_ACCESS = "network_access"
    CODE_EXECUTION = "code_execution"
    DATA_PROCESSING = "data_processing"
    SYSTEM_INFORMATION = "system_information"
    EXTERNAL_INTEGRATION = "external_integration"
    DATABASE_ACCESS = "database_access"
    CLOUD_SERVICES = "cloud_services"
    AUTHENTICATION = "authentication"
    CRYPTOGRAPHY = "cryptography"


class DeploymentType(Enum):
    """Types of deployment environments."""
    LOCAL = "local"
    REMOTE = "remote"
    CLOUD = "cloud"
    HYBRID = "hybrid"
    EDGE = "edge"


class SecurityPosture(Enum):
    """Security posture levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"


class DataSensitivity(Enum):
    """Data sensitivity levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class NetworkExposure(Enum):
    """Network exposure levels."""
    ISOLATED = "isolated"
    INTERNAL = "internal"
    INTERNET_FACING = "internet_facing"
    PUBLIC = "public"


class UserPrivileges(Enum):
    """User privilege levels."""
    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"
    ROOT = "root"


class ComplianceFramework(Enum):
    """Compliance frameworks."""
    OWASP_TOP_10 = "owasp_top_10"
    NIST_CSF = "nist_csf"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO_27001 = "iso_27001"


@dataclass
class RiskSurface:
    """Represents the attack surface exposed by tool capabilities."""
    file_access_paths: List[str] = None
    network_endpoints: List[str] = None
    system_commands: List[str] = None
    external_apis: List[str] = None
    risk_score: float = 0.0
    
    def __post_init__(self):
        if self.file_access_paths is None:
            self.file_access_paths = []
        if self.network_endpoints is None:
            self.network_endpoints = []
        if self.system_commands is None:
            self.system_commands = []
        if self.external_apis is None:
            self.external_apis = []


@dataclass
class AccessRequirements:
    """Represents access requirements for using tools."""
    minimum_privilege: AccessLevel = AccessLevel.USER
    authentication_required: bool = True
    network_access_required: bool = False
    file_system_access: bool = False
    system_command_access: bool = False


@dataclass
class ExternalDependency:
    """Represents external dependencies of MCP tools."""
    name: str
    type: str
    endpoint: Optional[str] = None
    authentication_method: Optional[str] = None
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL


@dataclass
class ToolFunction:
    """Represents a function within an MCP tool."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    categories: List[CapabilityCategory]
    risk_indicators: List[str]
    requires_privileges: bool
    external_access: bool


@dataclass
class ToolCapabilities:
    """Represents the capabilities of an MCP tool."""
    tool_name: str
    tool_id: str
    tool_functions: List[ToolFunction]
    capability_categories: List[CapabilityCategory]
    risk_indicators: List[str]
    requires_privileges: bool
    external_access: bool
    risk_score: float
    confidence: float
    risk_surface: RiskSurface = None
    access_requirements: AccessRequirements = None
    external_dependencies: List[ExternalDependency] = None
    
    def __post_init__(self):
        if self.risk_surface is None:
            self.risk_surface = RiskSurface()
        if self.access_requirements is None:
            self.access_requirements = AccessRequirements()
        if self.external_dependencies is None:
            self.external_dependencies = []


@dataclass
class EnvironmentContext:
    """Represents the deployment environment context."""
    deployment_type: DeploymentType
    security_posture: SecurityPosture
    data_sensitivity: DataSensitivity
    network_exposure: NetworkExposure
    user_privileges: UserPrivileges
    compliance_requirements: List[ComplianceFramework]


@dataclass
class AttackStep:
    """Represents a step in an attack sequence."""
    step_number: int
    description: str
    prerequisites: List[str]
    tools_required: List[str]


@dataclass
class AttackVector:
    """Represents a specific attack vector."""
    name: str
    severity: SeverityLevel
    description: str
    attack_steps: List[str]
    prerequisites: List[str]
    impact: str
    likelihood: float
    example_code: Optional[str] = None
    mitigations: List[str] = None
    
    def __post_init__(self):
        if self.mitigations is None:
            self.mitigations = []


@dataclass
class BusinessImpact:
    """Represents business impact of an attack."""
    financial_impact: str
    operational_impact: str
    reputation_impact: str


@dataclass
class ChainLink:
    """Represents a single link in an attack chain."""
    tool_name: str
    tool_capabilities: List[str]
    attack_action: str
    prerequisites: List[str]
    output_artifacts: List[str]  # What this step produces for the next step
    required_access: AccessLevel
    difficulty: DifficultyLevel
    time_estimate: int  # Minutes to execute this step


@dataclass
class AttackChain:
    """Represents a multi-tool attack chain."""
    chain_id: str
    chain_name: str
    description: str
    threat_actor: ThreatActorType
    attack_objective: str
    chain_links: List[ChainLink]
    overall_difficulty: DifficultyLevel
    overall_impact: BusinessImpact
    total_time_estimate: int  # Total minutes for entire chain
    detection_difficulty: DifficultyLevel
    mitigation_strategies: List[str]
    prerequisites: List[str]  # Initial requirements to start the chain
    success_probability: float  # Probability of chain succeeding (0.0-1.0)
    

@dataclass
class ChainFeasibilityScore:
    """Represents the feasibility assessment of an attack chain."""
    chain_id: str
    overall_score: float  # 0.0-1.0, higher means more feasible
    technical_feasibility: float
    access_feasibility: float
    detection_avoidance: float
    environmental_suitability: float
    resource_requirements: float
    scoring_rationale: str
    confidence_level: float


@dataclass
class AbuseScenario:
    """Represents a tool abuse scenario."""
    scenario_name: str
    threat_actor: ThreatActorType
    motivation: str
    attack_flow: List[AttackStep]
    required_access: AccessLevel
    detection_difficulty: DifficultyLevel
    business_impact: BusinessImpact


@dataclass
class MitigationStrategy:
    """Represents a mitigation strategy."""
    name: str
    description: str
    implementation_steps: List[str]
    effectiveness_score: float
    complexity: DifficultyLevel = DifficultyLevel.MEDIUM
    cost_estimate: str = "Medium"


@dataclass
class DetectionIndicator:
    """Represents a detection indicator."""
    indicator_name: str
    indicator_type: str
    pattern: str
    confidence: float
    false_positive_rate: float = 0.1


@dataclass
class ComplianceImpact:
    """Represents compliance impact of threats."""
    affected_frameworks: List[ComplianceFramework]
    violation_risk: ThreatLevel
    required_controls: List[str]


@dataclass
class AnalysisMetadata:
    """Metadata about the threat analysis."""
    provider: str
    model: str
    timestamp: datetime
    analysis_duration: float
    cost: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    confidence_score: float = 0.0


@dataclass
class ThreatAnalysis:
    """Complete threat analysis for an MCP tool."""
    tool_signature: str
    tool_capabilities: ToolCapabilities
    environment_context: EnvironmentContext
    threat_level: ThreatLevel
    attack_vectors: List[AttackVector]
    abuse_scenarios: List[AbuseScenario]
    mitigation_strategies: List[MitigationStrategy]
    detection_indicators: List[DetectionIndicator]
    compliance_impact: ComplianceImpact
    confidence_score: float
    analysis_metadata: AnalysisMetadata
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatAnalysis':
        """Create ThreatAnalysis from dictionary."""
        # Parse attack vectors
        attack_vectors = []
        for av_data in data.get("attack_vectors", []):
            attack_vector = AttackVector(
                name=av_data["name"],
                severity=SeverityLevel(av_data["severity"].lower()),
                description=av_data["description"],
                attack_steps=av_data.get("attack_steps", []),
                prerequisites=av_data.get("prerequisites", []),
                impact=av_data.get("impact", ""),
                likelihood=av_data.get("likelihood", 0.5),
                mitigations=av_data.get("mitigations", [])
            )
            attack_vectors.append(attack_vector)
        
        # Parse abuse scenarios
        abuse_scenarios = []
        for as_data in data.get("abuse_scenarios", []):
            # Convert attack_flow to AttackStep objects
            attack_flow = []
            for i, step in enumerate(as_data.get("attack_flow", [])):
                if isinstance(step, str):
                    attack_step = AttackStep(
                        step_number=i + 1,
                        description=step,
                        prerequisites=[],
                        tools_required=[]
                    )
                else:
                    attack_step = AttackStep(**step)
                attack_flow.append(attack_step)
            
            business_impact = BusinessImpact(
                financial_impact=as_data.get("impact", "Unknown"),
                operational_impact=as_data.get("impact", "Unknown"),
                reputation_impact=as_data.get("impact", "Unknown")
            )
            
            scenario = AbuseScenario(
                scenario_name=as_data["scenario_name"],
                threat_actor=ThreatActorType(as_data.get("threat_actor", "external_attacker")),
                motivation=as_data.get("motivation", "Unknown"),
                attack_flow=attack_flow,
                required_access=AccessLevel.USER,
                detection_difficulty=DifficultyLevel.MEDIUM,
                business_impact=business_impact
            )
            abuse_scenarios.append(scenario)
        
        # Parse mitigation strategies
        mitigation_strategies = []
        for ms_data in data.get("mitigation_strategies", []):
            strategy = MitigationStrategy(
                name=ms_data.get("name", ms_data["description"][:50]),
                description=ms_data["description"],
                implementation_steps=ms_data.get("implementation_steps", []),
                effectiveness_score=ms_data.get("effectiveness", ms_data.get("effectiveness_score", 0.5))
            )
            mitigation_strategies.append(strategy)
        
        # Parse detection indicators (optional)
        detection_indicators = []
        for di_data in data.get("detection_indicators", []):
            indicator = DetectionIndicator(
                indicator_name=di_data["indicator_name"],
                indicator_type=di_data["indicator_type"],
                pattern=di_data["pattern"],
                confidence=di_data.get("confidence", 0.5)
            )
            detection_indicators.append(indicator)
        
        # Create minimal required objects
        tool_capabilities = ToolCapabilities(
            tool_name="Unknown",
            tool_id="unknown",
            tool_functions=[],
            capability_categories=[],
            risk_indicators=[],
            requires_privileges=False,
            external_access=False,
            risk_score=0.5,
            confidence=0.5
        )
        
        environment_context = EnvironmentContext(
            deployment_type=DeploymentType.LOCAL,
            security_posture=SecurityPosture.MEDIUM,
            data_sensitivity=DataSensitivity.INTERNAL,
            network_exposure=NetworkExposure.INTERNAL,
            user_privileges=UserPrivileges.STANDARD,
            compliance_requirements=[]
        )
        
        compliance_impact = ComplianceImpact(
            affected_frameworks=[],
            violation_risk=ThreatLevel.MEDIUM,
            required_controls=[]
        )
        
        analysis_metadata = AnalysisMetadata(
            provider="unknown",
            model="unknown",
            timestamp=datetime.now(),
            analysis_duration=0.0,
            cost=0.0
        )
        
        # Create ThreatAnalysis object
        threat_analysis = ThreatAnalysis(
            tool_signature="unknown",
            tool_capabilities=tool_capabilities,
            environment_context=environment_context,
            threat_level=ThreatLevel(data["threat_level"].lower()),
            attack_vectors=attack_vectors,
            abuse_scenarios=abuse_scenarios,
            mitigation_strategies=mitigation_strategies,
            detection_indicators=detection_indicators,
            compliance_impact=compliance_impact,
            confidence_score=data.get("confidence_score", 0.8),
            analysis_metadata=analysis_metadata
        )
        
        return threat_analysis 