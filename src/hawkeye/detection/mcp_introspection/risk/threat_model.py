"""
Capability-based Threat Modeling for MCP Introspection

Provides comprehensive threat modeling based on MCP server capabilities,
analyzing potential attack vectors and security implications.
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from ..models import (
    MCPServerInfo, MCPTool, MCPResource, MCPCapabilities, 
    RiskLevel, RiskCategory, SecurityRisk
)


class ThreatCategory(str, Enum):
    """Categories of threats in MCP environments."""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    DENIAL_OF_SERVICE = "denial_of_service"
    CODE_INJECTION = "code_injection"
    CONFIGURATION_TAMPERING = "configuration_tampering"
    CREDENTIAL_THEFT = "credential_theft"
    SUPPLY_CHAIN = "supply_chain"
    INFORMATION_DISCLOSURE = "information_disclosure"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


class AttackVector(str, Enum):
    """Attack vectors for MCP threats."""
    TOOL_ABUSE = "tool_abuse"
    RESOURCE_MANIPULATION = "resource_manipulation"
    PROTOCOL_EXPLOITATION = "protocol_exploitation"
    CONFIGURATION_WEAKNESS = "configuration_weakness"
    TRANSPORT_INTERCEPTION = "transport_interception"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INPUT_VALIDATION = "input_validation"
    DEPENDENCY_CONFUSION = "dependency_confusion"


@dataclass
class ThreatVector:
    """Represents a specific threat vector."""
    vector_id: str
    name: str
    description: str
    category: ThreatCategory
    attack_vector: AttackVector
    likelihood: float  # 0.0 to 1.0
    impact: RiskLevel
    affected_assets: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


# Alias for backward compatibility
Threat = ThreatVector


@dataclass
class ThreatModel:
    """Complete threat model for an MCP server."""
    server_id: str
    server_name: Optional[str]
    model_timestamp: datetime
    threat_vectors: List[ThreatVector] = field(default_factory=list)
    overall_threat_level: RiskLevel = RiskLevel.LOW
    critical_threats: int = 0
    high_threats: int = 0
    medium_threats: int = 0
    low_threats: int = 0
    
    def add_threat_vector(self, threat: ThreatVector) -> None:
        """Add a threat vector to the model."""
        self.threat_vectors.append(threat)
        self._update_statistics()
    
    def get_threats_by_category(self, category: ThreatCategory) -> List[ThreatVector]:
        """Get all threats in a specific category."""
        return [t for t in self.threat_vectors if t.category == category]
    
    def get_threats_by_attack_vector(self, attack_vector: AttackVector) -> List[ThreatVector]:
        """Get all threats using a specific attack vector."""
        return [t for t in self.threat_vectors if t.attack_vector == attack_vector]
    
    def get_high_likelihood_threats(self, threshold: float = 0.7) -> List[ThreatVector]:
        """Get threats with likelihood above threshold."""
        return [t for t in self.threat_vectors if t.likelihood >= threshold]
    
    def _update_statistics(self) -> None:
        """Update threat statistics."""
        self.critical_threats = sum(1 for t in self.threat_vectors if t.impact == RiskLevel.CRITICAL)
        self.high_threats = sum(1 for t in self.threat_vectors if t.impact == RiskLevel.HIGH)
        self.medium_threats = sum(1 for t in self.threat_vectors if t.impact == RiskLevel.MEDIUM)
        self.low_threats = sum(1 for t in self.threat_vectors if t.impact == RiskLevel.LOW)
        
        # Determine overall threat level
        if self.critical_threats > 0:
            self.overall_threat_level = RiskLevel.CRITICAL
        elif self.high_threats > 0:
            self.overall_threat_level = RiskLevel.HIGH
        elif self.medium_threats > 0:
            self.overall_threat_level = RiskLevel.MEDIUM
        elif self.low_threats > 0:
            self.overall_threat_level = RiskLevel.LOW
        else:
            self.overall_threat_level = RiskLevel.MINIMAL


class ThreatModelingEngine:
    """
    Engine for generating threat models based on MCP server capabilities.
    
    Analyzes server capabilities, tools, and resources to identify potential
    threat vectors and security risks.
    """
    
    def __init__(self):
        """Initialize the threat modeling engine."""
        self.logger = logging.getLogger(__name__)
        self._threat_templates = self._initialize_threat_templates()
        self._capability_threats = self._initialize_capability_threats()
        self._tool_threats = self._initialize_tool_threats()
        self._resource_threats = self._initialize_resource_threats()
    
    def generate_threat_model(self, server_info: MCPServerInfo) -> ThreatModel:
        """
        Generate a comprehensive threat model for an MCP server.
        
        Args:
            server_info: Server information including capabilities, tools, and resources
            
        Returns:
            Complete threat model for the server
        """
        model = ThreatModel(
            server_id=server_info.server_id,
            server_name=getattr(server_info, 'name', None),
            model_timestamp=datetime.now()
        )
        
        # Analyze capability-based threats
        capability_threats = self._analyze_capability_threats(server_info)
        for threat in capability_threats:
            model.add_threat_vector(threat)
        
        # Analyze tool-based threats
        tool_threats = self._analyze_tool_threats(server_info.tools)
        for threat in tool_threats:
            model.add_threat_vector(threat)
        
        # Analyze resource-based threats
        resource_threats = self._analyze_resource_threats(server_info.resources)
        for threat in resource_threats:
            model.add_threat_vector(threat)
        
        # Analyze combination threats (tools + resources + capabilities)
        combination_threats = self._analyze_combination_threats(server_info)
        for threat in combination_threats:
            model.add_threat_vector(threat)
        
        self.logger.info(f"Generated threat model for server '{server_info.server_id}': "
                        f"{len(model.threat_vectors)} threats identified")
        
        return model
    
    def generate_threat_models(self, servers: List[MCPServerInfo]) -> Dict[str, ThreatModel]:
        """
        Generate threat models for multiple servers.
        
        Args:
            servers: List of server information
            
        Returns:
            Dictionary mapping server IDs to their threat models
        """
        models = {}
        
        for server in servers:
            try:
                model = self.generate_threat_model(server)
                models[server.server_id] = model
            except Exception as e:
                self.logger.error(f"Error generating threat model for server '{server.server_id}': {e}")
                # Create minimal threat model with error
                models[server.server_id] = ThreatModel(
                    server_id=server.server_id,
                    server_name=getattr(server, 'name', None),
                    model_timestamp=datetime.now(),
                    threat_vectors=[
                        ThreatVector(
                            vector_id="analysis_error",
                            name="Threat Analysis Error",
                            description=f"Failed to analyze threats: {str(e)}",
                            category=ThreatCategory.INFORMATION_DISCLOSURE,
                            attack_vector=AttackVector.CONFIGURATION_WEAKNESS,
                            likelihood=0.0,
                            impact=RiskLevel.UNKNOWN
                        )
                    ]
                )
        
        return models
    
    def _analyze_capability_threats(self, server_info: MCPServerInfo) -> List[ThreatVector]:
        """Analyze threats based on server capabilities."""
        threats = []
        
        # Check if server has capabilities information
        if not server_info.capabilities:
            return threats
        
        for capability in server_info.capabilities:
            capability_name = capability.name.lower()
            
            # Check against known capability threat patterns
            for pattern, threat_info in self._capability_threats.items():
                if pattern in capability_name:
                    threat = ThreatVector(
                        vector_id=f"cap_{capability.name}_{threat_info['category'].value}",
                        name=f"Capability-based {threat_info['name']}",
                        description=threat_info['description'],
                        category=threat_info['category'],
                        attack_vector=threat_info['attack_vector'],
                        likelihood=threat_info['likelihood'],
                        impact=threat_info['impact'],
                        affected_assets=[f"capability:{capability.name}"],
                        prerequisites=threat_info.get('prerequisites', []),
                        mitigations=threat_info.get('mitigations', [])
                    )
                    threats.append(threat)
        
        return threats
    
    def _analyze_tool_threats(self, tools: List[MCPTool]) -> List[ThreatVector]:
        """Analyze threats based on available tools."""
        threats = []
        
        for tool in tools:
            tool_name = tool.name.lower()
            tool_desc = tool.description.lower()
            
            # Check against known tool threat patterns
            for pattern, threat_info in self._tool_threats.items():
                if pattern in tool_name or pattern in tool_desc:
                    threat = ThreatVector(
                        vector_id=f"tool_{tool.name}_{threat_info['category'].value}",
                        name=f"Tool-based {threat_info['name']}",
                        description=f"{threat_info['description']} via tool '{tool.name}'",
                        category=threat_info['category'],
                        attack_vector=threat_info['attack_vector'],
                        likelihood=threat_info['likelihood'],
                        impact=threat_info['impact'],
                        affected_assets=[f"tool:{tool.name}"],
                        prerequisites=threat_info.get('prerequisites', []),
                        mitigations=threat_info.get('mitigations', [])
                    )
                    threats.append(threat)
            
            # Analyze tool parameters for additional threats
            param_threats = self._analyze_tool_parameter_threats(tool)
            threats.extend(param_threats)
        
        return threats
    
    def _analyze_resource_threats(self, resources: List[MCPResource]) -> List[ThreatVector]:
        """Analyze threats based on available resources."""
        threats = []
        
        for resource in resources:
            resource_uri = resource.uri.lower()
            resource_name = resource.name.lower()
            
            # Check against known resource threat patterns
            for pattern, threat_info in self._resource_threats.items():
                if pattern in resource_uri or pattern in resource_name:
                    threat = ThreatVector(
                        vector_id=f"resource_{resource.name}_{threat_info['category'].value}",
                        name=f"Resource-based {threat_info['name']}",
                        description=f"{threat_info['description']} via resource '{resource.name}'",
                        category=threat_info['category'],
                        attack_vector=threat_info['attack_vector'],
                        likelihood=threat_info['likelihood'],
                        impact=threat_info['impact'],
                        affected_assets=[f"resource:{resource.uri}"],
                        prerequisites=threat_info.get('prerequisites', []),
                        mitigations=threat_info.get('mitigations', [])
                    )
                    threats.append(threat)
        
        return threats
    
    def _analyze_combination_threats(self, server_info: MCPServerInfo) -> List[ThreatVector]:
        """Analyze threats that arise from combinations of capabilities."""
        threats = []
        
        # Check for dangerous combinations
        has_file_tools = any("file" in tool.name.lower() or "read" in tool.name.lower() 
                           for tool in server_info.tools)
        has_network_tools = any("http" in tool.name.lower() or "request" in tool.name.lower() 
                              for tool in server_info.tools)
        has_exec_tools = any("exec" in tool.name.lower() or "command" in tool.name.lower() 
                           for tool in server_info.tools)
        
        # File + Network = Data exfiltration risk
        if has_file_tools and has_network_tools:
            threat = ThreatVector(
                vector_id=f"combo_file_network_{server_info.server_id}",
                name="Data Exfiltration via File and Network Access",
                description="Combination of file access and network capabilities enables data exfiltration",
                category=ThreatCategory.DATA_EXFILTRATION,
                attack_vector=AttackVector.TOOL_ABUSE,
                likelihood=0.6,
                impact=RiskLevel.HIGH,
                affected_assets=["file_system", "network"],
                prerequisites=["file_access_tools", "network_access_tools"],
                mitigations=[
                    "Implement file access controls",
                    "Monitor network traffic",
                    "Use data loss prevention (DLP) tools"
                ]
            )
            threats.append(threat)
        
        # Exec + Network = Remote code execution risk
        if has_exec_tools and has_network_tools:
            threat = ThreatVector(
                vector_id=f"combo_exec_network_{server_info.server_id}",
                name="Remote Code Execution via Command and Network Access",
                description="Combination of command execution and network access enables remote code execution",
                category=ThreatCategory.CODE_INJECTION,
                attack_vector=AttackVector.TOOL_ABUSE,
                likelihood=0.8,
                impact=RiskLevel.CRITICAL,
                affected_assets=["system", "network"],
                prerequisites=["command_execution_tools", "network_access_tools"],
                mitigations=[
                    "Restrict command execution capabilities",
                    "Implement network segmentation",
                    "Use application sandboxing"
                ]
            )
            threats.append(threat)
        
        return threats
    
    def _analyze_tool_parameter_threats(self, tool: MCPTool) -> List[ThreatVector]:
        """Analyze threats based on tool parameters."""
        threats = []
        
        for param in tool.parameters:
            param_name = param.name.lower()
            
            # Check for dangerous parameter patterns
            if any(danger in param_name for danger in ["command", "exec", "shell", "script"]):
                threat = ThreatVector(
                    vector_id=f"param_{tool.name}_{param.name}_exec",
                    name="Command Injection via Tool Parameter",
                    description=f"Tool parameter '{param.name}' may allow command injection",
                    category=ThreatCategory.CODE_INJECTION,
                    attack_vector=AttackVector.INPUT_VALIDATION,
                    likelihood=0.7,
                    impact=RiskLevel.HIGH,
                    affected_assets=[f"tool:{tool.name}", f"parameter:{param.name}"],
                    prerequisites=["tool_access", "parameter_control"],
                    mitigations=[
                        "Implement input validation",
                        "Use parameterized commands",
                        "Apply principle of least privilege"
                    ]
                )
                threats.append(threat)
            
            if any(danger in param_name for danger in ["path", "file", "directory"]):
                threat = ThreatVector(
                    vector_id=f"param_{tool.name}_{param.name}_path",
                    name="Path Traversal via Tool Parameter",
                    description=f"Tool parameter '{param.name}' may allow path traversal attacks",
                    category=ThreatCategory.UNAUTHORIZED_ACCESS,
                    attack_vector=AttackVector.INPUT_VALIDATION,
                    likelihood=0.6,
                    impact=RiskLevel.MEDIUM,
                    affected_assets=[f"tool:{tool.name}", f"parameter:{param.name}"],
                    prerequisites=["tool_access", "parameter_control"],
                    mitigations=[
                        "Validate file paths",
                        "Use chroot or similar containment",
                        "Implement file access controls"
                    ]
                )
                threats.append(threat)
        
        return threats
    
    def _initialize_threat_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat vector templates."""
        return {
            "file_access": {
                "name": "Unauthorized File Access",
                "description": "Potential for unauthorized access to file system",
                "category": ThreatCategory.UNAUTHORIZED_ACCESS,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.5,
                "impact": RiskLevel.MEDIUM
            },
            "network_access": {
                "name": "Unauthorized Network Access",
                "description": "Potential for unauthorized network communication",
                "category": ThreatCategory.LATERAL_MOVEMENT,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.6,
                "impact": RiskLevel.MEDIUM
            },
            "code_execution": {
                "name": "Arbitrary Code Execution",
                "description": "Potential for executing arbitrary code",
                "category": ThreatCategory.CODE_INJECTION,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.8,
                "impact": RiskLevel.CRITICAL
            }
        }
    
    def _initialize_capability_threats(self) -> Dict[str, Dict[str, Any]]:
        """Initialize capability-based threat patterns."""
        return {
            "tools": {
                "name": "Tool Abuse",
                "description": "Server tools may be abused for malicious purposes",
                "category": ThreatCategory.PRIVILEGE_ESCALATION,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.5,
                "impact": RiskLevel.MEDIUM,
                "prerequisites": ["tool_access"],
                "mitigations": ["Implement tool access controls", "Monitor tool usage"]
            },
            "resources": {
                "name": "Resource Manipulation",
                "description": "Server resources may be manipulated or accessed inappropriately",
                "category": ThreatCategory.DATA_EXFILTRATION,
                "attack_vector": AttackVector.RESOURCE_MANIPULATION,
                "likelihood": 0.4,
                "impact": RiskLevel.MEDIUM,
                "prerequisites": ["resource_access"],
                "mitigations": ["Implement resource access controls", "Monitor resource usage"]
            }
        }
    
    def _initialize_tool_threats(self) -> Dict[str, Dict[str, Any]]:
        """Initialize tool-based threat patterns."""
        return {
            "file": {
                "name": "File System Access",
                "description": "Tool provides file system access capabilities",
                "category": ThreatCategory.UNAUTHORIZED_ACCESS,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.5,
                "impact": RiskLevel.MEDIUM
            },
            "exec": {
                "name": "Command Execution",
                "description": "Tool provides command execution capabilities",
                "category": ThreatCategory.CODE_INJECTION,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.8,
                "impact": RiskLevel.CRITICAL
            },
            "http": {
                "name": "Network Communication",
                "description": "Tool provides network communication capabilities",
                "category": ThreatCategory.LATERAL_MOVEMENT,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.6,
                "impact": RiskLevel.MEDIUM
            },
            "database": {
                "name": "Database Access",
                "description": "Tool provides database access capabilities",
                "category": ThreatCategory.DATA_EXFILTRATION,
                "attack_vector": AttackVector.TOOL_ABUSE,
                "likelihood": 0.7,
                "impact": RiskLevel.HIGH
            }
        }
    
    def _initialize_resource_threats(self) -> Dict[str, Dict[str, Any]]:
        """Initialize resource-based threat patterns."""
        return {
            "file://": {
                "name": "File Resource Access",
                "description": "Resource provides access to file system",
                "category": ThreatCategory.INFORMATION_DISCLOSURE,
                "attack_vector": AttackVector.RESOURCE_MANIPULATION,
                "likelihood": 0.4,
                "impact": RiskLevel.MEDIUM
            },
            "http://": {
                "name": "HTTP Resource Access",
                "description": "Resource provides access to HTTP endpoints",
                "category": ThreatCategory.LATERAL_MOVEMENT,
                "attack_vector": AttackVector.RESOURCE_MANIPULATION,
                "likelihood": 0.5,
                "impact": RiskLevel.MEDIUM
            },
            "database": {
                "name": "Database Resource Access",
                "description": "Resource provides access to database",
                "category": ThreatCategory.DATA_EXFILTRATION,
                "attack_vector": AttackVector.RESOURCE_MANIPULATION,
                "likelihood": 0.6,
                "impact": RiskLevel.HIGH
            }
        } 