"""
Enhanced Data Models for MCP Capabilities

Provides comprehensive data models for representing MCP server information,
capabilities, tools, resources, and risk assessments.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, Set
from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel, Field, validator


class RiskLevel(str, Enum):
    """Risk level enumeration for security assessment."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


class TransportType(str, Enum):
    """MCP transport type enumeration."""
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class RiskCategory(str, Enum):
    """Risk category enumeration for threat classification."""
    FILE_SYSTEM = "file_system"
    NETWORK_ACCESS = "network_access"
    CODE_EXECUTION = "code_execution"
    DATA_ACCESS = "data_access"
    SYSTEM_MODIFICATION = "system_modification"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    CLOUD_SERVICES = "cloud_services"
    UNKNOWN = "unknown"


class SecurityCategory(str, Enum):
    """Security category enumeration."""
    FILE_SYSTEM = "file_system"
    NETWORK_ACCESS = "network_access"
    CODE_EXECUTION = "code_execution"
    DATA_ACCESS = "data_access"
    SYSTEM_ACCESS = "system_access"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    CLOUD_SERVICES = "cloud_services"
    UNKNOWN = "unknown"


class ComplianceStatus(str, Enum):
    """Compliance status enumeration."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ValidationError(Exception):
    """Custom validation error for MCP models."""
    pass


class MCPCapabilities(BaseModel):
    """
    Server capabilities discovered via initialize response.
    
    Represents the features and experimental capabilities supported
    by an MCP server.
    """
    supports_tools: bool = Field(default=False, description="Server supports tools")
    supports_resources: bool = Field(default=False, description="Server supports resources")
    supports_prompts: bool = Field(default=False, description="Server supports prompts")
    supports_logging: bool = Field(default=False, description="Server supports logging")
    supports_completion: bool = Field(default=False, description="Server supports completion")
    supports_sampling: bool = Field(default=False, description="Server supports sampling")
    
    # Experimental and custom capabilities
    experimental_capabilities: Dict[str, Any] = Field(
        default_factory=dict,
        description="Experimental capabilities reported by server"
    )
    custom_capabilities: Dict[str, Any] = Field(
        default_factory=dict,
        description="Custom capabilities specific to this server"
    )
    
    # Version and protocol information
    protocol_version: Optional[str] = Field(default=None, description="MCP protocol version")
    server_version: Optional[str] = Field(default=None, description="Server implementation version")
    
    def get_capability_count(self) -> int:
        """Get the total number of supported capabilities."""
        standard_caps = sum([
            self.supports_tools,
            self.supports_resources,
            self.supports_prompts,
            self.supports_logging,
            self.supports_completion,
            self.supports_sampling,
        ])
        return standard_caps + len(self.experimental_capabilities) + len(self.custom_capabilities)
    
    def has_dangerous_capabilities(self) -> bool:
        """Check if server has potentially dangerous capabilities."""
        # Tools and code execution are generally higher risk
        return self.supports_tools or "code_execution" in self.experimental_capabilities

    def has_capability(self, capability: str) -> bool:
        """Check if server has specific capability."""
        if capability == "tools":
            return self.supports_tools
        elif capability == "resources":
            return self.supports_resources
        elif capability == "prompts":
            return self.supports_prompts
        elif capability == "logging":
            return self.supports_logging
        elif capability == "completion":
            return self.supports_completion
        elif capability == "sampling":
            return self.supports_sampling
        else:
            return capability in self.experimental_capabilities


class MCPToolParameter(BaseModel):
    """Parameter information for MCP tools."""
    name: str = Field(description="Parameter name")
    type: str = Field(description="Parameter type")
    description: str = Field(default="", description="Parameter description")
    required: bool = Field(default=False, description="Whether parameter is required")
    default: Optional[Any] = Field(default=None, description="Default value")
    enum: Optional[List[Any]] = Field(default=None, description="Allowed values")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class MCPTool(BaseModel):
    """
    Tool information from tools/list endpoint.
    
    Represents a tool exposed by an MCP server with security analysis.
    """
    name: str = Field(description="Tool name")
    description: str = Field(description="Tool description")
    parameters: List[MCPToolParameter] = Field(default_factory=list, description="Tool parameters")
    input_schema: Dict[str, Any] = Field(default_factory=dict, description="JSON schema for tool input")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    risk_categories: List[SecurityCategory] = Field(default_factory=list, description="Risk categories")
    risk_level: RiskLevel = Field(default=RiskLevel.UNKNOWN, description="Risk level")
    security_notes: List[str] = Field(default_factory=list, description="Security notes")

    def has_risk_category(self, category: SecurityCategory) -> bool:
        """Check if tool has specific risk category."""
        return category in self.risk_categories

    def get_required_parameters(self) -> List[str]:
        """Get required parameters from schema."""
        return self.input_schema.get("required", [])

    def get_optional_parameters(self) -> List[str]:
        """Get optional parameters from schema."""
        properties = self.input_schema.get("properties", {})
        required = set(self.input_schema.get("required", []))
        return [prop for prop in properties.keys() if prop not in required]


class MCPResource(BaseModel):
    """
    Resource information from resources/list endpoint.
    
    Represents a resource exposed by an MCP server.
    """
    uri: str = Field(description="Resource URI")
    name: str = Field(description="Resource name")
    description: str = Field(description="Resource description")
    mime_type: Optional[str] = Field(default=None, description="MIME type of resource")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    risk_categories: List[SecurityCategory] = Field(default_factory=list, description="Risk categories")
    risk_level: RiskLevel = Field(default=RiskLevel.UNKNOWN, description="Risk level")
    security_notes: List[str] = Field(default_factory=list, description="Security notes")

    def get_uri_scheme(self) -> str:
        """Get URI scheme."""
        if "://" in self.uri:
            return self.uri.split("://")[0]
        return ""

    def is_local_resource(self) -> bool:
        """Check if resource is local."""
        scheme = self.get_uri_scheme()
        return scheme in ["file", ""]


class MCPServerConfig(BaseModel):
    """
    Configuration for an MCP server.
    
    Contains the information needed to connect to and introspect an MCP server.
    """
    server_id: str = Field(description="Unique identifier for the server")
    name: Optional[str] = Field(default=None, description="Human-readable server name")
    command: Optional[List[str]] = Field(default=None, description="Command to start server")
    executable: Optional[str] = Field(default=None, description="Server executable path")
    args: Optional[List[str]] = Field(default=None, description="Command line arguments")
    url: Optional[str] = Field(default=None, description="Server URL for network transports")
    env: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    transport_type: TransportType = Field(default=TransportType.STDIO, description="Transport protocol")
    transport_config: Dict[str, Any] = Field(default_factory=dict, description="Transport configuration")
    timeout: float = Field(default=30.0, description="Connection timeout in seconds")
    
    def get_display_name(self) -> str:
        """Get display name for the server."""
        return self.name or self.server_id


class MCPCapability(BaseModel):
    """Capability information for MCP servers."""
    name: str = Field(description="Capability name")
    description: str = Field(default="", description="Capability description")
    capabilities: List[str] = Field(default_factory=list, description="List of capabilities")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SecurityRisk(BaseModel):
    """Security risk information."""
    category: str = Field(description="Risk category")
    severity: RiskLevel = Field(description="Risk severity level")
    description: str = Field(description="Risk description")
    details: Dict[str, Any] = Field(default_factory=dict, description="Risk details")
    mitigation: str = Field(default="", description="Suggested mitigation")


class SecurityFinding(BaseModel):
    """Security finding from risk assessment."""
    id: str = Field(description="Finding identifier")
    title: str = Field(description="Finding title")
    description: str = Field(description="Finding description")
    severity: RiskLevel = Field(description="Finding severity")
    category: SecurityCategory = Field(description="Security category")
    affected_components: List[str] = Field(default_factory=list, description="Affected components")
    mitigation: str = Field(default="", description="Suggested mitigation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    def is_high_severity(self) -> bool:
        """Check if finding is high severity."""
        return self.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]


class ComplianceCheck(BaseModel):
    """Compliance check result."""
    check_id: str = Field(description="Check identifier")
    name: str = Field(description="Check name")
    description: str = Field(description="Check description")
    status: ComplianceStatus = Field(description="Compliance status")
    framework: str = Field(description="Compliance framework")
    control_id: str = Field(description="Control identifier")
    evidence: List[str] = Field(default_factory=list, description="Evidence")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    def is_compliant(self) -> bool:
        """Check if compliant."""
        return self.status == ComplianceStatus.COMPLIANT


class PerformanceMetrics(BaseModel):
    """Performance metrics for MCP operations."""
    operation: str = Field(description="Operation name")
    duration: float = Field(description="Operation duration in seconds")
    memory_usage: int = Field(description="Memory usage in bytes")
    cpu_usage: float = Field(description="CPU usage percentage")
    network_io: int = Field(description="Network I/O in bytes")
    disk_io: int = Field(description="Disk I/O in bytes")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    def is_performant(self, max_duration: float = 10.0) -> bool:
        """Check if operation is performant."""
        return self.duration <= max_duration


class TransportConfig(BaseModel):
    """Transport configuration for MCP connections."""
    transport_type: TransportType = Field(description="Transport type")
    command: Optional[List[str]] = Field(default=None, description="Command for stdio transport")
    args: Optional[List[str]] = Field(default=None, description="Arguments")
    env: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    url: Optional[str] = Field(default=None, description="URL for network transport")
    timeout: float = Field(default=30.0, description="Connection timeout")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    def validate_stdio_config(self) -> bool:
        """Validate stdio transport configuration."""
        if self.transport_type == TransportType.STDIO:
            return self.command is not None and len(self.command) > 0
        return True

    def validate_sse_config(self) -> bool:
        """Validate SSE transport configuration."""
        if self.transport_type == TransportType.SSE:
            return self.url is not None
        return True


class RiskAssessment(BaseModel):
    """Risk assessment for MCP server or component."""
    target_id: str = Field(description="Target identifier")
    target_type: str = Field(description="Target type (server, tool, resource)")
    overall_risk: RiskLevel = Field(description="Overall risk level")
    findings: List[SecurityFinding] = Field(default_factory=list, description="Security findings")
    compliance_checks: List[ComplianceCheck] = Field(default_factory=list, description="Compliance checks")
    assessment_date: datetime = Field(default_factory=datetime.now, description="Assessment date")
    assessor: str = Field(default="HawkEye", description="Assessor name")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    def get_findings_by_severity(self, severity: RiskLevel) -> List[SecurityFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: SecurityCategory) -> List[SecurityFinding]:
        """Get findings by security category."""
        return [f for f in self.findings if f.category == category]


class MCPServerInfo(BaseModel):
    """
    Enhanced server information with introspection data.
    
    Comprehensive information about an MCP server including capabilities,
    tools, resources, and security assessment.
    """
    # Basic server information
    server_id: str = Field(description="Unique server identifier")
    server_url: Optional[str] = Field(default=None, description="Server URL if applicable")
    host: Optional[str] = Field(default="localhost", description="Server host")
    port: Optional[int] = Field(default=None, description="Server port")
    is_secure: bool = Field(default=False, description="Whether connection is secure (HTTPS/WSS)")
    has_authentication: bool = Field(default=False, description="Whether server requires authentication")
    discovery_timestamp: datetime = Field(default_factory=datetime.now, description="When server was discovered")
    
    # Introspection data
    tools: List[MCPTool] = Field(default_factory=list, description="Available tools")
    resources: List[MCPResource] = Field(default_factory=list, description="Available resources")
    capabilities: List[MCPCapability] = Field(default_factory=list, description="Server capabilities")
    security_risks: List[SecurityRisk] = Field(default_factory=list, description="Identified security risks")
    overall_risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="Overall risk level")
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    def get_tool_count(self) -> int:
        """Get the number of tools exposed by this server."""
        return len(self.tools)
    
    def get_resource_count(self) -> int:
        """Get the number of resources exposed by this server."""
        return len(self.resources)

    def get_high_risk_tools(self) -> List[MCPTool]:
        """Get high risk tools."""
        return [tool for tool in self.tools 
                if tool.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
    
    def get_capability_count(self) -> int:
        """Get the number of capabilities exposed by this server."""
        return len(self.capabilities)


class DiscoveryResult(BaseModel):
    """Result of a discovery operation."""
    server_id: str = Field(description="Server identifier")
    discovery_type: str = Field(description="Type of discovery performed")
    timestamp: datetime = Field(description="Discovery timestamp")
    duration: Any = Field(description="Discovery duration")  # timedelta
    success: bool = Field(description="Whether discovery was successful")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    tools: List[MCPTool] = Field(default_factory=list, description="Discovered tools")
    resources: List[MCPResource] = Field(default_factory=list, description="Discovered resources")
    capabilities: List[MCPCapability] = Field(default_factory=list, description="Discovered capabilities")
    security_risks: List[SecurityRisk] = Field(default_factory=list, description="Identified security risks")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class IntrospectionResult(BaseModel):
    """Result of MCP server introspection."""
    timestamp: datetime = Field(description="Introspection timestamp")
    duration: Any = Field(description="Introspection duration")  # timedelta
    success: bool = Field(description="Whether introspection was successful")
    servers: List[MCPServerInfo] = Field(default_factory=list, description="Introspected servers")
    total_servers: int = Field(description="Total number of servers")
    successful_servers: int = Field(description="Number of successful introspections")
    failed_servers: int = Field(description="Number of failed introspections")
    overall_risk_level: RiskLevel = Field(description="Overall risk level")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class MCPIntrospectionResult(BaseModel):
    """
    Complete result of MCP introspection operation.
    
    Contains all discovered servers and summary statistics.
    """
    servers: List[MCPServerInfo] = Field(default_factory=list, description="Discovered servers")
    scan_timestamp: datetime = Field(default_factory=datetime.now, description="When scan was performed")
    scan_duration: float = Field(default=0.0, description="Total scan duration (seconds)")
    
    # Summary statistics
    total_servers: int = Field(default=0, description="Total number of servers found")
    successful_introspections: int = Field(default=0, description="Successful introspections")
    failed_introspections: int = Field(default=0, description="Failed introspections")
    
    # Risk summary
    critical_risk_servers: int = Field(default=0, description="Servers with critical risk")
    high_risk_servers: int = Field(default=0, description="Servers with high risk")
    medium_risk_servers: int = Field(default=0, description="Servers with medium risk")
    
    def update_statistics(self) -> None:
        """Update summary statistics based on current servers."""
        self.total_servers = len(self.servers)
        self.successful_introspections = len([s for s in self.servers if s.error_message is None])
        self.failed_introspections = len([s for s in self.servers if s.error_message is not None])
        
        # Risk statistics
        self.critical_risk_servers = len([s for s in self.servers if s.overall_risk_level == RiskLevel.CRITICAL])
        self.high_risk_servers = len([s for s in self.servers if s.overall_risk_level == RiskLevel.HIGH])
        self.medium_risk_servers = len([s for s in self.servers if s.overall_risk_level == RiskLevel.MEDIUM])
    
    def get_servers_by_risk(self, risk_level: RiskLevel) -> List[MCPServerInfo]:
        """Get servers filtered by risk level."""
        return [server for server in self.servers if server.overall_risk_level == risk_level]
    
    def get_all_tools(self) -> List[MCPTool]:
        """Get all tools from all servers."""
        tools = []
        for server in self.servers:
            tools.extend(server.tools)
        return tools
    
    def get_all_risk_categories(self) -> Set[RiskCategory]:
        """Get all risk categories found across all servers."""
        categories = set()
        for server in self.servers:
            categories.update(server.get_risk_categories())
        return categories

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scan_duration": self.scan_duration,
            "total_servers": self.total_servers,
            "successful_introspections": self.successful_introspections,
            "failed_introspections": self.failed_introspections,
            "critical_risk_servers": self.critical_risk_servers,
            "high_risk_servers": self.high_risk_servers,
            "medium_risk_servers": self.medium_risk_servers,
            "servers": [server.dict() for server in self.servers]
        } 