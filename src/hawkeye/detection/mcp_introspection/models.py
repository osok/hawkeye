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


class MCPServerInfo(BaseModel):
    """
    Enhanced server information with introspection data.
    
    Comprehensive information about an MCP server including capabilities,
    tools, resources, and security assessment.
    """
    # Basic server information
    server_id: str = Field(description="Unique server identifier")
    server_url: Optional[str] = Field(default=None, description="Server URL if applicable")
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