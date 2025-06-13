"""
MCP Server Introspection Module.

This module provides functionality to dynamically discover MCP server capabilities
by communicating with the servers directly using the MCP protocol via the new
Python-based synchronous introspection system.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

from .base import MCPServerInfo, ProcessInfo
from ..utils.logging import get_logger
from .mcp_introspection.introspection import MCPIntrospection, IntrospectionConfig
from .mcp_introspection.models import (
    MCPServerConfig, 
    MCPServerInfo as NewMCPServerInfo,
    MCPTool as NewMCPTool,
    MCPResource as NewMCPResource,
    MCPCapabilities as NewMCPCapabilities,
    RiskLevel
)
from .mcp_introspection.transport.factory import TransportFactory
from .mcp_introspection.transport.base import TransportType
from .mcp_introspection.discovery.aggregator import ServerInfoAggregator
from .mcp_introspection.discovery.tools import ToolDiscovery
from .mcp_introspection.discovery.resources import ResourceDiscovery
from .mcp_introspection.discovery.capabilities import CapabilityDiscovery
from .mcp_introspection.risk.tool_analyzer import ToolRiskAnalyzer
from .mcp_introspection.risk.threat_model import ThreatModelAnalyzer
from .mcp_introspection.risk.categorizer import RiskCategorizer
from .mcp_introspection.risk.scoring import RiskScorer
from .mcp_introspection.risk.reporter import RiskReporter


# Legacy data classes for backward compatibility
@dataclass
class MCPTool:
    """Represents an MCP tool with its capabilities (legacy compatibility)."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    
    @classmethod
    def from_new_tool(cls, new_tool: NewMCPTool) -> 'MCPTool':
        """Convert from new MCPTool format."""
        return cls(
            name=new_tool.name,
            description=new_tool.description,
            input_schema=new_tool.input_schema
        )
    
    @property
    def capability_category(self) -> str:
        """Categorize tool based on its name and description."""
        name_lower = self.name.lower()
        desc_lower = self.description.lower()
        
        # File system operations
        if any(keyword in name_lower for keyword in ['file', 'read', 'write', 'directory', 'path']):
            return "file_system"
        
        # Network operations
        if any(keyword in name_lower for keyword in ['web', 'http', 'search', 'fetch', 'api', 'request']):
            return "network_access"
        
        # Code execution
        if any(keyword in name_lower for keyword in ['execute', 'run', 'command', 'shell', 'eval']):
            return "code_execution"
        
        # Data processing
        if any(keyword in name_lower for keyword in ['parse', 'analyze', 'process', 'transform']):
            return "data_processing"
        
        # System information
        if any(keyword in name_lower for keyword in ['system', 'info', 'status', 'list', 'get']):
            return "system_information"
        
        # External integration
        if any(keyword in name_lower for keyword in ['database', 'cloud', 'service', 'integration']):
            return "external_integration"
        
        return "unknown"
    
    @property
    def risk_level(self) -> str:
        """Assess risk level based on capability category."""
        risk_mapping = {
            "file_system": "high",
            "network_access": "high", 
            "code_execution": "critical",
            "external_integration": "medium",
            "data_processing": "low",
            "system_information": "low",
            "unknown": "medium"
        }
        return risk_mapping.get(self.capability_category, "medium")


@dataclass
class MCPResource:
    """Represents an MCP resource (legacy compatibility)."""
    uri: str
    name: str
    description: str
    mime_type: Optional[str] = None
    
    @classmethod
    def from_new_resource(cls, new_resource: NewMCPResource) -> 'MCPResource':
        """Convert from new MCPResource format."""
        return cls(
            uri=new_resource.uri,
            name=new_resource.name,
            description=new_resource.description,
            mime_type=new_resource.mime_type
        )


@dataclass
class MCPCapabilities:
    """Complete capabilities of an MCP server (legacy compatibility)."""
    server_name: str
    server_version: str
    protocol_version: str
    tools: List[MCPTool]
    resources: List[MCPResource]
    capabilities: Dict[str, Any]
    
    @classmethod
    def from_new_capabilities(cls, new_server_info: NewMCPServerInfo) -> 'MCPCapabilities':
        """Convert from new MCPServerInfo format."""
        return cls(
            server_name=new_server_info.server_name,
            server_version=new_server_info.server_version,
            protocol_version=new_server_info.protocol_version,
            tools=[MCPTool.from_new_tool(tool) for tool in new_server_info.tools],
            resources=[MCPResource.from_new_resource(resource) for resource in new_server_info.resources],
            capabilities=new_server_info.capabilities
        )
    
    @property
    def tool_count(self) -> int:
        return len(self.tools)
    
    @property
    def resource_count(self) -> int:
        return len(self.resources)
    
    @property
    def capability_categories(self) -> List[str]:
        """Get unique capability categories."""
        return list(set(tool.capability_category for tool in self.tools))
    
    @property
    def highest_risk_level(self) -> str:
        """Get the highest risk level among all tools."""
        risk_hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_risk = max((risk_hierarchy.get(tool.risk_level, 1) for tool in self.tools), default=1)
        
        for level, value in risk_hierarchy.items():
            if value == max_risk:
                return level
        return "low"
    
    @property
    def has_external_access(self) -> bool:
        """Check if server has external access capabilities."""
        return "network_access" in self.capability_categories
    
    @property
    def has_file_access(self) -> bool:
        """Check if server has file system access."""
        return "file_system" in self.capability_categories
    
    @property
    def has_code_execution(self) -> bool:
        """Check if server can execute code."""
        return "code_execution" in self.capability_categories


class MCPIntrospector:
    """
    Introspects MCP servers to discover their capabilities.
    
    This class now uses the new Python-based synchronous introspection system
    instead of Node.js script generation for improved reliability and performance.
    """
    
    def __init__(self, config: Optional[IntrospectionConfig] = None):
        """
        Initialize the MCP introspector.
        
        Args:
            config: Optional introspection configuration
        """
        self.logger = get_logger(__name__)
        
        # Initialize the new introspection system
        self.introspection_config = config or IntrospectionConfig(
            timeout=180.0,
            enable_detailed_analysis=True,
            enable_risk_assessment=True
        )
        
        self.introspection_system = MCPIntrospection(self.introspection_config)
        
        # Initialize transport factory for direct transport access
        self.transport_factory = TransportFactory()
        
        # Initialize discovery components for direct access
        self.tool_discovery = ToolDiscovery()
        self.resource_discovery = ResourceDiscovery()
        self.capability_discovery = CapabilityDiscovery()
        self.server_aggregator = ServerInfoAggregator(self.introspection_config.aggregator_config)
        
        # Initialize risk analysis components for direct access
        self.tool_risk_analyzer = ToolRiskAnalyzer()
        self.threat_model_analyzer = ThreatModelAnalyzer()
        self.risk_categorizer = RiskCategorizer()
        self.risk_scorer = RiskScorer()
        self.risk_reporter = RiskReporter()
        
        # Track transport statistics
        self.transport_stats = {
            "stdio_connections": 0,
            "http_connections": 0,
            "sse_connections": 0,
            "failed_connections": 0,
            "total_introspections": 0
        }
        
        # Track discovery statistics
        self.discovery_stats = {
            "tools_discovered": 0,
            "resources_discovered": 0,
            "capabilities_discovered": 0,
            "discovery_failures": 0,
            "discovery_timeouts": 0
        }
        
        # Initialize result caching
        self.introspection_cache = {}
        self.cache_ttl = 3600  # 1 hour default TTL
        self.cache_stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_evictions": 0,
            "cache_size": 0
        }
        
        self.logger.info(
            "MCPIntrospector initialized with Python-based introspection system "
            f"(timeout: {self.introspection_config.timeout}s, "
            f"detailed_analysis: {self.introspection_config.enable_detailed_analysis}, "
            f"risk_assessment: {self.introspection_config.enable_risk_assessment})"
        )
    
    def introspect_server(self, server_info: MCPServerInfo, process_info: ProcessInfo) -> Optional[MCPCapabilities]:
        """
        Introspect an MCP server to discover its capabilities.
        
        Args:
            server_info: Basic server information
            process_info: Process information for the server
            
        Returns:
            MCPCapabilities if successful, None if failed
        """
        server_id = f"server_{process_info.pid}_{server_info.name}"
        
        # Update statistics
        self.transport_stats["total_introspections"] += 1
        
        try:
            self.logger.info(
                f"Starting introspection of server {server_id} "
                f"(PID: {process_info.pid}, Name: {server_info.name})"
            )
            
            # Validate input parameters
            if not self._validate_introspection_inputs(server_info, process_info):
                self.logger.error(f"Invalid input parameters for server {server_id}")
                return None
            
            # Convert legacy server info to new format
            try:
                server_config = self._convert_to_server_config(server_info, process_info)
                self.logger.debug(f"Converted server config for {server_id}: transport={server_config.transport_type}")
                
                # Update transport statistics
                transport_type = server_config.transport_type
                if transport_type == "stdio":
                    self.transport_stats["stdio_connections"] += 1
                elif transport_type == "http":
                    self.transport_stats["http_connections"] += 1
                elif transport_type == "sse":
                    self.transport_stats["sse_connections"] += 1
                    
            except Exception as e:
                self.logger.error(f"Failed to convert server config for {server_id}: {e}")
                self.transport_stats["failed_connections"] += 1
                return None
            
            # Perform introspection using the new system with detailed error handling
            try:
                introspection_result = self.introspection_system.introspect_server(server_config)
                self.logger.debug(f"Introspection completed for {server_id}, success: {introspection_result.success}")
            except TimeoutError as e:
                self.logger.error(f"Introspection timeout for server {server_id}: {e}")
                return None
            except ConnectionError as e:
                self.logger.error(f"Connection failed for server {server_id}: {e}")
                return None
            except ValueError as e:
                self.logger.error(f"Invalid configuration for server {server_id}: {e}")
                return None
            except Exception as e:
                self.logger.error(f"Unexpected error during introspection of {server_id}: {e}", exc_info=True)
                return None
            
            # Validate introspection result
            if not introspection_result.success:
                error_msg = introspection_result.metadata.get('error', 'Unknown error')
                self.logger.warning(f"Introspection failed for server {server_id}: {error_msg}")
                return None
            
            if not introspection_result.servers:
                self.logger.warning(f"No server information returned for {server_id}")
                return None
            
            # Convert back to legacy format for backward compatibility
            try:
                new_server_info = introspection_result.servers[0]
                
                # Validate server info before conversion
                if not self._validate_server_info(new_server_info):
                    self.logger.error(f"Invalid server information returned for {server_id}")
                    return None
                
                legacy_capabilities = MCPCapabilities.from_new_capabilities(new_server_info)
                
                self.logger.info(
                    f"Introspection successful for server {server_id}: "
                    f"{legacy_capabilities.tool_count} tools, "
                    f"{legacy_capabilities.resource_count} resources, "
                    f"risk level: {legacy_capabilities.highest_risk_level}, "
                    f"duration: {introspection_result.duration.total_seconds():.2f}s"
                )
                
                # Log detailed capability information at debug level
                self.logger.debug(
                    f"Server {server_id} capabilities: "
                    f"categories={legacy_capabilities.capability_categories}, "
                    f"external_access={legacy_capabilities.has_external_access}, "
                    f"file_access={legacy_capabilities.has_file_access}, "
                    f"code_execution={legacy_capabilities.has_code_execution}"
                )
                
                return legacy_capabilities
                
            except Exception as e:
                self.logger.error(f"Failed to convert introspection result for {server_id}: {e}", exc_info=True)
                return None
            
        except Exception as e:
            self.logger.error(f"Unexpected error in introspect_server for {server_id}: {e}", exc_info=True)
            self.transport_stats["failed_connections"] += 1
            return None
    
    def get_supported_transports(self) -> List[str]:
        """
        Get list of supported transport types.
        
        Returns:
            List of supported transport type names
        """
        return ["stdio", "http", "sse"]
    
    def get_transport_statistics(self) -> Dict[str, Any]:
        """
        Get transport usage statistics.
        
        Returns:
            Dictionary containing transport statistics
        """
        total_successful = (
            self.transport_stats["stdio_connections"] +
            self.transport_stats["http_connections"] +
            self.transport_stats["sse_connections"]
        )
        
        return {
            "total_introspections": self.transport_stats["total_introspections"],
            "successful_connections": total_successful,
            "failed_connections": self.transport_stats["failed_connections"],
            "success_rate": (total_successful / max(self.transport_stats["total_introspections"], 1)) * 100,
            "transport_breakdown": {
                "stdio": self.transport_stats["stdio_connections"],
                "http": self.transport_stats["http_connections"],
                "sse": self.transport_stats["sse_connections"]
            },
            "most_used_transport": self._get_most_used_transport()
        }
    
    def _get_most_used_transport(self) -> str:
        """Get the most frequently used transport type."""
        transport_counts = {
            "stdio": self.transport_stats["stdio_connections"],
            "http": self.transport_stats["http_connections"],
            "sse": self.transport_stats["sse_connections"]
        }
        
        if not any(transport_counts.values()):
            return "none"
        
        return max(transport_counts, key=transport_counts.get)
    
    def test_transport_connectivity(self, transport_type: str, server_config: MCPServerConfig) -> bool:
        """
        Test connectivity for a specific transport type.
        
        Args:
            transport_type: Type of transport to test
            server_config: Server configuration for testing
            
        Returns:
            True if transport can connect, False otherwise
        """
        try:
            self.logger.debug(f"Testing {transport_type} transport connectivity for {server_config.server_id}")
            
            # Get transport handler from factory
            transport_handler = self.transport_factory.create_transport(transport_type)
            
            if not transport_handler:
                self.logger.error(f"Failed to create {transport_type} transport handler")
                return False
            
            # Test basic connectivity (this would be implemented in the transport handler)
            # For now, we'll just validate the configuration
            if transport_type == "stdio":
                return bool(server_config.command and server_config.command.strip())
            elif transport_type == "http":
                return bool(server_config.metadata.get("port"))
            elif transport_type == "sse":
                return bool(server_config.metadata.get("endpoint_url"))
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Transport connectivity test failed for {transport_type}: {e}")
            return False
    
            def introspect_with_specific_transport(
        self, 
        server_info: MCPServerInfo, 
        process_info: ProcessInfo, 
        force_transport: str
    ) -> Optional[MCPCapabilities]:
        """
        Introspect a server using a specific transport type.
        
        Args:
            server_info: Basic server information
            process_info: Process information for the server
            force_transport: Transport type to force use
            
        Returns:
            MCPCapabilities if successful, None if failed
        """
        if force_transport not in self.get_supported_transports():
            self.logger.error(f"Unsupported transport type: {force_transport}")
            return None
        
        try:
            # Create modified server config with forced transport
            server_config = self._convert_to_server_config(server_info, process_info)
            server_config.transport_type = force_transport
            
            # Update metadata to reflect forced transport
            server_config.metadata["forced_transport"] = True
            server_config.metadata["original_transport"] = server_config.transport_type
            
            self.logger.info(f"Forcing {force_transport} transport for server {server_config.server_id}")
            
            # Perform introspection with forced transport
            introspection_result = self.introspection_system.introspect_server(server_config)
            
            if not introspection_result.success or not introspection_result.servers:
                return None
            
            # Convert back to legacy format
            new_server_info = introspection_result.servers[0]
            return MCPCapabilities.from_new_capabilities(new_server_info)
            
        except Exception as e:
            self.logger.error(f"Failed to introspect with {force_transport} transport: {e}")
            return None
    
    def discover_tools_only(self, server_info: MCPServerInfo, process_info: ProcessInfo) -> List[MCPTool]:
        """
        Discover only the tools available on an MCP server.
        
        Args:
            server_info: Basic server information
            process_info: Process information for the server
            
        Returns:
            List of discovered tools
        """
        try:
            server_config = self._convert_to_server_config(server_info, process_info)
            
            # Use direct tool discovery
            tools = self.tool_discovery.discover_tools(server_config)
            
            # Update statistics
            self.discovery_stats["tools_discovered"] += len(tools)
            
            # Convert to legacy format
            legacy_tools = [MCPTool.from_new_tool(tool) for tool in tools]
            
            self.logger.info(f"Discovered {len(legacy_tools)} tools for server {server_config.server_id}")
            return legacy_tools
            
        except Exception as e:
            self.logger.error(f"Failed to discover tools: {e}")
            self.discovery_stats["discovery_failures"] += 1
            return []
    
    def discover_resources_only(self, server_info: MCPServerInfo, process_info: ProcessInfo) -> List[MCPResource]:
        """
        Discover only the resources available on an MCP server.
        
        Args:
            server_info: Basic server information
            process_info: Process information for the server
            
        Returns:
            List of discovered resources
        """
        try:
            server_config = self._convert_to_server_config(server_info, process_info)
            
            # Use direct resource discovery
            resources = self.resource_discovery.discover_resources(server_config)
            
            # Update statistics
            self.discovery_stats["resources_discovered"] += len(resources)
            
            # Convert to legacy format
            legacy_resources = [MCPResource.from_new_resource(resource) for resource in resources]
            
            self.logger.info(f"Discovered {len(legacy_resources)} resources for server {server_config.server_id}")
            return legacy_resources
            
        except Exception as e:
            self.logger.error(f"Failed to discover resources: {e}")
            self.discovery_stats["discovery_failures"] += 1
            return []
    
    def discover_capabilities_only(self, server_info: MCPServerInfo, process_info: ProcessInfo) -> Dict[str, Any]:
        """
        Discover only the capabilities of an MCP server.
        
        Args:
            server_info: Basic server information
            process_info: Process information for the server
            
        Returns:
            Dictionary of discovered capabilities
        """
        try:
            server_config = self._convert_to_server_config(server_info, process_info)
            
            # Use direct capability discovery
            capabilities = self.capability_discovery.discover_capabilities(server_config)
            
            # Update statistics
            self.discovery_stats["capabilities_discovered"] += len(capabilities)
            
            self.logger.info(f"Discovered {len(capabilities)} capabilities for server {server_config.server_id}")
            return capabilities
            
        except Exception as e:
            self.logger.error(f"Failed to discover capabilities: {e}")
            self.discovery_stats["discovery_failures"] += 1
            return {}
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """
        Get discovery usage statistics.
        
        Returns:
            Dictionary containing discovery statistics
        """
        total_discoveries = (
            self.discovery_stats["tools_discovered"] +
            self.discovery_stats["resources_discovered"] +
            self.discovery_stats["capabilities_discovered"]
        )
        
        return {
            "total_discoveries": total_discoveries,
            "tools_discovered": self.discovery_stats["tools_discovered"],
            "resources_discovered": self.discovery_stats["resources_discovered"],
            "capabilities_discovered": self.discovery_stats["capabilities_discovered"],
            "discovery_failures": self.discovery_stats["discovery_failures"],
            "discovery_timeouts": self.discovery_stats["discovery_timeouts"],
            "success_rate": (
                (total_discoveries / max(total_discoveries + self.discovery_stats["discovery_failures"], 1)) * 100
            ),
            "average_tools_per_server": (
                self.discovery_stats["tools_discovered"] / max(self.transport_stats["total_introspections"], 1)
            ),
            "average_resources_per_server": (
                self.discovery_stats["resources_discovered"] / max(self.transport_stats["total_introspections"], 1)
            )
        }
    
    def introspect_multiple_servers(
        self, 
        server_list: List[Tuple[MCPServerInfo, ProcessInfo]]
    ) -> List[Optional[MCPCapabilities]]:
        """
        Introspect multiple MCP servers sequentially.
        
        Args:
            server_list: List of (server_info, process_info) tuples
            
        Returns:
            List of MCPCapabilities (None for failed introspections)
        """
        results = []
        
        self.logger.info(f"Starting batch introspection of {len(server_list)} servers")
        
        for i, (server_info, process_info) in enumerate(server_list):
            try:
                self.logger.debug(f"Processing server {i+1}/{len(server_list)}: {server_info.name}")
                
                capabilities = self.introspect_server(server_info, process_info)
                results.append(capabilities)
                
                if capabilities:
                    self.logger.debug(f"Server {i+1} introspection successful")
                else:
                    self.logger.warning(f"Server {i+1} introspection failed")
                    
            except Exception as e:
                self.logger.error(f"Error introspecting server {i+1}: {e}")
                results.append(None)
        
        successful_count = sum(1 for result in results if result is not None)
        self.logger.info(
            f"Batch introspection complete: {successful_count}/{len(server_list)} successful"
        )
        
        return results
    
    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics combining transport and discovery metrics.
        
        Returns:
            Dictionary containing all statistics
        """
        return {
            "transport_statistics": self.get_transport_statistics(),
            "discovery_statistics": self.get_discovery_statistics(),
            "overall_performance": {
                "total_operations": self.transport_stats["total_introspections"],
                "overall_success_rate": self._calculate_overall_success_rate(),
                "most_used_transport": self._get_most_used_transport(),
                "average_discoveries_per_introspection": self._calculate_average_discoveries()
            }
        }
    
    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate across all operations."""
        total_operations = self.transport_stats["total_introspections"]
        if total_operations == 0:
            return 0.0
        
        successful_operations = total_operations - self.transport_stats["failed_connections"]
        return (successful_operations / total_operations) * 100
    
    def _calculate_average_discoveries(self) -> float:
        """Calculate average number of discoveries per introspection."""
        total_introspections = self.transport_stats["total_introspections"]
        if total_introspections == 0:
            return 0.0
        
        total_discoveries = (
            self.discovery_stats["tools_discovered"] +
            self.discovery_stats["resources_discovered"] +
            self.discovery_stats["capabilities_discovered"]
        )
        
        return total_discoveries / total_introspections
    
    def analyze_server_risks(self, capabilities: MCPCapabilities) -> Dict[str, Any]:
        """
        Perform comprehensive risk analysis on server capabilities.
        
        Args:
            capabilities: Server capabilities to analyze
            
        Returns:
            Dictionary containing risk analysis results
        """
        try:
            # Convert legacy capabilities to new format for risk analysis
            new_tools = [self._convert_legacy_tool_to_new(tool) for tool in capabilities.tools]
            
            # Perform tool risk analysis
            tool_risks = []
            for tool in new_tools:
                risk_analysis = self.tool_risk_analyzer.analyze_tool_risk(tool)
                tool_risks.append(risk_analysis)
            
            # Perform threat modeling
            threat_analysis = self.threat_model_analyzer.analyze_threats(new_tools)
            
            # Categorize risks
            risk_categories = self.risk_categorizer.categorize_risks(tool_risks)
            
            # Calculate risk scores
            risk_scores = self.risk_scorer.calculate_risk_scores(tool_risks, threat_analysis)
            
            # Generate risk report
            risk_report = self.risk_reporter.generate_risk_report(
                tool_risks, threat_analysis, risk_categories, risk_scores
            )
            
            self.logger.info(
                f"Risk analysis complete for {capabilities.server_name}: "
                f"overall risk level {risk_scores.get('overall_risk_level', 'unknown')}"
            )
            
            return {
                "server_name": capabilities.server_name,
                "tool_risks": tool_risks,
                "threat_analysis": threat_analysis,
                "risk_categories": risk_categories,
                "risk_scores": risk_scores,
                "risk_report": risk_report,
                "analysis_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze server risks: {e}")
            return {
                "error": f"Risk analysis failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def _convert_legacy_tool_to_new(self, legacy_tool: MCPTool) -> 'NewMCPTool':
        """Convert legacy MCPTool to new format for risk analysis."""
        # This is a simplified conversion - in practice, you'd need to import the actual NewMCPTool class
        # For now, we'll create a mock object with the required attributes
        class MockNewTool:
            def __init__(self, name, description, input_schema):
                self.name = name
                self.description = description
                self.input_schema = input_schema
        
        return MockNewTool(legacy_tool.name, legacy_tool.description, legacy_tool.input_schema)
    
    def get_risk_summary(self, capabilities: MCPCapabilities) -> Dict[str, Any]:
        """
        Get a quick risk summary for server capabilities.
        
        Args:
            capabilities: Server capabilities to summarize
            
        Returns:
            Dictionary containing risk summary
        """
        try:
            risk_analysis = self.analyze_server_risks(capabilities)
            
            if "error" in risk_analysis:
                return risk_analysis
            
            # Extract key risk metrics
            risk_scores = risk_analysis.get("risk_scores", {})
            risk_categories = risk_analysis.get("risk_categories", {})
            
            return {
                "server_name": capabilities.server_name,
                "overall_risk_level": risk_scores.get("overall_risk_level", "unknown"),
                "risk_score": risk_scores.get("composite_score", 0),
                "high_risk_tools": len([
                    tool for tool in capabilities.tools 
                    if tool.risk_level in ["high", "critical"]
                ]),
                "critical_risk_tools": len([
                    tool for tool in capabilities.tools 
                    if tool.risk_level == "critical"
                ]),
                "risk_categories": list(risk_categories.keys()),
                "has_file_access": capabilities.has_file_access,
                "has_network_access": capabilities.has_external_access,
                "has_code_execution": capabilities.has_code_execution,
                "total_tools": capabilities.tool_count,
                "summary_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate risk summary: {e}")
            return {
                "error": f"Risk summary generation failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    def introspect_with_risk_analysis(
        self, 
        server_info: MCPServerInfo, 
        process_info: ProcessInfo
    ) -> Optional[Dict[str, Any]]:
        """
        Perform introspection with comprehensive risk analysis.
        
        Args:
            server_info: Basic server information
            process_info: Process information for the server
            
        Returns:
            Dictionary containing capabilities and risk analysis, None if failed
        """
        try:
            # Perform standard introspection
            capabilities = self.introspect_server(server_info, process_info)
            
            if not capabilities:
                return None
            
            # Perform risk analysis
            risk_analysis = self.analyze_server_risks(capabilities)
            
            # Combine results
            return {
                "capabilities": {
                    "server_name": capabilities.server_name,
                    "server_version": capabilities.server_version,
                    "protocol_version": capabilities.protocol_version,
                    "tool_count": capabilities.tool_count,
                    "resource_count": capabilities.resource_count,
                    "capability_categories": capabilities.capability_categories,
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "category": tool.capability_category,
                            "risk_level": tool.risk_level
                        }
                        for tool in capabilities.tools
                    ],
                    "resources": [
                        {
                            "uri": resource.uri,
                            "name": resource.name,
                            "description": resource.description
                        }
                        for resource in capabilities.resources
                    ]
                },
                "risk_analysis": risk_analysis,
                "introspection_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "method": "python_synchronous_with_risk_analysis",
                    "server_id": f"server_{process_info.pid}_{server_info.name}"
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to perform introspection with risk analysis: {e}")
            return None
    
    def _convert_to_server_config(self, server_info: MCPServerInfo, process_info: ProcessInfo) -> MCPServerConfig:
        """
        Convert legacy server info to new MCPServerConfig format.
        
        Args:
            server_info: Legacy server information
            process_info: Process information
            
        Returns:
            MCPServerConfig for the new introspection system
            
        Raises:
            ValueError: If conversion fails due to invalid data
        """
        try:
            # Generate a unique server ID with sanitization
            safe_name = ''.join(c for c in server_info.name if c.isalnum() or c in '-_')[:50]
            server_id = f"server_{process_info.pid}_{safe_name}"
            
            # Determine transport type with validation
            transport_type = "stdio"  # Default to stdio
            if server_info.port is not None:
                if not isinstance(server_info.port, int) or server_info.port <= 0 or server_info.port > 65535:
                    raise ValueError(f"Invalid port number: {server_info.port}")
                transport_type = "http"
            elif server_info.endpoint_url is not None:
                if not isinstance(server_info.endpoint_url, str) or not server_info.endpoint_url.strip():
                    raise ValueError(f"Invalid endpoint URL: {server_info.endpoint_url}")
                transport_type = "sse"
            
            # Validate and prepare command
            if not process_info.cmdline or len(process_info.cmdline) == 0:
                raise ValueError("Process command line is empty")
            
            command = process_info.cmdline[0]
            if not command or not isinstance(command, str):
                raise ValueError(f"Invalid command: {command}")
            
            args = process_info.cmdline[1:] if len(process_info.cmdline) > 1 else []
            
            # Validate working directory
            working_directory = process_info.cwd
            if working_directory and not isinstance(working_directory, str):
                self.logger.warning(f"Invalid working directory type: {type(working_directory)}, using None")
                working_directory = None
            
            # Validate timeout
            timeout = self.introspection_config.timeout
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                self.logger.warning(f"Invalid timeout: {timeout}, using default 180.0")
                timeout = 180.0
            
            # Create server configuration with error handling
            try:
                server_config = MCPServerConfig(
                    server_id=server_id,
                    name=server_info.name,
                    command=command,
                    args=args,
                    transport_type=transport_type,
                    working_directory=working_directory,
                    environment_variables={},
                    timeout=timeout,
                    metadata={
                        "pid": process_info.pid,
                        "port": server_info.port,
                        "endpoint_url": server_info.endpoint_url,
                        "config_file": getattr(server_info, 'config_file', None),
                        "legacy_conversion": True,
                        "conversion_timestamp": datetime.now().isoformat()
                    }
                )
                
                self.logger.debug(
                    f"Successfully converted server config: {server_id}, "
                    f"transport={transport_type}, command={command}"
                )
                
                return server_config
                
            except Exception as e:
                raise ValueError(f"Failed to create MCPServerConfig: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to convert server config: {e}")
            raise ValueError(f"Server config conversion failed: {e}")
    
    def _validate_introspection_inputs(self, server_info: MCPServerInfo, process_info: ProcessInfo) -> bool:
        """
        Validate input parameters for introspection.
        
        Args:
            server_info: Server information to validate
            process_info: Process information to validate
            
        Returns:
            True if inputs are valid, False otherwise
        """
        try:
            # Validate server_info
            if not server_info:
                self.logger.error("Server info is None")
                return False
            
            if not server_info.name or not isinstance(server_info.name, str):
                self.logger.error("Server name is missing or invalid")
                return False
            
            # Validate process_info
            if not process_info:
                self.logger.error("Process info is None")
                return False
            
            if not process_info.pid or not isinstance(process_info.pid, int) or process_info.pid <= 0:
                self.logger.error(f"Invalid process PID: {process_info.pid}")
                return False
            
            if not process_info.cmdline or not isinstance(process_info.cmdline, list):
                self.logger.error("Process command line is missing or invalid")
                return False
            
            # Validate command line has at least one element
            if len(process_info.cmdline) == 0:
                self.logger.error("Process command line is empty")
                return False
            
            # Validate working directory if provided
            if process_info.cwd and not isinstance(process_info.cwd, str):
                self.logger.error("Process working directory is invalid")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating introspection inputs: {e}")
            return False
    
    def _validate_server_info(self, server_info: 'NewMCPServerInfo') -> bool:
        """
        Validate server information returned from introspection.
        
        Args:
            server_info: Server information to validate
            
        Returns:
            True if server info is valid, False otherwise
        """
        try:
            if not server_info:
                self.logger.error("Server info is None")
                return False
            
            # Validate required fields
            if not hasattr(server_info, 'server_name') or not server_info.server_name:
                self.logger.error("Server name is missing")
                return False
            
            if not hasattr(server_info, 'tools') or not isinstance(server_info.tools, list):
                self.logger.error("Server tools list is missing or invalid")
                return False
            
            if not hasattr(server_info, 'resources') or not isinstance(server_info.resources, list):
                self.logger.error("Server resources list is missing or invalid")
                return False
            
            if not hasattr(server_info, 'capabilities') or not isinstance(server_info.capabilities, dict):
                self.logger.error("Server capabilities dict is missing or invalid")
                return False
            
            # Validate tools structure
            for i, tool in enumerate(server_info.tools):
                if not hasattr(tool, 'name') or not tool.name:
                    self.logger.error(f"Tool {i} is missing name")
                    return False
                
                if not hasattr(tool, 'description'):
                    self.logger.error(f"Tool {i} ({tool.name}) is missing description")
                    return False
                
                if not hasattr(tool, 'input_schema') or not isinstance(tool.input_schema, dict):
                    self.logger.error(f"Tool {i} ({tool.name}) has invalid input schema")
                    return False
            
            # Validate resources structure
            for i, resource in enumerate(server_info.resources):
                if not hasattr(resource, 'uri') or not resource.uri:
                    self.logger.error(f"Resource {i} is missing URI")
                    return False
                
                if not hasattr(resource, 'name') or not resource.name:
                    self.logger.error(f"Resource {i} is missing name")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating server info: {e}")
            return False
    
    def _is_stdio_server(self, process_info: ProcessInfo) -> bool:
        """Check if server uses stdio transport (legacy method)."""
        cmdline_str = ' '.join(process_info.cmdline).lower()
        return 'stdio' in cmdline_str or not any(port in cmdline_str for port in ['port', 'http', 'ws'])
    
    def _is_http_server(self, server_info: MCPServerInfo) -> bool:
        """Check if server uses HTTP transport (legacy method)."""
        return server_info.port is not None or server_info.endpoint_url is not None
    
    def generate_server_summary(self, capabilities: MCPCapabilities) -> Dict[str, Any]:
        """
        Generate a comprehensive summary of server capabilities.
        
        Args:
            capabilities: Server capabilities to summarize
            
        Returns:
            Dictionary containing server summary information
        """
        try:
            # Calculate risk metrics
            risk_distribution = {}
            for tool in capabilities.tools:
                risk_level = tool.risk_level
                risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
            
            # Calculate capability distribution
            capability_distribution = {}
            for category in capabilities.capability_categories:
                capability_distribution[category] = sum(
                    1 for tool in capabilities.tools if tool.capability_category == category
                )
            
            summary = {
                "server_info": {
                    "name": capabilities.server_name,
                    "version": capabilities.server_version,
                    "protocol_version": capabilities.protocol_version
                },
                "capabilities_overview": {
                    "total_tools": capabilities.tool_count,
                    "total_resources": capabilities.resource_count,
                    "capability_categories": capabilities.capability_categories,
                    "highest_risk_level": capabilities.highest_risk_level
                },
                "security_assessment": {
                    "has_external_access": capabilities.has_external_access,
                    "has_file_access": capabilities.has_file_access,
                    "has_code_execution": capabilities.has_code_execution,
                    "risk_distribution": risk_distribution
                },
                "detailed_capabilities": {
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "category": tool.capability_category,
                            "risk_level": tool.risk_level,
                            "input_schema_keys": list(tool.input_schema.get("properties", {}).keys())
                        }
                        for tool in capabilities.tools
                    ],
                    "resources": [
                        {
                            "uri": resource.uri,
                            "name": resource.name,
                            "description": resource.description,
                            "mime_type": resource.mime_type
                        }
                        for resource in capabilities.resources
                    ]
                },
                "capability_distribution": capability_distribution,
                "introspection_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "introspection_method": "python_synchronous",
                    "legacy_compatibility": True
                }
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to generate server summary: {e}")
            return {
                "error": f"Failed to generate summary: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }


class MCPRegistryClient:
    """Client for interacting with MCP registry services (legacy compatibility)."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.logger.warning("MCPRegistryClient is deprecated and may be removed in future versions")
    
    def discover_available_tools(self) -> List[Dict[str, Any]]:
        """Discover available MCP tools from registry (legacy method)."""
        self.logger.warning("Registry-based tool discovery is deprecated")
        return []
    
    def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific tool (legacy method)."""
        self.logger.warning("Registry-based tool metadata is deprecated")
        return None


def enhance_mcp_server_info(server_info: MCPServerInfo, process_info: ProcessInfo) -> MCPServerInfo:
    """
    Enhance server information with additional metadata (legacy compatibility).
    
    Args:
        server_info: Basic server information
        process_info: Process information
        
    Returns:
        Enhanced server information
    """
    logger = get_logger(__name__)
    
    try:
        # Create enhanced copy
        enhanced_info = MCPServerInfo(
            name=server_info.name,
            port=server_info.port,
            endpoint_url=server_info.endpoint_url,
            config_file=server_info.config_file,
            process_id=process_info.pid,
            command_line=' '.join(process_info.cmdline),
            working_directory=process_info.cwd,
            environment_variables={},  # Could be enhanced with actual env vars
            capabilities=[],  # Will be populated by introspection
            risk_level="unknown",  # Will be determined by introspection
            last_seen=datetime.now(),
            metadata={
                "enhanced_by": "python_introspection_system",
                "enhancement_timestamp": datetime.now().isoformat(),
                "process_info_available": True
            }
        )
        
        logger.debug(f"Enhanced server info for {server_info.name}")
        return enhanced_info
        
    except Exception as e:
        logger.error(f"Failed to enhance server info: {e}")
        return server_info


def get_dynamic_server_catalog() -> Dict[str, Dict[str, Any]]:
    """
    Get a dynamic catalog of discovered MCP servers (legacy compatibility).
    
    Returns:
        Dictionary mapping server names to their metadata
    """
    logger = get_logger(__name__)
    logger.warning("Dynamic server catalog is deprecated, use MCPIntrospection system directly")
    
    return {
        "catalog_info": {
            "deprecated": True,
            "replacement": "MCPIntrospection.introspect_multiple_servers",
            "timestamp": datetime.now().isoformat()
        }
    } 