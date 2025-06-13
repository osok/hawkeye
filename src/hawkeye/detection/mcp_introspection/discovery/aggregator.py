"""
Server Information Aggregator Module

Aggregates discovery results from tools, resources, and capabilities
into comprehensive server information using synchronous methods.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..models import (
    MCPServerInfo,
    MCPTool,
    MCPResource,
    MCPCapability,
    SecurityRisk,
    RiskLevel,
    DiscoveryResult
)
from ..utils import ErrorHandler
from .tools import ToolDiscovery, ToolDiscoveryConfig
from .resources import ResourceDiscovery, ResourceDiscoveryConfig
from .capabilities import CapabilityAssessment, CapabilityAssessmentConfig


logger = logging.getLogger(__name__)


@dataclass
class AggregatorConfig:
    """Configuration for server information aggregation."""
    timeout: float = 120.0  # Longer timeout for complete discovery
    enable_parallel_discovery: bool = False  # Disabled since we're synchronous
    enable_risk_aggregation: bool = True
    tool_discovery_config: Optional[ToolDiscoveryConfig] = None
    resource_discovery_config: Optional[ResourceDiscoveryConfig] = None
    capability_assessment_config: Optional[CapabilityAssessmentConfig] = None
    
    def __post_init__(self):
        if self.tool_discovery_config is None:
            self.tool_discovery_config = ToolDiscoveryConfig()
        if self.resource_discovery_config is None:
            self.resource_discovery_config = ResourceDiscoveryConfig()
        if self.capability_assessment_config is None:
            self.capability_assessment_config = CapabilityAssessmentConfig()


class ServerInfoAggregator:
    """
    Aggregates discovery results from multiple sources into comprehensive
    server information using synchronous methods.
    
    Coordinates tool discovery, resource discovery, and capability assessment
    to provide complete MCP server analysis.
    """
    
    def __init__(self, config: Optional[AggregatorConfig] = None):
        """
        Initialize server information aggregator.
        
        Args:
            config: Aggregation configuration options
        """
        self.config = config or AggregatorConfig()
        self.error_handler = ErrorHandler()
        
        # Initialize discovery components
        self.tool_discovery = ToolDiscovery(self.config.tool_discovery_config)
        self.resource_discovery = ResourceDiscovery(self.config.resource_discovery_config)
        self.capability_assessment = CapabilityAssessment(self.config.capability_assessment_config)
        
        self._aggregation_cache: Dict[str, MCPServerInfo] = {}
        
    def aggregate_server_info(
        self,
        server_command: List[str],
        server_id: str,
        server_url: Optional[str] = None
    ) -> MCPServerInfo:
        """
        Aggregate comprehensive server information.
        
        Args:
            server_command: Command to start the MCP server
            server_id: Unique identifier for the server
            server_url: Optional server URL for metadata
            
        Returns:
            MCPServerInfo with aggregated discovery results
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting server information aggregation for {server_id}")
            
            # Check cache first
            if server_id in self._aggregation_cache:
                cached_info = self._aggregation_cache[server_id]
                if self._is_cache_valid(cached_info):
                    logger.debug(f"Using cached server info for {server_id}")
                    return cached_info
            
            # Perform discovery with timeout
            discovery_start = time.time()
            discovery_results = self._sequential_discovery(server_command, server_id)
            
            # Check overall timeout
            if time.time() - discovery_start > self.config.timeout:
                raise TimeoutError("Server aggregation timeout")
            
            # Aggregate results
            server_info = self._aggregate_results(
                server_id, server_url, discovery_results, start_time
            )
            
            # Cache result
            self._aggregation_cache[server_id] = server_info
            
            aggregation_time = datetime.now() - start_time
            logger.info(
                f"Server information aggregation complete for {server_id}: "
                f"{len(server_info.tools)} tools, {len(server_info.resources)} resources, "
                f"{len(server_info.capabilities)} capabilities, "
                f"{len(server_info.security_risks)} risks, "
                f"{aggregation_time.total_seconds():.2f}s"
            )
            
            return server_info
            
        except TimeoutError:
            logger.error(f"Server information aggregation timeout for {server_id}")
            return self._create_error_server_info(
                server_id, server_url, start_time, "Aggregation timeout"
            )
            
        except Exception as e:
            logger.error(f"Unexpected error during server aggregation for {server_id}: {e}")
            return self._create_error_server_info(
                server_id, server_url, start_time, f"Unexpected error: {str(e)}"
            )
    
    def _sequential_discovery(
        self,
        server_command: List[str],
        server_id: str
    ) -> Dict[str, DiscoveryResult]:
        """
        Perform sequential discovery of tools, resources, and capabilities.
        
        Args:
            server_command: Command to start the MCP server
            server_id: Server identifier
            
        Returns:
            Dictionary of discovery results by type
        """
        logger.debug(f"Starting sequential discovery for {server_id}")
        
        results = {}
        
        # Tool discovery
        try:
            results['tools'] = self.tool_discovery.discover_tools(server_command, server_id)
        except Exception as e:
            logger.warning(f"Tool discovery failed for {server_id}: {e}")
            results['tools'] = self._create_error_discovery_result(server_id, 'tools', str(e))
        
        # Resource discovery
        try:
            results['resources'] = self.resource_discovery.discover_resources(server_command, server_id)
        except Exception as e:
            logger.warning(f"Resource discovery failed for {server_id}: {e}")
            results['resources'] = self._create_error_discovery_result(server_id, 'resources', str(e))
        
        # Capability assessment
        try:
            results['capabilities'] = self.capability_assessment.assess_capabilities(server_command, server_id)
        except Exception as e:
            logger.warning(f"Capability assessment failed for {server_id}: {e}")
            results['capabilities'] = self._create_error_discovery_result(server_id, 'capabilities', str(e))
        
        return results
    
    def _aggregate_results(
        self,
        server_id: str,
        server_url: Optional[str],
        discovery_results: Dict[str, DiscoveryResult],
        start_time: datetime
    ) -> MCPServerInfo:
        """
        Aggregate discovery results into server information.
        
        Args:
            server_id: Server identifier
            server_url: Optional server URL
            discovery_results: Discovery results by type
            start_time: Aggregation start time
            
        Returns:
            MCPServerInfo with aggregated data
        """
        # Collect all data
        all_tools = []
        all_resources = []
        all_capabilities = []
        all_security_risks = []
        
        # Aggregate tools
        tools_result = discovery_results.get('tools')
        if tools_result and tools_result.success:
            all_tools.extend(tools_result.tools or [])
            all_security_risks.extend(tools_result.security_risks or [])
        
        # Aggregate resources
        resources_result = discovery_results.get('resources')
        if resources_result and resources_result.success:
            all_resources.extend(resources_result.resources or [])
            all_security_risks.extend(resources_result.security_risks or [])
        
        # Aggregate capabilities
        capabilities_result = discovery_results.get('capabilities')
        if capabilities_result and capabilities_result.success:
            all_capabilities.extend(capabilities_result.capabilities or [])
            all_security_risks.extend(capabilities_result.security_risks or [])
        
        # Perform risk aggregation if enabled
        if self.config.enable_risk_aggregation:
            aggregated_risks = self._aggregate_risks(
                all_tools, all_resources, all_capabilities, all_security_risks
            )
            all_security_risks = aggregated_risks
        
        # Calculate overall risk level
        overall_risk = self._calculate_overall_risk(all_security_risks)
        
        # Create server info
        aggregation_time = datetime.now() - start_time
        server_info = MCPServerInfo(
            server_id=server_id,
            server_url=server_url,
            discovery_timestamp=start_time,
            tools=all_tools,
            resources=all_resources,
            capabilities=all_capabilities,
            security_risks=all_security_risks,
            overall_risk_level=overall_risk,
            metadata={
                "aggregation_duration": aggregation_time.total_seconds(),
                "discovery_results": {
                    "tools_success": discovery_results.get('tools', DiscoveryResult(
                        server_id="", discovery_type="", timestamp=datetime.now(),
                        duration=timedelta(0), success=False, tools=[], resources=[],
                        capabilities=[], security_risks=[], metadata={}
                    )).success,
                    "resources_success": discovery_results.get('resources', DiscoveryResult(
                        server_id="", discovery_type="", timestamp=datetime.now(),
                        duration=timedelta(0), success=False, tools=[], resources=[],
                        capabilities=[], security_risks=[], metadata={}
                    )).success,
                    "capabilities_success": discovery_results.get('capabilities', DiscoveryResult(
                        server_id="", discovery_type="", timestamp=datetime.now(),
                        duration=timedelta(0), success=False, tools=[], resources=[],
                        capabilities=[], security_risks=[], metadata={}
                    )).success
                },
                "parallel_discovery": False,  # Always false for synchronous implementation
                "risk_aggregation": self.config.enable_risk_aggregation
            }
        )
        
        return server_info
    
    def _aggregate_risks(
        self,
        tools: List[MCPTool],
        resources: List[MCPResource],
        capabilities: List[MCPCapability],
        existing_risks: List[SecurityRisk]
    ) -> List[SecurityRisk]:
        """
        Aggregate and deduplicate security risks.
        
        Args:
            tools: Discovered tools
            resources: Discovered resources
            capabilities: Discovered capabilities
            existing_risks: Existing security risks
            
        Returns:
            Aggregated and deduplicated security risks
        """
        # Start with existing risks
        aggregated_risks = list(existing_risks)
        
        # Add cross-component risks
        
        # Check for dangerous tool + resource combinations
        if tools and resources:
            file_tools = [t for t in tools if any(
                pattern in t.name.lower() 
                for pattern in ['file', 'write', 'delete', 'create']
            )]
            file_resources = [r for r in resources if 
                             r.metadata.get('uri_scheme') in ['file', 'local']]
            
            if file_tools and file_resources:
                aggregated_risks.append(SecurityRisk(
                    category="file_access_combination",
                    severity=RiskLevel.HIGH,
                    description="Server has both file manipulation tools and file system resources",
                    details={
                        "file_tools": [t.name for t in file_tools],
                        "file_resources": [r.uri for r in file_resources]
                    },
                    mitigation="Implement strict file access controls and path validation"
                ))
        
        # Check for network tool + resource combinations
        if tools and resources:
            network_tools = [t for t in tools if any(
                pattern in t.name.lower() 
                for pattern in ['http', 'request', 'fetch', 'download', 'upload']
            )]
            network_resources = [r for r in resources if 
                               r.metadata.get('uri_scheme') in ['http', 'https', 'ftp']]
            
            if network_tools and network_resources:
                aggregated_risks.append(SecurityRisk(
                    category="network_access_combination",
                    severity=RiskLevel.MEDIUM,
                    description="Server has both network tools and network resources",
                    details={
                        "network_tools": [t.name for t in network_tools],
                        "network_resources": [r.uri for r in network_resources]
                    },
                    mitigation="Implement network access controls and URL validation"
                ))
        
        # Deduplicate risks by category and description
        seen_risks = set()
        deduplicated_risks = []
        
        for risk in aggregated_risks:
            risk_key = (risk.category, risk.description)
            if risk_key not in seen_risks:
                seen_risks.add(risk_key)
                deduplicated_risks.append(risk)
        
        return deduplicated_risks
    
    def _calculate_overall_risk(self, security_risks: List[SecurityRisk]) -> RiskLevel:
        """
        Calculate overall risk level from individual risks.
        
        Args:
            security_risks: List of security risks
            
        Returns:
            Overall risk level
        """
        if not security_risks:
            return RiskLevel.LOW
        
        # Count risks by severity
        risk_counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0
        }
        
        for risk in security_risks:
            risk_counts[risk.severity] += 1
        
        # Determine overall risk
        if risk_counts[RiskLevel.CRITICAL] > 0:
            return RiskLevel.CRITICAL
        elif risk_counts[RiskLevel.HIGH] >= 3:
            return RiskLevel.CRITICAL
        elif risk_counts[RiskLevel.HIGH] > 0:
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] >= 5:
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] > 0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _create_error_discovery_result(
        self,
        server_id: str,
        discovery_type: str,
        error_message: str
    ) -> DiscoveryResult:
        """
        Create error discovery result.
        
        Args:
            server_id: Server identifier
            discovery_type: Type of discovery
            error_message: Error description
            
        Returns:
            DiscoveryResult with error information
        """
        return DiscoveryResult(
            server_id=server_id,
            discovery_type=discovery_type,
            timestamp=datetime.now(),
            duration=timedelta(0),
            success=False,
            error=error_message,
            tools=[],
            resources=[],
            capabilities=[],
            security_risks=[],
            metadata={
                "error": True,
                "error_message": error_message
            }
        )
    
    def _create_error_server_info(
        self,
        server_id: str,
        server_url: Optional[str],
        start_time: datetime,
        error_message: str
    ) -> MCPServerInfo:
        """
        Create error server info.
        
        Args:
            server_id: Server identifier
            server_url: Optional server URL
            start_time: Aggregation start time
            error_message: Error description
            
        Returns:
            MCPServerInfo with error information
        """
        return MCPServerInfo(
            server_id=server_id,
            server_url=server_url,
            discovery_timestamp=start_time,
            tools=[],
            resources=[],
            capabilities=[],
            security_risks=[],
            overall_risk_level=RiskLevel.LOW,
            metadata={
                "error": True,
                "error_message": error_message,
                "aggregation_duration": (datetime.now() - start_time).total_seconds()
            }
        )
    
    def _is_cache_valid(self, server_info: MCPServerInfo) -> bool:
        """
        Check if cached server info is still valid.
        
        Args:
            server_info: Cached server info
            
        Returns:
            True if cache is valid, False otherwise
        """
        # Cache valid for 15 minutes
        cache_ttl = timedelta(minutes=15)
        return datetime.now() - server_info.discovery_timestamp < cache_ttl
    
    def clear_cache(self, server_id: Optional[str] = None):
        """
        Clear aggregation cache.
        
        Args:
            server_id: Specific server to clear, or None for all
        """
        if server_id:
            self._aggregation_cache.pop(server_id, None)
            logger.debug(f"Cleared aggregation cache for {server_id}")
        else:
            self._aggregation_cache.clear()
            logger.debug("Cleared all aggregation cache")
        
        # Also clear component caches
        self.tool_discovery.clear_cache(server_id)
        self.resource_discovery.clear_cache(server_id)
        self.capability_assessment.clear_cache(server_id) 