"""
MCP Introspection Module

Main module for MCP server introspection and analysis.
Provides comprehensive server discovery, analysis, and reporting
using synchronous methods to avoid async complexity.
"""

import logging
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import (
    MCPServerInfo,
    MCPServerConfig,
    IntrospectionResult,
    RiskLevel
)
from .utils import ErrorHandler
from .discovery.aggregator import ServerInfoAggregator, AggregatorConfig
from .transport.factory import TransportFactory


logger = logging.getLogger(__name__)


@dataclass
class IntrospectionConfig:
    """Configuration for MCP introspection operations."""
    timeout: float = 180.0  # Extended timeout for complete introspection
    max_concurrent_servers: int = 1  # Disabled since we're synchronous
    enable_detailed_analysis: bool = True
    enable_risk_assessment: bool = True
    aggregator_config: Optional[AggregatorConfig] = None
    
    def __post_init__(self):
        if self.aggregator_config is None:
            self.aggregator_config = AggregatorConfig()


class MCPIntrospection:
    """
    Main MCP introspection system.
    
    Provides comprehensive analysis of MCP servers including:
    - Server discovery and connection
    - Tool, resource, and capability enumeration
    - Security risk assessment
    - Detailed reporting and analysis
    
    Uses synchronous methods to avoid async complexity.
    """
    
    def __init__(self, config: Optional[IntrospectionConfig] = None):
        """
        Initialize MCP introspection system.
        
        Args:
            config: Introspection configuration options
        """
        self.config = config or IntrospectionConfig()
        self.error_handler = ErrorHandler()
        
        # Initialize components
        self.transport_factory = TransportFactory()
        self.aggregator = ServerInfoAggregator(self.config.aggregator_config)
        
        self._introspection_cache: Dict[str, IntrospectionResult] = {}
        
    def introspect_server(
        self,
        server_config: MCPServerConfig
    ) -> IntrospectionResult:
        """
        Perform comprehensive introspection of a single MCP server.
        
        Args:
            server_config: Server configuration for introspection
            
        Returns:
            IntrospectionResult with comprehensive analysis
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting introspection of server {server_config.server_id}")
            
            # Check cache first
            cache_key = server_config.server_id
            if cache_key in self._introspection_cache:
                cached_result = self._introspection_cache[cache_key]
                if self._is_cache_valid(cached_result):
                    logger.debug(f"Using cached introspection for {server_config.server_id}")
                    return cached_result
            
            # Perform introspection with timeout
            introspection_start = time.time()
            server_info = self._introspect_single_server(server_config)
            
            # Check timeout
            if time.time() - introspection_start > self.config.timeout:
                raise TimeoutError("Server introspection timeout")
            
            # Create introspection result
            introspection_time = datetime.now() - start_time
            result = IntrospectionResult(
                timestamp=start_time,
                duration=introspection_time,
                success=True,
                servers=[server_info],
                total_servers=1,
                successful_servers=1 if not server_info.metadata.get('error') else 0,
                failed_servers=1 if server_info.metadata.get('error') else 0,
                overall_risk_level=server_info.overall_risk_level,
                metadata={
                    "introspection_method": "synchronous",
                    "detailed_analysis": self.config.enable_detailed_analysis,
                    "risk_assessment": self.config.enable_risk_assessment,
                    "server_id": server_config.server_id
                }
            )
            
            # Cache result
            self._introspection_cache[cache_key] = result
            
            logger.info(
                f"Introspection complete for {server_config.server_id}: "
                f"{len(server_info.tools)} tools, {len(server_info.resources)} resources, "
                f"{len(server_info.capabilities)} capabilities, "
                f"risk level: {server_info.overall_risk_level.value}, "
                f"{introspection_time.total_seconds():.2f}s"
            )
            
            return result
            
        except TimeoutError:
            logger.error(f"Server introspection timeout for {server_config.server_id}")
            return self._create_error_result(
                server_config, start_time, "Introspection timeout"
            )
            
        except Exception as e:
            logger.error(f"Unexpected error during introspection of {server_config.server_id}: {e}")
            return self._create_error_result(
                server_config, start_time, f"Unexpected error: {str(e)}"
            )
    
    def introspect_multiple_servers(
        self,
        server_configs: List[MCPServerConfig]
    ) -> IntrospectionResult:
        """
        Perform introspection of multiple MCP servers sequentially.
        
        Args:
            server_configs: List of server configurations
            
        Returns:
            IntrospectionResult with analysis of all servers
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting introspection of {len(server_configs)} servers")
            
            # Process servers sequentially
            all_servers = []
            successful_count = 0
            failed_count = 0
            
            for server_config in server_configs:
                try:
                    server_info = self._introspect_single_server(server_config)
                    all_servers.append(server_info)
                    
                    if server_info.metadata.get('error'):
                        failed_count += 1
                    else:
                        successful_count += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to introspect server {server_config.server_id}: {e}")
                    # Create error server info
                    error_server_info = self._create_error_server_info(
                        server_config, start_time, str(e)
                    )
                    all_servers.append(error_server_info)
                    failed_count += 1
            
            # Calculate overall risk level
            overall_risk = self._calculate_overall_risk([s.overall_risk_level for s in all_servers])
            
            # Create combined result
            introspection_time = datetime.now() - start_time
            result = IntrospectionResult(
                timestamp=start_time,
                duration=introspection_time,
                success=successful_count > 0,
                servers=all_servers,
                total_servers=len(server_configs),
                successful_servers=successful_count,
                failed_servers=failed_count,
                overall_risk_level=overall_risk,
                metadata={
                    "introspection_method": "sequential",
                    "detailed_analysis": self.config.enable_detailed_analysis,
                    "risk_assessment": self.config.enable_risk_assessment,
                    "server_count": len(server_configs)
                }
            )
            
            logger.info(
                f"Multi-server introspection complete: "
                f"{successful_count}/{len(server_configs)} successful, "
                f"overall risk: {overall_risk.value}, "
                f"{introspection_time.total_seconds():.2f}s"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Unexpected error during multi-server introspection: {e}")
            return IntrospectionResult(
                timestamp=start_time,
                duration=datetime.now() - start_time,
                success=False,
                servers=[],
                total_servers=len(server_configs),
                successful_servers=0,
                failed_servers=len(server_configs),
                overall_risk_level=RiskLevel.LOW,
                error=f"Multi-server introspection failed: {str(e)}",
                metadata={
                    "error": True,
                    "error_message": str(e)
                }
            )
    
    def _introspect_single_server(self, server_config: MCPServerConfig) -> MCPServerInfo:
        """
        Introspect a single MCP server.
        
        Args:
            server_config: Server configuration
            
        Returns:
            MCPServerInfo with server analysis
        """
        try:
            # Create server command from config
            server_command = self._create_server_command(server_config)
            
            # Aggregate server information
            server_info = self.aggregator.aggregate_server_info(
                server_command=server_command,
                server_id=server_config.server_id,
                server_url=getattr(server_config, 'url', None)
            )
            
            return server_info
            
        except Exception as e:
            logger.error(f"Failed to introspect server {server_config.server_id}: {e}")
            return self._create_error_server_info(
                server_config, datetime.now(), str(e)
            )
    
    def _create_server_command(self, server_config: MCPServerConfig) -> List[str]:
        """
        Create server command from configuration.
        
        Args:
            server_config: Server configuration
            
        Returns:
            Command list to start the server
        """
        if hasattr(server_config, 'command') and server_config.command:
            # Direct command specified
            if isinstance(server_config.command, list):
                return server_config.command
            else:
                return [str(server_config.command)]
        
        elif hasattr(server_config, 'executable') and server_config.executable:
            # Executable with optional args
            command = [server_config.executable]
            if hasattr(server_config, 'args') and server_config.args:
                if isinstance(server_config.args, list):
                    command.extend(server_config.args)
                else:
                    command.append(str(server_config.args))
            return command
        
        else:
            # Fallback: try to construct from server_id
            return ['mcp-server', server_config.server_id]
    
    def _calculate_overall_risk(self, risk_levels: List[RiskLevel]) -> RiskLevel:
        """
        Calculate overall risk level from multiple server risks.
        
        Args:
            risk_levels: List of individual server risk levels
            
        Returns:
            Overall risk level
        """
        if not risk_levels:
            return RiskLevel.LOW
        
        # Count risks by level
        risk_counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0
        }
        
        for risk_level in risk_levels:
            risk_counts[risk_level] += 1
        
        # Determine overall risk
        if risk_counts[RiskLevel.CRITICAL] > 0:
            return RiskLevel.CRITICAL
        elif risk_counts[RiskLevel.HIGH] >= 2:
            return RiskLevel.CRITICAL
        elif risk_counts[RiskLevel.HIGH] > 0:
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] >= 3:
            return RiskLevel.HIGH
        elif risk_counts[RiskLevel.MEDIUM] > 0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _create_error_result(
        self,
        server_config: MCPServerConfig,
        start_time: datetime,
        error_message: str
    ) -> IntrospectionResult:
        """
        Create error introspection result.
        
        Args:
            server_config: Server configuration
            start_time: Introspection start time
            error_message: Error description
            
        Returns:
            IntrospectionResult with error information
        """
        error_server_info = self._create_error_server_info(
            server_config, start_time, error_message
        )
        
        return IntrospectionResult(
            timestamp=start_time,
            duration=datetime.now() - start_time,
            success=False,
            servers=[error_server_info],
            total_servers=1,
            successful_servers=0,
            failed_servers=1,
            overall_risk_level=RiskLevel.LOW,
            error=error_message,
            metadata={
                "error": True,
                "error_message": error_message,
                "server_id": server_config.server_id
            }
        )
    
    def _create_error_server_info(
        self,
        server_config: MCPServerConfig,
        start_time: datetime,
        error_message: str
    ) -> MCPServerInfo:
        """
        Create error server info.
        
        Args:
            server_config: Server configuration
            start_time: Start time
            error_message: Error description
            
        Returns:
            MCPServerInfo with error information
        """
        return MCPServerInfo(
            server_id=server_config.server_id,
            server_url=getattr(server_config, 'url', None),
            discovery_timestamp=start_time,
            tools=[],
            resources=[],
            capabilities=[],
            security_risks=[],
            overall_risk_level=RiskLevel.LOW,
            metadata={
                "error": True,
                "error_message": error_message,
                "introspection_duration": (datetime.now() - start_time).total_seconds()
            }
        )
    
    def _is_cache_valid(self, result: IntrospectionResult) -> bool:
        """
        Check if cached introspection result is still valid.
        
        Args:
            result: Cached introspection result
            
        Returns:
            True if cache is valid, False otherwise
        """
        # Cache valid for 30 minutes
        cache_ttl = timedelta(minutes=30)
        return datetime.now() - result.timestamp < cache_ttl
    
    def clear_cache(self, server_id: Optional[str] = None):
        """
        Clear introspection cache.
        
        Args:
            server_id: Specific server to clear, or None for all
        """
        if server_id:
            self._introspection_cache.pop(server_id, None)
            logger.debug(f"Cleared introspection cache for {server_id}")
        else:
            self._introspection_cache.clear()
            logger.debug("Cleared all introspection cache")
        
        # Also clear aggregator cache
        self.aggregator.clear_cache(server_id)
    
    def get_server_summary(self, server_id: str) -> Optional[Dict[str, Any]]:
        """
        Get summary information for a specific server.
        
        Args:
            server_id: Server identifier
            
        Returns:
            Server summary dictionary or None if not found
        """
        # Check cache for recent introspection
        if server_id in self._introspection_cache:
            result = self._introspection_cache[server_id]
            if self._is_cache_valid(result) and result.servers:
                server_info = result.servers[0]
                return {
                    "server_id": server_info.server_id,
                    "server_url": server_info.server_url,
                    "discovery_timestamp": server_info.discovery_timestamp.isoformat(),
                    "tool_count": len(server_info.tools),
                    "resource_count": len(server_info.resources),
                    "capability_count": len(server_info.capabilities),
                    "security_risk_count": len(server_info.security_risks),
                    "overall_risk_level": server_info.overall_risk_level.value,
                    "has_error": bool(server_info.metadata.get('error'))
                }
        
        return None 