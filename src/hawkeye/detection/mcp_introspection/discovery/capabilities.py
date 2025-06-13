"""
Capability Assessment Module

Implements capability assessment via MCP initialize response.
Provides comprehensive capability analysis and risk assessment.
Uses synchronous subprocess communication to avoid async complexity.
"""

import json
import logging
import subprocess
import time
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..models import (
    MCPCapability,
    RiskLevel,
    SecurityRisk,
    DiscoveryResult
)
from ..utils import ErrorHandler


logger = logging.getLogger(__name__)


@dataclass
class CapabilityAssessmentConfig:
    """Configuration for capability assessment operations."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_risk_assessment: bool = True
    high_risk_capabilities: Set[str] = None
    
    def __post_init__(self):
        if self.high_risk_capabilities is None:
            self.high_risk_capabilities = {
                'tools', 'resources', 'prompts', 'sampling',
                'experimental', 'admin', 'system', 'file_access',
                'network_access', 'database_access'
            }


class CapabilityAssessment:
    """
    Assesses MCP server capabilities via direct communication.
    
    Provides comprehensive capability analysis with risk assessment
    and security evaluation using synchronous methods.
    """
    
    def __init__(self, config: Optional[CapabilityAssessmentConfig] = None):
        """
        Initialize capability assessment.
        
        Args:
            config: Assessment configuration options
        """
        self.config = config or CapabilityAssessmentConfig()
        self.error_handler = ErrorHandler()
        self._assessment_cache: Dict[str, DiscoveryResult] = {}
        
    def assess_capabilities(
        self,
        server_command: List[str],
        server_id: str
    ) -> DiscoveryResult:
        """
        Assess capabilities from an MCP server.
        
        Args:
            server_command: Command to start the MCP server
            server_id: Unique identifier for the server
            
        Returns:
            DiscoveryResult containing capability assessment and metadata
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting capability assessment for server {server_id}")
            
            # Check cache first
            cache_key = f"capabilities_{server_id}"
            if cache_key in self._assessment_cache:
                cached_result = self._assessment_cache[cache_key]
                if self._is_cache_valid(cached_result):
                    logger.debug(f"Using cached capability assessment for {server_id}")
                    return cached_result
            
            # Get server capabilities with timeout
            start_assessment = time.time()
            capabilities_data = self._get_capabilities_with_retry(server_command)
            
            # Check timeout
            if time.time() - start_assessment > self.config.timeout:
                raise TimeoutError("Capability assessment timeout")
            
            # Process capabilities
            capabilities = []
            security_risks = []
            
            if capabilities_data:
                try:
                    # Convert to internal model
                    capability = self._convert_capabilities(capabilities_data)
                    capabilities.append(capability)
                    
                    # Perform risk assessment if enabled
                    if self.config.enable_risk_assessment:
                        risks = self._assess_capability_risks(capability)
                        security_risks.extend(risks)
                        
                except Exception as e:
                    logger.warning(f"Failed to process capabilities: {e}")
            
            # Create discovery result
            assessment_time = datetime.now() - start_time
            result = DiscoveryResult(
                server_id=server_id,
                discovery_type="capabilities",
                timestamp=start_time,
                duration=assessment_time,
                success=True,
                capabilities=capabilities,
                security_risks=security_risks,
                metadata={
                    "capability_count": len(capabilities),
                    "risk_count": len(security_risks),
                    "assessment_method": "subprocess_communication",
                    "risk_assessment": self.config.enable_risk_assessment
                }
            )
            
            # Cache result
            self._assessment_cache[cache_key] = result
            
            logger.info(
                f"Capability assessment complete for {server_id}: "
                f"{len(capabilities)} capabilities, {len(security_risks)} risks, "
                f"{assessment_time.total_seconds():.2f}s"
            )
            
            return result
            
        except TimeoutError:
            logger.error(f"Capability assessment timeout for server {server_id}")
            return self._create_error_result(
                server_id, start_time, "Assessment timeout"
            )
            
        except Exception as e:
            logger.error(f"Unexpected error during capability assessment for {server_id}: {e}")
            return self._create_error_result(
                server_id, start_time, f"Unexpected error: {str(e)}"
            )
    
    def _get_capabilities_with_retry(self, server_command: List[str]) -> Optional[Dict[str, Any]]:
        """
        Get server capabilities with retry logic using subprocess communication.
        
        Args:
            server_command: Command to start the MCP server
            
        Returns:
            Server capabilities data or None
        """
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                logger.debug(f"Capability assessment attempt {attempt + 1}")
                
                # Create MCP request for initialize
                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "roots": {
                                "listChanged": True
                            },
                            "sampling": {}
                        },
                        "clientInfo": {
                            "name": "hawkeye-mcp-introspector",
                            "version": "1.0.0"
                        }
                    }
                }
                
                # Communicate with server
                result = self._communicate_with_server(server_command, request)
                
                if result and "result" in result:
                    return result["result"]
                elif result and "error" in result:
                    raise Exception(f"MCP error: {result['error']}")
                else:
                    return None
                    
            except Exception as e:
                last_error = e
                logger.warning(f"Capability assessment attempt {attempt + 1} failed: {e}")
                
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2 ** attempt))
                    
        # All retries failed - return None instead of raising
        logger.warning(f"Capability assessment failed after all retries: {last_error}")
        return None
    
    def _communicate_with_server(self, server_command: List[str], request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Communicate with MCP server via subprocess.
        
        Args:
            server_command: Command to start the server
            request: JSON-RPC request to send
            
        Returns:
            Server response or None
        """
        try:
            # Start the server process
            process = subprocess.Popen(
                server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            
            # Send request
            request_json = json.dumps(request) + "\n"
            stdout, stderr = process.communicate(input=request_json, timeout=self.config.timeout)
            
            # Parse response
            if stdout.strip():
                try:
                    response = json.loads(stdout.strip())
                    return response
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse server response: {e}")
                    logger.debug(f"Raw response: {stdout}")
                    return None
            else:
                logger.warning(f"No response from server. stderr: {stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Server communication timeout")
            if process:
                process.kill()
            return None
        except Exception as e:
            logger.error(f"Server communication failed: {e}")
            return None
    
    def _convert_capabilities(self, capabilities_data: Dict[str, Any]) -> MCPCapability:
        """
        Convert capabilities data to internal MCPCapability model.
        
        Args:
            capabilities_data: Raw capabilities data
            
        Returns:
            MCPCapability instance
        """
        # Extract capabilities from different possible structures
        capabilities = []
        
        if isinstance(capabilities_data, dict):
            # Check for common capability fields
            if 'capabilities' in capabilities_data:
                cap_data = capabilities_data['capabilities']
                if isinstance(cap_data, dict):
                    capabilities.extend(cap_data.keys())
                elif isinstance(cap_data, list):
                    capabilities.extend(cap_data)
            
            # Check for direct capability indicators
            for key in capabilities_data.keys():
                if key.endswith('_support') or key.endswith('_enabled'):
                    if capabilities_data[key]:
                        capabilities.append(key.replace('_support', '').replace('_enabled', ''))
            
            # Check for specific capability types
            capability_indicators = [
                'tools', 'resources', 'prompts', 'sampling',
                'logging', 'experimental'
            ]
            
            for indicator in capability_indicators:
                if indicator in capabilities_data:
                    capabilities.append(indicator)
        
        return MCPCapability(
            name="server_capabilities",
            description="MCP server capabilities",
            capabilities=list(set(capabilities)),  # Remove duplicates
            metadata={
                "assessment_method": "subprocess_communication",
                "raw_data": capabilities_data,
                "capability_count": len(capabilities)
            }
        )
    
    def _assess_capability_risks(self, capability: MCPCapability) -> List[SecurityRisk]:
        """
        Assess security risks for capabilities.
        
        Args:
            capability: MCPCapability to assess
            
        Returns:
            List of identified security risks
        """
        risks = []
        
        # Check for high-risk capabilities
        for cap in capability.capabilities:
            cap_lower = cap.lower()
            
            # Check against high-risk patterns
            for risk_pattern in self.config.high_risk_capabilities:
                if risk_pattern in cap_lower:
                    severity = RiskLevel.HIGH if risk_pattern in [
                        'tools', 'system', 'admin', 'file_access', 'database_access'
                    ] else RiskLevel.MEDIUM
                    
                    risks.append(SecurityRisk(
                        category="high_risk_capability",
                        severity=severity,
                        description=f"Server has high-risk capability: {cap}",
                        details={
                            "capability": cap,
                            "risk_pattern": risk_pattern
                        },
                        mitigation="Review capability usage and implement appropriate access controls"
                    ))
        
        # Check for tool execution capabilities
        if any('tool' in cap.lower() for cap in capability.capabilities):
            risks.append(SecurityRisk(
                category="tool_execution",
                severity=RiskLevel.HIGH,
                description="Server can execute tools",
                details={
                    "capabilities": [cap for cap in capability.capabilities if 'tool' in cap.lower()]
                },
                mitigation="Validate all tool executions and implement sandboxing"
            ))
        
        # Check for resource access capabilities
        if any('resource' in cap.lower() for cap in capability.capabilities):
            risks.append(SecurityRisk(
                category="resource_access",
                severity=RiskLevel.MEDIUM,
                description="Server can access resources",
                details={
                    "capabilities": [cap for cap in capability.capabilities if 'resource' in cap.lower()]
                },
                mitigation="Validate resource access and implement proper authorization"
            ))
        
        # Check for experimental capabilities
        if any('experimental' in cap.lower() for cap in capability.capabilities):
            risks.append(SecurityRisk(
                category="experimental_features",
                severity=RiskLevel.MEDIUM,
                description="Server uses experimental features",
                details={
                    "capabilities": [cap for cap in capability.capabilities if 'experimental' in cap.lower()]
                },
                mitigation="Monitor experimental features for stability and security issues"
            ))
        
        # Check for sampling capabilities (AI model access)
        if any('sampling' in cap.lower() for cap in capability.capabilities):
            risks.append(SecurityRisk(
                category="ai_model_access",
                severity=RiskLevel.MEDIUM,
                description="Server can access AI models for sampling",
                details={
                    "capabilities": [cap for cap in capability.capabilities if 'sampling' in cap.lower()]
                },
                mitigation="Monitor AI model usage and implement rate limiting"
            ))
        
        return risks
    
    def _is_cache_valid(self, result: DiscoveryResult) -> bool:
        """
        Check if cached assessment result is still valid.
        
        Args:
            result: Cached assessment result
            
        Returns:
            True if cache is valid, False otherwise
        """
        # Cache valid for 10 minutes (capabilities change less frequently)
        cache_ttl = timedelta(minutes=10)
        return datetime.now() - result.timestamp < cache_ttl
    
    def _create_error_result(
        self,
        server_id: str,
        start_time: datetime,
        error_message: str
    ) -> DiscoveryResult:
        """
        Create error assessment result.
        
        Args:
            server_id: Server identifier
            start_time: Assessment start time
            error_message: Error description
            
        Returns:
            DiscoveryResult with error information
        """
        return DiscoveryResult(
            server_id=server_id,
            discovery_type="capabilities",
            timestamp=start_time,
            duration=datetime.now() - start_time,
            success=False,
            error=error_message,
            capabilities=[],
            security_risks=[],
            metadata={
                "error": True,
                "error_message": error_message
            }
        )
    
    def clear_cache(self, server_id: Optional[str] = None):
        """
        Clear assessment cache.
        
        Args:
            server_id: Specific server to clear, or None for all
        """
        if server_id:
            cache_key = f"capabilities_{server_id}"
            self._assessment_cache.pop(cache_key, None)
            logger.debug(f"Cleared capability assessment cache for {server_id}")
        else:
            self._assessment_cache.clear()
            logger.debug("Cleared all capability assessment cache") 