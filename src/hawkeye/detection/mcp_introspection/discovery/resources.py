"""
Resource Discovery Module

Implements resource discovery via MCP resources/list endpoint.
Provides comprehensive resource enumeration, schema analysis, and risk assessment.
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
    MCPResource,
    RiskLevel,
    SecurityRisk,
    DiscoveryResult
)
from ..utils import ErrorHandler


logger = logging.getLogger(__name__)


@dataclass
class ResourceDiscoveryConfig:
    """Configuration for resource discovery operations."""
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_schema_analysis: bool = True
    enable_risk_assessment: bool = True
    sensitive_patterns: Set[str] = None
    
    def __post_init__(self):
        if self.sensitive_patterns is None:
            self.sensitive_patterns = {
                'password', 'secret', 'key', 'token', 'credential',
                'private', 'confidential', 'sensitive', 'admin',
                'config', 'env', 'database', 'db', 'sql'
            }


class ResourceDiscovery:
    """
    Discovers and analyzes MCP resources via direct communication.
    
    Provides comprehensive resource enumeration with schema analysis,
    risk assessment, and security evaluation using synchronous methods.
    """
    
    def __init__(self, config: Optional[ResourceDiscoveryConfig] = None):
        """
        Initialize resource discovery.
        
        Args:
            config: Discovery configuration options
        """
        self.config = config or ResourceDiscoveryConfig()
        self.error_handler = ErrorHandler()
        self._discovery_cache: Dict[str, DiscoveryResult] = {}
        
    def discover_resources(
        self,
        server_command: List[str],
        server_id: str
    ) -> DiscoveryResult:
        """
        Discover resources from an MCP server.
        
        Args:
            server_command: Command to start the MCP server
            server_id: Unique identifier for the server
            
        Returns:
            DiscoveryResult containing discovered resources and metadata
        """
        start_time = datetime.now()
        
        try:
            logger.info(f"Starting resource discovery for server {server_id}")
            
            # Check cache first
            cache_key = f"resources_{server_id}"
            if cache_key in self._discovery_cache:
                cached_result = self._discovery_cache[cache_key]
                if self._is_cache_valid(cached_result):
                    logger.debug(f"Using cached resource discovery for {server_id}")
                    return cached_result
            
            # Discover resources with timeout
            start_discovery = time.time()
            resources_data = self._list_resources_with_retry(server_command)
            
            # Check timeout
            if time.time() - start_discovery > self.config.timeout:
                raise TimeoutError("Resource discovery timeout")
            
            # Process discovered resources
            mcp_resources = []
            security_risks = []
            
            if resources_data and isinstance(resources_data, list):
                for resource_data in resources_data:
                    try:
                        # Convert to internal model
                        mcp_resource = self._convert_resource(resource_data)
                        mcp_resources.append(mcp_resource)
                        
                        # Perform risk assessment if enabled
                        if self.config.enable_risk_assessment:
                            risks = self._assess_resource_risks(mcp_resource)
                            security_risks.extend(risks)
                            
                    except Exception as e:
                        logger.warning(f"Failed to process resource {resource_data.get('uri', 'unknown')}: {e}")
                        continue
            
            # Create discovery result
            discovery_time = datetime.now() - start_time
            result = DiscoveryResult(
                server_id=server_id,
                discovery_type="resources",
                timestamp=start_time,
                duration=discovery_time,
                success=True,
                resources=mcp_resources,
                security_risks=security_risks,
                metadata={
                    "resource_count": len(mcp_resources),
                    "risk_count": len(security_risks),
                    "discovery_method": "subprocess_communication",
                    "schema_analysis": self.config.enable_schema_analysis,
                    "risk_assessment": self.config.enable_risk_assessment
                }
            )
            
            # Cache result
            self._discovery_cache[cache_key] = result
            
            logger.info(
                f"Resource discovery complete for {server_id}: "
                f"{len(mcp_resources)} resources, {len(security_risks)} risks, "
                f"{discovery_time.total_seconds():.2f}s"
            )
            
            return result
            
        except TimeoutError:
            logger.error(f"Resource discovery timeout for server {server_id}")
            return self._create_error_result(
                server_id, start_time, "Discovery timeout"
            )
            
        except Exception as e:
            logger.error(f"Unexpected error during resource discovery for {server_id}: {e}")
            return self._create_error_result(
                server_id, start_time, f"Unexpected error: {str(e)}"
            )
    
    def _list_resources_with_retry(self, server_command: List[str]) -> Optional[List[Dict[str, Any]]]:
        """
        List resources with retry logic using subprocess communication.
        
        Args:
            server_command: Command to start the MCP server
            
        Returns:
            List of discovered resources or None
        """
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                logger.debug(f"Resource discovery attempt {attempt + 1}")
                
                # Create MCP request for resources/list
                request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "resources/list",
                    "params": {}
                }
                
                # Communicate with server
                result = self._communicate_with_server(server_command, request)
                
                if result and "result" in result:
                    resources = result["result"].get("resources", [])
                    return resources
                elif result and "error" in result:
                    raise Exception(f"MCP error: {result['error']}")
                else:
                    return []
                    
            except Exception as e:
                last_error = e
                logger.warning(f"Resource discovery attempt {attempt + 1} failed: {e}")
                
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2 ** attempt))
                    
        # All retries failed
        logger.error(f"Resource discovery failed after all retries: {last_error}")
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
    
    def _convert_resource(self, resource_data: Dict[str, Any]) -> MCPResource:
        """
        Convert resource data to internal MCPResource model.
        
        Args:
            resource_data: Raw resource data from server
            
        Returns:
            MCPResource instance
        """
        return MCPResource(
            uri=resource_data.get('uri', ''),
            name=resource_data.get('name', ''),
            description=resource_data.get('description', ''),
            mime_type=resource_data.get('mimeType'),
            metadata={
                "discovery_method": "subprocess_communication",
                "has_mime_type": bool(resource_data.get('mimeType')),
                "uri_scheme": self._extract_uri_scheme(resource_data.get('uri', ''))
            }
        )
    
    def _extract_uri_scheme(self, uri: str) -> str:
        """
        Extract scheme from URI.
        
        Args:
            uri: Resource URI
            
        Returns:
            URI scheme or 'unknown'
        """
        try:
            if '://' in uri:
                return uri.split('://')[0].lower()
            return 'unknown'
        except Exception:
            return 'unknown'
    
    def _assess_resource_risks(self, resource: MCPResource) -> List[SecurityRisk]:
        """
        Assess security risks for a resource.
        
        Args:
            resource: MCPResource to assess
            
        Returns:
            List of identified security risks
        """
        risks = []
        
        # Check for sensitive patterns in resource URI
        uri_lower = resource.uri.lower()
        for pattern in self.config.sensitive_patterns:
            if pattern in uri_lower:
                risks.append(SecurityRisk(
                    category="sensitive_resource_uri",
                    severity=RiskLevel.MEDIUM,
                    description=f"Resource URI contains sensitive pattern: {pattern}",
                    details={
                        "resource_uri": resource.uri,
                        "pattern": pattern,
                        "location": "uri"
                    },
                    mitigation="Review resource access controls and ensure proper authorization"
                ))
        
        # Check for sensitive patterns in resource name
        if resource.name:
            name_lower = resource.name.lower()
            for pattern in self.config.sensitive_patterns:
                if pattern in name_lower:
                    risks.append(SecurityRisk(
                        category="sensitive_resource_name",
                        severity=RiskLevel.MEDIUM,
                        description=f"Resource name contains sensitive pattern: {pattern}",
                        details={
                            "resource_name": resource.name,
                            "pattern": pattern,
                            "location": "name"
                        },
                        mitigation="Review resource naming and access controls"
                    ))
        
        # Check for file system access
        uri_scheme = resource.metadata.get('uri_scheme', '').lower()
        if uri_scheme in ['file', 'local']:
            risks.append(SecurityRisk(
                category="file_system_resource",
                severity=RiskLevel.HIGH,
                description="Resource provides file system access",
                details={
                    "resource_uri": resource.uri,
                    "scheme": uri_scheme
                },
                mitigation="Validate file paths and restrict access to safe directories"
            ))
        
        # Check for network resources
        if uri_scheme in ['http', 'https', 'ftp', 'sftp']:
            risks.append(SecurityRisk(
                category="network_resource",
                severity=RiskLevel.MEDIUM,
                description="Resource provides network access",
                details={
                    "resource_uri": resource.uri,
                    "scheme": uri_scheme
                },
                mitigation="Validate URLs and restrict access to trusted domains"
            ))
        
        # Check for database resources
        if uri_scheme in ['mysql', 'postgresql', 'sqlite', 'mongodb']:
            risks.append(SecurityRisk(
                category="database_resource",
                severity=RiskLevel.HIGH,
                description="Resource provides database access",
                details={
                    "resource_uri": resource.uri,
                    "scheme": uri_scheme
                },
                mitigation="Ensure proper database access controls and authentication"
            ))
        
        # Check for executable MIME types
        if resource.mime_type:
            mime_lower = resource.mime_type.lower()
            executable_types = [
                'application/x-executable',
                'application/x-msdos-program',
                'application/x-msdownload',
                'application/x-sh',
                'application/x-shellscript'
            ]
            
            if any(exec_type in mime_lower for exec_type in executable_types):
                risks.append(SecurityRisk(
                    category="executable_resource",
                    severity=RiskLevel.HIGH,
                    description="Resource has executable MIME type",
                    details={
                        "resource_uri": resource.uri,
                        "mime_type": resource.mime_type
                    },
                    mitigation="Validate executable resources and restrict execution permissions"
                ))
        
        return risks
    
    def _is_cache_valid(self, result: DiscoveryResult) -> bool:
        """
        Check if cached discovery result is still valid.
        
        Args:
            result: Cached discovery result
            
        Returns:
            True if cache is valid, False otherwise
        """
        # Cache valid for 5 minutes
        cache_ttl = timedelta(minutes=5)
        return datetime.now() - result.timestamp < cache_ttl
    
    def _create_error_result(
        self,
        server_id: str,
        start_time: datetime,
        error_message: str
    ) -> DiscoveryResult:
        """
        Create error discovery result.
        
        Args:
            server_id: Server identifier
            start_time: Discovery start time
            error_message: Error description
            
        Returns:
            DiscoveryResult with error information
        """
        return DiscoveryResult(
            server_id=server_id,
            discovery_type="resources",
            timestamp=start_time,
            duration=datetime.now() - start_time,
            success=False,
            error=error_message,
            resources=[],
            security_risks=[],
            metadata={
                "error": True,
                "error_message": error_message
            }
        )
    
    def clear_cache(self, server_id: Optional[str] = None):
        """
        Clear discovery cache.
        
        Args:
            server_id: Specific server to clear, or None for all
        """
        if server_id:
            cache_key = f"resources_{server_id}"
            self._discovery_cache.pop(cache_key, None)
            logger.debug(f"Cleared resource discovery cache for {server_id}")
        else:
            self._discovery_cache.clear()
            logger.debug("Cleared all resource discovery cache") 