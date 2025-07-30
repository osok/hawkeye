"""
Detection Pipeline Orchestrator for HawkEye.

This module provides a unified detection pipeline that orchestrates multiple
detection methods including the enhanced MCP introspection system, process
enumeration, configuration discovery, and other detection techniques.
"""

import time
import logging
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .base import MCPDetector, DetectionResult, DetectionMethod, MCPServerInfo, ProcessInfo
from .process_enum import ProcessEnumerator
from .config_discovery import ConfigFileDiscovery
from .protocol_verify import ProtocolVerifier
from .transport_detect import TransportDetector
from .npx_detect import NPXDetector
from .docker_inspect import DockerInspector
from .env_analysis import EnvironmentAnalyzer
from .mcp_introspection import MCPIntrospector, IntrospectionConfig
from .mcp_introspection.models import MCPCapabilities
from ..utils.logging import get_logger
from ..config.settings import get_settings


@dataclass
class PipelineConfig:
    """Configuration for the detection pipeline."""
    enable_process_enumeration: bool = True
    enable_config_discovery: bool = True
    enable_protocol_verification: bool = True
    enable_transport_detection: bool = True
    enable_npx_detection: bool = True
    enable_docker_inspection: bool = True
    enable_environment_analysis: bool = True
    enable_mcp_introspection: bool = True
    
    # Introspection-specific settings
    introspection_timeout: float = 180.0
    enable_detailed_analysis: bool = True
    enable_risk_assessment: bool = True
    
    # Pipeline behavior settings
    fail_fast: bool = False
    parallel_detection: bool = False  # Keep false to avoid asyncio
    max_concurrent_detections: int = 1
    
    # Result filtering
    min_confidence_threshold: float = 0.3
    include_failed_detections: bool = True


@dataclass
class PipelineResult:
    """Result of a complete detection pipeline execution."""
    target_host: str
    start_time: datetime
    end_time: datetime
    duration: float
    success: bool
    
    # Detection results by method
    detection_results: Dict[DetectionMethod, List[DetectionResult]]
    
    # Enhanced introspection results
    introspection_results: Dict[str, MCPCapabilities]
    
    # Summary statistics
    total_detections: int
    successful_detections: int
    failed_detections: int
    mcp_servers_found: int
    
    # Overall findings
    best_mcp_server: Optional[MCPServerInfo]
    highest_confidence_result: Optional[DetectionResult]
    risk_assessment: Optional[Dict[str, Any]]
    
    # Error information
    errors: List[str]
    warnings: List[str]
    
    # Raw data for further analysis
    raw_data: Dict[str, Any]


class DetectionPipeline:
    """
    Unified detection pipeline that orchestrates multiple detection methods.
    
    This pipeline integrates the enhanced MCP introspection system with
    traditional detection methods to provide comprehensive MCP server
    discovery and analysis.
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None, settings=None):
        """
        Initialize the detection pipeline.
        
        Args:
            config: Pipeline configuration options
            settings: Application settings
        """
        self.config = config or PipelineConfig()
        self.settings = settings or get_settings()
        self.logger = get_logger(__name__)
        
        # Initialize detection components
        self._init_detectors()
        
        # Initialize enhanced MCP introspection
        self._init_introspection()
        
        # Pipeline statistics
        self.stats = {
            "total_pipelines_executed": 0,
            "successful_pipelines": 0,
            "failed_pipelines": 0,
            "total_introspections": 0,
            "successful_introspections": 0,
            "average_pipeline_duration": 0.0
        }
        
        self.logger.info(
            f"Detection pipeline initialized with {len(self.detectors)} detectors "
            f"and enhanced MCP introspection (introspection: {self.config.enable_mcp_introspection})"
        )
    
    def _init_detectors(self):
        """Initialize all detection components based on configuration."""
        self.detectors = {}
        
        if self.config.enable_process_enumeration:
            self.detectors[DetectionMethod.PROCESS_ENUMERATION] = ProcessEnumerator(self.settings)
        
        if self.config.enable_config_discovery:
            self.detectors[DetectionMethod.CONFIG_FILE_DISCOVERY] = ConfigFileDiscovery(self.settings)
        
        if self.config.enable_protocol_verification:
            self.detectors[DetectionMethod.PROTOCOL_HANDSHAKE] = ProtocolVerifier(self.settings)
        
        if self.config.enable_transport_detection:
            self.detectors[DetectionMethod.TRANSPORT_DETECTION] = TransportDetector(self.settings)
        
        if self.config.enable_npx_detection:
            self.detectors[DetectionMethod.NPX_PACKAGE_DETECTION] = NPXDetector(self.settings)
        
        if self.config.enable_docker_inspection:
            self.detectors[DetectionMethod.DOCKER_INSPECTION] = DockerInspector(self.settings)
        
        if self.config.enable_environment_analysis:
            self.detectors[DetectionMethod.ENVIRONMENT_ANALYSIS] = EnvironmentAnalyzer(self.settings)
    
    def _init_introspection(self):
        """Initialize the enhanced MCP introspection system."""
        if self.config.enable_mcp_introspection:
            introspection_config = IntrospectionConfig(
                timeout=self.config.introspection_timeout,
                enable_detailed_analysis=self.config.enable_detailed_analysis,
                enable_risk_assessment=self.config.enable_risk_assessment
            )
            self.introspector = MCPIntrospector(introspection_config)
            self.logger.debug("Enhanced MCP introspection system initialized")
        else:
            self.introspector = None
            self.logger.debug("MCP introspection disabled")
    
    def execute_pipeline(self, target_host: str, **kwargs) -> PipelineResult:
        """
        Execute the complete detection pipeline for a target.
        
        Args:
            target_host: Target host to analyze
            **kwargs: Additional detection parameters
            
        Returns:
            PipelineResult with comprehensive detection results
        """
        start_time = datetime.now()
        self.stats["total_pipelines_executed"] += 1
        
        try:
            self.logger.info(f"Starting detection pipeline for {target_host}")
            
            # Initialize result structure
            result = PipelineResult(
                target_host=target_host,
                start_time=start_time,
                end_time=start_time,  # Will be updated
                duration=0.0,
                success=False,
                detection_results={},
                introspection_results={},
                total_detections=0,
                successful_detections=0,
                failed_detections=0,
                mcp_servers_found=0,
                best_mcp_server=None,
                highest_confidence_result=None,
                risk_assessment=None,
                errors=[],
                warnings=[],
                raw_data={}
            )
            
            # Phase 1: Traditional detection methods
            self.logger.debug("Phase 1: Executing traditional detection methods")
            detection_results = self._execute_traditional_detection(target_host, **kwargs)
            result.detection_results = detection_results
            
            # Phase 2: Enhanced MCP introspection
            self.logger.debug("Phase 2: Executing enhanced MCP introspection")
            introspection_results = self._execute_introspection(target_host, detection_results, **kwargs)
            result.introspection_results = introspection_results
            
            # Phase 3: Result analysis and aggregation
            self.logger.debug("Phase 3: Analyzing and aggregating results")
            self._analyze_results(result)
            
            # Phase 4: Risk assessment (if enabled)
            if self.config.enable_risk_assessment and self.introspector:
                self.logger.debug("Phase 4: Performing risk assessment")
                result.risk_assessment = self._perform_risk_assessment(result)
            
            # Finalize result
            result.end_time = datetime.now()
            result.duration = (result.end_time - result.start_time).total_seconds()
            result.success = result.successful_detections > 0 or len(result.introspection_results) > 0
            
            # Update statistics
            if result.success:
                self.stats["successful_pipelines"] += 1
            else:
                self.stats["failed_pipelines"] += 1
            
            self._update_average_duration(result.duration)
            
            self.logger.info(
                f"Detection pipeline completed for {target_host}: "
                f"{result.successful_detections}/{result.total_detections} detections successful, "
                f"{len(result.introspection_results)} servers introspected, "
                f"{result.mcp_servers_found} MCP servers found, "
                f"duration: {result.duration:.2f}s"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Detection pipeline failed for {target_host}: {e}", exc_info=True)
            self.stats["failed_pipelines"] += 1
            
            # Return error result
            end_time = datetime.now()
            return PipelineResult(
                target_host=target_host,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                success=False,
                detection_results={},
                introspection_results={},
                total_detections=0,
                successful_detections=0,
                failed_detections=1,
                mcp_servers_found=0,
                best_mcp_server=None,
                highest_confidence_result=None,
                risk_assessment=None,
                errors=[str(e)],
                warnings=[],
                raw_data={}
            )
    
    def _execute_traditional_detection(self, target_host: str, **kwargs) -> Dict[DetectionMethod, List[DetectionResult]]:
        """Execute traditional detection methods."""
        results = {}
        
        for method, detector in self.detectors.items():
            try:
                self.logger.debug(f"Executing {method.value} detection")
                
                # Execute detection
                if method == DetectionMethod.PROCESS_ENUMERATION:
                    # Process enumeration returns multiple results
                    detection_results = detector.enumerate_mcp_processes()
                    results[method] = detection_results
                else:
                    # Other detectors return single result
                    detection_result = detector.detect(target_host, **kwargs)
                    results[method] = [detection_result] if detection_result else []
                
                self.logger.debug(f"{method.value} detection completed: {len(results[method])} results")
                
            except Exception as e:
                self.logger.warning(f"{method.value} detection failed: {e}")
                results[method] = []
                
                if self.config.fail_fast:
                    raise
        
        return results
    
    def _execute_introspection(
        self, 
        target_host: str, 
        detection_results: Dict[DetectionMethod, List[DetectionResult]], 
        **kwargs
    ) -> Dict[str, MCPCapabilities]:
        """Execute enhanced MCP introspection on detected servers."""
        introspection_results = {}
        
        if not self.introspector:
            self.logger.debug("MCP introspection disabled, skipping")
            return introspection_results
        
        # Extract MCP servers from detection results
        mcp_servers = self._extract_mcp_servers(detection_results)
        
        if not mcp_servers:
            self.logger.debug("No MCP servers found for introspection")
            return introspection_results
        
        self.logger.info(f"Found {len(mcp_servers)} MCP servers for introspection")
        
        for server_info, process_info in mcp_servers:
            server_id = f"{server_info.host}_{process_info.pid}"
            try:
                self.logger.debug(f"Introspecting server {server_id}")
                
                self.stats["total_introspections"] += 1
                
                # Perform introspection
                capabilities = self.introspector.introspect_server(server_info, process_info)
                
                if capabilities:
                    introspection_results[server_id] = capabilities
                    self.stats["successful_introspections"] += 1
                    
                    self.logger.info(
                        f"Introspection successful for {server_id}: "
                        f"{len(capabilities.experimental_capabilities)} experimental capabilities, "
                        f"supports tools: {capabilities.supports_tools}, "
                        f"supports resources: {capabilities.supports_resources}"
                    )
                else:
                    self.logger.warning(f"Introspection failed for {server_id}")
                
            except Exception as e:
                self.logger.error(f"Introspection error for {server_id}: {e}")
                
                if self.config.fail_fast:
                    raise
        
        return introspection_results
    
    def _extract_mcp_servers(self, detection_results: Dict[DetectionMethod, List[DetectionResult]]) -> List[Tuple[MCPServerInfo, ProcessInfo]]:
        """Extract MCP server information from detection results."""
        mcp_servers = []
        
        # Extract from process enumeration results
        if DetectionMethod.PROCESS_ENUMERATION in detection_results:
            for result in detection_results[DetectionMethod.PROCESS_ENUMERATION]:
                if result.success and result.mcp_server and result.mcp_server.process_info:
                    mcp_servers.append((result.mcp_server, result.mcp_server.process_info))
        
        # Extract from other detection methods that might have server info
        for method, results in detection_results.items():
            if method == DetectionMethod.PROCESS_ENUMERATION:
                continue  # Already processed
            
            for result in results:
                if result.success and result.mcp_server:
                    # Create a synthetic process info if not available
                    if not result.mcp_server.process_info:
                        process_info = ProcessInfo(
                            pid=0,  # Unknown PID
                            name="unknown",
                            cmdline=[],
                            cwd="",
                            env_vars={}
                        )
                    else:
                        process_info = result.mcp_server.process_info
                    
                    mcp_servers.append((result.mcp_server, process_info))
        
        return mcp_servers
    
    def _analyze_results(self, result: PipelineResult):
        """Analyze and aggregate detection results."""
        # Count statistics
        for method_results in result.detection_results.values():
            for detection_result in method_results:
                result.total_detections += 1
                
                if detection_result.success:
                    result.successful_detections += 1
                    
                    if detection_result.is_mcp_detected:
                        result.mcp_servers_found += 1
                else:
                    result.failed_detections += 1
        
        # Add introspection results to MCP server count
        result.mcp_servers_found += len(result.introspection_results)
        
        # Find best MCP server and highest confidence result
        all_results = []
        for method_results in result.detection_results.values():
            all_results.extend(method_results)
        
        # Filter by confidence threshold
        filtered_results = [
            r for r in all_results 
            if r.success and r.confidence >= self.config.min_confidence_threshold
        ]
        
        if filtered_results:
            # Find highest confidence result
            result.highest_confidence_result = max(filtered_results, key=lambda r: r.confidence)
            
            # Find best MCP server (highest confidence with MCP detection)
            mcp_results = [r for r in filtered_results if r.is_mcp_detected and r.mcp_server]
            if mcp_results:
                best_result = max(mcp_results, key=lambda r: r.confidence)
                result.best_mcp_server = best_result.mcp_server
        
        # Collect errors and warnings
        for method_results in result.detection_results.values():
            for detection_result in method_results:
                if detection_result.error:
                    result.errors.append(detection_result.error)
                if hasattr(detection_result, 'warnings') and detection_result.warnings:
                    result.warnings.extend(detection_result.warnings)
    
    def _perform_risk_assessment(self, result: PipelineResult) -> Dict[str, Any]:
        """Perform comprehensive risk assessment."""
        risk_assessment = {
            "overall_risk_level": "low",
            "risk_factors": [],
            "security_concerns": [],
            "recommendations": [],
            "detailed_analysis": {}
        }
        
        try:
            # Analyze introspection results for risk factors
            high_risk_servers = []
            critical_risk_servers = []
            
            for server_id, capabilities in result.introspection_results.items():
                # Determine risk level based on capabilities
                risk_level = "low"
                if capabilities.supports_tools:
                    risk_level = "medium"
                if capabilities.has_dangerous_capabilities():
                    risk_level = "high"
                
                if risk_level == "critical":
                    critical_risk_servers.append(server_id)
                elif risk_level == "high":
                    high_risk_servers.append(server_id)
                
                # Analyze specific risk factors
                if capabilities.supports_tools:
                    risk_assessment["risk_factors"].append(f"Server {server_id} supports tools (potential code execution)")
                
                if "file" in str(capabilities.experimental_capabilities).lower():
                    risk_assessment["risk_factors"].append(f"Server {server_id} may have file system access")
                
                if "network" in str(capabilities.experimental_capabilities).lower():
                    risk_assessment["risk_factors"].append(f"Server {server_id} may have external network access")
            
            # Determine overall risk level
            if critical_risk_servers:
                risk_assessment["overall_risk_level"] = "critical"
            elif high_risk_servers:
                risk_assessment["overall_risk_level"] = "high"
            elif result.mcp_servers_found > 0:
                risk_assessment["overall_risk_level"] = "medium"
            
            # Add security concerns and recommendations
            if critical_risk_servers:
                risk_assessment["security_concerns"].append(
                    f"Critical risk servers detected: {', '.join(critical_risk_servers)}"
                )
                risk_assessment["recommendations"].append(
                    "Immediately review and restrict capabilities of critical risk servers"
                )
            
            if high_risk_servers:
                risk_assessment["security_concerns"].append(
                    f"High risk servers detected: {', '.join(high_risk_servers)}"
                )
                risk_assessment["recommendations"].append(
                    "Review and monitor high risk servers for security compliance"
                )
            
            # Add detailed analysis
            risk_assessment["detailed_analysis"] = {
                "total_servers_analyzed": len(result.introspection_results),
                "critical_risk_count": len(critical_risk_servers),
                "high_risk_count": len(high_risk_servers),
                "servers_with_tools": sum(
                    1 for cap in result.introspection_results.values() 
                    if cap.supports_tools
                ),
                "servers_with_resources": sum(
                    1 for cap in result.introspection_results.values() 
                    if cap.supports_resources
                ),
                "servers_with_dangerous_capabilities": sum(
                    1 for cap in result.introspection_results.values() 
                    if cap.has_dangerous_capabilities()
                )
            }
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            risk_assessment["error"] = str(e)
        
        return risk_assessment
    
    def _update_average_duration(self, duration: float):
        """Update average pipeline duration statistics."""
        total_pipelines = self.stats["total_pipelines_executed"]
        current_avg = self.stats["average_pipeline_duration"]
        
        # Calculate new average
        new_avg = ((current_avg * (total_pipelines - 1)) + duration) / total_pipelines
        self.stats["average_pipeline_duration"] = new_avg
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """Get pipeline execution statistics."""
        total_pipelines = self.stats["total_pipelines_executed"]
        
        return {
            "total_pipelines_executed": total_pipelines,
            "successful_pipelines": self.stats["successful_pipelines"],
            "failed_pipelines": self.stats["failed_pipelines"],
            "success_rate": (self.stats["successful_pipelines"] / max(total_pipelines, 1)) * 100,
            "total_introspections": self.stats["total_introspections"],
            "successful_introspections": self.stats["successful_introspections"],
            "introspection_success_rate": (
                self.stats["successful_introspections"] / max(self.stats["total_introspections"], 1)
            ) * 100,
            "average_pipeline_duration": self.stats["average_pipeline_duration"],
            "enabled_detectors": list(self.detectors.keys()),
            "introspection_enabled": self.introspector is not None
        }
    
    def execute_batch_pipeline(self, targets: List[str], **kwargs) -> List[PipelineResult]:
        """
        Execute detection pipeline on multiple targets.
        
        Args:
            targets: List of target hosts
            **kwargs: Additional detection parameters
            
        Returns:
            List of PipelineResult objects
        """
        self.logger.info(f"Starting batch detection pipeline for {len(targets)} targets")
        
        results = []
        for i, target in enumerate(targets):
            try:
                self.logger.debug(f"Processing target {i+1}/{len(targets)}: {target}")
                result = self.execute_pipeline(target, **kwargs)
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Batch pipeline failed for target {target}: {e}")
                # Create error result
                error_result = PipelineResult(
                    target_host=target,
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    duration=0.0,
                    success=False,
                    detection_results={},
                    introspection_results={},
                    total_detections=0,
                    successful_detections=0,
                    failed_detections=1,
                    mcp_servers_found=0,
                    best_mcp_server=None,
                    highest_confidence_result=None,
                    risk_assessment=None,
                    errors=[str(e)],
                    warnings=[],
                    raw_data={}
                )
                results.append(error_result)
        
        successful_count = sum(1 for r in results if r.success)
        self.logger.info(
            f"Batch detection pipeline completed: {successful_count}/{len(targets)} successful"
        )
        
        return results


def create_detection_pipeline(config: Optional[PipelineConfig] = None, settings=None) -> DetectionPipeline:
    """
    Factory function to create a detection pipeline instance.
    
    Args:
        config: Pipeline configuration
        settings: Application settings
        
    Returns:
        DetectionPipeline instance
    """
    return DetectionPipeline(config, settings)