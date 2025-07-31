"""
MCP Capability Analysis

This module provides capability analysis for MCP tools, extracting security-relevant
information from tool functions and building comprehensive capability profiles.
"""

import logging
import time
import platform
import os
import subprocess
import psutil
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

from .models import (
    ToolCapabilities, ToolFunction, CapabilityCategory, RiskSurface,
    AccessRequirements, ExternalDependency, AccessLevel, DataSensitivity,
    EnvironmentContext, DeploymentType, SecurityPosture, NetworkExposure,
    UserPrivileges, ComplianceFramework
)
from ..mcp_introspection.models import MCPServerInfo, MCPTool
from ..base import DetectionResult


logger = logging.getLogger(__name__)


@dataclass
class SystemInfo:
    """System information for environment context analysis."""
    platform: str
    python_version: str
    memory_total: int
    cpu_count: int
    disk_usage: Dict[str, Any]
    network_interfaces: List[Dict[str, Any]]
    running_processes: List[str]
    environment_variables: Dict[str, str]
    installed_packages: List[str]
    user_groups: List[str]
    system_uptime: float
    security_features: Dict[str, bool]
    
    @classmethod
    def gather_system_info(cls) -> 'SystemInfo':
        """Gather comprehensive system information."""
        try:
            # Basic system info
            platform_info = platform.platform()
            python_version = platform.python_version()
            
            # Memory info
            memory = psutil.virtual_memory()
            memory_total = memory.total
            
            # CPU info
            cpu_count = psutil.cpu_count()
            
            # Disk usage
            disk_usage = {}
            for disk in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(disk.mountpoint)
                    disk_usage[disk.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': (usage.used / usage.total) * 100
                    }
                except (PermissionError, FileNotFoundError):
                    continue
            
            # Network interfaces
            network_interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {'name': interface, 'addresses': []}
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                network_interfaces.append(interface_info)
            
            # Running processes (limited for security)
            running_processes = []
            try:
                for proc in psutil.process_iter(['name']):
                    try:
                        running_processes.append(proc.info['name'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                # Limit to avoid too much data
                running_processes = list(set(running_processes))[:50]
            except Exception:
                running_processes = []
            
            # Environment variables (filtered for security)
            safe_env_vars = {}
            safe_prefixes = ['PATH', 'HOME', 'USER', 'SHELL', 'TERM', 'LANG']
            for key, value in os.environ.items():
                if any(key.startswith(prefix) for prefix in safe_prefixes):
                    safe_env_vars[key] = value[:100]  # Truncate long values
            
            # Installed packages (simplified)
            installed_packages = []
            try:
                import pkg_resources
                installed_packages = [pkg.project_name for pkg in pkg_resources.working_set][:100]
            except Exception:
                installed_packages = []
            
            # User groups
            user_groups = []
            try:
                import grp
                user_groups = [g.gr_name for g in grp.getgrall() if os.getenv('USER') in g.gr_mem]
            except Exception:
                user_groups = []
            
            # System uptime
            system_uptime = time.time() - psutil.boot_time()
            
            # Security features detection
            security_features = {
                'firewall_detected': cls._detect_firewall(),
                'antivirus_detected': cls._detect_antivirus(),
                'docker_available': cls._detect_docker(),
                'selinux_enabled': cls._detect_selinux(),
                'apparmor_enabled': cls._detect_apparmor(),
                'encryption_available': cls._detect_encryption_tools()
            }
            
            return cls(
                platform=platform_info,
                python_version=python_version,
                memory_total=memory_total,
                cpu_count=cpu_count,
                disk_usage=disk_usage,
                network_interfaces=network_interfaces,
                running_processes=running_processes,
                environment_variables=safe_env_vars,
                installed_packages=installed_packages,
                user_groups=user_groups,
                system_uptime=system_uptime,
                security_features=security_features
            )
            
        except Exception as e:
            logger.error(f"Failed to gather system info: {e}")
            # Return minimal system info
            return cls(
                platform=platform.platform(),
                python_version=platform.python_version(),
                memory_total=0,
                cpu_count=1,
                disk_usage={},
                network_interfaces=[],
                running_processes=[],
                environment_variables={},
                installed_packages=[],
                user_groups=[],
                system_uptime=0.0,
                security_features={}
            )
    
    @staticmethod
    def _detect_firewall() -> bool:
        """Detect if firewall is active."""
        try:
            # Check for common firewall indicators
            if platform.system() == 'Linux':
                # Check iptables
                import subprocess
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                return result.returncode == 0 and 'Chain' in result.stdout
            elif platform.system() == 'Darwin':
                # Check pfctl on macOS
                import subprocess
                result = subprocess.run(['pfctl', '-s', 'info'], capture_output=True, text=True)
                return result.returncode == 0
            elif platform.system() == 'Windows':
                # Check Windows firewall
                import subprocess
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                      capture_output=True, text=True)
                return result.returncode == 0 and 'State' in result.stdout
        except Exception:
            pass
        return False
    
    @staticmethod
    def _detect_antivirus() -> bool:
        """Detect if antivirus is running."""
        try:
            # Look for common antivirus processes
            av_processes = ['clamav', 'avast', 'kaspersky', 'norton', 'mcafee', 'defender']
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(av in proc_name for av in av_processes):
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return False
    
    @staticmethod
    def _detect_docker() -> bool:
        """Detect if Docker is available."""
        try:
            import subprocess
            result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            pass
        return False
    
    @staticmethod
    def _detect_selinux() -> bool:
        """Detect if SELinux is enabled."""
        try:
            if platform.system() == 'Linux':
                import subprocess
                result = subprocess.run(['getenforce'], capture_output=True, text=True)
                return result.returncode == 0 and 'Enforcing' in result.stdout
        except Exception:
            pass
        return False
    
    @staticmethod
    def _detect_apparmor() -> bool:
        """Detect if AppArmor is enabled."""
        try:
            if platform.system() == 'Linux':
                import subprocess
                result = subprocess.run(['aa-status'], capture_output=True, text=True)
                return result.returncode == 0
        except Exception:
            pass
        return False
    
    @staticmethod
    def _detect_encryption_tools() -> bool:
        """Detect if encryption tools are available."""
        try:
            # Check for common encryption tools
            encryption_tools = ['gpg', 'openssl', 'cryptsetup']
            for tool in encryption_tools:
                import subprocess
                result = subprocess.run([tool, '--version'], capture_output=True, text=True)
                if result.returncode == 0:
                    return True
        except Exception:
            pass
        return False


class ThreatContextBuilder:
    """
    Builds comprehensive environment context for AI threat analysis.
    
    This class analyzes detection results and system information to build
    a detailed understanding of the deployment environment, security posture,
    and risk factors that influence threat analysis.
    """
    
    def __init__(self):
        """Initialize the threat context builder."""
        self.logger = logging.getLogger(__name__)
        self._system_info_cache = None
        self._cache_timestamp = 0
        self._cache_ttl = 300  # 5 minutes
        self.environment_detector = EnvironmentDetector()  # Add environment detector
        
        self.logger.info("ThreatContextBuilder initialized")
    
    def build_context(self, 
                     detection_results: List[DetectionResult],
                     system_info: Optional[SystemInfo] = None) -> EnvironmentContext:
        """
        Build comprehensive environment context from detection results and system info.
        
        Args:
            detection_results: List of MCP detection results
            system_info: Optional system information (will be gathered if not provided)
            
        Returns:
            EnvironmentContext with comprehensive environment analysis
        """
        try:
            self.logger.info(f"Building environment context from {len(detection_results)} detection results")
            
            # Gather system info if not provided
            if system_info is None:
                system_info = self._get_cached_system_info()
            
            # Analyze detection results
            mcp_servers = []
            for result in detection_results:
                if result.is_mcp_detected and result.mcp_server:
                    mcp_servers.append(result.mcp_server)
            
            # Build context components
            deployment_type = self._analyze_deployment_type(mcp_servers, system_info)
            security_posture = self._analyze_security_posture(mcp_servers, system_info)
            data_sensitivity = self._analyze_data_sensitivity(mcp_servers, system_info)
            network_exposure = self._analyze_network_exposure(mcp_servers, system_info)
            user_privileges = self._analyze_user_privileges(system_info)
            compliance_requirements = self._analyze_compliance_requirements(mcp_servers, system_info)
            
            context = EnvironmentContext(
                deployment_type=deployment_type,
                security_posture=security_posture,
                data_sensitivity=data_sensitivity,
                network_exposure=network_exposure,
                user_privileges=user_privileges,
                compliance_requirements=compliance_requirements
            )
            
            self.logger.info(f"Environment context built: {deployment_type.value}, {security_posture.value}, {network_exposure.value}")
            return context
            
        except Exception as e:
            self.logger.error(f"Failed to build environment context: {e}")
            # Return default context
            return self._get_default_context()
    
    def build_context_from_servers(self, 
                                  mcp_servers: List[MCPServerInfo],
                                  system_info: Optional[SystemInfo] = None) -> EnvironmentContext:
        """
        Build environment context directly from MCP server info.
        
        Args:
            mcp_servers: List of MCP server information
            system_info: Optional system information
            
        Returns:
            EnvironmentContext based on server analysis
        """
        try:
            # Gather system info if not provided
            if system_info is None:
                system_info = self._get_cached_system_info()
            
            # Build context components
            deployment_type = self._analyze_deployment_type(mcp_servers, system_info)
            security_posture = self._analyze_security_posture(mcp_servers, system_info) 
            data_sensitivity = self._analyze_data_sensitivity(mcp_servers, system_info)
            network_exposure = self._analyze_network_exposure(mcp_servers, system_info)
            user_privileges = self._analyze_user_privileges(system_info)
            compliance_requirements = self._analyze_compliance_requirements(mcp_servers, system_info)
            
            return EnvironmentContext(
                deployment_type=deployment_type,
                security_posture=security_posture,
                data_sensitivity=data_sensitivity,
                network_exposure=network_exposure,
                user_privileges=user_privileges,
                compliance_requirements=compliance_requirements
            )
            
        except Exception as e:
            self.logger.error(f"Failed to build context from servers: {e}")
            return self._get_default_context()
    
    def analyze_deployment_environment(self, 
                                     mcp_servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """
        Analyze deployment environment characteristics.
        
        Args:
            mcp_servers: List of MCP servers to analyze
            
        Returns:
            Dictionary with deployment environment analysis
        """
        analysis = {
            'total_servers': len(mcp_servers),
            'unique_hosts': len(set(server.host for server in mcp_servers)),
            'transport_types': {},
            'security_features': {
                'encrypted_transport': 0,
                'authentication_enabled': 0,
                'localhost_only': 0
            },
            'deployment_patterns': {
                'cloud_indicators': 0,
                'container_indicators': 0,
                'development_indicators': 0,
                'production_indicators': 0
            }
        }
        
        for server in mcp_servers:
            # Transport type analysis
            transport = server.transport_type.value if server.transport_type else 'unknown'
            analysis['transport_types'][transport] = analysis['transport_types'].get(transport, 0) + 1
            
            # Security features
            if server.is_secure:
                analysis['security_features']['encrypted_transport'] += 1
            if server.has_authentication:
                analysis['security_features']['authentication_enabled'] += 1
            if server.host in ['localhost', '127.0.0.1', '::1']:
                analysis['security_features']['localhost_only'] += 1
            
            # Deployment pattern analysis
            server_metadata = str(server.metadata).lower()
            if any(indicator in server_metadata for indicator in ['aws', 'gcp', 'azure', 'cloud']):
                analysis['deployment_patterns']['cloud_indicators'] += 1
            if any(indicator in server_metadata for indicator in ['docker', 'container', 'k8s', 'kubernetes']):
                analysis['deployment_patterns']['container_indicators'] += 1
            if any(indicator in server_metadata for indicator in ['dev', 'test', 'staging', 'localhost']):
                analysis['deployment_patterns']['development_indicators'] += 1
            if any(indicator in server_metadata for indicator in ['prod', 'production', 'live']):
                analysis['deployment_patterns']['production_indicators'] += 1
        
        return analysis
    
    def _get_cached_system_info(self) -> SystemInfo:
        """Get cached system info or gather new info if cache is stale."""
        current_time = time.time()
        
        if (self._system_info_cache is None or 
            current_time - self._cache_timestamp > self._cache_ttl):
            
            self.logger.debug("Gathering fresh system information")
            self._system_info_cache = SystemInfo.gather_system_info()
            self._cache_timestamp = current_time
        
        return self._system_info_cache
    
    def _analyze_deployment_type(self, 
                               mcp_servers: List[MCPServerInfo],
                               system_info: SystemInfo) -> DeploymentType:
        """Analyze deployment type from servers and system info."""
        try:
            # Check for cloud indicators
            cloud_indicators = 0
            remote_indicators = 0
            local_indicators = 0
            
            # Analyze servers
            for server in mcp_servers:
                if server.host not in ['localhost', '127.0.0.1', '::1']:
                    remote_indicators += 1
                else:
                    local_indicators += 1
                
                # Check metadata for cloud services
                metadata_str = str(server.metadata).lower()
                if any(cloud in metadata_str for cloud in ['aws', 'gcp', 'azure', 'cloud']):
                    cloud_indicators += 1
            
            # Check system info for cloud/container indicators
            if system_info.security_features.get('docker_available', False):
                cloud_indicators += 1
            
            # Look for cloud provider metadata in environment
            cloud_env_indicators = ['AWS_', 'GOOGLE_', 'AZURE_', 'CLOUD_']
            for env_key in system_info.environment_variables:
                if any(indicator in env_key for indicator in cloud_env_indicators):
                    cloud_indicators += 1
                    break
            
            # Determine deployment type
            if cloud_indicators > 0:
                if remote_indicators > 0 and local_indicators > 0:
                    return DeploymentType.HYBRID
                else:
                    return DeploymentType.CLOUD
            elif remote_indicators > local_indicators:
                return DeploymentType.REMOTE
            else:
                return DeploymentType.LOCAL
                
        except Exception as e:
            self.logger.warning(f"Failed to analyze deployment type: {e}")
            return DeploymentType.LOCAL
    
    def _analyze_security_posture(self, 
                                mcp_servers: List[MCPServerInfo],
                                system_info: SystemInfo) -> SecurityPosture:
        """Analyze security posture from servers and system info."""
        try:
            security_score = 0
            total_checks = 0
            
            # Check server security features
            for server in mcp_servers:
                total_checks += 2
                if server.is_secure:
                    security_score += 1
                if server.has_authentication:
                    security_score += 1
            
            # Check system security features
            security_features = system_info.security_features
            system_security_checks = [
                'firewall_detected',
                'antivirus_detected', 
                'selinux_enabled',
                'apparmor_enabled',
                'encryption_available'
            ]
            
            for feature in system_security_checks:
                total_checks += 1
                if security_features.get(feature, False):
                    security_score += 1
            
            # Check for privileged user groups
            privileged_groups = ['admin', 'root', 'sudo', 'wheel']
            for group in system_info.user_groups:
                if group.lower() in privileged_groups:
                    total_checks += 1
                    # Running as privileged user decreases security score
                    pass  # Don't add to security_score
                else:
                    total_checks += 1
                    security_score += 1
                    break
            
            # Calculate security posture
            if total_checks > 0:
                security_ratio = security_score / total_checks
                if security_ratio >= 0.8:
                    return SecurityPosture.HIGH
                elif security_ratio >= 0.5:
                    return SecurityPosture.MEDIUM
                else:
                    return SecurityPosture.LOW
            else:
                return SecurityPosture.MEDIUM
                
        except Exception as e:
            self.logger.warning(f"Failed to analyze security posture: {e}")
            return SecurityPosture.MEDIUM
    
    def _analyze_data_sensitivity(self, 
                                mcp_servers: List[MCPServerInfo],
                                system_info: SystemInfo) -> DataSensitivity:
        """Analyze data sensitivity from servers and environment."""
        try:
            # Look for sensitivity indicators in server metadata
            high_sensitivity_indicators = [
                'financial', 'medical', 'personal', 'confidential', 
                'secret', 'classified', 'private'
            ]
            
            medium_sensitivity_indicators = [
                'internal', 'company', 'proprietary', 'business'
            ]
            
            for server in mcp_servers:
                metadata_str = str(server.metadata).lower()
                if any(indicator in metadata_str for indicator in high_sensitivity_indicators):
                    return DataSensitivity.CONFIDENTIAL
                elif any(indicator in metadata_str for indicator in medium_sensitivity_indicators):
                    return DataSensitivity.INTERNAL
            
            # Check environment variables for sensitivity indicators
            for env_key in system_info.environment_variables:
                env_key_lower = env_key.lower()
                if any(indicator in env_key_lower for indicator in high_sensitivity_indicators):
                    return DataSensitivity.CONFIDENTIAL
                elif any(indicator in env_key_lower for indicator in medium_sensitivity_indicators):
                    return DataSensitivity.INTERNAL
            
            # Default to internal for business environments
            return DataSensitivity.INTERNAL
            
        except Exception as e:
            self.logger.warning(f"Failed to analyze data sensitivity: {e}")
            return DataSensitivity.INTERNAL
    
    def _analyze_network_exposure(self, 
                                mcp_servers: List[MCPServerInfo],
                                system_info: SystemInfo) -> NetworkExposure:
        """Analyze network exposure from servers and network config."""
        try:
            # Check if any servers are listening on non-localhost addresses
            external_servers = 0
            localhost_servers = 0
            
            for server in mcp_servers:
                if server.host in ['localhost', '127.0.0.1', '::1']:
                    localhost_servers += 1
                elif server.host in ['0.0.0.0', '::']:
                    # Listening on all interfaces
                    external_servers += 1
                    return NetworkExposure.INTERNET_FACING
                else:
                    external_servers += 1
            
            # Check network interfaces for public IPs
            for interface in system_info.network_interfaces:
                for addr_info in interface['addresses']:
                    addr = addr_info['address']
                    if self._is_public_ip(addr):
                        return NetworkExposure.INTERNET_FACING
            
            # Determine exposure level
            if external_servers > 0:
                return NetworkExposure.INTERNAL
            else:
                return NetworkExposure.ISOLATED
                
        except Exception as e:
            self.logger.warning(f"Failed to analyze network exposure: {e}")
            return NetworkExposure.INTERNAL
    
    def _analyze_user_privileges(self, system_info: SystemInfo) -> UserPrivileges:
        """Analyze user privilege level from system info."""
        try:
            # Check user groups for privilege indicators
            privileged_groups = ['root', 'admin', 'administrator', 'sudo', 'wheel']
            elevated_groups = ['staff', 'users', 'power users']
            
            for group in system_info.user_groups:
                group_lower = group.lower()
                if group_lower in privileged_groups:
                    if group_lower == 'root':
                        return UserPrivileges.ROOT
                    else:
                        return UserPrivileges.ADMIN
                elif group_lower in elevated_groups:
                    return UserPrivileges.ELEVATED
            
            # Check environment variables for privilege indicators
            user = system_info.environment_variables.get('USER', '').lower()
            if user in ['root', 'administrator']:
                return UserPrivileges.ROOT
            elif user in ['admin']:
                return UserPrivileges.ADMIN
            
            return UserPrivileges.STANDARD
            
        except Exception as e:
            self.logger.warning(f"Failed to analyze user privileges: {e}")
            return UserPrivileges.STANDARD
    
    def _analyze_compliance_requirements(self, 
                                       mcp_servers: List[MCPServerInfo],
                                       system_info: SystemInfo) -> List[ComplianceFramework]:
        """Analyze potential compliance requirements."""
        try:
            requirements = []
            
            # Look for compliance indicators in server metadata
            compliance_indicators = {
                'pci': ComplianceFramework.PCI_DSS,
                'hipaa': ComplianceFramework.HIPAA,
                'gdpr': ComplianceFramework.GDPR,
                'sox': ComplianceFramework.SOC2,
                'iso27001': ComplianceFramework.ISO_27001,
                'nist': ComplianceFramework.NIST_CSF
            }
            
            # Check server metadata
            for server in mcp_servers:
                metadata_str = str(server.metadata).lower()
                for indicator, framework in compliance_indicators.items():
                    if indicator in metadata_str and framework not in requirements:
                        requirements.append(framework)
            
            # Check environment variables
            for env_key in system_info.environment_variables:
                env_key_lower = env_key.lower()
                for indicator, framework in compliance_indicators.items():
                    if indicator in env_key_lower and framework not in requirements:
                        requirements.append(framework)
            
            # Default compliance frameworks for business environments
            if not requirements:
                requirements.append(ComplianceFramework.OWASP_TOP_10)
            
            return requirements
            
        except Exception as e:
            self.logger.warning(f"Failed to analyze compliance requirements: {e}")
            return [ComplianceFramework.OWASP_TOP_10]
    
    def _is_public_ip(self, ip_address: str) -> bool:
        """Check if an IP address is publicly routable."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except Exception:
            return False
    
    def _get_default_context(self) -> EnvironmentContext:
        """Get default environment context."""
        return EnvironmentContext(
            deployment_type=DeploymentType.LOCAL,
            security_posture=SecurityPosture.MEDIUM,
            data_sensitivity=DataSensitivity.INTERNAL,
            network_exposure=NetworkExposure.INTERNAL,
            user_privileges=UserPrivileges.STANDARD,
            compliance_requirements=[ComplianceFramework.OWASP_TOP_10]
        )
    
    def build_enhanced_context(self, 
                             mcp_servers: List[MCPServerInfo],
                             system_info: Optional[SystemInfo] = None) -> Dict[str, Any]:
        """
        Build enhanced environment context using advanced detection capabilities.
        
        This method combines the basic context building with advanced environment
        detection to provide comprehensive environment analysis.
        
        Args:
            mcp_servers: List of MCP servers to analyze
            system_info: Optional system information
            
        Returns:
            Enhanced environment context with comprehensive analysis
        """
        try:
            self.logger.info("Building enhanced environment context")
            
            # Get basic environment context
            basic_context = self.build_context_from_servers(mcp_servers, system_info)
            
            # Get advanced environment detection results
            advanced_detection = self.environment_detector.detect_comprehensive_environment(
                mcp_servers, system_info
            )
            
            # Combine results into enhanced context
            enhanced_context = {
                # Basic context (from original ThreatContextBuilder)
                'basic_context': {
                    'deployment_type': basic_context.deployment_type,
                    'security_posture': basic_context.security_posture,
                    'data_sensitivity': basic_context.data_sensitivity,
                    'network_exposure': basic_context.network_exposure,
                    'user_privileges': basic_context.user_privileges,
                    'compliance_requirements': basic_context.compliance_requirements
                },
                
                # Advanced detection results (from EnvironmentDetector)
                'advanced_detection': advanced_detection,
                
                # Enhanced analysis combining both
                'enhanced_analysis': self._build_enhanced_analysis(basic_context, advanced_detection),
                
                # Metadata
                'detection_metadata': {
                    'detection_confidence': advanced_detection.get('detection_confidence', 0.0),
                    'analysis_timestamp': advanced_detection.get('analysis_timestamp', time.time()),
                    'detection_method': 'enhanced',
                    'components_analyzed': [
                        'infrastructure', 'security_environment', 'network_architecture',
                        'deployment_classification', 'technology_stack', 'deployment_patterns'
                    ]
                }
            }
            
            self.logger.info(f"Enhanced context built with {enhanced_context['detection_metadata']['detection_confidence']:.2f} confidence")
            return enhanced_context
            
        except Exception as e:
            self.logger.error(f"Enhanced context building failed: {e}")
            # Fallback to basic context
            basic_context = self.build_context_from_servers(mcp_servers, system_info)
            return {
                'basic_context': {
                    'deployment_type': basic_context.deployment_type,
                    'security_posture': basic_context.security_posture,
                    'data_sensitivity': basic_context.data_sensitivity,
                    'network_exposure': basic_context.network_exposure,
                    'user_privileges': basic_context.user_privileges,
                    'compliance_requirements': basic_context.compliance_requirements
                },
                'advanced_detection': self.environment_detector._get_default_detection_results(),
                'enhanced_analysis': {'threat_multiplier': 1.0, 'risk_factors': []},
                'detection_metadata': {
                    'detection_confidence': 0.0,
                    'analysis_timestamp': time.time(),
                    'detection_method': 'fallback',
                    'error': str(e)
                }
            }
    
    def _build_enhanced_analysis(self, 
                               basic_context: EnvironmentContext,
                               advanced_detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build enhanced analysis by combining basic context with advanced detection.
        
        Args:
            basic_context: Basic environment context
            advanced_detection: Advanced detection results
            
        Returns:
            Enhanced analysis combining both sources
        """
        try:
            enhanced_analysis = {
                'threat_multiplier': 1.0,
                'risk_factors': [],
                'security_recommendations': [],
                'deployment_risks': [],
                'compliance_gaps': [],
                'monitoring_gaps': []
            }
            
            # Calculate threat multiplier based on environment characteristics
            threat_multiplier = 1.0
            
            # Infrastructure complexity increases threat surface
            infra = advanced_detection.get('infrastructure', {})
            if infra.get('cloud_provider'):
                threat_multiplier += 0.2
                enhanced_analysis['risk_factors'].append('Cloud deployment increases attack surface')
            
            if infra.get('container_runtime', {}).get('detected'):
                threat_multiplier += 0.15
                enhanced_analysis['risk_factors'].append('Container runtime adds complexity')
            
            # Security environment affects threat landscape
            security_env = advanced_detection.get('security_environment', {})
            security_maturity = security_env.get('security_maturity', 'unknown')
            
            if security_maturity == 'minimal':
                threat_multiplier += 0.5
                enhanced_analysis['risk_factors'].append('Minimal security controls')
                enhanced_analysis['security_recommendations'].extend([
                    'Implement endpoint detection and response (EDR)',
                    'Deploy security information and event management (SIEM)',
                    'Enable host-based firewalls',
                    'Implement regular vulnerability scanning'
                ])
            elif security_maturity == 'basic':
                threat_multiplier += 0.3
                enhanced_analysis['risk_factors'].append('Basic security controls only')
                enhanced_analysis['security_recommendations'].extend([
                    'Upgrade to advanced threat detection',
                    'Implement centralized logging',
                    'Add network segmentation'
                ])
            elif security_maturity == 'advanced':
                threat_multiplier -= 0.1  # Advanced security reduces risk
                enhanced_analysis['risk_factors'].append('Advanced security controls detected')
            
            # Network exposure significantly impacts risk
            network_arch = advanced_detection.get('network_architecture', {})
            exposure_level = network_arch.get('exposure_level', 'unknown')
            
            if exposure_level == 'internet_facing':
                threat_multiplier += 0.4
                enhanced_analysis['risk_factors'].append('Internet-facing services')
                enhanced_analysis['deployment_risks'].extend([
                    'Public IP addresses increase attack surface',
                    'Consider implementing WAF/DDoS protection',
                    'Ensure all services have proper authentication'
                ])
            elif exposure_level == 'network_accessible':
                threat_multiplier += 0.2
                enhanced_analysis['risk_factors'].append('Network-accessible services')
            
            # Deployment classification affects risk profile
            deployment_class = advanced_detection.get('deployment_classification', {})
            env_type = deployment_class.get('environment_type', 'unknown')
            
            if env_type == 'production':
                threat_multiplier += 0.25
                enhanced_analysis['risk_factors'].append('Production environment')
                enhanced_analysis['deployment_risks'].extend([
                    'Production systems are high-value targets',
                    'Ensure proper backup and recovery procedures',
                    'Implement change management controls'
                ])
            elif env_type == 'development':
                threat_multiplier += 0.1
                enhanced_analysis['risk_factors'].append('Development environment with potentially weak controls')
                enhanced_analysis['deployment_risks'].append('Development environments often lack security controls')
            
            # Technology stack diversity affects complexity
            tech_stack = advanced_detection.get('technology_stack', {})
            language_count = len(tech_stack.get('languages', []))
            if language_count > 3:
                threat_multiplier += 0.1
                enhanced_analysis['risk_factors'].append('Complex technology stack')
            
            # Compliance analysis
            compliance_requirements = basic_context.compliance_requirements
            compliance_indicators = security_env.get('compliance_indicators', [])
            
            for requirement in compliance_requirements:
                requirement_name = requirement.value if hasattr(requirement, 'value') else str(requirement)
                if requirement_name.lower() not in [ind.lower() for ind in compliance_indicators]:
                    enhanced_analysis['compliance_gaps'].append(f'Missing indicators for {requirement_name}')
            
            # Monitoring gaps
            monitoring_capabilities = security_env.get('monitoring_capabilities', [])
            if not monitoring_capabilities:
                enhanced_analysis['monitoring_gaps'].append('No security monitoring detected')
            elif len(monitoring_capabilities) < 2:
                enhanced_analysis['monitoring_gaps'].append('Limited security monitoring capabilities')
            
            # Finalize threat multiplier
            enhanced_analysis['threat_multiplier'] = max(0.5, min(3.0, threat_multiplier))
            
            return enhanced_analysis
            
        except Exception as e:
            self.logger.warning(f"Enhanced analysis building failed: {e}")
            return {
                'threat_multiplier': 1.0,
                'risk_factors': ['Analysis failed - using default multiplier'],
                'security_recommendations': [],
                'deployment_risks': [],
                'compliance_gaps': [],
                'monitoring_gaps': []
            }


class EnvironmentDetector:
    """
    Enhanced environment detection system for comprehensive deployment analysis.
    
    This class provides advanced environment detection capabilities beyond the basic
    ThreatContextBuilder, focusing on infrastructure detection, security environment
    analysis, network architecture discovery, and deployment pattern recognition.
    """
    
    def __init__(self):
        """Initialize the environment detector."""
        self.logger = logging.getLogger(__name__)
        self._detection_cache = {}
        self._cache_ttl = 600  # 10 minutes
        
        # Cloud platform indicators
        self.cloud_indicators = {
            'aws': {
                'environment_vars': ['AWS_', 'AMAZON_', 'EC2_'],
                'processes': ['aws-cli', 'awscli', 'amazon-ssm-agent'],
                'metadata_urls': ['http://169.254.169.254/latest/meta-data/'],
                'file_paths': ['/opt/aws/', '/var/lib/amazon/']
            },
            'gcp': {
                'environment_vars': ['GOOGLE_', 'GCP_', 'GCLOUD_'],
                'processes': ['gcloud', 'google-cloud-sdk'],
                'metadata_urls': ['http://metadata.google.internal/'],
                'file_paths': ['/usr/lib/google-cloud-sdk/']
            },
            'azure': {
                'environment_vars': ['AZURE_', 'MICROSOFT_'],
                'processes': ['azure-cli', 'waagent'],
                'metadata_urls': ['http://169.254.169.254/metadata/'],
                'file_paths': ['/var/lib/waagent/']
            }
        }
        
        # Container and virtualization indicators
        self.container_indicators = {
            'docker': {
                'files': ['/.dockerenv', '/proc/1/cgroup'],
                'processes': ['dockerd', 'docker-proxy', 'containerd'],
                'environment_vars': ['DOCKER_']
            },
            'kubernetes': {
                'environment_vars': ['KUBERNETES_', 'K8S_'],
                'files': ['/var/run/secrets/kubernetes.io/'],
                'processes': ['kubelet', 'kube-proxy']
            },
            'podman': {
                'processes': ['podman', 'conmon'],
                'files': ['/run/podman/']
            }
        }
        
        # Security tool indicators
        self.security_tools = {
            'edr_solutions': {
                'crowdstrike': ['CsFalconService', 'falcon-sensor'],
                'sentinelone': ['SentinelAgent', 'sentinelctl'],
                'carbonblack': ['cb-enterprise', 'cbagentd'],
                'cylance': ['CylanceSvc', 'CylanceUI'],
                'defender': ['MsMpEng.exe', 'microsoft-defender']
            },
            'siem_agents': {
                'splunk': ['splunkd', 'splunk-forwarder'],
                'elastic': ['elastic-agent', 'filebeat', 'metricbeat'],
                'datadog': ['datadog-agent', 'dd-agent'],
                'newrelic': ['newrelic-daemon', 'nri-agent']
            },
            'vulnerability_scanners': {
                'nessus': ['nessusd', 'nessus-agent'],
                'qualys': ['qualys-cloud-agent'],
                'rapid7': ['ir_agent', 'insight_agent']
            }
        }
        
        self.logger.info("EnvironmentDetector initialized")
    
    def detect_comprehensive_environment(self, 
                                       mcp_servers: List[MCPServerInfo],
                                       system_info: Optional[SystemInfo] = None) -> Dict[str, Any]:
        """
        Perform comprehensive environment detection and analysis.
        
        Args:
            mcp_servers: List of detected MCP servers
            system_info: Optional system information
            
        Returns:
            Comprehensive environment detection results
        """
        try:
            self.logger.info("Starting comprehensive environment detection")
            
            if system_info is None:
                system_info = SystemInfo.gather_system_info()
            
            # Core detection components
            infrastructure = self._detect_infrastructure(system_info)
            security_environment = self._analyze_security_environment(system_info)
            network_architecture = self._discover_network_architecture(system_info)
            deployment_classification = self._classify_deployment_environment(mcp_servers, system_info)
            technology_stack = self._detect_technology_stack(mcp_servers, system_info)
            deployment_patterns = self._analyze_deployment_patterns(mcp_servers, system_info)
            
            # Composite analysis
            environment_profile = self._build_environment_profile(
                infrastructure, security_environment, network_architecture,
                deployment_classification, technology_stack, deployment_patterns
            )
            
            detection_results = {
                'infrastructure': infrastructure,
                'security_environment': security_environment,
                'network_architecture': network_architecture,
                'deployment_classification': deployment_classification,
                'technology_stack': technology_stack,
                'deployment_patterns': deployment_patterns,
                'environment_profile': environment_profile,
                'detection_confidence': self._calculate_detection_confidence(environment_profile),
                'analysis_timestamp': time.time()
            }
            
            self.logger.info(f"Environment detection completed with {detection_results['detection_confidence']:.2f} confidence")
            return detection_results
            
        except Exception as e:
            self.logger.error(f"Comprehensive environment detection failed: {e}")
            return self._get_default_detection_results()
    
    def _detect_infrastructure(self, system_info: SystemInfo) -> Dict[str, Any]:
        """Detect infrastructure platform and virtualization."""
        infrastructure = {
            'platform_type': 'unknown',
            'cloud_provider': None,
            'virtualization': {
                'type': 'unknown',
                'detected': False,
                'indicators': []
            },
            'container_runtime': {
                'detected': False,
                'types': [],
                'orchestration': None
            },
            'hardware_profile': {
                'cpu_type': 'unknown',
                'memory_profile': 'unknown',
                'storage_type': 'unknown'
            },
            'confidence_score': 0.0
        }
        
        try:
            # Cloud platform detection
            cloud_provider = self._detect_cloud_provider(system_info)
            if cloud_provider:
                infrastructure['platform_type'] = 'cloud'
                infrastructure['cloud_provider'] = cloud_provider
                infrastructure['confidence_score'] += 0.3
            
            # Virtualization detection
            virtualization = self._detect_virtualization(system_info)
            infrastructure['virtualization'] = virtualization
            if virtualization['detected']:
                infrastructure['confidence_score'] += 0.2
            
            # Container runtime detection
            containers = self._detect_container_runtime(system_info)
            infrastructure['container_runtime'] = containers  
            if containers['detected']:
                infrastructure['confidence_score'] += 0.2
            
            # Hardware profile analysis
            hardware = self._analyze_hardware_profile(system_info)
            infrastructure['hardware_profile'] = hardware
            infrastructure['confidence_score'] += 0.1
            
            # Platform type determination
            if not infrastructure['cloud_provider']:
                if containers['detected']:
                    infrastructure['platform_type'] = 'containerized'
                elif virtualization['detected']:
                    infrastructure['platform_type'] = 'virtualized'
                else:
                    infrastructure['platform_type'] = 'physical'
            
            infrastructure['confidence_score'] = min(infrastructure['confidence_score'], 1.0)
            
        except Exception as e:
            self.logger.warning(f"Infrastructure detection failed: {e}")
        
        return infrastructure
    
    def _analyze_security_environment(self, system_info: SystemInfo) -> Dict[str, Any]:
        """Analyze security tools and environment."""
        security_env = {
            'edr_solutions': [],
            'siem_agents': [],
            'vulnerability_scanners': [],
            'security_controls': {
                'firewall': False,
                'antivirus': False,
                'encryption': False,
                'access_controls': False
            },
            'security_posture': 'unknown',
            'monitoring_capabilities': [],
            'compliance_indicators': [],
            'security_maturity': 'unknown'
        }
        
        try:
            # Detect EDR solutions
            for edr_name, indicators in self.security_tools['edr_solutions'].items():
                if self._check_process_indicators(indicators, system_info.running_processes):
                    security_env['edr_solutions'].append(edr_name)
            
            # Detect SIEM agents
            for siem_name, indicators in self.security_tools['siem_agents'].items():
                if self._check_process_indicators(indicators, system_info.running_processes):
                    security_env['siem_agents'].append(siem_name)
            
            # Detect vulnerability scanners
            for scanner_name, indicators in self.security_tools['vulnerability_scanners'].items():
                if self._check_process_indicators(indicators, system_info.running_processes):
                    security_env['vulnerability_scanners'].append(scanner_name)
            
            # Analyze security controls
            security_env['security_controls'] = self._analyze_security_controls(system_info)
            
            # Determine security posture
            security_env['security_posture'] = self._determine_security_posture(security_env)
            
            # Analyze monitoring capabilities
            security_env['monitoring_capabilities'] = self._analyze_monitoring_capabilities(security_env)
            
            # Detect compliance indicators
            security_env['compliance_indicators'] = self._detect_compliance_indicators(system_info)
            
            # Assess security maturity
            security_env['security_maturity'] = self._assess_security_maturity(security_env)
            
        except Exception as e:
            self.logger.warning(f"Security environment analysis failed: {e}")
        
        return security_env
    
    def _discover_network_architecture(self, system_info: SystemInfo) -> Dict[str, Any]:
        """Discover network architecture and topology."""
        network_arch = {
            'network_interfaces': [],
            'network_topology': 'unknown',
            'exposure_level': 'unknown',
            'network_security': {
                'vpn_detected': False,
                'proxy_detected': False,
                'load_balancer': False
            },
            'connectivity_patterns': {
                'inbound_services': 0,
                'outbound_connections': 0,
                'peer_to_peer': False
            },
            'network_monitoring': {
                'snmp_enabled': False,
                'netflow_detected': False,
                'packet_capture': False
            }
        }
        
        try:
            # Analyze network interfaces
            network_arch['network_interfaces'] = self._analyze_network_interfaces(system_info)
            
            # Determine network topology
            network_arch['network_topology'] = self._determine_network_topology(system_info)
            
            # Assess exposure level
            network_arch['exposure_level'] = self._assess_network_exposure_level(system_info)
            
            # Detect network security features
            network_arch['network_security'] = self._detect_network_security_features(system_info)
            
            # Analyze connectivity patterns
            network_arch['connectivity_patterns'] = self._analyze_connectivity_patterns(system_info)
            
            # Detect network monitoring
            network_arch['network_monitoring'] = self._detect_network_monitoring(system_info)
            
        except Exception as e:
            self.logger.warning(f"Network architecture discovery failed: {e}")
        
        return network_arch
    
    def _classify_deployment_environment(self, 
                                       mcp_servers: List[MCPServerInfo],
                                       system_info: SystemInfo) -> Dict[str, Any]:
        """Classify deployment environment (dev/staging/prod)."""
        classification = {
            'environment_type': 'unknown',
            'confidence': 0.0,
            'indicators': {
                'development': [],
                'staging': [],
                'production': []
            },
            'characteristics': {
                'stability': 'unknown',
                'security_level': 'unknown',
                'monitoring_level': 'unknown',
                'change_frequency': 'unknown'
            }
        }
        
        try:
            # Analyze environment indicators from MCP servers
            dev_indicators = self._analyze_development_indicators(mcp_servers, system_info)
            staging_indicators = self._analyze_staging_indicators(mcp_servers, system_info)
            prod_indicators = self._analyze_production_indicators(mcp_servers, system_info)
            
            classification['indicators']['development'] = dev_indicators
            classification['indicators']['staging'] = staging_indicators  
            classification['indicators']['production'] = prod_indicators
            
            # Determine environment type based on strongest indicators
            scores = {
                'development': len(dev_indicators),
                'staging': len(staging_indicators),
                'production': len(prod_indicators)
            }
            
            if max(scores.values()) > 0:
                classification['environment_type'] = max(scores, key=scores.get)
                classification['confidence'] = max(scores.values()) / (sum(scores.values()) + 1)
            
            # Analyze environment characteristics
            classification['characteristics'] = self._analyze_environment_characteristics(
                classification['environment_type'], system_info
            )
            
        except Exception as e:
            self.logger.warning(f"Deployment environment classification failed: {e}")
        
        return classification
    
    def _detect_technology_stack(self, 
                               mcp_servers: List[MCPServerInfo],
                               system_info: SystemInfo) -> Dict[str, Any]:
        """Detect technology stack and frameworks."""
        tech_stack = {
            'languages': [],
            'frameworks': [],
            'databases': [],
            'web_servers': [],
            'application_servers': [],
            'messaging_systems': [],
            'development_tools': [],
            'package_managers': [],
            'runtime_environments': []
        }
        
        try:
            # Analyze running processes for technology indicators
            processes = system_info.running_processes
            
            # Language runtimes
            language_indicators = {
                'python': ['python', 'python3', 'gunicorn', 'uwsgi'],
                'node.js': ['node', 'npm', 'nodejs'],
                'java': ['java', 'javac', 'tomcat'],
                'ruby': ['ruby', 'rails', 'puma'],
                'php': ['php', 'php-fpm'],
                'go': ['go'],
                'rust': ['cargo'],
                'dotnet': ['dotnet', 'mono']
            }
            
            for language, indicators in language_indicators.items():
                if any(indicator in ' '.join(processes).lower() for indicator in indicators):
                    tech_stack['languages'].append(language)
            
            # Web servers
            web_server_indicators = ['nginx', 'apache', 'httpd', 'lighttpd', 'caddy']
            for indicator in web_server_indicators:
                if indicator in ' '.join(processes).lower():
                    tech_stack['web_servers'].append(indicator)
            
            # Databases
            db_indicators = ['mysql', 'postgresql', 'redis', 'mongodb', 'elasticsearch']
            for indicator in db_indicators:
                if indicator in ' '.join(processes).lower():
                    tech_stack['databases'].append(indicator)
            
            # Analyze MCP servers for additional technology indicators
            tech_stack = self._analyze_mcp_technology_indicators(mcp_servers, tech_stack)
            
        except Exception as e:
            self.logger.warning(f"Technology stack detection failed: {e}")
        
        return tech_stack
    
    def _analyze_deployment_patterns(self, 
                                   mcp_servers: List[MCPServerInfo],
                                   system_info: SystemInfo) -> Dict[str, Any]:
        """Analyze deployment patterns and architecture."""
        patterns = {
            'architecture_pattern': 'unknown',
            'deployment_strategy': 'unknown',
            'scalability_indicators': {
                'load_balancing': False,
                'clustering': False,
                'auto_scaling': False
            },
            'integration_patterns': {
                'microservices': False,
                'monolithic': False,
                'serverless': False
            },
            'reliability_patterns': {
                'redundancy': False,
                'failover': False,
                'backup_systems': False
            }
        }
        
        try:
            # Analyze MCP server deployment patterns
            if len(mcp_servers) > 5:
                patterns['integration_patterns']['microservices'] = True
            elif len(mcp_servers) <= 2:
                patterns['integration_patterns']['monolithic'] = True
            
            # Look for serverless indicators
            serverless_indicators = ['lambda', 'azure-functions', 'cloud-functions']
            if any(indicator in str(server.metadata).lower() for server in mcp_servers for indicator in serverless_indicators):
                patterns['integration_patterns']['serverless'] = True
            
            # Analyze scalability indicators
            patterns['scalability_indicators'] = self._analyze_scalability_indicators(system_info)
            
            # Determine architecture pattern
            patterns['architecture_pattern'] = self._determine_architecture_pattern(patterns)
            
            # Analyze deployment strategy
            patterns['deployment_strategy'] = self._analyze_deployment_strategy(mcp_servers, system_info)
            
        except Exception as e:
            self.logger.warning(f"Deployment pattern analysis failed: {e}")
        
        return patterns

    # Supporting helper methods for EnvironmentDetector
    
    def _detect_cloud_provider(self, system_info: SystemInfo) -> Optional[str]:
        """Detect cloud provider from system information."""
        try:
            # Check environment variables
            for provider, indicators in self.cloud_indicators.items():
                for env_prefix in indicators['environment_vars']:
                    if any(env_key.startswith(env_prefix) for env_key in system_info.environment_variables):
                        return provider
            
            # Check running processes
            for provider, indicators in self.cloud_indicators.items():
                for process_indicator in indicators['processes']:
                    if any(process_indicator in process for process in system_info.running_processes):
                        return provider
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Cloud provider detection failed: {e}")
            return None
    
    def _detect_virtualization(self, system_info: SystemInfo) -> Dict[str, Any]:
        """Detect virtualization platform."""
        virtualization = {
            'type': 'unknown',
            'detected': False,
            'indicators': []
        }
        
        try:
            # Check for virtualization indicators in processes
            vm_indicators = {
                'vmware': ['vmware-toolbox', 'vmtoolsd'],
                'virtualbox': ['VBoxService', 'vboxguest'],
                'hyper-v': ['hv_', 'hypervvssd'],
                'kvm': ['kvm', 'qemu'],
                'xen': ['xenstore', 'xen-']
            }
            
            for vm_type, indicators in vm_indicators.items():
                for indicator in indicators:
                    if any(indicator in process for process in system_info.running_processes):
                        virtualization['type'] = vm_type
                        virtualization['detected'] = True
                        virtualization['indicators'].append(f"Process: {indicator}")
                        break
                        
                if virtualization['detected']:
                    break
            
            # Additional platform-specific checks
            if platform.system() == 'Linux':
                # Check DMI information if available
                try:
                    import subprocess
                    result = subprocess.run(['dmidecode', '-s', 'system-product-name'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        product_name = result.stdout.strip().lower()
                        if 'vmware' in product_name:
                            virtualization.update({'type': 'vmware', 'detected': True})
                            virtualization['indicators'].append("DMI: VMware")
                        elif 'virtualbox' in product_name:
                            virtualization.update({'type': 'virtualbox', 'detected': True})
                            virtualization['indicators'].append("DMI: VirtualBox")
                except Exception:
                    pass
            
        except Exception as e:
            self.logger.warning(f"Virtualization detection failed: {e}")
        
        return virtualization
    
    def _detect_container_runtime(self, system_info: SystemInfo) -> Dict[str, Any]:
        """Detect container runtime environment."""
        containers = {
            'detected': False,
            'types': [],
            'orchestration': None
        }
        
        try:
            # Check for container file indicators
            container_files = [
                '/.dockerenv',
                '/proc/1/cgroup'
            ]
            
            for file_path in container_files:
                if os.path.exists(file_path):
                    containers['detected'] = True
                    if 'docker' not in containers['types']:
                        containers['types'].append('docker')
                    break
            
            # Check for container processes
            container_processes = {
                'docker': ['dockerd', 'docker-proxy', 'containerd'],
                'podman': ['podman', 'conmon'],
                'kubernetes': ['kubelet', 'kube-proxy']
            }
            
            for container_type, processes in container_processes.items():
                if any(proc in ' '.join(system_info.running_processes) for proc in processes):
                    containers['detected'] = True
                    if container_type not in containers['types']:
                        containers['types'].append(container_type)
                    
                    if container_type == 'kubernetes':
                        containers['orchestration'] = 'kubernetes'
            
            # Check environment variables
            if any(env_key.startswith('DOCKER_') for env_key in system_info.environment_variables):
                containers['detected'] = True
                if 'docker' not in containers['types']:
                    containers['types'].append('docker')
            
            if any(env_key.startswith(('KUBERNETES_', 'K8S_')) for env_key in system_info.environment_variables):
                containers['orchestration'] = 'kubernetes'
            
        except Exception as e:
            self.logger.warning(f"Container runtime detection failed: {e}")
        
        return containers
    
    def _analyze_hardware_profile(self, system_info: SystemInfo) -> Dict[str, str]:
        """Analyze hardware profile characteristics."""
        try:
            # Analyze CPU
            cpu_type = 'unknown'
            if system_info.cpu_count <= 2:
                cpu_type = 'low_end'
            elif system_info.cpu_count <= 8:
                cpu_type = 'medium'
            else:
                cpu_type = 'high_end'
            
            # Analyze memory
            memory_profile = 'unknown'
            memory_gb = system_info.memory_total / (1024**3)
            if memory_gb < 4:
                memory_profile = 'low_memory'
            elif memory_gb < 16:
                memory_profile = 'medium_memory'
            else:
                memory_profile = 'high_memory'
            
            # Analyze storage (simplified)
            storage_type = 'unknown'
            total_disk_space = sum(
                disk_info.get('total', 0) 
                for disk_info in system_info.disk_usage.values()
            )
            if total_disk_space > 0:
                storage_type = 'standard'  # Could be enhanced with SSD/HDD detection
            
            return {
                'cpu_type': cpu_type,
                'memory_profile': memory_profile,
                'storage_type': storage_type
            }
            
        except Exception as e:
            self.logger.warning(f"Hardware profile analysis failed: {e}")
            return {
                'cpu_type': 'unknown',
                'memory_profile': 'unknown',
                'storage_type': 'unknown'
            }
    
    def _check_process_indicators(self, indicators: List[str], processes: List[str]) -> bool:
        """Check if any process indicators are present."""
        processes_str = ' '.join(processes).lower()
        return any(indicator.lower() in processes_str for indicator in indicators)
    
    def _analyze_security_controls(self, system_info: SystemInfo) -> Dict[str, bool]:
        """Analyze security controls from system info."""
        controls = {
            'firewall': system_info.security_features.get('firewall_detected', False),
            'antivirus': system_info.security_features.get('antivirus_detected', False),
            'encryption': system_info.security_features.get('encryption_available', False),
            'access_controls': system_info.security_features.get('selinux_enabled', False) or 
                            system_info.security_features.get('apparmor_enabled', False)
        }
        return controls
    
    def _determine_security_posture(self, security_env: Dict[str, Any]) -> str:
        """Determine overall security posture."""
        score = 0
        total = 0
        
        # EDR solutions
        total += 1
        if security_env['edr_solutions']:
            score += 1
        
        # SIEM agents
        total += 1
        if security_env['siem_agents']:
            score += 1
        
        # Security controls
        control_count = sum(security_env['security_controls'].values())
        total += len(security_env['security_controls'])
        score += control_count
        
        if total > 0:
            ratio = score / total
            if ratio >= 0.7:
                return 'high'
            elif ratio >= 0.4:
                return 'medium'
            else:
                return 'low'
        
        return 'unknown'
    
    def _analyze_monitoring_capabilities(self, security_env: Dict[str, Any]) -> List[str]:
        """Analyze monitoring capabilities."""
        capabilities = []
        
        if security_env['edr_solutions']:
            capabilities.append('endpoint_detection_response')
        
        if security_env['siem_agents']:
            capabilities.append('security_information_event_management')
        
        if security_env['vulnerability_scanners']:
            capabilities.append('vulnerability_assessment')
        
        return capabilities
    
    def _detect_compliance_indicators(self, system_info: SystemInfo) -> List[str]:
        """Detect compliance framework indicators."""
        indicators = []
        
        compliance_keywords = {
            'pci': ['pci', 'payment', 'card'],
            'hipaa': ['hipaa', 'health', 'medical'],
            'gdpr': ['gdpr', 'privacy', 'personal'],
            'sox': ['sox', 'sarbanes', 'oxley'],
            'iso27001': ['iso27001', 'information', 'security']
        }
        
        # Check environment variables
        for framework, keywords in compliance_keywords.items():
            for env_key in system_info.environment_variables:
                if any(keyword in env_key.lower() for keyword in keywords):
                    if framework not in indicators:
                        indicators.append(framework)
        
        return indicators
    
    def _assess_security_maturity(self, security_env: Dict[str, Any]) -> str:
        """Assess security maturity level."""
        maturity_score = 0
        
        # Basic security controls
        if any(security_env['security_controls'].values()):
            maturity_score += 1
        
        # Advanced security tools
        if security_env['edr_solutions']:
            maturity_score += 2
        
        if security_env['siem_agents']:
            maturity_score += 2
        
        if security_env['vulnerability_scanners']:
            maturity_score += 1
        
        # Monitoring capabilities
        if len(security_env['monitoring_capabilities']) > 1:
            maturity_score += 1
        
        if maturity_score >= 5:
            return 'advanced'
        elif maturity_score >= 3:
            return 'intermediate'
        elif maturity_score >= 1:
            return 'basic'
        else:
            return 'minimal'
    
    def _analyze_network_interfaces(self, system_info: SystemInfo) -> List[Dict[str, Any]]:
        """Analyze network interfaces for security implications."""
        analyzed_interfaces = []
        
        for interface in system_info.network_interfaces:
            interface_analysis = {
                'name': interface['name'],
                'addresses': [],
                'exposure_risk': 'low',
                'security_implications': []
            }
            
            for addr_info in interface['addresses']:
                addr = addr_info['address']
                addr_analysis = {
                    'address': addr,
                    'type': 'unknown',
                    'public': False
                }
                
                # Classify address type
                if addr.startswith('127.'):
                    addr_analysis['type'] = 'loopback'
                elif addr.startswith('192.168.') or addr.startswith('10.') or addr.startswith('172.'):
                    addr_analysis['type'] = 'private'
                elif addr == '0.0.0.0' or addr == '::':
                    addr_analysis['type'] = 'wildcard'
                    interface_analysis['exposure_risk'] = 'high'
                    interface_analysis['security_implications'].append('Listening on all interfaces')
                else:
                    addr_analysis['type'] = 'public'
                    addr_analysis['public'] = True
                    interface_analysis['exposure_risk'] = 'high'
                    interface_analysis['security_implications'].append('Public IP address')
                
                interface_analysis['addresses'].append(addr_analysis)
            
            analyzed_interfaces.append(interface_analysis)
        
        return analyzed_interfaces
    
    def _determine_network_topology(self, system_info: SystemInfo) -> str:
        """Determine network topology type."""
        # Simplified network topology detection
        interface_count = len(system_info.network_interfaces)
        
        if interface_count <= 1:
            return 'isolated'
        elif interface_count <= 3:
            return 'simple'
        else:
            return 'complex'
    
    def _assess_network_exposure_level(self, system_info: SystemInfo) -> str:
        """Assess network exposure level."""
        has_public_ip = False
        has_wildcard_binding = False
        
        for interface in system_info.network_interfaces:
            for addr_info in interface['addresses']:
                addr = addr_info['address']
                if self._is_public_ip(addr):
                    has_public_ip = True
                elif addr in ['0.0.0.0', '::']:
                    has_wildcard_binding = True
        
        if has_public_ip:
            return 'internet_facing'
        elif has_wildcard_binding:
            return 'network_accessible'
        else:
            return 'localhost_only'
    
    def _detect_network_security_features(self, system_info: SystemInfo) -> Dict[str, bool]:
        """Detect network security features."""
        security_features = {
            'vpn_detected': False,
            'proxy_detected': False,
            'load_balancer': False
        }
        
        # Check for VPN processes
        vpn_processes = ['openvpn', 'strongswan', 'ipsec', 'wireguard']
        if any(vpn_proc in ' '.join(system_info.running_processes).lower() for vpn_proc in vpn_processes):
            security_features['vpn_detected'] = True
        
        # Check for proxy processes
        proxy_processes = ['squid', 'nginx', 'haproxy', 'traefik']
        if any(proxy_proc in ' '.join(system_info.running_processes).lower() for proxy_proc in proxy_processes):
            security_features['proxy_detected'] = True
        
        # Check for load balancer
        lb_processes = ['haproxy', 'nginx', 'traefik', 'keepalived']
        if any(lb_proc in ' '.join(system_info.running_processes).lower() for lb_proc in lb_processes):
            security_features['load_balancer'] = True
        
        return security_features
    
    def _analyze_connectivity_patterns(self, system_info: SystemInfo) -> Dict[str, Any]:
        """Analyze connectivity patterns (simplified)."""
        # This is a simplified implementation
        # In a real implementation, you might analyze network connections, ports, etc.
        return {
            'inbound_services': len([proc for proc in system_info.running_processes if 'server' in proc.lower()]),
            'outbound_connections': 0,  # Would need netstat or similar
            'peer_to_peer': False  # Would need network analysis
        }
    
    def _detect_network_monitoring(self, system_info: SystemInfo) -> Dict[str, bool]:
        """Detect network monitoring capabilities."""
        monitoring = {
            'snmp_enabled': False,
            'netflow_detected': False,
            'packet_capture': False
        }
        
        # Check for SNMP
        if 'snmpd' in ' '.join(system_info.running_processes):
            monitoring['snmp_enabled'] = True
        
        # Check for packet capture tools
        pcap_tools = ['tcpdump', 'wireshark', 'tshark']
        if any(tool in ' '.join(system_info.running_processes) for tool in pcap_tools):
            monitoring['packet_capture'] = True
        
        return monitoring
    
    def _analyze_development_indicators(self, mcp_servers: List[MCPServerInfo], system_info: SystemInfo) -> List[str]:
        """Analyze development environment indicators."""
        indicators = []
        
        dev_keywords = ['dev', 'development', 'test', 'debug', 'localhost', 'staging']
        
        # Check MCP server metadata
        for server in mcp_servers:
            metadata_str = str(server.metadata).lower()
            for keyword in dev_keywords:
                if keyword in metadata_str:
                    indicators.append(f"MCP metadata contains '{keyword}'")
                    break
        
        # Check environment variables
        for env_key in system_info.environment_variables:
            env_key_lower = env_key.lower()
            for keyword in dev_keywords:
                if keyword in env_key_lower:
                    indicators.append(f"Environment variable contains '{keyword}'")
                    break
        
        # Check for development tools
        dev_tools = ['git', 'docker', 'npm', 'pip', 'yarn', 'composer']
        for tool in dev_tools:
            if tool in ' '.join(system_info.running_processes):
                indicators.append(f"Development tool '{tool}' running")
        
        return list(set(indicators))  # Remove duplicates
    
    def _analyze_staging_indicators(self, mcp_servers: List[MCPServerInfo], system_info: SystemInfo) -> List[str]:
        """Analyze staging environment indicators."""
        indicators = []
        
        staging_keywords = ['staging', 'stage', 'pre-prod', 'uat', 'qa']
        
        # Check MCP server metadata
        for server in mcp_servers:
            metadata_str = str(server.metadata).lower()
            for keyword in staging_keywords:
                if keyword in metadata_str:
                    indicators.append(f"MCP metadata contains '{keyword}'")
        
        # Check environment variables
        for env_key in system_info.environment_variables:
            env_key_lower = env_key.lower()
            for keyword in staging_keywords:
                if keyword in env_key_lower:
                    indicators.append(f"Environment variable contains '{keyword}'")
        
        return list(set(indicators))
    
    def _analyze_production_indicators(self, mcp_servers: List[MCPServerInfo], system_info: SystemInfo) -> List[str]:
        """Analyze production environment indicators."""
        indicators = []
        
        prod_keywords = ['prod', 'production', 'live', 'release']
        
        # Check MCP server metadata
        for server in mcp_servers:
            metadata_str = str(server.metadata).lower()
            for keyword in prod_keywords:
                if keyword in metadata_str:
                    indicators.append(f"MCP metadata contains '{keyword}'")
        
        # Check for production-like characteristics
        if len(system_info.running_processes) > 50:
            indicators.append("High number of running processes")
        
        if system_info.memory_total > 16 * 1024**3:  # > 16GB
            indicators.append("High memory configuration")
        
        # Check for monitoring/logging tools
        monitoring_tools = ['splunk', 'elasticsearch', 'logstash', 'prometheus']
        for tool in monitoring_tools:
            if tool in ' '.join(system_info.running_processes):
                indicators.append(f"Production monitoring tool '{tool}' detected")
        
        return list(set(indicators))
    
    def _analyze_environment_characteristics(self, env_type: str, system_info: SystemInfo) -> Dict[str, str]:
        """Analyze environment characteristics based on type."""
        characteristics = {
            'stability': 'unknown',
            'security_level': 'unknown',
            'monitoring_level': 'unknown',
            'change_frequency': 'unknown'
        }
        
        if env_type == 'production':
            characteristics.update({
                'stability': 'high',
                'security_level': 'high',
                'monitoring_level': 'high',
                'change_frequency': 'low'
            })
        elif env_type == 'staging':
            characteristics.update({
                'stability': 'medium',
                'security_level': 'medium',
                'monitoring_level': 'medium',
                'change_frequency': 'medium'
            })
        elif env_type == 'development':
            characteristics.update({
                'stability': 'low',
                'security_level': 'low',
                'monitoring_level': 'low',
                'change_frequency': 'high'
            })
        
        return characteristics
    
    def _analyze_mcp_technology_indicators(self, mcp_servers: List[MCPServerInfo], tech_stack: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Analyze MCP servers for technology indicators."""
        for server in mcp_servers:
            metadata_str = str(server.metadata).lower()
            
            # Framework detection
            framework_indicators = {
                'flask': 'python',
                'django': 'python',
                'express': 'node.js',
                'spring': 'java',
                'rails': 'ruby'
            }
            
            for framework, language in framework_indicators.items():
                if framework in metadata_str:
                    if framework not in tech_stack['frameworks']:
                        tech_stack['frameworks'].append(framework)
                    if language not in tech_stack['languages']:
                        tech_stack['languages'].append(language)
        
        return tech_stack
    
    def _analyze_scalability_indicators(self, system_info: SystemInfo) -> Dict[str, bool]:
        """Analyze scalability indicators."""
        indicators = {
            'load_balancing': False,
            'clustering': False,
            'auto_scaling': False
        }
        
        # Check for load balancing
        lb_processes = ['haproxy', 'nginx', 'traefik']
        if any(proc in ' '.join(system_info.running_processes) for proc in lb_processes):
            indicators['load_balancing'] = True
        
        # Check for clustering
        cluster_processes = ['consul', 'etcd', 'zookeeper']
        if any(proc in ' '.join(system_info.running_processes) for proc in cluster_processes):
            indicators['clustering'] = True
        
        # Check for auto-scaling (cloud environment indicators)
        autoscale_env_vars = ['AWS_AUTO_SCALING', 'AZURE_SCALE', 'GCP_AUTOSCALE']
        if any(env_var in system_info.environment_variables for env_var in autoscale_env_vars):
            indicators['auto_scaling'] = True
        
        return indicators
    
    def _determine_architecture_pattern(self, patterns: Dict[str, Any]) -> str:
        """Determine overall architecture pattern."""
        if patterns['integration_patterns']['microservices']:
            return 'microservices'
        elif patterns['integration_patterns']['serverless']:
            return 'serverless'
        elif patterns['integration_patterns']['monolithic']:
            return 'monolithic'
        else:
            return 'hybrid'
    
    def _analyze_deployment_strategy(self, mcp_servers: List[MCPServerInfo], system_info: SystemInfo) -> str:
        """Analyze deployment strategy."""
        # Check for containerization
        if any('docker' in str(server.metadata).lower() for server in mcp_servers):
            return 'containerized'
        
        # Check for cloud deployment
        cloud_indicators = ['aws', 'gcp', 'azure', 'cloud']
        if any(indicator in str(server.metadata).lower() for server in mcp_servers for indicator in cloud_indicators):
            return 'cloud_native'
        
        # Default to traditional
        return 'traditional'
    
    def _build_environment_profile(self, infrastructure: Dict[str, Any], security_environment: Dict[str, Any],
                                 network_architecture: Dict[str, Any], deployment_classification: Dict[str, Any],
                                 technology_stack: Dict[str, Any], deployment_patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive environment profile."""
        profile = {
            'deployment_complexity': 'unknown',
            'security_maturity': security_environment.get('security_maturity', 'unknown'),
            'technology_diversity': len(technology_stack.get('languages', [])),
            'infrastructure_sophistication': 'unknown',
            'operational_maturity': 'unknown',
            'risk_profile': 'unknown'
        }
        
        # Assess deployment complexity
        complexity_factors = 0
        if infrastructure.get('cloud_provider'):
            complexity_factors += 1
        if infrastructure.get('container_runtime', {}).get('detected'):
            complexity_factors += 1
        if deployment_patterns.get('integration_patterns', {}).get('microservices'):
            complexity_factors += 2
        
        if complexity_factors >= 3:
            profile['deployment_complexity'] = 'high'
        elif complexity_factors >= 2:
            profile['deployment_complexity'] = 'medium'
        else:
            profile['deployment_complexity'] = 'low'
        
        # Assess infrastructure sophistication
        if infrastructure.get('cloud_provider') and infrastructure.get('container_runtime', {}).get('detected'):
            profile['infrastructure_sophistication'] = 'high'
        elif infrastructure.get('cloud_provider') or infrastructure.get('container_runtime', {}).get('detected'):
            profile['infrastructure_sophistication'] = 'medium'
        else:
            profile['infrastructure_sophistication'] = 'low'
        
        # Assess operational maturity
        if (security_environment.get('security_maturity') == 'advanced' and 
            deployment_classification.get('environment_type') == 'production'):
            profile['operational_maturity'] = 'high'
        elif security_environment.get('security_maturity') in ['intermediate', 'basic']:
            profile['operational_maturity'] = 'medium'
        else:
            profile['operational_maturity'] = 'low'
        
        # Assess risk profile
        risk_factors = 0
        if network_architecture.get('exposure_level') == 'internet_facing':
            risk_factors += 2
        if security_environment.get('security_maturity') in ['minimal', 'basic']:
            risk_factors += 2
        if deployment_classification.get('environment_type') == 'production':
            risk_factors += 1
        
        if risk_factors >= 4:
            profile['risk_profile'] = 'high'
        elif risk_factors >= 2:
            profile['risk_profile'] = 'medium'
        else:
            profile['risk_profile'] = 'low'
        
        return profile
    
    def _calculate_detection_confidence(self, environment_profile: Dict[str, Any]) -> float:
        """Calculate overall detection confidence score."""
        confidence_factors = []
        
        # Check if we have meaningful data for each component
        if environment_profile.get('deployment_complexity') != 'unknown':
            confidence_factors.append(0.2)
        if environment_profile.get('security_maturity') != 'unknown':
            confidence_factors.append(0.2)
        if environment_profile.get('infrastructure_sophistication') != 'unknown':
            confidence_factors.append(0.2)
        if environment_profile.get('operational_maturity') != 'unknown':
            confidence_factors.append(0.2)
        if environment_profile.get('risk_profile') != 'unknown':
            confidence_factors.append(0.2)
        
        return sum(confidence_factors)
    
    def _get_default_detection_results(self) -> Dict[str, Any]:
        """Get default detection results when detection fails."""
        return {
            'infrastructure': {'platform_type': 'unknown', 'confidence_score': 0.0},
            'security_environment': {'security_posture': 'unknown'},
            'network_architecture': {'network_topology': 'unknown'},
            'deployment_classification': {'environment_type': 'unknown', 'confidence': 0.0},
            'technology_stack': {'languages': [], 'frameworks': []},
            'deployment_patterns': {'architecture_pattern': 'unknown'},
            'environment_profile': {'risk_profile': 'unknown'},
            'detection_confidence': 0.0,
            'analysis_timestamp': time.time()
        }
    
    def _is_public_ip(self, ip_address: str) -> bool:
        """Check if an IP address is publicly routable."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except Exception:
            return False


class MCPCapabilityAnalyzer:
    """
    Analyzes MCP tools to extract security-relevant capabilities.
    
    This class examines MCP server information to identify tool functions,
    categorize capabilities, and assess the attack surface exposed by the tools.
    """
    
    def __init__(self):
        """Initialize the capability analyzer."""
        self.logger = logging.getLogger(__name__)
        self.context_builder = ThreatContextBuilder()
        
        # Tool function patterns for capability categorization
        self.capability_patterns = {
            CapabilityCategory.FILE_SYSTEM: [
                'read_file', 'write_file', 'delete_file', 'list_directory',
                'create_directory', 'move_file', 'copy_file', 'file_search',
                'get_file_info', 'set_permissions'
            ],
            CapabilityCategory.NETWORK_ACCESS: [
                'web_search', 'http_request', 'api_call', 'download_file',
                'upload_file', 'send_email', 'websocket', 'ftp', 'ssh'
            ],
            CapabilityCategory.CODE_EXECUTION: [
                'execute_command', 'run_script', 'eval_code', 'shell_command',
                'python_exec', 'javascript_exec', 'compile_code', 'run_terminal_cmd'
            ],
            CapabilityCategory.DATA_PROCESSING: [
                'parse_data', 'transform_data', 'analyze_content', 'encrypt_data',
                'decrypt_data', 'hash_data', 'compress_data', 'extract_data'
            ],
            CapabilityCategory.SYSTEM_INFORMATION: [
                'get_system_info', 'list_processes', 'environment_vars',
                'system_stats', 'hardware_info', 'network_info', 'user_info'
            ],
            CapabilityCategory.EXTERNAL_INTEGRATION: [
                'database_query', 'cloud_api', 'third_party_service',
                'oauth_flow', 'webhook', 'integration', 'connector'
            ],
            CapabilityCategory.DATABASE_ACCESS: [
                'sql_query', 'database_connect', 'create_table', 'insert_data',
                'update_data', 'delete_data', 'backup_database', 'restore_database'
            ],
            CapabilityCategory.CLOUD_SERVICES: [
                'aws_', 'gcp_', 'azure_', 's3_', 'lambda_', 'ec2_',
                'cloud_storage', 'cloud_compute', 'cloud_database'
            ],
            CapabilityCategory.AUTHENTICATION: [
                'login', 'authenticate', 'oauth', 'token', 'credentials',
                'session', 'jwt', 'saml', 'ldap'
            ],
            CapabilityCategory.CRYPTOGRAPHY: [
                'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'hmac',
                'rsa', 'aes', 'certificate', 'keystore'
            ]
        }
        
        self.logger.info("MCP Capability Analyzer initialized")
    
    def analyze_tool(self, mcp_server: MCPServerInfo) -> ToolCapabilities:
        """
        Analyze an MCP tool to extract its capabilities.
        
        Args:
            mcp_server: MCP server information to analyze
            
        Returns:
            ToolCapabilities object with comprehensive capability analysis
        """
        try:
            tool_name = mcp_server.metadata.get('name', mcp_server.server_id)
            self.logger.debug(f"Analyzing capabilities for tool: {tool_name}")
            
            # Extract tool functions from server info
            tool_functions = self._extract_tool_functions(mcp_server)
            
            # Categorize capabilities
            capability_categories = self._categorize_capabilities(tool_functions)
            
            # Identify risk indicators  
            risk_indicators = self._identify_risk_indicators(tool_functions, mcp_server)
            
            # Assess privilege requirements
            requires_privileges = self._assess_privilege_requirements(tool_functions)
            
            # Check external access
            external_access = self._check_external_access(tool_functions, mcp_server)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(capability_categories, risk_indicators, mcp_server)
            
            # Build risk surface
            risk_surface = self._build_risk_surface(tool_functions, mcp_server)
            
            # Build access requirements
            access_requirements = self._build_access_requirements(tool_functions, mcp_server)
            
            # Identify external dependencies
            external_dependencies = self._identify_external_dependencies(tool_functions, mcp_server)
            
            capabilities = ToolCapabilities(
                tool_name=tool_name,
                tool_id=f"{tool_name}:{mcp_server.server_id}",
                tool_functions=tool_functions,
                capability_categories=capability_categories,
                risk_indicators=risk_indicators,
                requires_privileges=requires_privileges,
                external_access=external_access,
                risk_score=risk_score,
                confidence=0.8,  # Default confidence
                risk_surface=risk_surface,
                access_requirements=access_requirements,
                external_dependencies=external_dependencies
            )
            
            self.logger.debug(f"Capability analysis completed for {tool_name}: {len(tool_functions)} functions, risk score {risk_score:.2f}")
            return capabilities
            
        except Exception as e:
            self.logger.error(f"Failed to analyze tool capabilities: {e}")
            return self._create_minimal_capabilities(mcp_server)
    
    def categorize_capabilities(self, tool_functions: List[str]) -> List[CapabilityCategory]:
        """
        Categorize tool functions into capability categories.
        
        Args:
            tool_functions: List of tool function names
            
        Returns:
            List of relevant capability categories
        """
        categories = set()
        
        for function_name in tool_functions:
            function_lower = function_name.lower()
            
            for category, patterns in self.capability_patterns.items():
                if any(pattern in function_lower for pattern in patterns):
                    categories.add(category)
        
        return list(categories)
    
    def assess_risk_surface(self, capabilities: ToolCapabilities) -> RiskSurface:
        """
        Assess the attack surface exposed by tool capabilities.
        
        Args:
            capabilities: Tool capabilities to assess
            
        Returns:
            RiskSurface object with attack surface analysis
        """
        return capabilities.risk_surface
    
    def build_environment_context(self, mcp_servers: List[MCPServerInfo]) -> EnvironmentContext:
        """
        Build environment context from multiple MCP servers.
        
        Args:
            mcp_servers: List of MCP servers to analyze
            
        Returns:
            EnvironmentContext for the deployment environment
        """
        return self.context_builder.build_context_from_servers(mcp_servers)
    
    def _extract_tool_functions(self, mcp_server: MCPServerInfo) -> List[ToolFunction]:
        """Extract tool functions from MCP server info."""
        functions = []
        
        try:
            # Extract from MCP tools if available
            if hasattr(mcp_server, 'tools') and mcp_server.tools:
                for tool in mcp_server.tools:
                    if isinstance(tool, MCPTool):
                        function = ToolFunction(
                            name=tool.name,
                            description=tool.description or "No description available",
                            input_schema=tool.input_schema or {},
                            categories=self.categorize_capabilities([tool.name]),
                            risk_indicators=self._get_function_risk_indicators(tool.name),
                            requires_privileges=self._function_requires_privileges(tool.name),
                            external_access=self._function_has_external_access(tool.name)
                        )
                        functions.append(function)
            
            # Extract from metadata if tools not available
            if not functions and mcp_server.metadata:
                # Look for function names in metadata
                metadata_str = str(mcp_server.metadata)
                potential_functions = self._extract_functions_from_metadata(metadata_str)
                
                for func_name in potential_functions:
                    function = ToolFunction(
                        name=func_name,
                        description=f"Function extracted from metadata: {func_name}",
                        input_schema={},
                        categories=self.categorize_capabilities([func_name]),
                        risk_indicators=self._get_function_risk_indicators(func_name),
                        requires_privileges=self._function_requires_privileges(func_name),
                        external_access=self._function_has_external_access(func_name)
                    )
                    functions.append(function)
            
            # If still no functions, create generic based on server type
            if not functions:
                generic_function = ToolFunction(
                    name="generic_mcp_tool",
                    description="Generic MCP tool function",
                    input_schema={},
                    categories=[CapabilityCategory.EXTERNAL_INTEGRATION],
                    risk_indicators=["unknown_capability"],
                    requires_privileges=False,
                    external_access=True
                )
                functions.append(generic_function)
                
        except Exception as e:
            self.logger.warning(f"Failed to extract tool functions: {e}")
            
        return functions
    
    def _categorize_capabilities(self, tool_functions: List[ToolFunction]) -> List[CapabilityCategory]:
        """Categorize capabilities from tool functions."""
        categories = set()
        
        for function in tool_functions:
            categories.update(function.categories)
        
        return list(categories)
    
    def _identify_risk_indicators(self, 
                                tool_functions: List[ToolFunction],
                                mcp_server: MCPServerInfo) -> List[str]:
        """Identify risk indicators from tool functions and server info."""
        indicators = set()
        
        # Collect risk indicators from functions
        for function in tool_functions:
            indicators.update(function.risk_indicators)
        
        # Add server-level risk indicators
        if not mcp_server.is_secure:
            indicators.add("unencrypted_transport")
        
        if not mcp_server.has_authentication:
            indicators.add("no_authentication")
        
        if mcp_server.host not in ['localhost', '127.0.0.1', '::1']:
            indicators.add("network_accessible")
        
        return list(indicators)
    
    def _assess_privilege_requirements(self, tool_functions: List[ToolFunction]) -> bool:
        """Assess if any tool functions require elevated privileges."""
        return any(func.requires_privileges for func in tool_functions)
    
    def _check_external_access(self, 
                             tool_functions: List[ToolFunction],
                             mcp_server: MCPServerInfo) -> bool:
        """Check if tool has external access capabilities."""
        # Check function-level external access
        if any(func.external_access for func in tool_functions):
            return True
        
        # Check server-level indicators
        if mcp_server.host not in ['localhost', '127.0.0.1', '::1']:
            return True
        
        return False
    
    def _calculate_risk_score(self, 
                            capability_categories: List[CapabilityCategory],
                            risk_indicators: List[str],
                            mcp_server: MCPServerInfo) -> float:
        """Calculate overall risk score for the tool."""
        base_score = 0.0
        
        # Category-based scoring
        category_weights = {
            CapabilityCategory.CODE_EXECUTION: 0.3,
            CapabilityCategory.FILE_SYSTEM: 0.2,
            CapabilityCategory.NETWORK_ACCESS: 0.15,
            CapabilityCategory.SYSTEM_INFORMATION: 0.1,
            CapabilityCategory.DATABASE_ACCESS: 0.15,
            CapabilityCategory.CLOUD_SERVICES: 0.1,
            CapabilityCategory.AUTHENTICATION: 0.05,
            CapabilityCategory.CRYPTOGRAPHY: 0.05,
            CapabilityCategory.DATA_PROCESSING: 0.05,
            CapabilityCategory.EXTERNAL_INTEGRATION: 0.05
        }
        
        for category in capability_categories:
            base_score += category_weights.get(category, 0.02)
        
        # Risk indicator scoring
        high_risk_indicators = [
            "code_execution", "file_write", "system_command", 
            "unencrypted_transport", "no_authentication"
        ]
        
        for indicator in risk_indicators:
            if indicator in high_risk_indicators:
                base_score += 0.1
            else:
                base_score += 0.02
        
        # Server security adjustments
        if not mcp_server.is_secure:
            base_score += 0.1
        if not mcp_server.has_authentication:
            base_score += 0.15
        
        # Normalize to 0-1 range
        return min(1.0, base_score)
    
    def _build_risk_surface(self, 
                          tool_functions: List[ToolFunction],
                          mcp_server: MCPServerInfo) -> RiskSurface:
        """Build risk surface from tool analysis."""
        risk_surface = RiskSurface()
        
        for function in tool_functions:
            # Identify file access paths
            if CapabilityCategory.FILE_SYSTEM in function.categories:
                risk_surface.file_access_paths.extend([
                    "/etc/", "/var/", "/home/", "/tmp/", "/opt/"
                ])
            
            # Identify network endpoints
            if CapabilityCategory.NETWORK_ACCESS in function.categories:
                risk_surface.network_endpoints.extend([
                    "http://", "https://", "ftp://", "ssh://"
                ])
            
            # Identify system commands
            if CapabilityCategory.CODE_EXECUTION in function.categories:
                risk_surface.system_commands.extend([
                    "sh", "bash", "python", "node", "curl", "wget"
                ])
            
            # Identify external APIs
            if CapabilityCategory.EXTERNAL_INTEGRATION in function.categories:
                risk_surface.external_apis.extend([
                    "api.openai.com", "api.anthropic.com", "api.github.com"
                ])
        
        # Remove duplicates
        risk_surface.file_access_paths = list(set(risk_surface.file_access_paths))
        risk_surface.network_endpoints = list(set(risk_surface.network_endpoints))
        risk_surface.system_commands = list(set(risk_surface.system_commands))
        risk_surface.external_apis = list(set(risk_surface.external_apis))
        
        return risk_surface
    
    def _build_access_requirements(self, 
                                 tool_functions: List[ToolFunction],
                                 mcp_server: MCPServerInfo) -> AccessRequirements:
        """Build access requirements from tool analysis."""
        min_privilege = AccessLevel.USER
        auth_required = mcp_server.has_authentication
        network_required = False
        file_access = False
        system_access = False
        
        for function in tool_functions:
            # Check privilege requirements
            if function.requires_privileges:
                min_privilege = AccessLevel.ELEVATED
            
            # Check access types
            if CapabilityCategory.NETWORK_ACCESS in function.categories:
                network_required = True
            if CapabilityCategory.FILE_SYSTEM in function.categories:
                file_access = True
            if CapabilityCategory.CODE_EXECUTION in function.categories:
                system_access = True
                min_privilege = AccessLevel.ELEVATED
        
        return AccessRequirements(
            minimum_privilege=min_privilege,
            authentication_required=auth_required,
            network_access_required=network_required,
            file_system_access=file_access,
            system_command_access=system_access
        )
    
    def _identify_external_dependencies(self, 
                                      tool_functions: List[ToolFunction],
                                      mcp_server: MCPServerInfo) -> List[ExternalDependency]:
        """Identify external dependencies from tool analysis."""
        dependencies = []
        
        # Common external services
        common_services = {
            'openai': {
                'type': 'ai_service',
                'endpoint': 'api.openai.com',
                'auth': 'api_key',
                'sensitivity': DataSensitivity.CONFIDENTIAL
            },
            'anthropic': {
                'type': 'ai_service', 
                'endpoint': 'api.anthropic.com',
                'auth': 'api_key',
                'sensitivity': DataSensitivity.CONFIDENTIAL
            },
            'github': {
                'type': 'code_repository',
                'endpoint': 'api.github.com',
                'auth': 'token',
                'sensitivity': DataSensitivity.INTERNAL
            }
        }
        
        # Look for service indicators in functions and metadata
        for function in tool_functions:
            function_name_lower = function.name.lower()
            
            for service_name, service_info in common_services.items():
                if service_name in function_name_lower:
                    dependency = ExternalDependency(
                        name=service_name,
                        type=service_info['type'],
                        endpoint=service_info['endpoint'],
                        authentication_method=service_info['auth'],
                        data_sensitivity=service_info['sensitivity']
                    )
                    dependencies.append(dependency)
        
        # Check metadata for service references
        if mcp_server.metadata:
            metadata_str = str(mcp_server.metadata).lower()
            for service_name, service_info in common_services.items():
                if service_name in metadata_str:
                    dependency = ExternalDependency(
                        name=service_name,
                        type=service_info['type'],
                        endpoint=service_info['endpoint'],
                        authentication_method=service_info['auth'],
                        data_sensitivity=service_info['sensitivity']
                    )
                    if dependency not in dependencies:
                        dependencies.append(dependency)
        
        return dependencies
    
    def _extract_functions_from_metadata(self, metadata_str: str) -> List[str]:
        """Extract potential function names from metadata string."""
        # Look for common function patterns
        import re
        
        function_patterns = [
            r'(\w+_\w+)',  # snake_case functions
            r'([a-z]+[A-Z]\w*)',  # camelCase functions  
            r'(get\w+)', r'(set\w+)', r'(create\w+)', r'(delete\w+)',  # CRUD operations
            r'(read\w+)', r'(write\w+)', r'(update\w+)', r'(list\w+)'  # More CRUD
        ]
        
        functions = set()
        for pattern in function_patterns:
            matches = re.findall(pattern, metadata_str, re.IGNORECASE)
            functions.update(matches)
        
        # Filter out common non-function words
        exclude_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        return [f for f in functions if f.lower() not in exclude_words and len(f) > 2]
    
    def _get_function_risk_indicators(self, function_name: str) -> List[str]:
        """Get risk indicators for a specific function name."""
        indicators = []
        function_lower = function_name.lower()
        
        # Enhanced security-relevant function patterns
        security_patterns = {
            # Code execution risks
            'exec': 'code_execution',
            'eval': 'code_execution', 
            'run': 'code_execution',
            'compile': 'code_execution',
            'interpret': 'code_execution',
            'execute': 'code_execution',
            
            # System command risks
            'command': 'system_command',
            'shell': 'system_command',
            'bash': 'system_command',
            'powershell': 'system_command',
            'cmd': 'system_command',
            'terminal': 'system_command',
            
            # File system risks
            'write': 'file_write',
            'delete': 'file_delete',
            'remove': 'file_delete',
            'unlink': 'file_delete',
            'create': 'file_create',
            'modify': 'file_modify',
            'move': 'file_move',
            'copy': 'file_copy',
            'chmod': 'permission_change',
            'chown': 'ownership_change',
            
            # Network risks
            'http': 'network_access',
            'url': 'network_access',
            'request': 'network_access',
            'fetch': 'network_access',
            'download': 'network_download',
            'upload': 'network_upload',
            'socket': 'network_socket',
            'connect': 'network_connect',
            
            # API and external service risks
            'api': 'external_api',
            'service': 'external_service',
            'webhook': 'webhook_access',
            'oauth': 'authentication_flow',
            'auth': 'authentication_access',
            'login': 'authentication_access',
            
            # Database risks
            'sql': 'database_access',
            'query': 'database_access',
            'database': 'database_access',
            'db': 'database_access',
            'insert': 'database_write',
            'update': 'database_write',
            'delete': 'database_delete',
            
            # Process and system risks
            'process': 'process_access',
            'kill': 'process_control',
            'spawn': 'process_create',
            'fork': 'process_create',
            'thread': 'thread_control',
            
            # Crypto and security risks
            'encrypt': 'cryptographic_operation',
            'decrypt': 'cryptographic_operation',
            'hash': 'cryptographic_operation',
            'sign': 'digital_signature',
            'verify': 'signature_verification',
            'key': 'key_management',
            'certificate': 'certificate_handling',
            
            # Privilege and access risks
            'admin': 'privileged_access',
            'root': 'privileged_access',
            'sudo': 'privilege_escalation',
            'elevation': 'privilege_escalation',
            'impersonate': 'identity_impersonation',
            
            # Data handling risks
            'sensitive': 'sensitive_data',
            'secret': 'secret_handling',
            'token': 'token_handling',
            'password': 'credential_handling',
            'credential': 'credential_handling',
        }
        
        for pattern, indicator in security_patterns.items():
            if pattern in function_lower:
                indicators.append(indicator)
        
        return indicators
    
    def _function_requires_privileges(self, function_name: str) -> bool:
        """Check if a function requires elevated privileges based on its name."""
        function_lower = function_name.lower()
        
        # Privilege-requiring patterns
        privilege_patterns = [
            'admin', 'root', 'sudo', 'execute', 'run', 'command', 'shell',
            'system', 'process', 'service', 'daemon', 'install', 'uninstall',
            'chmod', 'chown', 'mount', 'unmount', 'kill', 'stop', 'start'
        ]
        
        return any(pattern in function_lower for pattern in privilege_patterns)
    
    def _function_has_external_access(self, function_name: str) -> bool:
        """Check if a function has external access capabilities based on its name."""
        function_lower = function_name.lower()
        
        # External access patterns
        external_patterns = [
            'http', 'https', 'url', 'web', 'api', 'request', 'fetch',
            'download', 'upload', 'connect', 'socket', 'network',
            'external', 'remote', 'service', 'cloud'
        ]
        
        return any(pattern in function_lower for pattern in external_patterns)

    def identify_security_relevant_functions(self, tool_functions: List[ToolFunction]) -> List[ToolFunction]:
        """
        Identify functions that are particularly relevant for security analysis.
        
        This enhanced method focuses on functions that could be used in attack scenarios
        or that represent significant security risks.
        
        Args:
            tool_functions: List of tool functions to analyze
            
        Returns:
            List of security-relevant functions with enhanced analysis
        """
        security_relevant = []
        
        for func in tool_functions:
            # Check if function has security-relevant patterns
            risk_indicators = self._get_function_risk_indicators(func.name)
            
            if risk_indicators:
                # Enhanced security analysis for this function
                enhanced_func = func.__class__(
                    name=func.name,
                    description=func.description,
                    parameters=func.parameters,
                    # Add enhanced security metadata
                    security_risk_level=self._calculate_function_security_risk(func, risk_indicators),
                    attack_vectors=self._identify_function_attack_vectors(func, risk_indicators),
                    abuse_scenarios=self._generate_function_abuse_scenarios(func, risk_indicators),
                    security_controls=self._recommend_function_security_controls(func, risk_indicators)
                )
                security_relevant.append(enhanced_func)
            
        return security_relevant

    def _calculate_function_security_risk(self, func: ToolFunction, risk_indicators: List[str]) -> str:
        """Calculate security risk level for a function based on indicators."""
        high_risk_indicators = [
            'code_execution', 'system_command', 'privilege_escalation', 
            'privileged_access', 'file_delete', 'database_delete',
            'process_control', 'network_socket'
        ]
        
        medium_risk_indicators = [
            'file_write', 'file_create', 'network_access', 'database_access',
            'external_api', 'authentication_access', 'cryptographic_operation'
        ]
        
        # Check for high-risk patterns
        if any(indicator in high_risk_indicators for indicator in risk_indicators):
            return "critical"
        elif any(indicator in medium_risk_indicators for indicator in risk_indicators):
            return "high" 
        elif risk_indicators:
            return "medium"
        else:
            return "low"

    def _identify_function_attack_vectors(self, func: ToolFunction, risk_indicators: List[str]) -> List[Dict[str, Any]]:
        """Identify potential attack vectors for a function."""
        attack_vectors = []
        
        # Map risk indicators to attack vectors
        attack_vector_mapping = {
            'code_execution': {
                'name': 'Code Injection',
                'description': f'Function {func.name} could be exploited to execute arbitrary code',
                'technique': 'Code injection through parameter manipulation',
                'impact': 'Complete system compromise'
            },
            'system_command': {
                'name': 'Command Injection',
                'description': f'Function {func.name} could be exploited to execute system commands',
                'technique': 'OS command injection through parameter manipulation',
                'impact': 'System command execution'
            },
            'file_write': {
                'name': 'Arbitrary File Write',
                'description': f'Function {func.name} could be exploited to write arbitrary files',
                'technique': 'Path traversal and file content manipulation',
                'impact': 'File system corruption or web shell deployment'
            },
            'network_access': {
                'name': 'Network Pivot',
                'description': f'Function {func.name} could be used for network reconnaissance',
                'technique': 'Internal network scanning and service discovery',
                'impact': 'Network reconnaissance and lateral movement'
            },
            'database_access': {
                'name': 'Data Extraction',
                'description': f'Function {func.name} could be exploited for unauthorized data access',
                'technique': 'SQL injection or direct database access',
                'impact': 'Sensitive data exposure'
            }
        }
        
        for indicator in risk_indicators:
            if indicator in attack_vector_mapping:
                attack_vectors.append(attack_vector_mapping[indicator])
        
        return attack_vectors

    def _generate_function_abuse_scenarios(self, func: ToolFunction, risk_indicators: List[str]) -> List[Dict[str, Any]]:
        """Generate realistic abuse scenarios for a function."""
        scenarios = []
        
        # Generate scenarios based on risk indicators
        scenario_templates = {
            'code_execution': {
                'title': 'Malicious Code Execution',
                'description': f'An attacker exploits {func.name} to execute malicious code',
                'steps': [
                    'Attacker identifies function parameters',
                    'Crafts malicious payload',
                    'Exploits parameter validation weakness',
                    'Executes arbitrary code on target system'
                ],
                'prerequisites': ['Access to MCP server', 'Knowledge of function parameters'],
                'impact': 'Complete system compromise'
            },
            'file_write': {
                'title': 'Web Shell Deployment',
                'description': f'An attacker uses {func.name} to deploy a web shell',
                'steps': [
                    'Attacker identifies writable directory',
                    'Crafts web shell payload',
                    'Uses function to write shell to web directory',
                    'Gains persistent access through web shell'
                ],
                'prerequisites': ['Write access to web directory', 'Knowledge of web server paths'],
                'impact': 'Persistent system access'
            },
            'network_access': {
                'title': 'Internal Network Reconnaissance',
                'description': f'An attacker leverages {func.name} for network discovery',
                'steps': [
                    'Attacker gains access to MCP server',
                    'Uses function to scan internal networks',
                    'Identifies additional targets',
                    'Plans lateral movement attacks'
                ],
                'prerequisites': ['MCP server access', 'Network connectivity'],
                'impact': 'Network reconnaissance and mapping'
            }
        }
        
        for indicator in risk_indicators:
            if indicator in scenario_templates:
                scenarios.append(scenario_templates[indicator])
        
        return scenarios

    def _recommend_function_security_controls(self, func: ToolFunction, risk_indicators: List[str]) -> List[Dict[str, Any]]:
        """Recommend security controls for a function based on its risks."""
        controls = []
        
        # Base security controls for all functions
        controls.append({
            'name': 'Input Validation',
            'description': f'Implement strict input validation for {func.name} parameters',
            'implementation': 'Validate and sanitize all input parameters',
            'effectiveness': 'High'
        })
        
        # Specific controls based on risk indicators
        control_mapping = {
            'code_execution': {
                'name': 'Code Execution Prevention',
                'description': 'Prevent dynamic code execution',
                'implementation': 'Disable eval/exec functions, use allowlists',
                'effectiveness': 'Critical'
            },
            'system_command': {
                'name': 'Command Injection Prevention',
                'description': 'Prevent OS command injection',
                'implementation': 'Use parameterized commands, avoid shell=True',
                'effectiveness': 'Critical'
            },
            'file_write': {
                'name': 'Path Traversal Prevention',
                'description': 'Restrict file write operations',
                'implementation': 'Validate file paths, use chroot/sandbox',
                'effectiveness': 'High'
            },
            'network_access': {
                'name': 'Network Access Control',
                'description': 'Restrict network access',
                'implementation': 'Use firewall rules, network segmentation',
                'effectiveness': 'Medium'
            }
        }
        
        for indicator in risk_indicators:
            if indicator in control_mapping:
                controls.append(control_mapping[indicator])
        
        return controls

    def analyze_attack_surface(self, tool_capabilities: ToolCapabilities) -> Dict[str, Any]:
        """
        Analyze the attack surface exposed by tool capabilities.
        
        This method performs comprehensive attack surface analysis to identify
        potential security weaknesses and attack vectors.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            
        Returns:
            Dict containing detailed attack surface analysis
        """
        attack_surface = {
            'total_functions': len(tool_capabilities.tool_functions),
            'security_relevant_functions': 0,
            'attack_vectors': [],
            'risk_categories': {},
            'attack_paths': [],
            'security_gaps': [],
            'mitigation_priorities': []
        }
        
        # Analyze each function for security relevance
        for func in tool_capabilities.tool_functions:
            risk_indicators = self._get_function_risk_indicators(func.name)
            
            if risk_indicators:
                attack_surface['security_relevant_functions'] += 1
                
                # Add function-specific attack vectors
                function_vectors = self._identify_function_attack_vectors(func, risk_indicators)
                attack_surface['attack_vectors'].extend(function_vectors)
                
                # Update risk categories
                for indicator in risk_indicators:
                    if indicator not in attack_surface['risk_categories']:
                        attack_surface['risk_categories'][indicator] = 0
                    attack_surface['risk_categories'][indicator] += 1
        
        # Identify attack paths (combinations of functions)
        attack_surface['attack_paths'] = self._identify_attack_paths(tool_capabilities)
        
        # Identify security gaps
        attack_surface['security_gaps'] = self._identify_security_gaps(tool_capabilities)
        
        # Prioritize mitigations
        attack_surface['mitigation_priorities'] = self._prioritize_mitigations(attack_surface)
        
        return attack_surface

    def _identify_attack_paths(self, tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Identify potential attack paths using combinations of functions."""
        attack_paths = []
        
        # Look for dangerous function combinations
        function_names = [func.name.lower() for func in tool_capabilities.tool_functions]
        
        # Define attack path patterns
        attack_patterns = [
            {
                'name': 'File Write + Code Execution',
                'description': 'Write malicious file then execute it',
                'functions': ['write', 'exec'],
                'impact': 'Critical - Complete compromise'
            },
            {
                'name': 'Network Access + File Write',
                'description': 'Download and deploy malicious payloads',
                'functions': ['http', 'write'],
                'impact': 'High - Malware deployment'
            },
            {
                'name': 'Database Access + Network Access',
                'description': 'Extract data and exfiltrate over network',
                'functions': ['database', 'http'],
                'impact': 'High - Data exfiltration'
            },
            {
                'name': 'System Command + Network Access',
                'description': 'Execute commands and communicate with C&C',
                'functions': ['command', 'http'],
                'impact': 'Critical - Remote control'
            }
        ]
        
        # Check which patterns are present
        for pattern in attack_patterns:
            if all(any(func_pattern in fname for fname in function_names) 
                   for func_pattern in pattern['functions']):
                attack_paths.append(pattern)
        
        return attack_paths

    def _identify_security_gaps(self, tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Identify security gaps in tool capabilities."""
        gaps = []
        
        # Check for common security weaknesses
        if any('auth' not in func.name.lower() for func in tool_capabilities.tool_functions):
            gaps.append({
                'type': 'Authentication Gap',
                'description': 'Functions may lack proper authentication checks',
                'severity': 'High',
                'recommendation': 'Implement authentication for all sensitive functions'
            })
        
        if any('validate' not in func.name.lower() for func in tool_capabilities.tool_functions):
            gaps.append({
                'type': 'Input Validation Gap', 
                'description': 'Functions may lack input validation',
                'severity': 'High',
                'recommendation': 'Implement comprehensive input validation'
            })
        
        # Check for dangerous combinations without safeguards
        dangerous_functions = [func for func in tool_capabilities.tool_functions 
                             if any(pattern in func.name.lower() 
                                   for pattern in ['exec', 'eval', 'command', 'shell'])]
        
        if dangerous_functions:
            gaps.append({
                'type': 'Code Execution Risk',
                'description': f'{len(dangerous_functions)} functions allow code execution',
                'severity': 'Critical',
                'recommendation': 'Implement sandboxing and strict validation for code execution'
            })
        
        return gaps

    def _prioritize_mitigations(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize mitigation strategies based on attack surface analysis."""
        priorities = []
        
        # Critical priority items
        if attack_surface['attack_paths']:
            priorities.append({
                'priority': 1,
                'category': 'Attack Path Mitigation',
                'description': f'Address {len(attack_surface["attack_paths"])} identified attack paths',
                'actions': ['Implement function isolation', 'Add access controls', 'Enable logging']
            })
        
        # High priority items
        critical_gaps = [gap for gap in attack_surface['security_gaps'] 
                        if gap['severity'] == 'Critical']
        if critical_gaps:
            priorities.append({
                'priority': 2,
                'category': 'Critical Security Gaps',
                'description': f'Fix {len(critical_gaps)} critical security gaps',
                'actions': [gap['recommendation'] for gap in critical_gaps]
            })
        
        # Medium priority items
        if attack_surface['security_relevant_functions'] > 0:
            priorities.append({
                'priority': 3,
                'category': 'Function Security Hardening',
                'description': f'Harden {attack_surface["security_relevant_functions"]} security-relevant functions',
                'actions': ['Add input validation', 'Implement rate limiting', 'Enable monitoring']
            })
        
        return priorities
    
    def _create_minimal_capabilities(self, mcp_server: MCPServerInfo) -> ToolCapabilities:
        """Create minimal capabilities object for failed analysis."""
        tool_name = mcp_server.metadata.get('name', mcp_server.server_id)
        
        return ToolCapabilities(
            tool_name=tool_name,
            tool_id=f"{tool_name}:minimal",
            tool_functions=[],
            capability_categories=[CapabilityCategory.EXTERNAL_INTEGRATION],
            risk_indicators=["analysis_failed"],
            requires_privileges=False,
            external_access=True,
            risk_score=0.5,
            confidence=0.1,
            risk_surface=RiskSurface(),
            access_requirements=AccessRequirements(),
            external_dependencies=[]
        ) 
    
    def map_capabilities_to_threats(self, 
                                  tool_capabilities: ToolCapabilities,
                                  environment_context: Optional[EnvironmentContext] = None) -> Dict[str, Any]:
        """
        Map tool capabilities to specific threats using pattern-based analysis.
        
        This implements the Capability-to-Threat Mapping Algorithm from the design:
        1. Extract function signatures and parameters
        2. Categorize by security impact
        3. Assess privilege requirements
        4. Map to attack techniques using pattern database
        5. Calculate exploitation difficulty
        6. Generate specific threat scenarios
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            environment_context: Optional environment context for threat modeling
            
        Returns:
            Dictionary containing threat mappings and analysis
        """
        try:
            self.logger.debug(f"Starting capability-to-threat mapping for {tool_capabilities.tool_name}")
            
            # Step 1: Extract function signatures and parameters
            function_analysis = self._extract_function_signatures(tool_capabilities)
            
            # Step 2: Categorize by security impact
            impact_categorization = self._categorize_security_impact(tool_capabilities, function_analysis)
            
            # Step 3: Assess privilege requirements
            privilege_assessment = self._assess_privilege_requirements_detailed(tool_capabilities, environment_context)
            
            # Step 4: Map to attack techniques using pattern database
            attack_technique_mapping = self._map_to_attack_techniques(
                tool_capabilities, 
                function_analysis, 
                impact_categorization
            )
            
            # Step 5: Calculate exploitation difficulty
            exploitation_difficulty = self._calculate_exploitation_difficulty(
                tool_capabilities,
                privilege_assessment,
                environment_context
            )
            
            # Step 6: Generate specific threat scenarios
            threat_scenarios = self._generate_threat_scenarios(
                tool_capabilities,
                attack_technique_mapping,
                exploitation_difficulty,
                environment_context
            )
            
            # Compile comprehensive threat mapping
            threat_mapping = {
                'tool_name': tool_capabilities.tool_name,
                'analysis_timestamp': datetime.now().isoformat(),
                'function_analysis': function_analysis,
                'security_impact': impact_categorization,
                'privilege_requirements': privilege_assessment,
                'attack_techniques': attack_technique_mapping,
                'exploitation_difficulty': exploitation_difficulty,
                'threat_scenarios': threat_scenarios,
                'overall_threat_score': self._calculate_overall_threat_score(
                    impact_categorization,
                    exploitation_difficulty,
                    len(attack_technique_mapping)
                ),
                'confidence_level': self._calculate_mapping_confidence(
                    tool_capabilities,
                    function_analysis,
                    environment_context
                )
            }
            
            self.logger.info(f"Capability-to-threat mapping completed for {tool_capabilities.tool_name}")
            return threat_mapping
            
        except Exception as e:
            self.logger.error(f"Capability-to-threat mapping failed: {e}")
            return {
                'tool_name': tool_capabilities.tool_name,
                'error': str(e),
                'threat_scenarios': [],
                'overall_threat_score': 0.5,
                'confidence_level': 0.1
            }
    
    def _extract_function_signatures(self, tool_capabilities: ToolCapabilities) -> Dict[str, Any]:
        """Extract detailed function signatures and parameter analysis."""
        signatures = {}
        
        for func in tool_capabilities.tool_functions:
            signature_analysis = {
                'name': func.name,
                'description': func.description,
                'parameters': [],
                'risk_indicators': [],
                'parameter_count': len(func.parameters) if func.parameters else 0,
                'has_file_params': False,
                'has_network_params': False,
                'has_command_params': False
            }
            
            # Analyze parameters
            if func.parameters:
                for param in func.parameters:
                    param_analysis = {
                        'name': param.get('name', ''),
                        'type': param.get('type', 'unknown'),
                        'required': param.get('required', False),
                        'risk_level': self._assess_parameter_risk(param)
                    }
                    signature_analysis['parameters'].append(param_analysis)
                    
                    # Check for high-risk parameter types
                    param_str = str(param).lower()
                    if any(keyword in param_str for keyword in ['file', 'path', 'directory']):
                        signature_analysis['has_file_params'] = True
                        signature_analysis['risk_indicators'].append('file_system_access')
                    
                    if any(keyword in param_str for keyword in ['url', 'endpoint', 'host', 'server']):
                        signature_analysis['has_network_params'] = True
                        signature_analysis['risk_indicators'].append('network_access')
                    
                    if any(keyword in param_str for keyword in ['command', 'cmd', 'script', 'execute']):
                        signature_analysis['has_command_params'] = True
                        signature_analysis['risk_indicators'].append('command_execution')
            
            signatures[func.name] = signature_analysis
        
        return signatures
    
    def _categorize_security_impact(self, 
                                  tool_capabilities: ToolCapabilities,
                                  function_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Categorize functions by their security impact level."""
        impact_categories = {
            'critical': [],  # Direct system access, code execution
            'high': [],      # File system, network access
            'medium': [],    # Data processing, information disclosure
            'low': [],       # Read-only operations, benign functions
            'unknown': []    # Unable to categorize
        }
        
        for func_name, analysis in function_analysis.items():
            impact_level = 'unknown'
            
            # Critical impact - code execution
            if any(indicator in analysis['risk_indicators'] for indicator in ['command_execution']):
                impact_level = 'critical'
                
            # High impact - file system or network access
            elif any(indicator in analysis['risk_indicators'] for indicator in ['file_system_access', 'network_access']):
                impact_level = 'high'
                
            # Medium impact - data processing
            elif analysis['parameter_count'] > 0:
                impact_level = 'medium'
                
            # Low impact - read-only or minimal parameters
            else:
                impact_level = 'low'
            
            impact_categories[impact_level].append({
                'function': func_name,
                'description': analysis['description'],
                'risk_indicators': analysis['risk_indicators'],
                'justification': self._get_impact_justification(impact_level, analysis)
            })
        
        # Calculate overall impact metrics
        total_functions = len(function_analysis)
        impact_distribution = {
            level: len(funcs) / total_functions if total_functions > 0 else 0
            for level, funcs in impact_categories.items()
        }
        
        return {
            'categories': impact_categories,
            'distribution': impact_distribution,
            'dominant_impact': max(impact_distribution.items(), key=lambda x: x[1])[0],
            'risk_concentration': impact_distribution.get('critical', 0) + impact_distribution.get('high', 0)
        }
    
    def _assess_privilege_requirements_detailed(self, 
                                     tool_capabilities: ToolCapabilities,
                                     environment_context: Optional[EnvironmentContext]) -> Dict[str, Any]:
        """Assess privilege requirements for tool exploitation."""
        privilege_assessment = {
            'requires_admin': False,
            'requires_user_auth': False,
            'requires_network_access': False,
            'requires_file_permissions': False,
            'privilege_escalation_potential': False,
            'assessment_reasoning': []
        }
        
        # Check capability categories for privilege requirements
        if CapabilityCategory.CODE_EXECUTION in tool_capabilities.capability_categories:
            privilege_assessment['requires_admin'] = True
            privilege_assessment['privilege_escalation_potential'] = True
            privilege_assessment['assessment_reasoning'].append('Code execution capabilities require elevated privileges')
        
        if CapabilityCategory.FILE_SYSTEM in tool_capabilities.capability_categories:
            privilege_assessment['requires_file_permissions'] = True
            privilege_assessment['assessment_reasoning'].append('File system access requires appropriate file permissions')
        
        if CapabilityCategory.NETWORK_ACCESS in tool_capabilities.capability_categories:
            privilege_assessment['requires_network_access'] = True
            privilege_assessment['assessment_reasoning'].append('Network operations require network connectivity')
        
        # Check access requirements from tool capabilities
        if hasattr(tool_capabilities, 'access_requirements'):
            access_req = tool_capabilities.access_requirements
            if access_req.requires_authentication:
                privilege_assessment['requires_user_auth'] = True
                privilege_assessment['assessment_reasoning'].append('Tool requires user authentication')
            
            if access_req.requires_admin_privileges:
                privilege_assessment['requires_admin'] = True
                privilege_assessment['assessment_reasoning'].append('Tool explicitly requires admin privileges')
        
        # Environment context considerations
        if environment_context:
            if environment_context.has_admin_access:
                privilege_assessment['privilege_escalation_potential'] = True
                privilege_assessment['assessment_reasoning'].append('Admin access available in environment')
        
        return privilege_assessment
    
    def _map_to_attack_techniques(self,
                                tool_capabilities: ToolCapabilities,
                                function_analysis: Dict[str, Any],
                                impact_categorization: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map capabilities to specific attack techniques."""
        attack_techniques = []
        
        # MITRE ATT&CK technique mappings based on capabilities
        technique_mappings = {
            'command_execution': {
                'technique_id': 'T1059',
                'technique_name': 'Command and Scripting Interpreter',
                'description': 'Execute arbitrary commands through tool functions',
                'severity': 'critical'
            },
            'file_system_access': {
                'technique_id': 'T1083',
                'technique_name': 'File and Directory Discovery',
                'description': 'Access and manipulate file system through tool capabilities',
                'severity': 'high'
            },
            'network_access': {
                'technique_id': 'T1071',
                'technique_name': 'Application Layer Protocol',
                'description': 'Abuse network capabilities for command and control',
                'severity': 'high'
            }
        }
        
        # Analyze each function for attack techniques
        for func_name, analysis in function_analysis.items():
            for risk_indicator in analysis['risk_indicators']:
                if risk_indicator in technique_mappings:
                    technique = technique_mappings[risk_indicator].copy()
                    technique.update({
                        'applicable_function': func_name,
                        'function_description': analysis['description'],
                        'exploitation_vector': self._generate_exploitation_vector(func_name, analysis),
                        'prerequisites': self._identify_prerequisites(analysis),
                        'detection_difficulty': self._assess_detection_difficulty(analysis)
                    })
                    attack_techniques.append(technique)
        
        # Add capability-based techniques
        for category in tool_capabilities.capability_categories:
            category_techniques = self._get_category_specific_techniques(category, tool_capabilities)
            attack_techniques.extend(category_techniques)
        
        # Remove duplicates and rank by severity
        unique_techniques = []
        seen_techniques = set()
        
        for tech in attack_techniques:
            tech_key = f"{tech['technique_id']}_{tech['applicable_function']}"
            if tech_key not in seen_techniques:
                seen_techniques.add(tech_key)
                unique_techniques.append(tech)
        
        # Sort by severity (critical > high > medium > low)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        unique_techniques.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return unique_techniques[:10]  # Top 10 most relevant techniques
    
    def _calculate_exploitation_difficulty(self,
                                         tool_capabilities: ToolCapabilities,
                                         privilege_assessment: Dict[str, Any],
                                         environment_context: Optional[EnvironmentContext]) -> Dict[str, Any]:
        """Calculate the difficulty of exploiting the tool capabilities."""
        difficulty_factors = {
            'authentication_required': 0.0,
            'privilege_escalation_needed': 0.0,
            'technical_complexity': 0.0,
            'environment_constraints': 0.0,
            'detection_likelihood': 0.0
        }
        
        # Authentication factor
        if privilege_assessment['requires_user_auth']:
            difficulty_factors['authentication_required'] = 0.3
        if privilege_assessment['requires_admin']:
            difficulty_factors['authentication_required'] = 0.5
        
        # Privilege escalation factor
        if privilege_assessment['privilege_escalation_potential']:
            difficulty_factors['privilege_escalation_needed'] = 0.2
        
        # Technical complexity based on function count and complexity
        func_count = len(tool_capabilities.tool_functions)
        if func_count > 10:
            difficulty_factors['technical_complexity'] = 0.1
        elif func_count > 5:
            difficulty_factors['technical_complexity'] = 0.05
        
        # Environment constraints
        if environment_context:
            if not environment_context.has_network_access:
                difficulty_factors['environment_constraints'] = 0.3
            if environment_context.security_controls_enabled:
                difficulty_factors['environment_constraints'] += 0.2
        
        # Detection likelihood based on monitoring capabilities
        if tool_capabilities.requires_privileges:
            difficulty_factors['detection_likelihood'] = 0.4
        
        # Calculate overall difficulty score (0.0 = very easy, 1.0 = very difficult)
        overall_difficulty = sum(difficulty_factors.values())
        overall_difficulty = min(1.0, overall_difficulty)  # Cap at 1.0
        
        # Determine difficulty level
        if overall_difficulty >= 0.7:
            difficulty_level = 'very_high'
        elif overall_difficulty >= 0.5:
            difficulty_level = 'high'
        elif overall_difficulty >= 0.3:
            difficulty_level = 'medium'
        elif overall_difficulty >= 0.1:
            difficulty_level = 'low'
        else:
            difficulty_level = 'very_low'
        
        return {
            'overall_score': overall_difficulty,
            'difficulty_level': difficulty_level,
            'factors': difficulty_factors,
            'explanation': self._generate_difficulty_explanation(difficulty_factors, difficulty_level)
        }
    
    def _generate_threat_scenarios(self,
                                 tool_capabilities: ToolCapabilities,
                                 attack_techniques: List[Dict[str, Any]],
                                 exploitation_difficulty: Dict[str, Any],
                                 environment_context: Optional[EnvironmentContext]) -> List[Dict[str, Any]]:
        """Generate specific threat scenarios based on capability analysis."""
        scenarios = []
        
        # Generate scenarios for each attack technique
        for technique in attack_techniques[:5]:  # Top 5 techniques
            scenario = {
                'scenario_id': f"scenario_{len(scenarios) + 1}",
                'title': f"{technique['technique_name']} via {technique['applicable_function']}",
                'severity': technique['severity'],
                'attack_technique': technique,
                'steps': self._generate_attack_steps(technique, tool_capabilities),
                'prerequisites': technique.get('prerequisites', []),
                'potential_impact': self._assess_scenario_impact(technique, tool_capabilities),
                'likelihood': self._calculate_scenario_likelihood(
                    technique,
                    exploitation_difficulty,
                    environment_context
                ),
                'detection_indicators': self._generate_detection_indicators(technique),
                'mitigation_strategies': self._suggest_mitigations(technique, tool_capabilities)
            }
            scenarios.append(scenario)
        
        # Add capability-combination scenarios
        if len(tool_capabilities.tool_functions) > 3:
            combination_scenario = self._generate_combination_scenario(
                tool_capabilities,
                exploitation_difficulty,
                environment_context
            )
            if combination_scenario:
                scenarios.append(combination_scenario)
        
        return scenarios
    
    def _calculate_overall_threat_score(self,
                                      impact_categorization: Dict[str, Any],
                                      exploitation_difficulty: Dict[str, Any],
                                      technique_count: int) -> float:
        """Calculate overall threat score for the tool."""
        # Impact score (0.0 - 1.0)
        impact_score = impact_categorization['risk_concentration']
        
        # Exploitation ease score (inverse of difficulty)
        ease_score = 1.0 - exploitation_difficulty['overall_score']
        
        # Technique diversity score
        diversity_score = min(1.0, technique_count / 10.0)
        
        # Weighted combination
        overall_score = (
            impact_score * 0.5 +      # 50% weight for impact
            ease_score * 0.3 +        # 30% weight for exploitation ease
            diversity_score * 0.2     # 20% weight for technique diversity
        )
        
        return round(overall_score, 3)
    
    def _calculate_mapping_confidence(self,
                                    tool_capabilities: ToolCapabilities,
                                    function_analysis: Dict[str, Any],
                                    environment_context: Optional[EnvironmentContext]) -> float:
        """Calculate confidence level in the threat mapping."""
        confidence_factors = []
        
        # Function analysis completeness
        if function_analysis:
            analyzed_funcs = len([f for f in function_analysis.values() if f['risk_indicators']])
            total_funcs = len(function_analysis)
            if total_funcs > 0:
                confidence_factors.append(analyzed_funcs / total_funcs)
        
        # Tool metadata completeness
        metadata_score = 0.0
        if tool_capabilities.tool_name:
            metadata_score += 0.25
        if tool_capabilities.tool_functions:
            metadata_score += 0.5
        if tool_capabilities.capability_categories:
            metadata_score += 0.25
        confidence_factors.append(metadata_score)
        
        # Environment context availability
        if environment_context:
            confidence_factors.append(0.9)
        else:
            confidence_factors.append(0.6)
        
        # Calculate average confidence
        if confidence_factors:
            return round(sum(confidence_factors) / len(confidence_factors), 3)
        else:
            return 0.5
    
    # Helper methods for the algorithm implementation
    
    def _assess_parameter_risk(self, param: Dict[str, Any]) -> str:
        """Assess risk level of a function parameter."""
        param_str = str(param).lower()
        
        # High-risk patterns
        high_risk_patterns = ['command', 'execute', 'eval', 'script', 'shell']
        if any(pattern in param_str for pattern in high_risk_patterns):
            return 'high'
        
        # Medium-risk patterns
        medium_risk_patterns = ['file', 'path', 'url', 'host', 'server', 'query']
        if any(pattern in param_str for pattern in medium_risk_patterns):
            return 'medium'
        
        return 'low'
    
    def _get_impact_justification(self, impact_level: str, analysis: Dict[str, Any]) -> str:
        """Get justification for impact level assessment."""
        if impact_level == 'critical':
            return f"Critical impact due to command execution capabilities: {', '.join(analysis['risk_indicators'])}"
        elif impact_level == 'high':
            return f"High impact due to system access: {', '.join(analysis['risk_indicators'])}"
        elif impact_level == 'medium':
            return f"Medium impact due to data processing with {analysis['parameter_count']} parameters"
        else:
            return "Low impact - limited functionality or read-only operations"
    
    def _generate_exploitation_vector(self, func_name: str, analysis: Dict[str, Any]) -> str:
        """Generate specific exploitation vector description."""
        risk_indicators = analysis['risk_indicators']
        
        if 'command_execution' in risk_indicators:
            return f"Execute arbitrary commands through {func_name} function parameters"
        elif 'file_system_access' in risk_indicators:
            return f"Access or modify files through {func_name} function"
        elif 'network_access' in risk_indicators:
            return f"Establish network connections through {func_name} function"
        else:
            return f"Abuse {func_name} function for unintended purposes"
    
    def _identify_prerequisites(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify prerequisites for exploiting a function."""
        prerequisites = []
        
        if analysis['has_command_params']:
            prerequisites.append("Access to command parameters")
        if analysis['has_file_params']:
            prerequisites.append("File system permissions")
        if analysis['has_network_params']:
            prerequisites.append("Network connectivity")
        if analysis['parameter_count'] > 5:
            prerequisites.append("Understanding of complex parameter structure")
        
        return prerequisites or ["Basic tool access"]
    
    def _assess_detection_difficulty(self, analysis: Dict[str, Any]) -> str:
        """Assess how difficult it would be to detect exploitation."""
        if 'command_execution' in analysis['risk_indicators']:
            return 'easy'  # Command execution is usually logged
        elif 'file_system_access' in analysis['risk_indicators']:
            return 'medium'  # File access can be monitored
        elif 'network_access' in analysis['risk_indicators']:
            return 'medium'  # Network activity can be monitored
        else:
            return 'hard'  # Data processing might be harder to detect
    
    def _get_category_specific_techniques(self, category: CapabilityCategory, tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Get attack techniques specific to capability categories."""
        techniques = []
        
        category_mappings = {
            CapabilityCategory.DATABASE_ACCESS: {
                'technique_id': 'T1505',
                'technique_name': 'Server Software Component',
                'description': 'Abuse database access for persistence or data theft',
                'severity': 'high'
            },
            CapabilityCategory.CLOUD_SERVICES: {
                'technique_id': 'T1078',
                'technique_name': 'Valid Accounts',
                'description': 'Abuse cloud service credentials for lateral movement',
                'severity': 'high'
            },
            CapabilityCategory.AUTHENTICATION: {
                'technique_id': 'T1110',
                'technique_name': 'Brute Force',
                'description': 'Abuse authentication functions for credential attacks',
                'severity': 'medium'
            }
        }
        
        if category in category_mappings:
            technique = category_mappings[category].copy()
            technique.update({
                'applicable_function': f"category_{category.value}",
                'function_description': f"Functions in {category.value} category",
                'exploitation_vector': f"Abuse {category.value} capabilities",
                'prerequisites': [f"Access to {category.value} functions"],
                'detection_difficulty': 'medium'
            })
            techniques.append(technique)
        
        return techniques
    
    def _generate_difficulty_explanation(self, factors: Dict[str, float], level: str) -> str:
        """Generate human-readable explanation of exploitation difficulty."""
        explanations = []
        
        if factors['authentication_required'] > 0.3:
            explanations.append("requires administrative privileges")
        elif factors['authentication_required'] > 0.0:
            explanations.append("requires user authentication")
        
        if factors['privilege_escalation_needed'] > 0.0:
            explanations.append("needs privilege escalation")
        
        if factors['technical_complexity'] > 0.0:
            explanations.append("has moderate technical complexity")
        
        if factors['environment_constraints'] > 0.2:
            explanations.append("limited by environment constraints")
        
        if factors['detection_likelihood'] > 0.3:
            explanations.append("likely to be detected")
        
        base_explanation = f"Exploitation difficulty is {level.replace('_', ' ')}"
        if explanations:
            return f"{base_explanation} because it {' and '.join(explanations)}"
        else:
            return f"{base_explanation} with minimal barriers to exploitation"
    
    def _generate_attack_steps(self, technique: Dict[str, Any], tool_capabilities: ToolCapabilities) -> List[str]:
        """Generate specific attack steps for a technique."""
        steps = [
            "1. Gain access to MCP tool interface",
            f"2. Identify exploitable function: {technique['applicable_function']}",
            f"3. {technique['exploitation_vector']}",
            "4. Execute malicious payload or commands",
            "5. Establish persistence or exfiltrate data"
        ]
        
        # Customize steps based on technique
        if technique['technique_id'] == 'T1059':  # Command execution
            steps[3] = "3. Inject malicious commands into function parameters"
            steps[4] = "4. Execute arbitrary system commands"
        elif technique['technique_id'] == 'T1083':  # File discovery
            steps[3] = "3. Use file system functions to explore directory structure"
            steps[4] = "4. Locate and access sensitive files"
        
        return steps
    
    def _assess_scenario_impact(self, technique: Dict[str, Any], tool_capabilities: ToolCapabilities) -> Dict[str, Any]:
        """Assess potential impact of a threat scenario."""
        impact = {
            'confidentiality': 'low',
            'integrity': 'low', 
            'availability': 'low',
            'scope': 'limited'
        }
        
        if technique['severity'] == 'critical':
            impact.update({
                'confidentiality': 'high',
                'integrity': 'high',
                'availability': 'medium',
                'scope': 'extensive'
            })
        elif technique['severity'] == 'high':
            impact.update({
                'confidentiality': 'medium',
                'integrity': 'medium',
                'availability': 'low',
                'scope': 'moderate'
            })
        
        return impact
    
    def _calculate_scenario_likelihood(self,
                                     technique: Dict[str, Any],
                                     exploitation_difficulty: Dict[str, Any],
                                     environment_context: Optional[EnvironmentContext]) -> str:
        """Calculate likelihood of scenario occurrence."""
        difficulty_score = exploitation_difficulty['overall_score']
        
        if difficulty_score < 0.3:
            return 'high'
        elif difficulty_score < 0.6:
            return 'medium'
        else:
            return 'low'
    
    def _generate_detection_indicators(self, technique: Dict[str, Any]) -> List[str]:
        """Generate detection indicators for a technique."""
        indicators = [
            f"Unusual {technique['applicable_function']} function calls",
            "Abnormal parameter patterns or values"
        ]
        
        if technique['technique_id'] == 'T1059':
            indicators.extend([
                "Process execution monitoring alerts",
                "Command line argument analysis"
            ])
        elif technique['technique_id'] == 'T1083':
            indicators.extend([
                "File access pattern analysis",
                "Directory traversal attempts"
            ])
        
        return indicators
    
    def _suggest_mitigations(self, technique: Dict[str, Any], tool_capabilities: ToolCapabilities) -> List[str]:
        """Suggest specific mitigation strategies."""
        mitigations = [
            "Implement strict input validation",
            "Enable comprehensive logging and monitoring",
            "Apply principle of least privilege"
        ]
        
        if technique['technique_id'] == 'T1059':
            mitigations.extend([
                "Disable or restrict command execution functions",
                "Implement command filtering and sanitization",
                "Use application sandboxing"
            ])
        elif technique['technique_id'] == 'T1083':
            mitigations.extend([
                "Implement file access controls",
                "Use directory access restrictions",
                "Enable file integrity monitoring"
            ])
        
        return mitigations
    
    def _generate_combination_scenario(self,
                                     tool_capabilities: ToolCapabilities,
                                     exploitation_difficulty: Dict[str, Any],
                                     environment_context: Optional[EnvironmentContext]) -> Optional[Dict[str, Any]]:
        """Generate scenario combining multiple tool functions."""
        if len(tool_capabilities.tool_functions) < 3:
            return None
        
        return {
            'scenario_id': 'combination_attack',
            'title': 'Multi-Function Attack Chain',
            'severity': 'high',
            'attack_technique': {
                'technique_id': 'T1105',  # Ingress Tool Transfer
                'technique_name': 'Multi-Stage Attack',
                'description': 'Combine multiple tool functions for complex attack'
            },
            'steps': [
                "1. Reconnaissance using information gathering functions",
                "2. Initial access through authentication functions", 
                "3. Privilege escalation using system functions",
                "4. Lateral movement with network functions",
                "5. Data exfiltration using file system functions"
            ],
            'prerequisites': ["Access to multiple tool functions"],
            'potential_impact': {
                'confidentiality': 'high',
                'integrity': 'high',
                'availability': 'medium',
                'scope': 'extensive'
            },
            'likelihood': 'medium',
            'detection_indicators': [
                "Sequential function calls across categories",
                "Unusual function combination patterns"
            ],
            'mitigation_strategies': [
                "Implement function call rate limiting",
                "Monitor for suspicious function sequences",
                "Segregate function categories by privilege level"
            ]
        }