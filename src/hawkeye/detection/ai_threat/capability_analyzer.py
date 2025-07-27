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
        
        # High-risk function patterns
        high_risk_patterns = {
            'exec': 'code_execution',
            'eval': 'code_execution', 
            'run': 'code_execution',
            'command': 'system_command',
            'shell': 'system_command',
            'write': 'file_write',
            'delete': 'file_delete',
            'remove': 'file_delete',
            'http': 'network_access',
            'url': 'network_access',
            'api': 'external_api',
            'sql': 'database_access',
            'query': 'database_access'
        }
        
        for pattern, indicator in high_risk_patterns.items():
            if pattern in function_lower:
                indicators.append(indicator)
        
        return indicators
    
    def _function_requires_privileges(self, function_name: str) -> bool:
        """Check if function requires elevated privileges."""
        function_lower = function_name.lower()
        
        privilege_patterns = [
            'admin', 'root', 'sudo', 'exec', 'command', 'shell',
            'system', 'install', 'delete', 'remove', 'kill'
        ]
        
        return any(pattern in function_lower for pattern in privilege_patterns)
    
    def _function_has_external_access(self, function_name: str) -> bool:
        """Check if function has external access capabilities."""
        function_lower = function_name.lower()
        
        external_patterns = [
            'http', 'url', 'api', 'web', 'download', 'upload',
            'fetch', 'request', 'curl', 'wget', 'socket'
        ]
        
        return any(pattern in function_lower for pattern in external_patterns)
    
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