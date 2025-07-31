"""
Mitigation Generator

This module provides actionable mitigation strategy generation for threat analysis reports.
It creates detailed, implementable security controls and remediation guidance based on
discovered threats, attack vectors, and environmental context.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from .models import (
    ToolCapabilities, EnvironmentContext, DeploymentType, 
    SecurityPosture, NetworkExposure, ComplianceFramework
)


logger = logging.getLogger(__name__)


class MitigationCategory(Enum):
    """Categories of security mitigations."""
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    RESPONSIVE = "responsive"
    RECOVERY = "recovery"


class ImplementationDifficulty(Enum):
    """Implementation difficulty levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class MitigationEffectiveness(Enum):
    """Mitigation effectiveness levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MitigationStrategy:
    """A comprehensive mitigation strategy."""
    id: str
    name: str
    category: MitigationCategory
    description: str
    threat_addressed: List[str]
    implementation_steps: List[str]
    technical_requirements: List[str]
    estimated_cost: str
    implementation_time: str
    difficulty: ImplementationDifficulty
    effectiveness: MitigationEffectiveness
    compliance_frameworks: List[str]
    dependencies: List[str]
    success_metrics: List[str]
    maintenance_requirements: List[str]
    risk_reduction_percentage: int
    business_justification: str


class MitigationGenerator:
    """
    Enhanced mitigation generator for creating actionable security guidance
    based on discovered threats and environmental context.
    
    This class generates comprehensive, implementable mitigation strategies
    that security teams can directly use to improve their security posture.
    """
    
    def __init__(self):
        """Initialize the mitigation generator."""
        self.logger = logging.getLogger(__name__)
        
        # Mitigation templates organized by threat type
        self.mitigation_templates = {
            'code_execution': {
                'preventive': [
                    {
                        'name': 'Input Validation and Sanitization',
                        'description': 'Implement comprehensive input validation to prevent code injection',
                        'implementation_steps': [
                            'Validate all user inputs against strict schemas',
                            'Sanitize inputs using appropriate encoding functions',
                            'Implement whitelist-based validation where possible',
                            'Use parameterized queries for database operations',
                            'Enable strict type checking in application code'
                        ],
                        'technical_requirements': [
                            'Input validation library or framework',
                            'Schema validation tools',
                            'Static code analysis tools',
                            'Developer training on secure coding practices'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 75
                    },
                    {
                        'name': 'Application Sandboxing',
                        'description': 'Isolate MCP server execution in secure sandbox environment',
                        'implementation_steps': [
                            'Deploy MCP servers in containerized environments',
                            'Configure strict container security policies',
                            'Implement resource limits (CPU, memory, network)',
                            'Use security profiles (AppArmor, SELinux)',
                            'Enable filesystem isolation and read-only mounts'
                        ],
                        'technical_requirements': [
                            'Container orchestration platform (Docker, Kubernetes)',
                            'Container security scanning tools',
                            'Security policy management system',
                            'Runtime security monitoring'
                        ],
                        'difficulty': ImplementationDifficulty.HIGH,
                        'effectiveness': MitigationEffectiveness.CRITICAL,
                        'risk_reduction': 85
                    }
                ],
                'detective': [
                    {
                        'name': 'Code Execution Monitoring',
                        'description': 'Monitor and detect unauthorized code execution attempts',
                        'implementation_steps': [
                            'Deploy runtime application security monitoring (RASP)',
                            'Configure system call monitoring',
                            'Implement process execution logging',
                            'Set up anomaly detection for unusual execution patterns',
                            'Create alerts for dangerous function usage'
                        ],
                        'technical_requirements': [
                            'Security monitoring platform (SIEM/SOAR)',
                            'Runtime security agent',
                            'Log aggregation and analysis tools',
                            'Behavioral analysis capabilities'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 60
                    }
                ]
            },
            
            'file_system': {
                'preventive': [
                    {
                        'name': 'File System Access Controls',
                        'description': 'Implement strict file system permissions and access controls',
                        'implementation_steps': [
                            'Apply principle of least privilege to file access',
                            'Implement mandatory access controls (MAC)',
                            'Use filesystem-level encryption for sensitive data',
                            'Configure file integrity monitoring (FIM)',
                            'Establish secure file operation APIs'
                        ],
                        'technical_requirements': [
                            'Access control system (ACLs, RBAC)',
                            'File encryption solution',
                            'File integrity monitoring tools',
                            'Secure filesystem (encrypted volumes)'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 70
                    },
                    {
                        'name': 'Path Traversal Prevention',
                        'description': 'Prevent directory traversal and path manipulation attacks',
                        'implementation_steps': [
                            'Implement strict path validation functions',
                            'Use canonical path resolution',
                            'Apply chroot jails or similar isolation',
                            'Blacklist dangerous path patterns (../, \\..\\)',
                            'Validate file extensions and types'
                        ],
                        'technical_requirements': [
                            'Path validation library',
                            'Filesystem isolation tools',
                            'File type validation utilities',
                            'Security testing tools'
                        ],
                        'difficulty': ImplementationDifficulty.LOW,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 80
                    }
                ],
                'detective': [
                    {
                        'name': 'File Activity Monitoring',
                        'description': 'Monitor and log all file system operations',
                        'implementation_steps': [
                            'Enable comprehensive file access logging',
                            'Monitor file creation, modification, and deletion',
                            'Track permission changes and ownership modifications',
                            'Implement real-time file integrity checking',
                            'Set up alerts for sensitive file access'
                        ],
                        'technical_requirements': [
                            'File activity monitoring solution',
                            'Centralized logging infrastructure',
                            'Real-time alerting system',
                            'File integrity monitoring tools'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 65
                    }
                ]
            },
            
            'network_access': {
                'preventive': [
                    {
                        'name': 'Network Segmentation',
                        'description': 'Isolate MCP servers in secure network segments',
                        'implementation_steps': [
                            'Deploy MCP servers in isolated VLANs',
                            'Implement micro-segmentation for inter-service communication',
                            'Configure strict firewall rules (default deny)',
                            'Use network access control (NAC) systems',
                            'Implement zero-trust network principles'
                        ],
                        'technical_requirements': [
                            'Network segmentation infrastructure',
                            'Next-generation firewalls (NGFW)',
                            'Network access control system',
                            'Software-defined networking (SDN) capabilities'
                        ],
                        'difficulty': ImplementationDifficulty.HIGH,
                        'effectiveness': MitigationEffectiveness.CRITICAL,
                        'risk_reduction': 85
                    },
                    {
                        'name': 'Network Traffic Filtering',
                        'description': 'Filter and restrict network communications',
                        'implementation_steps': [
                            'Implement application-layer firewalls',
                            'Configure deep packet inspection (DPI)',
                            'Block unnecessary protocols and ports',
                            'Implement rate limiting and throttling',
                            'Use network intrusion prevention systems (NIPS)'
                        ],
                        'technical_requirements': [
                            'Application-aware firewall',
                            'Deep packet inspection engine',
                            'Network intrusion prevention system',
                            'Traffic analysis tools'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 75
                    }
                ],
                'detective': [
                    {
                        'name': 'Network Traffic Monitoring',
                        'description': 'Monitor and analyze network communications',
                        'implementation_steps': [
                            'Deploy network traffic analysis (NTA) solutions',
                            'Implement network security monitoring (NSM)',
                            'Configure flow-based monitoring and analysis',
                            'Set up DNS monitoring and analysis',
                            'Implement SSL/TLS traffic inspection'
                        ],
                        'technical_requirements': [
                            'Network traffic analysis platform',
                            'Network security monitoring tools',
                            'Flow collection and analysis system',
                            'SSL/TLS inspection capabilities'
                        ],
                        'difficulty': ImplementationDifficulty.HIGH,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 70
                    }
                ]
            },
            
            'database_access': {
                'preventive': [
                    {
                        'name': 'Database Security Hardening',
                        'description': 'Implement comprehensive database security controls',
                        'implementation_steps': [
                            'Apply principle of least privilege to database access',
                            'Implement database-level encryption (TDE)',
                            'Configure database firewalls and access controls',
                            'Use parameterized queries and prepared statements',
                            'Enable database audit logging'
                        ],
                        'technical_requirements': [
                            'Database security solution',
                            'Database encryption capabilities',
                            'Database firewall or proxy',
                            'Database activity monitoring (DAM) tools'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.HIGH,
                        'risk_reduction': 80
                    }
                ]
            },
            
            'authentication': {
                'preventive': [
                    {
                        'name': 'Multi-Factor Authentication',
                        'description': 'Implement strong multi-factor authentication',
                        'implementation_steps': [
                            'Deploy enterprise MFA solution',
                            'Require MFA for all administrative access',
                            'Implement adaptive authentication based on risk',
                            'Configure session management and timeout policies',
                            'Use certificate-based authentication where possible'
                        ],
                        'technical_requirements': [
                            'Multi-factor authentication system',
                            'Identity and access management (IAM) platform',
                            'Certificate authority (CA) infrastructure',
                            'Risk-based authentication engine'
                        ],
                        'difficulty': ImplementationDifficulty.MEDIUM,
                        'effectiveness': MitigationEffectiveness.CRITICAL,
                        'risk_reduction': 90
                    }
                ]
            }
        }
        
        # Compliance framework mappings
        self.compliance_mappings = {
            'SOC2': {
                'authentication': ['CC6.1', 'CC6.2', 'CC6.3'],
                'access_control': ['CC6.1', 'CC6.2', 'CC6.7'],
                'monitoring': ['CC7.1', 'CC7.2', 'CC7.3'],
                'data_protection': ['CC6.4', 'CC6.5']
            },
            'PCI_DSS': {
                'authentication': ['8.1', '8.2', '8.3'],
                'access_control': ['7.1', '7.2', '7.3'],
                'monitoring': ['10.1', '10.2', '10.3'],
                'encryption': ['3.1', '3.2', '4.1']
            },
            'NIST_CSF': {
                'identify': ['ID.AM', 'ID.GV', 'ID.RA'],
                'protect': ['PR.AC', 'PR.AT', 'PR.DS', 'PR.IP', 'PR.MA', 'PR.PT'],
                'detect': ['DE.AE', 'DE.CM', 'DE.DP'],
                'respond': ['RS.RP', 'RS.CO', 'RS.AN', 'RS.MI', 'RS.IM'],
                'recover': ['RC.RP', 'RC.IM', 'RC.CO']
            }
        }
    
    def generate_mitigation_strategies(self,
                                     threat_analysis: Dict[str, Any],
                                     environment_context: EnvironmentContext,
                                     compliance_requirements: List[ComplianceFramework] = None,
                                     budget_constraint: Optional[str] = None) -> List[MitigationStrategy]:
        """
        Generate comprehensive mitigation strategies based on threat analysis.
        
        Args:
            threat_analysis: Results from threat analysis containing identified risks
            environment_context: Environment context for customization
            compliance_requirements: Required compliance frameworks
            budget_constraint: Budget constraints (low, medium, high, unlimited)
            
        Returns:
            List of prioritized mitigation strategies
        """
        try:
            self.logger.info("Generating mitigation strategies")
            
            strategies = []
            
            # Extract threats from analysis
            identified_threats = self._extract_threats_from_analysis(threat_analysis)
            
            # Generate strategies for each threat category
            for threat_category, threat_details in identified_threats.items():
                category_strategies = self._generate_strategies_for_category(
                    threat_category, 
                    threat_details,
                    environment_context,
                    compliance_requirements
                )
                strategies.extend(category_strategies)
            
            # Apply budget constraints
            if budget_constraint:
                strategies = self._filter_by_budget(strategies, budget_constraint)
            
            # Prioritize strategies
            strategies = self._prioritize_strategies(strategies, environment_context)
            
            # Add implementation guidance
            strategies = self._add_implementation_guidance(strategies, environment_context)
            
            self.logger.info(f"Generated {len(strategies)} mitigation strategies")
            return strategies
            
        except Exception as e:
            self.logger.error(f"Error generating mitigation strategies: {e}")
            return []
    
    def _extract_threats_from_analysis(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and categorize threats from threat analysis results."""
        threats = {}
        
        # Extract attack vectors
        if 'attack_vectors' in threat_analysis:
            for vector in threat_analysis['attack_vectors']:
                category = self._categorize_threat(vector)
                if category not in threats:
                    threats[category] = []
                threats[category].append(vector)
        
        # Extract risk indicators
        if 'risk_indicators' in threat_analysis:
            for indicator in threat_analysis['risk_indicators']:
                category = self._categorize_risk_indicator(indicator)
                if category not in threats:
                    threats[category] = []
                threats[category].append({'type': 'risk_indicator', 'details': indicator})
        
        # Extract vulnerabilities
        if 'vulnerabilities' in threat_analysis:
            for vuln in threat_analysis['vulnerabilities']:
                category = self._categorize_vulnerability(vuln)
                if category not in threats:
                    threats[category] = []
                threats[category].append(vuln)
        
        return threats
    
    def _categorize_threat(self, threat: Dict[str, Any]) -> str:
        """Categorize a threat based on its characteristics."""
        threat_name = threat.get('name', '').lower()
        threat_desc = threat.get('description', '').lower()
        
        # Code execution threats
        if any(keyword in threat_name or keyword in threat_desc 
               for keyword in ['code', 'execution', 'inject', 'eval', 'command']):
            return 'code_execution'
        
        # File system threats
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['file', 'write', 'read', 'path', 'directory']):
            return 'file_system'
        
        # Network threats
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['network', 'http', 'api', 'connection', 'traffic']):
            return 'network_access'
        
        # Database threats
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['database', 'sql', 'query', 'data']):
            return 'database_access'
        
        # Authentication threats
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['auth', 'login', 'credential', 'token', 'session']):
            return 'authentication'
        
        else:
            return 'general'
    
    def _categorize_risk_indicator(self, indicator: str) -> str:
        """Categorize a risk indicator."""
        indicator_lower = indicator.lower()
        
        if any(keyword in indicator_lower 
               for keyword in ['exec', 'command', 'code', 'eval']):
            return 'code_execution'
        elif any(keyword in indicator_lower 
                 for keyword in ['file', 'write', 'read', 'path']):
            return 'file_system'
        elif any(keyword in indicator_lower 
                 for keyword in ['network', 'http', 'api']):
            return 'network_access'
        elif any(keyword in indicator_lower 
                 for keyword in ['database', 'sql', 'query']):
            return 'database_access'
        elif any(keyword in indicator_lower 
                 for keyword in ['auth', 'login', 'credential']):
            return 'authentication'
        else:
            return 'general'
    
    def _categorize_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """Categorize a vulnerability."""
        vuln_type = vulnerability.get('type', '').lower()
        vuln_desc = vulnerability.get('description', '').lower()
        
        # Use similar categorization logic as threats
        return self._categorize_threat({'name': vuln_type, 'description': vuln_desc})
    
    def _generate_strategies_for_category(self,
                                        threat_category: str,
                                        threat_details: List[Dict[str, Any]],
                                        environment_context: EnvironmentContext,
                                        compliance_requirements: List[ComplianceFramework] = None) -> List[MitigationStrategy]:
        """Generate mitigation strategies for a specific threat category."""
        strategies = []
        
        if threat_category not in self.mitigation_templates:
            return strategies
        
        category_templates = self.mitigation_templates[threat_category]
        
        # Generate strategies for each mitigation category (preventive, detective, etc.)
        for mitigation_type, templates in category_templates.items():
            for template in templates:
                strategy = self._create_strategy_from_template(
                    template,
                    threat_category,
                    threat_details,
                    mitigation_type,
                    environment_context,
                    compliance_requirements
                )
                if strategy:
                    strategies.append(strategy)
        
        return strategies
    
    def _create_strategy_from_template(self,
                                     template: Dict[str, Any],
                                     threat_category: str,
                                     threat_details: List[Dict[str, Any]],
                                     mitigation_type: str,
                                     environment_context: EnvironmentContext,
                                     compliance_requirements: List[ComplianceFramework] = None) -> Optional[MitigationStrategy]:
        """Create a mitigation strategy from a template."""
        try:
            # Generate unique ID
            strategy_id = f"{threat_category}_{mitigation_type}_{template['name'].lower().replace(' ', '_')}"
            
            # Extract threats addressed
            threats_addressed = [detail.get('name', 'Unknown') for detail in threat_details]
            
            # Calculate estimated cost and time
            cost_estimate = self._estimate_implementation_cost(template, environment_context)
            time_estimate = self._estimate_implementation_time(template, environment_context)
            
            # Determine compliance frameworks
            compliance_frameworks = self._map_to_compliance_frameworks(
                threat_category, compliance_requirements
            )
            
            # Generate success metrics
            success_metrics = self._generate_success_metrics(template, threat_category)
            
            # Create business justification
            business_justification = self._create_business_justification(
                template, threat_details, environment_context
            )
            
            # Determine dependencies
            dependencies = self._identify_dependencies(template, environment_context)
            
            # Generate maintenance requirements
            maintenance_requirements = self._generate_maintenance_requirements(template)
            
            strategy = MitigationStrategy(
                id=strategy_id,
                name=template['name'],
                category=MitigationCategory(mitigation_type),
                description=template['description'],
                threat_addressed=threats_addressed,
                implementation_steps=template['implementation_steps'],
                technical_requirements=template['technical_requirements'],
                estimated_cost=cost_estimate,
                implementation_time=time_estimate,
                difficulty=template['difficulty'],
                effectiveness=template['effectiveness'],
                compliance_frameworks=compliance_frameworks,
                dependencies=dependencies,
                success_metrics=success_metrics,
                maintenance_requirements=maintenance_requirements,
                risk_reduction_percentage=template['risk_reduction'],
                business_justification=business_justification
            )
            
            return strategy
            
        except Exception as e:
            self.logger.error(f"Error creating strategy from template: {e}")
            return None
    
    def _estimate_implementation_cost(self,
                                    template: Dict[str, Any],
                                    environment_context: EnvironmentContext) -> str:
        """Estimate implementation cost based on template and environment."""
        base_cost_map = {
            ImplementationDifficulty.LOW: 'Low ($5K - $20K)',
            ImplementationDifficulty.MEDIUM: 'Medium ($20K - $100K)',
            ImplementationDifficulty.HIGH: 'High ($100K - $500K)',
            ImplementationDifficulty.VERY_HIGH: 'Very High ($500K+)'
        }
        
        base_cost = base_cost_map.get(template['difficulty'], 'Medium ($20K - $100K)')
        
        # Adjust based on environment
        if environment_context.deployment_type == DeploymentType.CLOUD:
            # Cloud deployments may have lower infrastructure costs
            cost_adjustments = {
                'Low ($5K - $20K)': 'Low ($3K - $15K)',
                'Medium ($20K - $100K)': 'Medium ($15K - $75K)',
                'High ($100K - $500K)': 'High ($75K - $400K)',
                'Very High ($500K+)': 'High ($400K+)'
            }
            base_cost = cost_adjustments.get(base_cost, base_cost)
        
        return base_cost
    
    def _estimate_implementation_time(self,
                                    template: Dict[str, Any],
                                    environment_context: EnvironmentContext) -> str:
        """Estimate implementation time based on template and environment."""
        time_map = {
            ImplementationDifficulty.LOW: '2-4 weeks',
            ImplementationDifficulty.MEDIUM: '1-3 months',
            ImplementationDifficulty.HIGH: '3-6 months',
            ImplementationDifficulty.VERY_HIGH: '6-12 months'
        }
        
        base_time = time_map.get(template['difficulty'], '1-3 months')
        
        # Adjust based on security posture
        if environment_context.security_posture == SecurityPosture.HIGH:
            # Environments with high security may take longer due to additional approvals
            time_adjustments = {
                '2-4 weeks': '3-6 weeks',
                '1-3 months': '2-4 months',
                '3-6 months': '4-8 months',
                '6-12 months': '8-15 months'
            }
            base_time = time_adjustments.get(base_time, base_time)
        
        return base_time
    
    def _map_to_compliance_frameworks(self,
                                    threat_category: str,
                                    compliance_requirements: List[ComplianceFramework] = None) -> List[str]:
        """Map threat category to relevant compliance frameworks."""
        frameworks = []
        
        if not compliance_requirements:
            return frameworks
        
        # Map categories to compliance controls
        category_mapping = {
            'authentication': ['authentication', 'access_control'],
            'access_control': ['access_control'],
            'monitoring': ['monitoring'],
            'data_protection': ['data_protection', 'encryption'],
            'code_execution': ['access_control', 'monitoring'],
            'file_system': ['access_control', 'monitoring', 'data_protection'],
            'network_access': ['monitoring', 'access_control'],
            'database_access': ['data_protection', 'access_control', 'monitoring']
        }
        
        relevant_controls = category_mapping.get(threat_category, [])
        
        for framework in compliance_requirements:
            framework_name = framework.name if hasattr(framework, 'name') else str(framework)
            if framework_name in self.compliance_mappings:
                framework_controls = self.compliance_mappings[framework_name]
                for control in relevant_controls:
                    if control in framework_controls:
                        frameworks.extend(framework_controls[control])
        
        return list(set(frameworks))  # Remove duplicates
    
    def _generate_success_metrics(self,
                                template: Dict[str, Any],
                                threat_category: str) -> List[str]:
        """Generate success metrics for the mitigation strategy."""
        base_metrics = [
            f'Reduction in {threat_category} incidents by {template["risk_reduction"]}%',
            'Implementation completed within planned timeline',
            'Technical requirements successfully deployed',
            'Staff training completed for relevant personnel'
        ]
        
        # Category-specific metrics
        category_metrics = {
            'code_execution': [
                'Zero code injection incidents detected',
                'All user inputs properly validated',
                'Sandboxing mechanisms operational'
            ],
            'file_system': [
                'File integrity monitoring active and alerting',
                'No unauthorized file modifications detected',
                'Access controls properly enforced'
            ],
            'network_access': [
                'Network segmentation rules active',
                'Unauthorized network connections blocked',
                'Network monitoring covering all traffic'
            ],
            'authentication': [
                'MFA adoption rate >95%',
                'Credential-based attacks blocked',
                'Session management policies enforced'
            ]
        }
        
        if threat_category in category_metrics:
            base_metrics.extend(category_metrics[threat_category])
        
        return base_metrics
    
    def _create_business_justification(self,
                                     template: Dict[str, Any],
                                     threat_details: List[Dict[str, Any]],
                                     environment_context: EnvironmentContext) -> str:
        """Create business justification for the mitigation strategy."""
        risk_reduction = template['risk_reduction']
        threat_count = len(threat_details)
        
        base_justification = f"This mitigation addresses {threat_count} identified threat(s) "
        base_justification += f"and can reduce related security risks by {risk_reduction}%. "
        
        # Add environment-specific justifications
        if environment_context.deployment_type == DeploymentType.PRODUCTION:
            base_justification += "Given the production environment, implementation is critical "
            base_justification += "to prevent business disruption and protect customer data. "
        
        if environment_context.security_posture == SecurityPosture.LOW:
            base_justification += "The current low security posture increases the urgency "
            base_justification += "of implementing this control to prevent exploitation. "
        
        # Add cost-benefit analysis
        effectiveness = template['effectiveness']
        if effectiveness == MitigationEffectiveness.CRITICAL:
            base_justification += "The critical effectiveness rating indicates high ROI "
            base_justification += "and should be prioritized for immediate implementation."
        elif effectiveness == MitigationEffectiveness.HIGH:
            base_justification += "The high effectiveness rating indicates strong ROI "
            base_justification += "and should be included in the next security improvement cycle."
        
        return base_justification
    
    def _identify_dependencies(self,
                             template: Dict[str, Any],
                             environment_context: EnvironmentContext) -> List[str]:
        """Identify implementation dependencies."""
        dependencies = []
        
        # Technical dependencies
        tech_requirements = template.get('technical_requirements', [])
        for requirement in tech_requirements:
            if 'monitoring' in requirement.lower():
                dependencies.append('Security monitoring infrastructure')
            elif 'firewall' in requirement.lower():
                dependencies.append('Network security infrastructure')
            elif 'container' in requirement.lower():
                dependencies.append('Container orchestration platform')
            elif 'encryption' in requirement.lower():
                dependencies.append('Cryptographic key management system')
        
        # Environment-specific dependencies
        if environment_context.deployment_type == DeploymentType.CLOUD:
            dependencies.append('Cloud security service integration')
        elif environment_context.deployment_type == DeploymentType.ON_PREMISE:
            dependencies.append('On-premise infrastructure capacity')
        
        # Organizational dependencies
        difficulty = template.get('difficulty', ImplementationDifficulty.MEDIUM)
        if difficulty in [ImplementationDifficulty.HIGH, ImplementationDifficulty.VERY_HIGH]:
            dependencies.extend([
                'Executive sponsorship and budget approval',
                'Dedicated project team with security expertise',
                'Change management process for system modifications'
            ])
        
        return dependencies
    
    def _generate_maintenance_requirements(self, template: Dict[str, Any]) -> List[str]:
        """Generate maintenance requirements for the mitigation strategy."""
        base_requirements = [
            'Regular review and update of security policies',
            'Periodic testing of implemented controls',
            'Staff training updates and awareness programs',
            'Monitoring system health and effectiveness metrics'
        ]
        
        # Template-specific requirements
        if 'monitoring' in template['name'].lower():
            base_requirements.extend([
                'Regular tuning of detection rules and thresholds',
                'Log retention and storage management',
                'Alert response procedure validation'
            ])
        
        if 'authentication' in template['name'].lower():
            base_requirements.extend([
                'Regular access review and certification',
                'MFA device management and replacement',
                'Identity provider integration maintenance'
            ])
        
        if 'network' in template['name'].lower():
            base_requirements.extend([
                'Firewall rule review and optimization',
                'Network topology change management',
                'Performance monitoring and capacity planning'
            ])
        
        return base_requirements
    
    def _filter_by_budget(self,
                         strategies: List[MitigationStrategy],
                         budget_constraint: str) -> List[MitigationStrategy]:
        """Filter strategies based on budget constraints."""
        budget_filters = {
            'low': [ImplementationDifficulty.LOW],
            'medium': [ImplementationDifficulty.LOW, ImplementationDifficulty.MEDIUM],
            'high': [ImplementationDifficulty.LOW, ImplementationDifficulty.MEDIUM, ImplementationDifficulty.HIGH],
            'unlimited': list(ImplementationDifficulty)
        }
        
        allowed_difficulties = budget_filters.get(budget_constraint.lower(), 
                                                 [ImplementationDifficulty.LOW, ImplementationDifficulty.MEDIUM])
        
        return [strategy for strategy in strategies if strategy.difficulty in allowed_difficulties]
    
    def _prioritize_strategies(self,
                             strategies: List[MitigationStrategy],
                             environment_context: EnvironmentContext) -> List[MitigationStrategy]:
        """Prioritize mitigation strategies based on effectiveness and context."""
        def priority_score(strategy):
            # Base score from effectiveness
            effectiveness_scores = {
                MitigationEffectiveness.CRITICAL: 4,
                MitigationEffectiveness.HIGH: 3,
                MitigationEffectiveness.MEDIUM: 2,
                MitigationEffectiveness.LOW: 1
            }
            score = effectiveness_scores.get(strategy.effectiveness, 2)
            
            # Adjust for risk reduction percentage
            score += (strategy.risk_reduction_percentage / 100) * 2
            
            # Adjust for implementation difficulty (easier = higher priority)
            difficulty_adjustments = {
                ImplementationDifficulty.LOW: 1.2,
                ImplementationDifficulty.MEDIUM: 1.0,
                ImplementationDifficulty.HIGH: 0.8,
                ImplementationDifficulty.VERY_HIGH: 0.6
            }
            score *= difficulty_adjustments.get(strategy.difficulty, 1.0)
            
            # Environment-specific adjustments
            if environment_context.security_posture == SecurityPosture.LOW:
                # Prioritize preventive controls in low-security environments
                if strategy.category == MitigationCategory.PREVENTIVE:
                    score *= 1.3
            
            if environment_context.deployment_type == DeploymentType.PRODUCTION:
                # Higher priority for production environments
                score *= 1.2
            
            return score
        
        return sorted(strategies, key=priority_score, reverse=True)
    
    def _add_implementation_guidance(self,
                                   strategies: List[MitigationStrategy],
                                   environment_context: EnvironmentContext) -> List[MitigationStrategy]:
        """Add implementation guidance to strategies."""
        for strategy in strategies:
            # Add environment-specific guidance
            if environment_context.deployment_type == DeploymentType.CLOUD:
                strategy.implementation_steps.insert(0, 
                    "Evaluate cloud-native security services for this control")
            elif environment_context.deployment_type == DeploymentType.CONTAINER:
                strategy.implementation_steps.insert(0,
                    "Consider container-specific implementation approaches")
            
            # Add security posture-specific guidance
            if environment_context.security_posture == SecurityPosture.LOW:
                strategy.implementation_steps.append(
                    "Implement in phases to minimize business disruption")
            elif environment_context.security_posture == SecurityPosture.HIGH:
                strategy.implementation_steps.append(
                    "Ensure change management approval before implementation")
        
        return strategies
    
    def generate_implementation_roadmap(self,
                                      strategies: List[MitigationStrategy],
                                      environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Generate an implementation roadmap for the mitigation strategies."""
        roadmap = {
            'phases': [],
            'total_duration': '12-18 months',
            'total_estimated_cost': 'TBD',
            'success_criteria': [],
            'risk_milestones': []
        }
        
        # Group strategies by priority and dependencies
        phase_1_strategies = []  # Critical, low dependency
        phase_2_strategies = []  # High priority, some dependencies
        phase_3_strategies = []  # Medium priority, complex dependencies
        
        for strategy in strategies:
            if (strategy.effectiveness == MitigationEffectiveness.CRITICAL and 
                len(strategy.dependencies) <= 2):
                phase_1_strategies.append(strategy)
            elif strategy.effectiveness in [MitigationEffectiveness.HIGH, MitigationEffectiveness.CRITICAL]:
                phase_2_strategies.append(strategy)
            else:
                phase_3_strategies.append(strategy)
        
        # Create phases
        if phase_1_strategies:
            roadmap['phases'].append({
                'phase': 1,
                'name': 'Critical Controls Implementation',
                'duration': '0-6 months',
                'strategies': [s.name for s in phase_1_strategies],
                'objectives': 'Address critical security gaps and highest risk threats',
                'success_criteria': f'Implement {len(phase_1_strategies)} critical controls'
            })
        
        if phase_2_strategies:
            roadmap['phases'].append({
                'phase': 2,
                'name': 'Enhanced Security Controls',
                'duration': '6-12 months',
                'strategies': [s.name for s in phase_2_strategies],
                'objectives': 'Strengthen security posture with comprehensive controls',
                'success_criteria': f'Implement {len(phase_2_strategies)} enhanced controls'
            })
        
        if phase_3_strategies:
            roadmap['phases'].append({
                'phase': 3,
                'name': 'Advanced Security Capabilities',
                'duration': '12-18 months',
                'strategies': [s.name for s in phase_3_strategies],
                'objectives': 'Achieve advanced security maturity',
                'success_criteria': f'Implement {len(phase_3_strategies)} advanced controls'
            })
        
        # Calculate total risk reduction
        total_risk_reduction = sum(s.risk_reduction_percentage for s in strategies) / len(strategies)
        roadmap['success_criteria'] = [
            f'Achieve {total_risk_reduction:.0f}% average risk reduction across all threat categories',
            'Complete implementation within planned timeline and budget',
            'Maintain business operations during implementation',
            'Achieve compliance with required frameworks'
        ]
        
        return roadmap 