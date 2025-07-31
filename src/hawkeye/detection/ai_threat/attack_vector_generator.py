"""
Attack Vector Generator

This module provides dynamic attack vector generation based on discovered MCP tool capabilities.
It implements pattern-based generation to create realistic, non-hardcoded attack vectors
for threat analysis reports.
"""

import logging
from typing import Dict, List, Optional, Any

from .models import (
    ToolCapabilities, ToolFunction, EnvironmentContext, 
    DeploymentType, SecurityPosture, NetworkExposure
)


logger = logging.getLogger(__name__)


class AttackVectorGenerator:
    """
    Enhanced attack vector generator for dynamically creating attack scenarios
    based on discovered MCP tool capabilities.
    
    This class implements pattern-based generation to create realistic, 
    non-hardcoded attack vectors for threat analysis reports.
    """
    
    def __init__(self):
        """Initialize the attack vector generator."""
        self.logger = logging.getLogger(__name__)
        
        # Attack vector templates organized by capability patterns
        self.attack_templates = {
            # File system attack vectors
            'file_write': {
                'base_vector': {
                    'name': 'Arbitrary File Write',
                    'category': 'File System',
                    'severity': 'high',
                    'description': 'Exploitation of file write functionality to deploy malicious files'
                },
                'variations': [
                    {
                        'name': 'Web Shell Deployment',
                        'technique': 'Deploy web shell for persistent access',
                        'prerequisites': ['Web server directory access', 'Write permissions'],
                        'steps': [
                            'Identify web-accessible directory',
                            'Craft web shell payload',
                            'Use {function_name} to write shell file',
                            'Access shell via web browser'
                        ],
                        'impact': 'Remote code execution and persistent access',
                        'detection_methods': ['File integrity monitoring', 'Web access logs'],
                        'example_payload': '<?php system($_GET["cmd"]); ?>',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    },
                    {
                        'name': 'Configuration File Tampering',
                        'technique': 'Modify system configuration files',
                        'prerequisites': ['Configuration file write access'],
                        'steps': [
                            'Identify critical configuration files',
                            'Craft malicious configuration',
                            'Use {function_name} to overwrite config',
                            'Trigger configuration reload'
                        ],
                        'impact': 'System misconfiguration and privilege escalation',
                        'detection_methods': ['Configuration monitoring', 'System behavior analysis'],
                        'example_payload': 'Modified SSH config allowing password auth',
                        'cvss_vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    },
                    {
                        'name': 'Log File Poisoning',
                        'technique': 'Inject malicious content into log files',
                        'prerequisites': ['Log file write access'],
                        'steps': [
                            'Identify log file locations',
                            'Craft log injection payload',
                            'Use {function_name} to inject content',
                            'Exploit log processing vulnerabilities'
                        ],
                        'impact': 'Log tampering and potential code execution',
                        'detection_methods': ['Log integrity monitoring', 'Anomaly detection'],
                        'example_payload': 'Malicious JavaScript in web logs',
                        'cvss_vector': 'CVSS:3.1/AV:L/AC:M/PR:L/UI:N/S:U/C:L/I:H/A:L'
                    }
                ]
            },
            
            'code_execution': {
                'base_vector': {
                    'name': 'Remote Code Execution',
                    'category': 'Code Execution',
                    'severity': 'critical',
                    'description': 'Direct execution of arbitrary code on the target system'
                },
                'variations': [
                    {
                        'name': 'Command Injection',
                        'technique': 'Inject malicious commands into function parameters',
                        'prerequisites': ['Function parameter access', 'Insufficient input validation'],
                        'steps': [
                            'Analyze function parameter structure',
                            'Identify injection points',
                            'Craft command injection payload',
                            'Execute {function_name} with malicious input'
                        ],
                        'impact': 'Complete system compromise',
                        'detection_methods': ['Command line monitoring', 'Process behavior analysis'],
                        'example_payload': 'normal_param; rm -rf / #',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H'
                    },
                    {
                        'name': 'Code Deserialization Attack',
                        'technique': 'Exploit unsafe deserialization in code execution',
                        'prerequisites': ['Serialized data processing', 'Unsafe deserialization'],
                        'steps': [
                            'Identify serialization format',
                            'Craft malicious serialized object',
                            'Use {function_name} to process payload',
                            'Trigger code execution during deserialization'
                        ],
                        'impact': 'Remote code execution with application privileges',
                        'detection_methods': ['Deserialization monitoring', 'Memory analysis'],
                        'example_payload': 'Malicious pickled Python object',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    },
                    {
                        'name': 'Template Injection',
                        'technique': 'Inject malicious code into template processing',
                        'prerequisites': ['Template processing functionality'],
                        'steps': [
                            'Identify template engine type',
                            'Research template injection techniques',
                            'Craft template injection payload',
                            'Execute {function_name} with malicious template'
                        ],
                        'impact': 'Code execution within template context',
                        'detection_methods': ['Template parsing monitoring', 'Output analysis'],
                        'example_payload': '{{7*7}} or similar template syntax',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:M/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    }
                ]
            },
            
            'network_access': {
                'base_vector': {
                    'name': 'Network-Based Attack',
                    'category': 'Network',
                    'severity': 'medium',
                    'description': 'Exploitation of network access for reconnaissance and lateral movement'
                },
                'variations': [
                    {
                        'name': 'Internal Network Reconnaissance',
                        'technique': 'Scan internal networks using MCP server as pivot',
                        'prerequisites': ['Network connectivity', 'Internal network access'],
                        'steps': [
                            'Use {function_name} to probe internal networks',
                            'Identify active hosts and services',
                            'Fingerprint running services',
                            'Plan lateral movement attacks'
                        ],
                        'impact': 'Network mapping and attack surface discovery',
                        'detection_methods': ['Network traffic monitoring', 'Port scan detection'],
                        'example_payload': 'Port scan targeting 192.168.1.0/24',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'
                    },
                    {
                        'name': 'Data Exfiltration',
                        'technique': 'Exfiltrate sensitive data over network',
                        'prerequisites': ['Data access', 'External network connectivity'],
                        'steps': [
                            'Identify sensitive data sources',
                            'Use {function_name} to retrieve data',
                            'Establish covert communication channel',
                            'Transmit data to external server'
                        ],
                        'impact': 'Confidential data breach',
                        'detection_methods': ['Data loss prevention', 'Network flow analysis'],
                        'example_payload': 'HTTPS POST to attacker-controlled server',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
                    },
                    {
                        'name': 'Command and Control',
                        'technique': 'Establish C&C communication channel',
                        'prerequisites': ['Network access', 'External connectivity'],
                        'steps': [
                            'Use {function_name} to connect to C&C server',
                            'Establish encrypted communication',
                            'Receive commands from attacker',
                            'Execute commands and report results'
                        ],
                        'impact': 'Remote system control',
                        'detection_methods': ['C&C traffic detection', 'Behavioral analysis'],
                        'example_payload': 'DNS tunneling or HTTPS beaconing',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    }
                ]
            },
            
            'database_access': {
                'base_vector': {
                    'name': 'Database Attack',
                    'category': 'Data Access',
                    'severity': 'high',
                    'description': 'Exploitation of database access for data theft and manipulation'
                },
                'variations': [
                    {
                        'name': 'SQL Injection',
                        'technique': 'Inject malicious SQL through function parameters',
                        'prerequisites': ['Database query functionality', 'Insufficient input validation'],
                        'steps': [
                            'Analyze database query structure',
                            'Identify injection points',
                            'Craft SQL injection payload',
                            'Use {function_name} to execute malicious query'
                        ],
                        'impact': 'Database compromise and data theft',
                        'detection_methods': ['SQL injection detection', 'Database activity monitoring'],
                        'example_payload': "'; DROP TABLE users; --",
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    },
                    {
                        'name': 'Privilege Escalation via Database',
                        'technique': 'Exploit database privileges for system access',
                        'prerequisites': ['Database access', 'Database privilege escalation vectors'],
                        'steps': [
                            'Enumerate database permissions',
                            'Identify privilege escalation paths',
                            'Use {function_name} to execute privileged operations',
                            'Gain higher system privileges'
                        ],
                        'impact': 'Privilege escalation and system compromise',
                        'detection_methods': ['Privilege monitoring', 'Database audit logs'],
                        'example_payload': 'xp_cmdshell or similar stored procedures',
                        'cvss_vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    },
                    {
                        'name': 'Data Mining and Extraction',
                        'technique': 'Extract sensitive data from database',
                        'prerequisites': ['Database read access'],
                        'steps': [
                            'Enumerate database schema',
                            'Identify sensitive tables and columns',
                            'Use {function_name} to extract data',
                            'Compile and exfiltrate sensitive information'
                        ],
                        'impact': 'Sensitive data exposure',
                        'detection_methods': ['Data access monitoring', 'Anomaly detection'],
                        'example_payload': 'SELECT * FROM sensitive_table',
                        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
                    }
                ]
            },
            
            'system_command': {
                'base_vector': {
                    'name': 'System Command Execution',
                    'category': 'System',
                    'severity': 'critical',
                    'description': 'Execution of arbitrary system commands'
                },
                'variations': [
                    {
                        'name': 'Privilege Escalation',
                        'technique': 'Escalate privileges using system commands',
                        'prerequisites': ['Command execution capability', 'Local privilege escalation vectors'],
                        'steps': [
                            'Enumerate system for privilege escalation vectors',
                            'Identify vulnerable services or configurations',
                            'Use {function_name} to execute escalation exploit',
                            'Gain elevated system privileges'
                        ],
                        'impact': 'Administrative access to system',
                        'detection_methods': ['Privilege change monitoring', 'Command auditing'],
                        'example_payload': 'sudo exploit or SUID binary abuse',
                        'cvss_vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    },
                    {
                        'name': 'System Information Gathering',
                        'technique': 'Collect system information for further attacks',
                        'prerequisites': ['Command execution capability'],
                        'steps': [
                            'Use {function_name} to execute system enumeration commands',
                            'Collect system configuration information',
                            'Identify installed software and versions',
                            'Plan targeted attacks based on findings'
                        ],
                        'impact': 'Intelligence gathering for targeted attacks',
                        'detection_methods': ['Command monitoring', 'System call analysis'],
                        'example_payload': 'uname -a, ps aux, netstat -an',
                        'cvss_vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'
                    },
                    {
                        'name': 'Persistence Establishment',
                        'technique': 'Establish persistent access using system commands',
                        'prerequisites': ['Command execution capability', 'Write access to system directories'],
                        'steps': [
                            'Identify persistence mechanisms',
                            'Use {function_name} to create persistent backdoor',
                            'Configure backdoor to survive reboots',
                            'Test persistent access'
                        ],
                        'impact': 'Long-term system compromise',
                        'detection_methods': ['Startup process monitoring', 'File system monitoring'],
                        'example_payload': 'Cron job or systemd service creation',
                        'cvss_vector': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'
                    }
                ]
            }
        }
    
    def generate_attack_vectors(self, 
                              tool_capabilities: ToolCapabilities,
                              environment_context: EnvironmentContext,
                              max_vectors: int = 10) -> List[Dict[str, Any]]:
        """
        Generate attack vectors based on tool capabilities and environment.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            environment_context: Environment context for targeted generation
            max_vectors: Maximum number of vectors to generate
            
        Returns:
            List of generated attack vectors with detailed information
        """
        attack_vectors = []
        
        try:
            self.logger.info(f"Generating attack vectors for {len(tool_capabilities.tool_functions)} functions")
            
            # Analyze functions for attack vector generation
            for func in tool_capabilities.tool_functions:
                risk_indicators = self._get_function_risk_indicators(func.name)
                
                for indicator in risk_indicators:
                    if indicator in self.attack_templates:
                        # Generate vectors for this indicator
                        generated_vectors = self._generate_vectors_for_indicator(
                            func, indicator, environment_context
                        )
                        attack_vectors.extend(generated_vectors)
                        
                        if len(attack_vectors) >= max_vectors:
                            break
                
                if len(attack_vectors) >= max_vectors:
                    break
            
            # Sort by severity and select top vectors
            attack_vectors = self._prioritize_attack_vectors(attack_vectors, environment_context)
            self.logger.info(f"Generated {len(attack_vectors)} attack vectors")
            return attack_vectors[:max_vectors]
            
        except Exception as e:
            self.logger.error(f"Error generating attack vectors: {e}")
            return []
    
    def _get_function_risk_indicators(self, function_name: str) -> List[str]:
        """Extract risk indicators from function name."""
        indicators = []
        function_lower = function_name.lower()
        
        # Map function patterns to risk indicators
        risk_patterns = {
            'write': 'file_write',
            'create': 'file_write',
            'save': 'file_write',
            'exec': 'code_execution',
            'eval': 'code_execution',
            'run': 'code_execution',
            'execute': 'code_execution',
            'command': 'system_command',
            'shell': 'system_command',
            'terminal': 'system_command',
            'bash': 'system_command',
            'http': 'network_access',
            'url': 'network_access',
            'api': 'network_access',
            'request': 'network_access',
            'fetch': 'network_access',
            'sql': 'database_access',
            'query': 'database_access',
            'database': 'database_access',
            'db': 'database_access'
        }
        
        for pattern, indicator in risk_patterns.items():
            if pattern in function_lower:
                indicators.append(indicator)
        
        return indicators
    
    def _generate_vectors_for_indicator(self, 
                                     func: ToolFunction,
                                     indicator: str,
                                     environment_context: EnvironmentContext) -> List[Dict[str, Any]]:
        """Generate specific attack vectors for a risk indicator."""
        vectors = []
        
        if indicator not in self.attack_templates:
            return vectors
        
        template = self.attack_templates[indicator]
        base_vector = template['base_vector']
        
        # Generate vectors from template variations
        for variation in template['variations']:
            vector = {
                'id': f"{func.name}_{indicator}_{variation['name'].lower().replace(' ', '_')}",
                'name': variation['name'],
                'function_name': func.name,
                'category': base_vector['category'],
                'severity': self._calculate_vector_severity(variation, environment_context),
                'description': variation['description'].replace('{function_name}', func.name),
                'technique': variation['technique'],
                'prerequisites': variation['prerequisites'],
                'attack_steps': [step.replace('{function_name}', func.name) for step in variation['steps']],
                'impact': variation['impact'],
                'detection_methods': variation['detection_methods'],
                'example_payload': variation.get('example_payload', 'N/A'),
                'cvss_vector': variation.get('cvss_vector', 'N/A'),
                'likelihood': self._calculate_likelihood(variation, environment_context),
                'exploitability': self._calculate_exploitability(func, variation),
                'mitigations': self._generate_mitigations(variation, func),
                'environment_factors': self._analyze_environment_factors(variation, environment_context),
                'confidence': 0.8  # Default confidence for generated vectors
            }
            vectors.append(vector)
        
        return vectors
    
    def _calculate_vector_severity(self, variation: Dict[str, Any], environment_context: EnvironmentContext) -> str:
        """Calculate dynamic severity based on variation and environment."""
        base_severity = 'medium'
        
        # Increase severity based on impact keywords
        impact_keywords = {
            'complete': 'critical',
            'compromise': 'critical', 
            'execution': 'high',
            'privilege': 'high',
            'access': 'high',
            'data': 'medium'
        }
        
        impact_lower = variation['impact'].lower()
        for keyword, severity in impact_keywords.items():
            if keyword in impact_lower:
                base_severity = severity
                break
        
        # Adjust based on environment
        if environment_context.deployment_type in [DeploymentType.PRODUCTION, DeploymentType.CLOUD]:
            severity_levels = ['low', 'medium', 'high', 'critical']
            current_index = severity_levels.index(base_severity)
            if current_index < len(severity_levels) - 1:
                base_severity = severity_levels[current_index + 1]
        
        return base_severity
    
    def _calculate_likelihood(self, variation: Dict[str, Any], environment_context: EnvironmentContext) -> float:
        """Calculate attack likelihood based on prerequisites and environment."""
        base_likelihood = 0.5
        
        # Reduce likelihood based on prerequisites complexity
        num_prerequisites = len(variation['prerequisites'])
        if num_prerequisites > 3:
            base_likelihood *= 0.7
        elif num_prerequisites > 1:
            base_likelihood *= 0.85
        
        # Adjust based on environment security posture
        if environment_context.security_posture == SecurityPosture.HIGH:
            base_likelihood *= 0.6
        elif environment_context.security_posture == SecurityPosture.LOW:
            base_likelihood *= 1.4
        
        # Adjust based on network exposure
        if environment_context.network_exposure == NetworkExposure.INTERNET:
            base_likelihood *= 1.3
        elif environment_context.network_exposure == NetworkExposure.INTERNAL:
            base_likelihood *= 0.8
        
        return min(base_likelihood, 1.0)
    
    def _calculate_exploitability(self, func: ToolFunction, variation: Dict[str, Any]) -> str:
        """Calculate how easily the attack vector can be exploited."""
        # Simple heuristic based on prerequisites and technique complexity
        num_prerequisites = len(variation['prerequisites'])
        technique_complexity_keywords = ['injection', 'deserialization', 'template']
        
        if num_prerequisites <= 1:
            return 'high'
        elif num_prerequisites <= 2 and not any(keyword in variation['technique'].lower() 
                                              for keyword in technique_complexity_keywords):
            return 'medium'
        else:
            return 'low'
    
    def _generate_mitigations(self, variation: Dict[str, Any], func: ToolFunction) -> List[Dict[str, Any]]:
        """Generate mitigation strategies for the attack vector."""
        mitigations = []
        
        # Base mitigations
        mitigations.append({
            'type': 'Input Validation',
            'description': f'Implement strict input validation for {func.name}',
            'implementation': 'Validate and sanitize all parameters',
            'effectiveness': 'high'
        })
        
        # Technique-specific mitigations
        technique_lower = variation['technique'].lower()
        
        if 'injection' in technique_lower:
            mitigations.append({
                'type': 'Injection Prevention',
                'description': 'Prevent injection attacks',
                'implementation': 'Use parameterized queries, escape special characters',
                'effectiveness': 'high'
            })
        
        if 'privilege' in technique_lower:
            mitigations.append({
                'type': 'Privilege Restriction',
                'description': 'Limit function privileges',
                'implementation': 'Run with minimal privileges, use sandboxing',
                'effectiveness': 'medium'
            })
        
        if 'network' in technique_lower:
            mitigations.append({
                'type': 'Network Controls',
                'description': 'Restrict network access',
                'implementation': 'Use firewall rules, network segmentation',
                'effectiveness': 'medium'
            })
        
        return mitigations
    
    def _analyze_environment_factors(self, variation: Dict[str, Any], environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Analyze how environment factors affect the attack vector."""
        factors = {
            'deployment_impact': 'neutral',
            'security_impact': 'neutral',
            'network_impact': 'neutral',
            'compliance_impact': 'neutral'
        }
        
        # Deployment type impact
        if environment_context.deployment_type == DeploymentType.PRODUCTION:
            factors['deployment_impact'] = 'increases_risk'
        elif environment_context.deployment_type == DeploymentType.DEVELOPMENT:
            factors['deployment_impact'] = 'decreases_risk'
        
        # Security posture impact
        if environment_context.security_posture == SecurityPosture.LOW:
            factors['security_impact'] = 'increases_risk'
        elif environment_context.security_posture == SecurityPosture.HIGH:
            factors['security_impact'] = 'decreases_risk'
        
        # Network exposure impact
        if environment_context.network_exposure == NetworkExposure.INTERNET:
            factors['network_impact'] = 'increases_risk'
        elif environment_context.network_exposure == NetworkExposure.ISOLATED:
            factors['network_impact'] = 'decreases_risk'
        
        return factors
    
    def _prioritize_attack_vectors(self, vectors: List[Dict[str, Any]], environment_context: EnvironmentContext) -> List[Dict[str, Any]]:
        """Prioritize attack vectors based on severity, likelihood, and environment."""
        severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        def calculate_priority_score(vector):
            severity_score = severity_weights.get(vector['severity'], 1)
            likelihood_score = vector['likelihood']
            exploitability_score = {'high': 3, 'medium': 2, 'low': 1}.get(vector['exploitability'], 1)
            
            return severity_score * likelihood_score * exploitability_score
        
        return sorted(vectors, key=calculate_priority_score, reverse=True)
    
    def generate_vector_summary(self, vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of generated attack vectors."""
        if not vectors:
            return {
                'total_vectors': 0,
                'severity_distribution': {},
                'category_distribution': {},
                'top_categories': [],
                'average_likelihood': 0.0
            }
        
        # Count distributions
        severity_dist = {}
        category_dist = {}
        total_likelihood = 0.0
        
        for vector in vectors:
            # Severity distribution
            severity = vector['severity']
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
            
            # Category distribution
            category = vector['category']
            category_dist[category] = category_dist.get(category, 0) + 1
            
            # Likelihood sum
            total_likelihood += vector['likelihood']
        
        # Top categories
        top_categories = sorted(category_dist.items(), key=lambda x: x[1], reverse=True)[:3]
        
        return {
            'total_vectors': len(vectors),
            'severity_distribution': severity_dist,
            'category_distribution': category_dist,
            'top_categories': [cat[0] for cat in top_categories],
            'average_likelihood': total_likelihood / len(vectors) if vectors else 0.0
        } 