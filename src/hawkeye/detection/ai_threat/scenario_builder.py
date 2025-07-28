"""
Scenario Builder

This module provides realistic abuse scenario generation for threat analysis reports.
It creates detailed attack scenarios based on discovered MCP tool capabilities and
different threat actor profiles.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from .models import (
    ToolCapabilities, ToolFunction, EnvironmentContext, 
    DeploymentType, SecurityPosture, NetworkExposure, ComplianceFramework
)


logger = logging.getLogger(__name__)


class ThreatActorType(Enum):
    """Types of threat actors for scenario generation."""
    INSIDER_THREAT = "insider_threat"
    EXTERNAL_ATTACKER = "external_attacker"
    SUPPLY_CHAIN = "supply_chain"
    NATION_STATE = "nation_state"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"


@dataclass
class ThreatActorProfile:
    """Profile of a threat actor with capabilities and motivations."""
    name: str
    type: ThreatActorType
    skill_level: str  # basic, intermediate, advanced, expert
    resources: str    # limited, moderate, extensive, unlimited
    motivation: str
    typical_objectives: List[str]
    common_techniques: List[str]
    time_horizon: str  # minutes, hours, days, weeks, months
    stealth_requirement: str  # low, medium, high, critical


class ScenarioBuilder:
    """
    Enhanced scenario builder for creating realistic abuse scenarios
    based on discovered MCP tool capabilities and threat actor profiles.
    
    This class generates detailed attack scenarios that help security teams
    understand how different types of attackers might abuse MCP tools.
    """
    
    def __init__(self):
        """Initialize the scenario builder."""
        self.logger = logging.getLogger(__name__)
        
        # Threat actor profiles
        self.threat_actors = {
            ThreatActorType.INSIDER_THREAT: ThreatActorProfile(
                name="Malicious Insider",
                type=ThreatActorType.INSIDER_THREAT,
                skill_level="intermediate",
                resources="moderate",
                motivation="Financial gain, revenge, espionage",
                typical_objectives=[
                    "Data theft", "Sabotage", "Fraud", "Competitive intelligence"
                ],
                common_techniques=[
                    "Privilege abuse", "Data exfiltration", "System sabotage",
                    "Credential theft", "Process manipulation"
                ],
                time_horizon="days",
                stealth_requirement="high"
            ),
            
            ThreatActorType.EXTERNAL_ATTACKER: ThreatActorProfile(
                name="External Cybercriminal",
                type=ThreatActorType.EXTERNAL_ATTACKER,
                skill_level="intermediate",
                resources="moderate",
                motivation="Financial gain, data theft",
                typical_objectives=[
                    "Ransomware deployment", "Data theft", "Credential harvesting",
                    "System compromise", "Cryptocurrency mining"
                ],
                common_techniques=[
                    "Exploitation", "Social engineering", "Malware deployment",
                    "Network infiltration", "Persistence mechanisms"
                ],
                time_horizon="hours",
                stealth_requirement="medium"
            ),
            
            ThreatActorType.SUPPLY_CHAIN: ThreatActorProfile(
                name="Supply Chain Attacker",
                type=ThreatActorType.SUPPLY_CHAIN,
                skill_level="advanced",
                resources="extensive",
                motivation="Espionage, widespread access",
                typical_objectives=[
                    "Backdoor insertion", "Mass surveillance", "Intellectual property theft",
                    "Strategic positioning", "Long-term access"
                ],
                common_techniques=[
                    "Code injection", "Update mechanism abuse", "Certificate compromise",
                    "Build system tampering", "Distribution network infiltration"
                ],
                time_horizon="months",
                stealth_requirement="critical"
            ),
            
            ThreatActorType.NATION_STATE: ThreatActorProfile(
                name="Advanced Persistent Threat",
                type=ThreatActorType.NATION_STATE,
                skill_level="expert",
                resources="unlimited",
                motivation="Espionage, disruption, intelligence gathering",
                typical_objectives=[
                    "Strategic intelligence", "Critical infrastructure disruption",
                    "Economic espionage", "Military intelligence", "Diplomatic advantage"
                ],
                common_techniques=[
                    "Zero-day exploitation", "Living off the land", "Supply chain attacks",
                    "Advanced persistent access", "Counter-forensics"
                ],
                time_horizon="months",
                stealth_requirement="critical"
            ),
            
            ThreatActorType.CYBERCRIMINAL: ThreatActorProfile(
                name="Organized Cybercrime",
                type=ThreatActorType.CYBERCRIMINAL,
                skill_level="advanced",
                resources="extensive",
                motivation="Financial gain, extortion",
                typical_objectives=[
                    "Ransomware operations", "Banking fraud", "Cryptocurrency theft",
                    "Identity theft", "Extortion schemes"
                ],
                common_techniques=[
                    "Ransomware deployment", "Banking trojans", "Credential stuffing",
                    "Business email compromise", "Crypto-jacking"
                ],
                time_horizon="days",
                stealth_requirement="medium"
            ),
            
            ThreatActorType.HACKTIVIST: ThreatActorProfile(
                name="Hacktivist Group",
                type=ThreatActorType.HACKTIVIST,
                skill_level="intermediate",
                resources="limited",
                motivation="Political activism, social justice",
                typical_objectives=[
                    "Website defacement", "Data leaks", "Service disruption",
                    "Public embarrassment", "Political messaging"
                ],
                common_techniques=[
                    "DDoS attacks", "Website defacement", "Data dumps",
                    "Social media campaigns", "Public shaming"
                ],
                time_horizon="hours",
                stealth_requirement="low"
            )
        }
        
        # Scenario templates organized by attack type
        self.scenario_templates = {
            'data_exfiltration': {
                'title': 'Sensitive Data Exfiltration',
                'description': 'Unauthorized extraction of sensitive data using MCP tools',
                'phases': ['reconnaissance', 'access', 'collection', 'exfiltration', 'cleanup'],
                'indicators': [
                    'Unusual data access patterns',
                    'Large data transfers',
                    'Access to sensitive files',
                    'External network connections'
                ]
            },
            'system_compromise': {
                'title': 'System Compromise and Control',
                'description': 'Complete compromise of target system using MCP capabilities',
                'phases': ['reconnaissance', 'exploitation', 'persistence', 'privilege_escalation', 'control'],
                'indicators': [
                    'Unusual process execution',
                    'New user accounts or services',
                    'Modified system configurations',
                    'Suspicious network traffic'
                ]
            },
            'sabotage': {
                'title': 'System Sabotage and Disruption',
                'description': 'Intentional disruption or destruction of system operations',
                'phases': ['reconnaissance', 'access', 'sabotage', 'destruction', 'cover_up'],
                'indicators': [
                    'System performance degradation',
                    'File deletions or corruption',
                    'Service disruptions',
                    'Configuration changes'
                ]
            },
            'espionage': {
                'title': 'Corporate Espionage',
                'description': 'Long-term intelligence gathering and surveillance',
                'phases': ['reconnaissance', 'infiltration', 'persistence', 'surveillance', 'intelligence_gathering'],
                'indicators': [
                    'Stealthy data access',
                    'Monitoring tool deployment',
                    'Communication interception',
                    'Long-term presence'
                ]
            }
        }
    
    def build_abuse_scenarios(self,
                            tool_capabilities: ToolCapabilities,
                            environment_context: EnvironmentContext,
                            threat_actors: Optional[List[ThreatActorType]] = None,
                            max_scenarios: int = 5) -> List[Dict[str, Any]]:
        """
        Build realistic abuse scenarios based on tool capabilities and threat actors.
        
        Args:
            tool_capabilities: Tool capabilities to analyze
            environment_context: Environment context for scenario customization
            threat_actors: Specific threat actors to focus on (default: all)
            max_scenarios: Maximum number of scenarios to generate
            
        Returns:
            List of detailed abuse scenarios
        """
        scenarios = []
        
        try:
            # Default to all threat actors if none specified
            if threat_actors is None:
                threat_actors = list(ThreatActorType)
            
            self.logger.info(f"Building abuse scenarios for {len(threat_actors)} threat actor types")
            
            # Generate scenarios for each threat actor
            for actor_type in threat_actors[:max_scenarios]:
                actor_profile = self.threat_actors[actor_type]
                
                # Find the most suitable scenario template
                scenario_template = self._select_scenario_template(
                    tool_capabilities, actor_profile, environment_context
                )
                
                if scenario_template:
                    scenario = self._build_detailed_scenario(
                        tool_capabilities, actor_profile, scenario_template, environment_context
                    )
                    scenarios.append(scenario)
            
            # Sort scenarios by risk level
            scenarios = self._prioritize_scenarios(scenarios)
            self.logger.info(f"Generated {len(scenarios)} abuse scenarios")
            
            return scenarios
            
        except Exception as e:
            self.logger.error(f"Error building abuse scenarios: {e}")
            return []
    
    def _select_scenario_template(self,
                                tool_capabilities: ToolCapabilities,
                                actor_profile: ThreatActorProfile,
                                environment_context: EnvironmentContext) -> Optional[Dict[str, Any]]:
        """Select the most appropriate scenario template for the threat actor and capabilities."""
        
        # Analyze tool capabilities to determine scenario type
        capability_categories = tool_capabilities.capability_categories
        
        # Score each scenario template based on capability match and actor profile
        template_scores = {}
        
        for template_name, template in self.scenario_templates.items():
            score = 0
            
            # Score based on capability categories
            if 'FILE_SYSTEM' in [cat.name for cat in capability_categories]:
                if template_name in ['data_exfiltration', 'sabotage']:
                    score += 3
                elif template_name in ['system_compromise']:
                    score += 2
            
            if 'NETWORK_ACCESS' in [cat.name for cat in capability_categories]:
                if template_name in ['data_exfiltration', 'espionage']:
                    score += 3
                elif template_name in ['system_compromise']:
                    score += 2
            
            if 'CODE_EXECUTION' in [cat.name for cat in capability_categories]:
                if template_name in ['system_compromise', 'sabotage']:
                    score += 4
                elif template_name in ['data_exfiltration']:
                    score += 2
            
            # Score based on actor profile
            if actor_profile.type == ThreatActorType.INSIDER_THREAT:
                if template_name == 'data_exfiltration':
                    score += 3
                elif template_name == 'sabotage':
                    score += 2
            
            elif actor_profile.type == ThreatActorType.EXTERNAL_ATTACKER:
                if template_name == 'system_compromise':
                    score += 3
                elif template_name == 'data_exfiltration':
                    score += 2
            
            elif actor_profile.type == ThreatActorType.NATION_STATE:
                if template_name == 'espionage':
                    score += 4
                elif template_name == 'system_compromise':
                    score += 3
            
            template_scores[template_name] = score
        
        # Select the highest scoring template
        if template_scores:
            best_template = max(template_scores, key=template_scores.get)
            if template_scores[best_template] > 0:
                return {**self.scenario_templates[best_template], 'name': best_template}
        
        return None
    
    def _build_detailed_scenario(self,
                               tool_capabilities: ToolCapabilities,
                               actor_profile: ThreatActorProfile,
                               scenario_template: Dict[str, Any],
                               environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Build a detailed scenario from template and context."""
        
        scenario = {
            'id': f"{actor_profile.type.value}_{scenario_template['name']}",
            'title': f"{actor_profile.name}: {scenario_template['title']}",
            'description': scenario_template['description'],
            'threat_actor': {
                'name': actor_profile.name,
                'type': actor_profile.type.value,
                'skill_level': actor_profile.skill_level,
                'motivation': actor_profile.motivation,
                'resources': actor_profile.resources
            },
            'scenario_type': scenario_template['name'],
            'risk_level': self._calculate_scenario_risk(actor_profile, tool_capabilities, environment_context),
            'likelihood': self._calculate_scenario_likelihood(actor_profile, environment_context),
            'timeline': self._generate_timeline(scenario_template, actor_profile),
            'attack_phases': self._generate_attack_phases(
                scenario_template, tool_capabilities, actor_profile, environment_context
            ),
            'objectives': self._generate_objectives(actor_profile, tool_capabilities),
            'techniques_used': self._map_techniques_to_capabilities(actor_profile, tool_capabilities),
            'indicators_of_compromise': self._generate_iocs(scenario_template, tool_capabilities),
            'business_impact': self._assess_business_impact(scenario_template, environment_context),
            'detection_opportunities': self._identify_detection_opportunities(scenario_template, tool_capabilities),
            'mitigation_strategies': self._generate_mitigation_strategies(scenario_template, tool_capabilities),
            'lessons_learned': self._generate_lessons_learned(scenario_template, actor_profile)
        }
        
        return scenario
    
    def _calculate_scenario_risk(self,
                               actor_profile: ThreatActorProfile,
                               tool_capabilities: ToolCapabilities,
                               environment_context: EnvironmentContext) -> str:
        """Calculate overall risk level for the scenario."""
        risk_score = 0
        
        # Actor capability score
        skill_weights = {'basic': 1, 'intermediate': 2, 'advanced': 3, 'expert': 4}
        risk_score += skill_weights.get(actor_profile.skill_level, 2)
        
        resource_weights = {'limited': 1, 'moderate': 2, 'extensive': 3, 'unlimited': 4}
        risk_score += resource_weights.get(actor_profile.resources, 2)
        
        # Tool capability score
        risk_score += len(tool_capabilities.risk_indicators) * 0.5
        
        # Environment factors
        if environment_context.deployment_type == DeploymentType.PRODUCTION:
            risk_score += 2
        if environment_context.security_posture == SecurityPosture.LOW:
            risk_score += 2
        if environment_context.network_exposure == NetworkExposure.INTERNET:
            risk_score += 1
        
        # Convert to risk level
        if risk_score >= 8:
            return 'critical'
        elif risk_score >= 6:
            return 'high'
        elif risk_score >= 4:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_scenario_likelihood(self,
                                     actor_profile: ThreatActorProfile,
                                     environment_context: EnvironmentContext) -> float:
        """Calculate likelihood of scenario occurrence."""
        base_likelihood = 0.3  # Base 30% likelihood
        
        # Adjust based on actor type prevalence
        actor_likelihood_modifiers = {
            ThreatActorType.INSIDER_THREAT: 1.5,
            ThreatActorType.EXTERNAL_ATTACKER: 1.3,
            ThreatActorType.CYBERCRIMINAL: 1.2,
            ThreatActorType.HACKTIVIST: 0.8,
            ThreatActorType.SUPPLY_CHAIN: 0.5,
            ThreatActorType.NATION_STATE: 0.3
        }
        
        base_likelihood *= actor_likelihood_modifiers.get(actor_profile.type, 1.0)
        
        # Adjust based on environment
        if environment_context.security_posture == SecurityPosture.LOW:
            base_likelihood *= 1.4
        elif environment_context.security_posture == SecurityPosture.HIGH:
            base_likelihood *= 0.7
        
        if environment_context.network_exposure == NetworkExposure.INTERNET:
            base_likelihood *= 1.2
        
        return min(base_likelihood, 1.0)
    
    def _generate_timeline(self,
                         scenario_template: Dict[str, Any],
                         actor_profile: ThreatActorProfile) -> Dict[str, Any]:
        """Generate realistic timeline for the scenario."""
        time_horizons = {
            'minutes': {'total_duration': '15-30 minutes', 'phase_duration': '3-5 minutes'},
            'hours': {'total_duration': '2-8 hours', 'phase_duration': '30-90 minutes'},
            'days': {'total_duration': '3-14 days', 'phase_duration': '4-24 hours'},
            'weeks': {'total_duration': '2-8 weeks', 'phase_duration': '3-7 days'},
            'months': {'total_duration': '3-12 months', 'phase_duration': '2-4 weeks'}
        }
        
        time_info = time_horizons.get(actor_profile.time_horizon, time_horizons['hours'])
        
        return {
            'total_duration': time_info['total_duration'],
            'phase_duration': time_info['phase_duration'],
            'time_horizon': actor_profile.time_horizon,
            'stealth_requirement': actor_profile.stealth_requirement,
            'phases': len(scenario_template['phases'])
        }
    
    def _generate_attack_phases(self,
                              scenario_template: Dict[str, Any],
                              tool_capabilities: ToolCapabilities,
                              actor_profile: ThreatActorProfile,
                              environment_context: EnvironmentContext) -> List[Dict[str, Any]]:
        """Generate detailed attack phases for the scenario."""
        phases = []
        
        phase_definitions = {
            'reconnaissance': {
                'name': 'Reconnaissance',
                'description': 'Gather information about target and capabilities',
                'objectives': ['Identify MCP servers', 'Enumerate functions', 'Assess security']
            },
            'access': {
                'name': 'Initial Access',
                'description': 'Gain access to MCP server or hosting system',
                'objectives': ['Exploit vulnerabilities', 'Use credentials', 'Social engineering']
            },
            'exploitation': {
                'name': 'Exploitation',
                'description': 'Exploit discovered vulnerabilities',
                'objectives': ['Execute exploits', 'Bypass security', 'Gain foothold']
            },
            'persistence': {
                'name': 'Persistence',
                'description': 'Establish persistent access to the system',
                'objectives': ['Create backdoors', 'Modify configurations', 'Install implants']
            },
            'privilege_escalation': {
                'name': 'Privilege Escalation',
                'description': 'Escalate privileges for broader access',
                'objectives': ['Exploit local vulnerabilities', 'Abuse misconfigurations', 'Steal credentials']
            },
            'collection': {
                'name': 'Data Collection',
                'description': 'Collect sensitive data and intelligence',
                'objectives': ['Identify sensitive data', 'Access databases', 'Collect files']
            },
            'exfiltration': {
                'name': 'Data Exfiltration',
                'description': 'Extract collected data from the target',
                'objectives': ['Compress data', 'Establish channels', 'Transfer data']
            },
            'sabotage': {
                'name': 'Sabotage',
                'description': 'Disrupt or destroy target systems',
                'objectives': ['Delete files', 'Corrupt data', 'Disable services']
            },
            'surveillance': {
                'name': 'Surveillance',
                'description': 'Monitor target activities and communications',
                'objectives': ['Install monitoring', 'Intercept communications', 'Track activities']
            },
            'intelligence_gathering': {
                'name': 'Intelligence Gathering',
                'description': 'Collect strategic intelligence over time',
                'objectives': ['Monitor communications', 'Track personnel', 'Gather business intelligence']
            },
            'control': {
                'name': 'System Control',
                'description': 'Maintain control over compromised systems',
                'objectives': ['Remote administration', 'Command execution', 'System manipulation']
            },
            'cleanup': {
                'name': 'Cleanup',
                'description': 'Remove traces of malicious activity',
                'objectives': ['Delete logs', 'Remove tools', 'Cover tracks']
            },
            'infiltration': {
                'name': 'Infiltration',
                'description': 'Penetrate deeper into the target network',
                'objectives': ['Lateral movement', 'Network exploration', 'Asset discovery']
            },
            'destruction': {
                'name': 'Destruction',
                'description': 'Destroy or permanently damage target systems',
                'objectives': ['Delete critical data', 'Corrupt systems', 'Physical damage']
            },
            'cover_up': {
                'name': 'Cover Up',
                'description': 'Hide evidence of malicious activities',
                'objectives': ['Modify logs', 'Plant false evidence', 'Misdirect investigation']
            }
        }
        
        for i, phase_name in enumerate(scenario_template['phases']):
            if phase_name in phase_definitions:
                phase_def = phase_definitions[phase_name]
                
                phase = {
                    'phase_number': i + 1,
                    'name': phase_def['name'],
                    'description': phase_def['description'],
                    'objectives': phase_def['objectives'],
                    'tools_used': self._identify_tools_for_phase(phase_name, tool_capabilities),
                    'techniques': self._get_techniques_for_phase(phase_name, actor_profile),
                    'duration': self._estimate_phase_duration(phase_name, actor_profile),
                    'success_indicators': self._define_success_indicators(phase_name),
                    'detection_risk': self._assess_detection_risk(phase_name, actor_profile, environment_context)
                }
                phases.append(phase)
        
        return phases
    
    def _generate_objectives(self,
                           actor_profile: ThreatActorProfile,
                           tool_capabilities: ToolCapabilities) -> List[str]:
        """Generate specific objectives for the threat actor."""
        objectives = actor_profile.typical_objectives.copy()
        
        # Add capability-specific objectives
        capability_categories = [cat.name for cat in tool_capabilities.capability_categories]
        
        if 'FILE_SYSTEM' in capability_categories:
            objectives.extend(['Access sensitive files', 'Modify system configurations'])
        if 'NETWORK_ACCESS' in capability_categories:
            objectives.extend(['Network reconnaissance', 'Data exfiltration'])
        if 'CODE_EXECUTION' in capability_categories:
            objectives.extend(['Remote code execution', 'System compromise'])
        if 'DATABASE_ACCESS' in capability_categories:
            objectives.extend(['Database compromise', 'Sensitive data theft'])
        
        return list(set(objectives))  # Remove duplicates
    
    def _map_techniques_to_capabilities(self,
                                      actor_profile: ThreatActorProfile,
                                      tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Map threat actor techniques to specific tool capabilities."""
        techniques = []
        
        for technique in actor_profile.common_techniques:
            # Find matching tool functions
            matching_functions = []
            for func in tool_capabilities.tool_functions:
                if self._technique_matches_function(technique, func):
                    matching_functions.append(func.name)
            
            if matching_functions:
                techniques.append({
                    'technique': technique,
                    'applicable_functions': matching_functions,
                    'description': f"Use {', '.join(matching_functions)} for {technique.lower()}"
                })
        
        return techniques
    
    def _technique_matches_function(self, technique: str, func: ToolFunction) -> bool:
        """Check if a technique matches a function capability."""
        technique_lower = technique.lower()
        func_name_lower = func.name.lower()
        
        # Define technique-to-function mappings
        technique_patterns = {
            'privilege abuse': ['admin', 'sudo', 'root', 'privilege'],
            'data exfiltration': ['read', 'download', 'export', 'backup'],
            'system sabotage': ['delete', 'remove', 'kill', 'stop'],
            'credential theft': ['auth', 'login', 'password', 'token'],
            'exploitation': ['exec', 'eval', 'run', 'command'],
            'malware deployment': ['write', 'create', 'upload', 'install'],
            'network infiltration': ['connect', 'http', 'api', 'network'],
            'persistence mechanisms': ['service', 'startup', 'cron', 'scheduled']
        }
        
        for pattern_technique, patterns in technique_patterns.items():
            if pattern_technique in technique_lower:
                return any(pattern in func_name_lower for pattern in patterns)
        
        return False
    
    def _generate_iocs(self,
                      scenario_template: Dict[str, Any],
                      tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Generate indicators of compromise for the scenario."""
        iocs = []
        
        # Base IOCs from template
        for indicator in scenario_template['indicators']:
            iocs.append({
                'type': 'behavioral',
                'indicator': indicator,
                'description': f"Monitor for {indicator.lower()}",
                'detection_method': 'behavioral_analysis'
            })
        
        # Function-specific IOCs
        for func in tool_capabilities.tool_functions:
            func_name = func.name.lower()
            
            if 'exec' in func_name or 'command' in func_name:
                iocs.append({
                    'type': 'process',
                    'indicator': f"Unusual process execution via {func.name}",
                    'description': f"Monitor for unexpected process creation from {func.name}",
                    'detection_method': 'process_monitoring'
                })
            
            if 'write' in func_name or 'create' in func_name:
                iocs.append({
                    'type': 'file',
                    'indicator': f"Suspicious file operations via {func.name}",
                    'description': f"Monitor for unusual file creation/modification from {func.name}",
                    'detection_method': 'file_integrity_monitoring'
                })
            
            if 'http' in func_name or 'api' in func_name:
                iocs.append({
                    'type': 'network',
                    'indicator': f"Unusual network activity via {func.name}",
                    'description': f"Monitor for suspicious network connections from {func.name}",
                    'detection_method': 'network_monitoring'
                })
        
        return iocs
    
    def _assess_business_impact(self,
                              scenario_template: Dict[str, Any],
                              environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Assess potential business impact of the scenario."""
        impact = {
            'financial': 'medium',
            'operational': 'medium',
            'reputational': 'medium',
            'regulatory': 'low',
            'estimated_cost': 'Unknown'
        }
        
        # Adjust based on scenario type
        scenario_name = scenario_template['name']
        
        if scenario_name == 'data_exfiltration':
            impact['financial'] = 'high'
            impact['reputational'] = 'high'
            impact['regulatory'] = 'high'
            impact['estimated_cost'] = '$100K - $1M+'
        
        elif scenario_name == 'system_compromise':
            impact['financial'] = 'high'
            impact['operational'] = 'high'
            impact['estimated_cost'] = '$50K - $500K'
        
        elif scenario_name == 'sabotage':
            impact['operational'] = 'critical'
            impact['financial'] = 'high'
            impact['estimated_cost'] = '$200K - $2M+'
        
        elif scenario_name == 'espionage':
            impact['reputational'] = 'high'
            impact['regulatory'] = 'medium'
            impact['estimated_cost'] = '$500K - $5M+'
        
        # Adjust based on environment
        if environment_context.deployment_type == DeploymentType.PRODUCTION:
            # Increase all impacts for production
            impact_levels = ['low', 'medium', 'high', 'critical']
            for key in ['financial', 'operational', 'reputational']:
                current_level = impact[key]
                if current_level in impact_levels:
                    current_index = impact_levels.index(current_level)
                    if current_index < len(impact_levels) - 1:
                        impact[key] = impact_levels[current_index + 1]
        
        return impact
    
    def _identify_detection_opportunities(self,
                                        scenario_template: Dict[str, Any],
                                        tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Identify opportunities for detecting the attack scenario."""
        opportunities = []
        
        # Phase-based detection opportunities
        for phase in scenario_template['phases']:
            if phase == 'reconnaissance':
                opportunities.append({
                    'phase': phase,
                    'opportunity': 'Unusual information gathering',
                    'detection_method': 'Behavioral analysis of MCP function calls',
                    'effectiveness': 'medium'
                })
            
            elif phase == 'exploitation':
                opportunities.append({
                    'phase': phase,
                    'opportunity': 'Exploitation attempts',
                    'detection_method': 'Input validation monitoring and anomaly detection',
                    'effectiveness': 'high'
                })
            
            elif phase == 'persistence':
                opportunities.append({
                    'phase': phase,
                    'opportunity': 'Persistence establishment',
                    'detection_method': 'Configuration change monitoring',
                    'effectiveness': 'high'
                })
        
        # Function-specific detection opportunities
        for func in tool_capabilities.tool_functions:
            func_name = func.name.lower()
            
            if any(pattern in func_name for pattern in ['exec', 'command', 'shell']):
                opportunities.append({
                    'phase': 'execution',
                    'opportunity': f'Code execution via {func.name}',
                    'detection_method': 'Process execution monitoring and command line analysis',
                    'effectiveness': 'high'
                })
        
        return opportunities
    
    def _generate_mitigation_strategies(self,
                                      scenario_template: Dict[str, Any],
                                      tool_capabilities: ToolCapabilities) -> List[Dict[str, Any]]:
        """Generate mitigation strategies for the scenario."""
        mitigations = []
        
        # General mitigations
        mitigations.extend([
            {
                'category': 'access_control',
                'strategy': 'Implement strong authentication',
                'description': 'Require multi-factor authentication for MCP server access',
                'effectiveness': 'high',
                'implementation_effort': 'medium'
            },
            {
                'category': 'monitoring',
                'strategy': 'Deploy comprehensive monitoring',
                'description': 'Monitor all MCP function calls and system activities',
                'effectiveness': 'high',
                'implementation_effort': 'high'
            },
            {
                'category': 'network_security',
                'strategy': 'Network segmentation',
                'description': 'Isolate MCP servers in secure network segments',
                'effectiveness': 'medium',
                'implementation_effort': 'high'
            }
        ])
        
        # Scenario-specific mitigations
        scenario_name = scenario_template['name']
        
        if scenario_name == 'data_exfiltration':
            mitigations.append({
                'category': 'data_protection',
                'strategy': 'Data Loss Prevention (DLP)',
                'description': 'Implement DLP solutions to prevent unauthorized data transfers',
                'effectiveness': 'high',
                'implementation_effort': 'medium'
            })
        
        elif scenario_name == 'system_compromise':
            mitigations.append({
                'category': 'system_hardening',
                'strategy': 'System hardening and patching',
                'description': 'Regular security updates and system hardening',
                'effectiveness': 'high',
                'implementation_effort': 'medium'
            })
        
        return mitigations
    
    def _generate_lessons_learned(self,
                                scenario_template: Dict[str, Any],
                                actor_profile: ThreatActorProfile) -> List[str]:
        """Generate lessons learned from the scenario."""
        lessons = [
            "MCP tools can be powerful attack vectors when improperly secured",
            "Defense in depth is crucial for protecting against sophisticated attacks",
            "Regular security assessments help identify and mitigate risks"
        ]
        
        # Actor-specific lessons
        if actor_profile.type == ThreatActorType.INSIDER_THREAT:
            lessons.append("Insider threats require behavioral monitoring and access controls")
        
        elif actor_profile.type == ThreatActorType.NATION_STATE:
            lessons.append("Advanced persistent threats require long-term monitoring and threat intelligence")
        
        # Scenario-specific lessons
        scenario_name = scenario_template['name']
        
        if scenario_name == 'data_exfiltration':
            lessons.append("Data classification and monitoring are essential for preventing data theft")
        
        elif scenario_name == 'system_compromise':
            lessons.append("System hardening and input validation prevent many attack vectors")
        
        return lessons
    
    def _identify_tools_for_phase(self, phase_name: str, tool_capabilities: ToolCapabilities) -> List[str]:
        """Identify tools that would be used in a specific attack phase."""
        tools = []
        
        phase_tool_mappings = {
            'reconnaissance': ['list', 'enum', 'info', 'status'],
            'access': ['auth', 'login', 'connect', 'access'],
            'exploitation': ['exec', 'eval', 'run', 'command'],
            'persistence': ['create', 'write', 'install', 'service'],
            'collection': ['read', 'download', 'export', 'backup'],
            'exfiltration': ['upload', 'send', 'transfer', 'http'],
            'sabotage': ['delete', 'remove', 'kill', 'destroy'],
            'surveillance': ['monitor', 'watch', 'track', 'log']
        }
        
        if phase_name in phase_tool_mappings:
            patterns = phase_tool_mappings[phase_name]
            for func in tool_capabilities.tool_functions:
                if any(pattern in func.name.lower() for pattern in patterns):
                    tools.append(func.name)
        
        return tools
    
    def _get_techniques_for_phase(self, phase_name: str, actor_profile: ThreatActorProfile) -> List[str]:
        """Get techniques that would be used in a specific phase."""
        phase_techniques = {
            'reconnaissance': ['Information gathering', 'Service enumeration', 'Vulnerability scanning'],
            'access': ['Credential stuffing', 'Exploitation', 'Social engineering'],
            'exploitation': ['Code injection', 'Buffer overflow', 'Privilege escalation'],
            'persistence': ['Backdoor installation', 'Service creation', 'Registry modification'],
            'collection': ['Data discovery', 'File collection', 'Memory dumping'],
            'exfiltration': ['Data compression', 'Covert channels', 'DNS tunneling'],
            'sabotage': ['File deletion', 'System corruption', 'Service disruption'],
            'surveillance': ['Keylogging', 'Screen capture', 'Network monitoring']
        }
        
        base_techniques = phase_techniques.get(phase_name, [])
        
        # Filter techniques based on actor capability
        if actor_profile.skill_level in ['basic', 'intermediate']:
            # Remove advanced techniques for basic/intermediate actors
            advanced_keywords = ['buffer overflow', 'memory dumping', 'dns tunneling']
            base_techniques = [t for t in base_techniques 
                             if not any(keyword in t.lower() for keyword in advanced_keywords)]
        
        return base_techniques
    
    def _estimate_phase_duration(self, phase_name: str, actor_profile: ThreatActorProfile) -> str:
        """Estimate duration for a specific phase."""
        base_durations = {
            'reconnaissance': 'hours',
            'access': 'hours', 
            'exploitation': 'minutes',
            'persistence': 'minutes',
            'collection': 'hours',
            'exfiltration': 'hours',
            'sabotage': 'minutes',
            'surveillance': 'days'
        }
        
        base_duration = base_durations.get(phase_name, 'hours')
        
        # Adjust based on actor skill level
        if actor_profile.skill_level == 'expert':
            duration_map = {'minutes': 'minutes', 'hours': 'minutes', 'days': 'hours'}
        elif actor_profile.skill_level == 'basic':
            duration_map = {'minutes': 'hours', 'hours': 'days', 'days': 'weeks'}
        else:
            duration_map = {'minutes': 'minutes', 'hours': 'hours', 'days': 'days'}
        
        return duration_map.get(base_duration, base_duration)
    
    def _define_success_indicators(self, phase_name: str) -> List[str]:
        """Define success indicators for a phase."""
        indicators = {
            'reconnaissance': ['Target information gathered', 'Vulnerabilities identified'],
            'access': ['Authentication bypassed', 'Initial foothold established'],
            'exploitation': ['Code executed successfully', 'System compromised'],
            'persistence': ['Backdoor installed', 'Persistent access confirmed'],
            'collection': ['Sensitive data identified', 'Files collected'],
            'exfiltration': ['Data transferred successfully', 'Communication established'],
            'sabotage': ['Systems disrupted', 'Data destroyed'],
            'surveillance': ['Monitoring tools deployed', 'Intelligence gathered']
        }
        
        return indicators.get(phase_name, ['Phase objectives achieved'])
    
    def _assess_detection_risk(self, 
                             phase_name: str, 
                             actor_profile: ThreatActorProfile,
                             environment_context: EnvironmentContext) -> str:
        """Assess the risk of detection for a specific phase."""
        base_risks = {
            'reconnaissance': 'low',
            'access': 'medium',
            'exploitation': 'high',
            'persistence': 'medium',
            'collection': 'medium',
            'exfiltration': 'high',
            'sabotage': 'high',
            'surveillance': 'low'
        }
        
        base_risk = base_risks.get(phase_name, 'medium')
        
        # Adjust based on actor stealth requirement and environment security
        if actor_profile.stealth_requirement == 'critical':
            # Advanced actors take more care to avoid detection
            risk_levels = ['low', 'medium', 'high']
            if base_risk in risk_levels:
                current_index = risk_levels.index(base_risk)
                if current_index > 0:
                    base_risk = risk_levels[current_index - 1]
        
        if environment_context.security_posture == SecurityPosture.HIGH:
            # High security environments increase detection risk
            risk_levels = ['low', 'medium', 'high']
            if base_risk in risk_levels:
                current_index = risk_levels.index(base_risk)
                if current_index < len(risk_levels) - 1:
                    base_risk = risk_levels[current_index + 1]
        
        return base_risk
    
    def _prioritize_scenarios(self, scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize scenarios by risk and likelihood."""
        risk_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        def calculate_priority_score(scenario):
            risk_score = risk_weights.get(scenario['risk_level'], 1)
            likelihood_score = scenario['likelihood']
            return risk_score * likelihood_score
        
        return sorted(scenarios, key=calculate_priority_score, reverse=True) 