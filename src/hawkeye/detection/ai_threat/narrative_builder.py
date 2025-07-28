"""
Narrative Builder for Threat Analysis Reports

This module creates coherent, engaging attack narratives and stories that help
security teams understand attack scenarios in a human-readable format.
"""

import logging
import random
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, 
    AttackVector, AbuseScenario, ThreatLevel, ThreatActorType,
    SeverityLevel, AccessLevel, DifficultyLevel
)
from ..mcp_introspection.models import MCPTool, MCPServerInfo


logger = logging.getLogger(__name__)


class NarrativeStyle(Enum):
    """Different narrative styles for different audiences."""
    EXECUTIVE = "executive"        # Business-focused, high-level
    TECHNICAL = "technical"        # Technical details, specifics
    SECURITY = "security"          # Security-focused, tactical
    EDUCATIONAL = "educational"    # Training/awareness focused
    INVESTIGATIVE = "investigative" # Incident response focused


class NarrativeLength(Enum):
    """Length options for narratives."""
    BRIEF = "brief"           # 1-2 paragraphs
    STANDARD = "standard"     # 3-5 paragraphs  
    DETAILED = "detailed"     # 6+ paragraphs
    COMPREHENSIVE = "comprehensive"  # Full story with all details


class StoryElement(Enum):
    """Elements that can be included in attack narratives."""
    INITIAL_ACCESS = "initial_access"
    RECONNAISSANCE = "reconnaissance"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    IMPACT = "impact"
    TIMELINE = "timeline"
    DETECTION_EVASION = "detection_evasion"
    BUSINESS_IMPACT = "business_impact"


@dataclass
class AttackNarrative:
    """Represents a complete attack narrative."""
    
    title: str
    style: NarrativeStyle
    length: NarrativeLength
    summary: str
    full_narrative: str
    key_points: List[str] = field(default_factory=list)
    timeline: List[Tuple[str, str]] = field(default_factory=list)  # (time, event)
    characters: Dict[str, str] = field(default_factory=dict)  # role -> description
    impact_assessment: str = ""
    mitigation_context: str = ""
    technical_details: List[str] = field(default_factory=list)
    business_context: str = ""
    call_to_action: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_html(self) -> str:
        """Convert narrative to HTML format for reports."""
        return f"""
        <div class="attack-narrative {self.style.value}">
            <div class="narrative-header">
                <h3>{self.title}</h3>
                <div class="narrative-meta">
                    <span class="style">{self.style.value.title()}</span>
                    <span class="length">{self.length.value.title()}</span>
                    <span class="timestamp">{self.timestamp.strftime("%Y-%m-%d %H:%M")}</span>
                </div>
            </div>
            
            <div class="narrative-summary">
                <h4>Executive Summary</h4>
                <p>{self.summary}</p>
            </div>
            
            <div class="narrative-content">
                <h4>Attack Scenario</h4>
                <div class="story-content">{self._format_narrative_html()}</div>
            </div>
            
            {self._render_timeline()}
            {self._render_key_points()}
            {self._render_impact_assessment()}
            {self._render_technical_details()}
            {self._render_call_to_action()}
        </div>
        """
    
    def _format_narrative_html(self) -> str:
        """Format the narrative content for HTML display."""
        paragraphs = self.full_narrative.split('\n\n')
        return "".join(f"<p>{para.strip()}</p>" for para in paragraphs if para.strip())
    
    def _render_timeline(self) -> str:
        """Render attack timeline."""
        if not self.timeline:
            return ""
        
        timeline_items = "".join(
            f'<div class="timeline-item"><span class="time">{time}</span><span class="event">{event}</span></div>'
            for time, event in self.timeline
        )
        
        return f"""
        <div class="attack-timeline">
            <h4>Attack Timeline</h4>
            <div class="timeline">{timeline_items}</div>
        </div>
        """
    
    def _render_key_points(self) -> str:
        """Render key points."""
        if not self.key_points:
            return ""
        
        points = "".join(f"<li>{point}</li>" for point in self.key_points)
        return f"""
        <div class="key-points">
            <h4>Key Points</h4>
            <ul>{points}</ul>
        </div>
        """
    
    def _render_impact_assessment(self) -> str:
        """Render impact assessment."""
        if not self.impact_assessment:
            return ""
        
        return f"""
        <div class="impact-assessment">
            <h4>Impact Assessment</h4>
            <p>{self.impact_assessment}</p>
        </div>
        """
    
    def _render_technical_details(self) -> str:
        """Render technical details."""
        if not self.technical_details:
            return ""
        
        details = "".join(f"<li>{detail}</li>" for detail in self.technical_details)
        return f"""
        <div class="technical-details">
            <h4>Technical Details</h4>
            <ul>{details}</ul>
        </div>
        """
    
    def _render_call_to_action(self) -> str:
        """Render call to action."""
        if not self.call_to_action:
            return ""
        
        return f"""
        <div class="call-to-action">
            <h4>Recommended Actions</h4>
            <p>{self.call_to_action}</p>
        </div>
        """


class NarrativeBuilder:
    """Builds coherent attack narratives from threat analysis data."""
    
    def __init__(self):
        """Initialize the narrative builder."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.story_templates: Dict[str, Dict[str, str]] = {}
        self.character_profiles: Dict[ThreatActorType, Dict[str, str]] = {}
        self.narrative_phrases: Dict[str, List[str]] = {}
        self._initialize_templates()
        self._initialize_character_profiles()
        self._initialize_phrases()
    
    def build_attack_narrative(self,
                             threat_analysis: ThreatAnalysis,
                             style: NarrativeStyle = NarrativeStyle.SECURITY,
                             length: NarrativeLength = NarrativeLength.STANDARD) -> AttackNarrative:
        """
        Build a complete attack narrative from threat analysis.
        
        Args:
            threat_analysis: Threat analysis data
            style: Narrative style for target audience
            length: Desired narrative length
            
        Returns:
            AttackNarrative: Complete attack narrative
        """
        # Determine the primary threat actor type
        threat_actor = self._identify_threat_actor(threat_analysis)
        
        # Generate narrative title
        title = self._generate_narrative_title(threat_analysis, threat_actor)
        
        # Create narrative summary
        summary = self._create_executive_summary(threat_analysis, style)
        
        # Build the main narrative
        narrative_content = self._build_narrative_content(
            threat_analysis, threat_actor, style, length
        )
        
        # Extract key elements
        key_points = self._extract_key_points(threat_analysis, style)
        timeline = self._build_attack_timeline(threat_analysis)
        impact_assessment = self._create_impact_assessment(threat_analysis, style)
        technical_details = self._extract_technical_details(threat_analysis)
        call_to_action = self._create_call_to_action(threat_analysis, style)
        
        return AttackNarrative(
            title=title,
            style=style,
            length=length,
            summary=summary,
            full_narrative=narrative_content,
            key_points=key_points,
            timeline=timeline,
            impact_assessment=impact_assessment,
            technical_details=technical_details,
            call_to_action=call_to_action
        )
    
    def build_scenario_narrative(self,
                               abuse_scenario: AbuseScenario,
                               context: EnvironmentContext,
                               style: NarrativeStyle = NarrativeStyle.EDUCATIONAL) -> AttackNarrative:
        """
        Build a narrative for a specific abuse scenario.
        
        Args:
            abuse_scenario: Abuse scenario to narrate
            context: Environment context
            style: Narrative style
            
        Returns:
            AttackNarrative: Scenario narrative
        """
        title = f"Attack Scenario: {abuse_scenario.scenario_name}"
        
        summary = self._create_scenario_summary(abuse_scenario, context)
        
        narrative_content = self._build_scenario_content(
            abuse_scenario, context, style
        )
        
        key_points = [
            f"Attack Type: {abuse_scenario.attack_type}",
            f"Difficulty: {abuse_scenario.difficulty.value.title()}",
            f"Impact: {abuse_scenario.potential_impact}"
        ]
        
        return AttackNarrative(
            title=title,
            style=style,
            length=NarrativeLength.STANDARD,
            summary=summary,
            full_narrative=narrative_content,
            key_points=key_points
        )
    
    def create_business_impact_story(self,
                                   threat_analysis: ThreatAnalysis,
                                   business_context: Optional[Dict[str, Any]] = None) -> AttackNarrative:
        """
        Create a business-focused impact story for executives.
        
        Args:
            threat_analysis: Threat analysis data
            business_context: Additional business context
            
        Returns:
            AttackNarrative: Business impact narrative
        """
        # Focus on business impact and financial consequences
        title = self._generate_business_title(threat_analysis)
        
        summary = self._create_business_summary(threat_analysis, business_context)
        
        narrative_content = self._build_business_narrative(
            threat_analysis, business_context
        )
        
        # Business-focused key points
        key_points = [
            "Potential financial impact from security incident",
            "Regulatory compliance implications",
            "Reputation and customer trust risks",
            "Operational disruption scenarios"
        ]
        
        impact_assessment = self._create_detailed_business_impact(
            threat_analysis, business_context
        )
        
        call_to_action = self._create_executive_call_to_action(threat_analysis)
        
        return AttackNarrative(
            title=title,
            style=NarrativeStyle.EXECUTIVE,
            length=NarrativeLength.STANDARD,
            summary=summary,
            full_narrative=narrative_content,
            key_points=key_points,
            impact_assessment=impact_assessment,
            call_to_action=call_to_action
        )
    
    def _identify_threat_actor(self, threat_analysis: ThreatAnalysis) -> ThreatActorType:
        """Identify the most likely threat actor type."""
        # Analysis based on attack vectors and complexity
        if not threat_analysis.attack_vectors:
            return ThreatActorType.EXTERNAL_ATTACKER
        
        # Look at attack complexity and types
        high_complexity_attacks = sum(
            1 for av in threat_analysis.attack_vectors 
            if av.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        )
        
        if high_complexity_attacks >= 2:
            return ThreatActorType.NATION_STATE
        elif any("insider" in av.description.lower() for av in threat_analysis.attack_vectors):
            return ThreatActorType.INSIDER_THREAT
        elif any("financial" in av.description.lower() for av in threat_analysis.attack_vectors):
            return ThreatActorType.CYBERCRIMINAL
        else:
            return ThreatActorType.EXTERNAL_ATTACKER
    
    def _generate_narrative_title(self, 
                                threat_analysis: ThreatAnalysis,
                                threat_actor: ThreatActorType) -> str:
        """Generate an engaging narrative title."""
        tool_name = threat_analysis.tool_capabilities.tool_name
        threat_level = threat_analysis.threat_level.value.title()
        
        actor_context = {
            ThreatActorType.NATION_STATE: "Advanced Persistent Threat",
            ThreatActorType.CYBERCRIMINAL: "Cybercrime Operation",
            ThreatActorType.INSIDER_THREAT: "Insider Threat Scenario",
            ThreatActorType.HACKTIVIST: "Hacktivist Campaign",
            ThreatActorType.EXTERNAL_ATTACKER: "External Attack Campaign"
        }
        
        context = actor_context.get(threat_actor, "Security Incident")
        
        return f"{threat_level} Risk: {context} Targeting {tool_name}"
    
    def _create_executive_summary(self, 
                                threat_analysis: ThreatAnalysis,
                                style: NarrativeStyle) -> str:
        """Create executive summary based on style."""
        tool_name = threat_analysis.tool_capabilities.tool_name
        threat_level = threat_analysis.threat_level.value
        num_vectors = len(threat_analysis.attack_vectors) if threat_analysis.attack_vectors else 0
        
        if style == NarrativeStyle.EXECUTIVE:
            return (f"Our security analysis has identified {num_vectors} potential attack vectors "
                   f"targeting the {tool_name} system with {threat_level} risk level. "
                   f"These vulnerabilities could result in significant business impact including "
                   f"data breaches, operational disruption, and regulatory violations. "
                   f"Immediate attention and remediation are recommended.")
        
        elif style == NarrativeStyle.TECHNICAL:
            return (f"Technical analysis of {tool_name} reveals {num_vectors} exploitable "
                   f"attack vectors with {threat_level} severity. The identified vulnerabilities "
                   f"span multiple attack categories and could enable attackers to compromise "
                   f"system integrity, confidentiality, and availability.")
        
        else:  # Security/Educational
            return (f"Security assessment of {tool_name} has uncovered {num_vectors} attack "
                   f"scenarios ranging from {threat_level} risk. These attack paths demonstrate "
                   f"how malicious actors could exploit the system capabilities to achieve "
                   f"unauthorized access, data theft, or system disruption.")
    
    def _build_narrative_content(self,
                               threat_analysis: ThreatAnalysis,
                               threat_actor: ThreatActorType,
                               style: NarrativeStyle,
                               length: NarrativeLength) -> str:
        """Build the main narrative content."""
        
        # Get character profile for threat actor
        character = self.character_profiles.get(threat_actor, {})
        actor_name = character.get("name", "the attacker")
        actor_motivation = character.get("motivation", "malicious intent")
        
        tool_name = threat_analysis.tool_capabilities.tool_name
        
        # Build narrative sections
        opening = self._create_opening(tool_name, actor_name, actor_motivation, style)
        
        attack_sequence = self._create_attack_sequence(
            threat_analysis, actor_name, style
        )
        
        impact_description = self._create_impact_description(
            threat_analysis, style
        )
        
        # Combine sections based on length
        if length == NarrativeLength.BRIEF:
            return f"{opening}\n\n{attack_sequence}"
        
        elif length == NarrativeLength.STANDARD:
            return f"{opening}\n\n{attack_sequence}\n\n{impact_description}"
        
        else:  # Detailed or Comprehensive
            detection_evasion = self._create_detection_evasion_section(
                threat_analysis, actor_name
            )
            business_context = self._create_business_context_section(
                threat_analysis, style
            )
            
            content = f"{opening}\n\n{attack_sequence}\n\n{impact_description}\n\n{detection_evasion}"
            
            if length == NarrativeLength.COMPREHENSIVE:
                content += f"\n\n{business_context}"
            
            return content
    
    def _create_opening(self, 
                       tool_name: str,
                       actor_name: str,
                       motivation: str,
                       style: NarrativeStyle) -> str:
        """Create narrative opening."""
        
        if style == NarrativeStyle.EXECUTIVE:
            return (f"In this security scenario, {actor_name} has identified your organization's "
                   f"{tool_name} system as a potential target. Driven by {motivation}, "
                   f"they begin a systematic approach to understand and exploit the system's "
                   f"capabilities for unauthorized access and data extraction.")
        
        elif style == NarrativeStyle.TECHNICAL:
            return (f"The attack scenario begins when {actor_name} discovers the {tool_name} "
                   f"system through network reconnaissance. After identifying exposed services "
                   f"and analyzing the system architecture, they proceed with targeted "
                   f"exploitation techniques.")
        
        else:  # Security/Educational
            return (f"Picture this scenario: {actor_name}, motivated by {motivation}, "
                   f"has set their sights on your {tool_name} system. Through a combination "
                   f"of technical skill and persistence, they begin mapping out potential "
                   f"attack paths that could compromise your security.")
    
    def _create_attack_sequence(self,
                              threat_analysis: ThreatAnalysis,
                              actor_name: str,
                              style: NarrativeStyle) -> str:
        """Create the attack sequence narrative."""
        
        if not threat_analysis.attack_vectors:
            return f"{actor_name} attempts various attack methods against the system."
        
        # Take the top 3 attack vectors for narrative
        top_vectors = threat_analysis.attack_vectors[:3]
        
        sequence_parts = []
        
        for i, vector in enumerate(top_vectors, 1):
            if style == NarrativeStyle.EXECUTIVE:
                part = (f"In phase {i}, {actor_name} exploits {vector.description.lower()} "
                       f"to gain {vector.required_access.value} access. This attack could "
                       f"result in {vector.impact.lower()}.")
            
            elif style == NarrativeStyle.TECHNICAL:
                part = (f"Attack Vector {i}: {actor_name} leverages {vector.vector_type} "
                       f"techniques to exploit {vector.description}. The attack requires "
                       f"{vector.required_access.value} privileges and has {vector.severity.value} "
                       f"severity.")
            
            else:  # Security/Educational
                part = (f"Next, {actor_name} turns their attention to {vector.description.lower()}. "
                       f"Using {vector.vector_type} techniques, they attempt to "
                       f"{self._get_attack_goal(vector)}. If successful, this could lead to "
                       f"{vector.impact.lower()}.")
            
            sequence_parts.append(part)
        
        return " ".join(sequence_parts)
    
    def _create_impact_description(self,
                                 threat_analysis: ThreatAnalysis,
                                 style: NarrativeStyle) -> str:
        """Create impact description section."""
        
        if style == NarrativeStyle.EXECUTIVE:
            return ("The successful execution of these attacks could result in significant "
                   "business disruption, financial losses, and damage to your organization's "
                   "reputation. Customer data could be compromised, leading to regulatory "
                   "penalties and loss of customer trust.")
        
        elif style == NarrativeStyle.TECHNICAL:
            return ("System compromise could lead to unauthorized data access, service "
                   "disruption, and potential lateral movement to other network resources. "
                   "The attacker may establish persistence mechanisms and exfiltrate "
                   "sensitive information.")
        
        else:  # Security/Educational
            return ("If these attacks succeed, the consequences extend far beyond just "
                   "technical issues. Your organization could face data breaches, system "
                   "downtime, financial losses, and regulatory compliance violations. "
                   "The impact ripples through operations, customer relationships, and "
                   "business continuity.")
    
    def _create_detection_evasion_section(self,
                                        threat_analysis: ThreatAnalysis,
                                        actor_name: str) -> str:
        """Create detection evasion narrative section."""
        return (f"Throughout the attack, {actor_name} employs various evasion techniques "
               f"to avoid detection. They may use legitimate tools and protocols to "
               f"blend in with normal network traffic, making their activities difficult "
               f"to distinguish from authorized users. Traditional security controls may "
               f"miss these subtle attack patterns.")
    
    def _create_business_context_section(self,
                                       threat_analysis: ThreatAnalysis,
                                       style: NarrativeStyle) -> str:
        """Create business context section."""
        return ("From a business perspective, this attack scenario highlights the "
               "critical importance of proactive security measures. Organizations "
               "that fail to address these vulnerabilities face not only immediate "
               "technical risks but also long-term business consequences including "
               "competitive disadvantage, regulatory scrutiny, and stakeholder loss "
               "of confidence.")
    
    def _build_attack_timeline(self, threat_analysis: ThreatAnalysis) -> List[Tuple[str, str]]:
        """Build attack timeline."""
        timeline = [
            ("T+0 hours", "Initial reconnaissance and target identification"),
            ("T+2 hours", "Capability assessment and attack vector selection"),
        ]
        
        if threat_analysis.attack_vectors:
            for i, vector in enumerate(threat_analysis.attack_vectors[:3], 1):
                time_offset = 2 + (i * 2)
                timeline.append((
                    f"T+{time_offset} hours",
                    f"Execute {vector.vector_type} attack: {vector.description}"
                ))
        
        timeline.extend([
            ("T+8 hours", "Establish persistence and expand access"),
            ("T+12 hours", "Data exfiltration and impact realization"),
        ])
        
        return timeline
    
    def _extract_key_points(self,
                          threat_analysis: ThreatAnalysis,
                          style: NarrativeStyle) -> List[str]:
        """Extract key points from threat analysis."""
        points = []
        
        # Threat level
        points.append(f"Overall threat level: {threat_analysis.threat_level.value.title()}")
        
        # Number of attack vectors
        if threat_analysis.attack_vectors:
            points.append(f"{len(threat_analysis.attack_vectors)} potential attack vectors identified")
        
        # Confidence level
        if hasattr(threat_analysis, 'confidence_score'):
            confidence = int(threat_analysis.confidence_score * 100)
            points.append(f"Analysis confidence: {confidence}%")
        
        # Style-specific points
        if style == NarrativeStyle.EXECUTIVE:
            points.extend([
                "Business continuity at risk",
                "Regulatory compliance implications",
                "Customer trust and reputation impact"
            ])
        elif style == NarrativeStyle.TECHNICAL:
            points.extend([
                "Multiple attack surfaces exposed",
                "Privilege escalation opportunities",
                "Data confidentiality risks"
            ])
        
        return points
    
    def _create_impact_assessment(self,
                                threat_analysis: ThreatAnalysis,
                                style: NarrativeStyle) -> str:
        """Create detailed impact assessment."""
        
        if style == NarrativeStyle.EXECUTIVE:
            return ("The potential business impact includes financial losses from downtime, "
                   "regulatory fines for data breaches, legal costs from customer lawsuits, "
                   "and long-term damage to market position and brand reputation. Recovery "
                   "costs could reach millions of dollars depending on the scope of compromise.")
        
        elif style == NarrativeStyle.TECHNICAL:
            return ("Technical impact includes system compromise, data integrity loss, "
                   "service availability disruption, and potential network propagation. "
                   "Recovery requires system rebuilding, security hardening, and "
                   "comprehensive forensic analysis.")
        
        else:
            return ("The combined impact spans technical systems, business operations, "
                   "and organizational reputation. Immediate costs include incident response, "
                   "system recovery, and customer notification. Long-term effects include "
                   "increased security spending, regulatory oversight, and competitive disadvantage.")
    
    def _extract_technical_details(self, threat_analysis: ThreatAnalysis) -> List[str]:
        """Extract technical details for the narrative."""
        details = []
        
        # Tool capabilities
        tool_name = threat_analysis.tool_capabilities.tool_name
        details.append(f"Target system: {tool_name}")
        
        # Attack vectors
        if threat_analysis.attack_vectors:
            details.append(f"Attack vectors: {len(threat_analysis.attack_vectors)} identified")
            
            for vector in threat_analysis.attack_vectors[:3]:
                details.append(f"- {vector.vector_type}: {vector.severity.value} severity")
        
        # Mitigation strategies
        if threat_analysis.mitigation_strategies:
            details.append(f"Mitigation options: {len(threat_analysis.mitigation_strategies)} available")
        
        return details
    
    def _create_call_to_action(self,
                             threat_analysis: ThreatAnalysis,
                             style: NarrativeStyle) -> str:
        """Create call to action based on style."""
        
        if style == NarrativeStyle.EXECUTIVE:
            return ("Immediate board and executive action is required. Authorize emergency "
                   "security budget allocation, engage incident response team, and implement "
                   "risk mitigation measures. Consider external security consultation for "
                   "comprehensive threat assessment.")
        
        elif style == NarrativeStyle.TECHNICAL:
            return ("Implement technical controls immediately: patch vulnerabilities, "
                   "strengthen access controls, enhance monitoring, and validate security "
                   "configurations. Conduct penetration testing to verify mitigations.")
        
        else:  # Security/Educational
            return ("Take action now: review security policies, update incident response "
                   "procedures, train staff on threat awareness, and implement recommended "
                   "security controls. Regular security assessments are essential for "
                   "maintaining protective measures.")
    
    def _build_scenario_content(self,
                              abuse_scenario: AbuseScenario,
                              context: EnvironmentContext,
                              style: NarrativeStyle) -> str:
        """Build content for abuse scenario."""
        return (f"In this scenario, an attacker leverages {abuse_scenario.scenario_name} "
               f"to achieve {abuse_scenario.attack_type}. The attack begins with "
               f"{abuse_scenario.initial_access} and progresses through multiple stages "
               f"to ultimately result in {abuse_scenario.potential_impact}. "
               f"The difficulty level is assessed as {abuse_scenario.difficulty.value}, "
               f"making this a {self._assess_likelihood(abuse_scenario.difficulty)} threat.")
    
    def _create_scenario_summary(self,
                               abuse_scenario: AbuseScenario,
                               context: EnvironmentContext) -> str:
        """Create summary for abuse scenario."""
        return (f"This scenario demonstrates how attackers could abuse "
               f"{abuse_scenario.scenario_name} functionality to execute "
               f"{abuse_scenario.attack_type} attacks, potentially resulting in "
               f"{abuse_scenario.potential_impact}.")
    
    def _generate_business_title(self, threat_analysis: ThreatAnalysis) -> str:
        """Generate business-focused title."""
        tool_name = threat_analysis.tool_capabilities.tool_name
        threat_level = threat_analysis.threat_level.value.title()
        return f"Business Risk Assessment: {threat_level} Security Threats to {tool_name}"
    
    def _create_business_summary(self,
                               threat_analysis: ThreatAnalysis,
                               business_context: Optional[Dict[str, Any]]) -> str:
        """Create business-focused summary."""
        return ("Security vulnerabilities in critical business systems pose significant "
               "financial and operational risks. This assessment identifies potential "
               "attack scenarios that could disrupt business operations, compromise "
               "customer data, and result in regulatory violations.")
    
    def _build_business_narrative(self,
                                threat_analysis: ThreatAnalysis,
                                business_context: Optional[Dict[str, Any]]) -> str:
        """Build business-focused narrative."""
        return ("From a business perspective, these security vulnerabilities represent "
               "material risk to organizational objectives. A successful attack could "
               "result in operational downtime, customer data breach, regulatory penalties, "
               "and significant damage to brand reputation. The financial implications "
               "include direct costs for incident response, system recovery, legal fees, "
               "and regulatory fines, as well as indirect costs from customer churn, "
               "business disruption, and competitive disadvantage.\n\n"
               "The organization's risk tolerance and business continuity requirements "
               "must be carefully balanced against the cost and complexity of implementing "
               "comprehensive security controls. However, the potential consequences of "
               "a successful attack far outweigh the investment required for proper "
               "security measures.")
    
    def _create_detailed_business_impact(self,
                                       threat_analysis: ThreatAnalysis,
                                       business_context: Optional[Dict[str, Any]]) -> str:
        """Create detailed business impact assessment."""
        return ("Business impact analysis reveals multiple risk categories: Financial "
               "losses from operational downtime and incident response could reach "
               "$1-5M depending on attack scope. Regulatory fines for data breaches "
               "range from $100K to $50M based on violation severity. Customer "
               "acquisition costs increase 3-5x following security incidents due to "
               "reputation damage. Competitive advantage erosion occurs when "
               "proprietary information is compromised.")
    
    def _create_executive_call_to_action(self, threat_analysis: ThreatAnalysis) -> str:
        """Create executive-focused call to action."""
        return ("Executive action required: (1) Approve emergency security budget for "
               "immediate threat mitigation, (2) Engage board-level discussion on "
               "organizational risk tolerance, (3) Authorize comprehensive security "
               "audit and remediation program, (4) Implement executive dashboard for "
               "ongoing risk monitoring and reporting.")
    
    def _get_attack_goal(self, vector: AttackVector) -> str:
        """Get attack goal description for vector."""
        goals = {
            "data_exfiltration": "steal sensitive information",
            "privilege_escalation": "gain administrative access", 
            "lateral_movement": "expand network access",
            "persistence": "maintain long-term access",
            "disruption": "disrupt business operations"
        }
        
        return goals.get(vector.vector_type.lower(), "compromise system security")
    
    def _assess_likelihood(self, difficulty: DifficultyLevel) -> str:
        """Assess attack likelihood based on difficulty."""
        likelihood_map = {
            DifficultyLevel.LOW: "high-probability",
            DifficultyLevel.MEDIUM: "moderate-probability", 
            DifficultyLevel.HIGH: "low-probability"
        }
        return likelihood_map.get(difficulty, "unknown-probability")
    
    def _initialize_templates(self):
        """Initialize narrative templates."""
        self.story_templates = {
            "executive": {
                "opening": "Our security analysis reveals {threat_level} risks...",
                "impact": "Business impact includes financial losses..."
            },
            "technical": {
                "opening": "Technical assessment identifies {num_vectors} attack vectors...",
                "impact": "System compromise enables unauthorized access..."
            }
        }
    
    def _initialize_character_profiles(self):
        """Initialize threat actor character profiles."""
        self.character_profiles = {
            ThreatActorType.NATION_STATE: {
                "name": "a sophisticated state-sponsored group",
                "motivation": "intelligence gathering and strategic advantage",
                "skill_level": "expert",
                "resources": "extensive"
            },
            ThreatActorType.CYBERCRIMINAL: {
                "name": "an organized cybercrime syndicate",
                "motivation": "financial gain through fraud and theft",
                "skill_level": "professional",
                "resources": "substantial"
            },
            ThreatActorType.INSIDER_THREAT: {
                "name": "a malicious insider",
                "motivation": "personal grievance or financial incentive",
                "skill_level": "intermediate",
                "resources": "privileged access"
            },
            ThreatActorType.HACKTIVIST: {
                "name": "an ideologically motivated hacktivist",
                "motivation": "political or social activism",
                "skill_level": "intermediate",
                "resources": "moderate"
            },
            ThreatActorType.EXTERNAL_ATTACKER: {
                "name": "an external attacker",
                "motivation": "various malicious objectives",
                "skill_level": "variable",
                "resources": "limited to moderate"
            }
        }
    
    def _initialize_phrases(self):
        """Initialize narrative phrases for variety."""
        self.narrative_phrases = {
            "transitions": [
                "Subsequently", "Following this", "Next", "Then", "Meanwhile",
                "In the next phase", "Building on this access", "With this foothold"
            ],
            "attack_actions": [
                "leverages", "exploits", "utilizes", "takes advantage of",
                "capitalizes on", "harnesses", "employs"
            ],
            "impact_descriptions": [
                "resulting in", "leading to", "enabling", "facilitating",
                "ultimately causing", "potentially resulting in"
            ]
        } 