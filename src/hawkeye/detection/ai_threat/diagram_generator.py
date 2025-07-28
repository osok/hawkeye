"""
Diagram Generator for Threat Analysis Reports

This module generates visual representations including attack flow diagrams,
network topology maps, timeline visualizations, and risk heat maps for
threat analysis reports.
"""

import json
import logging
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


class DiagramType(Enum):
    """Types of diagrams that can be generated."""
    ATTACK_FLOW = "attack_flow"
    NETWORK_TOPOLOGY = "network_topology"
    TIMELINE = "timeline"
    RISK_HEAT_MAP = "risk_heat_map"
    ATTACK_TREE = "attack_tree"
    DATA_FLOW = "data_flow"
    THREAT_LANDSCAPE = "threat_landscape"
    MITIGATION_MATRIX = "mitigation_matrix"


class DiagramFormat(Enum):
    """Output formats for diagrams."""
    MERMAID = "mermaid"
    GRAPHVIZ = "graphviz"
    SVG = "svg"
    HTML_CSS = "html_css"
    JSON = "json"
    PLANTUML = "plantuml"


class DiagramStyle(Enum):
    """Visual styles for diagrams."""
    PROFESSIONAL = "professional"
    DARK_THEME = "dark_theme"
    COLORFUL = "colorful"
    MINIMAL = "minimal"
    SECURITY_FOCUSED = "security_focused"


@dataclass
class VisualDiagram:
    """Represents a generated visual diagram."""
    
    title: str
    diagram_type: DiagramType
    format: DiagramFormat
    style: DiagramStyle
    content: str
    description: str
    legend: Dict[str, str] = field(default_factory=dict)
    interactions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_html(self) -> str:
        """Convert diagram to HTML format for reports."""
        
        if self.format == DiagramFormat.MERMAID:
            return self._render_mermaid_html()
        elif self.format == DiagramFormat.HTML_CSS:
            return self._render_html_css()
        elif self.format == DiagramFormat.SVG:
            return self._render_svg_html()
        else:
            return self._render_code_block()
    
    def _render_mermaid_html(self) -> str:
        """Render Mermaid diagram in HTML."""
        return f"""
        <div class="diagram-container {self.style.value}">
            <div class="diagram-header">
                <h4>{self.title}</h4>
                <div class="diagram-meta">
                    <span class="type">{self.diagram_type.value.replace('_', ' ').title()}</span>
                    <span class="format">{self.format.value.upper()}</span>
                </div>
            </div>
            
            <div class="diagram-description">
                <p>{self.description}</p>
            </div>
            
            <div class="mermaid-diagram">
                <div class="mermaid">
{self.content}
                </div>
            </div>
            
            {self._render_legend()}
            {self._render_interactions()}
        </div>
        
        <script>
            // Initialize Mermaid if not already done
            if (typeof mermaid !== 'undefined') {{
                mermaid.initialize({{ theme: '{self._get_mermaid_theme()}' }});
            }}
        </script>
        """
    
    def _render_html_css(self) -> str:
        """Render HTML/CSS diagram."""
        return f"""
        <div class="diagram-container {self.style.value}">
            <div class="diagram-header">
                <h4>{self.title}</h4>
            </div>
            
            <div class="diagram-description">
                <p>{self.description}</p>
            </div>
            
            <div class="html-diagram">
                {self.content}
            </div>
            
            {self._render_legend()}
        </div>
        """
    
    def _render_svg_html(self) -> str:
        """Render SVG diagram in HTML."""
        return f"""
        <div class="diagram-container {self.style.value}">
            <div class="diagram-header">
                <h4>{self.title}</h4>
            </div>
            
            <div class="diagram-description">
                <p>{self.description}</p>
            </div>
            
            <div class="svg-diagram">
                {self.content}
            </div>
            
            {self._render_legend()}
        </div>
        """
    
    def _render_code_block(self) -> str:
        """Render as code block for non-visual formats."""
        return f"""
        <div class="diagram-container {self.style.value}">
            <div class="diagram-header">
                <h4>{self.title}</h4>
            </div>
            
            <div class="diagram-description">
                <p>{self.description}</p>
            </div>
            
            <div class="code-diagram">
                <pre><code class="language-{self.format.value}">{self.content}</code></pre>
            </div>
            
            {self._render_legend()}
        </div>
        """
    
    def _render_legend(self) -> str:
        """Render diagram legend."""
        if not self.legend:
            return ""
        
        legend_items = "".join(
            f'<div class="legend-item"><span class="legend-symbol">{symbol}</span><span class="legend-label">{label}</span></div>'
            for symbol, label in self.legend.items()
        )
        
        return f"""
        <div class="diagram-legend">
            <h5>Legend</h5>
            <div class="legend-items">{legend_items}</div>
        </div>
        """
    
    def _render_interactions(self) -> str:
        """Render interaction notes."""
        if not self.interactions:
            return ""
        
        interaction_items = "".join(f"<li>{interaction}</li>" for interaction in self.interactions)
        return f"""
        <div class="diagram-interactions">
            <h5>Interactive Elements</h5>
            <ul>{interaction_items}</ul>
        </div>
        """
    
    def _get_mermaid_theme(self) -> str:
        """Get Mermaid theme based on style."""
        theme_mapping = {
            DiagramStyle.PROFESSIONAL: "default",
            DiagramStyle.DARK_THEME: "dark",
            DiagramStyle.COLORFUL: "base",
            DiagramStyle.MINIMAL: "neutral",
            DiagramStyle.SECURITY_FOCUSED: "dark"
        }
        return theme_mapping.get(self.style, "default")


class DiagramGenerator:
    """Generates visual diagrams for threat analysis reports."""
    
    def __init__(self):
        """Initialize the diagram generator."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.color_schemes: Dict[DiagramStyle, Dict[str, str]] = {}
        self.diagram_templates: Dict[DiagramType, str] = {}
        self._initialize_color_schemes()
        self._initialize_templates()
    
    def generate_attack_flow_diagram(self,
                                   threat_analysis: ThreatAnalysis,
                                   format: DiagramFormat = DiagramFormat.MERMAID,
                                   style: DiagramStyle = DiagramStyle.SECURITY_FOCUSED) -> VisualDiagram:
        """
        Generate an attack flow diagram showing the progression of an attack.
        
        Args:
            threat_analysis: Threat analysis data
            format: Output format for the diagram
            style: Visual style for the diagram
            
        Returns:
            VisualDiagram: Generated attack flow diagram
        """
        
        if format == DiagramFormat.MERMAID:
            content = self._generate_mermaid_attack_flow(threat_analysis)
        elif format == DiagramFormat.GRAPHVIZ:
            content = self._generate_graphviz_attack_flow(threat_analysis)
        else:
            content = self._generate_json_attack_flow(threat_analysis)
        
        return VisualDiagram(
            title=f"Attack Flow: {threat_analysis.tool_capabilities.tool_name}",
            diagram_type=DiagramType.ATTACK_FLOW,
            format=format,
            style=style,
            content=content,
            description=f"Visual representation of potential attack flows against {threat_analysis.tool_capabilities.tool_name}",
            legend=self._get_attack_flow_legend(),
            interactions=[
                "Click on attack stages to see detailed information",
                "Hover over connections to see relationships",
                "Use zoom controls for detailed view"
            ]
        )
    
    def generate_timeline_diagram(self,
                                threat_analysis: ThreatAnalysis,
                                time_window: int = 24,  # hours
                                format: DiagramFormat = DiagramFormat.HTML_CSS) -> VisualDiagram:
        """
        Generate a timeline diagram showing attack progression over time.
        
        Args:
            threat_analysis: Threat analysis data
            time_window: Time window in hours for the attack timeline
            format: Output format for the diagram
            
        Returns:
            VisualDiagram: Generated timeline diagram
        """
        
        if format == DiagramFormat.HTML_CSS:
            content = self._generate_html_timeline(threat_analysis, time_window)
        elif format == DiagramFormat.MERMAID:
            content = self._generate_mermaid_timeline(threat_analysis, time_window)
        else:
            content = self._generate_json_timeline(threat_analysis, time_window)
        
        return VisualDiagram(
            title=f"Attack Timeline: {threat_analysis.tool_capabilities.tool_name}",
            diagram_type=DiagramType.TIMELINE,
            format=format,
            style=DiagramStyle.PROFESSIONAL,
            content=content,
            description=f"Timeline visualization of attack progression over {time_window} hours",
            legend={
                "🔴": "Critical stage",
                "🟡": "Intermediate stage", 
                "🟢": "Initial reconnaissance",
                "⚫": "Persistence established"
            }
        )
    
    def generate_risk_heat_map(self,
                             servers: List[MCPServerInfo],
                             threat_analyses: List[ThreatAnalysis],
                             format: DiagramFormat = DiagramFormat.HTML_CSS) -> VisualDiagram:
        """
        Generate a risk heat map showing threat levels across multiple servers.
        
        Args:
            servers: List of MCP servers
            threat_analyses: List of threat analyses for each server
            format: Output format for the diagram
            
        Returns:
            VisualDiagram: Generated risk heat map
        """
        
        if format == DiagramFormat.HTML_CSS:
            content = self._generate_html_heat_map(servers, threat_analyses)
        elif format == DiagramFormat.SVG:
            content = self._generate_svg_heat_map(servers, threat_analyses)
        else:
            content = self._generate_json_heat_map(servers, threat_analyses)
        
        return VisualDiagram(
            title="MCP Servers Risk Heat Map",
            diagram_type=DiagramType.RISK_HEAT_MAP,
            format=format,
            style=DiagramStyle.COLORFUL,
            content=content,
            description="Heat map visualization showing risk levels across MCP servers",
            legend={
                "🔴": "Critical risk (9-10)",
                "🟠": "High risk (7-8)",
                "🟡": "Medium risk (4-6)",
                "🟢": "Low risk (1-3)",
                "⚪": "No analysis available"
            }
        )
    
    def generate_attack_tree_diagram(self,
                                   attack_vectors: List[AttackVector],
                                   format: DiagramFormat = DiagramFormat.MERMAID) -> VisualDiagram:
        """
        Generate an attack tree diagram showing different attack paths.
        
        Args:
            attack_vectors: List of attack vectors to visualize
            format: Output format for the diagram
            
        Returns:
            VisualDiagram: Generated attack tree diagram
        """
        
        if format == DiagramFormat.MERMAID:
            content = self._generate_mermaid_attack_tree(attack_vectors)
        elif format == DiagramFormat.GRAPHVIZ:
            content = self._generate_graphviz_attack_tree(attack_vectors)
        else:
            content = self._generate_json_attack_tree(attack_vectors)
        
        return VisualDiagram(
            title="Attack Tree Analysis",
            diagram_type=DiagramType.ATTACK_TREE,
            format=format,
            style=DiagramStyle.SECURITY_FOCUSED,
            content=content,
            description="Hierarchical view of possible attack paths and their relationships",
            legend=self._get_attack_tree_legend()
        )
    
    def generate_network_topology_diagram(self,
                                        environment_context: EnvironmentContext,
                                        servers: List[MCPServerInfo],
                                        format: DiagramFormat = DiagramFormat.MERMAID) -> VisualDiagram:
        """
        Generate a network topology diagram showing server relationships.
        
        Args:
            environment_context: Environment context information
            servers: List of MCP servers
            format: Output format for the diagram
            
        Returns:
            VisualDiagram: Generated network topology diagram
        """
        
        if format == DiagramFormat.MERMAID:
            content = self._generate_mermaid_topology(environment_context, servers)
        elif format == DiagramFormat.GRAPHVIZ:
            content = self._generate_graphviz_topology(environment_context, servers)
        else:
            content = self._generate_json_topology(environment_context, servers)
        
        return VisualDiagram(
            title="Network Topology & Attack Surface",
            diagram_type=DiagramType.NETWORK_TOPOLOGY,
            format=format,
            style=DiagramStyle.PROFESSIONAL,
            content=content,
            description="Network topology showing MCP servers and potential attack paths",
            legend={
                "🖥️": "MCP Server",
                "🌐": "Network boundary",
                "🔒": "Secured connection",
                "⚠️": "Vulnerable service",
                "🔥": "High-risk component"
            }
        )
    
    def _generate_mermaid_attack_flow(self, threat_analysis: ThreatAnalysis) -> str:
        """Generate Mermaid attack flow diagram."""
        
        tool_name = threat_analysis.tool_capabilities.tool_name
        attack_vectors = threat_analysis.attack_vectors or []
        
        # Start with the tool as the central node
        mermaid_code = f"""graph TD
    Start([Attacker]) --> Recon[Reconnaissance]
    Recon --> Target["{tool_name}"]
    Target --> Analysis[Capability Analysis]
"""
        
        # Add attack vectors
        for i, vector in enumerate(attack_vectors[:5], 1):  # Limit to 5 vectors
            vector_id = f"AV{i}"
            severity_class = vector.severity.value.lower()
            
            mermaid_code += f"""
    Analysis --> {vector_id}["{vector.vector_type}"]
    {vector_id} --> Impact{i}["{vector.impact[:30]}..."]
    
    class {vector_id} {severity_class}
    class Impact{i} impact"""
        
        # Add final impact node
        mermaid_code += f"""
    
    {'Impact1' if attack_vectors else 'Analysis'} --> Compromise[System Compromise]
    Compromise --> Persistence[Establish Persistence]
    Persistence --> Exfiltration[Data Exfiltration]
    
    class Compromise critical
    class Persistence critical
    class Exfiltration critical
    
    classDef critical fill:#ff4444,stroke:#cc0000,stroke-width:3px,color:#fff
    classDef high fill:#ff8800,stroke:#cc4400,stroke-width:2px,color:#fff
    classDef medium fill:#ffcc00,stroke:#cc8800,stroke-width:2px,color:#000
    classDef low fill:#88cc00,stroke:#448800,stroke-width:1px,color:#000
    classDef impact fill:#e1e1e1,stroke:#999,stroke-width:1px,color:#000
"""
        
        return mermaid_code
    
    def _generate_html_timeline(self, threat_analysis: ThreatAnalysis, time_window: int) -> str:
        """Generate HTML/CSS timeline diagram."""
        
        # Create timeline events
        events = []
        start_time = datetime.now()
        
        # Add reconnaissance phase
        events.append({
            'time': start_time,
            'title': 'Initial Reconnaissance',
            'description': f'Target identification: {threat_analysis.tool_capabilities.tool_name}',
            'severity': 'low',
            'duration': 2
        })
        
        # Add attack vector events
        if threat_analysis.attack_vectors:
            for i, vector in enumerate(threat_analysis.attack_vectors[:4], 1):
                event_time = start_time + timedelta(hours=i * 2)
                events.append({
                    'time': event_time,
                    'title': vector.vector_type.replace('_', ' ').title(),
                    'description': vector.description[:100] + "...",
                    'severity': vector.severity.value.lower(),
                    'duration': 1
                })
        
        # Add final impact event
        final_time = start_time + timedelta(hours=time_window - 2)
        events.append({
            'time': final_time,
            'title': 'System Compromise Complete',
            'description': 'Full system access achieved, persistence established',
            'severity': 'critical',
            'duration': 1
        })
        
        # Generate HTML timeline
        timeline_html = '''
        <div class="attack-timeline">
            <div class="timeline-container">
'''
        
        for i, event in enumerate(events):
            severity_class = event['severity']
            time_str = event['time'].strftime('%H:%M')
            
            timeline_html += f'''
                <div class="timeline-event {severity_class}" data-time="{time_str}">
                    <div class="timeline-marker"></div>
                    <div class="timeline-content">
                        <div class="event-time">{time_str}</div>
                        <div class="event-title">{event['title']}</div>
                        <div class="event-description">{event['description']}</div>
                        <div class="event-duration">Duration: ~{event['duration']} hour(s)</div>
                    </div>
                </div>
'''
        
        timeline_html += '''
            </div>
        </div>
        
        <style>
        .attack-timeline {
            position: relative;
            margin: 20px 0;
        }
        
        .timeline-container {
            position: relative;
            padding-left: 30px;
        }
        
        .timeline-container::before {
            content: '';
            position: absolute;
            left: 15px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: #ddd;
        }
        
        .timeline-event {
            position: relative;
            margin-bottom: 30px;
            padding: 15px 20px;
            background: #f9f9f9;
            border-radius: 8px;
            border-left: 4px solid #ddd;
        }
        
        .timeline-event.low { border-left-color: #28a745; }
        .timeline-event.medium { border-left-color: #ffc107; }
        .timeline-event.high { border-left-color: #fd7e14; }
        .timeline-event.critical { border-left-color: #dc3545; }
        
        .timeline-marker {
            position: absolute;
            left: -24px;
            top: 20px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #fff;
            border: 3px solid #ddd;
        }
        
        .timeline-event.low .timeline-marker { border-color: #28a745; }
        .timeline-event.medium .timeline-marker { border-color: #ffc107; }
        .timeline-event.high .timeline-marker { border-color: #fd7e14; }
        .timeline-event.critical .timeline-marker { border-color: #dc3545; }
        
        .event-time {
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
        }
        
        .event-title {
            font-size: 1.2em;
            font-weight: bold;
            margin: 5px 0;
        }
        
        .event-description {
            color: #666;
            margin: 5px 0;
        }
        
        .event-duration {
            font-size: 0.8em;
            color: #999;
            font-style: italic;
        }
        </style>
'''
        
        return timeline_html
    
    def _generate_html_heat_map(self, servers: List[MCPServerInfo], threat_analyses: List[ThreatAnalysis]) -> str:
        """Generate HTML/CSS risk heat map."""
        
        # Create risk matrix
        risk_matrix = []
        
        for i, server in enumerate(servers[:20]):  # Limit to 20 servers
            threat_analysis = threat_analyses[i] if i < len(threat_analyses) else None
            
            if threat_analysis:
                risk_level = self._calculate_risk_score(threat_analysis)
                risk_class = self._get_risk_class(risk_level)
            else:
                risk_level = 0
                risk_class = "unknown"
            
            risk_matrix.append({
                'name': server.name[:15] + "..." if len(server.name) > 15 else server.name,
                'full_name': server.name,
                'risk_level': risk_level,
                'risk_class': risk_class,
                'port': getattr(server, 'port', 'N/A'),
                'transport': getattr(server, 'transport_type', 'Unknown')
            })
        
        # Generate HTML heat map grid
        heat_map_html = '''
        <div class="risk-heat-map">
            <div class="heat-map-grid">
'''
        
        for server in risk_matrix:
            heat_map_html += f'''
                <div class="heat-map-cell {server['risk_class']}" 
                     title="{server['full_name']} - Risk Level: {server['risk_level']}/10">
                    <div class="cell-name">{server['name']}</div>
                    <div class="cell-risk">{server['risk_level']}</div>
                    <div class="cell-info">
                        <div>Port: {server['port']}</div>
                        <div>Transport: {server['transport']}</div>
                    </div>
                </div>
'''
        
        heat_map_html += '''
            </div>
        </div>
        
        <style>
        .risk-heat-map {
            padding: 20px;
        }
        
        .heat-map-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            max-width: 1200px;
        }
        
        .heat-map-cell {
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.2s;
            cursor: pointer;
            position: relative;
        }
        
        .heat-map-cell:hover {
            transform: scale(1.05);
            z-index: 10;
        }
        
        .heat-map-cell.critical {
            background: linear-gradient(135deg, #dc3545, #a71e2a);
            color: white;
        }
        
        .heat-map-cell.high {
            background: linear-gradient(135deg, #fd7e14, #e55100);
            color: white;
        }
        
        .heat-map-cell.medium {
            background: linear-gradient(135deg, #ffc107, #ff8f00);
            color: black;
        }
        
        .heat-map-cell.low {
            background: linear-gradient(135deg, #28a745, #1e7e34);
            color: white;
        }
        
        .heat-map-cell.unknown {
            background: linear-gradient(135deg, #6c757d, #495057);
            color: white;
        }
        
        .cell-name {
            font-weight: bold;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .cell-risk {
            font-size: 1.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .cell-info {
            font-size: 0.7em;
            opacity: 0.8;
        }
        
        .heat-map-cell:hover .cell-info {
            opacity: 1;
        }
        </style>
'''
        
        return heat_map_html
    
    def _generate_mermaid_attack_tree(self, attack_vectors: List[AttackVector]) -> str:
        """Generate Mermaid attack tree diagram."""
        
        mermaid_code = """graph TD
    Goal[System Compromise] --> OR1{OR}
"""
        
        # Add attack vectors as paths to the goal
        for i, vector in enumerate(attack_vectors[:6], 1):  # Limit to 6 vectors
            vector_id = f"Vector{i}"
            severity_class = vector.severity.value.lower()
            
            mermaid_code += f"""
    OR1 --> {vector_id}["{vector.vector_type}"]
    {vector_id} --> Steps{i}["{vector.description[:30]}..."]
    
    class {vector_id} {severity_class}
"""
        
        # Add class definitions
        mermaid_code += """
    class Goal goal
    class OR1 logic
    
    classDef goal fill:#ff4444,stroke:#cc0000,stroke-width:3px,color:#fff
    classDef logic fill:#4444ff,stroke:#0000cc,stroke-width:2px,color:#fff
    classDef critical fill:#ff4444,stroke:#cc0000,stroke-width:3px,color:#fff
    classDef high fill:#ff8800,stroke:#cc4400,stroke-width:2px,color:#fff
    classDef medium fill:#ffcc00,stroke:#cc8800,stroke-width:2px,color:#000
    classDef low fill:#88cc00,stroke:#448800,stroke-width:1px,color:#000
"""
        
        return mermaid_code
    
    def _generate_mermaid_topology(self, environment_context: EnvironmentContext, servers: List[MCPServerInfo]) -> str:
        """Generate Mermaid network topology diagram."""
        
        mermaid_code = """graph LR
    Internet[Internet] --> Firewall[Firewall]
    Firewall --> DMZ[DMZ Network]
    Firewall --> Internal[Internal Network]
"""
        
        # Add servers to appropriate network zones
        for i, server in enumerate(servers[:8], 1):  # Limit to 8 servers
            server_id = f"Server{i}"
            server_name = server.name[:20] + "..." if len(server.name) > 20 else server.name
            
            # Determine network placement based on server characteristics
            if hasattr(server, 'transport_type') and server.transport_type in ['http', 'https']:
                network = "DMZ"
            else:
                network = "Internal"
            
            mermaid_code += f"""
    {network} --> {server_id}["{server_name}"]
"""
        
        # Add potential attack paths
        mermaid_code += """
    Internet -.->|"Attack Path"| DMZ
    DMZ -.->|"Lateral Movement"| Internal
    
    classDef network fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef server fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef security fill:#e8f5e8,stroke:#388e3c,stroke-width:2px
    classDef attack stroke:#d32f2f,stroke-width:2px,stroke-dasharray: 5 5
    
    class DMZ,Internal network
    class Firewall security
"""
        
        # Add server classes
        for i in range(1, min(9, len(servers) + 1)):
            mermaid_code += f"    class Server{i} server\n"
        
        return mermaid_code
    
    def _get_attack_flow_legend(self) -> Dict[str, str]:
        """Get legend for attack flow diagrams."""
        return {
            "🔴": "Critical severity attack",
            "🟠": "High severity attack",
            "🟡": "Medium severity attack", 
            "🟢": "Low severity attack",
            "➡️": "Attack progression",
            "⚠️": "High-risk stage",
            "🎯": "Primary target"
        }
    
    def _get_attack_tree_legend(self) -> Dict[str, str]:
        """Get legend for attack tree diagrams."""
        return {
            "🎯": "Attack goal",
            "⚡": "OR gate (any path succeeds)",
            "🔗": "AND gate (all paths required)",
            "🔴": "Critical attack vector",
            "🟠": "High risk vector",
            "🟡": "Medium risk vector",
            "🟢": "Low risk vector"
        }
    
    def _calculate_risk_score(self, threat_analysis: ThreatAnalysis) -> int:
        """Calculate numerical risk score from threat analysis."""
        base_score = {
            ThreatLevel.MINIMAL: 1,
            ThreatLevel.LOW: 3,
            ThreatLevel.MEDIUM: 5,
            ThreatLevel.HIGH: 8,
            ThreatLevel.CRITICAL: 10
        }
        
        score = base_score.get(threat_analysis.threat_level, 5)
        
        # Adjust based on number of attack vectors
        if threat_analysis.attack_vectors:
            vector_bonus = min(len(threat_analysis.attack_vectors), 3)
            score = min(10, score + vector_bonus)
        
        return score
    
    def _get_risk_class(self, risk_score: int) -> str:
        """Get CSS class for risk level."""
        if risk_score >= 9:
            return "critical"
        elif risk_score >= 7:
            return "high" 
        elif risk_score >= 4:
            return "medium"
        elif risk_score >= 1:
            return "low"
        else:
            return "unknown"
    
    def _initialize_color_schemes(self):
        """Initialize color schemes for different diagram styles."""
        self.color_schemes = {
            DiagramStyle.PROFESSIONAL: {
                "primary": "#2E86C1",
                "secondary": "#F39C12", 
                "danger": "#E74C3C",
                "success": "#27AE60",
                "warning": "#F1C40F"
            },
            DiagramStyle.DARK_THEME: {
                "primary": "#3498DB",
                "secondary": "#E67E22",
                "danger": "#E74C3C", 
                "success": "#2ECC71",
                "warning": "#F39C12"
            },
            DiagramStyle.SECURITY_FOCUSED: {
                "primary": "#C0392B",
                "secondary": "#8E44AD",
                "danger": "#E74C3C",
                "success": "#27AE60", 
                "warning": "#F39C12"
            }
        }
    
    def _initialize_templates(self):
        """Initialize diagram templates."""
        self.diagram_templates = {
            DiagramType.ATTACK_FLOW: "graph TD",
            DiagramType.NETWORK_TOPOLOGY: "graph LR",
            DiagramType.ATTACK_TREE: "graph TD"
        }
    
    # Placeholder methods for additional diagram formats
    def _generate_graphviz_attack_flow(self, threat_analysis: ThreatAnalysis) -> str:
        """Generate Graphviz attack flow diagram."""
        return "digraph G { /* Graphviz implementation */ }"
    
    def _generate_json_attack_flow(self, threat_analysis: ThreatAnalysis) -> str:
        """Generate JSON representation of attack flow."""
        return json.dumps({"type": "attack_flow", "data": "JSON implementation"}, indent=2)
    
    def _generate_mermaid_timeline(self, threat_analysis: ThreatAnalysis, time_window: int) -> str:
        """Generate Mermaid timeline diagram."""
        return "gantt\n    title Attack Timeline\n    section Phase 1\n    Reconnaissance: 0, 2h"
    
    def _generate_json_timeline(self, threat_analysis: ThreatAnalysis, time_window: int) -> str:
        """Generate JSON timeline representation."""
        return json.dumps({"type": "timeline", "window": time_window}, indent=2)
    
    def _generate_svg_heat_map(self, servers: List[MCPServerInfo], threat_analyses: List[ThreatAnalysis]) -> str:
        """Generate SVG heat map."""
        return '<svg width="400" height="300"><!-- SVG heat map implementation --></svg>'
    
    def _generate_json_heat_map(self, servers: List[MCPServerInfo], threat_analyses: List[ThreatAnalysis]) -> str:
        """Generate JSON heat map representation."""
        return json.dumps({"type": "heat_map", "servers": len(servers)}, indent=2)
    
    def _generate_graphviz_attack_tree(self, attack_vectors: List[AttackVector]) -> str:
        """Generate Graphviz attack tree."""
        return "digraph AttackTree { /* Graphviz attack tree */ }"
    
    def _generate_json_attack_tree(self, attack_vectors: List[AttackVector]) -> str:
        """Generate JSON attack tree representation."""
        return json.dumps({"type": "attack_tree", "vectors": len(attack_vectors)}, indent=2)
    
    def _generate_graphviz_topology(self, environment_context: EnvironmentContext, servers: List[MCPServerInfo]) -> str:
        """Generate Graphviz topology diagram."""
        return "digraph Topology { /* Graphviz topology */ }"
    
    def _generate_json_topology(self, environment_context: EnvironmentContext, servers: List[MCPServerInfo]) -> str:
        """Generate JSON topology representation."""
        return json.dumps({"type": "topology", "servers": len(servers)}, indent=2) 