"""
Enhanced Introspection Reporter for Dynamic MCP Data Analysis.

This module provides specialized reporting capabilities for MCP introspection data,
including detailed analysis of tools, resources, capabilities, and security risks
discovered through dynamic introspection.
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from .base import BaseReporter, ReportData, ReportFormat, ReportType
from ..detection.mcp_introspection.models import (
    MCPServerInfo, MCPTool, MCPResource, MCPCapabilities, 
    RiskLevel, TransportType, RiskCategory, SecurityRisk
)
from ..utils.logging import get_logger


class IntrospectionReporter(BaseReporter):
    """
    Specialized reporter for MCP introspection data.
    
    Generates comprehensive reports focusing on dynamically discovered
    MCP server capabilities, tools, resources, and security analysis.
    """
    
    def __init__(self, settings=None):
        """Initialize the introspection reporter."""
        super().__init__(settings)
        self.logger = get_logger(__name__)
    
    def get_format(self) -> ReportFormat:
        """Get the report format."""
        return ReportFormat.JSON
    
    def generate_report(self, data: ReportData, output_path: Optional[Path] = None) -> str:
        """
        Generate comprehensive introspection report.
        
        Args:
            data: Report data containing introspection information
            output_path: Optional output file path
            
        Returns:
            Generated report content as string
        """
        start_time = datetime.now()
        
        try:
            # Validate introspection data
            self.validate_data(data)
            
            # Generate comprehensive analysis
            analysis = self._generate_introspection_analysis(data)
            
            # Create report structure
            report = {
                "metadata": data.metadata.to_dict(),
                "introspection_analysis": analysis,
                "generation_info": {
                    "generated_at": start_time.isoformat(),
                    "generator": "HawkEye Introspection Reporter",
                    "version": "1.0.0"
                }
            }
            
            # Convert to JSON
            report_content = json.dumps(report, indent=2, default=str)
            
            # Write to file if path provided
            if output_path:
                output_path = self._create_output_path(output_path, data)
                output_path.write_text(report_content, encoding='utf-8')
                self.logger.info(f"Introspection report written to {output_path}")
            
            # Update statistics
            generation_time = (datetime.now() - start_time).total_seconds()
            self._update_statistics(True, generation_time)
            
            return report_content
            
        except Exception as e:
            generation_time = (datetime.now() - start_time).total_seconds()
            self._update_statistics(False, generation_time)
            self.logger.error(f"Failed to generate introspection report: {e}")
            raise
    
    def _generate_introspection_analysis(self, data: ReportData) -> Dict[str, Any]:
        """Generate comprehensive introspection analysis."""
        
        # Get all introspected servers
        servers = data.introspected_servers
        
        # Generate analysis sections
        analysis = {
            "executive_summary": self._generate_executive_summary(data, servers),
            "server_analysis": self._analyze_servers(servers),
            "tool_analysis": self._analyze_tools(servers),
            "resource_analysis": self._analyze_resources(servers),
            "capability_analysis": self._analyze_capabilities(servers),
            "security_analysis": self._analyze_security_risks(servers),
            "risk_assessment": self._generate_risk_assessment(servers),
            "recommendations": self._generate_recommendations(servers),
            "detailed_findings": self._generate_detailed_findings(servers)
        }
        
        return analysis
    
    def _generate_executive_summary(self, data: ReportData, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Generate executive summary of introspection findings."""
        
        total_servers = len(servers)
        total_tools = sum(server.get_tool_count() for server in servers)
        total_resources = sum(server.get_resource_count() for server in servers)
        
        # Risk distribution
        risk_distribution = {level.value: 0 for level in RiskLevel}
        for server in servers:
            risk_level = server.overall_risk_level
            if hasattr(risk_level, 'value'):
                risk_distribution[risk_level.value] += 1
            else:
                risk_distribution[str(risk_level)] += 1
        
        # High-risk findings
        high_risk_servers = [
            server for server in servers 
            if server.overall_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]
        
        # Key findings
        key_findings = []
        if high_risk_servers:
            key_findings.append(f"{len(high_risk_servers)} servers identified with high or critical risk levels")
        
        if total_tools > 0:
            dangerous_tools = self._count_dangerous_tools(servers)
            if dangerous_tools > 0:
                key_findings.append(f"{dangerous_tools} potentially dangerous tools discovered")
        
        # Security status
        if risk_distribution.get('critical', 0) > 0:
            security_status = "CRITICAL"
        elif risk_distribution.get('high', 0) > 0:
            security_status = "HIGH RISK"
        elif risk_distribution.get('medium', 0) > 0:
            security_status = "MEDIUM RISK"
        else:
            security_status = "LOW RISK"
        
        return {
            "total_servers_introspected": total_servers,
            "total_tools_discovered": total_tools,
            "total_resources_discovered": total_resources,
            "security_status": security_status,
            "risk_distribution": risk_distribution,
            "high_risk_servers_count": len(high_risk_servers),
            "key_findings": key_findings,
            "introspection_success_rate": data.introspection_summary.success_rate if data.introspection_summary else 0.0
        }
    
    def _analyze_servers(self, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Analyze server characteristics and patterns."""
        
        if not servers:
            return {"total_servers": 0, "analysis": "No servers available for analysis"}
        
        # Server categorization
        server_categories = {}
        
        for server in servers:
            # Categorize by tools
            tool_names = [tool.name for tool in server.tools]
            if any('file' in name.lower() for name in tool_names):
                server_categories['file_access'] = server_categories.get('file_access', 0) + 1
            if any('web' in name.lower() or 'http' in name.lower() for name in tool_names):
                server_categories['web_access'] = server_categories.get('web_access', 0) + 1
            if any('database' in name.lower() or 'sql' in name.lower() for name in tool_names):
                server_categories['database'] = server_categories.get('database', 0) + 1
        
        # Most common tools
        tool_frequency = {}
        for server in servers:
            for tool in server.tools:
                tool_frequency[tool.name] = tool_frequency.get(tool.name, 0) + 1
        
        most_common_tools = sorted(tool_frequency.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_servers": len(servers),
            "server_categories": server_categories,
            "most_common_tools": most_common_tools,
            "average_tools_per_server": sum(len(s.tools) for s in servers) / len(servers) if servers else 0,
            "average_resources_per_server": sum(len(s.resources) for s in servers) / len(servers) if servers else 0
        }
    
    def _analyze_tools(self, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Analyze discovered tools and their characteristics."""
        
        all_tools = []
        for server in servers:
            all_tools.extend(server.tools)
        
        if not all_tools:
            return {"total_tools": 0, "analysis": "No tools discovered"}
        
        # Tool categorization
        categories = {
            "file_operations": [],
            "network_operations": [],
            "data_processing": [],
            "system_operations": [],
            "external_apis": [],
            "unknown": []
        }
        
        for tool in all_tools:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
            
            if any(keyword in name_lower or keyword in desc_lower 
                   for keyword in ['file', 'read', 'write', 'directory', 'path']):
                categories["file_operations"].append(tool)
            elif any(keyword in name_lower or keyword in desc_lower 
                     for keyword in ['http', 'web', 'api', 'request', 'url']):
                categories["network_operations"].append(tool)
            elif any(keyword in name_lower or keyword in desc_lower 
                     for keyword in ['data', 'process', 'parse', 'convert']):
                categories["data_processing"].append(tool)
            elif any(keyword in name_lower or keyword in desc_lower 
                     for keyword in ['system', 'execute', 'command', 'shell']):
                categories["system_operations"].append(tool)
            elif any(keyword in name_lower or keyword in desc_lower 
                     for keyword in ['external', 'service', 'cloud']):
                categories["external_apis"].append(tool)
            else:
                categories["unknown"].append(tool)
        
        # Risk analysis
        high_risk_tools = []
        for tool in all_tools:
            if self._is_high_risk_tool(tool):
                high_risk_tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "risk_factors": self._get_tool_risk_factors(tool)
                })
        
        return {
            "total_tools": len(all_tools),
            "categories": {k: len(v) for k, v in categories.items()},
            "detailed_categories": {
                k: [{"name": t.name, "description": t.description} for t in v[:5]]  # Top 5 per category
                for k, v in categories.items()
            },
            "high_risk_tools": high_risk_tools,
            "unique_tool_names": len(set(tool.name for tool in all_tools)),
            "tools_with_parameters": len([tool for tool in all_tools if tool.parameters])
        }
    
    def _analyze_resources(self, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Analyze discovered resources and their characteristics."""
        
        all_resources = []
        for server in servers:
            all_resources.extend(server.resources)
        
        if not all_resources:
            return {"total_resources": 0, "analysis": "No resources discovered"}
        
        # Resource type analysis
        mime_types = {}
        uri_schemes = {}
        
        for resource in all_resources:
            if resource.mime_type:
                mime_types[resource.mime_type] = mime_types.get(resource.mime_type, 0) + 1
            
            if resource.uri:
                scheme = resource.uri.split('://')[0] if '://' in resource.uri else 'unknown'
                uri_schemes[scheme] = uri_schemes.get(scheme, 0) + 1
        
        return {
            "total_resources": len(all_resources),
            "mime_type_distribution": mime_types,
            "uri_scheme_distribution": uri_schemes,
            "unique_resource_names": len(set(resource.name for resource in all_resources)),
            "resources_with_descriptions": len([r for r in all_resources if r.description])
        }
    
    def _analyze_capabilities(self, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Analyze server capabilities."""
        
        if not servers:
            return {"analysis": "No servers available for capability analysis"}
        
        # Aggregate capabilities
        capability_counts = {}
        for server in servers:
            for capability in server.capabilities:
                capability_counts[capability.name] = capability_counts.get(capability.name, 0) + 1
        
        return {
            "total_unique_capabilities": len(capability_counts),
            "capability_distribution": capability_counts,
            "servers_with_capabilities": len([s for s in servers if s.capabilities])
        }
    
    def _analyze_security_risks(self, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Analyze security risks across all servers."""
        
        all_risks = []
        for server in servers:
            all_risks.extend(server.security_risks)
        
        if not all_risks:
            return {"total_risks": 0, "analysis": "No security risks identified"}
        
        # Risk categorization
        risk_by_category = {}
        risk_by_severity = {}
        
        for risk in all_risks:
            category = risk.category
            severity = risk.severity.value if hasattr(risk.severity, 'value') else str(risk.severity)
            
            risk_by_category[category] = risk_by_category.get(category, 0) + 1
            risk_by_severity[severity] = risk_by_severity.get(severity, 0) + 1
        
        # Critical risks
        critical_risks = [
            {
                "category": risk.category,
                "description": risk.description,
                "mitigation": risk.mitigation
            }
            for risk in all_risks 
            if risk.severity == RiskLevel.CRITICAL
        ]
        
        return {
            "total_risks": len(all_risks),
            "risk_by_category": risk_by_category,
            "risk_by_severity": risk_by_severity,
            "critical_risks": critical_risks,
            "servers_with_risks": len([s for s in servers if s.security_risks])
        }
    
    def _generate_risk_assessment(self, servers: List[MCPServerInfo]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment."""
        
        if not servers:
            return {"overall_risk": "UNKNOWN", "assessment": "No servers to assess"}
        
        # Calculate overall risk
        risk_scores = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.MINIMAL: 1
        }
        
        total_score = 0
        for server in servers:
            risk_level = server.overall_risk_level
            total_score += risk_scores.get(risk_level, 1)
        
        average_score = total_score / len(servers)
        
        if average_score >= 4.5:
            overall_risk = "CRITICAL"
        elif average_score >= 3.5:
            overall_risk = "HIGH"
        elif average_score >= 2.5:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        # Risk factors
        risk_factors = []
        if any(server.overall_risk_level == RiskLevel.CRITICAL for server in servers):
            risk_factors.append("Critical risk servers detected")
        
        dangerous_tool_count = self._count_dangerous_tools(servers)
        if dangerous_tool_count > 0:
            risk_factors.append(f"{dangerous_tool_count} potentially dangerous tools")
        
        return {
            "overall_risk": overall_risk,
            "average_risk_score": average_score,
            "risk_factors": risk_factors,
            "servers_by_risk": {
                level.value: len([s for s in servers if s.overall_risk_level == level])
                for level in RiskLevel
            }
        }
    
    def _generate_recommendations(self, servers: List[MCPServerInfo]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings."""
        
        recommendations = []
        
        # High-risk server recommendations
        high_risk_servers = [s for s in servers if s.overall_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        if high_risk_servers:
            recommendations.append({
                "priority": "HIGH",
                "category": "Risk Mitigation",
                "title": "Address High-Risk Servers",
                "description": f"Review and secure {len(high_risk_servers)} servers with high or critical risk levels",
                "affected_servers": [s.server_id for s in high_risk_servers]
            })
        
        # Dangerous tools recommendations
        dangerous_tools = self._count_dangerous_tools(servers)
        if dangerous_tools > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Tool Security",
                "title": "Review Dangerous Tools",
                "description": f"Audit {dangerous_tools} potentially dangerous tools for security implications",
                "details": "Focus on file system access, code execution, and network tools"
            })
        
        # General recommendations
        recommendations.extend([
            {
                "priority": "LOW",
                "category": "Monitoring",
                "title": "Implement Continuous Monitoring",
                "description": "Set up regular introspection scans to detect changes in MCP server configurations"
            },
            {
                "priority": "LOW",
                "category": "Documentation",
                "title": "Document MCP Server Inventory",
                "description": "Maintain an inventory of all discovered MCP servers and their capabilities"
            }
        ])
        
        return recommendations
    
    def _generate_detailed_findings(self, servers: List[MCPServerInfo]) -> List[Dict[str, Any]]:
        """Generate detailed findings for each server."""
        
        findings = []
        
        for server in servers:
            finding = {
                "server_id": server.server_id,
                "discovery_timestamp": server.discovery_timestamp.isoformat(),
                "risk_level": server.overall_risk_level.value if hasattr(server.overall_risk_level, 'value') else str(server.overall_risk_level),
                "tools_count": len(server.tools),
                "resources_count": len(server.resources),
                "capabilities_count": len(server.capabilities),
                "security_risks_count": len(server.security_risks),
                "notable_tools": [
                    {"name": tool.name, "description": tool.description}
                    for tool in server.tools[:5]  # Top 5 tools
                ],
                "security_concerns": [
                    {"category": risk.category, "severity": risk.severity.value if hasattr(risk.severity, 'value') else str(risk.severity), "description": risk.description}
                    for risk in server.security_risks
                    if risk.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]
                ]
            }
            findings.append(finding)
        
        return findings
    
    def _count_dangerous_tools(self, servers: List[MCPServerInfo]) -> int:
        """Count potentially dangerous tools across all servers."""
        count = 0
        for server in servers:
            for tool in server.tools:
                if self._is_high_risk_tool(tool):
                    count += 1
        return count
    
    def _is_high_risk_tool(self, tool: MCPTool) -> bool:
        """Determine if a tool is potentially high risk."""
        name_lower = tool.name.lower()
        desc_lower = tool.description.lower()
        
        high_risk_keywords = [
            'execute', 'shell', 'command', 'system', 'file', 'write', 'delete',
            'modify', 'create', 'network', 'http', 'request', 'api', 'external'
        ]
        
        return any(keyword in name_lower or keyword in desc_lower for keyword in high_risk_keywords)
    
    def _get_tool_risk_factors(self, tool: MCPTool) -> List[str]:
        """Get risk factors for a specific tool."""
        factors = []
        name_lower = tool.name.lower()
        desc_lower = tool.description.lower()
        
        if 'execute' in name_lower or 'execute' in desc_lower:
            factors.append("Code execution capability")
        if 'file' in name_lower or 'file' in desc_lower:
            factors.append("File system access")
        if 'network' in name_lower or 'http' in desc_lower:
            factors.append("Network access")
        if 'external' in desc_lower:
            factors.append("External service access")
        
        return factors 