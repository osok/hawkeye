"""
Dynamic Tool Risk Analysis for MCP Introspection

Provides comprehensive risk analysis for MCP tools based on their capabilities,
parameters, and potential security implications.
"""

import re
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from ..models import MCPTool, MCPToolParameter, RiskLevel, RiskCategory, SecurityRisk


class ToolRiskPattern(Enum):
    """Predefined risk patterns for tool analysis."""
    FILE_OPERATIONS = "file_operations"
    NETWORK_ACCESS = "network_access"
    CODE_EXECUTION = "code_execution"
    SYSTEM_COMMANDS = "system_commands"
    DATABASE_ACCESS = "database_access"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    EXTERNAL_API = "external_api"
    CLOUD_SERVICES = "cloud_services"
    DATA_MANIPULATION = "data_manipulation"


@dataclass
class RiskIndicator:
    """Risk indicator for tool analysis."""
    pattern: str
    category: RiskCategory
    severity: RiskLevel
    description: str
    confidence: float  # 0.0 to 1.0


class ToolRiskAnalyzer:
    """
    Analyzes MCP tools for security risks and categorizes threats.
    
    Provides dynamic analysis of tool capabilities, parameters, and schemas
    to identify potential security risks and assign appropriate risk levels.
    """
    
    def __init__(self):
        """Initialize the tool risk analyzer."""
        self.logger = logging.getLogger(__name__)
        self._risk_patterns = self._initialize_risk_patterns()
        self._parameter_risks = self._initialize_parameter_risks()
        self._schema_risks = self._initialize_schema_risks()
    
    def analyze_tool(self, tool: MCPTool) -> List[SecurityRisk]:
        """
        Analyze a single tool for security risks.
        
        Args:
            tool: The MCP tool to analyze
            
        Returns:
            List of identified security risks
        """
        risks = []
        
        # Analyze tool name and description
        name_risks = self._analyze_tool_name(tool)
        risks.extend(name_risks)
        
        # Analyze tool description
        desc_risks = self._analyze_tool_description(tool)
        risks.extend(desc_risks)
        
        # Analyze tool parameters
        param_risks = self._analyze_tool_parameters(tool)
        risks.extend(param_risks)
        
        # Analyze input schema
        schema_risks = self._analyze_input_schema(tool)
        risks.extend(schema_risks)
        
        # Analyze metadata
        metadata_risks = self._analyze_tool_metadata(tool)
        risks.extend(metadata_risks)
        
        # Deduplicate and prioritize risks
        unique_risks = self._deduplicate_risks(risks)
        
        self.logger.debug(f"Analyzed tool '{tool.name}': found {len(unique_risks)} risks")
        return unique_risks
    
    def analyze_tools(self, tools: List[MCPTool]) -> Dict[str, List[SecurityRisk]]:
        """
        Analyze multiple tools for security risks.
        
        Args:
            tools: List of MCP tools to analyze
            
        Returns:
            Dictionary mapping tool names to their security risks
        """
        results = {}
        
        for tool in tools:
            try:
                risks = self.analyze_tool(tool)
                results[tool.name] = risks
            except Exception as e:
                self.logger.error(f"Error analyzing tool '{tool.name}': {e}")
                results[tool.name] = [
                    SecurityRisk(
                        category="analysis_error",
                        severity=RiskLevel.UNKNOWN,
                        description=f"Failed to analyze tool: {str(e)}",
                        details={"error": str(e), "tool_name": tool.name}
                    )
                ]
        
        return results
    
    def get_tool_risk_level(self, tool: MCPTool) -> RiskLevel:
        """
        Get the overall risk level for a tool.
        
        Args:
            tool: The MCP tool to assess
            
        Returns:
            Overall risk level for the tool
        """
        risks = self.analyze_tool(tool)
        
        if not risks:
            return RiskLevel.MINIMAL
        
        # Find the highest risk level
        risk_levels = [risk.severity for risk in risks]
        
        if RiskLevel.CRITICAL in risk_levels:
            return RiskLevel.CRITICAL
        elif RiskLevel.HIGH in risk_levels:
            return RiskLevel.HIGH
        elif RiskLevel.MEDIUM in risk_levels:
            return RiskLevel.MEDIUM
        elif RiskLevel.LOW in risk_levels:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def get_risk_categories(self, tool: MCPTool) -> Set[RiskCategory]:
        """
        Get all risk categories for a tool.
        
        Args:
            tool: The MCP tool to assess
            
        Returns:
            Set of risk categories identified for the tool
        """
        risks = self.analyze_tool(tool)
        categories = set()
        
        for risk in risks:
            try:
                category = RiskCategory(risk.category)
                categories.add(category)
            except ValueError:
                # Handle custom categories
                categories.add(RiskCategory.UNKNOWN)
        
        return categories
    
    def _analyze_tool_name(self, tool: MCPTool) -> List[SecurityRisk]:
        """Analyze tool name for risk indicators."""
        risks = []
        name = tool.name.lower()
        
        for pattern, indicators in self._risk_patterns.items():
            for indicator in indicators:
                if re.search(indicator.pattern, name, re.IGNORECASE):
                    risk = SecurityRisk(
                        category=indicator.category.value,
                        severity=indicator.severity,
                        description=f"Tool name indicates {indicator.description}",
                        details={
                            "pattern": indicator.pattern,
                            "confidence": indicator.confidence,
                            "source": "tool_name",
                            "matched_text": name
                        }
                    )
                    risks.append(risk)
        
        return risks
    
    def _analyze_tool_description(self, tool: MCPTool) -> List[SecurityRisk]:
        """Analyze tool description for risk indicators."""
        risks = []
        description = tool.description.lower()
        
        for pattern, indicators in self._risk_patterns.items():
            for indicator in indicators:
                if re.search(indicator.pattern, description, re.IGNORECASE):
                    risk = SecurityRisk(
                        category=indicator.category.value,
                        severity=indicator.severity,
                        description=f"Tool description indicates {indicator.description}",
                        details={
                            "pattern": indicator.pattern,
                            "confidence": indicator.confidence,
                            "source": "tool_description",
                            "matched_text": description
                        }
                    )
                    risks.append(risk)
        
        return risks
    
    def _analyze_tool_parameters(self, tool: MCPTool) -> List[SecurityRisk]:
        """Analyze tool parameters for risk indicators."""
        risks = []
        
        for param in tool.parameters:
            param_risks = self._analyze_parameter(param, tool.name)
            risks.extend(param_risks)
        
        return risks
    
    def _analyze_parameter(self, param: MCPToolParameter, tool_name: str) -> List[SecurityRisk]:
        """Analyze a single parameter for risk indicators."""
        risks = []
        param_name = param.name.lower()
        param_desc = param.description.lower()
        
        # Check parameter name patterns
        for pattern, risk_info in self._parameter_risks.items():
            if re.search(pattern, param_name, re.IGNORECASE):
                risk = SecurityRisk(
                    category=risk_info["category"].value,
                    severity=risk_info["severity"],
                    description=f"Parameter '{param.name}' indicates {risk_info['description']}",
                    details={
                        "parameter_name": param.name,
                        "parameter_type": param.type,
                        "tool_name": tool_name,
                        "pattern": pattern,
                        "source": "parameter_name"
                    }
                )
                risks.append(risk)
        
        # Check parameter description patterns
        for pattern, risk_info in self._parameter_risks.items():
            if re.search(pattern, param_desc, re.IGNORECASE):
                risk = SecurityRisk(
                    category=risk_info["category"].value,
                    severity=risk_info["severity"],
                    description=f"Parameter description indicates {risk_info['description']}",
                    details={
                        "parameter_name": param.name,
                        "parameter_description": param.description,
                        "tool_name": tool_name,
                        "pattern": pattern,
                        "source": "parameter_description"
                    }
                )
                risks.append(risk)
        
        # Check for dangerous parameter types
        if param.type in ["object", "any"] and param.required:
            risk = SecurityRisk(
                category=RiskCategory.DATA_ACCESS.value,
                severity=RiskLevel.MEDIUM,
                description="Required parameter accepts arbitrary data",
                details={
                    "parameter_name": param.name,
                    "parameter_type": param.type,
                    "tool_name": tool_name,
                    "source": "parameter_type"
                }
            )
            risks.append(risk)
        
        return risks
    
    def _analyze_input_schema(self, tool: MCPTool) -> List[SecurityRisk]:
        """Analyze tool input schema for risk indicators."""
        risks = []
        
        if not tool.input_schema:
            return risks
        
        # Analyze schema properties
        properties = tool.input_schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            schema_risks = self._analyze_schema_property(prop_name, prop_schema, tool.name)
            risks.extend(schema_risks)
        
        # Check for overly permissive schemas
        if tool.input_schema.get("additionalProperties", False):
            risk = SecurityRisk(
                category=RiskCategory.DATA_ACCESS.value,
                severity=RiskLevel.MEDIUM,
                description="Schema allows additional properties",
                details={
                    "tool_name": tool.name,
                    "source": "input_schema",
                    "issue": "additional_properties_allowed"
                }
            )
            risks.append(risk)
        
        return risks
    
    def _analyze_schema_property(self, prop_name: str, prop_schema: Dict[str, Any], tool_name: str) -> List[SecurityRisk]:
        """Analyze a single schema property for risks."""
        risks = []
        
        # Check property name patterns
        for pattern, risk_info in self._schema_risks.items():
            if re.search(pattern, prop_name, re.IGNORECASE):
                risk = SecurityRisk(
                    category=risk_info["category"].value,
                    severity=risk_info["severity"],
                    description=f"Schema property '{prop_name}' indicates {risk_info['description']}",
                    details={
                        "property_name": prop_name,
                        "property_schema": prop_schema,
                        "tool_name": tool_name,
                        "pattern": pattern,
                        "source": "schema_property"
                    }
                )
                risks.append(risk)
        
        return risks
    
    def _analyze_tool_metadata(self, tool: MCPTool) -> List[SecurityRisk]:
        """Analyze tool metadata for risk indicators."""
        risks = []
        
        if not tool.metadata:
            return risks
        
        # Check for dangerous metadata keys
        dangerous_keys = ["exec", "command", "shell", "eval", "system", "subprocess"]
        for key in tool.metadata.keys():
            if any(danger in key.lower() for danger in dangerous_keys):
                risk = SecurityRisk(
                    category=RiskCategory.CODE_EXECUTION.value,
                    severity=RiskLevel.HIGH,
                    description=f"Metadata contains potentially dangerous key: {key}",
                    details={
                        "metadata_key": key,
                        "metadata_value": tool.metadata[key],
                        "tool_name": tool.name,
                        "source": "tool_metadata"
                    }
                )
                risks.append(risk)
        
        return risks
    
    def _deduplicate_risks(self, risks: List[SecurityRisk]) -> List[SecurityRisk]:
        """Remove duplicate risks and merge similar ones."""
        unique_risks = []
        seen_risks = set()
        
        for risk in risks:
            # Create a signature for the risk
            signature = (risk.category, risk.severity.value, risk.description)
            
            if signature not in seen_risks:
                seen_risks.add(signature)
                unique_risks.append(risk)
        
        return unique_risks
    
    def _initialize_risk_patterns(self) -> Dict[ToolRiskPattern, List[RiskIndicator]]:
        """Initialize risk patterns for tool analysis."""
        patterns = {
            ToolRiskPattern.FILE_OPERATIONS: [
                RiskIndicator(
                    pattern=r'\b(file|read|write|delete|create|copy|move|rename)\b',
                    category=RiskCategory.FILE_SYSTEM,
                    severity=RiskLevel.MEDIUM,
                    description="file system operations",
                    confidence=0.8
                ),
                RiskIndicator(
                    pattern=r'\b(path|directory|folder|upload|download)\b',
                    category=RiskCategory.FILE_SYSTEM,
                    severity=RiskLevel.MEDIUM,
                    description="file system access",
                    confidence=0.7
                ),
            ],
            ToolRiskPattern.NETWORK_ACCESS: [
                RiskIndicator(
                    pattern=r'\b(http|https|url|request|fetch|download|upload)\b',
                    category=RiskCategory.NETWORK_ACCESS,
                    severity=RiskLevel.MEDIUM,
                    description="network access",
                    confidence=0.8
                ),
                RiskIndicator(
                    pattern=r'\b(api|endpoint|webhook|socket|tcp|udp)\b',
                    category=RiskCategory.NETWORK_ACCESS,
                    severity=RiskLevel.MEDIUM,
                    description="network communication",
                    confidence=0.7
                ),
            ],
            ToolRiskPattern.CODE_EXECUTION: [
                RiskIndicator(
                    pattern=r'\b(exec|execute|run|command|shell|script|eval)\b',
                    category=RiskCategory.CODE_EXECUTION,
                    severity=RiskLevel.HIGH,
                    description="code execution",
                    confidence=0.9
                ),
                RiskIndicator(
                    pattern=r'\b(subprocess|process|spawn|fork|system)\b',
                    category=RiskCategory.CODE_EXECUTION,
                    severity=RiskLevel.HIGH,
                    description="process execution",
                    confidence=0.8
                ),
            ],
            ToolRiskPattern.DATABASE_ACCESS: [
                RiskIndicator(
                    pattern=r'\b(sql|database|db|query|select|insert|update|delete)\b',
                    category=RiskCategory.DATABASE,
                    severity=RiskLevel.MEDIUM,
                    description="database access",
                    confidence=0.8
                ),
                RiskIndicator(
                    pattern=r'\b(mysql|postgres|sqlite|mongodb|redis)\b',
                    category=RiskCategory.DATABASE,
                    severity=RiskLevel.MEDIUM,
                    description="database operations",
                    confidence=0.9
                ),
            ],
            ToolRiskPattern.AUTHENTICATION: [
                RiskIndicator(
                    pattern=r'\b(auth|login|password|token|key|credential|secret)\b',
                    category=RiskCategory.AUTHENTICATION,
                    severity=RiskLevel.HIGH,
                    description="authentication handling",
                    confidence=0.8
                ),
                RiskIndicator(
                    pattern=r'\b(oauth|jwt|session|cookie|bearer)\b',
                    category=RiskCategory.AUTHENTICATION,
                    severity=RiskLevel.MEDIUM,
                    description="authentication mechanisms",
                    confidence=0.7
                ),
            ],
        }
        
        return patterns
    
    def _initialize_parameter_risks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize parameter-specific risk patterns."""
        return {
            r'\b(command|cmd|exec|shell)\b': {
                "category": RiskCategory.CODE_EXECUTION,
                "severity": RiskLevel.HIGH,
                "description": "command execution"
            },
            r'\b(path|file|filename|directory)\b': {
                "category": RiskCategory.FILE_SYSTEM,
                "severity": RiskLevel.MEDIUM,
                "description": "file system access"
            },
            r'\b(url|endpoint|host|server)\b': {
                "category": RiskCategory.NETWORK_ACCESS,
                "severity": RiskLevel.MEDIUM,
                "description": "network access"
            },
            r'\b(password|secret|key|token|credential)\b': {
                "category": RiskCategory.AUTHENTICATION,
                "severity": RiskLevel.HIGH,
                "description": "sensitive credentials"
            },
            r'\b(sql|query|database|db)\b': {
                "category": RiskCategory.DATABASE,
                "severity": RiskLevel.MEDIUM,
                "description": "database operations"
            },
        }
    
    def _initialize_schema_risks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize schema-specific risk patterns."""
        return {
            r'\b(command|cmd|exec|shell|script)\b': {
                "category": RiskCategory.CODE_EXECUTION,
                "severity": RiskLevel.HIGH,
                "description": "command execution"
            },
            r'\b(path|file|filename|directory|folder)\b': {
                "category": RiskCategory.FILE_SYSTEM,
                "severity": RiskLevel.MEDIUM,
                "description": "file system access"
            },
            r'\b(url|endpoint|host|server|api)\b': {
                "category": RiskCategory.NETWORK_ACCESS,
                "severity": RiskLevel.MEDIUM,
                "description": "network access"
            },
            r'\b(password|secret|key|token|credential|auth)\b': {
                "category": RiskCategory.AUTHENTICATION,
                "severity": RiskLevel.HIGH,
                "description": "authentication data"
            },
        } 