"""
Schema-based Security Analysis for MCP Introspection

Provides comprehensive analysis of MCP tool and resource schemas to identify
potential security vulnerabilities and risks based on parameter types and structures.
"""

import logging
import re
from typing import Dict, List, Set, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum

from ..models import (
    MCPTool, MCPResource, MCPToolParameter, SecurityRisk,
    RiskLevel, RiskCategory
)


class SchemaRiskType(str, Enum):
    """Types of schema-based security risks."""
    INJECTION_VULNERABILITY = "injection_vulnerability"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    SCRIPT_INJECTION = "script_injection"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    BUFFER_OVERFLOW = "buffer_overflow"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    WEAK_VALIDATION = "weak_validation"


class ParameterRiskLevel(str, Enum):
    """Risk levels for parameter analysis."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class SchemaRisk:
    """Schema-based security risk."""
    risk_type: SchemaRiskType
    severity: RiskLevel
    parameter_name: str
    parameter_type: str
    description: str
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)  # Common Weakness Enumeration IDs


@dataclass
class SchemaAnalysisResult:
    """Result of schema security analysis."""
    tool_name: str
    total_parameters: int
    risky_parameters: int
    schema_risks: List[SchemaRisk] = field(default_factory=list)
    overall_risk_level: RiskLevel = RiskLevel.MINIMAL
    security_score: float = 0.0  # 0.0 to 10.0
    
    def get_risks_by_type(self, risk_type: SchemaRiskType) -> List[SchemaRisk]:
        """Get all risks of a specific type."""
        return [risk for risk in self.schema_risks if risk.risk_type == risk_type]
    
    def get_critical_risks(self) -> List[SchemaRisk]:
        """Get all critical severity risks."""
        return [risk for risk in self.schema_risks if risk.severity == RiskLevel.CRITICAL]


class SchemaAnalyzer:
    """
    Analyzes MCP tool and resource schemas for security vulnerabilities.
    
    Examines parameter types, validation patterns, and schema structures
    to identify potential security risks and attack vectors.
    """
    
    def __init__(self):
        """Initialize the schema analyzer."""
        self.logger = logging.getLogger(__name__)
        self._risk_patterns = self._initialize_risk_patterns()
        self._dangerous_types = self._initialize_dangerous_types()
        self._injection_patterns = self._initialize_injection_patterns()
        self._validation_patterns = self._initialize_validation_patterns()
    
    def analyze_tool_schema(self, tool: MCPTool) -> SchemaAnalysisResult:
        """
        Analyze a tool's schema for security risks.
        
        Args:
            tool: MCP tool to analyze
            
        Returns:
            Schema analysis result with identified risks
        """
        result = SchemaAnalysisResult(
            tool_name=tool.name,
            total_parameters=len(tool.parameters),
            risky_parameters=0
        )
        
        # Analyze each parameter
        for param in tool.parameters:
            param_risks = self._analyze_parameter_schema(param, tool.name)
            result.schema_risks.extend(param_risks)
            
            if param_risks:
                result.risky_parameters += 1
        
        # Analyze input schema if available
        if hasattr(tool, 'input_schema') and tool.input_schema:
            schema_risks = self._analyze_input_schema(tool.input_schema, tool.name)
            result.schema_risks.extend(schema_risks)
        
        # Calculate overall risk level and security score
        result.overall_risk_level = self._calculate_overall_risk_level(result.schema_risks)
        result.security_score = self._calculate_security_score(result)
        
        self.logger.info(f"Analyzed schema for tool '{tool.name}': "
                        f"{len(result.schema_risks)} risks found, "
                        f"risk level: {result.overall_risk_level.value}")
        
        return result
    
    def analyze_multiple_tools(self, tools: List[MCPTool]) -> Dict[str, SchemaAnalysisResult]:
        """
        Analyze schemas for multiple tools.
        
        Args:
            tools: List of MCP tools to analyze
            
        Returns:
            Dictionary mapping tool names to their analysis results
        """
        results = {}
        
        for tool in tools:
            try:
                result = self.analyze_tool_schema(tool)
                results[tool.name] = result
            except Exception as e:
                self.logger.error(f"Error analyzing schema for tool '{tool.name}': {e}")
                # Create minimal result with error
                results[tool.name] = SchemaAnalysisResult(
                    tool_name=tool.name,
                    total_parameters=len(tool.parameters),
                    risky_parameters=0,
                    schema_risks=[
                        SchemaRisk(
                            risk_type=SchemaRiskType.WEAK_VALIDATION,
                            severity=RiskLevel.UNKNOWN,
                            parameter_name="analysis_error",
                            parameter_type="unknown",
                            description=f"Failed to analyze schema: {str(e)}",
                            evidence=[str(e)]
                        )
                    ],
                    overall_risk_level=RiskLevel.UNKNOWN
                )
        
        return results
    
    def analyze_resource_schema(self, resource: MCPResource) -> List[SchemaRisk]:
        """
        Analyze a resource's schema for security risks.
        
        Args:
            resource: MCP resource to analyze
            
        Returns:
            List of identified schema risks
        """
        risks = []
        
        # Analyze resource URI for risks
        uri_risks = self._analyze_resource_uri(resource)
        risks.extend(uri_risks)
        
        # Analyze resource metadata if available
        if hasattr(resource, 'metadata') and resource.metadata:
            metadata_risks = self._analyze_resource_metadata(resource)
            risks.extend(metadata_risks)
        
        return risks
    
    def _analyze_parameter_schema(self, param: MCPToolParameter, tool_name: str) -> List[SchemaRisk]:
        """Analyze a single parameter for schema risks."""
        risks = []
        param_name = param.name.lower()
        param_type = getattr(param, 'type', 'string').lower()
        
        # Check for dangerous parameter names
        for pattern, risk_info in self._risk_patterns.items():
            if re.search(pattern, param_name, re.IGNORECASE):
                risk = SchemaRisk(
                    risk_type=risk_info['type'],
                    severity=risk_info['severity'],
                    parameter_name=param.name,
                    parameter_type=param_type,
                    description=f"Parameter name '{param.name}' suggests {risk_info['description']}",
                    evidence=[f"Parameter name matches pattern: {pattern}"],
                    recommendations=risk_info.get('recommendations', []),
                    cwe_ids=risk_info.get('cwe_ids', [])
                )
                risks.append(risk)
        
        # Check for dangerous parameter types
        if param_type in self._dangerous_types:
            type_info = self._dangerous_types[param_type]
            risk = SchemaRisk(
                risk_type=type_info['type'],
                severity=type_info['severity'],
                parameter_name=param.name,
                parameter_type=param_type,
                description=f"Parameter type '{param_type}' {type_info['description']}",
                evidence=[f"Parameter type: {param_type}"],
                recommendations=type_info.get('recommendations', []),
                cwe_ids=type_info.get('cwe_ids', [])
            )
            risks.append(risk)
        
        # Check for injection vulnerabilities
        injection_risks = self._check_injection_vulnerabilities(param, tool_name)
        risks.extend(injection_risks)
        
        # Check for validation weaknesses
        validation_risks = self._check_validation_weaknesses(param)
        risks.extend(validation_risks)
        
        return risks
    
    def _analyze_input_schema(self, schema: Dict[str, Any], tool_name: str) -> List[SchemaRisk]:
        """Analyze input schema for security risks."""
        risks = []
        
        if not isinstance(schema, dict):
            return risks
        
        # Analyze schema properties
        properties = schema.get('properties', {})
        for prop_name, prop_schema in properties.items():
            prop_risks = self._analyze_schema_property(prop_name, prop_schema, tool_name)
            risks.extend(prop_risks)
        
        # Check for missing validation
        if 'required' not in schema or not schema['required']:
            risk = SchemaRisk(
                risk_type=SchemaRiskType.WEAK_VALIDATION,
                severity=RiskLevel.MEDIUM,
                parameter_name="schema",
                parameter_type="object",
                description="Schema lacks required field validation",
                evidence=["No required fields specified in schema"],
                recommendations=[
                    "Define required fields in schema",
                    "Implement proper input validation"
                ],
                cwe_ids=["CWE-20"]
            )
            risks.append(risk)
        
        return risks
    
    def _analyze_schema_property(self, prop_name: str, prop_schema: Dict[str, Any], tool_name: str) -> List[SchemaRisk]:
        """Analyze a schema property for security risks."""
        risks = []
        
        prop_type = prop_schema.get('type', 'string')
        
        # Check for dangerous property patterns
        for pattern, risk_info in self._risk_patterns.items():
            if re.search(pattern, prop_name, re.IGNORECASE):
                risk = SchemaRisk(
                    risk_type=risk_info['type'],
                    severity=risk_info['severity'],
                    parameter_name=prop_name,
                    parameter_type=prop_type,
                    description=f"Schema property '{prop_name}' suggests {risk_info['description']}",
                    evidence=[f"Property name matches pattern: {pattern}"],
                    recommendations=risk_info.get('recommendations', []),
                    cwe_ids=risk_info.get('cwe_ids', [])
                )
                risks.append(risk)
        
        # Check for missing constraints
        if prop_type == 'string' and 'maxLength' not in prop_schema:
            risk = SchemaRisk(
                risk_type=SchemaRiskType.BUFFER_OVERFLOW,
                severity=RiskLevel.MEDIUM,
                parameter_name=prop_name,
                parameter_type=prop_type,
                description=f"String property '{prop_name}' lacks length constraints",
                evidence=["No maxLength constraint specified"],
                recommendations=[
                    "Add maxLength constraint to string properties",
                    "Implement input length validation"
                ],
                cwe_ids=["CWE-120", "CWE-20"]
            )
            risks.append(risk)
        
        # Check for unsafe patterns in property schema
        if 'pattern' in prop_schema:
            pattern_risks = self._analyze_regex_pattern(prop_name, prop_schema['pattern'])
            risks.extend(pattern_risks)
        
        return risks
    
    def _analyze_resource_uri(self, resource: MCPResource) -> List[SchemaRisk]:
        """Analyze resource URI for security risks."""
        risks = []
        uri = resource.uri.lower()
        
        # Check for file:// URIs (potential path traversal)
        if uri.startswith('file://'):
            risk = SchemaRisk(
                risk_type=SchemaRiskType.PATH_TRAVERSAL,
                severity=RiskLevel.HIGH,
                parameter_name="uri",
                parameter_type="string",
                description="File URI may allow path traversal attacks",
                evidence=[f"URI: {resource.uri}"],
                recommendations=[
                    "Validate file paths to prevent directory traversal",
                    "Use chroot or similar containment",
                    "Implement file access controls"
                ],
                cwe_ids=["CWE-22"]
            )
            risks.append(risk)
        
        # Check for dynamic URIs (potential injection)
        if any(char in uri for char in ['${', '{', '}', '$(']):
            risk = SchemaRisk(
                risk_type=SchemaRiskType.INJECTION_VULNERABILITY,
                severity=RiskLevel.HIGH,
                parameter_name="uri",
                parameter_type="string",
                description="Dynamic URI may allow injection attacks",
                evidence=[f"URI contains dynamic elements: {resource.uri}"],
                recommendations=[
                    "Validate and sanitize dynamic URI components",
                    "Use parameterized URI construction",
                    "Implement strict input validation"
                ],
                cwe_ids=["CWE-74"]
            )
            risks.append(risk)
        
        return risks
    
    def _analyze_resource_metadata(self, resource: MCPResource) -> List[SchemaRisk]:
        """Analyze resource metadata for security risks."""
        risks = []
        
        # This would analyze metadata if present
        # Implementation depends on specific metadata structure
        
        return risks
    
    def _check_injection_vulnerabilities(self, param: MCPToolParameter, tool_name: str) -> List[SchemaRisk]:
        """Check parameter for injection vulnerabilities."""
        risks = []
        param_name = param.name.lower()
        
        # Check for SQL injection patterns
        if any(pattern in param_name for pattern in ['query', 'sql', 'select', 'where', 'table']):
            risk = SchemaRisk(
                risk_type=SchemaRiskType.SQL_INJECTION,
                severity=RiskLevel.HIGH,
                parameter_name=param.name,
                parameter_type=getattr(param, 'type', 'string'),
                description=f"Parameter '{param.name}' may be vulnerable to SQL injection",
                evidence=[f"Parameter name suggests SQL usage: {param.name}"],
                recommendations=[
                    "Use parameterized queries",
                    "Implement SQL input validation",
                    "Apply principle of least privilege for database access"
                ],
                cwe_ids=["CWE-89"]
            )
            risks.append(risk)
        
        # Check for command injection patterns
        if any(pattern in param_name for pattern in ['command', 'cmd', 'exec', 'shell', 'script']):
            risk = SchemaRisk(
                risk_type=SchemaRiskType.COMMAND_INJECTION,
                severity=RiskLevel.CRITICAL,
                parameter_name=param.name,
                parameter_type=getattr(param, 'type', 'string'),
                description=f"Parameter '{param.name}' may be vulnerable to command injection",
                evidence=[f"Parameter name suggests command execution: {param.name}"],
                recommendations=[
                    "Use parameterized command execution",
                    "Implement strict input validation",
                    "Use command whitelisting",
                    "Apply sandboxing or containerization"
                ],
                cwe_ids=["CWE-78"]
            )
            risks.append(risk)
        
        # Check for script injection patterns
        if any(pattern in param_name for pattern in ['script', 'code', 'eval', 'expression']):
            risk = SchemaRisk(
                risk_type=SchemaRiskType.SCRIPT_INJECTION,
                severity=RiskLevel.HIGH,
                parameter_name=param.name,
                parameter_type=getattr(param, 'type', 'string'),
                description=f"Parameter '{param.name}' may be vulnerable to script injection",
                evidence=[f"Parameter name suggests script execution: {param.name}"],
                recommendations=[
                    "Avoid dynamic script execution",
                    "Use safe evaluation methods",
                    "Implement strict input validation",
                    "Use sandboxing for script execution"
                ],
                cwe_ids=["CWE-94"]
            )
            risks.append(risk)
        
        return risks
    
    def _check_validation_weaknesses(self, param: MCPToolParameter) -> List[SchemaRisk]:
        """Check parameter for validation weaknesses."""
        risks = []
        
        # Check if parameter has validation constraints
        has_constraints = any(hasattr(param, attr) for attr in ['min_length', 'max_length', 'pattern', 'enum'])
        
        if not has_constraints:
            risk = SchemaRisk(
                risk_type=SchemaRiskType.WEAK_VALIDATION,
                severity=RiskLevel.MEDIUM,
                parameter_name=param.name,
                parameter_type=getattr(param, 'type', 'string'),
                description=f"Parameter '{param.name}' lacks validation constraints",
                evidence=["No validation constraints found"],
                recommendations=[
                    "Add appropriate validation constraints",
                    "Implement input sanitization",
                    "Define acceptable value ranges"
                ],
                cwe_ids=["CWE-20"]
            )
            risks.append(risk)
        
        return risks
    
    def _analyze_regex_pattern(self, prop_name: str, pattern: str) -> List[SchemaRisk]:
        """Analyze regex pattern for security issues."""
        risks = []
        
        # Check for ReDoS (Regular Expression Denial of Service) patterns
        redos_patterns = [
            r'\(\.\*\)\+',  # (.*)+
            r'\(\.\+\)\+',  # (.+)+
            r'\(\.\*\)\*',  # (.*)* 
            r'\(\.\+\)\*',  # (.+)*
        ]
        
        for redos_pattern in redos_patterns:
            if re.search(redos_pattern, pattern):
                risk = SchemaRisk(
                    risk_type=SchemaRiskType.WEAK_VALIDATION,
                    severity=RiskLevel.MEDIUM,
                    parameter_name=prop_name,
                    parameter_type="string",
                    description=f"Regex pattern may be vulnerable to ReDoS attacks",
                    evidence=[f"Pattern: {pattern}", f"Vulnerable pattern: {redos_pattern}"],
                    recommendations=[
                        "Review regex pattern for ReDoS vulnerabilities",
                        "Use atomic grouping or possessive quantifiers",
                        "Implement regex timeout limits"
                    ],
                    cwe_ids=["CWE-1333"]
                )
                risks.append(risk)
                break
        
        return risks
    
    def _calculate_overall_risk_level(self, risks: List[SchemaRisk]) -> RiskLevel:
        """Calculate overall risk level from individual risks."""
        if not risks:
            return RiskLevel.MINIMAL
        
        # Find highest severity
        severities = [risk.severity for risk in risks]
        
        if RiskLevel.CRITICAL in severities:
            return RiskLevel.CRITICAL
        elif RiskLevel.HIGH in severities:
            return RiskLevel.HIGH
        elif RiskLevel.MEDIUM in severities:
            return RiskLevel.MEDIUM
        elif RiskLevel.LOW in severities:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _calculate_security_score(self, result: SchemaAnalysisResult) -> float:
        """Calculate security score (0.0 to 10.0, where 10.0 is most secure)."""
        if result.total_parameters == 0:
            return 10.0  # No parameters = no risk
        
        # Base score starts at 10.0 (perfect security)
        score = 10.0
        
        # Deduct points for each risk
        for risk in result.schema_risks:
            if risk.severity == RiskLevel.CRITICAL:
                score -= 3.0
            elif risk.severity == RiskLevel.HIGH:
                score -= 2.0
            elif risk.severity == RiskLevel.MEDIUM:
                score -= 1.0
            elif risk.severity == RiskLevel.LOW:
                score -= 0.5
        
        # Additional deduction for high percentage of risky parameters
        if result.total_parameters > 0:
            risky_percentage = result.risky_parameters / result.total_parameters
            score -= risky_percentage * 2.0
        
        return max(score, 0.0)
    
    def _initialize_risk_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize risk detection patterns."""
        return {
            r'(command|cmd|exec|execute|shell|bash|sh|powershell|ps1)': {
                'type': SchemaRiskType.COMMAND_INJECTION,
                'severity': RiskLevel.CRITICAL,
                'description': 'command execution capabilities',
                'recommendations': [
                    'Use parameterized command execution',
                    'Implement strict input validation',
                    'Apply sandboxing'
                ],
                'cwe_ids': ['CWE-78']
            },
            r'(sql|query|select|insert|update|delete|drop|table|database)': {
                'type': SchemaRiskType.SQL_INJECTION,
                'severity': RiskLevel.HIGH,
                'description': 'SQL query capabilities',
                'recommendations': [
                    'Use parameterized queries',
                    'Implement SQL input validation',
                    'Apply principle of least privilege'
                ],
                'cwe_ids': ['CWE-89']
            },
            r'(path|file|directory|folder|filename|filepath)': {
                'type': SchemaRiskType.PATH_TRAVERSAL,
                'severity': RiskLevel.HIGH,
                'description': 'file system access',
                'recommendations': [
                    'Validate file paths',
                    'Use chroot containment',
                    'Implement file access controls'
                ],
                'cwe_ids': ['CWE-22']
            },
            r'(script|code|eval|expression|javascript|python|ruby)': {
                'type': SchemaRiskType.SCRIPT_INJECTION,
                'severity': RiskLevel.HIGH,
                'description': 'script execution capabilities',
                'recommendations': [
                    'Avoid dynamic script execution',
                    'Use safe evaluation methods',
                    'Implement sandboxing'
                ],
                'cwe_ids': ['CWE-94']
            },
            r'(password|passwd|secret|key|token|credential|auth)': {
                'type': SchemaRiskType.INFORMATION_DISCLOSURE,
                'severity': RiskLevel.MEDIUM,
                'description': 'sensitive credential handling',
                'recommendations': [
                    'Use secure credential storage',
                    'Implement proper access controls',
                    'Avoid logging sensitive data'
                ],
                'cwe_ids': ['CWE-200']
            }
        }
    
    def _initialize_dangerous_types(self) -> Dict[str, Dict[str, Any]]:
        """Initialize dangerous parameter types."""
        return {
            'object': {
                'type': SchemaRiskType.UNSAFE_DESERIALIZATION,
                'severity': RiskLevel.MEDIUM,
                'description': 'may allow unsafe deserialization',
                'recommendations': [
                    'Validate object structure',
                    'Use safe deserialization methods',
                    'Implement type checking'
                ],
                'cwe_ids': ['CWE-502']
            },
            'any': {
                'type': SchemaRiskType.WEAK_VALIDATION,
                'severity': RiskLevel.MEDIUM,
                'description': 'allows any type without validation',
                'recommendations': [
                    'Use specific types instead of any',
                    'Implement strict type validation',
                    'Define clear parameter constraints'
                ],
                'cwe_ids': ['CWE-20']
            }
        }
    
    def _initialize_injection_patterns(self) -> Dict[str, SchemaRiskType]:
        """Initialize injection vulnerability patterns."""
        return {
            'sql': SchemaRiskType.SQL_INJECTION,
            'command': SchemaRiskType.COMMAND_INJECTION,
            'script': SchemaRiskType.SCRIPT_INJECTION,
            'path': SchemaRiskType.PATH_TRAVERSAL
        }
    
    def _initialize_validation_patterns(self) -> Dict[str, List[str]]:
        """Initialize validation requirement patterns."""
        return {
            'string': ['maxLength', 'pattern', 'enum'],
            'number': ['minimum', 'maximum', 'multipleOf'],
            'integer': ['minimum', 'maximum', 'multipleOf'],
            'array': ['maxItems', 'minItems', 'uniqueItems'],
            'object': ['properties', 'required', 'additionalProperties']
        }
