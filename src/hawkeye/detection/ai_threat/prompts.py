"""
Threat Analysis Prompt Engineering Framework

This module provides structured prompts for AI-powered threat analysis,
implementing the prompt engineering framework from the design document.
"""

import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .models import ToolCapabilities, EnvironmentContext, ThreatLevel


@dataclass
class PromptTemplate:
    """Template for AI prompts with system and user components."""
    
    system_prompt: str
    user_prompt_template: str
    response_schema: Dict[str, Any]
    temperature: float = 0.1
    max_tokens: int = 8000


class ThreatAnalysisPrompts:
    """
    Structured prompts for AI-powered threat analysis.
    
    This class implements the prompt engineering framework from the design document,
    providing specialized prompts for different types of threat analysis.
    """
    
    def __init__(self):
        """Initialize the prompt engineering framework."""
        self.templates = self._initialize_templates()
        
    def _initialize_templates(self) -> Dict[str, PromptTemplate]:
        """Initialize all prompt templates."""
        return {
            "capability_analysis": self._create_capability_analysis_template(),
            "attack_vector": self._create_attack_vector_template(),
            "mitigation_strategy": self._create_mitigation_strategy_template(),
            "comprehensive": self._create_comprehensive_template(),
            "quick_assessment": self._create_quick_assessment_template(),
            "context_aware": self._create_context_aware_template(),
            "attack_chain": self._create_attack_chain_template(),
        }
    
    def build_capability_analysis_prompt(
        self, 
        capabilities: ToolCapabilities,
        context: EnvironmentContext
    ) -> Dict[str, Any]:
        """Build prompt for analyzing tool capabilities."""
        template = self.templates["capability_analysis"]
        
        # Format capabilities for analysis
        capability_text = self._format_capabilities(capabilities)
        context_text = self._format_context(context)
        
        user_prompt = template.user_prompt_template.format(
            capabilities=capability_text,
            context=context_text,
            tool_name=capabilities.tool_name,
            tool_functions=len(capabilities.tool_functions)
        )
        
        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt,
            "response_schema": template.response_schema,
            "temperature": template.temperature,
            "max_tokens": template.max_tokens
        }
    
    def build_attack_vector_prompt(
        self, 
        capability_analysis: str,
        capabilities: ToolCapabilities,
        context: EnvironmentContext
    ) -> Dict[str, Any]:
        """Build prompt for generating attack vectors."""
        template = self.templates["attack_vector"]
        
        user_prompt = template.user_prompt_template.format(
            capability_analysis=capability_analysis,
            tool_name=capabilities.tool_name,
            context=self._format_context(context),
            deployment_type=context.deployment_type.value,
            security_posture=context.security_posture.value
        )
        
        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt,
            "response_schema": template.response_schema,
            "temperature": template.temperature,
            "max_tokens": template.max_tokens
        }
    
    def build_mitigation_prompt(
        self, 
        attack_vectors: List[str],
        capabilities: ToolCapabilities,
        context: EnvironmentContext
    ) -> Dict[str, Any]:
        """Build prompt for generating mitigation strategies."""
        template = self.templates["mitigation_strategy"]
        
        vectors_text = "\n".join([f"- {vector}" for vector in attack_vectors])
        
        user_prompt = template.user_prompt_template.format(
            attack_vectors=vectors_text,
            tool_name=capabilities.tool_name,
            context=self._format_context(context),
            deployment_type=context.deployment_type.value
        )
        
        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt,
            "response_schema": template.response_schema,
            "temperature": template.temperature,
            "max_tokens": template.max_tokens
        }
    
    def build_comprehensive_prompt(
        self,
        capabilities: ToolCapabilities,
        context: EnvironmentContext
    ) -> Dict[str, Any]:
        """Build comprehensive analysis prompt."""
        template = self.templates["comprehensive"]
        
        capability_text = self._format_capabilities(capabilities)
        context_text = self._format_context(context)
        
        user_prompt = template.user_prompt_template.format(
            tool_name=capabilities.tool_name,
            capabilities=capability_text,
            context=context_text,
            deployment_type=context.deployment_type.value,
            security_posture=context.security_posture.value,
            response_schema=json.dumps(template.response_schema, indent=2)
        )
        
        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt,
            "response_schema": template.response_schema,
            "temperature": template.temperature,
            "max_tokens": template.max_tokens
        }
    
    def build_context_aware_prompt(
        self,
        capabilities: ToolCapabilities,
        context: EnvironmentContext,
        similar_tools: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Build context-aware analysis prompt."""
        template = self.templates["context_aware"]
        
        similar_tools_text = ""
        if similar_tools:
            similar_tools_text = f"\n\nSimilar tools in environment: {', '.join(similar_tools)}"
        
        user_prompt = template.user_prompt_template.format(
            tool_name=capabilities.tool_name,
            capabilities=self._format_capabilities(capabilities),
            context=self._format_context(context),
            similar_tools=similar_tools_text,
            compliance_requirements=", ".join([cf.value for cf in context.compliance_requirements])
        )
        
        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt,
            "response_schema": template.response_schema,
            "temperature": template.temperature,
            "max_tokens": template.max_tokens
        }
    
    def build_attack_chain_prompt(
        self,
        tools: List[ToolCapabilities],
        context: EnvironmentContext
    ) -> Dict[str, Any]:
        """Build attack chain analysis prompt."""
        template = self.templates["attack_chain"]
        
        tools_text = ""
        for i, tool in enumerate(tools, 1):
            tools_text += f"{i}. {tool.tool_name}: {self._format_capabilities(tool)}\n"
        
        user_prompt = template.user_prompt_template.format(
            tools=tools_text,
            context=self._format_context(context),
            num_tools=len(tools)
        )
        
        return {
            "system_prompt": template.system_prompt,
            "user_prompt": user_prompt,
            "response_schema": template.response_schema,
            "temperature": template.temperature,
            "max_tokens": template.max_tokens
        }
    
    def _create_capability_analysis_template(self) -> PromptTemplate:
        """Create capability analysis prompt template."""
        return PromptTemplate(
            system_prompt="""You are a cybersecurity expert specializing in MCP tool security analysis. 
Your role is to analyze MCP tool capabilities and identify potential security implications.

Focus on:
- Understanding what the tool can do and how it could be misused
- Identifying security-relevant capabilities and their risk levels
- Considering the deployment context and environment
- Providing accurate, actionable security insights""",
            
            user_prompt_template="""Analyze the security implications of this MCP tool's capabilities:

TOOL INFORMATION:
Name: {tool_name}
Functions: {tool_functions}

CAPABILITIES:
{capabilities}

DEPLOYMENT CONTEXT:
{context}

Provide a detailed capability analysis focusing on:
1. Security-relevant capabilities and their implications
2. Potential for abuse or misuse
3. Access requirements and privilege levels needed
4. External dependencies and network access
5. Data sensitivity and privacy concerns

Be specific and technical in your analysis.""",
            
            response_schema={
                "type": "object",
                "properties": {
                    "capability_assessment": {
                        "type": "string",
                        "description": "Detailed assessment of security-relevant capabilities"
                    },
                    "risk_factors": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of identified risk factors"
                    },
                    "access_requirements": {
                        "type": "string",
                        "description": "Required access levels and permissions"
                    },
                    "external_dependencies": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "External systems or services the tool depends on"
                    }
                },
                "required": ["capability_assessment", "risk_factors"]
            }
        )
    
    def _create_attack_vector_template(self) -> PromptTemplate:
        """Create attack vector generation prompt template."""
        return PromptTemplate(
            system_prompt="""You are a cybersecurity expert specializing in attack vector identification. 
Your role is to generate realistic, practical attack scenarios based on MCP tool capabilities.

Focus on:
- Realistic attack scenarios that could actually occur
- Considering the specific deployment context and security posture
- Providing detailed attack steps and prerequisites
- Assessing likelihood and impact accurately""",
            
            user_prompt_template="""Generate attack vectors for this MCP tool based on the capability analysis:

TOOL: {tool_name}
DEPLOYMENT: {deployment_type}
SECURITY POSTURE: {security_posture}

CAPABILITY ANALYSIS:
{capability_analysis}

CONTEXT:
{context}

Generate 3-5 realistic attack vectors, each including:
1. Attack name and category
2. Detailed description of the attack
3. Step-by-step attack methodology
4. Prerequisites and access requirements
5. Potential impact and consequences
6. Likelihood assessment (0.0-1.0)
7. Severity level (low/medium/high/critical)

Focus on practical, actionable attack scenarios.""",
            
            response_schema={
                "type": "object",
                "properties": {
                    "attack_vectors": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "category": {"type": "string"},
                                "description": {"type": "string"},
                                "attack_steps": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "prerequisites": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "impact": {"type": "string"},
                                "likelihood": {"type": "number", "minimum": 0, "maximum": 1},
                                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
                            },
                            "required": ["name", "description", "attack_steps", "impact", "likelihood", "severity"]
                        }
                    }
                },
                "required": ["attack_vectors"]
            }
        )
    
    def _create_mitigation_strategy_template(self) -> PromptTemplate:
        """Create mitigation strategy prompt template."""
        return PromptTemplate(
            system_prompt="""You are a cybersecurity expert specializing in security mitigation strategies. 
Your role is to develop practical, implementable mitigation strategies for identified attack vectors.

Focus on:
- Practical, implementable security controls
- Considering deployment constraints and context
- Providing specific, actionable recommendations
- Balancing security with operational requirements""",
            
            user_prompt_template="""Develop mitigation strategies for these identified attack vectors:

TOOL: {tool_name}
DEPLOYMENT: {deployment_type}

ATTACK VECTORS:
{attack_vectors}

CONTEXT:
{context}

For each attack vector, provide mitigation strategies including:
1. Primary mitigation approach
2. Specific implementation steps
3. Alternative/supplementary controls
4. Effectiveness rating (0.0-1.0)
5. Implementation complexity (low/medium/high)
6. Operational impact assessment
7. Monitoring and detection recommendations

Focus on practical, cost-effective solutions.""",
            
            response_schema={
                "type": "object",
                "properties": {
                    "mitigation_strategies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "attack_vector": {"type": "string"},
                                "primary_mitigation": {"type": "string"},
                                "implementation_steps": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "alternative_controls": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "effectiveness": {"type": "number", "minimum": 0, "maximum": 1},
                                "complexity": {"type": "string", "enum": ["low", "medium", "high"]},
                                "operational_impact": {"type": "string"},
                                "monitoring": {"type": "string"}
                            },
                            "required": ["attack_vector", "primary_mitigation", "implementation_steps", "effectiveness"]
                        }
                    }
                },
                "required": ["mitigation_strategies"]
            }
        )
    
    def _create_comprehensive_template(self) -> PromptTemplate:
        """Create comprehensive analysis prompt template."""
        return PromptTemplate(
            system_prompt="""You are an expert cybersecurity analyst specializing in MCP (Model Context Protocol) tool security analysis.
Your role is to provide detailed threat analysis with actionable attack scenarios and code examples.

CRITICAL REQUIREMENTS:
- Generate realistic, step-by-step attack scenarios based on actual MCP tool capabilities
- Provide specific example code/commands that demonstrate each attack vector
- Focus on practical attacks that could actually be executed against the tool
- Consider the specific deployment context and security posture
- Base analysis on real MCP tool functionality and common attack patterns

For each attack vector, you MUST provide:
1. Detailed step-by-step attack methodology
2. Specific example code or commands showing the attack
3. Prerequisites and access requirements
4. Realistic impact assessment""",
            
            user_prompt_template="""Analyze this MCP tool for security threats and generate detailed attack scenarios:

=== MCP TOOL INFORMATION ===
TOOL: {tool_name}
DEPLOYMENT: {deployment_type}
SECURITY POSTURE: {security_posture}

=== TOOL CAPABILITIES ===
{capabilities}

=== ENVIRONMENT CONTEXT ===
{context}

=== ANALYSIS REQUIREMENTS ===
Generate a comprehensive threat analysis including:

1. **THREAT LEVEL**: Overall risk assessment (minimal/low/medium/high/critical)

2. **ATTACK VECTORS** (3-5 detailed scenarios):
   - Each vector must include specific attack steps (numbered list)
   - Provide example code/commands for each attack
   - Explain prerequisites and access requirements
   - Assess impact and likelihood

3. **ABUSE SCENARIOS** (2-3 realistic cases):
   - Specific threat actor profiles and motivations
   - Detailed attack flow with technical steps
   - Business impact assessment

4. **MITIGATION STRATEGIES**:
   - Specific countermeasures for each attack vector
   - Implementation steps and effectiveness ratings

5. **RISK ASSESSMENT**:
   - Overall risk level with justification
   - Key security concerns and recommendations

=== OUTPUT FORMAT ===
Respond in the following JSON format:
{response_schema}

=== EXAMPLE ATTACK VECTOR FORMAT ===
For attack vectors like "Information Reconnaissance", provide:
- Name: Clear, descriptive attack name
- Description: What the attack does and why it's dangerous
- Attack Steps: ["Step 1: Gain access to...", "Step 2: Execute command...", etc.]
- Example Code: Actual code/commands that demonstrate the attack
- Prerequisites: What the attacker needs to execute this attack
- Impact: Specific consequences of successful attack
- Likelihood: Realistic probability assessment (0.0-1.0)

Generate detailed, technical analysis based on the specific MCP tool capabilities provided.""",
            
            response_schema={
                "type": "object",
                "properties": {
                    "threat_level": {
                        "type": "string",
                        "enum": ["minimal", "low", "medium", "high", "critical"]
                    },
                    "confidence_score": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1
                    },
                    "attack_vectors": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                                "description": {"type": "string"},
                                "attack_steps": {"type": "array", "items": {"type": "string"}},
                                "example_code": {"type": "string", "description": "Code example demonstrating the attack"},
                                "prerequisites": {"type": "array", "items": {"type": "string"}},
                                "impact": {"type": "string"},
                                "likelihood": {"type": "number", "minimum": 0, "maximum": 1}
                            },
                            "required": ["name", "severity", "description", "attack_steps", "example_code", "impact", "likelihood"]
                        }
                    },
                    "abuse_scenarios": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "scenario_name": {"type": "string"},
                                "threat_actor": {"type": "string"},
                                "motivation": {"type": "string"},
                                "attack_flow": {"type": "array", "items": {"type": "string"}},
                                "impact": {"type": "string"}
                            },
                            "required": ["scenario_name", "threat_actor", "attack_flow", "impact"]
                        }
                    },
                    "mitigation_strategies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "effectiveness": {"type": "number", "minimum": 0, "maximum": 1},
                                "implementation_steps": {"type": "array", "items": {"type": "string"}}
                            },
                            "required": ["description", "effectiveness", "implementation_steps"]
                        }
                    },
                    "risk_assessment": {
                        "type": "object",
                        "properties": {
                            "overall_risk": {"type": "string"},
                            "key_concerns": {"type": "array", "items": {"type": "string"}},
                            "recommendations": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["overall_risk", "key_concerns", "recommendations"]
                    }
                },
                "required": ["threat_level", "confidence_score", "attack_vectors", "mitigation_strategies", "risk_assessment"]
            },
            temperature=0.1,
            max_tokens=8000
        )
    
    def _create_quick_assessment_template(self) -> PromptTemplate:
        """Create quick assessment prompt template."""
        return PromptTemplate(
            system_prompt="""You are a cybersecurity expert. Provide quick, accurate risk assessments for MCP tools.""",
            
            user_prompt_template="""Quickly assess the risk level for an MCP tool with these capabilities:

{capabilities}

Context: {context}

Respond with: RISK_LEVEL|CONFIDENCE_SCORE|KEY_CONCERN

Where:
- RISK_LEVEL: minimal/low/medium/high/critical
- CONFIDENCE_SCORE: 0.0-1.0
- KEY_CONCERN: Primary security concern (brief)""",
            
            response_schema={
                "type": "string",
                "description": "Format: RISK_LEVEL|CONFIDENCE_SCORE|KEY_CONCERN"
            },
            temperature=0.0,
            max_tokens=100
        )
    
    def _create_context_aware_template(self) -> PromptTemplate:
        """Create context-aware analysis prompt template."""
        return PromptTemplate(
            system_prompt="""You are a cybersecurity expert specializing in context-aware threat analysis.
Consider the specific deployment environment, security posture, and organizational context when analyzing threats.

Focus on:
- Environment-specific threats and risks
- Compliance requirements and regulatory impact
- Organizational security posture and capabilities
- Industry-specific threat landscape
- Attack patterns relevant to the deployment context""",
            
            user_prompt_template="""Analyze this MCP tool considering the specific deployment context:

TOOL: {tool_name}

CAPABILITIES:
{capabilities}

ENVIRONMENT CONTEXT:
{context}

COMPLIANCE REQUIREMENTS: {compliance_requirements}
{similar_tools}

Provide context-aware analysis including:
1. Environment-specific threats and attack scenarios
2. Compliance impact and regulatory considerations
3. Context-appropriate mitigation strategies
4. Industry-specific threat intelligence
5. Risk prioritization based on organizational context

Consider how the deployment environment affects threat likelihood and impact.""",
            
            response_schema={
                "type": "object",
                "properties": {
                    "context_threats": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "threat": {"type": "string"},
                                "context_relevance": {"type": "string"},
                                "impact_factor": {"type": "number"}
                            }
                        }
                    },
                    "compliance_impact": {"type": "string"},
                    "context_mitigations": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "risk_prioritization": {"type": "string"}
                },
                "required": ["context_threats", "compliance_impact", "context_mitigations"]
            }
        )
    
    def _create_attack_chain_template(self) -> PromptTemplate:
        """Create attack chain analysis prompt template."""
        return PromptTemplate(
            system_prompt="""You are a cybersecurity expert specializing in attack chain analysis.
Analyze how multiple MCP tools can be combined to create sophisticated attack scenarios.

Focus on:
- Multi-tool attack scenarios and sequences
- Tool combination synergies and amplification effects
- Complex attack chains with multiple stages
- Defense evasion through tool chaining
- Persistence and lateral movement opportunities""",
            
            user_prompt_template="""Analyze potential attack chains using these {num_tools} MCP tools:

TOOLS:
{tools}

ENVIRONMENT:
{context}

Identify attack chains that combine multiple tools including:
1. Multi-stage attack scenarios using tool combinations
2. Tool synergies that amplify attack effectiveness
3. Attack chain feasibility and prerequisites
4. Defense evasion techniques using tool chaining
5. Persistence and lateral movement opportunities

Focus on realistic, practical attack chains.""",
            
            response_schema={
                "type": "object",
                "properties": {
                    "attack_chains": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "chain_name": {"type": "string"},
                                "tools_involved": {"type": "array", "items": {"type": "string"}},
                                "attack_stages": {"type": "array", "items": {"type": "string"}},
                                "feasibility": {"type": "number", "minimum": 0, "maximum": 1},
                                "impact": {"type": "string"},
                                "complexity": {"type": "string"}
                            },
                            "required": ["chain_name", "tools_involved", "attack_stages", "feasibility"]
                        }
                    },
                    "tool_synergies": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tools": {"type": "array", "items": {"type": "string"}},
                                "synergy_effect": {"type": "string"},
                                "risk_amplification": {"type": "number"}
                            }
                        }
                    }
                },
                "required": ["attack_chains"]
            }
        )
    
    def _format_capabilities(self, capabilities: ToolCapabilities) -> str:
        """Format tool capabilities for prompt inclusion."""
        lines = []
        
        for func in capabilities.tool_functions:
            lines.append(f"- {func.name}: {func.description}")
            if hasattr(func, 'input_schema') and func.input_schema:
                lines.append(f"  Parameters: {json.dumps(func.input_schema, indent=2)}")
        
        lines.append(f"\nCategories: {[cat.value for cat in capabilities.capability_categories]}")
        lines.append(f"Risk Indicators: {capabilities.risk_indicators}")
        lines.append(f"Requires Privileges: {capabilities.requires_privileges}")
        lines.append(f"External Access: {capabilities.external_access}")
        
        return "\n".join(lines)
    
    def _format_context(self, context: EnvironmentContext) -> str:
        """Format environment context for prompt inclusion."""
        lines = [
            f"Deployment Type: {context.deployment_type.value}",
            f"Security Posture: {context.security_posture.value}",
            f"Data Sensitivity: {context.data_sensitivity.value}",
            f"Network Exposure: {context.network_exposure.value}",
            f"User Privileges: {context.user_privileges.value}",
        ]
        
        if context.compliance_requirements:
            lines.append(f"Compliance: {[req.value for req in context.compliance_requirements]}")
        
        return "\n".join(lines) 