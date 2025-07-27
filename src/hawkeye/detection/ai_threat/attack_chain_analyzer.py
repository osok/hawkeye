"""
Attack Chain Analyzer

This module provides analysis of potential attack chains across multiple MCP tools,
identifying how tools can be combined for sophisticated multi-stage attacks.
"""

import logging
import hashlib
from typing import List, Dict, Optional, Set, Tuple, Any
from datetime import datetime
from collections import defaultdict

from .models import (
    AttackChain, ChainLink, ChainFeasibilityScore, ThreatLevel, 
    ThreatActorType, AccessLevel, DifficultyLevel, BusinessImpact,
    ToolCapabilities, EnvironmentContext, CapabilityCategory,
    SecurityPosture, DeploymentType, DataSensitivity
)
from ..mcp_introspection.models import MCPServerInfo


logger = logging.getLogger(__name__)


class AttackChainAnalyzer:
    """
    Analyzes combinations of MCP tools for potential attack chains.
    
    This class identifies multi-tool attack scenarios where the output of one
    tool can be used as input for another tool, creating sophisticated attack
    chains that would be more difficult to detect and defend against.
    """
    
    def __init__(self):
        """Initialize the attack chain analyzer."""
        self.capability_relationships = self._build_capability_relationships()
        self.attack_patterns = self._load_attack_patterns()
        self.chain_cache = {}  # Cache for analyzed chains
        
        # Statistics tracking
        self.stats = {
            "chains_analyzed": 0,
            "feasible_chains_found": 0,
            "high_risk_chains": 0,
            "analysis_time_total": 0.0
        }
        
        logger.info("Attack Chain Analyzer initialized")
    
    def identify_attack_chains(self, 
                             detected_tools: List[MCPServerInfo],
                             environment_context: EnvironmentContext,
                             max_chain_length: int = 5,
                             min_feasibility_score: float = 0.3) -> List[AttackChain]:
        """
        Identify potential attack chains using multiple tools.
        
        Args:
            detected_tools: List of detected MCP servers
            environment_context: Environment context for analysis
            max_chain_length: Maximum number of tools in a chain
            min_feasibility_score: Minimum feasibility score to include chain
            
        Returns:
            List of identified attack chains
        """
        start_time = datetime.now()
        logger.info(f"Starting attack chain analysis for {len(detected_tools)} tools")
        
        try:
            # Step 1: Extract tool capabilities
            tool_capabilities = self._extract_tool_capabilities(detected_tools)
            
            # Step 2: Build capability graph
            capability_graph = self._build_capability_graph(tool_capabilities)
            
            # Step 3: Find potential attack paths
            attack_paths = self._find_attack_paths(
                capability_graph, 
                max_chain_length,
                environment_context
            )
            
            # Step 4: Convert paths to attack chains
            attack_chains = []
            for path in attack_paths:
                chain = self._path_to_attack_chain(path, tool_capabilities, environment_context)
                if chain:
                    # Assess feasibility
                    feasibility = self.assess_chain_feasibility(chain, environment_context)
                    if feasibility.overall_score >= min_feasibility_score:
                        chain.success_probability = feasibility.overall_score
                        attack_chains.append(chain)
            
            # Step 5: Rank and filter chains
            attack_chains = self._rank_attack_chains(attack_chains, environment_context)
            
            # Update statistics
            analysis_time = (datetime.now() - start_time).total_seconds()
            self.stats["chains_analyzed"] += len(attack_chains)
            self.stats["feasible_chains_found"] += len([c for c in attack_chains if c.success_probability >= 0.5])
            self.stats["high_risk_chains"] += len([c for c in attack_chains if c.overall_difficulty == DifficultyLevel.LOW])
            self.stats["analysis_time_total"] += analysis_time
            
            logger.info(f"Attack chain analysis completed: {len(attack_chains)} chains identified in {analysis_time:.2f}s")
            return attack_chains
            
        except Exception as e:
            logger.error(f"Attack chain analysis failed: {e}")
            return []
    
    def assess_chain_feasibility(self, 
                               attack_chain: AttackChain,
                               environment: EnvironmentContext) -> ChainFeasibilityScore:
        """
        Assess the feasibility of an attack chain in the given environment.
        
        Args:
            attack_chain: Attack chain to assess
            environment: Environment context
            
        Returns:
            Feasibility score with detailed breakdown
        """
        try:
            # Technical feasibility - can the tools actually be chained?
            technical_feasibility = self._assess_technical_feasibility(attack_chain)
            
            # Access feasibility - can attacker get required access?
            access_feasibility = self._assess_access_feasibility(attack_chain, environment)
            
            # Detection avoidance - how likely is chain to go undetected?
            detection_avoidance = self._assess_detection_avoidance(attack_chain, environment)
            
            # Environmental suitability - is environment suitable for this attack?
            environmental_suitability = self._assess_environmental_suitability(attack_chain, environment)
            
            # Resource requirements - does attacker have required resources?
            resource_requirements = self._assess_resource_requirements(attack_chain, environment)
            
            # Calculate overall score (weighted average)
            weights = {
                "technical": 0.25,
                "access": 0.25,
                "detection": 0.20,
                "environmental": 0.15,
                "resources": 0.15
            }
            
            overall_score = (
                technical_feasibility * weights["technical"] +
                access_feasibility * weights["access"] +
                detection_avoidance * weights["detection"] +
                environmental_suitability * weights["environmental"] +
                resource_requirements * weights["resources"]
            )
            
            # Generate rationale
            rationale = self._generate_feasibility_rationale(
                technical_feasibility, access_feasibility, detection_avoidance,
                environmental_suitability, resource_requirements
            )
            
            # Calculate confidence level
            confidence_level = min(0.9, max(0.3, overall_score * 1.1))
            
            return ChainFeasibilityScore(
                chain_id=attack_chain.chain_id,
                overall_score=overall_score,
                technical_feasibility=technical_feasibility,
                access_feasibility=access_feasibility,
                detection_avoidance=detection_avoidance,
                environmental_suitability=environmental_suitability,
                resource_requirements=resource_requirements,
                scoring_rationale=rationale,
                confidence_level=confidence_level
            )
            
        except Exception as e:
            logger.error(f"Feasibility assessment failed for chain {attack_chain.chain_id}: {e}")
            # Return conservative assessment
            return ChainFeasibilityScore(
                chain_id=attack_chain.chain_id,
                overall_score=0.1,
                technical_feasibility=0.1,
                access_feasibility=0.1,
                detection_avoidance=0.1,
                environmental_suitability=0.1,
                resource_requirements=0.1,
                scoring_rationale="Assessment failed - conservative estimate",
                confidence_level=0.2
            )
    
    def find_lateral_movement_chains(self,
                                   detected_tools: List[MCPServerInfo],
                                   environment_context: EnvironmentContext) -> List[AttackChain]:
        """
        Find attack chains specifically focused on lateral movement scenarios.
        
        Args:
            detected_tools: List of detected MCP servers
            environment_context: Environment context
            
        Returns:
            List of lateral movement attack chains
        """
        logger.info("Analyzing lateral movement attack chains")
        
        # Filter for tools commonly used in lateral movement
        lateral_movement_categories = [
            CapabilityCategory.NETWORK_ACCESS,
            CapabilityCategory.SYSTEM_INFORMATION,
            CapabilityCategory.FILE_SYSTEM,
            CapabilityCategory.CODE_EXECUTION
        ]
        
        # Get all attack chains
        all_chains = self.identify_attack_chains(detected_tools, environment_context)
        
        # Filter for lateral movement patterns
        lateral_chains = []
        for chain in all_chains:
            if self._is_lateral_movement_chain(chain, lateral_movement_categories):
                lateral_chains.append(chain)
        
        logger.info(f"Found {len(lateral_chains)} lateral movement chains")
        return lateral_chains
    
    def find_data_exfiltration_chains(self,
                                    detected_tools: List[MCPServerInfo],
                                    environment_context: EnvironmentContext) -> List[AttackChain]:
        """
        Find attack chains focused on data exfiltration scenarios.
        
        Args:
            detected_tools: List of detected MCP servers
            environment_context: Environment context
            
        Returns:
            List of data exfiltration attack chains
        """
        logger.info("Analyzing data exfiltration attack chains")
        
        # Filter for tools commonly used in data exfiltration
        exfiltration_categories = [
            CapabilityCategory.FILE_SYSTEM,
            CapabilityCategory.NETWORK_ACCESS,
            CapabilityCategory.DATABASE_ACCESS,
            CapabilityCategory.CLOUD_SERVICES,
            CapabilityCategory.DATA_PROCESSING
        ]
        
        # Get all attack chains
        all_chains = self.identify_attack_chains(detected_tools, environment_context)
        
        # Filter for data exfiltration patterns
        exfiltration_chains = []
        for chain in all_chains:
            if self._is_data_exfiltration_chain(chain, exfiltration_categories):
                exfiltration_chains.append(chain)
        
        logger.info(f"Found {len(exfiltration_chains)} data exfiltration chains")
        return exfiltration_chains
    
    def get_chain_visualization_data(self, attack_chain: AttackChain) -> Dict[str, Any]:
        """
        Generate visualization data for an attack chain.
        
        Args:
            attack_chain: Attack chain to visualize
            
        Returns:
            Visualization data structure
        """
        try:
            nodes = []
            edges = []
            
            # Create nodes for each chain link
            for i, link in enumerate(attack_chain.chain_links):
                node = {
                    "id": f"step_{i}",
                    "label": link.tool_name,
                    "type": "tool",
                    "action": link.attack_action,
                    "difficulty": link.difficulty.value,
                    "access_required": link.required_access.value,
                    "time_estimate": link.time_estimate,
                    "capabilities": link.tool_capabilities
                }
                nodes.append(node)
                
                # Create edge to next node
                if i < len(attack_chain.chain_links) - 1:
                    edge = {
                        "id": f"edge_{i}",
                        "source": f"step_{i}",
                        "target": f"step_{i+1}",
                        "artifacts": link.output_artifacts,
                        "flow_type": "sequential"
                    }
                    edges.append(edge)
            
            return {
                "chain_id": attack_chain.chain_id,
                "chain_name": attack_chain.chain_name,
                "graph": {
                    "nodes": nodes,
                    "edges": edges
                },
                "metadata": {
                    "total_steps": len(attack_chain.chain_links),
                    "estimated_duration": attack_chain.total_time_estimate,
                    "overall_difficulty": attack_chain.overall_difficulty.value,
                    "success_probability": attack_chain.success_probability,
                    "threat_actor": attack_chain.threat_actor.value
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to generate visualization data for chain {attack_chain.chain_id}: {e}")
            return {"error": str(e)}
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get attack chain analysis statistics."""
        stats = self.stats.copy()
        
        if self.stats["chains_analyzed"] > 0:
            stats["avg_analysis_time"] = self.stats["analysis_time_total"] / self.stats["chains_analyzed"]
            stats["feasible_chain_ratio"] = self.stats["feasible_chains_found"] / self.stats["chains_analyzed"]
            stats["high_risk_ratio"] = self.stats["high_risk_chains"] / self.stats["chains_analyzed"]
        
        return stats
    
    def _extract_tool_capabilities(self, detected_tools: List[MCPServerInfo]) -> Dict[str, ToolCapabilities]:
        """Extract and normalize tool capabilities from detected tools."""
        capabilities = {}
        
        for tool in detected_tools:
            tool_name = tool.metadata.get('name', tool.server_id)
            
            # Extract capabilities from tool metadata and available tools
            tool_functions = []
            capability_categories = set()
            
            # Analyze available tools if present
            if hasattr(tool, 'available_tools') and tool.available_tools:
                for mcp_tool in tool.available_tools:
                    tool_functions.append(mcp_tool.name)
                    # Categorize based on tool name patterns
                    categories = self._categorize_tool_function(mcp_tool.name)
                    capability_categories.update(categories)
            
            # Create ToolCapabilities object (simplified for this analysis)
            capabilities[tool_name] = {
                'tool_name': tool_name,
                'tool_functions': tool_functions,
                'capability_categories': list(capability_categories),
                'server_info': tool
            }
        
        return capabilities
    
    def _categorize_tool_function(self, function_name: str) -> List[CapabilityCategory]:
        """Categorize a tool function based on its name."""
        name_lower = function_name.lower()
        categories = []
        
        # File system operations
        if any(keyword in name_lower for keyword in ['file', 'read', 'write', 'directory', 'path']):
            categories.append(CapabilityCategory.FILE_SYSTEM)
        
        # Network operations
        if any(keyword in name_lower for keyword in ['http', 'web', 'request', 'url', 'api', 'network']):
            categories.append(CapabilityCategory.NETWORK_ACCESS)
        
        # Code execution
        if any(keyword in name_lower for keyword in ['execute', 'run', 'command', 'shell', 'script']):
            categories.append(CapabilityCategory.CODE_EXECUTION)
        
        # System information
        if any(keyword in name_lower for keyword in ['system', 'process', 'info', 'list', 'get', 'describe']):
            categories.append(CapabilityCategory.SYSTEM_INFORMATION)
        
        # Database operations
        if any(keyword in name_lower for keyword in ['database', 'db', 'sql', 'query']):
            categories.append(CapabilityCategory.DATABASE_ACCESS)
        
        # Data processing
        if any(keyword in name_lower for keyword in ['parse', 'analyze', 'transform', 'process', 'search']):
            categories.append(CapabilityCategory.DATA_PROCESSING)
        
        # Default to data processing if no category found
        if not categories:
            categories.append(CapabilityCategory.DATA_PROCESSING)
        
        return categories
    
    def _build_capability_graph(self, tool_capabilities: Dict[str, Any]) -> Dict[str, List[str]]:
        """Build a graph of capability relationships between tools."""
        graph = defaultdict(list)
        
        # Build connections based on output-input relationships
        tools = list(tool_capabilities.keys())
        
        for i, tool1 in enumerate(tools):
            for j, tool2 in enumerate(tools):
                if i != j:  # Don't connect tool to itself
                    if self._can_tools_chain(tool_capabilities[tool1], tool_capabilities[tool2]):
                        graph[tool1].append(tool2)
        
        return dict(graph)
    
    def _can_tools_chain(self, tool1: Dict[str, Any], tool2: Dict[str, Any]) -> bool:
        """Determine if two tools can be chained together."""
        tool1_categories = set(tool1['capability_categories'])
        tool2_categories = set(tool2['capability_categories'])
        
        # Define chaining relationships
        chain_relationships = {
            CapabilityCategory.SYSTEM_INFORMATION: [
                CapabilityCategory.FILE_SYSTEM,
                CapabilityCategory.NETWORK_ACCESS,
                CapabilityCategory.CODE_EXECUTION
            ],
            CapabilityCategory.FILE_SYSTEM: [
                CapabilityCategory.DATA_PROCESSING,
                CapabilityCategory.NETWORK_ACCESS,
                CapabilityCategory.CODE_EXECUTION
            ],
            CapabilityCategory.NETWORK_ACCESS: [
                CapabilityCategory.FILE_SYSTEM,
                CapabilityCategory.DATA_PROCESSING,
                CapabilityCategory.DATABASE_ACCESS
            ],
            CapabilityCategory.DATA_PROCESSING: [
                CapabilityCategory.FILE_SYSTEM,
                CapabilityCategory.NETWORK_ACCESS,
                CapabilityCategory.DATABASE_ACCESS
            ],
            CapabilityCategory.DATABASE_ACCESS: [
                CapabilityCategory.DATA_PROCESSING,
                CapabilityCategory.FILE_SYSTEM,
                CapabilityCategory.NETWORK_ACCESS
            ]
        }
        
        # Check if tool1's output can feed into tool2's input
        for category1 in tool1_categories:
            if category1 in chain_relationships:
                for category2 in tool2_categories:
                    if category2 in chain_relationships[category1]:
                        return True
        
        return False
    
    def _find_attack_paths(self, 
                          capability_graph: Dict[str, List[str]], 
                          max_length: int,
                          environment_context: EnvironmentContext) -> List[List[str]]:
        """Find potential attack paths through the capability graph."""
        paths = []
        
        # Find all possible paths using DFS
        for start_tool in capability_graph.keys():
            self._dfs_find_paths(capability_graph, start_tool, [], paths, max_length)
        
        # Filter paths based on environment context
        filtered_paths = self._filter_paths_by_environment(paths, environment_context)
        
        return filtered_paths
    
    def _dfs_find_paths(self, 
                       graph: Dict[str, List[str]], 
                       current: str, 
                       path: List[str], 
                       all_paths: List[List[str]], 
                       max_length: int) -> None:
        """Depth-first search to find all possible paths."""
        path.append(current)
        
        # If we have a path of at least 2 tools, it's potentially interesting
        if len(path) >= 2:
            all_paths.append(path.copy())
        
        # Continue searching if we haven't reached max length
        if len(path) < max_length:
            for neighbor in graph.get(current, []):
                if neighbor not in path:  # Avoid cycles
                    self._dfs_find_paths(graph, neighbor, path, all_paths, max_length)
        
        path.pop()
    
    def _filter_paths_by_environment(self, 
                                   paths: List[List[str]], 
                                   environment_context: EnvironmentContext) -> List[List[str]]:
        """Filter paths based on environment suitability."""
        filtered_paths = []
        
        for path in paths:
            # Apply environment-specific filtering
            if self._is_path_suitable_for_environment(path, environment_context):
                filtered_paths.append(path)
        
        return filtered_paths
    
    def _is_path_suitable_for_environment(self, 
                                        path: List[str], 
                                        environment_context: EnvironmentContext) -> bool:
        """Check if a path is suitable for the given environment."""
        # For now, allow all paths - can be enhanced with environment-specific logic
        return len(path) >= 2  # Minimum chain length
    
    def _path_to_attack_chain(self, 
                            path: List[str], 
                            tool_capabilities: Dict[str, Any],
                            environment_context: EnvironmentContext) -> Optional[AttackChain]:
        """Convert a tool path to a structured attack chain."""
        try:
            chain_links = []
            total_time = 0
            overall_difficulty = DifficultyLevel.MEDIUM
            
            for i, tool_name in enumerate(path):
                tool_caps = tool_capabilities[tool_name]
                
                # Create chain link
                link = ChainLink(
                    tool_name=tool_name,
                    tool_capabilities=tool_caps['tool_functions'],
                    attack_action=self._generate_attack_action(tool_caps, i == 0),
                    prerequisites=self._generate_prerequisites(tool_caps, i == 0),
                    output_artifacts=self._generate_output_artifacts(tool_caps),
                    required_access=self._determine_required_access(tool_caps),
                    difficulty=self._assess_link_difficulty(tool_caps),
                    time_estimate=self._estimate_execution_time(tool_caps)
                )
                
                chain_links.append(link)
                total_time += link.time_estimate
            
            # Generate chain ID
            chain_id = self._generate_chain_id(path)
            
            # Determine threat actor based on complexity
            threat_actor = self._determine_threat_actor(chain_links, environment_context)
            
            # Create attack chain
            attack_chain = AttackChain(
                chain_id=chain_id,
                chain_name=self._generate_chain_name(path),
                description=self._generate_chain_description(chain_links),
                threat_actor=threat_actor,
                attack_objective=self._determine_attack_objective(chain_links),
                chain_links=chain_links,
                overall_difficulty=self._assess_overall_difficulty(chain_links),
                overall_impact=self._assess_business_impact(chain_links, environment_context),
                total_time_estimate=total_time,
                detection_difficulty=self._assess_detection_difficulty(chain_links),
                mitigation_strategies=self._generate_mitigation_strategies(chain_links),
                prerequisites=self._generate_chain_prerequisites(chain_links),
                success_probability=0.5  # Will be updated by feasibility assessment
            )
            
            return attack_chain
            
        except Exception as e:
            logger.error(f"Failed to convert path to attack chain: {e}")
            return None
    
    def _generate_attack_action(self, tool_caps: Dict[str, Any], is_first: bool) -> str:
        """Generate attack action description for a tool."""
        categories = tool_caps['capability_categories']
        
        if CapabilityCategory.SYSTEM_INFORMATION in categories:
            return "Reconnaissance and system enumeration" if is_first else "Gather additional system intelligence"
        elif CapabilityCategory.FILE_SYSTEM in categories:
            return "Access and enumerate file system" if is_first else "Extract or modify files"
        elif CapabilityCategory.NETWORK_ACCESS in categories:
            return "Network reconnaissance and connection" if is_first else "Establish external communication"
        elif CapabilityCategory.CODE_EXECUTION in categories:
            return "Execute initial payload" if is_first else "Execute secondary payloads"
        elif CapabilityCategory.DATABASE_ACCESS in categories:
            return "Database reconnaissance" if is_first else "Extract database contents"
        else:
            return "Process and analyze data" if is_first else "Manipulate and exfiltrate data"
    
    def _generate_prerequisites(self, tool_caps: Dict[str, Any], is_first: bool) -> List[str]:
        """Generate prerequisites for using a tool in an attack."""
        if is_first:
            return ["Network access to target system", "MCP server discovery"]
        else:
            return ["Successful completion of previous step", "Maintained access to system"]
    
    def _generate_output_artifacts(self, tool_caps: Dict[str, Any]) -> List[str]:
        """Generate output artifacts that a tool produces."""
        categories = tool_caps['capability_categories']
        artifacts = []
        
        if CapabilityCategory.SYSTEM_INFORMATION in categories:
            artifacts.extend(["System configuration data", "Process information", "User accounts"])
        if CapabilityCategory.FILE_SYSTEM in categories:
            artifacts.extend(["File contents", "Directory listings", "File metadata"])
        if CapabilityCategory.NETWORK_ACCESS in categories:
            artifacts.extend(["Network responses", "Downloaded data", "External connections"])
        if CapabilityCategory.DATABASE_ACCESS in categories:
            artifacts.extend(["Database records", "Schema information", "Query results"])
        if CapabilityCategory.DATA_PROCESSING in categories:
            artifacts.extend(["Processed data", "Analysis results", "Structured output"])
        
        return artifacts if artifacts else ["Tool execution results"]
    
    def _determine_required_access(self, tool_caps: Dict[str, Any]) -> AccessLevel:
        """Determine required access level for a tool."""
        categories = tool_caps['capability_categories']
        
        if CapabilityCategory.CODE_EXECUTION in categories:
            return AccessLevel.ELEVATED
        elif CapabilityCategory.FILE_SYSTEM in categories:
            return AccessLevel.USER
        elif CapabilityCategory.DATABASE_ACCESS in categories:
            return AccessLevel.ELEVATED
        else:
            return AccessLevel.USER
    
    def _assess_link_difficulty(self, tool_caps: Dict[str, Any]) -> DifficultyLevel:
        """Assess the difficulty of exploiting a tool."""
        categories = tool_caps['capability_categories']
        
        # More dangerous capabilities are often easier to exploit
        if CapabilityCategory.CODE_EXECUTION in categories:
            return DifficultyLevel.LOW
        elif CapabilityCategory.FILE_SYSTEM in categories:
            return DifficultyLevel.MEDIUM
        else:
            return DifficultyLevel.HIGH
    
    def _estimate_execution_time(self, tool_caps: Dict[str, Any]) -> int:
        """Estimate execution time for a tool in minutes."""
        categories = tool_caps['capability_categories']
        
        if CapabilityCategory.SYSTEM_INFORMATION in categories:
            return 5  # Quick information gathering
        elif CapabilityCategory.FILE_SYSTEM in categories:
            return 15  # File operations take longer
        elif CapabilityCategory.NETWORK_ACCESS in categories:
            return 10  # Network operations
        elif CapabilityCategory.DATABASE_ACCESS in categories:
            return 20  # Database operations
        else:
            return 10  # Default
    
    def _generate_chain_id(self, path: List[str]) -> str:
        """Generate unique ID for attack chain."""
        path_str = "->".join(sorted(path))
        return hashlib.md5(path_str.encode()).hexdigest()[:8]
    
    def _generate_chain_name(self, path: List[str]) -> str:
        """Generate descriptive name for attack chain."""
        return f"Multi-tool attack chain: {' -> '.join(path[:3])}{'...' if len(path) > 3 else ''}"
    
    def _generate_chain_description(self, chain_links: List[ChainLink]) -> str:
        """Generate description of the attack chain."""
        actions = [link.attack_action for link in chain_links[:3]]
        return f"Attack chain involving: {', '.join(actions)}"
    
    def _determine_threat_actor(self, chain_links: List[ChainLink], environment: EnvironmentContext) -> ThreatActorType:
        """Determine most likely threat actor for this attack chain."""
        # Complex chains suggest more sophisticated actors
        if len(chain_links) >= 4:
            return ThreatActorType.NATION_STATE
        elif len(chain_links) >= 3:
            return ThreatActorType.CYBERCRIMINAL
        else:
            return ThreatActorType.EXTERNAL_ATTACKER
    
    def _determine_attack_objective(self, chain_links: List[ChainLink]) -> str:
        """Determine the objective of the attack chain."""
        # Analyze the types of tools to infer objective
        has_file_access = any("file" in link.attack_action.lower() for link in chain_links)
        has_network = any("network" in link.attack_action.lower() for link in chain_links)
        has_data_processing = any("data" in link.attack_action.lower() for link in chain_links)
        
        if has_file_access and has_network:
            return "Data exfiltration and system compromise"
        elif has_network and has_data_processing:
            return "Intelligence gathering and data theft"
        elif has_file_access:
            return "System compromise and persistence"
        else:
            return "System reconnaissance and exploitation"
    
    def _assess_overall_difficulty(self, chain_links: List[ChainLink]) -> DifficultyLevel:
        """Assess overall difficulty of the attack chain."""
        difficulties = [link.difficulty for link in chain_links]
        
        # Chain is as difficult as its hardest link
        if DifficultyLevel.HIGH in difficulties:
            return DifficultyLevel.HIGH
        elif DifficultyLevel.MEDIUM in difficulties:
            return DifficultyLevel.MEDIUM
        else:
            return DifficultyLevel.LOW
    
    def _assess_business_impact(self, chain_links: List[ChainLink], environment: EnvironmentContext) -> BusinessImpact:
        """Assess business impact of the attack chain."""
        # Impact depends on environment sensitivity and chain capabilities
        if environment.data_sensitivity == DataSensitivity.RESTRICTED:
            financial_impact = "High - Regulatory fines and business disruption"
            operational_impact = "Critical - Major operational disruption"
            reputation_impact = "Severe - Long-term reputation damage"
        elif environment.data_sensitivity == DataSensitivity.CONFIDENTIAL:
            financial_impact = "Medium - Recovery costs and potential fines"
            operational_impact = "Significant - Temporary operational impact"
            reputation_impact = "Moderate - Short-term reputation impact"
        else:
            financial_impact = "Low - Minimal direct financial impact"
            operational_impact = "Minor - Limited operational disruption"
            reputation_impact = "Low - Minimal reputation impact"
        
        return BusinessImpact(
            financial_impact=financial_impact,
            operational_impact=operational_impact,
            reputation_impact=reputation_impact
        )
    
    def _assess_detection_difficulty(self, chain_links: List[ChainLink]) -> DifficultyLevel:
        """Assess how difficult the attack chain is to detect."""
        # Longer chains are harder to detect as they appear as normal operations
        if len(chain_links) >= 4:
            return DifficultyLevel.HIGH
        elif len(chain_links) >= 3:
            return DifficultyLevel.MEDIUM
        else:
            return DifficultyLevel.LOW
    
    def _generate_mitigation_strategies(self, chain_links: List[ChainLink]) -> List[str]:
        """Generate mitigation strategies for the attack chain."""
        strategies = [
            "Implement comprehensive logging and monitoring",
            "Deploy behavioral analysis tools",
            "Apply principle of least privilege",
            "Segment network access"
        ]
        
        # Add specific mitigations based on chain characteristics
        has_code_exec = any("execute" in link.attack_action.lower() for link in chain_links)
        has_file_access = any("file" in link.attack_action.lower() for link in chain_links)
        
        if has_code_exec:
            strategies.append("Implement application whitelisting")
        if has_file_access:
            strategies.append("Deploy file integrity monitoring")
        
        return strategies
    
    def _generate_chain_prerequisites(self, chain_links: List[ChainLink]) -> List[str]:
        """Generate overall prerequisites for the attack chain."""
        return [
            "Initial access to MCP server environment",
            "Network connectivity to target systems",
            "Basic understanding of MCP protocol",
            "Time and persistence for multi-stage attack"
        ]
    
    def _rank_attack_chains(self, attack_chains: List[AttackChain], environment: EnvironmentContext) -> List[AttackChain]:
        """Rank attack chains by risk and feasibility."""
        def chain_risk_score(chain):
            # Calculate risk score based on multiple factors
            difficulty_score = {"low": 3, "medium": 2, "high": 1}[chain.overall_difficulty.value]
            length_score = min(len(chain.chain_links), 5)  # Longer chains are riskier
            feasibility_score = chain.success_probability * 3
            
            return difficulty_score + length_score + feasibility_score
        
        return sorted(attack_chains, key=chain_risk_score, reverse=True)
    
    def _is_lateral_movement_chain(self, chain: AttackChain, lateral_categories: List[CapabilityCategory]) -> bool:
        """Check if chain represents lateral movement."""
        # Check if chain involves network access + system information gathering
        chain_categories = set()
        for link in chain.chain_links:
            for func in link.tool_capabilities:
                categories = self._categorize_tool_function(func)
                chain_categories.update(categories)
        
        # Lateral movement typically involves network + system info + file access
        return (CapabilityCategory.NETWORK_ACCESS in chain_categories and
                CapabilityCategory.SYSTEM_INFORMATION in chain_categories)
    
    def _is_data_exfiltration_chain(self, chain: AttackChain, exfiltration_categories: List[CapabilityCategory]) -> bool:
        """Check if chain represents data exfiltration."""
        chain_categories = set()
        for link in chain.chain_links:
            for func in link.tool_capabilities:
                categories = self._categorize_tool_function(func)
                chain_categories.update(categories)
        
        # Data exfiltration typically involves file/data access + network
        return (CapabilityCategory.NETWORK_ACCESS in chain_categories and
                (CapabilityCategory.FILE_SYSTEM in chain_categories or
                 CapabilityCategory.DATABASE_ACCESS in chain_categories or
                 CapabilityCategory.DATA_PROCESSING in chain_categories))
    
    # Feasibility assessment helper methods
    def _assess_technical_feasibility(self, attack_chain: AttackChain) -> float:
        """Assess technical feasibility of chaining tools together."""
        # Based on how well the tools can actually be chained
        chain_coherence = 0.8  # Assume good coherence for now
        tool_availability = 0.9  # Most tools are available
        complexity_penalty = max(0.3, 1.0 - (len(attack_chain.chain_links) * 0.1))
        
        return min(1.0, chain_coherence * tool_availability * complexity_penalty)
    
    def _assess_access_feasibility(self, attack_chain: AttackChain, environment: EnvironmentContext) -> float:
        """Assess feasibility of obtaining required access levels."""
        max_access_required = max(
            [self._access_level_score(link.required_access) for link in attack_chain.chain_links]
        )
        
        # Environment security affects access feasibility
        security_modifier = {
            SecurityPosture.HIGH: 0.3,
            SecurityPosture.MEDIUM: 0.6,
            SecurityPosture.LOW: 0.9
        }
        
        base_feasibility = 1.0 - (max_access_required * 0.2)
        return base_feasibility * security_modifier.get(environment.security_posture, 0.6)
    
    def _assess_detection_avoidance(self, attack_chain: AttackChain, environment: EnvironmentContext) -> float:
        """Assess likelihood of avoiding detection."""
        # Longer chains are harder to detect but more complex
        length_factor = min(1.0, len(attack_chain.chain_links) * 0.15)
        
        # Environment monitoring affects detection
        monitoring_factor = {
            SecurityPosture.HIGH: 0.3,
            SecurityPosture.MEDIUM: 0.6,
            SecurityPosture.LOW: 0.8
        }
        
        return length_factor + monitoring_factor.get(environment.security_posture, 0.6)
    
    def _assess_environmental_suitability(self, attack_chain: AttackChain, environment: EnvironmentContext) -> float:
        """Assess how suitable the environment is for this attack."""
        # Cloud environments might be more suitable for certain attacks
        deployment_suitability = {
            DeploymentType.LOCAL: 0.7,
            DeploymentType.REMOTE: 0.8,
            DeploymentType.CLOUD: 0.9,
            DeploymentType.HYBRID: 0.8
        }
        
        return deployment_suitability.get(environment.deployment_type, 0.7)
    
    def _assess_resource_requirements(self, attack_chain: AttackChain, environment: EnvironmentContext) -> float:
        """Assess whether attackers likely have required resources."""
        # Longer chains require more resources
        complexity_factor = max(0.4, 1.0 - (len(attack_chain.chain_links) * 0.1))
        
        # Time requirements
        time_factor = max(0.5, 1.0 - (attack_chain.total_time_estimate / 120.0))  # 2 hours baseline
        
        return (complexity_factor + time_factor) / 2
    
    def _access_level_score(self, access_level: AccessLevel) -> float:
        """Convert access level to numeric score."""
        scores = {
            AccessLevel.NONE: 0.0,
            AccessLevel.USER: 0.2,
            AccessLevel.ELEVATED: 0.6,
            AccessLevel.ADMIN: 0.8,
            AccessLevel.ROOT: 1.0
        }
        return scores.get(access_level, 0.5)
    
    def _generate_feasibility_rationale(self, technical: float, access: float, detection: float, 
                                      environmental: float, resources: float) -> str:
        """Generate human-readable rationale for feasibility score."""
        factors = [
            ("Technical feasibility", technical),
            ("Access requirements", access),
            ("Detection avoidance", detection),
            ("Environmental suitability", environmental),
            ("Resource requirements", resources)
        ]
        
        factors.sort(key=lambda x: x[1], reverse=True)
        
        strongest = factors[0]
        weakest = factors[-1]
        
        return f"Strongest factor: {strongest[0]} ({strongest[1]:.2f}), Weakest factor: {weakest[0]} ({weakest[1]:.2f})"
    
    def _build_capability_relationships(self) -> Dict[str, List[str]]:
        """Build predefined capability relationships."""
        return {
            "reconnaissance": ["file_access", "network_probe", "system_enum"],
            "file_access": ["data_extraction", "lateral_movement", "persistence"],
            "network_probe": ["service_enum", "lateral_movement", "c2_comm"],
            "data_extraction": ["exfiltration", "analysis"],
            "lateral_movement": ["privilege_escalation", "persistence"],
        }
    
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load known attack patterns."""
        return {
            "apt_pattern": {
                "steps": ["reconnaissance", "initial_access", "persistence", "lateral_movement", "exfiltration"],
                "indicators": ["multi_stage", "persistent", "stealthy"]
            },
            "ransomware_pattern": {
                "steps": ["reconnaissance", "lateral_movement", "encryption", "ransom_demand"],
                "indicators": ["file_encryption", "network_spread", "payment_demand"]
            }
        } 