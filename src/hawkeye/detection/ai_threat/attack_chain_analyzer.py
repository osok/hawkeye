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
    
    def identify_advanced_attack_chains(self,
                                      detected_tools: List[MCPServerInfo],
                                      environment_context: EnvironmentContext,
                                      threat_actor_types: List[ThreatActorType] = None,
                                      include_time_based_chains: bool = True,
                                      include_conditional_chains: bool = True) -> List[AttackChain]:
        """
        Enhanced attack chain identification with advanced analysis capabilities.
        
        This method provides more sophisticated attack chain analysis including:
        - Time-based attack sequences
        - Conditional attack paths
        - Threat actor-specific chains
        - Multi-objective attack scenarios
        
        Args:
            detected_tools: List of detected MCP servers
            environment_context: Environment context for analysis
            threat_actor_types: Specific threat actors to focus on
            include_time_based_chains: Include chains that require timing
            include_conditional_chains: Include chains with conditional steps
            
        Returns:
            List of advanced attack chains
        """
        start_time = datetime.now()
        logger.info(f"Starting advanced attack chain analysis for {len(detected_tools)} tools")
        
        try:
            # Extract enhanced tool capabilities with context
            tool_capabilities = self._extract_enhanced_tool_capabilities(detected_tools, environment_context)
            
            # Build enhanced capability graph with relationships
            capability_graph = self._build_enhanced_capability_graph(tool_capabilities, environment_context)
            
            # Find advanced attack paths
            advanced_paths = []
            
            # 1. Multi-objective attack paths
            multi_objective_paths = self._find_multi_objective_paths(
                capability_graph, tool_capabilities, environment_context
            )
            advanced_paths.extend(multi_objective_paths)
            
            # 2. Time-based attack sequences
            if include_time_based_chains:
                time_based_paths = self._find_time_based_attack_sequences(
                    capability_graph, tool_capabilities, environment_context
                )
                advanced_paths.extend(time_based_paths)
            
            # 3. Conditional attack paths
            if include_conditional_chains:
                conditional_paths = self._find_conditional_attack_paths(
                    capability_graph, tool_capabilities, environment_context
                )
                advanced_paths.extend(conditional_paths)
            
            # 4. Threat actor-specific chains
            if threat_actor_types:
                for actor_type in threat_actor_types:
                    actor_paths = self._find_actor_specific_chains(
                        capability_graph, tool_capabilities, environment_context, actor_type
                    )
                    advanced_paths.extend(actor_paths)
            
            # Convert paths to attack chains with enhanced analysis
            attack_chains = []
            for path in advanced_paths:
                chain = self._path_to_enhanced_attack_chain(path, tool_capabilities, environment_context)
                if chain:
                    # Enhanced feasibility assessment
                    feasibility = self._assess_enhanced_chain_feasibility(chain, environment_context)
                    chain.success_probability = feasibility.overall_score
                    chain.complexity_score = feasibility.complexity_score
                    chain.stealth_score = feasibility.stealth_score
                    attack_chains.append(chain)
            
            # Advanced chain ranking and optimization
            attack_chains = self._optimize_attack_chains(attack_chains, environment_context)
            
            analysis_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"Found {len(attack_chains)} advanced attack chains in {analysis_time:.2f}s")
            
            return attack_chains
            
        except Exception as e:
            logger.error(f"Error in advanced attack chain analysis: {e}")
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

    def discover_attack_chains(self,
                             detected_tools: List[MCPServerInfo],
                             environment_context: EnvironmentContext,
                             max_chain_depth: int = 5,
                             min_chain_score: float = 0.4) -> Dict[str, Any]:
        """
        Discover attack chains using the Attack Chain Discovery Algorithm.
        
        This implements the Attack Chain Discovery Algorithm from the design:
        1. Build capability dependency graph
        2. Identify potential pivot points
        3. Calculate chain feasibility scores
        4. Generate attack progression narratives
        5. Assess overall chain risk
        
        Args:
            detected_tools: List of detected MCP servers
            environment_context: Environment context for chain analysis
            max_chain_depth: Maximum chain length to consider
            min_chain_score: Minimum feasibility score for viable chains
            
        Returns:
            Dictionary containing discovered attack chains and analysis
        """
        try:
            start_time = datetime.now()
            logger.info(f"Starting attack chain discovery for {len(detected_tools)} tools")
            
            # Step 1: Build capability dependency graph
            dependency_graph = self._build_capability_dependency_graph(detected_tools)
            
            # Step 2: Identify potential pivot points
            pivot_points = self._identify_pivot_points(dependency_graph, detected_tools)
            
            # Step 3: Calculate chain feasibility scores
            chain_candidates = self._generate_chain_candidates(
                dependency_graph, 
                pivot_points, 
                max_chain_depth
            )
            
            feasible_chains = []
            for candidate in chain_candidates:
                feasibility_score = self._calculate_chain_feasibility_score(
                    candidate,
                    environment_context
                )
                
                if feasibility_score >= min_chain_score:
                    candidate['feasibility_score'] = feasibility_score
                    feasible_chains.append(candidate)
            
            # Step 4: Generate attack progression narratives
            chain_narratives = []
            for chain in feasible_chains:
                narrative = self._generate_attack_progression_narrative(
                    chain,
                    environment_context
                )
                chain['narrative'] = narrative
                chain_narratives.append(chain)
            
            # Step 5: Assess overall chain risk
            overall_risk_assessment = self._assess_overall_chain_risk(
                chain_narratives,
                environment_context
            )
            
            # Compile comprehensive discovery results
            discovery_results = {
                'analysis_timestamp': start_time.isoformat(),
                'tools_analyzed': len(detected_tools),
                'dependency_graph': {
                    'nodes': len(dependency_graph['nodes']),
                    'edges': len(dependency_graph['edges']),
                    'connected_components': dependency_graph['connected_components']
                },
                'pivot_points': {
                    'total_identified': len(pivot_points),
                    'high_value_pivots': len([p for p in pivot_points if p['pivot_value'] > 0.7]),
                    'pivot_details': pivot_points
                },
                'chain_candidates': {
                    'total_generated': len(chain_candidates),
                    'feasible_chains': len(feasible_chains),
                    'high_risk_chains': len([c for c in feasible_chains if c['feasibility_score'] > 0.7])
                },
                'discovered_chains': chain_narratives,
                'overall_risk': overall_risk_assessment,
                'discovery_metrics': {
                    'analysis_duration_seconds': (datetime.now() - start_time).total_seconds(),
                    'chains_per_tool_ratio': len(feasible_chains) / len(detected_tools) if detected_tools else 0.0,
                    'average_chain_length': sum(len(c['chain_steps']) for c in feasible_chains) / len(feasible_chains) if feasible_chains else 0.0,
                    'discovery_efficiency': len(feasible_chains) / len(chain_candidates) if chain_candidates else 0.0
                }
            }
            
            logger.info(f"Attack chain discovery completed: {len(feasible_chains)} viable chains found")
            return discovery_results
            
        except Exception as e:
            logger.error(f"Attack chain discovery failed: {e}")
            return {
                'error': str(e),
                'discovered_chains': [],
                'overall_risk': {'risk_level': 'unknown', 'confidence': 0.0}
            }
    
    def _build_capability_dependency_graph(self, detected_tools: List[MCPServerInfo]) -> Dict[str, Any]:
        """Build a graph of capability dependencies for attack chain discovery."""
        nodes = {}
        edges = []
        
        # Create nodes for each tool capability
        for tool in detected_tools:
            tool_id = tool.server_id
            
            # Extract tool capabilities (this would use the capability analyzer)
            capabilities = self._extract_tool_capabilities_for_graph(tool)
            
            for capability in capabilities:
                node_id = f"{tool_id}:{capability['name']}"
                nodes[node_id] = {
                    'tool_id': tool_id,
                    'capability_name': capability['name'],
                    'capability_type': capability['type'],
                    'risk_level': capability['risk_level'],
                    'prerequisites': capability['prerequisites'],
                    'outputs': capability['outputs'],
                    'access_requirements': capability['access_requirements']
                }
        
        # Create edges based on dependency relationships
        for source_id, source_node in nodes.items():
            for target_id, target_node in nodes.items():
                if source_id != target_id:
                    dependency_strength = self._calculate_dependency_strength(source_node, target_node)
                    
                    if dependency_strength > 0.3:  # Threshold for meaningful dependency
                        edges.append({
                            'source': source_id,
                            'target': target_id,
                            'strength': dependency_strength,
                            'dependency_type': self._classify_dependency_type(source_node, target_node),
                            'transition_difficulty': self._assess_transition_difficulty(source_node, target_node)
                        })
        
        # Analyze graph structure
        connected_components = self._find_connected_components(nodes, edges)
        
        return {
            'nodes': nodes,
            'edges': edges,
            'connected_components': connected_components,
            'graph_metrics': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'average_degree': (2 * len(edges)) / len(nodes) if nodes else 0,
                'graph_density': (2 * len(edges)) / (len(nodes) * (len(nodes) - 1)) if len(nodes) > 1 else 0
            }
        }
    
    def _identify_pivot_points(self, 
                             dependency_graph: Dict[str, Any],
                             detected_tools: List[MCPServerInfo]) -> List[Dict[str, Any]]:
        """Identify potential pivot points in the attack chain."""
        pivot_points = []
        nodes = dependency_graph['nodes']
        edges = dependency_graph['edges']
        
        # Calculate node centrality metrics
        for node_id, node_data in nodes.items():
            # Calculate incoming and outgoing connections
            incoming_edges = [e for e in edges if e['target'] == node_id]
            outgoing_edges = [e for e in edges if e['source'] == node_id]
            
            # Degree centrality
            degree_centrality = (len(incoming_edges) + len(outgoing_edges)) / (len(nodes) - 1) if len(nodes) > 1 else 0
            
            # Betweenness centrality (simplified)
            betweenness_score = self._calculate_betweenness_centrality(node_id, dependency_graph)
            
            # Access level scoring
            access_score = self._score_access_requirements(node_data['access_requirements'])
            
            # Capability diversity score
            diversity_score = self._calculate_capability_diversity_score(node_id, dependency_graph)
            
            # Calculate overall pivot value
            pivot_value = (
                degree_centrality * 0.3 +
                betweenness_score * 0.25 +
                access_score * 0.25 +
                diversity_score * 0.2
            )
            
            # Only consider high-value pivots
            if pivot_value > 0.5:
                pivot_point = {
                    'node_id': node_id,
                    'tool_id': node_data['tool_id'],
                    'capability_name': node_data['capability_name'],
                    'pivot_value': round(pivot_value, 3),
                    'pivot_characteristics': {
                        'degree_centrality': round(degree_centrality, 3),
                        'betweenness_centrality': round(betweenness_score, 3),
                        'access_score': round(access_score, 3),
                        'diversity_score': round(diversity_score, 3)
                    },
                    'incoming_connections': len(incoming_edges),
                    'outgoing_connections': len(outgoing_edges),
                    'pivot_rationale': self._generate_pivot_rationale(node_data, pivot_value),
                    'exploitation_difficulty': self._assess_pivot_exploitation_difficulty(node_data),
                    'strategic_value': self._assess_strategic_value(node_data, incoming_edges, outgoing_edges)
                }
                pivot_points.append(pivot_point)
        
        # Sort by pivot value (highest first)
        pivot_points.sort(key=lambda x: x['pivot_value'], reverse=True)
        
        return pivot_points[:10]  # Return top 10 pivot points
    
    def _generate_chain_candidates(self,
                                 dependency_graph: Dict[str, Any],
                                 pivot_points: List[Dict[str, Any]],
                                 max_depth: int) -> List[Dict[str, Any]]:
        """Generate candidate attack chains using graph traversal."""
        chain_candidates = []
        nodes = dependency_graph['nodes']
        edges = dependency_graph['edges']
        
        # Start chain generation from each high-value pivot point
        for pivot in pivot_points[:5]:  # Top 5 pivots
            start_node = pivot['node_id']
            
            # Use depth-first search to find attack paths
            paths = self._find_attack_paths_dfs(
                start_node,
                dependency_graph,
                max_depth,
                visited=set(),
                current_path=[start_node]
            )
            
            for path in paths:
                if len(path) >= 2:  # At least 2 steps for a meaningful chain
                    chain_candidate = {
                        'chain_id': f"chain_{len(chain_candidates) + 1}",
                        'starting_pivot': pivot['node_id'],
                        'chain_steps': path,
                        'chain_length': len(path),
                        'involved_tools': list(set(nodes[node]['tool_id'] for node in path)),
                        'attack_progression': [self._describe_attack_step(nodes[node], i) for i, node in enumerate(path)],
                        'chain_complexity': self._calculate_chain_complexity(path, dependency_graph),
                        'required_capabilities': [nodes[node]['capability_type'] for node in path],
                        'cumulative_risk': self._calculate_cumulative_risk(path, nodes)
                    }
                    chain_candidates.append(chain_candidate)
        
        # Remove duplicate or similar chains
        unique_candidates = self._deduplicate_chain_candidates(chain_candidates)
        
        return unique_candidates[:20]  # Return top 20 candidates
    
    def _calculate_chain_feasibility_score(self,
                                         chain_candidate: Dict[str, Any],
                                         environment_context: EnvironmentContext) -> float:
        """Calculate detailed feasibility score for an attack chain."""
        
        # Technical feasibility (0.0-1.0)
        technical_score = 1.0 - (chain_candidate['chain_complexity'] / 10.0)  # Normalize complexity
        technical_score = max(0.1, min(1.0, technical_score))
        
        # Resource requirements (0.0-1.0)
        resource_score = 1.0 - (chain_candidate['chain_length'] / 10.0)  # Longer chains need more resources
        resource_score = max(0.1, min(1.0, resource_score))
        
        # Environment suitability (0.0-1.0)
        environment_score = self._assess_environment_suitability(chain_candidate, environment_context)
        
        # Detection avoidance (0.0-1.0)
        stealth_score = self._assess_chain_stealth(chain_candidate, environment_context)
        
        # Success probability based on historical patterns (0.0-1.0)
        success_probability = self._estimate_chain_success_probability(chain_candidate)
        
        # Weighted combination
        feasibility_score = (
            technical_score * 0.25 +      # 25% technical feasibility
            resource_score * 0.2 +        # 20% resource requirements
            environment_score * 0.25 +    # 25% environment suitability
            stealth_score * 0.15 +        # 15% detection avoidance
            success_probability * 0.15    # 15% success probability
        )
        
        return round(feasibility_score, 3)
    
    def _generate_attack_progression_narrative(self,
                                             chain: Dict[str, Any],
                                             environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Generate detailed narrative for attack progression."""
        narrative = {
            'chain_id': chain['chain_id'],
            'title': f"Multi-Stage Attack: {chain['starting_pivot']} → {len(chain['chain_steps'])} steps",
            'attack_scenario': self._create_attack_scenario_description(chain),
            'detailed_steps': [],
            'timeline_estimate': self._estimate_attack_timeline(chain),
            'actor_profile': self._identify_likely_threat_actors(chain),
            'required_skills': self._assess_required_skills(chain),
            'indicators_of_compromise': self._generate_chain_iocs(chain),
            'defensive_opportunities': self._identify_defensive_opportunities(chain)
        }
        
        # Generate detailed step descriptions
        for i, step in enumerate(chain['attack_progression']):
            step_detail = {
                'step_number': i + 1,
                'step_title': step,
                'detailed_description': self._generate_step_description(i, chain, environment_context),
                'required_access': self._determine_step_access_requirements(i, chain),
                'tools_involved': self._identify_step_tools(i, chain),
                'expected_outputs': self._predict_step_outputs(i, chain),
                'detection_likelihood': self._assess_step_detection_risk(i, chain, environment_context),
                'mitigation_opportunities': self._identify_step_mitigations(i, chain)
            }
            narrative['detailed_steps'].append(step_detail)
        
        return narrative
    
    def _assess_overall_chain_risk(self,
                                 chain_narratives: List[Dict[str, Any]],
                                 environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Assess overall risk posed by discovered attack chains."""
        if not chain_narratives:
            return {
                'risk_level': 'low',
                'confidence': 0.2,
                'risk_factors': [],
                'recommendations': ['No viable attack chains identified']
            }
        
        # Calculate risk metrics
        high_risk_chains = len([c for c in chain_narratives if c['feasibility_score'] > 0.7])
        medium_risk_chains = len([c for c in chain_narratives if 0.4 <= c['feasibility_score'] <= 0.7])
        
        average_feasibility = sum(c['feasibility_score'] for c in chain_narratives) / len(chain_narratives)
        max_chain_length = max(c['chain_length'] for c in chain_narratives)
        unique_tools_involved = len(set().union(*[c['involved_tools'] for c in chain_narratives]))
        
        # Determine overall risk level
        if high_risk_chains >= 3 or average_feasibility > 0.75:
            risk_level = 'critical'
            confidence = 0.9
        elif high_risk_chains >= 1 or average_feasibility > 0.6:
            risk_level = 'high'
            confidence = 0.8
        elif medium_risk_chains >= 2 or average_feasibility > 0.4:
            risk_level = 'medium'
            confidence = 0.7
        else:
            risk_level = 'low'
            confidence = 0.6
        
        # Identify key risk factors
        risk_factors = []
        if high_risk_chains > 0:
            risk_factors.append(f"{high_risk_chains} high-feasibility attack chains identified")
        if max_chain_length > 4:
            risk_factors.append(f"Complex multi-stage attacks possible ({max_chain_length} steps)")
        if unique_tools_involved > 5:
            risk_factors.append(f"Large attack surface ({unique_tools_involved} tools involved)")
        if average_feasibility > 0.6:
            risk_factors.append(f"High average attack feasibility ({average_feasibility:.2f})")
        
        # Generate risk-based recommendations
        recommendations = self._generate_risk_recommendations(
            chain_narratives,
            risk_level,
            environment_context
        )
        
        return {
            'risk_level': risk_level,
            'confidence': confidence,
            'risk_score': round(average_feasibility, 3),
            'risk_factors': risk_factors,
            'chain_statistics': {
                'total_chains': len(chain_narratives),
                'high_risk_chains': high_risk_chains,
                'medium_risk_chains': medium_risk_chains,
                'average_feasibility': round(average_feasibility, 3),
                'max_chain_length': max_chain_length,
                'unique_tools_involved': unique_tools_involved
            },
            'recommendations': recommendations,
            'priority_actions': self._prioritize_defensive_actions(chain_narratives)
        }

    def _extract_tool_capabilities_for_graph(self, tool: MCPServerInfo) -> List[Dict[str, Any]]:
        """Extract tool capabilities for graph building (simplified version)."""
        # This is a simplified version - in practice would use the full capability analyzer
        capabilities = []
        
        # Mock capability extraction based on tool metadata
        tool_name = tool.metadata.get('name', 'unknown')
        
        # Basic capability inference (would be replaced with real analysis)
        if 'file' in tool_name.lower():
            capabilities.append({
                'name': 'file_access',
                'type': 'filesystem',
                'risk_level': 0.7,
                'prerequisites': ['file_permissions'],
                'outputs': ['file_contents', 'directory_listing'],
                'access_requirements': 'user'
            })
        
        if 'network' in tool_name.lower() or 'web' in tool_name.lower():
            capabilities.append({
                'name': 'network_access',
                'type': 'network',
                'risk_level': 0.6,
                'prerequisites': ['network_connectivity'],
                'outputs': ['network_data', 'external_responses'],
                'access_requirements': 'user'
            })
        
        if 'exec' in tool_name.lower() or 'run' in tool_name.lower():
            capabilities.append({
                'name': 'code_execution',
                'type': 'execution',
                'risk_level': 0.9,
                'prerequisites': ['execution_permissions'],
                'outputs': ['command_results', 'process_output'],
                'access_requirements': 'elevated'
            })
        
        # Default capability if none identified
        if not capabilities:
            capabilities.append({
                'name': 'data_processing',
                'type': 'processing',
                'risk_level': 0.3,
                'prerequisites': ['tool_access'],
                'outputs': ['processed_data'],
                'access_requirements': 'user'
            })
        
        return capabilities
    
    def _calculate_dependency_strength(self, source_node: Dict[str, Any], target_node: Dict[str, Any]) -> float:
        """Calculate dependency strength between two capability nodes."""
        strength = 0.0
        
        # Output-to-prerequisite matching
        source_outputs = source_node.get('outputs', [])
        target_prerequisites = target_node.get('prerequisites', [])
        
        matches = sum(1 for output in source_outputs 
                     for prereq in target_prerequisites 
                     if self._outputs_match_prerequisites(output, prereq))
        
        if matches > 0:
            strength += 0.4 * (matches / max(len(source_outputs), len(target_prerequisites)))
        
        # Access level progression
        source_access = source_node.get('access_requirements', 'user')
        target_access = target_node.get('access_requirements', 'user')
        
        if self._access_progression_valid(source_access, target_access):
            strength += 0.3
        
        # Capability type synergy
        source_type = source_node.get('capability_type', '')
        target_type = target_node.get('capability_type', '')
        
        if self._types_have_synergy(source_type, target_type):
            strength += 0.3
        
        return min(1.0, strength)
    
    def _classify_dependency_type(self, source_node: Dict[str, Any], target_node: Dict[str, Any]) -> str:
        """Classify the type of dependency between nodes."""
        source_type = source_node.get('capability_type', '')
        target_type = target_node.get('capability_type', '')
        
        type_transitions = {
            ('filesystem', 'network'): 'data_exfiltration',
            ('network', 'filesystem'): 'payload_delivery',
            ('filesystem', 'execution'): 'payload_execution',
            ('network', 'execution'): 'remote_execution',
            ('execution', 'filesystem'): 'persistence',
            ('execution', 'network'): 'command_control'
        }
        
        return type_transitions.get((source_type, target_type), 'generic_flow')
    
    def _assess_transition_difficulty(self, source_node: Dict[str, Any], target_node: Dict[str, Any]) -> float:
        """Assess difficulty of transitioning between capabilities."""
        # Base difficulty
        difficulty = 0.3
        
        # Access level requirements
        source_access = source_node.get('access_requirements', 'user')
        target_access = target_node.get('access_requirements', 'user')
        
        access_levels = {'user': 1, 'elevated': 2, 'admin': 3}
        source_level = access_levels.get(source_access, 1)
        target_level = access_levels.get(target_access, 1)
        
        if target_level > source_level:
            difficulty += 0.2 * (target_level - source_level)
        
        # Risk level difference
        source_risk = source_node.get('risk_level', 0.5)
        target_risk = target_node.get('risk_level', 0.5)
        
        if target_risk > source_risk:
            difficulty += 0.1 * (target_risk - source_risk)
        
        return min(1.0, difficulty)

    def _find_connected_components(self, nodes: Dict[str, Any], edges: List[Dict[str, Any]]) -> List[List[str]]:
        """Find connected components in a graph."""
        visited = set()
        components = []
        
        for node_id in nodes:
            if node_id not in visited:
                component = []
                self._dfs_find_connected_components(node_id, nodes, edges, visited, component)
                components.append(component)
        return components

    def _dfs_find_connected_components(self, node_id: str, nodes: Dict[str, Any], edges: List[Dict[str, Any]], visited: Set[str], component: List[str]) -> None:
        """Depth-first search to find connected components."""
        visited.add(node_id)
        component.append(node_id)
        for edge in edges:
            if edge['source'] == node_id and edge['target'] not in visited:
                self._dfs_find_connected_components(edge['target'], nodes, edges, visited, component)
            elif edge['target'] == node_id and edge['source'] not in visited:
                self._dfs_find_connected_components(edge['source'], nodes, edges, visited, component)

    def _calculate_betweenness_centrality(self, node_id: str, graph: Dict[str, Any]) -> float:
        """Calculate betweenness centrality for a node."""
        nodes = graph['nodes']
        edges = graph['edges']
        
        # Initialize betweenness centrality
        betweenness = {n: 0.0 for n in nodes}
        
        # For each pair of nodes, calculate shortest paths
        for source_id, source_node in nodes.items():
            for target_id, target_node in nodes.items():
                if source_id != target_id:
                    shortest_paths = self._find_all_shortest_paths(source_id, target_id, graph)
                    for path in shortest_paths:
                        for i, node in enumerate(path):
                            if node == node_id:
                                # Count how many shortest paths pass through node_id
                                betweenness[node_id] += 1.0 / len(shortest_paths)
                                break
        
        # Normalize betweenness centrality
        max_betweenness = max(betweenness.values())
        if max_betweenness > 0:
            for node in betweenness:
                betweenness[node] /= max_betweenness
        
        return betweenness.get(node_id, 0.0)

    def _find_all_shortest_paths(self, start: str, end: str, graph: Dict[str, Any]) -> List[List[str]]:
        """Find all shortest paths between two nodes using BFS."""
        nodes = graph['nodes']
        edges = graph['edges']
        
        # Use a queue for BFS
        queue = [(start, [start])] # (current_node, path)
        all_paths = []
        
        while queue:
            current_node, path = queue.pop(0)
            
            if current_node == end:
                all_paths.append(path)
                continue
            
            for edge in edges:
                if edge['source'] == current_node and edge['target'] not in path:
                    queue.append((edge['target'], path + [edge['target']]))
                elif edge['target'] == current_node and edge['source'] not in path:
                    queue.append((edge['source'], path + [edge['source']]))
        
        return all_paths

    def _score_access_requirements(self, access_requirements: List[str]) -> float:
        """Score access requirements based on severity."""
        scores = {
            'none': 0.0,
            'user': 0.2,
            'elevated': 0.6,
            'admin': 0.8,
            'root': 1.0
        }
        return scores.get(min(access_requirements, key=lambda x: scores[x]), 0.5)

    def _calculate_capability_diversity_score(self, node_id: str, graph: Dict[str, Any]) -> float:
        """Calculate capability diversity score for a node."""
        nodes = graph['nodes']
        edges = graph['edges']
        
        # Get all capabilities connected to this node
        connected_capabilities = set()
        for edge in edges:
            if edge['source'] == node_id:
                connected_capabilities.add(edge['target'])
            elif edge['target'] == node_id:
                connected_capabilities.add(edge['source'])
        
        # If no other capabilities are connected, it's a single-capability node
        if len(connected_capabilities) == 1:
            return 0.0
        
        # Calculate diversity
        diversity = 0.0
        for cap_id in connected_capabilities:
            cap_node = nodes.get(cap_id)
            if cap_node:
                diversity += cap_node.get('risk_level', 0.5) # Use risk level as a proxy for diversity
        
        # Normalize diversity
        max_diversity = max(nodes[cap_id].get('risk_level', 0.5) for cap_id in connected_capabilities)
        if max_diversity > 0:
            diversity /= max_diversity
        
        return diversity

    def _assess_strategic_value(self, node_data: Dict[str, Any], incoming_edges: List[Dict[str, Any]], outgoing_edges: List[Dict[str, Any]]) -> float:
        """Assess the strategic value of a pivot point."""
        # High strategic value if it connects to multiple high-risk capabilities
        # or if it's a critical transition point (e.g., network to filesystem)
        strategic_value = 0.0
        
        # Check for high-risk capabilities connected to this node
        high_risk_connected = False
        for edge in incoming_edges + outgoing_edges:
            if edge['strength'] > 0.7: # Threshold for high-strength dependency
                target_node = graph['nodes'].get(edge['target'])
                if target_node and target_node.get('risk_level', 0.5) > 0.7:
                    high_risk_connected = True
                    break
        
        # Check for critical transitions
        critical_transitions = 0
        for edge in outgoing_edges:
            if edge['dependency_type'] in ['data_exfiltration', 'payload_delivery', 'remote_execution']:
                critical_transitions += 1
        
        # Combine factors
        strategic_value = 0.5 # Base value
        if high_risk_connected:
            strategic_value += 0.3
        if critical_transitions > 0:
            strategic_value += 0.2 * critical_transitions
        
        return min(1.0, strategic_value)

    def _assess_pivot_exploitation_difficulty(self, node_data: Dict[str, Any]) -> float:
        """Assess the difficulty of exploiting a pivot point."""
        # Difficulty increases with higher access requirements and risk level
        access_score = self._score_access_requirements(node_data['access_requirements'])
        risk_level = node_data.get('risk_level', 0.5)
        
        difficulty = 0.3 + (access_score * 0.5) + (risk_level * 0.2)
        return min(1.0, difficulty)

    def _find_attack_paths_dfs(self,
                              current_node: str,
                              graph: Dict[str, Any],
                              max_depth: int,
                              visited: Set[str],
                              current_path: List[str]) -> List[List[str]]:
        """Depth-first search to find all possible attack paths."""
        visited.add(current_node)
        current_path.append(current_node)
        
        if len(current_path) >= max_depth:
            visited.remove(current_node)
            current_path.pop()
            return []
        
        all_paths = []
        for edge in graph['edges']:
            if edge['source'] == current_node and edge['target'] not in visited:
                new_paths = self._find_attack_paths_dfs(edge['target'], graph, max_depth, visited, current_path)
                all_paths.extend(new_paths)
            elif edge['target'] == current_node and edge['source'] not in visited:
                new_paths = self._find_attack_paths_dfs(edge['source'], graph, max_depth, visited, current_path)
                all_paths.extend(new_paths)
        
        visited.remove(current_node)
        current_path.pop()
        
        return all_paths

    def _calculate_chain_complexity(self, path: List[str], graph: Dict[str, Any]) -> float:
        """Calculate complexity of an attack chain based on path length and dependencies."""
        # Simple complexity: length + number of unique capabilities
        complexity = len(path)
        unique_capabilities = set(graph['nodes'][node]['capability_type'] for node in path)
        complexity += len(unique_capabilities) * 0.5 # More unique capabilities increase complexity
        
        # Add penalty for high-risk transitions
        penalty = 0.0
        for i in range(len(path) - 1):
            current_node = path[i]
            next_node = path[i+1]
            for edge in graph['edges']:
                if (edge['source'] == current_node and edge['target'] == next_node) or \
                   (edge['target'] == current_node and edge['source'] == next_node):
                    if edge['transition_difficulty'] > 0.7: # High difficulty transition
                        penalty += 0.5
        
        return min(10.0, complexity + penalty) # Cap complexity at 10

    def _calculate_cumulative_risk(self, path: List[str], nodes: Dict[str, Any]) -> float:
        """Calculate cumulative risk of an attack chain."""
        risk_sum = 0.0
        for node_id in path:
            node_data = nodes.get(node_id)
            if node_data:
                risk_sum += node_data.get('risk_level', 0.5)
        return risk_sum / len(path) if path else 0.0 # Average risk per step

    def _deduplicate_chain_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate or highly similar chain candidates."""
        seen_chains = set()
        unique_candidates = []
        
        for candidate in candidates:
            # Create a unique identifier for the chain
            chain_id = "->".join(sorted(candidate['chain_steps']))
            
            if chain_id not in seen_chains:
                unique_candidates.append(candidate)
                seen_chains.add(chain_id)
        
        return unique_candidates

    def _generate_pivot_rationale(self, node_data: Dict[str, Any], pivot_value: float) -> str:
        """Generate rationale for a high-value pivot point."""
        rationale = f"High pivot value ({pivot_value:.3f}) due to: "
        
        if node_data['incoming_connections'] > 0 and node_data['outgoing_connections'] > 0:
            rationale += f"Multiple connections ({node_data['incoming_connections']} incoming, {node_data['outgoing_connections']} outgoing) "
        elif node_data['incoming_connections'] > 0:
            rationale += f"Many incoming connections ({node_data['incoming_connections']}) "
        elif node_data['outgoing_connections'] > 0:
            rationale += f"Many outgoing connections ({node_data['outgoing_connections']}) "
        
        if node_data['access_score'] > 0.6:
            rationale += f"High access requirements ({node_data['access_score']:.2f}) "
        if node_data['diversity_score'] > 0.6:
            rationale += f"High capability diversity ({node_data['diversity_score']:.2f}) "
        if node_data['strategic_value'] > 0.6:
            rationale += f"Strategic value ({node_data['strategic_value']:.2f}) "
        
        return rationale.strip()

    def _assess_strategic_value(self, node_data: Dict[str, Any], incoming_edges: List[Dict[str, Any]], outgoing_edges: List[Dict[str, Any]]) -> float:
        """Assess the strategic value of a pivot point."""
        # High strategic value if it connects to multiple high-risk capabilities
        # or if it's a critical transition point (e.g., network to filesystem)
        strategic_value = 0.0
        
        # Check for high-risk capabilities connected to this node
        high_risk_connected = False
        for edge in incoming_edges + outgoing_edges:
            if edge['strength'] > 0.7: # Threshold for high-strength dependency
                target_node = graph['nodes'].get(edge['target'])
                if target_node and target_node.get('risk_level', 0.5) > 0.7:
                    high_risk_connected = True
                    break
        
        # Check for critical transitions
        critical_transitions = 0
        for edge in outgoing_edges:
            if edge['dependency_type'] in ['data_exfiltration', 'payload_delivery', 'remote_execution']:
                critical_transitions += 1
        
        # Combine factors
        strategic_value = 0.5 # Base value
        if high_risk_connected:
            strategic_value += 0.3
        if critical_transitions > 0:
            strategic_value += 0.2 * critical_transitions
        
        return min(1.0, strategic_value)

    def _assess_pivot_exploitation_difficulty(self, node_data: Dict[str, Any]) -> float:
        """Assess the difficulty of exploiting a pivot point."""
        # Difficulty increases with higher access requirements and risk level
        access_score = self._score_access_requirements(node_data['access_requirements'])
        risk_level = node_data.get('risk_level', 0.5)
        
        difficulty = 0.3 + (access_score * 0.5) + (risk_level * 0.2)
        return min(1.0, difficulty)

    def _generate_step_description(self, step_index: int, chain: Dict[str, Any], environment_context: EnvironmentContext) -> str:
        """Generate a detailed description for each step in the chain."""
        nodes = chain['chain_steps']
        if step_index == 0:
            return f"Starting with a high-value pivot point: {nodes[0]}"
        elif step_index == len(nodes) - 1:
            return f"Final step: {nodes[-1]}"
        else:
            current_node = nodes[step_index]
            next_node = nodes[step_index + 1]
            current_cap = self._describe_capability(current_node)
            next_cap = self._describe_capability(next_node)
            
            # Determine the type of transition
            transition_type = 'generic'
            for edge in environment_context.graph['edges']:
                if (edge['source'] == current_node and edge['target'] == next_node) or \
                   (edge['target'] == current_node and edge['source'] == next_node):
                    transition_type = edge['dependency_type']
                    break
            
            if transition_type == 'generic_flow':
                return f"Transitioning from {current_cap} to {next_cap}."
            else:
                return f"Executing a {transition_type} from {current_cap} to {next_cap}."

    def _describe_capability(self, node_id: str) -> str:
        """Helper to get a descriptive name for a capability node."""
        nodes = environment_context.graph['nodes']
        node_data = nodes.get(node_id)
        if node_data:
            return f"{node_data['capability_type']} capability"
        return node_id

    def _determine_step_access_requirements(self, step_index: int, chain: Dict[str, Any]) -> List[str]:
        """Determine required access for each step in the chain."""
        nodes = chain['chain_steps']
        if step_index == 0:
            return ["Initial access to MCP server"]
        elif step_index == len(nodes) - 1:
            return ["Maintained access to target systems"]
        else:
            current_node = nodes[step_index]
            current_cap = self._describe_capability(current_node)
            return [f"Access to {current_cap}"]

    def _identify_step_tools(self, step_index: int, chain: Dict[str, Any]) -> List[str]:
        """Identify tools involved in each step of the chain."""
        nodes = chain['chain_steps']
        tools = []
        for node_id in nodes:
            for tool_id, tool_data in environment_context.graph['nodes'].items():
                if tool_id == node_id:
                    tools.append(tool_data['tool_id'])
                    break
        return list(set(tools))

    def _predict_step_outputs(self, step_index: int, chain: Dict[str, Any]) -> List[str]:
        """Predict outputs for each step of the chain."""
        nodes = chain['chain_steps']
        outputs = []
        for node_id in nodes:
            for tool_id, tool_data in environment_context.graph['nodes'].items():
                if tool_id == node_id:
                    outputs.extend(tool_data.get('outputs', []))
                    break
        return list(set(outputs))

    def _assess_step_detection_risk(self, step_index: int, chain: Dict[str, Any], environment_context: EnvironmentContext) -> float:
        """Assess detection likelihood for each step of the chain."""
        nodes = chain['chain_steps']
        detection_risk = 0.0
        for node_id in nodes:
            for tool_id, tool_data in environment_context.graph['nodes'].items():
                if tool_id == node_id:
                    detection_risk += tool_data.get('risk_level', 0.5)
                    break
        return detection_risk / len(nodes) if nodes else 0.0

    def _identify_step_mitigations(self, step_index: int, chain: Dict[str, Any]) -> List[str]:
        """Identify potential mitigations for each step of the chain."""
        nodes = chain['chain_steps']
        mitigations = []
        for node_id in nodes:
            for tool_id, tool_data in environment_context.graph['nodes'].items():
                if tool_id == node_id:
                    mitigations.extend(tool_data.get('mitigation_strategies', []))
                    break
        return list(set(mitigations))

    def _generate_chain_iocs(self, chain: Dict[str, Any]) -> List[str]:
        """Generate indicators of compromise for the attack chain."""
        nodes = chain['chain_steps']
        iocs = []
        for node_id in nodes:
            for tool_id, tool_data in environment_context.graph['nodes'].items():
                if tool_id == node_id:
                    iocs.extend(tool_data.get('outputs', []))
                    break
        return list(set(iocs))

    def _identify_defensive_opportunities(self, chain: Dict[str, Any]) -> List[str]:
        """Identify potential defensive opportunities for the attack chain."""
        nodes = chain['chain_steps']
        opportunities = []
        for node_id in nodes:
            for tool_id, tool_data in environment_context.graph['nodes'].items():
                if tool_id == node_id:
                    opportunities.extend(tool_data.get('mitigation_strategies', []))
                    break
        return list(set(opportunities))

    def _generate_risk_recommendations(self, chain_narratives: List[Dict[str, Any]], risk_level: str, environment_context: EnvironmentContext) -> List[str]:
        """Generate risk-based recommendations."""
        recommendations = []
        
        if risk_level == 'critical':
            recommendations.append("Immediate attention required. High-risk attack chains identified.")
            recommendations.append("Implement all recommended mitigations immediately.")
            recommendations.append("Enhance security posture to HIGH.")
            recommendations.append("Conduct threat actor simulation exercises.")
            recommendations.append("Review and update incident response plans.")
        elif risk_level == 'high':
            recommendations.append("High-risk attack chains identified. Prioritize mitigations.")
            recommendations.append("Enhance security posture to MEDIUM.")
            recommendations.append("Conduct regular security assessments.")
            recommendations.append("Review and update incident response plans.")
        elif risk_level == 'medium':
            recommendations.append("Medium-risk attack chains identified. Monitor for anomalies.")
            recommendations.append("Enhance security posture to LOW.")
            recommendations.append("Conduct regular security audits.")
            recommendations.append("Review and update incident response plans.")
        else: # low
            recommendations.append("No high-risk attack chains identified. Continue with normal security measures.")
            recommendations.append("Monitor for unusual activity patterns.")
        
        return recommendations

    def _prioritize_defensive_actions(self, chain_narratives: List[Dict[str, Any]]) -> List[str]:
        """Prioritize defensive actions based on discovered chains."""
        # This is a simplified example. In a real system, you'd analyze
        # the chains to identify common patterns and prioritize mitigations.
        # For now, return a generic list.
        return [
            "Implement comprehensive logging and monitoring",
            "Deploy behavioral analysis tools",
            "Apply principle of least privilege",
            "Segment network access"
        ]

    def _assess_enhanced_chain_feasibility(self, chain: AttackChain, environment: EnvironmentContext) -> ChainFeasibilityScore:
        """Assess feasibility of an enhanced attack chain."""
        # This is a simplified version of the original assess_chain_feasibility
        # that uses the new discovery algorithm's scoring.
        # In a real system, you'd integrate this with the new discovery logic.
        # For now, we'll just return a placeholder score.
        return ChainFeasibilityScore(
            chain_id=chain.chain_id,
            overall_score=0.7, # Placeholder score
            technical_feasibility=0.8,
            access_feasibility=0.6,
            detection_avoidance=0.9,
            environmental_suitability=0.8,
            resource_requirements=0.7,
            scoring_rationale="Enhanced feasibility assessment (placeholder)",
            confidence_level=0.8
        )

    def _optimize_attack_chains(self, attack_chains: List[AttackChain], environment: EnvironmentContext) -> List[AttackChain]:
        """Optimize attack chains based on environmental factors."""
        # This is a simplified optimization.
        # In a real system, you'd use a more sophisticated algorithm
        # that considers environmental factors and chain complexity.
        return sorted(attack_chains, key=lambda c: c.success_probability, reverse=True)

    def _outputs_match_prerequisites(self, output: str, prerequisite: str) -> bool:
        """Check if an output can be used to satisfy a prerequisite."""
        # This is a very basic matching. In a real system, you'd have
        # a more sophisticated mapping of outputs to prerequisites.
        return output.lower() in prerequisite.lower()

    def _access_progression_valid(self, source_access: str, target_access: str) -> bool:
        """Check if access level progression is valid."""
        # This is a simplified check. In a real system, you'd have
        # a more sophisticated mapping of access levels and their capabilities.
        access_levels = {'user': 1, 'elevated': 2, 'admin': 3, 'root': 4}
        return access_levels.get(source_access, 1) <= access_levels.get(target_access, 1)

    def _types_have_synergy(self, source_type: str, target_type: str) -> bool:
        """Check if two capability types have synergy."""
        # This is a simplified check. In a real system, you'd have
        # a more sophisticated mapping of capability types and their combinations.
        return source_type == 'network' and target_type == 'filesystem' # Example synergy

    def _assess_chain_stealth(self, chain: Dict[str, Any], environment: EnvironmentContext) -> float:
        """Assess the stealth of an attack chain."""
        # This is a simplified stealth assessment.
        # In a real system, you'd consider factors like:
        # - Length of the chain
        # - Number of steps
        # - Complexity of transitions
        # - Access requirements
        # - Environmental monitoring
        stealth_score = 0.0
        stealth_score += 0.2 * (chain['chain_length'] / 10.0) # Longer chains are harder to detect
        stealth_score += 0.2 * (chain['chain_complexity'] / 10.0) # More complex chains are harder
        stealth_score += 0.2 * (self._access_level_score(chain['required_capabilities'][-1]) * 0.5) # Final step access
        stealth_score += 0.2 * (self._assess_environmental_suitability(chain, environment) * 0.5) # Environment suitability
        stealth_score += 0.2 * (self._assess_detection_avoidance(chain, environment) * 0.5) # Detection avoidance
        
        return min(1.0, stealth_score)

    def _estimate_chain_success_probability(self, chain: Dict[str, Any]) -> float:
        """Estimate the overall success probability of an attack chain."""
        # This is a simplified success probability estimation.
        # In a real system, you'd use historical data, threat models,
        # and the feasibility score of the chain.
        return min(1.0, chain['feasibility_score'] * 1.5) # Feasibility score influences success

    def _describe_attack_step(self, node_data: Dict[str, Any], index: int) -> str:
        """Describe a single step in the chain."""
        return f"Step {index + 1}: {node_data['capability_name']}"

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