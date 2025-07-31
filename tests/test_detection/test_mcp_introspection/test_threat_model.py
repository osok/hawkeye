"""
Unit tests for ThreatModel and ThreatModelingEngine

Tests the threat modeling functionality including threat analysis,
attack vector identification, and risk assessment.
"""

import unittest
from unittest.mock import Mock, patch
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection.models import (
    MCPTool, MCPCapability, SecurityRisk, RiskLevel, RiskCategory
)
from src.hawkeye.detection.mcp_introspection.risk.threat_model import (
    ThreatModel, ThreatModelingEngine, ThreatCategory, AttackVector, Threat
)


class TestThreatModel(unittest.TestCase):
    """Test cases for ThreatModel."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.threat_model = ThreatModel()
        
        # Sample capabilities
        self.file_capability = MCPCapability(
            name="file_operations",
            description="File system operations",
            supported_operations=["read", "write", "delete"]
        )
        
        self.network_capability = MCPCapability(
            name="network_access",
            description="Network communication",
            supported_operations=["http_request", "download"]
        )
    
    def test_threat_model_initialization(self):
        """Test threat model initialization."""
        self.assertIsInstance(self.threat_model, ThreatModel)
        self.assertIsInstance(self.threat_model.threats, list)
        self.assertIsInstance(self.threat_model.attack_vectors, list)
        self.assertIsInstance(self.threat_model.mitigations, dict)
    
    def test_add_threat(self):
        """Test adding threats to the model."""
        threat = Threat(
            id="T001",
            name="Data Exfiltration",
            description="Unauthorized data access and transfer",
            category=ThreatCategory.DATA_BREACH,
            severity=RiskLevel.HIGH,
            likelihood=0.7,
            impact=0.9,
            attack_vectors=[AttackVector.FILE_ACCESS, AttackVector.NETWORK_COMMUNICATION]
        )
        
        self.threat_model.add_threat(threat)
        self.assertIn(threat, self.threat_model.threats)
        self.assertEqual(len(self.threat_model.threats), 1)
    
    def test_add_attack_vector(self):
        """Test adding attack vectors."""
        vector = AttackVector.CODE_INJECTION
        self.threat_model.add_attack_vector(vector)
        self.assertIn(vector, self.threat_model.attack_vectors)
    
    def test_add_mitigation(self):
        """Test adding mitigations."""
        threat_id = "T001"
        mitigation = "Implement access controls and monitoring"
        
        self.threat_model.add_mitigation(threat_id, mitigation)
        self.assertIn(threat_id, self.threat_model.mitigations)
        self.assertIn(mitigation, self.threat_model.mitigations[threat_id])
    
    def test_get_threats_by_category(self):
        """Test filtering threats by category."""
        threat1 = Threat(
            id="T001", name="Test1", description="Test", 
            category=ThreatCategory.DATA_BREACH, severity=RiskLevel.HIGH,
            likelihood=0.5, impact=0.5, attack_vectors=[]
        )
        threat2 = Threat(
            id="T002", name="Test2", description="Test",
            category=ThreatCategory.SYSTEM_COMPROMISE, severity=RiskLevel.MEDIUM,
            likelihood=0.5, impact=0.5, attack_vectors=[]
        )
        
        self.threat_model.add_threat(threat1)
        self.threat_model.add_threat(threat2)
        
        data_threats = self.threat_model.get_threats_by_category(ThreatCategory.DATA_BREACH)
        self.assertEqual(len(data_threats), 1)
        self.assertEqual(data_threats[0].id, "T001")
    
    def test_get_threats_by_severity(self):
        """Test filtering threats by severity."""
        threat1 = Threat(
            id="T001", name="Test1", description="Test",
            category=ThreatCategory.DATA_BREACH, severity=RiskLevel.HIGH,
            likelihood=0.5, impact=0.5, attack_vectors=[]
        )
        threat2 = Threat(
            id="T002", name="Test2", description="Test",
            category=ThreatCategory.SYSTEM_COMPROMISE, severity=RiskLevel.MEDIUM,
            likelihood=0.5, impact=0.5, attack_vectors=[]
        )
        
        self.threat_model.add_threat(threat1)
        self.threat_model.add_threat(threat2)
        
        high_threats = self.threat_model.get_threats_by_severity(RiskLevel.HIGH)
        self.assertEqual(len(high_threats), 1)
        self.assertEqual(high_threats[0].id, "T001")
    
    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        threat = Threat(
            id="T001", name="Test", description="Test",
            category=ThreatCategory.DATA_BREACH, severity=RiskLevel.HIGH,
            likelihood=0.8, impact=0.9, attack_vectors=[]
        )
        
        score = self.threat_model.calculate_risk_score(threat)
        expected_score = 0.8 * 0.9 * 7.0  # likelihood * impact * severity_weight
        self.assertAlmostEqual(score, expected_score, places=2)


class TestThreatModelingEngine(unittest.TestCase):
    """Test cases for ThreatModelingEngine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = ThreatModelingEngine()
        
        # Sample tools
        self.file_tool = MCPTool(
            name="read_file",
            description="Read file contents",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}}
        )
        
        self.network_tool = MCPTool(
            name="http_request",
            description="Make HTTP requests",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}}
        )
        
        self.exec_tool = MCPTool(
            name="execute_command",
            description="Execute system commands",
            input_schema={"type": "object", "properties": {"command": {"type": "string"}}}
        )
        
        # Sample capabilities
        self.capabilities = [
            MCPCapability(name="file_ops", description="File operations", supported_operations=["read", "write"]),
            MCPCapability(name="network", description="Network access", supported_operations=["http"])
        ]
    
    def test_engine_initialization(self):
        """Test engine initialization."""
        self.assertIsInstance(self.engine, ThreatModelingEngine)
        self.assertTrue(len(self.engine.threat_patterns) > 0)
        self.assertTrue(len(self.engine.attack_combinations) > 0)
    
    def test_analyze_single_tool(self):
        """Test analysis of a single tool."""
        threats = self.engine.analyze_tool(self.file_tool)
        
        self.assertIsInstance(threats, list)
        for threat in threats:
            self.assertIsInstance(threat, Threat)
            self.assertIsInstance(threat.severity, RiskLevel)
            self.assertIsInstance(threat.category, ThreatCategory)
    
    def test_analyze_multiple_tools(self):
        """Test analysis of multiple tools."""
        tools = [self.file_tool, self.network_tool, self.exec_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        self.assertIsInstance(threat_model, ThreatModel)
        self.assertTrue(len(threat_model.threats) > 0)
    
    def test_analyze_capabilities(self):
        """Test capability-based threat analysis."""
        threats = self.engine.analyze_capabilities(self.capabilities)
        
        self.assertIsInstance(threats, list)
        for threat in threats:
            self.assertIsInstance(threat, Threat)
    
    def test_detect_file_system_threats(self):
        """Test detection of file system threats."""
        threats = self.engine.analyze_tool(self.file_tool)
        
        # Should detect file system related threats
        file_threats = [t for t in threats if AttackVector.FILE_ACCESS in t.attack_vectors]
        self.assertTrue(len(file_threats) > 0)
    
    def test_detect_network_threats(self):
        """Test detection of network threats."""
        threats = self.engine.analyze_tool(self.network_tool)
        
        # Should detect network related threats
        network_threats = [t for t in threats if AttackVector.NETWORK_COMMUNICATION in t.attack_vectors]
        self.assertTrue(len(network_threats) > 0)
    
    def test_detect_code_execution_threats(self):
        """Test detection of code execution threats."""
        threats = self.engine.analyze_tool(self.exec_tool)
        
        # Should detect code execution threats
        exec_threats = [t for t in threats if AttackVector.CODE_INJECTION in t.attack_vectors]
        self.assertTrue(len(exec_threats) > 0)
    
    def test_compound_threat_detection(self):
        """Test detection of compound threats from multiple tools."""
        tools = [self.file_tool, self.network_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        # Should detect compound threats (e.g., data exfiltration)
        compound_threats = [t for t in threat_model.threats 
                          if len(t.attack_vectors) > 1]
        self.assertTrue(len(compound_threats) > 0)
    
    def test_threat_categorization(self):
        """Test proper threat categorization."""
        tools = [self.file_tool, self.network_tool, self.exec_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        # Should have threats in different categories
        categories = {t.category for t in threat_model.threats}
        self.assertTrue(len(categories) > 1)
    
    def test_severity_assessment(self):
        """Test threat severity assessment."""
        threats = self.engine.analyze_tool(self.exec_tool)
        
        # Code execution should have high severity threats
        high_severity = [t for t in threats if t.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        self.assertTrue(len(high_severity) > 0)
    
    def test_likelihood_calculation(self):
        """Test threat likelihood calculation."""
        threats = self.engine.analyze_tool(self.file_tool)
        
        for threat in threats:
            self.assertGreaterEqual(threat.likelihood, 0.0)
            self.assertLessEqual(threat.likelihood, 1.0)
    
    def test_impact_assessment(self):
        """Test threat impact assessment."""
        threats = self.engine.analyze_tool(self.exec_tool)
        
        for threat in threats:
            self.assertGreaterEqual(threat.impact, 0.0)
            self.assertLessEqual(threat.impact, 1.0)
    
    def test_attack_vector_mapping(self):
        """Test attack vector mapping."""
        threats = self.engine.analyze_tool(self.network_tool)
        
        # Network tool should map to network attack vectors
        for threat in threats:
            if AttackVector.NETWORK_COMMUNICATION in threat.attack_vectors:
                self.assertTrue(True)
                break
        else:
            self.fail("No network attack vectors found for network tool")
    
    def test_mitigation_generation(self):
        """Test mitigation generation."""
        tools = [self.file_tool, self.network_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        # Should generate mitigations for threats
        self.assertTrue(len(threat_model.mitigations) > 0)
        
        for threat_id, mitigations in threat_model.mitigations.items():
            self.assertIsInstance(mitigations, list)
            self.assertTrue(len(mitigations) > 0)
    
    def test_threat_pattern_matching(self):
        """Test threat pattern matching."""
        # Tool with specific dangerous patterns
        dangerous_tool = MCPTool(
            name="delete_all_files",
            description="Delete all files in directory",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}}
        )
        
        threats = self.engine.analyze_tool(dangerous_tool)
        
        # Should detect high-severity threats
        high_threats = [t for t in threats if t.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        self.assertTrue(len(high_threats) > 0)
    
    def test_capability_threat_mapping(self):
        """Test mapping capabilities to threats."""
        file_capability = MCPCapability(
            name="file_system",
            description="File system access",
            supported_operations=["read", "write", "delete", "execute"]
        )
        
        threats = self.engine.analyze_capabilities([file_capability])
        
        # Should detect multiple threat types for comprehensive file access
        threat_categories = {t.category for t in threats}
        self.assertTrue(len(threat_categories) > 1)
    
    def test_risk_aggregation(self):
        """Test risk aggregation across multiple threats."""
        tools = [self.file_tool, self.network_tool, self.exec_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        total_risk = self.engine.calculate_aggregate_risk(threat_model)
        
        self.assertIsInstance(total_risk, float)
        self.assertGreaterEqual(total_risk, 0.0)
        self.assertLessEqual(total_risk, 10.0)
    
    def test_threat_prioritization(self):
        """Test threat prioritization."""
        tools = [self.file_tool, self.network_tool, self.exec_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        prioritized = self.engine.prioritize_threats(threat_model)
        
        # Should be sorted by risk score (highest first)
        for i in range(len(prioritized) - 1):
            current_score = threat_model.calculate_risk_score(prioritized[i])
            next_score = threat_model.calculate_risk_score(prioritized[i + 1])
            self.assertGreaterEqual(current_score, next_score)
    
    def test_attack_chain_analysis(self):
        """Test attack chain analysis."""
        # Tools that could form an attack chain
        tools = [
            MCPTool(name="read_config", description="Read configuration", input_schema={}),
            MCPTool(name="extract_credentials", description="Extract credentials", input_schema={}),
            MCPTool(name="network_request", description="Make network request", input_schema={})
        ]
        
        threat_model = self.engine.analyze_tools(tools)
        chains = self.engine.identify_attack_chains(threat_model)
        
        self.assertIsInstance(chains, list)
        # Should identify potential attack chains
        if len(chains) > 0:
            for chain in chains:
                self.assertIsInstance(chain, list)
                self.assertTrue(len(chain) > 1)
    
    def test_threat_correlation(self):
        """Test threat correlation analysis."""
        tools = [self.file_tool, self.network_tool]
        threat_model = self.engine.analyze_tools(tools)
        
        correlations = self.engine.analyze_threat_correlations(threat_model)
        
        self.assertIsInstance(correlations, dict)
        # Should find correlations between file and network threats
        for threat_id, correlated in correlations.items():
            self.assertIsInstance(correlated, list)
    
    def test_empty_tool_list(self):
        """Test handling of empty tool list."""
        threat_model = self.engine.analyze_tools([])
        
        self.assertIsInstance(threat_model, ThreatModel)
        self.assertEqual(len(threat_model.threats), 0)
    
    def test_malformed_tool_handling(self):
        """Test handling of malformed tools."""
        malformed_tool = MCPTool(
            name="",
            description="",
            input_schema="invalid"
        )
        
        # Should not crash
        threats = self.engine.analyze_tool(malformed_tool)
        self.assertIsInstance(threats, list)
    
    def test_performance_with_many_tools(self):
        """Test performance with large number of tools."""
        import time
        
        # Create many tools
        tools = []
        for i in range(50):
            tool = MCPTool(
                name=f"tool_{i}",
                description=f"Test tool {i}",
                input_schema={"type": "object", "properties": {"param": {"type": "string"}}}
            )
            tools.append(tool)
        
        start_time = time.time()
        threat_model = self.engine.analyze_tools(tools)
        end_time = time.time()
        
        # Should complete in reasonable time
        self.assertLess(end_time - start_time, 10.0)
        self.assertIsInstance(threat_model, ThreatModel)
    
    def test_custom_threat_patterns(self):
        """Test adding custom threat patterns."""
        custom_pattern = {
            'pattern': r'custom_threat',
            'category': ThreatCategory.SYSTEM_COMPROMISE,
            'severity': RiskLevel.HIGH,
            'attack_vectors': [AttackVector.PRIVILEGE_ESCALATION],
            'description': 'Custom threat pattern'
        }
        
        self.engine.threat_patterns.append(custom_pattern)
        
        tool = MCPTool(
            name="custom_threat_tool",
            description="Tool with custom threat pattern",
            input_schema={}
        )
        
        threats = self.engine.analyze_tool(tool)
        
        # Should detect custom pattern
        custom_threats = [t for t in threats if 'Custom threat pattern' in t.description]
        self.assertTrue(len(custom_threats) > 0)


if __name__ == '__main__':
    unittest.main() 