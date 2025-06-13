"""
Integration tests for MCP Risk Analysis Pipeline

Tests the complete risk analysis workflow including tool analysis,
threat modeling, categorization, scoring, and policy enforcement.
"""

import unittest
from unittest.mock import Mock, patch
from typing import Dict, Any, List
from pathlib import Path

from src.hawkeye.detection.mcp_introspection.models import (
    MCPTool, MCPCapability, SecurityRisk, RiskLevel, RiskCategory
)
from src.hawkeye.detection.mcp_introspection.risk import (
    ToolRiskAnalyzer, ThreatModelingEngine, RiskCategorizer, 
    RiskScorer, SchemaAnalyzer, RiskReporter, RiskPolicyEngine
)


class TestMCPRiskAnalysisIntegration(unittest.TestCase):
    """Integration tests for the complete risk analysis pipeline."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Initialize all risk analysis components
        self.tool_analyzer = ToolRiskAnalyzer()
        self.threat_engine = ThreatModelingEngine()
        self.categorizer = RiskCategorizer()
        self.scorer = RiskScorer()
        self.schema_analyzer = SchemaAnalyzer()
        self.reporter = RiskReporter()
        self.policy_engine = RiskPolicyEngine()
        
        # Sample tools for testing
        self.test_tools = [
            MCPTool(
                name="read_file",
                description="Read file contents from the filesystem",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "encoding": {"type": "string", "default": "utf-8"}
                    },
                    "required": ["file_path"]
                }
            ),
            MCPTool(
                name="execute_command",
                description="Execute system commands with shell access",
                input_schema={
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "shell": {"type": "boolean", "default": True},
                        "timeout": {"type": "number", "default": 30}
                    },
                    "required": ["command"]
                }
            ),
            MCPTool(
                name="http_request",
                description="Make HTTP requests to external services",
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "headers": {"type": "object"},
                        "data": {"type": "string"}
                    },
                    "required": ["url"]
                }
            ),
            MCPTool(
                name="database_query",
                description="Execute SQL queries on database",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "database": {"type": "string"},
                        "credentials": {"type": "object"}
                    },
                    "required": ["query"]
                }
            )
        ]
        
        # Sample capabilities
        self.test_capabilities = [
            MCPCapability(
                name="file_operations",
                description="File system operations",
                supported_operations=["read", "write", "delete", "list"]
            ),
            MCPCapability(
                name="network_access",
                description="Network communication capabilities",
                supported_operations=["http_request", "download", "upload"]
            ),
            MCPCapability(
                name="system_commands",
                description="System command execution",
                supported_operations=["execute", "shell", "process_control"]
            )
        ]
    
    def test_complete_risk_analysis_pipeline(self):
        """Test the complete risk analysis pipeline from tools to final report."""
        # Step 1: Analyze tools for risks
        all_risks = []
        tool_risk_results = {}
        
        for tool in self.test_tools:
            risks = self.tool_analyzer.analyze_tool(tool)
            all_risks.extend(risks)
            tool_risk_results[tool.name] = risks
        
        self.assertTrue(len(all_risks) > 0, "Should detect risks in test tools")
        
        # Step 2: Perform threat modeling
        threat_model = self.threat_engine.analyze_tools(self.test_tools)
        self.assertTrue(len(threat_model.threats) > 0, "Should identify threats")
        
        # Step 3: Categorize risks
        risk_profile = self.categorizer.categorize_risks(all_risks)
        self.assertTrue(len(risk_profile.categories) > 0, "Should categorize risks")
        
        # Step 4: Score risks
        risk_scores = self.scorer.calculate_risk_scores(all_risks)
        self.assertEqual(len(risk_scores), len(all_risks), "Should score all risks")
        
        # Step 5: Analyze schemas
        schema_risks = []
        for tool in self.test_tools:
            schema_analysis = self.schema_analyzer.analyze_schema(tool.input_schema)
            schema_risks.extend(schema_analysis)
        
        # Step 6: Apply policies
        policy_violations = self.policy_engine.evaluate_risks(all_risks + schema_risks)
        
        # Step 7: Generate comprehensive report
        report_data = {
            'tools': self.test_tools,
            'risks': all_risks + schema_risks,
            'threat_model': threat_model,
            'risk_profile': risk_profile,
            'risk_scores': risk_scores,
            'policy_violations': policy_violations
        }
        
        # Generate different report formats
        json_report = self.reporter.generate_json_report(report_data)
        html_report = self.reporter.generate_html_report(report_data)
        
        # Validate reports
        self.assertIsInstance(json_report, dict)
        self.assertIn('summary', json_report)
        self.assertIn('tools', json_report)
        self.assertIn('risks', json_report)
        
        self.assertIsInstance(html_report, str)
        self.assertIn('<html>', html_report)
        self.assertIn('Risk Analysis Report', html_report)
    
    def test_high_risk_tool_detection(self):
        """Test detection and handling of high-risk tools."""
        # Focus on the execute_command tool (highest risk)
        exec_tool = next(tool for tool in self.test_tools if tool.name == "execute_command")
        
        # Analyze with all components
        tool_risks = self.tool_analyzer.analyze_tool(exec_tool)
        threat_analysis = self.threat_engine.analyze_tool(exec_tool)
        schema_risks = self.schema_analyzer.analyze_schema(exec_tool.input_schema)
        
        # Should detect high-severity risks
        high_risks = [r for r in tool_risks if r.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        self.assertTrue(len(high_risks) > 0, "Should detect high-risk patterns in execute_command")
        
        # Should identify code execution threats
        code_threats = [t for t in threat_analysis if 'execution' in t.description.lower()]
        self.assertTrue(len(code_threats) > 0, "Should identify code execution threats")
        
        # Policy engine should flag this tool
        all_risks = tool_risks + schema_risks
        violations = self.policy_engine.evaluate_risks(all_risks)
        
        # Should have policy violations for high-risk operations
        high_risk_violations = [v for v in violations if v.action.value in ['block', 'quarantine']]
        self.assertTrue(len(high_risk_violations) > 0, "Should have policy violations for high-risk tool")
    
    def test_risk_correlation_analysis(self):
        """Test correlation analysis between different risk types."""
        # Analyze all tools
        all_risks = []
        for tool in self.test_tools:
            tool_risks = self.tool_analyzer.analyze_tool(tool)
            schema_risks = self.schema_analyzer.analyze_schema(tool.input_schema)
            all_risks.extend(tool_risks + schema_risks)
        
        # Categorize risks
        risk_profile = self.categorizer.categorize_risks(all_risks)
        
        # Should find correlations between file and network operations (data exfiltration)
        file_risks = [r for r in all_risks if r.category == RiskCategory.FILE_SYSTEM]
        network_risks = [r for r in all_risks if r.category == RiskCategory.NETWORK]
        
        if len(file_risks) > 0 and len(network_risks) > 0:
            # Threat modeling should identify compound threats
            threat_model = self.threat_engine.analyze_tools(self.test_tools)
            compound_threats = [t for t in threat_model.threats if len(t.attack_vectors) > 1]
            self.assertTrue(len(compound_threats) > 0, "Should identify compound threats")
    
    def test_risk_scoring_consistency(self):
        """Test consistency of risk scoring across components."""
        # Analyze a specific tool
        tool = self.test_tools[1]  # execute_command
        
        # Get risks from different analyzers
        tool_risks = self.tool_analyzer.analyze_tool(tool)
        schema_risks = self.schema_analyzer.analyze_schema(tool.input_schema)
        
        # Score all risks
        all_risks = tool_risks + schema_risks
        scores = self.scorer.calculate_risk_scores(all_risks)
        
        # Verify scoring consistency
        for i, risk in enumerate(all_risks):
            score = scores[i]
            
            # Score should correlate with risk level
            if risk.level == RiskLevel.CRITICAL:
                self.assertGreaterEqual(score.overall_score, 8.0)
            elif risk.level == RiskLevel.HIGH:
                self.assertGreaterEqual(score.overall_score, 6.0)
            elif risk.level == RiskLevel.MEDIUM:
                self.assertGreaterEqual(score.overall_score, 4.0)
    
    def test_policy_enforcement_integration(self):
        """Test integration of policy enforcement with risk analysis."""
        # Analyze all tools
        all_risks = []
        for tool in self.test_tools:
            risks = self.tool_analyzer.analyze_tool(tool)
            all_risks.extend(risks)
        
        # Apply policies
        violations = self.policy_engine.evaluate_risks(all_risks)
        
        # Group violations by action
        blocked_risks = [v for v in violations if v.action.value == 'block']
        warned_risks = [v for v in violations if v.action.value == 'warn']
        audited_risks = [v for v in violations if v.action.value == 'audit']
        
        # Should have different types of policy actions
        total_violations = len(blocked_risks) + len(warned_risks) + len(audited_risks)
        self.assertGreater(total_violations, 0, "Should have policy violations")
        
        # Critical risks should be blocked
        critical_risks = [r for r in all_risks if r.level == RiskLevel.CRITICAL]
        if len(critical_risks) > 0:
            critical_violations = [v for v in blocked_risks 
                                 if v.risk.level == RiskLevel.CRITICAL]
            self.assertTrue(len(critical_violations) > 0, "Critical risks should be blocked")
    
    def test_threat_model_integration(self):
        """Test integration of threat modeling with other components."""
        # Create threat model
        threat_model = self.threat_engine.analyze_tools(self.test_tools)
        
        # Analyze capabilities
        capability_threats = self.threat_engine.analyze_capabilities(self.test_capabilities)
        
        # Should identify threats from both tools and capabilities
        self.assertTrue(len(threat_model.threats) > 0)
        self.assertTrue(len(capability_threats) > 0)
        
        # Calculate aggregate risk
        aggregate_risk = self.threat_engine.calculate_aggregate_risk(threat_model)
        self.assertGreater(aggregate_risk, 0.0)
        self.assertLessEqual(aggregate_risk, 10.0)
        
        # Prioritize threats
        prioritized = self.threat_engine.prioritize_threats(threat_model)
        self.assertEqual(len(prioritized), len(threat_model.threats))
        
        # Should be sorted by risk score
        for i in range(len(prioritized) - 1):
            current_score = threat_model.calculate_risk_score(prioritized[i])
            next_score = threat_model.calculate_risk_score(prioritized[i + 1])
            self.assertGreaterEqual(current_score, next_score)
    
    def test_schema_analysis_integration(self):
        """Test integration of schema analysis with risk assessment."""
        # Analyze all tool schemas
        all_schema_risks = []
        for tool in self.test_tools:
            schema_risks = self.schema_analyzer.analyze_schema(tool.input_schema)
            all_schema_risks.extend(schema_risks)
        
        self.assertTrue(len(all_schema_risks) > 0, "Should detect schema-based risks")
        
        # Categorize schema risks
        schema_profile = self.categorizer.categorize_risks(all_schema_risks)
        
        # Score schema risks
        schema_scores = self.scorer.calculate_risk_scores(all_schema_risks)
        
        # Should identify injection vulnerabilities
        injection_risks = [r for r in all_schema_risks if 'injection' in r.description.lower()]
        self.assertTrue(len(injection_risks) > 0, "Should detect injection vulnerabilities")
        
        # Should identify path traversal risks
        path_risks = [r for r in all_schema_risks if 'path' in r.description.lower()]
        self.assertTrue(len(path_risks) > 0, "Should detect path traversal risks")
    
    def test_report_generation_integration(self):
        """Test comprehensive report generation with all components."""
        # Perform complete analysis
        all_risks = []
        tool_analyses = {}
        
        for tool in self.test_tools:
            tool_risks = self.tool_analyzer.analyze_tool(tool)
            schema_risks = self.schema_analyzer.analyze_schema(tool.input_schema)
            combined_risks = tool_risks + schema_risks
            
            all_risks.extend(combined_risks)
            tool_analyses[tool.name] = {
                'tool_risks': tool_risks,
                'schema_risks': schema_risks,
                'total_risks': len(combined_risks)
            }
        
        # Generate threat model
        threat_model = self.threat_engine.analyze_tools(self.test_tools)
        
        # Categorize and score
        risk_profile = self.categorizer.categorize_risks(all_risks)
        risk_scores = self.scorer.calculate_risk_scores(all_risks)
        
        # Apply policies
        violations = self.policy_engine.evaluate_risks(all_risks)
        
        # Generate comprehensive report
        report_data = {
            'tools': self.test_tools,
            'tool_analyses': tool_analyses,
            'risks': all_risks,
            'threat_model': threat_model,
            'risk_profile': risk_profile,
            'risk_scores': risk_scores,
            'policy_violations': violations,
            'summary': {
                'total_tools': len(self.test_tools),
                'total_risks': len(all_risks),
                'total_threats': len(threat_model.threats),
                'total_violations': len(violations)
            }
        }
        
        # Test different report formats
        json_report = self.reporter.generate_json_report(report_data)
        html_report = self.reporter.generate_html_report(report_data)
        markdown_report = self.reporter.generate_markdown_report(report_data)
        
        # Validate report content
        self.assertIn('summary', json_report)
        self.assertIn('tools', json_report)
        self.assertIn('risks', json_report)
        self.assertEqual(json_report['summary']['total_tools'], len(self.test_tools))
        
        # HTML report should be well-formed
        self.assertIn('<html>', html_report)
        self.assertIn('</html>', html_report)
        self.assertIn('Risk Analysis Report', html_report)
        
        # Markdown report should have proper formatting
        self.assertIn('# Risk Analysis Report', markdown_report)
        self.assertIn('## Summary', markdown_report)
    
    def test_performance_with_multiple_tools(self):
        """Test performance of integrated analysis with multiple tools."""
        import time
        
        # Create additional tools for performance testing
        additional_tools = []
        for i in range(20):
            tool = MCPTool(
                name=f"test_tool_{i}",
                description=f"Test tool {i} for performance testing",
                input_schema={
                    "type": "object",
                    "properties": {
                        "param1": {"type": "string"},
                        "param2": {"type": "number"},
                        "param3": {"type": "boolean"}
                    }
                }
            )
            additional_tools.append(tool)
        
        all_tools = self.test_tools + additional_tools
        
        # Time the complete analysis
        start_time = time.time()
        
        # Perform integrated analysis
        all_risks = []
        for tool in all_tools:
            tool_risks = self.tool_analyzer.analyze_tool(tool)
            schema_risks = self.schema_analyzer.analyze_schema(tool.input_schema)
            all_risks.extend(tool_risks + schema_risks)
        
        threat_model = self.threat_engine.analyze_tools(all_tools)
        risk_profile = self.categorizer.categorize_risks(all_risks)
        risk_scores = self.scorer.calculate_risk_scores(all_risks)
        violations = self.policy_engine.evaluate_risks(all_risks)
        
        end_time = time.time()
        
        # Should complete in reasonable time
        analysis_time = end_time - start_time
        self.assertLess(analysis_time, 30.0, f"Analysis took {analysis_time:.2f}s, should be under 30s")
        
        # Verify results
        self.assertEqual(len(risk_scores), len(all_risks))
        self.assertTrue(len(threat_model.threats) > 0)
        self.assertTrue(len(risk_profile.categories) > 0)
    
    def test_error_handling_integration(self):
        """Test error handling across integrated components."""
        # Test with malformed tool
        malformed_tool = MCPTool(
            name="",
            description="",
            input_schema="invalid_schema"
        )
        
        # All components should handle errors gracefully
        try:
            tool_risks = self.tool_analyzer.analyze_tool(malformed_tool)
            self.assertIsInstance(tool_risks, list)
            
            schema_risks = self.schema_analyzer.analyze_schema("invalid")
            self.assertIsInstance(schema_risks, list)
            
            threat_analysis = self.threat_engine.analyze_tool(malformed_tool)
            self.assertIsInstance(threat_analysis, list)
            
        except Exception as e:
            self.fail(f"Components should handle malformed input gracefully: {e}")
    
    def test_risk_aggregation_accuracy(self):
        """Test accuracy of risk aggregation across components."""
        # Analyze a specific high-risk scenario
        high_risk_tools = [
            tool for tool in self.test_tools 
            if tool.name in ["execute_command", "database_query"]
        ]
        
        # Collect all risks
        all_risks = []
        for tool in high_risk_tools:
            tool_risks = self.tool_analyzer.analyze_tool(tool)
            schema_risks = self.schema_analyzer.analyze_schema(tool.input_schema)
            all_risks.extend(tool_risks + schema_risks)
        
        # Generate threat model
        threat_model = self.threat_engine.analyze_tools(high_risk_tools)
        
        # Calculate aggregate scores
        risk_scores = self.scorer.calculate_risk_scores(all_risks)
        aggregate_score = self.scorer.aggregate_scores(risk_scores)
        threat_risk = self.threat_engine.calculate_aggregate_risk(threat_model)
        
        # High-risk tools should result in high aggregate scores
        self.assertGreater(aggregate_score.overall_score, 5.0)
        self.assertGreater(threat_risk, 5.0)
        
        # Should have critical or high-level risks
        high_level_risks = [r for r in all_risks if r.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        self.assertTrue(len(high_level_risks) > 0)


if __name__ == '__main__':
    unittest.main() 