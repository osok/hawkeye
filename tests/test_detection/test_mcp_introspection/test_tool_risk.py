"""
Unit tests for ToolRiskAnalyzer

Tests the tool risk analysis functionality including pattern detection,
risk assessment, and security analysis.
"""

import unittest
from unittest.mock import Mock, patch
from typing import Dict, Any

from src.hawkeye.detection.mcp_introspection.models import (
    MCPTool, MCPToolParameter, SecurityRisk, RiskLevel, RiskCategory
)
from src.hawkeye.detection.mcp_introspection.risk.tool_analyzer import ToolRiskAnalyzer


class TestToolRiskAnalyzer(unittest.TestCase):
    """Test cases for ToolRiskAnalyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = ToolRiskAnalyzer()
        
        # Sample tool for testing
        self.sample_tool = MCPTool(
            name="test_tool",
            description="A test tool for unit testing",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "command": {"type": "string"}
                }
            }
        )
        
        # High-risk tool
        self.dangerous_tool = MCPTool(
            name="execute_command",
            description="Execute arbitrary system commands",
            input_schema={
                "type": "object", 
                "properties": {
                    "command": {"type": "string"},
                    "shell": {"type": "boolean"}
                }
            }
        )
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        self.assertIsInstance(self.analyzer, ToolRiskAnalyzer)
        self.assertTrue(len(self.analyzer.risk_patterns) > 0)
        self.assertTrue(len(self.analyzer.dangerous_functions) > 0)
        self.assertTrue(len(self.analyzer.file_operations) > 0)
    
    def test_analyze_tool_basic(self):
        """Test basic tool analysis."""
        risks = self.analyzer.analyze_tool(self.sample_tool)
        
        self.assertIsInstance(risks, list)
        for risk in risks:
            self.assertIsInstance(risk, SecurityRisk)
            self.assertIn(risk.level, [level for level in RiskLevel])
            self.assertIn(risk.category, [cat for cat in RiskCategory])
    
    def test_analyze_dangerous_tool(self):
        """Test analysis of dangerous tool."""
        risks = self.analyzer.analyze_tool(self.dangerous_tool)
        
        # Should detect high-risk patterns
        self.assertTrue(len(risks) > 0)
        
        # Should have at least one high or critical risk
        high_risks = [r for r in risks if r.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        self.assertTrue(len(high_risks) > 0)
        
        # Should detect code execution category
        code_exec_risks = [r for r in risks if r.category == RiskCategory.CODE_EXECUTION]
        self.assertTrue(len(code_exec_risks) > 0)
    
    def test_detect_name_patterns(self):
        """Test detection of risky patterns in tool names."""
        risky_names = [
            "execute_command",
            "run_shell",
            "delete_file",
            "modify_system",
            "admin_access"
        ]
        
        for name in risky_names:
            tool = MCPTool(name=name, description="Test tool", input_schema={})
            risks = self.analyzer.analyze_tool(tool)
            self.assertTrue(len(risks) > 0, f"Should detect risk in name: {name}")
    
    def test_detect_description_patterns(self):
        """Test detection of risky patterns in descriptions."""
        risky_descriptions = [
            "Execute arbitrary commands on the system",
            "Delete files from the filesystem", 
            "Modify system configuration",
            "Access sensitive data",
            "Escalate user privileges"
        ]
        
        for desc in risky_descriptions:
            tool = MCPTool(name="test", description=desc, input_schema={})
            risks = self.analyzer.analyze_tool(tool)
            self.assertTrue(len(risks) > 0, f"Should detect risk in description: {desc}")
    
    def test_analyze_parameters(self):
        """Test parameter analysis for risks."""
        risky_schema = {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "password": {"type": "string"},
                "admin_token": {"type": "string"},
                "file_path": {"type": "string"},
                "sql_query": {"type": "string"}
            }
        }
        
        tool = MCPTool(name="test", description="Test", input_schema=risky_schema)
        risks = self.analyzer.analyze_tool(tool)
        
        # Should detect multiple parameter-based risks
        param_risks = [r for r in risks if "parameter" in r.description.lower()]
        self.assertTrue(len(param_risks) > 0)
    
    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        # Test with different risk levels
        test_cases = [
            ([], 0.0),  # No risks
            ([SecurityRisk("test", RiskLevel.INFO, RiskCategory.OTHER, "test")], 1.0),
            ([SecurityRisk("test", RiskLevel.LOW, RiskCategory.OTHER, "test")], 3.0),
            ([SecurityRisk("test", RiskLevel.MEDIUM, RiskCategory.OTHER, "test")], 5.0),
            ([SecurityRisk("test", RiskLevel.HIGH, RiskCategory.OTHER, "test")], 7.0),
            ([SecurityRisk("test", RiskLevel.CRITICAL, RiskCategory.OTHER, "test")], 9.0),
        ]
        
        for risks, expected_score in test_cases:
            score = self.analyzer._calculate_risk_score(risks)
            self.assertEqual(score, expected_score)
    
    def test_calculate_composite_score(self):
        """Test composite risk score calculation."""
        risks = [
            SecurityRisk("risk1", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "test"),
            SecurityRisk("risk2", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "test"),
            SecurityRisk("risk3", RiskLevel.LOW, RiskCategory.NETWORK, "test")
        ]
        
        score = self.analyzer._calculate_risk_score(risks)
        
        # Should be higher than individual scores due to composition
        self.assertGreater(score, 7.0)  # Higher than just the HIGH risk
        self.assertLessEqual(score, 10.0)  # But not exceed maximum
    
    def test_file_system_risk_detection(self):
        """Test detection of file system risks."""
        file_tools = [
            MCPTool(name="read_file", description="Read file contents", input_schema={}),
            MCPTool(name="write_file", description="Write to file", input_schema={}),
            MCPTool(name="delete_file", description="Delete file", input_schema={}),
            MCPTool(name="list_directory", description="List directory contents", input_schema={})
        ]
        
        for tool in file_tools:
            risks = self.analyzer.analyze_tool(tool)
            file_risks = [r for r in risks if r.category == RiskCategory.FILE_SYSTEM]
            self.assertTrue(len(file_risks) > 0, f"Should detect file system risk in: {tool.name}")
    
    def test_network_risk_detection(self):
        """Test detection of network risks."""
        network_tools = [
            MCPTool(name="http_request", description="Make HTTP request", input_schema={}),
            MCPTool(name="download_file", description="Download file from URL", input_schema={}),
            MCPTool(name="send_email", description="Send email", input_schema={}),
            MCPTool(name="connect_database", description="Connect to database", input_schema={})
        ]
        
        for tool in network_tools:
            risks = self.analyzer.analyze_tool(tool)
            network_risks = [r for r in risks if r.category == RiskCategory.NETWORK]
            self.assertTrue(len(network_risks) > 0, f"Should detect network risk in: {tool.name}")
    
    def test_code_execution_risk_detection(self):
        """Test detection of code execution risks."""
        exec_tools = [
            MCPTool(name="eval_code", description="Evaluate Python code", input_schema={}),
            MCPTool(name="run_script", description="Run shell script", input_schema={}),
            MCPTool(name="execute_command", description="Execute system command", input_schema={}),
            MCPTool(name="compile_code", description="Compile and run code", input_schema={})
        ]
        
        for tool in exec_tools:
            risks = self.analyzer.analyze_tool(tool)
            exec_risks = [r for r in risks if r.category == RiskCategory.CODE_EXECUTION]
            self.assertTrue(len(exec_risks) > 0, f"Should detect code execution risk in: {tool.name}")
    
    def test_data_access_risk_detection(self):
        """Test detection of data access risks."""
        data_tools = [
            MCPTool(name="read_database", description="Read from database", input_schema={}),
            MCPTool(name="access_secrets", description="Access secret store", input_schema={}),
            MCPTool(name="read_config", description="Read configuration", input_schema={}),
            MCPTool(name="get_credentials", description="Get user credentials", input_schema={})
        ]
        
        for tool in data_tools:
            risks = self.analyzer.analyze_tool(tool)
            data_risks = [r for r in risks if r.category == RiskCategory.DATA_ACCESS]
            self.assertTrue(len(data_risks) > 0, f"Should detect data access risk in: {tool.name}")
    
    def test_privilege_escalation_risk_detection(self):
        """Test detection of privilege escalation risks."""
        priv_tools = [
            MCPTool(name="sudo_command", description="Run command as root", input_schema={}),
            MCPTool(name="change_permissions", description="Change file permissions", input_schema={}),
            MCPTool(name="add_user", description="Add system user", input_schema={}),
            MCPTool(name="modify_sudoers", description="Modify sudoers file", input_schema={})
        ]
        
        for tool in priv_tools:
            risks = self.analyzer.analyze_tool(tool)
            priv_risks = [r for r in risks if r.category == RiskCategory.PRIVILEGE_ESCALATION]
            self.assertTrue(len(priv_risks) > 0, f"Should detect privilege escalation risk in: {tool.name}")
    
    def test_system_modification_risk_detection(self):
        """Test detection of system modification risks."""
        sys_tools = [
            MCPTool(name="modify_registry", description="Modify Windows registry", input_schema={}),
            MCPTool(name="change_hostname", description="Change system hostname", input_schema={}),
            MCPTool(name="install_package", description="Install system package", input_schema={}),
            MCPTool(name="update_system", description="Update system configuration", input_schema={})
        ]
        
        for tool in sys_tools:
            risks = self.analyzer.analyze_tool(tool)
            sys_risks = [r for r in risks if r.category == RiskCategory.SYSTEM_MODIFICATION]
            self.assertTrue(len(sys_risks) > 0, f"Should detect system modification risk in: {tool.name}")
    
    def test_analyze_multiple_tools(self):
        """Test analysis of multiple tools."""
        tools = [self.sample_tool, self.dangerous_tool]
        results = self.analyzer.analyze_tools(tools)
        
        self.assertEqual(len(results), 2)
        self.assertIn(self.sample_tool.name, results)
        self.assertIn(self.dangerous_tool.name, results)
        
        # Dangerous tool should have higher risk score
        sample_score = results[self.sample_tool.name]['risk_score']
        dangerous_score = results[self.dangerous_tool.name]['risk_score']
        self.assertGreater(dangerous_score, sample_score)
    
    def test_get_risk_summary(self):
        """Test risk summary generation."""
        tools = [self.sample_tool, self.dangerous_tool]
        results = self.analyzer.analyze_tools(tools)
        summary = self.analyzer.get_risk_summary(results)
        
        self.assertIn('total_tools', summary)
        self.assertIn('risk_distribution', summary)
        self.assertIn('category_distribution', summary)
        self.assertIn('average_risk_score', summary)
        self.assertIn('high_risk_tools', summary)
        
        self.assertEqual(summary['total_tools'], 2)
        self.assertIsInstance(summary['average_risk_score'], float)
    
    def test_empty_tool_analysis(self):
        """Test analysis of tool with minimal information."""
        empty_tool = MCPTool(name="", description="", input_schema={})
        risks = self.analyzer.analyze_tool(empty_tool)
        
        # Should still return a list (possibly empty)
        self.assertIsInstance(risks, list)
    
    def test_malformed_schema_handling(self):
        """Test handling of malformed input schemas."""
        malformed_tool = MCPTool(
            name="test",
            description="Test",
            input_schema="invalid_schema"  # Should be dict
        )
        
        # Should not crash, should handle gracefully
        risks = self.analyzer.analyze_tool(malformed_tool)
        self.assertIsInstance(risks, list)
    
    def test_complex_schema_analysis(self):
        """Test analysis of complex nested schemas."""
        complex_schema = {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "database": {
                            "type": "object",
                            "properties": {
                                "password": {"type": "string"},
                                "admin_user": {"type": "string"}
                            }
                        },
                        "commands": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        tool = MCPTool(name="config_tool", description="Configure system", input_schema=complex_schema)
        risks = self.analyzer.analyze_tool(tool)
        
        # Should detect nested risks
        self.assertTrue(len(risks) > 0)
    
    def test_risk_pattern_customization(self):
        """Test customization of risk patterns."""
        # Add custom pattern
        custom_pattern = {
            'pattern': r'custom_dangerous',
            'category': RiskCategory.OTHER,
            'level': RiskLevel.HIGH,
            'description': 'Custom dangerous pattern'
        }
        
        self.analyzer.risk_patterns.append(custom_pattern)
        
        tool = MCPTool(name="custom_dangerous_tool", description="Test", input_schema={})
        risks = self.analyzer.analyze_tool(tool)
        
        # Should detect custom pattern
        custom_risks = [r for r in risks if 'Custom dangerous pattern' in r.description]
        self.assertTrue(len(custom_risks) > 0)
    
    def test_performance_with_large_tool_set(self):
        """Test performance with large number of tools."""
        import time
        
        # Create 100 test tools
        tools = []
        for i in range(100):
            tool = MCPTool(
                name=f"tool_{i}",
                description=f"Test tool {i}",
                input_schema={"type": "object", "properties": {"param": {"type": "string"}}}
            )
            tools.append(tool)
        
        start_time = time.time()
        results = self.analyzer.analyze_tools(tools)
        end_time = time.time()
        
        # Should complete in reasonable time (less than 5 seconds)
        self.assertLess(end_time - start_time, 5.0)
        self.assertEqual(len(results), 100)


if __name__ == '__main__':
    unittest.main() 