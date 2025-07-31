"""
Unit tests for AI threat analysis Phase 5 components - Simplified version.

This module tests the enhanced threat intelligence engine components including:
- MCPCapabilityAnalyzer enhancement validation (T5.1)
- AttackVectorGenerator pattern-based generation (T5.2)
- ScenarioBuilder realistic abuse scenarios (T5.3)
- Algorithm accuracy validation (T5.4)
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, List, Any

from src.hawkeye.detection.ai_threat.capability_analyzer import MCPCapabilityAnalyzer
from src.hawkeye.detection.ai_threat.attack_vector_generator import AttackVectorGenerator
from src.hawkeye.detection.ai_threat.scenario_builder import ScenarioBuilder
from src.hawkeye.detection.ai_threat.risk_prioritizer import RiskPrioritizationAlgorithm
from src.hawkeye.detection.ai_threat.models import (
    CapabilityCategory, DeploymentType, SecurityPosture, NetworkExposure,
    DataSensitivity, UserPrivileges, ComplianceFramework, EnvironmentContext
)
from src.hawkeye.detection.mcp_introspection.models import MCPServerInfo, MCPTool


class TestMCPCapabilityAnalyzer:
    """Test cases for enhanced MCPCapabilityAnalyzer (T5.1)."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = MCPCapabilityAnalyzer()
        
        # Create mock MCP server info for testing
        self.sample_mcp_server = MCPServerInfo(
            server_id='file-server-1',
            host='localhost',
            port=3000,
            is_secure=False,
            has_authentication=False,
            metadata={
                'name': 'file-server',
                'version': '1.0.0',
                'description': 'File management server',
                'tools': ['file_read', 'file_write', 'file_delete', 'list_directory'],
                'capabilities': ['filesystem_access', 'data_manipulation']
            },
            tools=[
                MCPTool(
                    name='file_operations',
                    description='File system operations including read, write, delete'
                )
            ]
        )
    
    def test_analyze_tool_basic(self):
        """Test basic tool analysis functionality."""
        result = self.analyzer.analyze_tool(self.sample_mcp_server)
        
        # Verify analysis results
        assert result is not None
        assert hasattr(result, 'capability_categories')
        assert hasattr(result, 'risk_surface')
        assert result.tool_name == 'file-server'
        assert len(result.capability_categories) > 0
        assert result.risk_surface is not None
    
    def test_categorize_capabilities(self):
        """Test capability categorization accuracy."""
        # Test different tool function names
        test_functions = [
            'file_read', 'file_write', 'database_query', 
            'execute_command', 'send_email', 'encrypt_data'
        ]
        
        # Test categorization
        categories = self.analyzer.categorize_capabilities(test_functions)
        
        # Verify categorization
        assert len(categories) > 0
        assert CapabilityCategory.FILE_SYSTEM in categories
        
        # Test specific function categorization
        file_functions = ['file_read', 'file_write', 'list_directory']
        file_categories = self.analyzer.categorize_capabilities(file_functions)
        assert CapabilityCategory.FILE_SYSTEM in file_categories
        
        # Test code execution functions
        exec_functions = ['execute_command', 'run_script', 'eval_code']
        exec_categories = self.analyzer.categorize_capabilities(exec_functions)
        assert CapabilityCategory.CODE_EXECUTION in exec_categories
    
    def test_identify_security_relevant_functions(self):
        """Test identification of security-relevant functions."""
        # Create tool functions with varying security relevance
        from src.hawkeye.detection.ai_threat.models import ToolFunction
        
        tool_functions = [
            ToolFunction(
                name='file_read',
                description='Read file contents',
                parameters=['path'],
                risk_indicators=['data_access', 'file_system']
            ),
            ToolFunction(
                name='get_weather',
                description='Get weather information',
                parameters=['location'],
                risk_indicators=[]
            ),
            ToolFunction(
                name='execute_command',
                description='Execute system command',
                parameters=['command'],
                risk_indicators=['code_execution', 'system_access']
            )
        ]
        
        # Test security relevance identification
        security_functions = self.analyzer.identify_security_relevant_functions(tool_functions)
        
        # Verify results
        assert len(security_functions) >= 2  # file_read and execute_command should be identified
        function_names = [f.name for f in security_functions]
        assert 'file_read' in function_names
        assert 'execute_command' in function_names
        # get_weather might not be identified as security-relevant
    
    def test_build_environment_context(self):
        """Test environment context building."""
        mcp_servers = [self.sample_mcp_server]
        
        # Test context building
        context = self.analyzer.build_environment_context(mcp_servers)
        
        # Verify context
        assert context is not None
        assert isinstance(context, EnvironmentContext)
        assert context.deployment_type is not None
        assert context.security_posture is not None
    
    def test_capability_coverage_95_percent(self):
        """Test that capability analysis covers 95%+ of detected tools."""
        # Create multiple servers with diverse tools
        servers = []
        for i in range(10):
            server = MCPServerInfo(
                server_id=f'test-server-{i}',
                host='localhost',
                port=3000 + i,
                is_secure=False,
                has_authentication=False,
                metadata={
                    'name': f'test-server-{i}',
                    'version': '1.0.0',
                    'description': f'Test server {i}',
                    'tools': [f'tool_{i}_func1', f'tool_{i}_func2']
                },
                tools=[
                    MCPTool(
                        name=f'tool_{i}',
                        description=f'Test tool {i}'
                    )
                ]
            )
            servers.append(server)
        
        # Analyze all servers
        results = []
        for server in servers:
            result = self.analyzer.analyze_tool(server)
            results.append(result)
        
        # Verify coverage - all servers should produce analysis results
        assert len(results) == len(servers)
        successful_analyses = [r for r in results if r is not None and len(r.categories) > 0]
        coverage_ratio = len(successful_analyses) / len(servers)
        
        # Should achieve 95%+ coverage
        assert coverage_ratio >= 0.95, f"Coverage {coverage_ratio:.2%} below 95% requirement"


class TestAttackVectorGenerator:
    """Test cases for AttackVectorGenerator (T5.2)."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_provider = Mock()
        self.mock_provider.generate_response = AsyncMock()
        
        # Initialize generator with mock provider
        with patch('src.hawkeye.detection.ai_threat.attack_vector_generator.OpenAIProvider'):
            self.generator = AttackVectorGenerator()
            # Replace the AI provider with our mock
            self.generator.ai_provider = self.mock_provider
    
    @pytest.mark.asyncio
    async def test_generate_attack_vectors_basic(self):
        """Test basic attack vector generation."""
        from src.hawkeye.detection.ai_threat.models import ToolCapabilities, RiskSurface
        
        # Mock AI response
        mock_response = '''
        {
            "attack_vectors": [
                {
                    "name": "File Exfiltration Attack",
                    "severity": "high",
                    "description": "Attacker uses file read capabilities to exfiltrate sensitive data",
                    "attack_steps": ["Identify target files", "Use file_read to access files", "Exfiltrate data"],
                    "prerequisites": ["Access to MCP server", "Knowledge of file paths"],
                    "impact": "Data breach, confidentiality loss",
                    "likelihood": 0.7,
                    "mitigations": ["Access controls", "File monitoring", "Encryption"]
                }
            ]
        }
        '''
        self.mock_provider.generate_response.return_value = mock_response
        
        # Create test capabilities
        capabilities = ToolCapabilities(
            name='file-server',
            categories=[CapabilityCategory.FILE_SYSTEM],
            functions=[],
            risk_surface=RiskSurface(),
            security_implications=['data_access'],
            access_requirements=None,
            external_dependencies=[]
        )
        
        context = EnvironmentContext(
            deployment_type=DeploymentType.PRODUCTION,
            security_posture=SecurityPosture.ENTERPRISE,
            data_sensitivity=DataSensitivity.HIGH,
            network_exposure=NetworkExposure.INTERNAL,
            user_privileges=UserPrivileges.STANDARD,
            compliance_requirements=[ComplianceFramework.SOC2]
        )
        
        # Generate attack vectors
        vectors = await self.generator.generate_attack_vectors([capabilities], context)
        
        # Verify results
        assert len(vectors) > 0
        vector = vectors[0]
        assert vector.name is not None
        assert len(vector.name) > 0
        assert vector.description is not None
        assert len(vector.description) > 10
    
    @pytest.mark.asyncio 
    async def test_pattern_based_generation(self):
        """Test that attack vector generation follows recognizable patterns."""
        from src.hawkeye.detection.ai_threat.models import ToolCapabilities, RiskSurface
        
        # Mock response with pattern-based attacks
        mock_response = '''
        {
            "attack_vectors": [
                {
                    "name": "SQL Injection Attack",
                    "severity": "high", 
                    "description": "Exploit database query functionality via injection",
                    "pattern": "injection",
                    "technique": "T1190",
                    "attack_steps": ["Identify input parameters", "Craft malicious SQL", "Execute injection"],
                    "prerequisites": ["Database access", "Input validation bypass"],
                    "impact": "Data breach, system compromise",
                    "likelihood": 0.6
                }
            ]
        }
        '''
        self.mock_provider.generate_response.return_value = mock_response
        
        # Test with database capabilities
        db_capabilities = ToolCapabilities(
            name='database-server',
            categories=[CapabilityCategory.DATABASE_ACCESS],
            functions=[],
            risk_surface=RiskSurface(),
            security_implications=['data_access', 'query_execution'],
            access_requirements=None,
            external_dependencies=[]
        )
        
        context = EnvironmentContext(
            deployment_type=DeploymentType.PRODUCTION,
            security_posture=SecurityPosture.BASIC,
            data_sensitivity=DataSensitivity.HIGH,
            network_exposure=NetworkExposure.PUBLIC,
            user_privileges=UserPrivileges.STANDARD,
            compliance_requirements=[]
        )
        
        # Generate attack vectors
        vectors = await self.generator.generate_attack_vectors([db_capabilities], context)
        
        # Verify pattern-based generation
        assert len(vectors) > 0
        vector = vectors[0]
        
        # Should generate database-specific attacks
        vector_text = (vector.name + vector.description).lower()
        db_terms = ['sql', 'database', 'query', 'injection']
        assert any(term in vector_text for term in db_terms)


class TestRiskPrioritizationAlgorithm:
    """Test cases for RiskPrioritizationAlgorithm (T5.4)."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.prioritizer = RiskPrioritizationAlgorithm()
    
    def test_calculate_priority_high_risk(self):
        """Test risk prioritization for high-risk scenarios."""
        # Test high-risk scenario
        priority = self.prioritizer.calculate_priority(
            technical_impact=0.9,
            business_impact=0.8,
            likelihood=0.7
        )
        
        # Should be high priority
        assert priority.value >= 0.7
    
    def test_calculate_priority_low_risk(self):
        """Test risk prioritization for low-risk scenarios."""
        # Test low-risk scenario
        priority = self.prioritizer.calculate_priority(
            technical_impact=0.2,
            business_impact=0.1,
            likelihood=0.3
        )
        
        # Should be low priority
        assert priority.value <= 0.4
    
    def test_calculate_priority_medium_risk(self):
        """Test risk prioritization for medium-risk scenarios."""
        # Test medium-risk scenario
        priority = self.prioritizer.calculate_priority(
            technical_impact=0.6,
            business_impact=0.5,
            likelihood=0.5
        )
        
        # Should be medium priority
        assert 0.3 <= priority.value <= 0.7
    
    def test_prioritization_algorithm_accuracy(self):
        """Test overall prioritization algorithm accuracy."""
        test_cases = [
            {
                'name': 'Critical System Access',
                'technical_impact': 0.9,
                'business_impact': 0.8, 
                'likelihood': 0.7,
                'expected_range': (0.7, 1.0)
            },
            {
                'name': 'Minor Information Disclosure',
                'technical_impact': 0.3,
                'business_impact': 0.2,
                'likelihood': 0.4,
                'expected_range': (0.0, 0.4)
            },
            {
                'name': 'Medium File Access Risk',
                'technical_impact': 0.6,
                'business_impact': 0.5,
                'likelihood': 0.6,
                'expected_range': (0.3, 0.7)
            }
        ]
        
        # Test each case
        for case in test_cases:
            priority = self.prioritizer.calculate_priority(
                technical_impact=case['technical_impact'],
                business_impact=case['business_impact'],
                likelihood=case['likelihood']
            )
            
            min_expected, max_expected = case['expected_range']
            assert min_expected <= priority.value <= max_expected, \
                f"{case['name']}: Priority {priority.value} not in expected range {case['expected_range']}"


class TestOverallPhase5Integration:
    """Integration tests for Phase 5 components (T5.4)."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.capability_analyzer = MCPCapabilityAnalyzer()
        self.risk_prioritizer = RiskPrioritizationAlgorithm()
    
    def test_phase5_performance_benchmark(self):
        """Test Phase 5 performance meets requirements."""
        import time
        
        # Create test data - 10 diverse MCP servers
        test_servers = []
        for i in range(10):
            server = MCPServerInfo(
                server_id=f'performance-test-server-{i}',
                host='localhost',
                port=3000 + i,
                is_secure=False,
                has_authentication=False,
                metadata={
                    'name': f'performance-test-server-{i}',
                    'version': '1.0.0',
                    'description': f'Performance test server {i}',
                    'tools': [f'tool_{i}_func1', f'tool_{i}_func2', f'tool_{i}_func3'],
                    'capabilities': [f'capability_{i}']
                },
                tools=[
                    MCPTool(
                        name=f'performance_tool_{i}',
                        description=f'Performance test tool {i}'
                    )
                ]
            )
            test_servers.append(server)
        
        # Measure performance
        start_time = time.time()
        
        # Analyze all servers
        results = []
        for server in test_servers:
            result = self.capability_analyzer.analyze_tool(server)
            results.append(result)
            
            # Test risk prioritization for each result
            if result and result.categories:
                priority = self.risk_prioritizer.calculate_priority(
                    technical_impact=0.6,
                    business_impact=0.5,
                    likelihood=0.5
                )
                assert priority is not None
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Performance requirement: <30 seconds for 10 tools
        assert processing_time < 30, f"Processing took {processing_time:.2f}s, exceeds 30s limit"
        
        # Verify all analyses completed successfully
        successful_results = [r for r in results if r is not None]
        success_rate = len(successful_results) / len(test_servers)
        assert success_rate >= 0.9, f"Success rate {success_rate:.2%} below 90%"
    
    def test_phase5_accuracy_validation(self):
        """Test Phase 5 accuracy meets requirements."""
        # Test with known capability patterns
        known_patterns = [
            {
                'server_name': 'file-access-server',
                'functions': ['file_read', 'file_write', 'file_delete'],
                'expected_category': CapabilityCategory.FILE_SYSTEM
            },
            {
                'server_name': 'database-server',
                'functions': ['sql_query', 'database_connect'],
                'expected_category': CapabilityCategory.DATABASE_ACCESS
            },
            {
                'server_name': 'execution-server',
                'functions': ['execute_command', 'run_script'],
                'expected_category': CapabilityCategory.CODE_EXECUTION
            }
        ]
        
        correct_categorizations = 0
        total_tests = len(known_patterns)
        
        for pattern in known_patterns:
            # Test categorization
            categories = self.capability_analyzer.categorize_capabilities(pattern['functions'])
            
            if pattern['expected_category'] in categories:
                correct_categorizations += 1
        
        # Accuracy requirement: 90%+ correct categorization
        accuracy = correct_categorizations / total_tests
        assert accuracy >= 0.9, f"Categorization accuracy {accuracy:.2%} below 90%" 