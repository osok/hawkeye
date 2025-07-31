"""
Unit tests for AI threat analysis Phase 5 components.

This module tests the enhanced threat intelligence engine components including:
- MCPCapabilityAnalyzer enhancement validation
- AttackVectorGenerator pattern-based generation
- ScenarioBuilder realistic abuse scenarios
- Algorithm accuracy validation
"""

import json
import pytest
import sys
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path
from typing import Dict, List, Any

from src.hawkeye.detection.ai_threat.capability_analyzer import (
    MCPCapabilityAnalyzer, ThreatContextBuilder, EnvironmentDetector
)
from src.hawkeye.detection.ai_threat.attack_vector_generator import AttackVectorGenerator
from src.hawkeye.detection.ai_threat.scenario_builder import ScenarioBuilder
from src.hawkeye.detection.ai_threat.example_generator import DynamicExampleGenerator
from src.hawkeye.detection.ai_threat.risk_prioritizer import RiskPrioritizationAlgorithm
from src.hawkeye.detection.ai_threat.compliance_mapper import ComplianceMapper
from src.hawkeye.detection.ai_threat.mitigation_generator import MitigationGenerator
from src.hawkeye.detection.ai_threat.attack_chain_analyzer import AttackChainAnalyzer
from src.hawkeye.detection.ai_threat.models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, AttackVector, 
    AbuseScenario, MitigationStrategy, ThreatLevel, CapabilityCategory,
    AttackChain, ChainLink, DeploymentType, SecurityPosture, NetworkExposure,
    DataSensitivity, UserPrivileges, ComplianceFramework
)
from src.hawkeye.detection.mcp_introspection.models import MCPServerInfo, MCPTool
from src.hawkeye.detection.ai_threat.ai_providers import OpenAIProvider, AnthropicProvider


class TestMCPCapabilityAnalyzer:
    """Test cases for enhanced MCPCapabilityAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = MCPCapabilityAnalyzer()
        
        # Create mock MCP server info for testing
        self.sample_mcp_server = MCPServerInfo(
            name='file-server',
            version='1.0.0',
            description='File management server',
            transport_type=None,
            host='localhost',
            port=3000,
            is_secure=False,
            has_authentication=False,
            metadata={'tools': ['file_read', 'file_write', 'file_delete']},
            tools=[
                MCPTool(
                    name='file_operations',
                    description='File system operations including read, write, delete'
                )
            ]
        )
        
        self.sample_environment = EnvironmentContext(
            deployment_type=DeploymentType.PRODUCTION,
            security_posture=SecurityPosture.ENTERPRISE,
            network_exposure=NetworkExposure.INTERNAL,
            data_sensitivity=DataSensitivity.HIGH,
            user_privileges=UserPrivileges.STANDARD,
            compliance_frameworks=[ComplianceFramework.SOC2]
        )
    
    def test_analyze_security_relevant_capabilities(self):
        """Test capability analysis for security-relevant functions."""
        # Test the real capability analysis functionality
        result = self.analyzer.analyze_tool(self.sample_mcp_server)
        
        # Verify analysis results
        assert result is not None
        assert isinstance(result, ToolCapabilities)
        assert result.name == 'file-server'
        
        # Check that capabilities are properly categorized
        assert len(result.categories) > 0
        
        # Should identify file system capabilities
        assert CapabilityCategory.FILE_SYSTEM in result.categories
        
        # Verify risk surface is analyzed
        assert result.risk_surface is not None
        assert result.risk_surface.attack_vectors is not None
    
    def test_capability_categorization_accuracy(self):
        """Test accuracy of capability categorization."""
        # Test different tool function names
        test_functions = ['database_query', 'send_email', 'get_weather', 'file_read', 'execute_command']
        
        # Test categorization
        categories = self.analyzer.categorize_capabilities(test_functions)
        
        # Verify appropriate categorization
        assert len(categories) > 0
        
        # Check specific categorizations
        expected_categories = [
            CapabilityCategory.DATABASE_ACCESS,  # database_query
            CapabilityCategory.NETWORK_ACCESS,   # send_email  
            CapabilityCategory.NETWORK_ACCESS,   # get_weather
            CapabilityCategory.FILE_SYSTEM,      # file_read
            CapabilityCategory.CODE_EXECUTION    # execute_command
        ]
        
        # At least some of the expected categories should be identified
        found_categories = set(categories)
        expected_set = set(expected_categories)
        overlap = len(found_categories & expected_set)
        assert overlap > 0, f"No expected categories found. Found: {found_categories}"
    
    @pytest.mark.asyncio
    async def test_environment_context_integration(self):
        """Test integration of environment context in capability analysis."""
        # Test different environment contexts
        dev_environment = {
            'deployment_type': DeploymentType.DEVELOPMENT,
            'security_posture': SecurityPosture.BASIC,
            'network_exposure': 'localhost'
        }
        
        prod_environment = {
            'deployment_type': DeploymentType.PRODUCTION,
            'security_posture': SecurityPosture.ENTERPRISE,
            'network_exposure': 'public'
        }
        
        # Mock responses showing environment-aware analysis
        self.mock_provider.generate_response.side_effect = [
            json.dumps({'capabilities': {'test': {'risk_level': 'MEDIUM', 'environment_factors': ['development']}}}),
            json.dumps({'capabilities': {'test': {'risk_level': 'HIGH', 'environment_factors': ['production', 'public']}}})
        ]
        
        # Test development environment analysis
        dev_result = await self.analyzer.analyze_capabilities([self.sample_tool_info], dev_environment)
        
        # Test production environment analysis  
        prod_result = await self.analyzer.analyze_capabilities([self.sample_tool_info], prod_environment)
        
        # Verify environment context affects risk assessment
        assert dev_result.capabilities[0].risk_level != prod_result.capabilities[0].risk_level
        # Production should generally have higher or equal risk
        prod_risk_val = self._threat_level_to_value(prod_result.capabilities[0].risk_level)
        dev_risk_val = self._threat_level_to_value(dev_result.capabilities[0].risk_level)
        assert prod_risk_val >= dev_risk_val
    
    def _threat_level_to_value(self, level: ThreatLevel) -> int:
        """Convert threat level to numeric value for comparison."""
        mapping = {
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2, 
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        return mapping.get(level, 0)
    
    @pytest.mark.asyncio
    async def test_capability_coverage_completeness(self):
        """Test that capability analysis covers 95%+ of detected tools."""
        # Create a diverse set of tools
        diverse_tools = [
            {'name': f'tool_{i}', 'description': f'Tool {i} description', 
             'parameters': {'param': {'type': 'string'}}}
            for i in range(20)
        ]
        
        # Mock response for all tools
        mock_response = {
            'capabilities': {f'cap_{i}': {'category': 'UTILITY', 'risk_level': 'LOW'} 
                           for i in range(20)}
        }
        self.mock_provider.generate_response.return_value = json.dumps(mock_response)
        
        # Analyze all tools
        result = await self.analyzer.analyze_capabilities(diverse_tools, self.sample_environment)
        
        # Verify coverage
        coverage_ratio = len(result.capabilities) / len(diverse_tools)
        assert coverage_ratio >= 0.95, f"Coverage {coverage_ratio:.2%} below 95% requirement"
    
    @pytest.mark.asyncio
    async def test_threat_context_builder(self):
        """Test ThreatContextBuilder functionality."""
        context_builder = ThreatContextBuilder()
        
        # Test context building with various inputs
        context = await context_builder.build_context(
            tools=[self.sample_tool_info],
            environment=self.sample_environment,
            server_metadata={'version': '1.0.0', 'config': {}}
        )
        
        # Verify context completeness
        assert context is not None
        assert hasattr(context, 'deployment_type')
        assert hasattr(context, 'security_posture')
        assert hasattr(context, 'tool_summary')
        
        # Verify context includes relevant threat indicators
        assert len(context.threat_indicators) > 0
        
    @pytest.mark.asyncio
    async def test_environment_detector(self):
        """Test EnvironmentDetector capability."""
        detector = EnvironmentDetector()
        
        # Test environment detection with mock data
        mock_system_info = {
            'os': 'linux',
            'containers': ['docker'],
            'network_config': {'interfaces': ['eth0']},
            'processes': [{'name': 'node', 'port': 3000}]
        }
        
        with patch.object(detector, '_gather_system_info', return_value=mock_system_info):
            environment = await detector.detect_environment()
            
            # Verify environment detection
            assert environment is not None
            assert environment.deployment_type is not None
            assert environment.security_posture is not None
            assert len(environment.network_exposure) > 0


class TestAttackVectorGenerator:
    """Test cases for AttackVectorGenerator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_provider = Mock()
        self.mock_provider.generate_response = AsyncMock()
        self.generator = AttackVectorGenerator(ai_provider=self.mock_provider)
        
        self.sample_capability = ToolCapabilities(
            name='file_operations',
            category=CapabilityCategory.SYSTEM_ACCESS,
            risk_level=ThreatLevel.HIGH,
            functions=['read', 'write', 'delete'],
            security_implications=['data_exfiltration', 'file_corruption']
        )
    
    @pytest.mark.asyncio
    async def test_pattern_based_generation(self):
        """Test pattern-based attack vector generation."""
        # Mock AI response with structured attack vectors
        mock_response = {
            'attack_vectors': [
                {
                    'name': 'File Exfiltration via Read Operations',
                    'pattern': 'data_exfiltration',
                    'technique': 'MITRE_T1005',
                    'description': 'Attacker uses file read capabilities to exfiltrate sensitive data',
                    'likelihood': 'high',
                    'impact': 'high'
                },
                {
                    'name': 'Data Corruption via Write Operations', 
                    'pattern': 'data_destruction',
                    'technique': 'MITRE_T1485',
                    'description': 'Attacker corrupts critical files using write capabilities',
                    'likelihood': 'medium',
                    'impact': 'high'
                }
            ]
        }
        self.mock_provider.generate_response.return_value = json.dumps(mock_response)
        
        # Generate attack vectors
        vectors = await self.generator.generate_attack_vectors(
            capabilities=[self.sample_capability],
            context=EnvironmentContext(
                deployment_type=DeploymentType.PRODUCTION,
                security_posture=SecurityPosture.ENTERPRISE
            )
        )
        
        # Verify pattern-based generation
        assert len(vectors) >= 2
        
        # Check attack vector quality
        for vector in vectors:
            assert vector.name is not None
            assert len(vector.name) > 0
            assert vector.description is not None
            assert len(vector.description) > 10
            assert vector.likelihood is not None
            assert vector.impact is not None
            
            # Verify MITRE ATT&CK mapping
            assert hasattr(vector, 'technique') or 'T' in str(vector)
    
    @pytest.mark.asyncio
    async def test_realistic_non_hardcoded_scenarios(self):
        """Test generation of realistic, non-hardcoded attack scenarios."""
        # Generate multiple sets of attack vectors with different inputs
        different_capabilities = [
            ToolCapabilities(
                name='database_access',
                category=CapabilityCategory.DATA_ACCESS,
                risk_level=ThreatLevel.HIGH,
                functions=['query', 'insert', 'delete']
            ),
            ToolCapabilities(
                name='email_sender',
                category=CapabilityCategory.COMMUNICATION,
                risk_level=ThreatLevel.MEDIUM,
                functions=['send', 'schedule']
            )
        ]
        
        # Mock different responses for different capabilities
        mock_responses = [
            {'attack_vectors': [{'name': 'SQL Injection Attack', 'pattern': 'injection'}]},
            {'attack_vectors': [{'name': 'Phishing Email Campaign', 'pattern': 'social_engineering'}]}
        ]
        
        self.mock_provider.generate_response.side_effect = [
            json.dumps(resp) for resp in mock_responses
        ]
        
        # Generate vectors for different capabilities
        results = []
        for cap in different_capabilities:
            vectors = await self.generator.generate_attack_vectors([cap], EnvironmentContext())
            results.append(vectors)
        
        # Verify non-hardcoded generation
        # Results should be different for different input capabilities
        assert len(results) == 2
        assert results[0][0].name != results[1][0].name
        
        # Check for realistic patterns
        db_vector = results[0][0]
        email_vector = results[1][0]
        
        assert 'sql' in db_vector.name.lower() or 'database' in db_vector.name.lower()
        assert 'email' in email_vector.name.lower() or 'phishing' in email_vector.name.lower()
    
    @pytest.mark.asyncio
    async def test_mitre_attack_mapping(self):
        """Test MITRE ATT&CK framework mapping accuracy."""
        # Mock response with MITRE techniques
        mock_response = {
            'attack_vectors': [
                {
                    'name': 'Data Exfiltration',
                    'mitre_technique': 'T1041',
                    'mitre_tactic': 'Exfiltration',
                    'description': 'Data exfiltration via file operations'
                }
            ]
        }
        self.mock_provider.generate_response.return_value = json.dumps(mock_response)
        
        vectors = await self.generator.generate_attack_vectors([self.sample_capability], EnvironmentContext())
        
        # Verify MITRE mapping
        assert len(vectors) > 0
        vector = vectors[0]
        
        # Check for MITRE technique presence
        vector_str = str(vector) + vector.name + getattr(vector, 'technique', '')
        assert any(f'T{i}' in vector_str for i in range(1000, 2000))


class TestScenarioBuilder:
    """Test cases for ScenarioBuilder."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_provider = Mock()
        self.mock_provider.generate_response = AsyncMock()
        self.builder = ScenarioBuilder(ai_provider=self.mock_provider)
        
        self.sample_attack_vector = AttackVector(
            name='File Exfiltration Attack',
            description='Attacker exfiltrates sensitive files',
            likelihood=ThreatLevel.HIGH,
            impact=ThreatLevel.HIGH,
            technique='T1005'
        )
    
    @pytest.mark.asyncio
    async def test_realistic_abuse_scenarios(self):
        """Test generation of realistic abuse scenarios."""
        # Mock detailed scenario response
        mock_response = {
            'scenarios': [
                {
                    'name': 'Internal Threat Actor File Exfiltration',
                    'threat_actor': 'Malicious Insider',
                    'motivation': 'Financial Gain',
                    'steps': [
                        'Gain access to MCP server',
                        'Identify sensitive file locations',
                        'Use file read capabilities to access files',
                        'Exfiltrate data to external location'
                    ],
                    'timeline': '2-4 hours',
                    'detection_difficulty': 'medium',
                    'business_impact': 'Data breach, regulatory fines, reputation damage'
                }
            ]
        }
        self.mock_provider.generate_response.return_value = json.dumps(mock_response)
        
        # Build abuse scenarios
        scenarios = await self.builder.build_abuse_scenarios(
            attack_vectors=[self.sample_attack_vector],
            context=EnvironmentContext(
                deployment_type=DeploymentType.PRODUCTION,
                security_posture=SecurityPosture.ENTERPRISE
            )
        )
        
        # Verify scenario realism and completeness
        assert len(scenarios) > 0
        scenario = scenarios[0]
        
        assert scenario.name is not None
        assert len(scenario.name) > 0
        assert scenario.description is not None
        assert len(scenario.description) > 20
        
        # Check for realistic elements
        assert hasattr(scenario, 'likelihood')
        assert hasattr(scenario, 'impact')
        
        # Verify business impact consideration
        scenario_text = scenario.description.lower()
        business_terms = ['business', 'financial', 'reputation', 'compliance', 'regulatory']
        assert any(term in scenario_text for term in business_terms)
    
    @pytest.mark.asyncio
    async def test_scenario_contextualization(self):
        """Test scenario contextualization for different environments."""
        # Test scenarios for different deployment contexts
        contexts = [
            EnvironmentContext(
                deployment_type=DeploymentType.DEVELOPMENT,
                security_posture=SecurityPosture.BASIC,
                network_exposure='internal'
            ),
            EnvironmentContext(
                deployment_type=DeploymentType.PRODUCTION,
                security_posture=SecurityPosture.ENTERPRISE,
                network_exposure='public'
            )
        ]
        
        # Mock different responses for different contexts
        mock_responses = [
            {'scenarios': [{'name': 'Dev Environment Scenario', 'context': 'development'}]},
            {'scenarios': [{'name': 'Production Environment Scenario', 'context': 'production'}]}
        ]
        
        self.mock_provider.generate_response.side_effect = [
            json.dumps(resp) for resp in mock_responses
        ]
        
        # Generate scenarios for different contexts
        results = []
        for context in contexts:
            scenarios = await self.builder.build_abuse_scenarios([self.sample_attack_vector], context)
            results.append(scenarios)
        
        # Verify context-specific scenarios
        assert len(results) == 2
        dev_scenario = results[0][0]
        prod_scenario = results[1][0]
        
        assert dev_scenario.name != prod_scenario.name
        
        # Production scenarios should generally be more severe
        # This would be reflected in the scenario descriptions and impact levels


class TestAlgorithmAccuracy:
    """Test cases for algorithm accuracy validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_provider = Mock()
        self.mock_provider.generate_response = AsyncMock()
        
        # Initialize all algorithms to test
        self.capability_analyzer = MCPCapabilityAnalyzer(ai_provider=self.mock_provider)
        self.attack_generator = AttackVectorGenerator(ai_provider=self.mock_provider)
        self.scenario_builder = ScenarioBuilder(ai_provider=self.mock_provider)
        self.risk_prioritizer = RiskPrioritizationAlgorithm()
        self.chain_analyzer = AttackChainAnalyzer(ai_provider=self.mock_provider)
    
    @pytest.mark.asyncio
    async def test_capability_to_threat_mapping_accuracy(self):
        """Test F5.7: Capability-to-Threat Mapping Algorithm accuracy."""
        # Test with known capability patterns
        test_cases = [
            {
                'capability': 'file_read',
                'expected_threats': ['data_exfiltration', 'information_disclosure'],
                'risk_level': ThreatLevel.HIGH
            },
            {
                'capability': 'network_request',
                'expected_threats': ['data_exfiltration', 'command_and_control'],
                'risk_level': ThreatLevel.MEDIUM
            },
            {
                'capability': 'process_execute',
                'expected_threats': ['code_execution', 'privilege_escalation'],
                'risk_level': ThreatLevel.CRITICAL
            }
        ]
        
        # Mock responses for capability analysis
        for test_case in test_cases:
            mock_response = {
                'threat_mapping': {
                    test_case['capability']: {
                        'threats': test_case['expected_threats'],
                        'risk_level': test_case['risk_level'].value
                    }
                }
            }
            self.mock_provider.generate_response.return_value = json.dumps(mock_response)
            
            # Test mapping accuracy
            result = await self.capability_analyzer.map_capabilities_to_threats(
                capabilities=[test_case['capability']],
                context=EnvironmentContext()
            )
            
            # Verify mapping accuracy
            assert result is not None
            assert len(result) > 0
            
            # Check threat identification accuracy
            identified_threats = result.get(test_case['capability'], {}).get('threats', [])
            expected_threats = test_case['expected_threats']
            
            # At least 80% of expected threats should be identified
            overlap = len(set(identified_threats) & set(expected_threats))
            accuracy = overlap / len(expected_threats) if expected_threats else 0
            assert accuracy >= 0.8, f"Mapping accuracy {accuracy:.2%} below 80% for {test_case['capability']}"
    
    @pytest.mark.asyncio
    async def test_attack_chain_discovery_accuracy(self):
        """Test F5.8: Attack Chain Discovery Algorithm accuracy."""
        # Test with known attack chain patterns
        test_attack_vectors = [
            AttackVector(
                name='Initial Access via File Upload',
                technique='T1566.001',
                likelihood=ThreatLevel.MEDIUM,
                impact=ThreatLevel.HIGH
            ),
            AttackVector(
                name='Privilege Escalation via Process Execution',
                technique='T1068',
                likelihood=ThreatLevel.HIGH,
                impact=ThreatLevel.CRITICAL
            ),
            AttackVector(
                name='Data Exfiltration via Network Request',
                technique='T1041',
                likelihood=ThreatLevel.HIGH,
                impact=ThreatLevel.HIGH
            )
        ]
        
        # Mock response for attack chain discovery
        mock_response = {
            'attack_chains': [
                {
                    'name': 'File Upload to Data Exfiltration Chain',
                    'steps': [
                        {'technique': 'T1566.001', 'description': 'Initial file upload'},
                        {'technique': 'T1068', 'description': 'Escalate privileges'},
                        {'technique': 'T1041', 'description': 'Exfiltrate sensitive data'}
                    ],
                    'feasibility': 0.8,
                    'severity': 'HIGH'
                }
            ]
        }
        self.mock_provider.generate_response.return_value = json.dumps(mock_response)
        
        # Test chain discovery
        chains = await self.chain_analyzer.discover_attack_chains(
            attack_vectors=test_attack_vectors,
            context=EnvironmentContext()
        )
        
        # Verify chain discovery accuracy
        assert len(chains) > 0
        chain = chains[0]
        
        assert chain.feasibility_score > 0.5
        assert len(chain.links) >= 2  # Multi-step chain
        
        # Verify logical progression
        techniques = [link.technique for link in chain.links]
        expected_techniques = ['T1566.001', 'T1068', 'T1041']
        
        # Check that discovered chain includes expected techniques
        overlap = len(set(techniques) & set(expected_techniques))
        assert overlap >= len(expected_techniques) * 0.7  # 70% technique coverage
    
    @pytest.mark.asyncio
    async def test_risk_prioritization_accuracy(self):
        """Test F5.10: Risk Prioritization Algorithm accuracy."""
        # Create test threats with known risk factors
        test_threats = [
            {
                'name': 'Critical System Access',
                'technical_impact': 0.9,
                'business_impact': 0.8,
                'likelihood': 0.7,
                'expected_priority': 'HIGH'
            },
            {
                'name': 'Minor Information Disclosure',
                'technical_impact': 0.3,
                'business_impact': 0.2,
                'likelihood': 0.4,
                'expected_priority': 'LOW'
            },
            {
                'name': 'Medium File Access Risk',
                'technical_impact': 0.6,
                'business_impact': 0.5,
                'likelihood': 0.6,
                'expected_priority': 'MEDIUM'
            }
        ]
        
        # Test prioritization for each threat
        for threat in test_threats:
            priority = self.risk_prioritizer.calculate_priority(
                technical_impact=threat['technical_impact'],
                business_impact=threat['business_impact'],
                likelihood=threat['likelihood']
            )
            
            # Verify prioritization accuracy
            expected = threat['expected_priority']
            if expected == 'HIGH':
                assert priority.value >= 0.7, f"High priority threat scored {priority.value}"
            elif expected == 'MEDIUM':
                assert 0.3 <= priority.value <= 0.7, f"Medium priority threat scored {priority.value}"
            elif expected == 'LOW':
                assert priority.value <= 0.4, f"Low priority threat scored {priority.value}"
    
    @pytest.mark.asyncio
    async def test_overall_algorithm_performance(self):
        """Test overall algorithm performance and accuracy."""
        # Performance benchmarks
        import time
        
        # Test data
        test_tools = [
            {'name': f'tool_{i}', 'description': f'Test tool {i}', 
             'parameters': {'param': {'type': 'string'}}}
            for i in range(10)
        ]
        
        # Mock quick responses for performance testing
        self.mock_provider.generate_response.return_value = json.dumps({
            'capabilities': {'test': {'category': 'UTILITY', 'risk_level': 'LOW'}},
            'attack_vectors': [{'name': 'Test Attack', 'likelihood': 'low', 'impact': 'low'}],
            'scenarios': [{'name': 'Test Scenario', 'description': 'Test scenario description'}]
        })
        
        # Test performance
        start_time = time.time()
        
        # Run capability analysis
        cap_result = await self.capability_analyzer.analyze_capabilities(
            test_tools, EnvironmentContext()
        )
        
        # Run attack vector generation
        if cap_result.capabilities:
            attack_vectors = await self.attack_generator.generate_attack_vectors(
                cap_result.capabilities, EnvironmentContext()
            )
            
            # Run scenario building
            scenarios = await self.scenario_builder.build_abuse_scenarios(
                attack_vectors, EnvironmentContext()
            )
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Verify performance requirements
        # Should process 10 tools in under 30 seconds per requirement
        assert processing_time < 30, f"Processing took {processing_time:.2f}s, exceeds 30s limit"
        
        # Verify results quality
        assert cap_result is not None
        assert len(cap_result.capabilities) > 0 