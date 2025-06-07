"""
Unit tests for remediation recommendation engine.
"""

import pytest
import time
from unittest.mock import Mock, patch

from src.hawkeye.assessment.remediation import (
    RemediationPriority, RemediationComplexity, RemediationCategory,
    RemediationAction, RemediationPlan, RemediationEngine,
    generate_remediation_plan, get_quick_wins, estimate_implementation_time
)
from src.hawkeye.assessment.base import (
    AssessmentResult, SecurityFinding, VulnerabilityInfo, RiskLevel,
    VulnerabilityCategory, ComplianceFramework
)


class TestRemediationAction:
    """Test cases for RemediationAction class."""
    
    def test_remediation_action_init(self):
        """Test RemediationAction initialization."""
        action = RemediationAction(
            id="REM_0001",
            title="Enable Authentication",
            description="Implement authentication mechanisms",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.HIGH,
            complexity=RemediationComplexity.MEDIUM,
            estimated_effort_hours=8,
            risk_reduction=7.0
        )
        
        assert action.id == "REM_0001"
        assert action.title == "Enable Authentication"
        assert action.category == RemediationCategory.AUTHENTICATION
        assert action.priority == RemediationPriority.HIGH
        assert action.complexity == RemediationComplexity.MEDIUM
        assert action.estimated_effort_hours == 8
        assert action.risk_reduction == 7.0
        assert action.implementation_steps == []
        assert action.verification_steps == []
    
    def test_priority_score(self):
        """Test priority score calculation."""
        # Test different priorities
        immediate_action = RemediationAction(
            id="REM_0001", title="Test", description="Test",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.IMMEDIATE,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=1
        )
        assert immediate_action.priority_score == 100
        
        high_action = RemediationAction(
            id="REM_0002", title="Test", description="Test",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.HIGH,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=1
        )
        assert high_action.priority_score == 75
        
        medium_action = RemediationAction(
            id="REM_0003", title="Test", description="Test",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.MEDIUM,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=1
        )
        assert medium_action.priority_score == 50
        
        low_action = RemediationAction(
            id="REM_0004", title="Test", description="Test",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.LOW,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=1
        )
        assert low_action.priority_score == 25
        
        info_action = RemediationAction(
            id="REM_0005", title="Test", description="Test",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.INFORMATIONAL,
            complexity=RemediationComplexity.LOW,
            estimated_effort_hours=1
        )
        assert info_action.priority_score == 10
    
    def test_effort_to_impact_ratio(self):
        """Test effort-to-impact ratio calculation."""
        # Normal case
        action = RemediationAction(
            id="REM_0001", title="Test", description="Test",
            category=RemediationCategory.AUTHENTICATION,
            priority=RemediationPriority.HIGH,
            complexity=RemediationComplexity.MEDIUM,
            estimated_effort_hours=8,
            risk_reduction=4.0
        )
        assert action.effort_to_impact_ratio == 0.5  # 4.0 / 8
        
        # Zero effort
        action.estimated_effort_hours = 0
        action.risk_reduction = 5.0
        assert action.effort_to_impact_ratio == 0.0
        
        # Zero effort and zero impact
        action.risk_reduction = 0.0
        assert action.effort_to_impact_ratio == float('inf')


class TestRemediationPlan:
    """Test cases for RemediationPlan class."""
    
    @pytest.fixture
    def sample_actions(self):
        """Create sample remediation actions for testing."""
        return [
            RemediationAction(
                id="REM_0001", title="Enable Auth", description="Enable authentication",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.IMMEDIATE,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=8, risk_reduction=7.0
            ),
            RemediationAction(
                id="REM_0002", title="Enable TLS", description="Enable TLS encryption",
                category=RemediationCategory.ENCRYPTION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=6, risk_reduction=8.0
            ),
            RemediationAction(
                id="REM_0003", title="Fix Config", description="Fix configuration",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2, risk_reduction=3.0
            ),
            RemediationAction(
                id="REM_0004", title="Training", description="Security training",
                category=RemediationCategory.PROCESS_IMPROVEMENT,
                priority=RemediationPriority.LOW,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4, risk_reduction=2.0
            )
        ]
    
    def test_remediation_plan_init(self):
        """Test RemediationPlan initialization."""
        plan = RemediationPlan(target_host="test.example.com")
        
        assert plan.target_host == "test.example.com"
        assert plan.actions == []
        assert plan.total_estimated_effort == 0
        assert plan.total_risk_reduction == 0.0
        assert plan.implementation_phases == []
        assert plan.executive_summary == ""
        assert plan.quick_wins == []
        assert plan.long_term_actions == []
    
    def test_immediate_actions(self, sample_actions):
        """Test immediate actions property."""
        plan = RemediationPlan(target_host="test.example.com", actions=sample_actions)
        
        immediate = plan.immediate_actions
        assert len(immediate) == 1
        assert immediate[0].id == "REM_0001"
        assert immediate[0].priority == RemediationPriority.IMMEDIATE
    
    def test_high_priority_actions(self, sample_actions):
        """Test high priority actions property."""
        plan = RemediationPlan(target_host="test.example.com", actions=sample_actions)
        
        high_priority = plan.high_priority_actions
        assert len(high_priority) == 1
        assert high_priority[0].id == "REM_0002"
        assert high_priority[0].priority == RemediationPriority.HIGH
    
    def test_get_actions_by_category(self, sample_actions):
        """Test getting actions by category."""
        plan = RemediationPlan(target_host="test.example.com", actions=sample_actions)
        
        auth_actions = plan.get_actions_by_category(RemediationCategory.AUTHENTICATION)
        assert len(auth_actions) == 1
        assert auth_actions[0].id == "REM_0001"
        
        encryption_actions = plan.get_actions_by_category(RemediationCategory.ENCRYPTION)
        assert len(encryption_actions) == 1
        assert encryption_actions[0].id == "REM_0002"
        
        network_actions = plan.get_actions_by_category(RemediationCategory.NETWORK_SECURITY)
        assert len(network_actions) == 0
    
    def test_get_actions_by_complexity(self, sample_actions):
        """Test getting actions by complexity."""
        plan = RemediationPlan(target_host="test.example.com", actions=sample_actions)
        
        medium_actions = plan.get_actions_by_complexity(RemediationComplexity.MEDIUM)
        assert len(medium_actions) == 2
        assert {a.id for a in medium_actions} == {"REM_0001", "REM_0002"}
        
        low_actions = plan.get_actions_by_complexity(RemediationComplexity.LOW)
        assert len(low_actions) == 2
        assert {a.id for a in low_actions} == {"REM_0003", "REM_0004"}
        
        high_actions = plan.get_actions_by_complexity(RemediationComplexity.HIGH)
        assert len(high_actions) == 0
    
    def test_calculate_totals(self, sample_actions):
        """Test total calculation."""
        plan = RemediationPlan(target_host="test.example.com", actions=sample_actions)
        plan.calculate_totals()
        
        assert plan.total_estimated_effort == 20  # 8 + 6 + 2 + 4
        assert plan.total_risk_reduction == 20.0  # 7.0 + 8.0 + 3.0 + 2.0


class TestRemediationEngine:
    """Test cases for RemediationEngine class."""
    
    @pytest.fixture
    def engine(self):
        """Create remediation engine for testing."""
        return RemediationEngine()
    
    @pytest.fixture
    def sample_findings(self):
        """Create sample security findings for testing."""
        return [
            SecurityFinding(
                id="FIND_001",
                title="Authentication Disabled",
                description="MCP server has authentication disabled",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.CRITICAL,
                confidence=0.9,
                affected_asset="test.example.com",
                remediation="Enable authentication to secure access"
            ),
            SecurityFinding(
                id="FIND_002",
                title="TLS Not Enabled",
                description="MCP server does not use TLS encryption",
                category=VulnerabilityCategory.ENCRYPTION,
                severity=RiskLevel.HIGH,
                confidence=0.8,
                affected_asset="test.example.com",
                remediation="Enable TLS encryption"
            ),
            SecurityFinding(
                id="FIND_003",
                title="Default Port Used",
                description="MCP server uses default port",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.MEDIUM,
                confidence=0.7,
                affected_asset="test.example.com",
                remediation="Change to non-default port"
            ),
            SecurityFinding(
                id="FIND_004",
                title="Debug Mode Enabled",
                description="Debug mode is enabled in production",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.LOW,
                confidence=0.6,
                affected_asset="test.example.com",
                remediation="Disable debug mode"
            ),
            SecurityFinding(
                id="FIND_005",
                title="CORS Wildcard",
                description="CORS allows all origins",
                category=VulnerabilityCategory.NETWORK,
                severity=RiskLevel.HIGH,
                confidence=0.8,
                affected_asset="test.example.com",
                remediation="Configure restrictive CORS policy"
            )
        ]
    
    @pytest.fixture
    def sample_assessment_results(self, sample_findings):
        """Create sample assessment results for testing."""
        result = AssessmentResult(
            target_host="test.example.com",
            findings=sample_findings
        )
        result.calculate_overall_risk()
        return [result]
    
    def test_engine_init(self, engine):
        """Test engine initialization."""
        assert engine.settings == {}
        assert engine.logger is not None
        assert engine._remediation_templates is not None
    
    def test_generate_remediation_plan_empty(self, engine):
        """Test generating plan with no assessment results."""
        plan = engine.generate_remediation_plan([])
        
        assert plan.target_host == "unknown"
        assert plan.actions == []
        assert plan.total_estimated_effort == 0
        assert plan.total_risk_reduction == 0.0
    
    def test_generate_remediation_plan_basic(self, engine, sample_assessment_results):
        """Test generating basic remediation plan."""
        plan = engine.generate_remediation_plan(sample_assessment_results)
        
        assert plan.target_host == "test.example.com"
        assert len(plan.actions) > 0
        assert plan.total_estimated_effort > 0
        assert plan.total_risk_reduction > 0.0
        assert plan.executive_summary != ""
        assert len(plan.implementation_phases) > 0
    
    def test_generate_auth_actions(self, engine, sample_findings):
        """Test generating authentication actions."""
        auth_findings = [f for f in sample_findings if f.category == VulnerabilityCategory.AUTHENTICATION]
        actions = engine._generate_auth_actions(auth_findings, 1)
        
        assert len(actions) > 0
        assert all(action.category == RemediationCategory.AUTHENTICATION for action in actions)
        assert any("Enable Authentication" in action.title for action in actions)
    
    def test_generate_encryption_actions(self, engine, sample_findings):
        """Test generating encryption actions."""
        encryption_findings = [f for f in sample_findings if f.category == VulnerabilityCategory.ENCRYPTION]
        actions = engine._generate_encryption_actions(encryption_findings, 1)
        
        assert len(actions) > 0
        assert all(action.category == RemediationCategory.ENCRYPTION for action in actions)
        assert any("TLS" in action.title for action in actions)
    
    def test_generate_config_actions(self, engine, sample_findings):
        """Test generating configuration actions."""
        config_findings = [f for f in sample_findings if f.category == VulnerabilityCategory.CONFIGURATION]
        actions = engine._generate_config_actions(config_findings, 1)
        
        assert len(actions) > 0
        assert all(action.category == RemediationCategory.CONFIGURATION for action in actions)
    
    def test_generate_network_actions(self, engine, sample_findings):
        """Test generating network security actions."""
        network_findings = [f for f in sample_findings if f.category == VulnerabilityCategory.NETWORK]
        actions = engine._generate_network_actions(network_findings, 1)
        
        assert len(actions) > 0
        assert all(action.category == RemediationCategory.NETWORK_SECURITY for action in actions)
        assert any("CORS" in action.title for action in actions)
    
    def test_prioritize_actions(self, engine):
        """Test action prioritization."""
        actions = [
            RemediationAction(
                id="REM_0001", title="Low Priority", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.LOW,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4, risk_reduction=2.0
            ),
            RemediationAction(
                id="REM_0002", title="High Priority", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2, risk_reduction=8.0
            ),
            RemediationAction(
                id="REM_0003", title="Immediate Priority", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.IMMEDIATE,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=1, risk_reduction=5.0
            )
        ]
        
        prioritized = engine._prioritize_actions(actions)
        
        # Should be ordered by priority (immediate, high, low)
        assert prioritized[0].id == "REM_0003"  # Immediate
        assert prioritized[1].id == "REM_0002"  # High
        assert prioritized[2].id == "REM_0001"  # Low
    
    def test_identify_quick_wins(self, engine):
        """Test quick win identification."""
        actions = [
            RemediationAction(
                id="REM_0001", title="Quick Win", description="Test",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.TRIVIAL,
                estimated_effort_hours=2, risk_reduction=4.0  # <= 4 hours, >= 3.0 reduction
            ),
            RemediationAction(
                id="REM_0002", title="Not Quick Win - High Effort", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.HIGH,
                estimated_effort_hours=20, risk_reduction=8.0  # > 4 hours
            ),
            RemediationAction(
                id="REM_0003", title="Not Quick Win - Low Impact", description="Test",
                category=RemediationCategory.MONITORING,
                priority=RemediationPriority.LOW,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2, risk_reduction=1.0  # < 3.0 reduction
            )
        ]
        
        quick_wins = engine._identify_quick_wins(actions)
        
        assert len(quick_wins) == 1
        assert quick_wins[0] == "REM_0001"
    
    def test_identify_long_term_actions(self, engine):
        """Test long-term action identification."""
        actions = [
            RemediationAction(
                id="REM_0001", title="Short Term", description="Test",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4, risk_reduction=3.0
            ),
            RemediationAction(
                id="REM_0002", title="Long Term - High Effort", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=20, risk_reduction=8.0  # > 16 hours
            ),
            RemediationAction(
                id="REM_0003", title="Long Term - High Complexity", description="Test",
                category=RemediationCategory.INFRASTRUCTURE,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.HIGH,  # High complexity
                estimated_effort_hours=8, risk_reduction=6.0
            )
        ]
        
        long_term = engine._identify_long_term_actions(actions)
        
        assert len(long_term) == 2
        assert set(long_term) == {"REM_0002", "REM_0003"}
    
    def test_create_implementation_phases(self, engine):
        """Test implementation phase creation."""
        actions = [
            RemediationAction(
                id="REM_0001", title="Immediate", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.IMMEDIATE,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2, risk_reduction=5.0
            ),
            RemediationAction(
                id="REM_0002", title="High", description="Test",
                category=RemediationCategory.ENCRYPTION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=6, risk_reduction=7.0
            ),
            RemediationAction(
                id="REM_0003", title="Medium", description="Test",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=3, risk_reduction=3.0
            ),
            RemediationAction(
                id="REM_0004", title="Low", description="Test",
                category=RemediationCategory.MONITORING,
                priority=RemediationPriority.LOW,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4, risk_reduction=2.0
            )
        ]
        
        phases = engine._create_implementation_phases(actions)
        
        assert len(phases) == 4  # All priority levels represented
        assert "REM_0001" in phases[0]  # Immediate in phase 1
        assert "REM_0002" in phases[1]  # High in phase 2
        assert "REM_0003" in phases[2]  # Medium in phase 3
        assert "REM_0004" in phases[3]  # Low in phase 4
    
    def test_generate_executive_summary(self, engine, sample_findings):
        """Test executive summary generation."""
        plan = RemediationPlan(target_host="test.example.com")
        plan.actions = [
            RemediationAction(
                id="REM_0001", title="Test", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=8, risk_reduction=6.0
            )
        ]
        plan.quick_wins = ["REM_0001"]
        plan.calculate_totals()
        
        summary = engine._generate_executive_summary(plan, sample_findings)
        
        assert "test.example.com" in summary
        assert str(len(sample_findings)) in summary
        assert "1 recommended actions" in summary
        assert "8 hours" in summary
        assert "6.0 points" in summary
        assert "1 quick wins" in summary


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    @pytest.fixture
    def sample_assessment_results(self):
        """Create sample assessment results for testing."""
        findings = [
            SecurityFinding(
                id="FIND_001",
                title="Test Finding",
                description="Test description",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.HIGH,
                confidence=0.8,
                affected_asset="test.example.com"
            )
        ]
        
        result = AssessmentResult(
            target_host="test.example.com",
            findings=findings
        )
        return [result]
    
    def test_generate_remediation_plan_function(self, sample_assessment_results):
        """Test generate_remediation_plan convenience function."""
        plan = generate_remediation_plan(sample_assessment_results)
        
        assert isinstance(plan, RemediationPlan)
        assert plan.target_host == "test.example.com"
        assert len(plan.actions) > 0
    
    def test_get_quick_wins_function(self):
        """Test get_quick_wins convenience function."""
        actions = [
            RemediationAction(
                id="REM_0001", title="Quick Win", description="Test",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2, risk_reduction=4.0
            ),
            RemediationAction(
                id="REM_0002", title="Not Quick Win", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.HIGH,
                estimated_effort_hours=20, risk_reduction=8.0
            )
        ]
        
        plan = RemediationPlan(
            target_host="test.example.com",
            actions=actions,
            quick_wins=["REM_0001"]
        )
        
        quick_wins = get_quick_wins(plan)
        
        assert len(quick_wins) == 1
        assert quick_wins[0].id == "REM_0001"
    
    def test_estimate_implementation_time_function(self):
        """Test estimate_implementation_time convenience function."""
        actions = [
            RemediationAction(
                id="REM_0001", title="Immediate", description="Test",
                category=RemediationCategory.AUTHENTICATION,
                priority=RemediationPriority.IMMEDIATE,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=4, risk_reduction=5.0
            ),
            RemediationAction(
                id="REM_0002", title="High", description="Test",
                category=RemediationCategory.ENCRYPTION,
                priority=RemediationPriority.HIGH,
                complexity=RemediationComplexity.MEDIUM,
                estimated_effort_hours=8, risk_reduction=7.0
            ),
            RemediationAction(
                id="REM_0003", title="Medium", description="Test",
                category=RemediationCategory.CONFIGURATION,
                priority=RemediationPriority.MEDIUM,
                complexity=RemediationComplexity.LOW,
                estimated_effort_hours=2, risk_reduction=3.0
            )
        ]
        
        plan = RemediationPlan(
            target_host="test.example.com",
            actions=actions,
            quick_wins=["REM_0003"],
            long_term_actions=[],
            implementation_phases=[["REM_0001"], ["REM_0002"], ["REM_0003"]]
        )
        plan.calculate_totals()
        
        estimates = estimate_implementation_time(plan)
        
        assert estimates["total_hours"] == 14  # 4 + 8 + 2
        assert "by_priority" in estimates
        assert "by_phase" in estimates
        assert estimates["by_priority"]["immediate"] == 4
        assert estimates["by_priority"]["high"] == 8
        assert estimates["by_priority"]["medium"] == 2
        assert len(estimates["by_phase"]) == 3
        assert estimates["quick_wins_hours"] == 2
        assert estimates["long_term_hours"] == 0


class TestRemediationIntegration:
    """Integration tests for remediation functionality."""
    
    def test_end_to_end_remediation_workflow(self):
        """Test complete remediation workflow from findings to plan."""
        # Create realistic security findings
        findings = [
            SecurityFinding(
                id="AUTH_001",
                title="Authentication Disabled",
                description="MCP server authentication is disabled",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.CRITICAL,
                confidence=0.9,
                affected_asset="mcp.example.com",
                remediation="Enable authentication mechanisms"
            ),
            SecurityFinding(
                id="ENC_001",
                title="TLS Not Configured",
                description="Server does not use TLS encryption",
                category=VulnerabilityCategory.ENCRYPTION,
                severity=RiskLevel.HIGH,
                confidence=0.8,
                affected_asset="mcp.example.com",
                remediation="Configure TLS encryption"
            ),
            SecurityFinding(
                id="CFG_001",
                title="Default Configuration",
                description="Server uses default configuration values",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.MEDIUM,
                confidence=0.7,
                affected_asset="mcp.example.com",
                remediation="Customize configuration settings"
            )
        ]
        
        # Create assessment result
        assessment_result = AssessmentResult(
            target_host="mcp.example.com",
            findings=findings
        )
        assessment_result.calculate_overall_risk()
        
        # Generate remediation plan
        plan = generate_remediation_plan([assessment_result])
        
        # Verify plan structure
        assert plan.target_host == "mcp.example.com"
        assert len(plan.actions) > 0
        assert plan.total_estimated_effort > 0
        assert plan.total_risk_reduction > 0
        assert plan.executive_summary != ""
        
        # Verify immediate actions exist for critical findings
        immediate_actions = plan.immediate_actions
        assert len(immediate_actions) > 0
        
        # Verify high priority actions exist for high severity findings
        high_priority_actions = plan.high_priority_actions
        assert len(high_priority_actions) > 0
        
        # Verify implementation phases are created
        assert len(plan.implementation_phases) > 0
        
        # Verify quick wins are identified
        quick_wins = get_quick_wins(plan)
        assert isinstance(quick_wins, list)
        
        # Verify time estimates
        estimates = estimate_implementation_time(plan)
        assert estimates["total_hours"] > 0
        assert "by_priority" in estimates
        assert "by_phase" in estimates
    
    def test_multiple_assessment_results(self):
        """Test remediation plan generation with multiple assessment results."""
        # Create multiple assessment results
        results = []
        for i in range(3):
            findings = [
                SecurityFinding(
                    id=f"FIND_{i}_001",
                    title=f"Finding {i}",
                    description=f"Test finding {i}",
                    category=VulnerabilityCategory.AUTHENTICATION,
                    severity=RiskLevel.HIGH,
                    confidence=0.8,
                    affected_asset=f"host{i}.example.com"
                )
            ]
            
            result = AssessmentResult(
                target_host=f"host{i}.example.com",
                findings=findings
            )
            results.append(result)
        
        # Generate plan
        plan = generate_remediation_plan(results)
        
        # Should use first host as primary target
        assert plan.target_host == "host0.example.com"
        
        # Should aggregate all findings
        total_findings = sum(len(result.findings) for result in results)
        assert len(plan.actions) > 0  # Should generate actions for aggregated findings
    
    def test_empty_findings_handling(self):
        """Test handling of assessment results with no findings."""
        # Create assessment result with no findings
        result = AssessmentResult(target_host="clean.example.com")
        
        # Generate plan
        plan = generate_remediation_plan([result])
        
        # Should handle gracefully
        assert plan.target_host == "clean.example.com"
        # May have minimal actions (like training) even with no findings
        assert plan.total_estimated_effort >= 0
        assert plan.total_risk_reduction >= 0.0 