"""
Unit tests for executive summary generator.

This module tests the executive summary generation functionality including
metrics extraction, finding identification, and summary text generation.
"""

import pytest
from datetime import datetime

from src.hawkeye.reporting.executive_summary import (
    ExecutiveSummaryGenerator,
    ExecutiveFinding,
    ExecutiveMetrics
)
from src.hawkeye.reporting.base import (
    ReportData,
    ReportMetadata,
    ScanSummary,
    DetectionSummary,
    RiskSummary
)


class TestExecutiveSummaryGenerator:
    """Test cases for executive summary generator."""
    
    @pytest.fixture
    def generator(self):
        """Create executive summary generator instance."""
        return ExecutiveSummaryGenerator()
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample report metadata."""
        return ReportMetadata(
            scan_id="exec-test-001",
            timestamp=datetime.now(),
            version="1.0.0",
            target_specification="192.168.1.0/24",
            scan_type="comprehensive"
        )
    
    @pytest.fixture
    def high_risk_data(self, sample_metadata):
        """Create high-risk sample data."""
        return ReportData(
            metadata=sample_metadata,
            scan_results=[
                {"target": "192.168.1.10", "status": "success", "ports": [8080, 8443]},
                {"target": "192.168.1.20", "status": "success", "ports": [3000]},
                {"target": "192.168.1.30", "status": "success", "ports": [8000]}
            ],
            detection_results=[
                {"target": "192.168.1.10", "mcp_detected": True, "confidence": 0.95},
                {"target": "192.168.1.20", "mcp_detected": True, "confidence": 0.87},
                {"target": "192.168.1.30", "mcp_detected": True, "confidence": 0.92}
            ],
            assessment_results=[
                {"target": "192.168.1.10", "risk_level": "critical", "score": 9.5},
                {"target": "192.168.1.20", "risk_level": "high", "score": 8.0},
                {"target": "192.168.1.30", "risk_level": "high", "score": 7.5}
            ],
            recommendations=[
                "Implement immediate network segmentation",
                "Enable authentication on all MCP servers",
                "Deploy monitoring and alerting systems"
            ],
            scan_summary=ScanSummary(
                total_targets=10,
                successful_scans=8,
                failed_scans=2,
                scan_duration=180.5,
                ports_scanned=1000
            ),
            detection_summary=DetectionSummary(
                total_detections=3,
                confirmed_mcp_servers=3,
                potential_mcp_servers=0,
                false_positives=0
            ),
            risk_summary=RiskSummary(
                critical_risk_count=1,
                high_risk_count=2,
                medium_risk_count=0,
                low_risk_count=0,
                overall_risk_score=8.5
            ),
            executive_summary=""
        )
    
    @pytest.fixture
    def low_risk_data(self, sample_metadata):
        """Create low-risk sample data."""
        return ReportData(
            metadata=sample_metadata,
            scan_results=[
                {"target": "192.168.1.10", "status": "success", "ports": [8080]}
            ],
            detection_results=[
                {"target": "192.168.1.10", "mcp_detected": True, "confidence": 0.85}
            ],
            assessment_results=[
                {"target": "192.168.1.10", "risk_level": "low", "score": 3.0}
            ],
            recommendations=[
                "Continue monitoring MCP deployments"
            ],
            scan_summary=ScanSummary(
                total_targets=5,
                successful_scans=5,
                failed_scans=0,
                scan_duration=60.0,
                ports_scanned=500
            ),
            detection_summary=DetectionSummary(
                total_detections=1,
                confirmed_mcp_servers=1,
                potential_mcp_servers=0,
                false_positives=0
            ),
            risk_summary=RiskSummary(
                critical_risk_count=0,
                high_risk_count=0,
                medium_risk_count=0,
                low_risk_count=1,
                overall_risk_score=3.0
            ),
            executive_summary=""
        )
    
    def test_generator_initialization(self, generator):
        """Test executive summary generator initialization."""
        assert generator is not None
        assert hasattr(generator, 'logger')
    
    def test_generate_summary_high_risk(self, generator, high_risk_data):
        """Test generating summary for high-risk scenario."""
        summary = generator.generate_summary(high_risk_data)
        
        assert summary is not None
        assert isinstance(summary, str)
        assert len(summary) > 0
        
        # Check for key sections
        assert "Executive Summary - HawkEye Security Assessment" in summary
        assert "Assessment Overview" in summary
        assert "Key Findings" in summary
        assert "Risk Assessment" in summary
        assert "Priority Recommendations" in summary
        assert "Conclusion" in summary
        
        # Check for high-risk indicators
        assert "Critical" in summary or "High" in summary
        assert "immediate" in summary.lower()
    
    def test_generate_summary_low_risk(self, generator, low_risk_data):
        """Test generating summary for low-risk scenario."""
        summary = generator.generate_summary(low_risk_data)
        
        assert summary is not None
        assert isinstance(summary, str)
        assert len(summary) > 0
        
        # Check for positive tone in low-risk scenario
        assert "strong security practices" in summary or "well-secured" in summary
    
    def test_extract_metrics_high_risk(self, generator, high_risk_data):
        """Test metrics extraction for high-risk data."""
        metrics = generator._extract_metrics(high_risk_data)
        
        assert isinstance(metrics, ExecutiveMetrics)
        assert metrics.total_systems_scanned == 10
        assert metrics.mcp_servers_detected == 3
        assert metrics.critical_vulnerabilities == 1
        assert metrics.high_risk_systems == 2
        assert metrics.security_score < 80  # Should be low for high-risk scenario
        assert metrics.risk_reduction_potential > 0
    
    def test_extract_metrics_low_risk(self, generator, low_risk_data):
        """Test metrics extraction for low-risk data."""
        metrics = generator._extract_metrics(low_risk_data)
        
        assert isinstance(metrics, ExecutiveMetrics)
        assert metrics.total_systems_scanned == 5
        assert metrics.mcp_servers_detected == 1
        assert metrics.critical_vulnerabilities == 0
        assert metrics.high_risk_systems == 0
        assert metrics.security_score > 80  # Should be high for low-risk scenario
    
    def test_identify_key_findings_high_risk(self, generator, high_risk_data):
        """Test key findings identification for high-risk data."""
        findings = generator._identify_key_findings(high_risk_data)
        
        assert isinstance(findings, list)
        assert len(findings) > 0
        
        # Check that findings are properly structured
        for finding in findings:
            assert isinstance(finding, ExecutiveFinding)
            assert finding.title
            assert finding.description
            assert finding.business_impact
            assert finding.risk_level
            assert finding.recommendation
            assert 1 <= finding.priority <= 5
        
        # Should have critical findings for high-risk data
        critical_findings = [f for f in findings if f.risk_level == "Critical"]
        assert len(critical_findings) > 0
    
    def test_identify_key_findings_low_risk(self, generator, low_risk_data):
        """Test key findings identification for low-risk data."""
        findings = generator._identify_key_findings(low_risk_data)
        
        # Low-risk data should have fewer or no critical findings
        critical_findings = [f for f in findings if f.risk_level == "Critical"]
        assert len(critical_findings) == 0
    
    def test_calculate_security_score(self, generator, high_risk_data, low_risk_data):
        """Test security score calculation."""
        high_risk_score = generator._calculate_security_score(high_risk_data)
        low_risk_score = generator._calculate_security_score(low_risk_data)
        
        assert 0 <= high_risk_score <= 100
        assert 0 <= low_risk_score <= 100
        assert low_risk_score > high_risk_score  # Low risk should have higher score
    
    def test_calculate_risk_reduction_potential(self, generator, high_risk_data):
        """Test risk reduction potential calculation."""
        potential = generator._calculate_risk_reduction_potential(high_risk_data)
        
        assert 0 <= potential <= 85
        assert potential > 0  # High-risk data should have reduction potential
    
    def test_determine_overall_risk_level(self, generator):
        """Test overall risk level determination."""
        # Test critical risk
        critical_metrics = ExecutiveMetrics(
            total_systems_scanned=10,
            mcp_servers_detected=5,
            critical_vulnerabilities=2,
            high_risk_systems=3,
            compliance_issues=1,
            security_score=30.0,
            risk_reduction_potential=70.0
        )
        assert generator._determine_overall_risk_level(critical_metrics) == "Critical"
        
        # Test high risk
        high_metrics = ExecutiveMetrics(
            total_systems_scanned=10,
            mcp_servers_detected=3,
            critical_vulnerabilities=0,
            high_risk_systems=3,
            compliance_issues=1,
            security_score=50.0,
            risk_reduction_potential=40.0
        )
        assert generator._determine_overall_risk_level(high_metrics) == "High"
        
        # Test low risk
        low_metrics = ExecutiveMetrics(
            total_systems_scanned=5,
            mcp_servers_detected=1,
            critical_vulnerabilities=0,
            high_risk_systems=0,
            compliance_issues=0,
            security_score=90.0,
            risk_reduction_potential=10.0
        )
        assert generator._determine_overall_risk_level(low_metrics) == "Low"
    
    def test_generate_overview_section(self, generator):
        """Test overview section generation."""
        metrics = ExecutiveMetrics(
            total_systems_scanned=10,
            mcp_servers_detected=3,
            critical_vulnerabilities=1,
            high_risk_systems=2,
            compliance_issues=1,
            security_score=65.0,
            risk_reduction_potential=45.0
        )
        
        overview = generator._generate_overview(metrics)
        
        assert overview is not None
        assert "Assessment Overview" in overview
        assert "10" in overview  # total systems
        assert "3" in overview   # MCP servers
        assert "65.0" in overview  # security score
    
    def test_generate_key_findings_section(self, generator):
        """Test key findings section generation."""
        findings = [
            ExecutiveFinding(
                title="Test Finding",
                description="Test description",
                business_impact="Test impact",
                risk_level="High",
                recommendation="Test recommendation",
                priority=1
            )
        ]
        
        section = generator._generate_key_findings(findings)
        
        assert section is not None
        assert "Key Findings" in section
        assert "Test Finding" in section
        assert "High Risk" in section
    
    def test_generate_recommendations_section(self, generator):
        """Test recommendations section generation."""
        findings = [
            ExecutiveFinding(
                title="Critical Issue",
                description="Critical description",
                business_impact="High impact",
                risk_level="Critical",
                recommendation="Fix immediately",
                priority=1
            ),
            ExecutiveFinding(
                title="Medium Issue",
                description="Medium description", 
                business_impact="Medium impact",
                risk_level="Medium",
                recommendation="Fix soon",
                priority=3
            )
        ]
        
        section = generator._generate_recommendations(findings)
        
        assert section is not None
        assert "Priority Recommendations" in section
        assert "Immediate Actions" in section
        assert "Fix immediately" in section
    
    def test_generate_conclusion_urgent(self, generator):
        """Test conclusion generation for urgent scenarios."""
        metrics = ExecutiveMetrics(
            total_systems_scanned=10,
            mcp_servers_detected=5,
            critical_vulnerabilities=3,
            high_risk_systems=4,
            compliance_issues=2,
            security_score=25.0,
            risk_reduction_potential=75.0
        )
        
        findings = [
            ExecutiveFinding(
                title="Critical Issue",
                description="Critical description",
                business_impact="High impact",
                risk_level="Critical",
                recommendation="Fix immediately",
                priority=1
            )
        ]
        
        conclusion = generator._generate_conclusion(metrics, findings)
        
        assert conclusion is not None
        assert "Conclusion" in conclusion
        assert "Immediate action is required" in conclusion
        assert "75%" in conclusion  # risk reduction potential
    
    def test_generate_conclusion_positive(self, generator):
        """Test conclusion generation for positive scenarios."""
        metrics = ExecutiveMetrics(
            total_systems_scanned=5,
            mcp_servers_detected=1,
            critical_vulnerabilities=0,
            high_risk_systems=0,
            compliance_issues=0,
            security_score=90.0,
            risk_reduction_potential=10.0
        )
        
        conclusion = generator._generate_conclusion(metrics, [])
        
        assert conclusion is not None
        assert "Conclusion" in conclusion
        assert "strong security practices" in conclusion
    
    def test_fallback_summary_generation(self, generator, high_risk_data):
        """Test fallback summary generation."""
        # This tests the fallback when detailed generation fails
        fallback = generator._generate_fallback_summary(high_risk_data)
        
        assert fallback is not None
        assert "Executive Summary - HawkEye Security Assessment" in fallback
        assert "Overview" in fallback
        assert "Key Findings" in fallback
        assert str(high_risk_data.total_targets) in fallback
    
    def test_count_compliance_issues(self, generator, high_risk_data):
        """Test compliance issues counting."""
        count = generator._count_compliance_issues(high_risk_data)
        
        assert isinstance(count, int)
        assert count >= 0
    
    def test_count_unprotected_deployments(self, generator, high_risk_data):
        """Test unprotected deployments counting."""
        count = generator._count_unprotected_deployments(high_risk_data)
        
        assert isinstance(count, int)
        assert count >= 0


class TestExecutiveFinding:
    """Test cases for ExecutiveFinding dataclass."""
    
    def test_executive_finding_creation(self):
        """Test creating ExecutiveFinding instance."""
        finding = ExecutiveFinding(
            title="Test Finding",
            description="Test description",
            business_impact="Test impact",
            risk_level="High",
            recommendation="Test recommendation",
            priority=1
        )
        
        assert finding.title == "Test Finding"
        assert finding.description == "Test description"
        assert finding.business_impact == "Test impact"
        assert finding.risk_level == "High"
        assert finding.recommendation == "Test recommendation"
        assert finding.priority == 1


class TestExecutiveMetrics:
    """Test cases for ExecutiveMetrics dataclass."""
    
    def test_executive_metrics_creation(self):
        """Test creating ExecutiveMetrics instance."""
        metrics = ExecutiveMetrics(
            total_systems_scanned=10,
            mcp_servers_detected=3,
            critical_vulnerabilities=1,
            high_risk_systems=2,
            compliance_issues=1,
            security_score=75.0,
            risk_reduction_potential=25.0
        )
        
        assert metrics.total_systems_scanned == 10
        assert metrics.mcp_servers_detected == 3
        assert metrics.critical_vulnerabilities == 1
        assert metrics.high_risk_systems == 2
        assert metrics.compliance_issues == 1
        assert metrics.security_score == 75.0
        assert metrics.risk_reduction_potential == 25.0 