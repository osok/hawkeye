"""
Unit tests for base risk assessment functionality.
"""

import pytest
import time
from unittest.mock import Mock, patch
from typing import List

from src.hawkeye.assessment.base import (
    RiskLevel, VulnerabilityCategory, ComplianceFramework,
    CVSSVector, VulnerabilityInfo, SecurityFinding, AssessmentResult,
    RiskAssessment, RiskAssessor, AssessmentError, CVSSError,
    ConfigurationError, ComplianceError
)
from src.hawkeye.detection.base import DetectionResult, DetectionMethod, MCPServerInfo, TransportType, MCPServerType


class TestRiskLevel:
    """Test cases for RiskLevel enum."""
    
    def test_risk_level_values(self):
        """Test risk level enum values."""
        assert RiskLevel.NONE.value == "none"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"


class TestVulnerabilityCategory:
    """Test cases for VulnerabilityCategory enum."""
    
    def test_vulnerability_category_values(self):
        """Test vulnerability category enum values."""
        assert VulnerabilityCategory.AUTHENTICATION.value == "authentication"
        assert VulnerabilityCategory.AUTHORIZATION.value == "authorization"
        assert VulnerabilityCategory.ENCRYPTION.value == "encryption"
        assert VulnerabilityCategory.CONFIGURATION.value == "configuration"
        assert VulnerabilityCategory.NETWORK.value == "network"


class TestComplianceFramework:
    """Test cases for ComplianceFramework enum."""
    
    def test_compliance_framework_values(self):
        """Test compliance framework enum values."""
        assert ComplianceFramework.OWASP_TOP_10.value == "owasp_top_10"
        assert ComplianceFramework.NIST_CSF.value == "nist_csf"
        assert ComplianceFramework.ISO_27001.value == "iso_27001"
        assert ComplianceFramework.SOC2.value == "soc2"


class TestCVSSVector:
    """Test cases for CVSSVector class."""
    
    def test_cvss_vector_init(self):
        """Test CVSS vector initialization."""
        vector = CVSSVector()
        
        # Test default values
        assert vector.attack_vector == "N"
        assert vector.attack_complexity == "L"
        assert vector.privileges_required == "N"
        assert vector.user_interaction == "N"
        assert vector.scope == "U"
        assert vector.confidentiality == "N"
        assert vector.integrity == "N"
        assert vector.availability == "N"
        
        # Test optional values are None
        assert vector.exploit_code_maturity is None
        assert vector.remediation_level is None
        assert vector.report_confidence is None
    
    def test_cvss_vector_custom_values(self):
        """Test CVSS vector with custom values."""
        vector = CVSSVector(
            attack_vector="A",
            attack_complexity="H",
            privileges_required="L",
            user_interaction="R",
            scope="C",
            confidentiality="H",
            integrity="H",
            availability="H"
        )
        
        assert vector.attack_vector == "A"
        assert vector.attack_complexity == "H"
        assert vector.privileges_required == "L"
        assert vector.user_interaction == "R"
        assert vector.scope == "C"
        assert vector.confidentiality == "H"
        assert vector.integrity == "H"
        assert vector.availability == "H"
    
    def test_to_vector_string_base_only(self):
        """Test CVSS vector string generation with base metrics only."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H"
        )
        
        expected = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert vector.to_vector_string() == expected
    
    def test_to_vector_string_with_temporal(self):
        """Test CVSS vector string generation with temporal metrics."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
            exploit_code_maturity="F",
            remediation_level="O",
            report_confidence="C"
        )
        
        expected = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
        assert vector.to_vector_string() == expected
    
    def test_to_vector_string_with_environmental(self):
        """Test CVSS vector string generation with environmental metrics."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
            confidentiality_requirement="H",
            integrity_requirement="H",
            availability_requirement="H"
        )
        
        expected = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"
        assert vector.to_vector_string() == expected


class TestVulnerabilityInfo:
    """Test cases for VulnerabilityInfo class."""
    
    def test_vulnerability_info_init(self):
        """Test vulnerability info initialization."""
        vuln = VulnerabilityInfo(
            id="CVE-2023-1234",
            title="Test Vulnerability",
            description="A test vulnerability",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH
        )
        
        assert vuln.id == "CVE-2023-1234"
        assert vuln.title == "Test Vulnerability"
        assert vuln.description == "A test vulnerability"
        assert vuln.category == VulnerabilityCategory.AUTHENTICATION
        assert vuln.severity == RiskLevel.HIGH
        assert vuln.cvss_vector is None
        assert vuln.cvss_score is None
        assert vuln.cwe_id is None
        assert vuln.references == []
        assert vuln.affected_components == []
        assert vuln.exploit_available is False
        assert vuln.patch_available is False
        assert vuln.workaround_available is False
    
    def test_is_exploitable_property(self):
        """Test is_exploitable property."""
        # High severity with exploit available
        vuln_exploitable = VulnerabilityInfo(
            id="CVE-2023-1234",
            title="Exploitable Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            exploit_available=True
        )
        assert vuln_exploitable.is_exploitable is True
        
        # Critical severity with exploit available
        vuln_critical = VulnerabilityInfo(
            id="CVE-2023-5678",
            title="Critical Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.CRITICAL,
            exploit_available=True
        )
        assert vuln_critical.is_exploitable is True
        
        # Medium severity with exploit available (not exploitable)
        vuln_medium = VulnerabilityInfo(
            id="CVE-2023-9999",
            title="Medium Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.MEDIUM,
            exploit_available=True
        )
        assert vuln_medium.is_exploitable is False
        
        # High severity without exploit available
        vuln_no_exploit = VulnerabilityInfo(
            id="CVE-2023-0000",
            title="No Exploit Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            exploit_available=False
        )
        assert vuln_no_exploit.is_exploitable is False
    
    def test_has_mitigation_property(self):
        """Test has_mitigation property."""
        # With patch available
        vuln_patch = VulnerabilityInfo(
            id="CVE-2023-1234",
            title="Patched Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            patch_available=True
        )
        assert vuln_patch.has_mitigation is True
        
        # With workaround available
        vuln_workaround = VulnerabilityInfo(
            id="CVE-2023-5678",
            title="Workaround Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            workaround_available=True
        )
        assert vuln_workaround.has_mitigation is True
        
        # With both patch and workaround
        vuln_both = VulnerabilityInfo(
            id="CVE-2023-9999",
            title="Both Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            patch_available=True,
            workaround_available=True
        )
        assert vuln_both.has_mitigation is True
        
        # Without mitigation
        vuln_no_mitigation = VulnerabilityInfo(
            id="CVE-2023-0000",
            title="No Mitigation Vuln",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            patch_available=False,
            workaround_available=False
        )
        assert vuln_no_mitigation.has_mitigation is False


class TestSecurityFinding:
    """Test cases for SecurityFinding class."""
    
    def test_security_finding_init(self):
        """Test security finding initialization."""
        finding = SecurityFinding(
            id="FIND-001",
            title="Test Finding",
            description="A test security finding",
            category=VulnerabilityCategory.CONFIGURATION,
            severity=RiskLevel.MEDIUM,
            confidence=0.8,
            affected_asset="localhost:3000"
        )
        
        assert finding.id == "FIND-001"
        assert finding.title == "Test Finding"
        assert finding.description == "A test security finding"
        assert finding.category == VulnerabilityCategory.CONFIGURATION
        assert finding.severity == RiskLevel.MEDIUM
        assert finding.confidence == 0.8
        assert finding.affected_asset == "localhost:3000"
        assert finding.evidence == {}
        assert finding.remediation is None
        assert finding.references == []
        assert finding.compliance_violations == []
        assert finding.vulnerability_info is None
    
    def test_risk_score_property(self):
        """Test risk score calculation."""
        # Critical severity with high confidence
        finding_critical = SecurityFinding(
            id="FIND-001",
            title="Critical Finding",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.CRITICAL,
            confidence=1.0,
            affected_asset="localhost"
        )
        assert finding_critical.risk_score == 10.0  # 10.0 * 1.0
        
        # High severity with medium confidence
        finding_high = SecurityFinding(
            id="FIND-002",
            title="High Finding",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.HIGH,
            confidence=0.8,
            affected_asset="localhost"
        )
        assert finding_high.risk_score == 6.0  # 7.5 * 0.8
        
        # Medium severity with low confidence
        finding_medium = SecurityFinding(
            id="FIND-003",
            title="Medium Finding",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.MEDIUM,
            confidence=0.5,
            affected_asset="localhost"
        )
        assert finding_medium.risk_score == 2.5  # 5.0 * 0.5
        
        # Low severity
        finding_low = SecurityFinding(
            id="FIND-004",
            title="Low Finding",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.LOW,
            confidence=1.0,
            affected_asset="localhost"
        )
        assert finding_low.risk_score == 2.5  # 2.5 * 1.0
        
        # None severity
        finding_none = SecurityFinding(
            id="FIND-005",
            title="None Finding",
            description="Test",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.NONE,
            confidence=1.0,
            affected_asset="localhost"
        )
        assert finding_none.risk_score == 0.0  # 0.0 * 1.0


class TestAssessmentResult:
    """Test cases for AssessmentResult class."""
    
    @pytest.fixture
    def sample_findings(self):
        """Create sample security findings for testing."""
        return [
            SecurityFinding(
                id="FIND-001",
                title="Critical Finding",
                description="Critical security issue",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.CRITICAL,
                confidence=1.0,
                affected_asset="localhost"
            ),
            SecurityFinding(
                id="FIND-002",
                title="High Finding",
                description="High security issue",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.HIGH,
                confidence=0.9,
                affected_asset="localhost"
            ),
            SecurityFinding(
                id="FIND-003",
                title="Medium Finding",
                description="Medium security issue",
                category=VulnerabilityCategory.NETWORK,
                severity=RiskLevel.MEDIUM,
                confidence=0.8,
                affected_asset="localhost"
            ),
            SecurityFinding(
                id="FIND-004",
                title="Low Finding",
                description="Low security issue",
                category=VulnerabilityCategory.LOGGING,
                severity=RiskLevel.LOW,
                confidence=0.7,
                affected_asset="localhost"
            )
        ]
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Create sample vulnerabilities for testing."""
        return [
            VulnerabilityInfo(
                id="CVE-2023-1234",
                title="Critical Vulnerability",
                description="Critical vulnerability",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.CRITICAL,
                exploit_available=True,
                patch_available=False
            ),
            VulnerabilityInfo(
                id="CVE-2023-5678",
                title="High Vulnerability",
                description="High vulnerability",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.HIGH,
                exploit_available=False,
                patch_available=True
            )
        ]
    
    def test_assessment_result_init(self):
        """Test assessment result initialization."""
        result = AssessmentResult(target_host="localhost")
        
        assert result.target_host == "localhost"
        assert isinstance(result.assessment_timestamp, float)
        assert result.overall_risk_level == RiskLevel.NONE
        assert result.overall_risk_score == 0.0
        assert result.findings == []
        assert result.vulnerabilities == []
        assert result.compliance_status == {}
        assert result.recommendations == []
        assert result.assessment_duration is None
        assert result.raw_data == {}
    
    def test_critical_findings_property(self, sample_findings):
        """Test critical_findings property."""
        result = AssessmentResult(target_host="localhost", findings=sample_findings)
        critical = result.critical_findings
        
        assert len(critical) == 1
        assert critical[0].severity == RiskLevel.CRITICAL
        assert critical[0].id == "FIND-001"
    
    def test_high_findings_property(self, sample_findings):
        """Test high_findings property."""
        result = AssessmentResult(target_host="localhost", findings=sample_findings)
        high = result.high_findings
        
        assert len(high) == 1
        assert high[0].severity == RiskLevel.HIGH
        assert high[0].id == "FIND-002"
    
    def test_exploitable_vulnerabilities_property(self, sample_vulnerabilities):
        """Test exploitable_vulnerabilities property."""
        result = AssessmentResult(target_host="localhost", vulnerabilities=sample_vulnerabilities)
        exploitable = result.exploitable_vulnerabilities
        
        assert len(exploitable) == 1
        assert exploitable[0].is_exploitable is True
        assert exploitable[0].id == "CVE-2023-1234"
    
    def test_unpatched_vulnerabilities_property(self, sample_vulnerabilities):
        """Test unpatched_vulnerabilities property."""
        result = AssessmentResult(target_host="localhost", vulnerabilities=sample_vulnerabilities)
        unpatched = result.unpatched_vulnerabilities
        
        assert len(unpatched) == 1
        assert unpatched[0].has_mitigation is False
        assert unpatched[0].id == "CVE-2023-1234"
    
    def test_get_findings_by_category(self, sample_findings):
        """Test get_findings_by_category method."""
        result = AssessmentResult(target_host="localhost", findings=sample_findings)
        
        auth_findings = result.get_findings_by_category(VulnerabilityCategory.AUTHENTICATION)
        assert len(auth_findings) == 1
        assert auth_findings[0].category == VulnerabilityCategory.AUTHENTICATION
        
        config_findings = result.get_findings_by_category(VulnerabilityCategory.CONFIGURATION)
        assert len(config_findings) == 1
        assert config_findings[0].category == VulnerabilityCategory.CONFIGURATION
        
        encryption_findings = result.get_findings_by_category(VulnerabilityCategory.ENCRYPTION)
        assert len(encryption_findings) == 0
    
    def test_get_compliance_violations(self):
        """Test get_compliance_violations method."""
        findings_with_violations = [
            SecurityFinding(
                id="FIND-001",
                title="OWASP Violation",
                description="Test",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.HIGH,
                confidence=1.0,
                affected_asset="localhost",
                compliance_violations=[ComplianceFramework.OWASP_TOP_10]
            ),
            SecurityFinding(
                id="FIND-002",
                title="Multiple Violations",
                description="Test",
                category=VulnerabilityCategory.CONFIGURATION,
                severity=RiskLevel.MEDIUM,
                confidence=1.0,
                affected_asset="localhost",
                compliance_violations=[ComplianceFramework.OWASP_TOP_10, ComplianceFramework.NIST_CSF]
            )
        ]
        
        result = AssessmentResult(target_host="localhost", findings=findings_with_violations)
        violations = result.get_compliance_violations()
        
        assert len(violations[ComplianceFramework.OWASP_TOP_10]) == 2
        assert len(violations[ComplianceFramework.NIST_CSF]) == 1
        assert len(violations[ComplianceFramework.ISO_27001]) == 0
    
    def test_calculate_overall_risk_no_findings(self):
        """Test calculate_overall_risk with no findings."""
        result = AssessmentResult(target_host="localhost")
        result.calculate_overall_risk()
        
        assert result.overall_risk_level == RiskLevel.NONE
        assert result.overall_risk_score == 0.0
    
    def test_calculate_overall_risk_with_findings(self, sample_findings):
        """Test calculate_overall_risk with findings."""
        result = AssessmentResult(target_host="localhost", findings=sample_findings)
        result.calculate_overall_risk()
        
        # Should be CRITICAL due to critical finding
        assert result.overall_risk_level == RiskLevel.CRITICAL
        assert result.overall_risk_score > 0.0
    
    def test_calculate_overall_risk_levels(self):
        """Test calculate_overall_risk with different severity combinations."""
        # Only high findings
        high_findings = [
            SecurityFinding(
                id="FIND-001",
                title="High Finding",
                description="Test",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.HIGH,
                confidence=1.0,
                affected_asset="localhost"
            )
        ]
        result = AssessmentResult(target_host="localhost", findings=high_findings)
        result.calculate_overall_risk()
        assert result.overall_risk_level == RiskLevel.HIGH
        
        # Only medium findings
        medium_findings = [
            SecurityFinding(
                id="FIND-001",
                title="Medium Finding",
                description="Test",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.MEDIUM,
                confidence=1.0,
                affected_asset="localhost"
            )
        ]
        result = AssessmentResult(target_host="localhost", findings=medium_findings)
        result.calculate_overall_risk()
        assert result.overall_risk_level == RiskLevel.MEDIUM
        
        # Only low findings
        low_findings = [
            SecurityFinding(
                id="FIND-001",
                title="Low Finding",
                description="Test",
                category=VulnerabilityCategory.AUTHENTICATION,
                severity=RiskLevel.LOW,
                confidence=1.0,
                affected_asset="localhost"
            )
        ]
        result = AssessmentResult(target_host="localhost", findings=low_findings)
        result.calculate_overall_risk()
        assert result.overall_risk_level == RiskLevel.LOW
    
    def test_to_dict(self, sample_findings, sample_vulnerabilities):
        """Test to_dict method."""
        compliance_status = {
            ComplianceFramework.OWASP_TOP_10: True,
            ComplianceFramework.NIST_CSF: False
        }
        
        result = AssessmentResult(
            target_host="localhost",
            findings=sample_findings[:2],  # First 2 findings
            vulnerabilities=sample_vulnerabilities,
            compliance_status=compliance_status,
            recommendations=["Fix authentication", "Update configuration"],
            assessment_duration=1.5
        )
        result.calculate_overall_risk()
        
        result_dict = result.to_dict()
        
        assert result_dict['target_host'] == "localhost"
        assert result_dict['overall_risk_level'] == result.overall_risk_level.value
        assert result_dict['overall_risk_score'] == result.overall_risk_score
        assert result_dict['assessment_duration'] == 1.5
        
        # Check summary
        summary = result_dict['summary']
        assert summary['total_findings'] == 2
        assert summary['critical_findings'] == 1
        assert summary['high_findings'] == 1
        assert summary['total_vulnerabilities'] == 2
        assert summary['exploitable_vulnerabilities'] == 1
        assert summary['unpatched_vulnerabilities'] == 1
        
        # Check findings
        assert len(result_dict['findings']) == 2
        assert result_dict['findings'][0]['id'] == "FIND-001"
        assert result_dict['findings'][0]['severity'] == "critical"
        
        # Check vulnerabilities
        assert len(result_dict['vulnerabilities']) == 2
        assert result_dict['vulnerabilities'][0]['id'] == "CVE-2023-1234"
        assert result_dict['vulnerabilities'][0]['is_exploitable'] is True
        
        # Check compliance status
        assert result_dict['compliance_status']['owasp_top_10'] is True
        assert result_dict['compliance_status']['nist_csf'] is False
        
        # Check recommendations
        assert len(result_dict['recommendations']) == 2
        assert "Fix authentication" in result_dict['recommendations']


class TestRiskAssessment:
    """Test cases for RiskAssessment class."""
    
    @pytest.fixture
    def sample_results(self):
        """Create sample assessment results for testing."""
        return [
            AssessmentResult(
                target_host="host1",
                overall_risk_level=RiskLevel.CRITICAL,
                findings=[
                    SecurityFinding(
                        id="FIND-001",
                        title="Critical Finding",
                        description="Test",
                        category=VulnerabilityCategory.AUTHENTICATION,
                        severity=RiskLevel.CRITICAL,
                        confidence=1.0,
                        affected_asset="host1"
                    )
                ]
            ),
            AssessmentResult(
                target_host="host2",
                overall_risk_level=RiskLevel.HIGH,
                findings=[
                    SecurityFinding(
                        id="FIND-002",
                        title="High Finding",
                        description="Test",
                        category=VulnerabilityCategory.CONFIGURATION,
                        severity=RiskLevel.HIGH,
                        confidence=1.0,
                        affected_asset="host2"
                    )
                ]
            ),
            AssessmentResult(
                target_host="host3",
                overall_risk_level=RiskLevel.LOW,
                findings=[
                    SecurityFinding(
                        id="FIND-003",
                        title="Low Finding",
                        description="Test",
                        category=VulnerabilityCategory.LOGGING,
                        severity=RiskLevel.LOW,
                        confidence=1.0,
                        affected_asset="host3"
                    )
                ]
            )
        ]
    
    def test_risk_assessment_init(self):
        """Test risk assessment initialization."""
        assessment = RiskAssessment()
        
        assert assessment.results == []
        assert assessment.start_time is None
        assert assessment.end_time is None
    
    def test_add_result(self, sample_results):
        """Test add_result method."""
        assessment = RiskAssessment()
        
        for result in sample_results:
            assessment.add_result(result)
        
        assert len(assessment.results) == 3
        assert assessment.results[0].target_host == "host1"
        assert assessment.results[1].target_host == "host2"
        assert assessment.results[2].target_host == "host3"
    
    def test_get_results_by_risk_level(self, sample_results):
        """Test get_results_by_risk_level method."""
        assessment = RiskAssessment()
        for result in sample_results:
            assessment.add_result(result)
        
        critical_results = assessment.get_results_by_risk_level(RiskLevel.CRITICAL)
        assert len(critical_results) == 1
        assert critical_results[0].target_host == "host1"
        
        high_results = assessment.get_results_by_risk_level(RiskLevel.HIGH)
        assert len(high_results) == 1
        assert high_results[0].target_host == "host2"
        
        medium_results = assessment.get_results_by_risk_level(RiskLevel.MEDIUM)
        assert len(medium_results) == 0
        
        low_results = assessment.get_results_by_risk_level(RiskLevel.LOW)
        assert len(low_results) == 1
        assert low_results[0].target_host == "host3"
    
    def test_get_high_risk_targets(self, sample_results):
        """Test get_high_risk_targets method."""
        assessment = RiskAssessment()
        for result in sample_results:
            assessment.add_result(result)
        
        high_risk = assessment.get_high_risk_targets()
        assert len(high_risk) == 2  # Critical and High
        
        target_hosts = [r.target_host for r in high_risk]
        assert "host1" in target_hosts  # Critical
        assert "host2" in target_hosts  # High
        assert "host3" not in target_hosts  # Low
    
    def test_get_overall_statistics_empty(self):
        """Test get_overall_statistics with no results."""
        assessment = RiskAssessment()
        stats = assessment.get_overall_statistics()
        
        assert stats == {}
    
    def test_get_overall_statistics_with_results(self, sample_results):
        """Test get_overall_statistics with results."""
        assessment = RiskAssessment()
        assessment.start_time = time.time()
        
        for result in sample_results:
            assessment.add_result(result)
        
        assessment.end_time = time.time()
        
        stats = assessment.get_overall_statistics()
        
        assert stats['total_targets_assessed'] == 3
        assert stats['total_findings'] == 3
        assert stats['total_vulnerabilities'] == 0  # No vulnerabilities in sample
        assert stats['high_risk_targets'] == 2
        assert stats['risk_distribution']['critical'] == 1
        assert stats['risk_distribution']['high'] == 1
        assert stats['risk_distribution']['medium'] == 0
        assert stats['risk_distribution']['low'] == 1
        assert stats['risk_distribution']['none'] == 0
        assert stats['assessment_duration'] is not None
        assert stats['assessment_duration'] >= 0


class TestRiskAssessor:
    """Test cases for RiskAssessor abstract base class."""
    
    class MockRiskAssessor(RiskAssessor):
        """Mock implementation of RiskAssessor for testing."""
        
        def assess(self, detection_result: DetectionResult, **kwargs) -> AssessmentResult:
            """Mock assess method."""
            result = AssessmentResult(target_host=detection_result.target_host)
            
            if detection_result.success:
                # Add a mock finding
                finding = SecurityFinding(
                    id="MOCK-001",
                    title="Mock Finding",
                    description="Mock security finding",
                    category=VulnerabilityCategory.CONFIGURATION,
                    severity=RiskLevel.MEDIUM,
                    confidence=0.8,
                    affected_asset=detection_result.target_host
                )
                result.findings.append(finding)
                result.calculate_overall_risk()
            
            return result
        
        def get_assessment_type(self) -> str:
            """Mock assessment type."""
            return "mock_assessment"
    
    @pytest.fixture
    def mock_assessor(self):
        """Create mock risk assessor for testing."""
        return self.MockRiskAssessor()
    
    @pytest.fixture
    def mock_detection_results(self):
        """Create mock detection results for testing."""
        return [
            DetectionResult(
                target_host="host1",
                detection_method=DetectionMethod.PROCESS_ENUMERATION,
                success=True,
                mcp_server=MCPServerInfo(
                    host="host1",
                    port=3000,
                    transport_type=TransportType.HTTP,
                    server_type=MCPServerType.STANDALONE
                ),
                confidence=0.9
            ),
            DetectionResult(
                target_host="host2",
                detection_method=DetectionMethod.CONFIG_FILE_DISCOVERY,
                success=True,
                mcp_server=MCPServerInfo(
                    host="host2",
                    port=8080,
                    transport_type=TransportType.WEBSOCKET,
                    server_type=MCPServerType.NPX_PACKAGE
                ),
                confidence=0.8
            ),
            DetectionResult(
                target_host="host3",
                detection_method=DetectionMethod.PROTOCOL_HANDSHAKE,
                success=False,
                confidence=0.0
            )
        ]
    
    def test_risk_assessor_init(self, mock_assessor):
        """Test risk assessor initialization."""
        assert mock_assessor.settings is not None
        assert mock_assessor.logger is not None
        assert mock_assessor._assessment_stats['total_assessments'] == 0
        assert mock_assessor._assessment_stats['successful_assessments'] == 0
        assert mock_assessor._assessment_stats['failed_assessments'] == 0
        assert mock_assessor._assessment_stats['findings_generated'] == 0
        assert mock_assessor._assessment_stats['vulnerabilities_identified'] == 0
    
    def test_assess_single_result(self, mock_assessor, mock_detection_results):
        """Test assess method with single detection result."""
        detection_result = mock_detection_results[0]  # Successful detection
        
        assessment_result = mock_assessor.assess(detection_result)
        
        assert assessment_result.target_host == "host1"
        assert len(assessment_result.findings) == 1
        assert assessment_result.overall_risk_level == RiskLevel.MEDIUM
    
    def test_assess_multiple_results(self, mock_assessor, mock_detection_results):
        """Test assess_multiple method."""
        assessment = mock_assessor.assess_multiple(mock_detection_results)
        
        assert len(assessment.results) == 3
        assert assessment.start_time is not None
        assert assessment.end_time is not None
        assert assessment.end_time >= assessment.start_time
        
        # Check statistics
        stats = mock_assessor.get_assessment_statistics()
        assert stats['total_assessments'] == 3
        assert stats['successful_assessments'] == 3  # Mock doesn't fail
        assert stats['failed_assessments'] == 0
        assert stats['findings_generated'] == 2  # Only successful detections get findings
    
    def test_assess_multiple_with_exception(self, mock_assessor):
        """Test assess_multiple with exception handling."""
        # Create a detection result that will cause an exception
        bad_detection = DetectionResult(
            target_host="bad_host",
            detection_method=DetectionMethod.PROCESS_ENUMERATION,
            success=True
        )
        
        # Mock the assess method to raise an exception
        original_assess = mock_assessor.assess
        def failing_assess(detection_result, **kwargs):
            if detection_result.target_host == "bad_host":
                raise Exception("Mock assessment error")
            return original_assess(detection_result, **kwargs)
        
        mock_assessor.assess = failing_assess
        
        assessment = mock_assessor.assess_multiple([bad_detection])
        
        assert len(assessment.results) == 0  # No successful assessments
        
        stats = mock_assessor.get_assessment_statistics()
        assert stats['total_assessments'] == 1
        assert stats['successful_assessments'] == 0
        assert stats['failed_assessments'] == 1
    
    def test_get_assessment_type(self, mock_assessor):
        """Test get_assessment_type method."""
        assert mock_assessor.get_assessment_type() == "mock_assessment"
    
    def test_get_assessment_statistics(self, mock_assessor, mock_detection_results):
        """Test get_assessment_statistics method."""
        # Initial statistics
        stats = mock_assessor.get_assessment_statistics()
        assert stats['total_assessments'] == 0
        
        # After assessment
        mock_assessor.assess_multiple(mock_detection_results)
        stats = mock_assessor.get_assessment_statistics()
        
        assert stats['total_assessments'] == 3
        assert stats['successful_assessments'] == 3
        assert stats['failed_assessments'] == 0
        assert stats['findings_generated'] == 2
        assert stats['vulnerabilities_identified'] == 0
    
    def test_clear_statistics(self, mock_assessor, mock_detection_results):
        """Test clear_statistics method."""
        # Generate some statistics
        mock_assessor.assess_multiple(mock_detection_results)
        stats = mock_assessor.get_assessment_statistics()
        assert stats['total_assessments'] > 0
        
        # Clear statistics
        mock_assessor.clear_statistics()
        stats = mock_assessor.get_assessment_statistics()
        
        assert stats['total_assessments'] == 0
        assert stats['successful_assessments'] == 0
        assert stats['failed_assessments'] == 0
        assert stats['findings_generated'] == 0
        assert stats['vulnerabilities_identified'] == 0


class TestExceptions:
    """Test cases for assessment exception classes."""
    
    def test_assessment_error(self):
        """Test AssessmentError exception."""
        with pytest.raises(AssessmentError):
            raise AssessmentError("Test assessment error")
    
    def test_cvss_error(self):
        """Test CVSSError exception."""
        with pytest.raises(CVSSError):
            raise CVSSError("Test CVSS error")
        
        # Test inheritance
        with pytest.raises(AssessmentError):
            raise CVSSError("Test CVSS error")
    
    def test_configuration_error(self):
        """Test ConfigurationError exception."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("Test configuration error")
        
        # Test inheritance
        with pytest.raises(AssessmentError):
            raise ConfigurationError("Test configuration error")
    
    def test_compliance_error(self):
        """Test ComplianceError exception."""
        with pytest.raises(ComplianceError):
            raise ComplianceError("Test compliance error")
        
        # Test inheritance
        with pytest.raises(AssessmentError):
            raise ComplianceError("Test compliance error")


if __name__ == '__main__':
    pytest.main([__file__]) 