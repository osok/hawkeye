"""
Unit tests for CVSS scoring functionality.
"""

import pytest
import math
from unittest.mock import Mock, patch

from src.hawkeye.assessment.cvss_scoring import (
    CVSSScores, CVSSCalculator, CVSSAssessment,
    calculate_cvss_score, get_risk_level_from_score,
    CVSS_METRICS
)
from src.hawkeye.assessment.base import (
    CVSSVector, VulnerabilityInfo, VulnerabilityCategory,
    RiskLevel, CVSSError
)


class TestCVSSScores:
    """Test cases for CVSSScores class."""
    
    def test_cvss_scores_init(self):
        """Test CVSSScores initialization."""
        scores = CVSSScores(
            base_score=7.5,
            exploitability_score=3.9,
            impact_score=5.9
        )
        
        assert scores.base_score == 7.5
        assert scores.temporal_score is None
        assert scores.environmental_score is None
        assert scores.exploitability_score == 3.9
        assert scores.impact_score == 5.9
        assert scores.overall_score == 7.5  # Should be calculated in __post_init__
        assert scores.risk_level == RiskLevel.HIGH  # 7.5 is HIGH
    
    def test_calculate_overall_score(self):
        """Test overall score calculation."""
        # Base score only
        scores = CVSSScores(base_score=6.0)
        scores.calculate_overall_score()
        assert scores.overall_score == 6.0
        
        # With temporal score
        scores.temporal_score = 5.5
        scores.calculate_overall_score()
        assert scores.overall_score == 6.0  # Base is higher
        
        # With environmental score
        scores.environmental_score = 7.2
        scores.calculate_overall_score()
        assert scores.overall_score == 7.2  # Environmental is highest
    
    def test_calculate_risk_level(self):
        """Test risk level calculation from score."""
        test_cases = [
            (0.0, RiskLevel.NONE),
            (2.5, RiskLevel.LOW),
            (3.9, RiskLevel.LOW),
            (4.0, RiskLevel.MEDIUM),
            (6.9, RiskLevel.MEDIUM),
            (7.0, RiskLevel.HIGH),
            (8.9, RiskLevel.HIGH),
            (9.0, RiskLevel.CRITICAL),
            (10.0, RiskLevel.CRITICAL)
        ]
        
        for score, expected_level in test_cases:
            scores = CVSSScores(base_score=score)
            scores.calculate_risk_level()
            assert scores.risk_level == expected_level, f"Score {score} should be {expected_level}"
    
    def test_to_dict(self):
        """Test to_dict method."""
        scores = CVSSScores(
            base_score=7.5,
            temporal_score=7.1,
            environmental_score=8.2,
            exploitability_score=3.9,
            impact_score=5.9,
            temporal_multiplier=0.946,
            modified_impact_score=6.1,
            modified_exploitability_score=4.0
        )
        
        result = scores.to_dict()
        
        assert result['base_score'] == 7.5
        assert result['temporal_score'] == 7.1
        assert result['environmental_score'] == 8.2
        assert result['overall_score'] == 8.2
        assert result['risk_level'] == 'high'
        
        components = result['components']
        assert components['exploitability_score'] == 3.9
        assert components['impact_score'] == 5.9
        assert components['temporal_multiplier'] == 0.946
        assert components['modified_impact_score'] == 6.1
        assert components['modified_exploitability_score'] == 4.0


class TestCVSSCalculator:
    """Test cases for CVSSCalculator class."""
    
    @pytest.fixture
    def calculator(self):
        """Create CVSS calculator for testing."""
        return CVSSCalculator()
    
    def test_calculator_init(self, calculator):
        """Test calculator initialization."""
        assert calculator.logger is not None
    
    def test_validate_vector_valid(self, calculator):
        """Test vector validation with valid vector."""
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
        
        # Should not raise exception
        calculator._validate_vector(vector)
    
    def test_validate_vector_invalid_base_metrics(self, calculator):
        """Test vector validation with invalid base metrics."""
        # Invalid attack vector
        vector = CVSSVector(attack_vector="X")
        with pytest.raises(CVSSError, match="Invalid Attack Vector"):
            calculator._validate_vector(vector)
        
        # Invalid attack complexity
        vector = CVSSVector(attack_complexity="X")
        with pytest.raises(CVSSError, match="Invalid Attack Complexity"):
            calculator._validate_vector(vector)
        
        # Invalid privileges required
        vector = CVSSVector(privileges_required="X")
        with pytest.raises(CVSSError, match="Invalid Privileges Required"):
            calculator._validate_vector(vector)
        
        # Invalid user interaction
        vector = CVSSVector(user_interaction="X")
        with pytest.raises(CVSSError, match="Invalid User Interaction"):
            calculator._validate_vector(vector)
        
        # Invalid scope
        vector = CVSSVector(scope="X")
        with pytest.raises(CVSSError, match="Invalid Scope"):
            calculator._validate_vector(vector)
        
        # Invalid confidentiality
        vector = CVSSVector(confidentiality="X")
        with pytest.raises(CVSSError, match="Invalid Confidentiality Impact"):
            calculator._validate_vector(vector)
        
        # Invalid integrity
        vector = CVSSVector(integrity="X")
        with pytest.raises(CVSSError, match="Invalid Integrity Impact"):
            calculator._validate_vector(vector)
        
        # Invalid availability
        vector = CVSSVector(availability="X")
        with pytest.raises(CVSSError, match="Invalid Availability Impact"):
            calculator._validate_vector(vector)
    
    def test_validate_vector_invalid_temporal_metrics(self, calculator):
        """Test vector validation with invalid temporal metrics."""
        # Invalid exploit code maturity
        vector = CVSSVector(exploit_code_maturity="Z")
        with pytest.raises(CVSSError, match="Invalid Exploit Code Maturity"):
            calculator._validate_vector(vector)
        
        # Invalid remediation level
        vector = CVSSVector(remediation_level="Z")
        with pytest.raises(CVSSError, match="Invalid Remediation Level"):
            calculator._validate_vector(vector)
        
        # Invalid report confidence
        vector = CVSSVector(report_confidence="Z")
        with pytest.raises(CVSSError, match="Invalid Report Confidence"):
            calculator._validate_vector(vector)
    
    def test_validate_vector_invalid_environmental_metrics(self, calculator):
        """Test vector validation with invalid environmental metrics."""
        # Invalid confidentiality requirement
        vector = CVSSVector(confidentiality_requirement="Z")
        with pytest.raises(CVSSError, match="Invalid Confidentiality Requirement"):
            calculator._validate_vector(vector)
        
        # Invalid integrity requirement
        vector = CVSSVector(integrity_requirement="Z")
        with pytest.raises(CVSSError, match="Invalid Integrity Requirement"):
            calculator._validate_vector(vector)
        
        # Invalid availability requirement
        vector = CVSSVector(availability_requirement="Z")
        with pytest.raises(CVSSError, match="Invalid Availability Requirement"):
            calculator._validate_vector(vector)
    
    def test_calculate_base_score_critical(self, calculator):
        """Test base score calculation for critical vulnerability."""
        # CVE-2017-0144 (EternalBlue) - like vector
        vector = CVSSVector(
            attack_vector="N",      # Network
            attack_complexity="L",  # Low
            privileges_required="N", # None
            user_interaction="N",   # None
            scope="C",              # Changed
            confidentiality="H",    # High
            integrity="H",          # High
            availability="H"        # High
        )
        
        base_score, exploitability, impact = calculator._calculate_base_score(vector)
        
        # Should be close to 9.3 (actual EternalBlue score)
        assert 9.0 <= base_score <= 10.0
        assert exploitability > 0
        assert impact > 0
    
    def test_calculate_base_score_medium(self, calculator):
        """Test base score calculation for medium vulnerability."""
        vector = CVSSVector(
            attack_vector="A",      # Adjacent Network (higher than Local)
            attack_complexity="L",  # Low (easier to exploit)
            privileges_required="L", # Low
            user_interaction="N",   # None (no user interaction required)
            scope="U",              # Unchanged
            confidentiality="H",    # High (more impact)
            integrity="L",          # Low
            availability="N"        # None
        )
        
        base_score, exploitability, impact = calculator._calculate_base_score(vector)
        
        # Should be in medium range (4.0-6.9)
        assert 4.0 <= base_score < 7.0
    
    def test_calculate_base_score_no_impact(self, calculator):
        """Test base score calculation with no impact."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="N",    # No impact
            integrity="N",          # No impact
            availability="N"        # No impact
        )
        
        base_score, exploitability, impact = calculator._calculate_base_score(vector)
        
        assert base_score == 0.0
        assert impact == 0.0
    
    def test_calculate_temporal_score(self, calculator):
        """Test temporal score calculation."""
        vector = CVSSVector(
            exploit_code_maturity="F",  # Functional
            remediation_level="O",      # Official Fix
            report_confidence="C"       # Confirmed
        )
        
        base_score = 7.5
        temporal_score, temporal_multiplier = calculator._calculate_temporal_score(vector, base_score)
        
        # Temporal score should be lower than base score
        assert temporal_score <= base_score
        assert 0.0 < temporal_multiplier <= 1.0
        
        # Check specific calculation
        expected_multiplier = CVSS_METRICS['E']['F'] * CVSS_METRICS['RL']['O'] * CVSS_METRICS['RC']['C']
        assert abs(temporal_multiplier - expected_multiplier) < 0.001
    
    def test_calculate_environmental_score(self, calculator):
        """Test environmental score calculation."""
        vector = CVSSVector(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
            confidentiality_requirement="H",  # High
            integrity_requirement="H",       # High
            availability_requirement="H"     # High
        )
        
        env_score, mod_impact, mod_exploit = calculator._calculate_environmental_score(vector)
        
        assert env_score > 0
        assert mod_impact > 0
        assert mod_exploit > 0
        assert env_score <= 10.0
    
    def test_has_temporal_metrics(self, calculator):
        """Test temporal metrics detection."""
        # No temporal metrics
        vector = CVSSVector()
        assert calculator._has_temporal_metrics(vector) is False
        
        # With exploit code maturity
        vector.exploit_code_maturity = "F"
        assert calculator._has_temporal_metrics(vector) is True
        
        # With remediation level
        vector = CVSSVector(remediation_level="O")
        assert calculator._has_temporal_metrics(vector) is True
        
        # With report confidence
        vector = CVSSVector(report_confidence="C")
        assert calculator._has_temporal_metrics(vector) is True
    
    def test_has_environmental_metrics(self, calculator):
        """Test environmental metrics detection."""
        # No environmental metrics
        vector = CVSSVector()
        assert calculator._has_environmental_metrics(vector) is False
        
        # With confidentiality requirement
        vector.confidentiality_requirement = "H"
        assert calculator._has_environmental_metrics(vector) is True
        
        # With integrity requirement
        vector = CVSSVector(integrity_requirement="H")
        assert calculator._has_environmental_metrics(vector) is True
        
        # With availability requirement
        vector = CVSSVector(availability_requirement="H")
        assert calculator._has_environmental_metrics(vector) is True
    
    def test_parse_vector_string_base_only(self, calculator):
        """Test parsing CVSS vector string with base metrics only."""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        vector = calculator.parse_vector_string(vector_string)
        
        assert vector.attack_vector == "N"
        assert vector.attack_complexity == "L"
        assert vector.privileges_required == "N"
        assert vector.user_interaction == "N"
        assert vector.scope == "U"
        assert vector.confidentiality == "H"
        assert vector.integrity == "H"
        assert vector.availability == "H"
        
        # Temporal and environmental should be None
        assert vector.exploit_code_maturity is None
        assert vector.remediation_level is None
        assert vector.report_confidence is None
        assert vector.confidentiality_requirement is None
        assert vector.integrity_requirement is None
        assert vector.availability_requirement is None
    
    def test_parse_vector_string_with_temporal(self, calculator):
        """Test parsing CVSS vector string with temporal metrics."""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
        
        vector = calculator.parse_vector_string(vector_string)
        
        # Base metrics
        assert vector.attack_vector == "N"
        assert vector.confidentiality == "H"
        
        # Temporal metrics
        assert vector.exploit_code_maturity == "F"
        assert vector.remediation_level == "O"
        assert vector.report_confidence == "C"
    
    def test_parse_vector_string_with_environmental(self, calculator):
        """Test parsing CVSS vector string with environmental metrics."""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H"
        
        vector = calculator.parse_vector_string(vector_string)
        
        # Base metrics
        assert vector.attack_vector == "N"
        assert vector.confidentiality == "H"
        
        # Environmental metrics
        assert vector.confidentiality_requirement == "H"
        assert vector.integrity_requirement == "H"
        assert vector.availability_requirement == "H"
    
    def test_parse_vector_string_cvss30(self, calculator):
        """Test parsing CVSS 3.0 vector string."""
        vector_string = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        vector = calculator.parse_vector_string(vector_string)
        
        assert vector.attack_vector == "N"
        assert vector.confidentiality == "H"
    
    def test_parse_vector_string_no_prefix(self, calculator):
        """Test parsing CVSS vector string without version prefix."""
        vector_string = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        vector = calculator.parse_vector_string(vector_string)
        
        assert vector.attack_vector == "N"
        assert vector.confidentiality == "H"
    
    def test_parse_vector_string_invalid(self, calculator):
        """Test parsing invalid CVSS vector string."""
        with pytest.raises(CVSSError):
            calculator.parse_vector_string("invalid_vector")
    
    def test_calculate_scores_complete(self, calculator):
        """Test complete score calculation with all metrics."""
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
            report_confidence="C",
            confidentiality_requirement="H",
            integrity_requirement="H",
            availability_requirement="H"
        )
        
        scores = calculator.calculate_scores(vector)
        
        assert scores.base_score > 0
        assert scores.temporal_score is not None
        assert scores.environmental_score is not None
        assert scores.overall_score > 0
        assert scores.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    
    def test_calculate_from_string(self, calculator):
        """Test calculating scores from vector string."""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        scores = calculator.calculate_from_string(vector_string)
        
        assert scores.base_score > 0
        assert scores.overall_score == scores.base_score  # No temporal/environmental
        assert scores.risk_level != RiskLevel.NONE


class TestCVSSAssessment:
    """Test cases for CVSSAssessment class."""
    
    @pytest.fixture
    def assessment(self):
        """Create CVSS assessment for testing."""
        return CVSSAssessment()
    
    def test_assessment_init(self, assessment):
        """Test assessment initialization."""
        assert assessment.calculator is not None
        assert assessment.logger is not None
    
    def test_assess_vulnerability_with_vector(self, assessment):
        """Test assessing vulnerability with CVSS vector."""
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
        
        vulnerability = VulnerabilityInfo(
            id="CVE-2023-1234",
            title="Test Vulnerability",
            description="Test description",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.NONE,  # Will be updated
            cvss_vector=vector
        )
        
        updated_vuln = assessment.assess_vulnerability(vulnerability)
        
        assert updated_vuln.cvss_score is not None
        assert updated_vuln.cvss_score > 0
        assert updated_vuln.severity != RiskLevel.NONE
    
    def test_assess_vulnerability_without_vector(self, assessment):
        """Test assessing vulnerability without CVSS vector."""
        vulnerability = VulnerabilityInfo(
            id="CVE-2023-1234",
            title="Test Vulnerability",
            description="Test description",
            category=VulnerabilityCategory.AUTHENTICATION,
            severity=RiskLevel.MEDIUM
        )
        
        updated_vuln = assessment.assess_vulnerability(vulnerability)
        
        # Should remain unchanged
        assert updated_vuln.cvss_score is None
        assert updated_vuln.severity == RiskLevel.MEDIUM
    
    def test_create_vulnerability_from_cvss(self, assessment):
        """Test creating vulnerability from CVSS vector string."""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        vulnerability = assessment.create_vulnerability_from_cvss(
            vuln_id="CVE-2023-1234",
            title="Test Vulnerability",
            description="Test description",
            cvss_vector_string=vector_string,
            category=VulnerabilityCategory.NETWORK,
            cwe_id="CWE-79"
        )
        
        assert vulnerability.id == "CVE-2023-1234"
        assert vulnerability.title == "Test Vulnerability"
        assert vulnerability.category == VulnerabilityCategory.NETWORK
        assert vulnerability.cvss_vector is not None
        assert vulnerability.cvss_score is not None
        assert vulnerability.cvss_score > 0
        assert vulnerability.severity != RiskLevel.NONE
        assert vulnerability.cwe_id == "CWE-79"
    
    def test_create_vulnerability_from_cvss_invalid(self, assessment):
        """Test creating vulnerability from invalid CVSS vector."""
        with pytest.raises(CVSSError):
            assessment.create_vulnerability_from_cvss(
                vuln_id="CVE-2023-1234",
                title="Test Vulnerability",
                description="Test description",
                cvss_vector_string="invalid_vector"
            )
    
    def test_get_score_breakdown(self, assessment):
        """Test getting detailed score breakdown."""
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
            remediation_level="O"
        )
        
        breakdown = assessment.get_score_breakdown(vector)
        
        assert 'vector_string' in breakdown
        assert 'scores' in breakdown
        assert 'metrics' in breakdown
        
        # Check vector string
        assert breakdown['vector_string'].startswith("CVSS:3.1/")
        
        # Check scores
        scores = breakdown['scores']
        assert 'base_score' in scores
        assert 'overall_score' in scores
        assert 'risk_level' in scores
        
        # Check metrics
        metrics = breakdown['metrics']
        assert 'base_metrics' in metrics
        assert 'temporal_metrics' in metrics
        assert metrics['environmental_metrics'] is None  # No environmental metrics
        
        # Check base metrics
        base_metrics = metrics['base_metrics']
        assert base_metrics['attack_vector'] == "N"
        assert base_metrics['confidentiality'] == "H"
        
        # Check temporal metrics
        temporal_metrics = metrics['temporal_metrics']
        assert temporal_metrics['exploit_code_maturity'] == "F"
        assert temporal_metrics['remediation_level'] == "O"


class TestConvenienceFunctions:
    """Test cases for convenience functions."""
    
    def test_calculate_cvss_score(self):
        """Test calculate_cvss_score function."""
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        score = calculate_cvss_score(vector_string)
        
        assert isinstance(score, float)
        assert score > 0
        assert score <= 10.0
    
    def test_get_risk_level_from_score(self):
        """Test get_risk_level_from_score function."""
        test_cases = [
            (0.0, RiskLevel.NONE),
            (2.5, RiskLevel.LOW),
            (3.9, RiskLevel.LOW),
            (4.0, RiskLevel.MEDIUM),
            (6.9, RiskLevel.MEDIUM),
            (7.0, RiskLevel.HIGH),
            (8.9, RiskLevel.HIGH),
            (9.0, RiskLevel.CRITICAL),
            (10.0, RiskLevel.CRITICAL)
        ]
        
        for score, expected_level in test_cases:
            level = get_risk_level_from_score(score)
            assert level == expected_level, f"Score {score} should be {expected_level}"


class TestCVSSMetrics:
    """Test cases for CVSS metrics constants."""
    
    def test_cvss_metrics_structure(self):
        """Test CVSS metrics dictionary structure."""
        # Check that all required metrics are present
        required_metrics = ['AV', 'AC', 'PR', 'PR_CHANGED', 'UI', 'S', 'C', 'I', 'A']
        for metric in required_metrics:
            assert metric in CVSS_METRICS
        
        # Check temporal metrics
        temporal_metrics = ['E', 'RL', 'RC']
        for metric in temporal_metrics:
            assert metric in CVSS_METRICS
        
        # Check environmental metrics
        environmental_metrics = ['CR', 'IR', 'AR']
        for metric in environmental_metrics:
            assert metric in CVSS_METRICS
    
    def test_cvss_metrics_values(self):
        """Test CVSS metrics values are within expected ranges."""
        # Most metrics should have values between 0 and 1
        for metric_name, metric_values in CVSS_METRICS.items():
            if metric_name == 'S':  # Scope is special (string values)
                continue
            
            for value in metric_values.values():
                if isinstance(value, (int, float)):
                    assert 0.0 <= value <= 1.5, f"Metric {metric_name} has invalid value {value}"
    
    def test_attack_vector_values(self):
        """Test Attack Vector metric values."""
        av = CVSS_METRICS['AV']
        assert av['N'] == 0.85  # Network
        assert av['A'] == 0.62  # Adjacent
        assert av['L'] == 0.55  # Local
        assert av['P'] == 0.2   # Physical
    
    def test_privileges_required_scope_dependency(self):
        """Test Privileges Required values depend on Scope."""
        pr = CVSS_METRICS['PR']
        pr_changed = CVSS_METRICS['PR_CHANGED']
        
        # When scope is changed, Low and High PR values should be higher
        assert pr_changed['L'] > pr['L']
        assert pr_changed['H'] > pr['H']
        assert pr_changed['N'] == pr['N']  # None should be the same


class TestRealWorldCVSSVectors:
    """Test cases using real-world CVSS vectors."""
    
    @pytest.fixture
    def calculator(self):
        """Create CVSS calculator for testing."""
        return CVSSCalculator()
    
    def test_eternalblue_cve_2017_0144(self, calculator):
        """Test EternalBlue (CVE-2017-0144) CVSS vector."""
        # Actual CVSS vector for EternalBlue
        vector_string = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        
        scores = calculator.calculate_from_string(vector_string)
        
        # Should be critical (actual score is 9.3)
        assert scores.base_score >= 9.0
        assert scores.risk_level == RiskLevel.CRITICAL
    
    def test_heartbleed_cve_2014_0160(self, calculator):
        """Test Heartbleed (CVE-2014-0160) CVSS vector."""
        # CVSS v3.1 vector for Heartbleed
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        
        scores = calculator.calculate_from_string(vector_string)
        
        # Should be high severity (actual score is 7.5)
        assert 7.0 <= scores.base_score < 9.0
        assert scores.risk_level == RiskLevel.HIGH
    
    def test_shellshock_cve_2014_6271(self, calculator):
        """Test Shellshock (CVE-2014-6271) CVSS vector."""
        # CVSS v3.1 vector for Shellshock
        vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        
        scores = calculator.calculate_from_string(vector_string)
        
        # Should be critical (actual score is 9.8)
        assert scores.base_score >= 9.0
        assert scores.risk_level == RiskLevel.CRITICAL
    
    def test_low_severity_vulnerability(self, calculator):
        """Test low severity vulnerability CVSS vector."""
        # Example low severity vector
        vector_string = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        
        scores = calculator.calculate_from_string(vector_string)
        
        # Should be low severity
        assert scores.base_score < 4.0
        assert scores.risk_level == RiskLevel.LOW


if __name__ == '__main__':
    pytest.main([__file__]) 