"""
Unit tests for RiskScorer and CompositeRiskScore

Tests the risk scoring functionality including different scoring methodologies,
composite score calculation, and risk assessment.
"""

import unittest
from unittest.mock import Mock, patch
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection.models import (
    MCPTool, SecurityRisk, RiskLevel, RiskCategory
)
from src.hawkeye.detection.mcp_introspection.risk.scoring import (
    RiskScorer, CompositeRiskScore, ScoringMethodology
)


class TestCompositeRiskScore(unittest.TestCase):
    """Test cases for CompositeRiskScore."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.score = CompositeRiskScore(
            overall_score=7.5,
            severity_score=8.0,
            likelihood_score=7.0,
            impact_score=8.5,
            exposure_score=6.5,
            exploitability_score=7.5
        )
    
    def test_score_initialization(self):
        """Test score initialization."""
        self.assertEqual(self.score.overall_score, 7.5)
        self.assertEqual(self.score.severity_score, 8.0)
        self.assertEqual(self.score.likelihood_score, 7.0)
        self.assertEqual(self.score.impact_score, 8.5)
        self.assertEqual(self.score.exposure_score, 6.5)
        self.assertEqual(self.score.exploitability_score, 7.5)
    
    def test_score_validation(self):
        """Test score validation."""
        # Valid scores should not raise exceptions
        valid_score = CompositeRiskScore(5.0, 5.0, 5.0, 5.0, 5.0, 5.0)
        self.assertIsInstance(valid_score, CompositeRiskScore)
        
        # Test boundary values
        boundary_score = CompositeRiskScore(0.0, 10.0, 0.0, 10.0, 0.0, 10.0)
        self.assertIsInstance(boundary_score, CompositeRiskScore)
    
    def test_get_risk_level(self):
        """Test risk level determination."""
        # Test different score ranges
        critical_score = CompositeRiskScore(9.5, 9.0, 9.0, 9.0, 9.0, 9.0)
        self.assertEqual(critical_score.get_risk_level(), RiskLevel.CRITICAL)
        
        high_score = CompositeRiskScore(7.5, 7.0, 7.0, 7.0, 7.0, 7.0)
        self.assertEqual(high_score.get_risk_level(), RiskLevel.HIGH)
        
        medium_score = CompositeRiskScore(5.0, 5.0, 5.0, 5.0, 5.0, 5.0)
        self.assertEqual(medium_score.get_risk_level(), RiskLevel.MEDIUM)
        
        low_score = CompositeRiskScore(3.0, 3.0, 3.0, 3.0, 3.0, 3.0)
        self.assertEqual(low_score.get_risk_level(), RiskLevel.LOW)
        
        info_score = CompositeRiskScore(1.0, 1.0, 1.0, 1.0, 1.0, 1.0)
        self.assertEqual(info_score.get_risk_level(), RiskLevel.INFO)
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        score_dict = self.score.to_dict()
        
        self.assertIsInstance(score_dict, dict)
        self.assertEqual(score_dict['overall_score'], 7.5)
        self.assertEqual(score_dict['severity_score'], 8.0)
        self.assertEqual(score_dict['likelihood_score'], 7.0)
        self.assertEqual(score_dict['impact_score'], 8.5)
        self.assertEqual(score_dict['exposure_score'], 6.5)
        self.assertEqual(score_dict['exploitability_score'], 7.5)
        self.assertIn('risk_level', score_dict)
    
    def test_score_breakdown(self):
        """Test score breakdown functionality."""
        breakdown = self.score.get_score_breakdown()
        
        self.assertIsInstance(breakdown, dict)
        self.assertIn('component_scores', breakdown)
        self.assertIn('weights', breakdown)
        self.assertIn('methodology', breakdown)
        
        component_scores = breakdown['component_scores']
        self.assertEqual(len(component_scores), 5)  # 5 component scores


class TestRiskScorer(unittest.TestCase):
    """Test cases for RiskScorer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scorer = RiskScorer()
        
        # Sample risks for testing
        self.sample_risks = [
            SecurityRisk("file_access", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "File access risk"),
            SecurityRisk("network_call", RiskLevel.HIGH, RiskCategory.NETWORK, "Network communication risk"),
            SecurityRisk("code_exec", RiskLevel.CRITICAL, RiskCategory.CODE_EXECUTION, "Code execution risk"),
            SecurityRisk("data_read", RiskLevel.LOW, RiskCategory.DATA_ACCESS, "Data access risk")
        ]
        
        # Sample tool
        self.sample_tool = MCPTool(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {"param": {"type": "string"}}}
        )
    
    def test_scorer_initialization(self):
        """Test scorer initialization."""
        self.assertIsInstance(self.scorer, RiskScorer)
        self.assertIn(self.scorer.methodology, [m for m in ScoringMethodology])
        self.assertTrue(len(self.scorer.component_weights) > 0)
    
    def test_calculate_risk_score_single(self):
        """Test calculation of single risk score."""
        risk = self.sample_risks[0]
        score = self.scorer.calculate_risk_score(risk)
        
        self.assertIsInstance(score, CompositeRiskScore)
        self.assertGreaterEqual(score.overall_score, 0.0)
        self.assertLessEqual(score.overall_score, 10.0)
    
    def test_calculate_risk_score_multiple(self):
        """Test calculation of multiple risk scores."""
        scores = self.scorer.calculate_risk_scores(self.sample_risks)
        
        self.assertEqual(len(scores), len(self.sample_risks))
        for score in scores:
            self.assertIsInstance(score, CompositeRiskScore)
    
    def test_calculate_tool_risk_score(self):
        """Test calculation of tool risk score."""
        score = self.scorer.calculate_tool_risk_score(self.sample_tool, self.sample_risks)
        
        self.assertIsInstance(score, CompositeRiskScore)
        # Tool score should aggregate individual risk scores
        self.assertGreater(score.overall_score, 0.0)
    
    def test_severity_score_calculation(self):
        """Test severity score calculation."""
        for risk in self.sample_risks:
            severity_score = self.scorer._calculate_severity_score(risk)
            
            self.assertGreaterEqual(severity_score, 0.0)
            self.assertLessEqual(severity_score, 10.0)
            
            # Higher risk levels should have higher scores
            if risk.level == RiskLevel.CRITICAL:
                self.assertGreaterEqual(severity_score, 8.0)
            elif risk.level == RiskLevel.HIGH:
                self.assertGreaterEqual(severity_score, 6.0)
    
    def test_likelihood_score_calculation(self):
        """Test likelihood score calculation."""
        for risk in self.sample_risks:
            likelihood_score = self.scorer._calculate_likelihood_score(risk)
            
            self.assertGreaterEqual(likelihood_score, 0.0)
            self.assertLessEqual(likelihood_score, 10.0)
    
    def test_impact_score_calculation(self):
        """Test impact score calculation."""
        for risk in self.sample_risks:
            impact_score = self.scorer._calculate_impact_score(risk)
            
            self.assertGreaterEqual(impact_score, 0.0)
            self.assertLessEqual(impact_score, 10.0)
    
    def test_exposure_score_calculation(self):
        """Test exposure score calculation."""
        for risk in self.sample_risks:
            exposure_score = self.scorer._calculate_exposure_score(risk)
            
            self.assertGreaterEqual(exposure_score, 0.0)
            self.assertLessEqual(exposure_score, 10.0)
    
    def test_exploitability_score_calculation(self):
        """Test exploitability score calculation."""
        for risk in self.sample_risks:
            exploitability_score = self.scorer._calculate_exploitability_score(risk)
            
            self.assertGreaterEqual(exploitability_score, 0.0)
            self.assertLessEqual(exploitability_score, 10.0)
    
    def test_cvss_methodology(self):
        """Test CVSS-like scoring methodology."""
        cvss_scorer = RiskScorer(methodology=ScoringMethodology.CVSS_LIKE)
        
        risk = SecurityRisk("test", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "Test risk")
        score = cvss_scorer.calculate_risk_score(risk)
        
        self.assertIsInstance(score, CompositeRiskScore)
        # CVSS-like should consider multiple factors
        self.assertGreater(score.overall_score, 0.0)
    
    def test_weighted_average_methodology(self):
        """Test weighted average scoring methodology."""
        weighted_scorer = RiskScorer(methodology=ScoringMethodology.WEIGHTED_AVERAGE)
        
        risk = SecurityRisk("test", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "Test risk")
        score = weighted_scorer.calculate_risk_score(risk)
        
        self.assertIsInstance(score, CompositeRiskScore)
        self.assertGreater(score.overall_score, 0.0)
    
    def test_maximum_methodology(self):
        """Test maximum scoring methodology."""
        max_scorer = RiskScorer(methodology=ScoringMethodology.MAXIMUM)
        
        risk = SecurityRisk("test", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "Test risk")
        score = max_scorer.calculate_risk_score(risk)
        
        self.assertIsInstance(score, CompositeRiskScore)
        # Maximum methodology should use highest component score
        component_scores = [
            score.severity_score, score.likelihood_score, score.impact_score,
            score.exposure_score, score.exploitability_score
        ]
        self.assertEqual(score.overall_score, max(component_scores))
    
    def test_category_weight_application(self):
        """Test category weight application."""
        # Code execution should typically have higher weight
        code_risk = SecurityRisk("code", RiskLevel.MEDIUM, RiskCategory.CODE_EXECUTION, "Code risk")
        file_risk = SecurityRisk("file", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "File risk")
        
        code_score = self.scorer.calculate_risk_score(code_risk)
        file_score = self.scorer.calculate_risk_score(file_risk)
        
        # Assuming code execution has higher weight
        if self.scorer.category_weights[RiskCategory.CODE_EXECUTION] > \
           self.scorer.category_weights[RiskCategory.FILE_SYSTEM]:
            self.assertGreater(code_score.overall_score, file_score.overall_score)
    
    def test_aggregate_scores(self):
        """Test score aggregation."""
        scores = self.scorer.calculate_risk_scores(self.sample_risks)
        aggregated = self.scorer.aggregate_scores(scores)
        
        self.assertIsInstance(aggregated, CompositeRiskScore)
        # Aggregated score should be influenced by all individual scores
        self.assertGreater(aggregated.overall_score, 0.0)
    
    def test_normalize_score(self):
        """Test score normalization."""
        # Test various score values
        test_values = [-1.0, 0.0, 5.0, 10.0, 15.0]
        
        for value in test_values:
            normalized = self.scorer._normalize_score(value)
            self.assertGreaterEqual(normalized, 0.0)
            self.assertLessEqual(normalized, 10.0)
    
    def test_get_score_recommendations(self):
        """Test score-based recommendations."""
        high_risk = SecurityRisk("high", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "High risk")
        score = self.scorer.calculate_risk_score(high_risk)
        
        recommendations = self.scorer.get_score_recommendations(score)
        
        self.assertIsInstance(recommendations, list)
        self.assertTrue(len(recommendations) > 0)
        
        for rec in recommendations:
            self.assertIsInstance(rec, str)
            self.assertTrue(len(rec) > 0)
    
    def test_compare_scores(self):
        """Test score comparison."""
        risk1 = SecurityRisk("risk1", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "Risk 1")
        risk2 = SecurityRisk("risk2", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "Risk 2")
        
        score1 = self.scorer.calculate_risk_score(risk1)
        score2 = self.scorer.calculate_risk_score(risk2)
        
        comparison = self.scorer.compare_scores(score1, score2)
        
        self.assertIsInstance(comparison, dict)
        self.assertIn('score_difference', comparison)
        self.assertIn('component_differences', comparison)
        self.assertIn('risk_level_change', comparison)
    
    def test_score_trend_analysis(self):
        """Test score trend analysis."""
        # Create scores representing different time periods
        scores = []
        for i in range(3):
            risk = SecurityRisk(f"risk_{i}", 
                              RiskLevel.LOW if i == 0 else RiskLevel.MEDIUM if i == 1 else RiskLevel.HIGH,
                              RiskCategory.FILE_SYSTEM, f"Risk {i}")
            scores.append(self.scorer.calculate_risk_score(risk))
        
        trend = self.scorer.analyze_score_trend(scores)
        
        self.assertIsInstance(trend, dict)
        self.assertIn('trend_direction', trend)
        self.assertIn('trend_magnitude', trend)
        self.assertIn('score_changes', trend)
        
        # Should detect increasing trend
        self.assertEqual(trend['trend_direction'], 'increasing')
    
    def test_custom_weights(self):
        """Test custom component weights."""
        custom_weights = {
            'severity': 0.4,
            'likelihood': 0.2,
            'impact': 0.3,
            'exposure': 0.05,
            'exploitability': 0.05
        }
        
        custom_scorer = RiskScorer(component_weights=custom_weights)
        
        # Verify weights are applied
        for component, weight in custom_weights.items():
            self.assertEqual(custom_scorer.component_weights[component], weight)
    
    def test_custom_category_weights(self):
        """Test custom category weights."""
        custom_category_weights = {
            RiskCategory.CODE_EXECUTION: 2.0,
            RiskCategory.FILE_SYSTEM: 1.0,
            RiskCategory.NETWORK: 1.5
        }
        
        custom_scorer = RiskScorer(category_weights=custom_category_weights)
        
        # Verify category weights are applied
        for category, weight in custom_category_weights.items():
            self.assertEqual(custom_scorer.category_weights[category], weight)
    
    def test_score_caching(self):
        """Test score caching functionality."""
        risk = self.sample_risks[0]
        
        # Calculate score twice
        score1 = self.scorer.calculate_risk_score(risk)
        score2 = self.scorer.calculate_risk_score(risk)
        
        # Should return same result (testing consistency)
        self.assertEqual(score1.overall_score, score2.overall_score)
    
    def test_batch_scoring_performance(self):
        """Test performance with batch scoring."""
        import time
        
        # Create many risks
        many_risks = []
        for i in range(100):
            risk = SecurityRisk(f"risk_{i}", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, f"Risk {i}")
            many_risks.append(risk)
        
        start_time = time.time()
        scores = self.scorer.calculate_risk_scores(many_risks)
        end_time = time.time()
        
        # Should complete in reasonable time
        self.assertLess(end_time - start_time, 5.0)
        self.assertEqual(len(scores), 100)
    
    def test_edge_case_zero_risks(self):
        """Test edge case with zero risks."""
        scores = self.scorer.calculate_risk_scores([])
        self.assertEqual(len(scores), 0)
        
        # Aggregating empty scores should return zero score
        aggregated = self.scorer.aggregate_scores([])
        self.assertEqual(aggregated.overall_score, 0.0)
    
    def test_edge_case_identical_risks(self):
        """Test edge case with identical risks."""
        identical_risks = [
            SecurityRisk("same", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "Same risk")
            for _ in range(5)
        ]
        
        scores = self.scorer.calculate_risk_scores(identical_risks)
        
        # All scores should be identical
        first_score = scores[0]
        for score in scores[1:]:
            self.assertEqual(score.overall_score, first_score.overall_score)
    
    def test_score_distribution_analysis(self):
        """Test score distribution analysis."""
        scores = self.scorer.calculate_risk_scores(self.sample_risks)
        distribution = self.scorer.analyze_score_distribution(scores)
        
        self.assertIsInstance(distribution, dict)
        self.assertIn('mean_score', distribution)
        self.assertIn('median_score', distribution)
        self.assertIn('std_deviation', distribution)
        self.assertIn('score_ranges', distribution)
        
        # Statistical measures should be reasonable
        self.assertGreaterEqual(distribution['mean_score'], 0.0)
        self.assertLessEqual(distribution['mean_score'], 10.0)
    
    def test_risk_level_mapping(self):
        """Test risk level to score mapping."""
        level_mappings = {
            RiskLevel.INFO: (0.0, 2.0),
            RiskLevel.LOW: (2.0, 4.0),
            RiskLevel.MEDIUM: (4.0, 6.0),
            RiskLevel.HIGH: (6.0, 8.0),
            RiskLevel.CRITICAL: (8.0, 10.0)
        }
        
        for level, (min_score, max_score) in level_mappings.items():
            risk = SecurityRisk("test", level, RiskCategory.OTHER, "Test")
            score = self.scorer.calculate_risk_score(risk)
            
            # Score should fall within expected range for the risk level
            self.assertGreaterEqual(score.overall_score, min_score)
            self.assertLessEqual(score.overall_score, max_score)


if __name__ == '__main__':
    unittest.main() 