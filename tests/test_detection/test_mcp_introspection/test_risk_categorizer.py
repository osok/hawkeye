"""
Unit tests for RiskCategorizer

Tests the risk categorization functionality including risk profiling,
distribution analysis, and priority ranking.
"""

import unittest
from unittest.mock import Mock, patch
from typing import Dict, Any, List

from src.hawkeye.detection.mcp_introspection.models import (
    MCPTool, SecurityRisk, RiskLevel, RiskCategory
)
from src.hawkeye.detection.mcp_introspection.risk.categorizer import (
    RiskCategorizer, RiskProfile, CategoryAnalysis
)


class TestRiskCategorizer(unittest.TestCase):
    """Test cases for RiskCategorizer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.categorizer = RiskCategorizer()
        
        # Sample risks for testing
        self.sample_risks = [
            SecurityRisk("file_access", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "File access risk"),
            SecurityRisk("network_call", RiskLevel.HIGH, RiskCategory.NETWORK, "Network communication risk"),
            SecurityRisk("code_exec", RiskLevel.CRITICAL, RiskCategory.CODE_EXECUTION, "Code execution risk"),
            SecurityRisk("data_read", RiskLevel.LOW, RiskCategory.DATA_ACCESS, "Data access risk"),
            SecurityRisk("privilege_esc", RiskLevel.HIGH, RiskCategory.PRIVILEGE_ESCALATION, "Privilege escalation risk"),
            SecurityRisk("system_mod", RiskLevel.MEDIUM, RiskCategory.SYSTEM_MODIFICATION, "System modification risk")
        ]
        
        # Sample tool
        self.sample_tool = MCPTool(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {"param": {"type": "string"}}}
        )
    
    def test_categorizer_initialization(self):
        """Test categorizer initialization."""
        self.assertIsInstance(self.categorizer, RiskCategorizer)
        self.assertTrue(len(self.categorizer.category_weights) > 0)
        self.assertTrue(len(self.categorizer.severity_multipliers) > 0)
    
    def test_categorize_risks_basic(self):
        """Test basic risk categorization."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        self.assertIsInstance(profile, RiskProfile)
        self.assertEqual(len(profile.categories), len(set(r.category for r in self.sample_risks)))
        self.assertEqual(profile.total_risks, len(self.sample_risks))
    
    def test_risk_profile_creation(self):
        """Test risk profile creation."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        # Check profile structure
        self.assertIsInstance(profile.categories, dict)
        self.assertIsInstance(profile.severity_distribution, dict)
        self.assertIsInstance(profile.risk_score, float)
        self.assertIsInstance(profile.priority_ranking, list)
        
        # Check that all risk categories are represented
        expected_categories = {r.category for r in self.sample_risks}
        actual_categories = set(profile.categories.keys())
        self.assertEqual(expected_categories, actual_categories)
    
    def test_severity_distribution(self):
        """Test severity distribution calculation."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        # Count expected severities
        expected_counts = {}
        for risk in self.sample_risks:
            expected_counts[risk.level] = expected_counts.get(risk.level, 0) + 1
        
        # Check distribution matches
        for level, count in expected_counts.items():
            self.assertEqual(profile.severity_distribution[level], count)
    
    def test_category_analysis(self):
        """Test category analysis functionality."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        for category, analysis in profile.categories.items():
            self.assertIsInstance(analysis, CategoryAnalysis)
            self.assertGreaterEqual(analysis.risk_count, 1)
            self.assertGreaterEqual(analysis.total_score, 0.0)
            self.assertGreaterEqual(analysis.average_score, 0.0)
            self.assertIn(analysis.highest_severity, [level for level in RiskLevel])
    
    def test_priority_ranking(self):
        """Test priority ranking of categories."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        # Should be sorted by priority (highest first)
        for i in range(len(profile.priority_ranking) - 1):
            current_cat = profile.priority_ranking[i]
            next_cat = profile.priority_ranking[i + 1]
            
            current_analysis = profile.categories[current_cat]
            next_analysis = profile.categories[next_cat]
            
            # Higher priority should have higher or equal total score
            self.assertGreaterEqual(current_analysis.total_score, next_analysis.total_score)
    
    def test_risk_score_calculation(self):
        """Test overall risk score calculation."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        # Risk score should be positive
        self.assertGreater(profile.risk_score, 0.0)
        
        # Should be reasonable (not exceed maximum possible)
        max_possible = len(self.sample_risks) * 10.0  # Assuming max risk level is 10
        self.assertLessEqual(profile.risk_score, max_possible)
    
    def test_empty_risk_list(self):
        """Test handling of empty risk list."""
        profile = self.categorizer.categorize_risks([])
        
        self.assertEqual(profile.total_risks, 0)
        self.assertEqual(profile.risk_score, 0.0)
        self.assertEqual(len(profile.categories), 0)
        self.assertEqual(len(profile.priority_ranking), 0)
    
    def test_single_risk_categorization(self):
        """Test categorization of single risk."""
        single_risk = [self.sample_risks[0]]
        profile = self.categorizer.categorize_risks(single_risk)
        
        self.assertEqual(profile.total_risks, 1)
        self.assertEqual(len(profile.categories), 1)
        self.assertIn(single_risk[0].category, profile.categories)
    
    def test_same_category_multiple_risks(self):
        """Test handling multiple risks in same category."""
        file_risks = [
            SecurityRisk("file1", RiskLevel.LOW, RiskCategory.FILE_SYSTEM, "File risk 1"),
            SecurityRisk("file2", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "File risk 2"),
            SecurityRisk("file3", RiskLevel.HIGH, RiskCategory.FILE_SYSTEM, "File risk 3")
        ]
        
        profile = self.categorizer.categorize_risks(file_risks)
        
        self.assertEqual(len(profile.categories), 1)
        file_analysis = profile.categories[RiskCategory.FILE_SYSTEM]
        self.assertEqual(file_analysis.risk_count, 3)
        self.assertEqual(file_analysis.highest_severity, RiskLevel.HIGH)
    
    def test_category_weights(self):
        """Test category weight application."""
        # Create risks with same severity but different categories
        risks = [
            SecurityRisk("code", RiskLevel.HIGH, RiskCategory.CODE_EXECUTION, "Code execution"),
            SecurityRisk("file", RiskLevel.HIGH, RiskCategory.FILE_SYSTEM, "File access")
        ]
        
        profile = self.categorizer.categorize_risks(risks)
        
        # Code execution should typically have higher weight than file system
        code_analysis = profile.categories[RiskCategory.CODE_EXECUTION]
        file_analysis = profile.categories[RiskCategory.FILE_SYSTEM]
        
        # Assuming code execution has higher weight
        if self.categorizer.category_weights[RiskCategory.CODE_EXECUTION] > \
           self.categorizer.category_weights[RiskCategory.FILE_SYSTEM]:
            self.assertGreater(code_analysis.total_score, file_analysis.total_score)
    
    def test_severity_multipliers(self):
        """Test severity multiplier application."""
        # Create risks with different severities in same category
        risks = [
            SecurityRisk("low", RiskLevel.LOW, RiskCategory.FILE_SYSTEM, "Low risk"),
            SecurityRisk("high", RiskLevel.HIGH, RiskCategory.FILE_SYSTEM, "High risk")
        ]
        
        profile = self.categorizer.categorize_risks(risks)
        analysis = profile.categories[RiskCategory.FILE_SYSTEM]
        
        # High severity should contribute more to total score
        self.assertGreater(analysis.total_score, 
                          self.categorizer.severity_multipliers[RiskLevel.LOW] * 
                          self.categorizer.category_weights[RiskCategory.FILE_SYSTEM])
    
    def test_get_high_risk_categories(self):
        """Test identification of high-risk categories."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        high_risk_cats = self.categorizer.get_high_risk_categories(profile)
        
        self.assertIsInstance(high_risk_cats, list)
        
        # Should include categories with critical or high severity risks
        expected_high_risk = set()
        for risk in self.sample_risks:
            if risk.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                expected_high_risk.add(risk.category)
        
        for cat in expected_high_risk:
            self.assertIn(cat, high_risk_cats)
    
    def test_get_category_recommendations(self):
        """Test category-specific recommendations."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        for category in profile.categories:
            recommendations = self.categorizer.get_category_recommendations(category, profile)
            self.assertIsInstance(recommendations, list)
            self.assertTrue(len(recommendations) > 0)
            
            for rec in recommendations:
                self.assertIsInstance(rec, str)
                self.assertTrue(len(rec) > 0)
    
    def test_compare_profiles(self):
        """Test profile comparison functionality."""
        # Create two different risk sets
        risks1 = self.sample_risks[:3]
        risks2 = self.sample_risks[3:]
        
        profile1 = self.categorizer.categorize_risks(risks1)
        profile2 = self.categorizer.categorize_risks(risks2)
        
        comparison = self.categorizer.compare_profiles(profile1, profile2)
        
        self.assertIsInstance(comparison, dict)
        self.assertIn('risk_score_diff', comparison)
        self.assertIn('category_changes', comparison)
        self.assertIn('severity_changes', comparison)
    
    def test_analyze_risk_trends(self):
        """Test risk trend analysis."""
        # Create profiles representing different time periods
        profiles = []
        for i in range(3):
            # Gradually increase risk severity
            risks = [
                SecurityRisk(f"risk_{i}", 
                           RiskLevel.LOW if i == 0 else RiskLevel.MEDIUM if i == 1 else RiskLevel.HIGH,
                           RiskCategory.FILE_SYSTEM, f"Risk {i}")
            ]
            profiles.append(self.categorizer.categorize_risks(risks))
        
        trends = self.categorizer.analyze_risk_trends(profiles)
        
        self.assertIsInstance(trends, dict)
        self.assertIn('risk_score_trend', trends)
        self.assertIn('category_trends', trends)
        
        # Should detect increasing trend
        self.assertGreater(trends['risk_score_trend'], 0)
    
    def test_generate_risk_summary(self):
        """Test risk summary generation."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        summary = self.categorizer.generate_risk_summary(profile)
        
        self.assertIsInstance(summary, dict)
        self.assertIn('total_risks', summary)
        self.assertIn('risk_score', summary)
        self.assertIn('top_categories', summary)
        self.assertIn('severity_breakdown', summary)
        self.assertIn('recommendations', summary)
        
        self.assertEqual(summary['total_risks'], len(self.sample_risks))
        self.assertIsInstance(summary['recommendations'], list)
    
    def test_filter_by_category(self):
        """Test filtering risks by category."""
        file_risks = self.categorizer.filter_by_category(self.sample_risks, RiskCategory.FILE_SYSTEM)
        
        self.assertEqual(len(file_risks), 1)
        self.assertEqual(file_risks[0].category, RiskCategory.FILE_SYSTEM)
    
    def test_filter_by_severity(self):
        """Test filtering risks by severity."""
        high_risks = self.categorizer.filter_by_severity(self.sample_risks, RiskLevel.HIGH)
        
        expected_count = len([r for r in self.sample_risks if r.level == RiskLevel.HIGH])
        self.assertEqual(len(high_risks), expected_count)
        
        for risk in high_risks:
            self.assertEqual(risk.level, RiskLevel.HIGH)
    
    def test_calculate_category_impact(self):
        """Test category impact calculation."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        
        for category, analysis in profile.categories.items():
            impact = self.categorizer.calculate_category_impact(category, analysis)
            self.assertIsInstance(impact, float)
            self.assertGreaterEqual(impact, 0.0)
            self.assertLessEqual(impact, 1.0)
    
    def test_risk_distribution_analysis(self):
        """Test risk distribution analysis."""
        profile = self.categorizer.categorize_risks(self.sample_risks)
        distribution = self.categorizer.analyze_risk_distribution(profile)
        
        self.assertIsInstance(distribution, dict)
        self.assertIn('category_percentages', distribution)
        self.assertIn('severity_percentages', distribution)
        self.assertIn('concentration_index', distribution)
        
        # Percentages should sum to 100
        cat_percentages = distribution['category_percentages']
        total_cat_percentage = sum(cat_percentages.values())
        self.assertAlmostEqual(total_cat_percentage, 100.0, places=1)
    
    def test_identify_risk_patterns(self):
        """Test risk pattern identification."""
        patterns = self.categorizer.identify_risk_patterns(self.sample_risks)
        
        self.assertIsInstance(patterns, dict)
        self.assertIn('common_categories', patterns)
        self.assertIn('severity_patterns', patterns)
        self.assertIn('risk_clusters', patterns)
    
    def test_custom_category_weights(self):
        """Test custom category weight configuration."""
        custom_weights = {
            RiskCategory.CODE_EXECUTION: 2.0,
            RiskCategory.FILE_SYSTEM: 1.0,
            RiskCategory.NETWORK: 1.5
        }
        
        custom_categorizer = RiskCategorizer(category_weights=custom_weights)
        
        # Test that custom weights are applied
        for category, weight in custom_weights.items():
            self.assertEqual(custom_categorizer.category_weights[category], weight)
    
    def test_custom_severity_multipliers(self):
        """Test custom severity multiplier configuration."""
        custom_multipliers = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 4.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.INFO: 1.0
        }
        
        custom_categorizer = RiskCategorizer(severity_multipliers=custom_multipliers)
        
        # Test that custom multipliers are applied
        for level, multiplier in custom_multipliers.items():
            self.assertEqual(custom_categorizer.severity_multipliers[level], multiplier)
    
    def test_performance_with_many_risks(self):
        """Test performance with large number of risks."""
        import time
        
        # Create many risks
        many_risks = []
        for i in range(1000):
            risk = SecurityRisk(
                f"risk_{i}",
                RiskLevel.MEDIUM,
                RiskCategory.FILE_SYSTEM,
                f"Risk {i}"
            )
            many_risks.append(risk)
        
        start_time = time.time()
        profile = self.categorizer.categorize_risks(many_risks)
        end_time = time.time()
        
        # Should complete in reasonable time
        self.assertLess(end_time - start_time, 2.0)
        self.assertEqual(profile.total_risks, 1000)
    
    def test_edge_case_all_same_risk(self):
        """Test edge case with all identical risks."""
        identical_risks = [
            SecurityRisk("same", RiskLevel.MEDIUM, RiskCategory.FILE_SYSTEM, "Same risk")
            for _ in range(5)
        ]
        
        profile = self.categorizer.categorize_risks(identical_risks)
        
        self.assertEqual(profile.total_risks, 5)
        self.assertEqual(len(profile.categories), 1)
        
        analysis = profile.categories[RiskCategory.FILE_SYSTEM]
        self.assertEqual(analysis.risk_count, 5)
        self.assertEqual(analysis.highest_severity, RiskLevel.MEDIUM)


if __name__ == '__main__':
    unittest.main() 