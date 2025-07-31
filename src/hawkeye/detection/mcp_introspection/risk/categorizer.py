"""
Risk Categorization System for MCP Introspection

Provides comprehensive risk categorization and classification for MCP security risks,
organizing threats by type, severity, and impact for better analysis and reporting.
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter

from ..models import (
    MCPServerInfo, MCPTool, MCPResource, SecurityRisk,
    RiskLevel, RiskCategory
)
from .threat_model import ThreatVector, ThreatCategory, AttackVector


class RiskClassification(str, Enum):
    """Risk classification levels."""
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    HIGH_IMPACT = "high_impact"
    MEDIUM_IMPACT = "medium_impact"
    LOW_IMPACT = "low_impact"
    INFORMATIONAL = "informational"


class RiskDomain(str, Enum):
    """Risk domains for categorization."""
    SECURITY = "security"
    PRIVACY = "privacy"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    BUSINESS = "business"
    TECHNICAL = "technical"


@dataclass
class RiskProfile:
    """Risk profile for categorized risks."""
    category: RiskCategory
    classification: RiskClassification
    domain: RiskDomain
    severity: RiskLevel
    count: int = 0
    risks: List[SecurityRisk] = field(default_factory=list)
    threat_vectors: List[ThreatVector] = field(default_factory=list)
    
    def add_risk(self, risk: SecurityRisk) -> None:
        """Add a security risk to this profile."""
        self.risks.append(risk)
        self.count += 1
    
    def add_threat_vector(self, threat: ThreatVector) -> None:
        """Add a threat vector to this profile."""
        self.threat_vectors.append(threat)
    
    def get_average_severity(self) -> RiskLevel:
        """Calculate average severity of risks in this profile."""
        if not self.risks:
            return RiskLevel.MINIMAL
        
        severity_weights = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.MINIMAL: 1,
            RiskLevel.UNKNOWN: 0
        }
        
        total_weight = sum(severity_weights.get(risk.severity, 0) for risk in self.risks)
        avg_weight = total_weight / len(self.risks) if self.risks else 0
        
        # Convert back to risk level
        if avg_weight >= 4.5:
            return RiskLevel.CRITICAL
        elif avg_weight >= 3.5:
            return RiskLevel.HIGH
        elif avg_weight >= 2.5:
            return RiskLevel.MEDIUM
        elif avg_weight >= 1.5:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL


@dataclass
class CategoryAnalysis:
    """Analysis results for a risk category."""
    category: RiskCategory
    total_risks: int
    severity_distribution: Dict[RiskLevel, int] = field(default_factory=dict)
    domain_distribution: Dict[RiskDomain, int] = field(default_factory=dict)
    classification_distribution: Dict[RiskClassification, int] = field(default_factory=dict)
    top_risks: List[SecurityRisk] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class RiskCategorizer:
    """
    Categorizes and classifies security risks for comprehensive analysis.
    
    Provides systematic categorization of risks by type, severity, domain,
    and classification to enable better risk management and reporting.
    """
    
    def __init__(self):
        """Initialize the risk categorizer."""
        self.logger = logging.getLogger(__name__)
        self._category_rules = self._initialize_category_rules()
        self._classification_rules = self._initialize_classification_rules()
        self._domain_rules = self._initialize_domain_rules()
    
    def categorize_risks(self, risks: List[SecurityRisk]) -> Dict[RiskCategory, RiskProfile]:
        """
        Categorize a list of security risks.
        
        Args:
            risks: List of security risks to categorize
            
        Returns:
            Dictionary mapping risk categories to their profiles
        """
        profiles = {}
        
        for risk in risks:
            category = self._determine_risk_category(risk)
            classification = self._determine_risk_classification(risk)
            domain = self._determine_risk_domain(risk)
            
            # Create or get existing profile
            if category not in profiles:
                profiles[category] = RiskProfile(
                    category=category,
                    classification=classification,
                    domain=domain,
                    severity=risk.severity
                )
            
            profiles[category].add_risk(risk)
        
        # Update severity for each profile
        for profile in profiles.values():
            profile.severity = profile.get_average_severity()
        
        self.logger.info(f"Categorized {len(risks)} risks into {len(profiles)} categories")
        return profiles
    
    def categorize_threat_vectors(self, threats: List[ThreatVector]) -> Dict[ThreatCategory, List[ThreatVector]]:
        """
        Categorize threat vectors by their threat category.
        
        Args:
            threats: List of threat vectors to categorize
            
        Returns:
            Dictionary mapping threat categories to their vectors
        """
        categories = defaultdict(list)
        
        for threat in threats:
            categories[threat.category].append(threat)
        
        return dict(categories)
    
    def analyze_risk_distribution(self, risks: List[SecurityRisk]) -> Dict[str, Any]:
        """
        Analyze the distribution of risks across categories and severities.
        
        Args:
            risks: List of security risks to analyze
            
        Returns:
            Dictionary containing distribution analysis
        """
        analysis = {
            "total_risks": len(risks),
            "severity_distribution": Counter(),
            "category_distribution": Counter(),
            "domain_distribution": Counter(),
            "classification_distribution": Counter(),
            "risk_density": {},
            "top_categories": [],
            "critical_areas": []
        }
        
        # Count distributions
        for risk in risks:
            analysis["severity_distribution"][risk.severity.value] += 1
            
            category = self._determine_risk_category(risk)
            analysis["category_distribution"][category.value] += 1
            
            domain = self._determine_risk_domain(risk)
            analysis["domain_distribution"][domain.value] += 1
            
            classification = self._determine_risk_classification(risk)
            analysis["classification_distribution"][classification.value] += 1
        
        # Calculate risk density (risks per category)
        total_categories = len(analysis["category_distribution"])
        if total_categories > 0:
            analysis["risk_density"] = {
                cat: count / total_categories 
                for cat, count in analysis["category_distribution"].items()
            }
        
        # Identify top categories and critical areas
        analysis["top_categories"] = [
            cat for cat, count in analysis["category_distribution"].most_common(5)
        ]
        
        analysis["critical_areas"] = [
            cat for cat, count in analysis["category_distribution"].items()
            if count >= len(risks) * 0.2  # Categories with >20% of risks
        ]
        
        return analysis
    
    def generate_category_analysis(self, category: RiskCategory, risks: List[SecurityRisk]) -> CategoryAnalysis:
        """
        Generate detailed analysis for a specific risk category.
        
        Args:
            category: Risk category to analyze
            risks: List of risks in this category
            
        Returns:
            Detailed category analysis
        """
        analysis = CategoryAnalysis(
            category=category,
            total_risks=len(risks)
        )
        
        # Severity distribution
        analysis.severity_distribution = Counter(risk.severity for risk in risks)
        
        # Domain distribution
        domains = [self._determine_risk_domain(risk) for risk in risks]
        analysis.domain_distribution = Counter(domains)
        
        # Classification distribution
        classifications = [self._determine_risk_classification(risk) for risk in risks]
        analysis.classification_distribution = Counter(classifications)
        
        # Top risks (highest severity first)
        analysis.top_risks = sorted(
            risks,
            key=lambda r: self._get_severity_weight(r.severity),
            reverse=True
        )[:10]
        
        # Generate recommendations
        analysis.recommendations = self._generate_category_recommendations(category, analysis)
        
        return analysis
    
    def get_risk_priorities(self, risks: List[SecurityRisk]) -> List[SecurityRisk]:
        """
        Prioritize risks based on category, severity, and impact.
        
        Args:
            risks: List of security risks to prioritize
            
        Returns:
            List of risks sorted by priority (highest first)
        """
        def priority_score(risk: SecurityRisk) -> float:
            """Calculate priority score for a risk."""
            severity_weight = self._get_severity_weight(risk.severity)
            category_weight = self._get_category_weight(self._determine_risk_category(risk))
            classification_weight = self._get_classification_weight(
                self._determine_risk_classification(risk)
            )
            
            return severity_weight * 0.5 + category_weight * 0.3 + classification_weight * 0.2
        
        return sorted(risks, key=priority_score, reverse=True)
    
    def _determine_risk_category(self, risk: SecurityRisk) -> RiskCategory:
        """Determine the risk category for a security risk."""
        risk_category = risk.category.lower()
        
        # Try to map to existing RiskCategory enum
        try:
            return RiskCategory(risk_category)
        except ValueError:
            # Use pattern matching for custom categories
            for pattern, category in self._category_rules.items():
                if pattern in risk_category or pattern in risk.description.lower():
                    return category
            
            return RiskCategory.UNKNOWN
    
    def _determine_risk_classification(self, risk: SecurityRisk) -> RiskClassification:
        """Determine the risk classification for a security risk."""
        severity = risk.severity
        category = self._determine_risk_category(risk)
        
        # Critical infrastructure risks
        if category in [RiskCategory.CODE_EXECUTION, RiskCategory.SYSTEM_MODIFICATION]:
            if severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                return RiskClassification.CRITICAL_INFRASTRUCTURE
        
        # High impact risks
        if severity == RiskLevel.CRITICAL:
            return RiskClassification.HIGH_IMPACT
        elif severity == RiskLevel.HIGH:
            return RiskClassification.HIGH_IMPACT
        elif severity == RiskLevel.MEDIUM:
            return RiskClassification.MEDIUM_IMPACT
        elif severity == RiskLevel.LOW:
            return RiskClassification.LOW_IMPACT
        else:
            return RiskClassification.INFORMATIONAL
    
    def _determine_risk_domain(self, risk: SecurityRisk) -> RiskDomain:
        """Determine the risk domain for a security risk."""
        category = self._determine_risk_category(risk)
        
        # Map categories to domains
        domain_mapping = {
            RiskCategory.AUTHENTICATION: RiskDomain.SECURITY,
            RiskCategory.CODE_EXECUTION: RiskDomain.SECURITY,
            RiskCategory.NETWORK_ACCESS: RiskDomain.SECURITY,
            RiskCategory.FILE_SYSTEM: RiskDomain.SECURITY,
            RiskCategory.DATA_ACCESS: RiskDomain.PRIVACY,
            RiskCategory.DATABASE: RiskDomain.PRIVACY,
            RiskCategory.SYSTEM_MODIFICATION: RiskDomain.OPERATIONAL,
            RiskCategory.ENCRYPTION: RiskDomain.COMPLIANCE,
            RiskCategory.EXTERNAL_API: RiskDomain.BUSINESS,
            RiskCategory.CLOUD_SERVICES: RiskDomain.TECHNICAL,
        }
        
        return domain_mapping.get(category, RiskDomain.TECHNICAL)
    
    def _get_severity_weight(self, severity: RiskLevel) -> float:
        """Get numeric weight for severity level."""
        weights = {
            RiskLevel.CRITICAL: 5.0,
            RiskLevel.HIGH: 4.0,
            RiskLevel.MEDIUM: 3.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.MINIMAL: 1.0,
            RiskLevel.UNKNOWN: 0.0
        }
        return weights.get(severity, 0.0)
    
    def _get_category_weight(self, category: RiskCategory) -> float:
        """Get numeric weight for risk category."""
        weights = {
            RiskCategory.CODE_EXECUTION: 5.0,
            RiskCategory.SYSTEM_MODIFICATION: 4.5,
            RiskCategory.AUTHENTICATION: 4.0,
            RiskCategory.NETWORK_ACCESS: 3.5,
            RiskCategory.FILE_SYSTEM: 3.0,
            RiskCategory.DATA_ACCESS: 3.0,
            RiskCategory.DATABASE: 3.5,
            RiskCategory.ENCRYPTION: 2.5,
            RiskCategory.EXTERNAL_API: 2.0,
            RiskCategory.CLOUD_SERVICES: 2.0,
            RiskCategory.UNKNOWN: 1.0
        }
        return weights.get(category, 1.0)
    
    def _get_classification_weight(self, classification: RiskClassification) -> float:
        """Get numeric weight for risk classification."""
        weights = {
            RiskClassification.CRITICAL_INFRASTRUCTURE: 5.0,
            RiskClassification.HIGH_IMPACT: 4.0,
            RiskClassification.MEDIUM_IMPACT: 3.0,
            RiskClassification.LOW_IMPACT: 2.0,
            RiskClassification.INFORMATIONAL: 1.0
        }
        return weights.get(classification, 1.0)
    
    def _generate_category_recommendations(self, category: RiskCategory, analysis: CategoryAnalysis) -> List[str]:
        """Generate recommendations for a risk category."""
        recommendations = []
        
        # Category-specific recommendations
        if category == RiskCategory.CODE_EXECUTION:
            recommendations.extend([
                "Implement strict input validation for all command parameters",
                "Use sandboxing or containerization to limit execution scope",
                "Apply principle of least privilege for command execution",
                "Monitor and log all command execution activities"
            ])
        elif category == RiskCategory.FILE_SYSTEM:
            recommendations.extend([
                "Implement file access controls and path validation",
                "Use chroot or similar containment mechanisms",
                "Monitor file system access patterns",
                "Implement data loss prevention (DLP) controls"
            ])
        elif category == RiskCategory.NETWORK_ACCESS:
            recommendations.extend([
                "Implement network segmentation and firewall rules",
                "Monitor network traffic for anomalous patterns",
                "Use VPNs or secure tunnels for sensitive communications",
                "Implement rate limiting for network requests"
            ])
        elif category == RiskCategory.AUTHENTICATION:
            recommendations.extend([
                "Implement multi-factor authentication (MFA)",
                "Use strong password policies and rotation",
                "Monitor authentication attempts and failures",
                "Implement session management and timeout controls"
            ])
        
        # Severity-based recommendations
        critical_count = analysis.severity_distribution.get(RiskLevel.CRITICAL, 0)
        high_count = analysis.severity_distribution.get(RiskLevel.HIGH, 0)
        
        if critical_count > 0:
            recommendations.append(f"Immediate attention required: {critical_count} critical risks identified")
        if high_count > 0:
            recommendations.append(f"High priority: {high_count} high-severity risks need remediation")
        
        return recommendations
    
    def _initialize_category_rules(self) -> Dict[str, RiskCategory]:
        """Initialize category mapping rules."""
        return {
            "command": RiskCategory.CODE_EXECUTION,
            "exec": RiskCategory.CODE_EXECUTION,
            "shell": RiskCategory.CODE_EXECUTION,
            "script": RiskCategory.CODE_EXECUTION,
            "file": RiskCategory.FILE_SYSTEM,
            "path": RiskCategory.FILE_SYSTEM,
            "directory": RiskCategory.FILE_SYSTEM,
            "network": RiskCategory.NETWORK_ACCESS,
            "http": RiskCategory.NETWORK_ACCESS,
            "url": RiskCategory.NETWORK_ACCESS,
            "api": RiskCategory.EXTERNAL_API,
            "database": RiskCategory.DATABASE,
            "sql": RiskCategory.DATABASE,
            "auth": RiskCategory.AUTHENTICATION,
            "password": RiskCategory.AUTHENTICATION,
            "token": RiskCategory.AUTHENTICATION,
            "credential": RiskCategory.AUTHENTICATION,
            "encrypt": RiskCategory.ENCRYPTION,
            "crypto": RiskCategory.ENCRYPTION,
            "cloud": RiskCategory.CLOUD_SERVICES,
            "aws": RiskCategory.CLOUD_SERVICES,
            "azure": RiskCategory.CLOUD_SERVICES,
            "gcp": RiskCategory.CLOUD_SERVICES,
        }
    
    def _initialize_classification_rules(self) -> Dict[str, RiskClassification]:
        """Initialize classification mapping rules."""
        return {
            "critical_system": RiskClassification.CRITICAL_INFRASTRUCTURE,
            "infrastructure": RiskClassification.CRITICAL_INFRASTRUCTURE,
            "high_impact": RiskClassification.HIGH_IMPACT,
            "medium_impact": RiskClassification.MEDIUM_IMPACT,
            "low_impact": RiskClassification.LOW_IMPACT,
            "informational": RiskClassification.INFORMATIONAL,
        }
    
    def _initialize_domain_rules(self) -> Dict[str, RiskDomain]:
        """Initialize domain mapping rules."""
        return {
            "security": RiskDomain.SECURITY,
            "privacy": RiskDomain.PRIVACY,
            "compliance": RiskDomain.COMPLIANCE,
            "operational": RiskDomain.OPERATIONAL,
            "business": RiskDomain.BUSINESS,
            "technical": RiskDomain.TECHNICAL,
        } 