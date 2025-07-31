"""
CVSS (Common Vulnerability Scoring System) scoring implementation.

This module provides comprehensive CVSS v3.1 scoring capabilities for
vulnerability assessment, including base score, temporal score, and
environmental score calculations.
"""

import re
import math
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass

from .base import CVSSVector, CVSSError, VulnerabilityInfo, VulnerabilityCategory, RiskLevel
from ..utils.logging import get_logger


# CVSS v3.1 Metric Values and Weights
CVSS_METRICS = {
    # Attack Vector (AV)
    'AV': {
        'N': 0.85,  # Network
        'A': 0.62,  # Adjacent Network
        'L': 0.55,  # Local
        'P': 0.2    # Physical
    },
    
    # Attack Complexity (AC)
    'AC': {
        'L': 0.77,  # Low
        'H': 0.44   # High
    },
    
    # Privileges Required (PR)
    'PR': {
        'N': 0.85,  # None
        'L': 0.62,  # Low (when Scope is Unchanged)
        'H': 0.27   # High (when Scope is Unchanged)
    },
    
    # Privileges Required when Scope is Changed
    'PR_CHANGED': {
        'N': 0.85,  # None
        'L': 0.68,  # Low (when Scope is Changed)
        'H': 0.50   # High (when Scope is Changed)
    },
    
    # User Interaction (UI)
    'UI': {
        'N': 0.85,  # None
        'R': 0.62   # Required
    },
    
    # Scope (S)
    'S': {
        'U': 'unchanged',  # Unchanged
        'C': 'changed'     # Changed
    },
    
    # Confidentiality Impact (C)
    'C': {
        'N': 0.0,   # None
        'L': 0.22,  # Low
        'H': 0.56   # High
    },
    
    # Integrity Impact (I)
    'I': {
        'N': 0.0,   # None
        'L': 0.22,  # Low
        'H': 0.56   # High
    },
    
    # Availability Impact (A)
    'A': {
        'N': 0.0,   # None
        'L': 0.22,  # Low
        'H': 0.56   # High
    },
    
    # Exploit Code Maturity (E)
    'E': {
        'X': 1.0,   # Not Defined
        'U': 0.91,  # Unproven
        'P': 0.94,  # Proof-of-Concept
        'F': 0.97,  # Functional
        'H': 1.0    # High
    },
    
    # Remediation Level (RL)
    'RL': {
        'X': 1.0,   # Not Defined
        'O': 0.95,  # Official Fix
        'T': 0.96,  # Temporary Fix
        'W': 0.97,  # Workaround
        'U': 1.0    # Unavailable
    },
    
    # Report Confidence (RC)
    'RC': {
        'X': 1.0,   # Not Defined
        'U': 0.92,  # Unknown
        'R': 0.96,  # Reasonable
        'C': 1.0    # Confirmed
    },
    
    # Confidentiality Requirement (CR)
    'CR': {
        'X': 1.0,   # Not Defined
        'L': 0.5,   # Low
        'M': 1.0,   # Medium
        'H': 1.5    # High
    },
    
    # Integrity Requirement (IR)
    'IR': {
        'X': 1.0,   # Not Defined
        'L': 0.5,   # Low
        'M': 1.0,   # Medium
        'H': 1.5    # High
    },
    
    # Availability Requirement (AR)
    'AR': {
        'X': 1.0,   # Not Defined
        'L': 0.5,   # Low
        'M': 1.0,   # Medium
        'H': 1.5    # High
    }
}


@dataclass
class CVSSScores:
    """Container for CVSS scores and components."""
    
    base_score: float = 0.0
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    
    # Base score components
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    
    # Temporal score components
    temporal_multiplier: Optional[float] = None
    
    # Environmental score components
    modified_impact_score: Optional[float] = None
    modified_exploitability_score: Optional[float] = None
    
    # Overall score (highest applicable score)
    overall_score: float = 0.0
    
    # Risk level based on score
    risk_level: RiskLevel = RiskLevel.NONE
    
    def __post_init__(self):
        """Calculate overall score and risk level after initialization."""
        self.calculate_overall_score()
        self.calculate_risk_level()
    
    def calculate_overall_score(self) -> None:
        """Calculate the overall CVSS score (highest applicable score)."""
        scores = [self.base_score]
        
        if self.temporal_score is not None:
            scores.append(self.temporal_score)
        
        if self.environmental_score is not None:
            scores.append(self.environmental_score)
        
        self.overall_score = max(scores)
    
    def calculate_risk_level(self) -> None:
        """Calculate risk level based on overall score."""
        if self.overall_score == 0.0:
            self.risk_level = RiskLevel.NONE
        elif self.overall_score < 4.0:
            self.risk_level = RiskLevel.LOW
        elif self.overall_score < 7.0:
            self.risk_level = RiskLevel.MEDIUM
        elif self.overall_score < 9.0:
            self.risk_level = RiskLevel.HIGH
        else:
            self.risk_level = RiskLevel.CRITICAL
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scores to dictionary representation."""
        return {
            'base_score': round(self.base_score, 1),
            'temporal_score': round(self.temporal_score, 1) if self.temporal_score is not None else None,
            'environmental_score': round(self.environmental_score, 1) if self.environmental_score is not None else None,
            'overall_score': round(self.overall_score, 1),
            'risk_level': self.risk_level.value,
            'components': {
                'exploitability_score': round(self.exploitability_score, 1),
                'impact_score': round(self.impact_score, 1),
                'temporal_multiplier': round(self.temporal_multiplier, 3) if self.temporal_multiplier is not None else None,
                'modified_impact_score': round(self.modified_impact_score, 1) if self.modified_impact_score is not None else None,
                'modified_exploitability_score': round(self.modified_exploitability_score, 1) if self.modified_exploitability_score is not None else None,
            }
        }


class CVSSCalculator:
    """CVSS v3.1 score calculator."""
    
    def __init__(self):
        """Initialize the CVSS calculator."""
        self.logger = get_logger(self.__class__.__name__)
    
    def calculate_scores(self, cvss_vector: CVSSVector) -> CVSSScores:
        """
        Calculate CVSS scores from a CVSS vector.
        
        Args:
            cvss_vector: CVSS vector with metric values
            
        Returns:
            CVSSScores: Calculated scores and components
            
        Raises:
            CVSSError: If vector contains invalid values
        """
        try:
            # Validate vector
            self._validate_vector(cvss_vector)
            
            # Calculate base score
            base_score, exploitability, impact = self._calculate_base_score(cvss_vector)
            
            scores = CVSSScores(
                base_score=base_score,
                exploitability_score=exploitability,
                impact_score=impact
            )
            
            # Calculate temporal score if temporal metrics are present
            if self._has_temporal_metrics(cvss_vector):
                temporal_score, temporal_multiplier = self._calculate_temporal_score(cvss_vector, base_score)
                scores.temporal_score = temporal_score
                scores.temporal_multiplier = temporal_multiplier
            
            # Calculate environmental score if environmental metrics are present
            if self._has_environmental_metrics(cvss_vector):
                env_score, mod_impact, mod_exploit = self._calculate_environmental_score(cvss_vector)
                scores.environmental_score = env_score
                scores.modified_impact_score = mod_impact
                scores.modified_exploitability_score = mod_exploit
            
            # Recalculate overall score and risk level
            scores.calculate_overall_score()
            scores.calculate_risk_level()
            
            return scores
            
        except Exception as e:
            self.logger.error(f"Error calculating CVSS scores: {e}")
            raise CVSSError(f"Failed to calculate CVSS scores: {e}")
    
    def parse_vector_string(self, vector_string: str) -> CVSSVector:
        """
        Parse a CVSS vector string into a CVSSVector object.
        
        Args:
            vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")
            
        Returns:
            CVSSVector: Parsed CVSS vector
            
        Raises:
            CVSSError: If vector string is invalid
        """
        try:
            if not vector_string or not isinstance(vector_string, str):
                raise CVSSError("Vector string cannot be empty or non-string")
            
            # Remove CVSS version prefix
            if vector_string.startswith("CVSS:3.1/"):
                vector_string = vector_string[9:]
            elif vector_string.startswith("CVSS:3.0/"):
                vector_string = vector_string[9:]
            
            # Check if we have any content left
            if not vector_string:
                raise CVSSError("Vector string contains no metrics")
            
            # Parse metrics
            metrics = {}
            for metric_pair in vector_string.split('/'):
                if ':' not in metric_pair:
                    if metric_pair.strip():  # Only raise error for non-empty invalid pairs
                        raise CVSSError(f"Invalid metric format: {metric_pair}")
                    continue
                
                parts = metric_pair.split(':', 1)
                if len(parts) != 2:
                    raise CVSSError(f"Invalid metric format: {metric_pair}")
                
                metric, value = parts
                if not metric or not value:
                    raise CVSSError(f"Empty metric or value in: {metric_pair}")
                
                metrics[metric] = value
            
            # Check for required base metrics
            required_base_metrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
            missing_metrics = [m for m in required_base_metrics if m not in metrics]
            if missing_metrics:
                raise CVSSError(f"Missing required base metrics: {missing_metrics}")
            
            # Create CVSSVector with parsed metrics
            vector = CVSSVector()
            
            # Base metrics
            vector.attack_vector = metrics['AV']
            vector.attack_complexity = metrics['AC']
            vector.privileges_required = metrics['PR']
            vector.user_interaction = metrics['UI']
            vector.scope = metrics['S']
            vector.confidentiality = metrics['C']
            vector.integrity = metrics['I']
            vector.availability = metrics['A']
            
            # Temporal metrics
            if 'E' in metrics:
                vector.exploit_code_maturity = metrics['E']
            if 'RL' in metrics:
                vector.remediation_level = metrics['RL']
            if 'RC' in metrics:
                vector.report_confidence = metrics['RC']
            
            # Environmental metrics
            if 'CR' in metrics:
                vector.confidentiality_requirement = metrics['CR']
            if 'IR' in metrics:
                vector.integrity_requirement = metrics['IR']
            if 'AR' in metrics:
                vector.availability_requirement = metrics['AR']
            
            return vector
            
        except CVSSError:
            raise
        except Exception as e:
            self.logger.error(f"Error parsing CVSS vector string: {e}")
            raise CVSSError(f"Invalid CVSS vector string: {vector_string}")
    
    def calculate_from_string(self, vector_string: str) -> CVSSScores:
        """
        Calculate CVSS scores from a vector string.
        
        Args:
            vector_string: CVSS vector string
            
        Returns:
            CVSSScores: Calculated scores
        """
        vector = self.parse_vector_string(vector_string)
        return self.calculate_scores(vector)
    
    def _validate_vector(self, vector: CVSSVector) -> None:
        """Validate CVSS vector values."""
        # Validate base metrics
        if vector.attack_vector not in CVSS_METRICS['AV']:
            raise CVSSError(f"Invalid Attack Vector: {vector.attack_vector}")
        
        if vector.attack_complexity not in CVSS_METRICS['AC']:
            raise CVSSError(f"Invalid Attack Complexity: {vector.attack_complexity}")
        
        if vector.privileges_required not in CVSS_METRICS['PR']:
            raise CVSSError(f"Invalid Privileges Required: {vector.privileges_required}")
        
        if vector.user_interaction not in CVSS_METRICS['UI']:
            raise CVSSError(f"Invalid User Interaction: {vector.user_interaction}")
        
        if vector.scope not in CVSS_METRICS['S']:
            raise CVSSError(f"Invalid Scope: {vector.scope}")
        
        if vector.confidentiality not in CVSS_METRICS['C']:
            raise CVSSError(f"Invalid Confidentiality Impact: {vector.confidentiality}")
        
        if vector.integrity not in CVSS_METRICS['I']:
            raise CVSSError(f"Invalid Integrity Impact: {vector.integrity}")
        
        if vector.availability not in CVSS_METRICS['A']:
            raise CVSSError(f"Invalid Availability Impact: {vector.availability}")
        
        # Validate temporal metrics if present
        if vector.exploit_code_maturity and vector.exploit_code_maturity not in CVSS_METRICS['E']:
            raise CVSSError(f"Invalid Exploit Code Maturity: {vector.exploit_code_maturity}")
        
        if vector.remediation_level and vector.remediation_level not in CVSS_METRICS['RL']:
            raise CVSSError(f"Invalid Remediation Level: {vector.remediation_level}")
        
        if vector.report_confidence and vector.report_confidence not in CVSS_METRICS['RC']:
            raise CVSSError(f"Invalid Report Confidence: {vector.report_confidence}")
        
        # Validate environmental metrics if present
        if vector.confidentiality_requirement and vector.confidentiality_requirement not in CVSS_METRICS['CR']:
            raise CVSSError(f"Invalid Confidentiality Requirement: {vector.confidentiality_requirement}")
        
        if vector.integrity_requirement and vector.integrity_requirement not in CVSS_METRICS['IR']:
            raise CVSSError(f"Invalid Integrity Requirement: {vector.integrity_requirement}")
        
        if vector.availability_requirement and vector.availability_requirement not in CVSS_METRICS['AR']:
            raise CVSSError(f"Invalid Availability Requirement: {vector.availability_requirement}")
    
    def _calculate_base_score(self, vector: CVSSVector) -> Tuple[float, float, float]:
        """Calculate CVSS base score and components."""
        # Get metric values
        av = CVSS_METRICS['AV'][vector.attack_vector]
        ac = CVSS_METRICS['AC'][vector.attack_complexity]
        ui = CVSS_METRICS['UI'][vector.user_interaction]
        
        # Privileges Required depends on Scope
        if vector.scope == 'C':  # Changed
            pr = CVSS_METRICS['PR_CHANGED'][vector.privileges_required]
        else:  # Unchanged
            pr = CVSS_METRICS['PR'][vector.privileges_required]
        
        c = CVSS_METRICS['C'][vector.confidentiality]
        i = CVSS_METRICS['I'][vector.integrity]
        a = CVSS_METRICS['A'][vector.availability]
        
        # Calculate Exploitability Score
        exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate Impact Score
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if vector.scope == 'U':  # Unchanged
            impact = 6.42 * iss
        else:  # Changed
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        else:
            if vector.scope == 'U':  # Unchanged
                base_score = min(10.0, (impact + exploitability))
            else:  # Changed
                base_score = min(10.0, 1.08 * (impact + exploitability))
        
        # Round to one decimal place
        base_score = math.ceil(base_score * 10) / 10
        
        return base_score, exploitability, impact
    
    def _calculate_temporal_score(self, vector: CVSSVector, base_score: float) -> Tuple[float, float]:
        """Calculate CVSS temporal score."""
        # Get temporal metric values (default to 'X' if not specified)
        e = CVSS_METRICS['E'].get(vector.exploit_code_maturity or 'X', 1.0)
        rl = CVSS_METRICS['RL'].get(vector.remediation_level or 'X', 1.0)
        rc = CVSS_METRICS['RC'].get(vector.report_confidence or 'X', 1.0)
        
        # Calculate temporal multiplier
        temporal_multiplier = e * rl * rc
        
        # Calculate temporal score
        temporal_score = math.ceil(base_score * temporal_multiplier * 10) / 10
        
        return temporal_score, temporal_multiplier
    
    def _calculate_environmental_score(self, vector: CVSSVector) -> Tuple[float, float, float]:
        """Calculate CVSS environmental score."""
        # Get environmental metric values (default to 'X' if not specified)
        cr = CVSS_METRICS['CR'].get(vector.confidentiality_requirement or 'X', 1.0)
        ir = CVSS_METRICS['IR'].get(vector.integrity_requirement or 'X', 1.0)
        ar = CVSS_METRICS['AR'].get(vector.availability_requirement or 'X', 1.0)
        
        # Get base metric values
        av = CVSS_METRICS['AV'][vector.attack_vector]
        ac = CVSS_METRICS['AC'][vector.attack_complexity]
        ui = CVSS_METRICS['UI'][vector.user_interaction]
        
        # Privileges Required depends on Scope
        if vector.scope == 'C':  # Changed
            pr = CVSS_METRICS['PR_CHANGED'][vector.privileges_required]
        else:  # Unchanged
            pr = CVSS_METRICS['PR'][vector.privileges_required]
        
        c = CVSS_METRICS['C'][vector.confidentiality]
        i = CVSS_METRICS['I'][vector.integrity]
        a = CVSS_METRICS['A'][vector.availability]
        
        # Calculate Modified Exploitability Score
        modified_exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate Modified Impact Score
        miss = min(1 - ((1 - c * cr) * (1 - i * ir) * (1 - a * ar)), 0.915)
        
        if vector.scope == 'U':  # Unchanged
            modified_impact = 6.42 * miss
        else:  # Changed
            modified_impact = 7.52 * (miss - 0.029) - 3.25 * pow(miss - 0.02, 15)
        
        # Calculate Environmental Score
        if modified_impact <= 0:
            environmental_score = 0.0
        else:
            # Get temporal metrics for environmental calculation
            e = CVSS_METRICS['E'].get(vector.exploit_code_maturity or 'X', 1.0)
            rl = CVSS_METRICS['RL'].get(vector.remediation_level or 'X', 1.0)
            rc = CVSS_METRICS['RC'].get(vector.report_confidence or 'X', 1.0)
            
            if vector.scope == 'U':  # Unchanged
                environmental_score = math.ceil((modified_impact + modified_exploitability) * e * rl * rc * 10) / 10
            else:  # Changed
                environmental_score = math.ceil(1.08 * (modified_impact + modified_exploitability) * e * rl * rc * 10) / 10
        
        environmental_score = min(10.0, environmental_score)
        
        return environmental_score, modified_impact, modified_exploitability
    
    def _has_temporal_metrics(self, vector: CVSSVector) -> bool:
        """Check if vector has temporal metrics."""
        return any([
            vector.exploit_code_maturity,
            vector.remediation_level,
            vector.report_confidence
        ])
    
    def _has_environmental_metrics(self, vector: CVSSVector) -> bool:
        """Check if vector has environmental metrics."""
        return any([
            vector.confidentiality_requirement,
            vector.integrity_requirement,
            vector.availability_requirement
        ])


class CVSSAssessment:
    """High-level CVSS assessment functionality."""
    
    def __init__(self):
        """Initialize CVSS assessment."""
        self.calculator = CVSSCalculator()
        self.logger = get_logger(self.__class__.__name__)
    
    def assess_vulnerability(self, vulnerability: VulnerabilityInfo) -> VulnerabilityInfo:
        """
        Assess a vulnerability and calculate CVSS scores.
        
        Args:
            vulnerability: Vulnerability to assess
            
        Returns:
            VulnerabilityInfo: Updated vulnerability with CVSS scores
        """
        try:
            if vulnerability.cvss_vector:
                scores = self.calculator.calculate_scores(vulnerability.cvss_vector)
                vulnerability.cvss_score = scores.overall_score
                vulnerability.severity = scores.risk_level
                
                self.logger.debug(f"Calculated CVSS score {scores.overall_score} for {vulnerability.id}")
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Error assessing vulnerability {vulnerability.id}: {e}")
            return vulnerability
    
    def create_vulnerability_from_cvss(
        self,
        vuln_id: str,
        title: str,
        description: str,
        cvss_vector_string: str,
        **kwargs
    ) -> VulnerabilityInfo:
        """
        Create a vulnerability from CVSS vector string.
        
        Args:
            vuln_id: Vulnerability identifier
            title: Vulnerability title
            description: Vulnerability description
            cvss_vector_string: CVSS vector string
            **kwargs: Additional vulnerability properties
            
        Returns:
            VulnerabilityInfo: Created vulnerability with CVSS scores
        """
        try:
            # Parse CVSS vector
            cvss_vector = self.calculator.parse_vector_string(cvss_vector_string)
            
            # Calculate scores
            scores = self.calculator.calculate_scores(cvss_vector)
            
            # Create vulnerability
            vulnerability = VulnerabilityInfo(
                id=vuln_id,
                title=title,
                description=description,
                category=kwargs.get('category', VulnerabilityCategory.CONFIGURATION),
                severity=scores.risk_level,
                cvss_vector=cvss_vector,
                cvss_score=scores.overall_score,
                **{k: v for k, v in kwargs.items() if k != 'category'}
            )
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"Error creating vulnerability from CVSS: {e}")
            raise CVSSError(f"Failed to create vulnerability from CVSS: {e}")
    
    def get_score_breakdown(self, cvss_vector: CVSSVector) -> Dict[str, Any]:
        """
        Get detailed CVSS score breakdown.
        
        Args:
            cvss_vector: CVSS vector to analyze
            
        Returns:
            Dict: Detailed score breakdown
        """
        try:
            scores = self.calculator.calculate_scores(cvss_vector)
            
            return {
                'vector_string': cvss_vector.to_vector_string(),
                'scores': scores.to_dict(),
                'metrics': {
                    'base_metrics': {
                        'attack_vector': cvss_vector.attack_vector,
                        'attack_complexity': cvss_vector.attack_complexity,
                        'privileges_required': cvss_vector.privileges_required,
                        'user_interaction': cvss_vector.user_interaction,
                        'scope': cvss_vector.scope,
                        'confidentiality': cvss_vector.confidentiality,
                        'integrity': cvss_vector.integrity,
                        'availability': cvss_vector.availability,
                    },
                    'temporal_metrics': {
                        'exploit_code_maturity': cvss_vector.exploit_code_maturity,
                        'remediation_level': cvss_vector.remediation_level,
                        'report_confidence': cvss_vector.report_confidence,
                    } if self.calculator._has_temporal_metrics(cvss_vector) else None,
                    'environmental_metrics': {
                        'confidentiality_requirement': cvss_vector.confidentiality_requirement,
                        'integrity_requirement': cvss_vector.integrity_requirement,
                        'availability_requirement': cvss_vector.availability_requirement,
                    } if self.calculator._has_environmental_metrics(cvss_vector) else None,
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting score breakdown: {e}")
            raise CVSSError(f"Failed to get score breakdown: {e}")


# Convenience functions
def calculate_cvss_score(vector_string: str) -> float:
    """
    Calculate CVSS score from vector string.
    
    Args:
        vector_string: CVSS vector string
        
    Returns:
        float: CVSS score
    """
    calculator = CVSSCalculator()
    scores = calculator.calculate_from_string(vector_string)
    return scores.overall_score


def get_risk_level_from_score(score: float) -> RiskLevel:
    """
    Get risk level from CVSS score.
    
    Args:
        score: CVSS score (0.0-10.0)
        
    Returns:
        RiskLevel: Corresponding risk level
    """
    if score == 0.0:
        return RiskLevel.NONE
    elif score < 4.0:
        return RiskLevel.LOW
    elif score < 7.0:
        return RiskLevel.MEDIUM
    elif score < 9.0:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL 