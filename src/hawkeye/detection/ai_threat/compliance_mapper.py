"""
Compliance Mapper

This module provides comprehensive compliance framework mapping for threat analysis reports.
It maps security findings, threats, and mitigations to specific compliance requirements
and generates compliance assessment reports.
"""

import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

from .models import (
    ToolCapabilities, EnvironmentContext, ComplianceFramework,
    DeploymentType, SecurityPosture
)


logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Compliance status levels."""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ControlCategory(Enum):
    """Control categories across frameworks."""
    ACCESS_CONTROL = "access_control"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    MONITORING = "monitoring"
    INCIDENT_RESPONSE = "incident_response"
    RISK_MANAGEMENT = "risk_management"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    SYSTEM_SECURITY = "system_security"
    BUSINESS_CONTINUITY = "business_continuity"


@dataclass
class ComplianceControl:
    """A specific compliance control requirement."""
    id: str
    framework: str
    category: ControlCategory
    title: str
    description: str
    requirements: List[str]
    evidence_requirements: List[str]
    testing_procedures: List[str]
    severity: str  # low, medium, high, critical
    applies_to_environment: bool


@dataclass
class ComplianceGap:
    """A gap in compliance requirements."""
    control_id: str
    framework: str
    gap_description: str
    current_status: ComplianceStatus
    required_status: ComplianceStatus
    risk_level: str
    remediation_recommendations: List[str]
    estimated_effort: str
    business_impact: str


@dataclass
class ComplianceAssessment:
    """Complete compliance assessment results."""
    assessment_id: str
    framework: str
    assessment_date: datetime
    overall_status: ComplianceStatus
    compliance_percentage: float
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    gaps: List[ComplianceGap]
    recommendations: List[str]
    executive_summary: str


class ComplianceMapper:
    """
    Enhanced compliance mapper for mapping security findings to compliance frameworks
    and generating comprehensive compliance assessments.
    
    This class provides detailed mapping between security threats, mitigations,
    and various compliance framework requirements.
    """
    
    def __init__(self):
        """Initialize the compliance mapper."""
        self.logger = logging.getLogger(__name__)
        
        # Comprehensive compliance framework definitions
        self.compliance_frameworks = self._initialize_compliance_frameworks()
        
        # Threat-to-control mappings
        self.threat_control_mappings = self._initialize_threat_mappings()
        
        # Environment-specific control applicability
        self.environment_applicability = self._initialize_environment_mappings()
    
    def _initialize_compliance_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive compliance framework definitions."""
        frameworks = {
            'SOC2': {
                'name': 'SOC 2 Type II',
                'description': 'Service Organization Control 2 - Security, Availability, Processing Integrity, Confidentiality, Privacy',
                'categories': ['Common Criteria', 'Additional Criteria'],
                'controls': {
                    'CC6.1': ComplianceControl(
                        id='CC6.1',
                        framework='SOC2',
                        category=ControlCategory.ACCESS_CONTROL,
                        title='Logical and Physical Access Controls',
                        description='The entity implements logical access security measures to protect against threats from sources outside its system boundaries',
                        requirements=[
                            'Implement user access management processes',
                            'Establish authentication mechanisms',
                            'Configure authorization controls',
                            'Monitor access activities'
                        ],
                        evidence_requirements=[
                            'Access control policies and procedures',
                            'User access reviews and certifications',
                            'Authentication system configuration',
                            'Access monitoring logs and reports'
                        ],
                        testing_procedures=[
                            'Review access control policies',
                            'Test user provisioning and deprovisioning',
                            'Validate authentication mechanisms',
                            'Examine access monitoring capabilities'
                        ],
                        severity='high',
                        applies_to_environment=True
                    ),
                    'CC6.2': ComplianceControl(
                        id='CC6.2',
                        framework='SOC2',
                        category=ControlCategory.AUTHENTICATION,
                        title='System Access Authorization',
                        description='Prior to issuing system credentials, the entity registers and authorizes new internal and external users',
                        requirements=[
                            'Establish user registration process',
                            'Implement authorization workflows',
                            'Maintain user access database',
                            'Regular access reviews'
                        ],
                        evidence_requirements=[
                            'User registration procedures',
                            'Authorization approval records',
                            'User access database records',
                            'Periodic access review reports'
                        ],
                        testing_procedures=[
                            'Review user registration process',
                            'Test authorization workflows',
                            'Examine user access records',
                            'Validate access review procedures'
                        ],
                        severity='high',
                        applies_to_environment=True
                    ),
                    'CC7.1': ComplianceControl(
                        id='CC7.1',
                        framework='SOC2',
                        category=ControlCategory.MONITORING,
                        title='System Monitoring',
                        description='The entity monitors the system and evaluates the adequacy of system security measures',
                        requirements=[
                            'Implement continuous monitoring',
                            'Deploy security information and event management (SIEM)',
                            'Establish incident detection capabilities',
                            'Regular security assessments'
                        ],
                        evidence_requirements=[
                            'Monitoring system documentation',
                            'SIEM configuration and logs',
                            'Incident detection reports',
                            'Security assessment reports'
                        ],
                        testing_procedures=[
                            'Review monitoring procedures',
                            'Test incident detection capabilities',
                            'Examine SIEM configuration',
                            'Validate security assessments'
                        ],
                        severity='high',
                        applies_to_environment=True
                    )
                }
            },
            
            'PCI_DSS': {
                'name': 'Payment Card Industry Data Security Standard',
                'description': 'Security standards for organizations that handle credit card information',
                'categories': ['Build and Maintain', 'Protect', 'Maintain', 'Monitor', 'Test', 'Policies'],
                'controls': {
                    '2.1': ComplianceControl(
                        id='2.1',
                        framework='PCI_DSS',
                        category=ControlCategory.SYSTEM_SECURITY,
                        title='Default Passwords and Security Parameters',
                        description='Always change vendor-supplied defaults and remove or disable unnecessary default accounts',
                        requirements=[
                            'Change all vendor-supplied default passwords',
                            'Remove or disable unnecessary default accounts',
                            'Implement strong authentication for all accounts',
                            'Document system configurations'
                        ],
                        evidence_requirements=[
                            'System configuration documentation',
                            'Password change records',
                            'Account management procedures',
                            'Security configuration standards'
                        ],
                        testing_procedures=[
                            'Verify default passwords changed',
                            'Confirm unnecessary accounts removed',
                            'Test authentication mechanisms',
                            'Review configuration documentation'
                        ],
                        severity='high',
                        applies_to_environment=True
                    ),
                    '8.2': ComplianceControl(
                        id='8.2',
                        framework='PCI_DSS',
                        category=ControlCategory.AUTHENTICATION,
                        title='User Authentication Management',
                        description='In addition to assigning unique IDs, ensure proper user authentication management',
                        requirements=[
                            'Verify user identity before modifying authentication credentials',
                            'Implement multi-factor authentication',
                            'Encrypt authentication data during transmission',
                            'Establish password complexity requirements'
                        ],
                        evidence_requirements=[
                            'Authentication policies and procedures',
                            'Multi-factor authentication configuration',
                            'Encryption implementation documentation',
                            'Password policy documentation'
                        ],
                        testing_procedures=[
                            'Test identity verification procedures',
                            'Validate multi-factor authentication',
                            'Verify encryption during transmission',
                            'Review password complexity settings'
                        ],
                        severity='critical',
                        applies_to_environment=True
                    ),
                    '10.1': ComplianceControl(
                        id='10.1',
                        framework='PCI_DSS',
                        category=ControlCategory.MONITORING,
                        title='Audit Trails',
                        description='Implement audit trails to link all access to system components to each individual user',
                        requirements=[
                            'Enable audit logging for all system components',
                            'Link access events to individual users',
                            'Log all administrative activities',
                            'Maintain secure audit trail storage'
                        ],
                        evidence_requirements=[
                            'Audit logging configuration',
                            'User access correlation records',
                            'Administrative activity logs',
                            'Audit trail protection mechanisms'
                        ],
                        testing_procedures=[
                            'Verify audit logging enabled',
                            'Test user access correlation',
                            'Review administrative logs',
                            'Validate audit trail security'
                        ],
                        severity='high',
                        applies_to_environment=True
                    )
                }
            },
            
            'NIST_CSF': {
                'name': 'NIST Cybersecurity Framework',
                'description': 'Framework for improving critical infrastructure cybersecurity',
                'categories': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
                'controls': {
                    'ID.AM-1': ComplianceControl(
                        id='ID.AM-1',
                        framework='NIST_CSF',
                        category=ControlCategory.RISK_MANAGEMENT,
                        title='Asset Management',
                        description='Physical devices and systems within the organization are inventoried',
                        requirements=[
                            'Maintain comprehensive asset inventory',
                            'Document asset ownership and responsibility',
                            'Classify assets by criticality',
                            'Regular asset inventory updates'
                        ],
                        evidence_requirements=[
                            'Asset inventory database',
                            'Asset ownership documentation',
                            'Asset classification criteria',
                            'Inventory update procedures'
                        ],
                        testing_procedures=[
                            'Review asset inventory completeness',
                            'Verify ownership assignments',
                            'Validate classification accuracy',
                            'Test update procedures'
                        ],
                        severity='medium',
                        applies_to_environment=True
                    ),
                    'PR.AC-1': ComplianceControl(
                        id='PR.AC-1',
                        framework='NIST_CSF',
                        category=ControlCategory.ACCESS_CONTROL,
                        title='Identity and Access Management',
                        description='Identities and credentials are issued, managed, verified, revoked for authorized devices, users and processes',
                        requirements=[
                            'Implement identity management system',
                            'Establish credential lifecycle management',
                            'Verify identity before access',
                            'Revoke access when no longer needed'
                        ],
                        evidence_requirements=[
                            'Identity management system documentation',
                            'Credential management procedures',
                            'Identity verification records',
                            'Access revocation procedures'
                        ],
                        testing_procedures=[
                            'Review identity management processes',
                            'Test credential lifecycle',
                            'Verify identity verification',
                            'Validate access revocation'
                        ],
                        severity='high',
                        applies_to_environment=True
                    ),
                    'DE.CM-1': ComplianceControl(
                        id='DE.CM-1',
                        framework='NIST_CSF',
                        category=ControlCategory.MONITORING,
                        title='Continuous Monitoring',
                        description='The network is monitored to detect potential cybersecurity events',
                        requirements=[
                            'Deploy network monitoring tools',
                            'Establish baseline network behavior',
                            'Detect anomalous network activity',
                            'Alert on potential security events'
                        ],
                        evidence_requirements=[
                            'Network monitoring tool configuration',
                            'Baseline behavior documentation',
                            'Anomaly detection rules',
                            'Security event alerting procedures'
                        ],
                        testing_procedures=[
                            'Verify monitoring tool deployment',
                            'Review baseline establishment',
                            'Test anomaly detection',
                            'Validate alerting mechanisms'
                        ],
                        severity='high',
                        applies_to_environment=True
                    )
                }
            },
            
            'ISO_27001': {
                'name': 'ISO/IEC 27001:2013',
                'description': 'Information security management systems requirements',
                'categories': ['Information Security Policies', 'Organization of Information Security', 'Human Resource Security', 'Asset Management', 'Access Control', 'Cryptography', 'Physical and Environmental Security', 'Operations Security', 'Communications Security', 'System Acquisition, Development and Maintenance', 'Supplier Relationships', 'Information Security Incident Management', 'Information Security Aspects of Business Continuity Management', 'Compliance'],
                'controls': {
                    'A.9.1.1': ComplianceControl(
                        id='A.9.1.1',
                        framework='ISO_27001',
                        category=ControlCategory.ACCESS_CONTROL,
                        title='Access Control Policy',
                        description='An access control policy shall be established, documented and reviewed',
                        requirements=[
                            'Establish access control policy',
                            'Document policy procedures',
                            'Review policy regularly',
                            'Communicate policy to users'
                        ],
                        evidence_requirements=[
                            'Access control policy document',
                            'Policy review records',
                            'Policy communication records',
                            'User acknowledgment records'
                        ],
                        testing_procedures=[
                            'Review policy documentation',
                            'Verify regular policy review',
                            'Confirm policy communication',
                            'Validate user awareness'
                        ],
                        severity='medium',
                        applies_to_environment=True
                    ),
                    'A.12.6.1': ComplianceControl(
                        id='A.12.6.1',
                        framework='ISO_27001',
                        category=ControlCategory.MONITORING,
                        title='Management of Technical Vulnerabilities',
                        description='Information about technical vulnerabilities shall be obtained in a timely fashion',
                        requirements=[
                            'Establish vulnerability management process',
                            'Monitor vulnerability sources',
                            'Assess vulnerability impact',
                            'Implement timely remediation'
                        ],
                        evidence_requirements=[
                            'Vulnerability management procedures',
                            'Vulnerability monitoring records',
                            'Impact assessment reports',
                            'Remediation tracking records'
                        ],
                        testing_procedures=[
                            'Review vulnerability process',
                            'Verify monitoring activities',
                            'Examine impact assessments',
                            'Validate remediation tracking'
                        ],
                        severity='high',
                        applies_to_environment=True
                    )
                }
            }
        }
        
        return frameworks
    
    def _initialize_threat_mappings(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize threat-to-control mappings."""
        mappings = {
            'code_execution': {
                'SOC2': ['CC6.1', 'CC6.2', 'CC7.1'],
                'PCI_DSS': ['2.1', '8.2', '10.1'],
                'NIST_CSF': ['PR.AC-1', 'DE.CM-1'],
                'ISO_27001': ['A.9.1.1', 'A.12.6.1']
            },
            'file_system': {
                'SOC2': ['CC6.1', 'CC6.2'],
                'PCI_DSS': ['2.1', '10.1'],
                'NIST_CSF': ['PR.AC-1', 'ID.AM-1'],
                'ISO_27001': ['A.9.1.1']
            },
            'network_access': {
                'SOC2': ['CC6.1', 'CC7.1'],
                'PCI_DSS': ['10.1'],
                'NIST_CSF': ['DE.CM-1', 'PR.AC-1'],
                'ISO_27001': ['A.12.6.1']
            },
            'database_access': {
                'SOC2': ['CC6.1', 'CC6.2', 'CC7.1'],
                'PCI_DSS': ['2.1', '8.2', '10.1'],
                'NIST_CSF': ['PR.AC-1', 'DE.CM-1'],
                'ISO_27001': ['A.9.1.1', 'A.12.6.1']
            },
            'authentication': {
                'SOC2': ['CC6.1', 'CC6.2'],
                'PCI_DSS': ['8.2'],
                'NIST_CSF': ['PR.AC-1'],
                'ISO_27001': ['A.9.1.1']
            }
        }
        
        return mappings
    
    def _initialize_environment_mappings(self) -> Dict[str, Dict[str, bool]]:
        """Initialize environment-specific control applicability."""
        mappings = {
            'cloud': {
                'physical_security': False,
                'network_security': True,
                'access_control': True,
                'encryption': True,
                'monitoring': True
            },
            'on_premise': {
                'physical_security': True,
                'network_security': True,
                'access_control': True,
                'encryption': True,
                'monitoring': True
            },
            'hybrid': {
                'physical_security': True,
                'network_security': True,
                'access_control': True,
                'encryption': True,
                'monitoring': True
            }
        }
        
        return mappings
    
    def generate_compliance_assessment(self,
                                     threat_analysis: Dict[str, Any],
                                     environment_context: EnvironmentContext,
                                     target_frameworks: List[str],
                                     current_controls: Optional[Dict[str, Any]] = None) -> List[ComplianceAssessment]:
        """
        Generate comprehensive compliance assessments for target frameworks.
        
        Args:
            threat_analysis: Results from threat analysis
            environment_context: Environment context
            target_frameworks: List of compliance frameworks to assess
            current_controls: Currently implemented controls (optional)
            
        Returns:
            List of compliance assessments for each framework
        """
        assessments = []
        
        try:
            self.logger.info(f"Generating compliance assessments for {len(target_frameworks)} frameworks")
            
            for framework in target_frameworks:
                if framework in self.compliance_frameworks:
                    assessment = self._assess_framework_compliance(
                        framework,
                        threat_analysis,
                        environment_context,
                        current_controls
                    )
                    if assessment:
                        assessments.append(assessment)
                else:
                    self.logger.warning(f"Framework {framework} not supported")
            
            self.logger.info(f"Generated {len(assessments)} compliance assessments")
            return assessments
            
        except Exception as e:
            self.logger.error(f"Error generating compliance assessments: {e}")
            return []
    
    def _assess_framework_compliance(self,
                                   framework: str,
                                   threat_analysis: Dict[str, Any],
                                   environment_context: EnvironmentContext,
                                   current_controls: Optional[Dict[str, Any]]) -> Optional[ComplianceAssessment]:
        """Assess compliance with a specific framework."""
        try:
            framework_def = self.compliance_frameworks[framework]
            controls = framework_def['controls']
            
            # Identify applicable controls
            applicable_controls = self._identify_applicable_controls(
                controls, environment_context, threat_analysis
            )
            
            # Assess each control
            gaps = []
            compliant_count = 0
            
            for control_id, control in applicable_controls.items():
                compliance_status = self._assess_control_compliance(
                    control, threat_analysis, current_controls
                )
                
                if compliance_status == ComplianceStatus.COMPLIANT:
                    compliant_count += 1
                elif compliance_status in [ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIALLY_COMPLIANT]:
                    gap = self._create_compliance_gap(
                        control, compliance_status, threat_analysis
                    )
                    gaps.append(gap)
            
            # Calculate overall compliance
            total_controls = len(applicable_controls)
            compliance_percentage = (compliant_count / total_controls * 100) if total_controls > 0 else 0
            
            # Determine overall status
            if compliance_percentage >= 95:
                overall_status = ComplianceStatus.COMPLIANT
            elif compliance_percentage >= 70:
                overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
            else:
                overall_status = ComplianceStatus.NON_COMPLIANT
            
            # Generate recommendations
            recommendations = self._generate_compliance_recommendations(
                gaps, framework, environment_context
            )
            
            # Create executive summary
            executive_summary = self._create_compliance_executive_summary(
                framework, overall_status, compliance_percentage, len(gaps)
            )
            
            assessment = ComplianceAssessment(
                assessment_id=f"{framework}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                framework=framework,
                assessment_date=datetime.now(),
                overall_status=overall_status,
                compliance_percentage=compliance_percentage,
                total_controls=total_controls,
                compliant_controls=compliant_count,
                non_compliant_controls=total_controls - compliant_count,
                gaps=gaps,
                recommendations=recommendations,
                executive_summary=executive_summary
            )
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error assessing framework {framework}: {e}")
            return None
    
    def _identify_applicable_controls(self,
                                    controls: Dict[str, ComplianceControl],
                                    environment_context: EnvironmentContext,
                                    threat_analysis: Dict[str, Any]) -> Dict[str, ComplianceControl]:
        """Identify controls applicable to the current environment and threats."""
        applicable_controls = {}
        
        for control_id, control in controls.items():
            # Check environment applicability
            if not control.applies_to_environment:
                continue
            
            # Check if control addresses identified threats
            addresses_identified_threats = self._control_addresses_threats(
                control, threat_analysis
            )
            
            if addresses_identified_threats:
                applicable_controls[control_id] = control
        
        return applicable_controls
    
    def _control_addresses_threats(self,
                                 control: ComplianceControl,
                                 threat_analysis: Dict[str, Any]) -> bool:
        """Check if a control addresses identified threats."""
        # Extract threat categories from analysis
        threat_categories = set()
        
        if 'attack_vectors' in threat_analysis:
            for vector in threat_analysis['attack_vectors']:
                category = self._categorize_threat_for_compliance(vector)
                threat_categories.add(category)
        
        if 'risk_indicators' in threat_analysis:
            for indicator in threat_analysis['risk_indicators']:
                category = self._categorize_risk_indicator_for_compliance(indicator)
                threat_categories.add(category)
        
        # Check if control category matches any threat categories
        control_category = control.category.value
        
        # Map control categories to threat categories
        category_mappings = {
            'access_control': ['authentication', 'access_control', 'authorization'],
            'authentication': ['authentication', 'credential_theft'],
            'monitoring': ['code_execution', 'network_access', 'data_access'],
            'system_security': ['code_execution', 'system_compromise'],
            'network_security': ['network_access', 'data_exfiltration'],
            'data_protection': ['data_access', 'database_access', 'file_system']
        }
        
        mapped_categories = category_mappings.get(control_category, [])
        return bool(threat_categories.intersection(mapped_categories))
    
    def _categorize_threat_for_compliance(self, threat: Dict[str, Any]) -> str:
        """Categorize a threat for compliance mapping."""
        threat_name = threat.get('name', '').lower()
        threat_desc = threat.get('description', '').lower()
        
        if any(keyword in threat_name or keyword in threat_desc 
               for keyword in ['auth', 'login', 'credential']):
            return 'authentication'
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['access', 'authorization', 'permission']):
            return 'access_control'
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['code', 'execution', 'command']):
            return 'code_execution'
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['network', 'traffic', 'communication']):
            return 'network_access'
        elif any(keyword in threat_name or keyword in threat_desc 
                 for keyword in ['data', 'file', 'database']):
            return 'data_access'
        else:
            return 'general'
    
    def _categorize_risk_indicator_for_compliance(self, indicator: str) -> str:
        """Categorize a risk indicator for compliance mapping."""
        indicator_lower = indicator.lower()
        
        if any(keyword in indicator_lower 
               for keyword in ['auth', 'login', 'credential']):
            return 'authentication'
        elif any(keyword in indicator_lower 
                 for keyword in ['access', 'permission']):
            return 'access_control'
        elif any(keyword in indicator_lower 
                 for keyword in ['exec', 'command', 'code']):
            return 'code_execution'
        elif any(keyword in indicator_lower 
                 for keyword in ['network', 'traffic']):
            return 'network_access'
        elif any(keyword in indicator_lower 
                 for keyword in ['data', 'file', 'database']):
            return 'data_access'
        else:
            return 'general'
    
    def _assess_control_compliance(self,
                                 control: ComplianceControl,
                                 threat_analysis: Dict[str, Any],
                                 current_controls: Optional[Dict[str, Any]]) -> ComplianceStatus:
        """Assess compliance status for a specific control."""
        # If current controls are provided, check implementation status
        if current_controls and control.id in current_controls:
            control_status = current_controls[control.id]
            if isinstance(control_status, dict):
                implementation_status = control_status.get('status', 'unknown')
                if implementation_status.lower() == 'implemented':
                    return ComplianceStatus.COMPLIANT
                elif implementation_status.lower() == 'partially_implemented':
                    return ComplianceStatus.PARTIALLY_COMPLIANT
                else:
                    return ComplianceStatus.NON_COMPLIANT
        
        # Otherwise, infer from threat analysis
        # This is a simplified heuristic - in practice, detailed control testing would be needed
        control_category = control.category.value
        
        # Check if threats exist that this control should address
        relevant_threats = self._find_relevant_threats(control, threat_analysis)
        
        if relevant_threats:
            # If threats exist that this control should address, assume non-compliance
            return ComplianceStatus.NON_COMPLIANT
        else:
            # If no relevant threats found, assume partial compliance
            return ComplianceStatus.PARTIALLY_COMPLIANT
    
    def _find_relevant_threats(self,
                             control: ComplianceControl,
                             threat_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find threats relevant to a specific control."""
        relevant_threats = []
        
        control_category = control.category.value
        
        if 'attack_vectors' in threat_analysis:
            for vector in threat_analysis['attack_vectors']:
                threat_category = self._categorize_threat_for_compliance(vector)
                
                # Map control categories to threat categories they should address
                if ((control_category == 'access_control' and threat_category in ['authentication', 'access_control']) or
                    (control_category == 'authentication' and threat_category == 'authentication') or
                    (control_category == 'monitoring' and threat_category in ['code_execution', 'network_access', 'data_access']) or
                    (control_category == 'system_security' and threat_category == 'code_execution')):
                    relevant_threats.append(vector)
        
        return relevant_threats
    
    def _create_compliance_gap(self,
                             control: ComplianceControl,
                             compliance_status: ComplianceStatus,
                             threat_analysis: Dict[str, Any]) -> ComplianceGap:
        """Create a compliance gap record."""
        relevant_threats = self._find_relevant_threats(control, threat_analysis)
        
        # Generate gap description
        gap_description = f"Control {control.id} ({control.title}) is not fully implemented. "
        if relevant_threats:
            gap_description += f"This control should address {len(relevant_threats)} identified threat(s)."
        
        # Determine risk level based on control severity and number of threats
        risk_level = 'medium'
        if control.severity == 'critical' or len(relevant_threats) > 2:
            risk_level = 'high'
        elif control.severity == 'low' and len(relevant_threats) <= 1:
            risk_level = 'low'
        
        # Generate remediation recommendations
        remediation_recommendations = [
            f"Implement the requirements specified in {control.id}",
            "Conduct gap analysis to identify specific implementation needs",
            "Develop implementation plan with timeline and resources",
            "Test control effectiveness after implementation"
        ]
        
        # Add control-specific recommendations
        if control.category == ControlCategory.ACCESS_CONTROL:
            remediation_recommendations.append("Review and update access control policies")
        elif control.category == ControlCategory.MONITORING:
            remediation_recommendations.append("Deploy monitoring tools and establish alerting")
        elif control.category == ControlCategory.AUTHENTICATION:
            remediation_recommendations.append("Implement multi-factor authentication")
        
        gap = ComplianceGap(
            control_id=control.id,
            framework=control.framework,
            gap_description=gap_description,
            current_status=compliance_status,
            required_status=ComplianceStatus.COMPLIANT,
            risk_level=risk_level,
            remediation_recommendations=remediation_recommendations,
            estimated_effort=self._estimate_remediation_effort(control),
            business_impact=self._assess_business_impact(control, relevant_threats)
        )
        
        return gap
    
    def _estimate_remediation_effort(self, control: ComplianceControl) -> str:
        """Estimate effort required to remediate a compliance gap."""
        effort_map = {
            'low': 'Low (2-4 weeks)',
            'medium': 'Medium (1-3 months)', 
            'high': 'High (3-6 months)',
            'critical': 'High (3-6 months)'
        }
        
        return effort_map.get(control.severity, 'Medium (1-3 months)')
    
    def _assess_business_impact(self,
                              control: ComplianceControl,
                              relevant_threats: List[Dict[str, Any]]) -> str:
        """Assess business impact of compliance gap."""
        if control.severity == 'critical' or len(relevant_threats) > 3:
            return 'High - Significant risk of regulatory penalties, business disruption, and reputational damage'
        elif control.severity == 'high' or len(relevant_threats) > 1:
            return 'Medium - Moderate risk of compliance violations and potential security incidents'
        else:
            return 'Low - Minor compliance gap with limited immediate business impact'
    
    def _generate_compliance_recommendations(self,
                                           gaps: List[ComplianceGap],
                                           framework: str,
                                           environment_context: EnvironmentContext) -> List[str]:
        """Generate overall compliance recommendations."""
        recommendations = []
        
        # High-level recommendations
        if gaps:
            high_risk_gaps = [gap for gap in gaps if gap.risk_level == 'high']
            if high_risk_gaps:
                recommendations.append(
                    f"Prioritize remediation of {len(high_risk_gaps)} high-risk compliance gaps"
                )
            
            recommendations.append(
                f"Develop comprehensive compliance program for {framework}"
            )
            recommendations.append(
                "Assign dedicated compliance officer or team"
            )
            recommendations.append(
                "Implement regular compliance monitoring and reporting"
            )
        
        # Framework-specific recommendations
        if framework == 'SOC2':
            recommendations.extend([
                "Engage qualified auditor for SOC 2 examination",
                "Implement comprehensive access controls and monitoring",
                "Establish incident response procedures"
            ])
        elif framework == 'PCI_DSS':
            recommendations.extend([
                "Conduct annual PCI DSS assessment",
                "Implement network segmentation for card data environment",
                "Establish vulnerability management program"
            ])
        elif framework == 'NIST_CSF':
            recommendations.extend([
                "Adopt NIST Cybersecurity Framework implementation tiers",
                "Develop cybersecurity risk management strategy",
                "Establish continuous improvement process"
            ])
        
        # Environment-specific recommendations
        if environment_context.deployment_type == DeploymentType.CLOUD:
            recommendations.append(
                "Leverage cloud-native security services for compliance controls"
            )
        elif environment_context.deployment_type == DeploymentType.ON_PREMISE:
            recommendations.append(
                "Implement comprehensive on-premise security infrastructure"
            )
        
        return recommendations
    
    def _create_compliance_executive_summary(self,
                                           framework: str,
                                           overall_status: ComplianceStatus,
                                           compliance_percentage: float,
                                           gap_count: int) -> str:
        """Create executive summary for compliance assessment."""
        framework_name = self.compliance_frameworks[framework]['name']
        
        summary = f"Compliance Assessment: {framework_name}\n\n"
        summary += f"Overall Status: {overall_status.value.replace('_', ' ').title()}\n"
        summary += f"Compliance Level: {compliance_percentage:.1f}%\n"
        summary += f"Identified Gaps: {gap_count}\n\n"
        
        if overall_status == ComplianceStatus.COMPLIANT:
            summary += "The organization demonstrates strong compliance with the framework requirements. "
            summary += "Continue monitoring and maintaining current controls."
        elif overall_status == ComplianceStatus.PARTIALLY_COMPLIANT:
            summary += f"The organization has implemented most controls but {gap_count} gaps require attention. "
            summary += "Focus on addressing high-risk gaps to achieve full compliance."
        else:
            summary += f"Significant compliance gaps exist that require immediate attention. "
            summary += f"A comprehensive remediation program is needed to address {gap_count} control gaps."
        
        return summary
    
    def map_threats_to_controls(self,
                              threat_analysis: Dict[str, Any],
                              frameworks: List[str]) -> Dict[str, Dict[str, List[str]]]:
        """
        Map identified threats to specific compliance controls.
        
        Args:
            threat_analysis: Results from threat analysis
            frameworks: List of compliance frameworks
            
        Returns:
            Dictionary mapping frameworks to threat-control mappings
        """
        mappings = {}
        
        try:
            for framework in frameworks:
                if framework in self.threat_control_mappings:
                    framework_mappings = {}
                    
                    # Extract threat categories from analysis
                    threat_categories = self._extract_threat_categories(threat_analysis)
                    
                    for threat_category in threat_categories:
                        if threat_category in self.threat_control_mappings[framework]:
                            framework_mappings[threat_category] = self.threat_control_mappings[framework][threat_category]
                    
                    mappings[framework] = framework_mappings
            
            return mappings
            
        except Exception as e:
            self.logger.error(f"Error mapping threats to controls: {e}")
            return {}
    
    def _extract_threat_categories(self, threat_analysis: Dict[str, Any]) -> Set[str]:
        """Extract threat categories from threat analysis."""
        categories = set()
        
        if 'attack_vectors' in threat_analysis:
            for vector in threat_analysis['attack_vectors']:
                category = self._categorize_threat_for_compliance(vector)
                categories.add(category)
        
        if 'risk_indicators' in threat_analysis:
            for indicator in threat_analysis['risk_indicators']:
                category = self._categorize_risk_indicator_for_compliance(indicator)
                categories.add(category)
        
        return categories
    
    def generate_compliance_roadmap(self,
                                  assessments: List[ComplianceAssessment],
                                  environment_context: EnvironmentContext) -> Dict[str, Any]:
        """Generate compliance implementation roadmap."""
        roadmap = {
            'phases': [],
            'total_duration': '12-24 months',
            'frameworks': [assessment.framework for assessment in assessments],
            'priority_actions': [],
            'resource_requirements': [],
            'success_metrics': []
        }
        
        # Collect all gaps across frameworks
        all_gaps = []
        for assessment in assessments:
            all_gaps.extend(assessment.gaps)
        
        # Prioritize gaps
        high_priority_gaps = [gap for gap in all_gaps if gap.risk_level == 'high']
        medium_priority_gaps = [gap for gap in all_gaps if gap.risk_level == 'medium']
        low_priority_gaps = [gap for gap in all_gaps if gap.risk_level == 'low']
        
        # Create phases
        if high_priority_gaps:
            roadmap['phases'].append({
                'phase': 1,
                'name': 'Critical Compliance Gaps',
                'duration': '0-6 months',
                'gaps': len(high_priority_gaps),
                'focus': 'Address high-risk compliance gaps to reduce immediate regulatory risk'
            })
        
        if medium_priority_gaps:
            roadmap['phases'].append({
                'phase': 2,
                'name': 'Standard Compliance Controls',
                'duration': '6-12 months',
                'gaps': len(medium_priority_gaps),
                'focus': 'Implement standard compliance controls to achieve substantial compliance'
            })
        
        if low_priority_gaps:
            roadmap['phases'].append({
                'phase': 3,
                'name': 'Compliance Optimization',
                'duration': '12-24 months',
                'gaps': len(low_priority_gaps),
                'focus': 'Optimize compliance posture and prepare for audit activities'
            })
        
        # Priority actions
        roadmap['priority_actions'] = [
            f"Address {len(high_priority_gaps)} high-risk compliance gaps immediately",
            "Assign dedicated compliance team and budget",
            "Engage external compliance consultants if needed",
            "Establish compliance monitoring and reporting processes"
        ]
        
        # Success metrics
        total_gaps = len(all_gaps)
        roadmap['success_metrics'] = [
            f"Achieve 95%+ compliance across all {len(assessments)} frameworks",
            f"Remediate {total_gaps} identified compliance gaps",
            "Pass external compliance audits",
            "Maintain continuous compliance monitoring"
        ]
        
        return roadmap 