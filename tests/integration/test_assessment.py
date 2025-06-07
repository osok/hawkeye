"""
Integration tests for risk assessment pipeline.

These tests verify the complete assessment workflow from detection results
through various assessment modules to final remediation recommendations.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch

from src.hawkeye.assessment import (
    RiskAssessment, AssessmentResult, SecurityFinding, VulnerabilityInfo,
    RiskLevel, VulnerabilityCategory, ComplianceFramework,
    ConfigurationAnalyzer, DefaultConfigurationDetector, AuthenticationAnalyzer,
    CVSSCalculator, RemediationEngine, generate_remediation_plan
)
from src.hawkeye.assessment.base import CVSSVector
from src.hawkeye.assessment.transport_security import TransportSecurityAssessor
from src.hawkeye.assessment.compliance import ComplianceChecker
from src.hawkeye.detection.base import (
    DetectionResult, MCPServerInfo, TransportType, ProcessInfo, DetectionMethod
)


class TestRiskAssessmentPipeline:
    """Integration tests for complete risk assessment pipeline."""
    
    @pytest.fixture
    def sample_detection_result(self):
        """Create a comprehensive detection result for testing."""
        server_info = MCPServerInfo(
            host="mcp.example.com",
            port=3000,
            transport_type=TransportType.HTTP,
            version="1.0.0",
            capabilities=["tools", "resources"],
            security_config={"tls": False, "secure": False}
        )
        
        process_info = ProcessInfo(
            pid=12345,
            name="node",
            cmdline=["node", "server.js", "--port", "3000", "--debug"],
            user="www-data",
            cwd="/opt/mcp-server",
            env_vars={
                "NODE_ENV": "development",
                "DEBUG": "true",
                "API_KEY": "default-key-123",
                "DB_PASSWORD": "admin123"
            }
        )
        
        # Set the process info on the server
        server_info.process_info = process_info
        
        return DetectionResult(
            target_host="mcp.example.com",
            detection_method=DetectionMethod.TRANSPORT_DETECTION,
            success=True,
            mcp_server=server_info,
            confidence=0.9,
            scan_duration=45.2,
            raw_data={
                "scan_timestamp": 1234567890,
                "scan_duration": 45.2,
                "network_info": {
                    "open_ports": [3000, 22, 80],
                    "services": {
                        "3000": "mcp-server",
                        "22": "ssh",
                        "80": "nginx"
                    }
                },
                "security_config": {
                    "authentication": {"enabled": False, "method": None},
                    "encryption": {"tls_enabled": False, "version": None},
                    "cors": {"enabled": True, "origins": ["*"]},
                    "rate_limiting": {"enabled": False}
                }
            }
        )
    
    @pytest.fixture
    def temp_config_file(self):
        """Create a temporary configuration file for testing."""
        config_data = {
            "server": {
                "port": 3000,
                "host": "0.0.0.0",
                "debug": True
            },
            "authentication": {
                "enabled": False,
                "api_key": "default-key-123"
            },
            "database": {
                "host": "localhost",
                "user": "admin",
                "password": "admin123"
            },
            "cors": {
                "origins": ["*"],
                "credentials": True
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f, indent=2)
            temp_path = f.name
        
        yield temp_path
        
        # Cleanup
        Path(temp_path).unlink(missing_ok=True)
    
    def test_complete_assessment_workflow(self, sample_detection_result, temp_config_file):
        """Test complete assessment workflow from detection to remediation."""
        # Update detection result with temp config file
        sample_detection_result.raw_data['configuration_files'] = [temp_config_file]
        
        # Step 1: Configuration Analysis
        config_analyzer = ConfigurationAnalyzer()
        config_assessment = config_analyzer.assess(sample_detection_result)
        
        assert isinstance(config_assessment, AssessmentResult)
        assert config_assessment.target_host == "mcp.example.com"
        assert len(config_assessment.findings) > 0
        
        # Should detect insecure configurations
        config_findings = [f for f in config_assessment.findings 
                          if f.category == VulnerabilityCategory.CONFIGURATION]
        assert len(config_findings) > 0
        
        # Step 2: Default Configuration Detection
        default_detector = DefaultConfigurationDetector()
        default_assessment = default_detector.assess(sample_detection_result)
        
        assert isinstance(default_assessment, AssessmentResult)
        assert len(default_assessment.findings) > 0
        
        # Should detect default configurations
        default_findings = [f for f in default_assessment.findings 
                           if "default" in f.title.lower()]
        assert len(default_findings) > 0
        
        # Step 3: Authentication Analysis
        auth_analyzer = AuthenticationAnalyzer()
        auth_assessment = auth_analyzer.assess(sample_detection_result)
        
        assert isinstance(auth_assessment, AssessmentResult)
        assert len(auth_assessment.findings) > 0
        
        # Should detect authentication issues
        auth_findings = [f for f in auth_assessment.findings 
                        if f.category == VulnerabilityCategory.AUTHENTICATION]
        assert len(auth_findings) > 0
        
        # Step 4: Transport Security Analysis
        transport_analyzer = TransportSecurityAssessor()
        transport_assessment = transport_analyzer.assess(sample_detection_result)
        
        assert isinstance(transport_assessment, AssessmentResult)
        assert len(transport_assessment.findings) > 0
        
        # Should detect transport security issues
        transport_findings = [f for f in transport_assessment.findings 
                             if f.category == VulnerabilityCategory.ENCRYPTION]
        assert len(transport_findings) > 0
        
        # Step 5: Compliance Assessment
        compliance_assessor = ComplianceChecker()
        compliance_assessment = compliance_assessor.assess(sample_detection_result)
        
        assert isinstance(compliance_assessment, AssessmentResult)
        # May or may not have findings depending on compliance requirements
        
        # Step 6: Aggregate All Assessments
        all_assessments = [
            config_assessment,
            default_assessment,
            auth_assessment,
            transport_assessment,
            compliance_assessment
        ]
        
        # Aggregate findings
        all_findings = []
        for assessment in all_assessments:
            all_findings.extend(assessment.findings)
        
        assert len(all_findings) > 0
        
        # Step 7: Generate Remediation Plan
        remediation_plan = generate_remediation_plan(all_assessments)
        
        assert remediation_plan.target_host == "mcp.example.com"
        assert len(remediation_plan.actions) > 0
        assert remediation_plan.total_estimated_effort > 0
        assert remediation_plan.total_risk_reduction > 0
        assert remediation_plan.executive_summary != ""
        
        # Verify remediation plan addresses key issues
        action_titles = [action.title for action in remediation_plan.actions]
        
        # Should have authentication-related actions
        auth_actions = [title for title in action_titles if "auth" in title.lower()]
        assert len(auth_actions) > 0
        
        # Should have encryption-related actions
        encryption_actions = [title for title in action_titles if "tls" in title.lower() or "encrypt" in title.lower()]
        assert len(encryption_actions) > 0
        
        # Should have configuration-related actions
        config_actions = [title for title in action_titles if "config" in title.lower() or "default" in title.lower()]
        assert len(config_actions) > 0
    
    def test_risk_assessment_aggregation(self, sample_detection_result):
        """Test aggregation of multiple assessment results."""
        # Create multiple assessments
        assessments = []
        
        # Configuration assessment
        config_analyzer = ConfigurationAnalyzer()
        config_result = config_analyzer.assess(sample_detection_result)
        assessments.append(config_result)
        
        # Authentication assessment
        auth_analyzer = AuthenticationAnalyzer()
        auth_result = auth_analyzer.assess(sample_detection_result)
        assessments.append(auth_result)
        
        # Transport security assessment
        transport_analyzer = TransportSecurityAssessor()
        transport_result = transport_analyzer.assess(sample_detection_result)
        assessments.append(transport_result)
        
        # Create risk assessment aggregator
        risk_assessment = RiskAssessment()
        
        # Add all results
        for result in assessments:
            risk_assessment.add_result(result)
        
        # Verify aggregation
        assert len(risk_assessment.results) == len(assessments)
        
        # Test filtering by risk level
        high_risk_results = risk_assessment.get_results_by_risk_level(RiskLevel.HIGH)
        assert isinstance(high_risk_results, list)
        
        critical_risk_results = risk_assessment.get_results_by_risk_level(RiskLevel.CRITICAL)
        assert isinstance(critical_risk_results, list)
        
        # Test high risk targets
        high_risk_targets = risk_assessment.get_high_risk_targets()
        assert isinstance(high_risk_targets, list)
        
        # Test overall statistics
        stats = risk_assessment.get_overall_statistics()
        assert isinstance(stats, dict)
        assert "total_results" in stats
        assert "risk_distribution" in stats
        assert "finding_categories" in stats
        assert stats["total_results"] == len(assessments)
    
    def test_cvss_scoring_integration(self, sample_detection_result):
        """Test CVSS scoring integration with assessment pipeline."""
        # Create assessment with CVSS-scored vulnerabilities
        config_analyzer = ConfigurationAnalyzer()
        assessment_result = config_analyzer.assess(sample_detection_result)
        
        # Create CVSS calculator
        cvss_calculator = CVSSCalculator()
        
        # Add CVSS scores to findings
        for finding in assessment_result.findings:
            if finding.severity == RiskLevel.CRITICAL:
                # Create high-impact CVSS vector
                cvss_vector = CVSSVector(
                    attack_vector="N",  # Network
                    attack_complexity="L",  # Low
                    privileges_required="N",  # None
                    user_interaction="N",  # None
                    scope="C",  # Changed
                    confidentiality="H",  # High
                    integrity="H",  # High
                    availability="H"  # High
                )
                
                scores = cvss_calculator.calculate_scores(cvss_vector)
                
                # Create vulnerability info with CVSS
                vuln_info = VulnerabilityInfo(
                    id=f"CVE-2024-{finding.id[-4:]}",
                    title=finding.title,
                    description=finding.description,
                    category=finding.category,
                    severity=finding.severity,
                    cvss_vector=cvss_vector,
                    cvss_score=scores.base_score,
                    cwe_id="CWE-287",  # Improper Authentication
                    exploit_available=True,
                    patch_available=False
                )
                
                finding.vulnerability_info = vuln_info
                assessment_result.vulnerabilities.append(vuln_info)
        
        # Verify CVSS integration
        cvss_vulnerabilities = [v for v in assessment_result.vulnerabilities if v.cvss_score is not None]
        assert len(cvss_vulnerabilities) > 0
        
        # Verify exploitable vulnerabilities are identified
        exploitable_vulns = assessment_result.exploitable_vulnerabilities
        assert len(exploitable_vulns) > 0
        
        # Verify unpatched vulnerabilities are identified
        unpatched_vulns = assessment_result.unpatched_vulnerabilities
        assert len(unpatched_vulns) > 0
    
    def test_compliance_framework_integration(self, sample_detection_result):
        """Test compliance framework integration."""
        # Run compliance assessment
        compliance_assessor = ComplianceChecker()
        compliance_result = compliance_assessor.assess(sample_detection_result)
        
        # Verify compliance status tracking
        assert isinstance(compliance_result.compliance_status, dict)
        
        # Check for compliance violations
        compliance_violations = compliance_result.get_compliance_violations()
        assert isinstance(compliance_violations, dict)
        
        # Verify compliance frameworks are represented
        for framework in ComplianceFramework:
            if framework in compliance_violations:
                violations = compliance_violations[framework]
                assert isinstance(violations, list)
                
                # Each violation should reference the framework
                for violation in violations:
                    assert framework in violation.compliance_violations
    
    def test_assessment_error_handling(self, sample_detection_result):
        """Test error handling in assessment pipeline."""
        # Test with invalid detection result
        invalid_result = DetectionResult(target_host="invalid.host")
        
        # Configuration analysis should handle gracefully
        config_analyzer = ConfigurationAnalyzer()
        config_assessment = config_analyzer.assess(invalid_result)
        
        # Should return valid result even with minimal data
        assert isinstance(config_assessment, AssessmentResult)
        assert config_assessment.target_host == "invalid.host"
        
        # Test with corrupted configuration file
        sample_detection_result.raw_data['configuration_files'] = ["/nonexistent/config.json"]
        
        # Should handle missing files gracefully
        default_detector = DefaultConfigurationDetector()
        default_assessment = default_detector.assess(sample_detection_result)
        
        assert isinstance(default_assessment, AssessmentResult)
        # May have fewer findings but should not crash
    
    def test_performance_with_large_dataset(self):
        """Test assessment pipeline performance with larger datasets."""
        # Create multiple detection results
        detection_results = []
        
        for i in range(10):  # Simulate 10 different hosts
            server_info = MCPServerInfo(
                host=f"mcp{i}.example.com",
                port=3000 + i,
                transport_type=TransportType.HTTP,
                authentication_required=False,
                tls_enabled=False
            )
            
            detection_result = DetectionResult(
                target_host=f"mcp{i}.example.com",
                servers=[server_info],
                processes=[],
                configuration_files=[],
                docker_containers=[]
            )
            
            detection_results.append(detection_result)
        
        # Run assessments on all results
        all_assessments = []
        
        for detection_result in detection_results:
            # Run basic configuration analysis
            config_analyzer = ConfigurationAnalyzer()
            assessment = config_analyzer.assess(detection_result)
            all_assessments.append(assessment)
        
        # Verify all assessments completed
        assert len(all_assessments) == 10
        
        # Generate remediation plans for all
        remediation_plans = []
        for assessment in all_assessments:
            plan = generate_remediation_plan([assessment])
            remediation_plans.append(plan)
        
        # Verify all plans generated
        assert len(remediation_plans) == 10
        
        # Verify each plan has appropriate content
        for plan in remediation_plans:
            assert plan.target_host.startswith("mcp")
            assert plan.target_host.endswith(".example.com")
            # May have minimal actions but should be valid
            assert plan.total_estimated_effort >= 0
            assert plan.total_risk_reduction >= 0
    
    def test_assessment_data_serialization(self, sample_detection_result):
        """Test serialization of assessment results."""
        # Run assessment
        config_analyzer = ConfigurationAnalyzer()
        assessment_result = config_analyzer.assess(sample_detection_result)
        
        # Test to_dict serialization
        result_dict = assessment_result.to_dict()
        
        # Verify structure
        assert isinstance(result_dict, dict)
        assert "target_host" in result_dict
        assert "assessment_timestamp" in result_dict
        assert "overall_risk_level" in result_dict
        assert "overall_risk_score" in result_dict
        assert "findings" in result_dict
        assert "vulnerabilities" in result_dict
        assert "compliance_status" in result_dict
        assert "recommendations" in result_dict
        
        # Verify findings structure
        assert isinstance(result_dict["findings"], list)
        if result_dict["findings"]:
            finding = result_dict["findings"][0]
            assert "id" in finding
            assert "title" in finding
            assert "description" in finding
            assert "category" in finding
            assert "severity" in finding
            assert "confidence" in finding
            assert "risk_score" in finding
        
        # Test JSON serialization
        import json
        json_str = json.dumps(result_dict)
        assert isinstance(json_str, str)
        
        # Test deserialization
        deserialized = json.loads(json_str)
        assert deserialized["target_host"] == assessment_result.target_host
    
    def test_remediation_plan_serialization(self, sample_detection_result):
        """Test serialization of remediation plans."""
        # Generate assessment and remediation plan
        config_analyzer = ConfigurationAnalyzer()
        assessment_result = config_analyzer.assess(sample_detection_result)
        
        remediation_plan = generate_remediation_plan([assessment_result])
        
        # Test plan serialization (manual since no built-in to_dict)
        plan_dict = {
            "target_host": remediation_plan.target_host,
            "plan_timestamp": remediation_plan.plan_timestamp,
            "total_estimated_effort": remediation_plan.total_estimated_effort,
            "total_risk_reduction": remediation_plan.total_risk_reduction,
            "executive_summary": remediation_plan.executive_summary,
            "actions": [
                {
                    "id": action.id,
                    "title": action.title,
                    "description": action.description,
                    "category": action.category.value,
                    "priority": action.priority.value,
                    "complexity": action.complexity.value,
                    "estimated_effort_hours": action.estimated_effort_hours,
                    "risk_reduction": action.risk_reduction,
                    "implementation_steps": action.implementation_steps,
                    "verification_steps": action.verification_steps,
                    "timeline_estimate": action.timeline_estimate
                }
                for action in remediation_plan.actions
            ],
            "quick_wins": remediation_plan.quick_wins,
            "long_term_actions": remediation_plan.long_term_actions,
            "implementation_phases": remediation_plan.implementation_phases
        }
        
        # Verify structure
        assert isinstance(plan_dict, dict)
        assert plan_dict["target_host"] == remediation_plan.target_host
        assert isinstance(plan_dict["actions"], list)
        
        # Test JSON serialization
        import json
        json_str = json.dumps(plan_dict)
        assert isinstance(json_str, str)
        
        # Test deserialization
        deserialized = json.loads(json_str)
        assert deserialized["target_host"] == remediation_plan.target_host


class TestAssessmentModuleInteraction:
    """Test interactions between different assessment modules."""
    
    @pytest.fixture
    def multi_issue_detection_result(self):
        """Create detection result with multiple types of issues."""
        server_info = MCPServerInfo(
            host="vulnerable.example.com",
            port=3000,
            transport_type=TransportType.HTTP,
            authentication_required=False,
            tls_enabled=False,
            server_name="vulnerable-mcp"
        )
        
        process_info = ProcessInfo(
            pid=12345,
            command_line="node server.js --debug --cors-origin=*",
            user="root",  # Running as root - security issue
            environment_variables={
                "NODE_ENV": "development",
                "DEBUG": "true",
                "API_KEY": "12345",  # Weak API key
                "JWT_SECRET": "secret",  # Weak JWT secret
                "DB_PASSWORD": "password"  # Weak password
            }
        )
        
        return DetectionResult(
            target_host="vulnerable.example.com",
            servers=[server_info],
            processes=[process_info],
            raw_data={
                "security_config": {
                    "authentication": {"enabled": False},
                    "encryption": {"tls_enabled": False},
                    "cors": {"origins": ["*"]},
                    "rate_limiting": {"enabled": False},
                    "debug_mode": {"enabled": True}
                }
            }
        )
    
    def test_cross_module_finding_correlation(self, multi_issue_detection_result):
        """Test how findings from different modules correlate."""
        # Run multiple assessments
        config_analyzer = ConfigurationAnalyzer()
        config_result = config_analyzer.assess(multi_issue_detection_result)
        
        auth_analyzer = AuthenticationAnalyzer()
        auth_result = auth_analyzer.assess(multi_issue_detection_result)
        
        transport_analyzer = TransportSecurityAnalyzer()
        transport_result = transport_analyzer.assess(multi_issue_detection_result)
        
        default_detector = DefaultConfigurationDetector()
        default_result = default_detector.assess(multi_issue_detection_result)
        
        # Collect all findings
        all_findings = []
        all_findings.extend(config_result.findings)
        all_findings.extend(auth_result.findings)
        all_findings.extend(transport_result.findings)
        all_findings.extend(default_result.findings)
        
        # Analyze finding categories
        categories = {}
        for finding in all_findings:
            category = finding.category
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        # Should have findings in multiple categories
        assert len(categories) > 1
        
        # Should have authentication issues
        assert VulnerabilityCategory.AUTHENTICATION in categories
        auth_findings = categories[VulnerabilityCategory.AUTHENTICATION]
        assert len(auth_findings) > 0
        
        # Should have configuration issues
        assert VulnerabilityCategory.CONFIGURATION in categories
        config_findings = categories[VulnerabilityCategory.CONFIGURATION]
        assert len(config_findings) > 0
        
        # Should have encryption/transport issues
        if VulnerabilityCategory.ENCRYPTION in categories:
            encryption_findings = categories[VulnerabilityCategory.ENCRYPTION]
            assert len(encryption_findings) > 0
    
    def test_remediation_action_deduplication(self, multi_issue_detection_result):
        """Test that remediation engine properly handles overlapping issues."""
        # Run multiple assessments
        assessments = []
        
        config_analyzer = ConfigurationAnalyzer()
        assessments.append(config_analyzer.assess(multi_issue_detection_result))
        
        auth_analyzer = AuthenticationAnalyzer()
        assessments.append(auth_analyzer.assess(multi_issue_detection_result))
        
        transport_analyzer = TransportSecurityAnalyzer()
        assessments.append(transport_analyzer.assess(multi_issue_detection_result))
        
        # Generate remediation plan
        remediation_plan = generate_remediation_plan(assessments)
        
        # Verify plan consolidates related actions
        assert len(remediation_plan.actions) > 0
        
        # Check for logical action grouping
        action_categories = {}
        for action in remediation_plan.actions:
            category = action.category
            if category not in action_categories:
                action_categories[category] = []
            action_categories[category].append(action)
        
        # Should have actions in multiple categories
        assert len(action_categories) > 1
        
        # Verify no duplicate actions (same title)
        action_titles = [action.title for action in remediation_plan.actions]
        unique_titles = set(action_titles)
        
        # Should not have exact duplicates
        # (Some similar actions are expected, but not identical ones)
        duplicate_ratio = len(action_titles) / len(unique_titles)
        assert duplicate_ratio <= 1.5  # Allow some similarity but not excessive duplication
    
    def test_assessment_priority_handling(self, multi_issue_detection_result):
        """Test that assessment results properly prioritize critical issues."""
        # Run comprehensive assessment
        assessments = []
        
        # Add assessments that should find critical issues
        config_analyzer = ConfigurationAnalyzer()
        assessments.append(config_analyzer.assess(multi_issue_detection_result))
        
        auth_analyzer = AuthenticationAnalyzer()
        assessments.append(auth_analyzer.assess(multi_issue_detection_result))
        
        transport_analyzer = TransportSecurityAnalyzer()
        assessments.append(transport_analyzer.assess(multi_issue_detection_result))
        
        # Collect findings by severity
        severity_counts = {level: 0 for level in RiskLevel}
        
        for assessment in assessments:
            for finding in assessment.findings:
                severity_counts[finding.severity] += 1
        
        # Should have findings of various severities
        total_findings = sum(severity_counts.values())
        assert total_findings > 0
        
        # Should prioritize critical/high issues appropriately
        critical_and_high = severity_counts[RiskLevel.CRITICAL] + severity_counts[RiskLevel.HIGH]
        
        # With the vulnerable configuration, should have some high-priority findings
        assert critical_and_high > 0
        
        # Generate remediation plan and verify prioritization
        remediation_plan = generate_remediation_plan(assessments)
        
        # Should have immediate or high priority actions
        immediate_actions = remediation_plan.immediate_actions
        high_priority_actions = remediation_plan.high_priority_actions
        
        priority_actions = len(immediate_actions) + len(high_priority_actions)
        assert priority_actions > 0
        
        # Implementation phases should start with high priority
        if remediation_plan.implementation_phases:
            first_phase = remediation_plan.implementation_phases[0]
            assert len(first_phase) > 0  # Should have actions in first phase 