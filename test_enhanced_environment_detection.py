#!/usr/bin/env python3
"""
Test script for enhanced environment detection system (F3.2)

This script demonstrates the capabilities of the enhanced EnvironmentDetector
and ThreatContextBuilder integration.
"""

import sys
import os
import json
from datetime import datetime

# Add the source directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from hawkeye.detection.ai_threat.capability_analyzer import EnvironmentDetector, ThreatContextBuilder, SystemInfo
from hawkeye.detection.mcp_introspection.models import MCPServerInfo
from hawkeye.detection.ai_threat.models import DeploymentType, SecurityPosture, DataSensitivity


def create_mock_mcp_servers():
    """Create mock MCP servers for testing."""
    mock_servers = [
        MCPServerInfo(
            server_id="test_server_1",
            host="localhost",
            port=8080,
            transport_type=None,
            is_secure=False,
            has_authentication=False,
            metadata={"name": "development_server", "environment": "dev"}
        ),
        MCPServerInfo(
            server_id="test_server_2", 
            host="api.example.com",
            port=443,
            transport_type=None,
            is_secure=True,
            has_authentication=True,
            metadata={"name": "production_api", "environment": "prod", "cloud": "aws"}
        ),
        MCPServerInfo(
            server_id="test_server_3",
            host="127.0.0.1",
            port=3000,
            transport_type=None,
            is_secure=False,
            has_authentication=False,
            metadata={"name": "docker_service", "container": "docker"}
        )
    ]
    return mock_servers


def test_environment_detector():
    """Test the EnvironmentDetector class."""
    print("=" * 60)
    print("TESTING ENHANCED ENVIRONMENT DETECTION SYSTEM (F3.2)")
    print("=" * 60)
    
    # Initialize components
    detector = EnvironmentDetector()
    mock_servers = create_mock_mcp_servers()
    
    print(f"Testing with {len(mock_servers)} mock MCP servers")
    print()
    
    # Gather system info
    print("1. Gathering system information...")
    system_info = SystemInfo.gather_system_info()
    print(f"   Platform: {system_info.platform}")
    print(f"   Python: {system_info.python_version}")
    print(f"   Memory: {system_info.memory_total / (1024**3):.1f} GB")
    print(f"   CPU cores: {system_info.cpu_count}")
    print(f"   Network interfaces: {len(system_info.network_interfaces)}")
    print(f"   Running processes: {len(system_info.running_processes)}")
    print()
    
    # Test comprehensive environment detection
    print("2. Running comprehensive environment detection...")
    detection_results = detector.detect_comprehensive_environment(mock_servers, system_info)
    
    print(f"   Detection confidence: {detection_results['detection_confidence']:.2f}")
    print()
    
    # Display infrastructure analysis
    print("3. Infrastructure Analysis:")
    infra = detection_results['infrastructure']
    print(f"   Platform type: {infra['platform_type']}")
    print(f"   Cloud provider: {infra.get('cloud_provider', 'None')}")
    print(f"   Virtualization detected: {infra['virtualization']['detected']}")
    if infra['virtualization']['detected']:
        print(f"   Virtualization type: {infra['virtualization']['type']}")
    print(f"   Container runtime detected: {infra['container_runtime']['detected']}")
    if infra['container_runtime']['detected']:
        print(f"   Container types: {', '.join(infra['container_runtime']['types'])}")
    print()
    
    # Display security environment
    print("4. Security Environment Analysis:")
    security = detection_results['security_environment']
    print(f"   Security posture: {security['security_posture']}")
    print(f"   Security maturity: {security['security_maturity']}")
    print(f"   EDR solutions: {len(security['edr_solutions'])}")
    print(f"   SIEM agents: {len(security['siem_agents'])}")
    print(f"   Vulnerability scanners: {len(security['vulnerability_scanners'])}")
    print(f"   Monitoring capabilities: {', '.join(security['monitoring_capabilities']) if security['monitoring_capabilities'] else 'None'}")
    print()
    
    # Display network architecture
    print("5. Network Architecture:")
    network = detection_results['network_architecture']
    print(f"   Network topology: {network['network_topology']}")
    print(f"   Exposure level: {network['exposure_level']}")
    print(f"   VPN detected: {network['network_security']['vpn_detected']}")
    print(f"   Proxy detected: {network['network_security']['proxy_detected']}")
    print(f"   Load balancer: {network['network_security']['load_balancer']}")
    print()
    
    # Display deployment classification
    print("6. Deployment Classification:")
    deployment = detection_results['deployment_classification']
    print(f"   Environment type: {deployment['environment_type']}")
    print(f"   Confidence: {deployment['confidence']:.2f}")
    print(f"   Development indicators: {len(deployment['indicators']['development'])}")
    print(f"   Production indicators: {len(deployment['indicators']['production'])}")
    print()
    
    # Display technology stack
    print("7. Technology Stack:")
    tech = detection_results['technology_stack']
    print(f"   Languages: {', '.join(tech['languages']) if tech['languages'] else 'None detected'}")
    print(f"   Frameworks: {', '.join(tech['frameworks']) if tech['frameworks'] else 'None detected'}")
    print(f"   Databases: {', '.join(tech['databases']) if tech['databases'] else 'None detected'}")
    print(f"   Web servers: {', '.join(tech['web_servers']) if tech['web_servers'] else 'None detected'}")
    print()
    
    # Display environment profile
    print("8. Environment Profile:")
    profile = detection_results['environment_profile']
    print(f"   Deployment complexity: {profile['deployment_complexity']}")
    print(f"   Security maturity: {profile['security_maturity']}")
    print(f"   Technology diversity: {profile['technology_diversity']}")
    print(f"   Infrastructure sophistication: {profile['infrastructure_sophistication']}")
    print(f"   Operational maturity: {profile['operational_maturity']}")
    print(f"   Risk profile: {profile['risk_profile']}")
    print()
    
    return detection_results


def test_threat_context_builder():
    """Test the enhanced ThreatContextBuilder integration."""
    print("=" * 60)
    print("TESTING THREAT CONTEXT BUILDER INTEGRATION")
    print("=" * 60)
    
    # Initialize components
    context_builder = ThreatContextBuilder()
    mock_servers = create_mock_mcp_servers()
    
    print("1. Building enhanced environment context...")
    enhanced_context = context_builder.build_enhanced_context(mock_servers)
    
    # Display basic context
    print("2. Basic Context:")
    basic = enhanced_context['basic_context']
    print(f"   Deployment type: {basic['deployment_type']}")
    print(f"   Security posture: {basic['security_posture']}")
    print(f"   Data sensitivity: {basic['data_sensitivity']}")
    print(f"   Network exposure: {basic['network_exposure']}")
    print(f"   User privileges: {basic['user_privileges']}")
    print(f"   Compliance requirements: {len(basic['compliance_requirements'])}")
    print()
    
    # Display enhanced analysis
    print("3. Enhanced Analysis:")
    enhanced = enhanced_context['enhanced_analysis']
    print(f"   Threat multiplier: {enhanced['threat_multiplier']:.2f}")
    print(f"   Risk factors: {len(enhanced['risk_factors'])}")
    for i, factor in enumerate(enhanced['risk_factors'][:5], 1):  # Show first 5
        print(f"     {i}. {factor}")
    
    print(f"   Security recommendations: {len(enhanced['security_recommendations'])}")
    for i, rec in enumerate(enhanced['security_recommendations'][:3], 1):  # Show first 3
        print(f"     {i}. {rec}")
    
    print(f"   Deployment risks: {len(enhanced['deployment_risks'])}")
    print(f"   Compliance gaps: {len(enhanced['compliance_gaps'])}")
    print(f"   Monitoring gaps: {len(enhanced['monitoring_gaps'])}")
    print()
    
    # Display metadata
    print("4. Detection Metadata:")
    metadata = enhanced_context['detection_metadata']
    print(f"   Detection confidence: {metadata['detection_confidence']:.2f}")
    print(f"   Detection method: {metadata['detection_method']}")
    print(f"   Components analyzed: {len(metadata['components_analyzed'])}")
    print()
    
    return enhanced_context


def save_results_to_file(detection_results, enhanced_context):
    """Save test results to a JSON file."""
    results = {
        'test_timestamp': datetime.now().isoformat(),
        'detection_results': detection_results,
        'enhanced_context': enhanced_context
    }
    
    # Convert non-serializable objects to strings
    def convert_for_json(obj):
        if hasattr(obj, 'value'):  # Enum objects
            return obj.value
        elif hasattr(obj, '__dict__'):  # Custom objects
            return str(obj)
        return obj
    
    def clean_for_json(data):
        if isinstance(data, dict):
            return {k: clean_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [clean_for_json(item) for item in data]
        else:
            return convert_for_json(data)
    
    clean_results = clean_for_json(results)
    
    filename = f"enhanced_environment_detection_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(filename, 'w') as f:
            json.dump(clean_results, f, indent=2, default=str)
        print(f"Test results saved to: {filename}")
    except Exception as e:
        print(f"Failed to save results: {e}")


def main():
    """Main test function."""
    print("Enhanced Environment Detection System Test")
    print(f"Test started at: {datetime.now()}")
    print()
    
    try:
        # Test environment detector
        detection_results = test_environment_detector()
        
        # Test threat context builder integration
        enhanced_context = test_threat_context_builder()
        
        # Save results
        save_results_to_file(detection_results, enhanced_context)
        
        print("=" * 60)
        print("✅ ENHANCED ENVIRONMENT DETECTION SYSTEM TEST COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print()
        print("F3.2 Implementation Summary:")
        print("✅ EnvironmentDetector class with infrastructure detection")
        print("✅ Advanced security environment analysis") 
        print("✅ Network architecture discovery")
        print("✅ Development vs production environment classification")
        print("✅ Technology stack detection")
        print("✅ Integration with ThreatContextBuilder")
        print("✅ Enhanced threat analysis with risk multipliers")
        print("✅ Security recommendations generation")
        print()
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 