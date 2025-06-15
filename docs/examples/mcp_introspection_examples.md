# MCP Introspection Examples and Use Cases

## Overview

This document provides comprehensive examples and use cases for the MCP Introspection system, demonstrating various configurations and scenarios for security assessment of MCP servers.

## Basic Usage Examples

### 1. Simple Local Server Introspection

```python
#!/usr/bin/env python3
"""
Basic MCP server introspection example.
Analyzes a local filesystem MCP server.
"""

import sys
import os
sys.path.append('src')

from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection, IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig

def basic_introspection():
    """Basic introspection of a local MCP server."""
    
    # Create introspection configuration
    config = IntrospectionConfig(
        timeout=30.0,
        enable_detailed_analysis=True,
        enable_risk_assessment=True
    )
    
    # Initialize introspector
    introspector = MCPIntrospection(config)
    
    # Create server configuration
    server_config = MCPServerConfig(
        server_id="filesystem-server",
        command=["node", "/usr/bin/mcp-server-filesystem", "/home/user/projects"]
    )
    
    print("🔍 Starting MCP Server Introspection...")
    print(f"Target: {' '.join(server_config.command)}")
    
    try:
        # Perform introspection
        result = introspector.introspect_server(server_config)
        
        if result.success and result.servers:
            server_info = result.servers[0]
            print("\n✅ Introspection Results:")
            print(f"Server ID: {server_info.server_id}")
            print(f"Tools: {len(server_info.tools)}")
            print(f"Resources: {len(server_info.resources)}")
            print(f"Capabilities: {len(server_info.capabilities)}")
            print(f"Security Risks: {len(server_info.security_risks)}")
            
            # Show tools
            for tool in server_info.tools:
                print(f"  📋 {tool.name}: {tool.description}")
                
        else:
            print("❌ Introspection failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    basic_introspection()
```

### 2. Batch Server Analysis

```python
#!/usr/bin/env python3
"""
Batch analysis of multiple MCP servers.
"""

from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection
from hawkeye.detection.mcp_introspection.models import MCPServerConfig

def batch_analysis():
    """Analyze multiple MCP servers concurrently."""
    
    server_configs = [
        MCPServerConfig(
            server_id="filesystem-server",
            command=["node", "mcp-server-filesystem", "/data"]
        ),
        MCPServerConfig(
            server_id="database-server", 
            command=["node", "mcp-server-database", "--port", "3001"]
        ),
        MCPServerConfig(
            server_id="api-server",
            command=["node", "mcp-server-api", "https://api.example.com"]
        )
    ]
    
    introspector = MCPIntrospection()
    
    print("🔍 Starting Batch MCP Server Analysis...")
    
    # Perform batch introspection
    result = introspector.introspect_multiple_servers(server_configs)
    
    print(f"\n📊 Batch Analysis Results:")
    print(f"Duration: {result.duration.total_seconds():.2f}s")
    print(f"Total servers: {result.total_servers}")
    print(f"Successful: {result.successful_servers}")
    print(f"Failed: {result.failed_servers}")
    print(f"Overall risk: {result.overall_risk_level.value}")
    
    for server_info in result.servers:
        print(f"\n🔸 {server_info.server_id}")
        
        if not server_info.metadata.get('error'):
            print(f"  Status: ✅ Success")
            print(f"  Tools: {len(server_info.tools)}")
            print(f"  Risk: {server_info.overall_risk_level.value}")
            
            # High-risk analysis
            high_risk_tools = [t for t in server_info.tools 
                             if t.risk_level.value == "HIGH"]
            if high_risk_tools:
                print(f"  ⚠️ High-risk tools: {[t.name for t in high_risk_tools]}")
        else:
            print(f"  Status: ❌ Failed - {server_info.metadata.get('error_message')}")

if __name__ == '__main__':
    batch_analysis()
```

## Configuration Examples

### 1. Basic Configuration

```python
# config/mcp_introspection.py
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

# Basic configuration for development
basic_config = IntrospectionConfig(
    timeout=30.0,
    max_retries=3,
    enable_detailed_analysis=True,
    enable_risk_assessment=True
)
```

### 2. Production Configuration

```python
# config/production_mcp.py
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

# Production configuration with optimizations
production_config = IntrospectionConfig(
    # Connection settings
    timeout=60.0,
    max_retries=5,
    
    # Analysis settings
    enable_detailed_analysis=True,
    enable_risk_assessment=True,
    
    # Performance settings
    enable_parallel_processing=True,
    max_concurrent_servers=10
)
```

### 3. High-Security Configuration

```python
# config/security_focused.py
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

# Security-focused configuration
security_config = IntrospectionConfig(
    # Conservative timeouts
    timeout=15.0,
    max_retries=2,
    
    # Enhanced security analysis
    enable_detailed_analysis=True,
    enable_risk_assessment=True,
    enable_schema_validation=True,
    
    # Strict policies
    fail_on_high_risk=True,
    
    # Limited concurrency for careful analysis
    max_concurrent_servers=3
)
```

## Advanced Use Cases

### 1. Enterprise Security Audit

```python
#!/usr/bin/env python3
"""
Enterprise security audit scenario.
Comprehensive analysis of all MCP servers in the environment.
"""

from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection, IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig
from hawkeye.detection.mcp_introspection.risk import RiskLevel

def enterprise_security_audit():
    """Perform enterprise-wide security audit."""
    
    # Security-focused configuration
    config = IntrospectionConfig(
        timeout=30.0,
        enable_detailed_analysis=True,
        enable_risk_assessment=True
    )
    
    introspector = MCPIntrospection(config)
    
    print("🏢 Enterprise MCP Security Audit")
    print("=" * 40)
    
    # Define servers to audit
    server_configs = [
        MCPServerConfig(
            server_id="prod-filesystem",
            command=["node", "mcp-server-filesystem", "/data/production"]
        ),
        MCPServerConfig(
            server_id="dev-database", 
            command=["node", "mcp-server-database", "dev-db"]
        ),
        MCPServerConfig(
            server_id="api-gateway",
            command=["node", "mcp-server-api", "https://api.company.com"]
        )
    ]
    
    print(f"1. Analyzing {len(server_configs)} MCP servers...")
    
    # Perform batch analysis
    result = introspector.introspect_multiple_servers(server_configs)
    
    print("\n2. Security Assessment Results:")
    print("=" * 40)
    
    high_risk_servers = []
    medium_risk_servers = []
    low_risk_servers = []
    
    for server_info in result.servers:
        if server_info.metadata.get('error'):
            continue
            
        risk_level = server_info.overall_risk_level
        
        if risk_level == RiskLevel.HIGH:
            high_risk_servers.append(server_info)
            print(f"🔴 HIGH RISK: {server_info.server_id}")
        elif risk_level == RiskLevel.MEDIUM:
            medium_risk_servers.append(server_info)
            print(f"🟡 MEDIUM RISK: {server_info.server_id}")
        else:
            low_risk_servers.append(server_info)
            print(f"🟢 LOW RISK: {server_info.server_id}")
    
    # Detailed findings for high-risk servers
    if high_risk_servers:
        print(f"\n⚠️ HIGH RISK FINDINGS ({len(high_risk_servers)} servers):")
        for server in high_risk_servers:
            print(f"\n📍 {server.server_id}:")
            
            # Show high-risk tools
            high_risk_tools = [t for t in server.tools 
                             if t.risk_level == RiskLevel.HIGH]
            for tool in high_risk_tools:
                print(f"  🔸 {tool.name}: {tool.category}")
            
            # Show security risks
            for risk in server.security_risks:
                print(f"  ⚠️ {risk.description}")
    
    # Summary
    print(f"\n📊 AUDIT SUMMARY:")
    print(f"Total Servers: {len(result.servers)}")
    print(f"High Risk: {len(high_risk_servers)}")
    print(f"Medium Risk: {len(medium_risk_servers)}")
    print(f"Low Risk: {len(low_risk_servers)}")

if __name__ == '__main__':
    enterprise_security_audit()
```

### 2. Incident Response Analysis

```python
#!/usr/bin/env python3
"""
Incident response scenario.
Rapid analysis of suspected compromised MCP servers.
"""

from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection, IntrospectionConfig
from hawkeye.detection.mcp_introspection.models import MCPServerConfig

def incident_response_analysis(server_command):
    """Perform rapid incident response analysis."""
    
    # Fast configuration for incident response
    config = IntrospectionConfig(
        timeout=15.0,  # Quick analysis
        max_retries=1,
        enable_detailed_analysis=True,
        enable_risk_assessment=True
    )
    
    introspector = MCPIntrospection(config)
    
    print("🚨 INCIDENT RESPONSE - MCP Server Analysis")
    print("=" * 50)
    print(f"Target Command: {' '.join(server_command)}")
    
    # Create server config
    server_config = MCPServerConfig(
        server_id="incident-target",
        command=server_command
    )
    
    # Analyze server
    result = introspector.introspect_server(server_config)
    
    if not result.success or not result.servers:
        print("❌ Unable to introspect MCP server")
        return
    
    server_info = result.servers[0]
    
    print(f"\n📋 Server Information:")
    print(f"Server ID: {server_info.server_id}")
    print(f"Tools: {len(server_info.tools)}")
    print(f"Resources: {len(server_info.resources)}")
    print(f"Risk Level: {server_info.overall_risk_level.value}")
    
    # Check for suspicious indicators
    suspicious_indicators = []
    
    # Check for high-risk tools
    high_risk_tools = [t for t in server_info.tools 
                      if t.risk_level.value == "HIGH"]
    if high_risk_tools:
        suspicious_indicators.append(f"High-risk tools: {[t.name for t in high_risk_tools]}")
    
    # Check for security risks
    if server_info.security_risks:
        suspicious_indicators.append(f"Security risks detected: {len(server_info.security_risks)}")
    
    # Report findings
    if suspicious_indicators:
        print(f"\n⚠️ SUSPICIOUS INDICATORS:")
        for indicator in suspicious_indicators:
            print(f"  🔸 {indicator}")
    else:
        print(f"\n✅ No immediate suspicious indicators found")
    
    # Tool analysis
    print(f"\n🛠️ Tool Analysis:")
    for tool in server_info.tools:
        risk_emoji = "🔴" if tool.risk_level.value == "HIGH" else "🟡" if tool.risk_level.value == "MEDIUM" else "🟢"
        print(f"  {risk_emoji} {tool.name} ({tool.category})")
        if tool.risk_level.value in ["HIGH", "MEDIUM"]:
            print(f"    Description: {tool.description}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python incident_response.py <server_command...>")
        sys.exit(1)
    
    server_command = sys.argv[1:]
    incident_response_analysis(server_command)
```

## Integration with HawkEye CLI

### 1. Custom Detection Command

```bash
#!/bin/bash
# MCP introspection integration with HawkEye CLI

echo "🦅 HawkEye MCP Introspection Workflow"

# 1. Scan network for potential MCP services
echo "1. Scanning network for MCP services..."
python application.py scan --target 192.168.1.0/24 --ports 3000-3010 --output network_scan.json

# 2. Detect and verify MCP servers
echo "2. Detecting MCP servers..."
python application.py detect target --input network_scan.json --output mcp_servers.json

# 3. Perform introspection analysis
echo "3. Performing MCP introspection..."
python application.py detect introspect --input mcp_servers.json --output introspection_results.json

# 4. Generate comprehensive security report
echo "4. Generating security report..."
python application.py report generate --input introspection_results.json --format html --output mcp_security_report.html

echo "✅ Complete MCP assessment available in mcp_security_report.html"
```

### 2. Automated Monitoring Script

```bash
#!/bin/bash
# Automated MCP monitoring with HawkEye

MONITOR_DIR="/opt/hawkeye/monitoring"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "🔍 Starting automated MCP monitoring - $TIMESTAMP"

# Create monitoring directory
mkdir -p $MONITOR_DIR

# Perform local MCP detection
python application.py detect local --output $MONITOR_DIR/local_mcp_$TIMESTAMP.json

# Introspect detected servers
python application.py detect introspect --input $MONITOR_DIR/local_mcp_$TIMESTAMP.json --output $MONITOR_DIR/introspection_$TIMESTAMP.json

# Generate summary report
python application.py report generate --input $MONITOR_DIR/introspection_$TIMESTAMP.json --format json --output $MONITOR_DIR/summary_$TIMESTAMP.json

# Check for high-risk findings
HIGH_RISK=$(cat $MONITOR_DIR/summary_$TIMESTAMP.json | jq '.high_risk_count // 0')

if [ "$HIGH_RISK" -gt 0 ]; then
    echo "⚠️ HIGH RISK ALERT: $HIGH_RISK high-risk findings detected"
    # Send alert (email, Slack, etc.)
    python scripts/send_alert.py --file $MONITOR_DIR/summary_$TIMESTAMP.json
else
    echo "✅ No high-risk findings detected"
fi

# Cleanup old files (keep last 30 days)
find $MONITOR_DIR -name "*.json" -mtime +30 -delete

echo "✅ Monitoring complete - $TIMESTAMP"
```

## Best Practices and Tips

### 1. Error Handling

```python
from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection
from hawkeye.detection.mcp_introspection.exceptions import IntrospectionError

def robust_introspection(server_config):
    """Robust introspection with comprehensive error handling."""
    
    introspector = MCPIntrospection()
    
    try:
        result = introspector.introspect_server(server_config)
        return result
        
    except IntrospectionError as e:
        print(f"Introspection failed: {e}")
        return None
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
```

### 2. Performance Optimization

```python
from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection, IntrospectionConfig

def optimized_batch_introspection(server_configs):
    """Optimized batch introspection with performance tuning."""
    
    # Performance-optimized configuration
    config = IntrospectionConfig(
        timeout=30.0,
        enable_parallel_processing=True,
        max_concurrent_servers=10
    )
    
    introspector = MCPIntrospection(config)
    
    # Execute with controlled concurrency
    result = introspector.introspect_multiple_servers(server_configs)
    
    return result
```

### 3. Custom Risk Analysis

```python
from hawkeye.detection.mcp_introspection.introspection import MCPIntrospection
from hawkeye.detection.mcp_introspection.risk import RiskLevel

def custom_risk_assessment(server_config):
    """Custom risk assessment with business logic."""
    
    introspector = MCPIntrospection()
    result = introspector.introspect_server(server_config)
    
    if not result.success or not result.servers:
        return None
    
    server_info = result.servers[0]
    
    # Custom risk factors
    custom_risk_score = 0
    custom_findings = []
    
    # Check for dangerous tool combinations
    tool_names = [t.name for t in server_info.tools]
    if 'filesystem_read' in tool_names and 'shell_execute' in tool_names:
        custom_risk_score += 8
        custom_findings.append("Dangerous combination: file read + shell execution")
    
    # Check for excessive permissions
    if len(server_info.tools) > 10:
        custom_risk_score += 3
        custom_findings.append(f"Excessive tool count: {len(server_info.tools)}")
    
    return {
        'server_id': server_info.server_id,
        'standard_risk': server_info.overall_risk_level.value,
        'custom_risk_score': custom_risk_score,
        'custom_findings': custom_findings,
        'total_tools': len(server_info.tools),
        'total_resources': len(server_info.resources)
    }
```

This comprehensive examples collection demonstrates the full capabilities of the MCP Introspection system across various real-world scenarios, from basic usage to advanced enterprise security auditing. 