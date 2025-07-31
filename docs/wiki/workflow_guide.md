# 🦅 HawkEye Complete Workflow Guide
## Comprehensive Testing and Analysis Scenarios with AI-Powered Threat Analysis

### Version 2.0 - Updated with AI Analysis Workflows

---

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Network Scanning Workflows](#network-scanning-workflows)
3. [Detection Workflows](#detection-workflows)
4. [AI-Powered Threat Analysis Workflows](#ai-powered-threat-analysis-workflows)
5. [Complete Security Assessment Workflows](#complete-security-assessment-workflows)
6. [Reporting Workflows](#reporting-workflows)
7. [Advanced Scenarios](#advanced-scenarios)
8. [Troubleshooting Common Issues](#troubleshooting-common-issues)
9. [Best Practices](#best-practices)

---

## Quick Start Guide

### Prerequisites Check

Before starting any workflow, ensure HawkEye is properly installed:

```bash
# Verify installation
python application.py --help

# Check system information
python application.py info

# Verify AI provider configuration (optional)
python application.py config show
```

### Basic Command Structure

All HawkEye commands follow this pattern:
```bash
python application.py [GLOBAL_OPTIONS] COMMAND [SUB_COMMAND] [OPTIONS]
```

**Important:** The `analyze-threats` command is under the `detect` group:
```bash
python application.py analyze-threats [OPTIONS]
```

**Global Options:**
- `--verbose` / `-v`: Enable detailed output
- `--quiet` / `-q`: Suppress non-essential output
- `--log-file <path>`: Write logs to file
- `--config-file <path>`: Load configuration from file

---

## Network Scanning Workflows

### Scenario 1: Single IP Address Scan

**Use Case:** Testing a specific server or service
**Risk Level:** Low
**Time Required:** 1-5 minutes

```bash
# Basic single IP scan
python application.py scan --target 192.168.1.100

# Verbose single IP scan with custom ports
python application.py --verbose scan --target 192.168.1.100 --ports 3000-9000

# Single IP with output file
python application.py scan --target 192.168.1.100 --output single_ip_results.json
```

**Expected Output:**
```
🦅 HawkEye v2.0 - MCP Security Reconnaissance
[INFO] Starting scan of target: 192.168.1.100
[INFO] Scanning ports: 3000, 8000, 8080, 9000
[PROGRESS] ████████████████████ 100% (4/4 ports)
[FOUND] 192.168.1.100:3000 - MCP Server (Node.js)
[INFO] Scan completed in 3.2 seconds
```

### Scenario 2: Small Network Scan (CIDR /24)

**Use Case:** Scanning a small office or lab network
**Risk Level:** Medium
**Time Required:** 5-15 minutes

```bash
# Basic CIDR scan
python application.py scan --target 192.168.1.0/24

# Aggressive small network scan
python application.py --verbose scan --target 192.168.1.0/24 \
  --ports 3000-9000 \
  --threads 50 \
  --timeout 3

# Small network with comprehensive output
python application.py scan --target 192.168.1.0/24 \
  --output small_network_scan.json
```

### Scenario 3: Large Network Scan (Enterprise)

**Use Case:** Enterprise network assessment
**Risk Level:** High
**Time Required:** 30-120 minutes

```bash
# Conservative enterprise scan
python application.py --verbose scan --target 10.0.0.0/16 \
  --threads 25 \
  --timeout 10 \
  --rate-limit 100 \
  --output enterprise_scan.json

# Multi-subnet scan
python application.py scan --target 192.168.0.0/16 \
  --exclude-ranges 192.168.100.0/24,192.168.200.0/24 \
  --output filtered_scan.json
```

---

## Detection Workflows

### Scenario 4: Target-Specific MCP Detection

**Use Case:** Detailed analysis of a specific server
**Risk Level:** Low
**Time Required:** 2-10 minutes

```bash
# Basic target detection
python application.py detect target --target 192.168.1.100

# Comprehensive target detection with output
python application.py detect target --target 192.168.1.100 \
  --output target_detection.json

# Target detection with protocol verification
python application.py --verbose detect target --target 192.168.1.100 \
  --verify-protocol \
  --detect-transport \
  --output verified_target.json
```

**Expected Output:**
```
🦅 HawkEye MCP Target Detection
Target: 192.168.1.100
Ports: 4 ports
Protocol Verification: Enabled
Transport Detection: Enabled

⠋ Detecting MCP services... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

MCP Detection Results
┏━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Target        ┃ Port ┃ Detection Method    ┃ Confidence ┃ Transport ┃
┡━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ 192.168.1.100 │ 3000 │ protocol_verify     │ 0.85       │ http      │
│ 192.168.1.100 │ 8080 │ transport_detect    │ 0.72       │ websocket │
└───────────────┴──────┴─────────────────────┴────────────┴───────────┘
```

### Scenario 5: Local System Detection

**Use Case:** Auditing the local development environment
**Risk Level:** Low
**Time Required:** 1-5 minutes

```bash
# Full local detection
python application.py --verbose detect local

# Local detection with output
python application.py detect local --output local_detection.json

# Minimal local detection (no Docker/environment)
python application.py detect local \
  --no-include-docker \
  --no-include-env \
  --output minimal_local.json
```

### Scenario 6: Network-Wide CIDR Detection

**Use Case:** Comprehensive MCP detection across network ranges
**Risk Level:** Medium-High
**Time Required:** 10-60 minutes (depending on network size)

```bash
# Basic CIDR detection for small networks
python application.py detect comprehensive --target 192.168.1.0/24 \
  --output network_detection.json

# Large enterprise network with optimized settings
python application.py detect comprehensive --target 10.0.0.0/16 \
  --confidence-threshold 0.5 \
  --introspection-timeout 120 \
  --output enterprise_detection.json

# Multi-subnet detection workflow
python application.py detect comprehensive --target 192.168.0.0/22 \
  --enable-risk-assessment \
  --format html \
  --output network_report.html

# CIDR detection with AI threat analysis
python application.py detect comprehensive --target 192.168.1.0/24 --output cidr_results.json
python application.py analyze-threats -i cidr_results.json -f html -o network_threats.html
```

### Scenario 7: Comprehensive Detection with Introspection

**Use Case:** Deep analysis with MCP introspection (single target)
**Risk Level:** Medium
**Time Required:** 5-20 minutes

```bash
# Comprehensive detection of single target
python application.py detect comprehensive --target 192.168.1.100 \
  --output comprehensive_results.json

# Comprehensive with custom introspection settings
python application.py --verbose detect comprehensive --target api.example.com \
  --introspection-timeout 30 \
  --output detailed_introspection.json

# Hostname-based comprehensive detection
python application.py detect comprehensive --target api.internal.company.com \
  --enable-risk-assessment \
  --generate-introspection-report \
  --format html
```

---

## AI-Powered Threat Analysis Workflows

### Scenario 8: Basic AI Threat Analysis

**Use Case:** AI-powered analysis of detected MCP servers
**Risk Level:** Low
**Time Required:** 2-10 minutes
**Requirements:** OpenAI or Anthropic API key

```bash
# Step 1: Detect MCP servers (supports CIDR) and save to JSON
python application.py detect comprehensive --target 192.168.1.100 \
  --output detection_results.json

# Step 2: Analyze threats using AI
python application.py analyze-threats \
  --input detection_results.json \
  --output threat_analysis.json

# Step 3: Generate HTML report with visualization
python application.py analyze-threats \
  --input detection_results.json \
  --format html \
  --output threat_report.html

# Alternative: Network-wide detection and analysis
python application.py detect comprehensive --target 192.168.1.0/24 --output network_results.json
python application.py analyze-threats -i network_results.json -f html -o network_threats.html
```

**Expected Output:**
```
🦅 HawkEye AI Threat Analysis
Input: detection_results.json
Analysis Type: comprehensive
AI Enabled: ✅

📂 Loading Detection Results
Found 2 MCP servers for analysis

🤖 Performing Threat Analysis
Servers to analyze: 2
Analysis type: comprehensive
Parallel processing: ✅

  Progress: 2/2 - Processing: file-operations-tool

📊 Threat Analysis Results
✅ Successful Analyses: 2
❌ Failed Analyses: 0

🎯 file-operations-tool
  Threat Level: MEDIUM
  Attack Vectors: 3
  Mitigations: 4
  Confidence: 0.87
  Cost: $0.0234

📈 Analysis Statistics
  Total Analyses: 2
  Cache Hits: 0
  Total Cost: $0.0456

💾 Saving Results
HTML threat analysis report saved to threat_report.html
```

### Scenario 9: Local System AI Analysis

**Use Case:** AI analysis of local MCP development environment
**Risk Level:** Low
**Time Required:** 2-15 minutes

```bash
# Step 1: Detect local MCP services
python application.py detect local --output local_results.json

# Step 2: AI analysis with cost control
python application.py analyze-threats \
  --input local_results.json \
  --cost-limit 5.0 \
  --output local_threats.json

# Step 3: Generate detailed HTML report
python application.py analyze-threats \
  --input local_results.json \
  --format html \
  --analysis-type detailed \
  --output local_security_report.html
```

### Scenario 10: Batch AI Analysis with Parallel Processing

**Use Case:** High-performance analysis of multiple servers
**Risk Level:** Medium
**Time Required:** 5-30 minutes
**Cost:** Variable (monitor with --cost-limit)

```bash
# Step 1: Comprehensive detection of multiple targets
python application.py detect comprehensive --target api.company.com \
  --output comprehensive_results.json

# Step 2: Parallel AI analysis with optimization
python application.py analyze-threats \
  --input comprehensive_results.json \
  --parallel-processing \
  --max-workers 5 \
  --cost-limit 25.0 \
  --format csv \
  --output batch_analysis.csv

# Step 3: Generate executive summary
python application.py analyze-threats \
  --input comprehensive_results.json \
  --format html \
  --analysis-type comprehensive \
  --output executive_summary.html
```

### Scenario 10: Cost-Controlled AI Analysis

**Use Case:** Budget-conscious threat analysis
**Risk Level:** Low
**Time Required:** Variable

```bash
# Quick analysis with strict cost limits
python application.py analyze-threats \
  --input detection_results.json \
  --analysis-type quick \
  --cost-limit 2.0 \
  --confidence-threshold 0.3 \
  --output budget_analysis.json

# Sequential processing to minimize costs
python application.py analyze-threats \
  --input bulk_detection.json \
  --sequential-processing \
  --cost-limit 10.0 \
  --output cost_controlled.json
```

### Scenario 11: Multi-Format AI Analysis Output

**Use Case:** Generate reports for different stakeholders
**Risk Level:** Low
**Time Required:** 5-15 minutes

```bash
# Detect first
python application.py detect target --target 192.168.1.100 \
  --output detection.json

# Generate JSON for technical teams
python application.py analyze-threats \
  --input detection.json \
  --format json \
  --output technical_analysis.json

# Generate CSV for data analysis
python application.py analyze-threats \
  --input detection.json \
  --format csv \
  --output analysis_data.csv

# Generate XML for SIEM integration
python application.py analyze-threats \
  --input detection.json \
  --format xml \
  --output siem_feed.xml

# Generate HTML for executives
python application.py analyze-threats \
  --input detection.json \
  --format html \
  --analysis-type comprehensive \
  --output executive_report.html
```

---

## Complete Security Assessment Workflows

### Scenario 12: Full Enterprise Security Assessment

**Use Case:** Complete organizational MCP security audit
**Risk Level:** High
**Time Required:** 1-4 hours
**Requirements:** Proper authorization, AI provider API keys

```bash
#!/bin/bash
# enterprise_assessment.sh - Complete MCP Security Assessment

echo "🦅 Starting Enterprise MCP Security Assessment"

# Phase 1: Network Discovery
echo "Phase 1: Network Discovery"
python application.py scan --target 10.0.0.0/16 \
  --threads 50 \
  --timeout 15 \
  --output phase1_network_discovery.json

# Phase 2: Local System Audit
echo "Phase 2: Local System Assessment"
python application.py detect local \
  --output phase2_local_audit.json

# Phase 3: Target-Specific Detection
echo "Phase 3: Detailed Target Analysis"
python application.py detect target --target 10.0.1.100 \
  --output phase3_target_analysis.json

# Phase 4: Comprehensive Introspection
echo "Phase 4: MCP Introspection Analysis"
python application.py detect comprehensive --target api.internal.com \
  --output phase4_introspection.json

# Phase 5: AI Threat Analysis
echo "Phase 5: AI-Powered Threat Analysis"
python application.py analyze-threats \
  --input phase1_network_discovery.json \
  --parallel-processing \
  --cost-limit 50.0 \
  --output phase5_network_threats.json

python application.py analyze-threats \
  --input phase2_local_audit.json \
  --analysis-type detailed \
  --output phase5_local_threats.json

python application.py analyze-threats \
  --input phase4_introspection.json \
  --analysis-type comprehensive \
  --format html \
  --output phase5_introspection_report.html

# Phase 6: Executive Reporting
echo "Phase 6: Executive Report Generation"
python application.py report aggregate \
  --input-files phase5_*.json \
  --output enterprise_security_assessment.json

python application.py report generate \
  --input enterprise_security_assessment.json \
  --format html \
  --template executive \
  --output Enterprise_MCP_Security_Report.html

echo "✅ Assessment Complete"
echo "📊 Executive Report: Enterprise_MCP_Security_Report.html"
echo "🔍 Detailed Analysis: phase5_introspection_report.html"
```

### Scenario 13: Incident Response Investigation

**Use Case:** Investigating potential MCP-related security incident
**Risk Level:** High
**Time Required:** 15-60 minutes

```bash
#!/bin/bash
# incident_response.sh - MCP Incident Response Investigation

echo "🚨 MCP Security Incident Response Investigation"

# Step 1: Immediate local assessment
echo "Step 1: Emergency Local Assessment"
python application.py --verbose detect local \
  --include-processes \
  --include-env \
  --output incident_local_snapshot.json

# Step 2: AI-powered threat analysis of local findings
echo "Step 2: AI Threat Analysis of Local Systems"
python application.py analyze-threats \
  --input incident_local_snapshot.json \
  --analysis-type detailed \
  --confidence-threshold 0.2 \
  --format html \
  --output incident_local_threats.html

# Step 3: Network investigation of suspicious IPs
echo "Step 3: Network Investigation"
SUSPICIOUS_IP="192.168.1.150"  # Replace with actual suspicious IP
python application.py detect comprehensive --target $SUSPICIOUS_IP \
  --output incident_network_analysis.json

# Step 4: AI analysis of network findings
echo "Step 4: AI Analysis of Network Findings"
python application.py analyze-threats \
  --input incident_network_analysis.json \
  --analysis-type comprehensive \
  --output incident_network_threats.json

# Step 5: Generate incident report
echo "Step 5: Incident Report Generation"
python application.py report generate \
  --input incident_network_threats.json \
  --format html \
  --template incident \
  --output MCP_Incident_Response_Report.html

echo "🔍 Investigation Complete"
echo "📋 Incident Report: MCP_Incident_Response_Report.html"
echo "🖥️  Local Threats: incident_local_threats.html"
```

### Scenario 14: Compliance Audit Workflow

**Use Case:** Regulatory compliance assessment
**Risk Level:** Medium
**Time Required:** 2-6 hours

```bash
#!/bin/bash
# compliance_audit.sh - MCP Compliance Assessment

echo "📋 MCP Compliance Audit Workflow"

# Phase 1: Complete Environment Discovery
echo "Phase 1: Environment Discovery"
python application.py detect local --output compliance_local.json
python application.py scan --target 192.168.1.0/24 --output compliance_network.json

# Phase 2: Detailed AI Analysis for Compliance
echo "Phase 2: Compliance-Focused AI Analysis"
python application.py analyze-threats \
  --input compliance_local.json \
  --analysis-type detailed \
  --confidence-threshold 0.8 \
  --output compliance_local_analysis.json

python application.py analyze-threats \
  --input compliance_network.json \
  --analysis-type comprehensive \
  --output compliance_network_analysis.json

# Phase 3: Compliance Report Generation
echo "Phase 3: Compliance Report Generation"
python application.py report generate \
  --input compliance_local_analysis.json \
  --format html \
  --template compliance \
  --include-cvss \
  --include-cwe \
  --output Compliance_Audit_Report.html

echo "✅ Compliance Audit Complete"
echo "📊 Report: Compliance_Audit_Report.html"
```

---

## Reporting Workflows

### Scenario 15: Multi-Format Report Generation

**Use Case:** Generate reports for different audiences
**Risk Level:** Low
**Time Required:** 5-15 minutes

```bash
# Generate all report formats from AI analysis
python application.py analyze-threats \
  --input detection_results.json \
  --format json \
  --output analysis.json

# Technical JSON report
python application.py report generate \
  --input analysis.json \
  --format json \
  --output technical_report.json

# Executive HTML dashboard
python application.py report generate \
  --input analysis.json \
  --format html \
  --template executive \
  --output executive_dashboard.html

# CSV for data analysis
python application.py report generate \
  --input analysis.json \
  --format csv \
  --output data_analysis.csv

# XML for SIEM integration
python application.py report generate \
  --input analysis.json \
  --format xml \
  --output siem_integration.xml
```

---

## Advanced Scenarios

### Scenario 16: Automated Continuous Monitoring

**Use Case:** Ongoing MCP security monitoring
**Risk Level:** Low
**Time Required:** Setup once, runs continuously

```bash
#!/bin/bash
# continuous_monitoring.sh - Automated MCP Monitoring

RESULTS_DIR="/var/log/hawkeye/monitoring"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

# Daily local system check
python application.py detect local \
  --output "$RESULTS_DIR/local_$DATE.json"

# AI analysis of local changes
python application.py analyze-threats \
  --input "$RESULTS_DIR/local_$DATE.json" \
  --cost-limit 1.0 \
  --output "$RESULTS_DIR/threats_$DATE.json"

# Alert on high-risk findings
python -c "
import json
import sys
with open('$RESULTS_DIR/threats_$DATE.json') as f:
    data = json.load(f)
    high_risk = [t for t in data.get('threat_analyses', {}).values() 
                 if t.get('threat_level') in ['HIGH', 'CRITICAL']]
    if high_risk:
        print(f'🚨 High-risk threats detected: {len(high_risk)}')
        sys.exit(1)
"

if [ $? -eq 1 ]; then
    # Send alert (customize for your environment)
    echo "High-risk MCP threats detected - check $RESULTS_DIR/threats_$DATE.json"
fi
```

### Scenario 17: AI Provider Comparison

**Use Case:** Compare different AI providers for threat analysis
**Risk Level:** Low
**Time Required:** 10-30 minutes
**Cost:** Variable

```bash
# Run same analysis with different providers
export AI_PROVIDER=openai
python application.py analyze-threats \
  --input detection_results.json \
  --output openai_analysis.json

export AI_PROVIDER=anthropic
python application.py analyze-threats \
  --input detection_results.json \
  --output anthropic_analysis.json

export AI_PROVIDER=local_llm
export AI_LOCAL_LLM_ENDPOINT=http://localhost:11434
python application.py analyze-threats \
  --input detection_results.json \
  --output local_llm_analysis.json

# Compare results
echo "🤖 AI Provider Comparison Complete"
echo "📊 OpenAI Analysis: openai_analysis.json"
echo "📊 Anthropic Analysis: anthropic_analysis.json"  
echo "📊 Local LLM Analysis: local_llm_analysis.json"
```

---

## Troubleshooting Common Issues

### Issue 1: "analyze-threats" Command Not Found

**Problem:** `python application.py analyze-threats` returns command not found
**Solution:** The command is under the `detect` group:

```bash
# ❌ Wrong
python application.py analyze-threats -i results.json

# ✅ Correct
python application.py analyze-threats -i results.json
```

### Issue 2: AI Provider API Errors

**Problem:** AI analysis fails with API errors
**Solution:**

```bash
# Check API key configuration
python application.py config show

# Test with cost limit
python application.py analyze-threats \
  --input results.json \
  --cost-limit 1.0 \
  --analysis-type quick

# Use fallback provider
export AI_FALLBACK_PROVIDER=anthropic
python application.py analyze-threats --input results.json
```

### Issue 3: "'NoneType' object has no attribute 'verbose'"

**Problem:** Context object not initialized properly
**Solution:**

```bash
# Ensure using correct command structure
python application.py analyze-threats --input results.json

# Use verbose mode for debugging
python application.py --verbose analyze-threats --input results.json
```

### Issue 4: High AI Analysis Costs

**Problem:** Unexpected high costs from AI analysis
**Solution:**

```bash
# Use cost limits
python application.py analyze-threats \
  --input results.json \
  --cost-limit 5.0

# Use quick analysis mode
python application.py analyze-threats \
  --input results.json \
  --analysis-type quick

# Use sequential processing
python application.py analyze-threats \
  --input results.json \
  --sequential-processing
```

### Issue 5: Large JSON Input Files

**Problem:** Memory issues with large detection result files
**Solution:**

```bash
# Filter by confidence threshold
python application.py analyze-threats \
  --input large_results.json \
  --confidence-threshold 0.7

# Process in smaller batches
python -c "
import json
with open('large_results.json') as f:
    data = json.load(f)
    # Split into smaller files
"
```

---

## Best Practices

### AI Analysis Best Practices

1. **Cost Management:**
   ```bash
   # Always use cost limits for production
   python application.py analyze-threats \
     --input results.json \
     --cost-limit 10.0
   ```

2. **Provider Selection:**
   ```bash
   # Use appropriate provider for use case
   export AI_PROVIDER=anthropic  # For detailed analysis
   export AI_PROVIDER=openai     # For general analysis  
   export AI_PROVIDER=local_llm  # For privacy/cost concerns
   ```

3. **Analysis Type Selection:**
   ```bash
   # Quick for monitoring/screening
   --analysis-type quick
   
   # Comprehensive for regular assessments
   --analysis-type comprehensive
   
   # Detailed for incident response/auditing
   --analysis-type detailed
   ```

### Security Considerations

1. **Authorization:** Always obtain proper authorization before scanning
2. **API Keys:** Secure storage of AI provider API keys
3. **Data Handling:** Secure storage and transmission of analysis results
4. **Rate Limiting:** Use conservative settings for production networks

### Performance Optimization

1. **Parallel Processing:** Use for multiple servers
2. **Cost Limits:** Prevent runaway AI costs
3. **Caching:** Benefits from repeat analysis
4. **Confidence Thresholds:** Filter low-confidence results

### Operational Guidelines

1. **Documentation:** Document all procedures and findings
2. **Validation:** Verify AI analysis results through multiple methods
3. **Follow-up:** Implement remediation based on AI recommendations
4. **Monitoring:** Continuous monitoring with automated analysis

---

This comprehensive workflow guide covers all HawkEye capabilities including the new AI-powered threat analysis system. Use these scenarios as templates for conducting thorough MCP security assessments in any environment. 