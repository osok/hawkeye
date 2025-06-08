# 🦅 HawkEye Complete Workflow Guide
## Comprehensive Testing and Analysis Scenarios

### Version 1.0

---

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Network Scanning Workflows](#network-scanning-workflows)
3. [Detection Workflows](#detection-workflows)
4. [Analysis Workflows](#analysis-workflows)
5. [Reporting Workflows](#reporting-workflows)
6. [Advanced Scenarios](#advanced-scenarios)
7. [Troubleshooting Common Issues](#troubleshooting-common-issues)
8. [Best Practices](#best-practices)

---

## Quick Start Guide

### Prerequisites Check

Before starting any workflow, ensure HawkEye is properly installed:

```bash
# Verify installation
python application.py --help

# Check dependencies
python application.py info

# Test basic functionality
python application.py --version
```

### Basic Command Structure

All HawkEye commands follow this pattern:
```bash
python application.py [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]
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
🦅 HawkEye v1.0 - MCP Security Reconnaissance
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
  --output small_network_scan.json \
  --format json
```

**Monitoring Progress:**
```
🦅 HawkEye Network Scan
Target: 192.168.1.0/24 (256 hosts)
Ports: 3000, 8000, 8080, 9000
[PROGRESS] ████████████████████ 100% (1024/1024 host:port combinations)
[FOUND] 192.168.1.15:3000 - MCP Server
[FOUND] 192.168.1.23:8080 - MCP Server
[FOUND] 192.168.1.45:3000 - MCP Server
[INFO] Scan completed: 3 MCP servers found
```

### Scenario 3: Large Network Scan (CIDR /16)

**Use Case:** Enterprise network assessment
**Risk Level:** High (requires approval)
**Time Required:** 30 minutes - 2 hours

```bash
# Conservative large network scan
python application.py scan --target 10.0.0.0/16 \
  --threads 25 \
  --timeout 10 \
  --rate-limit 50 \
  --output large_network_scan.json

# Large network with stealth settings
python application.py --quiet scan --target 10.0.0.0/16 \
  --threads 10 \
  --timeout 15 \
  --ports 3000,8000,8080,9000 \
  --log-file large_scan.log
```

**Resource Management:**
```bash
# Monitor system resources during large scans
htop  # In another terminal

# Check scan progress
tail -f large_scan.log
```

### Scenario 4: Custom Port Range Scan

**Use Case:** Scanning non-standard MCP deployments
**Risk Level:** Medium
**Time Required:** Variable

```bash
# Wide port range scan
python application.py scan --target 192.168.1.100 \
  --ports 1-65535 \
  --threads 100

# Specific port list
python application.py scan --target 192.168.1.0/24 \
  --ports 3000,3001,8000,8080,8443,9000,9001

# Custom range with UDP
python application.py scan --target 192.168.1.100 \
  --ports 3000-9000 \
  --udp \
  --tcp
```

---

## Detection Workflows

### Scenario 5: Remote Target Detection

**Use Case:** Detailed analysis of a known MCP server
**Risk Level:** Medium
**Time Required:** 2-10 minutes

```bash
# Basic target detection
python application.py detect target --target 192.168.1.100

# Comprehensive target detection
python application.py --verbose detect target --target 192.168.1.100 \
  --ports 3000,8000,8080,9000 \
  --verify-protocol \
  --detect-transport \
  --output target_detection.json

# Target detection with custom timeout
python application.py detect target --target example.com \
  --timeout 15 \
  --ports 3000-3010
```

**Expected Output:**
```
🦅 HawkEye MCP Detection
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

### Scenario 6: Local System Detection

**Use Case:** Auditing the local development environment
**Risk Level:** Low
**Time Required:** 1-5 minutes

```bash
# Full local detection
python application.py --verbose detect local

# Local detection without Docker
python application.py detect local --no-include-docker

# Local detection with output
python application.py detect local \
  --output local_detection.json \
  --format json

# Minimal local detection
python application.py detect local \
  --no-include-env \
  --no-include-docker
```

**Expected Output:**
```
🦅 HawkEye Local MCP Detection
Interface: auto-detect
Process Enumeration: Enabled
Config Discovery: Enabled
Docker Inspection: Enabled
Environment Analysis: Enabled

⠋ Local Detection... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

Local Detection Results
┏━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Target    ┃ Port ┃ Detection Method      ┃ Confidence ┃ Transport ┃
┡━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ localhost │ N/A  │ process_enumeration   │ 0.50       │ stdio     │
│ localhost │ N/A  │ config_file_discovery │ 0.70       │ http      │
│ localhost │ N/A  │ docker_inspection     │ 0.40       │ http      │
│ localhost │ N/A  │ environment_analysis  │ 0.32       │ stdio     │
└───────────┴──────┴───────────────────────┴────────────┴───────────┘

Detected 4 MCP services
```

### Scenario 7: Process-Specific Analysis

**Use Case:** Investigating a suspicious process
**Risk Level:** Low
**Time Required:** 1-3 minutes

```bash
# Find processes first
ps aux | grep node

# Analyze specific process
python application.py detect process --pid 1234

# Deep process analysis
python application.py --verbose detect process --pid 1234 \
  --deep-analysis \
  --check-children \
  --analyze-env

# Process analysis with output
python application.py detect process --pid 1234 \
  --output process_analysis.json
```

**Expected Output:**
```
🦅 HawkEye Process Analysis
Process ID: 1234
Deep Analysis: Enabled
Check Children: Enabled
Environment Analysis: Enabled

Process 1234 Analysis Results

Process Information:
  • PID: 1234
  • Name: node
  • Command: node /usr/bin/mcp-server-filesystem /path/to/project
  • Working Directory: /home/user/project
  • User: user
  • Environment Variables: 30 found

Environment Variables:
  • MCP-related variables detected
```

### Scenario 8: Configuration Discovery

**Use Case:** Finding MCP configuration files in a project
**Risk Level:** Low
**Time Required:** 1-5 minutes

```bash
# Basic config discovery
python application.py detect config

# Recursive config discovery
python application.py detect config --path /opt/mcp --recursive

# Deep config search with hidden files
python application.py --verbose detect config \
  --path /home/user/projects \
  --recursive \
  --include-hidden \
  --max-depth 10

# Config discovery with output
python application.py detect config \
  --path . \
  --output config_discovery.json
```

**Expected Output:**
```
🦅 HawkEye Configuration Discovery
Search Path: /home/user/projects
Recursive: Enabled
Include Hidden: Enabled
Max Depth: 10

Configuration Discovery Results
📁 /home/user/projects
├── 📄 package.json (2 files)
│   ├── ./project1/package.json
│   └── ./project2/package.json
├── 📄 docker-compose.yml (1 files)
│   └── ./project1/docker-compose.yml
└── 📄 dockerfile (1 files)
    └── ./project2/Dockerfile

Found 4 configuration files
```

---

## Analysis Workflows

### Scenario 9: Comprehensive Security Assessment

**Use Case:** Full security audit of MCP infrastructure
**Risk Level:** Medium
**Time Required:** 15-60 minutes

```bash
# Step 1: Network discovery
python application.py scan --target 192.168.1.0/24 \
  --output network_scan.json

# Step 2: Detailed detection on found targets
python application.py detect target --target 192.168.1.100 \
  --verify-protocol \
  --detect-transport \
  --output target_1_detection.json

# Step 3: Local system audit
python application.py detect local \
  --output local_audit.json

# Step 4: Configuration audit
python application.py detect config --path /opt \
  --recursive \
  --output config_audit.json
```

### Scenario 10: Incident Response Investigation

**Use Case:** Investigating potential MCP-related security incident
**Risk Level:** High
**Time Required:** 10-30 minutes

```bash
# Step 1: Quick local assessment
python application.py --verbose detect local \
  --output incident_local.json

# Step 2: Process investigation
# (Get PIDs from local detection results)
python application.py detect process --pid <SUSPICIOUS_PID> \
  --deep-analysis \
  --analyze-env \
  --output incident_process.json

# Step 3: Network verification
python application.py detect target --target <EXTERNAL_IP> \
  --verify-protocol \
  --output incident_network.json

# Step 4: Configuration analysis
python application.py detect config --path /var/log \
  --include-hidden \
  --output incident_config.json
```

---

## Reporting Workflows

### Scenario 11: Executive Report Generation

**Use Case:** Creating reports for management
**Risk Level:** Low
**Time Required:** 2-5 minutes

```bash
# Generate HTML executive report
python application.py report generate \
  --input network_scan.json \
  --format html \
  --output executive_report.html

# Generate CSV for spreadsheet analysis
python application.py report generate \
  --input local_audit.json \
  --format csv \
  --output audit_results.csv

# Generate XML for integration
python application.py report generate \
  --input target_detection.json \
  --format xml \
  --output integration_data.xml
```

### Scenario 12: Aggregated Analysis

**Use Case:** Combining multiple scan results
**Risk Level:** Low
**Time Required:** 5-10 minutes

```bash
# Combine multiple scan results
python application.py report aggregate \
  --input-dir ./scan_results/ \
  --output combined_analysis.json

# Generate comprehensive report
python application.py report generate \
  --input combined_analysis.json \
  --format html \
  --template comprehensive \
  --output full_assessment_report.html
```

---

## Advanced Scenarios

### Scenario 13: Automated Continuous Monitoring

**Use Case:** Regular security monitoring
**Risk Level:** Medium
**Time Required:** Setup once, runs automatically

```bash
#!/bin/bash
# monitoring_script.sh

DATE=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="./monitoring_results"

# Create results directory
mkdir -p $RESULTS_DIR

# Daily local scan
python application.py detect local \
  --output "$RESULTS_DIR/local_scan_$DATE.json"

# Weekly network scan
if [ $(date +%u) -eq 1 ]; then  # Monday
  python application.py scan --target 192.168.1.0/24 \
    --output "$RESULTS_DIR/network_scan_$DATE.json"
fi

# Generate daily report
python application.py report generate \
  --input "$RESULTS_DIR/local_scan_$DATE.json" \
  --format html \
  --output "$RESULTS_DIR/daily_report_$DATE.html"
```

### Scenario 14: Custom Configuration Scanning

**Use Case:** Organization-specific MCP detection
**Risk Level:** Medium
**Time Required:** Variable

```bash
# Create custom configuration
cat > custom_hawkeye.yaml << EOF
scanning:
  default_ports: [3000, 3001, 8000, 8080, 8443, 9000, 9001]
  default_threads: 25
  default_timeout: 10

detection:
  custom_patterns:
    - "my-company-mcp-*"
    - "internal-mcp-server"
  
reporting:
  company_template: true
  include_compliance: true
EOF

# Use custom configuration
python application.py --config-file custom_hawkeye.yaml \
  scan --target 10.0.0.0/16 \
  --output custom_scan.json
```

### Scenario 15: Integration with Security Tools

**Use Case:** Feeding results to SIEM or security platforms
**Risk Level:** Low
**Time Required:** Variable

```bash
# Generate JSON for SIEM ingestion
python application.py scan --target 192.168.1.0/24 \
  --format json \
  --output siem_feed.json

# Convert to specific formats
python application.py report generate \
  --input siem_feed.json \
  --format csv \
  --output splunk_import.csv

# Real-time monitoring with syslog
python application.py --log-file /dev/log detect local
```

---

## Troubleshooting Common Issues

### Issue 1: Permission Denied Errors

**Problem:** Cannot access certain processes or files
**Solution:**
```bash
# Check current permissions
id

# Run with appropriate permissions (if needed)
sudo python application.py detect local

# Use non-privileged alternatives
python application.py detect local --no-include-docker
```

### Issue 2: Network Timeouts

**Problem:** Scans timing out on slow networks
**Solution:**
```bash
# Increase timeout values
python application.py scan --target 192.168.1.0/24 \
  --timeout 30 \
  --threads 10

# Use conservative settings
python application.py scan --target 192.168.1.0/24 \
  --rate-limit 10 \
  --timeout 15
```

### Issue 3: Large Result Sets

**Problem:** Too much output to process
**Solution:**
```bash
# Use quiet mode
python application.py --quiet scan --target 192.168.1.0/24

# Filter results
python application.py scan --target 192.168.1.0/24 \
  --risk-threshold 0.5

# Save to file for later analysis
python application.py scan --target 192.168.1.0/24 \
  --output large_scan.json
```

### Issue 4: False Positives

**Problem:** Detecting non-MCP services as MCP
**Solution:**
```bash
# Use protocol verification
python application.py detect target --target 192.168.1.100 \
  --verify-protocol

# Manual verification
python application.py detect process --pid <PID> \
  --deep-analysis
```

---

## Best Practices

### Security Considerations

1. **Authorization:** Always obtain proper authorization before scanning
2. **Rate Limiting:** Use conservative settings for production networks
3. **Logging:** Maintain audit trails of all scanning activities
4. **Data Handling:** Secure storage and transmission of scan results

### Performance Optimization

1. **Threading:** Adjust thread count based on system capabilities
2. **Timeouts:** Set appropriate timeouts for network conditions
3. **Scope:** Limit scan scope to necessary targets only
4. **Scheduling:** Run large scans during off-peak hours

### Operational Guidelines

1. **Documentation:** Document all scanning procedures and findings
2. **Validation:** Verify results through multiple detection methods
3. **Reporting:** Generate appropriate reports for different audiences
4. **Follow-up:** Implement remediation based on findings

### Example Complete Workflow

```bash
#!/bin/bash
# complete_assessment.sh - Full MCP security assessment

echo "🦅 Starting Complete MCP Security Assessment"

# Phase 1: Local Assessment
echo "Phase 1: Local System Assessment"
python application.py --verbose detect local \
  --output phase1_local.json

# Phase 2: Network Discovery
echo "Phase 2: Network Discovery"
python application.py scan --target 192.168.1.0/24 \
  --output phase2_network.json

# Phase 3: Detailed Analysis
echo "Phase 3: Detailed Target Analysis"
# Extract IPs from network scan and analyze each
python -c "
import json
with open('phase2_network.json') as f:
    data = json.load(f)
    # Extract found IPs and create target list
"

# Phase 4: Configuration Audit
echo "Phase 4: Configuration Discovery"
python application.py detect config --path /opt \
  --recursive \
  --output phase4_config.json

# Phase 5: Report Generation
echo "Phase 5: Report Generation"
python application.py report aggregate \
  --input-dir . \
  --output final_assessment.json

python application.py report generate \
  --input final_assessment.json \
  --format html \
  --output MCP_Security_Assessment_Report.html

echo "✅ Assessment Complete - Report: MCP_Security_Assessment_Report.html"
```

This workflow guide provides comprehensive coverage of all HawkEye capabilities and scenarios. Use it as a reference for conducting thorough MCP security assessments in any environment. 