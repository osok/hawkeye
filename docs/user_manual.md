# 🦅 HawkEye User Manual
## Hidden Application Weaknesses & Key Entry-point Yielding Evaluator

### Version 1.0

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Command Reference](#command-reference)
5. [Configuration](#configuration)
6. [Scanning Strategies](#scanning-strategies)
7. [Understanding Results](#understanding-results)
8. [Advanced Usage](#advanced-usage)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)
11. [Examples](#examples)

---

## Introduction

HawkEye is a specialized security reconnaissance tool designed to identify and assess Model Context Protocol (MCP) server deployments within network infrastructure. This manual provides comprehensive guidance for security professionals, system administrators, and compliance teams.

### What HawkEye Does

- **Discovers MCP Servers**: Identifies Node.js/NPX-based MCP implementations
- **Assesses Security Posture**: Evaluates configurations and identifies vulnerabilities
- **Generates Reports**: Provides actionable intelligence in multiple formats
- **Maintains Compliance**: Operates within ethical and legal boundaries

### Who Should Use HawkEye

- Security analysts and penetration testers
- System administrators managing MCP deployments
- Compliance officers conducting security audits
- DevOps teams implementing security controls

---

## Installation

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python**: Version 3.8 or higher
- **Memory**: Minimum 512MB RAM (2GB recommended for large scans)
- **Network**: Access to target infrastructure
- **Permissions**: Standard user privileges (no root required)

### Installation Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
```

#### 2. Create Virtual Environment

```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Verify Installation

```bash
python application.py --help
```

### Docker Installation (Alternative)

```bash
# Build the container
docker build -t hawkeye .

# Run HawkEye
docker run -it hawkeye scan --target 192.168.1.0/24
```

---

## Getting Started

### First Scan

Start with a simple scan of a single IP address:

```bash
python application.py scan --target 192.168.1.100
```

### Understanding Output

HawkEye provides real-time feedback during scanning:

```
🦅 HawkEye v1.0 - MCP Security Reconnaissance
[INFO] Starting scan of target: 192.168.1.100
[INFO] Scanning ports: 3000, 8000, 8080, 9000
[PROGRESS] ████████████████████ 100% (4/4 ports)
[FOUND] 192.168.1.100:3000 - MCP Server (Node.js)
[RISK] Medium risk: Default configuration detected
[INFO] Scan completed in 12.3 seconds
[INFO] Results saved to: hawkeye_scan_YYYYMMDD_HHMMSS.json
```

### Basic Workflow

1. **Plan Your Scan**: Define target scope and objectives
2. **Execute Scan**: Run HawkEye with appropriate parameters
3. **Analyze Results**: Review findings and risk assessments
4. **Generate Reports**: Create documentation for stakeholders
5. **Take Action**: Implement remediation recommendations

---

## Command Reference

### Main Commands

#### `scan` - Network Scanning

Performs comprehensive network scanning to discover MCP services.

```bash
python application.py scan [OPTIONS]
```

**Required Options:**
- `--target <CIDR|IP>`: Target specification (IP address or CIDR range)

**Optional Parameters:**
- `--ports <range>`: Port range to scan (default: 3000,8000,8080,9000)
- `--threads <count>`: Number of concurrent threads (default: 50)
- `--timeout <seconds>`: Connection timeout (default: 5)
- `--tcp/--no-tcp`: Enable/disable TCP scanning (default: enabled)
- `--udp/--no-udp`: Enable/disable UDP scanning (default: disabled)
- `--output <path>`: Output file path
- `--format <json|csv|xml>`: Output format (default: json)

**Examples:**
```bash
# Scan single IP
python application.py scan --target 192.168.1.100

# Scan CIDR range with custom ports
python application.py scan --target 192.168.1.0/24 --ports 3000-9000

# Scan with UDP enabled and custom threading
python application.py scan --target 10.0.0.0/16 --udp --threads 25
```

#### `detect` - MCP Detection

Performs detailed MCP service analysis. This is a command group with multiple subcommands.

**Subcommands:**
- `detect target`: Detect MCP servers on specified target
- `detect local`: Detect MCP servers on local system  
- `detect process`: Analyze specific process for MCP indicators
- `detect config`: Discover MCP configuration files

##### `detect target` - Target Detection

```bash
python application.py detect target [OPTIONS]
```

**Required Options:**
- `--target <IP>`: Target IP address or hostname

**Optional Parameters:**
- `--ports <ports>`: Port range or comma-separated ports (default: 3000,8000,8080,9000)
- `--timeout <seconds>`: Connection timeout (default: 10)
- `--verify-protocol/--no-verify-protocol`: Verify MCP protocol handshake (default: enabled)
- `--detect-transport/--no-detect-transport`: Detect transport layer (default: enabled)
- `--output <path>`: Output file path
- `--format <json|csv|xml>`: Output format (default: json)

**Examples:**
```bash
# Basic target detection
python application.py detect target --target 192.168.1.100

# Detection with custom ports
python application.py detect target --target example.com --ports 3000-3010
```

##### `detect local` - Local Detection

```bash
python application.py detect local [OPTIONS]
```

**Optional Parameters:**
- `--interface <interface>`: Network interface to scan (default: auto-detect)
- `--include-processes/--no-include-processes`: Include process enumeration (default: enabled)
- `--include-configs/--no-include-configs`: Include config discovery (default: enabled)
- `--include-docker/--no-include-docker`: Include Docker inspection (default: enabled)
- `--include-env/--no-include-env`: Include environment analysis (default: enabled)
- `--output <path>`: Output file path
- `--format <json|csv|xml>`: Output format (default: json)

**Examples:**
```bash
# Full local detection
python application.py detect local

# Local detection without environment analysis
python application.py detect local --no-include-env
```

##### `detect process` - Process Analysis

```bash
python application.py detect process [OPTIONS]
```

**Required Options:**
- `--pid <PID>`: Process ID to analyze

**Optional Parameters:**
- `--deep-analysis/--no-deep-analysis`: Perform deep process analysis (default: enabled)
- `--check-children/--no-check-children`: Check child processes (default: enabled)
- `--analyze-env/--no-analyze-env`: Analyze environment variables (default: enabled)
- `--output <path>`: Output file path
- `--format <json|csv|xml>`: Output format (default: json)

**Examples:**
```bash
# Analyze specific process
python application.py detect process --pid 1234

# Basic process analysis without children
python application.py detect process --pid 5678 --no-check-children
```

##### `detect config` - Configuration Discovery

```bash
python application.py detect config [OPTIONS]
```

**Optional Parameters:**
- `--path <path>`: Path to search (default: current directory)
- `--recursive/--no-recursive`: Search recursively (default: enabled)
- `--include-hidden/--no-include-hidden`: Include hidden files (default: disabled)
- `--max-depth <depth>`: Maximum directory depth (default: 5)
- `--output <path>`: Output file path
- `--format <json|csv|xml>`: Output format (default: json)

**Examples:**
```bash
# Discover configs in current directory
python application.py detect config

# Deep config search with hidden files
python application.py detect config --path /opt/mcp --include-hidden --max-depth 10
```

##### `detect introspect` - MCP Introspection

Performs comprehensive introspection of discovered MCP servers using the Python-based introspection system. This command directly communicates with MCP servers to discover their capabilities, tools, resources, and security implications.

```bash
python application.py detect introspect [OPTIONS]
```

**Required Options:**
- `--target <IP|hostname>`: Target MCP server address
- `--server-id <id>`: Unique identifier for the server (if known)

**Optional Parameters:**
- `--transport <stdio|sse|http>`: Force specific transport type (default: auto-detect)
- `--timeout <seconds>`: Connection timeout (default: 30)
- `--max-retries <count>`: Maximum retry attempts (default: 3)
- `--enable-caching/--no-caching`: Enable result caching (default: enabled)
- `--cache-ttl <seconds>`: Cache time-to-live (default: 300)
- `--risk-analysis/--no-risk-analysis`: Enable comprehensive risk analysis (default: enabled)
- `--concurrent-limit <count>`: Maximum concurrent connections (default: 5)
- `--output <path>`: Output file path
- `--format <json|html|markdown|csv>`: Output format (default: json)
- `--include-tools/--no-tools`: Include tool discovery (default: enabled)
- `--include-resources/--no-resources`: Include resource discovery (default: enabled)
- `--include-capabilities/--no-capabilities`: Include capability discovery (default: enabled)

**Examples:**
```bash
# Basic server introspection
python application.py detect introspect --target 192.168.1.100 --server-id mcp-server-1

# Introspection with specific transport
python application.py detect introspect --target localhost:3000 --transport stdio --server-id local-server

# Full introspection with risk analysis
python application.py detect introspect --target api.example.com --risk-analysis --format html

# Batch introspection with caching disabled
python application.py detect introspect --target 192.168.1.100 --no-caching --concurrent-limit 10
```

**Output Includes:**
- **Server Information**: Name, version, protocol details
- **Tool Inventory**: Available tools with descriptions and schemas
- **Resource Catalog**: Accessible resources and their types
- **Capability Assessment**: Supported MCP features and extensions
- **Risk Analysis**: Security assessment and threat modeling
- **Performance Metrics**: Connection statistics and timing information

**Security Features:**
- **521+ Risk Patterns**: Comprehensive security pattern matching
- **CWE Mapping**: Common Weakness Enumeration integration
- **CVSS-like Scoring**: Industry-standard risk scoring
- **Threat Modeling**: Capability-based security assessment
- **Attack Vector Analysis**: Potential security vulnerabilities

##### `detect introspect-batch` - Batch MCP Introspection

Performs introspection on multiple MCP servers concurrently for efficiency in large deployments.

```bash
python application.py detect introspect-batch [OPTIONS]
```

**Required Options:**
- `--servers-file <path>`: JSON file containing server configurations
- OR `--targets <targets>`: Comma-separated list of server addresses

**Optional Parameters:**
- `--max-concurrent <count>`: Maximum concurrent introspections (default: 10)
- `--timeout <seconds>`: Per-server timeout (default: 30)
- `--output <path>`: Output file path
- `--format <json|html|csv>`: Output format (default: json)
- `--continue-on-error/--stop-on-error`: Error handling strategy (default: continue)
- `--progress/--no-progress`: Show progress indicators (default: enabled)

**Server Configuration File Format:**
```json
{
  "servers": [
    {
      "server_id": "production-mcp-1",
      "target": "192.168.1.100:3000",
      "transport": "stdio",
      "timeout": 45
    },
    {
      "server_id": "api-gateway",
      "target": "api.example.com",
      "transport": "http",
      "timeout": 30
    }
  ]
}
```

**Examples:**
```bash
# Batch introspection from configuration file
python application.py detect introspect-batch --servers-file mcp_servers.json --format html

# Quick batch introspection of multiple targets
python application.py detect introspect-batch --targets "192.168.1.100,192.168.1.101,192.168.1.102"

# Large-scale batch with custom concurrency
python application.py detect introspect-batch --servers-file large_deployment.json --max-concurrent 20
```

#### `report` - Report Generation

Generates formatted reports from scan results.

```bash
python application.py report [OPTIONS]
```

**Required Options:**
- `--input <path>`: Input scan results file

**Optional Parameters:**
- `--format <json|csv|xml|html>`: Output format (default: html)
- `--output <path>`: Output file path
- `--template <name>`: Report template to use
- `--risk-threshold <level>`: Minimum risk level to include

**Examples:**
```bash
# Generate HTML report
python application.py report --input scan_results.json --format html

# Executive summary
python application.py report --input scan_results.json --template executive
```

### Utility Commands

#### `scan-local` - Local System Scan

Scans the local system for MCP services.

```bash
python application.py scan-local [OPTIONS]
```

#### `analyze-process` - Process Analysis

Analyzes a specific process for MCP indicators.

```bash
python application.py analyze-process --pid <PID>
```

#### `config` - Configuration Management

Manages HawkEye configuration settings.

```bash
python application.py config [show|set|reset]
```

---

## Configuration

### Configuration File

HawkEye supports configuration files for persistent settings:

```yaml
# hawkeye.yaml
scanning:
  default_ports: [3000, 8000, 8080, 9000]
  default_threads: 50
  default_timeout: 5
  rate_limit: 100

detection:
  deep_inspection: false
  protocol_verification: true
  docker_inspection: true

reporting:
  default_format: json
  include_metadata: true
  risk_threshold: 0.0

logging:
  level: INFO
  file: hawkeye.log
  audit_trail: true
```

### Environment Variables

Configure HawkEye using environment variables:

```bash
export HAWKEYE_THREADS=25
export HAWKEYE_TIMEOUT=10
export HAWKEYE_RATE_LIMIT=50
export HAWKEYE_LOG_LEVEL=DEBUG
```

### Command-Line Configuration

```bash
# Load configuration file
python application.py --config hawkeye.yaml scan --target 192.168.1.0/24

# Override specific settings
python application.py scan --target 192.168.1.0/24 --threads 100 --timeout 3
```

---

## Scanning Strategies

### Small Networks (< 256 hosts)

For small networks, use aggressive scanning for comprehensive coverage:

```bash
python application.py scan --target 192.168.1.0/24 \
  --ports 1-65535 \
  --threads 100 \
  --timeout 3
```

### Large Networks (> 1000 hosts)

For large networks, use conservative settings to avoid detection:

```bash
python application.py scan --target 10.0.0.0/16 \
  --ports 3000,8000,8080,9000 \
  --threads 25 \
  --rate-limit 25 \
  --timeout 10
```

### Stealth Scanning

For maximum stealth, use minimal footprint settings:

```bash
python application.py scan --target 192.168.1.0/24 \
  --threads 5 \
  --rate-limit 5 \
  --timeout 15 \
  --random-delay
```

### Production Environment Scanning

For production environments, prioritize stability:

```bash
python application.py scan --target production.network.com \
  --threads 10 \
  --rate-limit 10 \
  --timeout 20 \
  --retry 3 \
  --exclude-critical-hours
```

---

## Understanding Results

### Risk Scoring

HawkEye uses CVSS-based scoring with contextual adjustments:

- **Critical (9.0-10.0)**: Immediate action required
- **High (7.0-8.9)**: High priority remediation
- **Medium (4.0-6.9)**: Moderate risk, plan remediation
- **Low (0.1-3.9)**: Low risk, monitor
- **Info (0.0)**: Informational findings

### Vulnerability Categories

#### Configuration Issues
- Default credentials
- Weak authentication
- Insecure transport
- Excessive permissions

#### Protocol Vulnerabilities
- Unencrypted communications
- Missing authentication
- Protocol version issues
- Insecure endpoints

#### Deployment Issues
- Public accessibility
- Development configurations in production
- Missing security headers
- Inadequate logging

### MCP Introspection Results

The new Python-based MCP introspection system provides comprehensive analysis of discovered MCP servers. Understanding these results is crucial for effective security assessment.

#### Introspection Report Structure

**Server Information Section:**
```json
{
  "server_info": {
    "server_id": "production-mcp-1",
    "server_name": "File Management Server",
    "server_version": "1.2.3",
    "protocol_version": "2024-11-05",
    "discovery_timestamp": "2024-12-28T10:30:00Z",
    "transport_type": "stdio",
    "overall_risk_level": "high"
  }
}
```

**Tools Analysis:**
```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read contents of a file",
      "risk_level": "high",
      "risk_categories": ["file_system", "data_access"],
      "security_implications": [
        "Potential for unauthorized file access",
        "Risk of sensitive data exposure"
      ],
      "parameters": [
        {
          "name": "path",
          "type": "string",
          "required": true,
          "description": "File path to read"
        }
      ]
    }
  ]
}
```

**Risk Assessment Summary:**
```json
{
  "risk_summary": {
    "overall_risk": "high",
    "cvss_score": 7.8,
    "risk_factors": {
      "file_system_access": true,
      "network_access": true,
      "code_execution": false,
      "data_modification": true
    },
    "threat_vectors": [
      "Unauthorized file system access",
      "Data exfiltration via network tools",
      "Configuration manipulation"
    ]
  }
}
```

#### Risk Categories Explained

**File System Access (HIGH RISK)**
- Tools that can read, write, or modify files
- Risk of unauthorized data access or system modification
- Examples: `read_file`, `write_file`, `list_directory`

**Network Access (HIGH RISK)**
- Tools that can make external network connections
- Risk of data exfiltration or external system compromise
- Examples: `web_search`, `http_request`, `api_call`

**Code Execution (CRITICAL RISK)**
- Tools that can execute arbitrary code or commands
- Maximum security risk requiring immediate attention
- Examples: `execute_command`, `run_script`, `eval_code`

**Data Access (MEDIUM RISK)**
- Tools that can access databases or structured data
- Risk depends on sensitivity of accessible data
- Examples: `database_query`, `csv_read`, `json_parse`

**System Modification (HIGH RISK)**
- Tools that can modify system configuration
- Risk of system compromise or denial of service
- Examples: `modify_config`, `install_package`, `restart_service`

**Authentication (MEDIUM RISK)**
- Tools that handle authentication or credentials
- Risk of credential exposure or bypass
- Examples: `authenticate_user`, `store_credentials`

#### Threat Modeling Results

**Attack Vector Analysis:**
- **Direct Access**: Tools accessible without authentication
- **Privilege Escalation**: Tools that can increase access levels
- **Lateral Movement**: Tools that can access other systems
- **Data Exfiltration**: Tools that can extract sensitive information
- **System Disruption**: Tools that can cause service interruption

**Capability Mapping:**
- **Read Operations**: What data can be accessed
- **Write Operations**: What can be modified or created
- **Execute Operations**: What commands or code can be run
- **Network Operations**: What external connections are possible

#### Security Recommendations

**Immediate Actions (Critical/High Risk):**
1. **Disable unnecessary tools** with code execution capabilities
2. **Implement authentication** for all tool access
3. **Restrict file system access** to necessary directories only
4. **Monitor network connections** from MCP servers
5. **Review tool permissions** and implement least privilege

**Medium-Term Actions (Medium Risk):**
1. **Implement input validation** for all tool parameters
2. **Add audit logging** for all tool usage
3. **Set up monitoring** for unusual activity patterns
4. **Create backup policies** for systems with write access
5. **Document security controls** and review regularly

**Long-Term Actions (Low Risk/Informational):**
1. **Regular security assessments** using HawkEye introspection
2. **Security awareness training** for MCP administrators
3. **Incident response procedures** for MCP-related security events
4. **Policy development** for MCP deployment and usage

#### Performance Metrics

The introspection system provides performance insights:

```json
{
  "performance_metrics": {
    "introspection_duration": 12.5,
    "tools_discovered": 15,
    "resources_discovered": 8,
    "transport_efficiency": 0.95,
    "cache_hit_rate": 0.65,
    "connection_success_rate": 1.0
  }
}
```

**Key Performance Indicators:**
- **Introspection Duration**: Time taken for complete analysis
- **Discovery Success Rate**: Percentage of successful component discoveries
- **Transport Efficiency**: Connection utilization effectiveness
- **Cache Hit Rate**: Efficiency of result caching
- **Error Rate**: Frequency of connection or protocol errors

#### Interpreting Risk Scores

**CVSS-like Scoring (0.0-10.0):**
- **9.0-10.0 (Critical)**: Immediate remediation required
- **7.0-8.9 (High)**: High priority, remediate within 24-48 hours
- **4.0-6.9 (Medium)**: Moderate priority, remediate within 1-2 weeks
- **0.1-3.9 (Low)**: Low priority, monitor and plan remediation
- **0.0 (Informational)**: No immediate security risk

**Composite Scoring Factors:**
- **Tool Risk Level**: Based on capability analysis
- **Access Control**: Authentication and authorization presence
- **Network Exposure**: Public accessibility and transport security
- **Data Sensitivity**: Type and classification of accessible data
- **System Criticality**: Importance of the affected system

### Report Sections

#### Executive Summary
- High-level risk assessment
- Key findings overview
- Remediation priorities
- Compliance status

#### Technical Details
- Detailed vulnerability descriptions
- Proof-of-concept information
- Technical remediation steps
- Reference materials

#### Appendices
- Scan methodology
- Tool configuration
- Raw scan data
- Glossary of terms

---

## Advanced Usage

### Custom Port Lists

Create custom port lists for specific environments:

```bash
# Web-focused scanning
python application.py scan --target 192.168.1.0/24 --ports 80,443,8080,8443

# Development environment scanning
python application.py scan --target 192.168.1.0/24 --ports 3000-3010,8000-8010
```

### Scripted Scanning

Automate HawkEye for regular assessments:

```bash
#!/bin/bash
# daily_scan.sh

DATE=$(date +%Y%m%d)
TARGETS=("192.168.1.0/24" "10.0.1.0/24" "172.16.1.0/24")

for target in "${TARGETS[@]}"; do
    python application.py scan \
        --target "$target" \
        --output "scan_${target//\//_}_${DATE}.json" \
        --format json
done

# Generate consolidated report
python application.py report \
    --input "scan_*_${DATE}.json" \
    --format html \
    --output "daily_report_${DATE}.html"
```

### Integration with CI/CD

Integrate HawkEye into continuous integration pipelines:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install HawkEye
        run: pip install -r requirements.txt
      - name: Run Security Scan
        run: |
          python application.py scan \
            --target ${{ secrets.SCAN_TARGET }} \
            --output scan_results.json
      - name: Generate Report
        run: |
          python application.py report \
            --input scan_results.json \
            --format html \
            --output security_report.html
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-results
          path: |
            scan_results.json
            security_report.html
```

---

## Best Practices

### Pre-Scan Preparation

1. **Obtain Authorization**: Ensure written permission for all scanning activities
2. **Define Scope**: Clearly identify target networks and exclusions
3. **Plan Timing**: Schedule scans during maintenance windows when possible
4. **Prepare Documentation**: Have incident response procedures ready

### During Scanning

1. **Monitor Impact**: Watch for network performance degradation
2. **Respect Rate Limits**: Use conservative settings for production systems
3. **Maintain Logs**: Keep detailed records of all activities
4. **Be Responsive**: Be prepared to stop scanning if issues arise

### Post-Scan Activities

1. **Secure Results**: Protect scan data with appropriate access controls
2. **Validate Findings**: Verify vulnerabilities before reporting
3. **Prioritize Remediation**: Focus on highest-risk issues first
4. **Track Progress**: Monitor remediation efforts over time

### Legal and Ethical Considerations

1. **Authorization**: Never scan without explicit permission
2. **Scope Compliance**: Stay within authorized boundaries
3. **Data Protection**: Handle scan results as sensitive information
4. **Responsible Disclosure**: Follow proper vulnerability disclosure procedures

---

## Troubleshooting

### Common Issues

#### "Permission Denied" Errors

**Symptoms**: Cannot bind to ports or access network interfaces
**Solution**: 
```bash
# Run with appropriate permissions
sudo python application.py scan --target 192.168.1.0/24

# Or use unprivileged ports only
python application.py scan --target 192.168.1.0/24 --source-port 32768-65535
```

#### "Connection Timeout" Errors

**Symptoms**: Many timeouts during scanning
**Solutions**:
```bash
# Increase timeout values
python application.py scan --target 192.168.1.0/24 --timeout 15

# Reduce thread count
python application.py scan --target 192.168.1.0/24 --threads 10

# Add retry attempts
python application.py scan --target 192.168.1.0/24 --retry 3
```

#### "Rate Limit Exceeded" Errors

**Symptoms**: Scanning stops due to rate limiting
**Solutions**:
```bash
# Reduce rate limit
python application.py scan --target 192.168.1.0/24 --rate-limit 25

# Increase delay between requests
python application.py scan --target 192.168.1.0/24 --delay 100
```

#### Memory Issues

**Symptoms**: High memory usage or out-of-memory errors
**Solutions**:
```bash
# Reduce thread count
python application.py scan --target 192.168.1.0/24 --threads 25

# Scan smaller ranges
python application.py scan --target 192.168.1.0/25
python application.py scan --target 192.168.1.128/25
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
python application.py --debug scan --target 192.168.1.100
```

### Log Analysis

Review logs for detailed error information:

```bash
# View recent logs
tail -f hawkeye.log

# Search for specific errors
grep "ERROR" hawkeye.log

# Analyze scan statistics
grep "STATS" hawkeye.log
```

---

## Examples

### Example 1: Basic Network Assessment

**Scenario**: Assess a small office network for MCP services

```bash
# Initial discovery scan
python application.py scan --target 192.168.1.0/24 --output office_scan.json

# Generate executive report
python application.py report --input office_scan.json --format html --template executive

# Detailed analysis of discovered services
python application.py detect --target 192.168.1.100 --deep --output detailed_analysis.json
```

### Example 2: Large Enterprise Scan

**Scenario**: Scan multiple enterprise network segments

```bash
# Create scan script
cat > enterprise_scan.sh << 'EOF'
#!/bin/bash
SEGMENTS=("10.1.0.0/16" "10.2.0.0/16" "10.3.0.0/16")
DATE=$(date +%Y%m%d_%H%M%S)

for segment in "${SEGMENTS[@]}"; do
    echo "Scanning $segment..."
    python application.py scan \
        --target "$segment" \
        --threads 50 \
        --rate-limit 100 \
        --timeout 10 \
        --output "scan_${segment//\//_}_${DATE}.json" \
        --format json
done

# Consolidate results
python application.py report \
    --input "scan_*_${DATE}.json" \
    --format html \
    --template comprehensive \
    --output "enterprise_report_${DATE}.html"
EOF

chmod +x enterprise_scan.sh
./enterprise_scan.sh
```

### Example 3: Compliance Scanning

**Scenario**: Regular compliance scanning for audit purposes

```bash
# Create compliance configuration
cat > compliance.yaml << 'EOF'
scanning:
  default_ports: [3000, 8000, 8080, 9000]
  default_threads: 25
  default_timeout: 10
  rate_limit: 50

detection:
  deep_inspection: true
  protocol_verification: true
  compliance_checks: true

reporting:
  default_format: html
  template: compliance
  include_metadata: true
  risk_threshold: 4.0

logging:
  level: INFO
  audit_trail: true
  compliance_logging: true
EOF

# Run compliance scan
python application.py --config compliance.yaml scan \
    --target 192.168.0.0/16 \
    --output compliance_scan_$(date +%Y%m%d).json

# Generate compliance report
python application.py report \
    --input compliance_scan_$(date +%Y%m%d).json \
    --format html \
    --template compliance \
    --output compliance_report_$(date +%Y%m%d).html
```

### Example 4: Continuous Monitoring

**Scenario**: Set up continuous monitoring for MCP services

```bash
# Create monitoring script
cat > monitor.sh << 'EOF'
#!/bin/bash
TARGETS_FILE="targets.txt"
BASELINE_DIR="baselines"
ALERTS_DIR="alerts"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BASELINE_DIR" "$ALERTS_DIR"

while IFS= read -r target; do
    echo "Monitoring $target..."
    
    # Current scan
    python application.py scan \
        --target "$target" \
        --output "current_${target//\//_}.json" \
        --format json
    
    # Compare with baseline
    if [ -f "$BASELINE_DIR/baseline_${target//\//_}.json" ]; then
        python application.py compare \
            --baseline "$BASELINE_DIR/baseline_${target//\//_}.json" \
            --current "current_${target//\//_}.json" \
            --output "$ALERTS_DIR/changes_${target//\//_}_${DATE}.json"
    else
        # Create baseline
        cp "current_${target//\//_}.json" "$BASELINE_DIR/baseline_${target//\//_}.json"
    fi
    
    # Clean up
    rm "current_${target//\//_}.json"
    
done < "$TARGETS_FILE"
EOF

# Create targets file
echo "192.168.1.0/24" > targets.txt
echo "10.0.1.0/24" >> targets.txt

# Set up cron job for hourly monitoring
echo "0 * * * * /path/to/monitor.sh" | crontab -
```

### Example 5: MCP Server Introspection

**Scenario**: Comprehensive security analysis of discovered MCP servers using the new Python-based introspection system

```bash
# Basic MCP server introspection
python application.py detect introspect \
    --target 192.168.1.100:3000 \
    --server-id production-mcp-1 \
    --risk-analysis \
    --format html \
    --output mcp_introspection_report.html

# Introspection with specific transport
python application.py detect introspect \
    --target localhost:3000 \
    --transport stdio \
    --server-id local-dev-server \
    --timeout 60 \
    --format json

# Detailed introspection with caching disabled for fresh analysis
python application.py detect introspect \
    --target api.example.com \
    --server-id api-gateway \
    --no-caching \
    --concurrent-limit 1 \
    --format markdown \
    --output detailed_analysis.md
```

### Example 6: Batch MCP Introspection

**Scenario**: Analyze multiple MCP servers across the enterprise infrastructure

```bash
# Create server configuration file
cat > mcp_servers.json << 'EOF'
{
  "servers": [
    {
      "server_id": "production-fileserver",
      "target": "192.168.1.100:3000",
      "transport": "stdio",
      "timeout": 45
    },
    {
      "server_id": "api-gateway",
      "target": "api.internal.company.com",
      "transport": "http",
      "timeout": 30
    },
    {
      "server_id": "development-server",
      "target": "dev.company.com:8080",
      "transport": "sse",
      "timeout": 60
    },
    {
      "server_id": "data-processor",
      "target": "192.168.2.50:9000",
      "transport": "stdio",
      "timeout": 40
    }
  ]
}
EOF

# Run batch introspection
python application.py detect introspect-batch \
    --servers-file mcp_servers.json \
    --max-concurrent 5 \
    --format html \
    --output batch_introspection_report.html \
    --progress

# Alternative: Quick batch introspection from command line
python application.py detect introspect-batch \
    --targets "192.168.1.100,192.168.1.101,192.168.1.102" \
    --max-concurrent 3 \
    --format csv \
    --output quick_batch_results.csv
```

### Example 7: Security-Focused Introspection

**Scenario**: Security assessment focusing on high-risk tools and capabilities

```bash
# High-security introspection with detailed risk analysis
python application.py detect introspect \
    --target secure.company.com \
    --server-id security-critical-server \
    --risk-analysis \
    --timeout 90 \
    --max-retries 5 \
    --format json \
    --output security_assessment.json

# Parse and analyze security results
cat security_assessment.json | jq '.risk_summary.threat_vectors'
cat security_assessment.json | jq '.tools[] | select(.risk_level == "critical" or .risk_level == "high")'

# Generate security-focused report
python application.py report \
    --input security_assessment.json \
    --format html \
    --template security \
    --risk-threshold 7.0 \
    --output security_report.html
```

### Example 8: Performance Monitoring and Optimization

**Scenario**: Monitor introspection performance and optimize for large deployments

```bash
# Performance-optimized introspection
python application.py detect introspect \
    --target large-deployment.company.com \
    --server-id large-scale-server \
    --enable-caching \
    --cache-ttl 600 \
    --concurrent-limit 15 \
    --format json \
    --output performance_test.json

# Extract performance metrics
cat performance_test.json | jq '.performance_metrics'

# Batch introspection with performance monitoring
python application.py detect introspect-batch \
    --servers-file large_servers.json \
    --max-concurrent 20 \
    --format json \
    --output performance_batch.json \
    --progress

# Analyze batch performance
cat performance_batch.json | jq '.performance_summary'
```

### Example 9: Automated Introspection Pipeline

**Scenario**: Create an automated pipeline for regular MCP security assessment

```bash
# Create automated introspection script
cat > automated_introspection.sh << 'EOF'
#!/bin/bash

# Configuration
DATE=$(date +%Y%m%d_%H%M%S)
SERVERS_CONFIG="mcp_servers.json"
OUTPUT_DIR="introspection_results"
REPORT_DIR="reports"
ARCHIVE_DIR="archive"

# Create directories
mkdir -p "$OUTPUT_DIR" "$REPORT_DIR" "$ARCHIVE_DIR"

echo "🦅 HawkEye Automated MCP Introspection - $DATE"

# Step 1: Discovery scan to find new MCP servers
echo "Step 1: Network discovery..."
python application.py scan \
    --target 192.168.0.0/16 \
    --ports 3000,8000,8080,9000 \
    --output "$OUTPUT_DIR/discovery_$DATE.json"

# Step 2: Extract MCP servers from discovery results
echo "Step 2: Processing discovery results..."
# (This would typically involve parsing discovery results to update servers config)

# Step 3: Comprehensive introspection
echo "Step 3: MCP server introspection..."
python application.py detect introspect-batch \
    --servers-file "$SERVERS_CONFIG" \
    --max-concurrent 10 \
    --format json \
    --output "$OUTPUT_DIR/introspection_$DATE.json" \
    --progress

# Step 4: Generate reports
echo "Step 4: Generating reports..."

# Executive summary
python application.py report \
    --input "$OUTPUT_DIR/introspection_$DATE.json" \
    --format html \
    --template executive \
    --output "$REPORT_DIR/executive_summary_$DATE.html"

# Technical report
python application.py report \
    --input "$OUTPUT_DIR/introspection_$DATE.json" \
    --format html \
    --template technical \
    --output "$REPORT_DIR/technical_report_$DATE.html"

# Security-focused report
python application.py report \
    --input "$OUTPUT_DIR/introspection_$DATE.json" \
    --format html \
    --template security \
    --risk-threshold 4.0 \
    --output "$REPORT_DIR/security_assessment_$DATE.html"

# CSV export for analysis
python application.py report \
    --input "$OUTPUT_DIR/introspection_$DATE.json" \
    --format csv \
    --output "$REPORT_DIR/data_export_$DATE.csv"

# Step 5: Security analysis
echo "Step 5: Security analysis..."

# Extract high-risk findings
jq '.servers[] | select(.overall_risk_level == "critical" or .overall_risk_level == "high")' \
    "$OUTPUT_DIR/introspection_$DATE.json" > "$OUTPUT_DIR/high_risk_servers_$DATE.json"

# Count findings by risk level
echo "Risk Level Summary:"
jq -r '.servers[].overall_risk_level' "$OUTPUT_DIR/introspection_$DATE.json" | sort | uniq -c

# Step 6: Archive old results
echo "Step 6: Archiving old results..."
find "$OUTPUT_DIR" -name "*.json" -mtime +30 -exec mv {} "$ARCHIVE_DIR/" \;
find "$REPORT_DIR" -name "*.html" -mtime +30 -exec mv {} "$ARCHIVE_DIR/" \;

echo "✅ Automated introspection completed successfully!"
echo "📊 Reports available in: $REPORT_DIR"
echo "📁 Raw data available in: $OUTPUT_DIR"

# Send notification (optional)
if command -v mail &> /dev/null; then
    echo "MCP introspection completed for $DATE. Reports available at $REPORT_DIR" | \
        mail -s "HawkEye MCP Introspection Report - $DATE" security-team@company.com
fi
EOF

# Make script executable
chmod +x automated_introspection.sh

# Set up daily automated introspection
echo "0 6 * * * /path/to/automated_introspection.sh" | crontab -

# Run manually
./automated_introspection.sh
```

### Example 10: Integration with Security Tools

**Scenario**: Integrate MCP introspection results with other security tools and workflows

```bash
# Export to SIEM format
python application.py detect introspect \
    --target critical.company.com \
    --server-id critical-server \
    --format json \
    --output introspection_results.json

# Convert to SIEM-compatible format
jq '.tools[] | {
    timestamp: .discovery_timestamp,
    source: "hawkeye-mcp",
    severity: .risk_level,
    category: .risk_categories[0],
    message: ("MCP tool " + .name + " has " + .risk_level + " risk"),
    tool_name: .name,
    description: .description,
    server_id: "critical-server"
}' introspection_results.json > siem_events.json

# Send to vulnerability management system
# (Example integration - adapt to your VM system API)
curl -X POST https://vm.company.com/api/vulnerabilities \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $VM_API_TOKEN" \
    -d @introspection_results.json

# Generate tickets for high-risk findings
jq -r '.tools[] | select(.risk_level == "critical" or .risk_level == "high") | 
    "Title: Critical MCP Tool: " + .name + "\n" +
    "Description: " + .description + "\n" +
    "Risk Level: " + .risk_level + "\n" +
    "Categories: " + (.risk_categories | join(", ")) + "\n" +
    "Server: critical-server\n\n"' introspection_results.json > security_tickets.txt

# Integration with Slack notifications
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
CRITICAL_COUNT=$(jq '[.tools[] | select(.risk_level == "critical")] | length' introspection_results.json)
HIGH_COUNT=$(jq '[.tools[] | select(.risk_level == "high")] | length' introspection_results.json)

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-type: application/json' \
        --data "{
            \"text\": \"🚨 HawkEye MCP Security Alert\",
            \"attachments\": [{
                \"color\": \"danger\",
                \"fields\": [
                    {\"title\": \"Critical Risk Tools\", \"value\": \"$CRITICAL_COUNT\", \"short\": true},
                    {\"title\": \"High Risk Tools\", \"value\": \"$HIGH_COUNT\", \"short\": true},
                    {\"title\": \"Server\", \"value\": \"critical-server\", \"short\": true}
                ]
            }]
        }"
fi
```

---

## Conclusion

HawkEye provides comprehensive MCP security assessment capabilities for organizations of all sizes. By following the guidelines in this manual, security professionals can effectively identify and assess MCP-related security risks while maintaining operational responsibility and compliance.

For additional support, consult the troubleshooting guide or contact the HawkEye support team.

---

**Document Version**: 1.0  
**Last Updated**: Current Version  
**Next Review**: Quarterly 