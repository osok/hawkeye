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

---

## Conclusion

HawkEye provides comprehensive MCP security assessment capabilities for organizations of all sizes. By following the guidelines in this manual, security professionals can effectively identify and assess MCP-related security risks while maintaining operational responsibility and compliance.

For additional support, consult the troubleshooting guide or contact the HawkEye support team.

---

**Document Version**: 1.0  
**Last Updated**: Current Version  
**Next Review**: Quarterly 