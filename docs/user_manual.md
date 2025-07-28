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
- AI/ML engineers assessing MCP tool security
- Threat researchers studying MCP attack vectors

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

## 🤖 AI-Powered Threat Analysis

HawkEye now includes sophisticated AI-powered threat analysis capabilities that provide dynamic, context-aware security assessment of MCP tools and servers.

### What is AI Threat Analysis?

The AI threat analysis system uses advanced language models to:

- **Analyze MCP Tool Capabilities**: Dynamically assess the security implications of discovered MCP tools
- **Generate Attack Vectors**: Identify potential attack paths and exploitation scenarios
- **Assess Risk Context**: Consider deployment environment, security posture, and compliance requirements
- **Provide Mitigation Strategies**: Recommend specific security controls and remediation steps
- **Learn from Patterns**: Build threat intelligence from previous analyses

### Key Features

#### 🧠 **Multi-Provider AI Support**
- **OpenAI Integration**: GPT-4 and GPT-3.5 models for threat analysis
- **Anthropic Integration**: Claude models for alternative AI perspectives
- **Local LLM Support**: Privacy-focused analysis using local language models
- **Intelligent Failover**: Automatic provider switching based on availability and performance

#### 🔍 **Advanced Analysis Capabilities**
- **Capability Categorization**: Automatic classification of MCP tools by risk category
- **Attack Chain Detection**: Identification of multi-tool attack scenarios
- **Context-Aware Assessment**: Environment-specific threat modeling
- **Confidence Scoring**: Dynamic confidence assessment with 9-factor analysis
- **Cost Optimization**: Intelligent AI usage optimization to minimize costs

#### 🛡️ **Threat Intelligence Database**
- **Learning System**: Pattern recognition from historical analyses
- **Similarity Matching**: Cost-effective analysis using similar tool patterns
- **Threat Pattern Discovery**: Automatic identification of common attack patterns
- **Performance Optimization**: Caching and optimization for large-scale analysis

### Getting Started with AI Analysis

#### Prerequisites

To use AI-powered threat analysis, you'll need API keys for one or more AI providers:

1. **OpenAI API Key** (recommended)
   - Sign up at https://platform.openai.com/
   - Generate an API key with appropriate credits

2. **Anthropic API Key** (optional)
   - Sign up at https://console.anthropic.com/
   - Generate an API key for Claude models

#### Configuration

1. **Copy the environment template:**
   ```bash
   cp env.example .env
   ```

2. **Edit the .env file with your API keys:**
   ```bash
   # AI Provider Configuration
   OPENAI_API_KEY=sk-proj-your-openai-key-here
   ANTHROPIC_API_KEY=sk-ant-api03-your-anthropic-key-here
   
   # Optional: Custom model configurations
   OPENAI_MODEL=gpt-4
   ANTHROPIC_MODEL=claude-3-sonnet-20240229
   ```

3. **Verify configuration:**
   ```bash
   python demo_ai_threat_analysis.py
   ```

#### Basic AI Analysis Workflow

1. **Run the Demonstration Script**
   ```bash
   python demo_ai_threat_analysis.py
   ```
   This script demonstrates:
   - Individual MCP server analysis
   - Batch processing of multiple servers
   - Rule-based fallback when AI providers are unavailable
   - Attack chain detection across tools
   - Cost optimization strategies

2. **Integrate with Detection Pipeline**
   ```bash
   # Comprehensive detection with AI analysis
   python application.py detect comprehensive --target 192.168.1.100 \
     --enable-risk-assessment
   ```

3. **Batch Analysis of Multiple Servers**
   The AI system can efficiently analyze multiple MCP servers:
   - Intelligent caching reduces redundant analyses
   - Similarity matching optimizes costs
   - Parallel processing improves performance

### Understanding AI Analysis Results

#### Analysis Components

**Tool Capabilities Assessment:**
```json
{
  "tool_name": "read_file",
  "categories": ["file_system", "data_access"],
  "risk_level": "high",
  "confidence": 0.92,
  "analysis_metadata": {
    "ai_provider": "openai",
    "model": "gpt-4",
    "analysis_time": "2024-12-28T10:30:00Z"
  }
}
```

**Threat Analysis:**
```json
{
  "threat_level": "high",
  "attack_vectors": [
    {
      "name": "Unauthorized File Access",
      "description": "Tool can read sensitive system files",
      "likelihood": "high",
      "impact": "high",
      "attack_steps": [
        "Gain access to MCP server",
        "Use read_file tool with sensitive paths",
        "Extract confidential information"
      ]
    }
  ],
  "abuse_scenarios": [
    {
      "scenario": "Data Exfiltration",
      "description": "Attacker uses file access to steal data",
      "prerequisites": ["Server access", "Knowledge of file paths"],
      "impact": "Confidentiality breach, regulatory violations"
    }
  ]
}
```

#### Risk Scoring

The AI system uses sophisticated risk scoring methodology:

- **Threat Level**: Critical, High, Medium, Low, Info
- **Confidence Score**: 0.0-1.0 indicating analysis confidence
- **Context Factors**: Environment, security posture, compliance requirements
- **Attack Feasibility**: Likelihood and impact of identified attack vectors

#### Attack Chain Analysis

Advanced analysis includes multi-tool attack chain detection:

```json
{
  "attack_chains": [
    {
      "chain_id": "data-exfiltration-chain-1",
      "tools": ["list_directory", "read_file", "web_request"],
      "feasibility_score": 0.85,
      "attack_path": [
        "Use list_directory to discover sensitive files",
        "Use read_file to access confidential data",
        "Use web_request to exfiltrate data"
      ],
      "risk_factors": {
        "tool_availability": 1.0,
        "access_requirements": 0.7,
        "technical_complexity": 0.4,
        "detection_difficulty": 0.9,
        "impact_severity": 0.9
      }
    }
  ]
}
```

### Advanced AI Features

#### Cost Optimization

The AI system includes several cost optimization strategies:

1. **Similarity-Based Analysis**: Reuse analysis for similar tools
2. **Intelligent Caching**: Cache results with appropriate TTL
3. **Provider Selection**: Choose optimal AI provider based on cost and performance
4. **Batch Processing**: Process multiple tools efficiently

#### Performance Monitoring

Real-time monitoring of AI analysis performance:

```bash
# Performance metrics are included in analysis results
{
  "performance_metrics": {
    "analysis_duration": 12.5,
    "tokens_used": 1250,
    "cost_estimate": 0.025,
    "cache_hit_rate": 0.65,
    "provider_health": 0.95
  }
}
```

#### Provider Health Monitoring

The system continuously monitors AI provider health:

- **Response Time Tracking**: Monitor API response times
- **Success Rate Monitoring**: Track successful vs. failed requests
- **Error Rate Analysis**: Identify patterns in API errors
- **Automatic Failover**: Switch providers when health degrades

### Integration with Existing Workflows

#### Command Line Integration

AI analysis integrates seamlessly with existing HawkEye commands:

```bash
# Enable AI analysis in comprehensive detection
python application.py detect comprehensive --target 192.168.1.100 \
  --enable-introspection \
  --enable-risk-assessment \
  --confidence-threshold 0.7

# Generate reports with AI analysis data
python application.py report generate \
  --input analysis_results.json \
  --format html \
  --template ai-analysis
```

#### Programmatic Integration

For advanced users, the AI analysis system can be integrated programmatically:

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer
from hawkeye.detection.ai_threat.models import EnvironmentContext

# Initialize analyzer
analyzer = AIThreatAnalyzer()

# Create environment context
context = EnvironmentContext(
    deployment_type="production",
    security_posture="medium",
    compliance_frameworks=["GDPR", "SOC2"]
)

# Analyze MCP server
result = analyzer.analyze_threats(mcp_server, context)
```

### Best Practices for AI Analysis

#### Security Considerations

1. **API Key Protection**: Store API keys securely, never commit to version control
2. **Cost Monitoring**: Set up budget alerts and monitoring for AI provider usage
3. **Result Validation**: Always validate AI analysis results with human expertise
4. **Data Privacy**: Consider data sensitivity when using cloud AI providers

#### Performance Optimization

1. **Batch Processing**: Analyze multiple servers together for efficiency
2. **Caching Strategy**: Configure appropriate cache TTL for your environment
3. **Provider Selection**: Choose AI providers based on your cost and performance requirements
4. **Parallel Processing**: Use parallel analysis for large-scale assessments

#### Quality Assurance

1. **Confidence Thresholds**: Set appropriate confidence thresholds for your use case
2. **Multi-Provider Validation**: Use multiple AI providers for critical analyses
3. **Historical Comparison**: Compare results with previous analyses for consistency
4. **Expert Review**: Have security experts review high-risk findings

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

##### `detect comprehensive` - Comprehensive MCP Detection

Performs comprehensive MCP detection using the integrated detection pipeline with Python-based introspection. This command combines traditional detection methods with advanced MCP introspection for complete analysis.

```bash
python application.py detect comprehensive [OPTIONS]
```

**Required Options:**
- `--target <IP|hostname>`: Target IP address or hostname

**Optional Parameters:**
- `--enable-introspection/--disable-introspection`: Enable enhanced MCP introspection (default: enabled)
- `--introspection-timeout <seconds>`: Timeout for MCP introspection (default: 180)
- `--enable-risk-assessment/--disable-risk-assessment`: Enable risk assessment (default: enabled)
- `--confidence-threshold <float>`: Minimum confidence threshold (default: 0.3)
- `--output <path>`: Output file path for comprehensive results
- `--format <json|csv|xml|html>`: Output format (default: json)
- `--generate-introspection-report/--no-introspection-report`: Generate detailed introspection report
- `--introspection-report-path <path>`: Path for introspection report

**Examples:**
```bash
# Basic comprehensive detection
python application.py detect comprehensive --target 192.168.1.100

# Full detection with risk analysis and reporting
python application.py detect comprehensive --target api.example.com \
  --enable-risk-assessment \
  --generate-introspection-report \
  --format html

# High-confidence detection with extended timeout
python application.py detect comprehensive --target 192.168.1.100 \
  --confidence-threshold 0.8 \
  --introspection-timeout 300
```

**Detection Methods Included:**
- **Process-based Detection**: Node.js/NPX process enumeration
- **Network Scanning**: Port scanning with MCP protocol verification
- **Configuration Discovery**: MCP server configuration file analysis
- **Docker Inspection**: Container-based MCP server detection
- **Environment Analysis**: Environment variable and path analysis
- **Transport Detection**: stdio, HTTP, WebSocket, SSE transport identification
- **Python-based Introspection**: Direct MCP server communication and analysis

**Output Features:**
- **Server Information**: Name, version, protocol details
- **Tool Inventory**: Available tools with descriptions and schemas (521+ risk patterns)
- **Resource Catalog**: Accessible resources and their types
- **Risk Analysis**: Comprehensive security assessment with CWE mapping
- **Attack Vector Analysis**: Potential security vulnerabilities and attack paths
- **Performance Metrics**: Detection and introspection timing information
- **Confidence Scoring**: Analysis confidence levels for all findings

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

### Using the AI Threat Analysis CLI Command

The `analyze-threats` command provides a production-ready CLI interface for processing JSON detection results through the AI-powered threat analysis system. This replaces the demo-only approach with a complete workflow integration.

#### Command Syntax

```bash
python application.py detect analyze-threats [OPTIONS]
```

#### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--input, -i PATH` | Input JSON file containing detection results | `--input detection_results.json` |

#### Optional Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--output, -o PATH` | Output file path for threat analysis results | None | `--output threat_analysis.json` |
| `--format, -f FORMAT` | Output format (json, html, csv, xml) | json | `--format html` |
| `--analysis-type TYPE` | Analysis depth (quick, comprehensive, detailed) | comprehensive | `--analysis-type detailed` |
| `--confidence-threshold FLOAT` | Minimum confidence threshold for analysis | 0.5 | `--confidence-threshold 0.8` |
| `--enable-ai/--disable-ai` | Enable AI-powered analysis | Enabled | `--disable-ai` |
| `--parallel-processing/--sequential-processing` | Enable parallel processing | Enabled | `--sequential-processing` |
| `--max-workers INTEGER` | Maximum number of parallel workers | 3 | `--max-workers 5` |
| `--cost-limit FLOAT` | Maximum cost limit for AI analysis (USD) | No limit | `--cost-limit 10.0` |

#### Complete Workflow Examples

**Basic Workflow:**
```bash
# Step 1: Run detection and save to JSON
python application.py detect target --target 192.168.1.100 --output detection_results.json

# Step 2: Analyze threats from detection results
python application.py detect analyze-threats --input detection_results.json --output threat_analysis.json
```

**Comprehensive Analysis:**
```bash
# Step 1: Comprehensive detection with introspection
python application.py detect comprehensive --target api.example.com --output comprehensive_results.json

# Step 2: Detailed AI threat analysis with custom settings
python application.py detect analyze-threats \
  --input comprehensive_results.json \
  --output detailed_threats.json \
  --analysis-type detailed \
  --parallel-processing \
  --max-workers 5 \
  --cost-limit 10.0
```

**HTML Report Generation:**
```bash
# Generate HTML threat analysis report
python application.py detect analyze-threats \
  --input detection_results.json \
  --format html \
  --output security_report.html \
  --analysis-type comprehensive
```

**Batch Processing Multiple Environments:**
```bash
# Local environment analysis
python application.py detect local --output local_detection.json
python application.py detect analyze-threats \
  --input local_detection.json \
  --output local_threats.json \
  --confidence-threshold 0.6

# Production environment analysis with cost controls
python application.py detect target --target prod.company.com --output prod_detection.json
python application.py detect analyze-threats \
  --input prod_detection.json \
  --output prod_threats.json \
  --cost-limit 5.0 \
  --analysis-type comprehensive
```

#### Output Formats

**JSON Format (Default):**
The JSON output includes comprehensive threat analysis data:

```json
{
  "metadata": {
    "title": "HawkEye AI Security Threat Analysis",
    "source_file": "detection_results.json",
    "analysis_type": "comprehensive",
    "generated_at": "2024-12-28T12:00:00Z",
    "total_servers_analyzed": 2,
    "successful_analyses": 2,
    "failed_analyses": 0,
    "ai_enabled": true,
    "parallel_processing": true
  },
  "threat_analyses": {
    "filesystem-mcp-server": {
      "tool_capabilities": {
        "tool_name": "Filesystem MCP Server",
        "capability_categories": ["file_system", "data_access"],
        "risk_score": 7.8,
        "confidence": 0.95
      },
      "threat_level": "high",
      "attack_vectors": [
        {
          "name": "Unauthorized File Access",
          "severity": "high",
          "description": "Server allows unrestricted file system access",
          "impact": "Complete file system compromise",
          "likelihood": 0.85,
          "prerequisites": ["Server access", "Tool permissions"],
          "attack_steps": [
            "Gain access to MCP server",
            "Use read_file tool with sensitive paths",
            "Extract confidential information"
          ]
        }
      ],
      "mitigation_strategies": [
        {
          "name": "Implement File Access Controls",
          "description": "Restrict file access to specific directories",
          "implementation_steps": [
            "Configure directory whitelist",
            "Implement path validation",
            "Add audit logging"
          ],
          "effectiveness_score": 0.9,
          "cost_estimate": "medium"
        }
      ],
      "confidence_score": 0.95,
      "analysis_metadata": {
        "provider": "anthropic",
        "model": "claude-3-sonnet-20240229",
        "cost": 0.0156,
        "analysis_time": 12.5,
        "timestamp": "2024-12-28T12:05:30Z"
      }
    }
  },
  "errors": {},
  "statistics": {
    "analyses_performed": 2,
    "cache_hits": 0,
    "total_cost": 0.0312
  }
}
```

**HTML Format:**
Generates a comprehensive HTML report with:
- Executive summary with risk overview
- Detailed threat analysis for each MCP server
- Attack vector visualization
- Mitigation strategy recommendations
- Interactive risk charts and graphs

**CSV Format:**
Produces a tabular format suitable for spreadsheet analysis:
```csv
tool_name,threat_level,attack_vectors_count,mitigations_count,confidence_score,analysis_cost
Filesystem MCP Server,high,3,2,0.95,0.0156
Web Search MCP Server,medium,2,3,0.88,0.0156
```

**XML Format:**
Structured XML output for integration with other security tools and systems.

#### Error Handling and Troubleshooting

**Common Error Scenarios:**

1. **Invalid JSON Input File:**
   ```bash
   Error: Invalid JSON format in input file: Expecting ',' delimiter: line 5 column 10
   ```
   **Solution:** Validate the JSON file format using `jq` or a JSON validator.

2. **No MCP Servers Found:**
   ```bash
   No MCP servers found above confidence threshold 0.5
   ```
   **Solution:** Lower the confidence threshold or verify the detection results contain valid MCP server data.

3. **AI API Configuration Issues:**
   ```bash
   Warning: No AI API keys configured! Falling back to rule-based analysis...
   ```
   **Solution:** Configure API keys in the `.env` file:
   ```bash
   AI_PROVIDER=anthropic
   AI_ANTHROPIC_API_KEY=your_key_here
   AI_OPENAI_API_KEY=your_key_here
   ```

4. **Cost Limit Exceeded:**
   ```bash
   Analysis stopped: Cost limit of $5.00 exceeded
   ```
   **Solution:** Increase cost limit or process fewer servers at once.

#### Performance Optimization

**Parallel Processing:**
- Use `--parallel-processing` for multiple servers (default: enabled)
- Adjust `--max-workers` based on system resources and API rate limits
- Monitor API rate limits to avoid throttling

**Cost Optimization:**
- Set `--cost-limit` to control AI usage costs
- Use `--confidence-threshold` to filter low-confidence detections
- Choose `--analysis-type quick` for basic analysis to reduce costs

**Memory and Performance:**
- For large-scale analysis, process servers in batches
- Use `--sequential-processing` if experiencing memory issues
- Monitor system resources during analysis

#### Integration Examples

**CI/CD Pipeline Integration:**
```bash
#!/bin/bash
# ci-security-check.sh

# Run detection
python application.py detect target --target $CI_TARGET --output detection.json

# Analyze threats with cost controls
python application.py detect analyze-threats \
  --input detection.json \
  --output threats.json \
  --cost-limit 2.0 \
  --confidence-threshold 0.7

# Check for high-risk findings
HIGH_RISK=$(jq '[.threat_analyses[] | select(.threat_level == "high" or .threat_level == "critical")] | length' threats.json)

if [ "$HIGH_RISK" -gt 0 ]; then
  echo "❌ Security check failed: $HIGH_RISK high-risk threats detected"
  exit 1
else
  echo "✅ Security check passed"
  exit 0
fi
```

**Automated Security Monitoring:**
```bash
#!/bin/bash
# daily-security-monitor.sh

DATE=$(date +%Y%m%d)
TARGETS=("prod.company.com" "api.company.com" "staging.company.com")

for target in "${TARGETS[@]}"; do
  # Detection
  python application.py detect target --target "$target" --output "detection_${target}_${DATE}.json"
  
  # Threat analysis
  python application.py detect analyze-threats \
    --input "detection_${target}_${DATE}.json" \
    --output "threats_${target}_${DATE}.json" \
    --format json \
    --cost-limit 5.0
  
  # Generate HTML report
  python application.py detect analyze-threats \
    --input "detection_${target}_${DATE}.json" \
    --output "report_${target}_${DATE}.html" \
    --format html
done

# Send notification if high-risk threats found
python send_security_alerts.py --date "$DATE"
```

**Security Dashboard Integration:**
```bash
# Export threat data to security dashboard
python application.py detect analyze-threats \
  --input detection_results.json \
  --format json \
  --output dashboard_data.json

# Transform for dashboard API
jq '.threat_analyses | to_entries | map({
  server_name: .key,
  threat_level: .value.threat_level,
  risk_score: .value.tool_capabilities.risk_score,
  attack_vectors: (.value.attack_vectors | length),
  timestamp: .value.analysis_metadata.timestamp
})' dashboard_data.json > dashboard_feed.json

# Send to dashboard API
curl -X POST https://dashboard.company.com/api/security-threats \
  -H "Content-Type: application/json" \
  --data @dashboard_feed.json
```

#### Best Practices

**Security Considerations:**
1. **Protect API Keys:** Store API keys securely, never commit to repositories
2. **Validate Results:** Always review AI analysis results with human expertise
3. **Monitor Costs:** Set up alerts for AI usage costs across all environments
4. **Audit Trails:** Maintain logs of all threat analysis activities

**Operational Excellence:**
1. **Regular Analysis:** Schedule daily or weekly automated threat analysis
2. **Baseline Comparisons:** Compare current results with historical baselines
3. **Escalation Procedures:** Define clear escalation paths for high-risk findings
4. **Documentation:** Document all security findings and remediation actions

**Performance Guidelines:**
1. **Batch Processing:** Analyze multiple servers together for efficiency
2. **Resource Management:** Monitor system resources during large-scale analysis
3. **API Rate Limits:** Respect AI provider rate limits and quotas
4. **Caching Strategy:** Configure appropriate cache settings for your environment

#### Advanced Usage Scenarios

**Multi-Environment Security Assessment:**
```bash
# Development environment
python application.py detect local --output dev_detection.json
python application.py detect analyze-threats \
  --input dev_detection.json \
  --output dev_threats.json \
  --analysis-type quick \
  --cost-limit 1.0

# Staging environment  
python application.py detect target --target staging.company.com --output staging_detection.json
python application.py detect analyze-threats \
  --input staging_detection.json \
  --output staging_threats.json \
  --analysis-type comprehensive \
  --cost-limit 3.0

# Production environment (detailed analysis)
python application.py detect comprehensive --target prod.company.com --output prod_detection.json
python application.py detect analyze-threats \
  --input prod_detection.json \
  --output prod_threats.json \
  --analysis-type detailed \
  --cost-limit 10.0 \
  --parallel-processing \
  --max-workers 5
```

**Compliance and Audit Support:**
```bash
# Generate compliance-ready reports
python application.py detect analyze-threats \
  --input audit_detection.json \
  --output compliance_analysis.xml \
  --format xml \
  --analysis-type detailed \
  --confidence-threshold 0.9

# Create executive summary for stakeholders
python application.py detect analyze-threats \
  --input audit_detection.json \
  --output executive_summary.html \
  --format html \
  --analysis-type comprehensive
```

This comprehensive CLI integration provides a production-ready workflow that replaces the previous demo-only approach with full enterprise capabilities for AI-powered MCP security analysis. 