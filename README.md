# 🪶 HawkEye
## Hidden Application Weaknesses & Key Entry-point Yielding Evaluator

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-focused-red.svg)](https://github.com/yourusername/hawkeye)

**HawkEye** is a comprehensive security reconnaissance tool designed to identify and assess Model Context Protocol (MCP) server deployments within network infrastructure. With its keen vision for security vulnerabilities, HawkEye helps organizations discover hidden weaknesses and key entry points in their MCP implementations.

## 🎯 Overview

HawkEye combines advanced network scanning capabilities with specialized MCP detection algorithms to provide security teams with actionable intelligence about their MCP server deployments. The tool focuses on responsible security assessment while maintaining operational stealth and compliance.

### Key Capabilities

- 🔍 **Network Discovery**: Comprehensive TCP/UDP port scanning with CIDR range support
- 🎯 **MCP Detection**: Specialized algorithms for identifying Node.js/NPX-based MCP servers
- ⚡ **Protocol Analysis**: MCP handshake verification and transport layer identification
- 🛡️ **Security Assessment**: CVSS-based vulnerability scoring and risk analysis
- 📊 **Multi-Format Reporting**: JSON, CSV, XML, and HTML output formats
- 🚀 **Performance Optimized**: Configurable threading and rate limiting
- 🔒 **Security-First**: Non-intrusive scanning with comprehensive audit trails

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Virtual environment (recommended)
- Network access to target infrastructure
- **Optional**: OpenAI/Anthropic API keys for AI-powered threat analysis

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure API keys for AI analysis (optional)
cp env.example .env
# Edit .env file with your API keys
```

### Basic Usage

```bash
# Quick scan for MCP services
python application.py quick-scan --target 192.168.1.100

# Comprehensive MCP detection with AI analysis
python application.py detect comprehensive --target 192.168.1.100

# Local system MCP detection
python application.py detect local

# Network scanning with MCP identification
python application.py scan --target 192.168.1.0/24

# Generate AI-powered threat analysis
python demo_ai_threat_analysis.py

# Generate detailed report
python application.py report generate --input scan_results.json --format html
```

### 🤖 AI-Powered Threat Analysis

HawkEye now includes sophisticated AI-powered threat analysis capabilities:

```bash
# Run the AI threat analysis demo
python demo_ai_threat_analysis.py

# The demo showcases:
# - Dynamic MCP tool capability analysis
# - AI-powered threat assessment
# - Attack vector identification
# - Risk scoring and mitigation strategies
# - Multi-provider AI support (OpenAI, Anthropic, Local LLM)
```

## 📖 Complete Workflow Guide

For comprehensive step-by-step instructions covering all HawkEye scenarios, see our **[Complete Workflow Guide](docs/workflow_guide.md)**. This guide includes:

### 🎯 **15 Detailed Scenarios:**
- **Network Scanning**: Single IP, CIDR ranges, custom ports
- **Detection Workflows**: Local systems, remote targets, process analysis
- **Security Assessment**: Comprehensive audits, incident response
- **Reporting**: Executive reports, aggregated analysis
- **Advanced Usage**: Automation, custom configurations, SIEM integration

### 🛠️ **Each Scenario Includes:**
- Complete command examples with all options
- Expected output samples and progress indicators
- Risk assessments and time requirements
- Troubleshooting tips and best practices

### 🚀 **Quick Navigation:**
```bash
# Local system scan (Scenario 6)
python application.py --verbose detect local

# Small network assessment (Scenario 2)
python application.py scan --target 192.168.1.0/24 --output network_scan.json

# Process investigation (Scenario 7)
python application.py detect process --pid 1234 --deep-analysis

# Complete security assessment (Scenario 9)
python application.py detect local --output local_audit.json
```

**👉 [View Complete Workflow Guide →](docs/workflow_guide.md)**

## 📋 Features

### 🚀 Advanced MCP Detection & Analysis

- **Comprehensive Detection Pipeline**
  - Multi-method MCP server discovery (7 detection methods)
  - Process-based detection with Node.js/NPX identification
  - Network scanning with MCP protocol verification
  - Configuration file discovery and analysis
  - Docker container inspection for MCP services
  - Environment variable analysis
  - Transport layer detection (stdio, HTTP, WebSocket, SSE)

- **Python-Based MCP Introspection**
  - Direct MCP server communication using Python MCP SDK
  - Real-time tool and resource discovery
  - Capability assessment via MCP protocol
  - Transport handler implementations (Stdio, SSE, HTTP)
  - Connection pooling and retry logic with exponential backoff
  - Advanced risk analysis with 521+ security patterns

### 🤖 AI-Powered Threat Analysis

- **Dynamic Threat Assessment**
  - AI-powered analysis of MCP tool capabilities
  - Multi-provider support (OpenAI, Anthropic, Local LLM)
  - Context-aware threat modeling
  - Attack vector identification and feasibility assessment
  - Attack chain detection across multiple tools
  - Intelligent caching with learning capabilities

- **Advanced AI Features**
  - ThreatIntelligenceDB with pattern recognition
  - Multi-stage threat analysis pipeline
  - Dynamic confidence scoring (9-factor system)
  - Provider failover with health monitoring
  - Cost optimization and budget controls
  - Parallel processing with streaming results

- **Sophisticated Analysis Components**
  - Environment context detection (cloud, container, virtualization)
  - Security posture assessment (EDR, SIEM detection)
  - Compliance framework mapping (PCI-DSS, HIPAA, GDPR, NIST)
  - Attack chain visualization and risk scoring
  - Threat intelligence learning from historical analyses

### 🛡️ Security Assessment Engine

- **Advanced Risk Analysis**
  - 521+ comprehensive security risk patterns
  - CWE (Common Weakness Enumeration) mapping
  - Multi-dimensional risk categorization
  - CVSS-like scoring with contextual adjustments
  - Schema-based parameter validation analysis
  - Capability-based threat modeling

- **Risk Scoring & Reporting**
  - Composite risk scoring (weighted average, maximum, CVSS-like)
  - Multi-format reporting (JSON, HTML, Markdown, CSV)
  - Configurable risk policies and thresholds
  - Executive summary generation
  - Attack vector prioritization

### 🌐 Network Scanning Engine

- **Target Specification**
  - CIDR notation support (e.g., `192.168.1.0/24`)
  - IP range specification (e.g., `192.168.1.1-192.168.1.50`)
  - Single IP targeting with hostname resolution
  - IPv4 and IPv6 support

- **Port Scanning Options**
  - Common MCP ports (3000, 8000, 8080, 9000)
  - Custom port ranges (1-65535)
  - TCP and UDP protocol support
  - Multiple scan modes (SYN, connect, stealth)

- **Service Detection**
  - Banner grabbing and fingerprinting
  - HTTP/HTTPS service identification
  - WebSocket endpoint detection
  - Custom MCP protocol detection

## 🛠️ Command Reference

### Core Commands

```bash
# Quick MCP service discovery
python application.py quick-scan --target <CIDR|IP> [options]

# Network scanning operations
python application.py scan --target <CIDR|IP> [options]

# MCP-specific detection and analysis
python application.py detect comprehensive --target <IP> [options]
python application.py detect target --target <IP> [options]
python application.py detect local [options]
python application.py detect process --pid <PID> [options]
python application.py detect config [options]

# Security assessment and risk analysis
python application.py assess [options]

# Report generation and formatting
python application.py report generate --input <results> --format <json|csv|xml|html> [options]

# Configuration management
python application.py config [options]

# System information
python application.py info
```

### AI-Powered Analysis

```bash
# Run AI threat analysis demonstration
python demo_ai_threat_analysis.py

# The demo includes:
# - Individual MCP server analysis
# - Batch processing of multiple servers
# - Rule-based fallback when AI unavailable
# - Attack chain detection
# - Cost optimization
```

### Configuration Options

```bash
# Scan parameters
--threads <count>          # Number of concurrent threads
--timeout <seconds>        # Network operation timeout
--rate-limit <requests>    # Rate limiting configuration
--retry <attempts>         # Retry attempts for failed connections

# Output control
--verbose                  # Verbose output mode
--quiet                    # Quiet operation mode
--log-file <path>         # Log file location
--output <path>           # Output file path

# Filtering options
--service-filter <type>    # Filter by service type
--risk-threshold <level>   # Minimum risk level to report
--port-range <range>      # Limit port scanning range
--protocol <tcp|udp>      # Protocol-specific scanning
```

## 📊 Output Formats

### JSON Output
```json
{
  "scan_metadata": {
    "timestamp": "2024-12-19T10:30:00Z",
    "target": "192.168.1.0/24",
    "scan_duration": 120.5
  },
  "discovered_services": [
    {
      "ip": "192.168.1.100",
      "port": 3000,
      "service": "mcp-server",
      "protocol": "http",
      "risk_score": 7.5,
      "vulnerabilities": ["default-config", "weak-auth"]
    }
  ]
}
```

### CSV Output
```csv
IP,Port,Service,Protocol,Risk Score,Vulnerabilities
192.168.1.100,3000,mcp-server,http,7.5,"default-config,weak-auth"
192.168.1.101,8080,mcp-server,websocket,5.2,"unencrypted-transport"
```

### HTML Report
Interactive HTML reports with:
- Executive summary dashboard
- Detailed findings tables
- Risk assessment charts
- Remediation recommendations
- Network topology visualization

## 🔒 Security Considerations

### Operational Security

- **Non-Intrusive Scanning**: Minimal network footprint with configurable rate limiting
- **Audit Trail**: Comprehensive logging of all scanning activities
- **Privilege Management**: Operates with minimal required privileges
- **Data Protection**: No credential harvesting or sensitive data storage

### Legal Compliance

- **Authorization Required**: Ensure proper authorization before scanning
- **Scope Limitation**: Respect network boundaries and security policies
- **Documentation**: Maintain records of scanning activities for compliance

### Best Practices

- Always obtain written authorization before scanning external networks
- Use rate limiting to avoid network disruption
- Review and understand local laws and regulations
- Implement proper access controls for scan results

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/test_scanner/
pytest tests/test_detection/
pytest tests/integration/

# Run with coverage
pytest --cov=src/hawkeye --cov-report=html
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Performance Tests**: Benchmarking and load testing
- **Security Tests**: Vulnerability and penetration testing

## 📚 Documentation

### Core Documentation
- **[User Manual](docs/user_manual.md)** - Comprehensive usage guide with AI analysis features
- **[Complete Workflow Guide](docs/workflow_guide.md)** - 15 step-by-step scenarios for all use cases
- [Security Guidelines](docs/security_guidelines.md) - Security best practices
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [Installation Guide](docs/installation.md) - Detailed setup instructions

### Advanced Features Documentation
- **[AI Threat Analysis README](AI_THREAT_ANALYSIS_README.md)** - Comprehensive AI analysis system guide
- [API Documentation](docs/api/) - Developer reference including MCP introspection APIs
- [MCP Introspection Guide](docs/api/mcp_introspection.md) - Python-based introspection system
- [Migration Guide](docs/migration/nodejs_to_python.md) - Node.js to Python transition guide

### Implementation Status
- **[Threat Analysis Task List](docs/task-list-threat-analysis.md)** - AI system implementation status (Phase 3 Complete)
- **[MCP Introspection Task List](docs/task_list-inspect-mcp.md)** - Introspection system status (99% Complete)
- [Design Documents](docs/Design-Threat-Analysis.md) - System architecture and design decisions

## 🤝 Contributing

We welcome contributions to HawkEye! Please read our contributing guidelines and code of conduct before submitting pull requests.

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Run development tools
black src/  # Code formatting
ruff src/   # Linting
mypy src/   # Type checking
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

HawkEye is designed for authorized security testing and assessment purposes only. Users are responsible for ensuring they have proper authorization before scanning any network infrastructure. The developers assume no liability for misuse of this tool.

## 🙏 Acknowledgments

- Model Context Protocol (MCP) community for protocol specifications
- Security research community for vulnerability assessment methodologies
- Open source contributors and maintainers

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourusername/hawkeye/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/hawkeye/discussions)
- 📧 **Security Issues**: security@hawkeye-project.org

---

**HawkEye** - *Seeing beyond the visible, securing the invisible.* 