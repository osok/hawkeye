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
```

### Basic Usage

```bash
# Scan a single IP address
python application.py scan --target 192.168.1.100

# Scan a CIDR range
python application.py scan --target 192.168.1.0/24

# Scan with custom port range
python application.py scan --target 192.168.1.0/24 --ports 3000-9000

# Generate detailed report
python application.py report --input scan_results.json --format html
```

## 📋 Features

### Network Scanning Engine

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

### MCP Detection Engine

- **Process Analysis**
  - Node.js process enumeration
  - Command-line argument inspection
  - Environment variable analysis
  - Working directory examination

- **Configuration Discovery**
  - Package.json file analysis
  - MCP server configuration files
  - Environment configuration detection
  - Docker container inspection

- **Protocol Verification**
  - MCP handshake simulation
  - Transport layer identification (stdio, HTTP, WebSocket)
  - Authentication mechanism detection
  - API endpoint enumeration

### Security Assessment

- **Vulnerability Detection**
  - Default configuration identification
  - Weak authentication mechanisms
  - Unencrypted transport protocols
  - Public accessibility assessment

- **Risk Scoring**
  - CVSS-based scoring methodology
  - Context-aware risk assessment
  - Business impact consideration
  - Remediation priority ranking

- **Compliance Checking**
  - Security best practice validation
  - Organizational policy compliance
  - Industry standard alignment
  - Regulatory requirement assessment

## 🛠️ Command Reference

### Scanning Commands

```bash
# Network scanning
hawkeye scan --target <CIDR|IP> [options]
hawkeye quick-scan --target <CIDR|IP> [options]

# MCP detection
hawkeye detect target --target <IP> [options]
hawkeye detect local [options]
hawkeye detect process --pid <PID> [options]
hawkeye detect config [options]

# Reporting
hawkeye report generate --input <scan_results> --format <json|csv|xml|html> [options]
hawkeye report aggregate --input <scan_results> [options]
hawkeye report combine --input-dir <results_dir> [options]

# Configuration and utilities
hawkeye config show [options]
hawkeye info
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

- [User Manual](docs/user_manual.md) - Comprehensive usage guide
- [API Documentation](docs/api/) - Developer reference
- [Security Guidelines](docs/security_guidelines.md) - Security best practices
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [Installation Guide](docs/installation.md) - Detailed setup instructions

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