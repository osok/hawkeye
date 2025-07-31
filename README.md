# 🪶 HawkEye
## Hidden Application Weaknesses & Key Entry-point Yielding Evaluator

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-focused-red.svg)](https://github.com/yourusername/hawkeye)

**HawkEye** is a comprehensive security reconnaissance tool designed to identify and assess Model Context Protocol (MCP) server deployments within network infrastructure. With its keen vision for security vulnerabilities, HawkEye helps organizations discover hidden weaknesses and key entry points in their MCP implementations.

## 🎯 Overview

HawkEye combines advanced network scanning capabilities with specialized MCP detection algorithms and AI-powered threat analysis to provide security teams with actionable intelligence about their MCP server deployments.

### Key Capabilities

- 🔍 **Network Discovery**: Comprehensive TCP/UDP port scanning with CIDR range support
- 🎯 **MCP Detection**: Specialized algorithms for identifying Node.js/NPX-based MCP servers  
- ⚡ **Protocol Analysis**: MCP handshake verification and transport layer identification
- 🤖 **AI Threat Analysis**: Dynamic threat assessment using OpenAI, Anthropic, or Local LLMs
- 🛡️ **Security Assessment**: CVSS-based vulnerability scoring and risk analysis
- 📊 **Multi-Format Reporting**: JSON, CSV, XML, and HTML output formats
- 🚀 **Performance Optimized**: Configurable threading and rate limiting

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Virtual environment (recommended)
- **Optional**: OpenAI/Anthropic API keys for AI-powered threat analysis

### Installation
📖 **[Complete Installation Guide →](docs/installation.md)**

```bash
# Clone and setup
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure AI providers (optional)
cp env.example .env
# Edit .env with your API keys
```

## 📋 Basic Usage

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `scan` | Network scanning with MCP detection | `python application.py scan --target 192.168.1.0/24` |
| `detect target` | Target-specific MCP detection | `python application.py detect target -t 192.168.1.100 -o results.json` |
| `detect local` | Local system MCP detection | `python application.py detect local -o local_results.json` |
| `detect comprehensive` | **Full detection with CIDR support** | `python application.py detect comprehensive -t 192.168.1.0/24 -o report.json` |
| `analyze-threats` | **AI threat analysis from JSON** | `python application.py analyze-threats -i results.json -o threats.html -f html` |
| `report generate` | Generate formatted reports | `python application.py report generate -i scan.json -f html` |

### AI-Powered Threat Analysis Workflow

```bash
# Step 1: Detect MCP servers on network (supports CIDR) and save to JSON
python application.py detect comprehensive -t 192.168.1.0/24 -o detection.json

# Step 2: Analyze threats using AI (REAL API calls to OpenAI/Anthropic)
python application.py analyze-threats -i detection.json -f html -o threat_report.html

# Single target analysis
python application.py detect comprehensive -t 192.168.1.100 -o single_target.json
python application.py analyze-threats -i single_target.json --cost-limit 5.0

# Local system analysis
python application.py detect local -o local.json
python application.py analyze-threats -i local.json --cost-limit 5.0
```

## 📖 Documentation

### 📚 **[Complete Documentation Wiki](https://github.com/osok/hawkeye/wiki)**
Centralized documentation hub with all user guides, technical references, and developer resources.

### Essential Guides
- 📘 **[Installation Guide](https://github.com/osok/hawkeye/wiki/Installation)** - Complete setup with AI provider configuration
- 🛠️ **[Workflow Guide](https://github.com/osok/hawkeye/wiki/Workflow-Guide)** - 15 step-by-step scenarios for all use cases  
- 📋 **[User Manual](https://github.com/osok/hawkeye/wiki/User-Manual)** - Comprehensive usage guide with AI analysis features
- 🔒 **[Security Guidelines](https://github.com/osok/hawkeye/wiki/Security-Guidelines)** - Security best practices and compliance

### Technical Documentation
- 🤖 **[AI Threat Analysis README](AI_THREAT_ANALYSIS_README.md)** - AI system architecture and capabilities
- 🔧 **[API Documentation](https://github.com/osok/hawkeye/wiki/API-Documentation)** - Developer reference and MCP introspection APIs
- 👨‍💻 **[Developer Documentation](https://github.com/osok/hawkeye/wiki/Developer-Documentation)** - Complete physical design, patterns, and implementation details

## 🌟 Key Features

### 🤖 AI-Powered Analysis
- **Multi-Provider Support**: OpenAI, Anthropic, Local LLM with intelligent failover
- **Dynamic Threat Assessment**: Real-time capability analysis of any MCP tool
- **Attack Chain Detection**: Multi-tool attack scenario identification
- **Cost Optimization**: Intelligent AI usage with budget controls

### 🔍 Advanced Detection
- **7 Detection Methods**: Process-based, network scanning, config discovery, Docker inspection
- **Python MCP Introspection**: Direct MCP server communication using Python MCP SDK
- **Transport Support**: Stdio, HTTP, WebSocket, SSE with connection pooling
- **521+ Security Patterns**: Comprehensive risk analysis framework

### 📊 Enterprise Reporting
- **Executive Dashboards**: Risk summaries and compliance mapping
- **Multiple Formats**: JSON, CSV, XML, HTML with interactive visualizations  
- **Audit Trails**: Comprehensive logging of all activities
- **CVSS Scoring**: Industry-standard vulnerability assessment

## 🚀 Quick Examples

```bash
# Network MCP detection (CIDR support)
python application.py detect comprehensive --target 192.168.1.0/24 --output network_results.json

# Complete security workflow with AI analysis
python application.py detect comprehensive -t 192.168.1.0/24 -o results.json
python application.py analyze-threats -i results.json -f html -o security_report.html

# Single target with detailed introspection
python application.py detect comprehensive -t api.example.com -o detailed_results.json

# Local system audit
python application.py detect local --output local_audit.json
python application.py analyze-threats -i local_audit.json --analysis-type detailed
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/hawkeye --cov-report=html
```

## 🔒 Security & Legal

- **Authorization Required**: Ensure proper authorization before scanning
- **Non-Intrusive**: Minimal network footprint with configurable rate limiting
- **Audit Trails**: Comprehensive logging of all scanning activities
- **Compliance**: Respects network boundaries and security policies

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

HawkEye is designed for authorized security testing and assessment purposes only. Users are responsible for ensuring they have proper authorization before scanning any network infrastructure.

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/yourusername/hawkeye/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourusername/hawkeye/discussions)  

---

**HawkEye** - *Seeing beyond the visible, securing the invisible.* 