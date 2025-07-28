# HawkEye API Documentation

## Overview

HawkEye provides a comprehensive API for MCP (Model Context Protocol) security reconnaissance and AI-powered threat analysis. The API is organized into several core modules, each handling specific aspects of the security analysis workflow, including real-time AI threat assessment.

## Quick Start

### Python API Usage

```python
from hawkeye.cli.main import cli
from hawkeye.detection.ai_threat import AIThreatAnalyzer
from hawkeye.detection.mcp_introspection.models import MCPServerInfo
from hawkeye.config.settings import get_settings

# Basic CLI usage programmatically
import sys
sys.argv = ['hawkeye', 'detect', 'local', '--output', 'results.json']
cli()

# Direct API usage for AI threat analysis
analyzer = AIThreatAnalyzer()
# ... (see AI Threat Analysis API section for details)
```

### Command Line Interface

**Important:** The correct CLI command structure includes the `detect` group:

```bash
# ✅ Correct commands
python application.py detect target -t 192.168.1.100 -o results.json
python application.py detect analyze-threats -i results.json -o threats.html -f html
python application.py detect local -o local.json

# ❌ Incorrect (missing detect group)
python application.py analyze-threats -i results.json  # This will fail
```

### AI-Powered Analysis Workflow

```bash
# Complete workflow with AI analysis
python application.py detect target -t 192.168.1.100 -o detection.json
python application.py detect analyze-threats -i detection.json -f html -o report.html
```

## API Modules

### 1. Scanner API
**File:** [scanner.md](scanner.md)

Network scanning capabilities for discovering MCP servers.

**Key Classes:**
- `TCPScanner` - TCP port scanning with MCP detection
- `UDPScanner` - UDP port scanning
- `ServiceFingerprinter` - Service identification and protocol verification
- `TargetEnumerator` - Target enumeration with CIDR support

**Common Use Cases:**
- Network discovery and reconnaissance
- Port scanning with MCP protocol detection
- Service fingerprinting and banner grabbing
- Batch scanning operations across network ranges

### 2. Detection API
**File:** [detection.md](detection.md)

MCP-specific detection and introspection capabilities.

**Key Classes:**
- `MCPDetector` - Main detection engine with 7 detection methods
- `ProcessEnumerator` - Local process discovery and analysis
- `ConfigFileDiscovery` - Configuration file discovery
- `DockerInspector` - Docker container MCP detection
- `TransportDetector` - Transport layer identification
- `ProtocolVerifier` - MCP protocol verification

**Common Use Cases:**
- Local MCP server detection and enumeration
- Remote MCP server verification and analysis
- Process-based MCP service discovery
- Configuration file and environment analysis

### 3. MCP Introspection API
**File:** [mcp_introspection.md](mcp_introspection.md)

Deep introspection and analysis of MCP servers using Python MCP SDK.

**Key Classes:**
- `MCPIntrospector` - Core introspection engine with connection pooling
- `TransportFactory` - Multi-transport support (Stdio, HTTP, SSE)
- `RiskAnalyzer` - 521+ security risk patterns and analysis
- `CapabilityAssessment` - Tool and resource capability analysis
- `ConnectionPool` - Efficient connection management and retry logic

**Common Use Cases:**
- Real-time tool and resource discovery via MCP protocol
- Advanced security risk assessment with pattern matching
- Protocol version compatibility checking
- Transport layer optimization and connection pooling

### 4. AI Threat Analysis API
**File:** [ai_threat_analysis.md](ai_threat_analysis.md)

**NEW:** AI-powered threat analysis with multi-provider support.

**Key Classes:**
- `AIThreatAnalyzer` - Main AI analysis orchestrator
- `OpenAIProvider` - OpenAI GPT-4/3.5 integration with cost management
- `AnthropicProvider` - Anthropic Claude integration
- `LocalLLMProvider` - Local LLM support (Ollama, etc.)
- `MCPCapabilityAnalyzer` - Dynamic MCP tool capability analysis
- `ThreatIntelligenceDB` - Threat pattern recognition and learning

**Common Use Cases:**
- Dynamic threat assessment of any detected MCP tool
- Multi-provider AI analysis with intelligent failover
- Attack vector identification and feasibility assessment
- Automated security recommendation generation
- Cost-controlled AI analysis with budget management

### 5. Assessment API
**File:** [assessment.md](assessment.md)

Security assessment and risk analysis functionality.

**Key Classes:**
- `SecurityAssessor` - Main assessment engine with CVSS scoring
- `CVSSScorer` - Industry-standard vulnerability scoring
- `ComplianceChecker` - Multi-framework compliance validation
- `RiskCalculator` - Composite risk calculation and prioritization
- `RemediationEngine` - Automated remediation recommendation

**Common Use Cases:**
- Comprehensive security risk assessment
- CVSS-based vulnerability scoring and prioritization
- Compliance framework mapping (PCI-DSS, HIPAA, GDPR, NIST)
- Risk calculation with environmental context

### 6. Reporting API
**File:** [reporting.md](reporting.md)

Multi-format report generation and executive dashboards.

**Key Classes:**
- `ReportGenerator` - Main reporting engine with template support
- `HTMLReporter` - Interactive HTML reports with threat analysis
- `JSONReporter` - Structured JSON output for API integration
- `CSVReporter` - Tabular data export for analysis
- `XMLReporter` - XML format for SIEM integration
- `ExecutiveSummary` - Executive-level reporting and dashboards

**Common Use Cases:**
- Multi-format report generation (HTML, JSON, CSV, XML)
- Executive summary generation with risk dashboards
- SIEM integration and automated alerting
- Historical trend analysis and reporting

## Configuration

### Environment-Based Configuration

HawkEye supports comprehensive configuration via environment variables:

```bash
# Core settings
export HAWKEYE_DEBUG=true
export HAWKEYE_LOG_LEVEL=DEBUG

# AI provider configuration
export AI_PROVIDER=anthropic
export AI_ANTHROPIC_API_KEY=your_key_here
export AI_FALLBACK_PROVIDER=openai
export AI_OPENAI_API_KEY=your_fallback_key

# Cost management
export AI_MAX_COST_PER_ANALYSIS=1.00
export AI_MAX_DAILY_COST=25.00

# Local LLM setup
export AI_LOCAL_LLM_ENDPOINT=http://localhost:11434
export AI_LOCAL_LLM_MODEL=llama3.1:8b
```

### Configuration File Support

```yaml
# hawkeye.yaml
ai:
  provider: anthropic
  fallback_provider: openai
  max_cost_per_analysis: 1.00
  
  anthropic:
    api_key: "your_key"
    model: "claude-3-haiku-20240307"
    
scan:
  max_threads: 50
  default_timeout: 30
  
detection:
  enable_ai_analysis: true
  parallel_processing: true
  max_workers: 3
```

## Authentication & Security

### API Key Management

```python
from hawkeye.detection.ai_threat.ai_providers import OpenAIProvider, AnthropicProvider
import os

# Secure API key loading
openai_provider = OpenAIProvider(api_key=os.getenv('AI_OPENAI_API_KEY'))
anthropic_provider = AnthropicProvider(api_key=os.getenv('AI_ANTHROPIC_API_KEY'))
```

### Transport Security

```python
from hawkeye.detection.mcp_introspection.transport import HTTPTransport, SSETransport

# Secure transport configuration
transport = HTTPTransport(
    endpoint="https://secure-mcp-server.com",
    verify_ssl=True,
    timeout=30
)
```

## Error Handling

### Comprehensive Exception Handling

```python
from hawkeye.exceptions import HawkEyeError, DetectionError, AIProviderError
from hawkeye.detection.ai_threat import AIThreatAnalyzer

try:
    analyzer = AIThreatAnalyzer()
    result = analyzer.analyze_threats(mcp_server, environment_context)
except AIProviderError as e:
    print(f"AI provider failed: {e}")
    # Fallback to rule-based analysis
except DetectionError as e:
    print(f"Detection failed: {e}")
except HawkEyeError as e:
    print(f"General HawkEye error: {e}")
```

### Graceful Degradation

```python
from hawkeye.detection.ai_threat.threat_analyzer import AIThreatAnalyzer

analyzer = AIThreatAnalyzer()
# AI analysis with automatic fallback to rule-based analysis
result = analyzer.analyze_threats_with_fallback(mcp_server, environment_context)
```

## Performance Optimization

### Connection Pooling

```python
from hawkeye.detection.mcp_introspection.optimization import create_memory_optimizer
from hawkeye.detection.mcp_introspection.transport.pool import ConnectionPool

# Optimized connection management
pool = ConnectionPool(max_connections=10, timeout=30)
memory_optimizer = create_memory_optimizer(optimization_level="aggressive")
```

### Batch Processing

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer

analyzer = AIThreatAnalyzer()

# Efficient batch analysis
results = analyzer.analyze_multiple_threats(
    mcp_servers=server_list,
    environment_context=context,
    analysis_type="comprehensive",
    parallel_processing=True,
    max_workers=5
)
```

### Cost Optimization

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer

analyzer = AIThreatAnalyzer()

# Cost-controlled analysis
result = analyzer.analyze_threats(
    mcp_server=server, 
    environment_context=context,
    cost_limit=1.0,  # Maximum $1.00 per analysis
    use_cache=True   # Enable intelligent caching
)
```

## Examples

### Complete Analysis Workflow

```python
from hawkeye.detection.pipeline import create_detection_pipeline
from hawkeye.detection.ai_threat import AIThreatAnalyzer
from hawkeye.detection.ai_threat.models import EnvironmentContext, DeploymentType

# Step 1: Detection Pipeline
pipeline = create_detection_pipeline(
    target_host="192.168.1.100",
    enable_introspection=True,
    enable_ai_analysis=True
)

detection_results = pipeline.execute()

# Step 2: AI Threat Analysis  
analyzer = AIThreatAnalyzer()
environment = EnvironmentContext(
    deployment_type=DeploymentType.REMOTE,
    security_posture="medium",
    compliance_requirements=["OWASP_TOP_10"]
)

threat_analyses = []
for result in detection_results:
    if result.mcp_server:
        analysis = analyzer.analyze_threats(
            result.mcp_server, 
            environment,
            analysis_type="comprehensive"
        )
        threat_analyses.append(analysis)

# Step 3: Report Generation
from hawkeye.reporting.html_reporter import HTMLReporter

reporter = HTMLReporter()
html_report = reporter.generate_threat_analysis_report(
    detection_results=detection_results,
    threat_analyses=threat_analyses
)
```

### Custom AI Provider Integration

```python
from hawkeye.detection.ai_threat.ai_providers import AIProvider
from hawkeye.detection.ai_threat.models import AnalysisRequest, AnalysisResponse

class CustomAIProvider(AIProvider):
    def __init__(self, api_key: str, endpoint: str):
        super().__init__()
        self.api_key = api_key
        self.endpoint = endpoint
    
    def generate_threat_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        # Custom AI provider implementation
        pass
    
    def estimate_cost(self, request: AnalysisRequest) -> float:
        # Cost estimation logic
        return 0.50

# Use custom provider
custom_provider = CustomAIProvider("your-api-key", "https://custom-ai.com/api")
analyzer = AIThreatAnalyzer(ai_provider=custom_provider)
```

### Advanced Introspection

```python
from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.transport.factory import create_transport

# Advanced MCP introspection with custom transport
transport = create_transport(
    transport_type="http",
    endpoint="https://mcp-server.example.com",
    timeout=30,
    retry_attempts=3
)

introspector = MCPIntrospector(transport=transport)

# Comprehensive server analysis
server_info = introspector.introspect_server(
    max_tools=100,
    include_schema_analysis=True,
    deep_capability_assessment=True
)

# Risk analysis
risk_analysis = introspector.analyze_security_risks(
    server_info=server_info,
    include_cwe_mapping=True,
    threat_modeling=True
)
```

## API Reference Links

- **[Scanner API](scanner.md)** - Network scanning and service discovery
- **[Detection API](detection.md)** - MCP-specific detection methods  
- **[MCP Introspection API](mcp_introspection.md)** - Deep server analysis
- **[AI Threat Analysis API](ai_threat_analysis.md)** - AI-powered threat assessment
- **[Assessment API](assessment.md)** - Security risk assessment
- **[Reporting API](reporting.md)** - Multi-format report generation

## Migration Guide

### From Version 1.x to 2.x

**CLI Command Changes:**
```bash
# Old (v1.x) - DEPRECATED
python application.py analyze-threats -i results.json

# New (v2.x) - CORRECT
python application.py detect analyze-threats -i results.json
```

**API Changes:**
```python
# Old approach - Basic detection only
from hawkeye.detection.mcp_introspection import MCPIntrospector
introspector = MCPIntrospector()
results = introspector.detect_servers()

# New approach - Detection + AI Analysis
from hawkeye.detection.ai_threat import AIThreatAnalyzer
analyzer = AIThreatAnalyzer()
threat_analysis = analyzer.analyze_threats(mcp_server, environment_context)
```

## Support and Community

- **GitHub Issues**: [Report bugs and request features](https://github.com/yourusername/hawkeye/issues)
- **GitHub Discussions**: [Community support and questions](https://github.com/yourusername/hawkeye/discussions)
- **Documentation**: [Complete user guide](../user_manual.md)
- **Security Issues**: security@hawkeye-project.org

---

**Last Updated**: Version 2.0 with AI Threat Analysis Integration  
**API Compatibility**: Python 3.8+ with MCP SDK integration 