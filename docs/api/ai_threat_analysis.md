# AI Threat Analysis API Documentation

## Overview

The AI Threat Analysis API provides AI-powered security assessment capabilities for detected MCP servers. It supports multiple AI providers, cost management, and intelligent fallback mechanisms to deliver comprehensive threat analysis with actionable security recommendations.

## Key Features

- **Multi-Provider AI Support**: OpenAI, Anthropic, and Local LLM integration
- **Dynamic Threat Assessment**: Real-time analysis of any MCP tool or server
- **Cost Management**: Configurable cost limits and optimization
- **Intelligent Failover**: Automatic provider switching and rule-based fallback
- **Parallel Processing**: High-performance batch analysis
- **Threat Intelligence**: Learning and pattern recognition capabilities

## Core Classes

### AIThreatAnalyzer

Main orchestrator for AI-powered threat analysis.

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer
from hawkeye.detection.ai_threat.models import EnvironmentContext, DeploymentType

analyzer = AIThreatAnalyzer()
```

#### Methods

##### `analyze_threats(mcp_server, environment_context, analysis_type="comprehensive")`

Analyzes a single MCP server for security threats.

**Parameters:**
- `mcp_server` (MCPServerInfo): Server information from detection
- `environment_context` (EnvironmentContext): Deployment environment context
- `analysis_type` (str): Analysis depth - "quick", "comprehensive", or "detailed"

**Returns:** `ThreatAnalysis` object with complete assessment

**Example:**
```python
from hawkeye.detection.ai_threat.models import EnvironmentContext, DeploymentType

environment = EnvironmentContext(
    deployment_type=DeploymentType.REMOTE,
    security_posture="medium",
    compliance_requirements=["OWASP_TOP_10", "PCI_DSS"]
)

analysis = analyzer.analyze_threats(
    mcp_server=detected_server,
    environment_context=environment,
    analysis_type="comprehensive"
)

print(f"Threat Level: {analysis.threat_level}")
print(f"Attack Vectors: {len(analysis.attack_vectors)}")
print(f"Mitigations: {len(analysis.mitigation_strategies)}")
```

##### `analyze_multiple_threats(mcp_servers, environment_context, analysis_type="comprehensive")`

Batch analysis of multiple MCP servers with parallel processing.

**Parameters:**
- `mcp_servers` (List[MCPServerInfo]): List of servers to analyze
- `environment_context` (EnvironmentContext): Environment context
- `analysis_type` (str): Analysis depth

**Returns:** `List[ThreatAnalysis]` with results for each server

**Example:**
```python
# Parallel analysis of multiple servers
analyses = analyzer.analyze_multiple_threats(
    mcp_servers=detected_servers,
    environment_context=environment,
    analysis_type="comprehensive"
)

# Process results
for analysis in analyses:
    if analysis.threat_level in ["HIGH", "CRITICAL"]:
        print(f"⚠️ High-risk server: {analysis.tool_capabilities.tool_name}")
```

##### `get_analysis_stats()`

Get analysis statistics including cost and performance metrics.

**Returns:** Dictionary with analysis statistics

**Example:**
```python
stats = analyzer.get_analysis_stats()
print(f"Total Cost: ${stats['total_cost']:.4f}")
print(f"Analyses Performed: {stats['analyses_performed']}")
print(f"Cache Hit Rate: {stats['cache_hits'] / stats['analyses_performed']:.2%}")
```

## AI Providers

### OpenAIProvider

Integration with OpenAI's GPT models for threat analysis.

```python
from hawkeye.detection.ai_threat.ai_providers import OpenAIProvider

provider = OpenAIProvider(
    api_key="your_openai_key",
    model="gpt-4",  # or "gpt-3.5-turbo"
    timeout=60
)
```

#### Configuration

**Environment Variables:**
```bash
export AI_OPENAI_API_KEY=your_api_key_here
export AI_OPENAI_MODEL=gpt-4
export AI_OPENAI_TIMEOUT=60
```

**Supported Models:**
- `gpt-4` - Highest quality, higher cost
- `gpt-3.5-turbo` - Good quality, lower cost

### AnthropicProvider

Integration with Anthropic's Claude models.

```python
from hawkeye.detection.ai_threat.ai_providers import AnthropicProvider

provider = AnthropicProvider(
    api_key="your_anthropic_key",
    model="claude-3-haiku-20240307",
    timeout=60
)
```

#### Configuration

**Environment Variables:**
```bash
export AI_ANTHROPIC_API_KEY=your_api_key_here
export AI_ANTHROPIC_MODEL=claude-3-haiku-20240307
export AI_ANTHROPIC_TIMEOUT=60
```

**Supported Models:**
- `claude-3-opus-20240229` - Highest capability
- `claude-3-sonnet-20240229` - Balanced performance
- `claude-3-haiku-20240307` - Fast and cost-effective

### LocalLLMProvider

Integration with local LLM endpoints (Ollama, etc.).

```python
from hawkeye.detection.ai_threat.ai_providers import LocalLLMProvider

provider = LocalLLMProvider(
    endpoint="http://localhost:11434",
    model="llama3.1:8b",
    timeout=120
)
```

#### Configuration

**Environment Variables:**
```bash
export AI_LOCAL_LLM_ENDPOINT=http://localhost:11434
export AI_LOCAL_LLM_MODEL=llama3.1:8b
export AI_LOCAL_LLM_TIMEOUT=120
```

**Recommended Models:**
- `llama3.1:8b` - Fast, good quality
- `llama3.1:70b` - High quality, slower
- `codellama:13b` - Good for technical analysis

## Data Models

### ThreatAnalysis

Complete threat analysis result from AI assessment.

```python
@dataclass
class ThreatAnalysis:
    tool_capabilities: ToolCapabilities
    threat_level: ThreatLevel
    attack_vectors: List[AttackVector]
    mitigation_strategies: List[MitigationStrategy]
    abuse_scenarios: List[AbuseScenario]
    compliance_impact: ComplianceImpact
    confidence_score: float
    analysis_metadata: AnalysisMetadata
```

**Key Fields:**
- `threat_level`: LOW, MEDIUM, HIGH, CRITICAL
- `attack_vectors`: Specific attack scenarios with likelihood and impact
- `mitigation_strategies`: Actionable security recommendations
- `compliance_impact`: Regulatory framework implications
- `confidence_score`: AI analysis confidence (0.0-1.0)

### EnvironmentContext

Deployment environment information for contextual analysis.

```python
@dataclass
class EnvironmentContext:
    deployment_type: DeploymentType
    security_posture: SecurityPosture
    data_sensitivity: DataSensitivity
    network_exposure: NetworkExposure
    user_privileges: UserPrivileges
    compliance_requirements: List[ComplianceFramework]
```

**Example:**
```python
from hawkeye.detection.ai_threat.models import (
    EnvironmentContext, DeploymentType, SecurityPosture, 
    DataSensitivity, NetworkExposure, UserPrivileges, ComplianceFramework
)

context = EnvironmentContext(
    deployment_type=DeploymentType.CLOUD,
    security_posture=SecurityPosture.HIGH,
    data_sensitivity=DataSensitivity.CONFIDENTIAL,
    network_exposure=NetworkExposure.PUBLIC,
    user_privileges=UserPrivileges.ADMIN,
    compliance_requirements=[
        ComplianceFramework.PCI_DSS,
        ComplianceFramework.HIPAA,
        ComplianceFramework.GDPR
    ]
)
```

### AttackVector

Specific attack scenario with detailed analysis.

```python
@dataclass
class AttackVector:
    name: str
    severity: SeverityLevel
    description: str
    impact: str
    likelihood: str
    prerequisites: List[str]
    attack_steps: List[str]
    detection_methods: List[str]
    prevention_measures: List[str]
```

### MitigationStrategy

Actionable security recommendation.

```python
@dataclass
class MitigationStrategy:
    name: str
    description: str
    implementation_steps: List[str]
    effectiveness_score: float
    cost_estimate: str
    urgency: str
    applicable_threats: List[str]
```

## Configuration and Cost Management

### Cost Limits

Configure cost limits to control AI analysis expenses:

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer

# Set cost limits during initialization
analyzer = AIThreatAnalyzer()

# Per-analysis cost limit
analysis = analyzer.analyze_threats(
    mcp_server=server,
    environment_context=context,
    cost_limit=1.0  # Maximum $1.00 per analysis
)
```

### Global Configuration

**Environment Variables:**
```bash
# Cost management
export AI_MAX_COST_PER_ANALYSIS=1.00
export AI_MAX_DAILY_COST=25.00

# Provider selection
export AI_PROVIDER=anthropic
export AI_FALLBACK_PROVIDER=openai

# Performance settings
export AI_MAX_WORKERS=3
export AI_ENABLE_CACHING=true
```

**Configuration File:**
```yaml
ai:
  provider: anthropic
  fallback_provider: openai
  max_cost_per_analysis: 1.00
  max_daily_cost: 25.00
  
  performance:
    max_workers: 3
    enable_caching: true
    cache_ttl: 3600
    
  providers:
    openai:
      api_key: "${AI_OPENAI_API_KEY}"
      model: "gpt-4"
    anthropic:
      api_key: "${AI_ANTHROPIC_API_KEY}"
      model: "claude-3-haiku-20240307"
```

## Advanced Usage

### Custom Provider Implementation

Create custom AI providers for specialized analysis:

```python
from hawkeye.detection.ai_threat.ai_providers import AIProvider
from hawkeye.detection.ai_threat.models import AnalysisRequest, AnalysisResponse

class CustomSecurityAIProvider(AIProvider):
    def __init__(self, api_key: str, endpoint: str):
        super().__init__()
        self.api_key = api_key
        self.endpoint = endpoint
    
    def generate_threat_analysis(self, request: AnalysisRequest) -> AnalysisResponse:
        # Custom AI provider implementation
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        payload = {
            "prompt": self._build_security_prompt(request),
            "max_tokens": request.max_tokens,
            "temperature": request.temperature
        }
        
        response = requests.post(f"{self.endpoint}/analyze", 
                               json=payload, headers=headers)
        
        return self._parse_response(response.json())
    
    def estimate_cost(self, request: AnalysisRequest) -> float:
        # Custom cost calculation
        return 0.50
    
    def _build_security_prompt(self, request: AnalysisRequest) -> str:
        # Custom prompt engineering for security analysis
        pass
    
    def _parse_response(self, response_data: dict) -> AnalysisResponse:
        # Parse custom response format
        pass

# Use custom provider
custom_provider = CustomSecurityAIProvider("api-key", "https://custom-ai.com")
analyzer = AIThreatAnalyzer(ai_provider=custom_provider)
```

### Batch Processing with Progress Tracking

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer
from rich.progress import Progress, SpinnerColumn, TextColumn

analyzer = AIThreatAnalyzer()

def progress_callback(completed: int, total: int, current_server: str):
    print(f"Progress: {completed}/{total} - Analyzing: {current_server}")

# Batch analysis with progress tracking
with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    console=console
) as progress:
    
    task = progress.add_task("Analyzing threats...", total=len(servers))
    
    analyses = analyzer.analyze_multiple_threats(
        mcp_servers=servers,
        environment_context=context,
        analysis_type="comprehensive",
        progress_callback=lambda c, t, s: progress.advance(task, 1)
    )
```

### Threat Intelligence Integration

```python
from hawkeye.detection.ai_threat.threat_intelligence_db import ThreatIntelligenceDB

# Initialize threat intelligence database
threat_db = ThreatIntelligenceDB()

# Add custom threat patterns
threat_db.add_pattern(
    pattern_name="custom_file_access",
    risk_score=8.5,
    description="Unrestricted file system access",
    indicators=["file_operations", "path_traversal_risk"],
    mitigation="Implement path validation and sandboxing"
)

# Use with analyzer
analyzer = AIThreatAnalyzer(threat_intelligence=threat_db)
```

## Error Handling and Resilience

### Exception Handling

```python
from hawkeye.exceptions import AIProviderError, CostLimitExceededError
from hawkeye.detection.ai_threat import AIThreatAnalyzer

analyzer = AIThreatAnalyzer()

try:
    analysis = analyzer.analyze_threats(server, context)
except AIProviderError as e:
    print(f"AI provider failed: {e}")
    # Automatic fallback to rule-based analysis
    analysis = analyzer.analyze_threats_fallback(server, context)
except CostLimitExceededError as e:
    print(f"Cost limit exceeded: {e}")
    # Reduce analysis scope or increase limit
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Graceful Degradation

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer

analyzer = AIThreatAnalyzer()

# Analysis with automatic fallback
result = analyzer.analyze_threats_with_fallback(
    mcp_server=server,
    environment_context=context,
    fallback_to_rules=True,  # Enable rule-based fallback
    cost_limit=2.0
)

if result.analysis_metadata.provider == "rule_based":
    print("⚠️ Used rule-based analysis due to AI provider failure")
else:
    print(f"✅ AI analysis completed using {result.analysis_metadata.provider}")
```

## Performance Optimization

### Caching

```python
from hawkeye.detection.ai_threat import AIThreatAnalyzer

# Enable intelligent caching
analyzer = AIThreatAnalyzer(enable_caching=True, cache_ttl=3600)

# Cache statistics
cache_stats = analyzer.get_cache_stats()
print(f"Cache hit rate: {cache_stats['hit_rate']:.2%}")
print(f"Cache size: {cache_stats['size']} entries")
```

### Memory Optimization

```python
from hawkeye.detection.mcp_introspection.optimization import create_memory_optimizer

# Create memory optimizer for large-scale analysis
memory_optimizer = create_memory_optimizer(
    optimization_level="aggressive",
    max_memory_mb=2048
)

analyzer = AIThreatAnalyzer(memory_optimizer=memory_optimizer)
```

## Integration Examples

### CLI Integration

```python
import click
from hawkeye.detection.ai_threat import AIThreatAnalyzer

@click.command()
@click.option('--input', '-i', required=True, help='Detection results JSON')
@click.option('--cost-limit', type=float, default=5.0, help='Cost limit')
@click.option('--analysis-type', default='comprehensive', 
              type=click.Choice(['quick', 'comprehensive', 'detailed']))
def analyze_threats(input: str, cost_limit: float, analysis_type: str):
    """AI-powered threat analysis command."""
    analyzer = AIThreatAnalyzer()
    
    # Load detection results
    with open(input) as f:
        detection_data = json.load(f)
    
    # Perform analysis
    for server_data in detection_data['servers']:
        analysis = analyzer.analyze_threats(
            server_data['mcp_server'],
            environment_context,
            analysis_type=analysis_type,
            cost_limit=cost_limit
        )
        
        print(f"Server: {analysis.tool_capabilities.tool_name}")
        print(f"Threat Level: {analysis.threat_level}")
        print(f"Confidence: {analysis.confidence_score:.2f}")
```

### Web API Integration

```python
from flask import Flask, request, jsonify
from hawkeye.detection.ai_threat import AIThreatAnalyzer

app = Flask(__name__)
analyzer = AIThreatAnalyzer()

@app.route('/api/analyze-threats', methods=['POST'])
def analyze_threats_api():
    """REST API endpoint for threat analysis."""
    try:
        data = request.json
        server_info = data['mcp_server']
        environment = data['environment_context']
        
        analysis = analyzer.analyze_threats(
            server_info, 
            environment,
            cost_limit=data.get('cost_limit', 1.0)
        )
        
        return jsonify({
            'status': 'success',
            'threat_level': analysis.threat_level.value,
            'attack_vectors': len(analysis.attack_vectors),
            'mitigations': len(analysis.mitigation_strategies),
            'confidence': analysis.confidence_score,
            'cost': analysis.analysis_metadata.cost
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
```

## Testing

### Unit Testing

```python
import unittest
from unittest.mock import Mock, patch
from hawkeye.detection.ai_threat import AIThreatAnalyzer

class TestAIThreatAnalyzer(unittest.TestCase):
    
    def setUp(self):
        self.analyzer = AIThreatAnalyzer()
        self.mock_server = Mock()
        self.mock_context = Mock()
    
    @patch('hawkeye.detection.ai_threat.ai_providers.OpenAIProvider')
    def test_analyze_threats_success(self, mock_provider):
        """Test successful threat analysis."""
        mock_provider.return_value.generate_threat_analysis.return_value = Mock()
        
        result = self.analyzer.analyze_threats(
            self.mock_server, 
            self.mock_context
        )
        
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, 'threat_level'))
    
    def test_cost_limit_enforcement(self):
        """Test cost limit enforcement."""
        with self.assertRaises(CostLimitExceededError):
            self.analyzer.analyze_threats(
                self.mock_server,
                self.mock_context,
                cost_limit=0.01  # Very low limit
            )
```

### Integration Testing

```python
import pytest
from hawkeye.detection.ai_threat import AIThreatAnalyzer
from hawkeye.detection.mcp_introspection.models import MCPServerInfo

@pytest.mark.integration
class TestAIThreatAnalysisIntegration:
    
    def test_full_analysis_workflow(self):
        """Test complete analysis workflow."""
        analyzer = AIThreatAnalyzer()
        
        # Create test server
        test_server = MCPServerInfo(
            server_id="test-server",
            tools=[
                MCPTool(name="file_operations", description="File system access")
            ]
        )
        
        # Perform analysis
        result = analyzer.analyze_threats(
            test_server,
            environment_context,
            cost_limit=0.50
        )
        
        assert result.threat_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert len(result.attack_vectors) > 0
        assert len(result.mitigation_strategies) > 0
        assert 0.0 <= result.confidence_score <= 1.0
```

## Best Practices

### Cost Management
- Always set cost limits for production use
- Monitor usage with `get_analysis_stats()`
- Use caching for repeated analyses
- Consider using local LLMs for privacy-sensitive data

### Performance
- Use batch processing for multiple servers
- Enable parallel processing for large datasets
- Implement progress tracking for user experience
- Use appropriate analysis types (quick vs comprehensive)

### Security
- Secure API key storage and rotation
- Validate input data before analysis
- Implement proper error handling and logging
- Regular security audits of AI provider integrations

### Quality Assurance
- Implement comprehensive testing
- Monitor analysis quality and accuracy
- Regular review of AI provider performance
- Feedback loop for continuous improvement

---

**Last Updated**: Version 2.0  
**API Stability**: Stable for production use  
**Required Dependencies**: OpenAI SDK, Anthropic SDK, requests, pydantic 