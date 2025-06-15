# MCP Introspection Configuration Reference

## Overview

The MCP Introspection system provides extensive configuration options to customize introspection behavior, performance, and security analysis. This document provides comprehensive reference for all configuration options.

## Configuration Hierarchy

```
IntrospectionConfig
├── Core Settings (timeout, analysis options)
├── AggregatorConfig
│   ├── ToolDiscoveryConfig
│   ├── ResourceDiscoveryConfig
│   └── CapabilityAssessmentConfig
├── TransportConfig
│   ├── RetryConfig
│   └── PoolOptimizationConfig
├── OptimizationConfig
│   ├── CacheConfig
│   ├── MemoryConfig
│   └── ScalingConfig
└── FallbackConfig
```

## Main Configuration Classes

### IntrospectionConfig

Primary configuration class for MCP introspection operations.

```python
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

config = IntrospectionConfig(
    timeout=180.0,
    max_concurrent_servers=1,
    enable_detailed_analysis=True,
    enable_risk_assessment=True,
    aggregator_config=None  # Optional custom aggregator config
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `float` | `180.0` | Maximum time (seconds) for complete introspection |
| `max_concurrent_servers` | `int` | `1` | Maximum concurrent server introspections (disabled for synchronous) |
| `enable_detailed_analysis` | `bool` | `True` | Enable comprehensive analysis including metadata |
| `enable_risk_assessment` | `bool` | `True` | Enable security risk assessment and threat modeling |
| `aggregator_config` | `AggregatorConfig` | `None` | Custom aggregator configuration |

#### Usage Examples

```python
# Basic configuration
config = IntrospectionConfig()

# High-performance configuration
config = IntrospectionConfig(
    timeout=300.0,
    enable_detailed_analysis=True,
    enable_risk_assessment=True
)

# Minimal configuration for speed
config = IntrospectionConfig(
    timeout=60.0,
    enable_detailed_analysis=False,
    enable_risk_assessment=False
)
```

### AggregatorConfig

Configuration for server information aggregation and discovery coordination.

```python
from hawkeye.detection.mcp_introspection.discovery.aggregator import AggregatorConfig

config = AggregatorConfig(
    timeout=120.0,
    enable_parallel_discovery=False,
    enable_risk_aggregation=True,
    tool_discovery_config=None,
    resource_discovery_config=None,
    capability_assessment_config=None
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `float` | `120.0` | Maximum time for discovery aggregation |
| `enable_parallel_discovery` | `bool` | `False` | Enable parallel discovery (disabled for synchronous) |
| `enable_risk_aggregation` | `bool` | `True` | Enable aggregation of security risks |
| `tool_discovery_config` | `ToolDiscoveryConfig` | `None` | Custom tool discovery configuration |
| `resource_discovery_config` | `ResourceDiscoveryConfig` | `None` | Custom resource discovery configuration |
| `capability_assessment_config` | `CapabilityAssessmentConfig` | `None` | Custom capability assessment configuration |

### ToolDiscoveryConfig

Configuration for tool discovery operations.

```python
from hawkeye.detection.mcp_introspection.discovery.tools import ToolDiscoveryConfig

config = ToolDiscoveryConfig(
    timeout=30.0,
    max_tools=100,
    enable_schema_analysis=True,
    enable_parameter_validation=True,
    tool_name_filters=[],
    exclude_dangerous_tools=False
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `float` | `30.0` | Maximum time for tool discovery |
| `max_tools` | `int` | `100` | Maximum number of tools to discover |
| `enable_schema_analysis` | `bool` | `True` | Enable detailed schema analysis |
| `enable_parameter_validation` | `bool` | `True` | Validate tool parameters |
| `tool_name_filters` | `List[str]` | `[]` | Filter tools by name patterns |
| `exclude_dangerous_tools` | `bool` | `False` | Exclude tools flagged as dangerous |

### ResourceDiscoveryConfig

Configuration for resource discovery operations.

```python
from hawkeye.detection.mcp_introspection.discovery.resources import ResourceDiscoveryConfig

config = ResourceDiscoveryConfig(
    timeout=30.0,
    max_resources=50,
    enable_content_analysis=True,
    resource_uri_filters=[],
    analyze_permissions=True
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `float` | `30.0` | Maximum time for resource discovery |
| `max_resources` | `int` | `50` | Maximum number of resources to discover |
| `enable_content_analysis` | `bool` | `True` | Enable resource content analysis |
| `resource_uri_filters` | `List[str]` | `[]` | Filter resources by URI patterns |
| `analyze_permissions` | `bool` | `True` | Analyze resource access permissions |

### CapabilityAssessmentConfig

Configuration for capability assessment operations.

```python
from hawkeye.detection.mcp_introspection.discovery.capabilities import CapabilityAssessmentConfig

config = CapabilityAssessmentConfig(
    timeout=20.0,
    enable_protocol_analysis=True,
    enable_version_detection=True,
    capability_filters=[],
    assess_experimental_features=True
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout` | `float` | `20.0` | Maximum time for capability assessment |
| `enable_protocol_analysis` | `bool` | `True` | Enable MCP protocol analysis |
| `enable_version_detection` | `bool` | `True` | Enable version detection |
| `capability_filters` | `List[str]` | `[]` | Filter capabilities by name patterns |
| `assess_experimental_features` | `bool` | `True` | Assess experimental MCP features |

## Transport Configuration

### MCPServerConfig

Configuration for individual MCP server connections.

```python
from hawkeye.detection.mcp_introspection.models import MCPServerConfig, TransportType

config = MCPServerConfig(
    server_id="production-server",
    name="Production MCP Server",
    command=["node", "server.js"],
    executable=None,
    args=[],
    url=None,
    env={},
    transport_type=TransportType.STDIO,
    transport_config={},
    timeout=30.0
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `server_id` | `str` | Required | Unique identifier for the server |
| `name` | `str` | `None` | Human-readable server name |
| `command` | `List[str]` | `None` | Command to start server (for stdio) |
| `executable` | `str` | `None` | Server executable path |
| `args` | `List[str]` | `[]` | Command line arguments |
| `url` | `str` | `None` | Server URL (for network transports) |
| `env` | `Dict[str, str]` | `{}` | Environment variables |
| `transport_type` | `TransportType` | `STDIO` | Transport protocol type |
| `transport_config` | `Dict[str, Any]` | `{}` | Transport-specific configuration |
| `timeout` | `float` | `30.0` | Connection timeout |

#### Transport Types

```python
from hawkeye.detection.mcp_introspection.models import TransportType

# Available transport types
TransportType.STDIO      # Local process stdio communication
TransportType.SSE        # Server-Sent Events over HTTP
TransportType.HTTP       # HTTP-based communication
TransportType.WEBSOCKET  # WebSocket communication (future)
TransportType.UNKNOWN    # Auto-detection
```

### RetryConfig

Configuration for connection retry behavior.

```python
from hawkeye.detection.mcp_introspection.transport.retry import RetryConfig

config = RetryConfig(
    max_retries=3,
    initial_delay=1.0,
    max_delay=30.0,
    exponential_base=2.0,
    jitter=True,
    retry_on_timeout=True,
    retry_on_connection_error=True
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_retries` | `int` | `3` | Maximum number of retry attempts |
| `initial_delay` | `float` | `1.0` | Initial delay between retries (seconds) |
| `max_delay` | `float` | `30.0` | Maximum delay between retries |
| `exponential_base` | `float` | `2.0` | Base for exponential backoff |
| `jitter` | `bool` | `True` | Add random jitter to delays |
| `retry_on_timeout` | `bool` | `True` | Retry on timeout errors |
| `retry_on_connection_error` | `bool` | `True` | Retry on connection errors |

## Optimization Configuration

### CacheConfig

Configuration for result caching behavior.

```python
from hawkeye.detection.mcp_introspection.optimization.caching import CacheConfig

config = CacheConfig(
    enable_caching=True,
    cache_ttl=300,
    max_cache_size=100,
    cache_directory=None,
    persistent_cache=False,
    cache_compression=True
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_caching` | `bool` | `True` | Enable result caching |
| `cache_ttl` | `int` | `300` | Cache time-to-live (seconds) |
| `max_cache_size` | `int` | `100` | Maximum number of cached entries |
| `cache_directory` | `str` | `None` | Directory for persistent cache |
| `persistent_cache` | `bool` | `False` | Enable persistent disk cache |
| `cache_compression` | `bool` | `True` | Compress cached data |

### MemoryConfig

Configuration for memory management and optimization.

```python
from hawkeye.detection.mcp_introspection.optimization.memory import MemoryConfig

config = MemoryConfig(
    max_memory_mb=100,
    enable_memory_monitoring=True,
    gc_threshold=0.8,
    auto_cleanup=True,
    memory_warning_threshold=0.9,
    enable_memory_profiling=False
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_memory_mb` | `int` | `100` | Maximum memory usage (MB) |
| `enable_memory_monitoring` | `bool` | `True` | Enable memory usage monitoring |
| `gc_threshold` | `float` | `0.8` | Garbage collection threshold (0.0-1.0) |
| `auto_cleanup` | `bool` | `True` | Enable automatic memory cleanup |
| `memory_warning_threshold` | `float` | `0.9` | Memory warning threshold |
| `enable_memory_profiling` | `bool` | `False` | Enable detailed memory profiling |

### ScalingConfig

Configuration for scaling and concurrent operations.

```python
from hawkeye.detection.mcp_introspection.optimization.scaling import ScalingConfig

config = ScalingConfig(
    max_concurrent_connections=10,
    connection_pool_size=20,
    enable_connection_reuse=True,
    batch_size=5,
    enable_load_balancing=False,
    scaling_factor=1.5
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_concurrent_connections` | `int` | `10` | Maximum concurrent connections |
| `connection_pool_size` | `int` | `20` | Connection pool size |
| `enable_connection_reuse` | `bool` | `True` | Enable connection reuse |
| `batch_size` | `int` | `5` | Batch size for operations |
| `enable_load_balancing` | `bool` | `False` | Enable load balancing |
| `scaling_factor` | `float` | `1.5` | Auto-scaling factor |

### PoolOptimizationConfig

Configuration for connection pool optimization.

```python
from hawkeye.detection.mcp_introspection.optimization.pooling import PoolOptimizationConfig

config = PoolOptimizationConfig(
    initial_pool_size=5,
    max_pool_size=20,
    pool_timeout=30.0,
    enable_pool_monitoring=True,
    pool_cleanup_interval=60,
    idle_connection_timeout=300
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `initial_pool_size` | `int` | `5` | Initial connection pool size |
| `max_pool_size` | `int` | `20` | Maximum pool size |
| `pool_timeout` | `float` | `30.0` | Pool operation timeout |
| `enable_pool_monitoring` | `bool` | `True` | Enable pool monitoring |
| `pool_cleanup_interval` | `int` | `60` | Pool cleanup interval (seconds) |
| `idle_connection_timeout` | `int` | `300` | Idle connection timeout |

## Fallback and Error Handling Configuration

### FallbackConfig

Configuration for fallback behavior when introspection fails.

```python
from hawkeye.detection.mcp_introspection.fallback import FallbackConfig

config = FallbackConfig(
    enable_fallback=True,
    fallback_timeout=30.0,
    fallback_to_legacy=False,
    graceful_degradation=True,
    partial_results_threshold=0.5,
    error_reporting=True
)
```

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_fallback` | `bool` | `True` | Enable fallback mechanisms |
| `fallback_timeout` | `float` | `30.0` | Timeout for fallback operations |
| `fallback_to_legacy` | `bool` | `False` | Fallback to legacy Node.js approach |
| `graceful_degradation` | `bool` | `True` | Enable graceful degradation |
| `partial_results_threshold` | `float` | `0.5` | Threshold for accepting partial results |
| `error_reporting` | `bool` | `True` | Enable detailed error reporting |

## Configuration Examples

### Production Configuration

```python
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig
from hawkeye.detection.mcp_introspection.discovery.aggregator import AggregatorConfig
from hawkeye.detection.mcp_introspection.optimization.caching import CacheConfig
from hawkeye.detection.mcp_introspection.optimization.memory import MemoryConfig

# Production-ready configuration
production_config = IntrospectionConfig(
    timeout=300.0,  # 5 minutes for comprehensive analysis
    enable_detailed_analysis=True,
    enable_risk_assessment=True,
    aggregator_config=AggregatorConfig(
        timeout=120.0,
        enable_risk_aggregation=True
    )
)

# With caching for performance
cache_config = CacheConfig(
    enable_caching=True,
    cache_ttl=600,  # 10 minutes
    max_cache_size=200,
    persistent_cache=True
)

# Memory management for production
memory_config = MemoryConfig(
    max_memory_mb=200,
    enable_memory_monitoring=True,
    gc_threshold=0.7,
    auto_cleanup=True
)
```

### Development Configuration

```python
# Development configuration for fast iteration
dev_config = IntrospectionConfig(
    timeout=60.0,  # Faster timeout for development
    enable_detailed_analysis=True,
    enable_risk_assessment=False,  # Skip risk analysis for speed
    aggregator_config=AggregatorConfig(
        timeout=30.0,
        enable_risk_aggregation=False
    )
)

# Minimal caching for development
dev_cache_config = CacheConfig(
    enable_caching=False,  # Disable caching for fresh results
    cache_ttl=60
)
```

### High-Performance Configuration

```python
from hawkeye.detection.mcp_introspection.optimization.scaling import ScalingConfig

# High-performance configuration for large deployments
high_perf_config = IntrospectionConfig(
    timeout=600.0,  # Extended timeout for large operations
    enable_detailed_analysis=True,
    enable_risk_assessment=True
)

# Scaling configuration
scaling_config = ScalingConfig(
    max_concurrent_connections=20,
    connection_pool_size=50,
    enable_connection_reuse=True,
    batch_size=10
)

# Aggressive caching
aggressive_cache_config = CacheConfig(
    enable_caching=True,
    cache_ttl=1800,  # 30 minutes
    max_cache_size=1000,
    persistent_cache=True,
    cache_compression=True
)
```

### Security-Focused Configuration

```python
from hawkeye.detection.mcp_introspection.discovery.tools import ToolDiscoveryConfig
from hawkeye.detection.mcp_introspection.discovery.resources import ResourceDiscoveryConfig

# Security-focused configuration
security_config = IntrospectionConfig(
    timeout=180.0,
    enable_detailed_analysis=True,
    enable_risk_assessment=True,  # Critical for security analysis
    aggregator_config=AggregatorConfig(
        tool_discovery_config=ToolDiscoveryConfig(
            enable_schema_analysis=True,
            enable_parameter_validation=True,
            exclude_dangerous_tools=False  # Include for analysis
        ),
        resource_discovery_config=ResourceDiscoveryConfig(
            enable_content_analysis=True,
            analyze_permissions=True
        )
    )
)
```

## Environment Variable Configuration

Many configuration options can be set via environment variables:

```bash
# Core configuration
export HAWKEYE_MCP_TIMEOUT=300
export HAWKEYE_MCP_ENABLE_DETAILED_ANALYSIS=true
export HAWKEYE_MCP_ENABLE_RISK_ASSESSMENT=true

# Caching configuration
export HAWKEYE_MCP_CACHE_ENABLED=true
export HAWKEYE_MCP_CACHE_TTL=600
export HAWKEYE_MCP_CACHE_MAX_SIZE=200

# Memory configuration
export HAWKEYE_MCP_MAX_MEMORY_MB=100
export HAWKEYE_MCP_ENABLE_MEMORY_MONITORING=true

# Transport configuration
export HAWKEYE_MCP_MAX_RETRIES=5
export HAWKEYE_MCP_RETRY_DELAY=2.0

# Debug configuration
export HAWKEYE_DEBUG_MCP=1
export HAWKEYE_DEBUG_TRANSPORT=1
export HAWKEYE_DEBUG_DISCOVERY=1
export HAWKEYE_DEBUG_RISK=1
```

## YAML Configuration File

Configuration can also be specified in YAML format:

```yaml
# hawkeye_mcp_config.yaml
mcp_introspection:
  core:
    timeout: 300.0
    enable_detailed_analysis: true
    enable_risk_assessment: true
  
  aggregator:
    timeout: 120.0
    enable_risk_aggregation: true
    
    tool_discovery:
      timeout: 30.0
      max_tools: 100
      enable_schema_analysis: true
      enable_parameter_validation: true
    
    resource_discovery:
      timeout: 30.0
      max_resources: 50
      enable_content_analysis: true
      analyze_permissions: true
    
    capability_assessment:
      timeout: 20.0
      enable_protocol_analysis: true
      enable_version_detection: true
  
  optimization:
    cache:
      enable_caching: true
      cache_ttl: 600
      max_cache_size: 200
      persistent_cache: true
    
    memory:
      max_memory_mb: 100
      enable_memory_monitoring: true
      gc_threshold: 0.8
      auto_cleanup: true
    
    scaling:
      max_concurrent_connections: 10
      connection_pool_size: 20
      enable_connection_reuse: true
  
  transport:
    retry:
      max_retries: 3
      initial_delay: 1.0
      exponential_base: 2.0
      jitter: true
  
  fallback:
    enable_fallback: true
    graceful_degradation: true
    partial_results_threshold: 0.5
```

### Loading YAML Configuration

```python
import yaml
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

# Load configuration from YAML file
with open('hawkeye_mcp_config.yaml', 'r') as f:
    yaml_config = yaml.safe_load(f)

# Create configuration objects
config = IntrospectionConfig.from_dict(yaml_config['mcp_introspection']['core'])
```

## Configuration Validation

The MCP introspection system includes comprehensive configuration validation:

```python
from hawkeye.detection.mcp_introspection.migration import ConfigurationValidator

# Validate configuration
validator = ConfigurationValidator()

# Validate single configuration
is_valid, errors = validator.validate_introspection_config(config)
if not is_valid:
    print("Configuration errors:")
    for error in errors:
        print(f"  - {error}")

# Validate complete configuration set
is_valid, errors = validator.validate_complete_configuration({
    'introspection': config,
    'aggregator': aggregator_config,
    'cache': cache_config
})
```

## Migration from Legacy Configuration

The system includes tools for migrating from the legacy Node.js configuration:

```python
from hawkeye.detection.mcp_introspection.migration import ConfigurationMigrator

# Migrate legacy configuration
migrator = ConfigurationMigrator()

# Convert legacy Node.js configuration
legacy_config = {
    'node_script_timeout': 60,
    'max_retries': 3,
    'script_path': '/tmp/mcp_scripts'
}

new_config = migrator.migrate_from_legacy(legacy_config)
```

## Performance Tuning Guidelines

### For Small Deployments (< 10 servers)
```python
small_deployment_config = IntrospectionConfig(
    timeout=120.0,
    aggregator_config=AggregatorConfig(timeout=60.0)
)
```

### For Medium Deployments (10-100 servers)
```python
medium_deployment_config = IntrospectionConfig(
    timeout=300.0,
    aggregator_config=AggregatorConfig(
        timeout=120.0,
        enable_risk_aggregation=True
    )
)

cache_config = CacheConfig(
    enable_caching=True,
    cache_ttl=600,
    max_cache_size=100
)
```

### For Large Deployments (100+ servers)
```python
large_deployment_config = IntrospectionConfig(
    timeout=600.0,
    aggregator_config=AggregatorConfig(
        timeout=180.0,
        enable_risk_aggregation=True
    )
)

scaling_config = ScalingConfig(
    max_concurrent_connections=20,
    connection_pool_size=50,
    batch_size=10
)

cache_config = CacheConfig(
    enable_caching=True,
    cache_ttl=1800,
    max_cache_size=500,
    persistent_cache=True
)
```

## Best Practices

1. **Always enable risk assessment** in production environments
2. **Use caching** for repeated introspections of the same servers
3. **Monitor memory usage** for large-scale operations
4. **Configure appropriate timeouts** based on network latency
5. **Enable fallback mechanisms** for reliability
6. **Use persistent caching** for long-running operations
7. **Validate configurations** before deployment
8. **Monitor performance metrics** and adjust as needed

## Troubleshooting Configuration Issues

See the [troubleshooting guide](../troubleshooting.md#mcp-introspection-issues) for detailed configuration troubleshooting information.

Common configuration problems:
- Timeout values too low for slow networks
- Memory limits too restrictive for large servers
- Cache settings causing stale data
- Transport configuration mismatches
- Missing required server configuration fields

For additional support, enable debug logging:
```bash
export HAWKEYE_DEBUG_CONFIG=1
```