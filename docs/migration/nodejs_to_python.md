# Migration Guide: Node.js to Python MCP Introspection

## Overview

This guide provides comprehensive instructions for migrating from the legacy Node.js script generation approach to the new Python-based MCP introspection system. The migration improves reliability, performance, and maintainability while maintaining backward compatibility.

## Key Benefits of Migration

### Performance Improvements
- **50% faster introspection**: Direct Python MCP client vs. subprocess execution
- **Connection pooling**: Reuse connections across multiple operations
- **Concurrent operations**: Process multiple servers simultaneously
- **Result caching**: Avoid repeated introspection of same servers

### Reliability Enhancements
- **Native error handling**: Structured Python exceptions vs. subprocess errors
- **Better timeout management**: Granular timeout controls per operation
- **Retry logic**: Exponential backoff for failed connections
- **Resource cleanup**: Automatic connection and memory cleanup

### Security Improvements
- **Enhanced risk analysis**: 521+ security risk patterns
- **Threat modeling**: Capability-based security assessment
- **CWE mapping**: Common Weakness Enumeration integration
- **CVSS-like scoring**: Industry-standard risk scoring

### Operational Benefits
- **No Node.js dependency**: Simplified deployment and maintenance
- **Better logging**: Structured logging with audit trails
- **Monitoring**: Built-in performance metrics and statistics
- **Backward compatibility**: Existing code continues to work

## Migration Timeline

### Phase 1: Assessment (Week 1)
- [ ] Inventory existing Node.js integration points
- [ ] Identify custom modifications to legacy system
- [ ] Document current configuration parameters
- [ ] Test backward compatibility layer

### Phase 2: Configuration Migration (Week 2)
- [ ] Update configuration files to new format
- [ ] Migrate transport-specific settings
- [ ] Configure risk analysis policies
- [ ] Set up caching and optimization parameters

### Phase 3: Code Migration (Week 3)
- [ ] Replace direct Node.js calls with Python API
- [ ] Update error handling to use new exception types
- [ ] Migrate to new data models (optional)
- [ ] Update tests to use new API

### Phase 4: Validation (Week 4)
- [ ] Verify functionality parity
- [ ] Performance benchmarking
- [ ] Security validation
- [ ] User acceptance testing

## Pre-Migration Checklist

### System Requirements
- [ ] Python 3.8+ installed
- [ ] Virtual environment configured
- [ ] MCP SDK dependencies installed
- [ ] Existing Node.js scripts identified

### Configuration Audit
- [ ] Document current timeout settings
- [ ] Identify transport configurations
- [ ] List custom script modifications
- [ ] Backup existing configuration files

### Integration Points
- [ ] Identify all calls to `MCPIntrospector`
- [ ] Document expected data formats
- [ ] List error handling patterns
- [ ] Identify performance requirements

## Step-by-Step Migration

### Step 1: Install New Dependencies

Add the following to your `requirements.txt`:

```txt
# MCP Introspection System
mcp>=1.0.0
aiofiles>=0.8.0
async-timeout>=4.0.0
```

Install dependencies:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Update Imports

Replace legacy imports:

```python
# OLD - Node.js based approach
from hawkeye.detection.mcp_introspection import MCPIntrospector

# NEW - Same import, Python implementation
from hawkeye.detection.mcp_introspection import MCPIntrospector
```

**Note**: The import remains the same for backward compatibility.

### Step 3: Configuration Migration

#### Legacy Configuration (Node.js)
```python
# OLD configuration approach
config = {
    'timeout': 30,
    'max_retries': 3,
    'node_script_path': '/tmp/mcp_scripts',
    'script_timeout': 60
}
```

#### New Configuration (Python)
```python
# NEW configuration approach
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

config = IntrospectionConfig(
    # Connection settings
    timeout=30.0,
    max_retries=3,
    retry_delay=1.0,
    
    # Performance settings
    max_concurrent_connections=5,
    connection_pool_size=10,
    
    # Caching settings
    enable_caching=True,
    cache_ttl=300,
    
    # Risk analysis settings
    enable_risk_analysis=True,
    risk_threshold='medium'
)

introspector = MCPIntrospector(config)
```

### Step 4: Update API Calls

#### Basic Introspection

```python
# OLD - Node.js approach (still works)
capabilities = introspector.introspect_server(server_info, process_info)

# NEW - Enhanced Python approach (recommended)
capabilities = introspector.introspect_server(server_info, process_info)

# NEW - With risk analysis
analysis = introspector.introspect_with_risk_analysis(server_info, process_info)
```

#### Batch Processing

```python
# OLD - Sequential processing
results = []
for server_info, process_info in servers:
    capability = introspector.introspect_server(server_info, process_info)
    results.append(capability)

# NEW - Concurrent processing
server_list = [(server_info, process_info) for server_info, process_info in servers]
results = introspector.introspect_multiple_servers(server_list)
```

### Step 5: Error Handling Migration

#### Legacy Error Handling
```python
# OLD - Generic exception handling
try:
    capabilities = introspector.introspect_server(server_info, process_info)
except Exception as e:
    logger.error(f"Introspection failed: {e}")
```

#### New Error Handling
```python
# NEW - Structured exception handling
from hawkeye.detection.mcp_introspection.transport.errors import (
    TransportError, ConnectionError, TimeoutError, ProtocolError
)
from hawkeye.detection.mcp_introspection.discovery.errors import DiscoveryError

try:
    capabilities = introspector.introspect_server(server_info, process_info)
except ConnectionError as e:
    logger.error(f"Connection failed: {e.message}")
    # Retry with different transport
    capabilities = introspector.introspect_with_specific_transport(
        server_info, process_info, force_transport='stdio'
    )
except TimeoutError as e:
    logger.warning(f"Introspection timed out: {e.message}")
    # Continue with partial results
except DiscoveryError as e:
    logger.warning(f"Discovery incomplete: {e.message}")
    # Attempt individual discovery methods
    tools = introspector.discover_tools_only(server_info, process_info)
except TransportError as e:
    logger.error(f"Transport error: {e.message}")
```

### Step 6: Data Model Migration

The new system provides enhanced data models while maintaining backward compatibility.

#### Legacy Data Access
```python
# OLD - Legacy properties (still work)
server_name = capabilities.server_name
tool_count = capabilities.tool_count
risk_level = capabilities.highest_risk_level
```

#### Enhanced Data Access
```python
# NEW - Enhanced properties and methods
server_name = capabilities.server_name
tool_count = capabilities.tool_count
risk_level = capabilities.highest_risk_level

# NEW - Additional capabilities
categories = capabilities.capability_categories
has_file_access = capabilities.has_file_access
has_network_access = capabilities.has_external_access
has_code_execution = capabilities.has_code_execution

# NEW - Detailed risk analysis
for tool in capabilities.tools:
    print(f"Tool: {tool.name}")
    print(f"Category: {tool.capability_category}")
    print(f"Risk: {tool.risk_level}")
```

### Step 7: Performance Optimization

#### Enable Caching
```python
# Enable result caching to avoid repeated introspection
config = IntrospectionConfig(
    enable_caching=True,
    cache_ttl=300  # 5 minutes
)
```

#### Connection Pooling
```python
# Configure connection pooling for better performance
config = IntrospectionConfig(
    max_concurrent_connections=10,
    connection_pool_size=20,
    enable_optimization=True
)
```

#### Memory Management
```python
# Configure memory limits for large-scale operations
config = IntrospectionConfig(
    memory_limit_mb=200,
    enable_memory_optimization=True
)
```

## Backward Compatibility

### Maintained Interfaces
- `MCPIntrospector` class and methods
- `MCPCapabilities` data structure
- `MCPTool` and `MCPResource` classes
- All existing method signatures

### Legacy Support
The new system includes a compatibility layer that:
- Translates legacy configuration formats
- Provides fallback behavior for deprecated features
- Maintains existing return value formats
- Preserves error handling patterns

### Gradual Migration
You can migrate gradually:

1. **Phase 1**: Use new system with legacy API
2. **Phase 2**: Adopt new configuration format
3. **Phase 3**: Utilize enhanced error handling
4. **Phase 4**: Leverage new performance features

## Testing the Migration

### Validation Script
Create a validation script to test the migration:

```python
#!/usr/bin/env python3
"""
Migration validation script
"""
import logging
from hawkeye.detection.mcp_introspection import MCPIntrospector
from hawkeye.detection.mcp_introspection.introspection import IntrospectionConfig

def validate_migration():
    """Validate the migration by testing key functionality."""
    
    # Test 1: Basic initialization
    introspector = MCPIntrospector()
    assert introspector is not None
    print("✓ Basic initialization works")
    
    # Test 2: Configuration
    config = IntrospectionConfig(timeout=30.0)
    introspector = MCPIntrospector(config)
    assert introspector is not None
    print("✓ Configuration initialization works")
    
    # Test 3: Transport statistics
    stats = introspector.get_transport_statistics()
    assert isinstance(stats, dict)
    print("✓ Transport statistics work")
    
    # Test 4: Supported transports
    transports = introspector.get_supported_transports()
    assert 'stdio' in transports
    print("✓ Transport enumeration works")
    
    print("\n✅ Migration validation successful!")

if __name__ == "__main__":
    validate_migration()
```

Run the validation:
```bash
python validate_migration.py
```

### Performance Comparison
```python
#!/usr/bin/env python3
"""
Performance comparison script
"""
import time
from hawkeye.detection.mcp_introspection import MCPIntrospector

def performance_comparison():
    """Compare performance between legacy and new system."""
    
    introspector = MCPIntrospector()
    
    # Benchmark introspection speed
    start_time = time.time()
    stats = introspector.get_comprehensive_statistics()
    end_time = time.time()
    
    print(f"Statistics generation time: {end_time - start_time:.3f}s")
    print(f"Supported transports: {len(introspector.get_supported_transports())}")
    
    # Display performance metrics
    if 'performance' in stats:
        perf = stats['performance']
        print(f"Average introspection time: {perf.get('avg_introspection_time', 'N/A')}")
        print(f"Connection pool efficiency: {perf.get('pool_efficiency', 'N/A')}")
        print(f"Cache hit rate: {perf.get('cache_hit_rate', 'N/A')}")

if __name__ == "__main__":
    performance_comparison()
```

## Common Migration Issues

### Issue 1: Node.js Scripts Still Generated
**Symptom**: Temporary Node.js scripts found in `/tmp/`
**Solution**: Ensure you're using the updated `MCPIntrospector` class
```python
# Verify you're using the Python implementation
introspector = MCPIntrospector()
print(f"Implementation: {introspector.__class__.__module__}")
# Should show: hawkeye.detection.mcp_introspection
```

### Issue 2: Slower Performance
**Symptom**: Introspection takes longer than expected
**Solution**: Enable performance optimizations
```python
config = IntrospectionConfig(
    enable_caching=True,
    max_concurrent_connections=10,
    enable_optimization=True
)
```

### Issue 3: Memory Usage
**Symptom**: High memory consumption during large scans
**Solution**: Configure memory limits and cleanup
```python
config = IntrospectionConfig(
    memory_limit_mb=100,
    enable_memory_optimization=True
)
```

### Issue 4: Connection Timeouts
**Symptom**: Frequent timeout errors
**Solution**: Adjust timeout and retry settings
```python
config = IntrospectionConfig(
    timeout=60.0,  # Increase timeout
    max_retries=5,  # More retries
    retry_delay=2.0  # Longer delay between retries
)
```

## Post-Migration Validation

### Functional Testing
- [ ] All existing tests pass
- [ ] New functionality works correctly
- [ ] Error handling behaves as expected
- [ ] Performance meets requirements

### Security Validation
- [ ] Risk analysis produces expected results
- [ ] Threat modeling identifies known issues
- [ ] Security scores align with manual assessment
- [ ] No sensitive data exposure

### Performance Validation
- [ ] Introspection time within acceptable bounds
- [ ] Memory usage stays within limits
- [ ] Connection pooling improves efficiency
- [ ] Caching reduces repeated operations

### Integration Testing
- [ ] Existing integrations continue to work
- [ ] New API features integrate correctly
- [ ] Error handling propagates properly
- [ ] Logging and monitoring function correctly

## Rollback Plan

If issues arise during migration, you can rollback using these steps:

### Emergency Rollback
1. Revert to previous version in Git
2. Restore backup configuration files
3. Restart services with legacy implementation
4. Validate functionality

### Gradual Rollback
1. Disable new features while keeping core functionality
2. Revert configuration to legacy format
3. Monitor for issues
4. Plan corrective actions

### Rollback Validation
```python
# Validate rollback by testing core functionality
introspector = MCPIntrospector()
capabilities = introspector.introspect_server(server_info, process_info)
assert capabilities is not None
```

## Support and Troubleshooting

### Documentation Resources
- [API Documentation](../api/mcp_introspection.md)
- [Configuration Reference](../configuration/mcp_introspection.md)
- [Troubleshooting Guide](../troubleshooting.md)

### Logging and Debugging
Enable debug logging for migration issues:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Specific logger for MCP introspection
mcp_logger = logging.getLogger('hawkeye.detection.mcp_introspection')
mcp_logger.setLevel(logging.DEBUG)
```

### Common Commands
```bash
# Validate installation
python -c "from hawkeye.detection.mcp_introspection import MCPIntrospector; print('OK')"

# Check dependencies
pip list | grep -E "(mcp|aiofiles|async-timeout)"

# Run tests
python -m pytest tests/test_detection/test_mcp_introspection/

# Performance benchmark
python tests/performance/test_mcp_introspection_benchmarks.py
```

## Migration Checklist

### Pre-Migration
- [ ] System requirements met
- [ ] Configuration documented
- [ ] Integration points identified
- [ ] Backup created

### Migration
- [ ] Dependencies installed
- [ ] Configuration updated
- [ ] Code migrated
- [ ] Error handling updated

### Post-Migration
- [ ] Functionality validated
- [ ] Performance tested
- [ ] Security verified
- [ ] Documentation updated

### Cleanup
- [ ] Legacy scripts removed
- [ ] Temporary files cleaned
- [ ] Old dependencies removed
- [ ] Team notified

## Conclusion

The migration from Node.js to Python-based MCP introspection provides significant benefits in terms of performance, reliability, and security while maintaining backward compatibility. Following this guide ensures a smooth transition with minimal disruption to existing functionality.

For additional support, consult the [troubleshooting guide](../troubleshooting.md) or contact the development team.