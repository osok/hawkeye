# Detection Pipeline State Diagram

## Overview

This document provides comprehensive state diagrams for the detection pipeline execution, showing states, transitions, error handling, retry logic, and fallback mechanisms. The detection system operates with multiple layers of state management for robustness and reliability.

## Main Pipeline State Machine

The following Mermaid state diagram illustrates the high-level pipeline execution states and transitions:

```mermaid
stateDiagram-v2
    [*] --> INITIALIZED: create_detection_pipeline()
    
    INITIALIZED --> EXECUTING_TRADITIONAL: execute_pipeline()
    INITIALIZED --> ERROR: initialization_failure
    
    EXECUTING_TRADITIONAL --> EXECUTING_INTROSPECTION: phase1_complete
    EXECUTING_TRADITIONAL --> ANALYZING_RESULTS: phase1_complete && introspection_disabled
    EXECUTING_TRADITIONAL --> ERROR: critical_error && fail_fast_enabled
    EXECUTING_TRADITIONAL --> EXECUTING_TRADITIONAL: detector_error && continue_on_error
    
    EXECUTING_INTROSPECTION --> ANALYZING_RESULTS: phase2_complete
    EXECUTING_INTROSPECTION --> ERROR: critical_error && fail_fast_enabled
    EXECUTING_INTROSPECTION --> EXECUTING_INTROSPECTION: server_error && continue_on_error
    
    ANALYZING_RESULTS --> PERFORMING_RISK_ASSESSMENT: risk_assessment_enabled
    ANALYZING_RESULTS --> COMPLETED_SUCCESS: analysis_complete && no_errors
    ANALYZING_RESULTS --> COMPLETED_FAILURE: analysis_complete && has_errors
    
    PERFORMING_RISK_ASSESSMENT --> COMPLETED_SUCCESS: assessment_complete && no_errors
    PERFORMING_RISK_ASSESSMENT --> COMPLETED_FAILURE: assessment_complete && has_errors
    PERFORMING_RISK_ASSESSMENT --> ERROR: assessment_critical_error
    
    ERROR --> COMPLETED_FAILURE: create_error_result
    COMPLETED_SUCCESS --> [*]
    COMPLETED_FAILURE --> [*]
    
    state EXECUTING_TRADITIONAL {
        [*] --> PROCESS_ENUMERATION
        PROCESS_ENUMERATION --> CONFIG_DISCOVERY: enumeration_complete
        CONFIG_DISCOVERY --> PROTOCOL_VERIFICATION: discovery_complete
        PROTOCOL_VERIFICATION --> TRANSPORT_DETECTION: verification_complete
        TRANSPORT_DETECTION --> NPX_DETECTION: transport_complete
        NPX_DETECTION --> DOCKER_INSPECTION: npx_complete
        DOCKER_INSPECTION --> ENVIRONMENT_ANALYSIS: docker_complete
        ENVIRONMENT_ANALYSIS --> [*]: analysis_complete
        
        PROCESS_ENUMERATION --> CONFIG_DISCOVERY: enumeration_failed && continue
        CONFIG_DISCOVERY --> PROTOCOL_VERIFICATION: discovery_failed && continue
        PROTOCOL_VERIFICATION --> TRANSPORT_DETECTION: verification_failed && continue
        TRANSPORT_DETECTION --> NPX_DETECTION: transport_failed && continue
        NPX_DETECTION --> DOCKER_INSPECTION: npx_failed && continue
        DOCKER_INSPECTION --> ENVIRONMENT_ANALYSIS: docker_failed && continue
    }
    
    state EXECUTING_INTROSPECTION {
        [*] --> EXTRACTING_SERVERS: start_introspection
        EXTRACTING_SERVERS --> INTROSPECTING_SERVERS: servers_found
        EXTRACTING_SERVERS --> [*]: no_servers_found
        
        INTROSPECTING_SERVERS --> [*]: all_servers_processed
        
        state INTROSPECTING_SERVERS {
            [*] --> SERVER_CONNECTION
            SERVER_CONNECTION --> CAPABILITY_EXCHANGE: connection_established
            SERVER_CONNECTION --> FALLBACK: connection_failed
            
            CAPABILITY_EXCHANGE --> TOOL_DISCOVERY: handshake_complete
            CAPABILITY_EXCHANGE --> FALLBACK: handshake_failed
            
            TOOL_DISCOVERY --> RESOURCE_DISCOVERY: tools_discovered
            TOOL_DISCOVERY --> RESOURCE_DISCOVERY: tools_failed && continue
            
            RESOURCE_DISCOVERY --> CAPABILITY_ASSESSMENT: resources_discovered
            RESOURCE_DISCOVERY --> CAPABILITY_ASSESSMENT: resources_failed && continue
            
            CAPABILITY_ASSESSMENT --> RISK_ASSESSMENT: capabilities_assessed
            CAPABILITY_ASSESSMENT --> AGGREGATION: capabilities_failed && continue
            
            RISK_ASSESSMENT --> AGGREGATION: risk_assessed
            RISK_ASSESSMENT --> AGGREGATION: risk_failed && continue
            
            AGGREGATION --> [*]: server_complete
            
            FALLBACK --> [*]: fallback_complete
        }
    }
```

## Individual Detector State Machine

Each detection method (Process Enumeration, Config Discovery, etc.) follows this state pattern:

```mermaid
stateDiagram-v2
    [*] --> PENDING: detector_created
    
    PENDING --> ACTIVE: start_detection()
    PENDING --> SKIPPED: disabled_in_config
    
    ACTIVE --> COMPLETED: detection_successful
    ACTIVE --> FAILED: detection_error && no_retry
    ACTIVE --> RETRYING: detection_error && retry_enabled
    ACTIVE --> TIMEOUT: timeout_exceeded
    
    RETRYING --> ACTIVE: retry_attempt
    RETRYING --> FAILED: max_retries_exceeded
    RETRYING --> TIMEOUT: retry_timeout
    
    TIMEOUT --> FAILED: timeout_final
    TIMEOUT --> RETRYING: timeout_retry_enabled
    
    COMPLETED --> [*]
    FAILED --> [*]
    SKIPPED --> [*]
    
    state ACTIVE {
        [*] --> CONNECTING: network_detector
        [*] --> SCANNING: local_detector
        
        CONNECTING --> HANDSHAKING: connection_established
        CONNECTING --> FAILED: connection_failed
        
        HANDSHAKING --> VERIFYING: handshake_complete
        HANDSHAKING --> FAILED: handshake_failed
        
        VERIFYING --> ANALYZING: verification_complete
        VERIFYING --> FAILED: verification_failed
        
        SCANNING --> PARSING: scan_complete
        SCANNING --> FAILED: scan_failed
        
        PARSING --> ANALYZING: parse_complete
        PARSING --> FAILED: parse_failed
        
        ANALYZING --> [*]: analysis_complete
        ANALYZING --> FAILED: analysis_failed
    }
```

## MCP Introspection Detailed State Machine

The MCP introspection process has complex state management with fallback strategies:

```mermaid
stateDiagram-v2
    [*] --> TRANSPORT_CREATION: start_introspection
    
    TRANSPORT_CREATION --> CLIENT_CONNECTION: transport_created
    TRANSPORT_CREATION --> TRANSPORT_FALLBACK: transport_failed
    
    CLIENT_CONNECTION --> MCP_HANDSHAKE: client_connected
    CLIENT_CONNECTION --> CONNECTION_FALLBACK: connection_failed
    
    MCP_HANDSHAKE --> CAPABILITY_EXCHANGE: handshake_successful
    MCP_HANDSHAKE --> HANDSHAKE_FALLBACK: handshake_failed
    
    CAPABILITY_EXCHANGE --> DISCOVERY_PHASE: capabilities_exchanged
    CAPABILITY_EXCHANGE --> CAPABILITY_FALLBACK: capability_failed
    
    DISCOVERY_PHASE --> ASSESSMENT_PHASE: discovery_complete
    DISCOVERY_PHASE --> DISCOVERY_FALLBACK: discovery_failed
    
    ASSESSMENT_PHASE --> AGGREGATION: assessment_complete
    ASSESSMENT_PHASE --> ASSESSMENT_FALLBACK: assessment_failed
    
    AGGREGATION --> COMPLETED: aggregation_successful
    AGGREGATION --> COMPLETED: aggregation_failed && fallback_complete
    
    %% Fallback States
    TRANSPORT_FALLBACK --> BASIC_INFO_STRATEGY: try_basic_info
    TRANSPORT_FALLBACK --> MINIMAL_SAFE_STRATEGY: basic_info_failed
    TRANSPORT_FALLBACK --> SKIP_STRATEGY: all_fallbacks_failed
    
    CONNECTION_FALLBACK --> CACHED_RESULT_STRATEGY: try_cache
    CONNECTION_FALLBACK --> HEURISTIC_ANALYSIS: cache_failed
    CONNECTION_FALLBACK --> DEGRADED_SCAN: heuristic_failed
    
    HANDSHAKE_FALLBACK --> RETRY_WITH_TIMEOUT: try_retry
    HANDSHAKE_FALLBACK --> HEURISTIC_ANALYSIS: retry_failed
    
    CAPABILITY_FALLBACK --> HEURISTIC_ANALYSIS: try_heuristic
    CAPABILITY_FALLBACK --> BASIC_INFO_STRATEGY: heuristic_failed
    
    DISCOVERY_FALLBACK --> CACHED_RESULT_STRATEGY: try_cache
    DISCOVERY_FALLBACK --> MINIMAL_SAFE_STRATEGY: cache_failed
    
    ASSESSMENT_FALLBACK --> BASIC_INFO_STRATEGY: try_basic_info
    ASSESSMENT_FALLBACK --> SKIP_STRATEGY: basic_info_failed
    
    %% Fallback Strategy States
    BASIC_INFO_STRATEGY --> COMPLETED: basic_info_success
    BASIC_INFO_STRATEGY --> MINIMAL_SAFE_STRATEGY: basic_info_failed
    
    CACHED_RESULT_STRATEGY --> COMPLETED: cache_hit
    CACHED_RESULT_STRATEGY --> HEURISTIC_ANALYSIS: cache_miss
    
    HEURISTIC_ANALYSIS --> COMPLETED: heuristic_success
    HEURISTIC_ANALYSIS --> BASIC_INFO_STRATEGY: heuristic_failed
    
    MINIMAL_SAFE_STRATEGY --> COMPLETED: minimal_success
    MINIMAL_SAFE_STRATEGY --> SKIP_STRATEGY: minimal_failed
    
    RETRY_WITH_TIMEOUT --> CLIENT_CONNECTION: retry_success
    RETRY_WITH_TIMEOUT --> DEGRADED_SCAN: retry_failed
    
    DEGRADED_SCAN --> COMPLETED: degraded_success
    DEGRADED_SCAN --> SKIP_STRATEGY: degraded_failed
    
    SKIP_STRATEGY --> COMPLETED: skip_complete
    
    COMPLETED --> [*]
    
    state DISCOVERY_PHASE {
        [*] --> TOOL_DISCOVERY
        TOOL_DISCOVERY --> RESOURCE_DISCOVERY: tools_complete
        TOOL_DISCOVERY --> RESOURCE_DISCOVERY: tools_failed && continue
        
        RESOURCE_DISCOVERY --> CAPABILITY_DETECTION: resources_complete
        RESOURCE_DISCOVERY --> CAPABILITY_DETECTION: resources_failed && continue
        
        CAPABILITY_DETECTION --> [*]: capabilities_complete
        CAPABILITY_DETECTION --> [*]: capabilities_failed
        
        state TOOL_DISCOVERY {
            [*] --> SENDING_TOOLS_LIST
            SENDING_TOOLS_LIST --> PARSING_TOOL_SCHEMAS: tools_received
            SENDING_TOOLS_LIST --> TOOL_TIMEOUT: request_timeout
            SENDING_TOOLS_LIST --> TOOL_ERROR: request_failed
            
            PARSING_TOOL_SCHEMAS --> ASSESSING_TOOL_RISKS: schemas_parsed
            PARSING_TOOL_SCHEMAS --> TOOL_ERROR: parse_failed
            
            ASSESSING_TOOL_RISKS --> [*]: assessment_complete
            ASSESSING_TOOL_RISKS --> [*]: assessment_failed
            
            TOOL_TIMEOUT --> TOOL_ERROR: timeout_final
            TOOL_ERROR --> [*]: error_handled
        }
        
        state RESOURCE_DISCOVERY {
            [*] --> SENDING_RESOURCES_LIST
            SENDING_RESOURCES_LIST --> ANALYZING_RESOURCES: resources_received
            SENDING_RESOURCES_LIST --> RESOURCE_TIMEOUT: request_timeout
            SENDING_RESOURCES_LIST --> RESOURCE_ERROR: request_failed
            
            ANALYZING_RESOURCES --> EVALUATING_ACCESS: analysis_complete
            ANALYZING_RESOURCES --> RESOURCE_ERROR: analysis_failed
            
            EVALUATING_ACCESS --> [*]: evaluation_complete
            EVALUATING_ACCESS --> [*]: evaluation_failed
            
            RESOURCE_TIMEOUT --> RESOURCE_ERROR: timeout_final
            RESOURCE_ERROR --> [*]: error_handled
        }
    }
```

## Error Handling and Recovery States

The system implements comprehensive error handling with multiple recovery strategies:

```mermaid
stateDiagram-v2
    [*] --> NORMAL_OPERATION: start_detection
    
    NORMAL_OPERATION --> TRANSIENT_ERROR: temporary_failure
    NORMAL_OPERATION --> PERMANENT_ERROR: critical_failure
    NORMAL_OPERATION --> TIMEOUT_ERROR: operation_timeout
    NORMAL_OPERATION --> CONFIGURATION_ERROR: config_invalid
    
    TRANSIENT_ERROR --> RETRY_BACKOFF: retry_enabled
    TRANSIENT_ERROR --> FALLBACK_STRATEGY: retry_disabled
    TRANSIENT_ERROR --> ERROR_LOGGED: max_retries_exceeded
    
    RETRY_BACKOFF --> NORMAL_OPERATION: retry_successful
    RETRY_BACKOFF --> TRANSIENT_ERROR: retry_failed
    RETRY_BACKOFF --> TIMEOUT_ERROR: retry_timeout
    
    TIMEOUT_ERROR --> TIMEOUT_RETRY: timeout_retry_enabled
    TIMEOUT_ERROR --> FALLBACK_STRATEGY: timeout_final
    
    TIMEOUT_RETRY --> NORMAL_OPERATION: timeout_retry_success
    TIMEOUT_RETRY --> PERMANENT_ERROR: timeout_retry_failed
    
    PERMANENT_ERROR --> FALLBACK_STRATEGY: fallback_available
    PERMANENT_ERROR --> ERROR_LOGGED: no_fallback
    
    CONFIGURATION_ERROR --> CONFIG_VALIDATION: auto_fix_enabled
    CONFIGURATION_ERROR --> ERROR_LOGGED: no_auto_fix
    
    CONFIG_VALIDATION --> NORMAL_OPERATION: validation_success
    CONFIG_VALIDATION --> ERROR_LOGGED: validation_failed
    
    FALLBACK_STRATEGY --> CACHED_RESULTS: cache_available
    FALLBACK_STRATEGY --> HEURISTIC_MODE: no_cache
    FALLBACK_STRATEGY --> MINIMAL_MODE: heuristic_failed
    
    CACHED_RESULTS --> NORMAL_OPERATION: cache_valid
    CACHED_RESULTS --> HEURISTIC_MODE: cache_stale
    
    HEURISTIC_MODE --> NORMAL_OPERATION: heuristic_success
    HEURISTIC_MODE --> MINIMAL_MODE: heuristic_failed
    
    MINIMAL_MODE --> GRACEFUL_DEGRADATION: minimal_success
    MINIMAL_MODE --> ERROR_LOGGED: minimal_failed
    
    GRACEFUL_DEGRADATION --> [*]: degraded_complete
    ERROR_LOGGED --> [*]: error_handled
    
    state RETRY_BACKOFF {
        [*] --> CALCULATING_DELAY
        CALCULATING_DELAY --> WAITING: delay_calculated
        WAITING --> [*]: delay_complete
        
        state CALCULATING_DELAY {
            [*] --> EXPONENTIAL_BACKOFF: default_strategy
            [*] --> LINEAR_BACKOFF: linear_strategy
            [*] --> FIXED_DELAY: fixed_strategy
            
            EXPONENTIAL_BACKOFF --> [*]: delay = base * (2 ^ attempt)
            LINEAR_BACKOFF --> [*]: delay = base * attempt
            FIXED_DELAY --> [*]: delay = constant
        }
    }
```

## Parallel vs Sequential Execution States

The pipeline supports both execution modes with different state management:

```mermaid
stateDiagram-v2
    [*] --> EXECUTION_MODE_SELECTION: start_pipeline
    
    EXECUTION_MODE_SELECTION --> SEQUENTIAL_EXECUTION: parallel_disabled
    EXECUTION_MODE_SELECTION --> PARALLEL_EXECUTION: parallel_enabled
    
    state SEQUENTIAL_EXECUTION {
        [*] --> DETECTOR_QUEUE
        DETECTOR_QUEUE --> EXECUTING_DETECTOR: next_detector
        DETECTOR_QUEUE --> [*]: queue_empty
        
        EXECUTING_DETECTOR --> DETECTOR_COMPLETE: execution_success
        EXECUTING_DETECTOR --> DETECTOR_FAILED: execution_failed
        
        DETECTOR_COMPLETE --> DETECTOR_QUEUE: continue_pipeline
        DETECTOR_COMPLETE --> [*]: fail_fast_success
        
        DETECTOR_FAILED --> DETECTOR_QUEUE: continue_on_error
        DETECTOR_FAILED --> [*]: fail_fast_error
    }
    
    state PARALLEL_EXECUTION {
        [*] --> WORKER_POOL_INIT
        WORKER_POOL_INIT --> TASK_DISTRIBUTION: pool_ready
        
        TASK_DISTRIBUTION --> MONITORING_WORKERS: tasks_distributed
        MONITORING_WORKERS --> COLLECTING_RESULTS: all_workers_complete
        MONITORING_WORKERS --> HANDLING_WORKER_ERROR: worker_error
        
        HANDLING_WORKER_ERROR --> MONITORING_WORKERS: error_handled
        HANDLING_WORKER_ERROR --> COLLECTING_RESULTS: critical_error
        
        COLLECTING_RESULTS --> [*]: results_collected
        
        state MONITORING_WORKERS {
            [*] --> WORKER_1_ACTIVE
            [*] --> WORKER_2_ACTIVE
            [*] --> WORKER_N_ACTIVE
            
            WORKER_1_ACTIVE --> WORKER_1_COMPLETE: task_success
            WORKER_1_ACTIVE --> WORKER_1_FAILED: task_failed
            
            WORKER_2_ACTIVE --> WORKER_2_COMPLETE: task_success
            WORKER_2_ACTIVE --> WORKER_2_FAILED: task_failed
            
            WORKER_N_ACTIVE --> WORKER_N_COMPLETE: task_success
            WORKER_N_ACTIVE --> WORKER_N_FAILED: task_failed
            
            WORKER_1_COMPLETE --> [*]
            WORKER_1_FAILED --> [*]
            WORKER_2_COMPLETE --> [*]
            WORKER_2_FAILED --> [*]
            WORKER_N_COMPLETE --> [*]
            WORKER_N_FAILED --> [*]
        }
    }
    
    SEQUENTIAL_EXECUTION --> [*]: execution_complete
    PARALLEL_EXECUTION --> [*]: execution_complete
```

## Key State Characteristics

### Pipeline States

- **INITIALIZED**: Pipeline configured and ready for execution
- **EXECUTING_TRADITIONAL**: Running Phase 1 detection methods sequentially
- **EXECUTING_INTROSPECTION**: Running Phase 2 MCP introspection per discovered server
- **ANALYZING_RESULTS**: Computing statistics, finding best results, collecting errors
- **PERFORMING_RISK_ASSESSMENT**: Evaluating security risks and generating recommendations
- **COMPLETED_SUCCESS**: Pipeline finished successfully with results
- **COMPLETED_FAILURE**: Pipeline finished with errors but handled gracefully
- **ERROR**: Unrecoverable error requiring immediate termination

### Error Recovery Mechanisms

1. **Retry Logic**: Configurable retry attempts with exponential backoff
2. **Fallback Strategies**: Multiple degradation levels for continued operation
3. **Timeout Handling**: Graceful timeout management with retry options
4. **Fail-Fast vs Continue**: Configurable error propagation behavior
5. **Graceful Degradation**: Reduced functionality rather than complete failure

### Performance Considerations

- Sequential execution prevents resource conflicts but may be slower
- Parallel execution improves performance but requires careful coordination
- Timeout mechanisms prevent indefinite hanging
- Caching reduces redundant operations
- Connection pooling optimizes network resource usage

### State Persistence

- Pipeline statistics are maintained across executions
- Error states are logged for debugging and analysis
- Introspection results can be cached for performance
- Fallback usage is tracked for optimization 