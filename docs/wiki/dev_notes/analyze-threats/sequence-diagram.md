# AI Threat Analysis Sequence Diagram

## Overview

This document provides a comprehensive sequence diagram of the AI-powered threat analysis workflow, documenting how the `analyze-threats` command processes detection results through various stages including data ingestion, AI model invocation, result generation, parallel processing, and cost management.

## Main Sequence Diagram

```mermaid
sequenceDiagram
    participant User
    participant CLI as CLI Handler
    participant Loader as Data Loader
    participant Converter as Detection Converter
    participant Analyzer as AIThreatAnalyzer
    participant CapAnalyzer as MCPCapabilityAnalyzer
    participant Memory as MemoryOptimizer
    participant Cache as ThreatIntelligenceCache
    participant Provider as AI Provider
    participant Monitor as ResponseTimeMonitor
    participant Reporter as Report Generator

    %% Phase 1: Command Initialization and Data Loading
    User->>CLI: hawkeye analyze-threats -i results.json -o report.html
    CLI->>CLI: Parse command arguments
    CLI->>CLI: Validate input file exists
    CLI->>Loader: Load JSON detection results

    Note over Loader: Handle multiple JSON structures:<br/>- detection_results<br/>- direct list<br/>- results key

    Loader->>Converter: Convert raw JSON to DetectionResult objects
    Converter->>Converter: Extract MCP server information
    Converter-->>CLI: List[MCPServerInfo]

    %% Phase 2: Environment Setup and Analyzer Initialization
    CLI->>CLI: Create EnvironmentContext from detection data
    CLI->>Analyzer: Initialize AIThreatAnalyzer()
    
    Analyzer->>Memory: Initialize MemoryOptimizer
    Analyzer->>Cache: Initialize ThreatIntelligenceCache
    Analyzer->>Provider: Initialize AI Provider (OpenAI/Anthropic/Local)
    Analyzer->>Monitor: Initialize ResponseTimeMonitor
    Analyzer-->>CLI: Ready for analysis

    %% Phase 3: Batch Analysis Decision Point
    CLI->>CLI: Check parallel_processing flag
    
    alt Parallel Processing Enabled
        CLI->>Analyzer: analyze_multiple_threats(mcp_servers, env_context)
        
        Note over Analyzer: Batch processing with memory optimization<br/>and load balancing
        
        loop For each MCP server batch
            Analyzer->>Memory: Check memory pressure
            alt Memory pressure critical
                Memory->>Memory: Force cleanup
                Memory-->>Analyzer: Cleanup stats
            end
            
            Analyzer->>Analyzer: Process batch optimally
        end
        
    else Sequential Processing
        loop For each MCP server
            CLI->>Analyzer: analyze_threats(mcp_server, env_context)
        end
    end

    %% Phase 4: Individual Threat Analysis (Core Workflow)
    Note over Analyzer,Provider: Core Analysis Workflow (per server)
    
    Analyzer->>Memory: Start memory context
    Analyzer->>CapAnalyzer: analyze_tool(mcp_server)
    
    Note over CapAnalyzer: Tool Capability Analysis:<br/>- Extract function signatures<br/>- Categorize security impact<br/>- Assess privilege requirements<br/>- Map to attack techniques<br/>- Calculate exploitation difficulty

    CapAnalyzer-->>Analyzer: ToolCapabilities

    %% Phase 5: Caching and AI Analysis
    Analyzer->>Analyzer: Generate cache key
    Analyzer->>Cache: Check for cached analysis
    
    alt Cache hit
        Cache-->>Analyzer: Cached ThreatAnalysis
        Note over Analyzer: Skip AI analysis, return cached result
    else Cache miss
        Analyzer->>Analyzer: Build AI analysis request
        Analyzer->>Provider: Enhanced AI analysis request
        
        Note over Provider: AI Provider Processing:<br/>- Prompt engineering<br/>- Model invocation<br/>- Response parsing<br/>- Cost tracking

        Provider-->>Analyzer: AnalysisResponse with cost data
        
        Analyzer->>Analyzer: Post-process AI response
        Analyzer->>Cache: Store result in cache
    end

    %% Phase 6: Result Processing and Monitoring
    Analyzer->>Monitor: Record operation metrics
    Analyzer->>Memory: End memory context
    Analyzer-->>CLI: ThreatAnalysis result

    %% Phase 7: Report Generation
    CLI->>CLI: Process analysis results
    CLI->>Reporter: Generate output report (JSON/HTML/CSV/XML)
    
    Note over Reporter: Report Generation:<br/>- Format conversion<br/>- Template application<br/>- Visualization creation

    Reporter-->>User: Final threat analysis report

    %% Phase 8: Statistics and Cleanup
    CLI->>Analyzer: Get analysis statistics
    CLI->>Monitor: Get performance metrics
    CLI->>Memory: Get memory usage stats
    CLI-->>User: Display execution summary
```

## Detailed Component Interactions

### 1. Data Ingestion Flow

```mermaid
sequenceDiagram
    participant CLI
    participant Loader
    participant Converter
    participant Validator

    CLI->>Loader: Load detection results JSON
    Loader->>Loader: Read and parse JSON file
    
    alt JSON structure: detection_results
        Loader->>Converter: Convert detection_results array
    else JSON structure: direct list
        Loader->>Converter: Convert direct list
    else JSON structure: results key
        Loader->>Converter: Convert results array
    else Invalid structure
        Loader-->>CLI: Raise ClickException
    end

    Converter->>Validator: Validate DetectionResult objects
    loop For each detection result
        Validator->>Validator: Check required fields
        Validator->>Validator: Extract MCP server data
        Validator->>Validator: Build MCPServerInfo object
    end
    
    Validator-->>CLI: List[MCPServerInfo]
```

### 2. AI Provider Selection and Analysis

```mermaid
sequenceDiagram
    participant Analyzer
    participant ProviderFactory
    participant OpenAI as OpenAI Provider
    participant Anthropic as Anthropic Provider
    participant Local as Local LLM Provider
    participant CostManager

    Analyzer->>ProviderFactory: Initialize AI provider
    ProviderFactory->>ProviderFactory: Check configuration settings
    
    alt Provider: OpenAI
        ProviderFactory->>OpenAI: Initialize OpenAI provider
        OpenAI-->>ProviderFactory: Ready
    else Provider: Anthropic
        ProviderFactory->>Anthropic: Initialize Anthropic provider
        Anthropic-->>ProviderFactory: Ready
    else Provider: Local
        ProviderFactory->>Local: Initialize Local LLM provider
        Local-->>ProviderFactory: Ready
    end

    ProviderFactory-->>Analyzer: AI Provider instance

    Note over Analyzer: For each threat analysis request

    Analyzer->>CostManager: Check cost limits
    alt Cost limit exceeded
        CostManager-->>Analyzer: Cost limit error
    else Within limits
        Analyzer->>OpenAI: Send analysis request
        OpenAI->>OpenAI: Process with GPT model
        OpenAI->>CostManager: Report token usage and cost
        OpenAI-->>Analyzer: Analysis response
    end
```

### 3. Memory Optimization and Performance Monitoring

```mermaid
sequenceDiagram
    participant Analyzer
    participant Memory as MemoryOptimizer
    participant Monitor as ResponseTimeMonitor
    participant GC as Garbage Collector

    Analyzer->>Memory: Start memory context
    Memory->>Memory: Check current memory usage
    
    alt Memory pressure: critical
        Memory->>GC: Force garbage collection
        Memory->>Memory: Clear optimization caches
        Memory-->>Analyzer: Memory cleanup performed
    else Memory pressure: normal
        Memory-->>Analyzer: Memory context ready
    end

    Note over Analyzer: During analysis execution

    loop For each analysis operation
        Analyzer->>Monitor: Start operation timer
        Analyzer->>Analyzer: Perform analysis
        
        alt Operation time > alert_threshold
            Monitor->>Monitor: Log slow operation alert
        else Operation time > warning_threshold
            Monitor->>Monitor: Log performance warning
        end
        
        Monitor->>Monitor: Record operation metrics
        Analyzer->>Monitor: End operation timer
    end

    Analyzer->>Memory: End memory context
    Memory->>Memory: Cleanup context-specific resources
```

### 4. Parallel Processing Workflow

```mermaid
sequenceDiagram
    participant CLI
    participant Analyzer
    participant Optimizer as BatchOptimizationEngine
    participant Pool as ThreadPool
    participant Worker1 as Worker Thread 1
    participant Worker2 as Worker Thread 2
    participant WorkerN as Worker Thread N

    CLI->>Analyzer: analyze_multiple_threats(parallel=True)
    Analyzer->>Optimizer: Initialize batch optimization
    Optimizer->>Optimizer: Calculate optimal batch size
    Optimizer->>Pool: Create thread pool
    
    Analyzer->>Optimizer: Prioritize servers for processing
    
    loop For each batch
        Optimizer->>Pool: Submit batch for processing
        
        par Parallel execution
            Pool->>Worker1: Process servers 1-3
            Worker1->>Worker1: analyze_threats()
            Worker1-->>Pool: Results batch 1
        and
            Pool->>Worker2: Process servers 4-6
            Worker2->>Worker2: analyze_threats()
            Worker2-->>Pool: Results batch 2
        and
            Pool->>WorkerN: Process servers N-N+2
            WorkerN->>WorkerN: analyze_threats()
            WorkerN-->>Pool: Results batch N
        end
        
        Pool-->>Optimizer: Aggregated batch results
        Optimizer->>Optimizer: Update performance metrics
        Optimizer->>Optimizer: Adjust next batch size
    end
    
    Optimizer-->>Analyzer: All analysis results
    Analyzer-->>CLI: Consolidated results
```

## Key Performance Optimizations

### 1. Caching Strategy

- **Cache Key Generation**: Based on tool capabilities, environment context, and analysis type
- **TTL Management**: Configurable time-to-live for cached analyses
- **Memory Efficiency**: Automatic cache cleanup based on memory pressure

### 2. Memory Management

- **Context-based Cleanup**: Memory contexts for each analysis operation
- **Pressure Monitoring**: Real-time memory usage tracking
- **Automatic Optimization**: Forced cleanup when memory pressure is critical

### 3. Cost Management

- **Provider Selection**: Automatic fallback between AI providers
- **Usage Tracking**: Real-time cost monitoring and limits
- **Batch Optimization**: Intelligent batching to minimize API calls

### 4. Performance Monitoring

- **Response Time Tracking**: Detailed operation timing metrics
- **Slow Operation Detection**: Automatic alerts for performance issues
- **Statistical Analysis**: Performance trend analysis and optimization

## Error Handling and Fallback Mechanisms

```mermaid
sequenceDiagram
    participant Analyzer
    participant Primary as Primary AI Provider
    participant Fallback as Fallback Provider
    participant Cache
    participant ErrorHandler

    Analyzer->>Primary: Analysis request
    
    alt Primary provider success
        Primary-->>Analyzer: Analysis response
    else Primary provider failure
        Primary-->>ErrorHandler: Provider error
        ErrorHandler->>Fallback: Try fallback provider
        
        alt Fallback success
            Fallback-->>Analyzer: Analysis response
        else Fallback failure
            Fallback-->>ErrorHandler: Fallback error
            ErrorHandler->>Analyzer: Create minimal fallback analysis
        end
    end

    alt Analysis completely failed
        Analyzer->>Analyzer: Generate minimal threat analysis
        Note over Analyzer: Fallback analysis with:<br/>- MEDIUM threat level<br/>- Basic mitigation strategies<br/>- Low confidence score
    end
```

## Analysis Types and Processing Variations

### 1. Quick Assessment
- **Purpose**: Fast risk evaluation
- **Processing**: Simplified prompts, cached results prioritized
- **Output**: Threat level and confidence score only

### 2. Comprehensive Analysis
- **Purpose**: Full threat modeling with detailed attack vectors
- **Processing**: Complete AI analysis pipeline
- **Output**: Full ThreatAnalysis object with all fields

### 3. Context-Aware Analysis
- **Purpose**: Environment-specific threat assessment
- **Processing**: Enhanced environment context integration
- **Output**: Tailored analysis based on deployment context

## Integration Points

1. **CLI Integration**: Command parsing and output formatting
2. **Detection Pipeline**: Input from detect commands via JSON
3. **Reporting System**: Output to multiple report formats
4. **Configuration Management**: Settings and API key management
5. **Logging System**: Comprehensive operation logging

## Summary

The AI threat analysis sequence represents a sophisticated pipeline that:

- **Efficiently processes** detection results through multiple optimization layers
- **Intelligently manages** AI provider interactions and costs
- **Optimizes performance** through caching, memory management, and parallel processing
- **Ensures reliability** through comprehensive error handling and fallback mechanisms
- **Provides flexibility** through multiple analysis types and output formats

This architecture enables scalable, cost-effective, and reliable AI-powered threat analysis for MCP security assessment workflows. 