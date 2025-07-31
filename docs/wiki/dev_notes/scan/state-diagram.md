# Scan Command State Diagram

## Overview

This document provides comprehensive state diagrams illustrating the HawkEye scan task lifecycle, from task creation to final completion or failure. The scanning system operates at multiple levels with different state machines managing different aspects of the scanning process.

## State Machine Hierarchy

The HawkEye scan system implements a hierarchical state machine structure:

1. **Task Execution States** - High-level task lifecycle in the ConnectionPool
2. **Port Scan States** - Individual port scanning results and states
3. **Connection States** - Low-level network connection states
4. **Pool Management States** - Connection pool operational states

## State Diagrams

### 1. Task Execution State Machine

```mermaid
stateDiagram-v2
    [*] --> Created : task = ScanTask()
    
    Created --> Pending : submit_scan(task)
    Pending --> Queued : executor.submit()
    
    Queued --> Active : worker_thread_available
    Active --> Executing : _execute_scan_task()
    
    Executing --> ScannerCall : task.scanner_func()
    ScannerCall --> NetworkCall : scan_port()
    NetworkCall --> SocketOperation : socket.connect() / socket.sendto()
    
    SocketOperation --> Completed : success / response_received
    SocketOperation --> Timeout : socket.timeout
    SocketOperation --> NetworkError : socket.error
    SocketOperation --> DNSError : socket.gaierror
    
    Timeout --> CompletedFiltered : create_timeout_result()
    NetworkError --> CompletedUnknown : create_error_result()
    DNSError --> CompletedUnknown : create_dns_error_result()
    
    Completed --> ResultProcessing : _task_completed()
    CompletedFiltered --> ResultProcessing
    CompletedUnknown --> ResultProcessing
    
    ResultProcessing --> Success : result.success = True
    ResultProcessing --> Failed : exception_occurred
    
    Success --> [*] : stats.completed_tasks++
    Failed --> [*] : stats.failed_tasks++
    
    %% Cancellation path
    Pending --> Cancelled : future.cancel()
    Queued --> Cancelled : future.cancel()
    Active --> Cancelled : future.cancel()
    
    Cancelled --> [*] : task_cancelled
    
    %% Error handling
    Executing --> ExecutionError : exception_in_scanner
    ExecutionError --> Failed : create_error_result()
    
    note right of Created
        task_id generated
        scanner_func assigned
        target and port set
    end note
    
    note right of Active
        worker thread assigned
        task removed from queue
        execution started
    end note
    
    note right of NetworkCall
        Protocol-specific logic:
        TCP: connect_ex()
        UDP: sendto() + recvfrom()
    end note
    
    note right of ResultProcessing
        Update statistics
        Store result
        Trigger callbacks
        Clean up resources
    end note
```

### 2. Port Scan Result State Machine

```mermaid
stateDiagram-v2
    [*] --> Scanning : scan_port(target, port)
    
    Scanning --> TCPScan : ScanType.TCP_CONNECT
    Scanning --> UDPScan : ScanType.UDP
    
    %% TCP Scanning States
    TCPScan --> TCPSocket : _create_socket()
    TCPSocket --> TCPConnect : connect_ex(host, port)
    
    TCPConnect --> TCPOpen : result == 0
    TCPConnect --> TCPClosed : result != 0
    TCPConnect --> TCPTimeout : socket.timeout
    TCPConnect --> TCPError : socket.error
    
    TCPOpen --> [*] : PortState.OPEN
    TCPClosed --> [*] : PortState.CLOSED
    TCPTimeout --> [*] : PortState.FILTERED
    TCPError --> TCPDNSError : socket.gaierror
    TCPError --> TCPNetError : other_socket_error
    
    TCPDNSError --> [*] : PortState.UNKNOWN + dns_error
    TCPNetError --> [*] : PortState.UNKNOWN + network_error
    
    %% UDP Scanning States
    UDPScan --> UDPSocket : _create_udp_socket()
    UDPSocket --> UDPProbe : sendto(probe_data)
    
    UDPProbe --> UDPWaitResponse : recvfrom(timeout)
    
    UDPWaitResponse --> UDPResponse : response_received
    UDPWaitResponse --> UDPTimeout : socket.timeout
    UDPWaitResponse --> UDPICMPError : icmp_port_unreachable
    UDPWaitResponse --> UDPNetError : socket.error
    
    UDPResponse --> [*] : PortState.OPEN + response_data
    UDPTimeout --> [*] : PortState.FILTERED + no_response
    UDPICMPError --> [*] : PortState.CLOSED + icmp_unreachable
    UDPNetError --> [*] : PortState.UNKNOWN + error_message
    
    note right of TCPConnect
        Connection attempt with timeout
        errno codes determine state:
        0 = success (OPEN)
        111 = connection refused (CLOSED)
        110 = timeout (FILTERED)
    end note
    
    note right of UDPWaitResponse
        UDP is connectionless:
        Response = OPEN
        Timeout = FILTERED (could be open)
        ICMP unreachable = CLOSED
        Other errors = UNKNOWN
    end note
```

### 3. Connection Pool State Machine

```mermaid
stateDiagram-v2
    [*] --> Initialized : ConnectionPool()
    
    Initialized --> Starting : start()
    Starting --> Active : ThreadPoolExecutor created
    
    Active --> AcceptingTasks : ready_for_tasks
    AcceptingTasks --> ProcessingTasks : tasks_submitted
    
    ProcessingTasks --> AcceptingTasks : waiting_for_more_tasks
    ProcessingTasks --> WaitingCompletion : all_tasks_submitted
    
    WaitingCompletion --> AllCompleted : all_futures_done
    WaitingCompletion --> SomeTimeout : timeout_exceeded
    
    %% Shutdown states
    AcceptingTasks --> Shutting : shutdown()
    ProcessingTasks --> Shutting : shutdown()
    WaitingCompletion --> Shutting : shutdown()
    
    Shutting --> CancellingTasks : cancel_all_tasks()
    CancellingTasks --> ExecutorShutdown : executor.shutdown()
    ExecutorShutdown --> Stopped : cleanup_complete
    
    AllCompleted --> [*] : normal_completion
    SomeTimeout --> [*] : timeout_completion
    Stopped --> [*] : forced_shutdown
    
    %% Error handling
    Active --> Error : initialization_failed
    AcceptingTasks --> Error : submit_error
    ProcessingTasks --> Error : executor_error
    
    Error --> [*] : error_handled
    
    note right of ProcessingTasks
        Statistics tracking:
        - total_tasks
        - active_tasks
        - completed_tasks
        - failed_tasks
    end note
    
    note right of CancellingTasks
        Cancel pending futures
        Wait for active tasks
        Clean up resources
    end note
```

### 4. Individual Task State Transitions

```mermaid
stateDiagram-v2
    [*] --> TaskCreated : ScanTask(target, port, scanner_func)
    
    TaskCreated --> TaskSubmitted : pool.submit_scan(task)
    TaskSubmitted --> TaskQueued : future = executor.submit()
    
    TaskQueued --> TaskExecuting : worker_available
    TaskExecuting --> ScanStarted : _execute_scan_task()
    
    ScanStarted --> ScannerInvocation : task.scanner_func(target, port)
    
    %% Scanner execution paths
    ScannerInvocation --> TCPScanning : TCPScanner.scan_port()
    ScannerInvocation --> UDPScanning : UDPScanner.scan_port()
    
    %% TCP path
    TCPScanning --> TCPSocketCreated : _create_socket()
    TCPSocketCreated --> TCPConnecting : socket.connect_ex()
    
    TCPConnecting --> TCPConnected : success
    TCPConnecting --> TCPRefused : connection_refused
    TCPConnecting --> TCPTimedOut : socket.timeout
    TCPConnecting --> TCPFailed : socket.error
    
    %% UDP path
    UDPScanning --> UDPSocketCreated : _create_udp_socket()
    UDPSocketCreated --> UDPSending : socket.sendto()
    UDPSending --> UDPReceiving : socket.recvfrom()
    
    UDPReceiving --> UDPReceived : response_data
    UDPReceiving --> UDPNoResponse : socket.timeout
    UDPReceiving --> UDPUnreachable : icmp_error
    UDPReceiving --> UDPError : socket.error
    
    %% Result creation
    TCPConnected --> ResultCreated : ScanResult(OPEN)
    TCPRefused --> ResultCreated : ScanResult(CLOSED)
    TCPTimedOut --> ResultCreated : ScanResult(FILTERED)
    TCPFailed --> ResultCreated : ScanResult(UNKNOWN)
    
    UDPReceived --> ResultCreated : ScanResult(OPEN)
    UDPNoResponse --> ResultCreated : ScanResult(FILTERED)
    UDPUnreachable --> ResultCreated : ScanResult(CLOSED)
    UDPError --> ResultCreated : ScanResult(UNKNOWN)
    
    %% Task completion
    ResultCreated --> TaskCompleted : return_result
    TaskCompleted --> CallbackInvoked : _task_completed()
    CallbackInvoked --> StatsUpdated : update_statistics()
    StatsUpdated --> TaskFinished : cleanup_resources()
    
    TaskFinished --> [*] : task_done
    
    %% Exception handling
    ScannerInvocation --> ScannerException : exception_thrown
    ScannerException --> ErrorResult : ScanResult(UNKNOWN, error)
    ErrorResult --> TaskFailed : log_error()
    TaskFailed --> [*] : task_failed
    
    %% Cancellation
    TaskQueued --> TaskCancelled : future.cancel()
    TaskExecuting --> TaskCancelled : future.cancel()
    TaskCancelled --> [*] : task_cancelled
    
    note right of TaskQueued
        Future object created
        Task added to executor queue
        Waiting for worker thread
    end note
    
    note right of CallbackInvoked
        Update active_tasks count
        Store result or error
        Update completion statistics
    end note
```

### 5. Error Handling State Machine

```mermaid
stateDiagram-v2
    [*] --> NormalOperation : task_executing
    
    NormalOperation --> NetworkTimeout : socket.timeout
    NormalOperation --> NetworkError : socket.error
    NormalOperation --> DNSError : socket.gaierror
    NormalOperation --> ScannerError : scanner_exception
    NormalOperation --> UnknownError : unexpected_exception
    
    %% Network timeout handling
    NetworkTimeout --> TimeoutLogged : log_timeout()
    TimeoutLogged --> FilteredResult : create_filtered_result()
    FilteredResult --> GracefulCompletion : return_result()
    
    %% Network error handling
    NetworkError --> ErrorAnalysis : analyze_error()
    ErrorAnalysis --> ConnectionRefused : errno_111
    ErrorAnalysis --> HostUnreachable : errno_113
    ErrorAnalysis --> NetworkUnreachable : errno_101
    ErrorAnalysis --> GenericNetworkError : other_errno
    
    ConnectionRefused --> ClosedResult : create_closed_result()
    HostUnreachable --> UnknownResult : create_unknown_result()
    NetworkUnreachable --> UnknownResult
    GenericNetworkError --> UnknownResult
    
    %% DNS error handling
    DNSError --> DNSLogged : log_dns_error()
    DNSLogged --> UnknownResult : create_dns_error_result()
    
    %% Scanner error handling
    ScannerError --> ErrorLogged : log_scanner_error()
    ErrorLogged --> UnknownResult : create_error_result()
    
    %% Unknown error handling
    UnknownError --> CriticalLogged : log_critical_error()
    CriticalLogged --> UnknownResult : create_fallback_result()
    
    %% Result completion
    ClosedResult --> [*] : task_completed
    UnknownResult --> [*] : task_completed
    GracefulCompletion --> [*] : task_completed
    
    note right of ErrorAnalysis
        Map errno codes to states:
        111 = Connection refused
        113 = Host unreachable  
        101 = Network unreachable
        110 = Timeout
    end note
    
    note right of UnknownResult
        All error paths lead to
        PortState.UNKNOWN result
        with error details preserved
    end note
```

### 6. Progress Tracking State Machine

```mermaid
stateDiagram-v2
    [*] --> ProgressInitialized : Progress()
    
    ProgressInitialized --> TasksCalculated : calculate_total_operations()
    TasksCalculated --> ProgressStarted : progress.start()
    
    ProgressStarted --> TrackingTasks : add_task()
    TrackingTasks --> UpdatingProgress : advance(1)
    
    UpdatingProgress --> TrackingTasks : more_tasks_pending
    UpdatingProgress --> AllTasksTracked : all_tasks_submitted
    
    AllTasksTracked --> ProgressCompleted : all_tasks_done
    ProgressCompleted --> [*] : progress.stop()
    
    %% Error states
    TrackingTasks --> ProgressError : tracking_error
    UpdatingProgress --> ProgressError : update_error
    
    ProgressError --> ProgressAborted : handle_error()
    ProgressAborted --> [*] : error_handled
    
    %% Interruption
    TrackingTasks --> ProgressInterrupted : user_interrupt
    UpdatingProgress --> ProgressInterrupted : KeyboardInterrupt
    
    ProgressInterrupted --> ProgressAborted : cleanup_progress()
    
    note right of UpdatingProgress
        Rich progress bar updates:
        - Current task description
        - Completed/Total tasks
        - Estimated time remaining
        - Current target information
    end note
```

## State Transition Triggers

### 1. Task Submission Triggers
- **Task Creation**: `ScanTask(target, port, scanner_func)`
- **Task Submission**: `pool.submit_scan(task)`
- **Worker Assignment**: Thread pool executor assigns available worker
- **Task Execution**: Worker thread calls `_execute_scan_task()`

### 2. Network Operation Triggers
- **Connection Success**: `socket.connect_ex()` returns 0
- **Connection Refused**: `socket.connect_ex()` returns errno 111
- **Connection Timeout**: `socket.timeout` exception raised
- **DNS Resolution Failure**: `socket.gaierror` exception raised
- **Network Error**: `socket.error` exception raised

### 3. UDP Specific Triggers
- **UDP Response**: `socket.recvfrom()` returns data
- **UDP Timeout**: `socket.timeout` on `recvfrom()`
- **ICMP Unreachable**: Socket error with "port unreachable" message
- **UDP Network Error**: Other socket errors during UDP operations

### 4. Completion Triggers
- **Result Creation**: Scanner returns `ScanResult` object
- **Task Completion**: `_task_completed()` callback invoked
- **Statistics Update**: Completion counters incremented
- **Resource Cleanup**: Socket closed, memory freed

### 5. Error Recovery Triggers
- **Timeout Recovery**: Create `FILTERED` result, continue processing
- **Network Error Recovery**: Create `UNKNOWN` result, log error
- **Exception Recovery**: Create error result, don't crash scanner
- **Graceful Degradation**: Continue with other tasks despite failures

## State Persistence and Recovery

### 1. Task State Tracking
```python
# Connection pool maintains task state
active_tasks: Dict[str, Future] = {}
completed_tasks: List[ScanResult] = []
failed_tasks: List[tuple] = []

# Statistics tracking
stats = {
    'total_tasks': 0,
    'completed_tasks': 0,
    'failed_tasks': 0,
    'active_tasks': 0,
}
```

### 2. Result State Management
```python
# Scan results maintain state information
@dataclass
class ScanResult:
    target: ScanTarget
    port: int
    state: PortState  # OPEN, CLOSED, FILTERED, UNKNOWN
    scan_type: ScanType
    response_time: Optional[float]
    error: Optional[str]
    raw_data: Dict[str, Any]
```

### 3. Error State Preservation
```python
# Error information preserved in results
error_states = {
    'timeout': PortState.FILTERED,
    'connection_refused': PortState.CLOSED,
    'dns_error': PortState.UNKNOWN,
    'network_error': PortState.UNKNOWN,
    'unknown_error': PortState.UNKNOWN,
}
```

## Performance Characteristics by State

### 1. State Transition Times
- **Task Creation → Submission**: < 1ms
- **Submission → Execution**: Depends on thread pool queue (0-100ms)
- **Execution → Network Call**: < 1ms
- **Network Call → Result**: Depends on network (1ms - 30s timeout)
- **Result → Completion**: < 1ms

### 2. Resource Usage by State
- **Pending/Queued**: Minimal memory (task object only)
- **Active/Executing**: Thread + socket resources
- **Network Operations**: Socket + network buffers
- **Completed**: Result object + statistics update

### 3. Concurrency Considerations
- **Multiple Tasks**: Up to `max_threads` tasks in Active state simultaneously
- **Thread Safety**: State transitions synchronized with locks
- **Resource Limits**: Thread pool and socket limits prevent resource exhaustion

## Error Recovery Strategies

### 1. Timeout Handling
- **Short Timeouts**: Mark as FILTERED, continue scanning
- **DNS Timeouts**: Mark as UNKNOWN, log DNS issues
- **Long Delays**: Progress indication, allow user interruption

### 2. Network Error Recovery
- **Transient Errors**: Retry with exponential backoff (future enhancement)
- **Permanent Errors**: Mark as appropriate state, continue with other targets
- **Critical Errors**: Log error, graceful degradation

### 3. Resource Exhaustion
- **Thread Pool Full**: Queue tasks, block if necessary
- **Memory Limits**: Process results in batches, clean up completed tasks
- **Socket Limits**: Reuse sockets where possible, proper cleanup

## State Machine Integration

### 1. Hierarchical State Management
The scan system uses multiple coordinated state machines:
- **Pool-level states** manage overall scanning lifecycle
- **Task-level states** track individual scan operations
- **Result-level states** represent final port states
- **Progress-level states** manage user interface updates

### 2. State Synchronization
State transitions are synchronized across levels:
- Task completion updates pool statistics
- Result creation triggers progress updates
- Error states propagate up the hierarchy
- Cancellation cascades down to active tasks

### 3. State Persistence
Critical state information is preserved:
- Task results stored for later retrieval
- Error information maintained for debugging
- Statistics tracked for performance analysis
- Progress state maintained for user experience

## Conclusion

The HawkEye scan command implements a sophisticated multi-level state machine that efficiently handles the complex lifecycle of network scanning operations. The state diagrams above illustrate how tasks flow through the system from creation to completion, with comprehensive error handling and recovery mechanisms.

Key architectural benefits:
- **Robust Error Handling**: All error conditions mapped to appropriate states
- **Resource Management**: Proper state transitions ensure resource cleanup
- **Concurrent Execution**: State synchronization enables safe parallel processing
- **Progress Tracking**: State changes drive user interface updates
- **Extensibility**: Well-defined states support future enhancements

The state machine design ensures reliable scanning operations while providing clear visibility into the scanning process and robust handling of network conditions and errors. 