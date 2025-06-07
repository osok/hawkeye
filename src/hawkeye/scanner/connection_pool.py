"""
Connection pool management for network scanning operations.

This module provides thread pool management and connection handling
for concurrent network scanning operations.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from queue import Queue, Empty
from typing import List, Callable, Any, Optional, Dict
from dataclasses import dataclass

from .base import ScanResult, ScanTarget
from ..config.settings import get_settings
from ..utils.logging import get_logger


@dataclass
class ScanTask:
    """Represents a scanning task."""
    
    target: ScanTarget
    port: int
    scanner_func: Callable
    task_id: str = None
    
    def __post_init__(self):
        """Generate task ID if not provided."""
        if self.task_id is None:
            self.task_id = f"{self.target.host}:{self.port}"


class ConnectionPool:
    """Manages connection pooling and threading for network scans."""
    
    def __init__(self, settings=None):
        """Initialize connection pool."""
        self.settings = settings or get_settings()
        self.logger = get_logger(self.__class__.__name__)
        
        # Thread pool configuration
        self.max_workers = self.settings.scan.max_threads
        self.executor: Optional[ThreadPoolExecutor] = None
        
        # Task management
        self.active_tasks: Dict[str, Future] = {}
        self.completed_tasks: List[ScanResult] = []
        self.failed_tasks: List[tuple] = []
        
        # Statistics
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'active_tasks': 0,
            'start_time': None,
            'end_time': None,
        }
        
        # Thread safety
        self._lock = threading.Lock()
        self._shutdown = False
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
    
    def start(self) -> None:
        """Start the connection pool."""
        if self.executor is not None:
            self.logger.warning("Connection pool already started")
            return
        
        self.logger.info(f"Starting connection pool with {self.max_workers} workers")
        self.executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="HawkEye-Scanner"
        )
        self.stats['start_time'] = time.time()
        self._shutdown = False
    
    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the connection pool."""
        if self.executor is None:
            return
        
        self.logger.info("Shutting down connection pool")
        self._shutdown = True
        
        # Cancel pending tasks
        with self._lock:
            for task_id, future in self.active_tasks.items():
                if not future.done():
                    future.cancel()
                    self.logger.debug(f"Cancelled task: {task_id}")
        
        # Shutdown executor
        self.executor.shutdown(wait=wait)
        self.executor = None
        self.stats['end_time'] = time.time()
        
        self.logger.info(f"Connection pool shutdown complete. Stats: {self.get_statistics()}")
    
    def submit_scan(self, task: ScanTask) -> Future[ScanResult]:
        """
        Submit a scan task to the pool.
        
        Args:
            task: The scan task to execute
            
        Returns:
            Future[ScanResult]: Future representing the scan result
        """
        if self.executor is None:
            raise RuntimeError("Connection pool not started")
        
        if self._shutdown:
            raise RuntimeError("Connection pool is shutting down")
        
        # Submit task to executor
        future = self.executor.submit(self._execute_scan_task, task)
        
        # Track the task
        with self._lock:
            self.active_tasks[task.task_id] = future
            self.stats['total_tasks'] += 1
            self.stats['active_tasks'] += 1
        
        # Add completion callback
        future.add_done_callback(lambda f: self._task_completed(task.task_id, f))
        
        self.logger.debug(f"Submitted scan task: {task.task_id}")
        return future
    
    def submit_multiple_scans(self, tasks: List[ScanTask]) -> List[Future[ScanResult]]:
        """
        Submit multiple scan tasks to the pool.
        
        Args:
            tasks: List of scan tasks to execute
            
        Returns:
            List[Future[ScanResult]]: List of futures representing scan results
        """
        futures = []
        for task in tasks:
            try:
                future = self.submit_scan(task)
                futures.append(future)
            except Exception as e:
                self.logger.error(f"Failed to submit task {task.task_id}: {e}")
        
        return futures
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> List[ScanResult]:
        """
        Wait for all active tasks to complete.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            List[ScanResult]: List of completed scan results
        """
        if not self.active_tasks:
            return self.completed_tasks.copy()
        
        self.logger.info(f"Waiting for {len(self.active_tasks)} tasks to complete")
        
        # Wait for all futures to complete
        futures = list(self.active_tasks.values())
        
        try:
            for future in as_completed(futures, timeout=timeout):
                try:
                    result = future.result()
                    # Result is already handled by callback
                except Exception as e:
                    self.logger.error(f"Task execution failed: {e}")
        
        except TimeoutError:
            self.logger.warning(f"Timeout waiting for task completion after {timeout} seconds")
        
        return self.completed_tasks.copy()
    
    def get_results_as_completed(self, futures: List[Future[ScanResult]], timeout: Optional[float] = None):
        """
        Yield results as they complete.
        
        Args:
            futures: List of futures to monitor
            timeout: Timeout for each result
            
        Yields:
            ScanResult: Completed scan results
        """
        for future in as_completed(futures, timeout=timeout):
            try:
                result = future.result()
                yield result
            except Exception as e:
                self.logger.error(f"Task execution failed: {e}")
    
    def cancel_all_tasks(self) -> int:
        """
        Cancel all pending tasks.
        
        Returns:
            int: Number of tasks cancelled
        """
        cancelled_count = 0
        
        with self._lock:
            for task_id, future in self.active_tasks.items():
                if not future.done() and future.cancel():
                    cancelled_count += 1
                    self.logger.debug(f"Cancelled task: {task_id}")
        
        self.logger.info(f"Cancelled {cancelled_count} tasks")
        return cancelled_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        stats = self.stats.copy()
        
        with self._lock:
            stats['active_tasks'] = len([f for f in self.active_tasks.values() if not f.done()])
        
        if stats['start_time'] and stats['end_time']:
            stats['duration'] = stats['end_time'] - stats['start_time']
            if stats['duration'] > 0:
                stats['tasks_per_second'] = stats['completed_tasks'] / stats['duration']
        elif stats['start_time']:
            current_time = time.time()
            stats['duration'] = current_time - stats['start_time']
            if stats['duration'] > 0:
                stats['tasks_per_second'] = stats['completed_tasks'] / stats['duration']
        
        return stats
    
    def _execute_scan_task(self, task: ScanTask) -> ScanResult:
        """
        Execute a single scan task.
        
        Args:
            task: The scan task to execute
            
        Returns:
            ScanResult: Result of the scan operation
        """
        try:
            self.logger.debug(f"Executing scan task: {task.task_id}")
            
            # Execute the scanner function
            result = task.scanner_func(task.target, task.port)
            
            self.logger.debug(f"Completed scan task: {task.task_id} - {result.state.value}")
            return result
            
        except Exception as e:
            self.logger.error(f"Scan task failed {task.task_id}: {e}")
            
            # Create error result
            from .base import ScanResult, PortState, ScanType
            return ScanResult(
                target=task.target,
                port=task.port,
                state=PortState.UNKNOWN,
                scan_type=ScanType.TCP_CONNECT,  # Default
                error=str(e)
            )
    
    def _task_completed(self, task_id: str, future: Future) -> None:
        """
        Handle task completion.
        
        Args:
            task_id: The task identifier
            future: The completed future
        """
        with self._lock:
            # Remove from active tasks
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]
            
            self.stats['active_tasks'] = len(self.active_tasks)
            
            try:
                result = future.result()
                self.completed_tasks.append(result)
                self.stats['completed_tasks'] += 1
                
            except Exception as e:
                self.failed_tasks.append((task_id, str(e)))
                self.stats['failed_tasks'] += 1
                self.logger.error(f"Task {task_id} failed: {e}")
    
    def is_active(self) -> bool:
        """Check if the connection pool is active."""
        return self.executor is not None and not self._shutdown
    
    def get_active_task_count(self) -> int:
        """Get the number of active tasks."""
        with self._lock:
            return len([f for f in self.active_tasks.values() if not f.done()])
    
    def get_completed_results(self) -> List[ScanResult]:
        """Get all completed scan results."""
        with self._lock:
            return self.completed_tasks.copy()
    
    def get_failed_tasks(self) -> List[tuple]:
        """Get all failed tasks."""
        with self._lock:
            return self.failed_tasks.copy()
    
    def clear_results(self) -> None:
        """Clear all stored results and statistics."""
        with self._lock:
            self.completed_tasks.clear()
            self.failed_tasks.clear()
            self.stats = {
                'total_tasks': 0,
                'completed_tasks': 0,
                'failed_tasks': 0,
                'active_tasks': len(self.active_tasks),
                'start_time': self.stats.get('start_time'),
                'end_time': None,
            } 