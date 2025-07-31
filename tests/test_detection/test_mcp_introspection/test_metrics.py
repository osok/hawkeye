"""
Unit tests for MCP introspection performance metrics.

Tests the performance monitoring and metrics collection functionality
for the MCP introspection system.
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.hawkeye.detection.mcp_introspection.metrics import (
    PerformanceMetric, TimingMetric, MetricsCollector,
    PerformanceMonitor, TimingContext, get_global_monitor,
    time_operation, monitor_function
)


class TestPerformanceMetric:
    """Test the PerformanceMetric class."""
    
    def test_metric_creation(self):
        """Test basic metric creation."""
        timestamp = datetime.now()
        metric = PerformanceMetric(
            name="test_metric",
            value=42.5,
            timestamp=timestamp,
            tags={"category": "test"},
            metadata={"source": "unit_test"}
        )
        
        assert metric.name == "test_metric"
        assert metric.value == 42.5
        assert metric.timestamp == timestamp
        assert metric.tags["category"] == "test"
        assert metric.metadata["source"] == "unit_test"
    
    def test_metric_with_defaults(self):
        """Test metric creation with default values."""
        metric = PerformanceMetric(
            name="simple_metric",
            value=10.0,
            timestamp=datetime.now()
        )
        
        assert metric.name == "simple_metric"
        assert metric.value == 10.0
        assert isinstance(metric.tags, dict)
        assert isinstance(metric.metadata, dict)
        assert len(metric.tags) == 0
        assert len(metric.metadata) == 0


class TestTimingMetric:
    """Test the TimingMetric class."""
    
    def test_timing_metric_creation(self):
        """Test basic timing metric creation."""
        start_time = time.time()
        timing = TimingMetric(
            operation="test_operation",
            start_time=start_time,
            tags={"type": "test"}
        )
        
        assert timing.operation == "test_operation"
        assert timing.start_time == start_time
        assert timing.end_time is None
        assert timing.duration is None
        assert timing.success is True
        assert timing.error_message is None
        assert timing.tags["type"] == "test"
    
    def test_timing_metric_finish_success(self):
        """Test finishing a timing metric successfully."""
        start_time = time.time()
        timing = TimingMetric("test_op", start_time)
        
        # Simulate some work
        time.sleep(0.01)
        
        timing.finish(success=True)
        
        assert timing.end_time is not None
        assert timing.duration is not None
        assert timing.duration > 0
        assert timing.success is True
        assert timing.error_message is None
    
    def test_timing_metric_finish_failure(self):
        """Test finishing a timing metric with failure."""
        start_time = time.time()
        timing = TimingMetric("test_op", start_time)
        
        timing.finish(success=False, error_message="Test error")
        
        assert timing.end_time is not None
        assert timing.duration is not None
        assert timing.success is False
        assert timing.error_message == "Test error"


class TestMetricsCollector:
    """Test the MetricsCollector class."""
    
    @pytest.fixture
    def collector(self):
        """Create a metrics collector for testing."""
        return MetricsCollector(max_metrics=100)
    
    def test_collector_initialization(self, collector):
        """Test collector initialization."""
        assert collector.max_metrics == 100
        assert len(collector._metrics) == 0
        assert len(collector._timing_metrics) == 0
        assert len(collector._counters) == 0
        assert len(collector._gauges) == 0
        assert len(collector._histograms) == 0
    
    def test_record_metric(self, collector):
        """Test recording a basic metric."""
        collector.record_metric("test_metric", 42.5, {"tag": "value"}, {"meta": "data"})
        
        assert len(collector._metrics) == 1
        metric = collector._metrics[0]
        assert metric.name == "test_metric"
        assert metric.value == 42.5
        assert metric.tags["tag"] == "value"
        assert metric.metadata["meta"] == "data"
        
        # Check histogram
        assert "test_metric" in collector._histograms
        assert collector._histograms["test_metric"] == [42.5]
    
    def test_start_and_finish_timing(self, collector):
        """Test starting and finishing timing operations."""
        timing = collector.start_timing("test_operation", {"type": "test"})
        
        assert timing.operation == "test_operation"
        assert timing.tags["type"] == "test"
        assert collector._operation_counts["test_operation"] == 1
        
        # Simulate work
        time.sleep(0.01)
        
        collector.finish_timing(timing, success=True)
        
        assert len(collector._timing_metrics) == 1
        assert timing.duration is not None
        assert timing.duration > 0
        assert collector._counters["test_operation_success"] == 1
    
    def test_timing_with_failure(self, collector):
        """Test timing with failure."""
        timing = collector.start_timing("failing_operation")
        
        collector.finish_timing(timing, success=False, error_message="Test failure")
        
        assert len(collector._timing_metrics) == 1
        assert timing.success is False
        assert timing.error_message == "Test failure"
        assert collector._counters["failing_operation_error"] == 1
        assert collector._error_counts["failing_operation"] == 1
    
    def test_increment_counter(self, collector):
        """Test counter increment functionality."""
        collector.increment_counter("test_counter", 5, {"category": "test"})
        
        assert collector._counters["test_counter"] == 5
        
        collector.increment_counter("test_counter", 3)
        
        assert collector._counters["test_counter"] == 8
        
        # Check that metric was also recorded
        assert len(collector._metrics) >= 2
    
    def test_set_gauge(self, collector):
        """Test gauge setting functionality."""
        collector.set_gauge("test_gauge", 100.0, {"unit": "bytes"})
        
        assert collector._gauges["test_gauge"] == 100.0
        
        collector.set_gauge("test_gauge", 150.0)
        
        assert collector._gauges["test_gauge"] == 150.0
        
        # Check that metric was also recorded
        assert len(collector._metrics) >= 2
    
    def test_get_counter(self, collector):
        """Test getting counter values."""
        collector.increment_counter("test_counter", 10)
        
        assert collector.get_counter("test_counter") == 10
        assert collector.get_counter("nonexistent_counter") == 0
    
    def test_get_gauge(self, collector):
        """Test getting gauge values."""
        collector.set_gauge("test_gauge", 42.0)
        
        assert collector.get_gauge("test_gauge") == 42.0
        assert collector.get_gauge("nonexistent_gauge") is None
    
    def test_histogram_stats(self, collector):
        """Test histogram statistics calculation."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        for value in values:
            collector.record_metric("test_histogram", value)
        
        stats = collector.get_histogram_stats("test_histogram")
        
        assert stats["count"] == 5
        assert stats["min"] == 1.0
        assert stats["max"] == 5.0
        assert stats["mean"] == 3.0
        assert stats["median"] == 3.0
        assert 0 < stats["std_dev"] < 2
    
    def test_histogram_stats_empty(self, collector):
        """Test histogram statistics for empty histogram."""
        stats = collector.get_histogram_stats("nonexistent_histogram")
        
        assert stats["count"] == 0
        assert stats["min"] == 0
        assert stats["max"] == 0
        assert stats["mean"] == 0
        assert stats["median"] == 0
        assert stats["std_dev"] == 0
    
    def test_operation_summary(self, collector):
        """Test operation summary generation."""
        # Record some operations
        timing1 = collector.start_timing("op1")
        collector.finish_timing(timing1, success=True)
        
        timing2 = collector.start_timing("op1")
        collector.finish_timing(timing2, success=False, error_message="Error")
        
        timing3 = collector.start_timing("op2")
        collector.finish_timing(timing3, success=True)
        
        summary = collector.get_operation_summary()
        
        assert "op1" in summary
        assert "op2" in summary
        
        op1_stats = summary["op1"]
        assert op1_stats["total_count"] == 2
        assert op1_stats["success_count"] == 1
        assert op1_stats["error_count"] == 1
        assert op1_stats["success_rate"] == 0.5
        
        op2_stats = summary["op2"]
        assert op2_stats["total_count"] == 1
        assert op2_stats["success_count"] == 1
        assert op2_stats["error_count"] == 0
        assert op2_stats["success_rate"] == 1.0
    
    def test_recent_metrics(self, collector):
        """Test getting recent metrics."""
        # Record some metrics
        collector.record_metric("metric1", 10.0)
        time.sleep(0.01)
        collector.record_metric("metric2", 20.0)
        
        recent = collector.get_recent_metrics(minutes=1)
        
        assert len(recent) == 2
        assert recent[0].name == "metric1"
        assert recent[1].name == "metric2"
    
    def test_performance_report(self, collector):
        """Test comprehensive performance report generation."""
        # Record various metrics
        collector.record_metric("test_metric", 42.0)
        collector.increment_counter("test_counter", 5)
        collector.set_gauge("test_gauge", 100.0)
        
        timing = collector.start_timing("test_operation")
        collector.finish_timing(timing, success=True)
        
        report = collector.get_performance_report()
        
        assert "summary" in report
        assert "counters" in report
        assert "gauges" in report
        assert "operations" in report
        assert "histograms" in report
        
        assert report["summary"]["total_metrics"] >= 3
        assert report["summary"]["total_operations"] == 1
        assert "test_counter" in report["counters"]
        assert "test_gauge" in report["gauges"]
    
    def test_clear_metrics(self, collector):
        """Test clearing all metrics."""
        # Record some data
        collector.record_metric("test", 1.0)
        collector.increment_counter("counter", 1)
        collector.set_gauge("gauge", 1.0)
        
        timing = collector.start_timing("operation")
        collector.finish_timing(timing)
        
        # Verify data exists
        assert len(collector._metrics) > 0
        assert len(collector._timing_metrics) > 0
        assert len(collector._counters) > 0
        assert len(collector._gauges) > 0
        
        # Clear and verify
        collector.clear_metrics()
        
        assert len(collector._metrics) == 0
        assert len(collector._timing_metrics) == 0
        assert len(collector._counters) == 0
        assert len(collector._gauges) == 0
        assert len(collector._histograms) == 0
    
    def test_thread_safety(self, collector):
        """Test thread safety of metrics collection."""
        def worker(worker_id):
            for i in range(10):
                collector.record_metric(f"worker_{worker_id}_metric", i)
                collector.increment_counter(f"worker_{worker_id}_counter")
        
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all metrics were recorded
        assert len(collector._metrics) == 50  # 5 workers * 10 metrics each
        
        # Verify counters
        for i in range(5):
            assert collector.get_counter(f"worker_{i}_counter") == 10


class TestPerformanceMonitor:
    """Test the PerformanceMonitor class."""
    
    @pytest.fixture
    def monitor(self):
        """Create a performance monitor for testing."""
        return PerformanceMonitor()
    
    def test_monitor_initialization(self, monitor):
        """Test monitor initialization."""
        assert monitor.metrics_collector is not None
        assert isinstance(monitor.metrics_collector, MetricsCollector)
    
    def test_time_operation_context(self, monitor):
        """Test timing operation using context manager."""
        with monitor.time_operation("test_operation", {"type": "test"}):
            time.sleep(0.01)
        
        # Check that timing was recorded
        report = monitor.get_performance_report()
        assert "test_operation" in report["operations"]
        assert report["operations"]["test_operation"]["total_count"] == 1
    
    def test_monitor_function_decorator(self, monitor):
        """Test function monitoring decorator."""
        @monitor.monitor_function("decorated_function", {"category": "test"})
        def test_function(x, y):
            time.sleep(0.01)
            return x + y
        
        result = test_function(2, 3)
        
        assert result == 5
        
        # Check that timing was recorded
        report = monitor.get_performance_report()
        assert "decorated_function" in report["operations"]
        assert report["operations"]["decorated_function"]["total_count"] == 1
    
    def test_monitor_function_with_exception(self, monitor):
        """Test function monitoring with exception."""
        @monitor.monitor_function("failing_function")
        def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            failing_function()
        
        # Check that failure was recorded
        report = monitor.get_performance_report()
        assert "failing_function" in report["operations"]
        stats = report["operations"]["failing_function"]
        assert stats["total_count"] == 1
        assert stats["error_count"] == 1
        assert stats["success_rate"] == 0.0
    
    def test_record_metric(self, monitor):
        """Test recording metrics through monitor."""
        monitor.record_metric("test_metric", 42.0, {"tag": "value"})
        
        report = monitor.get_performance_report()
        assert report["summary"]["total_metrics"] >= 1
    
    def test_increment_counter(self, monitor):
        """Test incrementing counters through monitor."""
        monitor.increment_counter("test_counter", 5, {"tag": "value"})
        
        report = monitor.get_performance_report()
        assert "test_counter" in report["counters"]
        assert report["counters"]["test_counter"] == 5
    
    def test_set_gauge(self, monitor):
        """Test setting gauges through monitor."""
        monitor.set_gauge("test_gauge", 100.0, {"tag": "value"})
        
        report = monitor.get_performance_report()
        assert "test_gauge" in report["gauges"]
        assert report["gauges"]["test_gauge"] == 100.0


class TestTimingContext:
    """Test the TimingContext class."""
    
    @pytest.fixture
    def collector(self):
        """Create a metrics collector for testing."""
        return MetricsCollector()
    
    def test_timing_context_success(self, collector):
        """Test timing context with successful operation."""
        with TimingContext(collector, "test_operation", {"type": "test"}):
            time.sleep(0.01)
        
        assert len(collector._timing_metrics) == 1
        timing = collector._timing_metrics[0]
        assert timing.operation == "test_operation"
        assert timing.success is True
        assert timing.duration is not None
        assert timing.duration > 0
    
    def test_timing_context_with_exception(self, collector):
        """Test timing context with exception."""
        with pytest.raises(ValueError):
            with TimingContext(collector, "failing_operation"):
                raise ValueError("Test error")
        
        assert len(collector._timing_metrics) == 1
        timing = collector._timing_metrics[0]
        assert timing.operation == "failing_operation"
        assert timing.success is False
        assert "ValueError: Test error" in timing.error_message


class TestGlobalFunctions:
    """Test global convenience functions."""
    
    def test_get_global_monitor(self):
        """Test getting global monitor instance."""
        monitor1 = get_global_monitor()
        monitor2 = get_global_monitor()
        
        # Should return the same instance
        assert monitor1 is monitor2
        assert isinstance(monitor1, PerformanceMonitor)
    
    def test_time_operation_decorator(self):
        """Test global time_operation decorator."""
        @time_operation("global_operation", {"type": "test"})
        def test_function():
            time.sleep(0.01)
            return "success"
        
        result = test_function()
        
        assert result == "success"
        
        # Check that timing was recorded in global monitor
        monitor = get_global_monitor()
        report = monitor.get_performance_report()
        assert "global_operation" in report["operations"]
    
    def test_monitor_function_decorator(self):
        """Test global monitor_function decorator."""
        @monitor_function("global_monitored_function")
        def test_function(value):
            return value * 2
        
        result = test_function(21)
        
        assert result == 42
        
        # Check that timing was recorded in global monitor
        monitor = get_global_monitor()
        report = monitor.get_performance_report()
        assert "global_monitored_function" in report["operations"]


if __name__ == "__main__":
    pytest.main([__file__]) 