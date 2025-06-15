"""
Integration tests for complete CLI workflows.

Tests cover end-to-end CLI operations including scan workflows,
detection workflows, report generation, and error scenarios.
"""

import pytest
import tempfile
import json
import subprocess
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from src.hawkeye.cli.main import cli
from src.hawkeye.config.settings import get_settings


class TestCLIIntegration:
    """Integration tests for complete CLI workflows."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    @pytest.fixture
    def mock_scan_results(self):
        """Create mock scan results."""
        return {
            "scan_metadata": {
                "target": "127.0.0.1",
                "start_time": "2024-01-01T12:00:00Z",
                "end_time": "2024-01-01T12:05:00Z",
                "total_ports_scanned": 3
            },
            "scan_results": [
                {
                    "target": "127.0.0.1",
                    "port": 22,
                    "state": "open",
                    "scan_type": "tcp",
                    "service": "ssh",
                    "response_time": 0.02
                },
                {
                    "target": "127.0.0.1",
                    "port": 80,
                    "state": "open", 
                    "scan_type": "tcp",
                    "service": "http",
                    "response_time": 0.01
                },
                {
                    "target": "127.0.0.1",
                    "port": 443,
                    "state": "closed",
                    "scan_type": "tcp",
                    "response_time": 0.05
                }
            ]
        }
    
    @pytest.fixture
    def mock_detection_results(self):
        """Create mock detection results."""
        return {
            "detection_metadata": {
                "target": "127.0.0.1",
                "scan_time": "2024-01-01T12:00:00Z",
                "total_processes_found": 2
            },
            "detection_results": [
                {
                    "process_id": 12345,
                    "process_name": "node",
                    "command_line": ["node", "mcp-server.js", "--stdio"],
                    "working_directory": "/opt/mcp-server",
                    "user": "mcp-user",
                    "mcp_detected": True,
                    "transport_type": "stdio",
                    "confidence": 0.95
                },
                {
                    "process_id": 54321,
                    "process_name": "node",
                    "command_line": ["node", "web-server.js"],
                    "working_directory": "/opt/web-server",
                    "user": "web-user",
                    "mcp_detected": False,
                    "confidence": 0.1
                }
            ]
        }
    
    def test_complete_scan_workflow(self, runner, temp_output_dir, mock_scan_results):
        """Test complete scan workflow from CLI to output."""
        output_file = Path(temp_output_dir) / "scan_results.json"
        
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            with patch('src.hawkeye.reporting.json_reporter.JSONReporter') as mock_reporter:
                # Mock scanner results
                mock_scanner.return_value.scan_port.return_value = Mock(
                    target="127.0.0.1",
                    port=80,
                    state="open",
                    scan_type="tcp"
                )
                
                # Mock reporter output
                mock_reporter.return_value.generate_report.return_value = mock_scan_results
                
                # Run scan command
                result = runner.invoke(cli, [
                    'scan',
                    '--target', '127.0.0.1',
                    '--ports', '22,80,443',
                    '--output', str(output_file),
                    '--format', 'json'
                ])
                
                # Verify command succeeded
                assert result.exit_code == 0
                
                # Verify scanner was called
                mock_scanner.assert_called()
                
                # Verify reporter was called
                mock_reporter.assert_called()
    
    def test_complete_detection_workflow(self, runner, temp_output_dir, mock_detection_results):
        """Test complete detection workflow from CLI to output."""
        output_file = Path(temp_output_dir) / "detection_results.json"
        
        with patch('src.hawkeye.detection.process_enum.ProcessEnumerator') as mock_enum:
            with patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier') as mock_verify:
                with patch('src.hawkeye.reporting.json_reporter.JSONReporter') as mock_reporter:
                    # Mock detection results
                    mock_enum.return_value.get_node_processes.return_value = []
                    mock_verify.return_value.verify_mcp_protocol.return_value = True
                    mock_reporter.return_value.generate_report.return_value = mock_detection_results
                    
                    # Run detect command
                    result = runner.invoke(cli, [
                        'detect',
                        '--local',
                        '--processes',
                        '--verify-protocol',
                        '--output', str(output_file),
                        '--format', 'json'
                    ])
                    
                    # Verify command succeeded
                    assert result.exit_code == 0
                    
                    # Verify detection components were called
                    mock_enum.assert_called()
                    mock_verify.assert_called()
    
    def test_scan_to_report_workflow(self, runner, temp_output_dir, mock_scan_results):
        """Test complete scan-to-report workflow."""
        scan_output = Path(temp_output_dir) / "scan_results.json"
        report_output = Path(temp_output_dir) / "scan_report.html"
        
        # Create scan results file
        with open(scan_output, 'w') as f:
            json.dump(mock_scan_results, f)
        
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            with patch('src.hawkeye.reporting.html_reporter.HTMLReporter') as mock_reporter:
                # Mock scan results
                mock_scanner.return_value.scan_port.return_value = Mock()
                
                # Mock report generation
                mock_reporter.return_value.generate_report.return_value = "<html>Report</html>"
                
                # Step 1: Run scan
                scan_result = runner.invoke(cli, [
                    'scan',
                    '--target', '127.0.0.1',
                    '--ports', '22,80,443',
                    '--output', str(scan_output),
                    '--format', 'json'
                ])
                
                assert scan_result.exit_code == 0
                
                # Step 2: Generate report
                report_result = runner.invoke(cli, [
                    'report',
                    '--input', str(scan_output),
                    '--format', 'html',
                    '--output', str(report_output)
                ])
                
                assert report_result.exit_code == 0
                
                # Verify both scanner and reporter were called
                mock_scanner.assert_called()
                mock_reporter.assert_called()
    
    def test_detect_to_report_workflow(self, runner, temp_output_dir, mock_detection_results):
        """Test complete detect-to-report workflow."""
        detection_output = Path(temp_output_dir) / "detection_results.json"
        report_output = Path(temp_output_dir) / "detection_report.html"
        
        # Create detection results file
        with open(detection_output, 'w') as f:
            json.dump(mock_detection_results, f)
        
        with patch('src.hawkeye.detection.process_enum.ProcessEnumerator') as mock_enum:
            with patch('src.hawkeye.reporting.html_reporter.HTMLReporter') as mock_reporter:
                # Mock detection results
                mock_enum.return_value.get_node_processes.return_value = []
                
                # Mock report generation
                mock_reporter.return_value.generate_report.return_value = "<html>Detection Report</html>"
                
                # Step 1: Run detection
                detect_result = runner.invoke(cli, [
                    'detect',
                    '--local',
                    '--output', str(detection_output),
                    '--format', 'json'
                ])
                
                assert detect_result.exit_code == 0
                
                # Step 2: Generate report
                report_result = runner.invoke(cli, [
                    'report',
                    '--input', str(detection_output),
                    '--format', 'html',
                    '--output', str(report_output)
                ])
                
                assert report_result.exit_code == 0
    
    def test_multi_format_report_generation(self, runner, temp_output_dir, mock_scan_results):
        """Test generating reports in multiple formats."""
        scan_output = Path(temp_output_dir) / "scan_results.json"
        
        # Create scan results file
        with open(scan_output, 'w') as f:
            json.dump(mock_scan_results, f)
        
        formats = ['json', 'csv', 'html', 'xml']
        
        for fmt in formats:
            report_output = Path(temp_output_dir) / f"report.{fmt}"
            
            with patch(f'src.hawkeye.reporting.{fmt}_reporter.{fmt.upper()}Reporter') as mock_reporter:
                mock_reporter.return_value.generate_report.return_value = f"<{fmt}>report</{fmt}>"
                
                result = runner.invoke(cli, [
                    'report',
                    '--input', str(scan_output),
                    '--format', fmt,
                    '--output', str(report_output)
                ])
                
                assert result.exit_code == 0
                mock_reporter.assert_called()
    
    def test_comprehensive_scan_with_all_options(self, runner, temp_output_dir):
        """Test comprehensive scan with all available options."""
        output_file = Path(temp_output_dir) / "comprehensive_scan.json"
        
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_tcp:
            with patch('src.hawkeye.scanner.udp_scanner.UDPScanner') as mock_udp:
                with patch('src.hawkeye.scanner.fingerprint.ServiceFingerprinter') as mock_fp:
                    # Mock all scanner components
                    mock_tcp.return_value.scan_port.return_value = Mock()
                    mock_udp.return_value.scan_port.return_value = Mock()
                    mock_fp.return_value.fingerprint_service.return_value = Mock()
                    
                    result = runner.invoke(cli, [
                        'scan',
                        '--target', '192.168.1.0/30',
                        '--ports', '22,80,443,53,161',
                        '--tcp', '--udp',
                        '--fingerprint',
                        '--threads', '5',
                        '--timeout', '10',
                        '--output', str(output_file),
                        '--format', 'json',
                        '--verbose'
                    ])
                    
                    assert result.exit_code == 0
                    
                    # Verify all components were used
                    mock_tcp.assert_called()
                    mock_udp.assert_called()
                    mock_fp.assert_called()
    
    def test_comprehensive_detection_with_all_options(self, runner, temp_output_dir):
        """Test comprehensive detection with all available options."""
        output_file = Path(temp_output_dir) / "comprehensive_detection.json"
        
        with patch('src.hawkeye.detection.process_enum.ProcessEnumerator') as mock_enum:
            with patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery') as mock_config:
                with patch('src.hawkeye.detection.docker_inspect.DockerInspector') as mock_docker:
                    with patch('src.hawkeye.detection.protocol_verify.ProtocolVerifier') as mock_verify:
                        # Mock all detection components
                        mock_enum.return_value.get_node_processes.return_value = []
                        mock_config.return_value.discover_mcp_configs.return_value = []
                        mock_docker.return_value.inspect_containers.return_value = []
                        mock_verify.return_value.verify_mcp_protocol.return_value = True
                        
                        result = runner.invoke(cli, [
                            'detect',
                            '--local',
                            '--processes',
                            '--config-discovery',
                            '--docker',
                            '--verify-protocol',
                            '--path', '/opt/mcp-servers',
                            '--output', str(output_file),
                            '--format', 'json',
                            '--verbose'
                        ])
                        
                        assert result.exit_code == 0
                        
                        # Verify all components were used
                        mock_enum.assert_called()
                        mock_config.assert_called()
                        mock_docker.assert_called()
                        mock_verify.assert_called()
    
    def test_error_handling_invalid_target(self, runner):
        """Test error handling with invalid target."""
        result = runner.invoke(cli, [
            'scan',
            '--target', '999.999.999.999',
            '--ports', '80'
        ])
        
        # Should fail gracefully with proper error message
        assert result.exit_code != 0
        assert "invalid" in result.output.lower() or "error" in result.output.lower()
    
    def test_error_handling_invalid_ports(self, runner):
        """Test error handling with invalid ports."""
        result = runner.invoke(cli, [
            'scan',
            '--target', '127.0.0.1',
            '--ports', '99999'  # Invalid port number
        ])
        
        # Should fail gracefully with proper error message
        assert result.exit_code != 0
        assert "port" in result.output.lower() or "error" in result.output.lower()
    
    def test_error_handling_missing_input_file(self, runner):
        """Test error handling with missing input file."""
        result = runner.invoke(cli, [
            'report',
            '--input', '/nonexistent/file.json',
            '--format', 'html'
        ])
        
        # Should fail gracefully with proper error message
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "error" in result.output.lower()
    
    def test_config_file_integration(self, runner, temp_output_dir):
        """Test integration with configuration file."""
        config_data = {
            "scan": {
                "timeout_seconds": 15,
                "max_threads": 8,
                "default_ports": [22, 80, 443]
            },
            "detection": {
                "enable_process_scan": True,
                "enable_config_discovery": True
            },
            "reporting": {
                "default_format": "json"
            }
        }
        
        config_file = Path(temp_output_dir) / "hawkeye_config.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                '--config', str(config_file),
                'scan',
                '--target', '127.0.0.1'
                # Should use ports from config file
            ])
            
            assert result.exit_code == 0
            mock_scanner.assert_called()
    
    def test_verbose_and_quiet_modes(self, runner):
        """Test verbose and quiet output modes."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            # Test verbose mode
            verbose_result = runner.invoke(cli, [
                '--verbose',
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80'
            ])
            
            assert verbose_result.exit_code == 0
            
            # Test quiet mode
            quiet_result = runner.invoke(cli, [
                '--quiet',
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80'
            ])
            
            assert quiet_result.exit_code == 0
            
            # Quiet output should be shorter than verbose
            assert len(quiet_result.output) <= len(verbose_result.output)
    
    def test_progress_indicators(self, runner):
        """Test progress indicators during long operations."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80-85',  # Multiple ports to show progress
                '--verbose'
            ])
            
            assert result.exit_code == 0
            # In a real implementation, would check for progress indicators
    
    def test_signal_handling_graceful_shutdown(self, runner):
        """Test graceful shutdown on interrupt signals."""
        # This would test SIGINT/SIGTERM handling in a real implementation
        # For now, just verify basic command structure works
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80'
            ])
            
            assert result.exit_code == 0 