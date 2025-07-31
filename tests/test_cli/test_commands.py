"""
Unit tests for CLI command argument parsing.

Tests cover scan, detect, and report command groups with various
argument combinations and validation scenarios.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner
import tempfile
import json

from src.hawkeye.cli.main import cli
from src.hawkeye.cli.scan_commands import scan
from src.hawkeye.cli.detect_commands import detect_group
from src.hawkeye.cli.report_commands import report_group
from src.hawkeye.config.settings import get_settings


class TestCLICommands:
    """Test cases for CLI command parsing."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()
    
    @pytest.fixture
    def temp_config_file(self):
        """Create temporary configuration file."""
        config_data = {
            "scan": {
                "timeout_seconds": 5,
                "max_threads": 10,
                "default_ports": [80, 443, 22]
            },
            "detection": {
                "enable_process_scan": True,
                "enable_config_discovery": True
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            return f.name
    
    def test_main_cli_help(self, runner):
        """Test main CLI help output."""
        result = runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert "HawkEye" in result.output
        assert "scan" in result.output
        assert "detect" in result.output
        assert "report" in result.output
    
    def test_scan_command_help(self, runner):
        """Test scan command help output."""
        result = runner.invoke(cli, ['scan', '--help'])
        
        assert result.exit_code == 0
        assert "target" in result.output
        assert "ports" in result.output
        assert "timeout" in result.output
    
    def test_scan_single_target(self, runner):
        """Test scan command with single target."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan', 
                '--target', '192.168.1.1',
                '--ports', '80,443',
                '--timeout', '5'
            ])
            
            # Should not fail with argument parsing
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_cidr_target(self, runner):
        """Test scan command with CIDR target."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '192.168.1.0/24',
                '--ports', '22,80,443',
                '--threads', '5'
            ])
            
            # Should accept CIDR notation
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_with_output_file(self, runner):
        """Test scan command with output file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
                mock_scanner.return_value.scan_port.return_value = Mock()
                
                result = runner.invoke(cli, [
                    'scan',
                    '--target', '127.0.0.1',
                    '--ports', '80',
                    '--output', output_file.name,
                    '--format', 'json'
                ])
                
                # Should accept output file parameter
                assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_udp_option(self, runner):
        """Test scan command with UDP option."""
        with patch('src.hawkeye.scanner.udp_scanner.UDPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '127.0.0.1',
                '--ports', '53,161',
                '--udp'
            ])
            
            # Should accept UDP scanning option
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_both_tcp_udp(self, runner):
        """Test scan command with both TCP and UDP."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_tcp:
            with patch('src.hawkeye.scanner.udp_scanner.UDPScanner') as mock_udp:
                mock_tcp.return_value.scan_port.return_value = Mock()
                mock_udp.return_value.scan_port.return_value = Mock()
                
                result = runner.invoke(cli, [
                    'scan',
                    '--target', '127.0.0.1',
                    '--ports', '80,53',
                    '--tcp', '--udp'
                ])
                
                # Should accept both TCP and UDP
                assert result.exit_code == 0 or "Error" not in result.output
    
    def test_detect_command_help(self, runner):
        """Test detect command help output."""
        result = runner.invoke(cli, ['detect', '--help'])
        
        assert result.exit_code == 0
        assert "target" in result.output
        assert "process" in result.output
        assert "config" in result.output
    
    def test_detect_local_processes(self, runner):
        """Test detect command for local processes."""
        with patch('src.hawkeye.detection.process_enum.ProcessEnumerator') as mock_enum:
            mock_enum.return_value.get_node_processes.return_value = []
            
            result = runner.invoke(cli, [
                'detect',
                '--local'
            ])
            
            # Should accept local detection
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_detect_with_target(self, runner):
        """Test detect command with specific target."""
        with patch('src.hawkeye.detection.process_enum.ProcessEnumerator') as mock_enum:
            mock_enum.return_value.get_node_processes.return_value = []
            
            result = runner.invoke(cli, [
                'detect',
                '--target', '192.168.1.100'
            ])
            
            # Should accept target detection
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_detect_config_discovery(self, runner):
        """Test detect command with config discovery."""
        with patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery') as mock_discovery:
            mock_discovery.return_value.discover_mcp_configs.return_value = []
            
            result = runner.invoke(cli, [
                'detect',
                '--config-discovery',
                '--path', '/opt/mcp-servers'
            ])
            
            # Should accept config discovery
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_detect_docker_inspection(self, runner):
        """Test detect command with Docker inspection."""
        with patch('src.hawkeye.detection.docker_inspect.DockerInspector') as mock_inspector:
            mock_inspector.return_value.inspect_containers.return_value = []
            
            result = runner.invoke(cli, [
                'detect',
                '--docker'
            ])
            
            # Should accept Docker inspection
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_report_command_help(self, runner):
        """Test report command help output."""
        result = runner.invoke(cli, ['report', '--help'])
        
        assert result.exit_code == 0
        assert "input" in result.output
        assert "format" in result.output
        assert "output" in result.output
    
    def test_report_json_format(self, runner):
        """Test report command with JSON format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
            # Create mock scan results
            mock_results = {
                "scan_results": [
                    {
                        "target": "127.0.0.1",
                        "port": 80,
                        "state": "open",
                        "service": "http"
                    }
                ]
            }
            json.dump(mock_results, input_file)
            input_file.flush()
            
            with patch('src.hawkeye.reporting.json_reporter.JSONReporter') as mock_reporter:
                mock_reporter.return_value.generate_report.return_value = mock_results
                
                result = runner.invoke(cli, [
                    'report',
                    '--input', input_file.name,
                    '--format', 'json'
                ])
                
                # Should accept JSON format
                assert result.exit_code == 0 or "Error" not in result.output
    
    def test_report_csv_format(self, runner):
        """Test report command with CSV format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
            mock_results = {"scan_results": []}
            json.dump(mock_results, input_file)
            input_file.flush()
            
            with patch('src.hawkeye.reporting.csv_reporter.CSVReporter') as mock_reporter:
                mock_reporter.return_value.generate_report.return_value = "csv,content"
                
                result = runner.invoke(cli, [
                    'report',
                    '--input', input_file.name,
                    '--format', 'csv'
                ])
                
                # Should accept CSV format
                assert result.exit_code == 0 or "Error" not in result.output
    
    def test_report_html_format(self, runner):
        """Test report command with HTML format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
            mock_results = {"scan_results": []}
            json.dump(mock_results, input_file)
            input_file.flush()
            
            with patch('src.hawkeye.reporting.html_reporter.HTMLReporter') as mock_reporter:
                mock_reporter.return_value.generate_report.return_value = "<html></html>"
                
                result = runner.invoke(cli, [
                    'report',
                    '--input', input_file.name,
                    '--format', 'html'
                ])
                
                # Should accept HTML format
                assert result.exit_code == 0 or "Error" not in result.output
    
    def test_report_with_template(self, runner):
        """Test report command with custom template."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as template_file:
                mock_results = {"scan_results": []}
                json.dump(mock_results, input_file)
                input_file.flush()
                
                template_file.write("<html><body>{{results}}</body></html>")
                template_file.flush()
                
                with patch('src.hawkeye.reporting.html_reporter.HTMLReporter') as mock_reporter:
                    mock_reporter.return_value.generate_report.return_value = "<html></html>"
                    
                    result = runner.invoke(cli, [
                        'report',
                        '--input', input_file.name,
                        '--format', 'html',
                        '--template', template_file.name
                    ])
                    
                    # Should accept custom template
                    assert result.exit_code == 0 or "Error" not in result.output
    
    def test_global_config_file_option(self, runner, temp_config_file):
        """Test global config file option."""
        result = runner.invoke(cli, [
            '--config', temp_config_file,
            'scan', '--help'
        ])
        
        # Should accept config file option
        assert result.exit_code == 0
    
    def test_global_verbose_option(self, runner):
        """Test global verbose option."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                '--verbose',
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80'
            ])
            
            # Should accept verbose option
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_global_quiet_option(self, runner):
        """Test global quiet option."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                '--quiet',
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80'
            ])
            
            # Should accept quiet option
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_port_range(self, runner):
        """Test scan command with port range."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '127.0.0.1',
                '--ports', '80-85'
            ])
            
            # Should accept port range
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_common_ports(self, runner):
        """Test scan command with common ports option."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '127.0.0.1',
                '--common-ports'
            ])
            
            # Should accept common ports option
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_scan_all_ports(self, runner):
        """Test scan command with all ports option."""
        with patch('src.hawkeye.scanner.tcp_scanner.TCPScanner') as mock_scanner:
            mock_scanner.return_value.scan_port.return_value = Mock()
            
            result = runner.invoke(cli, [
                'scan',
                '--target', '127.0.0.1',
                '--all-ports'
            ])
            
            # Should accept all ports option
            assert result.exit_code == 0 or "Error" not in result.output
    
    def test_detect_all_options(self, runner):
        """Test detect command with all options enabled."""
        with patch('src.hawkeye.detection.process_enum.ProcessEnumerator') as mock_enum:
            with patch('src.hawkeye.detection.config_discovery.ConfigFileDiscovery') as mock_config:
                with patch('src.hawkeye.detection.docker_inspect.DockerInspector') as mock_docker:
                    mock_enum.return_value.get_node_processes.return_value = []
                    mock_config.return_value.discover_mcp_configs.return_value = []
                    mock_docker.return_value.inspect_containers.return_value = []
                    
                    result = runner.invoke(cli, [
                        'detect',
                        '--local',
                        '--config-discovery',
                        '--docker',
                        '--processes',
                        '--verify-protocol'
                    ])
                    
                    # Should accept all detection options
                    assert result.exit_code == 0 or "Error" not in result.output
    
    def test_report_executive_summary(self, runner):
        """Test report command with executive summary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
            mock_results = {"scan_results": []}
            json.dump(mock_results, input_file)
            input_file.flush()
            
            with patch('src.hawkeye.reporting.executive_summary.ExecutiveSummary') as mock_summary:
                mock_summary.return_value.generate_summary.return_value = {"summary": "test"}
                
                result = runner.invoke(cli, [
                    'report',
                    '--input', input_file.name,
                    '--executive-summary'
                ])
                
                # Should accept executive summary option
                assert result.exit_code == 0 or "Error" not in result.output 