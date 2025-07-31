"""
Unit tests for MCP introspection configuration migration tools
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.hawkeye.detection.mcp_introspection.migration import (
    ConfigurationMigrator,
    ConfigurationValidator,
    LegacyMCPConfig,
    MigrationConfig,
    MigrationResult,
    migrate_legacy_configuration,
    validate_configuration
)


class TestMigrationConfig(unittest.TestCase):
    """Test MigrationConfig model"""
    
    def test_default_values(self):
        """Test default configuration values"""
        config = MigrationConfig()
        
        self.assertTrue(config.backup_enabled)
        self.assertEqual(config.backup_directory, "backups")
        self.assertTrue(config.validate_migration)
        self.assertTrue(config.preserve_old_config)
        self.assertEqual(config.migration_log_level, "INFO")
    
    def test_custom_values(self):
        """Test custom configuration values"""
        config = MigrationConfig(
            backup_enabled=False,
            backup_directory="custom_backups",
            validate_migration=False,
            preserve_old_config=False,
            migration_log_level="DEBUG"
        )
        
        self.assertFalse(config.backup_enabled)
        self.assertEqual(config.backup_directory, "custom_backups")
        self.assertFalse(config.validate_migration)
        self.assertFalse(config.preserve_old_config)
        self.assertEqual(config.migration_log_level, "DEBUG")


class TestLegacyMCPConfig(unittest.TestCase):
    """Test LegacyMCPConfig model"""
    
    def test_default_values(self):
        """Test default configuration values"""
        config = LegacyMCPConfig()
        
        self.assertEqual(config.servers, [])
        self.assertIsNone(config.nodejs_script_path)
        self.assertEqual(config.timeout_seconds, 30)
        self.assertEqual(config.max_retries, 3)
        self.assertTrue(config.enable_introspection)
    
    def test_with_servers(self):
        """Test configuration with servers"""
        servers = [
            {"name": "test-server", "command": "node", "args": ["server.js"]},
            {"name": "another-server", "command": "python", "args": ["server.py"]}
        ]
        
        config = LegacyMCPConfig(servers=servers)
        
        self.assertEqual(len(config.servers), 2)
        self.assertEqual(config.servers[0]["name"], "test-server")
        self.assertEqual(config.servers[1]["name"], "another-server")


class TestMigrationResult(unittest.TestCase):
    """Test MigrationResult model"""
    
    def test_initialization(self):
        """Test result initialization"""
        result = MigrationResult(success=True, migrated_servers=5, failed_servers=1)
        
        self.assertTrue(result.success)
        self.assertEqual(result.migrated_servers, 5)
        self.assertEqual(result.failed_servers, 1)
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.errors, [])
        self.assertIsNone(result.backup_path)
        self.assertIsNotNone(result.migration_timestamp)


class TestConfigurationMigrator(unittest.TestCase):
    """Test ConfigurationMigrator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.migrator = ConfigurationMigrator()
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test migrator initialization"""
        # Default config
        migrator = ConfigurationMigrator()
        self.assertIsInstance(migrator.config, MigrationConfig)
        
        # Custom config
        custom_config = MigrationConfig(backup_enabled=False)
        migrator = ConfigurationMigrator(custom_config)
        self.assertFalse(migrator.config.backup_enabled)
    
    def test_create_backup(self):
        """Test backup creation"""
        # Create test config file
        config_file = self.temp_path / "test_config.json"
        config_data = {"test": "data"}
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        # Create backup
        backup_path = self.migrator._create_backup(str(config_file))
        
        # Verify backup exists and contains correct data
        self.assertTrue(Path(backup_path).exists())
        with open(backup_path, 'r') as f:
            backup_data = json.load(f)
        self.assertEqual(backup_data, config_data)
    
    def test_load_legacy_config_json(self):
        """Test loading legacy JSON configuration"""
        # Create test JSON config
        config_data = {
            "servers": [{"name": "test", "command": "node"}],
            "timeout_seconds": 45,
            "enable_introspection": True
        }
        config_file = self.temp_path / "legacy.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        # Load configuration
        legacy_config = self.migrator._load_legacy_config(str(config_file))
        
        self.assertIsInstance(legacy_config, LegacyMCPConfig)
        self.assertEqual(len(legacy_config.servers), 1)
        self.assertEqual(legacy_config.timeout_seconds, 45)
        self.assertTrue(legacy_config.enable_introspection)
    
    def test_load_legacy_config_yaml(self):
        """Test loading legacy YAML configuration"""
        # Create test YAML config
        config_content = """
servers:
  - name: test
    command: node
timeout_seconds: 45
enable_introspection: true
"""
        config_file = self.temp_path / "legacy.yml"
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Mock yaml module
        with patch('yaml.safe_load') as mock_yaml:
            mock_yaml.return_value = {
                "servers": [{"name": "test", "command": "node"}],
                "timeout_seconds": 45,
                "enable_introspection": True
            }
            
            legacy_config = self.migrator._load_legacy_config(str(config_file))
            
            self.assertIsInstance(legacy_config, LegacyMCPConfig)
            self.assertEqual(len(legacy_config.servers), 1)
            self.assertEqual(legacy_config.timeout_seconds, 45)
    
    def test_detect_transport_type(self):
        """Test transport type detection"""
        # Explicit transport type
        config = {"transport": "sse"}
        self.assertEqual(self.migrator._detect_transport_type(config), "sse")
        
        # Stdio detection
        config = {"command": "node", "args": ["server.js"]}
        self.assertEqual(self.migrator._detect_transport_type(config), "stdio")
        
        # SSE detection
        config = {"url": "http://localhost:3000"}
        self.assertEqual(self.migrator._detect_transport_type(config), "sse")
        
        # HTTP detection
        config = {"http": {"url": "http://localhost:8080"}}
        self.assertEqual(self.migrator._detect_transport_type(config), "http")
        
        # Default fallback
        config = {}
        self.assertEqual(self.migrator._detect_transport_type(config), "stdio")
    
    def test_migrate_server_config(self):
        """Test individual server configuration migration"""
        server_config = {
            "name": "test-server",
            "command": "node",
            "args": ["server.js"],
            "env": {"NODE_ENV": "production"},
            "cwd": "/app",
            "enabled": True
        }
        
        migrated = self.migrator._migrate_server_config(server_config)
        
        self.assertEqual(migrated["name"], "test-server")
        self.assertEqual(migrated["command"], "node")
        self.assertEqual(migrated["args"], ["server.js"])
        self.assertEqual(migrated["transport_type"], "stdio")
        self.assertEqual(migrated["env"], {"NODE_ENV": "production"})
        self.assertEqual(migrated["working_directory"], "/app")
        self.assertTrue(migrated["enabled"])
    
    def test_migrate_config_structure(self):
        """Test complete configuration structure migration"""
        legacy_config = LegacyMCPConfig(
            servers=[
                {"name": "server1", "command": "node", "args": ["s1.js"]},
                {"name": "server2", "command": "python", "args": ["s2.py"]}
            ],
            timeout_seconds=60,
            max_retries=5,
            enable_introspection=True
        )
        
        result = MigrationResult(success=False, migrated_servers=0, failed_servers=0)
        migrated = self.migrator._migrate_config_structure(legacy_config, result)
        
        # Check structure
        self.assertIn("mcp_introspection", migrated)
        mcp_config = migrated["mcp_introspection"]
        
        # Check basic settings
        self.assertTrue(mcp_config["enabled"])
        self.assertEqual(mcp_config["timeout_seconds"], 60)
        self.assertEqual(mcp_config["max_retries"], 5)
        self.assertTrue(mcp_config["use_python_client"])
        
        # Check servers
        self.assertEqual(len(mcp_config["servers"]), 2)
        self.assertEqual(mcp_config["servers"][0]["name"], "server1")
        self.assertEqual(mcp_config["servers"][1]["name"], "server2")
        
        # Check new sections
        self.assertIn("transport", mcp_config)
        self.assertIn("discovery", mcp_config)
        self.assertIn("risk_analysis", mcp_config)
        
        # Check result
        self.assertEqual(result.migrated_servers, 2)
        self.assertEqual(result.failed_servers, 0)
    
    def test_validate_migrated_config(self):
        """Test migrated configuration validation"""
        # Valid configuration
        valid_config = {
            "mcp_introspection": {
                "enabled": True,
                "timeout_seconds": 30,
                "servers": [
                    {"name": "test", "transport_type": "stdio", "command": "node"}
                ]
            }
        }
        
        errors = self.migrator._validate_migrated_config(valid_config)
        self.assertEqual(errors, [])
        
        # Invalid configuration - missing section
        invalid_config = {}
        errors = self.migrator._validate_migrated_config(invalid_config)
        self.assertIn("Missing mcp_introspection section", errors)
        
        # Invalid configuration - missing required field
        invalid_config = {"mcp_introspection": {"enabled": True}}
        errors = self.migrator._validate_migrated_config(invalid_config)
        self.assertTrue(any("Missing required field" in error for error in errors))
    
    def test_validate_server_config(self):
        """Test server configuration validation"""
        # Valid server
        valid_server = {"name": "test", "transport_type": "stdio", "command": "node"}
        errors = self.migrator._validate_server_config(valid_server, 0)
        self.assertEqual(errors, [])
        
        # Missing required fields
        invalid_server = {}
        errors = self.migrator._validate_server_config(invalid_server, 0)
        self.assertTrue(any("Missing required field" in error for error in errors))
        
        # Invalid transport type
        invalid_server = {"name": "test", "transport_type": "invalid"}
        errors = self.migrator._validate_server_config(invalid_server, 0)
        self.assertTrue(any("Invalid transport type" in error for error in errors))
        
        # Stdio without command
        invalid_server = {"name": "test", "transport_type": "stdio"}
        errors = self.migrator._validate_server_config(invalid_server, 0)
        self.assertTrue(any("stdio transport requires 'command'" in error for error in errors))
    
    def test_save_migrated_config_json(self):
        """Test saving migrated configuration as JSON"""
        config = {"test": "data"}
        output_path = self.temp_path / "output.json"
        
        self.migrator._save_migrated_config(config, str(output_path))
        
        # Verify file was created and contains correct data
        self.assertTrue(output_path.exists())
        with open(output_path, 'r') as f:
            saved_data = json.load(f)
        self.assertEqual(saved_data, config)
    
    def test_save_migrated_config_yaml(self):
        """Test saving migrated configuration as YAML"""
        config = {"test": "data"}
        output_path = self.temp_path / "output.yml"
        
        with patch('yaml.dump') as mock_yaml:
            self.migrator._save_migrated_config(config, str(output_path))
            mock_yaml.assert_called_once()
    
    def test_migrate_configuration_success(self):
        """Test successful configuration migration"""
        # Create legacy config file
        legacy_config = {
            "servers": [{"name": "test", "command": "node"}],
            "enable_introspection": True
        }
        legacy_file = self.temp_path / "legacy.json"
        with open(legacy_file, 'w') as f:
            json.dump(legacy_config, f)
        
        # Migrate configuration
        output_file = self.temp_path / "migrated.json"
        result = self.migrator.migrate_configuration(str(legacy_file), str(output_file))
        
        # Check result
        self.assertTrue(result.success)
        self.assertEqual(result.migrated_servers, 1)
        self.assertEqual(result.failed_servers, 0)
        self.assertIsNotNone(result.backup_path)
        
        # Check output file exists
        self.assertTrue(output_file.exists())
    
    def test_migrate_configuration_failure(self):
        """Test configuration migration failure"""
        # Try to migrate non-existent file
        result = self.migrator.migrate_configuration("non_existent.json")
        
        self.assertFalse(result.success)
        self.assertTrue(len(result.errors) > 0)


class TestConfigurationValidator(unittest.TestCase):
    """Test ConfigurationValidator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.validator = ConfigurationValidator()
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_validate_valid_configuration(self):
        """Test validation of valid configuration"""
        valid_config = {
            "mcp_introspection": {
                "enabled": True,
                "servers": [
                    {"name": "test", "transport_type": "stdio", "command": "node"}
                ]
            }
        }
        
        config_file = self.temp_path / "valid.json"
        with open(config_file, 'w') as f:
            json.dump(valid_config, f)
        
        is_valid, errors = self.validator.validate_configuration(str(config_file))
        
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])
    
    def test_validate_invalid_configuration(self):
        """Test validation of invalid configuration"""
        invalid_config = {
            "mcp_introspection": {
                "enabled": "not_boolean",  # Should be boolean
                "servers": "not_list"      # Should be list
            }
        }
        
        config_file = self.temp_path / "invalid.json"
        with open(config_file, 'w') as f:
            json.dump(invalid_config, f)
        
        is_valid, errors = self.validator.validate_configuration(str(config_file))
        
        self.assertFalse(is_valid)
        self.assertTrue(len(errors) > 0)
    
    def test_validate_missing_section(self):
        """Test validation with missing mcp_introspection section"""
        config = {"other_section": {}}
        
        config_file = self.temp_path / "missing.json"
        with open(config_file, 'w') as f:
            json.dump(config, f)
        
        is_valid, errors = self.validator.validate_configuration(str(config_file))
        
        self.assertFalse(is_valid)
        self.assertTrue(any("Missing 'mcp_introspection' section" in error for error in errors))
    
    def test_validate_server_configuration(self):
        """Test server configuration validation"""
        # Valid server
        valid_server = {"name": "test", "transport_type": "stdio", "command": "node"}
        errors = self.validator._validate_server_configuration(valid_server, 0)
        self.assertEqual(errors, [])
        
        # Invalid server - missing name
        invalid_server = {"transport_type": "stdio", "command": "node"}
        errors = self.validator._validate_server_configuration(invalid_server, 0)
        self.assertTrue(any("Missing required field 'name'" in error for error in errors))
        
        # Invalid server - invalid transport
        invalid_server = {"name": "test", "transport_type": "invalid"}
        errors = self.validator._validate_server_configuration(invalid_server, 0)
        self.assertTrue(any("Invalid transport type" in error for error in errors))
        
        # SSE server without URL
        invalid_server = {"name": "test", "transport_type": "sse"}
        errors = self.validator._validate_server_configuration(invalid_server, 0)
        self.assertTrue(any("sse transport requires 'url'" in error for error in errors))


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_migrate_legacy_configuration(self):
        """Test migrate_legacy_configuration convenience function"""
        # Create legacy config
        legacy_config = {
            "servers": [{"name": "test", "command": "node"}],
            "enable_introspection": True
        }
        legacy_file = self.temp_path / "legacy.json"
        with open(legacy_file, 'w') as f:
            json.dump(legacy_config, f)
        
        # Migrate using convenience function
        result = migrate_legacy_configuration(str(legacy_file))
        
        self.assertIsInstance(result, MigrationResult)
        self.assertTrue(result.success)
    
    def test_validate_configuration(self):
        """Test validate_configuration convenience function"""
        # Create valid config
        valid_config = {
            "mcp_introspection": {
                "enabled": True,
                "servers": [{"name": "test", "transport_type": "stdio", "command": "node"}]
            }
        }
        config_file = self.temp_path / "valid.json"
        with open(config_file, 'w') as f:
            json.dump(valid_config, f)
        
        # Validate using convenience function
        is_valid, errors = validate_configuration(str(config_file))
        
        self.assertTrue(is_valid)
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()