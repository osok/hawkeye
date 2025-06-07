"""
Node.js Process Enumeration for MCP Detection.

This module provides functionality to enumerate running Node.js processes
and identify potential MCP server instances based on process characteristics.
"""

import os
import time
from typing import List, Dict, Optional, Any
import psutil

from .base import (
    MCPDetector,
    DetectionResult,
    DetectionMethod,
    ProcessInfo,
    MCPServerInfo,
    TransportType,
    MCPServerType,
    ProcessDetectionError,
)


class ProcessEnumerator(MCPDetector):
    """Detector for identifying MCP servers through process enumeration."""
    
    def __init__(self, settings=None):
        """Initialize the process enumerator."""
        super().__init__(settings)
        self.mcp_keywords = [
            'mcp',
            'model-context-protocol',
            '@modelcontextprotocol',
            'mcp-server',
            'mcp-client',
        ]
        self.node_executables = [
            'node',
            'nodejs',
            'npm',
            'npx',
        ]
    
    def get_detection_method(self) -> DetectionMethod:
        """Get the detection method."""
        return DetectionMethod.PROCESS_ENUMERATION
    
    def detect(self, target_host: str = "localhost", **kwargs) -> DetectionResult:
        """
        Detect MCP servers through process enumeration.
        
        Args:
            target_host: Target host (only localhost supported for process enumeration)
            **kwargs: Additional parameters (include_env, detailed_analysis)
            
        Returns:
            DetectionResult: Result of the detection operation
        """
        start_time = time.time()
        
        # Process enumeration only works on localhost
        if target_host not in ['localhost', '127.0.0.1', '::1']:
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error="Process enumeration only supported on localhost",
                scan_duration=time.time() - start_time
            )
        
        try:
            # Get configuration options
            include_env = kwargs.get('include_env', False)
            detailed_analysis = kwargs.get('detailed_analysis', True)
            
            # Enumerate all processes
            processes = self._enumerate_processes(include_env, detailed_analysis)
            
            # Filter for Node.js processes
            node_processes = self._filter_node_processes(processes)
            
            # Analyze for MCP indicators
            mcp_processes = self._analyze_mcp_processes(node_processes)
            
            if mcp_processes:
                # Create MCP server info from the most promising process
                best_process = max(mcp_processes, key=lambda p: self._calculate_confidence(p))
                mcp_server = self._create_mcp_server_info(best_process, target_host)
                confidence = self._calculate_confidence(best_process)
                
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    mcp_server=mcp_server,
                    confidence=confidence,
                    raw_data={
                        'total_processes': len(processes),
                        'node_processes': len(node_processes),
                        'mcp_processes': len(mcp_processes),
                        'all_mcp_processes': [self._process_to_dict(p) for p in mcp_processes]
                    },
                    scan_duration=time.time() - start_time
                )
            else:
                return DetectionResult(
                    target_host=target_host,
                    detection_method=self.get_detection_method(),
                    success=True,
                    confidence=0.0,
                    raw_data={
                        'total_processes': len(processes),
                        'node_processes': len(node_processes),
                        'mcp_processes': 0,
                    },
                    scan_duration=time.time() - start_time
                )
                
        except Exception as e:
            self.logger.error(f"Process enumeration failed: {e}")
            return DetectionResult(
                target_host=target_host,
                detection_method=self.get_detection_method(),
                success=False,
                error=str(e),
                scan_duration=time.time() - start_time
            )
    
    def _enumerate_processes(self, include_env: bool = False, detailed: bool = True) -> List[ProcessInfo]:
        """
        Enumerate all running processes.
        
        Args:
            include_env: Whether to include environment variables
            detailed: Whether to include detailed process information
            
        Returns:
            List[ProcessInfo]: List of process information
        """
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd', 'username', 'create_time']):
            try:
                pinfo = proc.info
                
                # Get additional details if requested
                env_vars = {}
                cpu_percent = None
                memory_percent = None
                
                if detailed:
                    try:
                        cpu_percent = proc.cpu_percent()
                        memory_percent = proc.memory_percent()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                if include_env:
                    try:
                        env_vars = proc.environ()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                process_info = ProcessInfo(
                    pid=pinfo['pid'],
                    name=pinfo['name'] or '',
                    cmdline=pinfo['cmdline'] or [],
                    cwd=pinfo['cwd'],
                    env_vars=env_vars,
                    user=pinfo['username'],
                    create_time=pinfo['create_time'],
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                )
                
                processes.append(process_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Skip processes we can't access
                continue
            except Exception as e:
                self.logger.debug(f"Error processing PID {proc.pid}: {e}")
                continue
        
        self.logger.info(f"Enumerated {len(processes)} processes")
        return processes
    
    def _filter_node_processes(self, processes: List[ProcessInfo]) -> List[ProcessInfo]:
        """
        Filter processes to find Node.js related processes.
        
        Args:
            processes: List of all processes
            
        Returns:
            List[ProcessInfo]: List of Node.js processes
        """
        node_processes = []
        
        for process in processes:
            if process.is_node_process:
                node_processes.append(process)
                continue
            
            # Check for NPX processes
            if any('npx' in arg.lower() for arg in process.cmdline):
                node_processes.append(process)
                continue
            
            # Check for npm scripts that might run Node.js
            cmdline_str = ' '.join(process.cmdline).lower()
            if 'npm' in cmdline_str and ('start' in cmdline_str or 'run' in cmdline_str):
                node_processes.append(process)
        
        self.logger.info(f"Found {len(node_processes)} Node.js processes")
        return node_processes
    
    def _analyze_mcp_processes(self, node_processes: List[ProcessInfo]) -> List[ProcessInfo]:
        """
        Analyze Node.js processes for MCP indicators.
        
        Args:
            node_processes: List of Node.js processes
            
        Returns:
            List[ProcessInfo]: List of processes with MCP indicators
        """
        mcp_processes = []
        
        for process in node_processes:
            if self._has_mcp_indicators(process):
                mcp_processes.append(process)
        
        self.logger.info(f"Found {len(mcp_processes)} processes with MCP indicators")
        return mcp_processes
    
    def _has_mcp_indicators(self, process: ProcessInfo) -> bool:
        """
        Check if a process has MCP-related indicators.
        
        Args:
            process: Process information
            
        Returns:
            bool: True if process has MCP indicators
        """
        # Check command line arguments
        cmdline_str = ' '.join(process.cmdline).lower()
        
        # Direct MCP keyword matches
        for keyword in self.mcp_keywords:
            if keyword in cmdline_str:
                return True
        
        # Check for common MCP server patterns
        mcp_patterns = [
            'server.js',
            'mcp.js',
            'index.js',  # Common entry point
        ]
        
        for pattern in mcp_patterns:
            if pattern in cmdline_str:
                # Additional validation for generic patterns
                if pattern == 'index.js':
                    # Only consider if in a directory that might contain MCP code
                    if process.cwd and any(keyword in process.cwd.lower() 
                                         for keyword in ['mcp', 'server', 'tool']):
                        return True
                else:
                    return True
        
        # Check environment variables for MCP configuration
        for var_name, var_value in process.env_vars.items():
            if any(keyword in var_name.lower() for keyword in self.mcp_keywords):
                return True
            if any(keyword in var_value.lower() for keyword in self.mcp_keywords):
                return True
        
        # Check working directory
        if process.cwd:
            cwd_lower = process.cwd.lower()
            if any(keyword in cwd_lower for keyword in self.mcp_keywords):
                return True
        
        return False
    
    def _calculate_confidence(self, process: ProcessInfo) -> float:
        """
        Calculate confidence score for MCP detection.
        
        Args:
            process: Process information
            
        Returns:
            float: Confidence score (0.0 to 1.0)
        """
        confidence = 0.0
        cmdline_str = ' '.join(process.cmdline).lower()
        
        # Direct MCP package references (high confidence)
        if '@modelcontextprotocol' in cmdline_str:
            confidence += 0.8
        elif 'mcp-server' in cmdline_str or 'mcp-client' in cmdline_str:
            confidence += 0.7
        elif 'mcp' in cmdline_str:
            confidence += 0.5
        
        # Server-like patterns
        if 'server.js' in cmdline_str or 'server.ts' in cmdline_str:
            confidence += 0.3
        
        # NPX execution (common for MCP tools)
        if any('npx' in arg for arg in process.cmdline):
            confidence += 0.2
        
        # Environment variables
        for var_name, var_value in process.env_vars.items():
            if 'mcp' in var_name.lower() or 'mcp' in var_value.lower():
                confidence += 0.2
                break
        
        # Working directory indicators
        if process.cwd and 'mcp' in process.cwd.lower():
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _create_mcp_server_info(self, process: ProcessInfo, host: str) -> MCPServerInfo:
        """
        Create MCP server info from process information.
        
        Args:
            process: Process information
            host: Target host
            
        Returns:
            MCPServerInfo: MCP server information
        """
        # Determine server type
        server_type = MCPServerType.STANDALONE
        if any('npx' in arg for arg in process.cmdline):
            server_type = MCPServerType.NPX_PACKAGE
        
        # Try to determine transport type from command line
        transport_type = TransportType.UNKNOWN
        cmdline_str = ' '.join(process.cmdline).lower()
        
        if 'stdio' in cmdline_str:
            transport_type = TransportType.STDIO
        elif any(port_indicator in cmdline_str for port_indicator in ['--port', '-p', 'port=']):
            transport_type = TransportType.HTTP
        elif 'websocket' in cmdline_str or 'ws' in cmdline_str:
            transport_type = TransportType.WEBSOCKET
        
        # Extract port if available
        port = self._extract_port_from_cmdline(process.cmdline)
        
        return MCPServerInfo(
            host=host,
            port=port,
            transport_type=transport_type,
            server_type=server_type,
            process_info=process,
        )
    
    def _extract_port_from_cmdline(self, cmdline: List[str]) -> Optional[int]:
        """
        Extract port number from command line arguments.
        
        Args:
            cmdline: Command line arguments
            
        Returns:
            Optional[int]: Port number if found
        """
        for i, arg in enumerate(cmdline):
            # Check for --port=XXXX or -p=XXXX
            if '=' in arg and any(prefix in arg.lower() for prefix in ['--port=', '-p=']):
                try:
                    port_str = arg.split('=')[1]
                    return int(port_str)
                except (ValueError, IndexError):
                    continue
            
            # Check for --port XXXX or -p XXXX
            if arg.lower() in ['--port', '-p'] and i + 1 < len(cmdline):
                try:
                    return int(cmdline[i + 1])
                except ValueError:
                    continue
        
        return None
    
    def _process_to_dict(self, process: ProcessInfo) -> Dict[str, Any]:
        """
        Convert process info to dictionary for raw data.
        
        Args:
            process: Process information
            
        Returns:
            Dict[str, Any]: Process information as dictionary
        """
        return {
            'pid': process.pid,
            'name': process.name,
            'cmdline': process.cmdline,
            'cwd': process.cwd,
            'user': process.user,
            'create_time': process.create_time,
            'cpu_percent': process.cpu_percent,
            'memory_percent': process.memory_percent,
            'is_node_process': process.is_node_process,
            'has_mcp_indicators': process.has_mcp_indicators,
        }
    
    def get_all_node_processes(self, include_env: bool = False) -> List[ProcessInfo]:
        """
        Get all Node.js processes without MCP filtering.
        
        Args:
            include_env: Whether to include environment variables
            
        Returns:
            List[ProcessInfo]: All Node.js processes
        """
        try:
            all_processes = self._enumerate_processes(include_env, detailed=True)
            return self._filter_node_processes(all_processes)
        except Exception as e:
            self.logger.error(f"Failed to enumerate Node.js processes: {e}")
            raise ProcessDetectionError(f"Process enumeration failed: {e}")
    
    def analyze_process_by_pid(self, pid: int, include_env: bool = True) -> Optional[ProcessInfo]:
        """
        Analyze a specific process by PID.
        
        Args:
            pid: Process ID
            include_env: Whether to include environment variables
            
        Returns:
            Optional[ProcessInfo]: Process information if accessible
        """
        try:
            proc = psutil.Process(pid)
            
            env_vars = {}
            if include_env:
                try:
                    env_vars = proc.environ()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
            
            process_info = ProcessInfo(
                pid=proc.pid,
                name=proc.name(),
                cmdline=proc.cmdline(),
                cwd=proc.cwd(),
                env_vars=env_vars,
                user=proc.username(),
                create_time=proc.create_time(),
                cpu_percent=proc.cpu_percent(),
                memory_percent=proc.memory_percent(),
            )
            
            return process_info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Cannot access process {pid}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error analyzing process {pid}: {e}")
            raise ProcessDetectionError(f"Process analysis failed: {e}") 