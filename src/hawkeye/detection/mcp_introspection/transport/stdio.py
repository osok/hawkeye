"""
Stdio Transport Handler

Implementation of MCP transport handler for local servers that communicate
via standard input/output (stdio).
"""

import asyncio
import logging
import subprocess
import signal
import os
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .base import BaseTransportHandler, ConnectionFailedError, TransportError


class StdioTransportHandler(BaseTransportHandler):
    """
    Transport handler for MCP servers using stdio communication.
    
    This handler manages local MCP server processes that communicate
    via standard input/output streams.
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the stdio transport handler.
        
        Args:
            timeout: Connection timeout in seconds
            max_retries: Maximum number of connection retries
            retry_delay: Delay between retries in seconds
            logger: Logger instance for this handler
        """
        super().__init__(timeout, max_retries, retry_delay, logger)
        self._process: Optional[subprocess.Popen] = None
        self._server_params: Optional[StdioServerParameters] = None
    
    async def _create_session(self, **kwargs) -> ClientSession:
        """
        Create and return a new MCP client session for stdio transport.
        
        Args:
            command: Command to start the MCP server
            args: Arguments for the server command
            env: Environment variables for the server process
            cwd: Working directory for the server process
            
        Returns:
            ClientSession: Configured MCP client session
            
        Raises:
            ConnectionFailedError: If session creation fails
        """
        command = kwargs.get('command')
        args = kwargs.get('args', [])
        env = kwargs.get('env', {})
        cwd = kwargs.get('cwd')
        
        if not command:
            raise ConnectionFailedError("Command is required for stdio transport")
        
        try:
            # Prepare server parameters
            self._server_params = StdioServerParameters(
                command=command,
                args=args,
                env=env if env else None
            )
            
            self.logger.debug(f"Starting MCP server: {command} {' '.join(args)}")
            
            # Create stdio client session
            session = await stdio_client(self._server_params)
            
            self.logger.info(f"Successfully created stdio session for: {command}")
            return session
            
        except Exception as e:
            self.logger.error(f"Failed to create stdio session: {e}")
            raise ConnectionFailedError(f"Failed to create stdio session: {e}")
    
    async def _cleanup_session(self) -> None:
        """
        Clean up the current session and terminate the server process.
        """
        try:
            if self._session:
                # Close the session
                await self._session.close()
                self.logger.debug("Closed MCP session")
            
            # The stdio client should handle process cleanup automatically,
            # but we can add additional cleanup if needed
            
        except Exception as e:
            self.logger.error(f"Error during stdio session cleanup: {e}")
    
    def _validate_command(self, command: str, args: List[str]) -> bool:
        """
        Validate that the command and arguments are safe to execute.
        
        Args:
            command: Command to validate
            args: Arguments to validate
            
        Returns:
            bool: True if command is valid and safe
        """
        try:
            # Check if command exists and is executable
            if not command:
                return False
            
            # For security, we should validate the command path
            command_path = Path(command)
            
            # If it's a relative path, check if it exists in PATH
            if not command_path.is_absolute():
                # Check if command exists in PATH
                import shutil
                if not shutil.which(command):
                    self.logger.warning(f"Command not found in PATH: {command}")
                    return False
            else:
                # For absolute paths, check if file exists and is executable
                if not command_path.exists():
                    self.logger.warning(f"Command file does not exist: {command}")
                    return False
                
                if not os.access(command_path, os.X_OK):
                    self.logger.warning(f"Command is not executable: {command}")
                    return False
            
            # Basic validation of arguments (avoid obviously dangerous patterns)
            dangerous_patterns = [';', '&&', '||', '|', '>', '<', '`', '$']
            for arg in args:
                if any(pattern in arg for pattern in dangerous_patterns):
                    self.logger.warning(f"Potentially dangerous argument detected: {arg}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating command: {e}")
            return False
    
    async def connect(self, **kwargs) -> None:
        """
        Establish connection to the MCP server via stdio.
        
        Args:
            command: Command to start the MCP server
            args: Arguments for the server command
            env: Environment variables for the server process
            cwd: Working directory for the server process
            validate_command: Whether to validate command safety (default: True)
            
        Raises:
            ConnectionFailedError: If connection fails
        """
        command = kwargs.get('command')
        args = kwargs.get('args', [])
        validate_command = kwargs.get('validate_command', True)
        
        if validate_command and not self._validate_command(command, args):
            raise ConnectionFailedError(f"Command validation failed: {command}")
        
        await super().connect(**kwargs)
    
    def get_server_info(self) -> Dict[str, Any]:
        """
        Get information about the connected server process.
        
        Returns:
            Dict containing server process information
        """
        if not self._server_params:
            return {}
        
        return {
            'transport_type': 'stdio',
            'command': self._server_params.command,
            'args': self._server_params.args,
            'env': self._server_params.env,
            'connected': self.is_connected,
        }
    
    async def health_check(self) -> bool:
        """
        Perform a health check on the stdio connection.
        
        Returns:
            bool: True if connection is healthy
        """
        if not self.is_connected:
            return False
        
        try:
            # Try to ping the server or list capabilities
            if hasattr(self._session, 'initialize'):
                # Try a simple initialize call to check if server is responsive
                await asyncio.wait_for(
                    self._session.initialize(),
                    timeout=5.0
                )
                return True
            
            return True
            
        except Exception as e:
            self.logger.warning(f"Health check failed: {e}")
            return False
    
    def __repr__(self) -> str:
        """String representation of the handler."""
        if self._server_params:
            return f"StdioTransportHandler(command='{self._server_params.command}')"
        return "StdioTransportHandler(not configured)" 