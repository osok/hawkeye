#!/usr/bin/env python3
"""
HawkEye - Hidden Application Weaknesses & Key Entry-point Yielding Evaluator

Main application entry point for the HawkEye MCP security reconnaissance tool.
This script provides the primary command-line interface for all HawkEye operations.

Usage:
    python application.py [COMMAND] [OPTIONS]
    
Commands:
    scan        Network scanning operations
    detect      MCP-specific detection and analysis
    assess      Security assessment and risk analysis
    report      Report generation and output formatting
    config      Configuration file management
    info        Display system information
    
Examples:
    python application.py scan target -t 192.168.1.0/24
    python application.py detect local
    python application.py report generate -i results.json -o report.html -f html
    python application.py config init
"""

import sys
import os
from pathlib import Path

# Add the src directory to Python path for imports
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

try:
    from hawkeye.cli.main import cli
    from hawkeye.utils import get_logger
    from hawkeye.exceptions import HawkEyeError
except ImportError as e:
    print(f"Error importing HawkEye modules: {e}")
    print("Please ensure you're running from the project root directory.")
    sys.exit(1)


def main():
    """Main application entry point."""
    try:
        # Initialize logging
        logger = get_logger("hawkeye.main")
        logger.info("HawkEye application starting")
        
        # Run CLI
        cli()
        
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
        sys.exit(130)  # Standard exit code for Ctrl+C
        
    except HawkEyeError as e:
        print(f"❌ HawkEye Error: {e.message}")
        if e.details:
            print(f"Details: {e.details}")
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("Run with --verbose for more details")
        sys.exit(1)


if __name__ == "__main__":
    main()