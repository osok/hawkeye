#!/usr/bin/env python3
"""
HawkEye - Hidden Application Weaknesses & Key Entry-point Yielding Evaluator

Main application entry point for the HawkEye security reconnaissance tool.
This script serves as the primary interface for running HawkEye from the command line.
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from hawkeye.cli.main import cli

if __name__ == "__main__":
    cli() 