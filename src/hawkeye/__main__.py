#!/usr/bin/env python3
"""
Main entry point for the HawkEye package when executed as a module.

This allows the package to be run with:
    python -m hawkeye

The main CLI interface is delegated to the CLI module.
"""

import sys

if __name__ == "__main__":
    from .cli.main import cli
    cli() 