#!/usr/bin/env python3
"""
HawkEye - Hidden Application Weaknesses & Key Entry-point Yielding Evaluator
Setup script for package distribution
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages

# Ensure we're using Python 3.8+
if sys.version_info < (3, 8):
    sys.exit("HawkEye requires Python 3.8 or higher")

# Get the long description from README
here = Path(__file__).parent.resolve()
long_description = (here / "README.md").read_text(encoding="utf-8")

# Read requirements from requirements.txt
def read_requirements(filename):
    """Read requirements from file and return as list"""
    requirements_file = here / filename
    if requirements_file.exists():
        with open(requirements_file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

# Get version from package
def get_version():
    """Get version from package __init__.py"""
    version_file = here / "src" / "hawkeye" / "__init__.py"
    if version_file.exists():
        with open(version_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"').strip("'")
    return "1.0.0"

# Package metadata
PACKAGE_NAME = "hawkeye-security"
VERSION = get_version()
DESCRIPTION = "MCP Security Reconnaissance Tool - Hidden Application Weaknesses & Key Entry-point Yielding Evaluator"
AUTHOR = "HawkEye Security Team"
AUTHOR_EMAIL = "security@hawkeye-project.org"
URL = "https://github.com/yourusername/hawkeye"
LICENSE = "MIT"

# Classifiers for PyPI
CLASSIFIERS = [
    # Development Status
    "Development Status :: 5 - Production/Stable",
    
    # Intended Audience
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "Intended Audience :: Developers",
    
    # Topic
    "Topic :: Security",
    "Topic :: System :: Networking :: Monitoring",
    "Topic :: System :: Systems Administration",
    "Topic :: Software Development :: Testing",
    
    # License
    "License :: OSI Approved :: MIT License",
    
    # Programming Language
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    
    # Operating System
    "Operating System :: OS Independent",
    "Operating System :: POSIX :: Linux",
    "Operating System :: MacOS",
    "Operating System :: Microsoft :: Windows",
    
    # Environment
    "Environment :: Console",
    "Environment :: No Input/Output (Daemon)",
]

# Keywords for PyPI search
KEYWORDS = [
    "security", "reconnaissance", "scanning", "mcp", "vulnerability",
    "network", "assessment", "penetration-testing", "security-audit",
    "compliance", "risk-assessment", "cybersecurity"
]

# Project URLs
PROJECT_URLS = {
    "Homepage": URL,
    "Documentation": f"{URL}/docs",
    "Source": URL,
    "Tracker": f"{URL}/issues",
    "Security": f"{URL}/security",
    "Changelog": f"{URL}/blob/main/CHANGELOG.md",
}

# Entry points for console scripts
ENTRY_POINTS = {
    "console_scripts": [
        "hawkeye=hawkeye.cli.main:main",
        "hawkeye-scan=hawkeye.cli.scan_commands:scan_main",
        "hawkeye-detect=hawkeye.cli.detect_commands:detect_main",
        "hawkeye-report=hawkeye.cli.report_commands:report_main",
    ],
}

# Package data to include
PACKAGE_DATA = {
    "hawkeye": [
        "config/*.yaml",
        "config/*.json",
        "reporting/templates/*.html",
        "reporting/templates/*.css",
        "reporting/templates/*.js",
        "data/*.json",
        "data/*.yaml",
    ],
}

# Additional data files
DATA_FILES = [
    ("share/hawkeye/docs", [
        "docs/user_manual.md",
        "docs/security_guidelines.md",
        "docs/troubleshooting.md",
        "docs/installation.md",
    ]),
    ("share/hawkeye/examples", [
        "examples/basic_scan.py",
        "examples/enterprise_scan.py",
        "examples/compliance_scan.py",
    ]),
    ("etc/hawkeye", [
        "config/hawkeye.yaml.example",
    ]),
]

# Read requirements
install_requires = read_requirements("requirements.txt")
extras_require = {
    "dev": read_requirements("requirements-dev.txt"),
    "test": [
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "pytest-mock>=3.10.0",
        "pytest-asyncio>=0.21.0",
        "coverage>=7.0.0",
    ],
    "docs": [
        "sphinx>=5.0.0",
        "sphinx-rtd-theme>=1.2.0",
        "myst-parser>=1.0.0",
        "sphinx-autodoc-typehints>=1.19.0",
    ],
    "performance": [
        "uvloop>=0.17.0; sys_platform != 'win32'",
        "orjson>=3.8.0",
        "msgpack>=1.0.0",
    ],
    "enterprise": [
        "redis>=4.5.0",
        "celery>=5.2.0",
        "sqlalchemy>=2.0.0",
        "alembic>=1.10.0",
    ],
}

# All extras combined
extras_require["all"] = list(set(sum(extras_require.values(), [])))

setup(
    # Basic package information
    name=PACKAGE_NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # Author information
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    maintainer=AUTHOR,
    maintainer_email=AUTHOR_EMAIL,
    
    # URLs
    url=URL,
    project_urls=PROJECT_URLS,
    
    # License
    license=LICENSE,
    
    # Package discovery
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data=PACKAGE_DATA,
    data_files=DATA_FILES,
    include_package_data=True,
    
    # Dependencies
    python_requires=">=3.8",
    install_requires=install_requires,
    extras_require=extras_require,
    
    # Entry points
    entry_points=ENTRY_POINTS,
    
    # Metadata for PyPI
    classifiers=CLASSIFIERS,
    keywords=", ".join(KEYWORDS),
    
    # Options
    zip_safe=False,
    platforms=["any"],
    
    # Additional metadata
    options={
        "bdist_wheel": {
            "universal": False,
        },
        "egg_info": {
            "tag_build": "",
            "tag_date": False,
        },
    },
    
    # Command classes for custom commands
    cmdclass={},
)

# Post-installation message
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🦅 HawkEye Installation Complete!")
    print("="*60)
    print("Thank you for installing HawkEye - MCP Security Reconnaissance Tool")
    print("\nQuick Start:")
    print("  hawkeye --help                    # Show help")
    print("  hawkeye scan --target 127.0.0.1  # Test scan")
    print("  hawkeye config init               # Initialize config")
    print("\nDocumentation:")
    print("  User Manual: docs/user_manual.md")
    print("  Security Guidelines: docs/security_guidelines.md")
    print("  Installation Guide: docs/installation.md")
    print("\nSecurity Notice:")
    print("  ⚠️  Always obtain proper authorization before scanning")
    print("  📖 Read security guidelines before use")
    print("  🔒 Use responsibly and ethically")
    print("\nSupport:")
    print(f"  🐛 Issues: {URL}/issues")
    print(f"  📚 Docs: {URL}/docs")
    print(f"  🔐 Security: {AUTHOR_EMAIL}")
    print("="*60) 