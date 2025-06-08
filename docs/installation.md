# 🚀 HawkEye Installation Guide
## Complete Setup and Deployment Instructions

### Version 1.0 

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Platform-Specific Installation](#platform-specific-installation)
4. [Docker Installation](#docker-installation)
5. [Development Setup](#development-setup)
6. [Configuration](#configuration)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)
9. [Uninstallation](#uninstallation)

---

## System Requirements

### Minimum Requirements

- **Operating System**: Linux, macOS, or Windows
- **Python**: Version 3.8 or higher
- **Memory**: 512MB RAM (2GB recommended for large scans)
- **Storage**: 100MB for installation, additional space for logs and results
- **Network**: Internet access for installation, target network access for scanning

### Recommended Requirements

- **Operating System**: Linux (Ubuntu 20.04+ or CentOS 8+)
- **Python**: Version 3.9 or higher
- **Memory**: 4GB RAM
- **Storage**: 1GB available space
- **CPU**: Multi-core processor for optimal performance
- **Network**: Gigabit network interface

### Supported Platforms

| Platform | Version | Status | Notes |
|----------|---------|--------|-------|
| Ubuntu | 18.04+ | ✅ Fully Supported | Recommended platform |
| Debian | 10+ | ✅ Fully Supported | |
| CentOS | 7+ | ✅ Fully Supported | |
| RHEL | 7+ | ✅ Fully Supported | |
| macOS | 10.15+ | ✅ Fully Supported | |
| Windows | 10+ | ⚠️ Limited Support | Some features may be limited |
| Docker | Any | ✅ Fully Supported | Recommended for containers |

---

## Quick Installation

### One-Line Installation

For most users, this single command will install HawkEye:

```bash
curl -sSL https://raw.githubusercontent.com/yourusername/hawkeye/main/install.sh | bash
```

### Manual Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python application.py --version
```

---

## Platform-Specific Installation

### Ubuntu/Debian

#### Prerequisites

```bash
# Update package list
sudo apt update

# Install required system packages
sudo apt install -y python3 python3-pip python3-venv git curl

# Install development tools (optional, for building some packages)
sudo apt install -y build-essential python3-dev libssl-dev libffi-dev
```

#### Installation Steps

```bash
# 1. Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Upgrade pip
pip install --upgrade pip setuptools wheel

# 4. Install HawkEye
pip install -r requirements.txt

# 5. Create configuration directory
mkdir -p ~/.hawkeye

# 6. Set up initial configuration
python application.py config init
```

#### System Service Setup (Optional)

```bash
# Create systemd service file
sudo tee /etc/systemd/system/hawkeye.service > /dev/null << 'EOF'
[Unit]
Description=HawkEye Security Scanner
After=network.target

[Service]
Type=simple
User=hawkeye
Group=hawkeye
WorkingDirectory=/opt/hawkeye
Environment=PATH=/opt/hawkeye/venv/bin
ExecStart=/opt/hawkeye/venv/bin/python application.py daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable hawkeye
sudo systemctl start hawkeye
```

### CentOS/RHEL

#### Prerequisites

```bash
# Install EPEL repository (CentOS 7)
sudo yum install -y epel-release

# Install required packages
sudo yum install -y python3 python3-pip git curl

# Install development tools
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3-devel openssl-devel libffi-devel
```

#### Installation Steps

```bash
# Follow the same steps as Ubuntu/Debian
# (The process is identical after prerequisites)
```

### macOS

#### Prerequisites

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.8+
brew install python@3.9

# Install Git (if not already installed)
brew install git
```

#### Installation Steps

```bash
# 1. Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# 2. Create virtual environment using Homebrew Python
/usr/local/bin/python3.9 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create configuration directory
mkdir -p ~/.hawkeye

# 5. Initialize configuration
python application.py config init
```

#### macOS-Specific Configuration

```bash
# Allow network scanning (may require admin password)
sudo dscl . -create /Groups/hawkeye
sudo dscl . -create /Groups/hawkeye PrimaryGroupID 1001
sudo dseditgroup -o edit -a $(whoami) -t user hawkeye

# Set up firewall rules (if needed)
sudo pfctl -f /etc/pf.conf
```

### Windows

#### Prerequisites

1. **Install Python 3.8+**:
   - Download from [python.org](https://www.python.org/downloads/)
   - During installation, check "Add Python to PATH"
   - Verify installation: `python --version`

2. **Install Git**:
   - Download from [git-scm.com](https://git-scm.com/download/win)
   - Use default installation options

#### Installation Steps

```cmd
REM 1. Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

REM 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

REM 3. Install dependencies
pip install -r requirements.txt

REM 4. Create configuration directory
mkdir %USERPROFILE%\.hawkeye

REM 5. Initialize configuration
python application.py config init
```

#### Windows-Specific Notes

- Some network scanning features may require administrator privileges
- Windows Defender may flag the tool as potentially unwanted software
- Consider adding HawkEye directory to Windows Defender exclusions

---

## Docker Installation

### Using Pre-built Image

```bash
# Pull the latest image
docker pull hawkeye/hawkeye:latest

# Run HawkEye
docker run -it --rm hawkeye/hawkeye:latest scan --target 192.168.1.0/24
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# Build Docker image
docker build -t hawkeye:local .

# Run container
docker run -it --rm hawkeye:local scan --target 192.168.1.0/24
```

### Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  hawkeye:
    build: .
    container_name: hawkeye
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - ./results:/app/results
    environment:
      - HAWKEYE_CONFIG=/app/config/hawkeye.yaml
    networks:
      - hawkeye-net
    restart: unless-stopped

  hawkeye-web:
    build:
      context: .
      dockerfile: Dockerfile.web
    container_name: hawkeye-web
    ports:
      - "8080:8080"
    depends_on:
      - hawkeye
    networks:
      - hawkeye-net

networks:
  hawkeye-net:
    driver: bridge
```

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f hawkeye

# Stop services
docker-compose down
```

### Kubernetes Deployment

```yaml
# hawkeye-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hawkeye
  labels:
    app: hawkeye
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hawkeye
  template:
    metadata:
      labels:
        app: hawkeye
    spec:
      containers:
      - name: hawkeye
        image: hawkeye/hawkeye:latest
        ports:
        - containerPort: 8080
        env:
        - name: HAWKEYE_CONFIG
          value: "/app/config/hawkeye.yaml"
        volumeMounts:
        - name: config-volume
          mountPath: /app/config
        - name: logs-volume
          mountPath: /app/logs
      volumes:
      - name: config-volume
        configMap:
          name: hawkeye-config
      - name: logs-volume
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: hawkeye-service
spec:
  selector:
    app: hawkeye
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8080
  type: LoadBalancer
```

```bash
# Deploy to Kubernetes
kubectl apply -f hawkeye-deployment.yaml

# Check deployment status
kubectl get pods -l app=hawkeye
kubectl get services hawkeye-service
```

---

## Development Setup

### Prerequisites for Development

```bash
# Install additional development tools
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Install testing tools
pip install pytest pytest-cov pytest-mock
```

### Development Environment Setup

```bash
# 1. Fork and clone repository
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye

# 2. Create development virtual environment
python3 -m venv venv-dev
source venv-dev/bin/activate

# 3. Install in development mode
pip install -e .

# 4. Install development dependencies
pip install -r requirements-dev.txt

# 5. Set up pre-commit hooks
pre-commit install

# 6. Run tests to verify setup
pytest tests/

# 7. Set up development configuration
cp config/hawkeye.yaml.example config/hawkeye-dev.yaml
export HAWKEYE_CONFIG=config/hawkeye-dev.yaml
```

### IDE Configuration

#### Visual Studio Code

```json
// .vscode/settings.json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests/"],
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        ".pytest_cache": true
    }
}
```

#### PyCharm

1. Open project in PyCharm
2. Configure Python interpreter: `File > Settings > Project > Python Interpreter`
3. Select the virtual environment: `./venv/bin/python`
4. Configure test runner: `File > Settings > Tools > Python Integrated Tools`
5. Set default test runner to `pytest`

---

## Configuration

### Initial Configuration

```bash
# Generate default configuration
python application.py config init

# Edit configuration file
nano ~/.hawkeye/config.yaml
```

### Configuration File Structure

```yaml
# ~/.hawkeye/config.yaml
scanning:
  default_ports: [3000, 8000, 8080, 9000]
  default_threads: 50
  default_timeout: 10
  rate_limit: 100

detection:
  deep_inspection: false
  protocol_verification: true
  docker_inspection: true

reporting:
  default_format: json
  output_directory: ./results
  include_metadata: true

logging:
  level: INFO
  file: ~/.hawkeye/hawkeye.log
  max_size: 10MB
  backup_count: 5

security:
  audit_logging: true
  require_authorization: true
  max_scan_range: 65536
```

### Environment Variables

```bash
# Set environment variables
export HAWKEYE_CONFIG=~/.hawkeye/config.yaml
export HAWKEYE_LOG_LEVEL=INFO
export HAWKEYE_THREADS=25
export HAWKEYE_TIMEOUT=15

# Make permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export HAWKEYE_CONFIG=~/.hawkeye/config.yaml' >> ~/.bashrc
```

### Network Configuration

```bash
# Configure network interfaces (if needed)
sudo ip link set dev eth0 up
sudo ip addr add 192.168.1.100/24 dev eth0

# Configure routing (if needed)
sudo ip route add default via 192.168.1.1

# Configure DNS (if needed)
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

---

## Verification

### Basic Functionality Test

```bash
# 1. Check version
python application.py --version

# 2. Run health check
python application.py health-check

# 3. Test configuration
python application.py config validate

# 4. Test basic scan (safe target)
python application.py scan --target 127.0.0.1

# 5. Generate test report
python application.py report --input scan_results.json --format html
```

### Comprehensive Test Suite

```bash
# Run all tests
pytest tests/ -v

# Run specific test categories
pytest tests/test_scanner/ -v
pytest tests/test_detection/ -v
pytest tests/integration/ -v

# Run with coverage
pytest tests/ --cov=src/hawkeye --cov-report=html
```

### Performance Verification

```bash
# Benchmark scanning performance
python application.py benchmark --target 192.168.1.0/24

# Memory usage test
python application.py test-memory --target 192.168.1.0/24

# Network performance test
python application.py test-network --target 192.168.1.0/24
```

---

## Troubleshooting

### Common Installation Issues

#### Python Version Issues

```bash
# Check Python version
python --version
python3 --version

# Install specific Python version (Ubuntu)
sudo apt install python3.9 python3.9-venv python3.9-pip

# Use specific Python version
python3.9 -m venv venv
```

#### Permission Issues

```bash
# Fix file permissions
chmod +x application.py
chmod 644 config.yaml

# Fix directory permissions
chmod 755 ~/.hawkeye
```

#### Network Issues

```bash
# Test network connectivity
ping 8.8.8.8
curl -I https://github.com

# Check firewall settings
sudo ufw status
sudo iptables -L
```

#### Dependency Issues

```bash
# Update pip
pip install --upgrade pip

# Clear pip cache
pip cache purge

# Reinstall dependencies
pip uninstall -r requirements.txt -y
pip install -r requirements.txt
```

### Getting Help

If you encounter issues during installation:

1. **Check the troubleshooting guide**: `docs/troubleshooting.md`
2. **Review system requirements**: Ensure your system meets minimum requirements
3. **Check logs**: Look for error messages in installation logs
4. **Search existing issues**: Check GitHub issues for similar problems
5. **Create new issue**: If problem persists, create a detailed issue report

---

## Uninstallation

### Complete Removal

```bash
# 1. Deactivate virtual environment
deactivate

# 2. Remove HawkEye directory
rm -rf /path/to/hawkeye

# 3. Remove configuration
rm -rf ~/.hawkeye

# 4. Remove logs (if stored separately)
rm -rf /var/log/hawkeye

# 5. Remove systemd service (if installed)
sudo systemctl stop hawkeye
sudo systemctl disable hawkeye
sudo rm /etc/systemd/system/hawkeye.service
sudo systemctl daemon-reload
```

### Docker Cleanup

```bash
# Remove containers
docker rm -f $(docker ps -aq --filter ancestor=hawkeye/hawkeye)

# Remove images
docker rmi hawkeye/hawkeye:latest

# Remove volumes
docker volume rm $(docker volume ls -q --filter name=hawkeye)

# Clean up Docker system
docker system prune -a
```

### Partial Removal (Keep Configuration)

```bash
# Remove only the application
rm -rf /path/to/hawkeye

# Keep configuration and logs for future use
# ~/.hawkeye directory remains intact
```

---

## Next Steps

After successful installation:

1. **Read the User Manual**: `docs/user_manual.md`
2. **Review Security Guidelines**: `docs/security_guidelines.md`
3. **Configure for Your Environment**: Customize settings in `config.yaml`
4. **Run Your First Scan**: Start with a small, authorized target
5. **Set Up Monitoring**: Configure logging and alerting
6. **Join the Community**: Participate in discussions and contribute

---

**Document Version**: 1.0  
**Last Updated**: Current Version  
**Next Review**: Quarterly 